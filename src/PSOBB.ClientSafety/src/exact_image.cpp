#include "psobb_client_safety/exact_image.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace psobb::client_safety {
namespace {

template <typename T>
[[nodiscard]] bool CopyStructure(
    const std::span<const std::byte> bytes,
    const std::size_t offset,
    T& structure) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
    return false;
  }
  std::memcpy(&structure, bytes.data() + offset, sizeof(T));
  return true;
}

struct ParsedPe {
  IMAGE_DOS_HEADER dos{};
  IMAGE_NT_HEADERS32 nt{};
  std::vector<IMAGE_SECTION_HEADER> sections;
};

[[nodiscard]] bool ParseExactPe(
    const std::span<const std::byte> bytes,
    const ExactImageIdentity& identity,
    ParsedPe& parsed,
    std::wstring& failure) {
  if (!CopyStructure(bytes, 0, parsed.dos) ||
      parsed.dos.e_magic != IMAGE_DOS_SIGNATURE ||
      parsed.dos.e_lfanew < 0) {
    failure = L"DOS header mismatch";
    return false;
  }

  const std::size_t nt_offset =
      static_cast<std::size_t>(parsed.dos.e_lfanew);
  if (!CopyStructure(bytes, nt_offset, parsed.nt) ||
      parsed.nt.Signature != IMAGE_NT_SIGNATURE) {
    failure = L"PE header mismatch";
    return false;
  }

  const auto& file = parsed.nt.FileHeader;
  const auto& optional = parsed.nt.OptionalHeader;
  if (file.Machine != identity.machine ||
      file.NumberOfSections != identity.section_count ||
      file.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32) ||
      optional.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      optional.ImageBase != identity.image_base ||
      optional.SizeOfImage != identity.image_size ||
      optional.AddressOfEntryPoint != identity.entry_point_rva ||
      optional.SizeOfHeaders != identity.size_of_headers ||
      optional.SectionAlignment != identity.section_alignment ||
      optional.FileAlignment != identity.file_alignment ||
      optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress != 0U ||
      optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0U) {
    failure = L"Exact PE32 contract mismatch";
    return false;
  }

  const std::size_t section_offset =
      nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
      file.SizeOfOptionalHeader;
  parsed.sections.clear();
  parsed.sections.reserve(file.NumberOfSections);
  for (std::size_t index = 0; index < file.NumberOfSections; ++index) {
    IMAGE_SECTION_HEADER section{};
    if (!CopyStructure(
            bytes,
            section_offset + index * sizeof(IMAGE_SECTION_HEADER),
            section)) {
      failure = L"Section table is truncated";
      return false;
    }
    parsed.sections.push_back(section);
  }
  return true;
}

[[nodiscard]] std::optional<std::size_t> RvaToFileOffset(
    const ParsedPe& parsed,
    const std::uint32_t rva) noexcept {
  if (rva < parsed.nt.OptionalHeader.SizeOfHeaders) {
    return static_cast<std::size_t>(rva);
  }

  for (const auto& section : parsed.sections) {
    const std::uint64_t start = section.VirtualAddress;
    const std::uint64_t end =
        start + std::max(section.Misc.VirtualSize, section.SizeOfRawData);
    if (rva < start || rva >= end) {
      continue;
    }

    const std::uint64_t delta = static_cast<std::uint64_t>(rva) - start;
    if (delta >= section.SizeOfRawData) {
      return std::nullopt;
    }
    return static_cast<std::size_t>(section.PointerToRawData + delta);
  }
  return std::nullopt;
}

[[nodiscard]] bool MatchBytes(
    const std::span<const std::byte> bytes,
    const std::size_t offset,
    const std::span<const std::byte> expected) noexcept {
  return offset <= bytes.size() && expected.size() <= bytes.size() - offset &&
         std::equal(
             expected.begin(), expected.end(), bytes.begin() + offset);
}

void SetGateFailure(
    std::wstring& failure,
    const wchar_t* prefix,
    const std::uint32_t rva) {
  std::array<wchar_t, 9> address{};
  _snwprintf_s(
      address.data(),
      address.size(),
      _TRUNCATE,
      L"%08X",
      static_cast<unsigned int>(rva));
  failure = prefix;
  failure.append(address.data());
}

[[nodiscard]] bool VerifyFileExpectations(
    const std::span<const std::byte> bytes,
    const ParsedPe& parsed,
    const std::span<const ExpectedBytes> expectations,
    std::wstring& failure) {
  for (const auto& expectation : expectations) {
    if (expectation.bytes.empty()) {
      SetGateFailure(
          failure, L"Empty expected-byte gate at RVA 0x", expectation.rva);
      return false;
    }
    const auto offset = RvaToFileOffset(parsed, expectation.rva);
    if (!offset || !MatchBytes(bytes, *offset, expectation.bytes)) {
      SetGateFailure(
          failure, L"File expected-byte gate failed at RVA 0x", expectation.rva);
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool VerifyLoadedExpectations(
    const std::span<const std::byte> image,
    const std::span<const ExpectedBytes> expectations,
    std::wstring& failure) {
  for (const auto& expectation : expectations) {
    if (expectation.bytes.empty() ||
        !MatchBytes(image, expectation.rva, expectation.bytes)) {
      SetGateFailure(
          failure,
          L"Loaded expected-byte gate failed at RVA 0x",
          expectation.rva);
      return false;
    }
  }
  return true;
}

}  // namespace

ImageVerification VerifyExecutable(
    const std::wstring& path,
    const ExactImageIdentity& identity,
    const std::span<const ExpectedBytes> expectations) {
  ImageVerification result;
  if (identity.sha256.size() != 64U) {
    result.failure = L"Expected SHA-256 identity must contain 64 hex digits";
    return result;
  }

  std::ifstream stream(
      std::filesystem::path(path), std::ios::binary | std::ios::ate);
  if (!stream) {
    result.failure = L"Unable to open the executable for read-only preflight";
    return result;
  }

  const std::streampos end = stream.tellg();
  if (end < 0) {
    result.failure = L"Unable to determine executable size";
    return result;
  }
  const auto size = static_cast<std::uint64_t>(end);
  result.file_size_matched = size == identity.file_size;
  if (!result.file_size_matched ||
      size > static_cast<std::uint64_t>(
                 std::numeric_limits<std::size_t>::max())) {
    result.failure = L"Executable size does not match the exact identity";
    return result;
  }

  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  stream.seekg(0, std::ios::beg);
  stream.read(
      reinterpret_cast<char*>(bytes.data()),
      static_cast<std::streamsize>(bytes.size()));
  if (!stream || static_cast<std::size_t>(stream.gcount()) != bytes.size()) {
    result.failure = L"Unable to read the complete executable";
    return result;
  }

  std::array<std::uint8_t, 32> digest{};
  if (!ComputeSha256(bytes, digest, result.failure)) {
    return result;
  }
  result.actual_sha256 = HexEncode(digest);
  result.sha256_matched = result.actual_sha256 == identity.sha256;
  if (!result.sha256_matched) {
    result.failure = L"Executable SHA-256 does not match the exact identity";
    return result;
  }

  ParsedPe parsed;
  if (!ParseExactPe(bytes, identity, parsed, result.failure)) {
    return result;
  }
  result.pe_contract_matched = true;

  if (!VerifyFileExpectations(
          bytes, parsed, expectations, result.failure)) {
    return result;
  }
  result.expected_bytes_matched = true;
  return result;
}

bool VerifyLoadedImage(
    const std::span<const std::byte> image,
    const ExactImageIdentity& identity,
    const std::span<const ExpectedBytes> expectations,
    std::wstring& failure) {
  if (image.size() < identity.image_size) {
    failure = L"Loaded image is smaller than the exact SizeOfImage";
    return false;
  }

  ParsedPe parsed;
  if (!ParseExactPe(image, identity, parsed, failure)) {
    return false;
  }
  return VerifyLoadedExpectations(image, expectations, failure);
}

}  // namespace psobb::client_safety
