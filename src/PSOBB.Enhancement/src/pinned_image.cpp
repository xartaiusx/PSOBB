#include "psobb_enhancement/pinned_image.h"

#include "sha256.h"

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

namespace psobb::enhancement {
namespace {

inline constexpr std::array<std::byte, 16> kExpectedEntryPointBytes = {
    std::byte{0xBB}, std::byte{0x27}, std::byte{0x02}, std::byte{0x00},
    std::byte{0x00}, std::byte{0xE9}, std::byte{0x69}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x90}, std::byte{0x90},
    std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};

inline constexpr std::array<std::byte, 6> kExpectedDirect3DThunkBytes = {
    std::byte{0xFF}, std::byte{0x25}, std::byte{0x1C},
    std::byte{0x84}, std::byte{0x8F}, std::byte{0x00}};

inline constexpr std::array<std::byte, 4> kExpectedIatFileBytes = {
    std::byte{0x1E}, std::byte{0xF6}, std::byte{0x75}, std::byte{0x00}};

inline constexpr std::array<std::byte, 18> kExpectedImportNameBytes = {
    std::byte{0x00}, std::byte{0x00}, std::byte{'D'}, std::byte{'i'},
    std::byte{'r'}, std::byte{'e'}, std::byte{'c'}, std::byte{'t'},
    std::byte{'3'}, std::byte{'D'}, std::byte{'C'}, std::byte{'r'},
    std::byte{'e'}, std::byte{'a'}, std::byte{'t'}, std::byte{'e'},
    std::byte{'8'}, std::byte{0x00}};

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

[[nodiscard]] bool ParsePinnedPe(
    const std::span<const std::byte> bytes,
    ParsedPe& parsed,
    std::wstring& failure) {
  if (!CopyStructure(bytes, 0, parsed.dos) ||
      parsed.dos.e_magic != IMAGE_DOS_SIGNATURE ||
      parsed.dos.e_lfanew < 0) {
    failure = L"DOS header mismatch";
    return false;
  }

  const std::size_t nt_offset = static_cast<std::size_t>(parsed.dos.e_lfanew);
  if (!CopyStructure(bytes, nt_offset, parsed.nt) ||
      parsed.nt.Signature != IMAGE_NT_SIGNATURE) {
    failure = L"PE header mismatch";
    return false;
  }

  const auto& file = parsed.nt.FileHeader;
  const auto& optional = parsed.nt.OptionalHeader;
  if (file.Machine != IMAGE_FILE_MACHINE_I386 ||
      file.NumberOfSections != 9 ||
      file.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32) ||
      optional.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      optional.ImageBase != kPinnedImageBase ||
      optional.SizeOfImage != kPinnedImageSize ||
      optional.AddressOfEntryPoint != kPinnedEntryPointRva ||
      optional.SizeOfHeaders != 0x400U ||
      optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress != 0 ||
      optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0) {
    failure = L"Pinned PE32 contract mismatch";
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
    const ParsedPe& parsed, const std::uint32_t rva) noexcept {
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

template <std::size_t Size>
[[nodiscard]] bool MatchBytes(
    const std::span<const std::byte> bytes,
    const std::size_t offset,
    const std::array<std::byte, Size>& expected) noexcept {
  if (offset > bytes.size() || expected.size() > bytes.size() - offset) {
    return false;
  }
  return std::equal(
      expected.begin(), expected.end(), bytes.begin() + offset);
}

[[nodiscard]] bool VerifyFileByteGates(
    const std::span<const std::byte> bytes,
    const ParsedPe& parsed,
    std::wstring& failure) {
  const auto entry = RvaToFileOffset(parsed, kPinnedEntryPointRva);
  const auto thunk = RvaToFileOffset(parsed, kDirect3DCreate8ThunkRva);
  const auto iat = RvaToFileOffset(parsed, kDirect3DCreate8IatRva);
  const auto name = RvaToFileOffset(parsed, 0x0075F61EU);
  if (!entry || !thunk || !iat || !name) {
    failure = L"A pinned RVA is not backed by file bytes";
    return false;
  }

  if (!MatchBytes(bytes, *entry, kExpectedEntryPointBytes)) {
    failure = L"Entrypoint expected-byte gate failed";
    return false;
  }
  if (!MatchBytes(bytes, *thunk, kExpectedDirect3DThunkBytes)) {
    failure = L"Direct3DCreate8 thunk expected-byte gate failed";
    return false;
  }
  if (!MatchBytes(bytes, *iat, kExpectedIatFileBytes)) {
    failure = L"Direct3DCreate8 IAT file-byte gate failed";
    return false;
  }
  if (!MatchBytes(bytes, *name, kExpectedImportNameBytes)) {
    failure = L"Direct3DCreate8 import-name gate failed";
    return false;
  }
  return true;
}

}  // namespace

ImageVerification VerifyPinnedExecutable(const std::wstring& path) {
  ImageVerification result;
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
  result.file_size_matched = size == kPinnedFileSize;
  if (!result.file_size_matched ||
      size > static_cast<std::uint64_t>(
                 std::numeric_limits<std::size_t>::max())) {
    result.failure = L"Executable size does not match the pinned base";
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
  result.sha256_matched = result.actual_sha256 == kPinnedSha256;
  if (!result.sha256_matched) {
    result.failure = L"Executable SHA-256 does not match the pinned base";
    return result;
  }

  ParsedPe parsed;
  if (!ParsePinnedPe(bytes, parsed, result.failure)) {
    return result;
  }
  result.pe_contract_matched = true;

  if (!VerifyFileByteGates(bytes, parsed, result.failure)) {
    return result;
  }
  result.expected_bytes_matched = true;
  return result;
}

bool VerifyLoadedImage(
    const std::span<const std::byte> image,
    std::wstring& failure) {
  if (image.size() < kPinnedImageSize) {
    failure = L"Loaded image is smaller than the pinned SizeOfImage";
    return false;
  }

  ParsedPe parsed;
  if (!ParsePinnedPe(image, parsed, failure)) {
    return false;
  }

  if (!MatchBytes(image, kPinnedEntryPointRva, kExpectedEntryPointBytes)) {
    failure = L"Loaded entrypoint expected-byte gate failed";
    return false;
  }
  if (!MatchBytes(
          image, kDirect3DCreate8ThunkRva, kExpectedDirect3DThunkBytes)) {
    failure = L"Loaded Direct3DCreate8 thunk expected-byte gate failed";
    return false;
  }
  return true;
}

}  // namespace psobb::enhancement
