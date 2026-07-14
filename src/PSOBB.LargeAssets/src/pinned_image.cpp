#include "psobb_large_assets/pinned_image.h"

#include "psobb_large_assets/patch_plan.h"

#include <windows.h>
#include <bcrypt.h>

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

namespace psobb::large_assets {
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
  std::array<IMAGE_SECTION_HEADER, 9> sections{};
};

[[nodiscard]] bool ParsePinnedPe(
    const std::span<const std::byte> bytes,
    ParsedPe& parsed,
    std::wstring& failure) noexcept {
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
  if (file.Machine != IMAGE_FILE_MACHINE_I386 ||
      file.NumberOfSections != parsed.sections.size() ||
      file.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32) ||
      optional.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
      optional.ImageBase != kPinnedImageBase ||
      optional.SizeOfImage != kPinnedImageSize ||
      optional.AddressOfEntryPoint != kPinnedEntryPointRva ||
      optional.SectionAlignment != 0x1000U ||
      optional.FileAlignment != 0x200U ||
      optional.SizeOfHeaders != 0x400U ||
      optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress != 0U ||
      optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0U) {
    failure = L"Pinned PE32 contract mismatch";
    return false;
  }

  const std::size_t section_offset =
      nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
      file.SizeOfOptionalHeader;
  for (std::size_t index = 0; index < parsed.sections.size(); ++index) {
    if (!CopyStructure(
            bytes,
            section_offset + index * sizeof(IMAGE_SECTION_HEADER),
            parsed.sections[index])) {
      failure = L"Section table is truncated";
      return false;
    }
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

    const std::uint64_t delta =
        static_cast<std::uint64_t>(rva) - start;
    if (delta >= section.SizeOfRawData) {
      return std::nullopt;
    }
    return static_cast<std::size_t>(section.PointerToRawData + delta);
  }
  return std::nullopt;
}

[[nodiscard]] bool MatchValue(
    const std::span<const std::byte> bytes,
    const std::size_t offset,
    const std::uint32_t expected) noexcept {
  std::uint32_t observed = 0;
  return CopyStructure(bytes, offset, observed) && observed == expected;
}

[[nodiscard]] bool VerifyFilePatchBytes(
    const std::span<const std::byte> bytes,
    const ParsedPe& parsed,
    std::wstring& failure) noexcept {
  for (const auto& site : kPatchSites) {
    const auto offset = RvaToFileOffset(parsed, site.rva);
    if (!offset || !MatchValue(bytes, *offset, site.expected_value)) {
      failure = L"Patch-site file expected-byte gate failed at VA 0x";
      wchar_t address[9]{};
      _snwprintf_s(
          address,
          _countof(address),
          _TRUNCATE,
          L"%08X",
          static_cast<unsigned int>(site.virtual_address));
      failure.append(address);
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool VerifyLoadedPatchBytes(
    const std::span<const std::byte> image,
    std::wstring& failure) noexcept {
  for (const auto& site : kPatchSites) {
    if (!MatchValue(image, site.rva, site.expected_value)) {
      failure = L"Loaded patch-site expected-byte gate failed at VA 0x";
      wchar_t address[9]{};
      _snwprintf_s(
          address,
          _countof(address),
          _TRUNCATE,
          L"%08X",
          static_cast<unsigned int>(site.virtual_address));
      failure.append(address);
      return false;
    }
  }
  return true;
}

class AlgorithmHandle final {
 public:
  AlgorithmHandle() = default;
  AlgorithmHandle(const AlgorithmHandle&) = delete;
  AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
  ~AlgorithmHandle() {
    if (handle_ != nullptr) {
      BCryptCloseAlgorithmProvider(handle_, 0);
    }
  }

  BCRYPT_ALG_HANDLE* receive() noexcept { return &handle_; }
  BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

 private:
  BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class HashHandle final {
 public:
  HashHandle() = default;
  HashHandle(const HashHandle&) = delete;
  HashHandle& operator=(const HashHandle&) = delete;
  ~HashHandle() {
    if (handle_ != nullptr) {
      BCryptDestroyHash(handle_);
    }
  }

  BCRYPT_HASH_HANDLE* receive() noexcept { return &handle_; }
  BCRYPT_HASH_HANDLE get() const noexcept { return handle_; }

 private:
  BCRYPT_HASH_HANDLE handle_ = nullptr;
};

[[nodiscard]] bool ComputeSha256(
    const std::span<const std::byte> bytes,
    std::array<std::uint8_t, 32>& digest,
    std::wstring& failure) {
  AlgorithmHandle algorithm;
  NTSTATUS status = BCryptOpenAlgorithmProvider(
      algorithm.receive(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (status < 0) {
    failure = L"BCryptOpenAlgorithmProvider(SHA-256) failed";
    return false;
  }

  DWORD object_length = 0;
  DWORD result_length = 0;
  status = BCryptGetProperty(
      algorithm.get(),
      BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&object_length),
      sizeof(object_length),
      &result_length,
      0);
  if (status < 0 || result_length != sizeof(object_length)) {
    failure = L"BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed";
    return false;
  }

  std::vector<std::uint8_t> hash_object(object_length);
  HashHandle hash;
  status = BCryptCreateHash(
      algorithm.get(),
      hash.receive(),
      hash_object.data(),
      static_cast<ULONG>(hash_object.size()),
      nullptr,
      0,
      0);
  if (status < 0) {
    failure = L"BCryptCreateHash failed";
    return false;
  }

  constexpr std::size_t kMaximumChunk = 1U << 30U;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const std::size_t count =
        std::min(kMaximumChunk, bytes.size() - offset);
    auto* data = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(
        bytes.data() + offset));
    status = BCryptHashData(
        hash.get(), data, static_cast<ULONG>(count), 0);
    if (status < 0) {
      failure = L"BCryptHashData failed";
      return false;
    }
    offset += count;
  }

  status = BCryptFinishHash(
      hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
  if (status < 0) {
    failure = L"BCryptFinishHash failed";
    return false;
  }
  return true;
}

[[nodiscard]] std::wstring HexEncode(
    const std::array<std::uint8_t, 32>& digest) {
  constexpr wchar_t kHex[] = L"0123456789ABCDEF";
  std::wstring value(digest.size() * 2U, L'0');
  for (std::size_t index = 0; index < digest.size(); ++index) {
    value[index * 2U] = kHex[digest[index] >> 4U];
    value[index * 2U + 1U] = kHex[digest[index] & 0x0FU];
  }
  return value;
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

  if (!VerifyPinnedPePatchBytes(bytes, result.failure)) {
    return result;
  }
  result.pe_contract_matched = true;
  result.patch_bytes_matched = true;
  return result;
}

bool VerifyPinnedPePatchBytes(
    const std::span<const std::byte> file_bytes,
    std::wstring& failure) noexcept {
  ParsedPe parsed;
  if (!ParsePinnedPe(file_bytes, parsed, failure)) {
    return false;
  }
  return VerifyFilePatchBytes(file_bytes, parsed, failure);
}

bool VerifyLoadedImage(
    const std::span<const std::byte> image,
    std::wstring& failure) noexcept {
  if (image.size() < kPinnedImageSize) {
    failure = L"Loaded image is smaller than the pinned SizeOfImage";
    return false;
  }

  ParsedPe parsed;
  if (!ParsePinnedPe(image, parsed, failure)) {
    return false;
  }
  return VerifyLoadedPatchBytes(image, failure);
}

}  // namespace psobb::large_assets
