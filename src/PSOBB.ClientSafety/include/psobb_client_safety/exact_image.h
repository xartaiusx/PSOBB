#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace psobb::client_safety {

struct ExactImageIdentity {
  std::uint64_t file_size;
  std::wstring_view sha256;
  std::uintptr_t image_base;
  std::uint32_t image_size;
  std::uint32_t entry_point_rva;
  std::uint32_t size_of_headers;
  std::uint32_t section_alignment;
  std::uint32_t file_alignment;
  std::uint16_t machine;
  std::uint16_t section_count;
};

inline constexpr wchar_t k59NlSha256[] =
    L"DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535";

inline constexpr ExactImageIdentity k59NlIdentity{
    6'971'904U,
    k59NlSha256,
    0x00400000U,
    0x00762000U,
    0x00760000U,
    0x00000400U,
    0x00001000U,
    0x00000200U,
    0x014CU,
    9U};

struct ExpectedBytes {
  std::uint32_t rva;
  std::span<const std::byte> bytes;
};

struct ImageVerification {
  bool file_size_matched = false;
  bool sha256_matched = false;
  bool pe_contract_matched = false;
  bool expected_bytes_matched = false;
  std::wstring actual_sha256;
  std::wstring failure;

  [[nodiscard]] bool passed() const noexcept {
    return file_size_matched && sha256_matched && pe_contract_matched &&
           expected_bytes_matched;
  }
};

[[nodiscard]] bool ComputeSha256(
    std::span<const std::byte> bytes,
    std::array<std::uint8_t, 32>& digest,
    std::wstring& failure);

[[nodiscard]] std::wstring HexEncode(
    const std::array<std::uint8_t, 32>& digest);

[[nodiscard]] ImageVerification VerifyExecutable(
    const std::wstring& path,
    const ExactImageIdentity& identity,
    std::span<const ExpectedBytes> expectations = {});

[[nodiscard]] bool VerifyLoadedImage(
    std::span<const std::byte> image,
    const ExactImageIdentity& identity,
    std::span<const ExpectedBytes> expectations,
    std::wstring& failure);

}  // namespace psobb::client_safety
