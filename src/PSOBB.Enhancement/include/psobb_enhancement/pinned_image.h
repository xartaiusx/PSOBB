#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace psobb::enhancement {

inline constexpr wchar_t kPinnedSha256[] =
    L"DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535";
inline constexpr std::uint64_t kPinnedFileSize = 6'971'904;
inline constexpr std::uintptr_t kPinnedImageBase = 0x00400000U;
inline constexpr std::uint32_t kPinnedImageSize = 0x00762000U;
inline constexpr std::uint32_t kPinnedEntryPointRva = 0x00760000U;
inline constexpr std::uint32_t kDirect3DCreate8IatRva = 0x004F841CU;
inline constexpr std::uint32_t kDirect3DCreate8ThunkRva = 0x004BEFF2U;

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

[[nodiscard]] ImageVerification VerifyPinnedExecutable(
    const std::wstring& path);

[[nodiscard]] bool VerifyLoadedImage(
    std::span<const std::byte> image,
    std::wstring& failure);

}  // namespace psobb::enhancement
