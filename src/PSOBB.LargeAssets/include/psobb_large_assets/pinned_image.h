#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace psobb::large_assets {

inline constexpr wchar_t kPinnedSha256[] =
    L"DD3D475916038E8E8E3F230CFAD6D8D93A2976B1B42AF0014413FF3B737C5535";
inline constexpr std::uint64_t kPinnedFileSize = 6'971'904U;
inline constexpr std::uint32_t kPinnedImageSize = 0x00762000U;
inline constexpr std::uint32_t kPinnedEntryPointRva = 0x00760000U;

struct ImageVerification {
  bool file_size_matched = false;
  bool sha256_matched = false;
  bool pe_contract_matched = false;
  bool patch_bytes_matched = false;
  std::wstring actual_sha256;
  std::wstring failure;

  [[nodiscard]] bool passed() const noexcept {
    return file_size_matched && sha256_matched && pe_contract_matched &&
           patch_bytes_matched;
  }
};

[[nodiscard]] ImageVerification VerifyPinnedExecutable(
    const std::wstring& path);

// Verifies the pinned PE contract and maps each patch-site RVA through the
// section table before checking raw file bytes. This is intentionally exposed
// so synthetic tests can prove the RVA-to-raw mapping independently of the
// proprietary executable hash gate.
[[nodiscard]] bool VerifyPinnedPePatchBytes(
    std::span<const std::byte> file_bytes,
    std::wstring& failure) noexcept;

[[nodiscard]] bool VerifyLoadedImage(
    std::span<const std::byte> image,
    std::wstring& failure) noexcept;

}  // namespace psobb::large_assets
