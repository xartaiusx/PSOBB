#pragma once

#include <cstdint>

#if defined(_WIN32)
#include <windows.h>
#else
using BOOL = int;
#define WINAPI
#endif

#define PSOBB_LARGE_ASSETS_API extern "C"

namespace psobb::large_assets {

inline constexpr std::uint32_t kCapabilityAbiVersion = 1U;
inline constexpr wchar_t kVersion[] = L"0.1.0-pinned-59nl";

enum class RuntimeState : std::uint32_t {
  cold = 0,
  initializing = 1,
  disabled_by_config = 2,
  applying = 3,
  active = 4,
  rejected = 5,
  rolled_back = 6,
  rollback_failed = 7,
};

enum CapabilityFlag : std::uint32_t {
  capability_none = 0,
  capability_file_hash_matched = 1U << 0U,
  capability_loaded_pe_matched = 1U << 1U,
  capability_expected_bytes_matched = 1U << 2U,
  capability_transactional_apply = 1U << 3U,
  capability_rollback_available = 1U << 4U,
};

struct CapabilitiesV1 {
  std::uint32_t struct_size;
  std::uint32_t abi_version;
  RuntimeState state;
  std::uint32_t flags;
  std::uint32_t patch_value;
  std::uint32_t upstream_address_entries;
  std::uint32_t unique_patch_sites;
  std::uint32_t patched_sites;
  std::uint32_t rolled_back_sites;
  wchar_t version[32];
  wchar_t last_error[256];
};

}  // namespace psobb::large_assets

PSOBB_LARGE_ASSETS_API BOOL WINAPI PSOBBLargeAssets_Initialize();
PSOBB_LARGE_ASSETS_API BOOL WINAPI PSOBBLargeAssets_GetCapabilities(
    psobb::large_assets::CapabilitiesV1* capabilities);
PSOBB_LARGE_ASSETS_API BOOL WINAPI PSOBBLargeAssets_Rollback();
PSOBB_LARGE_ASSETS_API const wchar_t* WINAPI PSOBBLargeAssets_GetVersion();
