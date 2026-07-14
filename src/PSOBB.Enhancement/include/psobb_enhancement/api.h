#pragma once

#include <cstdint>

#if defined(_WIN32)
#include <windows.h>
#else
using BOOL = int;
#define WINAPI
#endif

#define PSOBB_ENHANCEMENT_API extern "C"

namespace psobb::enhancement {

inline constexpr std::uint32_t kCapabilityAbiVersion = 1;
inline constexpr wchar_t kVersion[] = L"0.1.0-cleanroom";

enum class RuntimeState : std::uint32_t {
  cold = 0,
  initializing = 1,
  disabled_by_config = 2,
  armed = 3,
  active = 4,
  runtime_fallback = 5,
  rejected = 6,
  rolled_back = 7,
};

enum CapabilityFlag : std::uint32_t {
  capability_none = 0,
  capability_base_hash_matched = 1U << 0U,
  capability_expected_bytes_matched = 1U << 1U,
  capability_direct3d_iat_hook = 1U << 2U,
  capability_resolution_2560x1600 = 1U << 3U,
  capability_resolution_3840x2400 = 1U << 4U,
  capability_horizontal_fov_hook = 1U << 5U,
  capability_borderless_window = 1U << 6U,
  capability_resizable_window = 1U << 7U,
  capability_game_initiated_reset_hook = 1U << 8U,
  capability_hud_minimap = 1U << 9U,
  capability_automatic_device_recreation = 1U << 10U,
};

struct CapabilitiesV1 {
  std::uint32_t struct_size;
  std::uint32_t abi_version;
  RuntimeState state;
  std::uint32_t flags;
  std::uint32_t configured_width;
  std::uint32_t configured_height;
  std::uint32_t create_device_attempts;
  std::uint32_t create_device_fallbacks;
  std::uint32_t projection_calls_seen;
  std::uint32_t projection_calls_adjusted;
  wchar_t version[32];
  wchar_t last_error[256];
};

}  // namespace psobb::enhancement

PSOBB_ENHANCEMENT_API BOOL WINAPI PSOBBEnhancement_Initialize();
PSOBB_ENHANCEMENT_API BOOL WINAPI PSOBBEnhancement_GetCapabilities(
    psobb::enhancement::CapabilitiesV1* capabilities);
PSOBB_ENHANCEMENT_API BOOL WINAPI PSOBBEnhancement_Rollback();
PSOBB_ENHANCEMENT_API const wchar_t* WINAPI PSOBBEnhancement_GetVersion();
