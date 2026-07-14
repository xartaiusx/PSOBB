#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>

namespace psobb::enhancement::d3d8 {

// Public Direct3D 8 ABI declarations kept local because current Windows SDKs
// no longer ship d3d8.h. These contain only the structures and method slots
// used by this component.
struct PresentParameters {
  UINT back_buffer_width;
  UINT back_buffer_height;
  std::int32_t back_buffer_format;
  UINT back_buffer_count;
  std::int32_t multi_sample_type;
  std::int32_t swap_effect;
  HWND device_window;
  BOOL windowed;
  BOOL enable_auto_depth_stencil;
  std::int32_t auto_depth_stencil_format;
  DWORD flags;
  UINT full_screen_refresh_rate_hz;
  UINT full_screen_presentation_interval;
};

struct Matrix {
  float value[4][4];
};

inline constexpr DWORD kTransformStateProjection = 3;
inline constexpr std::size_t kDirect3D8CreateDeviceSlot = 15;
inline constexpr std::size_t kDeviceResetSlot = 14;
inline constexpr std::size_t kDeviceSetTransformSlot = 37;

using Direct3DCreate8 = void*(WINAPI*)(UINT sdk_version);
using CreateDevice = HRESULT(WINAPI*)(
    void* self,
    UINT adapter,
    std::int32_t device_type,
    HWND focus_window,
    DWORD behavior_flags,
    PresentParameters* presentation,
    void** returned_device);
using Reset = HRESULT(WINAPI*)(void* self, PresentParameters* presentation);
using SetTransform = HRESULT(WINAPI*)(
    void* self, DWORD state, const Matrix* matrix);

static_assert(sizeof(PresentParameters) == 52);
static_assert(sizeof(Matrix) == 64);

}  // namespace psobb::enhancement::d3d8
