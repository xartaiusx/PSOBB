#include "enhancement_internal.h"

#include "psobb_enhancement/api.h"
#include "psobb_enhancement/d3d8_abi.h"
#include "psobb_enhancement/pinned_image.h"
#include "psobb_enhancement/policy.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace psobb::enhancement {
namespace {

constexpr std::size_t kMaximumPatches = 12;
constexpr wchar_t kIniSection[] = L"Enhancement";
constexpr wchar_t kIniFileName[] = L"PSOBB.Enhancement.ini";

HMODULE g_module = nullptr;
INIT_ONCE g_initialize_once = INIT_ONCE_STATIC_INIT;
std::atomic_bool g_initialize_result{false};
std::atomic<RuntimeState> g_state{RuntimeState::cold};
std::atomic_uint32_t g_flags{capability_none};
std::atomic_uint32_t g_width{0};
std::atomic_uint32_t g_height{0};
std::atomic_uint32_t g_create_device_attempts{0};
std::atomic_uint32_t g_create_device_fallbacks{0};
std::atomic_uint32_t g_projection_calls_seen{0};
std::atomic_uint32_t g_projection_calls_adjusted{0};

SRWLOCK g_status_lock = SRWLOCK_INIT;
std::array<wchar_t, 256> g_last_error{};

Configuration g_configuration;

struct PointerPatch {
  void** slot = nullptr;
  void* original = nullptr;
  void* replacement = nullptr;
  bool installed = false;
};

SRWLOCK g_patch_lock = SRWLOCK_INIT;
std::array<PointerPatch, kMaximumPatches> g_patches{};

struct WindowSnapshot {
  HWND window = nullptr;
  LONG_PTR style = 0;
  LONG_PTR extended_style = 0;
  RECT rectangle{};
  bool active = false;
};

SRWLOCK g_window_lock = SRWLOCK_INIT;
WindowSnapshot g_window_snapshot;

void* WINAPI HookDirect3DCreate8(UINT sdk_version);
HRESULT WINAPI HookCreateDevice(
    void* self,
    UINT adapter,
    std::int32_t device_type,
    HWND focus_window,
    DWORD behavior_flags,
    d3d8::PresentParameters* presentation,
    void** returned_device);
HRESULT WINAPI HookReset(
    void* self, d3d8::PresentParameters* presentation);
HRESULT WINAPI HookSetTransform(
    void* self, DWORD state, const d3d8::Matrix* matrix);

void SetLastErrorText(const std::wstring_view message) noexcept {
  AcquireSRWLockExclusive(&g_status_lock);
  const std::size_t count =
      std::min(message.size(), g_last_error.size() - 1U);
  std::wmemcpy(g_last_error.data(), message.data(), count);
  g_last_error[count] = L'\0';
  ReleaseSRWLockExclusive(&g_status_lock);

  OutputDebugStringW(L"[PSOBB.Enhancement] ");
  OutputDebugStringW(g_last_error.data());
  OutputDebugStringW(L"\n");
}

[[nodiscard]] std::wstring WindowsError(
    const std::wstring_view operation, const DWORD error) {
  std::wstring message(operation);
  message.append(L" failed with Windows error ");
  message.append(std::to_wstring(error));
  return message;
}

[[nodiscard]] bool IsExecutableProtection(const DWORD protection) noexcept {
  const DWORD base = protection & 0xFFU;
  return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
         base == PAGE_EXECUTE_READWRITE ||
         base == PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] bool IsExecutableImageAddress(void* address) noexcept {
  MEMORY_BASIC_INFORMATION information{};
  if (address == nullptr ||
      VirtualQuery(address, &information, sizeof(information)) !=
          sizeof(information)) {
    return false;
  }
  return information.State == MEM_COMMIT && information.Type == MEM_IMAGE &&
         IsExecutableProtection(information.Protect) &&
         (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
}

[[nodiscard]] DWORD WritableProtection(const DWORD original) noexcept {
  return IsExecutableProtection(original) ? PAGE_EXECUTE_READWRITE
                                          : PAGE_READWRITE;
}

[[nodiscard]] bool InstallPointerPatch(
    void** slot, void* expected, void* replacement) {
  if (slot == nullptr || expected == nullptr || replacement == nullptr ||
      !IsExecutableImageAddress(expected) ||
      !IsExecutableImageAddress(replacement)) {
    SetLastErrorText(L"Pointer patch rejected an invalid slot or target");
    return false;
  }

  AcquireSRWLockExclusive(&g_patch_lock);
  for (const auto& patch : g_patches) {
    if (patch.installed && patch.slot == slot) {
      const bool same = patch.original == expected &&
                        patch.replacement == replacement;
      ReleaseSRWLockExclusive(&g_patch_lock);
      if (!same) {
        SetLastErrorText(L"Pointer patch slot is already owned");
      }
      return same;
    }
  }

  PointerPatch* record = nullptr;
  for (auto& patch : g_patches) {
    if (!patch.installed && patch.slot == nullptr) {
      record = &patch;
      break;
    }
  }
  if (record == nullptr) {
    ReleaseSRWLockExclusive(&g_patch_lock);
    SetLastErrorText(L"Pointer patch registry is full");
    return false;
  }

  MEMORY_BASIC_INFORMATION information{};
  if (VirtualQuery(slot, &information, sizeof(information)) !=
          sizeof(information) ||
      information.State != MEM_COMMIT ||
      (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
    ReleaseSRWLockExclusive(&g_patch_lock);
    SetLastErrorText(L"Pointer patch slot is not committed readable memory");
    return false;
  }

  record->slot = slot;
  record->original = expected;
  record->replacement = replacement;

  DWORD original_protection = 0;
  if (!VirtualProtect(
          slot,
          sizeof(*slot),
          WritableProtection(information.Protect),
          &original_protection)) {
    *record = {};
    ReleaseSRWLockExclusive(&g_patch_lock);
    SetLastErrorText(WindowsError(L"VirtualProtect", GetLastError()));
    return false;
  }

  void* observed = InterlockedCompareExchangePointer(
      reinterpret_cast<void* volatile*>(slot), replacement, expected);
  if (observed != expected) {
    DWORD ignored = 0;
    VirtualProtect(slot, sizeof(*slot), original_protection, &ignored);
    *record = {};
    ReleaseSRWLockExclusive(&g_patch_lock);
    SetLastErrorText(L"Expected-pointer preflight changed before the write");
    return false;
  }

  DWORD ignored = 0;
  if (!VirtualProtect(slot, sizeof(*slot), original_protection, &ignored)) {
    void* rollback_observed = InterlockedCompareExchangePointer(
        reinterpret_cast<void* volatile*>(slot), expected, replacement);
    const bool protection_restored =
        VirtualProtect(slot, sizeof(*slot), original_protection, &ignored) !=
        FALSE;
    if (rollback_observed == replacement && protection_restored) {
      *record = {};
    } else {
      record->installed = true;
    }
    ReleaseSRWLockExclusive(&g_patch_lock);
    SetLastErrorText(
        rollback_observed == replacement && protection_restored
            ? L"Protection restore failed; pointer write was rolled back"
            : L"Protection restore and pointer rollback both failed; module "
              L"remains pinned");
    return false;
  }

  FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));
  record->installed = true;
  ReleaseSRWLockExclusive(&g_patch_lock);
  return true;
}

[[nodiscard]] void* FindOriginal(
    void** slot, void* replacement) noexcept {
  void* original = nullptr;
  AcquireSRWLockShared(&g_patch_lock);
  for (const auto& patch : g_patches) {
    if (patch.installed && patch.slot == slot &&
        patch.replacement == replacement) {
      original = patch.original;
      break;
    }
  }
  ReleaseSRWLockShared(&g_patch_lock);
  return original;
}

[[nodiscard]] bool RollbackPointerPatches() noexcept {
  bool all_restored = true;
  AcquireSRWLockExclusive(&g_patch_lock);
  for (std::size_t index = g_patches.size(); index > 0; --index) {
    auto& patch = g_patches[index - 1U];
    if (!patch.installed) {
      continue;
    }

    MEMORY_BASIC_INFORMATION information{};
    DWORD original_protection = 0;
    if (VirtualQuery(patch.slot, &information, sizeof(information)) !=
            sizeof(information) ||
        !VirtualProtect(
            patch.slot,
            sizeof(*patch.slot),
            WritableProtection(information.Protect),
            &original_protection)) {
      all_restored = false;
      continue;
    }

    void* observed = InterlockedCompareExchangePointer(
        reinterpret_cast<void* volatile*>(patch.slot),
        patch.original,
        patch.replacement);
    DWORD ignored = 0;
    if (!VirtualProtect(
            patch.slot,
            sizeof(*patch.slot),
            original_protection,
            &ignored) ||
        observed != patch.replacement) {
      all_restored = false;
      continue;
    }

    FlushInstructionCache(
        GetCurrentProcess(), patch.slot, sizeof(*patch.slot));
    patch = {};
  }
  ReleaseSRWLockExclusive(&g_patch_lock);
  return all_restored;
}

template <typename Function>
[[nodiscard]] Function OriginalFor(
    void* object, const std::size_t slot_index, Function replacement) noexcept {
  if (object == nullptr) {
    return nullptr;
  }
  auto** table = *reinterpret_cast<void***>(object);
  if (table == nullptr) {
    return nullptr;
  }
  void** slot = &table[slot_index];
  return reinterpret_cast<Function>(
      FindOriginal(slot, reinterpret_cast<void*>(replacement)));
}

template <typename Function>
[[nodiscard]] bool PatchVtable(
    void* object, const std::size_t slot_index, Function replacement) {
  if (object == nullptr) {
    return false;
  }
  auto** table = *reinterpret_cast<void***>(object);
  if (table == nullptr) {
    return false;
  }
  void** slot = &table[slot_index];
  void* expected = *slot;
  return InstallPointerPatch(
      slot, expected, reinterpret_cast<void*>(replacement));
}

[[nodiscard]] bool ParseBoolean(
    const std::wstring& value, bool& parsed) {
  std::wstring lowered(value);
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
      });
  if (lowered == L"1" || lowered == L"true" || lowered == L"yes") {
    parsed = true;
    return true;
  }
  if (lowered == L"0" || lowered == L"false" || lowered == L"no") {
    parsed = false;
    return true;
  }
  return false;
}

[[nodiscard]] std::wstring ReadIniValue(
    const std::filesystem::path& path,
    const wchar_t* key,
    const wchar_t* default_value) {
  std::array<wchar_t, 128> buffer{};
  GetPrivateProfileStringW(
      kIniSection,
      key,
      default_value,
      buffer.data(),
      static_cast<DWORD>(buffer.size()),
      path.c_str());
  return buffer.data();
}

[[nodiscard]] bool ParseUnsigned(
    const std::wstring& value, std::uint32_t& parsed) noexcept {
  if (value.empty()) {
    return false;
  }
  wchar_t* end = nullptr;
  errno = 0;
  const unsigned long number = std::wcstoul(value.c_str(), &end, 10);
  if (errno != 0 || end == value.c_str() || *end != L'\0') {
    return false;
  }
  parsed = static_cast<std::uint32_t>(number);
  return static_cast<unsigned long>(parsed) == number;
}

[[nodiscard]] bool LoadConfiguration(Configuration& configuration) {
  if (g_module == nullptr) {
    SetLastErrorText(L"Enhancement module handle is unavailable");
    return false;
  }

  std::array<wchar_t, 32768> module_path{};
  const DWORD length = GetModuleFileNameW(
      g_module, module_path.data(), static_cast<DWORD>(module_path.size()));
  if (length == 0 || length >= module_path.size()) {
    SetLastErrorText(WindowsError(L"GetModuleFileNameW", GetLastError()));
    return false;
  }

  std::filesystem::path ini_path(module_path.data());
  ini_path.replace_filename(kIniFileName);
  if (GetFileAttributesW(ini_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
    configuration = {};
    SetLastErrorText(L"Configuration file is absent; enhancement is disabled");
    return true;
  }

  Configuration parsed;
  if (!ParseBoolean(ReadIniValue(ini_path, L"Enabled", L"0"),
                    parsed.enabled)) {
    SetLastErrorText(L"Enabled must be a strict boolean");
    return false;
  }
  if (!parsed.enabled) {
    configuration = parsed;
    SetLastErrorText(L"Enhancement is disabled by configuration");
    return true;
  }

  if (!ParseUnsigned(ReadIniValue(ini_path, L"Width", L""), parsed.width) ||
      !ParseUnsigned(ReadIniValue(ini_path, L"Height", L""), parsed.height)) {
    SetLastErrorText(L"Width and Height must be unsigned decimal integers");
    return false;
  }
  if (!ParseBoolean(
          ReadIniValue(ini_path, L"HorizontalFov", L"0"),
          parsed.horizontal_fov) ||
      !ParseBoolean(
          ReadIniValue(ini_path, L"HudMinimap", L"0"),
          parsed.hud_minimap) ||
      !ParseBoolean(
          ReadIniValue(ini_path, L"AutomaticDeviceRecreation", L"0"),
          parsed.automatic_device_recreation)) {
    SetLastErrorText(L"Feature switches must be strict booleans");
    return false;
  }

  std::wstring window_mode = ReadIniValue(
      ini_path, L"WindowMode", L"Unchanged");
  std::transform(
      window_mode.begin(), window_mode.end(), window_mode.begin(),
      [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
      });
  if (window_mode == L"unchanged") {
    parsed.window_mode = WindowMode::unchanged;
  } else if (window_mode == L"borderless") {
    parsed.window_mode = WindowMode::borderless;
  } else if (window_mode == L"resizable") {
    parsed.window_mode = WindowMode::resizable;
  } else {
    SetLastErrorText(
        L"WindowMode must be Unchanged, Borderless, or Resizable");
    return false;
  }

  std::wstring validation_error;
  if (!ValidateConfiguration(parsed, validation_error)) {
    SetLastErrorText(validation_error);
    return false;
  }
  configuration = parsed;
  return true;
}

[[nodiscard]] bool SetWindowLongChecked(
    HWND window, int index, LONG_PTR value) noexcept {
  SetLastError(ERROR_SUCCESS);
  const LONG_PTR previous = SetWindowLongPtrW(window, index, value);
  return previous != 0 || GetLastError() == ERROR_SUCCESS;
}

void RestoreWindowUnlocked() noexcept {
  if (!g_window_snapshot.active ||
      !IsWindow(g_window_snapshot.window)) {
    g_window_snapshot = {};
    return;
  }

  SetWindowLongPtrW(
      g_window_snapshot.window, GWL_STYLE, g_window_snapshot.style);
  SetWindowLongPtrW(
      g_window_snapshot.window,
      GWL_EXSTYLE,
      g_window_snapshot.extended_style);
  SetWindowPos(
      g_window_snapshot.window,
      nullptr,
      g_window_snapshot.rectangle.left,
      g_window_snapshot.rectangle.top,
      g_window_snapshot.rectangle.right - g_window_snapshot.rectangle.left,
      g_window_snapshot.rectangle.bottom - g_window_snapshot.rectangle.top,
      SWP_FRAMECHANGED | SWP_NOACTIVATE | SWP_NOZORDER |
          SWP_NOOWNERZORDER);
  g_window_snapshot = {};
}

[[nodiscard]] bool ApplyWindowPolicy(HWND window) {
  if (g_configuration.window_mode == WindowMode::unchanged) {
    return true;
  }
  if (window == nullptr) {
    AcquireSRWLockShared(&g_window_lock);
    const bool already_applied = g_window_snapshot.active;
    ReleaseSRWLockShared(&g_window_lock);
    if (already_applied) {
      return true;
    }
  }
  if (window == nullptr || !IsWindow(window)) {
    SetLastErrorText(L"Configured window mode has no valid device window");
    return false;
  }

  AcquireSRWLockExclusive(&g_window_lock);
  if (g_window_snapshot.active) {
    const bool same_window = g_window_snapshot.window == window;
    ReleaseSRWLockExclusive(&g_window_lock);
    if (!same_window) {
      SetLastErrorText(L"A second device window was rejected");
    }
    return same_window;
  }

  WindowSnapshot snapshot;
  snapshot.window = window;
  snapshot.style = GetWindowLongPtrW(window, GWL_STYLE);
  snapshot.extended_style = GetWindowLongPtrW(window, GWL_EXSTYLE);
  if (!GetWindowRect(window, &snapshot.rectangle)) {
    ReleaseSRWLockExclusive(&g_window_lock);
    SetLastErrorText(WindowsError(L"GetWindowRect", GetLastError()));
    return false;
  }
  snapshot.active = true;
  g_window_snapshot = snapshot;

  MONITORINFO monitor_info{};
  monitor_info.cbSize = sizeof(monitor_info);
  const HMONITOR monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
  if (monitor == nullptr || !GetMonitorInfoW(monitor, &monitor_info)) {
    RestoreWindowUnlocked();
    ReleaseSRWLockExclusive(&g_window_lock);
    SetLastErrorText(WindowsError(L"GetMonitorInfoW", GetLastError()));
    return false;
  }

  LONG_PTR style = snapshot.style;
  LONG_PTR extended_style = snapshot.extended_style;
  RECT target{};
  if (g_configuration.window_mode == WindowMode::borderless) {
    style &= ~static_cast<LONG_PTR>(WS_OVERLAPPEDWINDOW);
    style |= WS_POPUP | WS_VISIBLE;
    extended_style &= ~static_cast<LONG_PTR>(
        WS_EX_DLGMODALFRAME | WS_EX_CLIENTEDGE | WS_EX_STATICEDGE |
        WS_EX_WINDOWEDGE);
    target = monitor_info.rcMonitor;
  } else {
    style &= ~static_cast<LONG_PTR>(WS_POPUP);
    style |= WS_OVERLAPPEDWINDOW | WS_VISIBLE;
    const RECT work = monitor_info.rcWork;
    const LONG work_width = work.right - work.left;
    const LONG work_height = work.bottom - work.top;
    const LONG client_width = std::min(
        static_cast<LONG>(g_configuration.width), work_width);
    const LONG client_height = std::min(
        static_cast<LONG>(g_configuration.height), work_height);
    target = {0, 0, client_width, client_height};
    if (!AdjustWindowRectEx(
            &target,
            static_cast<DWORD>(style),
            FALSE,
            static_cast<DWORD>(extended_style))) {
      RestoreWindowUnlocked();
      ReleaseSRWLockExclusive(&g_window_lock);
      SetLastErrorText(WindowsError(L"AdjustWindowRectEx", GetLastError()));
      return false;
    }
    const LONG outer_width = target.right - target.left;
    const LONG outer_height = target.bottom - target.top;
    target.left = work.left + std::max(0L, (work_width - outer_width) / 2L);
    target.top = work.top + std::max(0L, (work_height - outer_height) / 2L);
    target.right = target.left + std::min(outer_width, work_width);
    target.bottom = target.top + std::min(outer_height, work_height);
  }

  if (!SetWindowLongChecked(window, GWL_STYLE, style) ||
      !SetWindowLongChecked(window, GWL_EXSTYLE, extended_style) ||
      !SetWindowPos(
          window,
          nullptr,
          target.left,
          target.top,
          target.right - target.left,
          target.bottom - target.top,
          SWP_FRAMECHANGED | SWP_NOACTIVATE | SWP_NOZORDER |
              SWP_NOOWNERZORDER)) {
    const DWORD error = GetLastError();
    RestoreWindowUnlocked();
    ReleaseSRWLockExclusive(&g_window_lock);
    SetLastErrorText(WindowsError(L"Window style update", error));
    return false;
  }

  ReleaseSRWLockExclusive(&g_window_lock);
  return true;
}

void RestoreWindow() noexcept {
  AcquireSRWLockExclusive(&g_window_lock);
  RestoreWindowUnlocked();
  ReleaseSRWLockExclusive(&g_window_lock);
}

[[nodiscard]] bool PresentationChanged(
    const d3d8::PresentParameters& left,
    const d3d8::PresentParameters& right) noexcept {
  return left.back_buffer_width != right.back_buffer_width ||
         left.back_buffer_height != right.back_buffer_height ||
         left.windowed != right.windowed ||
         left.full_screen_refresh_rate_hz !=
             right.full_screen_refresh_rate_hz;
}

void MarkRuntimeFallback(const std::wstring_view reason) noexcept {
  g_create_device_fallbacks.fetch_add(1, std::memory_order_relaxed);
  g_state.store(RuntimeState::runtime_fallback, std::memory_order_release);
  SetLastErrorText(reason);
}

void* WINAPI HookDirect3DCreate8(const UINT sdk_version) {
  auto* executable = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
  if (executable == nullptr) {
    return nullptr;
  }
  auto** slot = reinterpret_cast<void**>(
      executable + kDirect3DCreate8IatRva);
  const auto original = reinterpret_cast<d3d8::Direct3DCreate8>(
      FindOriginal(slot, reinterpret_cast<void*>(&HookDirect3DCreate8)));
  if (original == nullptr) {
    SetLastErrorText(L"Direct3DCreate8 hook lost its original function");
    return nullptr;
  }

  void* direct3d = original(sdk_version);
  if (direct3d != nullptr &&
      !PatchVtable(
          direct3d,
          d3d8::kDirect3D8CreateDeviceSlot,
          &HookCreateDevice)) {
    SetLastErrorText(L"IDirect3D8::CreateDevice pointer preflight failed");
  }
  return direct3d;
}

HRESULT WINAPI HookCreateDevice(
    void* self,
    const UINT adapter,
    const std::int32_t device_type,
    HWND focus_window,
    const DWORD behavior_flags,
    d3d8::PresentParameters* presentation,
    void** returned_device) {
  const auto original = OriginalFor(
      self, d3d8::kDirect3D8CreateDeviceSlot, &HookCreateDevice);
  if (original == nullptr) {
    SetLastErrorText(L"CreateDevice hook lost its original function");
    return E_FAIL;
  }
  if (presentation == nullptr || returned_device == nullptr) {
    return original(
        self,
        adapter,
        device_type,
        focus_window,
        behavior_flags,
        presentation,
        returned_device);
  }

  g_create_device_attempts.fetch_add(1, std::memory_order_relaxed);
  const d3d8::PresentParameters unchanged = *presentation;
  d3d8::PresentParameters effective =
      ApplyPresentationPolicy(g_configuration, unchanged);
  HRESULT result = original(
      self,
      adapter,
      device_type,
      focus_window,
      behavior_flags,
      &effective,
      returned_device);

  if (FAILED(result) && PresentationChanged(effective, unchanged)) {
    d3d8::PresentParameters fallback = unchanged;
    result = original(
        self,
        adapter,
        device_type,
        focus_window,
        behavior_flags,
        &fallback,
        returned_device);
    if (SUCCEEDED(result)) {
      *presentation = fallback;
      MarkRuntimeFallback(
          L"Configured CreateDevice failed; original parameters succeeded");
    }
    return result;
  }
  if (FAILED(result)) {
    return result;
  }

  *presentation = effective;
  HWND device_window = effective.device_window;
  if (device_window == nullptr) {
    device_window = focus_window;
  }
  [[maybe_unused]] const bool window_applied =
      ApplyWindowPolicy(device_window);

  bool reset_hook = false;
  bool projection_hook = false;
  if (*returned_device != nullptr) {
    reset_hook = PatchVtable(
        *returned_device, d3d8::kDeviceResetSlot, &HookReset);
    if (g_configuration.horizontal_fov) {
      projection_hook = PatchVtable(
          *returned_device,
          d3d8::kDeviceSetTransformSlot,
          &HookSetTransform);
    }
  }

  std::uint32_t flags = g_flags.load(std::memory_order_acquire);
  if (reset_hook) {
    flags |= capability_game_initiated_reset_hook;
  }
  if (projection_hook) {
    flags |= capability_horizontal_fov_hook;
  }
  g_flags.store(flags, std::memory_order_release);
  g_state.store(RuntimeState::active, std::memory_order_release);
  return result;
}

HRESULT WINAPI HookReset(
    void* self, d3d8::PresentParameters* presentation) {
  const auto original =
      OriginalFor(self, d3d8::kDeviceResetSlot, &HookReset);
  if (original == nullptr) {
    SetLastErrorText(L"Reset hook lost its original function");
    return E_FAIL;
  }
  if (presentation == nullptr) {
    return original(self, presentation);
  }

  const d3d8::PresentParameters unchanged = *presentation;
  d3d8::PresentParameters effective =
      ApplyPresentationPolicy(g_configuration, unchanged);
  HRESULT result = original(self, &effective);
  if (FAILED(result) && PresentationChanged(effective, unchanged)) {
    d3d8::PresentParameters fallback = unchanged;
    result = original(self, &fallback);
    if (SUCCEEDED(result)) {
      *presentation = fallback;
      RestoreWindow();
      MarkRuntimeFallback(
          L"Configured Reset failed; original parameters succeeded");
    }
    return result;
  }
  if (SUCCEEDED(result)) {
    *presentation = effective;
    [[maybe_unused]] const bool window_applied =
        ApplyWindowPolicy(effective.device_window);
  }
  return result;
}

HRESULT WINAPI HookSetTransform(
    void* self, const DWORD state, const d3d8::Matrix* matrix) {
  const auto original = OriginalFor(
      self, d3d8::kDeviceSetTransformSlot, &HookSetTransform);
  if (original == nullptr) {
    SetLastErrorText(L"SetTransform hook lost its original function");
    return E_FAIL;
  }
  if (state != d3d8::kTransformStateProjection || matrix == nullptr) {
    return original(self, state, matrix);
  }

  g_projection_calls_seen.fetch_add(1, std::memory_order_relaxed);
  d3d8::Matrix adjusted{};
  if (!AdjustHorizontalFov(g_configuration, *matrix, adjusted)) {
    return original(self, state, matrix);
  }

  g_projection_calls_adjusted.fetch_add(1, std::memory_order_relaxed);
  const HRESULT result = original(self, state, &adjusted);
  if (FAILED(result)) {
    SetLastErrorText(
        L"Adjusted projection was rejected; original matrix retried");
    return original(self, state, matrix);
  }
  return result;
}

[[nodiscard]] bool InitializeImplementation() {
  g_state.store(RuntimeState::initializing, std::memory_order_release);
  Configuration configuration;
  if (!LoadConfiguration(configuration)) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  g_configuration = configuration;
  g_width.store(configuration.width, std::memory_order_release);
  g_height.store(configuration.height, std::memory_order_release);
  if (!configuration.enabled) {
    g_state.store(
        RuntimeState::disabled_by_config, std::memory_order_release);
    return true;
  }

  auto* executable = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
  if (executable == nullptr ||
      reinterpret_cast<std::uintptr_t>(executable) != kPinnedImageBase) {
    SetLastErrorText(L"Loaded executable base does not match 0x00400000");
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  std::array<wchar_t, 32768> executable_path{};
  const DWORD path_length = GetModuleFileNameW(
      nullptr,
      executable_path.data(),
      static_cast<DWORD>(executable_path.size()));
  if (path_length == 0 || path_length >= executable_path.size()) {
    SetLastErrorText(WindowsError(L"GetModuleFileNameW", GetLastError()));
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  const ImageVerification file_verification =
      VerifyPinnedExecutable(executable_path.data());
  if (!file_verification.passed()) {
    SetLastErrorText(file_verification.failure);
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  g_flags.fetch_or(
      capability_base_hash_matched, std::memory_order_release);

  std::wstring loaded_failure;
  if (!VerifyLoadedImage(
          std::span<const std::byte>(executable, kPinnedImageSize),
          loaded_failure)) {
    SetLastErrorText(loaded_failure);
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  g_flags.fetch_or(
      capability_expected_bytes_matched, std::memory_order_release);

  HMODULE pinned_module = nullptr;
  if (!GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_PIN,
          reinterpret_cast<LPCWSTR>(g_module),
          &pinned_module)) {
    SetLastErrorText(WindowsError(L"GetModuleHandleExW(PIN)", GetLastError()));
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  HMODULE d3d8_module = GetModuleHandleW(L"d3d8.dll");
  FARPROC direct3d_create8 =
      d3d8_module == nullptr
          ? nullptr
          : GetProcAddress(d3d8_module, "Direct3DCreate8");
  auto** iat_slot = reinterpret_cast<void**>(
      executable + kDirect3DCreate8IatRva);
  void* expected = reinterpret_cast<void*>(direct3d_create8);
  if (expected == nullptr || *iat_slot != expected) {
    SetLastErrorText(
        L"Direct3DCreate8 IAT expected-pointer preflight failed");
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  if (!InstallPointerPatch(
          iat_slot,
          expected,
          reinterpret_cast<void*>(&HookDirect3DCreate8))) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  std::uint32_t flags =
      capability_direct3d_iat_hook |
      capability_resolution_2560x1600 |
      capability_resolution_3840x2400 |
      capability_borderless_window |
      capability_resizable_window;
  flags |= g_flags.load(std::memory_order_acquire);
  g_flags.store(flags, std::memory_order_release);
  g_state.store(RuntimeState::armed, std::memory_order_release);
  SetLastErrorText(L"Pinned preflight passed; Direct3D hook is armed");
  return true;
}

BOOL CALLBACK InitializeOnceCallback(
    PINIT_ONCE, PVOID, PVOID*) noexcept {
  bool initialized = false;
  try {
    initialized = InitializeImplementation();
  } catch (...) {
    SetLastErrorText(L"Unhandled exception during enhancement initialization");
    g_state.store(RuntimeState::rejected, std::memory_order_release);
  }
  g_initialize_result.store(initialized, std::memory_order_release);
  return TRUE;
}

}  // namespace

void SetEnhancementModule(HMODULE module) noexcept {
  g_module = module;
}

DWORD WINAPI EnhancementInitializationThread(void*) noexcept {
  PSOBBEnhancement_Initialize();
  return 0;
}

}  // namespace psobb::enhancement

BOOL WINAPI PSOBBEnhancement_Initialize() {
  if (!InitOnceExecuteOnce(
          &psobb::enhancement::g_initialize_once,
          psobb::enhancement::InitializeOnceCallback,
          nullptr,
          nullptr)) {
    return FALSE;
  }
  return psobb::enhancement::g_initialize_result.load(
             std::memory_order_acquire)
             ? TRUE
             : FALSE;
}

BOOL WINAPI PSOBBEnhancement_GetCapabilities(
    psobb::enhancement::CapabilitiesV1* capabilities) {
  using namespace psobb::enhancement;
  if (capabilities == nullptr ||
      capabilities->struct_size < sizeof(CapabilitiesV1)) {
    return FALSE;
  }

  CapabilitiesV1 snapshot{};
  snapshot.struct_size = sizeof(snapshot);
  snapshot.abi_version = kCapabilityAbiVersion;
  snapshot.state = g_state.load(std::memory_order_acquire);
  snapshot.flags = g_flags.load(std::memory_order_acquire);
  snapshot.configured_width = g_width.load(std::memory_order_acquire);
  snapshot.configured_height = g_height.load(std::memory_order_acquire);
  snapshot.create_device_attempts =
      g_create_device_attempts.load(std::memory_order_acquire);
  snapshot.create_device_fallbacks =
      g_create_device_fallbacks.load(std::memory_order_acquire);
  snapshot.projection_calls_seen =
      g_projection_calls_seen.load(std::memory_order_acquire);
  snapshot.projection_calls_adjusted =
      g_projection_calls_adjusted.load(std::memory_order_acquire);
  wcsncpy_s(snapshot.version, kVersion, _TRUNCATE);

  AcquireSRWLockShared(&g_status_lock);
  wcsncpy_s(snapshot.last_error, g_last_error.data(), _TRUNCATE);
  ReleaseSRWLockShared(&g_status_lock);

  *capabilities = snapshot;
  return TRUE;
}

BOOL WINAPI PSOBBEnhancement_Rollback() {
  using namespace psobb::enhancement;
  const bool hooks_restored = RollbackPointerPatches();
  RestoreWindow();
  if (!hooks_restored) {
    SetLastErrorText(
        L"Rollback found a pointer ownership conflict; relaunch is required");
    return FALSE;
  }

  const std::uint32_t retained =
      g_flags.load(std::memory_order_acquire) &
      (capability_base_hash_matched | capability_expected_bytes_matched |
       capability_resolution_2560x1600 |
       capability_resolution_3840x2400);
  g_flags.store(retained, std::memory_order_release);
  g_state.store(RuntimeState::rolled_back, std::memory_order_release);
  SetLastErrorText(
      L"Hooks and window style restored; relaunch restores the existing device");
  return TRUE;
}

const wchar_t* WINAPI PSOBBEnhancement_GetVersion() {
  return psobb::enhancement::kVersion;
}
