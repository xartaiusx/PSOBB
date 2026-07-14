#include "runtime_internal.h"

#include "psobb_large_assets/api.h"
#include "psobb_large_assets/patch_plan.h"
#include "psobb_large_assets/pinned_image.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace psobb::large_assets {
namespace {

constexpr wchar_t kIniSection[] = L"LargeAssets";
constexpr wchar_t kIniFileName[] = L"PSOBB.LargeAssets.ini";

HMODULE g_module = nullptr;
INIT_ONCE g_initialize_once = INIT_ONCE_STATIC_INIT;
SRWLOCK g_runtime_lock = SRWLOCK_INIT;
SRWLOCK g_status_lock = SRWLOCK_INIT;

std::atomic_bool g_initialize_result{false};
std::atomic_bool g_initialization_in_progress{false};
std::atomic<RuntimeState> g_state{RuntimeState::cold};
std::atomic_uint32_t g_flags{capability_none};
std::atomic_uint32_t g_patched_sites{0};
std::atomic_uint32_t g_rolled_back_sites{0};
std::array<wchar_t, 256> g_last_error{};

class ExclusiveSrwLock final {
 public:
  explicit ExclusiveSrwLock(SRWLOCK& lock) noexcept : lock_(lock) {
    AcquireSRWLockExclusive(&lock_);
  }
  ExclusiveSrwLock(const ExclusiveSrwLock&) = delete;
  ExclusiveSrwLock& operator=(const ExclusiveSrwLock&) = delete;
  ~ExclusiveSrwLock() { ReleaseSRWLockExclusive(&lock_); }

 private:
  SRWLOCK& lock_;
};

void SetLastErrorText(const std::wstring_view message) noexcept {
  AcquireSRWLockExclusive(&g_status_lock);
  const std::size_t count =
      std::min(message.size(), g_last_error.size() - 1U);
  std::wmemcpy(g_last_error.data(), message.data(), count);
  g_last_error[count] = L'\0';
  ReleaseSRWLockExclusive(&g_status_lock);

  OutputDebugStringW(L"[PSOBB.LargeAssets] ");
  OutputDebugStringW(g_last_error.data());
  OutputDebugStringW(L"\n");
}

[[nodiscard]] std::wstring WindowsError(
    const std::wstring_view operation,
    const DWORD error) {
  std::wstring message(operation);
  message.append(L" failed with Windows error ");
  message.append(std::to_wstring(error));
  return message;
}

[[nodiscard]] bool ReadEnabledConfiguration(bool& enabled) {
  enabled = false;
  if (g_module == nullptr) {
    SetLastErrorText(L"Large-assets module handle is unavailable");
    return false;
  }

  std::array<wchar_t, 32768> module_path{};
  const DWORD length = GetModuleFileNameW(
      g_module,
      module_path.data(),
      static_cast<DWORD>(module_path.size()));
  if (length == 0 || length >= module_path.size()) {
    SetLastErrorText(WindowsError(L"GetModuleFileNameW", GetLastError()));
    return false;
  }

  std::filesystem::path ini_path(module_path.data());
  ini_path.replace_filename(kIniFileName);
  const DWORD attributes = GetFileAttributesW(ini_path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    SetLastErrorText(
        L"PSOBB.LargeAssets.ini is absent; patch remains disabled");
    return true;
  }
  if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
    SetLastErrorText(L"PSOBB.LargeAssets.ini resolves to a directory");
    return false;
  }

  std::array<wchar_t, 32> value{};
  GetPrivateProfileStringW(
      kIniSection,
      L"Enabled",
      L"",
      value.data(),
      static_cast<DWORD>(value.size()),
      ini_path.c_str());
  if (std::wcscmp(value.data(), L"1") == 0) {
    enabled = true;
    return true;
  }
  if (value[0] == L'\0' || std::wcscmp(value.data(), L"0") == 0) {
    SetLastErrorText(
        L"Enabled=1 is not explicitly set; patch remains disabled");
    return true;
  }

  SetLastErrorText(L"Enabled must be exactly 0 or 1");
  return false;
}

[[nodiscard]] bool IsExecutableProtection(const DWORD protection) noexcept {
  const DWORD base = protection & 0xFFU;
  return base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
         base == PAGE_EXECUTE_READWRITE ||
         base == PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] bool ValidateRuntimeAddress(
    const std::uintptr_t address,
    MEMORY_BASIC_INFORMATION& information) noexcept {
  if (address < kPinnedImageBase ||
      address + sizeof(std::uint32_t) < address ||
      address + sizeof(std::uint32_t) >
          kPinnedImageBase + kPinnedImageSize ||
      VirtualQuery(
          reinterpret_cast<const void*>(address),
          &information,
          sizeof(information)) != sizeof(information)) {
    return false;
  }

  return information.State == MEM_COMMIT &&
         information.Type == MEM_IMAGE &&
         information.AllocationBase ==
             reinterpret_cast<const void*>(kPinnedImageBase) &&
         IsExecutableProtection(information.Protect) &&
         (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0U;
}

[[nodiscard]] bool RuntimeRead(
    void*,
    const std::uintptr_t address,
    std::uint32_t& value) noexcept {
  MEMORY_BASIC_INFORMATION information{};
  if (!ValidateRuntimeAddress(address, information)) {
    return false;
  }
  std::memcpy(
      &value,
      reinterpret_cast<const void*>(address),
      sizeof(value));
  return true;
}

[[nodiscard]] bool RuntimeCompareWrite(
    void*,
    const std::uintptr_t address,
    const std::uint32_t expected,
    const std::uint32_t replacement,
    bool& modified) noexcept {
  modified = false;
  MEMORY_BASIC_INFORMATION information{};
  std::uint32_t observed = 0;
  if (!ValidateRuntimeAddress(address, information) ||
      !RuntimeRead(nullptr, address, observed) || observed != expected) {
    return false;
  }

  DWORD original_protection = 0;
  auto* target = reinterpret_cast<void*>(address);
  if (!VirtualProtect(
          target,
          sizeof(replacement),
          PAGE_EXECUTE_READWRITE,
          &original_protection)) {
    return false;
  }

  std::uint32_t after_protect = 0;
  if (!RuntimeRead(nullptr, address, after_protect) ||
      after_protect != expected) {
    DWORD ignored = 0;
    VirtualProtect(
        target, sizeof(replacement), original_protection, &ignored);
    return false;
  }

  std::memcpy(target, &replacement, sizeof(replacement));
  modified = true;
  FlushInstructionCache(
      GetCurrentProcess(), target, sizeof(replacement));

  std::uint32_t written = 0;
  const bool write_verified =
      RuntimeRead(nullptr, address, written) && written == replacement;
  DWORD ignored = 0;
  const bool protection_restored =
      VirtualProtect(
          target, sizeof(replacement), original_protection, &ignored) !=
      FALSE;
  if (write_verified && protection_restored) {
    return true;
  }

  // The page is still expected to be writable if protection restoration
  // failed. Restore the original immediate before returning a failed write.
  if (!protection_restored) {
    std::memcpy(target, &expected, sizeof(expected));
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(expected));
    modified = false;
    VirtualProtect(
        target, sizeof(expected), original_protection, &ignored);
  }
  return false;
}

inline constexpr MemoryOperations kRuntimeMemory{
    nullptr, &RuntimeRead, &RuntimeCompareWrite};

[[nodiscard]] std::uint32_t CountPatchedSites() noexcept {
  std::uint32_t count = 0;
  for (const auto& site : kPatchSites) {
    std::uint32_t observed = 0;
    if (RuntimeRead(nullptr, site.virtual_address, observed) &&
        observed == kLargeAssetLimit) {
      ++count;
    }
  }
  return count;
}

[[nodiscard]] bool RollbackUnlocked() noexcept {
  const TransactionResult result =
      RollbackPatchTransaction(kRuntimeMemory);
  g_patched_sites.store(CountPatchedSites(), std::memory_order_release);
  g_rolled_back_sites.fetch_add(
      result.rolled_back_count, std::memory_order_release);
  return result.passed &&
         g_patched_sites.load(std::memory_order_acquire) == 0U;
}

[[nodiscard]] bool InitializeImplementation() {
  ExclusiveSrwLock runtime_lock(g_runtime_lock);
  g_state.store(RuntimeState::initializing, std::memory_order_release);

  bool enabled = false;
  if (!ReadEnabledConfiguration(enabled)) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  if (!enabled) {
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

  const ImageVerification file =
      VerifyPinnedExecutable(executable_path.data());
  if (!file.passed()) {
    SetLastErrorText(file.failure);
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  g_flags.fetch_or(
      capability_file_hash_matched, std::memory_order_release);

  std::wstring loaded_failure;
  if (!VerifyLoadedImage(
          std::span<const std::byte>(executable, kPinnedImageSize),
          loaded_failure)) {
    SetLastErrorText(loaded_failure);
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  g_flags.fetch_or(
      capability_loaded_pe_matched |
          capability_expected_bytes_matched |
          capability_transactional_apply,
      std::memory_order_release);

  g_state.store(RuntimeState::applying, std::memory_order_release);
  const TransactionResult transaction =
      ApplyPatchTransaction(kRuntimeMemory);
  const std::uint32_t still_patched = CountPatchedSites();
  g_patched_sites.store(still_patched, std::memory_order_release);
  g_rolled_back_sites.fetch_add(
      transaction.rolled_back_count, std::memory_order_release);
  if (!transaction.passed) {
    if (!transaction.rollback_complete || still_patched != 0U) {
      SetLastErrorText(
          L"Patch transaction failed and rollback was incomplete");
      g_state.store(RuntimeState::rollback_failed, std::memory_order_release);
    } else {
      SetLastErrorText(
          L"Patch transaction failed closed; original bytes were restored");
      g_state.store(RuntimeState::rejected, std::memory_order_release);
    }
    return false;
  }

  g_flags.fetch_or(
      capability_rollback_available, std::memory_order_release);
  g_state.store(RuntimeState::active, std::memory_order_release);
  SetLastErrorText(
      L"Pinned preflight passed; 17 large-asset limits are active");
  return true;
}

BOOL CALLBACK InitializeOnceCallback(
    PINIT_ONCE,
    PVOID,
    PVOID*) noexcept {
  g_initialization_in_progress.store(true, std::memory_order_release);
  bool initialized = false;
  try {
    initialized = InitializeImplementation();
  } catch (...) {
    SetLastErrorText(
        L"Unhandled exception during large-assets initialization");
    g_state.store(RuntimeState::rejected, std::memory_order_release);
  }
  g_initialize_result.store(initialized, std::memory_order_release);
  g_initialization_in_progress.store(false, std::memory_order_release);
  return TRUE;
}

DWORD WINAPI InitializationThread(void* context) noexcept {
  PSOBBLargeAssets_Initialize();
  FreeLibraryAndExitThread(static_cast<HMODULE>(context), 0);
}

}  // namespace

void SetLargeAssetsModule(const HMODULE module) noexcept {
  g_module = module;
}

void StartInitializationThread() noexcept {
  HMODULE retained_module = nullptr;
  if (g_module == nullptr ||
      !GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
          reinterpret_cast<LPCWSTR>(g_module),
          &retained_module)) {
    return;
  }
  HANDLE thread = CreateThread(
      nullptr, 0, InitializationThread, retained_module, 0, nullptr);
  if (thread != nullptr) {
    CloseHandle(thread);
  } else {
    FreeLibrary(retained_module);
  }
}

void RollbackForProcessDetach() noexcept {
  if (g_initialization_in_progress.load(std::memory_order_acquire) ||
      g_patched_sites.load(std::memory_order_acquire) == 0U ||
      !TryAcquireSRWLockExclusive(&g_runtime_lock)) {
    return;
  }
  const bool restored = RollbackUnlocked();
  g_state.store(
      restored ? RuntimeState::rolled_back : RuntimeState::rollback_failed,
      std::memory_order_release);
  ReleaseSRWLockExclusive(&g_runtime_lock);
}

}  // namespace psobb::large_assets

BOOL WINAPI PSOBBLargeAssets_Initialize() {
  if (!InitOnceExecuteOnce(
          &psobb::large_assets::g_initialize_once,
          psobb::large_assets::InitializeOnceCallback,
          nullptr,
          nullptr)) {
    return FALSE;
  }
  return psobb::large_assets::g_initialize_result.load(
             std::memory_order_acquire)
             ? TRUE
             : FALSE;
}

BOOL WINAPI PSOBBLargeAssets_GetCapabilities(
    psobb::large_assets::CapabilitiesV1* capabilities) {
  using namespace psobb::large_assets;
  if (capabilities == nullptr ||
      capabilities->struct_size < sizeof(CapabilitiesV1)) {
    return FALSE;
  }

  CapabilitiesV1 snapshot{};
  snapshot.struct_size = sizeof(snapshot);
  snapshot.abi_version = kCapabilityAbiVersion;
  snapshot.state = g_state.load(std::memory_order_acquire);
  snapshot.flags = g_flags.load(std::memory_order_acquire);
  snapshot.patch_value = kLargeAssetLimit;
  snapshot.upstream_address_entries = kUpstreamAddressEntryCount;
  snapshot.unique_patch_sites = static_cast<std::uint32_t>(kPatchSites.size());
  snapshot.patched_sites =
      g_patched_sites.load(std::memory_order_acquire);
  snapshot.rolled_back_sites =
      g_rolled_back_sites.load(std::memory_order_acquire);
  wcsncpy_s(snapshot.version, kVersion, _TRUNCATE);

  AcquireSRWLockShared(&g_status_lock);
  wcsncpy_s(snapshot.last_error, g_last_error.data(), _TRUNCATE);
  ReleaseSRWLockShared(&g_status_lock);
  *capabilities = snapshot;
  return TRUE;
}

BOOL WINAPI PSOBBLargeAssets_Rollback() {
  using namespace psobb::large_assets;
  // Join an in-flight automatic initialization before deciding whether there
  // is anything to restore. A failed initialization may still need a retry of
  // a partial rollback, so its return value is intentionally not a gate here.
  PSOBBLargeAssets_Initialize();
  AcquireSRWLockExclusive(&g_runtime_lock);
  const std::uint32_t patched =
      g_patched_sites.load(std::memory_order_acquire);
  if (patched == 0U) {
    ReleaseSRWLockExclusive(&g_runtime_lock);
    return TRUE;
  }

  const bool restored = RollbackUnlocked();
  if (restored) {
    g_state.store(RuntimeState::rolled_back, std::memory_order_release);
    SetLastErrorText(L"All 17 large-asset limits were restored");
  } else {
    g_state.store(RuntimeState::rollback_failed, std::memory_order_release);
    SetLastErrorText(
        L"Rollback found an ownership conflict; relaunch is required");
  }
  ReleaseSRWLockExclusive(&g_runtime_lock);
  return restored ? TRUE : FALSE;
}

const wchar_t* WINAPI PSOBBLargeAssets_GetVersion() {
  return psobb::large_assets::kVersion;
}
