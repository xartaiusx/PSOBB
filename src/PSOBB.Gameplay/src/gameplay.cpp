#include "gameplay_internal.h"

#include "psobb_client_safety/exact_image.h"
#include "psobb_gameplay/api.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psobb::gameplay {
namespace {

constexpr wchar_t kIniSection[] = L"Gameplay";
constexpr wchar_t kIniFileName[] = L"PSOBB.Gameplay.ini";

HMODULE g_module = nullptr;
INIT_ONCE g_initialize_once = INIT_ONCE_STATIC_INIT;
std::atomic_bool g_initialize_result{false};
std::atomic<RuntimeState> g_state{RuntimeState::cold};
std::atomic_uint32_t g_verification_flags{verification_none};
std::atomic_uint64_t g_accepted_feature_bits{feature_none};
SRWLOCK g_status_lock = SRWLOCK_INIT;
std::array<wchar_t, 256> g_last_reason{};

void SetLastReason(const std::wstring_view message) noexcept {
  std::array<wchar_t, 256> local{};
  const std::size_t count =
      std::min(message.size(), local.size() - 1U);
  if (count != 0U) {
    std::wmemcpy(local.data(), message.data(), count);
  }
  local[count] = L'\0';

  AcquireSRWLockExclusive(&g_status_lock);
  g_last_reason = local;
  ReleaseSRWLockExclusive(&g_status_lock);

  OutputDebugStringW(L"[PSOBB.Gameplay] ");
  OutputDebugStringW(local.data());
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
    SetLastReason(L"Gameplay module handle is unavailable");
    return false;
  }

  std::vector<wchar_t> module_path(32768U);
  const DWORD length = GetModuleFileNameW(
      g_module,
      module_path.data(),
      static_cast<DWORD>(module_path.size()));
  if (length == 0 || length >= module_path.size()) {
    SetLastReason(WindowsError(L"GetModuleFileNameW", GetLastError()));
    return false;
  }

  std::filesystem::path ini_path(module_path.data());
  ini_path.replace_filename(kIniFileName);
  const DWORD attributes = GetFileAttributesW(ini_path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      SetLastReason(
          L"PSOBB.Gameplay.ini is absent; module remains disabled");
      return true;
    }
    SetLastReason(WindowsError(L"GetFileAttributesW", error));
    return false;
  }
  if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
    SetLastReason(L"PSOBB.Gameplay.ini resolves to a directory");
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
    SetLastReason(
        L"Enabled=1 is not explicitly set; module remains disabled");
    return true;
  }

  SetLastReason(L"Enabled must be exactly 0 or 1");
  return false;
}

[[nodiscard]] bool VerifyExactClient() {
  using namespace psobb::client_safety;
  auto* executable = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
  if (executable == nullptr ||
      reinterpret_cast<std::uintptr_t>(executable) !=
          k59NlIdentity.image_base) {
    SetLastReason(L"Loaded executable base does not match the exact client");
    return false;
  }

  std::vector<wchar_t> executable_path(32768U);
  const DWORD path_length = GetModuleFileNameW(
      nullptr,
      executable_path.data(),
      static_cast<DWORD>(executable_path.size()));
  if (path_length == 0 || path_length >= executable_path.size()) {
    SetLastReason(WindowsError(L"GetModuleFileNameW", GetLastError()));
    return false;
  }

  const ImageVerification file =
      VerifyExecutable(executable_path.data(), k59NlIdentity);
  if (!file.passed()) {
    SetLastReason(file.failure);
    return false;
  }
  g_verification_flags.fetch_or(
      verification_file_hash_matched, std::memory_order_release);

  std::wstring loaded_failure;
  if (!VerifyLoadedImage(
          std::span<const std::byte>(executable, k59NlIdentity.image_size),
          k59NlIdentity,
          {},
          loaded_failure)) {
    SetLastReason(loaded_failure);
    return false;
  }
  g_verification_flags.fetch_or(
      verification_loaded_pe_contract_matched, std::memory_order_release);
  return true;
}

[[nodiscard]] bool InitializeImplementation() {
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

  if (!VerifyExactClient()) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  g_accepted_feature_bits.store(feature_none, std::memory_order_release);
  g_state.store(RuntimeState::exact_client_ready, std::memory_order_release);
  SetLastReason(
      L"Exact client accepted; observation shell is ready with no hook installed");
  return true;
}

BOOL CALLBACK InitializeOnceCallback(
    PINIT_ONCE,
    PVOID,
    PVOID*) noexcept {
  bool initialized = false;
  try {
    initialized = InitializeImplementation();
  } catch (...) {
    SetLastReason(L"Unhandled exception during gameplay initialization");
    g_state.store(RuntimeState::rejected, std::memory_order_release);
  }
  g_initialize_result.store(initialized, std::memory_order_release);
  return TRUE;
}

}  // namespace

void SetGameplayModule(const HMODULE module) noexcept {
  g_module = module;
}

}  // namespace psobb::gameplay

extern "C" void InitializeASI() noexcept {
  static_cast<void>(PSOBBGameplay_Initialize());
}

BOOL WINAPI PSOBBGameplay_Initialize() {
  if (!InitOnceExecuteOnce(
          &psobb::gameplay::g_initialize_once,
          psobb::gameplay::InitializeOnceCallback,
          nullptr,
          nullptr)) {
    return FALSE;
  }
  return psobb::gameplay::g_initialize_result.load(
             std::memory_order_acquire)
             ? TRUE
             : FALSE;
}

BOOL WINAPI PSOBBGameplay_GetCapabilities(
    psobb::gameplay::GameplayCapabilitiesV1* capabilities) {
  using namespace psobb::gameplay;
  if (capabilities == nullptr ||
      capabilities->struct_size < sizeof(GameplayCapabilitiesV1)) {
    return FALSE;
  }

  GameplayCapabilitiesV1 snapshot{};
  snapshot.struct_size = sizeof(snapshot);
  snapshot.abi_version = kCapabilityAbiVersion;
  snapshot.state = g_state.load(std::memory_order_acquire);
  snapshot.verification_flags =
      g_verification_flags.load(std::memory_order_acquire);
  snapshot.accepted_feature_bits =
      g_accepted_feature_bits.load(std::memory_order_acquire);
  snapshot.active_page = kNoActivePage;
  snapshot.display_slot_count = kDisplaySlotCount;
  constexpr std::uint32_t kAcceptedClientVerification =
      verification_file_hash_matched |
      verification_loaded_pe_contract_matched;
  if ((snapshot.verification_flags & kAcceptedClientVerification) ==
      kAcceptedClientVerification) {
    wcsncpy_s(
        snapshot.client_sha256,
        psobb::client_safety::k59NlSha256,
        _TRUNCATE);
  }
  wcsncpy_s(snapshot.version, kVersion, _TRUNCATE);

  AcquireSRWLockShared(&g_status_lock);
  wcsncpy_s(
      snapshot.last_fail_closed_reason, g_last_reason.data(), _TRUNCATE);
  ReleaseSRWLockShared(&g_status_lock);
  *capabilities = snapshot;
  return TRUE;
}

BOOL WINAPI PSOBBGameplay_Rollback() {
  using namespace psobb::gameplay;
  // Complete one-time preflight before publishing the final no-write state.
  // A rejected preflight is still complete and requires no restoration.
  static_cast<void>(PSOBBGameplay_Initialize());
  g_accepted_feature_bits.store(feature_none, std::memory_order_release);
  g_state.store(RuntimeState::rolled_back, std::memory_order_release);
  SetLastReason(L"No gameplay hook or write exists; rollback is complete");
  return TRUE;
}

const wchar_t* WINAPI PSOBBGameplay_GetVersion() {
  return psobb::gameplay::kVersion;
}
