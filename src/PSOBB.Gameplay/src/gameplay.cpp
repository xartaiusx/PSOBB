#include "gameplay_internal.h"
#include "observation_evidence_session.h"
#include "observation_ring.h"
#include "send60_probe.h"

#include "psobb_client_safety/exact_image.h"
#include "psobb_client_safety/relative_call_hook.h"
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

extern "C" void* __cdecl PSOBBGameplay_ObserveSend60Copy(
    void* destination,
    const void* source,
    std::size_t length) noexcept;

namespace psobb::gameplay {
namespace {

constexpr wchar_t kIniSection[] = L"Gameplay";
constexpr wchar_t kIniFileName[] = L"PSOBB.Gameplay.ini";
constexpr wchar_t kObservationEvidenceRunIdEnvironment[] =
    L"PSOBB_GAMEPLAY_OBSERVATION_RUN_ID";
constexpr std::uint32_t kObservationSiteRva = 0x003D3F9CU;
constexpr std::uint32_t kObservationSiteSize = 11U;
constexpr wchar_t kObservationSiteSha256[] =
    L"3847A37EC7DD127540DD2317594754B86134CD1D9D3C4E68668C36D6194B24FC";
constexpr std::uintptr_t kSend60CopyCallAddress = 0x007D3F9FU;
constexpr std::uintptr_t kOriginalCopyAddress = 0x0086B6B8U;
constexpr psobb::client_safety::HookPatchOwner kObservationHookOwner{
    0x50534F42424F4253ULL};

static_assert(sizeof(void*) == 4U);
static_assert(std::atomic<bool>::is_always_lock_free);
static_assert(std::atomic<std::uint32_t>::is_always_lock_free);

struct GameplayConfiguration {
  bool enabled = false;
  bool observation = false;
};

[[nodiscard]] std::uint32_t CurrentGameplayThreadId() noexcept {
  return static_cast<std::uint32_t>(GetCurrentThreadId());
}

HMODULE g_module = nullptr;
INIT_ONCE g_initialize_once = INIT_ONCE_STATIC_INIT;
std::atomic_bool g_initialize_result{false};
std::atomic<RuntimeState> g_state{RuntimeState::cold};
std::atomic_uint32_t g_verification_flags{verification_none};
std::atomic_uint64_t g_accepted_feature_bits{feature_none};
std::atomic_bool g_observation_publication_enabled{false};
std::atomic_uint32_t g_active_observation_callbacks{0U};
std::atomic_flag g_rollback_active = ATOMIC_FLAG_INIT;
ObservationRing g_observations{CurrentGameplayThreadId};
ObservationEvidenceSession g_observation_evidence{};
SRWLOCK g_status_lock = SRWLOCK_INIT;
std::array<wchar_t, 256> g_last_reason{};

class RollbackCallGuard final {
 public:
  explicit RollbackCallGuard(std::atomic_flag& active) noexcept
      : active_(active), acquired_(!active_.test_and_set()) {}

  ~RollbackCallGuard() noexcept {
    if (acquired_) {
      active_.clear();
    }
  }

  RollbackCallGuard(const RollbackCallGuard&) = delete;
  RollbackCallGuard& operator=(const RollbackCallGuard&) = delete;

  [[nodiscard]] bool acquired() const noexcept { return acquired_; }

 private:
  std::atomic_flag& active_;
  bool acquired_;
};

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

void HandleObservationEvidenceFailure(
    const ObservationEvidenceFailure) noexcept {
  g_observation_publication_enabled.store(false, std::memory_order_release);
  g_accepted_feature_bits.store(feature_none, std::memory_order_release);
  SetLastReason(L"Bounded observation evidence worker failed closed");
  g_state.store(RuntimeState::rejected, std::memory_order_release);
}

[[nodiscard]] std::wstring WindowsError(
    const std::wstring_view operation,
    const DWORD error) {
  std::wstring message(operation);
  message.append(L" failed with Windows error ");
  message.append(std::to_wstring(error));
  return message;
}

[[nodiscard]] bool ReadConfiguration(
    GameplayConfiguration& configuration) {
  configuration = {};
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
    configuration.enabled = true;
  } else if (value[0] == L'\0' ||
             std::wcscmp(value.data(), L"0") == 0) {
    SetLastReason(
        L"Enabled=1 is not explicitly set; module remains disabled");
    return true;
  } else {
    SetLastReason(L"Enabled must be exactly 0 or 1");
    return false;
  }

  value.fill(L'\0');
  GetPrivateProfileStringW(
      kIniSection,
      L"Observation",
      L"0",
      value.data(),
      static_cast<DWORD>(value.size()),
      ini_path.c_str());
  if (std::wcscmp(value.data(), L"1") == 0) {
    configuration.observation = true;
    return true;
  }
  if (std::wcscmp(value.data(), L"0") == 0) {
    return true;
  }
  SetLastReason(L"Observation must be exactly 0 or 1");
  return false;
}

[[nodiscard]] bool ReadObservationEvidenceRequest(
    bool& requested,
    std::wstring& run_id) {
  requested = false;
  run_id.clear();
  std::array<wchar_t, 64U> value{};
  SetLastError(ERROR_SUCCESS);
  const DWORD length = GetEnvironmentVariableW(
      kObservationEvidenceRunIdEnvironment,
      value.data(),
      static_cast<DWORD>(value.size()));
  if (length == 0U) {
    const DWORD error = GetLastError();
    if (error == ERROR_SUCCESS || error == ERROR_ENVVAR_NOT_FOUND) {
      return true;
    }
    SetLastReason(WindowsError(L"GetEnvironmentVariableW", error));
    return false;
  }
  if (length >= value.size()) {
    SetLastReason(L"Observation evidence run ID exceeds its fixed bound");
    return false;
  }
  run_id.assign(value.data(), length);
  if (!ObservationEvidenceSession::IsValidRunId(run_id)) {
    SetLastReason(L"Observation evidence run ID is not canonical");
    return false;
  }
  requested = true;
  return true;
}

[[nodiscard]] bool GetGameplayModulePath(std::wstring& module_path) {
  if (g_module == nullptr) {
    SetLastReason(L"Gameplay module handle is unavailable");
    return false;
  }
  std::vector<wchar_t> value(32'768U);
  const DWORD length = GetModuleFileNameW(
      g_module,
      value.data(),
      static_cast<DWORD>(value.size()));
  if (length == 0U || length >= value.size()) {
    SetLastReason(WindowsError(L"GetModuleFileNameW", GetLastError()));
    return false;
  }
  module_path.assign(value.data(), length);
  return true;
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

[[nodiscard]] bool VerifyObservationSite() {
  using namespace psobb::client_safety;
  auto* const executable =
      reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
  if (executable == nullptr ||
      kObservationSiteRva > k59NlIdentity.image_size ||
      kObservationSiteSize >
          k59NlIdentity.image_size - kObservationSiteRva) {
    SetLastReason(L"Observation site is outside the exact client image");
    return false;
  }

  std::array<std::uint8_t, 32> digest{};
  std::wstring failure;
  if (!ComputeSha256(
          std::span<const std::byte>(
              executable + kObservationSiteRva,
              kObservationSiteSize),
          digest,
          failure)) {
    SetLastReason(failure);
    return false;
  }
  if (HexEncode(digest) != kObservationSiteSha256) {
    SetLastReason(
        L"Exact-client send_60 observation site digest did not match");
    return false;
  }
  g_verification_flags.fetch_or(
      verification_observation_site_matched,
      std::memory_order_release);
  return true;
}

[[nodiscard]] bool PinGameplayModule() {
  if (g_module == nullptr) {
    SetLastReason(L"Gameplay module handle is unavailable for pinning");
    return false;
  }
  HMODULE pinned = nullptr;
  if (!GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_PIN,
          reinterpret_cast<LPCWSTR>(g_module),
          &pinned)) {
    SetLastReason(WindowsError(L"GetModuleHandleExW(PIN)", GetLastError()));
    return false;
  }
  if (pinned != g_module) {
    SetLastReason(L"Pinned gameplay module identity did not match");
    return false;
  }
  return true;
}

void SetRelativeCallFailure(
    const wchar_t* const operation,
    const psobb::client_safety::RelativeCallHookResult result) noexcept {
  std::array<wchar_t, 256> message{};
  static_cast<void>(_snwprintf_s(
      message.data(),
      message.size(),
      _TRUNCATE,
      L"%ls failed closed: failure=%u, rollback-complete=%u, "
      L"rollback-failure=%u",
      operation,
      static_cast<unsigned>(result.failure),
      result.rollback_complete ? 1U : 0U,
      static_cast<unsigned>(result.rollback_failure)));
  SetLastReason(message.data());
}

void FailClosedEvidenceInitialization(
    const std::wstring_view evidence_failure) {
  g_observation_publication_enabled.store(false, std::memory_order_release);
  g_accepted_feature_bits.store(feature_none, std::memory_order_release);

  const psobb::client_safety::RelativeCallHookResult restored =
      psobb::client_safety::RollbackRelativeCallHook(
          kObservationHookOwner);
  if (restored.passed()) {
    g_verification_flags.fetch_and(
        ~static_cast<std::uint32_t>(
            verification_observation_hook_installed),
        std::memory_order_release);
  } else {
    SetRelativeCallFailure(
        L"send_60 observation hook rollback after evidence failure",
        restored);
  }

  std::wstring stop_failure;
  const bool stopped =
      g_observation_evidence.StopAndJoin(stop_failure);
  if (!stopped && restored.passed()) {
    if (!stop_failure.empty()) {
      SetLastReason(stop_failure);
    }
  } else if (restored.passed() && !stop_failure.empty()) {
    SetLastReason(stop_failure);
  } else if (restored.passed() && !evidence_failure.empty()) {
    SetLastReason(evidence_failure);
  }
  g_verification_flags.fetch_and(
      ~static_cast<std::uint32_t>(
          verification_observation_evidence_ready),
      std::memory_order_release);
  g_state.store(RuntimeState::rejected, std::memory_order_release);
}

void FailClosedAfterInitializationException() noexcept {
  g_observation_publication_enabled.store(false, std::memory_order_release);
  g_accepted_feature_bits.store(feature_none, std::memory_order_release);

  const std::uint32_t flags =
      g_verification_flags.load(std::memory_order_acquire);
  if ((flags & verification_observation_hook_installed) != 0U) {
    const psobb::client_safety::RelativeCallHookResult restored =
        psobb::client_safety::RollbackRelativeCallHook(
            kObservationHookOwner);
    if (restored.passed()) {
      g_verification_flags.fetch_and(
          ~static_cast<std::uint32_t>(
              verification_observation_hook_installed),
          std::memory_order_release);
    }
  }

  std::wstring ignored;
  const bool stopped = g_observation_evidence.StopAndJoin(ignored);
  g_verification_flags.fetch_and(
      ~static_cast<std::uint32_t>(
          verification_observation_evidence_ready),
      std::memory_order_release);
  SetLastReason(
      stopped
          ? L"Unhandled exception during gameplay initialization"
          : L"Gameplay initialization exception cleanup is incomplete");
  g_state.store(RuntimeState::rejected, std::memory_order_release);
}

using OriginalCopyFunction =
    void*(__cdecl*)(void*, const void*, std::size_t);

[[nodiscard]] __declspec(noinline) __declspec(guard(nocf))
void* CallExactOriginalCopy(
    void* const destination,
    const void* const source,
    const std::size_t length) noexcept {
  const auto original =
      reinterpret_cast<OriginalCopyFunction>(kOriginalCopyAddress);
  return original(destination, source, length);
}

[[nodiscard]] bool InitializeImplementation() {
  g_state.store(RuntimeState::initializing, std::memory_order_release);
  GameplayConfiguration configuration{};
  if (!ReadConfiguration(configuration)) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  if (!configuration.enabled) {
    g_state.store(
        RuntimeState::disabled_by_config, std::memory_order_release);
    return true;
  }

  if (!VerifyExactClient()) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  g_accepted_feature_bits.store(feature_none, std::memory_order_release);
  if (!configuration.observation) {
    SetLastReason(
        L"Exact client accepted; Observation=1 is not enabled");
    g_state.store(
        RuntimeState::exact_client_ready, std::memory_order_release);
    return true;
  }

  if (!VerifyObservationSite() || !PinGameplayModule()) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  bool evidence_requested = false;
  std::wstring evidence_run_id;
  if (!ReadObservationEvidenceRequest(
          evidence_requested, evidence_run_id)) {
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }
  if (evidence_requested) {
    std::wstring module_path;
    std::wstring evidence_failure;
    if (!GetGameplayModulePath(module_path) ||
        !g_observation_evidence.Prepare(
            module_path, evidence_run_id, evidence_failure)) {
      if (!evidence_failure.empty()) {
        SetLastReason(evidence_failure);
      }
      g_state.store(RuntimeState::rejected, std::memory_order_release);
      return false;
    }
  }

  const psobb::client_safety::RelativeCallHookResult installed =
      psobb::client_safety::InstallRelativeCallHook(
          kObservationHookOwner,
          {psobb::client_safety::k59NlIdentity.image_base,
           psobb::client_safety::k59NlIdentity.image_size},
          {kSend60CopyCallAddress,
           kOriginalCopyAddress,
           reinterpret_cast<std::uintptr_t>(
               &PSOBBGameplay_ObserveSend60Copy)});
  if (!installed.passed()) {
    g_observation_evidence.CancelPrepared();
    SetRelativeCallFailure(L"send_60 observation hook installation", installed);
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return false;
  }

  g_verification_flags.fetch_or(
      verification_observation_hook_installed,
      std::memory_order_release);
  if (evidence_requested) {
    std::wstring evidence_failure;
    if (!g_observation_evidence.Start(
            g_observations,
            HandleObservationEvidenceFailure,
            evidence_failure)) {
      FailClosedEvidenceInitialization(evidence_failure);
      return false;
    }
    g_verification_flags.fetch_or(
        verification_observation_evidence_ready,
        std::memory_order_release);
  }
  g_accepted_feature_bits.store(
      feature_observation |
          (evidence_requested ? feature_diagnostics : feature_none),
      std::memory_order_release);
  g_observation_publication_enabled.store(true, std::memory_order_release);
  SetLastReason(evidence_requested
                    ? L"Exact-client send_60 observation and bounded evidence are active"
                    : L"Exact-client send_60 observation is active");
  if (evidence_requested) {
    std::wstring evidence_failure;
    if (!g_observation_evidence.Activate(evidence_failure)) {
      FailClosedEvidenceInitialization(evidence_failure);
      return false;
    }
    RuntimeState expected = RuntimeState::initializing;
    if (!g_state.compare_exchange_strong(
            expected,
            RuntimeState::observation_ready,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      FailClosedEvidenceInitialization(
          L"Observation evidence failed while activation was committing");
      return false;
    }
  } else {
    g_state.store(
        RuntimeState::observation_ready, std::memory_order_release);
  }
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
    FailClosedAfterInitializationException();
  }
  g_initialize_result.store(initialized, std::memory_order_release);
  return TRUE;
}

}  // namespace

void SetGameplayModule(const HMODULE module) noexcept {
  g_module = module;
}

}  // namespace psobb::gameplay

extern "C" void* __cdecl PSOBBGameplay_ObserveSend60Copy(
    void* const destination,
    const void* const source,
    const std::size_t length) noexcept {
  using namespace psobb::gameplay;
  g_active_observation_callbacks.fetch_add(1U);

  void* const result = CallExactOriginalCopy(destination, source, length);
  if (g_observation_publication_enabled.load()) {
    Send60CombatAttempt attempt{};
    if (DecodeSend60CombatAttempt(source, length, attempt) &&
        g_observations.BindProducerThread()) {
      static_cast<void>(g_observations.TryRecordSend60Attempt(
          static_cast<std::uint32_t>(GetTickCount64()),
          attempt.local_client_id,
          attempt.subcommand_header_le,
          attempt.subcommand_byte_count));
    }
  }

  g_active_observation_callbacks.fetch_sub(1U);
  return result;
}

extern "C" void InitializeASI() noexcept {
  static_cast<void>(PSOBBGameplay_Initialize());
}

BOOL WINAPI PSOBBGameplay_Initialize() noexcept {
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
    psobb::gameplay::GameplayCapabilitiesV1* capabilities) noexcept {
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

BOOL WINAPI PSOBBGameplay_DrainObservations(
    psobb::gameplay::ObservationSnapshotV1* observations) noexcept {
  if (observations == nullptr ||
      observations->struct_size <
          sizeof(psobb::gameplay::ObservationSnapshotV1)) {
    return FALSE;
  }
  return psobb::gameplay::g_observations.Drain(*observations)
             ? TRUE
             : FALSE;
}

BOOL WINAPI PSOBBGameplay_Rollback() noexcept {
  using namespace psobb::gameplay;
  RollbackCallGuard rollback_guard(g_rollback_active);
  if (!rollback_guard.acquired()) {
    return FALSE;
  }
  static_cast<void>(PSOBBGameplay_Initialize());

  g_observation_publication_enabled.store(false);
  g_state.store(RuntimeState::initializing, std::memory_order_release);
  const psobb::client_safety::RelativeCallHookResult restored =
      psobb::client_safety::RollbackRelativeCallHook(
          kObservationHookOwner);
  if (!restored.passed()) {
    g_accepted_feature_bits.store(feature_none, std::memory_order_release);
    SetRelativeCallFailure(L"send_60 observation hook rollback", restored);
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return FALSE;
  }

  g_verification_flags.fetch_and(
      ~static_cast<std::uint32_t>(
          verification_observation_hook_installed),
      std::memory_order_release);
  g_accepted_feature_bits.store(feature_none, std::memory_order_release);
  if (g_active_observation_callbacks.load() != 0U) {
    SetLastReason(
        L"Observation callback is active; rollback must be retried");
    g_state.store(
        RuntimeState::exact_client_ready, std::memory_order_release);
    return FALSE;
  }
  std::wstring evidence_failure;
  if (!g_observation_evidence.StopAndJoin(evidence_failure)) {
    if (!evidence_failure.empty()) {
      SetLastReason(evidence_failure);
    }
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return FALSE;
  }
  const ObservationEvidenceFailure terminal_evidence_failure =
      g_observation_evidence.worker_failure();
  g_verification_flags.fetch_and(
      ~static_cast<std::uint32_t>(
          verification_observation_evidence_ready),
      std::memory_order_release);
  if (!g_observations.TryResetQuiescent()) {
    SetLastReason(L"Observation drain is active; rollback must be retried");
    g_state.store(
        RuntimeState::exact_client_ready, std::memory_order_release);
    return FALSE;
  }
  if (terminal_evidence_failure != ObservationEvidenceFailure::none) {
    if (!evidence_failure.empty()) {
      SetLastReason(evidence_failure);
    } else {
      SetLastReason(L"Observation evidence worker failed before rollback");
    }
    g_state.store(RuntimeState::rejected, std::memory_order_release);
    return FALSE;
  }
  SetLastReason(L"send_60 observation rollback is complete");
  g_state.store(RuntimeState::rolled_back, std::memory_order_release);
  return TRUE;
}

const wchar_t* WINAPI PSOBBGameplay_GetVersion() noexcept {
  return psobb::gameplay::kVersion;
}
