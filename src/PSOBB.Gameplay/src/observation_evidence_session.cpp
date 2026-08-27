#include "observation_evidence_session.h"

#include "psobb_client_safety/exact_image.h"
#include "psobb_gameplay/api.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <new>
#include <process.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psobb::gameplay {
namespace {

constexpr wchar_t kExpectedModuleName[] = L"PSOBB.Gameplay.asi";
constexpr wchar_t kPluginsDirectoryName[] = L"plugins";
constexpr wchar_t kClientDirectoryName[] = L"client";
constexpr wchar_t kRuntimeDirectoryName[] = L"runtime";
constexpr wchar_t kEnvironmentDirectoryName[] = L"combat-canary";
constexpr wchar_t kEvidenceDirectoryName[] = L"evidence";
constexpr wchar_t kObservationDirectoryName[] = L"gameplay-observation";
constexpr wchar_t kPartialFileName[] = L"events-v1.partial";
constexpr wchar_t kFinalizeControlEventFormat[] =
    L"Local\\PSOBB.Gameplay.Observation.Finalize.%08x.%016llx";
constexpr wchar_t kCompletionControlEventFormat[] =
    L"Local\\PSOBB.Gameplay.Observation.Completed.%08x.%016llx";
constexpr std::uint32_t kWorkerIntervalMilliseconds = 250U;
constexpr std::uint32_t kReadyTimeoutMilliseconds = 2'000U;
constexpr std::uint32_t kStopTimeoutMilliseconds = 5'000U;
constexpr std::uint64_t kFlushIntervalMilliseconds = 1'000U;

[[nodiscard]] constexpr std::uint8_t HexNibble(const wchar_t value) noexcept {
  return value >= L'0' && value <= L'9'
             ? static_cast<std::uint8_t>(value - L'0')
         : value >= L'A' && value <= L'F'
             ? static_cast<std::uint8_t>(value - L'A' + 10)
             : 0U;
}

[[nodiscard]] consteval auto ExactClientSha256Bytes() noexcept {
  std::array<std::uint8_t, kObservationEvidenceSha256ByteCount> digest{};
  for (std::size_t index = 0U; index < digest.size(); ++index) {
    digest[index] = static_cast<std::uint8_t>(
        (HexNibble(psobb::client_safety::k59NlSha256[index * 2U]) << 4U) |
        HexNibble(psobb::client_safety::k59NlSha256[index * 2U + 1U]));
  }
  return digest;
}

[[nodiscard]] consteval auto ModuleVersionBytes() noexcept {
  std::array<char, kObservationEvidenceModuleVersionByteCount> version{};
  for (std::size_t index = 0U;
       index + 1U < version.size() && kVersion[index] != L'\0';
       ++index) {
    version[index] = static_cast<char>(kVersion[index]);
  }
  return version;
}

inline constexpr auto kExactClientSha256 = ExactClientSha256Bytes();
inline constexpr auto kModuleVersion = ModuleVersionBytes();

void SetWindowsFailure(
    std::wstring& failure,
    const std::wstring_view operation,
    const DWORD error) {
  failure.assign(operation);
  failure.append(L" failed with Windows error ");
  failure.append(std::to_wstring(error));
}

void SetFailureNoThrow(
    std::wstring& failure,
    const std::wstring_view message) noexcept {
  try {
    failure.assign(message);
  } catch (...) {
  }
}

[[nodiscard]] bool EqualsComponent(
    const std::filesystem::path& path,
    const wchar_t* const expected) noexcept {
  return _wcsicmp(path.filename().c_str(), expected) == 0;
}

[[nodiscard]] std::wstring AddExtendedPrefix(
    const std::filesystem::path& path) {
  std::wstring value = path.native();
  if (value.starts_with(LR"(\\?\)")) {
    return value;
  }
  return std::wstring(LR"(\\?\)") + value;
}

[[nodiscard]] bool OpenExactDirectory(
    const std::filesystem::path& expected_path,
    HANDLE& result,
    std::wstring& failure) {
  result = INVALID_HANDLE_VALUE;
  std::error_code path_error;
  const std::filesystem::path absolute =
      std::filesystem::absolute(expected_path, path_error).lexically_normal();
  if (path_error) {
    failure = L"Evidence directory path could not be normalized";
    return false;
  }

  HANDLE directory = CreateFileW(
      absolute.c_str(),
      FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      nullptr);
  if (directory == INVALID_HANDLE_VALUE) {
    SetWindowsFailure(failure, L"CreateFileW(evidence directory)", GetLastError());
    return false;
  }

  BY_HANDLE_FILE_INFORMATION information{};
  if (!GetFileInformationByHandle(directory, &information)) {
    const DWORD error = GetLastError();
    CloseHandle(directory);
    SetWindowsFailure(failure, L"GetFileInformationByHandle(directory)", error);
    return false;
  }
  if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
      (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
    CloseHandle(directory);
    failure = L"Evidence directory must be an exact non-reparse directory";
    return false;
  }

  std::vector<wchar_t> final_path(32'768U);
  const DWORD final_length = GetFinalPathNameByHandleW(
      directory,
      final_path.data(),
      static_cast<DWORD>(final_path.size()),
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (final_length == 0U || final_length >= final_path.size()) {
    const DWORD error = GetLastError();
    CloseHandle(directory);
    SetWindowsFailure(failure, L"GetFinalPathNameByHandleW(directory)", error);
    return false;
  }
  const std::wstring expected_final = AddExtendedPrefix(absolute);
  if (_wcsicmp(final_path.data(), expected_final.c_str()) != 0) {
    CloseHandle(directory);
    failure = L"Evidence directory final path escaped its canonical location";
    return false;
  }

  result = directory;
  return true;
}

[[nodiscard]] bool IsDecimal(const wchar_t value) noexcept {
  return value >= L'0' && value <= L'9';
}

[[nodiscard]] bool IsLowerHex(const wchar_t value) noexcept {
  return IsDecimal(value) || (value >= L'a' && value <= L'f');
}

[[nodiscard]] bool CreateExclusiveManualResetEvent(
    const wchar_t* const name,
    HANDLE& result,
    DWORD& failure) noexcept {
  result = nullptr;
  failure = ERROR_SUCCESS;
  SetLastError(ERROR_SUCCESS);
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, name);
  const DWORD create_result = GetLastError();
  if (event == nullptr) {
    failure = create_result;
    return false;
  }
  if (create_result == ERROR_ALREADY_EXISTS) {
    CloseHandle(event);
    failure = ERROR_ALREADY_EXISTS;
    return false;
  }
  result = event;
  return true;
}

}  // namespace

bool ObservationEvidenceSession::IsValidRunId(
    const std::wstring_view run_id) noexcept {
  constexpr std::size_t kRunIdLength = 41U;
  constexpr std::wstring_view kMiddle = L"-gameplay-";
  if (run_id.size() != kRunIdLength || run_id[8] != L'T' ||
      run_id[18] != L'Z' || run_id.substr(19U, kMiddle.size()) != kMiddle) {
    return false;
  }
  for (std::size_t index = 0U; index < 19U; ++index) {
    if (index != 8U && index != 18U && !IsDecimal(run_id[index])) {
      return false;
    }
  }
  return std::all_of(
      run_id.begin() + 29,
      run_id.end(),
      IsLowerHex);
}

bool ObservationEvidenceSession::BuildControlEventNames(
    const std::uint32_t process_id,
    const std::uint64_t process_start_filetime,
    ObservationEvidenceControlEventNames& names) noexcept {
  names = {};
  if (process_id == 0U || process_start_filetime == 0U) {
    return false;
  }

  const unsigned formatted_process_id =
      static_cast<unsigned>(process_id);
  const unsigned long long formatted_process_start =
      static_cast<unsigned long long>(process_start_filetime);
  const int finalize_length = _snwprintf_s(
      names.finalize.data(),
      names.finalize.size(),
      _TRUNCATE,
      kFinalizeControlEventFormat,
      formatted_process_id,
      formatted_process_start);
  const int completion_length = _snwprintf_s(
      names.completion.data(),
      names.completion.size(),
      _TRUNCATE,
      kCompletionControlEventFormat,
      formatted_process_id,
      formatted_process_start);
  if (finalize_length <= 0 || completion_length <= 0) {
    names = {};
    return false;
  }
  return true;
}

bool ObservationEvidenceSession::Prepare(
    const std::wstring_view module_path,
    const std::wstring_view run_id,
    std::wstring& failure) {
  try {
    return PrepareImplementation(module_path, run_id, failure);
  } catch (...) {
    CancelPrepared();
    try {
      failure = L"Observation evidence preparation raised an exception";
    } catch (...) {
    }
    return false;
  }
}

bool ObservationEvidenceSession::PrepareImplementation(
    const std::wstring_view module_path,
    const std::wstring_view run_id,
    std::wstring& failure) {
  failure.clear();
  if (prepared_ || thread_ != nullptr || !IsValidRunId(run_id) ||
      module_path.empty() || module_path.find(L'\0') != std::wstring_view::npos) {
    failure = L"Observation evidence preparation input is invalid";
    return false;
  }

  const std::filesystem::path module{module_path};
  const std::filesystem::path plugins = module.parent_path();
  const std::filesystem::path client = plugins.parent_path();
  const std::filesystem::path runtime = client.parent_path();
  const std::filesystem::path environment = runtime.parent_path();
  if (!EqualsComponent(module, kExpectedModuleName) ||
      !EqualsComponent(plugins, kPluginsDirectoryName) ||
      !EqualsComponent(client, kClientDirectoryName) ||
      !EqualsComponent(runtime, kRuntimeDirectoryName) ||
      !EqualsComponent(environment, kEnvironmentDirectoryName)) {
    failure = L"Gameplay module is outside the exact CombatCanary layout";
    return false;
  }

  const std::filesystem::path category =
      environment / kEvidenceDirectoryName / kObservationDirectoryName;
  const std::filesystem::path run = category / std::wstring(run_id);
  if (!OpenExactDirectory(category, category_directory_, failure) ||
      !OpenExactDirectory(run, run_directory_, failure)) {
    CancelPrepared();
    return false;
  }

  const std::filesystem::path partial = run / kPartialFileName;
  const std::wstring partial_text = partial.native();
  if (partial_text.size() >= partial_path_.size()) {
    failure = L"Observation evidence file path is too long";
    CancelPrepared();
    return false;
  }
  std::copy(partial_text.begin(), partial_text.end(), partial_path_.begin());
  partial_path_[partial_text.size()] = L'\0';
  partial_path_length_ = partial_text.size();

  file_ = CreateFileW(
      partial_path_.data(),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ,
      nullptr,
      CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);
  if (file_ == INVALID_HANDLE_VALUE) {
    SetWindowsFailure(failure, L"CreateFileW(observation evidence)", GetLastError());
    CancelPrepared();
    return false;
  }

  BY_HANDLE_FILE_INFORMATION file_information{};
  if (!GetFileInformationByHandle(file_, &file_information) ||
      (file_information.dwFileAttributes &
       (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U ||
      file_information.nNumberOfLinks != 1U) {
    failure = L"Observation evidence file identity is not exact";
    CancelPrepared();
    return false;
  }

  LARGE_INTEGER maximum_size{};
  maximum_size.QuadPart = kObservationEvidenceMaximumFileSize;
  if (!SetFilePointerEx(file_, maximum_size, nullptr, FILE_BEGIN) ||
      !SetEndOfFile(file_)) {
    SetWindowsFailure(failure, L"Preallocate observation evidence", GetLastError());
    CancelPrepared();
    return false;
  }

  FILETIME creation_time{};
  FILETIME exit_time{};
  FILETIME kernel_time{};
  FILETIME user_time{};
  if (!GetProcessTimes(
          GetCurrentProcess(),
          &creation_time,
          &exit_time,
          &kernel_time,
          &user_time)) {
    SetWindowsFailure(failure, L"GetProcessTimes", GetLastError());
    CancelPrepared();
    return false;
  }
  ULARGE_INTEGER process_start{};
  process_start.LowPart = creation_time.dwLowDateTime;
  process_start.HighPart = creation_time.dwHighDateTime;
  process_start_filetime_ = process_start.QuadPart;
  process_id_ = static_cast<std::uint32_t>(GetCurrentProcessId());
  prepared_ = true;
  return true;
}

bool ObservationEvidenceSession::Start(
    ObservationRing& ring,
    const ObservationEvidenceFailureHandler failure_handler,
    std::wstring& failure) {
  try {
    return StartImplementation(ring, failure_handler, failure);
  } catch (...) {
    if (thread_ != nullptr) {
      if (finalize_event_ != nullptr) {
        static_cast<void>(SetEvent(finalize_event_));
      }
      if (start_event_ != nullptr) {
        static_cast<void>(SetEvent(start_event_));
      }
      if (activation_event_ != nullptr) {
        static_cast<void>(SetEvent(activation_event_));
      }
      const HANDLE stopped_events[] = {completion_event_, thread_};
      if (completion_event_ != nullptr &&
          WaitForMultipleObjects(
              static_cast<DWORD>(std::size(stopped_events)),
              stopped_events,
              TRUE,
              kStopTimeoutMilliseconds) == WAIT_OBJECT_0) {
        CloseStoppedHandles();
      }
    } else {
      CloseStoppedHandles();
    }
    try {
      failure = L"Observation evidence startup raised an exception";
    } catch (...) {
    }
    return false;
  }
}

bool ObservationEvidenceSession::StartImplementation(
    ObservationRing& ring,
    const ObservationEvidenceFailureHandler failure_handler,
    std::wstring& failure) {
  failure.clear();
  if (!prepared_ || file_ == INVALID_HANDLE_VALUE || thread_ != nullptr ||
      accumulator_ != nullptr) {
    failure = L"Observation evidence session is not prepared for startup";
    return false;
  }

  ObservationEvidenceControlEventNames control_event_names{};
  if (!BuildControlEventNames(
          process_id_, process_start_filetime_, control_event_names)) {
    failure = L"Observation evidence control-event identity is invalid";
    CloseStoppedHandles();
    return false;
  }

  DWORD control_event_failure = ERROR_SUCCESS;
  if (!CreateExclusiveManualResetEvent(
          control_event_names.finalize.data(),
          finalize_event_,
          control_event_failure)) {
    if (control_event_failure == ERROR_ALREADY_EXISTS) {
      failure = L"Observation evidence finalize event already exists";
    } else {
      SetWindowsFailure(
          failure,
          L"CreateEventW(observation evidence finalize)",
          control_event_failure);
    }
    CloseStoppedHandles();
    return false;
  }
  if (!CreateExclusiveManualResetEvent(
          control_event_names.completion.data(),
          completion_event_,
          control_event_failure)) {
    if (control_event_failure == ERROR_ALREADY_EXISTS) {
      failure = L"Observation evidence completion event already exists";
    } else {
      SetWindowsFailure(
          failure,
          L"CreateEventW(observation evidence completion)",
          control_event_failure);
    }
    CloseStoppedHandles();
    return false;
  }

  start_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  activation_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  active_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (start_event_ == nullptr || ready_event_ == nullptr ||
      activation_event_ == nullptr || active_event_ == nullptr) {
    SetWindowsFailure(failure, L"CreateEventW(observation evidence)", GetLastError());
    CloseStoppedHandles();
    return false;
  }

  if (!ring.TryClaimEvidenceConsumer()) {
    failure = L"Observation ring already has an active consumer";
    CloseStoppedHandles();
    return false;
  }
  ring_ = &ring;
  failure_handler_ = failure_handler;
  worker_failure_.store(
      ObservationEvidenceFailure::none, std::memory_order_release);
  consumer_owned_.store(true, std::memory_order_release);

  unsigned consumer_thread_id = 0U;
  const std::uintptr_t thread_value = _beginthreadex(
      nullptr,
      0U,
      &ObservationEvidenceSession::WorkerEntry,
      this,
      0U,
      &consumer_thread_id);
  if (thread_value == 0U) {
    failure = L"_beginthreadex(observation evidence) failed";
    CloseStoppedHandles();
    return false;
  }
  thread_ = reinterpret_cast<HANDLE>(thread_value);
  consumer_thread_id_ = consumer_thread_id;

  ObservationEvidenceSessionIdentity identity{};
  identity.exact_client_sha256 = kExactClientSha256;
  identity.module_version = kModuleVersion;
  identity.consumer_thread_id = consumer_thread_id;
  identity.process_id = process_id_;
  identity.process_start_filetime = process_start_filetime_;
  accumulator_ = ::new (accumulator_storage_.data())
      ObservationEvidenceAccumulator(identity);

  if (!SetEvent(start_event_)) {
    ReportFailure(ObservationEvidenceFailure::ready_signal_failed);
    static_cast<void>(SetEvent(finalize_event_));
    static_cast<void>(SetEvent(start_event_));
  } else {
    const DWORD ready = WaitForSingleObject(
        ready_event_, kReadyTimeoutMilliseconds);
    if (ready != WAIT_OBJECT_0) {
      ReportFailure(ObservationEvidenceFailure::initial_wait_failed);
      static_cast<void>(SetEvent(finalize_event_));
      static_cast<void>(SetEvent(start_event_));
    }
  }

  if (worker_failure_.load(std::memory_order_acquire) !=
          ObservationEvidenceFailure::none) {
    const HANDLE stopped_events[] = {completion_event_, thread_};
    const DWORD stopped = WaitForMultipleObjects(
        static_cast<DWORD>(std::size(stopped_events)),
        stopped_events,
        TRUE,
        kStopTimeoutMilliseconds);
    if (stopped == WAIT_OBJECT_0) {
      CloseStoppedHandles();
    }
    failure = L"Observation evidence worker did not become ready";
    return false;
  }
  return true;
}

bool ObservationEvidenceSession::Activate(std::wstring& failure) {
  failure.clear();
  if (thread_ == nullptr || activation_event_ == nullptr ||
      active_event_ == nullptr || accumulator_ == nullptr ||
      worker_failure_.load(std::memory_order_acquire) !=
          ObservationEvidenceFailure::none) {
    failure = L"Observation evidence worker is not ready for activation";
    return false;
  }
  if (!SetEvent(activation_event_)) {
    ReportFailure(ObservationEvidenceFailure::activation_signal_failed);
    failure = L"Observation evidence activation signal failed";
    return false;
  }
  const DWORD activated =
      WaitForSingleObject(active_event_, kReadyTimeoutMilliseconds);
  if (activated != WAIT_OBJECT_0) {
    ReportFailure(ObservationEvidenceFailure::activation_wait_failed);
    failure = L"Observation evidence worker did not activate";
    return false;
  }
  if (worker_failure_.load(std::memory_order_acquire) !=
      ObservationEvidenceFailure::none) {
    failure = L"Observation evidence worker failed during activation";
    return false;
  }
  return true;
}

unsigned __stdcall ObservationEvidenceSession::WorkerEntry(
    void* const context) noexcept {
  if (context == nullptr) {
    return 1U;
  }
  return static_cast<ObservationEvidenceSession*>(context)->Worker();
}

unsigned ObservationEvidenceSession::Worker() noexcept {
  const auto finish = [this](const unsigned result) noexcept {
    if (completion_event_ == nullptr ||
        SetEvent(completion_event_) == FALSE) {
      ReportFailure(ObservationEvidenceFailure::completion_signal_failed);
      return 1U;
    }
    return result;
  };

  const DWORD initial = WaitForSingleObject(start_event_, INFINITE);
  if (initial != WAIT_OBJECT_0 || accumulator_ == nullptr) {
    ReportFailure(ObservationEvidenceFailure::initial_wait_failed);
    static_cast<void>(SetEvent(ready_event_));
    return finish(1U);
  }

  static_cast<void>(SetThreadPriority(
      GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL));
  accumulator_->MarkReady(CurrentFiletime());
  if (!WriteExactAt(
          0U, &accumulator_->Header(), sizeof(ObservationEvidenceHeaderV1)) ||
      !Flush()) {
    ReportFailure(ObservationEvidenceFailure::initial_header_write_failed);
    static_cast<void>(SetEvent(ready_event_));
    return finish(1U);
  }
  last_flush_tick_ = GetTickCount64();
  if (!SetEvent(ready_event_)) {
    ReportFailure(ObservationEvidenceFailure::ready_signal_failed);
    return finish(1U);
  }

  const HANDLE activation_events[] = {
      finalize_event_, activation_event_};
  const DWORD activation = WaitForMultipleObjects(
      static_cast<DWORD>(std::size(activation_events)),
      activation_events,
      FALSE,
      INFINITE);
  if (activation == WAIT_OBJECT_0) {
    const bool persisted = PersistStoppedState();
    if (!persisted) {
      ReportFailure(
          ObservationEvidenceFailure::terminal_header_write_failed);
    }
    static_cast<void>(SetEvent(active_event_));
    return finish(persisted ? 0U : 1U);
  }
  if (activation != WAIT_OBJECT_0 + 1U) {
    ReportFailure(ObservationEvidenceFailure::activation_wait_failed);
    static_cast<void>(SetEvent(active_event_));
    return finish(1U);
  }

  const std::uint64_t active_tick = GetTickCount64();
  accumulator_->MarkActive(CurrentFiletime(), active_tick);
  if (!WriteExactAt(
          0U, &accumulator_->Header(), sizeof(ObservationEvidenceHeaderV1)) ||
      !Flush()) {
    ReportFailure(ObservationEvidenceFailure::active_header_write_failed);
    static_cast<void>(SetEvent(active_event_));
    return finish(1U);
  }
  last_flush_tick_ = active_tick;
  if (!SetEvent(active_event_)) {
    ReportFailure(ObservationEvidenceFailure::activation_signal_failed);
    return finish(1U);
  }

  for (;;) {
    const DWORD wait = WaitForSingleObject(
        finalize_event_, kWorkerIntervalMilliseconds);
    const bool stopping = wait == WAIT_OBJECT_0;
    if (wait != WAIT_TIMEOUT && !stopping) {
      ReportFailure(ObservationEvidenceFailure::stop_wait_failed);
      return finish(1U);
    }
    if (!DrainAndCommit(stopping)) {
      return finish(1U);
    }
    if (stopping) {
      if (!PersistStoppedState()) {
        ReportFailure(
            ObservationEvidenceFailure::terminal_header_write_failed);
        return finish(1U);
      }
      return finish(0U);
    }
  }
}

bool ObservationEvidenceSession::DrainAndCommit(
    const bool final_flush) noexcept {
  if (ring_ == nullptr || accumulator_ == nullptr ||
      !ring_->DrainClaimed(snapshot_)) {
    ReportFailure(ObservationEvidenceFailure::ring_drain_failed);
    return false;
  }

  const ObservationEvidenceHeaderV1 previous_header =
      accumulator_->Header();
  const std::uint32_t previous_count =
      previous_header.committed_event_count;
  if (!accumulator_->Append(snapshot_)) {
    ReportFailure(ObservationEvidenceFailure::accumulator_rejected_snapshot);
    return false;
  }

  const std::uint64_t now = GetTickCount64();
  const bool flush_due =
      final_flush || now - last_flush_tick_ >= kFlushIntervalMilliseconds;
  if (flush_due) {
    accumulator_->MarkHeartbeat(CurrentFiletime(), now);
  }

  const ObservationEvidenceHeaderV1& header = accumulator_->Header();
  const std::uint32_t appended =
      header.committed_event_count - previous_count;
  if (appended != 0U) {
    const std::span<const ObservationEventV1> events =
        accumulator_->CommittedEvents().subspan(previous_count, appended);
    const std::uint64_t offset =
        sizeof(ObservationEvidenceHeaderV1) +
        static_cast<std::uint64_t>(previous_count) *
            sizeof(ObservationEventV1);
    if (!WriteExactAt(offset, events.data(), events.size_bytes())) {
      accumulator_->RestoreHeaderAfterPayloadFailure(previous_header);
      ReportFailure(ObservationEvidenceFailure::event_write_failed);
      return false;
    }
    dirty_ = true;
  }

  if (std::memcmp(&previous_header, &header, sizeof(header)) != 0) {
    if (!WriteExactAt(0U, &header, sizeof(header))) {
      ReportFailure(ObservationEvidenceFailure::header_write_failed);
      return false;
    }
    dirty_ = true;
  }

  if (dirty_ && flush_due) {
    if (!Flush()) {
      ReportFailure(ObservationEvidenceFailure::flush_failed);
      return false;
    }
    dirty_ = false;
    last_flush_tick_ = now;
  }
  return true;
}

bool ObservationEvidenceSession::WriteExactAt(
    const std::uint64_t offset,
    const void* const data,
    const std::size_t size) noexcept {
  if (file_ == INVALID_HANDLE_VALUE || data == nullptr ||
      size > (std::numeric_limits<DWORD>::max)() ||
      offset > kObservationEvidenceMaximumFileSize ||
      size > kObservationEvidenceMaximumFileSize - offset) {
    return false;
  }
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (!SetFilePointerEx(file_, position, nullptr, FILE_BEGIN)) {
    return false;
  }

  const auto* bytes = static_cast<const std::byte*>(data);
  std::size_t written_total = 0U;
  while (written_total < size) {
    DWORD written = 0U;
    const DWORD remaining = static_cast<DWORD>(size - written_total);
    if (!WriteFile(
            file_,
            bytes + written_total,
            remaining,
            &written,
            nullptr) ||
        written == 0U) {
      return false;
    }
    written_total += written;
  }
  return true;
}

bool ObservationEvidenceSession::Flush() noexcept {
  return file_ != INVALID_HANDLE_VALUE && FlushFileBuffers(file_) != FALSE;
}

std::uint64_t ObservationEvidenceSession::CurrentFiletime() noexcept {
  FILETIME value{};
  GetSystemTimeAsFileTime(&value);
  ULARGE_INTEGER combined{};
  combined.LowPart = value.dwLowDateTime;
  combined.HighPart = value.dwHighDateTime;
  return combined.QuadPart;
}

void ObservationEvidenceSession::ReportFailure(
    const ObservationEvidenceFailure failure) noexcept {
  ObservationEvidenceFailure expected = ObservationEvidenceFailure::none;
  if (worker_failure_.compare_exchange_strong(
          expected,
          failure,
          std::memory_order_acq_rel,
          std::memory_order_acquire)) {
    PersistFailureBestEffort(failure);
    if (failure_handler_ != nullptr) {
      failure_handler_(failure);
    }
  }
}

void ObservationEvidenceSession::PersistFailureBestEffort(
    const ObservationEvidenceFailure failure) noexcept {
  if (accumulator_ == nullptr ||
      consumer_thread_id_ == 0U ||
      GetCurrentThreadId() != consumer_thread_id_) {
    return;
  }
  accumulator_->MarkFailed(
      static_cast<std::uint32_t>(failure),
      CurrentFiletime(),
      GetTickCount64());
  static_cast<void>(WriteExactAt(
      0U, &accumulator_->Header(), sizeof(ObservationEvidenceHeaderV1)));
  static_cast<void>(Flush());
}

bool ObservationEvidenceSession::PersistStoppedState() noexcept {
  if (accumulator_ == nullptr) {
    return false;
  }
  const ObservationEvidenceFailure terminal_failure =
      worker_failure_.load(std::memory_order_acquire);
  const std::uint64_t now_filetime = CurrentFiletime();
  const std::uint64_t now_tick = GetTickCount64();
  if (terminal_failure == ObservationEvidenceFailure::none) {
    accumulator_->MarkCompleted(now_filetime, now_tick);
  } else {
    accumulator_->MarkFailed(
        static_cast<std::uint32_t>(terminal_failure),
        now_filetime,
        now_tick);
  }
  return WriteExactAt(
             0U,
             &accumulator_->Header(),
             sizeof(ObservationEvidenceHeaderV1)) &&
         Flush();
}

bool ObservationEvidenceSession::StopAndJoin(
    std::wstring& failure) noexcept {
  failure.clear();
  if (thread_ == nullptr) {
    CancelPrepared();
    return true;
  }
  const bool finalize_signaled =
      finalize_event_ != nullptr && SetEvent(finalize_event_) != FALSE;
  const bool start_signaled = SetEvent(start_event_) != FALSE;
  const bool activation_signaled = SetEvent(activation_event_) != FALSE;
  if (!finalize_signaled || !start_signaled || !activation_signaled ||
      completion_event_ == nullptr) {
    SetFailureNoThrow(
        failure, L"Observation evidence finalize signal failed");
    return false;
  }
  const HANDLE stopped_events[] = {completion_event_, thread_};
  const DWORD stopped = WaitForMultipleObjects(
      static_cast<DWORD>(std::size(stopped_events)),
      stopped_events,
      TRUE,
      kStopTimeoutMilliseconds);
  if (stopped != WAIT_OBJECT_0) {
    SetFailureNoThrow(
        failure,
        L"Observation evidence worker is still active; retry rollback");
    return false;
  }
  const ObservationEvidenceFailure terminal_failure =
      worker_failure_.load(std::memory_order_acquire);
  CloseStoppedHandles();
  if (terminal_failure != ObservationEvidenceFailure::none) {
    try {
      failure = L"Observation evidence worker failed with code ";
      failure.append(
          std::to_wstring(static_cast<std::uint32_t>(terminal_failure)));
    } catch (...) {
    }
  }
  return true;
}

void ObservationEvidenceSession::CloseStoppedHandles() noexcept {
  if (thread_ != nullptr) {
    CloseHandle(thread_);
    thread_ = nullptr;
  }
  if (ready_event_ != nullptr) {
    CloseHandle(ready_event_);
    ready_event_ = nullptr;
  }
  if (active_event_ != nullptr) {
    CloseHandle(active_event_);
    active_event_ = nullptr;
  }
  if (activation_event_ != nullptr) {
    CloseHandle(activation_event_);
    activation_event_ = nullptr;
  }
  if (completion_event_ != nullptr) {
    CloseHandle(completion_event_);
    completion_event_ = nullptr;
  }
  if (finalize_event_ != nullptr) {
    CloseHandle(finalize_event_);
    finalize_event_ = nullptr;
  }
  if (start_event_ != nullptr) {
    CloseHandle(start_event_);
    start_event_ = nullptr;
  }
  if (consumer_owned_.exchange(false, std::memory_order_acq_rel) &&
      ring_ != nullptr) {
    ring_->ReleaseEvidenceConsumer();
  }
  CancelPrepared();
}

void ObservationEvidenceSession::CancelPrepared() noexcept {
  if (thread_ != nullptr) {
    return;
  }
  if (file_ != INVALID_HANDLE_VALUE) {
    CloseHandle(file_);
    file_ = INVALID_HANDLE_VALUE;
  }
  if (run_directory_ != INVALID_HANDLE_VALUE) {
    CloseHandle(run_directory_);
    run_directory_ = INVALID_HANDLE_VALUE;
  }
  if (category_directory_ != INVALID_HANDLE_VALUE) {
    CloseHandle(category_directory_);
    category_directory_ = INVALID_HANDLE_VALUE;
  }
  ring_ = nullptr;
  failure_handler_ = nullptr;
  accumulator_ = nullptr;
  partial_path_.fill(L'\0');
  partial_path_length_ = 0U;
  prepared_ = false;
  dirty_ = false;
  last_flush_tick_ = 0U;
  process_id_ = 0U;
  consumer_thread_id_ = 0U;
  process_start_filetime_ = 0U;
}

bool ObservationEvidenceSession::prepared() const noexcept {
  return prepared_;
}

bool ObservationEvidenceSession::owns_consumer() const noexcept {
  return consumer_owned_.load(std::memory_order_acquire);
}

ObservationEvidenceFailure
ObservationEvidenceSession::worker_failure() const noexcept {
  return worker_failure_.load(std::memory_order_acquire);
}

std::wstring_view ObservationEvidenceSession::partial_path() const noexcept {
  return std::wstring_view(partial_path_.data(), partial_path_length_);
}

}  // namespace psobb::gameplay
