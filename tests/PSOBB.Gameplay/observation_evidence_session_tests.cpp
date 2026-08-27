#include "observation_evidence_session.h"

#include "psobb_gameplay/observation_evidence.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

namespace psobb::gameplay {

struct ObservationEvidenceSessionTestAccess final {
  static void InvalidateEvidenceFile(
      ObservationEvidenceSession& session) noexcept {
    if (session.file_ != INVALID_HANDLE_VALUE) {
      CloseHandle(session.file_);
      session.file_ = INVALID_HANDLE_VALUE;
    }
  }

  static void ReportCallerFailure(
      ObservationEvidenceSession& session,
      const ObservationEvidenceFailure failure) noexcept {
    session.ReportFailure(failure);
  }
};

}  // namespace psobb::gameplay

namespace {

constexpr std::wstring_view kRunId =
    L"20260726T103456789Z-gameplay-012345abcdef";

std::atomic<psobb::gameplay::ObservationEvidenceFailure> g_worker_failure{
    psobb::gameplay::ObservationEvidenceFailure::none};
int g_failures = 0;

void Check(const bool condition, const char* const expression) {
  if (!condition) {
    std::cerr << "FAIL: " << expression << '\n';
    ++g_failures;
  }
}

#define CHECK(expression) Check((expression), #expression)

[[nodiscard]] std::uint32_t CurrentThreadId() noexcept {
  return static_cast<std::uint32_t>(GetCurrentThreadId());
}

[[nodiscard]] bool CurrentProcessIdentity(
    std::uint32_t& process_id,
    std::uint64_t& process_start_filetime) noexcept {
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
    return false;
  }
  ULARGE_INTEGER combined{};
  combined.LowPart = creation_time.dwLowDateTime;
  combined.HighPart = creation_time.dwHighDateTime;
  process_id = static_cast<std::uint32_t>(GetCurrentProcessId());
  process_start_filetime = combined.QuadPart;
  return process_id != 0U && process_start_filetime != 0U;
}

void RecordWorkerFailure(
    const psobb::gameplay::ObservationEvidenceFailure failure) noexcept {
  g_worker_failure.store(failure, std::memory_order_release);
}

class TemporaryLayout final {
 public:
  TemporaryLayout() {
    const std::wstring unique =
        L"PSOBB-GameplayEvidence-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64()) + L"-" +
        std::to_wstring(next_id_.fetch_add(1U));
    root_ = std::filesystem::temp_directory_path() / unique;
    module_path_ = root_ / L"combat-canary" / L"runtime" / L"client" /
                   L"plugins" / L"PSOBB.Gameplay.asi";
    category_path_ =
        root_ / L"combat-canary" / L"evidence" /
        L"gameplay-observation";
    run_path_ = category_path_ / std::wstring(kRunId);
    std::filesystem::create_directories(module_path_.parent_path());
    std::filesystem::create_directories(run_path_);
    std::ofstream module(module_path_, std::ios::binary);
    module.put('\0');
  }

  ~TemporaryLayout() {
    std::error_code ignored;
    std::filesystem::remove_all(root_, ignored);
  }

  TemporaryLayout(const TemporaryLayout&) = delete;
  TemporaryLayout& operator=(const TemporaryLayout&) = delete;

  [[nodiscard]] const std::filesystem::path& module_path() const noexcept {
    return module_path_;
  }
  [[nodiscard]] const std::filesystem::path& category_path() const noexcept {
    return category_path_;
  }
  [[nodiscard]] const std::filesystem::path& run_path() const noexcept {
    return run_path_;
  }
  [[nodiscard]] std::filesystem::path partial_path() const {
    return run_path_ / L"events-v1.partial";
  }

 private:
  inline static std::atomic_uint32_t next_id_{1U};
  std::filesystem::path root_;
  std::filesystem::path module_path_;
  std::filesystem::path category_path_;
  std::filesystem::path run_path_;
};

void TestRunIdValidation() {
  using psobb::gameplay::ObservationEvidenceSession;
  CHECK(ObservationEvidenceSession::IsValidRunId(kRunId));
  CHECK(!ObservationEvidenceSession::IsValidRunId(L""));
  CHECK(!ObservationEvidenceSession::IsValidRunId(
      L"20260726T103456789Z-gameplay-012345ABCDEf"));
  CHECK(!ObservationEvidenceSession::IsValidRunId(
      L"20260726T103456789Z-gameplay-012345abcde"));
  CHECK(!ObservationEvidenceSession::IsValidRunId(
      L"20260726T103456789Z-gameplay-012345abcdef0"));
  CHECK(!ObservationEvidenceSession::IsValidRunId(
      L"20260726T103456789Z-gameplay-..\\outside"));
  CHECK(!ObservationEvidenceSession::IsValidRunId(
      L"20260726X103456789Z-gameplay-012345abcdef"));
}

void TestControlEventNameDerivation() {
  using namespace psobb::gameplay;
  ObservationEvidenceControlEventNames names{};
  CHECK(ObservationEvidenceSession::BuildControlEventNames(
      0x12AB34CDU, 0x0123456789ABCDEFULL, names));
  CHECK(std::wstring_view(names.finalize.data()) ==
        L"Local\\PSOBB.Gameplay.Observation.Finalize.12ab34cd."
        L"0123456789abcdef");
  CHECK(std::wstring_view(names.completion.data()) ==
        L"Local\\PSOBB.Gameplay.Observation.Completed.12ab34cd."
        L"0123456789abcdef");

  names.finalize[0] = L'x';
  names.completion[0] = L'x';
  CHECK(!ObservationEvidenceSession::BuildControlEventNames(
      0U, 0x0123456789ABCDEFULL, names));
  CHECK(names.finalize[0] == L'\0');
  CHECK(names.completion[0] == L'\0');
  CHECK(!ObservationEvidenceSession::BuildControlEventNames(
      0x12AB34CDU, 0U, names));
}

void TestPreexistingControlEventsAreRejected() {
  using namespace psobb::gameplay;
  std::uint32_t process_id = 0U;
  std::uint64_t process_start_filetime = 0U;
  CHECK(CurrentProcessIdentity(process_id, process_start_filetime));
  ObservationEvidenceControlEventNames names{};
  CHECK(ObservationEvidenceSession::BuildControlEventNames(
      process_id, process_start_filetime, names));

  const auto verify_rejected = [&names](
                                   const wchar_t* const event_name) {
    SetLastError(ERROR_SUCCESS);
    HANDLE preexisting =
        CreateEventW(nullptr, TRUE, FALSE, event_name);
    CHECK(preexisting != nullptr);
    CHECK(GetLastError() != ERROR_ALREADY_EXISTS);

    TemporaryLayout layout;
    auto session = std::make_unique<ObservationEvidenceSession>();
    std::wstring failure;
    CHECK(session->Prepare(
        layout.module_path().native(), kRunId, failure));
    ObservationRing ring(CurrentThreadId);
    failure.clear();
    CHECK(!session->Start(ring, RecordWorkerFailure, failure));
    CHECK(!failure.empty());
    CHECK(!session->prepared());
    CHECK(!session->owns_consumer());
    CHECK(session->StopAndJoin(failure));

    if (preexisting != nullptr) {
      CloseHandle(preexisting);
    }
  };

  verify_rejected(names.finalize.data());
  verify_rejected(names.completion.data());
}

void TestPrepareRejectsWrongLayoutAndNoClobber() {
  using psobb::gameplay::ObservationEvidenceSession;
  std::wstring failure;
  auto wrong_layout = std::make_unique<ObservationEvidenceSession>();
  CHECK(!wrong_layout->Prepare(
      L"C:\\temporary\\plugins\\PSOBB.Gameplay.asi", kRunId, failure));
  CHECK(!failure.empty());

  TemporaryLayout layout;
  const std::filesystem::path partial = layout.partial_path();
  {
    std::ofstream existing(partial, std::ios::binary);
    existing << "sentinel";
  }
  auto no_clobber = std::make_unique<ObservationEvidenceSession>();
  failure.clear();
  CHECK(!no_clobber->Prepare(
      layout.module_path().native(), kRunId, failure));
  CHECK(!failure.empty());
  std::ifstream existing(partial, std::ios::binary);
  std::string value;
  existing >> value;
  CHECK(value == "sentinel");
}

void TestPrepareRequiresExistingExactDirectories() {
  using psobb::gameplay::ObservationEvidenceSession;
  TemporaryLayout layout;
  std::error_code error;
  std::filesystem::remove_all(layout.run_path(), error);
  CHECK(!error);
  auto missing_run = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(!missing_run->Prepare(
      layout.module_path().native(), kRunId, failure));
  CHECK(!failure.empty());
  CHECK(!std::filesystem::exists(layout.partial_path()));
}

void TestWorkerDrainsAndCommits() {
  using namespace psobb::gameplay;
  TemporaryLayout layout;
  auto session = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(session->Prepare(
      layout.module_path().native(), kRunId, failure));
  const std::filesystem::path partial = layout.partial_path();
  CHECK(session->prepared());
  CHECK(!session->owns_consumer());
  CHECK(session->partial_path() == partial.native());
  CHECK(std::filesystem::file_size(partial) ==
        kObservationEvidenceMaximumFileSize);

  ObservationRing ring(CurrentThreadId);
  CHECK(ring.BindProducerThread());
  CHECK(ring.TryRecordTick(100U));
  CHECK(ring.TryRecordLocalStateTransition(101U, 0U, 7U, 8U));
  CHECK(ring.TryRecordSend60Attempt(102U, 0U, 0x00000043U, 12U));

  g_worker_failure.store(
      ObservationEvidenceFailure::none, std::memory_order_release);
  CHECK(session->Start(ring, RecordWorkerFailure, failure));
  CHECK(session->owns_consumer());
  CHECK(session->worker_failure() == ObservationEvidenceFailure::none);
  ObservationSnapshotV1 rejected_external_drain{};
  CHECK(!ring.Drain(rejected_external_drain));
  CHECK(session->Activate(failure));
  CHECK(session->StopAndJoin(failure));
  CHECK(!session->owns_consumer());
  ObservationSnapshotV1 accepted_external_drain{};
  CHECK(ring.Drain(accepted_external_drain));
  CHECK(g_worker_failure.load(std::memory_order_acquire) ==
        ObservationEvidenceFailure::none);

  std::ifstream stream(partial, std::ios::binary);
  ObservationEvidenceHeaderV1 header{};
  stream.read(reinterpret_cast<char*>(&header), sizeof(header));
  std::array<ObservationEventV1, 3U> events{};
  stream.read(
      reinterpret_cast<char*>(events.data()),
      static_cast<std::streamsize>(sizeof(events)));
  CHECK(stream.good());
  CHECK(std::memcmp(
            header.magic,
            kObservationEvidenceMagic,
            sizeof(header.magic)) == 0);
  CHECK(header.struct_size == sizeof(header));
  CHECK(header.format_version == kObservationEvidenceFormatVersion);
  CHECK(header.maximum_file_size == kObservationEvidenceMaximumFileSize);
  CHECK(header.event_abi_version == kObservationAbiVersion);
  CHECK(header.event_record_size == sizeof(ObservationEventV1));
  CHECK(header.event_capacity == kObservationEvidenceEventCapacity);
  CHECK(header.committed_event_count == events.size());
  CHECK(header.total_drained_event_count == events.size());
  CHECK(header.ring_dropped_event_count == 0U);
  CHECK(header.producer_violation_count == 0U);
  CHECK(header.evidence_capacity_dropped_event_count == 0U);
  CHECK(header.producer_thread_id == CurrentThreadId());
  CHECK(header.consumer_thread_id != 0U);
  CHECK(header.consumer_thread_id != header.producer_thread_id);
  CHECK(header.process_id == GetCurrentProcessId());
  CHECK(header.process_start_filetime != 0U);
  CHECK(header.lifecycle_state ==
        ObservationEvidenceLifecycleState::completed);
  CHECK(header.terminal_failure_code == 0U);
  CHECK(header.capture_start_filetime != 0U);
  CHECK(header.last_commit_filetime >= header.capture_start_filetime);
  CHECK(header.completion_filetime == header.last_commit_filetime);
  CHECK(header.heartbeat_count != 0U);
  CHECK(header.active_start_tick_milliseconds != 0U);
  CHECK(header.last_commit_tick_milliseconds >=
        header.active_start_tick_milliseconds);
  CHECK(std::string(header.module_version) ==
        "0.4.0-observation-evidence");
  CHECK(header.first_sequence == 1U);
  CHECK(header.last_sequence == events.size());
  CHECK(events[0].kind == ObservationEventKind::tick);
  CHECK(events[1].kind ==
        ObservationEventKind::local_action_state_transition);
  CHECK(events[2].kind ==
        ObservationEventKind::send60_serialization_attempt);
  CHECK(events[0].sequence == 1U);
  CHECK(events[1].sequence == 2U);
  CHECK(events[2].sequence == 3U);
}

void TestNamedFinalizeDrainsSignalsCompletionAndStops() {
  using namespace psobb::gameplay;
  TemporaryLayout layout;
  auto session = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(session->Prepare(
      layout.module_path().native(), kRunId, failure));

  ObservationRing ring(CurrentThreadId);
  CHECK(ring.BindProducerThread());
  CHECK(session->Start(ring, RecordWorkerFailure, failure));
  CHECK(session->Activate(failure));
  CHECK(ring.TryRecordTick(700U));

  std::uint32_t process_id = 0U;
  std::uint64_t process_start_filetime = 0U;
  CHECK(CurrentProcessIdentity(process_id, process_start_filetime));
  ObservationEvidenceControlEventNames names{};
  CHECK(ObservationEvidenceSession::BuildControlEventNames(
      process_id, process_start_filetime, names));

  HANDLE finalize = OpenEventW(
      EVENT_MODIFY_STATE | SYNCHRONIZE,
      FALSE,
      names.finalize.data());
  HANDLE completion = OpenEventW(
      SYNCHRONIZE,
      FALSE,
      names.completion.data());
  CHECK(finalize != nullptr);
  CHECK(completion != nullptr);

  const std::uint64_t finalize_tick = GetTickCount64();
  CHECK(finalize != nullptr && SetEvent(finalize) != FALSE);
  CHECK(completion != nullptr &&
        WaitForSingleObject(completion, 5'000U) == WAIT_OBJECT_0);
  const std::uint64_t completion_observed_tick = GetTickCount64();
  CHECK(completion != nullptr &&
        WaitForSingleObject(completion, 0U) == WAIT_OBJECT_0);
  CHECK(session->StopAndJoin(failure));

  if (completion != nullptr) {
    CloseHandle(completion);
  }
  if (finalize != nullptr) {
    CloseHandle(finalize);
  }

  std::ifstream stream(layout.partial_path(), std::ios::binary);
  ObservationEvidenceHeaderV1 header{};
  stream.read(reinterpret_cast<char*>(&header), sizeof(header));
  CHECK(stream.good());
  CHECK(header.lifecycle_state ==
        ObservationEvidenceLifecycleState::completed);
  CHECK(header.terminal_failure_code == 0U);
  CHECK(header.committed_event_count == 1U);
  CHECK(header.active_start_tick_milliseconds != 0U);
  CHECK(header.last_commit_tick_milliseconds >= finalize_tick);
  CHECK(header.last_commit_tick_milliseconds <= completion_observed_tick);
  CHECK(header.last_commit_tick_milliseconds >=
        header.active_start_tick_milliseconds);
}

void TestPreparedSessionCanBeCancelledWithoutWorker() {
  using psobb::gameplay::ObservationEvidenceSession;
  TemporaryLayout layout;
  auto session = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(session->Prepare(
      layout.module_path().native(), kRunId, failure));
  CHECK(session->StopAndJoin(failure));
  CHECK(!session->prepared());
  CHECK(!session->owns_consumer());
  CHECK(std::filesystem::exists(layout.partial_path()));
}

void TestActivationFailureIsTerminalAndReleasesConsumer() {
  using namespace psobb::gameplay;
  TemporaryLayout layout;
  auto session = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(session->Prepare(
      layout.module_path().native(), kRunId, failure));
  ObservationRing ring(CurrentThreadId);
  CHECK(session->Start(ring, RecordWorkerFailure, failure));
  ObservationEvidenceSessionTestAccess::InvalidateEvidenceFile(*session);
  CHECK(!session->Activate(failure));
  CHECK(!failure.empty());
  CHECK(session->worker_failure() ==
        ObservationEvidenceFailure::active_header_write_failed);
  CHECK(session->StopAndJoin(failure));
  CHECK(!failure.empty());
  CHECK(!session->owns_consumer());
  ObservationSnapshotV1 snapshot{};
  CHECK(ring.Drain(snapshot));
}

void TestCallerFailurePersistsAsFailedLifecycle() {
  using namespace psobb::gameplay;
  TemporaryLayout layout;
  auto session = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(session->Prepare(
      layout.module_path().native(), kRunId, failure));
  ObservationRing ring(CurrentThreadId);
  CHECK(session->Start(ring, RecordWorkerFailure, failure));
  ObservationEvidenceSessionTestAccess::ReportCallerFailure(
      *session, ObservationEvidenceFailure::activation_wait_failed);
  CHECK(session->StopAndJoin(failure));
  CHECK(!failure.empty());

  std::ifstream stream(layout.partial_path(), std::ios::binary);
  ObservationEvidenceHeaderV1 header{};
  stream.read(reinterpret_cast<char*>(&header), sizeof(header));
  CHECK(stream.good());
  CHECK(header.lifecycle_state == ObservationEvidenceLifecycleState::failed);
  CHECK(header.terminal_failure_code == static_cast<std::uint32_t>(
        ObservationEvidenceFailure::activation_wait_failed));
  CHECK(header.completion_filetime == header.last_commit_filetime);
  CHECK(header.committed_event_count == 0U);
}

void TestCallerFailureAfterActivationRemainsFailed() {
  using namespace psobb::gameplay;
  TemporaryLayout layout;
  auto session = std::make_unique<ObservationEvidenceSession>();
  std::wstring failure;
  CHECK(session->Prepare(
      layout.module_path().native(), kRunId, failure));
  ObservationRing ring(CurrentThreadId);
  CHECK(session->Start(ring, RecordWorkerFailure, failure));
  CHECK(session->Activate(failure));
  ObservationEvidenceSessionTestAccess::ReportCallerFailure(
      *session, ObservationEvidenceFailure::activation_wait_failed);
  CHECK(session->StopAndJoin(failure));

  std::ifstream stream(layout.partial_path(), std::ios::binary);
  ObservationEvidenceHeaderV1 header{};
  stream.read(reinterpret_cast<char*>(&header), sizeof(header));
  CHECK(stream.good());
  CHECK(header.lifecycle_state == ObservationEvidenceLifecycleState::failed);
  CHECK(header.terminal_failure_code == static_cast<std::uint32_t>(
        ObservationEvidenceFailure::activation_wait_failed));
}

}  // namespace

int main() {
  TestRunIdValidation();
  TestControlEventNameDerivation();
  TestPreexistingControlEventsAreRejected();
  TestPrepareRejectsWrongLayoutAndNoClobber();
  TestPrepareRequiresExistingExactDirectories();
  TestWorkerDrainsAndCommits();
  TestNamedFinalizeDrainsSignalsCompletionAndStops();
  TestPreparedSessionCanBeCancelledWithoutWorker();
  TestActivationFailureIsTerminalAndReleasesConsumer();
  TestCallerFailurePersistsAsFailedLifecycle();
  TestCallerFailureAfterActivationRemainsFailed();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.Gameplay evidence-session tests passed\n";
  return 0;
}
