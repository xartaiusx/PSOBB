#include "observation_evidence_accumulator.h"

#include "psobb_gameplay/observation_evidence.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <span>
#include <type_traits>
#include <utility>

std::atomic_bool g_track_allocations{false};
std::atomic_uint64_t g_allocation_count{0U};

_NODISCARD _Ret_notnull_ _Post_writable_byte_size_(size) _VCRT_ALLOCATOR
void* __CRTDECL operator new(std::size_t size) {
  if (g_track_allocations.load(std::memory_order_relaxed)) {
    g_allocation_count.fetch_add(1U, std::memory_order_relaxed);
  }
  if (size == 0U) {
    size = 1U;
  }
  if (void* const memory = std::malloc(size); memory != nullptr) {
    return memory;
  }
  throw std::bad_alloc{};
}

_NODISCARD _Ret_notnull_ _Post_writable_byte_size_(size) _VCRT_ALLOCATOR
void* __CRTDECL operator new[](const std::size_t size) {
  return ::operator new(size);
}

void __CRTDECL operator delete(void* const memory) noexcept {
  std::free(memory);
}

void __CRTDECL operator delete[](void* const memory) noexcept {
  ::operator delete(memory);
}

void __CRTDECL operator delete(
    void* const memory,
    const std::size_t) noexcept {
  ::operator delete(memory);
}

void __CRTDECL operator delete[](
    void* const memory,
    const std::size_t) noexcept {
  ::operator delete(memory);
}

namespace psobb::gameplay {

struct ObservationEvidenceAccumulatorTestAccess final {
  static void SetCounters(
      ObservationEvidenceAccumulator& accumulator,
      const std::uint64_t total_drained,
      const std::uint64_t ring_dropped,
      const std::uint64_t producer_violations,
      const std::uint64_t capacity_dropped) noexcept {
    accumulator.header_.total_drained_event_count = total_drained;
    accumulator.header_.ring_dropped_event_count = ring_dropped;
    accumulator.header_.producer_violation_count = producer_violations;
    accumulator.header_.evidence_capacity_dropped_event_count =
        capacity_dropped;
  }

  static void SetCommittedCount(
      ObservationEvidenceAccumulator& accumulator,
      const std::uint32_t committed) noexcept {
    accumulator.header_.committed_event_count = committed;
  }

  static void SetLastCumulativeCounters(
      ObservationEvidenceAccumulator& accumulator,
      const std::uint32_t ring_dropped,
      const std::uint32_t producer_violations) noexcept {
    accumulator.last_ring_dropped_event_count_ = ring_dropped;
    accumulator.last_producer_violation_count_ = producer_violations;
  }

  static void SetEvent(
      ObservationEvidenceAccumulator& accumulator,
      const std::uint32_t index,
      const ObservationEventV1 event) noexcept {
    accumulator.events_[index] = event;
  }

  static void RestoreHeaderAfterPayloadFailure(
      ObservationEvidenceAccumulator& accumulator,
      const ObservationEvidenceHeaderV1& previous_header) noexcept {
    accumulator.RestoreHeaderAfterPayloadFailure(previous_header);
  }
};

}  // namespace psobb::gameplay

namespace {

int g_failures = 0;

void Check(const bool condition, const char* expression) {
  if (!condition) {
    std::cerr << "FAIL: " << expression << '\n';
    ++g_failures;
  }
}

#define CHECK(expression) Check((expression), #expression)

[[nodiscard]] psobb::gameplay::ObservationEvidenceSessionIdentity
MakeIdentity() noexcept {
  psobb::gameplay::ObservationEvidenceSessionIdentity identity{};
  for (std::uint32_t index = 0U;
       index < identity.exact_client_sha256.size();
       ++index) {
    identity.exact_client_sha256[index] =
        static_cast<std::uint8_t>(index + 1U);
  }
  constexpr char kVersion[] = "test-observation-evidence";
  std::copy(
      std::begin(kVersion),
      std::end(kVersion),
      identity.module_version.begin());
  identity.consumer_thread_id = 0x10203040U;
  identity.process_id = 0x50607080U;
  identity.process_start_filetime = 0x0123456789ABCDEFULL;
  return identity;
}

void InitializeSnapshot(
    psobb::gameplay::ObservationSnapshotV1& snapshot,
    const std::uint32_t producer_thread_id = 0xA0B0C0D0U) noexcept {
  snapshot = {};
  snapshot.struct_size = sizeof(snapshot);
  snapshot.abi_version = psobb::gameplay::kObservationAbiVersion;
  snapshot.ring_capacity = psobb::gameplay::kObservationRingCapacity;
  snapshot.producer_thread_id = producer_thread_id;
}

void FillTickEvents(
    psobb::gameplay::ObservationSnapshotV1& snapshot,
    const std::uint32_t event_count,
    const std::uint64_t first_sequence) noexcept {
  snapshot.event_count = event_count;
  for (std::uint32_t index = 0U; index < event_count; ++index) {
    psobb::gameplay::ObservationEventV1& event = snapshot.events[index];
    event = {};
    event.sequence = first_sequence + index;
    event.client_tick = index;
    event.kind = psobb::gameplay::ObservationEventKind::tick;
    event.local_client_id = psobb::gameplay::kNoLocalClientId;
  }
}

void TestContractLayoutAndInitialization() {
  using namespace psobb::gameplay;
  static_assert(std::is_standard_layout_v<ObservationEvidenceHeaderV1>);
  static_assert(std::is_trivially_copyable_v<ObservationEvidenceHeaderV1>);
  static_assert(sizeof(ObservationEvidenceHeaderV1) == 256U);
  static_assert(
      offsetof(
          ObservationEvidenceHeaderV1,
          active_start_tick_milliseconds) == 224U);
  static_assert(
      offsetof(
          ObservationEvidenceHeaderV1,
          last_commit_tick_milliseconds) == 232U);
  static_assert(offsetof(ObservationEvidenceHeaderV1, reserved) == 240U);
  static_assert(kObservationEvidenceMaximumFileSize == 524'544U);
  static_assert(kObservationEvidenceMaximumFileSize < 1024U * 1024U);
  static_assert(!std::is_copy_constructible_v<ObservationEvidenceAccumulator>);
  static_assert(!std::is_move_constructible_v<ObservationEvidenceAccumulator>);
  static_assert(noexcept(std::declval<ObservationEvidenceAccumulator&>().Append(
      std::declval<const ObservationSnapshotV1&>())));
  static_assert(noexcept(
      std::declval<const ObservationEvidenceAccumulator&>().Header()));
  static_assert(noexcept(
      std::declval<const ObservationEvidenceAccumulator&>().CommittedEvents()));
  static_assert(noexcept(
      std::declval<const ObservationEvidenceAccumulator&>().CommittedFileSize()));

  const ObservationEvidenceSessionIdentity identity = MakeIdentity();
  const auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(identity);
  const ObservationEvidenceHeaderV1& header = accumulator->Header();

  CHECK(std::equal(
      std::begin(header.magic),
      std::end(header.magic),
      std::begin(kObservationEvidenceMagic)));
  CHECK(header.struct_size == sizeof(header));
  CHECK(header.format_version == kObservationEvidenceFormatVersion);
  CHECK(header.byte_order_marker == kObservationEvidenceByteOrderMarker);
  CHECK(header.maximum_file_size == kObservationEvidenceMaximumFileSize);
  CHECK(header.event_abi_version == kObservationAbiVersion);
  CHECK(header.event_record_size == sizeof(ObservationEventV1));
  CHECK(header.event_capacity == kObservationEvidenceEventCapacity);
  CHECK(header.committed_event_count == 0U);
  CHECK(header.client_identity_version ==
        kObservationEvidenceClientIdentityVersion);
  CHECK(header.client_sha256_byte_count ==
        kObservationEvidenceSha256ByteCount);
  CHECK(header.total_drained_event_count == 0U);
  CHECK(header.ring_dropped_event_count == 0U);
  CHECK(header.producer_violation_count == 0U);
  CHECK(header.evidence_capacity_dropped_event_count == 0U);
  CHECK(header.producer_thread_id == 0U);
  CHECK(header.consumer_thread_id == identity.consumer_thread_id);
  CHECK(header.process_id == identity.process_id);
  CHECK(header.reserved0 == 0U);
  CHECK(header.process_start_filetime == identity.process_start_filetime);
  CHECK(header.first_sequence == 0U);
  CHECK(header.last_sequence == 0U);
  CHECK(std::equal(
      std::begin(header.exact_client_sha256),
      std::end(header.exact_client_sha256),
      identity.exact_client_sha256.begin()));
  CHECK(std::equal(
      std::begin(header.module_version),
      std::end(header.module_version),
      identity.module_version.begin()));
  CHECK(header.lifecycle_state ==
        ObservationEvidenceLifecycleState::uninitialized);
  CHECK(header.terminal_failure_code == 0U);
  CHECK(header.capture_start_filetime == 0U);
  CHECK(header.last_commit_filetime == 0U);
  CHECK(header.completion_filetime == 0U);
  CHECK(header.heartbeat_count == 0U);
  CHECK(header.active_start_tick_milliseconds == 0U);
  CHECK(header.last_commit_tick_milliseconds == 0U);
  CHECK(std::all_of(
      std::begin(header.reserved),
      std::end(header.reserved),
      [](const std::uint8_t value) { return value == 0U; }));
  CHECK(accumulator->CommittedEvents().empty());
  CHECK(accumulator->CommittedFileSize() == sizeof(header));
}

void TestLifecycleMarkers() {
  using namespace psobb::gameplay;
  auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());

  accumulator->MarkReady(100U);
  CHECK(accumulator->Header().lifecycle_state ==
        ObservationEvidenceLifecycleState::ready);
  CHECK(accumulator->Header().capture_start_filetime == 100U);
  CHECK(accumulator->Header().last_commit_filetime == 100U);

  accumulator->MarkHeartbeat(150U, 1'500U);
  CHECK(accumulator->Header().last_commit_filetime == 100U);
  CHECK(accumulator->Header().heartbeat_count == 0U);
  CHECK(accumulator->Header().active_start_tick_milliseconds == 0U);
  CHECK(accumulator->Header().last_commit_tick_milliseconds == 0U);

  accumulator->MarkActive(200U, 2'000U);
  accumulator->MarkHeartbeat(300U, 3'000U);
  CHECK(accumulator->Header().lifecycle_state ==
        ObservationEvidenceLifecycleState::active);
  CHECK(accumulator->Header().last_commit_filetime == 300U);
  CHECK(accumulator->Header().heartbeat_count == 2U);
  CHECK(accumulator->Header().active_start_tick_milliseconds == 2'000U);
  CHECK(accumulator->Header().last_commit_tick_milliseconds == 3'000U);

  accumulator->MarkCompleted(400U, 4'000U);
  CHECK(accumulator->Header().lifecycle_state ==
        ObservationEvidenceLifecycleState::completed);
  CHECK(accumulator->Header().completion_filetime == 400U);
  CHECK(accumulator->Header().terminal_failure_code == 0U);
  CHECK(accumulator->Header().active_start_tick_milliseconds == 2'000U);
  CHECK(accumulator->Header().last_commit_tick_milliseconds == 4'000U);

  accumulator->MarkFailed(9U, 500U, 5'000U);
  CHECK(accumulator->Header().lifecycle_state ==
        ObservationEvidenceLifecycleState::failed);
  CHECK(accumulator->Header().terminal_failure_code == 9U);
  CHECK(accumulator->Header().last_commit_filetime == 500U);
  CHECK(accumulator->Header().completion_filetime == 500U);
  CHECK(accumulator->Header().active_start_tick_milliseconds == 2'000U);
  CHECK(accumulator->Header().last_commit_tick_milliseconds == 5'000U);
}

void TestAppendAndCumulativeCounters() {
  using namespace psobb::gameplay;
  auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());
  auto snapshot = std::make_unique<ObservationSnapshotV1>();
  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 3U, 100U);
  snapshot->dropped_event_count = 4U;
  snapshot->producer_violation_count = 2U;

  CHECK(accumulator->Append(*snapshot));
  const ObservationEvidenceHeaderV1& first_header = accumulator->Header();
  CHECK(first_header.committed_event_count == 3U);
  CHECK(first_header.total_drained_event_count == 3U);
  CHECK(first_header.ring_dropped_event_count == 4U);
  CHECK(first_header.producer_violation_count == 2U);
  CHECK(first_header.evidence_capacity_dropped_event_count == 0U);
  CHECK(first_header.producer_thread_id == snapshot->producer_thread_id);
  CHECK(first_header.first_sequence == 100U);
  CHECK(first_header.last_sequence == 102U);
  CHECK(accumulator->CommittedFileSize() ==
        sizeof(ObservationEvidenceHeaderV1) +
            3U * sizeof(ObservationEventV1));

  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 2U, 103U);
  snapshot->dropped_event_count = 7U;
  snapshot->producer_violation_count = 2U;
  CHECK(accumulator->Append(*snapshot));

  const ObservationEvidenceHeaderV1& second_header = accumulator->Header();
  CHECK(second_header.committed_event_count == 5U);
  CHECK(second_header.total_drained_event_count == 5U);
  CHECK(second_header.ring_dropped_event_count == 7U);
  CHECK(second_header.producer_violation_count == 2U);
  CHECK(second_header.first_sequence == 100U);
  CHECK(second_header.last_sequence == 104U);
  const std::span<const ObservationEventV1> events =
      accumulator->CommittedEvents();
  CHECK(events.size() == 5U);
  for (std::uint32_t index = 0U; index < events.size(); ++index) {
    CHECK(events[index].sequence == 100U + index);
  }

  InitializeSnapshot(*snapshot);
  snapshot->dropped_event_count = 1U;
  snapshot->producer_violation_count = 1U;
  CHECK(accumulator->Append(*snapshot));
  CHECK(accumulator->Header().ring_dropped_event_count == 8U);
  CHECK(accumulator->Header().producer_violation_count == 3U);
}

void TestCapacityAndCommittedBoundary() {
  using namespace psobb::gameplay;
  auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());
  auto snapshot = std::make_unique<ObservationSnapshotV1>();
  std::uint64_t next_sequence = 1U;
  for (std::uint32_t batch = 0U; batch < 8U; ++batch) {
    InitializeSnapshot(*snapshot);
    FillTickEvents(*snapshot, kObservationRingCapacity, next_sequence);
    CHECK(accumulator->Append(*snapshot));
    next_sequence += kObservationRingCapacity;
  }
  CHECK(accumulator->Header().committed_event_count ==
        kObservationEvidenceEventCapacity);
  CHECK(accumulator->Header().total_drained_event_count ==
        kObservationEvidenceEventCapacity);
  CHECK(accumulator->CommittedFileSize() ==
        kObservationEvidenceMaximumFileSize);
  CHECK(accumulator->CommittedEvents().back().sequence ==
        kObservationEvidenceEventCapacity);

  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 3U, next_sequence);
  CHECK(accumulator->Append(*snapshot));
  CHECK(accumulator->Header().committed_event_count ==
        kObservationEvidenceEventCapacity);
  CHECK(accumulator->Header().total_drained_event_count ==
        kObservationEvidenceEventCapacity + 3U);
  CHECK(accumulator->Header().evidence_capacity_dropped_event_count == 3U);
  CHECK(accumulator->Header().last_sequence ==
        kObservationEvidenceEventCapacity);
  CHECK(accumulator->CommittedEvents().size() ==
        accumulator->Header().committed_event_count);
  CHECK(accumulator->CommittedFileSize() ==
        kObservationEvidenceMaximumFileSize);

  auto partial =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());
  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 1U, 55U);
  CHECK(partial->Append(*snapshot));
  ObservationEventV1 stale{};
  stale.sequence = 999U;
  ObservationEvidenceAccumulatorTestAccess::SetEvent(*partial, 1U, stale);
  CHECK(partial->CommittedEvents().size() == 1U);
  CHECK(partial->CommittedEvents()[0].sequence == 55U);
  CHECK(partial->CommittedFileSize() ==
        sizeof(ObservationEvidenceHeaderV1) + sizeof(ObservationEventV1));
}

void TestMalformedSnapshotsFailClosed() {
  using namespace psobb::gameplay;
  auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());
  auto snapshot = std::make_unique<ObservationSnapshotV1>();
  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 1U, 1U);

  snapshot->struct_size = 0U;
  CHECK(!accumulator->Append(*snapshot));
  InitializeSnapshot(*snapshot);
  snapshot->abi_version = kObservationAbiVersion + 1U;
  CHECK(!accumulator->Append(*snapshot));
  InitializeSnapshot(*snapshot);
  snapshot->ring_capacity = kObservationRingCapacity - 1U;
  CHECK(!accumulator->Append(*snapshot));
  InitializeSnapshot(*snapshot);
  snapshot->event_count = kObservationRingCapacity + 1U;
  CHECK(!accumulator->Append(*snapshot));
  InitializeSnapshot(*snapshot);
  snapshot->reserved = 1U;
  CHECK(!accumulator->Append(*snapshot));
  CHECK(accumulator->Header().committed_event_count == 0U);
  CHECK(accumulator->Header().total_drained_event_count == 0U);

  InitializeSnapshot(*snapshot, 10U);
  FillTickEvents(*snapshot, 1U, 1U);
  CHECK(accumulator->Append(*snapshot));
  const ObservationEvidenceHeaderV1 before = accumulator->Header();
  InitializeSnapshot(*snapshot, 11U);
  FillTickEvents(*snapshot, 1U, 2U);
  CHECK(!accumulator->Append(*snapshot));
  CHECK(accumulator->Header().committed_event_count ==
        before.committed_event_count);
  CHECK(accumulator->Header().total_drained_event_count ==
        before.total_drained_event_count);
  CHECK(accumulator->Header().last_sequence == before.last_sequence);
}

void TestFailedPayloadCannotAdvanceCommittedBoundary() {
  using namespace psobb::gameplay;
  auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());
  accumulator->MarkReady(100U);
  accumulator->MarkActive(200U, 2'000U);
  const ObservationEvidenceHeaderV1 previous = accumulator->Header();

  auto snapshot = std::make_unique<ObservationSnapshotV1>();
  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 2U, 1U);
  CHECK(accumulator->Append(*snapshot));
  CHECK(accumulator->Header().committed_event_count == 2U);

  ObservationEvidenceAccumulatorTestAccess::RestoreHeaderAfterPayloadFailure(
      *accumulator, previous);
  accumulator->MarkFailed(7U, 300U, 3'000U);
  CHECK(accumulator->Header().committed_event_count == 0U);
  CHECK(accumulator->Header().total_drained_event_count == 0U);
  CHECK(accumulator->Header().first_sequence == 0U);
  CHECK(accumulator->Header().last_sequence == 0U);
  CHECK(accumulator->Header().lifecycle_state ==
        ObservationEvidenceLifecycleState::failed);
  CHECK(accumulator->Header().terminal_failure_code == 7U);
}

void TestCounterSaturationAndAppendDoesNotAllocate() {
  using namespace psobb::gameplay;
  const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
  auto accumulator =
      std::make_unique<ObservationEvidenceAccumulator>(MakeIdentity());
  auto snapshot = std::make_unique<ObservationSnapshotV1>();
  ObservationEvidenceAccumulatorTestAccess::SetCounters(
      *accumulator,
      maximum - 1U,
      maximum - 1U,
      maximum - 1U,
      maximum - 1U);
  ObservationEvidenceAccumulatorTestAccess::SetCommittedCount(
      *accumulator, kObservationEvidenceEventCapacity);
  ObservationEvidenceAccumulatorTestAccess::SetLastCumulativeCounters(
      *accumulator, 10U, 20U);
  InitializeSnapshot(*snapshot);
  FillTickEvents(*snapshot, 2U, 1U);
  snapshot->dropped_event_count = 12U;
  snapshot->producer_violation_count = 22U;

  g_allocation_count.store(0U, std::memory_order_relaxed);
  g_track_allocations.store(true, std::memory_order_release);
  const bool appended = accumulator->Append(*snapshot);
  const ObservationEvidenceHeaderV1& header = accumulator->Header();
  const std::span<const ObservationEventV1> events =
      accumulator->CommittedEvents();
  const std::size_t file_size = accumulator->CommittedFileSize();
  g_track_allocations.store(false, std::memory_order_release);

  CHECK(appended);
  CHECK(header.total_drained_event_count == maximum);
  CHECK(header.ring_dropped_event_count == maximum);
  CHECK(header.producer_violation_count == maximum);
  CHECK(header.evidence_capacity_dropped_event_count == maximum);
  CHECK(events.size() == kObservationEvidenceEventCapacity);
  CHECK(file_size == kObservationEvidenceMaximumFileSize);
  CHECK(g_allocation_count.load(std::memory_order_acquire) == 0U);
}

}  // namespace

int main() {
  TestContractLayoutAndInitialization();
  TestLifecycleMarkers();
  TestAppendAndCumulativeCounters();
  TestCapacityAndCommittedBoundary();
  TestMalformedSnapshotsFailClosed();
  TestFailedPayloadCannotAdvanceCommittedBoundary();
  TestCounterSaturationAndAppendDoesNotAllocate();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout <<
      "All PSOBB.Gameplay observation-evidence accumulator tests passed\n";
  return 0;
}
