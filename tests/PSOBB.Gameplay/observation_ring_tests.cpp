#include "observation_ring.h"

#include "psobb_gameplay/observation.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <thread>
#include <type_traits>
#include <utility>

std::atomic_bool g_track_allocations{false};
std::atomic_uint64_t g_allocation_count{0U};
std::atomic_uint32_t g_next_test_thread_id{1U};
thread_local const std::uint32_t g_test_thread_id =
    g_next_test_thread_id.fetch_add(1U, std::memory_order_relaxed);

[[nodiscard]] std::uint32_t CurrentTestThreadId() noexcept {
  return g_test_thread_id;
}

[[nodiscard]] std::uint32_t ZeroThreadId() noexcept {
  return 0U;
}

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

struct ObservationRingTestAccess final {
  static void SetCursors(
      ObservationRing& ring,
      const std::uint32_t read_cursor,
      const std::uint32_t write_cursor) noexcept {
    ring.read_cursor_.store(read_cursor, std::memory_order_relaxed);
    ring.write_cursor_.store(write_cursor, std::memory_order_relaxed);
  }

  static void SetCounters(
      ObservationRing& ring,
      const std::uint32_t dropped,
      const std::uint32_t producer_violations) noexcept {
    ring.dropped_event_count_.store(dropped, std::memory_order_relaxed);
    ring.producer_violation_count_.store(
        producer_violations, std::memory_order_relaxed);
  }

  static void SetNextSequence(
      ObservationRing& ring,
      const std::uint64_t next_sequence) noexcept {
    ring.next_sequence_ = next_sequence;
  }

  [[nodiscard]] static bool AcquireConsumerGate(
      ObservationRing& ring) noexcept {
    return !ring.drain_active_.test_and_set(std::memory_order_acquire);
  }

  static void ReleaseConsumerGate(ObservationRing& ring) noexcept {
    ring.drain_active_.clear(std::memory_order_release);
  }
};

}  // namespace psobb::gameplay

namespace {

struct RingFixture final {
  RingFixture() noexcept : ring(CurrentTestThreadId) {}

  psobb::gameplay::ObservationRing ring;
  psobb::gameplay::ObservationSnapshotV1 snapshot{};
};

int g_failures = 0;

void Check(const bool condition, const char* expression) {
  if (!condition) {
    std::cerr << "FAIL: " << expression << '\n';
    ++g_failures;
  }
}

#define CHECK(expression) Check((expression), #expression)

void TestAbiLayout() {
  using namespace psobb::gameplay;
  static_assert(std::is_standard_layout_v<ObservationEventV1>);
  static_assert(std::is_trivially_copyable_v<ObservationEventV1>);
  static_assert(std::is_standard_layout_v<ObservationSnapshotV1>);
  static_assert(std::is_trivially_copyable_v<ObservationSnapshotV1>);
  static_assert(sizeof(ObservationEventV1) == 32U);
  static_assert(sizeof(ObservationSnapshotV1) == 65'568U);
  static_assert(offsetof(ObservationSnapshotV1, events) == 32U);
  static_assert(!std::is_copy_constructible_v<ObservationRing>);
  static_assert(!std::is_move_constructible_v<ObservationRing>);
  static_assert(noexcept(std::declval<ObservationRing&>().TryRecordTick(
      std::uint32_t{})));
  static_assert(noexcept(std::declval<ObservationRing&>().Drain(
      std::declval<ObservationSnapshotV1&>())));

  CHECK(kObservationRingCapacity == 2048U);
  CHECK(kObservationAbiVersion == 1U);
}

void TestBindingAndTypedRecords() {
  using namespace psobb::gameplay;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;

  CHECK(!ring.TryRecordTick(1U));
  const auto invalid_provider =
      std::make_unique<ObservationRing>(ZeroThreadId);
  CHECK(!invalid_provider->BindProducerThread());
  CHECK(ring.BindProducerThread());
  CHECK(ring.BindProducerThread());
  std::atomic_bool wrong_bind_result{true};
  std::atomic_bool wrong_record_result{true};
  std::thread wrong_producer([&]() {
    wrong_bind_result.store(
        ring.BindProducerThread(), std::memory_order_release);
    wrong_record_result.store(
        ring.TryRecordTick(2U), std::memory_order_release);
  });
  wrong_producer.join();
  CHECK(!wrong_bind_result.load(std::memory_order_acquire));
  CHECK(!wrong_record_result.load(std::memory_order_acquire));

  CHECK(ring.TryRecordTick(10U));
  CHECK(ring.TryRecordLocalStateTransition(
      11U, 0x1234U, 7U, 8U));
  CHECK(ring.TryRecordOutboundHeader(
      12U, 0x1234U, 0x44332211U, 36U));

  ObservationSnapshotV1& snapshot = fixture->snapshot;
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.struct_size == sizeof(snapshot));
  CHECK(snapshot.abi_version == kObservationAbiVersion);
  CHECK(snapshot.ring_capacity == kObservationRingCapacity);
  CHECK(snapshot.event_count == 3U);
  CHECK(snapshot.dropped_event_count == 0U);
  CHECK(snapshot.producer_violation_count == 3U);
  CHECK(snapshot.producer_thread_id == CurrentTestThreadId());
  CHECK(snapshot.reserved == 0U);

  const ObservationEventV1& tick = snapshot.events[0];
  CHECK(tick.sequence == 1U);
  CHECK(tick.client_tick == 10U);
  CHECK(tick.kind == ObservationEventKind::tick);
  CHECK(tick.local_client_id == kNoLocalClientId);
  CHECK(tick.previous_action_state == 0U);
  CHECK(tick.next_action_state == 0U);
  CHECK(tick.subcommand_header_le == 0U);
  CHECK(tick.subcommand_byte_count == 0U);

  const ObservationEventV1& transition = snapshot.events[1];
  CHECK(transition.sequence == 2U);
  CHECK(transition.client_tick == 11U);
  CHECK(transition.kind ==
        ObservationEventKind::local_action_state_transition);
  CHECK(transition.local_client_id == 0x1234U);
  CHECK(transition.previous_action_state == 7U);
  CHECK(transition.next_action_state == 8U);
  CHECK(transition.subcommand_header_le == 0U);
  CHECK(transition.subcommand_byte_count == 0U);

  const ObservationEventV1& outbound = snapshot.events[2];
  CHECK(outbound.sequence == 3U);
  CHECK(outbound.client_tick == 12U);
  CHECK(outbound.kind ==
        ObservationEventKind::outbound_subcommand_header);
  CHECK(outbound.local_client_id == 0x1234U);
  CHECK(outbound.previous_action_state == 0U);
  CHECK(outbound.next_action_state == 0U);
  CHECK(outbound.subcommand_header_le == 0x44332211U);
  CHECK(outbound.subcommand_byte_count == 36U);

  snapshot.events[0].sequence = 999U;
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 0U);
  CHECK(snapshot.events[0].sequence == 0U);
  CHECK(snapshot.producer_violation_count == 3U);
}

void TestCapacityDropAndReuse() {
  using namespace psobb::gameplay;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;
  CHECK(ring.BindProducerThread());

  for (std::uint32_t index = 0U;
       index < kObservationRingCapacity;
       ++index) {
    CHECK(ring.TryRecordTick(index));
  }
  CHECK(!ring.TryRecordTick(kObservationRingCapacity));

  ObservationSnapshotV1& snapshot = fixture->snapshot;
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == kObservationRingCapacity);
  CHECK(snapshot.dropped_event_count == 1U);
  CHECK(snapshot.events[0].sequence == 1U);
  CHECK(snapshot.events[0].client_tick == 0U);
  CHECK(snapshot.events[kObservationRingCapacity - 1U].sequence ==
        kObservationRingCapacity);
  CHECK(snapshot.events[kObservationRingCapacity - 1U].client_tick ==
        kObservationRingCapacity - 1U);

  CHECK(ring.TryRecordTick(99U));
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 1U);
  CHECK(snapshot.dropped_event_count == 1U);
  CHECK(snapshot.events[0].sequence ==
        static_cast<std::uint64_t>(kObservationRingCapacity) + 1U);
  CHECK(snapshot.events[0].client_tick == 99U);
}

void TestRecordAndDrainDoNotAllocate() {
  using namespace psobb::gameplay;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;
  ObservationSnapshotV1& snapshot = fixture->snapshot;
  CHECK(ring.BindProducerThread());

  g_allocation_count.store(0U, std::memory_order_relaxed);
  g_track_allocations.store(true, std::memory_order_release);
  const bool tick_recorded = ring.TryRecordTick(1U);
  const bool transition_recorded = ring.TryRecordLocalStateTransition(
      2U, 0U, 3U, 4U);
  const bool outbound_recorded = ring.TryRecordOutboundHeader(
      3U, 0U, 0x04030201U, 12U);
  const bool drained = ring.Drain(snapshot);
  g_track_allocations.store(false, std::memory_order_release);

  CHECK(tick_recorded);
  CHECK(transition_recorded);
  CHECK(outbound_recorded);
  CHECK(drained);
  CHECK(snapshot.event_count == 3U);
  CHECK(g_allocation_count.load(std::memory_order_acquire) == 0U);
}

void TestIndexWrapAndQuiescentReset() {
  using namespace psobb::gameplay;
  constexpr std::uint32_t kCycles = 6U;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;
  ObservationSnapshotV1& snapshot = fixture->snapshot;
  CHECK(ring.BindProducerThread());

  for (std::uint32_t cycle = 0U; cycle < kCycles; ++cycle) {
    const std::uint32_t first_tick =
        cycle * kObservationRingCapacity;
    for (std::uint32_t index = 0U;
         index < kObservationRingCapacity;
         ++index) {
      CHECK(ring.TryRecordTick(first_tick + index));
    }
    CHECK(ring.Drain(snapshot));
    CHECK(snapshot.event_count == kObservationRingCapacity);
    CHECK(snapshot.events[0].sequence ==
          static_cast<std::uint64_t>(first_tick) + 1U);
    CHECK(snapshot.events[0].client_tick == first_tick);
    CHECK(snapshot.events[kObservationRingCapacity - 1U].sequence ==
          static_cast<std::uint64_t>(first_tick) +
              kObservationRingCapacity);
  }
  CHECK(snapshot.dropped_event_count == 0U);

  CHECK(ring.TryRecordTick(500U));
  CHECK(ring.TryResetQuiescent());
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 0U);
  CHECK(snapshot.dropped_event_count == 0U);
  CHECK(snapshot.producer_violation_count == 0U);
  CHECK(snapshot.producer_thread_id == 0U);

  CHECK(!ring.TryRecordTick(501U));
  CHECK(ring.BindProducerThread());
  CHECK(ring.TryRecordTick(502U));
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 1U);
  CHECK(snapshot.producer_violation_count == 1U);
  CHECK(snapshot.events[0].sequence == 1U);
  CHECK(snapshot.events[0].client_tick == 502U);
}

void TestCursorSequenceAndCounterBoundaries() {
  using namespace psobb::gameplay;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;
  ObservationSnapshotV1& snapshot = fixture->snapshot;
  CHECK(ring.BindProducerThread());

  constexpr std::uint32_t kCursorStart =
      std::numeric_limits<std::uint32_t>::max() - 7U;
  ObservationRingTestAccess::SetCursors(
      ring, kCursorStart, kCursorStart);
  for (std::uint32_t index = 0U; index < 16U; ++index) {
    CHECK(ring.TryRecordTick(1'000U + index));
  }
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 16U);
  for (std::uint32_t index = 0U; index < 16U; ++index) {
    CHECK(snapshot.events[index].sequence == index + 1U);
    CHECK(snapshot.events[index].client_tick == 1'000U + index);
  }

  ObservationRingTestAccess::SetNextSequence(
      ring, std::numeric_limits<std::uint64_t>::max());
  CHECK(ring.TryRecordTick(2'000U));
  CHECK(!ring.TryRecordTick(2'001U));
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 1U);
  CHECK(snapshot.events[0].sequence ==
        std::numeric_limits<std::uint64_t>::max());
  CHECK(snapshot.dropped_event_count == 1U);

  CHECK(ring.TryResetQuiescent());
  CHECK(ring.BindProducerThread());
  ObservationRingTestAccess::SetCounters(
      ring,
      std::numeric_limits<std::uint32_t>::max() - 1U,
      std::numeric_limits<std::uint32_t>::max() - 1U);
  for (std::uint32_t index = 0U;
       index < kObservationRingCapacity;
       ++index) {
    CHECK(ring.TryRecordTick(index));
  }
  CHECK(!ring.TryRecordTick(kObservationRingCapacity));
  CHECK(!ring.TryRecordTick(kObservationRingCapacity + 1U));

  std::atomic_bool wrong_record_one{true};
  std::atomic_bool wrong_record_two{true};
  std::thread wrong_producer([&]() {
    wrong_record_one.store(
        ring.TryRecordTick(3'000U), std::memory_order_release);
    wrong_record_two.store(
        ring.TryRecordTick(3'001U), std::memory_order_release);
  });
  wrong_producer.join();
  CHECK(!wrong_record_one.load(std::memory_order_acquire));
  CHECK(!wrong_record_two.load(std::memory_order_acquire));
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.dropped_event_count ==
        std::numeric_limits<std::uint32_t>::max());
  CHECK(snapshot.producer_violation_count ==
        std::numeric_limits<std::uint32_t>::max());
}

void TestConsumerGateRejectsConcurrentDrainAndReset() {
  using namespace psobb::gameplay;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;
  ObservationSnapshotV1& snapshot = fixture->snapshot;
  CHECK(ring.BindProducerThread());
  CHECK(ring.TryRecordTick(77U));
  CHECK(ObservationRingTestAccess::AcquireConsumerGate(ring));

  snapshot.struct_size = 123U;
  CHECK(!ring.Drain(snapshot));
  CHECK(snapshot.struct_size == 123U);
  CHECK(!ring.TryResetQuiescent());

  ObservationRingTestAccess::ReleaseConsumerGate(ring);
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 1U);
  CHECK(snapshot.events[0].client_tick == 77U);
  CHECK(ring.TryResetQuiescent());
  CHECK(ring.Drain(snapshot));
  CHECK(snapshot.event_count == 0U);
}

void TestConcurrentSpscOrdering() {
  using namespace psobb::gameplay;
  constexpr std::uint32_t kEventTotal = 50'000U;
  auto fixture = std::make_unique<RingFixture>();
  ObservationRing& ring = fixture->ring;
  std::atomic_bool start{false};
  std::atomic_bool abort{false};
  std::atomic_bool producer_bound{false};
  std::atomic_bool producer_done{false};
  std::atomic_uint32_t producer_thread_id{0U};
  std::atomic_uint32_t thread_failures{0U};
  std::atomic_uint32_t consumed_events{0U};

  std::thread producer([&]() {
    producer_thread_id.store(
        CurrentTestThreadId(), std::memory_order_release);
    if (!ring.BindProducerThread()) {
      thread_failures.fetch_add(1U, std::memory_order_relaxed);
      abort.store(true, std::memory_order_release);
      return;
    }
    producer_bound.store(true, std::memory_order_release);
    while (!start.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    for (std::uint32_t tick = 1U; tick <= kEventTotal; ++tick) {
      while (!ring.TryRecordTick(tick)) {
        if (abort.load(std::memory_order_acquire)) {
          return;
        }
        std::this_thread::yield();
      }
    }
    producer_done.store(true, std::memory_order_release);
  });

  std::thread consumer([&]() {
    ObservationSnapshotV1& snapshot = fixture->snapshot;
    std::uint32_t consumed = 0U;
    std::uint64_t expected_sequence = 1U;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!start.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    while (consumed < kEventTotal) {
      if (std::chrono::steady_clock::now() >= deadline) {
        thread_failures.fetch_add(1U, std::memory_order_relaxed);
        abort.store(true, std::memory_order_release);
        return;
      }
      if (!ring.Drain(snapshot)) {
        thread_failures.fetch_add(1U, std::memory_order_relaxed);
        abort.store(true, std::memory_order_release);
        return;
      }
      for (std::uint32_t index = 0U;
           index < snapshot.event_count;
           ++index) {
        const ObservationEventV1& event = snapshot.events[index];
        if (event.sequence != expected_sequence ||
            event.client_tick != consumed + 1U ||
            event.kind != ObservationEventKind::tick ||
            event.local_client_id != kNoLocalClientId) {
          thread_failures.fetch_add(1U, std::memory_order_relaxed);
          abort.store(true, std::memory_order_release);
          return;
        }
        ++expected_sequence;
        ++consumed;
      }
      if (snapshot.event_count == 0U) {
        std::this_thread::yield();
      }
    }
    consumed_events.store(consumed, std::memory_order_release);
  });

  start.store(true, std::memory_order_release);
  consumer.join();
  abort.store(true, std::memory_order_release);
  producer.join();

  CHECK(thread_failures.load(std::memory_order_acquire) == 0U);
  CHECK(producer_bound.load(std::memory_order_acquire));
  CHECK(producer_done.load(std::memory_order_acquire));
  CHECK(consumed_events.load(std::memory_order_acquire) == kEventTotal);

  ObservationSnapshotV1& final_snapshot = fixture->snapshot;
  CHECK(ring.Drain(final_snapshot));
  CHECK(final_snapshot.event_count == 0U);
  CHECK(final_snapshot.producer_violation_count == 0U);
  CHECK(final_snapshot.producer_thread_id ==
        producer_thread_id.load(std::memory_order_acquire));
}

}  // namespace

int main() {
  TestAbiLayout();
  TestBindingAndTypedRecords();
  TestCapacityDropAndReuse();
  TestRecordAndDrainDoNotAllocate();
  TestIndexWrapAndQuiescentReset();
  TestCursorSequenceAndCounterBoundaries();
  TestConsumerGateRejectsConcurrentDrainAndReset();
  TestConcurrentSpscOrdering();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.Gameplay observation-ring tests passed\n";
  return 0;
}
