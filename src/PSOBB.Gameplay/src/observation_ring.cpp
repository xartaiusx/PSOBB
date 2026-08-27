#include "observation_ring.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace psobb::gameplay {
namespace {

inline constexpr std::uint32_t kRingIndexMask =
    kObservationRingCapacity - 1U;

void SaturatingIncrement(std::atomic<std::uint32_t>& value) noexcept {
  std::uint32_t current = value.load(std::memory_order_relaxed);
  while (current != std::numeric_limits<std::uint32_t>::max() &&
         !value.compare_exchange_weak(
             current,
             current + 1U,
             std::memory_order_relaxed,
             std::memory_order_relaxed)) {
  }
}

}  // namespace

ObservationRing::ObservationRing(
    const ObservationThreadIdProvider thread_id_provider) noexcept
    : thread_id_provider_(thread_id_provider) {}

std::uint32_t ObservationRing::CurrentThreadId() const noexcept {
  return thread_id_provider_ == nullptr ? 0U : thread_id_provider_();
}

bool ObservationRing::BindProducerThread() noexcept {
  const std::uint32_t producer_thread_id = CurrentThreadId();
  if (producer_thread_id == 0U) {
    SaturatingIncrement(producer_violation_count_);
    return false;
  }

  std::uint32_t unbound = 0U;
  if (producer_thread_id_.compare_exchange_strong(
          unbound,
          producer_thread_id,
          std::memory_order_release,
          std::memory_order_acquire)) {
    return true;
  }
  if (unbound == producer_thread_id) {
    return true;
  }

  SaturatingIncrement(producer_violation_count_);
  return false;
}

bool ObservationRing::TryRecordTick(
    const std::uint32_t client_tick) noexcept {
  ObservationEventV1 event{};
  event.client_tick = client_tick;
  event.kind = ObservationEventKind::tick;
  event.local_client_id = kNoLocalClientId;
  return TryRecord(event);
}

bool ObservationRing::TryRecordLocalStateTransition(
    const std::uint32_t client_tick,
    const std::uint32_t local_client_id,
    const std::uint16_t previous_action_state,
    const std::uint16_t next_action_state) noexcept {
  ObservationEventV1 event{};
  event.client_tick = client_tick;
  event.kind = ObservationEventKind::local_action_state_transition;
  event.local_client_id = local_client_id;
  event.previous_action_state = previous_action_state;
  event.next_action_state = next_action_state;
  return TryRecord(event);
}

bool ObservationRing::TryRecordSend60Attempt(
    const std::uint32_t client_tick,
    const std::uint32_t local_client_id,
    const std::uint32_t subcommand_header_le,
    const std::uint32_t subcommand_byte_count) noexcept {
  ObservationEventV1 event{};
  event.client_tick = client_tick;
  event.kind = ObservationEventKind::send60_serialization_attempt;
  event.local_client_id = local_client_id;
  event.subcommand_header_le = subcommand_header_le;
  event.subcommand_byte_count = subcommand_byte_count;
  return TryRecord(event);
}

bool ObservationRing::TryRecord(
    ObservationEventV1 event) noexcept {
  const std::uint32_t observed_thread_id = CurrentThreadId();
  const std::uint32_t producer_thread_id =
      producer_thread_id_.load(std::memory_order_acquire);
  if (observed_thread_id == 0U || producer_thread_id == 0U ||
      observed_thread_id != producer_thread_id) {
    SaturatingIncrement(producer_violation_count_);
    return false;
  }

  const std::uint32_t write_cursor =
      write_cursor_.load(std::memory_order_relaxed);
  const std::uint32_t read_cursor =
      read_cursor_.load(std::memory_order_acquire);
  if (write_cursor - read_cursor >= kObservationRingCapacity) {
    SaturatingIncrement(dropped_event_count_);
    return false;
  }
  if (next_sequence_ == 0U) {
    SaturatingIncrement(dropped_event_count_);
    return false;
  }

  event.sequence = next_sequence_;
  next_sequence_ = next_sequence_ ==
                           std::numeric_limits<std::uint64_t>::max()
                       ? 0U
                       : next_sequence_ + 1U;
  events_[write_cursor & kRingIndexMask] = event;
  write_cursor_.store(write_cursor + 1U, std::memory_order_release);
  return true;
}

bool ObservationRing::DrainClaimed(
    ObservationSnapshotV1& snapshot) noexcept {
  std::memset(&snapshot, 0, sizeof(snapshot));
  snapshot.struct_size = static_cast<std::uint32_t>(sizeof(snapshot));
  snapshot.abi_version = kObservationAbiVersion;
  snapshot.ring_capacity = kObservationRingCapacity;

  const std::uint32_t read_cursor =
      read_cursor_.load(std::memory_order_relaxed);
  const std::uint32_t write_cursor =
      write_cursor_.load(std::memory_order_acquire);
  const std::uint32_t event_count = write_cursor - read_cursor;
  if (event_count > kObservationRingCapacity) {
    return false;
  }

  for (std::uint32_t index = 0U; index < event_count; ++index) {
    snapshot.events[index] =
        events_[(read_cursor + index) & kRingIndexMask];
  }
  snapshot.event_count = event_count;
  snapshot.dropped_event_count =
      dropped_event_count_.load(std::memory_order_relaxed);
  snapshot.producer_violation_count =
      producer_violation_count_.load(std::memory_order_relaxed);
  snapshot.producer_thread_id =
      producer_thread_id_.load(std::memory_order_acquire);

  read_cursor_.store(read_cursor + event_count, std::memory_order_release);
  return true;
}

bool ObservationRing::Drain(ObservationSnapshotV1& snapshot) noexcept {
  if (drain_active_.test_and_set(std::memory_order_acquire)) {
    return false;
  }
  const bool drained = DrainClaimed(snapshot);
  drain_active_.clear(std::memory_order_release);
  return drained;
}

bool ObservationRing::TryClaimEvidenceConsumer() noexcept {
  return !drain_active_.test_and_set(std::memory_order_acquire);
}

void ObservationRing::ReleaseEvidenceConsumer() noexcept {
  drain_active_.clear(std::memory_order_release);
}

bool ObservationRing::TryResetQuiescent() noexcept {
  if (drain_active_.test_and_set(std::memory_order_acquire)) {
    return false;
  }
  events_.fill(ObservationEventV1{});
  read_cursor_.store(0U, std::memory_order_relaxed);
  write_cursor_.store(0U, std::memory_order_relaxed);
  producer_thread_id_.store(0U, std::memory_order_release);
  dropped_event_count_.store(0U, std::memory_order_relaxed);
  producer_violation_count_.store(0U, std::memory_order_relaxed);
  next_sequence_ = 1U;
  drain_active_.clear(std::memory_order_release);
  return true;
}

}  // namespace psobb::gameplay
