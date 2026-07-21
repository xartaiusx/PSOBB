#pragma once

#include "psobb_gameplay/observation.h"

#include <array>
#include <atomic>
#include <cstdint>

namespace psobb::gameplay {

static_assert(std::atomic<std::uint32_t>::is_always_lock_free);
static_assert(
    (kObservationRingCapacity & (kObservationRingCapacity - 1U)) == 0U);

using ObservationThreadIdProvider = std::uint32_t (*)() noexcept;

struct ObservationRingTestAccess;

class ObservationRing final {
 public:
  explicit ObservationRing(
      ObservationThreadIdProvider thread_id_provider) noexcept;

  ObservationRing(const ObservationRing&) = delete;
  ObservationRing& operator=(const ObservationRing&) = delete;
  ObservationRing(ObservationRing&&) = delete;
  ObservationRing& operator=(ObservationRing&&) = delete;

  [[nodiscard]] bool BindProducerThread() noexcept;

  [[nodiscard]] bool TryRecordTick(
      std::uint32_t client_tick) noexcept;

  [[nodiscard]] bool TryRecordLocalStateTransition(
      std::uint32_t client_tick,
      std::uint32_t local_client_id,
      std::uint16_t previous_action_state,
      std::uint16_t next_action_state) noexcept;

  [[nodiscard]] bool TryRecordSend60Attempt(
      std::uint32_t client_tick,
      std::uint32_t local_client_id,
      std::uint32_t subcommand_header_le,
      std::uint32_t subcommand_byte_count) noexcept;

  // A successful drain consumes the events present when its write cursor is
  // acquired. A simultaneous drain is rejected instead of waiting.
  [[nodiscard]] bool Drain(ObservationSnapshotV1& snapshot) noexcept;

  // The caller must prove that the producer is absent. A concurrent consumer
  // makes the reset fail immediately without changing ring state.
  [[nodiscard]] bool TryResetQuiescent() noexcept;

 private:
  [[nodiscard]] bool TryRecord(
      ObservationEventV1 event) noexcept;
  [[nodiscard]] std::uint32_t CurrentThreadId() const noexcept;

  friend struct ObservationRingTestAccess;

  ObservationThreadIdProvider thread_id_provider_;
  std::array<ObservationEventV1, kObservationRingCapacity> events_{};
  std::atomic<std::uint32_t> read_cursor_{0U};
  std::atomic<std::uint32_t> write_cursor_{0U};
  std::atomic<std::uint32_t> producer_thread_id_{0U};
  std::atomic<std::uint32_t> dropped_event_count_{0U};
  std::atomic<std::uint32_t> producer_violation_count_{0U};
  std::atomic_flag drain_active_ = ATOMIC_FLAG_INIT;
  std::uint64_t next_sequence_ = 1U;
};

}  // namespace psobb::gameplay
