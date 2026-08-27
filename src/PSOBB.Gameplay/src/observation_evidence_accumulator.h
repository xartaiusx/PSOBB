#pragma once

#include "psobb_gameplay/observation_evidence.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psobb::gameplay {

struct ObservationEvidenceSessionIdentity final {
  std::array<std::uint8_t, kObservationEvidenceSha256ByteCount>
      exact_client_sha256{};
  std::array<char, kObservationEvidenceModuleVersionByteCount>
      module_version{};
  std::uint32_t consumer_thread_id = 0U;
  std::uint32_t process_id = 0U;
  std::uint64_t process_start_filetime = 0U;
};

struct ObservationEvidenceAccumulatorTestAccess;
class ObservationEvidenceSession;

// A single consumer owns this accumulator. Append performs no allocation,
// locking, I/O, or logging.
class ObservationEvidenceAccumulator final {
 public:
  explicit ObservationEvidenceAccumulator(
      const ObservationEvidenceSessionIdentity& identity) noexcept;

  ObservationEvidenceAccumulator(const ObservationEvidenceAccumulator&) =
      delete;
  ObservationEvidenceAccumulator& operator=(
      const ObservationEvidenceAccumulator&) = delete;
  ObservationEvidenceAccumulator(ObservationEvidenceAccumulator&&) = delete;
  ObservationEvidenceAccumulator& operator=(
      ObservationEvidenceAccumulator&&) = delete;

  [[nodiscard]] bool Append(
      const ObservationSnapshotV1& snapshot) noexcept;

  void MarkReady(std::uint64_t filetime) noexcept;
  void MarkActive(
      std::uint64_t filetime,
      std::uint64_t tick_milliseconds) noexcept;
  void MarkHeartbeat(
      std::uint64_t filetime,
      std::uint64_t tick_milliseconds) noexcept;
  void MarkCompleted(
      std::uint64_t filetime,
      std::uint64_t tick_milliseconds) noexcept;
  void MarkFailed(
      std::uint32_t terminal_failure_code,
      std::uint64_t filetime,
      std::uint64_t tick_milliseconds) noexcept;

  [[nodiscard]] const ObservationEvidenceHeaderV1& Header() const noexcept;
  [[nodiscard]] std::span<const ObservationEventV1>
  CommittedEvents() const noexcept;
  [[nodiscard]] std::size_t CommittedFileSize() const noexcept;

 private:
  friend struct ObservationEvidenceAccumulatorTestAccess;
  friend class ObservationEvidenceSession;

  // An event payload is durable before its header boundary is published. If
  // that payload write fails partway through, the worker restores this prior
  // header so best-effort failure persistence cannot expose partial records.
  void RestoreHeaderAfterPayloadFailure(
      const ObservationEvidenceHeaderV1& previous_header) noexcept;

  ObservationEvidenceHeaderV1 header_{};
  std::array<ObservationEventV1, kObservationEvidenceEventCapacity> events_{};
  std::uint32_t last_ring_dropped_event_count_ = 0U;
  std::uint32_t last_producer_violation_count_ = 0U;
};

}  // namespace psobb::gameplay
