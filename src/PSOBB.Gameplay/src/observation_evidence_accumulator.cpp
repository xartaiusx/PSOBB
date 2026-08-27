#include "observation_evidence_accumulator.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace psobb::gameplay {
namespace {

void SaturatingAdd(
    std::uint64_t& destination,
    const std::uint64_t increment) noexcept {
  constexpr std::uint64_t maximum =
      std::numeric_limits<std::uint64_t>::max();
  destination = increment > maximum - destination
                    ? maximum
                    : destination + increment;
}

[[nodiscard]] std::uint32_t CumulativeCounterDelta(
    const std::uint32_t current,
    const std::uint32_t previous) noexcept {
  return current >= previous ? current - previous : current;
}

[[nodiscard]] bool HasValidSnapshotShape(
    const ObservationSnapshotV1& snapshot) noexcept {
  return snapshot.struct_size == sizeof(ObservationSnapshotV1) &&
         snapshot.abi_version == kObservationAbiVersion &&
         snapshot.ring_capacity == kObservationRingCapacity &&
         snapshot.event_count <= kObservationRingCapacity &&
         snapshot.reserved == 0U;
}

}  // namespace

ObservationEvidenceAccumulator::ObservationEvidenceAccumulator(
    const ObservationEvidenceSessionIdentity& identity) noexcept {
  std::copy(
      std::begin(kObservationEvidenceMagic),
      std::end(kObservationEvidenceMagic),
      std::begin(header_.magic));
  header_.struct_size = kObservationEvidenceHeaderSize;
  header_.format_version = kObservationEvidenceFormatVersion;
  header_.byte_order_marker = kObservationEvidenceByteOrderMarker;
  header_.maximum_file_size = kObservationEvidenceMaximumFileSize;
  header_.event_abi_version = kObservationAbiVersion;
  header_.event_record_size =
      static_cast<std::uint32_t>(sizeof(ObservationEventV1));
  header_.event_capacity = kObservationEvidenceEventCapacity;
  header_.client_identity_version =
      kObservationEvidenceClientIdentityVersion;
  header_.client_sha256_byte_count = kObservationEvidenceSha256ByteCount;
  header_.consumer_thread_id = identity.consumer_thread_id;
  header_.process_id = identity.process_id;
  header_.process_start_filetime = identity.process_start_filetime;
  std::copy(
      identity.exact_client_sha256.begin(),
      identity.exact_client_sha256.end(),
      std::begin(header_.exact_client_sha256));
  std::copy(
      identity.module_version.begin(),
      identity.module_version.end(),
      std::begin(header_.module_version));
}

bool ObservationEvidenceAccumulator::Append(
    const ObservationSnapshotV1& snapshot) noexcept {
  if (!HasValidSnapshotShape(snapshot)) {
    return false;
  }
  if (header_.producer_thread_id != 0U &&
      snapshot.producer_thread_id != 0U &&
      header_.producer_thread_id != snapshot.producer_thread_id) {
    return false;
  }

  const std::uint32_t committed = header_.committed_event_count;
  const std::uint32_t available =
      kObservationEvidenceEventCapacity - committed;
  const std::uint32_t retained =
      std::min(snapshot.event_count, available);
  for (std::uint32_t index = 0U; index < retained; ++index) {
    events_[committed + index] = snapshot.events[index];
  }

  if (header_.producer_thread_id == 0U) {
    header_.producer_thread_id = snapshot.producer_thread_id;
  }
  SaturatingAdd(
      header_.total_drained_event_count,
      snapshot.event_count);
  SaturatingAdd(
      header_.ring_dropped_event_count,
      CumulativeCounterDelta(
          snapshot.dropped_event_count,
          last_ring_dropped_event_count_));
  SaturatingAdd(
      header_.producer_violation_count,
      CumulativeCounterDelta(
          snapshot.producer_violation_count,
          last_producer_violation_count_));
  SaturatingAdd(
      header_.evidence_capacity_dropped_event_count,
      static_cast<std::uint64_t>(snapshot.event_count - retained));
  last_ring_dropped_event_count_ = snapshot.dropped_event_count;
  last_producer_violation_count_ = snapshot.producer_violation_count;

  if (retained != 0U) {
    if (committed == 0U) {
      header_.first_sequence = snapshot.events[0].sequence;
    }
    header_.last_sequence = snapshot.events[retained - 1U].sequence;
  }

  // Publish the payload boundary only after all retained records and metadata
  // have been copied.
  header_.committed_event_count = committed + retained;
  return true;
}

void ObservationEvidenceAccumulator::MarkReady(
    const std::uint64_t filetime) noexcept {
  header_.lifecycle_state = ObservationEvidenceLifecycleState::ready;
  header_.capture_start_filetime = filetime;
  header_.last_commit_filetime = filetime;
}

void ObservationEvidenceAccumulator::MarkActive(
    const std::uint64_t filetime,
    const std::uint64_t tick_milliseconds) noexcept {
  header_.lifecycle_state = ObservationEvidenceLifecycleState::active;
  header_.last_commit_filetime = filetime;
  header_.active_start_tick_milliseconds = tick_milliseconds;
  header_.last_commit_tick_milliseconds = tick_milliseconds;
  SaturatingAdd(header_.heartbeat_count, 1U);
}

void ObservationEvidenceAccumulator::MarkHeartbeat(
    const std::uint64_t filetime,
    const std::uint64_t tick_milliseconds) noexcept {
  if (header_.lifecycle_state !=
      ObservationEvidenceLifecycleState::active) {
    return;
  }
  header_.last_commit_filetime = filetime;
  header_.last_commit_tick_milliseconds = tick_milliseconds;
  SaturatingAdd(header_.heartbeat_count, 1U);
}

void ObservationEvidenceAccumulator::MarkCompleted(
    const std::uint64_t filetime,
    const std::uint64_t tick_milliseconds) noexcept {
  header_.lifecycle_state = ObservationEvidenceLifecycleState::completed;
  header_.last_commit_filetime = filetime;
  header_.completion_filetime = filetime;
  header_.last_commit_tick_milliseconds = tick_milliseconds;
}

void ObservationEvidenceAccumulator::MarkFailed(
    const std::uint32_t terminal_failure_code,
    const std::uint64_t filetime,
    const std::uint64_t tick_milliseconds) noexcept {
  header_.lifecycle_state = ObservationEvidenceLifecycleState::failed;
  header_.terminal_failure_code = terminal_failure_code;
  header_.last_commit_filetime = filetime;
  header_.completion_filetime = filetime;
  header_.last_commit_tick_milliseconds = tick_milliseconds;
}

void ObservationEvidenceAccumulator::RestoreHeaderAfterPayloadFailure(
    const ObservationEvidenceHeaderV1& previous_header) noexcept {
  header_ = previous_header;
}

const ObservationEvidenceHeaderV1&
ObservationEvidenceAccumulator::Header() const noexcept {
  return header_;
}

std::span<const ObservationEventV1>
ObservationEvidenceAccumulator::CommittedEvents() const noexcept {
  return std::span<const ObservationEventV1>{
      events_.data(), header_.committed_event_count};
}

std::size_t ObservationEvidenceAccumulator::CommittedFileSize() const noexcept {
  return sizeof(ObservationEvidenceHeaderV1) +
         static_cast<std::size_t>(header_.committed_event_count) *
             sizeof(ObservationEventV1);
}

}  // namespace psobb::gameplay
