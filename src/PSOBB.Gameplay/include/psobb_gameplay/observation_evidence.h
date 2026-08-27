#pragma once

#include "psobb_gameplay/observation.h"

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace psobb::gameplay {

inline constexpr std::uint8_t kObservationEvidenceMagic[8] = {
    'P', 'S', 'O', 'B', 'B', 'O', 'B', 'S'};
inline constexpr std::uint32_t kObservationEvidenceFormatVersion = 1U;
inline constexpr std::uint32_t kObservationEvidenceByteOrderMarker =
    0x01020304U;
inline constexpr std::uint32_t kObservationEvidenceClientIdentityVersion =
    1U;
inline constexpr std::uint32_t kObservationEvidenceSha256ByteCount = 32U;
inline constexpr std::uint32_t kObservationEvidenceModuleVersionByteCount =
    32U;
inline constexpr std::uint32_t kObservationEvidenceEventCapacity = 16'384U;
inline constexpr std::uint32_t kObservationEvidenceHeaderSize = 256U;
inline constexpr std::uint32_t kObservationEvidenceMaximumFileSize =
    kObservationEvidenceHeaderSize +
    kObservationEvidenceEventCapacity *
        static_cast<std::uint32_t>(sizeof(ObservationEventV1));

#pragma pack(push, 8)

enum class ObservationEvidenceLifecycleState : std::uint32_t {
  uninitialized = 0U,
  ready = 1U,
  active = 2U,
  completed = 3U,
  failed = 4U,
};

// The committed event count is the sole payload boundary. Bytes after the
// committed records are not evidence and may contain stale storage.
struct ObservationEvidenceHeaderV1 {
  std::uint8_t magic[8];
  std::uint32_t struct_size;
  std::uint32_t format_version;
  std::uint32_t byte_order_marker;
  std::uint32_t maximum_file_size;
  std::uint32_t event_abi_version;
  std::uint32_t event_record_size;
  std::uint32_t event_capacity;
  std::uint32_t committed_event_count;
  std::uint32_t client_identity_version;
  std::uint32_t client_sha256_byte_count;
  std::uint64_t total_drained_event_count;
  std::uint64_t ring_dropped_event_count;
  std::uint64_t producer_violation_count;
  std::uint64_t evidence_capacity_dropped_event_count;
  std::uint32_t producer_thread_id;
  std::uint32_t consumer_thread_id;
  std::uint32_t process_id;
  std::uint32_t reserved0;
  std::uint64_t process_start_filetime;
  std::uint64_t first_sequence;
  std::uint64_t last_sequence;
  std::uint8_t exact_client_sha256[kObservationEvidenceSha256ByteCount];
  char module_version[kObservationEvidenceModuleVersionByteCount];
  ObservationEvidenceLifecycleState lifecycle_state;
  std::uint32_t terminal_failure_code;
  std::uint64_t capture_start_filetime;
  std::uint64_t last_commit_filetime;
  std::uint64_t completion_filetime;
  std::uint64_t heartbeat_count;
  std::uint64_t active_start_tick_milliseconds;
  std::uint64_t last_commit_tick_milliseconds;
  std::uint8_t reserved[16];
};

#pragma pack(pop)

static_assert(std::is_standard_layout_v<ObservationEvidenceHeaderV1>);
static_assert(std::is_trivially_copyable_v<ObservationEvidenceHeaderV1>);
static_assert(sizeof(ObservationEvidenceHeaderV1) ==
              kObservationEvidenceHeaderSize);
static_assert(alignof(ObservationEvidenceHeaderV1) == 8U);
static_assert(kObservationEvidenceMaximumFileSize == 524'544U);
static_assert(kObservationEvidenceMaximumFileSize < 1024U * 1024U);
static_assert(offsetof(ObservationEvidenceHeaderV1, magic) == 0U);
static_assert(offsetof(ObservationEvidenceHeaderV1, struct_size) == 8U);
static_assert(offsetof(ObservationEvidenceHeaderV1, format_version) == 12U);
static_assert(offsetof(ObservationEvidenceHeaderV1, byte_order_marker) == 16U);
static_assert(offsetof(ObservationEvidenceHeaderV1, maximum_file_size) == 20U);
static_assert(offsetof(ObservationEvidenceHeaderV1, event_abi_version) == 24U);
static_assert(offsetof(ObservationEvidenceHeaderV1, event_record_size) == 28U);
static_assert(offsetof(ObservationEvidenceHeaderV1, event_capacity) == 32U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, committed_event_count) == 36U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, client_identity_version) == 40U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, client_sha256_byte_count) == 44U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, total_drained_event_count) == 48U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, ring_dropped_event_count) == 56U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, producer_violation_count) == 64U);
static_assert(offsetof(
                  ObservationEvidenceHeaderV1,
                  evidence_capacity_dropped_event_count) == 72U);
static_assert(offsetof(ObservationEvidenceHeaderV1, producer_thread_id) == 80U);
static_assert(offsetof(ObservationEvidenceHeaderV1, consumer_thread_id) == 84U);
static_assert(offsetof(ObservationEvidenceHeaderV1, process_id) == 88U);
static_assert(offsetof(ObservationEvidenceHeaderV1, reserved0) == 92U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, process_start_filetime) == 96U);
static_assert(offsetof(ObservationEvidenceHeaderV1, first_sequence) == 104U);
static_assert(offsetof(ObservationEvidenceHeaderV1, last_sequence) == 112U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, exact_client_sha256) == 120U);
static_assert(offsetof(ObservationEvidenceHeaderV1, module_version) == 152U);
static_assert(offsetof(ObservationEvidenceHeaderV1, lifecycle_state) == 184U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, terminal_failure_code) == 188U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, capture_start_filetime) == 192U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, last_commit_filetime) == 200U);
static_assert(
    offsetof(ObservationEvidenceHeaderV1, completion_filetime) == 208U);
static_assert(offsetof(ObservationEvidenceHeaderV1, heartbeat_count) == 216U);
static_assert(
    offsetof(
        ObservationEvidenceHeaderV1,
        active_start_tick_milliseconds) == 224U);
static_assert(
    offsetof(
        ObservationEvidenceHeaderV1,
        last_commit_tick_milliseconds) == 232U);
static_assert(offsetof(ObservationEvidenceHeaderV1, reserved) == 240U);

}  // namespace psobb::gameplay
