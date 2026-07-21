#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace psobb::gameplay {

inline constexpr std::uint32_t kObservationAbiVersion = 1U;
inline constexpr std::uint32_t kObservationRingCapacity = 2048U;
inline constexpr std::uint32_t kNoLocalClientId =
    std::numeric_limits<std::uint32_t>::max();

enum class ObservationEventKind : std::uint32_t {
  none = 0U,
  tick = 1U,
  local_action_state_transition = 2U,
  send60_serialization_attempt = 3U,
};

#pragma pack(push, 8)

struct ObservationEventV1 {
  std::uint64_t sequence;
  std::uint32_t client_tick;
  ObservationEventKind kind;
  std::uint32_t local_client_id;
  std::uint16_t previous_action_state;
  std::uint16_t next_action_state;
  std::uint32_t subcommand_header_le;
  std::uint32_t subcommand_byte_count;
};

struct ObservationSnapshotV1 {
  std::uint32_t struct_size;
  std::uint32_t abi_version;
  std::uint32_t ring_capacity;
  std::uint32_t event_count;
  std::uint32_t dropped_event_count;
  std::uint32_t producer_violation_count;
  std::uint32_t producer_thread_id;
  std::uint32_t reserved;
  ObservationEventV1 events[kObservationRingCapacity];
};

#pragma pack(pop)

static_assert(std::is_standard_layout_v<ObservationEventV1>);
static_assert(std::is_trivially_copyable_v<ObservationEventV1>);
static_assert(sizeof(ObservationEventV1) == 32U);
static_assert(alignof(ObservationEventV1) == 8U);
static_assert(offsetof(ObservationEventV1, sequence) == 0U);
static_assert(offsetof(ObservationEventV1, client_tick) == 8U);
static_assert(offsetof(ObservationEventV1, kind) == 12U);
static_assert(offsetof(ObservationEventV1, local_client_id) == 16U);
static_assert(
    offsetof(ObservationEventV1, previous_action_state) == 20U);
static_assert(offsetof(ObservationEventV1, next_action_state) == 22U);
static_assert(offsetof(ObservationEventV1, subcommand_header_le) == 24U);
static_assert(
    offsetof(ObservationEventV1, subcommand_byte_count) == 28U);

static_assert(std::is_standard_layout_v<ObservationSnapshotV1>);
static_assert(std::is_trivially_copyable_v<ObservationSnapshotV1>);
static_assert(sizeof(ObservationSnapshotV1) == 65'568U);
static_assert(alignof(ObservationSnapshotV1) == 8U);
static_assert(offsetof(ObservationSnapshotV1, struct_size) == 0U);
static_assert(offsetof(ObservationSnapshotV1, abi_version) == 4U);
static_assert(offsetof(ObservationSnapshotV1, ring_capacity) == 8U);
static_assert(offsetof(ObservationSnapshotV1, event_count) == 12U);
static_assert(offsetof(ObservationSnapshotV1, dropped_event_count) == 16U);
static_assert(
    offsetof(ObservationSnapshotV1, producer_violation_count) == 20U);
static_assert(offsetof(ObservationSnapshotV1, producer_thread_id) == 24U);
static_assert(offsetof(ObservationSnapshotV1, reserved) == 28U);
static_assert(offsetof(ObservationSnapshotV1, events) == 32U);

}  // namespace psobb::gameplay
