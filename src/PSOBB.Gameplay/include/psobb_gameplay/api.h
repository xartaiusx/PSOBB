#pragma once

#include <cstddef>
#include <cstdint>

#include "psobb_gameplay/observation.h"

#if defined(_WIN32)
#include <windows.h>
#else
using BOOL = int;
#define WINAPI
#endif

#define PSOBB_GAMEPLAY_API extern "C"

namespace psobb::gameplay {

inline constexpr std::uint32_t kCapabilityAbiVersion = 1U;
inline constexpr std::uint32_t kDisplaySlotCount = 10U;
inline constexpr std::uint32_t kNoActivePage = 0U;
inline constexpr wchar_t kVersion[] = L"0.3.0-send60-observation";

enum class RuntimeState : std::uint32_t {
  cold = 0,
  initializing = 1,
  disabled_by_config = 2,
  exact_client_ready = 3,
  rejected = 4,
  rolled_back = 5,
  observation_ready = 6,
};

enum VerificationFlag : std::uint32_t {
  verification_none = 0,
  verification_file_hash_matched = 1U << 0U,
  verification_loaded_pe_contract_matched = 1U << 1U,
  verification_observation_site_matched = 1U << 2U,
  verification_observation_hook_installed = 1U << 3U,
};

enum FeatureBit : std::uint64_t {
  feature_none = 0,
  feature_observation = 1ULL << 0U,
  feature_hotbar = 1ULL << 1U,
  feature_held_normal = 1ULL << 2U,
  feature_held_heavy = 1ULL << 3U,
  feature_held_special = 1ULL << 4U,
  feature_mixed_combo = 1ULL << 5U,
  feature_physical_buffer = 1ULL << 6U,
  feature_technique_buffer = 1ULL << 7U,
  feature_item_quick_use = 1ULL << 8U,
  feature_physical_recovery = 1ULL << 9U,
  feature_technique_recovery = 1ULL << 10U,
  feature_knockdown_recovery = 1ULL << 11U,
  feature_movement_resume = 1ULL << 12U,
  feature_diagnostics = 1ULL << 13U,
};

enum class DisplaySlotKind : std::uint32_t {
  empty = 0,
  technique = 1,
  consumable = 2,
  utility = 3,
};

#pragma pack(push, 8)

struct DisplaySlotV1 {
  DisplaySlotKind kind;
  std::uint32_t logical_action_id;
  std::uint32_t flags;
  std::uint32_t reserved;
};

struct GameplayCapabilitiesV1 {
  std::uint32_t struct_size;
  std::uint32_t abi_version;
  RuntimeState state;
  std::uint32_t verification_flags;
  std::uint64_t accepted_feature_bits;
  std::uint32_t active_page;
  std::uint32_t display_slot_count;
  DisplaySlotV1 display_slots[kDisplaySlotCount];
  wchar_t client_sha256[65];
  wchar_t version[32];
  wchar_t last_fail_closed_reason[256];
};

#pragma pack(pop)

#if defined(_WIN32)
static_assert(sizeof(DisplaySlotV1) == 16U);
static_assert(offsetof(DisplaySlotV1, kind) == 0U);
static_assert(offsetof(DisplaySlotV1, logical_action_id) == 4U);
static_assert(offsetof(DisplaySlotV1, flags) == 8U);
static_assert(offsetof(DisplaySlotV1, reserved) == 12U);
static_assert(sizeof(GameplayCapabilitiesV1) == 904U);
static_assert(offsetof(GameplayCapabilitiesV1, struct_size) == 0U);
static_assert(offsetof(GameplayCapabilitiesV1, abi_version) == 4U);
static_assert(offsetof(GameplayCapabilitiesV1, state) == 8U);
static_assert(offsetof(GameplayCapabilitiesV1, verification_flags) == 12U);
static_assert(offsetof(GameplayCapabilitiesV1, accepted_feature_bits) == 16U);
static_assert(offsetof(GameplayCapabilitiesV1, active_page) == 24U);
static_assert(offsetof(GameplayCapabilitiesV1, display_slot_count) == 28U);
static_assert(offsetof(GameplayCapabilitiesV1, display_slots) == 32U);
static_assert(offsetof(GameplayCapabilitiesV1, client_sha256) == 192U);
static_assert(offsetof(GameplayCapabilitiesV1, version) == 322U);
static_assert(
    offsetof(GameplayCapabilitiesV1, last_fail_closed_reason) == 386U);
#endif

}  // namespace psobb::gameplay

PSOBB_GAMEPLAY_API BOOL WINAPI PSOBBGameplay_Initialize() noexcept;
PSOBB_GAMEPLAY_API BOOL WINAPI PSOBBGameplay_GetCapabilities(
    psobb::gameplay::GameplayCapabilitiesV1* capabilities) noexcept;
PSOBB_GAMEPLAY_API BOOL WINAPI PSOBBGameplay_DrainObservations(
    psobb::gameplay::ObservationSnapshotV1* observations) noexcept;
PSOBB_GAMEPLAY_API BOOL WINAPI PSOBBGameplay_Rollback() noexcept;
PSOBB_GAMEPLAY_API const wchar_t* WINAPI
PSOBBGameplay_GetVersion() noexcept;
