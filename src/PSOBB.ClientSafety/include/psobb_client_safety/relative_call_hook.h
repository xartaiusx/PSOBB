#pragma once

#include "psobb_client_safety/hook_patch.h"

#include <cstdint>

namespace psobb::client_safety {

struct RelativeCallHookSite {
  std::uintptr_t instruction_address;
  std::uintptr_t expected_target;
  std::uintptr_t replacement_target;
};

enum class RelativeCallHookFailure : std::uint32_t {
  none = 0,
  invalid_argument = 1,
  range_overflow = 2,
  outside_executable_range = 3,
  site_not_committed_writable_executable_image = 4,
  opcode_mismatch = 5,
  target_not_committed_executable = 6,
  target_out_of_range = 7,
  expected_target_mismatch = 8,
  ownership_conflict = 9,
  ownership_capacity_exceeded = 10,
  owner_active = 11,
  ownership_claim_failed = 12,
  atomic_exchange_failed = 13,
  instruction_cache_flush_failed = 14,
  foreign_mutation = 15,
  instruction_crosses_page = 16,
};

struct RelativeCallHookResult {
  RelativeCallHookFailure failure = RelativeCallHookFailure::none;
  bool rollback_complete = true;
  RelativeCallHookFailure rollback_failure =
      RelativeCallHookFailure::none;

  [[nodiscard]] bool passed() const noexcept {
    return failure == RelativeCallHookFailure::none &&
           rollback_complete &&
           rollback_failure == RelativeCallHookFailure::none;
  }
};

// Replaces only the aligned rel32 operand of one five-byte x86 near CALL. The
// complete instruction must reside on one writable executable MEM_IMAGE page,
// so this primitive never broadens page protection. The caller first
// verifies the exact loaded image and the complete surrounding instruction
// sequence. Both targets and the owning module remain loaded through rollback.
[[nodiscard]] RelativeCallHookResult InstallRelativeCallHook(
    HookPatchOwner owner,
    ExecutableRange executable_range,
    RelativeCallHookSite site) noexcept;

[[nodiscard]] RelativeCallHookResult RollbackRelativeCallHook(
    HookPatchOwner owner) noexcept;

[[nodiscard]] bool IsRelativeCallHookOwnerActive(
    HookPatchOwner owner) noexcept;

}  // namespace psobb::client_safety
