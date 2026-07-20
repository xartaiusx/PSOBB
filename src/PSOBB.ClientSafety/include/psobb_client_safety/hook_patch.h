#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace psobb::client_safety {

inline constexpr std::size_t kMinimumHookPatchBytes = 2U;
inline constexpr std::size_t kMaximumHookPatchBytes = 16U;
inline constexpr std::size_t kMaximumHookPatchSites = 8U;

struct ExecutableRange {
  std::uintptr_t begin;
  std::size_t size;
};

struct HookPatchSite {
  std::uintptr_t address;
  std::span<const std::byte> expected;
  std::span<const std::byte> replacement;
};

enum class HookPatchFailure : std::uint32_t {
  none = 0,
  invalid_argument = 1,
  range_overflow = 2,
  outside_executable_range = 3,
  memory_not_committed_executable = 4,
  expected_bytes_mismatch = 5,
  ownership_conflict = 6,
  ownership_capacity_exceeded = 7,
  transaction_active = 8,
  protection_change_failed = 9,
  protection_restore_failed = 10,
  instruction_cache_flush_failed = 11,
  write_verification_failed = 12,
  foreign_mutation = 13,
  ownership_claim_failed = 14,
};

struct HookPatchResult {
  HookPatchFailure failure = HookPatchFailure::none;
  std::uint32_t failed_site_index =
      std::numeric_limits<std::uint32_t>::max();
  std::uint32_t applied_count = 0;
  std::uint32_t rolled_back_count = 0;
  bool rollback_complete = true;
  HookPatchFailure rollback_failure = HookPatchFailure::none;
  std::uint32_t rollback_failed_site_index =
      std::numeric_limits<std::uint32_t>::max();

  [[nodiscard]] bool passed() const noexcept {
    return failure == HookPatchFailure::none && rollback_complete &&
           rollback_failure == HookPatchFailure::none;
  }
};

// A project-owned module assigns one stable, nonzero, process-wide unique value
// per logical owner and retains it for the entire process lifetime. The module
// must remain pinned while it owns a patch and must call
// RollbackHookPatchTransaction explicitly. The token is a recoverable identity,
// not a fallible RAII resource handle. Reusing another owner's value would
// authorize rollback of that owner's sites within the same library instance.
struct HookPatchOwner {
  std::uint64_t value;
};

// Installing or restoring 2-16 x86 code bytes is not atomic. Before either
// operation, the caller must prove that no thread can execute the target range.
// A first Gameplay integration must run before the target becomes reachable
// from InitializeASI, or marshal the operation to a separately proven safe
// point.
[[nodiscard]] HookPatchResult InstallHookPatchTransaction(
    HookPatchOwner owner,
    ExecutableRange executable_range,
    std::span<const HookPatchSite> sites) noexcept;

[[nodiscard]] HookPatchResult RollbackHookPatchTransaction(
    HookPatchOwner owner) noexcept;

[[nodiscard]] bool IsHookPatchOwnerActive(HookPatchOwner owner) noexcept;

}  // namespace psobb::client_safety
