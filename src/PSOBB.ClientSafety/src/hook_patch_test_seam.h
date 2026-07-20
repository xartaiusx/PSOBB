#pragma once

#include <cstddef>
#include <cstdint>

#include <windows.h>

namespace psobb::client_safety::detail {

using ProtectForTesting = bool (*)(
    void* context,
    std::uintptr_t address,
    std::size_t size,
    DWORD requested_protection,
    DWORD& prior_protection) noexcept;

using FlushForTesting = bool (*)(
    void* context,
    std::uintptr_t address,
    std::size_t size) noexcept;

struct HookPatchOperationsForTesting {
  void* context = nullptr;
  ProtectForTesting protect = nullptr;
  FlushForTesting flush = nullptr;
};

// Available only in the separate fault-injection test library target.
[[nodiscard]] bool SetHookPatchOperationsForTesting(
    HookPatchOperationsForTesting operations) noexcept;

}  // namespace psobb::client_safety::detail
