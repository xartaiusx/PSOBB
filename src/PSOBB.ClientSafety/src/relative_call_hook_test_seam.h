#pragma once

#include <cstddef>
#include <cstdint>

namespace psobb::client_safety::detail {

using RelativeCallFlushForTesting = bool (*)(
    void* context,
    std::uintptr_t address,
    std::size_t size) noexcept;

struct RelativeCallHookOperationsForTesting {
  void* context = nullptr;
  RelativeCallFlushForTesting flush = nullptr;
};

// Available only in the separate fault-injection test library target.
[[nodiscard]] bool SetRelativeCallHookOperationsForTesting(
    RelativeCallHookOperationsForTesting operations) noexcept;

}  // namespace psobb::client_safety::detail
