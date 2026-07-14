#include "psobb_large_assets/patch_plan.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace psobb::large_assets {
namespace {

[[nodiscard]] bool OperationsValid(
    const MemoryOperations& memory) noexcept {
  return memory.read != nullptr && memory.compare_write != nullptr;
}

void RollbackAppliedPrefix(
    const MemoryOperations& memory,
    const std::span<const PatchSite> sites,
    const std::size_t count,
    TransactionResult& result) noexcept {
  for (std::size_t position = count; position > 0; --position) {
    const auto& site = sites[position - 1U];
    bool modified = false;
    if (memory.compare_write(
            memory.context,
            site.virtual_address,
            kLargeAssetLimit,
            site.expected_value,
            modified)) {
      ++result.rolled_back_count;
    } else {
      result.rollback_complete = false;
    }
  }
}

}  // namespace

TransactionResult ApplyPatchTransaction(
    const MemoryOperations& memory,
    const std::span<const PatchSite> sites) noexcept {
  TransactionResult result;
  if (!OperationsValid(memory) || sites.empty()) {
    return result;
  }

  for (std::size_t index = 0; index < sites.size(); ++index) {
    std::uint32_t observed = 0;
    if (!memory.read(
            memory.context, sites[index].virtual_address, observed) ||
        observed != sites[index].expected_value) {
      result.failed_site_index = static_cast<std::uint32_t>(index);
      return result;
    }
  }
  result.preflight_passed = true;

  for (std::size_t index = 0; index < sites.size(); ++index) {
    bool modified = false;
    if (!memory.compare_write(
            memory.context,
            sites[index].virtual_address,
            sites[index].expected_value,
            kLargeAssetLimit,
            modified)) {
      result.failed_site_index = static_cast<std::uint32_t>(index);
      const std::size_t rollback_count =
          index + (modified ? 1U : 0U);
      RollbackAppliedPrefix(memory, sites, rollback_count, result);
      result.applied_count = static_cast<std::uint32_t>(rollback_count);
      return result;
    }
    result.applied_count = static_cast<std::uint32_t>(index + 1U);
  }

  result.passed = true;
  return result;
}

TransactionResult RollbackPatchTransaction(
    const MemoryOperations& memory,
    const std::span<const PatchSite> sites) noexcept {
  TransactionResult result;
  if (!OperationsValid(memory) || sites.empty()) {
    return result;
  }

  result.preflight_passed = true;
  for (std::size_t position = sites.size(); position > 0; --position) {
    const auto& site = sites[position - 1U];
    std::uint32_t observed = 0;
    if (!memory.read(memory.context, site.virtual_address, observed)) {
      result.rollback_complete = false;
      result.failed_site_index = static_cast<std::uint32_t>(position - 1U);
      continue;
    }
    if (observed == site.expected_value) {
      continue;
    }
    if (observed != kLargeAssetLimit) {
      result.rollback_complete = false;
      result.failed_site_index = static_cast<std::uint32_t>(position - 1U);
      continue;
    }

    bool modified = false;
    if (memory.compare_write(
            memory.context,
            site.virtual_address,
            kLargeAssetLimit,
            site.expected_value,
            modified)) {
      ++result.rolled_back_count;
    } else {
      result.rollback_complete = false;
      result.failed_site_index = static_cast<std::uint32_t>(position - 1U);
    }
  }
  result.applied_count = static_cast<std::uint32_t>(sites.size());
  result.passed = result.rollback_complete;
  return result;
}

}  // namespace psobb::large_assets
