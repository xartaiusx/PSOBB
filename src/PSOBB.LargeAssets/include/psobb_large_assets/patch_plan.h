#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace psobb::large_assets {

inline constexpr std::uintptr_t kPinnedImageBase = 0x00400000U;
inline constexpr std::uint32_t kLargeAssetLimit = 100'000'000U;
inline constexpr std::uint32_t kUpstreamAddressEntryCount = 18U;

struct PatchSite {
  std::uintptr_t virtual_address;
  std::uint32_t rva;
  std::uint32_t expected_value;
};

// The MIT Blue Burst Patch Project source lists 18 entries. Address
// 0x005B7CFC appears twice there, so this transactional plan intentionally
// contains the 17 unique writes only.
inline constexpr std::array<PatchSite, 17> kPatchSites = {{
    {0x00800C32U, 0x00400C32U, 0x00090000U},
    {0x005B7CFCU, 0x001B7CFCU, 0x00090000U},
    {0x005B80F8U, 0x001B80F8U, 0x00090000U},
    {0x005B913FU, 0x001B913FU, 0x00090000U},
    {0x005B7215U, 0x001B7215U, 0x00090000U},
    {0x005B7937U, 0x001B7937U, 0x00090000U},
    {0x005B97C2U, 0x001B97C2U, 0x00090000U},
    {0x005BA613U, 0x001BA613U, 0x00090000U},
    {0x005BB405U, 0x001BB405U, 0x00090000U},
    {0x005B77E3U, 0x001B77E3U, 0x00090000U},
    {0x005C74C1U, 0x001C74C1U, 0x00090000U},
    {0x0070EB5BU, 0x0030EB5BU, 0x00090000U},
    {0x00800A34U, 0x00400A34U, 0x00090000U},
    {0x005B82ADU, 0x001B82ADU, 0x00090000U},
    {0x005BB40CU, 0x001BB40CU, 0x00090000U},
    {0x005E581EU, 0x001E581EU, 0x00090000U},
    {0x007A6573U, 0x003A6573U, 0x00100000U},
}};

static_assert([] {
  for (const auto& site : kPatchSites) {
    if (site.virtual_address != kPinnedImageBase + site.rva) {
      return false;
    }
  }
  return true;
}());

using ReadValue = bool (*)(
    void* context,
    std::uintptr_t address,
    std::uint32_t& value) noexcept;

// A failed write reports modified=true only when the replacement may still be
// present. This lets the transaction include that site in its rollback set.
using CompareWriteValue = bool (*)(
    void* context,
    std::uintptr_t address,
    std::uint32_t expected,
    std::uint32_t replacement,
    bool& modified) noexcept;

struct MemoryOperations {
  void* context = nullptr;
  ReadValue read = nullptr;
  CompareWriteValue compare_write = nullptr;
};

struct TransactionResult {
  bool passed = false;
  bool preflight_passed = false;
  bool rollback_complete = true;
  std::uint32_t applied_count = 0;
  std::uint32_t rolled_back_count = 0;
  std::uint32_t failed_site_index =
      std::numeric_limits<std::uint32_t>::max();
};

[[nodiscard]] TransactionResult ApplyPatchTransaction(
    const MemoryOperations& memory,
    std::span<const PatchSite> sites = kPatchSites) noexcept;

[[nodiscard]] TransactionResult RollbackPatchTransaction(
    const MemoryOperations& memory,
    std::span<const PatchSite> sites = kPatchSites) noexcept;

}  // namespace psobb::large_assets
