#include "psobb_client_safety/hook_patch.h"
#include "hook_patch_test_seam.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>

namespace {

int g_failures = 0;

void Check(const bool condition, const char* expression) {
  if (!condition) {
    std::cerr << "FAIL: " << expression << '\n';
    ++g_failures;
  }
}

#define CHECK(expression) Check((expression), #expression)

class ExecutablePages final {
 public:
  explicit ExecutablePages(const std::size_t page_count) noexcept {
    SYSTEM_INFO information{};
    GetSystemInfo(&information);
    page_size_ = information.dwPageSize;
    size_ = page_size_ * page_count;
    data_ = static_cast<std::byte*>(VirtualAlloc(
        nullptr,
        size_,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE));
  }

  ~ExecutablePages() noexcept {
    if (data_ != nullptr) {
      VirtualFree(data_, 0U, MEM_RELEASE);
    }
  }

  ExecutablePages(const ExecutablePages&) = delete;
  ExecutablePages& operator=(const ExecutablePages&) = delete;

  [[nodiscard]] bool valid() const noexcept { return data_ != nullptr; }
  [[nodiscard]] std::byte* data() noexcept { return data_; }
  [[nodiscard]] const std::byte* data() const noexcept { return data_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t page_size() const noexcept { return page_size_; }

  [[nodiscard]] bool Protect(
      const std::size_t offset,
      const std::size_t size,
      const DWORD protection) noexcept {
    DWORD ignored = 0U;
    return data_ != nullptr && offset <= size_ && size <= size_ - offset &&
           VirtualProtect(data_ + offset, size, protection, &ignored) != FALSE;
  }

  [[nodiscard]] DWORD ProtectionAt(const std::size_t offset) const noexcept {
    MEMORY_BASIC_INFORMATION information{};
    if (data_ == nullptr || offset >= size_ ||
        VirtualQuery(
            data_ + offset,
            &information,
            sizeof(information)) != sizeof(information)) {
      return 0U;
    }
    return information.Protect;
  }

 private:
  std::byte* data_ = nullptr;
  std::size_t size_ = 0U;
  std::size_t page_size_ = 0U;
};

template <std::size_t Size>
void WriteBytes(
    ExecutablePages& pages,
    const std::size_t offset,
    const std::array<std::byte, Size>& bytes) {
  CHECK(pages.Protect(offset, bytes.size(), PAGE_EXECUTE_READWRITE));
  std::memcpy(pages.data() + offset, bytes.data(), bytes.size());
  CHECK(FlushInstructionCache(
            GetCurrentProcess(), pages.data() + offset, bytes.size()) != FALSE);
  CHECK(pages.Protect(offset, bytes.size(), PAGE_EXECUTE_READ));
}

template <std::size_t Size>
[[nodiscard]] bool MatchBytes(
    const ExecutablePages& pages,
    const std::size_t offset,
    const std::array<std::byte, Size>& bytes) noexcept {
  return std::memcmp(
             pages.data() + offset,
             bytes.data(),
             bytes.size()) == 0;
}

[[nodiscard]] std::array<wchar_t, 96> OwnershipName(
    const std::uintptr_t address) noexcept {
  std::array<wchar_t, 96> name{};
  const int written = _snwprintf_s(
      name.data(),
      name.size(),
      _TRUNCATE,
      L"Local\\PSOBB.ClientSafety.HookByte.%08lX.%08lX",
      static_cast<unsigned long>(GetCurrentProcessId()),
      static_cast<unsigned long>(address));
  CHECK(written > 0);
  return name;
}

[[nodiscard]] std::array<wchar_t, 96> PageOwnershipName(
    const std::uintptr_t address,
    const std::size_t page_size) noexcept {
  const std::uintptr_t page = address - (address % page_size);
  std::array<wchar_t, 96> name{};
  const int written = _snwprintf_s(
      name.data(),
      name.size(),
      _TRUNCATE,
      L"Local\\PSOBB.ClientSafety.HookPage.%08lX.%08lX",
      static_cast<unsigned long>(GetCurrentProcessId()),
      static_cast<unsigned long>(page));
  CHECK(written > 0);
  return name;
}

[[nodiscard]] psobb::client_safety::ExecutableRange RangeOf(
    ExecutablePages& pages) noexcept {
  return {
      reinterpret_cast<std::uintptr_t>(pages.data()),
      pages.size()};
}

class HookPatchTransaction final {
 public:
  HookPatchTransaction() noexcept : owner_{NextOwnerValue()} {}

  [[nodiscard]] psobb::client_safety::HookPatchResult Install(
      const psobb::client_safety::ExecutableRange range,
      const std::span<const psobb::client_safety::HookPatchSite> sites)
      const noexcept {
    return psobb::client_safety::InstallHookPatchTransaction(
        owner_, range, sites);
  }

  [[nodiscard]] psobb::client_safety::HookPatchResult Rollback()
      const noexcept {
    return psobb::client_safety::RollbackHookPatchTransaction(owner_);
  }

  [[nodiscard]] bool active() const noexcept {
    return psobb::client_safety::IsHookPatchOwnerActive(owner_);
  }

 private:
  [[nodiscard]] static std::uint64_t NextOwnerValue() noexcept {
    static std::uint64_t next = 0x50534F4242000001ULL;
    return next++;
  }

  psobb::client_safety::HookPatchOwner owner_;
};

struct FaultOperations {
  std::uint32_t protect_calls = 0U;
  std::uint32_t flush_calls = 0U;
  std::uint32_t fail_protect_mask = 0U;
  std::uint32_t fail_flush_mask = 0U;
  std::uint32_t race_on_protect_call = 0U;
  DWORD raced_prior_protection = 0U;
  bool cfg_requests_valid = true;

  [[nodiscard]] static bool Protect(
      void* context,
      const std::uintptr_t address,
      const std::size_t size,
      const DWORD requested,
      DWORD& prior) noexcept {
    auto& state = *static_cast<FaultOperations*>(context);
    ++state.protect_calls;
    const DWORD base = requested & 0xFFU;
    const bool executable =
        base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_READWRITE ||
        base == PAGE_EXECUTE_WRITECOPY;
    const bool preserves_cfg =
        (requested & PAGE_TARGETS_NO_UPDATE) != 0U;
    state.cfg_requests_valid =
        state.cfg_requests_valid && (executable == preserves_cfg);

    if (state.race_on_protect_call == state.protect_calls) {
      DWORD ignored = 0U;
      if (VirtualProtect(
              reinterpret_cast<void*>(address),
              size,
              state.raced_prior_protection,
              &ignored) == FALSE) {
        return false;
      }
    }

    const std::uint32_t bit =
        state.protect_calls <= 32U
            ? 1U << (state.protect_calls - 1U)
            : 0U;
    if ((state.fail_protect_mask & bit) != 0U) {
      return false;
    }
    return VirtualProtect(
               reinterpret_cast<void*>(address),
               size,
               requested,
               &prior) != FALSE;
  }

  [[nodiscard]] static bool Flush(
      void* context,
      const std::uintptr_t address,
      const std::size_t size) noexcept {
    auto& state = *static_cast<FaultOperations*>(context);
    ++state.flush_calls;
    const std::uint32_t bit =
        state.flush_calls <= 32U
            ? 1U << (state.flush_calls - 1U)
            : 0U;
    if ((state.fail_flush_mask & bit) != 0U) {
      return false;
    }
    return FlushInstructionCache(
               GetCurrentProcess(),
               reinterpret_cast<const void*>(address),
               size) != FALSE;
  }
};

void SetFaultOperations(FaultOperations& state) {
  using namespace psobb::client_safety::detail;
  CHECK(SetHookPatchOperationsForTesting(
      HookPatchOperationsForTesting{
          &state, &FaultOperations::Protect, &FaultOperations::Flush}));
}

void ResetFaultOperations() {
  using namespace psobb::client_safety::detail;
  CHECK(SetHookPatchOperationsForTesting({}));
}

template <std::size_t Size>
[[nodiscard]] psobb::client_safety::HookPatchSite SiteAt(
    ExecutablePages& pages,
    const std::size_t offset,
    const std::array<std::byte, Size>& expected,
    const std::array<std::byte, Size>& replacement) noexcept {
  return {
      reinterpret_cast<std::uintptr_t>(pages.data() + offset),
      expected,
      replacement};
}

void TestInstallAndDeterministicRollback() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x55}, std::byte{0x8B}, std::byte{0xEC},
      std::byte{0x83}, std::byte{0xEC}};
  constexpr std::array replacement{
      std::byte{0xE9}, std::byte{0x10}, std::byte{0x20},
      std::byte{0x30}, std::byte{0x40}};
  WriteBytes(pages, 32U, original);
  const DWORD original_protection = pages.ProtectionAt(32U);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 32U, original, replacement)};
  const HookPatchResult installed = transaction.Install(RangeOf(pages), sites);
  CHECK(installed.passed());
  CHECK(installed.applied_count == 1U);
  CHECK(transaction.active());
  CHECK(MatchBytes(pages, 32U, replacement));
  CHECK(pages.ProtectionAt(32U) == original_protection);

  const HookPatchResult rolled_back = transaction.Rollback();
  CHECK(rolled_back.passed());
  CHECK(rolled_back.rolled_back_count == 1U);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 32U, original));
  CHECK(pages.ProtectionAt(32U) == original_protection);
}

void TestExpectedByteMismatchIsInert() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array actual{
      std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};
  constexpr std::array expected{
      std::byte{0x90}, std::byte{0x91}, std::byte{0x90}};
  constexpr std::array replacement{
      std::byte{0xCC}, std::byte{0xCC}, std::byte{0xCC}};
  WriteBytes(pages, 16U, actual);
  const DWORD original_protection = pages.ProtectionAt(16U);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 16U, expected, replacement)};
  const HookPatchResult result = transaction.Install(RangeOf(pages), sites);
  CHECK(!result.passed());
  CHECK(result.failure == HookPatchFailure::expected_bytes_mismatch);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 16U, actual));
  CHECK(pages.ProtectionAt(16U) == original_protection);
}

void TestAllSitesArePreflightedBeforeAnyWrite() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_original{
      std::byte{0x01}, std::byte{0x02}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}};
  constexpr std::array second_actual{
      std::byte{0x03}, std::byte{0x04}};
  constexpr std::array second_expected{
      std::byte{0x03}, std::byte{0x05}};
  constexpr std::array second_replacement{
      std::byte{0x13}, std::byte{0x14}};
  WriteBytes(pages, 32U, first_original);
  WriteBytes(pages, 48U, second_actual);

  HookPatchTransaction transaction;
  const std::array sites{
      SiteAt(pages, 32U, first_original, first_replacement),
      SiteAt(pages, 48U, second_expected, second_replacement)};
  const HookPatchResult result = transaction.Install(RangeOf(pages), sites);
  CHECK(result.failure == HookPatchFailure::expected_bytes_mismatch);
  CHECK(result.applied_count == 0U);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 32U, first_original));
  CHECK(MatchBytes(pages, 48U, second_actual));
}

void TestDuplicateAndOverlapOwnership() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
      std::byte{0x04}, std::byte{0x05}, std::byte{0x06}};
  constexpr std::array replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
      std::byte{0x14}, std::byte{0x15}, std::byte{0x16}};
  WriteBytes(pages, 64U, original);

  HookPatchTransaction owner;
  const std::array owned{SiteAt(pages, 64U, original, replacement)};
  CHECK(owner.Install(RangeOf(pages), owned).passed());

  HookPatchTransaction duplicate;
  const std::array duplicate_site{SiteAt(pages, 64U, replacement, original)};
  const HookPatchResult duplicate_result =
      duplicate.Install(RangeOf(pages), duplicate_site);
  CHECK(duplicate_result.failure == HookPatchFailure::ownership_conflict);
  CHECK(!duplicate.active());

  constexpr std::array overlap_expected{
      std::byte{0x13}, std::byte{0x14}, std::byte{0x15}};
  constexpr std::array overlap_replacement{
      std::byte{0x21}, std::byte{0x22}, std::byte{0x23}};
  HookPatchTransaction overlap;
  const std::array overlap_site{
      SiteAt(pages, 66U, overlap_expected, overlap_replacement)};
  const HookPatchResult overlap_result =
      overlap.Install(RangeOf(pages), overlap_site);
  CHECK(overlap_result.failure == HookPatchFailure::ownership_conflict);
  CHECK(!overlap.active());

  CHECK(owner.Rollback().passed());
  CHECK(MatchBytes(pages, 64U, original));
}

void TestProcessWideOwnershipClaim() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  constexpr std::array replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
  WriteBytes(pages, 80U, original);

  const std::uintptr_t address =
      reinterpret_cast<std::uintptr_t>(pages.data() + 81U);
  const auto name = OwnershipName(address);
  SetLastError(ERROR_SUCCESS);
  HANDLE foreign_claim = CreateFileMappingW(
      INVALID_HANDLE_VALUE,
      nullptr,
      PAGE_READONLY,
      0U,
      1U,
      name.data());
  CHECK(foreign_claim != nullptr);
  CHECK(GetLastError() != ERROR_ALREADY_EXISTS);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 80U, original, replacement)};
  const HookPatchResult rejected = transaction.Install(RangeOf(pages), sites);
  CHECK(rejected.failure == HookPatchFailure::ownership_conflict);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 80U, original));

  if (foreign_claim != nullptr) {
    CloseHandle(foreign_claim);
  }
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  CHECK(transaction.Rollback().passed());
}

void TestDisjointSitesOnOwnedPageConflict() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
  constexpr std::array second_original{
      std::byte{0x04}, std::byte{0x05}, std::byte{0x06}};
  constexpr std::array second_replacement{
      std::byte{0x14}, std::byte{0x15}, std::byte{0x16}};
  WriteBytes(pages, 64U, first_original);
  WriteBytes(pages, 256U, second_original);

  HookPatchTransaction first;
  const std::array first_site{
      SiteAt(pages, 64U, first_original, first_replacement)};
  CHECK(first.Install(RangeOf(pages), first_site).passed());

  HookPatchTransaction second;
  const std::array second_site{
      SiteAt(pages, 256U, second_original, second_replacement)};
  CHECK(second.Install(RangeOf(pages), second_site).failure ==
        HookPatchFailure::ownership_conflict);
  CHECK(MatchBytes(pages, 256U, second_original));

  CHECK(first.Rollback().passed());
  CHECK(second.Install(RangeOf(pages), second_site).passed());
  CHECK(second.Rollback().passed());
}

void TestSamePagePartialRollbackRetainsPageClaim() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
  constexpr std::array second_original{
      std::byte{0x04}, std::byte{0x05}, std::byte{0x06}};
  constexpr std::array second_replacement{
      std::byte{0x14}, std::byte{0x15}, std::byte{0x16}};
  constexpr std::array second_foreign{
      std::byte{0x24}, std::byte{0x25}, std::byte{0x26}};
  constexpr std::array third_original{
      std::byte{0x07}, std::byte{0x08}, std::byte{0x09}};
  constexpr std::array third_replacement{
      std::byte{0x17}, std::byte{0x18}, std::byte{0x19}};
  WriteBytes(pages, 320U, first_original);
  WriteBytes(pages, 336U, second_original);
  WriteBytes(pages, 352U, third_original);

  HookPatchTransaction owner;
  const std::array sites{
      SiteAt(pages, 320U, first_original, first_replacement),
      SiteAt(pages, 336U, second_original, second_replacement)};
  CHECK(owner.Install(RangeOf(pages), sites).passed());
  WriteBytes(pages, 336U, second_foreign);

  const HookPatchResult partial = owner.Rollback();
  CHECK(partial.failure == HookPatchFailure::foreign_mutation);
  CHECK(partial.failed_site_index == 1U);
  CHECK(!partial.rollback_complete);
  CHECK(owner.active());
  CHECK(MatchBytes(pages, 320U, first_original));
  CHECK(MatchBytes(pages, 336U, second_foreign));

  HookPatchTransaction blocked;
  const std::array third_site{
      SiteAt(pages, 352U, third_original, third_replacement)};
  CHECK(blocked.Install(RangeOf(pages), third_site).failure ==
        HookPatchFailure::ownership_conflict);

  WriteBytes(pages, 336U, second_replacement);
  CHECK(owner.Rollback().passed());
  CHECK(MatchBytes(pages, 336U, second_original));
  CHECK(blocked.Install(RangeOf(pages), third_site).passed());
  CHECK(blocked.Rollback().passed());
}

void TestForeignProcessWidePageClaim() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x31}, std::byte{0x32}, std::byte{0x33}};
  constexpr std::array replacement{
      std::byte{0x41}, std::byte{0x42}, std::byte{0x43}};
  WriteBytes(pages, 272U, original);

  const std::uintptr_t address =
      reinterpret_cast<std::uintptr_t>(pages.data() + 272U);
  const auto name = PageOwnershipName(address, pages.page_size());
  SetLastError(ERROR_SUCCESS);
  HANDLE foreign_claim = CreateFileMappingW(
      INVALID_HANDLE_VALUE,
      nullptr,
      PAGE_READONLY,
      0U,
      1U,
      name.data());
  CHECK(foreign_claim != nullptr);
  CHECK(GetLastError() != ERROR_ALREADY_EXISTS);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 272U, original, replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).failure ==
        HookPatchFailure::ownership_conflict);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 272U, original));

  if (foreign_claim != nullptr) {
    CloseHandle(foreign_claim);
  }
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  CHECK(transaction.Rollback().passed());
}

void TestForeignMutationIsNeverOverwritten() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
  constexpr std::array replacement{
      std::byte{0x50}, std::byte{0x60}, std::byte{0x70}, std::byte{0x80}};
  constexpr std::array foreign{
      std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
  WriteBytes(pages, 96U, original);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 96U, original, replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  WriteBytes(pages, 96U, foreign);

  const HookPatchResult conflicted = transaction.Rollback();
  CHECK(!conflicted.passed());
  CHECK(conflicted.failure == HookPatchFailure::foreign_mutation);
  CHECK(!conflicted.rollback_complete);
  CHECK(transaction.active());
  CHECK(MatchBytes(pages, 96U, foreign));

  WriteBytes(pages, 96U, replacement);
  CHECK(transaction.Rollback().passed());
  CHECK(MatchBytes(pages, 96U, original));
}

void TestRollbackFailureKeepsMatchingFirstSiteIndex() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_original{
      std::byte{0x01}, std::byte{0x02}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}};
  constexpr std::array first_foreign{
      std::byte{0x21}, std::byte{0x22}};
  constexpr std::array second_original{
      std::byte{0x03}, std::byte{0x04}};
  constexpr std::array second_replacement{
      std::byte{0x13}, std::byte{0x14}};
  constexpr std::array second_foreign{
      std::byte{0x23}, std::byte{0x24}};
  WriteBytes(pages, 104U, first_original);
  WriteBytes(pages, 108U, second_original);

  HookPatchTransaction transaction;
  const std::array sites{
      SiteAt(pages, 104U, first_original, first_replacement),
      SiteAt(pages, 108U, second_original, second_replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  WriteBytes(pages, 104U, first_foreign);
  WriteBytes(pages, 108U, second_foreign);

  const HookPatchResult failed = transaction.Rollback();
  CHECK(failed.failure == HookPatchFailure::foreign_mutation);
  CHECK(failed.failed_site_index == 1U);
  CHECK(!failed.rollback_complete);
  CHECK(transaction.active());

  WriteBytes(pages, 104U, first_replacement);
  WriteBytes(pages, 108U, second_replacement);
  CHECK(transaction.Rollback().passed());
  CHECK(MatchBytes(pages, 104U, first_original));
  CHECK(MatchBytes(pages, 108U, second_original));
}

void TestForeignProtectionMutationIsNeverNormalized() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
  constexpr std::array replacement{
      std::byte{0x50}, std::byte{0x60}, std::byte{0x70}, std::byte{0x80}};
  WriteBytes(pages, 112U, original);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 112U, original, replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  CHECK(pages.Protect(0U, pages.page_size(), PAGE_EXECUTE_READWRITE));

  const HookPatchResult conflicted = transaction.Rollback();
  CHECK(!conflicted.passed());
  CHECK(conflicted.failure == HookPatchFailure::foreign_mutation);
  CHECK(transaction.active());
  CHECK(MatchBytes(pages, 112U, replacement));
  CHECK(pages.ProtectionAt(112U) == PAGE_EXECUTE_READWRITE);

  CHECK(pages.Protect(0U, pages.page_size(), PAGE_EXECUTE_READ));
  CHECK(transaction.Rollback().passed());
  CHECK(MatchBytes(pages, 112U, original));
}

void TestRollbackFlushFailureRetainsOwnershipUntilRetry() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}};
  constexpr std::array replacement{
      std::byte{0x50}, std::byte{0x60}, std::byte{0x70}, std::byte{0x80}};
  WriteBytes(pages, 120U, original);

  FaultOperations faults{};
  faults.fail_flush_mask = 1U << 1U;
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 120U, original, replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  const HookPatchResult failed = transaction.Rollback();
  CHECK(failed.failure == HookPatchFailure::instruction_cache_flush_failed);
  CHECK(!failed.rollback_complete);
  CHECK(transaction.active());
  CHECK(MatchBytes(pages, 120U, original));
  CHECK(pages.ProtectionAt(120U) == PAGE_EXECUTE_READ);

  HookPatchTransaction blocked;
  CHECK(blocked.Install(RangeOf(pages), sites).failure ==
        HookPatchFailure::ownership_conflict);

  CHECK(transaction.Rollback().passed());
  CHECK(!transaction.active());
  CHECK(faults.flush_calls == 3U);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestApplyCleanupFlushFailurePersistsUntilRetry() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x21}, std::byte{0x22}, std::byte{0x23}, std::byte{0x24}};
  constexpr std::array replacement{
      std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34}};
  WriteBytes(pages, 136U, original);

  FaultOperations faults{};
  faults.fail_flush_mask = 0x7U;
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 136U, original, replacement)};
  const HookPatchResult failed = transaction.Install(RangeOf(pages), sites);
  CHECK(failed.failure == HookPatchFailure::instruction_cache_flush_failed);
  CHECK(!failed.rollback_complete);
  CHECK(failed.rollback_failure ==
        HookPatchFailure::instruction_cache_flush_failed);
  CHECK(failed.rollback_failed_site_index == 0U);
  CHECK(transaction.active());
  CHECK(MatchBytes(pages, 136U, original));

  HookPatchTransaction blocked;
  CHECK(blocked.Install(RangeOf(pages), sites).failure ==
        HookPatchFailure::ownership_conflict);
  CHECK(transaction.Rollback().passed());
  CHECK(faults.flush_calls == 4U);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestApplyPrimaryFailureSurvivesRecoveredCleanupFailure() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x35}, std::byte{0x36}, std::byte{0x37}, std::byte{0x38}};
  constexpr std::array replacement{
      std::byte{0x45}, std::byte{0x46}, std::byte{0x47}, std::byte{0x48}};
  WriteBytes(pages, 144U, original);

  FaultOperations faults{};
  faults.fail_flush_mask = 1U;
  faults.fail_protect_mask = (1U << 1U) | (1U << 2U);
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 144U, original, replacement)};
  const HookPatchResult failed = transaction.Install(RangeOf(pages), sites);
  CHECK(failed.failure == HookPatchFailure::instruction_cache_flush_failed);
  CHECK(failed.failed_site_index == 0U);
  CHECK(failed.rollback_complete);
  CHECK(failed.rollback_failure == HookPatchFailure::none);
  CHECK(failed.rollback_failed_site_index ==
        std::numeric_limits<std::uint32_t>::max());
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 144U, original));
  CHECK(pages.ProtectionAt(144U) == PAGE_EXECUTE_READ);
  CHECK(faults.protect_calls == 4U);
  CHECK(faults.flush_calls == 2U);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestForeignPriorProtectionIsRestoredWithoutNormalization() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44}};
  constexpr std::array replacement{
      std::byte{0x51}, std::byte{0x52}, std::byte{0x53}, std::byte{0x54}};
  WriteBytes(pages, 152U, original);

  FaultOperations faults{};
  faults.race_on_protect_call = 1U;
  faults.raced_prior_protection = PAGE_READONLY;
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 152U, original, replacement)};
  const HookPatchResult rejected = transaction.Install(RangeOf(pages), sites);
  CHECK(rejected.failure == HookPatchFailure::foreign_mutation);
  CHECK(rejected.rollback_complete);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 152U, original));
  CHECK(pages.ProtectionAt(152U) == PAGE_READONLY);
  CHECK(faults.protect_calls == 2U);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestFailedForeignProtectionRestoreRetriesExactState() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x61}, std::byte{0x62}, std::byte{0x63}, std::byte{0x64}};
  constexpr std::array replacement{
      std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74}};
  WriteBytes(pages, 168U, original);

  FaultOperations faults{};
  faults.race_on_protect_call = 1U;
  faults.raced_prior_protection = PAGE_READONLY;
  faults.fail_protect_mask = (1U << 1U) | (1U << 2U);
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 168U, original, replacement)};
  const HookPatchResult failed = transaction.Install(RangeOf(pages), sites);
  CHECK(failed.failure == HookPatchFailure::protection_restore_failed);
  CHECK(!failed.rollback_complete);
  CHECK(transaction.active());
  CHECK(MatchBytes(pages, 168U, original));
  CHECK(pages.ProtectionAt(168U) == PAGE_EXECUTE_READWRITE);

  CHECK(pages.Protect(0U, pages.page_size(), PAGE_EXECUTE_READ));
  const HookPatchResult foreign = transaction.Rollback();
  CHECK(foreign.failure == HookPatchFailure::foreign_mutation);
  CHECK(!foreign.rollback_complete);
  CHECK(transaction.active());
  CHECK(pages.ProtectionAt(168U) == PAGE_EXECUTE_READ);

  CHECK(pages.Protect(0U, pages.page_size(), PAGE_EXECUTE_READWRITE));
  CHECK(transaction.Rollback().passed());
  CHECK(!transaction.active());
  CHECK(pages.ProtectionAt(168U) == PAGE_READONLY);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestRestoreProtectionRaceIsRejectedAndRecovered() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84}};
  constexpr std::array replacement{
      std::byte{0x91}, std::byte{0x92}, std::byte{0x93}, std::byte{0x94}};
  WriteBytes(pages, 184U, original);

  FaultOperations faults{};
  faults.race_on_protect_call = 2U;
  faults.raced_prior_protection = PAGE_EXECUTE_READ;
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 184U, original, replacement)};
  const HookPatchResult rejected = transaction.Install(RangeOf(pages), sites);
  CHECK(rejected.failure == HookPatchFailure::foreign_mutation);
  CHECK(rejected.rollback_complete);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 184U, original));
  CHECK(pages.ProtectionAt(184U) == PAGE_EXECUTE_READ);
  CHECK(faults.protect_calls == 5U);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestWriteRollbackSettlesNonWritableRecoveryState() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}, std::byte{0xA4}};
  constexpr std::array replacement{
      std::byte{0xB1}, std::byte{0xB2}, std::byte{0xB3}, std::byte{0xB4}};
  WriteBytes(pages, 200U, original);

  FaultOperations faults{};
  faults.race_on_protect_call = 2U;
  faults.raced_prior_protection = PAGE_EXECUTE_READ;
  faults.fail_protect_mask = 1U << 2U;
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, 200U, original, replacement)};
  const HookPatchResult rejected = transaction.Install(RangeOf(pages), sites);
  CHECK(rejected.failure == HookPatchFailure::protection_restore_failed);
  CHECK(rejected.rollback_complete);
  CHECK(rejected.rollback_failure == HookPatchFailure::none);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 200U, original));
  CHECK(pages.ProtectionAt(200U) == PAGE_EXECUTE_READ);
  CHECK(faults.protect_calls == 6U);
  CHECK(faults.flush_calls == 2U);
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestSecondSiteFailureRollsBackFirstWrite() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
  constexpr std::array second_original{
      std::byte{0x04}, std::byte{0x05}, std::byte{0x06}};
  constexpr std::array second_replacement{
      std::byte{0x14}, std::byte{0x15}, std::byte{0x16}};
  WriteBytes(pages, 208U, first_original);
  WriteBytes(pages, 224U, second_original);

  FaultOperations faults{};
  faults.fail_protect_mask = 1U << 2U;
  SetFaultOperations(faults);

  HookPatchTransaction transaction;
  const std::array sites{
      SiteAt(pages, 208U, first_original, first_replacement),
      SiteAt(pages, 224U, second_original, second_replacement)};
  const HookPatchResult failed = transaction.Install(RangeOf(pages), sites);
  CHECK(failed.failure == HookPatchFailure::protection_change_failed);
  CHECK(failed.failed_site_index == 1U);
  CHECK(failed.applied_count == 1U);
  CHECK(failed.rolled_back_count == 1U);
  CHECK(failed.rollback_complete);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 208U, first_original));
  CHECK(MatchBytes(pages, 224U, second_original));
  CHECK(faults.cfg_requests_valid);
  ResetFaultOperations();
}

void TestMultiSiteRollbackAndTransactionReuse() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_original{
      std::byte{0x01}, std::byte{0x02}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}};
  constexpr std::array second_original{
      std::byte{0x03}, std::byte{0x04}};
  constexpr std::array second_replacement{
      std::byte{0x13}, std::byte{0x14}};
  WriteBytes(pages, 128U, first_original);
  WriteBytes(pages, 160U, second_original);

  HookPatchTransaction transaction;
  const std::array sites{
      SiteAt(pages, 128U, first_original, first_replacement),
      SiteAt(pages, 160U, second_original, second_replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  CHECK(transaction.Install(RangeOf(pages), sites).failure ==
        HookPatchFailure::transaction_active);
  CHECK(transaction.Rollback().passed());
  CHECK(MatchBytes(pages, 128U, first_original));
  CHECK(MatchBytes(pages, 160U, second_original));
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  CHECK(transaction.Rollback().passed());
}

void TestStableOwnerTokenSupportsExplicitRecovery() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  constexpr std::array replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
  WriteBytes(pages, 176U, original);
  constexpr HookPatchOwner owner{0x50534F4242524356ULL};
  {
    const std::array sites{SiteAt(pages, 176U, original, replacement)};
    const HookPatchOwner copied_owner = owner;
    CHECK(InstallHookPatchTransaction(
              copied_owner, RangeOf(pages), sites).passed());
    CHECK(MatchBytes(pages, 176U, replacement));
  }
  CHECK(IsHookPatchOwnerActive(owner));
  CHECK(RollbackHookPatchTransaction(owner).passed());
  CHECK(MatchBytes(pages, 176U, original));
  CHECK(pages.ProtectionAt(176U) == PAGE_EXECUTE_READ);
}

void TestPageBoundaryAndProtectionRestoration() {
  using namespace psobb::client_safety;
  ExecutablePages pages(2U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34}};
  constexpr std::array replacement{
      std::byte{0x41}, std::byte{0x42}, std::byte{0x43}, std::byte{0x44}};
  const std::size_t offset = pages.page_size() - 2U;
  WriteBytes(pages, offset, original);
  const DWORD first_protection = pages.ProtectionAt(offset);
  const DWORD second_protection = pages.ProtectionAt(offset + 2U);

  HookPatchTransaction transaction;
  const std::array sites{SiteAt(pages, offset, original, replacement)};
  CHECK(transaction.Install(RangeOf(pages), sites).passed());
  CHECK(MatchBytes(pages, offset, replacement));
  CHECK(pages.ProtectionAt(offset) == first_protection);
  CHECK(pages.ProtectionAt(offset + 2U) == second_protection);
  CHECK(transaction.Rollback().passed());
  CHECK(MatchBytes(pages, offset, original));
  CHECK(pages.ProtectionAt(offset) == first_protection);
  CHECK(pages.ProtectionAt(offset + 2U) == second_protection);
}

void TestProtectionBoundaryAndNonExecutableRangeReject() {
  using namespace psobb::client_safety;
  ExecutablePages pages(2U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x71}, std::byte{0x72}, std::byte{0x73}, std::byte{0x74}};
  constexpr std::array replacement{
      std::byte{0x81}, std::byte{0x82}, std::byte{0x83}, std::byte{0x84}};
  const std::size_t boundary = pages.page_size() - 2U;
  WriteBytes(pages, boundary, original);
  CHECK(pages.Protect(
      pages.page_size(), pages.page_size(), PAGE_EXECUTE_READWRITE));

  HookPatchTransaction crossing;
  const std::array crossing_site{
      SiteAt(pages, boundary, original, replacement)};
  const HookPatchResult crossing_result =
      crossing.Install(RangeOf(pages), crossing_site);
  CHECK(crossing_result.failure ==
        HookPatchFailure::memory_not_committed_executable);
  CHECK(MatchBytes(pages, boundary, original));

  CHECK(pages.Protect(0U, pages.page_size(), PAGE_READONLY));
  HookPatchTransaction non_executable;
  const std::array non_executable_site{
      SiteAt(pages, 32U, original, replacement)};
  const HookPatchResult non_executable_result =
      non_executable.Install(RangeOf(pages), non_executable_site);
  CHECK(non_executable_result.failure ==
        HookPatchFailure::memory_not_committed_executable);
  CHECK(!non_executable.active());
}

void TestRangeValidationAndOverflow() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array original{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
  constexpr std::array replacement{
      std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};
  WriteBytes(pages, 8U, original);

  HookPatchTransaction outside;
  const std::array outside_site{SiteAt(pages, 8U, original, replacement)};
  const ExecutableRange too_narrow{
      reinterpret_cast<std::uintptr_t>(pages.data()), 10U};
  CHECK(outside.Install(too_narrow, outside_site).failure ==
        HookPatchFailure::outside_executable_range);
  CHECK(MatchBytes(pages, 8U, original));

  HookPatchTransaction allowed_overflow;
  const ExecutableRange overflow{
      std::numeric_limits<std::uintptr_t>::max() - 1U, 4U};
  CHECK(allowed_overflow.Install(overflow, outside_site).failure ==
        HookPatchFailure::range_overflow);

  HookPatchTransaction site_overflow;
  const HookPatchSite impossible{
      std::numeric_limits<std::uintptr_t>::max() - 1U,
      original,
      replacement};
  const std::array impossible_sites{impossible};
  CHECK(site_overflow.Install(RangeOf(pages), impossible_sites).failure ==
        HookPatchFailure::range_overflow);

  constexpr std::array one_expected{std::byte{0x01}};
  constexpr std::array one_replacement{std::byte{0x02}};
  HookPatchTransaction too_short;
  const std::array one_byte_site{
      SiteAt(pages, 8U, one_expected, one_replacement)};
  CHECK(too_short.Install(RangeOf(pages), one_byte_site).failure ==
        HookPatchFailure::invalid_argument);
}

void TestOverlappingSitesInOnePlanReject() {
  using namespace psobb::client_safety;
  ExecutablePages pages(1U);
  CHECK(pages.valid());

  constexpr std::array first_expected{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
  constexpr std::array first_replacement{
      std::byte{0x11}, std::byte{0x12}, std::byte{0x13}};
  constexpr std::array second_expected{
      std::byte{0x03}, std::byte{0x04}, std::byte{0x05}};
  constexpr std::array second_replacement{
      std::byte{0x21}, std::byte{0x22}, std::byte{0x23}};
  constexpr std::array source{
      std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
      std::byte{0x04}, std::byte{0x05}};
  WriteBytes(pages, 192U, source);

  HookPatchTransaction transaction;
  const std::array sites{
      SiteAt(pages, 192U, first_expected, first_replacement),
      SiteAt(pages, 194U, second_expected, second_replacement)};
  const HookPatchResult result = transaction.Install(RangeOf(pages), sites);
  CHECK(result.failure == HookPatchFailure::ownership_conflict);
  CHECK(!transaction.active());
  CHECK(MatchBytes(pages, 192U, source));
}

}  // namespace

int main() {
  TestInstallAndDeterministicRollback();
  TestExpectedByteMismatchIsInert();
  TestAllSitesArePreflightedBeforeAnyWrite();
  TestDuplicateAndOverlapOwnership();
  TestProcessWideOwnershipClaim();
  TestDisjointSitesOnOwnedPageConflict();
  TestSamePagePartialRollbackRetainsPageClaim();
  TestForeignProcessWidePageClaim();
  TestForeignMutationIsNeverOverwritten();
  TestRollbackFailureKeepsMatchingFirstSiteIndex();
  TestForeignProtectionMutationIsNeverNormalized();
  TestRollbackFlushFailureRetainsOwnershipUntilRetry();
  TestApplyCleanupFlushFailurePersistsUntilRetry();
  TestApplyPrimaryFailureSurvivesRecoveredCleanupFailure();
  TestForeignPriorProtectionIsRestoredWithoutNormalization();
  TestFailedForeignProtectionRestoreRetriesExactState();
  TestRestoreProtectionRaceIsRejectedAndRecovered();
  TestWriteRollbackSettlesNonWritableRecoveryState();
  TestSecondSiteFailureRollsBackFirstWrite();
  TestMultiSiteRollbackAndTransactionReuse();
  TestStableOwnerTokenSupportsExplicitRecovery();
  TestPageBoundaryAndProtectionRestoration();
  TestProtectionBoundaryAndNonExecutableRangeReject();
  TestRangeValidationAndOverflow();
  TestOverlappingSitesInOnePlanReject();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.ClientSafety hook-patch tests passed\n";
  return 0;
}
