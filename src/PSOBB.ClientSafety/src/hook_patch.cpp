#include "psobb_client_safety/hook_patch.h"

#if defined(PSOBB_CLIENT_SAFETY_TEST_SEAM)
#include "hook_patch_test_seam.h"
#endif

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>

namespace psobb::client_safety {
namespace {

inline constexpr std::size_t kOwnershipCapacity = 32U;
inline constexpr std::size_t kMaximumPagesPerPatch = 2U;
inline constexpr DWORD kWritableExecutableProtection =
    PAGE_EXECUTE_READWRITE;

static_assert(sizeof(void*) == 4U);

struct AddressRange {
  std::uintptr_t begin;
  std::uintptr_t end;
};

struct OwnedPatch {
  std::uint64_t owner_id = 0U;
  std::uint32_t site_index = 0U;
  std::uintptr_t address = 0U;
  std::size_t size = 0U;
  void* allocation_base = nullptr;
  DWORD memory_type = 0U;
  DWORD original_protection = 0U;
  DWORD owed_protection = 0U;
  DWORD uncertain_current_protection = 0U;
  std::array<std::byte, kMaximumHookPatchBytes> expected{};
  std::array<std::byte, kMaximumHookPatchBytes> replacement{};
  std::array<HANDLE, kMaximumHookPatchBytes> byte_claims{};
  std::array<std::uintptr_t, kMaximumPagesPerPatch> claimed_page_bases{};
  std::array<HANDLE, kMaximumPagesPerPatch> page_claims{};
  bool installed = false;
  bool write_attempted = false;
  bool protection_uncertain = false;
  bool instruction_cache_uncertain = false;
};

SRWLOCK g_ownership_lock = SRWLOCK_INIT;
std::array<OwnedPatch, kOwnershipCapacity> g_owned_patches{};

#if defined(PSOBB_CLIENT_SAFETY_TEST_SEAM)
detail::HookPatchOperationsForTesting g_test_operations{};
#endif

class ExclusiveOwnershipLock final {
 public:
  ExclusiveOwnershipLock() noexcept {
    AcquireSRWLockExclusive(&g_ownership_lock);
  }

  ~ExclusiveOwnershipLock() noexcept {
    ReleaseSRWLockExclusive(&g_ownership_lock);
  }

  ExclusiveOwnershipLock(const ExclusiveOwnershipLock&) = delete;
  ExclusiveOwnershipLock& operator=(const ExclusiveOwnershipLock&) = delete;
};

[[nodiscard]] bool MakeAddressRange(
    const std::uintptr_t begin,
    const std::size_t size,
    AddressRange& range) noexcept {
  if (begin == 0U || size == 0U ||
      size > std::numeric_limits<std::uintptr_t>::max() - begin) {
    return false;
  }
  range = AddressRange{begin, begin + size};
  return true;
}

[[nodiscard]] bool RangesOverlap(
    const AddressRange left,
    const AddressRange right) noexcept {
  return left.begin < right.end && right.begin < left.end;
}

[[nodiscard]] bool IsExecutableProtection(const DWORD protection) noexcept {
  switch (protection & 0xFFU) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] HookPatchFailure ValidateCommittedMemory(
    const AddressRange patch_range,
    MEMORY_BASIC_INFORMATION& information) noexcept {
  if (VirtualQuery(
          reinterpret_cast<const void*>(patch_range.begin),
          &information,
          sizeof(information)) != sizeof(information)) {
    return HookPatchFailure::memory_not_committed_executable;
  }

  const auto region_begin =
      reinterpret_cast<std::uintptr_t>(information.BaseAddress);
  AddressRange region{};
  if (!MakeAddressRange(region_begin, information.RegionSize, region) ||
      patch_range.begin < region.begin || patch_range.end > region.end ||
      information.State != MEM_COMMIT ||
      (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0U) {
    return HookPatchFailure::memory_not_committed_executable;
  }
  return HookPatchFailure::none;
}

[[nodiscard]] HookPatchFailure ValidateExecutableMemory(
    const AddressRange patch_range,
    MEMORY_BASIC_INFORMATION& information) noexcept {
  const HookPatchFailure committed =
      ValidateCommittedMemory(patch_range, information);
  if (committed != HookPatchFailure::none ||
      !IsExecutableProtection(information.Protect)) {
    return HookPatchFailure::memory_not_committed_executable;
  }
  return HookPatchFailure::none;
}

[[nodiscard]] bool ReadBytes(
    const std::uintptr_t address,
    const std::size_t size,
    std::array<std::byte, kMaximumHookPatchBytes>& bytes) noexcept {
  SIZE_T read = 0U;
  return ReadProcessMemory(
             GetCurrentProcess(),
             reinterpret_cast<const void*>(address),
             bytes.data(),
             size,
             &read) != FALSE &&
         read == size;
}

[[nodiscard]] bool BytesEqual(
    const std::uintptr_t address,
    const std::span<const std::byte> expected) noexcept {
  std::array<std::byte, kMaximumHookPatchBytes> observed{};
  return expected.size() <= observed.size() &&
         ReadBytes(address, expected.size(), observed) &&
         std::equal(
             expected.begin(), expected.end(), observed.begin());
}

[[nodiscard]] bool BytesEqual(
    const OwnedPatch& patch,
    const std::array<std::byte, kMaximumHookPatchBytes>& expected) noexcept {
  return BytesEqual(
      patch.address,
      std::span<const std::byte>(expected.data(), patch.size));
}

[[nodiscard]] bool ChangeExecutableProtection(
    const std::uintptr_t address,
    const std::size_t size,
    const DWORD base_protection,
    DWORD& prior_protection) noexcept {
  const DWORD requested =
      IsExecutableProtection(base_protection)
          ? base_protection | PAGE_TARGETS_NO_UPDATE
          : base_protection;
#if defined(PSOBB_CLIENT_SAFETY_TEST_SEAM)
  if (g_test_operations.protect != nullptr) {
    return g_test_operations.protect(
        g_test_operations.context,
        address,
        size,
        requested,
        prior_protection);
  }
#endif
  return VirtualProtect(
             reinterpret_cast<void*>(address),
             size,
             requested,
             &prior_protection) != FALSE;
}

[[nodiscard]] bool FlushPatchedInstructions(
    const std::uintptr_t address,
    const std::size_t size) noexcept {
#if defined(PSOBB_CLIENT_SAFETY_TEST_SEAM)
  if (g_test_operations.flush != nullptr) {
    return g_test_operations.flush(
        g_test_operations.context, address, size);
  }
#endif
  return FlushInstructionCache(
             GetCurrentProcess(),
             reinterpret_cast<const void*>(address),
             size) != FALSE;
}

void ReleaseByteClaims(OwnedPatch& patch) noexcept {
  for (HANDLE& claim : patch.byte_claims) {
    if (claim != nullptr) {
      CloseHandle(claim);
      claim = nullptr;
    }
  }
}

void ReleasePageClaims(OwnedPatch& patch) noexcept {
  for (HANDLE& claim : patch.page_claims) {
    if (claim != nullptr) {
      CloseHandle(claim);
      claim = nullptr;
    }
  }
}

void ClearRecord(OwnedPatch& patch) noexcept {
  ReleaseByteClaims(patch);
  ReleasePageClaims(patch);
  patch = {};
}

[[nodiscard]] HANDLE FindPageClaimByOwner(
    const std::uint64_t owner_id,
    const std::uintptr_t page_base) noexcept {
  for (const auto& owned : g_owned_patches) {
    if (owned.owner_id != owner_id) {
      continue;
    }
    for (std::size_t index = 0; index < owned.page_claims.size(); ++index) {
      if (owned.page_claims[index] != nullptr &&
          owned.claimed_page_bases[index] == page_base) {
        return owned.page_claims[index];
      }
    }
  }
  return nullptr;
}

[[nodiscard]] HookPatchFailure AcquirePageClaims(
    OwnedPatch& patch,
    const std::size_t page_size) noexcept {
  const std::uintptr_t first_page =
      patch.address - (patch.address % page_size);
  const std::uintptr_t last_address = patch.address + patch.size - 1U;
  const std::uintptr_t last_page =
      last_address - (last_address % page_size);
  const std::array pages{first_page, last_page};
  std::size_t stored = 0U;

  for (std::size_t index = 0U; index < pages.size(); ++index) {
    if (index != 0U && pages[index] == pages[index - 1U]) {
      continue;
    }
    const std::uintptr_t page = pages[index];
    const HANDLE existing = FindPageClaimByOwner(patch.owner_id, page);
    if (existing != nullptr) {
      HANDLE duplicate = nullptr;
      if (DuplicateHandle(
              GetCurrentProcess(),
              existing,
              GetCurrentProcess(),
              &duplicate,
              0U,
              FALSE,
              DUPLICATE_SAME_ACCESS) == FALSE) {
        ReleasePageClaims(patch);
        return HookPatchFailure::ownership_claim_failed;
      }
      patch.claimed_page_bases[stored] = page;
      patch.page_claims[stored] = duplicate;
      ++stored;
      continue;
    }

    std::array<wchar_t, 96> name{};
    const int written = _snwprintf_s(
        name.data(),
        name.size(),
        _TRUNCATE,
        L"Local\\PSOBB.ClientSafety.HookPage.%08lX.%08lX",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(page));
    if (written <= 0) {
      ReleasePageClaims(patch);
      return HookPatchFailure::ownership_claim_failed;
    }

    SetLastError(ERROR_SUCCESS);
    HANDLE claim = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READONLY,
        0U,
        1U,
        name.data());
    const DWORD error = GetLastError();
    if (claim == nullptr) {
      ReleasePageClaims(patch);
      return error == ERROR_INVALID_HANDLE
                 ? HookPatchFailure::ownership_conflict
                 : HookPatchFailure::ownership_claim_failed;
    }
    if (error == ERROR_ALREADY_EXISTS) {
      CloseHandle(claim);
      ReleasePageClaims(patch);
      return HookPatchFailure::ownership_conflict;
    }
    patch.claimed_page_bases[stored] = page;
    patch.page_claims[stored] = claim;
    ++stored;
  }
  return HookPatchFailure::none;
}

[[nodiscard]] HookPatchFailure AcquireByteClaims(
    OwnedPatch& patch) noexcept {
  for (std::size_t offset = 0U; offset < patch.size; ++offset) {
    std::array<wchar_t, 96> name{};
    const int written = _snwprintf_s(
        name.data(),
        name.size(),
        _TRUNCATE,
        L"Local\\PSOBB.ClientSafety.HookByte.%08lX.%08lX",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(patch.address + offset));
    if (written <= 0) {
      ReleaseByteClaims(patch);
      return HookPatchFailure::ownership_claim_failed;
    }

    SetLastError(ERROR_SUCCESS);
    HANDLE claim = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READONLY,
        0U,
        1U,
        name.data());
    const DWORD error = GetLastError();
    if (claim == nullptr) {
      ReleaseByteClaims(patch);
      return error == ERROR_INVALID_HANDLE
                 ? HookPatchFailure::ownership_conflict
                 : HookPatchFailure::ownership_claim_failed;
    }
    if (error == ERROR_ALREADY_EXISTS) {
      CloseHandle(claim);
      ReleaseByteClaims(patch);
      return HookPatchFailure::ownership_conflict;
    }
    patch.byte_claims[offset] = claim;
  }
  return HookPatchFailure::none;
}

[[nodiscard]] HookPatchFailure RestoreOwedProtection(
    OwnedPatch& patch) noexcept {
  AddressRange patch_range{};
  MEMORY_BASIC_INFORMATION information{};
  if (!patch.protection_uncertain ||
      !MakeAddressRange(patch.address, patch.size, patch_range) ||
      ValidateCommittedMemory(patch_range, information) !=
          HookPatchFailure::none ||
      information.AllocationBase != patch.allocation_base ||
      information.Type != patch.memory_type ||
      information.Protect != patch.uncertain_current_protection) {
    return HookPatchFailure::foreign_mutation;
  }
  const DWORD expected_current = patch.uncertain_current_protection;
  const DWORD requested_owed = patch.owed_protection;
  DWORD immediately_prior = 0U;
  if (!ChangeExecutableProtection(
          patch.address,
          patch.size,
          requested_owed,
          immediately_prior)) {
    patch.protection_uncertain = true;
    return HookPatchFailure::protection_restore_failed;
  }

  if (immediately_prior != expected_current) {
    DWORD recovery_prior = 0U;
    if (!ChangeExecutableProtection(
            patch.address,
            patch.size,
            immediately_prior,
            recovery_prior)) {
      patch.owed_protection = immediately_prior;
      patch.uncertain_current_protection = requested_owed;
      return HookPatchFailure::protection_restore_failed;
    }
    if (recovery_prior != requested_owed) {
      patch.owed_protection = recovery_prior;
      patch.uncertain_current_protection = immediately_prior;
      return HookPatchFailure::foreign_mutation;
    }
    patch.protection_uncertain = false;
    patch.owed_protection = 0U;
    patch.uncertain_current_protection = 0U;
    return HookPatchFailure::foreign_mutation;
  }

  patch.protection_uncertain = false;
  patch.owed_protection = 0U;
  patch.uncertain_current_protection = 0U;
  return HookPatchFailure::none;
}

[[nodiscard]] HookPatchFailure RetryInstructionCacheFlush(
    OwnedPatch& patch) noexcept {
  if (!patch.instruction_cache_uncertain) {
    return HookPatchFailure::none;
  }
  if (!FlushPatchedInstructions(patch.address, patch.size)) {
    return HookPatchFailure::instruction_cache_flush_failed;
  }
  patch.instruction_cache_uncertain = false;
  return HookPatchFailure::none;
}

[[nodiscard]] HookPatchFailure RollbackRecord(
    OwnedPatch& patch,
    bool& restored) noexcept {
  restored = false;

  if (!patch.write_attempted && !patch.protection_uncertain &&
      !patch.instruction_cache_uncertain) {
    restored = true;
    return HookPatchFailure::none;
  }

  AddressRange patch_range{};
  MEMORY_BASIC_INFORMATION information{};
  if (!MakeAddressRange(patch.address, patch.size, patch_range) ||
      (patch.protection_uncertain
           ? ValidateCommittedMemory(patch_range, information)
           : ValidateExecutableMemory(patch_range, information)) !=
          HookPatchFailure::none ||
      information.AllocationBase != patch.allocation_base ||
      information.Type != patch.memory_type) {
    return HookPatchFailure::memory_not_committed_executable;
  }

  if (!patch.write_attempted) {
    const HookPatchFailure cache = RetryInstructionCacheFlush(patch);
    HookPatchFailure protection = HookPatchFailure::none;
    if (patch.protection_uncertain) {
      protection = RestoreOwedProtection(patch);
    }
    if (cache != HookPatchFailure::none) {
      return cache;
    }
    if (protection != HookPatchFailure::none) {
      return protection;
    }
    restored = true;
    return HookPatchFailure::none;
  }

  const auto expected = std::span<const std::byte>(
      patch.expected.data(), patch.size);
  const auto replacement = std::span<const std::byte>(
      patch.replacement.data(), patch.size);

  if (BytesEqual(patch, patch.expected)) {
    const HookPatchFailure cache = RetryInstructionCacheFlush(patch);
    HookPatchFailure protection = HookPatchFailure::none;
    if (patch.protection_uncertain) {
      protection = RestoreOwedProtection(patch);
    } else if (information.Protect != patch.original_protection) {
      return HookPatchFailure::foreign_mutation;
    }
    if (cache != HookPatchFailure::none) {
      return cache;
    }
    if (protection != HookPatchFailure::none) {
      return protection;
    }
    restored = true;
    return HookPatchFailure::none;
  }
  if (!BytesEqual(patch.address, replacement)) {
    return HookPatchFailure::foreign_mutation;
  }

  if (!patch.protection_uncertain &&
      information.Protect != patch.original_protection) {
    return HookPatchFailure::foreign_mutation;
  }
  if (patch.protection_uncertain &&
      information.Protect != patch.uncertain_current_protection) {
    return HookPatchFailure::foreign_mutation;
  }
  if (patch.protection_uncertain &&
      patch.uncertain_current_protection !=
          kWritableExecutableProtection) {
    const HookPatchFailure protection = RestoreOwedProtection(patch);
    return protection == HookPatchFailure::none
               ? HookPatchFailure::foreign_mutation
               : protection;
  }

  DWORD prior_protection = 0U;
  const bool protection_was_uncertain = patch.protection_uncertain;
  if (!protection_was_uncertain) {
    if (!ChangeExecutableProtection(
            patch.address,
            patch.size,
            kWritableExecutableProtection,
            prior_protection)) {
      return HookPatchFailure::protection_change_failed;
    }
    patch.owed_protection = prior_protection;
    patch.protection_uncertain = true;
    patch.uncertain_current_protection = kWritableExecutableProtection;
    if (prior_protection != patch.original_protection) {
      const HookPatchFailure protection = RestoreOwedProtection(patch);
      if (protection != HookPatchFailure::none) {
        return protection;
      }
      return HookPatchFailure::foreign_mutation;
    }
  }

  if (!BytesEqual(patch.address, replacement)) {
    const HookPatchFailure protection =
        RestoreOwedProtection(patch);
    return protection == HookPatchFailure::none
               ? HookPatchFailure::foreign_mutation
               : protection;
  }

  std::memcpy(
      reinterpret_cast<void*>(patch.address),
      expected.data(),
      expected.size());
  patch.instruction_cache_uncertain = true;
  const HookPatchFailure cache = RetryInstructionCacheFlush(patch);
  const bool write_verified = BytesEqual(patch.address, expected);
  const HookPatchFailure protection = RestoreOwedProtection(patch);

  if (!write_verified) {
    return HookPatchFailure::write_verification_failed;
  }
  patch.installed = false;
  if (cache != HookPatchFailure::none) {
    return cache;
  }
  if (protection != HookPatchFailure::none) {
    return protection;
  }

  restored = true;
  return HookPatchFailure::none;
}

[[nodiscard]] HookPatchFailure ApplyRecord(OwnedPatch& patch) noexcept {
  AddressRange patch_range{};
  MEMORY_BASIC_INFORMATION information{};
  if (!MakeAddressRange(patch.address, patch.size, patch_range) ||
      ValidateExecutableMemory(patch_range, information) !=
          HookPatchFailure::none ||
      information.AllocationBase != patch.allocation_base ||
      information.Type != patch.memory_type ||
      information.Protect != patch.original_protection) {
    return HookPatchFailure::memory_not_committed_executable;
  }
  if (!BytesEqual(patch, patch.expected)) {
    return HookPatchFailure::expected_bytes_mismatch;
  }

  DWORD prior_protection = 0U;
  if (!ChangeExecutableProtection(
          patch.address,
          patch.size,
          kWritableExecutableProtection,
          prior_protection)) {
    return HookPatchFailure::protection_change_failed;
  }
  patch.owed_protection = prior_protection;
  patch.protection_uncertain = true;
  patch.uncertain_current_protection = kWritableExecutableProtection;
  if (prior_protection != patch.original_protection) {
    const HookPatchFailure protection = RestoreOwedProtection(patch);
    return protection == HookPatchFailure::none
               ? HookPatchFailure::foreign_mutation
               : protection;
  }

  if (!BytesEqual(patch, patch.expected)) {
    const HookPatchFailure protection =
        RestoreOwedProtection(patch);
    return protection == HookPatchFailure::none
               ? HookPatchFailure::expected_bytes_mismatch
               : protection;
  }

  patch.write_attempted = true;
  std::memcpy(
      reinterpret_cast<void*>(patch.address),
      patch.replacement.data(),
      patch.size);
  patch.instruction_cache_uncertain = true;
  patch.installed = BytesEqual(patch, patch.replacement);
  const HookPatchFailure cache = RetryInstructionCacheFlush(patch);

  const HookPatchFailure protection = RestoreOwedProtection(patch);
  if (patch.installed && cache == HookPatchFailure::none &&
      protection == HookPatchFailure::none) {
    return HookPatchFailure::none;
  }

  const HookPatchFailure primary_failure =
      !patch.installed
          ? HookPatchFailure::write_verification_failed
          : (cache != HookPatchFailure::none
                 ? cache
                 : protection);
  bool restored = false;
  static_cast<void>(RollbackRecord(patch, restored));
  return primary_failure;
}

[[nodiscard]] bool OwnerActiveUnlocked(const std::uint64_t owner_id) noexcept {
  return std::any_of(
      g_owned_patches.begin(),
      g_owned_patches.end(),
      [owner_id](const OwnedPatch& patch) {
        return patch.owner_id == owner_id;
      });
}

}  // namespace

#if defined(PSOBB_CLIENT_SAFETY_TEST_SEAM)
namespace detail {

bool SetHookPatchOperationsForTesting(
    const HookPatchOperationsForTesting operations) noexcept {
  ExclusiveOwnershipLock lock;
  if (std::any_of(
          g_owned_patches.begin(),
          g_owned_patches.end(),
          [](const OwnedPatch& patch) { return patch.owner_id != 0U; })) {
    return false;
  }
  g_test_operations = operations;
  return true;
}

}  // namespace detail
#endif

bool IsHookPatchOwnerActive(const HookPatchOwner owner) noexcept {
  if (owner.value == 0U) {
    return false;
  }
  ExclusiveOwnershipLock lock;
  return OwnerActiveUnlocked(owner.value);
}

HookPatchResult InstallHookPatchTransaction(
    const HookPatchOwner owner,
    const ExecutableRange executable_range,
    const std::span<const HookPatchSite> sites) noexcept {
  HookPatchResult result;
  if (owner.value == 0U || sites.empty() ||
      sites.size() > kMaximumHookPatchSites) {
    result.failure = HookPatchFailure::invalid_argument;
    return result;
  }

  AddressRange allowed{};
  if (!MakeAddressRange(
          executable_range.begin, executable_range.size, allowed)) {
    result.failure = HookPatchFailure::range_overflow;
    return result;
  }

  SYSTEM_INFO system_information{};
  GetSystemInfo(&system_information);
  const std::size_t page_size = system_information.dwPageSize;
  if (page_size < kMaximumHookPatchBytes) {
    result.failure = HookPatchFailure::invalid_argument;
    return result;
  }

  std::array<AddressRange, kMaximumHookPatchSites> ranges{};
  std::array<MEMORY_BASIC_INFORMATION, kMaximumHookPatchSites> memory{};
  for (std::size_t index = 0; index < sites.size(); ++index) {
    const HookPatchSite& site = sites[index];
    result.failed_site_index = static_cast<std::uint32_t>(index);
    if (site.expected.size() < kMinimumHookPatchBytes ||
        site.expected.size() > kMaximumHookPatchBytes ||
        site.replacement.size() != site.expected.size()) {
      result.failure = HookPatchFailure::invalid_argument;
      return result;
    }
    if (!MakeAddressRange(site.address, site.expected.size(), ranges[index])) {
      result.failure = HookPatchFailure::range_overflow;
      return result;
    }
    if (ranges[index].begin < allowed.begin ||
        ranges[index].end > allowed.end) {
      result.failure = HookPatchFailure::outside_executable_range;
      return result;
    }
    result.failure = ValidateExecutableMemory(ranges[index], memory[index]);
    if (result.failure != HookPatchFailure::none) {
      return result;
    }
    for (std::size_t previous = 0; previous < index; ++previous) {
      if (RangesOverlap(ranges[index], ranges[previous])) {
        result.failure = HookPatchFailure::ownership_conflict;
        return result;
      }
    }
  }

  ExclusiveOwnershipLock lock;
  if (OwnerActiveUnlocked(owner.value)) {
    result.failure = HookPatchFailure::transaction_active;
    return result;
  }
  for (std::size_t index = 0; index < sites.size(); ++index) {
    for (const auto& owned : g_owned_patches) {
      if (owned.owner_id == 0U) {
        continue;
      }
      AddressRange occupied{};
      if (!MakeAddressRange(owned.address, owned.size, occupied) ||
          RangesOverlap(ranges[index], occupied)) {
        result.failure = HookPatchFailure::ownership_conflict;
        result.failed_site_index = static_cast<std::uint32_t>(index);
        return result;
      }
    }
  }

  std::array<std::size_t, kMaximumHookPatchSites> slots{};
  std::size_t available = 0U;
  for (std::size_t index = 0;
       index < g_owned_patches.size() && available < sites.size();
       ++index) {
    if (g_owned_patches[index].owner_id == 0U) {
      slots[available++] = index;
    }
  }
  if (available != sites.size()) {
    result.failure = HookPatchFailure::ownership_capacity_exceeded;
    return result;
  }

  for (std::size_t index = 0; index < sites.size(); ++index) {
    if (!BytesEqual(sites[index].address, sites[index].expected)) {
      result.failure = HookPatchFailure::expected_bytes_mismatch;
      result.failed_site_index = static_cast<std::uint32_t>(index);
      return result;
    }
  }

  for (std::size_t index = 0; index < sites.size(); ++index) {
    OwnedPatch& owned = g_owned_patches[slots[index]];
    owned.owner_id = owner.value;
    owned.site_index = static_cast<std::uint32_t>(index);
    owned.address = sites[index].address;
    owned.size = sites[index].expected.size();
    owned.allocation_base = memory[index].AllocationBase;
    owned.memory_type = memory[index].Type;
    owned.original_protection = memory[index].Protect;
    std::copy(
        sites[index].expected.begin(),
        sites[index].expected.end(),
        owned.expected.begin());
    std::copy(
        sites[index].replacement.begin(),
        sites[index].replacement.end(),
        owned.replacement.begin());
  }

  for (std::size_t index = 0; index < sites.size(); ++index) {
    HookPatchFailure claim = AcquirePageClaims(
        g_owned_patches[slots[index]], page_size);
    if (claim == HookPatchFailure::none) {
      claim = AcquireByteClaims(g_owned_patches[slots[index]]);
    }
    if (claim == HookPatchFailure::none) {
      continue;
    }
    for (std::size_t reserved = 0; reserved < sites.size(); ++reserved) {
      ClearRecord(g_owned_patches[slots[reserved]]);
    }
    result.failure = claim;
    result.failed_site_index = static_cast<std::uint32_t>(index);
    return result;
  }

  for (std::size_t index = 0; index < sites.size(); ++index) {
    OwnedPatch& owned = g_owned_patches[slots[index]];
    const HookPatchFailure failure = ApplyRecord(owned);
    if (failure == HookPatchFailure::none) {
      ++result.applied_count;
      continue;
    }

    result.failure = failure;
    result.failed_site_index = static_cast<std::uint32_t>(index);
    for (std::size_t position = index + 1U; position > 0U; --position) {
      OwnedPatch& candidate = g_owned_patches[slots[position - 1U]];
      const bool had_effect =
          candidate.write_attempted || candidate.installed ||
          candidate.protection_uncertain ||
          candidate.instruction_cache_uncertain;
      bool restored = false;
      const HookPatchFailure current =
          RollbackRecord(candidate, restored);
      if (restored) {
        if (had_effect) {
          ++result.rolled_back_count;
        }
        ClearRecord(candidate);
      } else {
        result.rollback_complete = false;
        if (result.rollback_failure == HookPatchFailure::none) {
          result.rollback_failure = current;
          result.rollback_failed_site_index = candidate.site_index;
        }
      }
    }
    for (std::size_t position = index + 1U;
         position < sites.size();
         ++position) {
      ClearRecord(g_owned_patches[slots[position]]);
    }
    return result;
  }

  result.failure = HookPatchFailure::none;
  result.failed_site_index =
      std::numeric_limits<std::uint32_t>::max();
  return result;
}

HookPatchResult RollbackHookPatchTransaction(
    const HookPatchOwner owner) noexcept {
  HookPatchResult result;
  if (owner.value == 0U) {
    result.failure = HookPatchFailure::invalid_argument;
    return result;
  }

  ExclusiveOwnershipLock lock;
  std::array<std::size_t, kOwnershipCapacity> slots{};
  std::size_t count = 0U;
  for (std::size_t index = 0; index < g_owned_patches.size(); ++index) {
    if (g_owned_patches[index].owner_id == owner.value) {
      slots[count++] = index;
    }
  }
  if (count == 0U) {
    return result;
  }

  for (std::size_t position = count; position > 0U; --position) {
    OwnedPatch& owned = g_owned_patches[slots[position - 1U]];
    bool restored = false;
    const HookPatchFailure failure = RollbackRecord(owned, restored);
    if (restored) {
      ++result.rolled_back_count;
      ClearRecord(owned);
    } else {
      result.rollback_complete = false;
      if (result.failure == HookPatchFailure::none) {
        result.failure = failure;
        result.failed_site_index = owned.site_index;
      }
      if (result.rollback_failure == HookPatchFailure::none) {
        result.rollback_failure = failure;
        result.rollback_failed_site_index = owned.site_index;
      }
    }
  }

  if (result.rollback_complete) {
    result.failure = HookPatchFailure::none;
    result.failed_site_index =
        std::numeric_limits<std::uint32_t>::max();
  }
  return result;
}

}  // namespace psobb::client_safety
