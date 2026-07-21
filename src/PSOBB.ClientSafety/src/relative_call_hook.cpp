#include "psobb_client_safety/relative_call_hook.h"

#if defined(PSOBB_CLIENT_SAFETY_RELATIVE_CALL_TEST_SEAM)
#include "relative_call_hook_test_seam.h"
#endif

#include <windows.h>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace psobb::client_safety {
namespace {

inline constexpr std::byte kNearCallOpcode{0xE8};
inline constexpr std::size_t kNearCallInstructionBytes = 5U;
inline constexpr std::size_t kRelativeOperandOffset = 1U;
inline constexpr std::size_t kRelativeOperandBytes = sizeof(LONG);
inline constexpr std::size_t kOwnershipCapacity = 16U;

static_assert(sizeof(void*) == 4U);
static_assert(sizeof(LONG) == 4U);

struct AddressRange {
  std::uintptr_t begin;
  std::uintptr_t end;
};

struct OwnedRelativeCall {
  std::uint64_t owner_id = 0U;
  std::uintptr_t instruction_address = 0U;
  LONG expected_operand = 0;
  LONG replacement_operand = 0;
  void* allocation_base = nullptr;
  DWORD memory_type = 0U;
  DWORD protection = 0U;
  HANDLE page_claim = nullptr;
  std::array<HANDLE, kNearCallInstructionBytes> byte_claims{};
};

SRWLOCK g_relative_call_lock = SRWLOCK_INIT;
std::array<OwnedRelativeCall, kOwnershipCapacity> g_owned_relative_calls{};

#if defined(PSOBB_CLIENT_SAFETY_RELATIVE_CALL_TEST_SEAM)
detail::RelativeCallHookOperationsForTesting g_test_operations{};
#endif

class ExclusiveRelativeCallLock final {
 public:
  ExclusiveRelativeCallLock() noexcept {
    AcquireSRWLockExclusive(&g_relative_call_lock);
  }

  ~ExclusiveRelativeCallLock() noexcept {
    ReleaseSRWLockExclusive(&g_relative_call_lock);
  }

  ExclusiveRelativeCallLock(const ExclusiveRelativeCallLock&) = delete;
  ExclusiveRelativeCallLock& operator=(
      const ExclusiveRelativeCallLock&) = delete;
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

[[nodiscard]] bool Contains(
    const AddressRange container,
    const AddressRange value) noexcept {
  return value.begin >= container.begin && value.end <= container.end;
}

[[nodiscard]] bool RegionContains(
    const MEMORY_BASIC_INFORMATION& information,
    const AddressRange range) noexcept {
  AddressRange region{};
  return MakeAddressRange(
             reinterpret_cast<std::uintptr_t>(information.BaseAddress),
             information.RegionSize,
             region) &&
         Contains(region, range);
}

[[nodiscard]] bool IsWritableExecutableProtection(
    const DWORD protection) noexcept {
  const DWORD base = protection & 0xFFU;
  return (protection & (PAGE_GUARD | PAGE_NOACCESS)) == 0U &&
         (base == PAGE_EXECUTE_READWRITE ||
          base == PAGE_EXECUTE_WRITECOPY);
}

[[nodiscard]] bool IsCommittedExecutableTarget(
    const std::uintptr_t target) noexcept {
  if (target == 0U) {
    return false;
  }
  MEMORY_BASIC_INFORMATION information{};
  if (VirtualQuery(
          reinterpret_cast<const void*>(target),
          &information,
          sizeof(information)) != sizeof(information) ||
      information.State != MEM_COMMIT ||
      (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0U) {
    return false;
  }
  switch (information.Protect & 0xFFU) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] bool ComputeRelativeOperand(
    const std::uintptr_t instruction_address,
    const std::uintptr_t target,
    LONG& operand) noexcept {
  AddressRange instruction{};
  if (!MakeAddressRange(
          instruction_address, kNearCallInstructionBytes, instruction)) {
    return false;
  }
  const std::uint32_t delta_bits =
      static_cast<std::uint32_t>(target) -
      static_cast<std::uint32_t>(instruction.end);
  operand = std::bit_cast<LONG>(delta_bits);
  return true;
}

[[nodiscard]] bool ReadOpcode(
    const std::uintptr_t instruction_address,
    std::byte& opcode) noexcept {
  SIZE_T read = 0U;
  return ReadProcessMemory(
             GetCurrentProcess(),
             reinterpret_cast<const void*>(instruction_address),
             &opcode,
             sizeof(opcode),
             &read) != FALSE &&
         read == sizeof(opcode);
}

[[nodiscard]] RelativeCallHookFailure ValidateSite(
    const ExecutableRange executable_range,
    const RelativeCallHookSite site,
    MEMORY_BASIC_INFORMATION& information,
    LONG& expected_operand,
    LONG& replacement_operand) noexcept {
  if (site.instruction_address == 0U ||
      site.expected_target == 0U || site.replacement_target == 0U ||
      site.expected_target == site.replacement_target) {
    return RelativeCallHookFailure::invalid_argument;
  }
  if (site.instruction_address >
      std::numeric_limits<std::uintptr_t>::max() -
          kRelativeOperandOffset) {
    return RelativeCallHookFailure::range_overflow;
  }
  if ((site.instruction_address + kRelativeOperandOffset) %
          alignof(LONG) !=
      0U) {
    return RelativeCallHookFailure::invalid_argument;
  }

  AddressRange allowed{};
  AddressRange instruction{};
  if (!MakeAddressRange(
          executable_range.begin, executable_range.size, allowed) ||
      !MakeAddressRange(
          site.instruction_address,
          kNearCallInstructionBytes,
          instruction)) {
    return RelativeCallHookFailure::range_overflow;
  }
  if (!Contains(allowed, instruction)) {
    return RelativeCallHookFailure::outside_executable_range;
  }

  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);
  const std::size_t page_size = system_info.dwPageSize;
  if (page_size == 0U) {
    return RelativeCallHookFailure::ownership_claim_failed;
  }
  if (site.instruction_address / page_size !=
      (instruction.end - 1U) / page_size) {
    return RelativeCallHookFailure::instruction_crosses_page;
  }

  if (VirtualQuery(
          reinterpret_cast<const void*>(site.instruction_address),
          &information,
          sizeof(information)) != sizeof(information) ||
      !RegionContains(information, instruction) ||
      information.State != MEM_COMMIT || information.Type != MEM_IMAGE ||
      information.AllocationBase !=
          reinterpret_cast<void*>(executable_range.begin) ||
      !IsWritableExecutableProtection(information.Protect)) {
    return RelativeCallHookFailure::
        site_not_committed_writable_executable_image;
  }

  std::byte opcode{};
  if (!ReadOpcode(site.instruction_address, opcode) ||
      opcode != kNearCallOpcode) {
    return RelativeCallHookFailure::opcode_mismatch;
  }
  if (!IsCommittedExecutableTarget(site.expected_target) ||
      !IsCommittedExecutableTarget(site.replacement_target)) {
    return RelativeCallHookFailure::target_not_committed_executable;
  }
  if (!ComputeRelativeOperand(
          site.instruction_address,
          site.expected_target,
          expected_operand) ||
      !ComputeRelativeOperand(
          site.instruction_address,
          site.replacement_target,
          replacement_operand)) {
    return RelativeCallHookFailure::target_out_of_range;
  }
  return RelativeCallHookFailure::none;
}

void ReleaseClaims(OwnedRelativeCall& owned) noexcept {
  for (HANDLE& claim : owned.byte_claims) {
    if (claim != nullptr) {
      CloseHandle(claim);
      claim = nullptr;
    }
  }
  if (owned.page_claim != nullptr) {
    CloseHandle(owned.page_claim);
    owned.page_claim = nullptr;
  }
}

void ClearRecord(OwnedRelativeCall& owned) noexcept {
  ReleaseClaims(owned);
  owned = {};
}

[[nodiscard]] RelativeCallHookFailure CreateExclusiveClaim(
    const wchar_t* format,
    const std::uintptr_t address,
    HANDLE& claim) noexcept {
  std::array<wchar_t, 96> name{};
  const int written = _snwprintf_s(
      name.data(),
      name.size(),
      _TRUNCATE,
      format,
      static_cast<unsigned long>(GetCurrentProcessId()),
      static_cast<unsigned long>(address));
  if (written <= 0) {
    return RelativeCallHookFailure::ownership_claim_failed;
  }

  SetLastError(ERROR_SUCCESS);
  claim = CreateFileMappingW(
      INVALID_HANDLE_VALUE,
      nullptr,
      PAGE_READONLY,
      0U,
      1U,
      name.data());
  const DWORD error = GetLastError();
  if (claim == nullptr) {
    return error == ERROR_INVALID_HANDLE
               ? RelativeCallHookFailure::ownership_conflict
               : RelativeCallHookFailure::ownership_claim_failed;
  }
  if (error == ERROR_ALREADY_EXISTS) {
    CloseHandle(claim);
    claim = nullptr;
    return RelativeCallHookFailure::ownership_conflict;
  }
  return RelativeCallHookFailure::none;
}

[[nodiscard]] RelativeCallHookFailure AcquireClaims(
    OwnedRelativeCall& owned) noexcept {
  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);
  const std::size_t page_size = system_info.dwPageSize;
  if (page_size == 0U) {
    return RelativeCallHookFailure::ownership_claim_failed;
  }
  const std::uintptr_t page = owned.instruction_address -
                              (owned.instruction_address % page_size);
  RelativeCallHookFailure failure = CreateExclusiveClaim(
      L"Local\\PSOBB.ClientSafety.HookPage.%08lX.%08lX",
      page,
      owned.page_claim);
  if (failure != RelativeCallHookFailure::none) {
    return failure;
  }

  for (std::size_t offset = 0U;
       offset < kNearCallInstructionBytes;
       ++offset) {
    failure = CreateExclusiveClaim(
        L"Local\\PSOBB.ClientSafety.HookByte.%08lX.%08lX",
        owned.instruction_address + offset,
        owned.byte_claims[offset]);
    if (failure != RelativeCallHookFailure::none) {
      ReleaseClaims(owned);
      return failure;
    }
  }
  return RelativeCallHookFailure::none;
}

[[nodiscard]] OwnedRelativeCall* FindOwner(
    const HookPatchOwner owner) noexcept {
  for (auto& owned : g_owned_relative_calls) {
    if (owned.owner_id == owner.value) {
      return &owned;
    }
  }
  return nullptr;
}

[[nodiscard]] OwnedRelativeCall* FindFreeRecord() noexcept {
  for (auto& owned : g_owned_relative_calls) {
    if (owned.owner_id == 0U) {
      return &owned;
    }
  }
  return nullptr;
}

[[nodiscard]] bool MemoryIdentityStillMatches(
    const OwnedRelativeCall& owned) noexcept {
  AddressRange instruction{};
  MEMORY_BASIC_INFORMATION information{};
  std::byte opcode{};
  return MakeAddressRange(
             owned.instruction_address,
             kNearCallInstructionBytes,
             instruction) &&
         VirtualQuery(
             reinterpret_cast<const void*>(owned.instruction_address),
             &information,
             sizeof(information)) == sizeof(information) &&
         RegionContains(information, instruction) &&
         information.State == MEM_COMMIT &&
         information.Type == owned.memory_type &&
         information.AllocationBase == owned.allocation_base &&
         information.Protect == owned.protection &&
         ReadOpcode(owned.instruction_address, opcode) &&
         opcode == kNearCallOpcode;
}

struct AtomicExchangeResult {
  bool completed;
  LONG observed;
};

// A foreign page-protection race must fail closed instead of terminating the
// game process. Keep SEH in a leaf function with no C++ unwinding objects.
[[nodiscard]] AtomicExchangeResult CompareExchangeOperand(
    const std::uintptr_t instruction_address,
    const LONG replacement,
    const LONG expected) noexcept {
  LONG observed = 0;
  __try {
    observed = InterlockedCompareExchange(
        reinterpret_cast<LONG volatile*>(
            instruction_address + kRelativeOperandOffset),
        replacement,
        expected);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return {false, 0};
  }
  return {true, observed};
}

[[nodiscard]] AtomicExchangeResult ReadOperand(
    const OwnedRelativeCall& owned) noexcept {
  return CompareExchangeOperand(owned.instruction_address, 0, 0);
}

[[nodiscard]] bool FlushRelativeCall(
    const std::uintptr_t instruction_address) noexcept {
#if defined(PSOBB_CLIENT_SAFETY_RELATIVE_CALL_TEST_SEAM)
  if (g_test_operations.flush != nullptr) {
    return g_test_operations.flush(
        g_test_operations.context,
        instruction_address,
        kNearCallInstructionBytes);
  }
#endif
  return FlushInstructionCache(
             GetCurrentProcess(),
             reinterpret_cast<const void*>(instruction_address),
             kNearCallInstructionBytes) != FALSE;
}

[[nodiscard]] RelativeCallHookFailure RollbackRecord(
    OwnedRelativeCall& owned,
    bool& complete) noexcept {
  complete = false;
  if (!MemoryIdentityStillMatches(owned)) {
    return RelativeCallHookFailure::foreign_mutation;
  }

  const AtomicExchangeResult restored = CompareExchangeOperand(
      owned.instruction_address,
      owned.expected_operand,
      owned.replacement_operand);
  if (!restored.completed) {
    return RelativeCallHookFailure::atomic_exchange_failed;
  }
  if (restored.observed != owned.replacement_operand &&
      restored.observed != owned.expected_operand) {
    return RelativeCallHookFailure::foreign_mutation;
  }

  if (!FlushRelativeCall(owned.instruction_address)) {
    return RelativeCallHookFailure::instruction_cache_flush_failed;
  }

  const AtomicExchangeResult verified = ReadOperand(owned);
  if (!verified.completed) {
    return RelativeCallHookFailure::atomic_exchange_failed;
  }
  if (verified.observed != owned.expected_operand) {
    return RelativeCallHookFailure::foreign_mutation;
  }

  complete = true;
  ClearRecord(owned);
  return RelativeCallHookFailure::none;
}

}  // namespace

#if defined(PSOBB_CLIENT_SAFETY_RELATIVE_CALL_TEST_SEAM)
namespace detail {

bool SetRelativeCallHookOperationsForTesting(
    const RelativeCallHookOperationsForTesting operations) noexcept {
  ExclusiveRelativeCallLock lock;
  for (const auto& owned : g_owned_relative_calls) {
    if (owned.owner_id != 0U) {
      return false;
    }
  }
  g_test_operations = operations;
  return true;
}

}  // namespace detail
#endif

RelativeCallHookResult InstallRelativeCallHook(
    const HookPatchOwner owner,
    const ExecutableRange executable_range,
    const RelativeCallHookSite site) noexcept {
  RelativeCallHookResult result{};
  if (owner.value == 0U) {
    result.failure = RelativeCallHookFailure::invalid_argument;
    return result;
  }

  ExclusiveRelativeCallLock lock;
  if (FindOwner(owner) != nullptr) {
    result.failure = RelativeCallHookFailure::owner_active;
    return result;
  }
  OwnedRelativeCall* const owned = FindFreeRecord();
  if (owned == nullptr) {
    result.failure =
        RelativeCallHookFailure::ownership_capacity_exceeded;
    return result;
  }

  MEMORY_BASIC_INFORMATION information{};
  LONG expected_operand = 0;
  LONG replacement_operand = 0;
  result.failure = ValidateSite(
      executable_range,
      site,
      information,
      expected_operand,
      replacement_operand);
  if (result.failure != RelativeCallHookFailure::none) {
    return result;
  }

  owned->owner_id = owner.value;
  owned->instruction_address = site.instruction_address;
  owned->expected_operand = expected_operand;
  owned->replacement_operand = replacement_operand;
  owned->allocation_base = information.AllocationBase;
  owned->memory_type = information.Type;
  owned->protection = information.Protect;

  result.failure = AcquireClaims(*owned);
  if (result.failure != RelativeCallHookFailure::none) {
    ClearRecord(*owned);
    return result;
  }
  if (!MemoryIdentityStillMatches(*owned)) {
    result.failure = RelativeCallHookFailure::foreign_mutation;
    ClearRecord(*owned);
    return result;
  }

  const AtomicExchangeResult installed = CompareExchangeOperand(
      owned->instruction_address,
      owned->replacement_operand,
      owned->expected_operand);
  if (!installed.completed) {
    result.failure = RelativeCallHookFailure::atomic_exchange_failed;
    ClearRecord(*owned);
    return result;
  }
  if (installed.observed != owned->expected_operand) {
    result.failure = RelativeCallHookFailure::expected_target_mismatch;
    ClearRecord(*owned);
    return result;
  }

  if (!FlushRelativeCall(owned->instruction_address)) {
    result.failure =
        RelativeCallHookFailure::instruction_cache_flush_failed;
    bool restored = false;
    result.rollback_failure = RollbackRecord(*owned, restored);
    result.rollback_complete = restored;
    return result;
  }

  const AtomicExchangeResult verified = ReadOperand(*owned);
  if (!verified.completed) {
    result.failure = RelativeCallHookFailure::atomic_exchange_failed;
    result.rollback_complete = false;
    result.rollback_failure = result.failure;
    return result;
  }
  if (verified.observed != owned->replacement_operand) {
    result.failure = RelativeCallHookFailure::foreign_mutation;
    if (verified.observed == owned->expected_operand) {
      ClearRecord(*owned);
    } else {
      result.rollback_complete = false;
      result.rollback_failure = result.failure;
    }
    return result;
  }
  return result;
}

RelativeCallHookResult RollbackRelativeCallHook(
    const HookPatchOwner owner) noexcept {
  RelativeCallHookResult result{};
  if (owner.value == 0U) {
    result.failure = RelativeCallHookFailure::invalid_argument;
    return result;
  }

  ExclusiveRelativeCallLock lock;
  OwnedRelativeCall* const owned = FindOwner(owner);
  if (owned == nullptr) {
    return result;
  }

  bool complete = false;
  result.failure = RollbackRecord(*owned, complete);
  result.rollback_complete = complete;
  if (!complete) {
    result.rollback_failure = result.failure;
  }
  return result;
}

bool IsRelativeCallHookOwnerActive(
    const HookPatchOwner owner) noexcept {
  if (owner.value == 0U) {
    return false;
  }
  ExclusiveRelativeCallLock lock;
  return FindOwner(owner) != nullptr;
}

}  // namespace psobb::client_safety
