#include "psobb_client_safety/relative_call_hook.h"

#include "relative_call_hook_test_seam.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>

namespace {

int g_failures = 0;

#define CHECK(condition)                                                \
  do {                                                                  \
    if (!(condition)) {                                                 \
      std::cerr << __FILE__ << ':' << __LINE__                         \
                << ": check failed: " #condition "\n";               \
      ++g_failures;                                                     \
    }                                                                   \
  } while (false)

extern "C" __declspec(noinline) int __cdecl OriginalTarget() noexcept {
  return 1;
}

extern "C" __declspec(noinline) int __cdecl ReplacementTarget() noexcept {
  return 2;
}

extern "C" __declspec(noinline) int __cdecl ForeignTarget() noexcept {
  return 3;
}

#pragma section(".hktest", execute, read)
extern "C" __declspec(allocate(".hktest")) __declspec(align(16))
    unsigned char g_call_stub[9] = {
        0x90U,
        0x90U,
        0x90U,
        0xE8U,
        0U,
        0U,
        0U,
        0U,
        0xC3U};

inline constexpr std::size_t kCallOffset = 3U;
inline constexpr std::size_t kOperandOffset = 4U;

[[nodiscard]] std::uintptr_t AddressOf(
    int(__cdecl* function)() noexcept) noexcept {
  return reinterpret_cast<std::uintptr_t>(function);
}

[[nodiscard]] std::uintptr_t InstructionAddress() noexcept {
  return reinterpret_cast<std::uintptr_t>(g_call_stub + kCallOffset);
}

[[nodiscard]] LONG OperandFor(const std::uintptr_t target) noexcept {
  const std::int64_t delta = static_cast<std::int64_t>(target) -
                             static_cast<std::int64_t>(
                                 InstructionAddress() + 5U);
  CHECK(delta >= std::numeric_limits<std::int32_t>::min());
  CHECK(delta <= std::numeric_limits<std::int32_t>::max());
  return static_cast<LONG>(delta);
}

void SetOperand(const LONG operand) noexcept {
  static_cast<void>(InterlockedExchange(
      reinterpret_cast<LONG volatile*>(g_call_stub + kOperandOffset),
      operand));
  CHECK(FlushInstructionCache(
            GetCurrentProcess(), g_call_stub, sizeof(g_call_stub)) !=
        FALSE);
}

[[nodiscard]] LONG ReadOperand() noexcept {
  return InterlockedCompareExchange(
      reinterpret_cast<LONG volatile*>(g_call_stub + kOperandOffset),
      0,
      0);
}

void ResetStub() noexcept {
  SetOperand(OperandFor(AddressOf(&OriginalTarget)));
}

[[nodiscard]] int InvokeStub() noexcept {
  int result = 0;
  __asm {
    mov eax, offset g_call_stub
    call eax
    mov result, eax
  }
  return result;
}

[[nodiscard]] psobb::client_safety::ExecutableRange ImageRange() {
  const auto* const base = reinterpret_cast<const std::byte*>(
      GetModuleHandleW(nullptr));
  CHECK(base != nullptr);
  const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  CHECK(dos->e_magic == IMAGE_DOS_SIGNATURE);
  const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
      base + dos->e_lfanew);
  CHECK(nt->Signature == IMAGE_NT_SIGNATURE);
  return {
      reinterpret_cast<std::uintptr_t>(base),
      nt->OptionalHeader.SizeOfImage};
}

[[nodiscard]] psobb::client_safety::RelativeCallHookSite Site(
    const std::uintptr_t expected = AddressOf(&OriginalTarget),
    const std::uintptr_t replacement =
        AddressOf(&ReplacementTarget)) noexcept {
  return {InstructionAddress(), expected, replacement};
}

struct FlushFaults {
  std::uint32_t call_count = 0U;
  std::uint32_t fail_mask = 0U;
  std::uintptr_t last_address = 0U;
  std::size_t last_size = 0U;

  [[nodiscard]] static bool Flush(
      void* context,
      const std::uintptr_t address,
      const std::size_t size) noexcept {
    auto& faults = *static_cast<FlushFaults*>(context);
    ++faults.call_count;
    faults.last_address = address;
    faults.last_size = size;
    const std::uint32_t bit =
        faults.call_count <= 32U
            ? 1U << (faults.call_count - 1U)
            : 0U;
    if ((faults.fail_mask & bit) != 0U) {
      return false;
    }
    return FlushInstructionCache(
               GetCurrentProcess(),
               reinterpret_cast<const void*>(address),
               size) != FALSE;
  }
};

void SetFlushFaults(FlushFaults& faults) {
  using namespace psobb::client_safety::detail;
  CHECK(SetRelativeCallHookOperationsForTesting(
      RelativeCallHookOperationsForTesting{
          &faults, &FlushFaults::Flush}));
}

void ResetFlushFaults() {
  using namespace psobb::client_safety::detail;
  CHECK(SetRelativeCallHookOperationsForTesting({}));
}

void TestInstallInvokeAndRollback() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner owner{0x52454C43414C4C31ULL};

  CHECK(InvokeStub() == 1);
  CHECK(InstallRelativeCallHook(owner, ImageRange(), Site()).passed());
  CHECK(IsRelativeCallHookOwnerActive(owner));
  CHECK(ReadOperand() == OperandFor(AddressOf(&ReplacementTarget)));
  CHECK(InvokeStub() == 2);
  CHECK(InstallRelativeCallHook(owner, ImageRange(), Site()).failure ==
        RelativeCallHookFailure::owner_active);

  CHECK(RollbackRelativeCallHook(owner).passed());
  CHECK(!IsRelativeCallHookOwnerActive(owner));
  CHECK(ReadOperand() == OperandFor(AddressOf(&OriginalTarget)));
  CHECK(InvokeStub() == 1);
  CHECK(RollbackRelativeCallHook(owner).passed());
}

void TestExpectedMismatchIsInert() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner owner{0x52454C43414C4C32ULL};
  const RelativeCallHookResult result = InstallRelativeCallHook(
      owner, ImageRange(), Site(AddressOf(&ForeignTarget)));
  CHECK(result.failure ==
        RelativeCallHookFailure::expected_target_mismatch);
  CHECK(!IsRelativeCallHookOwnerActive(owner));
  CHECK(InvokeStub() == 1);
}

void TestForeignMutationIsNeverOverwritten() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner owner{0x52454C43414C4C33ULL};
  CHECK(InstallRelativeCallHook(owner, ImageRange(), Site()).passed());

  SetOperand(OperandFor(AddressOf(&ForeignTarget)));
  const RelativeCallHookResult rejected =
      RollbackRelativeCallHook(owner);
  CHECK(rejected.failure == RelativeCallHookFailure::foreign_mutation);
  CHECK(!rejected.rollback_complete);
  CHECK(IsRelativeCallHookOwnerActive(owner));
  CHECK(InvokeStub() == 3);

  SetOperand(OperandFor(AddressOf(&ReplacementTarget)));
  CHECK(RollbackRelativeCallHook(owner).passed());
  CHECK(InvokeStub() == 1);
}

void TestFlushFailureRollsBackAndCanRetry() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner recovered_owner{0x52454C43414C4C34ULL};
  FlushFaults recovered{};
  recovered.fail_mask = 1U;
  SetFlushFaults(recovered);

  const RelativeCallHookResult failed = InstallRelativeCallHook(
      recovered_owner, ImageRange(), Site());
  CHECK(failed.failure ==
        RelativeCallHookFailure::instruction_cache_flush_failed);
  CHECK(failed.rollback_complete);
  CHECK(failed.rollback_failure == RelativeCallHookFailure::none);
  CHECK(!IsRelativeCallHookOwnerActive(recovered_owner));
  CHECK(InvokeStub() == 1);
  CHECK(recovered.call_count == 2U);
  CHECK(recovered.last_address == InstructionAddress());
  CHECK(recovered.last_size == 5U);
  ResetFlushFaults();

  constexpr HookPatchOwner retry_owner{0x52454C43414C4C35ULL};
  FlushFaults retry{};
  retry.fail_mask = 3U;
  SetFlushFaults(retry);
  const RelativeCallHookResult retained = InstallRelativeCallHook(
      retry_owner, ImageRange(), Site());
  CHECK(retained.failure ==
        RelativeCallHookFailure::instruction_cache_flush_failed);
  CHECK(!retained.rollback_complete);
  CHECK(retained.rollback_failure ==
        RelativeCallHookFailure::instruction_cache_flush_failed);
  CHECK(IsRelativeCallHookOwnerActive(retry_owner));
  CHECK(ReadOperand() == OperandFor(AddressOf(&OriginalTarget)));
  CHECK(RollbackRelativeCallHook(retry_owner).passed());
  CHECK(retry.call_count == 3U);
  CHECK(!IsRelativeCallHookOwnerActive(retry_owner));
  ResetFlushFaults();
}

void TestExclusiveOwnership() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner first{0x52454C43414C4C36ULL};
  constexpr HookPatchOwner second{0x52454C43414C4C37ULL};
  CHECK(InstallRelativeCallHook(first, ImageRange(), Site()).passed());
  const RelativeCallHookResult conflict = InstallRelativeCallHook(
      second,
      ImageRange(),
      Site(AddressOf(&ReplacementTarget), AddressOf(&ForeignTarget)));
  CHECK(conflict.failure == RelativeCallHookFailure::ownership_conflict);
  CHECK(!IsRelativeCallHookOwnerActive(second));
  CHECK(RollbackRelativeCallHook(first).passed());
}

void TestOwnershipIsSharedWithHookPatch() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner relative_owner{0x52454C43414C4C39ULL};
  constexpr HookPatchOwner patch_owner{0x52454C43414C5031ULL};
  const std::array expected{std::byte{0x90U}, std::byte{0x90U}};
  const std::array replacement{std::byte{0x66U}, std::byte{0x90U}};
  const HookPatchSite patch_site{
      reinterpret_cast<std::uintptr_t>(g_call_stub),
      expected,
      replacement};

  CHECK(InstallRelativeCallHook(
            relative_owner, ImageRange(), Site())
            .passed());
  CHECK(InstallHookPatchTransaction(
            patch_owner, ImageRange(), {&patch_site, 1U})
            .failure == HookPatchFailure::ownership_conflict);
  CHECK(RollbackRelativeCallHook(relative_owner).passed());

  CHECK(InstallHookPatchTransaction(
            patch_owner, ImageRange(), {&patch_site, 1U})
            .passed());
  CHECK(InstallRelativeCallHook(
            relative_owner, ImageRange(), Site())
            .failure == RelativeCallHookFailure::ownership_conflict);
  CHECK(RollbackHookPatchTransaction(patch_owner).passed());
  CHECK(g_call_stub[0] == 0x90U);
  CHECK(g_call_stub[1] == 0x90U);
}

void TestValidation() {
  using namespace psobb::client_safety;
  ResetStub();
  constexpr HookPatchOwner owner{0x52454C43414C4C38ULL};
  const ExecutableRange image = ImageRange();

  CHECK(InstallRelativeCallHook({}, image, Site()).failure ==
        RelativeCallHookFailure::invalid_argument);
  CHECK(InstallRelativeCallHook(
            owner,
            image,
            {Site().instruction_address + 1U,
             Site().expected_target,
             Site().replacement_target})
            .failure == RelativeCallHookFailure::invalid_argument);
  CHECK(InstallRelativeCallHook(
            owner,
            image,
            {Site().instruction_address,
             Site().expected_target,
             Site().expected_target})
            .failure == RelativeCallHookFailure::invalid_argument);
  CHECK(InstallRelativeCallHook(
            owner, {image.begin, 1U}, Site())
            .failure == RelativeCallHookFailure::outside_executable_range);
  CHECK(InstallRelativeCallHook(
            owner,
            {std::numeric_limits<std::uintptr_t>::max() - 1U, 4U},
            Site())
            .failure == RelativeCallHookFailure::range_overflow);
  SYSTEM_INFO system_info{};
  GetSystemInfo(&system_info);
  const std::uintptr_t crossing_instruction =
      image.begin + system_info.dwPageSize - 1U;
  CHECK(InstallRelativeCallHook(
            owner,
            image,
            {crossing_instruction,
             Site().expected_target,
             Site().replacement_target})
            .failure ==
        RelativeCallHookFailure::instruction_crosses_page);
  CHECK(InstallRelativeCallHook(
            owner,
            image,
            {std::numeric_limits<std::uintptr_t>::max(),
             Site().expected_target,
             Site().replacement_target})
            .failure == RelativeCallHookFailure::range_overflow);
  CHECK(InstallRelativeCallHook(
            owner,
            image,
            {Site().instruction_address, 1U, Site().replacement_target})
            .failure ==
        RelativeCallHookFailure::target_not_committed_executable);
  CHECK(!IsRelativeCallHookOwnerActive(owner));
}

}  // namespace

int main() {
  TestInstallInvokeAndRollback();
  TestExpectedMismatchIsInert();
  TestForeignMutationIsNeverOverwritten();
  TestFlushFailureRollsBackAndCanRetry();
  TestExclusiveOwnership();
  TestOwnershipIsSharedWithHookPatch();
  TestValidation();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout
      << "All PSOBB.ClientSafety relative-call-hook tests passed\n";
  return 0;
}
