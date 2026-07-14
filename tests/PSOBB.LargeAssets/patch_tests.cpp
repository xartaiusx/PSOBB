#include "psobb_large_assets/patch_plan.h"
#include "psobb_large_assets/pinned_image.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void Check(const bool condition, const char* expression) {
  if (!condition) {
    std::cerr << "FAIL: " << expression << '\n';
    ++g_failures;
  }
}

#define CHECK(expression) Check((expression), #expression)

struct FakeMemory {
  std::array<std::uint32_t, psobb::large_assets::kPatchSites.size()> values{};
  std::size_t write_calls = 0;
  std::size_t fail_apply_call = std::numeric_limits<std::size_t>::max();
  bool fail_apply_after_modify = false;
  std::uintptr_t fail_rollback_address = 0;

  FakeMemory() {
    for (std::size_t index = 0; index < values.size(); ++index) {
      values[index] =
          psobb::large_assets::kPatchSites[index].expected_value;
    }
  }
};

[[nodiscard]] std::size_t SiteIndex(const std::uintptr_t address) noexcept {
  for (std::size_t index = 0;
       index < psobb::large_assets::kPatchSites.size();
       ++index) {
    if (psobb::large_assets::kPatchSites[index].virtual_address == address) {
      return index;
    }
  }
  return psobb::large_assets::kPatchSites.size();
}

bool FakeRead(
    void* context,
    const std::uintptr_t address,
    std::uint32_t& value) noexcept {
  auto& memory = *static_cast<FakeMemory*>(context);
  const std::size_t index = SiteIndex(address);
  if (index >= memory.values.size()) {
    return false;
  }
  value = memory.values[index];
  return true;
}

bool FakeCompareWrite(
    void* context,
    const std::uintptr_t address,
    const std::uint32_t expected,
    const std::uint32_t replacement,
    bool& modified) noexcept {
  auto& memory = *static_cast<FakeMemory*>(context);
  const std::size_t index = SiteIndex(address);
  modified = false;
  if (index >= memory.values.size() || memory.values[index] != expected) {
    return false;
  }

  const bool is_apply =
      replacement == psobb::large_assets::kLargeAssetLimit;
  if (is_apply && memory.write_calls == memory.fail_apply_call) {
    ++memory.write_calls;
    if (memory.fail_apply_after_modify) {
      memory.values[index] = replacement;
      modified = true;
    }
    return false;
  }
  if (!is_apply && address == memory.fail_rollback_address) {
    return false;
  }

  ++memory.write_calls;
  memory.values[index] = replacement;
  modified = true;
  return true;
}

[[nodiscard]] psobb::large_assets::MemoryOperations Operations(
    FakeMemory& memory) noexcept {
  return {&memory, &FakeRead, &FakeCompareWrite};
}

void CheckAllOriginal(const FakeMemory& memory) {
  for (std::size_t index = 0; index < memory.values.size(); ++index) {
    CHECK(
        memory.values[index] ==
        psobb::large_assets::kPatchSites[index].expected_value);
  }
}

void TestPatchMetadata() {
  using namespace psobb::large_assets;
  CHECK(kUpstreamAddressEntryCount == 18U);
  CHECK(kPatchSites.size() == 17U);
  CHECK(kLargeAssetLimit == 100'000'000U);

  std::size_t standard_limit_count = 0;
  for (std::size_t left = 0; left < kPatchSites.size(); ++left) {
    CHECK(
        kPatchSites[left].virtual_address ==
        kPinnedImageBase + kPatchSites[left].rva);
    if (kPatchSites[left].expected_value == 0x00090000U) {
      ++standard_limit_count;
    }
    for (std::size_t right = left + 1U;
         right < kPatchSites.size();
         ++right) {
      CHECK(
          kPatchSites[left].virtual_address !=
          kPatchSites[right].virtual_address);
    }
  }
  CHECK(standard_limit_count == 16U);
  CHECK(kPatchSites.back().virtual_address == 0x007A6573U);
  CHECK(kPatchSites.back().expected_value == 0x00100000U);
}

void TestApplyAndRollback() {
  using namespace psobb::large_assets;
  FakeMemory memory;
  const TransactionResult applied = ApplyPatchTransaction(Operations(memory));
  CHECK(applied.passed);
  CHECK(applied.preflight_passed);
  CHECK(applied.applied_count == kPatchSites.size());
  for (const std::uint32_t value : memory.values) {
    CHECK(value == kLargeAssetLimit);
  }

  const TransactionResult rolled_back =
      RollbackPatchTransaction(Operations(memory));
  CHECK(rolled_back.passed);
  CHECK(rolled_back.rolled_back_count == kPatchSites.size());
  CheckAllOriginal(memory);
}

void TestPreflightMismatchWritesNothing() {
  using namespace psobb::large_assets;
  FakeMemory memory;
  memory.values[4] ^= 1U;
  const TransactionResult result = ApplyPatchTransaction(Operations(memory));
  CHECK(!result.passed);
  CHECK(!result.preflight_passed);
  CHECK(result.failed_site_index == 4U);
  CHECK(memory.write_calls == 0U);
}

void TestFailureBeforeWriteRollsBackPrefix() {
  using namespace psobb::large_assets;
  FakeMemory memory;
  memory.fail_apply_call = 5U;
  const TransactionResult result = ApplyPatchTransaction(Operations(memory));
  CHECK(!result.passed);
  CHECK(result.preflight_passed);
  CHECK(result.rollback_complete);
  CHECK(result.failed_site_index == 5U);
  CHECK(result.applied_count == 5U);
  CHECK(result.rolled_back_count == 5U);
  CheckAllOriginal(memory);
}

void TestFailureAfterWriteIncludesFailedSiteInRollback() {
  using namespace psobb::large_assets;
  FakeMemory memory;
  memory.fail_apply_call = 5U;
  memory.fail_apply_after_modify = true;
  const TransactionResult result = ApplyPatchTransaction(Operations(memory));
  CHECK(!result.passed);
  CHECK(result.rollback_complete);
  CHECK(result.applied_count == 6U);
  CHECK(result.rolled_back_count == 6U);
  CheckAllOriginal(memory);
}

void TestIncompleteRollbackCanBeRetried() {
  using namespace psobb::large_assets;
  FakeMemory memory;
  memory.fail_apply_call = 5U;
  memory.fail_apply_after_modify = true;
  memory.fail_rollback_address = kPatchSites[2].virtual_address;
  const TransactionResult result = ApplyPatchTransaction(Operations(memory));
  CHECK(!result.passed);
  CHECK(!result.rollback_complete);
  CHECK(memory.values[2] == kLargeAssetLimit);

  memory.fail_rollback_address = 0U;
  const TransactionResult retry =
      RollbackPatchTransaction(Operations(memory));
  CHECK(retry.passed);
  CHECK(retry.rolled_back_count == 1U);
  CheckAllOriginal(memory);
}

void PopulatePinnedHeaders(std::vector<std::byte>& bytes) {
  using namespace psobb::large_assets;
  IMAGE_DOS_HEADER dos{};
  dos.e_magic = IMAGE_DOS_SIGNATURE;
  dos.e_lfanew = 0x100;
  std::memcpy(bytes.data(), &dos, sizeof(dos));

  IMAGE_NT_HEADERS32 nt{};
  nt.Signature = IMAGE_NT_SIGNATURE;
  nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt.FileHeader.NumberOfSections = 9;
  nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt.OptionalHeader.ImageBase = static_cast<DWORD>(kPinnedImageBase);
  nt.OptionalHeader.SizeOfImage = kPinnedImageSize;
  nt.OptionalHeader.AddressOfEntryPoint = kPinnedEntryPointRva;
  nt.OptionalHeader.SectionAlignment = 0x1000U;
  nt.OptionalHeader.FileAlignment = 0x200U;
  nt.OptionalHeader.SizeOfHeaders = 0x400U;
  std::memcpy(bytes.data() + dos.e_lfanew, &nt, sizeof(nt));

  IMAGE_SECTION_HEADER text{};
  std::memcpy(text.Name, ".text", 5);
  text.Misc.VirtualSize = 0x00500000U;
  text.VirtualAddress = 0x00001000U;
  text.SizeOfRawData = 0x00500000U;
  text.PointerToRawData = 0x00000400U;
  const std::size_t sections =
      static_cast<std::size_t>(dos.e_lfanew) + sizeof(DWORD) +
      sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32);
  std::memcpy(bytes.data() + sections, &text, sizeof(text));
}

void TestPeRvaToRawMapping() {
  using namespace psobb::large_assets;
  std::vector<std::byte> file(kPinnedFileSize);
  PopulatePinnedHeaders(file);

  for (const auto& site : kPatchSites) {
    const std::size_t raw_offset =
        0x400U + static_cast<std::size_t>(site.rva - 0x1000U);
    std::memcpy(
        file.data() + raw_offset,
        &site.expected_value,
        sizeof(site.expected_value));
    // Keep the naive RVA-as-file-offset location deliberately different.
    const std::uint32_t decoy = 0xDEADBEEFU;
    std::memcpy(file.data() + site.rva, &decoy, sizeof(decoy));
  }

  std::wstring failure;
  CHECK(VerifyPinnedPePatchBytes(file, failure));
  const auto& changed = kPatchSites[3];
  const std::size_t changed_raw =
      0x400U + static_cast<std::size_t>(changed.rva - 0x1000U);
  file[changed_raw] ^= std::byte{0x01};
  CHECK(!VerifyPinnedPePatchBytes(file, failure));
  CHECK(failure.find(L"005B913F") != std::wstring::npos);
}

void TestLoadedImageUsesRvas() {
  using namespace psobb::large_assets;
  std::vector<std::byte> image(kPinnedImageSize);
  PopulatePinnedHeaders(image);
  for (const auto& site : kPatchSites) {
    std::memcpy(
        image.data() + site.rva,
        &site.expected_value,
        sizeof(site.expected_value));
  }

  std::wstring failure;
  CHECK(VerifyLoadedImage(image, failure));
  image[kPatchSites[0].rva] ^= std::byte{0x01};
  CHECK(!VerifyLoadedImage(image, failure));
  CHECK(failure.find(L"00800C32") != std::wstring::npos);
}

}  // namespace

int main() {
  TestPatchMetadata();
  TestApplyAndRollback();
  TestPreflightMismatchWritesNothing();
  TestFailureBeforeWriteRollsBackPrefix();
  TestFailureAfterWriteIncludesFailedSiteInRollback();
  TestIncompleteRollbackCanBeRetried();
  TestPeRvaToRawMapping();
  TestLoadedImageUsesRvas();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.LargeAssets tests passed\n";
  return 0;
}
