#include "psobb_large_assets/patch_plan.h"
#include "psobb_large_assets/pinned_image.h"

#include <windows.h>

#include <cstdint>
#include <iomanip>
#include <iostream>

int wmain(const int argc, wchar_t** argv) {
  using namespace psobb::large_assets;
  if (argc != 2) {
    std::wcerr << L"Usage: PSOBB.LargeAssets.Verify.exe <Psobb.exe>\n";
    return 2;
  }

  const ImageVerification verification = VerifyPinnedExecutable(argv[1]);
  std::wcout << L"fileSizeMatched="
             << (verification.file_size_matched ? L"true" : L"false")
             << L"\nsha256Matched="
             << (verification.sha256_matched ? L"true" : L"false")
             << L"\npeContractMatched="
             << (verification.pe_contract_matched ? L"true" : L"false")
             << L"\npatchBytesMatched="
             << (verification.patch_bytes_matched ? L"true" : L"false")
             << L"\nactualSha256=" << verification.actual_sha256
             << L"\nupstreamAddressEntries=" << kUpstreamAddressEntryCount
             << L"\nuniquePatchSites=" << kPatchSites.size()
             << L"\npatchValue=" << kLargeAssetLimit << L'\n';

  for (const auto& site : kPatchSites) {
    std::wcout << L"site=0x" << std::uppercase << std::hex
               << std::setw(8) << std::setfill(L'0')
               << site.virtual_address << L",rva=0x" << std::setw(8)
               << site.rva << L",expected=0x" << std::setw(8)
               << site.expected_value << std::dec << L'\n';
  }

  if (!verification.passed()) {
    std::wcerr << L"failure=" << verification.failure << L'\n';
    return 1;
  }
  return 0;
}
