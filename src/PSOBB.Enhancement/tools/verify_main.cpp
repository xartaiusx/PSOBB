#include "psobb_enhancement/pinned_image.h"

#include <windows.h>

#include <iostream>
#include <string>

int wmain(const int argument_count, wchar_t** arguments) {
  using psobb::enhancement::ImageVerification;
  using psobb::enhancement::VerifyPinnedExecutable;
  using psobb::enhancement::kPinnedSha256;

  if (argument_count != 2) {
    std::wcerr
        << L"Usage: PSOBB.Enhancement.Verify.exe <path-to-Psobb.exe>\n";
    return 2;
  }

  const std::wstring path(arguments[1]);
  const ImageVerification verification = VerifyPinnedExecutable(path);
  std::wcout << L"PSOBB.Enhancement clean-room verifier\n"
             << L"Path: " << path << L"\n"
             << L"Expected SHA-256: " << kPinnedSha256 << L"\n"
             << L"Actual SHA-256:   "
             << (verification.actual_sha256.empty()
                     ? L"<unavailable>"
                     : verification.actual_sha256)
             << L"\n"
             << L"File size gate:  "
             << (verification.file_size_matched ? L"PASS" : L"FAIL")
             << L"\n"
             << L"SHA-256 gate:     "
             << (verification.sha256_matched ? L"PASS" : L"FAIL")
             << L"\n"
             << L"PE32 gate:        "
             << (verification.pe_contract_matched ? L"PASS" : L"FAIL")
             << L"\n"
             << L"Byte gates:       "
             << (verification.expected_bytes_matched ? L"PASS" : L"FAIL")
             << L"\n";

  if (!verification.passed()) {
    std::wcerr << L"VERDICT: FAIL\nReason: " << verification.failure
               << L"\n";
    return 1;
  }

  std::wcout << L"VERDICT: PASS\n";
  return 0;
}
