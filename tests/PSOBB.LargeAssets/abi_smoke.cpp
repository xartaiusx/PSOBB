#include "psobb_large_assets/api.h"

#include <windows.h>

#include <iostream>
#include <string>

namespace {

using GetCapabilitiesFunction = BOOL(WINAPI*)(
    psobb::large_assets::CapabilitiesV1*);
using GetVersionFunction = const wchar_t*(WINAPI*)();
using InitializeFunction = BOOL(WINAPI*)();
using RollbackFunction = BOOL(WINAPI*)();

}  // namespace

int wmain(const int argc, wchar_t** argv) {
  if (argc != 2) {
    std::wcerr << L"Usage: abi-smoke <PSOBB.LargeAssets.asi>\n";
    return 2;
  }

  HMODULE module = LoadLibraryW(argv[1]);
  if (module == nullptr) {
    std::wcerr << L"LoadLibraryW failed: " << GetLastError() << L'\n';
    return 1;
  }

  auto get_capabilities = reinterpret_cast<GetCapabilitiesFunction>(
      GetProcAddress(module, "PSOBBLargeAssets_GetCapabilities"));
  auto get_version = reinterpret_cast<GetVersionFunction>(
      GetProcAddress(module, "PSOBBLargeAssets_GetVersion"));
  auto initialize = reinterpret_cast<InitializeFunction>(
      GetProcAddress(module, "PSOBBLargeAssets_Initialize"));
  auto rollback = reinterpret_cast<RollbackFunction>(
      GetProcAddress(module, "PSOBBLargeAssets_Rollback"));
  if (get_capabilities == nullptr || get_version == nullptr ||
      initialize == nullptr || rollback == nullptr) {
    std::cerr << "An expected undecorated export is missing\n";
    FreeLibrary(module);
    return 1;
  }

  psobb::large_assets::CapabilitiesV1 capabilities{};
  capabilities.struct_size = sizeof(capabilities);
  const wchar_t* version = get_version();
  const bool passed = version != nullptr && version[0] != L'\0' &&
                      initialize() &&
                      get_capabilities(&capabilities) &&
                      capabilities.abi_version ==
                          psobb::large_assets::kCapabilityAbiVersion &&
                      capabilities.state ==
                          psobb::large_assets::RuntimeState::
                              disabled_by_config &&
                      capabilities.flags == 0U &&
                      capabilities.patch_value == 100'000'000U &&
                      capabilities.upstream_address_entries == 18U &&
                      capabilities.unique_patch_sites == 17U && rollback();
  FreeLibrary(module);
  if (!passed) {
    std::cerr << "Large-assets ABI smoke test failed\n";
    return 1;
  }
  std::cout << "PSOBB.LargeAssets ABI smoke test passed\n";
  return 0;
}
