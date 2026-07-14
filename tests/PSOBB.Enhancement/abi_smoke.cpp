#include "psobb_enhancement/api.h"

#include <windows.h>

#include <iostream>
#include <string>

namespace {

using Initialize = BOOL(WINAPI*)();
using GetCapabilities = BOOL(WINAPI*)(
    psobb::enhancement::CapabilitiesV1* capabilities);
using GetVersionFunction = const wchar_t*(WINAPI*)();
using Rollback = BOOL(WINAPI*)();

template <typename Function>
[[nodiscard]] Function Resolve(HMODULE module, const char* name) noexcept {
  return reinterpret_cast<Function>(GetProcAddress(module, name));
}

}  // namespace

int wmain(const int argument_count, wchar_t** arguments) {
  using namespace psobb::enhancement;
  if (argument_count != 2) {
    std::cerr << "ABI smoke test requires the ASI path\n";
    return 2;
  }

  HMODULE module = LoadLibraryW(arguments[1]);
  if (module == nullptr) {
    std::cerr << "LoadLibraryW failed: " << GetLastError() << '\n';
    return 1;
  }

  const auto initialize = Resolve<Initialize>(
      module, "PSOBBEnhancement_Initialize");
  const auto get_capabilities = Resolve<GetCapabilities>(
      module, "PSOBBEnhancement_GetCapabilities");
  const auto get_version = Resolve<GetVersionFunction>(
      module, "PSOBBEnhancement_GetVersion");
  const auto rollback = Resolve<Rollback>(
      module, "PSOBBEnhancement_Rollback");

  if (initialize == nullptr || get_capabilities == nullptr ||
      get_version == nullptr || rollback == nullptr) {
    std::cerr << "One or more undecorated ABI exports are missing\n";
    FreeLibrary(module);
    return 1;
  }

  if (!initialize()) {
    std::cerr << "Disabled-by-default initialization unexpectedly failed\n";
    FreeLibrary(module);
    return 1;
  }

  CapabilitiesV1 capabilities{};
  capabilities.struct_size = sizeof(capabilities);
  if (!get_capabilities(&capabilities) ||
      capabilities.abi_version != kCapabilityAbiVersion ||
      capabilities.state != RuntimeState::disabled_by_config ||
      capabilities.flags != capability_none ||
      std::wstring(get_version()) != kVersion) {
    std::cerr << "Capability ABI returned an unexpected disabled state\n";
    FreeLibrary(module);
    return 1;
  }

  if (!rollback()) {
    std::cerr << "No-write rollback unexpectedly failed\n";
    FreeLibrary(module);
    return 1;
  }

  FreeLibrary(module);
  std::cout << "PSOBB.Enhancement ABI smoke test passed\n";
  return 0;
}
