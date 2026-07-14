#include "runtime_internal.h"

#include <windows.h>

BOOL APIENTRY DllMain(
    HMODULE module,
    const DWORD reason,
    LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    psobb::large_assets::SetLargeAssetsModule(module);
    DisableThreadLibraryCalls(module);
    psobb::large_assets::StartInitializationThread();
  } else if (reason == DLL_PROCESS_DETACH && reserved == nullptr) {
    // FreeLibrary detach only. Process termination discards the address space;
    // attempting writes then would add risk without restoring persistent data.
    psobb::large_assets::RollbackForProcessDetach();
  }
  return TRUE;
}
