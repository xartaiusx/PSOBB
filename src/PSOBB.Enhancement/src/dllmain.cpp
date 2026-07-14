#include "enhancement_internal.h"

#include "psobb_enhancement/api.h"

#include <windows.h>

namespace psobb::enhancement {

void StartInitializationThread() noexcept {
  HANDLE thread = CreateThread(
      nullptr, 0, EnhancementInitializationThread, nullptr, 0, nullptr);
  if (thread != nullptr) {
    CloseHandle(thread);
  }
}
}  // namespace psobb::enhancement

BOOL APIENTRY DllMain(
    HMODULE module, const DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    psobb::enhancement::SetEnhancementModule(module);
    DisableThreadLibraryCalls(module);
    psobb::enhancement::StartInitializationThread();
  } else if (reason == DLL_PROCESS_DETACH && reserved == nullptr) {
    // The module pins itself before installing a hook, so a normal unload
    // cannot leave a dangling function pointer. This path is retained for a
    // pre-initialization FreeLibrary call, where no writes have occurred.
  }
  return TRUE;
}
