#include "gameplay_internal.h"

#include <windows.h>

BOOL APIENTRY DllMain(
    HMODULE module,
    const DWORD reason,
    LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    psobb::gameplay::SetGameplayModule(module);
  }
  return TRUE;
}
