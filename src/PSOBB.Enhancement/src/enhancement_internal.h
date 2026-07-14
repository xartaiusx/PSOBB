#pragma once

#include <windows.h>

namespace psobb::enhancement {

void SetEnhancementModule(HMODULE module) noexcept;
DWORD WINAPI EnhancementInitializationThread(void*) noexcept;

}  // namespace psobb::enhancement
