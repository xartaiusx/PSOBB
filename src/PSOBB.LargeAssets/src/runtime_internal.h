#pragma once

#include <windows.h>

namespace psobb::large_assets {

void SetLargeAssetsModule(HMODULE module) noexcept;
void StartInitializationThread() noexcept;
void RollbackForProcessDetach() noexcept;

}  // namespace psobb::large_assets
