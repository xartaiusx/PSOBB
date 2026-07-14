#pragma once

#include "psobb_enhancement/d3d8_abi.h"

#include <cstdint>
#include <string>

namespace psobb::enhancement {

enum class WindowMode {
  unchanged,
  borderless,
  resizable,
};

struct Configuration {
  bool enabled = false;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  bool horizontal_fov = false;
  WindowMode window_mode = WindowMode::unchanged;
  bool hud_minimap = false;
  bool automatic_device_recreation = false;
};

[[nodiscard]] bool IsSupportedResolution(
    std::uint32_t width, std::uint32_t height) noexcept;

[[nodiscard]] bool ValidateConfiguration(
    const Configuration& configuration, std::wstring& error);

[[nodiscard]] d3d8::PresentParameters ApplyPresentationPolicy(
    const Configuration& configuration,
    const d3d8::PresentParameters& original) noexcept;

[[nodiscard]] bool IsPerspectiveProjection(
    const d3d8::Matrix& matrix) noexcept;

[[nodiscard]] bool AdjustHorizontalFov(
    const Configuration& configuration,
    const d3d8::Matrix& original,
    d3d8::Matrix& adjusted) noexcept;

}  // namespace psobb::enhancement
