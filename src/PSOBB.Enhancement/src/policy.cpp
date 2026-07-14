#include "psobb_enhancement/policy.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>

namespace psobb::enhancement {

bool IsSupportedResolution(
    const std::uint32_t width, const std::uint32_t height) noexcept {
  return (width == 2560U && height == 1600U) ||
         (width == 3840U && height == 2400U);
}

bool ValidateConfiguration(
    const Configuration& configuration, std::wstring& error) {
  error.clear();
  if (!configuration.enabled) {
    return true;
  }

  if (!IsSupportedResolution(configuration.width, configuration.height)) {
    error = L"Resolution must be exactly 2560x1600 or 3840x2400";
    return false;
  }

  if (configuration.hud_minimap) {
    error = L"HUD/minimap adjustment is gated: no safe hook has been proven";
    return false;
  }

  if (configuration.automatic_device_recreation) {
    error =
        L"Automatic device recreation is gated: application resource "
        L"lifecycle has not been proven";
    return false;
  }

  return true;
}

d3d8::PresentParameters ApplyPresentationPolicy(
    const Configuration& configuration,
    const d3d8::PresentParameters& original) noexcept {
  d3d8::PresentParameters effective = original;
  if (!configuration.enabled ||
      !IsSupportedResolution(configuration.width, configuration.height)) {
    return effective;
  }

  effective.back_buffer_width = configuration.width;
  effective.back_buffer_height = configuration.height;
  if (configuration.window_mode != WindowMode::unchanged) {
    effective.windowed = TRUE;
    effective.full_screen_refresh_rate_hz = 0;
  }
  return effective;
}

bool IsPerspectiveProjection(const d3d8::Matrix& matrix) noexcept {
  for (const auto& row : matrix.value) {
    for (const float value : row) {
      if (!std::isfinite(value)) {
        return false;
      }
    }
  }

  constexpr float kNearZero = 0.001F;
  const auto near_zero = [](const float value) noexcept {
    return std::abs(value) <= kNearZero;
  };

  if (matrix.value[0][0] <= kNearZero ||
      matrix.value[1][1] <= kNearZero ||
      std::abs(matrix.value[2][3]) < 0.5F ||
      !near_zero(matrix.value[3][3])) {
    return false;
  }

  return near_zero(matrix.value[0][1]) &&
         near_zero(matrix.value[0][2]) &&
         near_zero(matrix.value[0][3]) &&
         near_zero(matrix.value[1][0]) &&
         near_zero(matrix.value[1][2]) &&
         near_zero(matrix.value[1][3]) &&
         near_zero(matrix.value[2][0]) &&
         near_zero(matrix.value[2][1]) &&
         near_zero(matrix.value[3][0]) &&
         near_zero(matrix.value[3][1]);
}

bool AdjustHorizontalFov(
    const Configuration& configuration,
    const d3d8::Matrix& original,
    d3d8::Matrix& adjusted) noexcept {
  adjusted = original;
  if (!configuration.enabled || !configuration.horizontal_fov ||
      !IsSupportedResolution(configuration.width, configuration.height) ||
      !IsPerspectiveProjection(original)) {
    return false;
  }

  constexpr float kSourceAspect = 4.0F / 3.0F;
  const float target_aspect = static_cast<float>(configuration.width) /
                              static_cast<float>(configuration.height);
  adjusted.value[0][0] *= kSourceAspect / target_aspect;
  return true;
}

}  // namespace psobb::enhancement
