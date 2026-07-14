#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace psobb::enhancement {

[[nodiscard]] bool ComputeSha256(
    std::span<const std::byte> bytes,
    std::array<std::uint8_t, 32>& digest,
    std::wstring& failure);

[[nodiscard]] std::wstring HexEncode(
    const std::array<std::uint8_t, 32>& digest);

}  // namespace psobb::enhancement
