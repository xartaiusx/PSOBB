#include "send60_probe.h"

#include "psobb_gameplay/observation.h"

#include <cstddef>
#include <cstdint>

namespace psobb::gameplay {

static_assert(sizeof(std::size_t) == sizeof(std::uint32_t));

bool DecodeSend60CombatAttempt(
    const void* const source,
    const std::size_t length,
    Send60CombatAttempt& attempt) noexcept {
  constexpr std::size_t kCommandHeaderBytes = 4U;
  constexpr std::uint8_t kFirstObservedCommand = 0x43U;
  constexpr std::uint8_t kLastObservedCommand = 0x48U;

  if (source == nullptr || length < kCommandHeaderBytes) {
    return false;
  }

  const auto* const bytes = static_cast<const std::uint8_t*>(source);
  if (bytes[0] < kFirstObservedCommand ||
      bytes[0] > kLastObservedCommand) {
    return false;
  }

  Send60CombatAttempt decoded{};
  decoded.subcommand_header_le =
      static_cast<std::uint32_t>(bytes[0]) |
      (static_cast<std::uint32_t>(bytes[1]) << 8U) |
      (static_cast<std::uint32_t>(bytes[2]) << 16U) |
      (static_cast<std::uint32_t>(bytes[3]) << 24U);
  decoded.subcommand_byte_count = static_cast<std::uint32_t>(length);
  decoded.local_client_id =
      static_cast<std::uint32_t>(bytes[2]) |
      (static_cast<std::uint32_t>(bytes[3]) << 8U);
  attempt = decoded;
  return true;
}

}  // namespace psobb::gameplay
