#pragma once

#include <cstddef>
#include <cstdint>

namespace psobb::gameplay {

struct Send60CombatAttempt {
  std::uint32_t subcommand_header_le;
  std::uint32_t subcommand_byte_count;
  std::uint32_t local_client_id;
};

// Reads only the four-byte G_ClientIDHeader and retains no source pointer or
// payload.
// Invalid native length/framing is passed through by the hook; this decoder
// simply declines data that cannot contain a complete command header.
[[nodiscard]] bool DecodeSend60CombatAttempt(
    const void* source,
    std::size_t length,
    Send60CombatAttempt& attempt) noexcept;

}  // namespace psobb::gameplay
