#include "send60_probe.h"

#include "psobb_gameplay/observation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>

namespace {

int g_failures = 0;

#define CHECK(condition)                                                \
  do {                                                                  \
    if (!(condition)) {                                                 \
      std::cerr << __FILE__ << ':' << __LINE__                         \
                << ": check failed: " #condition "\n";               \
      ++g_failures;                                                     \
    }                                                                   \
  } while (false)

void TestObservedCommandRange() {
  using namespace psobb::gameplay;
  for (std::uint8_t command = 0x43U; command <= 0x48U; ++command) {
    const std::array<std::uint8_t, 8> bytes{
        command, 2U, 0xA5U, 0x5AU, 3U, 0U, 0x11U, 0x22U};
    Send60CombatAttempt attempt{};
    CHECK(DecodeSend60CombatAttempt(
        bytes.data(), bytes.size(), attempt));
    CHECK(attempt.subcommand_header_le ==
          (0x5AA50200U | command));
    CHECK(attempt.subcommand_byte_count == bytes.size());
    CHECK(attempt.local_client_id == 0x5AA5U);
  }
}

void TestUnrelatedAndTruncatedCommandsAreIgnored() {
  using namespace psobb::gameplay;
  const std::array<std::uint8_t, 6> below{
      0x42U, 1U, 0U, 0U, 2U, 0U};
  const std::array<std::uint8_t, 6> above{
      0x49U, 1U, 0U, 0U, 2U, 0U};
  const std::array<std::uint8_t, 3> short_header{0x43U, 1U, 0U};
  Send60CombatAttempt unchanged{1U, 2U, 3U};
  CHECK(!DecodeSend60CombatAttempt(
      below.data(), below.size(), unchanged));
  CHECK(!DecodeSend60CombatAttempt(
      above.data(), above.size(), unchanged));
  CHECK(!DecodeSend60CombatAttempt(
      short_header.data(), short_header.size(), unchanged));
  CHECK(!DecodeSend60CombatAttempt(nullptr, 8U, unchanged));
  CHECK(unchanged.subcommand_header_le == 1U);
  CHECK(unchanged.subcommand_byte_count == 2U);
  CHECK(unchanged.local_client_id == 3U);
}

void TestMinimumHeaderIncludesClientId() {
  using namespace psobb::gameplay;
  const std::array<std::uint8_t, 4> bytes{0x47U, 1U, 0x34U, 0x12U};
  Send60CombatAttempt attempt{};
  CHECK(DecodeSend60CombatAttempt(
      bytes.data(), bytes.size(), attempt));
  CHECK(attempt.subcommand_header_le == 0x12340147U);
  CHECK(attempt.subcommand_byte_count == 4U);
  CHECK(attempt.local_client_id == 0x1234U);
}

void TestDeclaredSizeMismatchDoesNotScanPayload() {
  using namespace psobb::gameplay;
  const std::array<std::uint8_t, 6> bytes{
      0x46U, 0xFFU, 0xCCU, 0xDDU, 0x0BU, 0U};
  Send60CombatAttempt attempt{};
  CHECK(DecodeSend60CombatAttempt(
      bytes.data(),
      std::numeric_limits<std::uint32_t>::max(),
      attempt));
  CHECK(attempt.subcommand_header_le == 0xDDCCFF46U);
  CHECK(attempt.subcommand_byte_count ==
        std::numeric_limits<std::uint32_t>::max());
  CHECK(attempt.local_client_id == 0xDDCCU);
}

}  // namespace

int main() {
  TestObservedCommandRange();
  TestUnrelatedAndTruncatedCommandsAreIgnored();
  TestMinimumHeaderIncludesClientId();
  TestDeclaredSizeMismatchDoesNotScanPayload();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.Gameplay send_60 probe tests passed\n";
  return 0;
}
