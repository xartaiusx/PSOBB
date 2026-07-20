#include "psobb_gameplay/api.h"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <type_traits>

namespace {

using InitializeFunction = BOOL(WINAPI*)();
using GetCapabilitiesFunction = BOOL(WINAPI*)(
    psobb::gameplay::GameplayCapabilitiesV1*);
using GetVersionFunction = const wchar_t*(WINAPI*)();
using RollbackFunction = BOOL(WINAPI*)();

template <typename Function>
[[nodiscard]] Function Resolve(HMODULE module, const char* name) noexcept {
  return reinterpret_cast<Function>(GetProcAddress(module, name));
}

class ScopedConfiguration final {
 public:
  ScopedConfiguration(
      const std::filesystem::path& module_path,
      const std::string_view mode) {
    path_ = module_path.parent_path() / L"PSOBB.Gameplay.ini";
    if (std::filesystem::exists(path_)) {
      failure_ = L"ABI build directory already contains PSOBB.Gameplay.ini";
      return;
    }

    if (mode == "missing") {
      valid_ = true;
      return;
    }

    std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
    if (!stream) {
      failure_ = L"Unable to create temporary ABI configuration";
      return;
    }
    created_ = true;
    stream << "[Gameplay]\r\nEnabled="
           << (mode == "disabled" ? "0" : "1") << "\r\n";
    valid_ = stream.good();
    if (!valid_) {
      failure_ = L"Unable to write temporary ABI configuration";
    }
  }

  ScopedConfiguration(const ScopedConfiguration&) = delete;
  ScopedConfiguration& operator=(const ScopedConfiguration&) = delete;

  ~ScopedConfiguration() {
    if (created_) {
      std::error_code ignored;
      std::filesystem::remove(path_, ignored);
    }
  }

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] const std::wstring& failure() const noexcept {
    return failure_;
  }

 private:
  std::filesystem::path path_;
  std::wstring failure_;
  bool created_ = false;
  bool valid_ = false;
};

[[nodiscard]] bool SlotsAreEmpty(
    const psobb::gameplay::GameplayCapabilitiesV1& capabilities) noexcept {
  return std::all_of(
      std::begin(capabilities.display_slots),
      std::end(capabilities.display_slots),
      [](const psobb::gameplay::DisplaySlotV1& slot) {
        return slot.kind == psobb::gameplay::DisplaySlotKind::empty &&
               slot.logical_action_id == 0U && slot.flags == 0U &&
               slot.reserved == 0U;
      });
}

}  // namespace

int wmain(const int argc, wchar_t** argv) {
  using namespace psobb::gameplay;
  static_assert(std::is_standard_layout_v<DisplaySlotV1>);
  static_assert(std::is_trivially_copyable_v<DisplaySlotV1>);
  static_assert(std::is_standard_layout_v<GameplayCapabilitiesV1>);
  static_assert(std::is_trivially_copyable_v<GameplayCapabilitiesV1>);
  static_assert(sizeof(DisplaySlotV1) == 16U);
  static_assert(offsetof(DisplaySlotV1, logical_action_id) == 4U);
  static_assert(offsetof(DisplaySlotV1, flags) == 8U);
  static_assert(offsetof(DisplaySlotV1, reserved) == 12U);
  static_assert(sizeof(GameplayCapabilitiesV1) == 904U);
  static_assert(offsetof(GameplayCapabilitiesV1, accepted_feature_bits) == 16U);
  static_assert(offsetof(GameplayCapabilitiesV1, active_page) == 24U);
  static_assert(offsetof(GameplayCapabilitiesV1, display_slot_count) == 28U);
  static_assert(offsetof(GameplayCapabilitiesV1, display_slots) == 32U);
  static_assert(offsetof(GameplayCapabilitiesV1, client_sha256) == 192U);
  static_assert(offsetof(GameplayCapabilitiesV1, version) == 322U);
  static_assert(
      offsetof(GameplayCapabilitiesV1, last_fail_closed_reason) == 386U);

  if (argc != 3) {
    std::wcerr << L"Usage: abi-smoke <PSOBB.Gameplay.asi> "
                  L"<missing|disabled|enabled-rejected>\n";
    return 2;
  }

  const std::string mode =
      std::filesystem::path(argv[2]).string();
  if (mode != "missing" && mode != "disabled" &&
      mode != "enabled-rejected") {
    std::cerr << "Unknown ABI smoke mode\n";
    return 2;
  }

  ScopedConfiguration configuration(argv[1], mode);
  if (!configuration.valid()) {
    std::wcerr << configuration.failure() << L'\n';
    return 1;
  }

  HMODULE module = LoadLibraryW(argv[1]);
  if (module == nullptr) {
    std::wcerr << L"LoadLibraryW failed: " << GetLastError() << L'\n';
    return 1;
  }

  const auto initialize = Resolve<InitializeFunction>(
      module, "PSOBBGameplay_Initialize");
  const auto get_capabilities = Resolve<GetCapabilitiesFunction>(
      module, "PSOBBGameplay_GetCapabilities");
  const auto get_version = Resolve<GetVersionFunction>(
      module, "PSOBBGameplay_GetVersion");
  const auto rollback = Resolve<RollbackFunction>(
      module, "PSOBBGameplay_Rollback");
  if (initialize == nullptr || get_capabilities == nullptr ||
      get_version == nullptr || rollback == nullptr) {
    std::cerr << "One or more undecorated gameplay exports are missing\n";
    FreeLibrary(module);
    return 1;
  }

  GameplayCapabilitiesV1 undersized{};
  undersized.struct_size = sizeof(undersized) - 1U;
  if (get_capabilities(nullptr) || get_capabilities(&undersized)) {
    std::cerr << "Capability ABI accepted an invalid output buffer\n";
    FreeLibrary(module);
    return 1;
  }

  GameplayCapabilitiesV1 before_initialize{};
  before_initialize.struct_size = sizeof(before_initialize);
  if (!get_capabilities(&before_initialize) ||
      before_initialize.state != RuntimeState::cold ||
      before_initialize.verification_flags != verification_none ||
      before_initialize.accepted_feature_bits != feature_none ||
      before_initialize.client_sha256[0] != L'\0') {
    std::cerr << "Gameplay module performed work before explicit initialization\n";
    FreeLibrary(module);
    return 1;
  }

  const bool initialized = initialize() != FALSE;
  GameplayCapabilitiesV1 capabilities{};
  capabilities.struct_size = sizeof(capabilities);
  const bool capability_read = get_capabilities(&capabilities) != FALSE;
  const bool expected_rejection = mode == "enabled-rejected";
  const bool state_matched =
      expected_rejection
          ? capabilities.state == RuntimeState::rejected
          : capabilities.state == RuntimeState::disabled_by_config;
  const bool passed =
      initialized != expected_rejection && capability_read && state_matched &&
      capabilities.abi_version == kCapabilityAbiVersion &&
      capabilities.verification_flags == verification_none &&
      capabilities.accepted_feature_bits == feature_none &&
      capabilities.active_page == kNoActivePage &&
      capabilities.display_slot_count == kDisplaySlotCount &&
      SlotsAreEmpty(capabilities) &&
      capabilities.client_sha256[0] == L'\0' &&
      std::wstring(get_version()) == kVersion &&
      capabilities.last_fail_closed_reason[0] != L'\0';

  const bool rollback_passed = rollback() != FALSE;
  GameplayCapabilitiesV1 rolled_back{};
  rolled_back.struct_size = sizeof(rolled_back);
  const bool rollback_state =
      get_capabilities(&rolled_back) &&
      rolled_back.state == RuntimeState::rolled_back &&
      rolled_back.accepted_feature_bits == feature_none;

  FreeLibrary(module);
  if (!passed || !rollback_passed || !rollback_state) {
    std::cerr << "PSOBB.Gameplay ABI smoke test failed\n";
    return 1;
  }
  std::cout << "PSOBB.Gameplay ABI smoke test passed\n";
  return 0;
}
