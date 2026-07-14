#include "psobb_enhancement/d3d8_abi.h"
#include "psobb_enhancement/pinned_image.h"
#include "psobb_enhancement/policy.h"

#include <windows.h>

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void Check(const bool condition, const char* expression) {
  if (!condition) {
    std::cerr << "FAIL: " << expression << '\n';
    ++g_failures;
  }
}
#define CHECK(expression) Check((expression), #expression)

[[nodiscard]] psobb::enhancement::d3d8::Matrix PerspectiveMatrix() {
  psobb::enhancement::d3d8::Matrix matrix{};
  matrix.value[0][0] = 1.5F;
  matrix.value[1][1] = 2.0F;
  matrix.value[2][2] = 1.001F;
  matrix.value[2][3] = 1.0F;
  matrix.value[3][2] = -0.1F;
  return matrix;
}

void TestResolutionPolicy() {
  using namespace psobb::enhancement;
  CHECK(IsSupportedResolution(2560, 1600));
  CHECK(IsSupportedResolution(3840, 2400));
  CHECK(!IsSupportedResolution(1920, 1200));
  CHECK(!IsSupportedResolution(3840, 2160));

  Configuration configuration;
  configuration.enabled = true;
  configuration.width = 2560;
  configuration.height = 1600;
  configuration.window_mode = WindowMode::borderless;

  d3d8::PresentParameters original{};
  original.back_buffer_width = 640;
  original.back_buffer_height = 480;
  original.windowed = FALSE;
  original.full_screen_refresh_rate_hz = 60;
  const auto effective = ApplyPresentationPolicy(configuration, original);
  CHECK(effective.back_buffer_width == 2560);
  CHECK(effective.back_buffer_height == 1600);
  CHECK(effective.windowed == TRUE);
  CHECK(effective.full_screen_refresh_rate_hz == 0);
}

void TestConfigurationGates() {
  using namespace psobb::enhancement;
  Configuration configuration;
  configuration.enabled = true;
  configuration.width = 2560;
  configuration.height = 1600;

  std::wstring error;
  CHECK(ValidateConfiguration(configuration, error));

  configuration.hud_minimap = true;
  CHECK(!ValidateConfiguration(configuration, error));
  CHECK(error.find(L"HUD/minimap") != std::wstring::npos);

  configuration.hud_minimap = false;
  configuration.automatic_device_recreation = true;
  CHECK(!ValidateConfiguration(configuration, error));
  CHECK(error.find(L"device recreation") != std::wstring::npos);
}

void TestProjectionPolicy() {
  using namespace psobb::enhancement;
  Configuration configuration;
  configuration.enabled = true;
  configuration.width = 2560;
  configuration.height = 1600;
  configuration.horizontal_fov = true;

  const auto original = PerspectiveMatrix();
  d3d8::Matrix adjusted{};
  CHECK(IsPerspectiveProjection(original));
  CHECK(AdjustHorizontalFov(configuration, original, adjusted));
  CHECK(std::abs(adjusted.value[0][0] - 1.25F) < 0.0001F);
  CHECK(adjusted.value[1][1] == original.value[1][1]);
  CHECK(adjusted.value[2][2] == original.value[2][2]);

  d3d8::Matrix orthographic{};
  orthographic.value[0][0] = 1.0F;
  orthographic.value[1][1] = 1.0F;
  orthographic.value[2][2] = 1.0F;
  orthographic.value[3][3] = 1.0F;
  CHECK(!IsPerspectiveProjection(orthographic));
  CHECK(!AdjustHorizontalFov(configuration, orthographic, adjusted));

  auto non_finite = original;
  non_finite.value[0][0] = std::nanf("");
  CHECK(!IsPerspectiveProjection(non_finite));
}

void TestLoadedImageByteGates() {
  using namespace psobb::enhancement;
  std::vector<std::byte> image(kPinnedImageSize);

  IMAGE_DOS_HEADER dos{};
  dos.e_magic = IMAGE_DOS_SIGNATURE;
  dos.e_lfanew = 0x100;
  std::memcpy(image.data(), &dos, sizeof(dos));

  IMAGE_NT_HEADERS32 nt{};
  nt.Signature = IMAGE_NT_SIGNATURE;
  nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt.FileHeader.NumberOfSections = 9;
  nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt.OptionalHeader.ImageBase = static_cast<DWORD>(kPinnedImageBase);
  nt.OptionalHeader.SizeOfImage = kPinnedImageSize;
  nt.OptionalHeader.AddressOfEntryPoint = kPinnedEntryPointRva;
  nt.OptionalHeader.SizeOfHeaders = 0x400;
  std::memcpy(image.data() + dos.e_lfanew, &nt, sizeof(nt));

  constexpr std::array<std::byte, 16> entry = {
      std::byte{0xBB}, std::byte{0x27}, std::byte{0x02}, std::byte{0x00},
      std::byte{0x00}, std::byte{0xE9}, std::byte{0x69}, std::byte{0x00},
      std::byte{0x00}, std::byte{0x00}, std::byte{0x90}, std::byte{0x90},
      std::byte{0x90}, std::byte{0x90}, std::byte{0x90}, std::byte{0x90}};
  constexpr std::array<std::byte, 6> thunk = {
      std::byte{0xFF}, std::byte{0x25}, std::byte{0x1C},
      std::byte{0x84}, std::byte{0x8F}, std::byte{0x00}};
  std::memcpy(image.data() + kPinnedEntryPointRva, entry.data(), entry.size());
  std::memcpy(
      image.data() + kDirect3DCreate8ThunkRva,
      thunk.data(),
      thunk.size());

  std::wstring failure;
  CHECK(VerifyLoadedImage(image, failure));
  image[kDirect3DCreate8ThunkRva] = std::byte{0x90};
  CHECK(!VerifyLoadedImage(image, failure));
  CHECK(failure.find(L"thunk") != std::wstring::npos);
}

}  // namespace

int main() {
  TestResolutionPolicy();
  TestConfigurationGates();
  TestProjectionPolicy();
  TestLoadedImageByteGates();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.Enhancement tests passed\n";
  return 0;
}
