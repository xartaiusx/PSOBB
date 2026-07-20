#include "psobb_client_safety/exact_image.h"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
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

struct SyntheticImage {
  std::vector<std::byte> file;
  std::vector<std::byte> loaded;
  psobb::client_safety::ExactImageIdentity identity{};
  std::array<std::byte, 4> expected{
      std::byte{0x11}, std::byte{0x22},
      std::byte{0x33}, std::byte{0x44}};
  std::wstring digest;
};

[[nodiscard]] SyntheticImage MakeSyntheticImage() {
  using namespace psobb::client_safety;
  SyntheticImage image;
  image.file.resize(0x800U);
  image.loaded.resize(0x3000U);

  IMAGE_DOS_HEADER dos{};
  dos.e_magic = IMAGE_DOS_SIGNATURE;
  dos.e_lfanew = 0x100;
  std::memcpy(image.file.data(), &dos, sizeof(dos));
  std::memcpy(image.loaded.data(), &dos, sizeof(dos));

  IMAGE_NT_HEADERS32 nt{};
  nt.Signature = IMAGE_NT_SIGNATURE;
  nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
  nt.FileHeader.NumberOfSections = 1;
  nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
  nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  nt.OptionalHeader.ImageBase = 0x00400000U;
  nt.OptionalHeader.SizeOfImage = 0x3000U;
  nt.OptionalHeader.AddressOfEntryPoint = 0x1000U;
  nt.OptionalHeader.SizeOfHeaders = 0x400U;
  nt.OptionalHeader.SectionAlignment = 0x1000U;
  nt.OptionalHeader.FileAlignment = 0x200U;
  std::memcpy(image.file.data() + dos.e_lfanew, &nt, sizeof(nt));
  std::memcpy(image.loaded.data() + dos.e_lfanew, &nt, sizeof(nt));

  IMAGE_SECTION_HEADER section{};
  section.Misc.VirtualSize = 0x200U;
  section.VirtualAddress = 0x1000U;
  section.SizeOfRawData = 0x200U;
  section.PointerToRawData = 0x400U;
  const std::size_t section_offset =
      static_cast<std::size_t>(dos.e_lfanew) + sizeof(DWORD) +
      sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32);
  std::memcpy(image.file.data() + section_offset, &section, sizeof(section));
  std::memcpy(
      image.loaded.data() + section_offset, &section, sizeof(section));

  std::memcpy(
      image.file.data() + 0x410U,
      image.expected.data(),
      image.expected.size());
  std::memcpy(
      image.loaded.data() + 0x1010U,
      image.expected.data(),
      image.expected.size());

  std::array<std::uint8_t, 32> hash{};
  std::wstring failure;
  CHECK(ComputeSha256(image.file, hash, failure));
  image.digest = HexEncode(hash);
  image.identity = ExactImageIdentity{
      image.file.size(),
      image.digest,
      0x00400000U,
      0x3000U,
      0x1000U,
      0x400U,
      0x1000U,
      0x200U,
      IMAGE_FILE_MACHINE_I386,
      1U};
  return image;
}

class TemporaryFile final {
 public:
  explicit TemporaryFile(const std::span<const std::byte> bytes) {
    std::array<wchar_t, MAX_PATH> directory{};
    const DWORD length = GetTempPathW(
        static_cast<DWORD>(directory.size()), directory.data());
    if (length == 0 || length >= directory.size()) {
      return;
    }

    std::array<wchar_t, MAX_PATH> path{};
    if (GetTempFileNameW(directory.data(), L"PSC", 0, path.data()) == 0) {
      return;
    }
    path_ = path.data();
    std::ofstream stream(
        std::filesystem::path(path_), std::ios::binary | std::ios::trunc);
    stream.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    valid_ = stream.good();
  }

  TemporaryFile(const TemporaryFile&) = delete;
  TemporaryFile& operator=(const TemporaryFile&) = delete;

  ~TemporaryFile() {
    if (!path_.empty()) {
      DeleteFileW(path_.c_str());
    }
  }

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] const std::wstring& path() const noexcept { return path_; }

 private:
  std::wstring path_;
  bool valid_ = false;
};

void TestKnownSha256() {
  using namespace psobb::client_safety;
  constexpr std::array<std::byte, 3> value{
      std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
  std::array<std::uint8_t, 32> digest{};
  std::wstring failure;
  CHECK(ComputeSha256(value, digest, failure));
  CHECK(HexEncode(digest) ==
        L"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
}

void TestSyntheticFileAndLoadedImage() {
  using namespace psobb::client_safety;
  SyntheticImage image = MakeSyntheticImage();
  TemporaryFile file(image.file);
  CHECK(file.valid());

  const ExpectedBytes gate{0x1010U, image.expected};
  const std::array expectations{gate};
  const ImageVerification verification =
      VerifyExecutable(file.path(), image.identity, expectations);
  CHECK(verification.passed());
  CHECK(verification.actual_sha256 == image.digest);

  std::wstring failure;
  CHECK(VerifyLoadedImage(
      image.loaded, image.identity, expectations, failure));

  image.loaded[0x1010U] = std::byte{0xFF};
  CHECK(!VerifyLoadedImage(
      image.loaded, image.identity, expectations, failure));
  CHECK(failure.find(L"00001010") != std::wstring::npos);
}

void TestFailClosedMutations() {
  using namespace psobb::client_safety;
  SyntheticImage image = MakeSyntheticImage();
  TemporaryFile file(image.file);
  CHECK(file.valid());

  auto wrong_hash = image.identity;
  wrong_hash.sha256 =
      L"0000000000000000000000000000000000000000000000000000000000000000";
  CHECK(!VerifyExecutable(file.path(), wrong_hash).passed());

  const std::array<std::byte, 1> wrong{std::byte{0x90}};
  const std::array expectations{ExpectedBytes{0x1010U, wrong}};
  const auto wrong_bytes =
      VerifyExecutable(file.path(), image.identity, expectations);
  CHECK(!wrong_bytes.passed());
  CHECK(wrong_bytes.failure.find(L"00001010") != std::wstring::npos);

  auto wrong_pe = image.loaded;
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(wrong_pe.data());
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(
      wrong_pe.data() + dos->e_lfanew);
  nt->OptionalHeader.ImageBase = 0x00500000U;
  std::wstring failure;
  CHECK(!VerifyLoadedImage(wrong_pe, image.identity, {}, failure));
  CHECK(failure.find(L"PE32") != std::wstring::npos);

  const std::array empty_gate{ExpectedBytes{0x1010U, {}}};
  CHECK(!VerifyLoadedImage(
      image.loaded, image.identity, empty_gate, failure));
}

void TestRangeAwareExpectedBytes() {
  using namespace psobb::client_safety;
  SyntheticImage image = MakeSyntheticImage();
  TemporaryFile file(image.file);
  CHECK(file.valid());

  const std::array<std::byte, 2> file_section_crossing{
      image.file[0x5FFU], image.file[0x600U]};
  const std::array file_section_gate{
      ExpectedBytes{0x11FFU, file_section_crossing}};
  CHECK(!VerifyExecutable(
      file.path(), image.identity, file_section_gate).passed());

  const std::array<std::byte, 2> loaded_section_crossing{
      image.loaded[0x11FFU], image.loaded[0x1200U]};
  const std::array loaded_section_gate{
      ExpectedBytes{0x11FFU, loaded_section_crossing}};
  std::wstring failure;
  CHECK(!VerifyLoadedImage(
      image.loaded, image.identity, loaded_section_gate, failure));

  const std::array<std::byte, 2> file_header_crossing{
      image.file[0x3FFU], image.file[0x400U]};
  const std::array file_header_gate{
      ExpectedBytes{0x3FFU, file_header_crossing}};
  CHECK(!VerifyExecutable(
      file.path(), image.identity, file_header_gate).passed());

  const std::array<std::byte, 2> loaded_header_crossing{
      image.loaded[0x3FFU], image.loaded[0x400U]};
  const std::array loaded_header_gate{
      ExpectedBytes{0x3FFU, loaded_header_crossing}};
  CHECK(!VerifyLoadedImage(
      image.loaded, image.identity, loaded_header_gate, failure));

  auto extended_loaded = image.loaded;
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(extended_loaded.data());
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(
      extended_loaded.data() + dos->e_lfanew);
  auto* section = IMAGE_FIRST_SECTION(nt);
  section->Misc.VirtualSize = 0x300U;

  const std::array<std::byte, 1> zero{std::byte{0x00}};
  const std::array virtual_tail_gate{ExpectedBytes{0x1200U, zero}};
  CHECK(VerifyLoadedImage(
      extended_loaded, image.identity, virtual_tail_gate, failure));
  CHECK(!VerifyExecutable(
      file.path(), image.identity, virtual_tail_gate).passed());

  const std::array unmapped_gap_gate{ExpectedBytes{0x1300U, zero}};
  CHECK(!VerifyLoadedImage(
      extended_loaded, image.identity, unmapped_gap_gate, failure));

  const std::array overflow_gate{ExpectedBytes{0xFFFFFFFFU, zero}};
  CHECK(!VerifyLoadedImage(
      extended_loaded, image.identity, overflow_gate, failure));
}

void TestPinnedIdentityConstants() {
  using namespace psobb::client_safety;
  CHECK(k59NlIdentity.file_size == 6'971'904U);
  CHECK(k59NlIdentity.sha256 == k59NlSha256);
  CHECK(k59NlIdentity.image_base == 0x00400000U);
  CHECK(k59NlIdentity.image_size == 0x00762000U);
  CHECK(k59NlIdentity.entry_point_rva == 0x00760000U);
  CHECK(k59NlIdentity.machine == IMAGE_FILE_MACHINE_I386);
  CHECK(k59NlIdentity.section_count == 9U);
}

}  // namespace

int main() {
  TestKnownSha256();
  TestSyntheticFileAndLoadedImage();
  TestFailClosedMutations();
  TestRangeAwareExpectedBytes();
  TestPinnedIdentityConstants();

  if (g_failures != 0) {
    std::cerr << g_failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All PSOBB.ClientSafety tests passed\n";
  return 0;
}
