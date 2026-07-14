#include "sha256.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace psobb::enhancement {
namespace {

class AlgorithmHandle final {
 public:
  ~AlgorithmHandle() {
    if (handle_ != nullptr) {
      BCryptCloseAlgorithmProvider(handle_, 0);
    }
  }

  AlgorithmHandle(const AlgorithmHandle&) = delete;
  AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
  AlgorithmHandle() = default;

  BCRYPT_ALG_HANDLE* receive() noexcept { return &handle_; }
  BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

 private:
  BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class HashHandle final {
 public:
  ~HashHandle() {
    if (handle_ != nullptr) {
      BCryptDestroyHash(handle_);
    }
  }

  HashHandle(const HashHandle&) = delete;
  HashHandle& operator=(const HashHandle&) = delete;
  HashHandle() = default;

  BCRYPT_HASH_HANDLE* receive() noexcept { return &handle_; }
  BCRYPT_HASH_HANDLE get() const noexcept { return handle_; }

 private:
  BCRYPT_HASH_HANDLE handle_ = nullptr;
};

}  // namespace

bool ComputeSha256(
    const std::span<const std::byte> bytes,
    std::array<std::uint8_t, 32>& digest,
    std::wstring& failure) {
  AlgorithmHandle algorithm;
  NTSTATUS status = BCryptOpenAlgorithmProvider(
      algorithm.receive(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (status < 0) {
    failure = L"BCryptOpenAlgorithmProvider(SHA-256) failed";
    return false;
  }

  DWORD object_length = 0;
  DWORD result_length = 0;
  status = BCryptGetProperty(
      algorithm.get(),
      BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&object_length),
      sizeof(object_length),
      &result_length,
      0);
  if (status < 0 || result_length != sizeof(object_length)) {
    failure = L"BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed";
    return false;
  }

  std::vector<std::uint8_t> hash_object(object_length);
  HashHandle hash;
  status = BCryptCreateHash(
      algorithm.get(),
      hash.receive(),
      hash_object.data(),
      static_cast<ULONG>(hash_object.size()),
      nullptr,
      0,
      0);
  if (status < 0) {
    failure = L"BCryptCreateHash failed";
    return false;
  }

  constexpr std::size_t kMaximumChunk = 1U << 30U;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    const std::size_t chunk_size =
        remaining < kMaximumChunk ? remaining : kMaximumChunk;
    auto* chunk = const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(
        bytes.data() + offset));
    status = BCryptHashData(
        hash.get(), chunk, static_cast<ULONG>(chunk_size), 0);
    if (status < 0) {
      failure = L"BCryptHashData failed";
      return false;
    }
    offset += chunk_size;
  }

  status = BCryptFinishHash(
      hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
  if (status < 0) {
    failure = L"BCryptFinishHash failed";
    return false;
  }

  return true;
}

std::wstring HexEncode(const std::array<std::uint8_t, 32>& digest) {
  constexpr wchar_t kHexDigits[] = L"0123456789ABCDEF";
  std::wstring encoded;
  encoded.resize(digest.size() * 2U);
  for (std::size_t index = 0; index < digest.size(); ++index) {
    encoded[index * 2U] = kHexDigits[digest[index] >> 4U];
    encoded[index * 2U + 1U] = kHexDigits[digest[index] & 0x0FU];
  }
  return encoded;
}

}  // namespace psobb::enhancement
