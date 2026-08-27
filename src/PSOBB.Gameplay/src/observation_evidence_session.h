#pragma once

#include "observation_evidence_accumulator.h"
#include "observation_ring.h"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>

namespace psobb::gameplay {

inline constexpr std::size_t
    kObservationEvidenceControlEventNameCapacity = 128U;

struct ObservationEvidenceControlEventNames final {
  std::array<wchar_t, kObservationEvidenceControlEventNameCapacity>
      finalize{};
  std::array<wchar_t, kObservationEvidenceControlEventNameCapacity>
      completion{};
};

enum class ObservationEvidenceFailure : std::uint32_t {
  none = 0U,
  initial_wait_failed = 1U,
  initial_header_write_failed = 2U,
  ready_signal_failed = 3U,
  stop_wait_failed = 4U,
  ring_drain_failed = 5U,
  accumulator_rejected_snapshot = 6U,
  event_write_failed = 7U,
  header_write_failed = 8U,
  flush_failed = 9U,
  activation_signal_failed = 10U,
  activation_wait_failed = 11U,
  active_header_write_failed = 12U,
  terminal_header_write_failed = 13U,
  completion_signal_failed = 14U,
};

using ObservationEvidenceFailureHandler =
    void (*)(ObservationEvidenceFailure failure) noexcept;

// This object has process lifetime. Its destructor intentionally performs no
// handle, thread, file, or ring work; explicit rollback owns bounded cleanup.
class ObservationEvidenceSession final {
 public:
  ObservationEvidenceSession() noexcept = default;
  ~ObservationEvidenceSession() = default;

  ObservationEvidenceSession(const ObservationEvidenceSession&) = delete;
  ObservationEvidenceSession& operator=(
      const ObservationEvidenceSession&) = delete;
  ObservationEvidenceSession(ObservationEvidenceSession&&) = delete;
  ObservationEvidenceSession& operator=(
      ObservationEvidenceSession&&) = delete;

  [[nodiscard]] static bool IsValidRunId(
      std::wstring_view run_id) noexcept;

  [[nodiscard]] static bool BuildControlEventNames(
      std::uint32_t process_id,
      std::uint64_t process_start_filetime,
      ObservationEvidenceControlEventNames& names) noexcept;

  // The launcher supplies only a validated run ID. This method independently
  // derives the fixed evidence path from the verified module placement.
  [[nodiscard]] bool Prepare(
      std::wstring_view module_path,
      std::wstring_view run_id,
      std::wstring& failure);

  [[nodiscard]] bool Start(
      ObservationRing& ring,
      ObservationEvidenceFailureHandler failure_handler,
      std::wstring& failure);

  // Start leaves the worker paused after its flushed ready header. The caller
  // publishes all success state before activating it, so an asynchronous
  // worker failure cannot be overwritten by initialization.
  [[nodiscard]] bool Activate(std::wstring& failure);

  // Returns false only while a worker cannot be proven stopped. A retry is
  // safe and retains every handle needed to finish cleanup.
  [[nodiscard]] bool StopAndJoin(std::wstring& failure) noexcept;

  // Valid only when no worker was created. Failed evidence is retained.
  void CancelPrepared() noexcept;

  [[nodiscard]] bool prepared() const noexcept;
  [[nodiscard]] bool owns_consumer() const noexcept;
  [[nodiscard]] ObservationEvidenceFailure worker_failure() const noexcept;
  [[nodiscard]] std::wstring_view partial_path() const noexcept;

 private:
  friend struct ObservationEvidenceSessionTestAccess;

  [[nodiscard]] bool PrepareImplementation(
      std::wstring_view module_path,
      std::wstring_view run_id,
      std::wstring& failure);
  [[nodiscard]] bool StartImplementation(
      ObservationRing& ring,
      ObservationEvidenceFailureHandler failure_handler,
      std::wstring& failure);
  [[nodiscard]] static unsigned __stdcall WorkerEntry(void* context) noexcept;
  [[nodiscard]] unsigned Worker() noexcept;
  [[nodiscard]] bool DrainAndCommit(bool final_flush) noexcept;
  [[nodiscard]] bool WriteExactAt(
      std::uint64_t offset,
      const void* data,
      std::size_t size) noexcept;
  [[nodiscard]] bool Flush() noexcept;
  [[nodiscard]] static std::uint64_t CurrentFiletime() noexcept;
  void ReportFailure(ObservationEvidenceFailure failure) noexcept;
  void PersistFailureBestEffort(
      ObservationEvidenceFailure failure) noexcept;
  [[nodiscard]] bool PersistStoppedState() noexcept;
  void CloseStoppedHandles() noexcept;

  static constexpr std::size_t kMaximumPathCharacters = 32'768U;
  alignas(ObservationEvidenceAccumulator)
      std::array<std::byte, sizeof(ObservationEvidenceAccumulator)>
          accumulator_storage_{};
  ObservationEvidenceAccumulator* accumulator_ = nullptr;
  ObservationRing* ring_ = nullptr;
  ObservationSnapshotV1 snapshot_{};
  std::array<wchar_t, kMaximumPathCharacters> partial_path_{};
  std::size_t partial_path_length_ = 0U;
  HANDLE category_directory_ = INVALID_HANDLE_VALUE;
  HANDLE run_directory_ = INVALID_HANDLE_VALUE;
  HANDLE file_ = INVALID_HANDLE_VALUE;
  HANDLE start_event_ = nullptr;
  HANDLE finalize_event_ = nullptr;
  HANDLE completion_event_ = nullptr;
  HANDLE ready_event_ = nullptr;
  HANDLE activation_event_ = nullptr;
  HANDLE active_event_ = nullptr;
  HANDLE thread_ = nullptr;
  ObservationEvidenceFailureHandler failure_handler_ = nullptr;
  std::atomic<ObservationEvidenceFailure> worker_failure_{
      ObservationEvidenceFailure::none};
  std::atomic_bool consumer_owned_{false};
  bool prepared_ = false;
  bool dirty_ = false;
  std::uint64_t last_flush_tick_ = 0U;
  std::uint32_t process_id_ = 0U;
  std::uint32_t consumer_thread_id_ = 0U;
  std::uint64_t process_start_filetime_ = 0U;
};

static_assert(
    std::atomic<ObservationEvidenceFailure>::is_always_lock_free);
static_assert(std::atomic<bool>::is_always_lock_free);
static_assert(std::is_trivially_destructible_v<ObservationEvidenceSession>);

}  // namespace psobb::gameplay
