// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <expected>
#include <optional>

namespace rdp::macos {

enum class NativeSessionChangeWatchError : std::uint8_t {
    AlreadyRegistered,
    InvalidCallbacks,
    RegistrationFailed,
    RemovalFailed,
    DeliveryUnavailable,
    RevisionExhausted,
};

using NativeSessionChangeRecorder =
    void (*)(std::uint64_t registrationEpoch) noexcept;

struct NativeSessionChangeWatchCallbacks final {
    void* context{};
    bool (*install)(void* context, std::uint64_t registrationEpoch,
                    NativeSessionChangeRecorder recorder) noexcept{};
    bool (*remove)(void* context) noexcept{};
};

// Process-scoped macOS GUI-session revocation signal. This is separate from
// display topology and grants no authentication, admission, capture or input
// authority. Only one registration owner may exist per process at a time.
//
// The monotonic process revision starts nonzero and is never reused. Numeric
// exhaustion is terminal. The minimal event recorder is allocation-free and
// uses only atomics; native callbacks carry a scalar registration epoch and
// never a watch-object pointer, so retired observers cannot dereference a
// destroyed owner. Start/stop are caller-serialized; event recording may run
// concurrently on an AppKit notification-delivery thread.
class NativeSessionChangeWatch final {
public:
    NativeSessionChangeWatch() noexcept = default;
    NativeSessionChangeWatch(const NativeSessionChangeWatch&) = delete;
    NativeSessionChangeWatch& operator=(const NativeSessionChangeWatch&) = delete;
    NativeSessionChangeWatch(NativeSessionChangeWatch&&) = delete;
    NativeSessionChangeWatch& operator=(NativeSessionChangeWatch&&) = delete;
    ~NativeSessionChangeWatch() noexcept;

    [[nodiscard]] static std::optional<std::uint64_t>
    coveredRevision() noexcept;
    [[nodiscard]] static bool current(std::uint64_t revision) noexcept;

    // Deterministic production recorder used by AppKit and ordinary CTests.
    static void
    recordSessionChange(std::uint64_t registrationEpoch) noexcept;

    // Deterministic test seam only; runtime code must use startNative().
    [[nodiscard]] std::expected<void, NativeSessionChangeWatchError>
    startWithCallbacks(NativeSessionChangeWatchCallbacks callbacks) noexcept;

    [[nodiscard]] std::expected<void, NativeSessionChangeWatchError>
    stop() noexcept;

    [[nodiscard]] bool registered() const noexcept { return registered_; }

#if defined(__APPLE__)
    // Explicit native opt-in. Coverage is accepted only from an already-running
    // AppKit main event-loop context. Ordinary CTests never call this method.
    [[nodiscard]] std::expected<void, NativeSessionChangeWatchError>
    startNative() noexcept;
#endif

private:
    NativeSessionChangeWatchCallbacks callbacks_{};
    std::uint64_t registrationEpoch_{};
    bool registered_{};
};

} // namespace rdp::macos
