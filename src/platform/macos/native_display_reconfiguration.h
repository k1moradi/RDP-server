// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <expected>

namespace rdp::macos {

enum class NativeDisplayWatchError : std::uint8_t {
    AlreadyRegistered,
    RegistrationFailed,
    RemovalFailed,
};

// Process-scoped Quartz topology signal; not an RDP session, geometry cache,
// consent token, callback scheduler or capture stream. Only one native
// registration may exist per process. CoreGraphics callback userInfo is null:
// callbacks can never dereference a retired watch object after unregister.
// Signal epochs are never reused, including after numeric exhaustion.
class NativeDisplayReconfigurationWatch final {
public:
    NativeDisplayReconfigurationWatch() noexcept = default;
    NativeDisplayReconfigurationWatch(const NativeDisplayReconfigurationWatch&) = delete;
    NativeDisplayReconfigurationWatch& operator=(const NativeDisplayReconfigurationWatch&) = delete;
    NativeDisplayReconfigurationWatch(NativeDisplayReconfigurationWatch&&) = delete;
    NativeDisplayReconfigurationWatch& operator=(NativeDisplayReconfigurationWatch&&) = delete;
    ~NativeDisplayReconfigurationWatch() noexcept;

    [[nodiscard]] static std::uint64_t revision() noexcept;
    [[nodiscard]] static bool changedSince(std::uint64_t revision) noexcept;

    // The CoreGraphics callback invokes this for begin AND end events.
    // Exposed as a deterministic synthetic event seam in CTest; no Quartz
    // callback registration or desktop access occurs in ordinary tests.
    static void recordTopologyChange() noexcept;

#if defined(__APPLE__)
    // Explicit opt-in by the future authorized per-user runtime. Never
    // register from CTest or implicitly from geometry construction.
    [[nodiscard]] std::expected<void, NativeDisplayWatchError> startNative() noexcept;
    [[nodiscard]] std::expected<void, NativeDisplayWatchError> stopNative() noexcept;
    [[nodiscard]] bool registered() const noexcept { return registered_; }
#endif

private:
#if defined(__APPLE__)
    bool registered_{};
#endif
};

} // namespace rdp::macos
