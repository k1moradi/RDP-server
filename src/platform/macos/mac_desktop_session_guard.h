// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/mac_input_controller.h"
#include "platform/macos/native_display_refresh.h"
#include "platform/macos/screen_capture_preflight.h"

#include <cstdint>

namespace rdp::macos {

enum class MacDesktopAccessKind : std::uint8_t {
    Capture,
    Input,
};

// Read-only facts about the caller's current Quartz GUI session. The selected
// user ID comes from a future R2/R3 authorization owner; this observation is
// only a revocation/precondition check and never authenticates a user.
struct MacDesktopSessionObservation final {
    std::uint32_t sessionUserId{};
    std::uint32_t effectiveUserId{};
    bool onConsole{};
    bool loginComplete{};

    friend bool operator==(const MacDesktopSessionObservation&,
                           const MacDesktopSessionObservation&) = default;
};

struct MacDesktopSessionReadCallbacks final {
    void* context{};
    bool (*read)(void* context,
                 MacDesktopSessionObservation& observation) noexcept{};
};

struct MacDesktopPermissionReadCallbacks final {
    void* context{};
    ScreenCapturePreflightStatus (*capture)(void* context) noexcept{};
    MacInputPermissionStatus (*input)(void* context) noexcept{};
};

// Single-thread-affine, revocation-only desktop precondition. It binds a
// caller-selected user ID to one display generation/topology revision and
// re-reads the GUI session plus the required OS permission synchronously on
// every allows() call. It owns no native session, credential, capture stream,
// input callback or RDP authority.
//
// Any malformed, stale, reentrant, permission-denied, user/session-mismatched
// observation closes the guard permanently. A replacement may be constructed
// only after the future R2/R3 owner independently reauthorizes and rebinds.
class MacDesktopSessionGuard final {
public:
    MacDesktopSessionGuard(
        const NativeDisplayGeometryRefresh& geometry,
        std::uint64_t geometryGeneration,
        std::uint32_t targetUserId,
        MacDesktopSessionReadCallbacks sessionReader,
        MacDesktopPermissionReadCallbacks permissionReader) noexcept;

    MacDesktopSessionGuard(const MacDesktopSessionGuard&) = delete;
    MacDesktopSessionGuard& operator=(const MacDesktopSessionGuard&) = delete;
    MacDesktopSessionGuard(MacDesktopSessionGuard&&) = delete;
    MacDesktopSessionGuard& operator=(MacDesktopSessionGuard&&) = delete;

    [[nodiscard]] bool allows(MacDesktopAccessKind access) noexcept;
    void close() noexcept;

    [[nodiscard]] bool closed() const noexcept { return closed_; }
    [[nodiscard]] std::uint32_t targetUserId() const noexcept {
        return closed_ ? 0U : targetUserId_;
    }
    [[nodiscard]] std::uint64_t geometryGeneration() const noexcept {
        return closed_ ? 0U : geometryGeneration_;
    }

private:
    [[nodiscard]] bool geometryCurrent() const noexcept;
    [[nodiscard]] bool sessionCurrent(
        MacDesktopSessionObservation& observation) noexcept;
    void invalidate() noexcept;

    const NativeDisplayGeometryRefresh* geometry_{};
    std::uint64_t geometryGeneration_{};
    std::uint64_t topologyRevision_{};
    std::uint32_t targetUserId_{};
    MacDesktopSessionReadCallbacks sessionReader_{};
    MacDesktopPermissionReadCallbacks permissionReader_{};
    bool operationInProgress_{};
    bool closed_{};
};

#if defined(__APPLE__)
// Read-only native observations. CGSessionCopyCurrentDictionary describes the
// caller's WindowServer session; permission probes never request a prompt.
// These callbacks grant no R2/R3 authority and expose no capture/input action.
[[nodiscard]] MacDesktopSessionReadCallbacks
macDesktopSessionReadCallbacks() noexcept;
[[nodiscard]] MacDesktopPermissionReadCallbacks
macDesktopPermissionReadCallbacks() noexcept;
#endif

} // namespace rdp::macos
