// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/security/native_desktop_authorization.h"
#include "windows_capture_session_guard.h"
#include "windows_cursor_snapshot.h"
#include "windows_input_controller.h"

#include <cstdint>
#include <memory>

namespace rdp_server::windows
{

// R2's authenticated-native authorization seam has landed, but R10 has not yet
// composed a live Windows owner and no production Windows authenticated-identity
// provider has qualified a real client. Keep native activation fail-closed.
inline constexpr bool kWindowsNativeDesktopPositiveActivationApproved = false;

enum class WindowsNativeDesktopOpenResult : std::uint8_t
{
    authorizationDenied,
    nativeCompositionUnavailable,
    ready,
    closed,
};

enum class WindowsNativeDesktopServiceResult : std::uint8_t
{
    authorizationRequired,
    nativeCompositionUnavailable,
    idle,
    frameConsumed,
    failed,
    closed,
};

// One serialized R6 owner for the Windows interactive desktop. R10 may own
// exactly one instance and call it from its existing bounded HostControl
// scheduler; this class never owns a listener, worker/server loop or GUI.
//
// R2's WindowsNativeDesktopAuthorization is mandatory at open and at every
// protected operation. Its visitor revalidates the authenticated SID, exact
// WTS/LUID/logon identity, owner-consent epoch and authorization generation.
// Those WTS/native facts remain evidence inside R2 and cannot construct this
// owner by themselves. R3 Share/input permission remains an additional
// upstream gate owned by the runtime composition.
class WindowsNativeDesktopOwner final
{
public:
    WindowsNativeDesktopOwner() noexcept;
    ~WindowsNativeDesktopOwner() noexcept;

    WindowsNativeDesktopOwner(const WindowsNativeDesktopOwner &) = delete;
    WindowsNativeDesktopOwner &operator=(const WindowsNativeDesktopOwner &) = delete;
    WindowsNativeDesktopOwner(WindowsNativeDesktopOwner &&) = delete;
    WindowsNativeDesktopOwner &operator=(WindowsNativeDesktopOwner &&) = delete;

    [[nodiscard]] WindowsNativeDesktopOpenResult open(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration) noexcept;

    // Bounded R10 seam: at most one native capture/presentation step when
    // positive composition is enabled. It must never become a second server
    // loop or block waiting for a desktop frame.
    [[nodiscard]] WindowsNativeDesktopServiceResult serviceOnce(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        WindowsR4BgraFrameConsumer frameConsumer) noexcept;

    // Positive native input must pass a fresh R2 input-permission visit
    // immediately before the private SendInput route. Current activation
    // remains denied until R10 composes the full protected-operation path.
    [[nodiscard]] bool handleInput(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        const WindowsInputEvent &event) noexcept;

    // Cursor observation is protected desktop access and re-enters the same
    // R2 authorization generation. Current activation remains denied.
    [[nodiscard]] WindowsCursorReadResult readCursorSnapshot(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        WindowsCursorSnapshot &output) noexcept;

    // WTS notifications are revocation-only. They can retire an active owner
    // but can never open/reopen one or substitute for R2 authentication.
    [[nodiscard]] WindowsCaptureSessionChangeResult notifySessionChange(
        std::uint32_t sessionId) noexcept;

    // R2/R3 authority must already be revoked before this serialized safe-point
    // call. The guard is closed first, then held input is discarded without a
    // native post, then DXGI children/COM state retire.
    void retireAfterAuthorizationLoss() noexcept;

    [[nodiscard]] bool ready() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_{};
    bool retired_{};
};

} // namespace rdp_server::windows
