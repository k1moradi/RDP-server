// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/security/native_desktop_authorization.h"
#include "windows_capture_session_guard.h"
#include "windows_cursor_snapshot.h"
#include "windows_dxgi_duplication_owner.h"
#include "windows_input_controller.h"

#include <cstdint>
#include <memory>

namespace rdp_server::windows
{

// R2's native authorization and R10's one-owner composition seams have landed.
// Production Windows activation still requires a qualified authenticated-identity
// provider and a reviewed native construction path. Keep that final gate closed.
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

#if defined(_WIN32)
struct WindowsNativeDesktopTestConfiguration final
{
    WindowsDesktopLayout layout{};
    WindowsDxgiTarget target{};
    WindowsCaptureSessionReadCallbacks sessionReader{};
    WindowsDxgiNativeCallbacks dxgiCallbacks{};
    WindowsDxgiOwnedCaptureCallbacks captureCallbacks{};
    WindowsCursorReadCallbacks cursorReader{};
    WindowsInputCallbacks inputCallbacks{};
};
#endif

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

#if defined(_WIN32)
    [[nodiscard]] WindowsNativeDesktopOpenResult openForTesting(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        WindowsNativeDesktopTestConfiguration configuration) noexcept;
#endif

    [[nodiscard]] WindowsNativeDesktopServiceResult serviceOnce(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        WindowsR4BgraFrameConsumer frameConsumer) noexcept;

    [[nodiscard]] bool handleInput(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        const WindowsInputEvent &event) noexcept;

    [[nodiscard]] WindowsCursorReadResult readCursorSnapshot(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        std::uint64_t expectedAuthorizationGeneration,
        WindowsCursorSnapshot &output) noexcept;

    [[nodiscard]] WindowsCaptureSessionChangeResult notifySessionChange(
        std::uint32_t sessionId) noexcept;

    void retireAfterAuthorizationLoss() noexcept;
    [[nodiscard]] bool ready() const noexcept;

private:
    struct State;
#if defined(_WIN32)
    struct InitializationVisitContext;
    [[nodiscard]] WindowsNativeDesktopOpenResult initializeForTestingAuthorized(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        WindowsNativeDesktopTestConfiguration &&configuration) noexcept;
    static bool initializeForTestingVisit(
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        void *context) noexcept;
#endif
    struct ServiceVisitContext;
    struct InputVisitContext;
    struct CursorVisitContext;
    static bool serviceAuthorizationVisit(
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        void *context) noexcept;
    static bool inputAuthorizationVisit(
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        void *context) noexcept;
    static bool cursorAuthorizationVisit(
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        void *context) noexcept;
    [[nodiscard]] bool authorizationViewMatches(
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        std::uint32_t requiredPermissions) const noexcept;

    std::unique_ptr<State> state_{};
    bool retired_{};
};

} // namespace rdp_server::windows
