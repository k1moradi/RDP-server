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

// R2's accepted-SSPI identity proof and R10's one-owner production seam have
// landed. The real native construction path is compiled below, but activation
// stays closed until an accepted Windows client binds that proof end-to-end and
// the live path is explicitly qualified.
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
    [[nodiscard]] WindowsNativeDesktopOpenResult initializeNativeAuthorized(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView) noexcept;
    [[nodiscard]] WindowsNativeDesktopOpenResult initializeForTestingAuthorized(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        WindowsNativeDesktopTestConfiguration &&configuration) noexcept;
    [[nodiscard]] WindowsNativeDesktopOpenResult initializeAuthorized(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization,
        const rdp_server::server::security::WindowsNativeDesktopAuthorizationView
            &authorizationView,
        WindowsNativeDesktopTestConfiguration &&configuration,
        bool requireInjectedCapture) noexcept;
    static bool initializeAuthorizationVisit(
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
