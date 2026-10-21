// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/framebuffer_view.h"
#include "core/geometry.h"
#include "platform/macos/mac_desktop_session_guard.h"
#include "platform/macos/mac_input_controller.h"
#include "platform/macos/native_display_reconfiguration.h"
#include "platform/macos/native_display_refresh.h"
#include "platform/macos/native_session_change_watch.h"
#include "platform/macos/screen_capture_stream.h"
#include "server/security/native_desktop_authorization.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>

namespace rdp::macos {

inline constexpr std::size_t kMaximumMacNativeDesktopFramebufferBytes =
    512U * 1024U * 1024U;

enum class MacNativeDesktopOwnerError : std::uint8_t {
    AuthorizationUnavailable,
    InvalidConfiguration,
    DisplayWatchUnavailable,
    SessionWatchUnavailable,
    DisplayUnavailable,
    SessionUnavailable,
    CaptureUnavailable,
    InputUnavailable,
    FramebufferUnavailable,
    AllocationUnavailable,
};

enum class MacNativeDesktopOwnerState : std::uint8_t {
    Initializing,
    CapturePreparing,
    CaptureStarting,
    Ready,
    Revoked,
};

struct MacNativeDesktopFrameConsumer final {
    void* context{};
    // The framebuffer borrows aggregate-owned storage and is valid only for
    // this synchronous callback. The callback must not reenter the owner.
    bool (*consume)(void* context,
                    const FramebufferView& framebuffer,
                    std::uint64_t geometryGeneration,
                    std::uint64_t admittedSessionGeneration,
                    std::uint64_t frameSequence) noexcept{};
};

struct MacNativeDesktopServiceObservation final {
    MacNativeDesktopOwnerState state{MacNativeDesktopOwnerState::Revoked};
    PixelSize pixelGeometry{};
    std::uint64_t geometryGeneration{};
    // Exact R2 authorization generation that admitted this native owner.
    // It is a freshness selector only and cannot reconstruct authority.
    std::uint64_t admittedSessionGeneration{};
    std::uint64_t latestFrameSequence{};
    bool frameAvailable{};
    bool inputReady{};
};

#if defined(__APPLE__)
struct MacNativeDesktopTestConfiguration final {
    std::uint32_t selectedDisplayId{};
    std::size_t maximumFramebufferBytes{
        kMaximumMacNativeDesktopFramebufferBytes};
    NativeDisplayReconfigurationWatch::Callbacks displayWatchCallbacks{};
    NativeSessionChangeWatchCallbacks sessionWatchCallbacks{};
    NativeDisplayReadFunction displayReader{};
    void* displayReaderContext{};
    MacDesktopSessionReadCallbacks sessionReader{};
    MacDesktopPermissionReadCallbacks permissionReader{};
    MacInputCallbacks inputCallbacks{};
    std::unique_ptr<detail::MacScreenCaptureBackend> captureBackend{};
};
#endif

// One serialized R5 macOS desktop aggregate for R10. It owns native desktop
// lifetime only: no socket, TLS, protocol parser, graphics scheduler or second
// service loop lives here. All public operations except the capture callback
// are owner-thread-affine. Frame publication may arrive concurrently on the
// ScreenCaptureKit serial queue and is copied into one bounded latest-frame
// mailbox before R10 can synchronously borrow it.
//
// Positive construction and every protected operation enter R2's
// MacNativeDesktopAuthorization::visit() with the exact expected generation.
// A UID, display ID, TCC grant, geometry/session generation or test fixture is
// never sufficient. The borrowed R2 authorization object must outlive this
// owner and remain serialized on the same R2/R10 owner thread.
class MacNativeDesktopOwner final {
public:
    MacNativeDesktopOwner() = delete;
    ~MacNativeDesktopOwner() noexcept;

    MacNativeDesktopOwner(const MacNativeDesktopOwner&) = delete;
    MacNativeDesktopOwner& operator=(const MacNativeDesktopOwner&) = delete;
    MacNativeDesktopOwner(MacNativeDesktopOwner&&) = delete;
    MacNativeDesktopOwner& operator=(MacNativeDesktopOwner&&) = delete;

#if defined(__APPLE__)
    [[nodiscard]] static std::expected<std::unique_ptr<MacNativeDesktopOwner>,
                                       MacNativeDesktopOwnerError>
    createAuthorized(
        const rdp_server::server::security::MacNativeDesktopAuthorization&
            authorization,
        std::uint64_t expectedAuthorizationGeneration) noexcept;

    // Permission-free deterministic lifecycle seam. R2 authorization is real,
    // while every native operation is injected; ordinary CTest never
    // enumerates a live display, requests TCC, starts ScreenCaptureKit or posts
    // Quartz input.
    [[nodiscard]] static std::expected<std::unique_ptr<MacNativeDesktopOwner>,
                                       MacNativeDesktopOwnerError>
    createForTesting(
        const rdp_server::server::security::MacNativeDesktopAuthorization&
            authorization,
        std::uint64_t expectedAuthorizationGeneration,
        MacNativeDesktopTestConfiguration configuration) noexcept;
#endif

    // Advance at most one capture lifecycle submission. The operation executes
    // inside one R2 View visit and repeats GUI-session/TCC capture checks.
    [[nodiscard]] MacNativeDesktopServiceObservation serviceOnce() noexcept;

    // Borrow exactly the requested latest frame synchronously inside one R2
    // View visit. Replacement frames make stale sequence numbers fail rather
    // than silently relabeling bytes.
    [[nodiscard]] bool borrowFramebuffer(
        std::uint64_t expectedFrameSequence,
        MacNativeDesktopFrameConsumer consumer) noexcept;

    // Dispatch one input event inside one R2 View+Input visit and one fresh
    // GUI-session/Accessibility check. View-only owners fail without posting.
    [[nodiscard]] bool handleInput(const MacInputEvent& event) noexcept;

    // Terminal and idempotent. Upstream authority loss discards held input
    // without synthesizing releases into a replacement desktop, then retires
    // the mailbox, capture stream, guard, geometry and native watches.
    void revoke() noexcept;

    [[nodiscard]] MacNativeDesktopOwnerState state() const noexcept {
        return state_;
    }
    [[nodiscard]] std::uint64_t admittedSessionGeneration() const noexcept {
        return state_ == MacNativeDesktopOwnerState::Revoked
            ? 0U : authorizationGeneration_;
    }

private:
    class FrameMailbox;

#if defined(__APPLE__)
    MacNativeDesktopOwner(
        const rdp_server::server::security::MacNativeDesktopAuthorization&
            authorization,
        std::uint64_t expectedAuthorizationGeneration) noexcept;

    [[nodiscard]] std::expected<void, MacNativeDesktopOwnerError>
    initializeNativeAuthorized(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization) noexcept;
    [[nodiscard]] std::expected<void, MacNativeDesktopOwnerError>
    initializeTestingAuthorized(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization,
        MacNativeDesktopTestConfiguration&& configuration) noexcept;

    static bool initializeAuthorizationVisit(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization,
        void* context) noexcept;
    static bool serviceAuthorizationVisit(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization,
        void* context) noexcept;
    static bool borrowAuthorizationVisit(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization,
        void* context) noexcept;
    static bool inputAuthorizationVisit(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization,
        void* context) noexcept;
#endif

    [[nodiscard]] bool authorizationViewMatches(
        const rdp_server::server::security::MacNativeDesktopAuthorizationView&
            authorization,
        std::uint32_t requiredPermissions) const noexcept;
    void serviceAuthorized() noexcept;
    [[nodiscard]] bool borrowAuthorized(
        std::uint64_t expectedFrameSequence,
        MacNativeDesktopFrameConsumer consumer) noexcept;
    [[nodiscard]] bool inputAuthorized(const MacInputEvent& event) noexcept;
    [[nodiscard]] bool captureLifetimeCurrent() noexcept;
    [[nodiscard]] MacNativeDesktopServiceObservation observation() const noexcept;

    const rdp_server::server::security::MacNativeDesktopAuthorization*
        authorization_{};
    NativeDisplayReconfigurationWatch displayWatch_{};
    NativeSessionChangeWatch sessionWatch_{};
    NativeDisplayGeometryRefresh geometry_{};
    std::unique_ptr<MacDesktopSessionGuard> sessionGuard_{};
    std::unique_ptr<MacInputController> input_{};
    std::unique_ptr<MacScreenCaptureStream> capture_{};
    std::shared_ptr<FrameMailbox> frameMailbox_{};
    PixelSize pixelGeometry_{};
    std::uint32_t targetUserId_{};
    std::uint32_t permissionMask_{};
    std::uint64_t authenticationGeneration_{};
    std::uint64_t geometryGeneration_{};
    std::uint64_t authorizationGeneration_{};
    MacNativeDesktopOwnerState state_{MacNativeDesktopOwnerState::Initializing};
};

} // namespace rdp::macos
