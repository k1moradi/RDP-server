// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_host_control.h"

#if defined(_WIN32)
#include "windows/windows_native_desktop_owner.h"
#elif defined(__APPLE__)
#include "platform/macos/mac_native_desktop_owner.h"
#endif

#include <cstdint>
#include <memory>
#include <thread>

namespace rdp_server::server::runtime
{

// One R10 owner-thread composition seam for native Windows/macOS desktop
// lifetimes. This class owns no listener, protocol parser, TLS object, worker
// thread or independent scheduler. Linux already composes its R5 owner inside
// LinuxRuntimeHostControl and deliberately does not use this platform seam.
//
// R2 owns authorization issuance. attach() accepts only a const, already-bound
// authorization object and captures its current generation directly; callers
// cannot supply a generation scalar to manufacture or refresh native access.
class RuntimePlatformNativeDesktop final
{
public:
    RuntimePlatformNativeDesktop() noexcept;
    ~RuntimePlatformNativeDesktop() noexcept;

    RuntimePlatformNativeDesktop(
        const RuntimePlatformNativeDesktop &) = delete;
    RuntimePlatformNativeDesktop &operator=(
        const RuntimePlatformNativeDesktop &) = delete;
    RuntimePlatformNativeDesktop(
        RuntimePlatformNativeDesktop &&) = delete;
    RuntimePlatformNativeDesktop &operator=(
        RuntimePlatformNativeDesktop &&) = delete;

#if defined(_WIN32) || defined(__APPLE__)
    // R10 consumes the exact R2 authenticated-session proof and never accepts
    // a caller-supplied SID/UID or authentication-kind override. The proof and
    // current-owner authority are borrowed for the complete attached lifetime
    // and must outlive retireAfterAuthorizationLoss().
    [[nodiscard]] RuntimeHostResult attachAuthenticatedSession(
        rdp_server::server::security::NativeDesktopAuthenticatedSessionProof
            &authenticatedSession,
        rdp_server::server::security::CurrentOwnerSharingAuthority
            &ownerSharingAuthority,
        std::uint32_t requestedPermissions) noexcept;
#endif

#if defined(_WIN32)
    [[nodiscard]] RuntimeHostResult attach(
        const rdp_server::server::security::WindowsNativeDesktopAuthorization
            &authorization) noexcept;
    [[nodiscard]] RuntimeHostResult serviceOnce(
        rdp_server::windows::WindowsR4BgraFrameConsumer frameConsumer) noexcept;
    [[nodiscard]] bool handleInput(
        const rdp_server::windows::WindowsInputEvent &event) noexcept;
    [[nodiscard]] rdp_server::windows::WindowsCursorReadResult
    readCursorSnapshot(
        rdp_server::windows::WindowsCursorSnapshot &output) noexcept;
    [[nodiscard]] rdp_server::windows::WindowsCaptureSessionChangeResult
    notifySessionChange(std::uint32_t sessionId) noexcept;
#elif defined(__APPLE__)
    [[nodiscard]] RuntimeHostResult attach(
        const rdp_server::server::security::MacNativeDesktopAuthorization
            &authorization) noexcept;
    [[nodiscard]] RuntimeHostResult serviceOnce() noexcept;
    [[nodiscard]] bool borrowFramebuffer(
        std::uint64_t expectedFrameSequence,
        rdp::macos::MacNativeDesktopFrameConsumer consumer) noexcept;
    [[nodiscard]] bool handleInput(
        const rdp::macos::MacInputEvent &event) noexcept;
#endif

    // Upstream R2/R3 routing must be closed before this call. Retirement is
    // owner-thread-affine and idempotent; platform owners perform their own
    // no-post native input teardown before native capture/session resources.
    [[nodiscard]] RuntimeHostResult retireAfterAuthorizationLoss() noexcept;

    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] bool ready() const noexcept;
    [[nodiscard]] std::uint64_t authorizationGeneration() const noexcept;

private:
    [[nodiscard]] bool onOwnerThread() const noexcept;
    void retireInternal() noexcept;

    const std::thread::id ownerThread_;
    std::uint64_t authorizationGeneration_{};

#if defined(_WIN32)
    // Production reader supplies fresh WTS/LSA session evidence; it never
    // authenticates the remote client. ownedAuthorization_ borrows the exact
    // accepted-session proof plus the longer-lived local-owner authority.
    rdp_server::server::security::WindowsNativeSessionEvidenceReader
        nativeEvidence_{};
    std::unique_ptr<
        rdp_server::server::security::WindowsNativeDesktopAuthorization>
        ownedAuthorization_{};
    const rdp_server::server::security::WindowsNativeDesktopAuthorization
        *authorization_{};
    std::unique_ptr<rdp_server::windows::WindowsNativeDesktopOwner>
        nativeDesktop_{};
#elif defined(__APPLE__)
    // Production reader supplies fresh console/audit/SecuritySession evidence;
    // it never authenticates the remote client.
    rdp_server::server::security::MacNativeSessionEvidenceReader
        nativeEvidence_{};
    std::unique_ptr<
        rdp_server::server::security::MacNativeDesktopAuthorization>
        ownedAuthorization_{};
    const rdp_server::server::security::MacNativeDesktopAuthorization
        *authorization_{};
    std::unique_ptr<rdp::macos::MacNativeDesktopOwner> nativeDesktop_{};
#endif
};

} // namespace rdp_server::server::runtime
