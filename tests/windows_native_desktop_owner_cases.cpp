// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/native_desktop_authorization.h"
#include "windows/windows_native_desktop_owner.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

using namespace rdp_server::windows;
using namespace rdp_server::server::security;

namespace
{

class DenyOnlyWindowsIdentity final : public WindowsAuthenticatedIdentityProof
{
public:
    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return 1;
    }

    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte> /* sid */) const noexcept override
    {
        return false;
    }
};

class UnavailableWindowsEvidence final : public WindowsNativeSessionEvidenceSource
{
public:
    [[nodiscard]] WindowsNativeSessionEvidenceStatus readCurrent(
        WindowsNativeSessionEvidence &output) const noexcept override
    {
        ++reads;
        output = {};
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    mutable unsigned reads{};
};

} // namespace

void windowsNativeDesktopOwnerAuthorizationBoundaryDenials()
{
    using OpenSignature =
        WindowsNativeDesktopOpenResult (WindowsNativeDesktopOwner::*)(
            const WindowsNativeDesktopAuthorization &, std::uint64_t) noexcept;
    using ServiceSignature =
        WindowsNativeDesktopServiceResult (WindowsNativeDesktopOwner::*)(
            const WindowsNativeDesktopAuthorization &, std::uint64_t,
            WindowsR4BgraFrameConsumer) noexcept;
    using InputSignature =
        bool (WindowsNativeDesktopOwner::*)(
            const WindowsNativeDesktopAuthorization &, std::uint64_t,
            const WindowsInputEvent &) noexcept;

    static_assert(std::is_same_v<
                  decltype(&WindowsNativeDesktopOwner::open), OpenSignature>);
    static_assert(std::is_same_v<
                  decltype(&WindowsNativeDesktopOwner::serviceOnce),
                  ServiceSignature>);
    static_assert(std::is_same_v<
                  decltype(&WindowsNativeDesktopOwner::handleInput),
                  InputSignature>);
    static_assert(!std::is_constructible_v<
                  WindowsNativeDesktopOwner, WindowsNativeSessionEvidence>);
    static_assert(!std::is_copy_constructible_v<WindowsNativeDesktopOwner>);
    static_assert(!std::is_move_constructible_v<WindowsNativeDesktopOwner>);
    static_assert(!kWindowsNativeDesktopPositiveActivationApproved);

    // Use the real R2 authorization object, deliberately unbound. This proves
    // R6 rejects before any native evidence/layout/DXGI/cursor/SendInput work
    // and does not manufacture a positive downstream grant in CTest.
    DenyOnlyWindowsIdentity identity;
    UnavailableWindowsEvidence evidence;
    CurrentOwnerSharingAuthority ownerSharingAuthority;
    WindowsNativeDesktopAuthorization authorization{
        identity, evidence, ownerSharingAuthority};

    WindowsNativeDesktopOwner owner;
    assert(!owner.ready());
    assert(owner.open(authorization, 1) ==
           WindowsNativeDesktopOpenResult::authorizationDenied);
    assert(evidence.reads == 0);

    assert(owner.serviceOnce(authorization, 1, {}) ==
           WindowsNativeDesktopServiceResult::authorizationRequired);
    assert(evidence.reads == 0);
    assert(!owner.handleInput(
        authorization, 1, WindowsKeyInput{0x1e, false, true}));
    assert(evidence.reads == 0);

    WindowsCursorSnapshot cursor{};
    assert(owner.readCursorSnapshot(authorization, 1, cursor) ==
           WindowsCursorReadResult::failed);
    assert(evidence.reads == 0);
    assert(owner.notifySessionChange(42) ==
           WindowsCaptureSessionChangeResult::alreadyClosed);

    owner.retireAfterAuthorizationLoss();
    assert(!owner.ready());
    assert(owner.open(authorization, 1) ==
           WindowsNativeDesktopOpenResult::closed);
    assert(owner.serviceOnce(authorization, 1, {}) ==
           WindowsNativeDesktopServiceResult::closed);
    owner.retireAfterAuthorizationLoss();
}
