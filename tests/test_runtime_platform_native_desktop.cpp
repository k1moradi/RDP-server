// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_platform_native_desktop.h"
#include "server/security/current_owner_sharing_authority.h"
#include "server/security/native_desktop_authorization.h"

#include <cassert>
#include <cstdint>
#include <span>
#include <thread>
#include <type_traits>

namespace
{
using rdp_server::server::runtime::RuntimeHostError;
using rdp_server::server::runtime::RuntimePlatformNativeDesktop;
using rdp_server::server::security::CurrentOwnerSharingAuthority;

static_assert(!std::is_copy_constructible_v<RuntimePlatformNativeDesktop>);
static_assert(!std::is_copy_assignable_v<RuntimePlatformNativeDesktop>);
static_assert(!std::is_move_constructible_v<RuntimePlatformNativeDesktop>);
static_assert(!std::is_move_assignable_v<RuntimePlatformNativeDesktop>);

#if defined(_WIN32)
class UnavailableIdentity final
    : public rdp_server::server::security::WindowsAuthenticatedIdentityProof
{
public:
    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return 0;
    }

    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte>) const noexcept override
    {
        return false;
    }
};

class UnavailableEvidence final
    : public rdp_server::server::security::WindowsNativeSessionEvidenceSource
{
public:
    [[nodiscard]]
    rdp_server::server::security::WindowsNativeSessionEvidenceStatus
    readCurrent(
        rdp_server::server::security::WindowsNativeSessionEvidence
            &evidence) const noexcept override
    {
        evidence = {};
        return rdp_server::server::security::
            WindowsNativeSessionEvidenceStatus::Unavailable;
    }
};
#elif defined(__APPLE__)
class UnavailableIdentity final
    : public rdp_server::server::security::MacAuthenticatedIdentityProof
{
public:
    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return 0;
    }

    [[nodiscard]] bool matchesAuthenticatedUserId(
        std::uint32_t) const noexcept override
    {
        return false;
    }
};

class UnavailableEvidence final
    : public rdp_server::server::security::MacNativeSessionEvidenceSource
{
public:
    [[nodiscard]]
    rdp_server::server::security::MacNativeSessionEvidenceStatus
    readCurrent(
        rdp_server::server::security::MacNativeSessionEvidence
            &evidence) const noexcept override
    {
        evidence = {};
        return rdp_server::server::security::
            MacNativeSessionEvidenceStatus::Unavailable;
    }
};
#endif

void testR2GatedComposition()
{
    RuntimePlatformNativeDesktop composition;
    assert(!composition.active());
    assert(!composition.ready());
    assert(composition.authorizationGeneration() == 0);

    CurrentOwnerSharingAuthority ownerAuthority;
    UnavailableIdentity identity;
    UnavailableEvidence evidence;

#if defined(_WIN32)
    rdp_server::server::security::WindowsNativeDesktopAuthorization
        authorization(identity, evidence, ownerAuthority);

    const auto noOwnerService = composition.serviceOnce({});
    assert(noOwnerService.error == RuntimeHostError::GraphicsUnavailable);

    const auto attachResult = composition.attach(authorization);
    assert(attachResult.error == RuntimeHostError::NativeAuthorizationDenied);

    const rdp_server::windows::WindowsInputEvent input{
        rdp_server::windows::WindowsKeyInput{}};
    assert(!composition.handleInput(input));

    rdp_server::windows::WindowsCursorSnapshot cursor{};
    assert(composition.readCursorSnapshot(cursor) ==
           rdp_server::windows::WindowsCursorReadResult::failed);
    assert(composition.notifySessionChange(1U) ==
           rdp_server::windows::WindowsCaptureSessionChangeResult::alreadyClosed);
#elif defined(__APPLE__)
    rdp_server::server::security::MacNativeDesktopAuthorization
        authorization(identity, evidence, ownerAuthority);

    const auto noOwnerService = composition.serviceOnce();
    assert(noOwnerService.error == RuntimeHostError::GraphicsUnavailable);

    const auto attachResult = composition.attach(authorization);
    assert(attachResult.error == RuntimeHostError::NativeAuthorizationDenied);

    const rdp::macos::MacInputEvent input{rdp::macos::MacKeyInput{}};
    assert(!composition.handleInput(input));
    assert(!composition.borrowFramebuffer(
        1U, rdp::macos::MacNativeDesktopFrameConsumer{}));
#endif

    assert(!composition.active());
    assert(!composition.ready());
    assert(composition.authorizationGeneration() == 0);

    rdp_server::server::runtime::RuntimeHostResult offThreadResult{};
    std::thread otherThread([&] {
        offThreadResult = composition.retireAfterAuthorizationLoss();
    });
    otherThread.join();
    assert(offThreadResult.error == RuntimeHostError::ControlUnavailable);

    const auto firstRetirement = composition.retireAfterAuthorizationLoss();
    const auto secondRetirement = composition.retireAfterAuthorizationLoss();
    assert(firstRetirement.succeeded());
    assert(secondRetirement.succeeded());
    assert(!composition.active());
}

} // namespace

int main()
{
    testR2GatedComposition();
    return 0;
}
