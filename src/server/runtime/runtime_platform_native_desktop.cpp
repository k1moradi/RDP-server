// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_platform_native_desktop.h"

#include <new>
#include <utility>

namespace rdp_server::server::runtime
{
namespace
{

[[nodiscard]] RuntimeHostError mapNativeAuthorizationBindResult(
    rdp_server::server::security::NativeDesktopAuthorizationBindResult
        result) noexcept
{
    using BindResult =
        rdp_server::server::security::NativeDesktopAuthorizationBindResult;
    switch (result)
    {
    case BindResult::Bound:
        return RuntimeHostError::None;
    case BindResult::InvalidPermissions:
        return RuntimeHostError::InvalidConfiguration;
    case BindResult::AuthenticatedIdentityUnavailable:
    case BindResult::NativeSessionUnavailable:
    case BindResult::AuthenticatedIdentityMismatch:
    case BindResult::OwnerAuthorizationUnavailable:
        return RuntimeHostError::NativeAuthorizationDenied;
    case BindResult::GenerationExhausted:
        return RuntimeHostError::InternalFailure;
    }
    return RuntimeHostError::InternalFailure;
}

#if defined(__APPLE__)
[[nodiscard]] RuntimeHostError mapMacOwnerError(
    rdp::macos::MacNativeDesktopOwnerError error) noexcept
{
    using Error = rdp::macos::MacNativeDesktopOwnerError;
    switch (error)
    {
    case Error::AuthorizationUnavailable:
    case Error::InputUnavailable:
        return RuntimeHostError::NativeAuthorizationDenied;
    case Error::InvalidConfiguration:
        return RuntimeHostError::InvalidConfiguration;
    case Error::DisplayWatchUnavailable:
    case Error::SessionWatchUnavailable:
    case Error::DisplayUnavailable:
    case Error::SessionUnavailable:
    case Error::CaptureUnavailable:
    case Error::FramebufferUnavailable:
        return RuntimeHostError::GraphicsUnavailable;
    case Error::AllocationUnavailable:
        return RuntimeHostError::InternalFailure;
    }
    return RuntimeHostError::InternalFailure;
}
#endif

} // namespace

RuntimePlatformNativeDesktop::RuntimePlatformNativeDesktop() noexcept
    : ownerThread_(std::this_thread::get_id())
{
}

RuntimePlatformNativeDesktop::~RuntimePlatformNativeDesktop() noexcept
{
    // Normal R10 teardown is serialized through retireAfterAuthorizationLoss().
    // Destruction remains fail-safe if an outer owner is itself being destroyed.
    retireInternal();
}

bool RuntimePlatformNativeDesktop::onOwnerThread() const noexcept
{
    return std::this_thread::get_id() == ownerThread_;
}

#if defined(_WIN32) || defined(__APPLE__)
RuntimeHostResult RuntimePlatformNativeDesktop::attachAuthenticatedSession(
    rdp_server::server::security::NativeDesktopAuthenticatedSessionProof
        &authenticatedSession,
    rdp_server::server::security::CurrentOwnerSharingAuthority
        &ownerSharingAuthority,
    std::uint32_t requestedPermissions) noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (nativeDesktop_ != nullptr || authorization_ != nullptr ||
        ownedAuthorization_ != nullptr)
    {
        return {RuntimeHostError::InvalidConfiguration, false};
    }

#if defined(_WIN32)
    using PlatformAuthorization =
        rdp_server::server::security::WindowsNativeDesktopAuthorization;
#elif defined(__APPLE__)
    using PlatformAuthorization =
        rdp_server::server::security::MacNativeDesktopAuthorization;
#endif

    auto candidate = std::unique_ptr<PlatformAuthorization>(
        new (std::nothrow) PlatformAuthorization(
            authenticatedSession, nativeEvidence_, ownerSharingAuthority));
    if (!candidate)
        return {RuntimeHostError::InternalFailure, false};

    const auto bindResult =
        candidate->bindAuthenticatedSession(requestedPermissions);
    if (bindResult != rdp_server::server::security::
                          NativeDesktopAuthorizationBindResult::Bound)
    {
        return {mapNativeAuthorizationBindResult(bindResult), false};
    }

    // Reuse the already-single R10/R5/R6 native owner. attach() captures the
    // authorization generation from the bound object; no caller scalar can
    // manufacture or refresh access.
    const RuntimeHostResult attachResult = attach(*candidate);
    if (!attachResult.succeeded())
    {
        candidate->revoke();
        return attachResult;
    }

    ownedAuthorization_ = std::move(candidate);
    return attachResult;
}
#endif

#if defined(_WIN32)
RuntimeHostResult RuntimePlatformNativeDesktop::attach(
    const rdp_server::server::security::WindowsNativeDesktopAuthorization
        &authorization) noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (nativeDesktop_ != nullptr)
        return {RuntimeHostError::InvalidConfiguration, false};

    const std::uint64_t generation = authorization.authorizationGeneration();
    if (generation == 0)
        return {RuntimeHostError::NativeAuthorizationDenied, false};

    auto candidate =
        std::unique_ptr<rdp_server::windows::WindowsNativeDesktopOwner>(
            new (std::nothrow)
                rdp_server::windows::WindowsNativeDesktopOwner());
    if (!candidate)
        return {RuntimeHostError::InternalFailure, false};

    using OpenResult =
        rdp_server::windows::WindowsNativeDesktopOpenResult;
    switch (candidate->open(authorization, generation))
    {
    case OpenResult::ready:
        authorization_ = &authorization;
        authorizationGeneration_ = generation;
        nativeDesktop_ = std::move(candidate);
        return {RuntimeHostError::None, false};
    case OpenResult::authorizationDenied:
        return {RuntimeHostError::NativeAuthorizationDenied, false};
    case OpenResult::nativeCompositionUnavailable:
        // R6 deliberately keeps positive Win32 construction disabled until
        // this R10 seam exists and a real authenticated provider is qualified.
        return {RuntimeHostError::GraphicsUnavailable, false};
    case OpenResult::closed:
        return {RuntimeHostError::AccessRevoked, false};
    }
    return {RuntimeHostError::InternalFailure, false};
}

RuntimeHostResult RuntimePlatformNativeDesktop::serviceOnce(
    rdp_server::windows::WindowsR4BgraFrameConsumer frameConsumer) noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (nativeDesktop_ == nullptr || authorization_ == nullptr ||
        authorizationGeneration_ == 0)
    {
        return {RuntimeHostError::GraphicsUnavailable, false};
    }

    using ServiceResult =
        rdp_server::windows::WindowsNativeDesktopServiceResult;
    switch (nativeDesktop_->serviceOnce(
        *authorization_, authorizationGeneration_, frameConsumer))
    {
    case ServiceResult::idle:
        return {RuntimeHostError::None, true};
    case ServiceResult::frameConsumed:
        return {RuntimeHostError::None, false};
    case ServiceResult::nativeCompositionUnavailable:
        return {RuntimeHostError::GraphicsUnavailable, false};
    case ServiceResult::authorizationRequired:
        retireInternal();
        return {RuntimeHostError::NativeAuthorizationDenied, false};
    case ServiceResult::failed:
        retireInternal();
        return {RuntimeHostError::InternalFailure, false};
    case ServiceResult::closed:
        retireInternal();
        return {RuntimeHostError::AccessRevoked, false};
    }
    retireInternal();
    return {RuntimeHostError::InternalFailure, false};
}

bool RuntimePlatformNativeDesktop::handleInput(
    const rdp_server::windows::WindowsInputEvent &event) noexcept
{
    if (!onOwnerThread() || nativeDesktop_ == nullptr ||
        authorization_ == nullptr || authorizationGeneration_ == 0)
    {
        return false;
    }

    const bool handled = nativeDesktop_->handleInput(
        *authorization_, authorizationGeneration_, event);
    if (!handled && !nativeDesktop_->ready())
        retireInternal();
    return handled;
}

rdp_server::windows::WindowsCursorReadResult
RuntimePlatformNativeDesktop::readCursorSnapshot(
    rdp_server::windows::WindowsCursorSnapshot &output) noexcept
{
    using Result = rdp_server::windows::WindowsCursorReadResult;
    if (!onOwnerThread() || nativeDesktop_ == nullptr ||
        authorization_ == nullptr || authorizationGeneration_ == 0)
    {
        return Result::failed;
    }

    const Result result = nativeDesktop_->readCursorSnapshot(
        *authorization_, authorizationGeneration_, output);
    if (result == Result::failed && !nativeDesktop_->ready())
        retireInternal();
    return result;
}

rdp_server::windows::WindowsCaptureSessionChangeResult
RuntimePlatformNativeDesktop::notifySessionChange(
    std::uint32_t sessionId) noexcept
{
    using Result =
        rdp_server::windows::WindowsCaptureSessionChangeResult;
    if (!onOwnerThread() || nativeDesktop_ == nullptr)
        return Result::alreadyClosed;

    const Result result = nativeDesktop_->notifySessionChange(sessionId);
    if (!nativeDesktop_->ready())
        retireInternal();
    return result;
}

#elif defined(__APPLE__)

RuntimeHostResult RuntimePlatformNativeDesktop::attach(
    const rdp_server::server::security::MacNativeDesktopAuthorization
        &authorization) noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (nativeDesktop_ != nullptr)
        return {RuntimeHostError::InvalidConfiguration, false};

    const std::uint64_t generation = authorization.authorizationGeneration();
    if (generation == 0)
        return {RuntimeHostError::NativeAuthorizationDenied, false};

    auto candidate =
        rdp::macos::MacNativeDesktopOwner::createAuthorized(
            authorization, generation);
    if (!candidate)
        return {mapMacOwnerError(candidate.error()), false};

    authorization_ = &authorization;
    authorizationGeneration_ = generation;
    nativeDesktop_ = std::move(*candidate);
    return {RuntimeHostError::None, false};
}

RuntimeHostResult RuntimePlatformNativeDesktop::serviceOnce() noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (nativeDesktop_ == nullptr || authorization_ == nullptr ||
        authorizationGeneration_ == 0)
    {
        return {RuntimeHostError::GraphicsUnavailable, false};
    }

    const rdp::macos::MacNativeDesktopServiceObservation observation =
        nativeDesktop_->serviceOnce();
    using State = rdp::macos::MacNativeDesktopOwnerState;
    switch (observation.state)
    {
    case State::Initializing:
    case State::CapturePreparing:
    case State::CaptureStarting:
        return {RuntimeHostError::None, true};
    case State::Ready:
        return {RuntimeHostError::None, false};
    case State::Revoked:
        retireInternal();
        return {RuntimeHostError::NativeAuthorizationDenied, false};
    }
    retireInternal();
    return {RuntimeHostError::InternalFailure, false};
}

bool RuntimePlatformNativeDesktop::borrowFramebuffer(
    std::uint64_t expectedFrameSequence,
    rdp::macos::MacNativeDesktopFrameConsumer consumer) noexcept
{
    if (!onOwnerThread() || nativeDesktop_ == nullptr)
        return false;

    const bool borrowed =
        nativeDesktop_->borrowFramebuffer(expectedFrameSequence, consumer);
    if (nativeDesktop_->state() ==
        rdp::macos::MacNativeDesktopOwnerState::Revoked)
    {
        retireInternal();
    }
    return borrowed;
}

bool RuntimePlatformNativeDesktop::handleInput(
    const rdp::macos::MacInputEvent &event) noexcept
{
    if (!onOwnerThread() || nativeDesktop_ == nullptr)
        return false;

    const bool handled = nativeDesktop_->handleInput(event);
    if (nativeDesktop_->state() ==
        rdp::macos::MacNativeDesktopOwnerState::Revoked)
    {
        retireInternal();
    }
    return handled;
}
#endif

RuntimeHostResult
RuntimePlatformNativeDesktop::retireAfterAuthorizationLoss() noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireInternal();
    return {RuntimeHostError::None, false};
}

void RuntimePlatformNativeDesktop::retireInternal() noexcept
{
#if defined(_WIN32)
    if (nativeDesktop_ != nullptr)
        nativeDesktop_->retireAfterAuthorizationLoss();
#elif defined(__APPLE__)
    if (nativeDesktop_ != nullptr)
        nativeDesktop_->revoke();
#endif
    nativeDesktop_.reset();
    authorization_ = nullptr;
    authorizationGeneration_ = 0;
    if (ownedAuthorization_ != nullptr)
    {
        // Native children are already retired. Drop the R2 grant snapshot only
        // afterward so teardown never needs to post cleanup input through
        // revoked desktop authority.
        ownedAuthorization_->revoke();
        ownedAuthorization_.reset();
    }
}

bool RuntimePlatformNativeDesktop::active() const noexcept
{
    return nativeDesktop_ != nullptr && authorization_ != nullptr &&
           authorizationGeneration_ != 0;
}

bool RuntimePlatformNativeDesktop::ready() const noexcept
{
#if defined(_WIN32)
    return active() && nativeDesktop_->ready();
#elif defined(__APPLE__)
    return active() &&
           nativeDesktop_->state() ==
               rdp::macos::MacNativeDesktopOwnerState::Ready;
#else
    return false;
#endif
}

std::uint64_t
RuntimePlatformNativeDesktop::authorizationGeneration() const noexcept
{
    return active() ? authorizationGeneration_ : 0;
}

} // namespace rdp_server::server::runtime
