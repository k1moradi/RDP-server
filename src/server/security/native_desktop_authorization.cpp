// SPDX-License-Identifier: GPL-3.0-or-later
#include "native_desktop_authorization.h"

#include <algorithm>
#include <limits>

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] bool validGrantPermissions(std::uint32_t permissions) noexcept
{
    return permissions != 0 &&
           (permissions & kConsoleViewPermission) != 0 &&
           (permissions & ~kNativeDesktopAuthorizationPermissions) == 0;
}

[[nodiscard]] bool validRequiredPermissions(
    std::uint32_t permissions) noexcept
{
    return permissions != 0 &&
           (permissions & ~kNativeDesktopAuthorizationPermissions) == 0;
}

[[nodiscard]] bool validAuthenticationKind(
    NativeDesktopAuthenticationKind kind) noexcept
{
    return kind == NativeDesktopAuthenticationKind::ExistingOsAccount ||
           kind == NativeDesktopAuthenticationKind::StandalonePassword;
}

[[nodiscard]] bool validWindowsEvidence(
    const WindowsNativeSessionEvidence &evidence) noexcept
{
    constexpr std::uint32_t kInteractiveLogonType = 2U;
    constexpr std::uint32_t kCachedInteractiveLogonType = 11U;

    return evidence.userSidBytes != 0 &&
           evidence.userSidBytes <= evidence.userSid.size() &&
           evidence.sessionId != 0 &&
           evidence.sessionId !=
               (std::numeric_limits<std::uint32_t>::max)() &&
           (evidence.authenticationIdLow != 0 ||
            evidence.authenticationIdHigh != 0) &&
           evidence.logonTime100Nanoseconds > 0 &&
           (evidence.logonType == kInteractiveLogonType ||
            evidence.logonType == kCachedInteractiveLogonType);
}

[[nodiscard]] bool sameWindowsEvidence(
    const WindowsNativeSessionEvidence &left,
    const WindowsNativeSessionEvidence &right) noexcept
{
    return validWindowsEvidence(left) &&
           validWindowsEvidence(right) &&
           left.userSidBytes == right.userSidBytes &&
           std::equal(
               left.userSid.begin(),
               left.userSid.begin() +
                   static_cast<std::ptrdiff_t>(left.userSidBytes),
               right.userSid.begin()) &&
           left.sessionId == right.sessionId &&
           left.authenticationIdLow == right.authenticationIdLow &&
           left.authenticationIdHigh == right.authenticationIdHigh &&
           left.logonTime100Nanoseconds == right.logonTime100Nanoseconds &&
           left.logonType == right.logonType;
}

[[nodiscard]] std::string_view macConsoleUser(
    const MacNativeSessionEvidence &evidence) noexcept
{
    if (evidence.consoleUserBytes == 0 ||
        evidence.consoleUserBytes > kMaximumMacNativeConsoleUserBytes)
    {
        return {};
    }
    return {evidence.consoleUser.data(), evidence.consoleUserBytes};
}

[[nodiscard]] bool validMacEvidence(
    const MacNativeSessionEvidence &evidence) noexcept
{
    return !macConsoleUser(evidence).empty() &&
           evidence.consoleUserId != 0 &&
           evidence.auditUserId == evidence.consoleUserId &&
           evidence.auditSessionId != 0 &&
           evidence.securitySessionId != 0 &&
           evidence.securitySessionAttributes != 0;
}

[[nodiscard]] bool sameMacEvidence(
    const MacNativeSessionEvidence &left,
    const MacNativeSessionEvidence &right) noexcept
{
    return validMacEvidence(left) &&
           validMacEvidence(right) &&
           macConsoleUser(left) == macConsoleUser(right) &&
           left.consoleUserId == right.consoleUserId &&
           left.auditUserId == right.auditUserId &&
           left.auditSessionId == right.auditSessionId &&
           left.securitySessionId == right.securitySessionId &&
           left.securitySessionAttributes == right.securitySessionAttributes;
}

} // namespace

WindowsNativeDesktopAuthorizationView::WindowsNativeDesktopAuthorizationView(
    const WindowsNativeSessionEvidence &evidence,
    NativeDesktopAuthenticationKind authenticationKind,
    std::uint32_t permissionMask,
    std::uint64_t authenticationGeneration,
    std::uint64_t authorizationGeneration,
    OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch) noexcept
    : evidence_(&evidence),
      authenticationKind_(authenticationKind),
      permissionMask_(permissionMask),
      authenticationGeneration_(authenticationGeneration),
      authorizationGeneration_(authorizationGeneration),
      ownerAuthorizationEpoch_(ownerAuthorizationEpoch)
{
}

NativeDesktopAuthenticationKind
WindowsNativeDesktopAuthorizationView::authenticationKind() const noexcept
{
    return authenticationKind_;
}

std::span<const std::byte>
WindowsNativeDesktopAuthorizationView::nativeSessionUserSid() const noexcept
{
    return {evidence_->userSid.data(), evidence_->userSidBytes};
}

std::span<const std::byte>
WindowsNativeDesktopAuthorizationView::authenticatedSid() const noexcept
{
    return authenticationKind_ ==
                   NativeDesktopAuthenticationKind::ExistingOsAccount
        ? nativeSessionUserSid()
        : std::span<const std::byte>{};
}

std::uint32_t
WindowsNativeDesktopAuthorizationView::wtsSessionId() const noexcept
{
    return evidence_->sessionId;
}

std::uint32_t
WindowsNativeDesktopAuthorizationView::authenticationIdLow() const noexcept
{
    return evidence_->authenticationIdLow;
}

std::int32_t
WindowsNativeDesktopAuthorizationView::authenticationIdHigh() const noexcept
{
    return evidence_->authenticationIdHigh;
}

std::int64_t
WindowsNativeDesktopAuthorizationView::logonTime100Nanoseconds() const noexcept
{
    return evidence_->logonTime100Nanoseconds;
}

std::uint32_t
WindowsNativeDesktopAuthorizationView::permissionMask() const noexcept
{
    return permissionMask_;
}

std::uint64_t
WindowsNativeDesktopAuthorizationView::authenticationGeneration() const noexcept
{
    return authenticationGeneration_;
}

std::uint64_t
WindowsNativeDesktopAuthorizationView::authorizationGeneration() const noexcept
{
    return authorizationGeneration_;
}

OwnerSharingAuthorizationEpoch
WindowsNativeDesktopAuthorizationView::ownerAuthorizationEpoch() const noexcept
{
    return ownerAuthorizationEpoch_;
}

MacNativeDesktopAuthorizationView::MacNativeDesktopAuthorizationView(
    const MacNativeSessionEvidence &evidence,
    NativeDesktopAuthenticationKind authenticationKind,
    std::uint32_t permissionMask,
    std::uint64_t authenticationGeneration,
    std::uint64_t authorizationGeneration,
    OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch) noexcept
    : evidence_(&evidence),
      authenticationKind_(authenticationKind),
      permissionMask_(permissionMask),
      authenticationGeneration_(authenticationGeneration),
      authorizationGeneration_(authorizationGeneration),
      ownerAuthorizationEpoch_(ownerAuthorizationEpoch)
{
}

NativeDesktopAuthenticationKind
MacNativeDesktopAuthorizationView::authenticationKind() const noexcept
{
    return authenticationKind_;
}

std::uint32_t
MacNativeDesktopAuthorizationView::nativeConsoleUserId() const noexcept
{
    return evidence_->consoleUserId;
}

std::uint32_t
MacNativeDesktopAuthorizationView::authenticatedUserId() const noexcept
{
    return authenticationKind_ ==
                   NativeDesktopAuthenticationKind::ExistingOsAccount
        ? nativeConsoleUserId()
        : 0U;
}

std::string_view
MacNativeDesktopAuthorizationView::consoleUser() const noexcept
{
    return macConsoleUser(*evidence_);
}

std::uint32_t
MacNativeDesktopAuthorizationView::auditUserId() const noexcept
{
    return evidence_->auditUserId;
}

std::uint64_t
MacNativeDesktopAuthorizationView::auditSessionId() const noexcept
{
    return evidence_->auditSessionId;
}

std::uint32_t
MacNativeDesktopAuthorizationView::securitySessionId() const noexcept
{
    return evidence_->securitySessionId;
}

std::uint32_t
MacNativeDesktopAuthorizationView::securitySessionAttributes() const noexcept
{
    return evidence_->securitySessionAttributes;
}

std::uint32_t
MacNativeDesktopAuthorizationView::permissionMask() const noexcept
{
    return permissionMask_;
}

std::uint64_t
MacNativeDesktopAuthorizationView::authenticationGeneration() const noexcept
{
    return authenticationGeneration_;
}

std::uint64_t
MacNativeDesktopAuthorizationView::authorizationGeneration() const noexcept
{
    return authorizationGeneration_;
}

OwnerSharingAuthorizationEpoch
MacNativeDesktopAuthorizationView::ownerAuthorizationEpoch() const noexcept
{
    return ownerAuthorizationEpoch_;
}

WindowsNativeDesktopAuthorization::WindowsNativeDesktopAuthorization(
    NativeDesktopAuthenticatedSessionProof &authenticatedSession,
    WindowsNativeSessionEvidenceSource &nativeEvidence,
    CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept
    : authenticatedSession_(&authenticatedSession),
      nativeEvidence_(&nativeEvidence),
      ownerSharingAuthority_(&ownerSharingAuthority)
{
}

NativeDesktopAuthorizationBindResult
WindowsNativeDesktopAuthorization::bindAuthenticatedSession(
    std::uint32_t requestedPermissions) noexcept
{
    clearGrant();
    if (!validGrantPermissions(requestedPermissions))
        return NativeDesktopAuthorizationBindResult::InvalidPermissions;

    const NativeDesktopAuthenticationKind authenticationKind =
        authenticatedSession_->authenticationKind();
    const std::uint64_t authenticationGeneration =
        authenticatedSession_->authenticationGeneration();
    if (!validAuthenticationKind(authenticationKind) ||
        authenticationGeneration == 0 ||
        !authenticatedSession_->revalidatesAuthenticatedSession())
    {
        return NativeDesktopAuthorizationBindResult::
            AuthenticatedIdentityUnavailable;
    }

    WindowsNativeSessionEvidence firstEvidence{};
    if (nativeEvidence_->readCurrent(firstEvidence) !=
            WindowsNativeSessionEvidenceStatus::Observed ||
        !validWindowsEvidence(firstEvidence))
    {
        return NativeDesktopAuthorizationBindResult::NativeSessionUnavailable;
    }

    const std::span<const std::byte> firstSid{
        firstEvidence.userSid.data(), firstEvidence.userSidBytes};
    if (authenticatedSession_->authenticationKind() != authenticationKind ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration ||
        !authenticatedSession_->revalidatesAuthenticatedSession() ||
        (authenticationKind ==
             NativeDesktopAuthenticationKind::ExistingOsAccount &&
         !authenticatedSession_->matchesWindowsOsAccountSid(firstSid)))
    {
        return NativeDesktopAuthorizationBindResult::
            AuthenticatedIdentityMismatch;
    }

    const auto ownerAuthorizationEpoch =
        ownerSharingAuthority_->authorizationEpoch(requestedPermissions);
    if (!ownerAuthorizationEpoch)
    {
        return NativeDesktopAuthorizationBindResult::
            OwnerAuthorizationUnavailable;
    }

    WindowsNativeSessionEvidence secondEvidence{};
    if (nativeEvidence_->readCurrent(secondEvidence) !=
            WindowsNativeSessionEvidenceStatus::Observed ||
        !sameWindowsEvidence(firstEvidence, secondEvidence))
    {
        return NativeDesktopAuthorizationBindResult::NativeSessionUnavailable;
    }

    const std::span<const std::byte> secondSid{
        secondEvidence.userSid.data(), secondEvidence.userSidBytes};
    if (authenticatedSession_->authenticationKind() != authenticationKind ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration ||
        !authenticatedSession_->revalidatesAuthenticatedSession() ||
        (authenticationKind ==
             NativeDesktopAuthenticationKind::ExistingOsAccount &&
         !authenticatedSession_->matchesWindowsOsAccountSid(secondSid)))
    {
        return NativeDesktopAuthorizationBindResult::
            AuthenticatedIdentityMismatch;
    }
    if (!ownerSharingAuthority_->authorizesAtEpoch(
            requestedPermissions, *ownerAuthorizationEpoch))
    {
        return NativeDesktopAuthorizationBindResult::
            OwnerAuthorizationUnavailable;
    }
    if (nextAuthorizationGeneration_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        return NativeDesktopAuthorizationBindResult::GenerationExhausted;
    }

    evidence_ = secondEvidence;
    authenticationKind_ = authenticationKind;
    ownerAuthorizationEpoch_ = *ownerAuthorizationEpoch;
    permissionMask_ = requestedPermissions;
    authenticationGeneration_ = authenticationGeneration;
    activeAuthorizationGeneration_ = ++nextAuthorizationGeneration_;
    return NativeDesktopAuthorizationBindResult::Bound;
}

void WindowsNativeDesktopAuthorization::revoke() noexcept
{
    clearGrant();
}

std::uint64_t
WindowsNativeDesktopAuthorization::authorizationGeneration() const noexcept
{
    return activeAuthorizationGeneration_;
}

bool WindowsNativeDesktopAuthorization::revalidatesCurrentGrant() const noexcept
{
    if (activeAuthorizationGeneration_ == 0 ||
        authenticationGeneration_ == 0 ||
        authenticatedSession_->authenticationKind() != authenticationKind_ ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration_ ||
        !authenticatedSession_->revalidatesAuthenticatedSession() ||
        !ownerSharingAuthority_->authorizesAtEpoch(
            permissionMask_, ownerAuthorizationEpoch_))
    {
        return false;
    }

    WindowsNativeSessionEvidence currentEvidence{};
    if (nativeEvidence_->readCurrent(currentEvidence) !=
            WindowsNativeSessionEvidenceStatus::Observed ||
        !sameWindowsEvidence(evidence_, currentEvidence))
    {
        return false;
    }

    const std::span<const std::byte> currentSid{
        currentEvidence.userSid.data(), currentEvidence.userSidBytes};
    return authenticatedSession_->authenticationKind() == authenticationKind_ &&
           authenticatedSession_->authenticationGeneration() ==
               authenticationGeneration_ &&
           authenticatedSession_->revalidatesAuthenticatedSession() &&
           (authenticationKind_ ==
                NativeDesktopAuthenticationKind::StandalonePassword ||
            authenticatedSession_->matchesWindowsOsAccountSid(currentSid));
}

bool WindowsNativeDesktopAuthorization::visit(
    std::uint64_t expectedAuthorizationGeneration,
    std::uint32_t requiredPermissions,
    WindowsNativeDesktopAuthorizationVisitor visitor,
    void *context) const noexcept
{
    if (expectedAuthorizationGeneration == 0 ||
        expectedAuthorizationGeneration != activeAuthorizationGeneration_ ||
        !validRequiredPermissions(requiredPermissions) ||
        (permissionMask_ & requiredPermissions) != requiredPermissions ||
        visitor == nullptr)
    {
        return false;
    }
    if (!revalidatesCurrentGrant())
    {
        clearGrant();
        return false;
    }

    const WindowsNativeDesktopAuthorizationView authorization{
        evidence_, authenticationKind_, permissionMask_, authenticationGeneration_,
        activeAuthorizationGeneration_, ownerAuthorizationEpoch_};
    if (!visitor(authorization, context) || !revalidatesCurrentGrant())
    {
        clearGrant();
        return false;
    }
    return true;
}

void WindowsNativeDesktopAuthorization::clearGrant() const noexcept
{
    evidence_ = {};
    authenticationKind_ = NativeDesktopAuthenticationKind::ExistingOsAccount;
    ownerAuthorizationEpoch_ = {};
    permissionMask_ = 0;
    authenticationGeneration_ = 0;
    activeAuthorizationGeneration_ = 0;
}

MacNativeDesktopAuthorization::MacNativeDesktopAuthorization(
    NativeDesktopAuthenticatedSessionProof &authenticatedSession,
    MacNativeSessionEvidenceSource &nativeEvidence,
    CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept
    : authenticatedSession_(&authenticatedSession),
      nativeEvidence_(&nativeEvidence),
      ownerSharingAuthority_(&ownerSharingAuthority)
{
}

NativeDesktopAuthorizationBindResult
MacNativeDesktopAuthorization::bindAuthenticatedSession(
    std::uint32_t requestedPermissions) noexcept
{
    clearGrant();
    if (!validGrantPermissions(requestedPermissions))
        return NativeDesktopAuthorizationBindResult::InvalidPermissions;

    const NativeDesktopAuthenticationKind authenticationKind =
        authenticatedSession_->authenticationKind();
    const std::uint64_t authenticationGeneration =
        authenticatedSession_->authenticationGeneration();
    if (!validAuthenticationKind(authenticationKind) ||
        authenticationGeneration == 0 ||
        !authenticatedSession_->revalidatesAuthenticatedSession())
    {
        return NativeDesktopAuthorizationBindResult::
            AuthenticatedIdentityUnavailable;
    }

    MacNativeSessionEvidence firstEvidence{};
    if (nativeEvidence_->readCurrent(firstEvidence) !=
            MacNativeSessionEvidenceStatus::Observed ||
        !validMacEvidence(firstEvidence))
    {
        return NativeDesktopAuthorizationBindResult::NativeSessionUnavailable;
    }
    if (authenticatedSession_->authenticationKind() != authenticationKind ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration ||
        !authenticatedSession_->revalidatesAuthenticatedSession() ||
        (authenticationKind ==
             NativeDesktopAuthenticationKind::ExistingOsAccount &&
         !authenticatedSession_->matchesMacOsAccountUserId(
             firstEvidence.consoleUserId)))
    {
        return NativeDesktopAuthorizationBindResult::
            AuthenticatedIdentityMismatch;
    }

    const auto ownerAuthorizationEpoch =
        ownerSharingAuthority_->authorizationEpoch(requestedPermissions);
    if (!ownerAuthorizationEpoch)
    {
        return NativeDesktopAuthorizationBindResult::
            OwnerAuthorizationUnavailable;
    }

    MacNativeSessionEvidence secondEvidence{};
    if (nativeEvidence_->readCurrent(secondEvidence) !=
            MacNativeSessionEvidenceStatus::Observed ||
        !sameMacEvidence(firstEvidence, secondEvidence))
    {
        return NativeDesktopAuthorizationBindResult::NativeSessionUnavailable;
    }
    if (authenticatedSession_->authenticationKind() != authenticationKind ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration ||
        !authenticatedSession_->revalidatesAuthenticatedSession() ||
        (authenticationKind ==
             NativeDesktopAuthenticationKind::ExistingOsAccount &&
         !authenticatedSession_->matchesMacOsAccountUserId(
             secondEvidence.consoleUserId)))
    {
        return NativeDesktopAuthorizationBindResult::
            AuthenticatedIdentityMismatch;
    }
    if (!ownerSharingAuthority_->authorizesAtEpoch(
            requestedPermissions, *ownerAuthorizationEpoch))
    {
        return NativeDesktopAuthorizationBindResult::
            OwnerAuthorizationUnavailable;
    }
    if (nextAuthorizationGeneration_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        return NativeDesktopAuthorizationBindResult::GenerationExhausted;
    }

    evidence_ = secondEvidence;
    authenticationKind_ = authenticationKind;
    ownerAuthorizationEpoch_ = *ownerAuthorizationEpoch;
    permissionMask_ = requestedPermissions;
    authenticationGeneration_ = authenticationGeneration;
    activeAuthorizationGeneration_ = ++nextAuthorizationGeneration_;
    return NativeDesktopAuthorizationBindResult::Bound;
}

void MacNativeDesktopAuthorization::revoke() noexcept
{
    clearGrant();
}

std::uint64_t
MacNativeDesktopAuthorization::authorizationGeneration() const noexcept
{
    return activeAuthorizationGeneration_;
}

bool MacNativeDesktopAuthorization::revalidatesCurrentGrant() const noexcept
{
    if (activeAuthorizationGeneration_ == 0 ||
        authenticationGeneration_ == 0 ||
        authenticatedSession_->authenticationKind() != authenticationKind_ ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration_ ||
        !authenticatedSession_->revalidatesAuthenticatedSession() ||
        !ownerSharingAuthority_->authorizesAtEpoch(
            permissionMask_, ownerAuthorizationEpoch_))
    {
        return false;
    }

    MacNativeSessionEvidence currentEvidence{};
    if (nativeEvidence_->readCurrent(currentEvidence) !=
            MacNativeSessionEvidenceStatus::Observed ||
        !sameMacEvidence(evidence_, currentEvidence))
    {
        return false;
    }

    // Evidence collection may synchronously revoke owner consent. Inspect the
    // exact epoch again after the native callback, not only before it.
    return ownerSharingAuthority_->authorizesAtEpoch(
               permissionMask_, ownerAuthorizationEpoch_) &&
           authenticatedSession_->authenticationKind() == authenticationKind_ &&
           authenticatedSession_->authenticationGeneration() ==
               authenticationGeneration_ &&
           authenticatedSession_->revalidatesAuthenticatedSession() &&
           (authenticationKind_ ==
                NativeDesktopAuthenticationKind::StandalonePassword ||
            authenticatedSession_->matchesMacOsAccountUserId(
                currentEvidence.consoleUserId));
}

bool MacNativeDesktopAuthorization::visit(
    std::uint64_t expectedAuthorizationGeneration,
    std::uint32_t requiredPermissions,
    MacNativeDesktopAuthorizationVisitor visitor,
    void *context) const noexcept
{
    if (expectedAuthorizationGeneration == 0 ||
        expectedAuthorizationGeneration != activeAuthorizationGeneration_ ||
        !validRequiredPermissions(requiredPermissions) ||
        (permissionMask_ & requiredPermissions) != requiredPermissions ||
        visitor == nullptr)
    {
        return false;
    }
    // Native evidence readers and protected consumers can synchronously call
    // back into the R2 owner. Deny nested positive visits without mutating the
    // original or a newer independent authorization generation.
    if (visitInProgress_)
        return false;
    struct VisitScope final
    {
        bool &inProgress;
        explicit VisitScope(bool &value) noexcept : inProgress(value)
        {
            inProgress = true;
        }
        ~VisitScope() noexcept { inProgress = false; }
    };
    const VisitScope activeVisit{visitInProgress_};

    if (!revalidatesCurrentGrant() ||
        expectedAuthorizationGeneration != activeAuthorizationGeneration_)
    {
        // A reentrant native evidence probe may have installed a later grant.
        // Deny the original visit without retiring that independent lifetime.
        if (expectedAuthorizationGeneration == activeAuthorizationGeneration_)
            clearGrant();
        return false;
    }

    // Keep the synchronous borrowed view stable if the visitor itself revokes
    // or replaces the grant. The view must not outlive this callback.
    const MacNativeSessionEvidence authorizedEvidence = evidence_;
    const MacNativeDesktopAuthorizationView authorization{
        authorizedEvidence, authenticationKind_, permissionMask_,
        authenticationGeneration_, activeAuthorizationGeneration_,
        ownerAuthorizationEpoch_};
    const bool visitorAccepted = visitor(authorization, context);
    if (expectedAuthorizationGeneration != activeAuthorizationGeneration_)
        return false;

    if (!visitorAccepted || !revalidatesCurrentGrant() ||
        expectedAuthorizationGeneration != activeAuthorizationGeneration_)
    {
        if (expectedAuthorizationGeneration == activeAuthorizationGeneration_)
            clearGrant();
        return false;
    }
    return true;
}

void MacNativeDesktopAuthorization::clearGrant() const noexcept
{
    evidence_ = {};
    authenticationKind_ = NativeDesktopAuthenticationKind::ExistingOsAccount;
    ownerAuthorizationEpoch_ = {};
    permissionMask_ = 0;
    authenticationGeneration_ = 0;
    activeAuthorizationGeneration_ = 0;
}

} // namespace rdp_server::server::security
