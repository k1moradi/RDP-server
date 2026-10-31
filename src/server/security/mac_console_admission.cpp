// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_console_admission.h"

#include <limits>

namespace rdp_server::server::security
{
namespace
{
struct PreparedLifetimeCapture final
{
    NativeDesktopAuthenticationKind authenticationKind{
        NativeDesktopAuthenticationKind::ExistingOsAccount};
    OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch{};
    std::uint32_t permissionMask{};
    std::uint32_t nativeConsoleUserId{};
    std::uint32_t auditUserId{};
    std::uint64_t auditSessionId{};
    std::uint32_t securitySessionId{};
    std::uint32_t securitySessionAttributes{};
    std::uint64_t authenticationGeneration{};
    std::uint64_t authorizationGeneration{};
    bool captured{};
};

[[nodiscard]] bool capturePreparedLifetime(
    const MacNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto *const capture = static_cast<PreparedLifetimeCapture *>(context);
    if (capture == nullptr)
        return false;
    capture->authenticationKind = authorization.authenticationKind();
    capture->ownerAuthorizationEpoch = authorization.ownerAuthorizationEpoch();
    capture->permissionMask = authorization.permissionMask();
    capture->nativeConsoleUserId = authorization.nativeConsoleUserId();
    capture->auditUserId = authorization.auditUserId();
    capture->auditSessionId = authorization.auditSessionId();
    capture->securitySessionId = authorization.securitySessionId();
    capture->securitySessionAttributes =
        authorization.securitySessionAttributes();
    capture->authenticationGeneration =
        authorization.authenticationGeneration();
    capture->authorizationGeneration =
        authorization.authorizationGeneration();
    capture->captured = true;
    return true;
}

[[nodiscard]] bool acceptPreparedLifetime(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void * /* context */) noexcept
{
    return true;
}
} // namespace

MacConsoleAdmissionBroker::MacConsoleAdmissionBroker(
    NativeDesktopAuthenticatedSessionProof &authenticatedSession,
    rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    MacNativeSessionEvidenceSource &nativeEvidence,
    CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept
    : authenticatedSession_(&authenticatedSession),
      connection_(&connection),
      nativeAuthorization_(
          authenticatedSession, nativeEvidence, ownerSharingAuthority)
{
}

MacConsoleAdmissionBroker::~MacConsoleAdmissionBroker()
{
    revoke(MacConsoleAdmissionRevocationReason::Explicit);
}

bool MacConsoleAdmissionBroker::authenticatedConnectionCurrent() const noexcept
{
    return authenticatedSession_ != nullptr &&
           connection_ != nullptr &&
           authenticatedSession_->authenticationKind() ==
               NativeDesktopAuthenticationKind::StandalonePassword &&
           authenticatedSession_->authenticationGeneration() != 0U &&
           authenticatedSession_->configuredCredentialGeneration() != 0U &&
           authenticatedSession_->revalidatesAuthenticatedSession() &&
           authenticatedSession_->revalidatesOwnedR1Connection(*connection_);
}

bool MacConsoleAdmissionBroker::preparedAuthenticationCurrent() const noexcept
{
    return state_ == MacConsoleAdmissionState::Prepared &&
           authenticatedConnectionCurrent() &&
           authenticatedSession_->authenticationGeneration() ==
               prepared_.authenticationGeneration &&
           authenticatedSession_->configuredCredentialGeneration() ==
               prepared_.credentialGeneration;
}

bool MacConsoleAdmissionBroker::validRequiredPermissions(
    std::uint32_t requiredPermissions) const noexcept
{
    return requiredPermissions != 0U &&
           (requiredPermissions & ~kNativeDesktopAuthorizationPermissions) == 0U &&
           (prepared_.permissionMask & requiredPermissions) ==
               requiredPermissions;
}

MacConsoleAdmissionPrepareResult MacConsoleAdmissionBroker::prepareAdmission(
    std::uint32_t requestedPermissions) noexcept
{
    if (state_ != MacConsoleAdmissionState::Ready)
        return MacConsoleAdmissionPrepareResult::InvalidState;
    if (requestedPermissions == 0U ||
        (requestedPermissions & kConsoleViewPermission) == 0U ||
        (requestedPermissions & ~kNativeDesktopAuthorizationPermissions) != 0U)
    {
        revoke(MacConsoleAdmissionRevocationReason::Explicit);
        return MacConsoleAdmissionPrepareResult::InvalidPermissions;
    }
    if (authenticatedSession_ == nullptr ||
        authenticatedSession_->authenticationKind() !=
            NativeDesktopAuthenticationKind::StandalonePassword ||
        authenticatedSession_->authenticationGeneration() == 0U ||
        authenticatedSession_->configuredCredentialGeneration() == 0U ||
        !authenticatedSession_->revalidatesAuthenticatedSession())
    {
        revoke(MacConsoleAdmissionRevocationReason::AuthenticationLost);
        return MacConsoleAdmissionPrepareResult::AuthenticationUnavailable;
    }
    if (connection_ == nullptr ||
        !authenticatedSession_->revalidatesOwnedR1Connection(*connection_))
    {
        revoke(MacConsoleAdmissionRevocationReason::ConnectionExpired);
        return MacConsoleAdmissionPrepareResult::ConnectionMismatch;
    }

    const std::uint64_t authenticationGeneration =
        authenticatedSession_->authenticationGeneration();
    const std::uint64_t credentialGeneration =
        authenticatedSession_->configuredCredentialGeneration();
    const NativeDesktopAuthorizationBindResult bindResult =
        nativeAuthorization_.bindAuthenticatedSession(requestedPermissions);
    if (bindResult != NativeDesktopAuthorizationBindResult::Bound)
    {
        if (bindResult == NativeDesktopAuthorizationBindResult::GenerationExhausted)
        {
            revoke(MacConsoleAdmissionRevocationReason::NativeSessionChanged);
            return MacConsoleAdmissionPrepareResult::GenerationExhausted;
        }
        if (bindResult ==
                NativeDesktopAuthorizationBindResult::AuthenticatedIdentityUnavailable ||
            bindResult ==
                NativeDesktopAuthorizationBindResult::AuthenticatedIdentityMismatch)
        {
            revoke(MacConsoleAdmissionRevocationReason::AuthenticationLost);
            return MacConsoleAdmissionPrepareResult::AuthenticationUnavailable;
        }
        revoke(MacConsoleAdmissionRevocationReason::NativeSessionChanged);
        return bindResult == NativeDesktopAuthorizationBindResult::InvalidPermissions
            ? MacConsoleAdmissionPrepareResult::InvalidPermissions
            : MacConsoleAdmissionPrepareResult::NativeAuthorizationUnavailable;
    }

    const std::uint64_t authorizationGeneration =
        nativeAuthorization_.authorizationGeneration();
    PreparedLifetimeCapture capture{};
    if (authorizationGeneration == 0U ||
        !nativeAuthorization_.visit(
            authorizationGeneration, requestedPermissions,
            &capturePreparedLifetime, &capture) ||
        !capture.captured ||
        capture.authenticationKind !=
            NativeDesktopAuthenticationKind::StandalonePassword ||
        capture.authenticationGeneration != authenticationGeneration ||
        capture.authorizationGeneration != authorizationGeneration ||
        capture.permissionMask != requestedPermissions ||
        !authenticatedConnectionCurrent() ||
        authenticatedSession_->authenticationGeneration() !=
            authenticationGeneration ||
        authenticatedSession_->configuredCredentialGeneration() !=
            credentialGeneration)
    {
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::
                ProtectedCallbackLostAuthority);
        return MacConsoleAdmissionPrepareResult::AuthorizationChanged;
    }
    if (nextAdmissionGeneration_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        revoke(MacConsoleAdmissionRevocationReason::Explicit);
        return MacConsoleAdmissionPrepareResult::GenerationExhausted;
    }

    prepared_.authenticationKind = capture.authenticationKind;
    prepared_.ownerAuthorizationEpoch = capture.ownerAuthorizationEpoch;
    prepared_.permissionMask = capture.permissionMask;
    prepared_.nativeConsoleUserId = capture.nativeConsoleUserId;
    prepared_.auditUserId = capture.auditUserId;
    prepared_.auditSessionId = capture.auditSessionId;
    prepared_.securitySessionId = capture.securitySessionId;
    prepared_.securitySessionAttributes = capture.securitySessionAttributes;
    prepared_.authenticationGeneration = capture.authenticationGeneration;
    prepared_.credentialGeneration = credentialGeneration;
    prepared_.authorizationGeneration = capture.authorizationGeneration;
    admissionGeneration_ = ++nextAdmissionGeneration_;
    state_ = MacConsoleAdmissionState::Prepared;
    revocationReason_ = MacConsoleAdmissionRevocationReason::None;
    return MacConsoleAdmissionPrepareResult::Prepared;
}

bool MacConsoleAdmissionBroker::viewMatchesPreparedLifetime(
    const MacNativeDesktopAuthorizationView &authorization) const noexcept
{
    return state_ == MacConsoleAdmissionState::Prepared &&
           authorization.authenticationKind() == prepared_.authenticationKind &&
           authorization.permissionMask() == prepared_.permissionMask &&
           authorization.authenticationGeneration() ==
               prepared_.authenticationGeneration &&
           authorization.authorizationGeneration() ==
               prepared_.authorizationGeneration &&
           authorization.ownerAuthorizationEpoch() ==
               prepared_.ownerAuthorizationEpoch &&
           authorization.nativeConsoleUserId() ==
               prepared_.nativeConsoleUserId &&
           authorization.auditUserId() == prepared_.auditUserId &&
           authorization.auditSessionId() == prepared_.auditSessionId &&
           authorization.securitySessionId() == prepared_.securitySessionId &&
           authorization.securitySessionAttributes() ==
               prepared_.securitySessionAttributes;
}

bool MacConsoleAdmissionBroker::revalidate(
    std::uint32_t requiredPermissions) noexcept
{
    return visitNativeAuthorization(
        requiredPermissions, &acceptPreparedLifetime, nullptr);
}

bool MacConsoleAdmissionBroker::visitNativeAuthorization(
    std::uint32_t requiredPermissions,
    MacNativeDesktopAuthorizationVisitor visitor,
    void *context) noexcept
{
    if (visitInProgress_)
        return false;
    if (state_ != MacConsoleAdmissionState::Prepared ||
        visitor == nullptr ||
        !validRequiredPermissions(requiredPermissions))
        return false;
    if (!preparedAuthenticationCurrent())
    {
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::AuthenticationLost);
        return false;
    }

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

    struct CheckedVisitorContext final
    {
        MacConsoleAdmissionBroker *broker{};
        MacNativeDesktopAuthorizationVisitor visitor{};
        void *context{};
        bool entered{};
    } checked{this, visitor, context};

    const auto checkedVisitor = +[](
        const MacNativeDesktopAuthorizationView &authorization,
        void *opaque) noexcept -> bool {
        auto *const current = static_cast<CheckedVisitorContext *>(opaque);
        if (current == nullptr || current->broker == nullptr ||
            current->visitor == nullptr ||
            !current->broker->viewMatchesPreparedLifetime(authorization) ||
            !current->broker->preparedAuthenticationCurrent())
            return false;
        current->entered = true;
        if (!current->visitor(authorization, current->context))
            return false;
        return current->broker->viewMatchesPreparedLifetime(authorization) &&
               current->broker->preparedAuthenticationCurrent();
    };

    const bool authorized = nativeAuthorization_.visit(
        prepared_.authorizationGeneration, requiredPermissions,
        checkedVisitor, &checked);
    if (!authorized || !checked.entered ||
        !preparedAuthenticationCurrent())
    {
        if (state_ != MacConsoleAdmissionState::Revoked)
            revokeForAuthorityLoss(
                MacConsoleAdmissionRevocationReason::
                    ProtectedCallbackLostAuthority);
        return false;
    }
    return true;
}

void MacConsoleAdmissionBroker::revokeForAuthorityLoss(
    MacConsoleAdmissionRevocationReason reason) noexcept
{
    revoke(
        reason == MacConsoleAdmissionRevocationReason::None
            ? MacConsoleAdmissionRevocationReason::
                  ProtectedCallbackLostAuthority
            : reason);
}

void MacConsoleAdmissionBroker::revoke(
    MacConsoleAdmissionRevocationReason reason) noexcept
{
    if (state_ == MacConsoleAdmissionState::Revoked)
        return;
    nativeAuthorization_.revoke();
    prepared_ = {};
    admissionGeneration_ = 0U;
    state_ = MacConsoleAdmissionState::Revoked;
    revocationReason_ =
        reason == MacConsoleAdmissionRevocationReason::None
            ? MacConsoleAdmissionRevocationReason::Explicit
            : reason;
}

} // namespace rdp_server::server::security
