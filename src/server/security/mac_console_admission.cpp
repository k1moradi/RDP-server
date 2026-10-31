// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_console_admission.h"
#include "runtime/runtime_deployment_policy.h"
#include "transport/nonblocking_tcp_adapter.h"

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

bool MacConsoleAdmissionBroker::onOwnerThread() const noexcept
{
    return std::this_thread::get_id() == ownerThread_;
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
    return (state_ == MacConsoleAdmissionState::Prepared ||
            state_ == MacConsoleAdmissionState::TransportAdmitted ||
            state_ == MacConsoleAdmissionState::Admitted) &&
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
    if (!onOwnerThread())
        return MacConsoleAdmissionPrepareResult::InvalidState;
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
    return (state_ == MacConsoleAdmissionState::Prepared ||
            state_ == MacConsoleAdmissionState::TransportAdmitted ||
            state_ == MacConsoleAdmissionState::Admitted) &&
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
    if (!onOwnerThread() || visitInProgress_)
        return false;
    if ((state_ != MacConsoleAdmissionState::Prepared &&
         state_ != MacConsoleAdmissionState::TransportAdmitted &&
         state_ != MacConsoleAdmissionState::Admitted) ||
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


bool MacConsoleAdmissionBroker::authorizeR1CredSspAdmission(
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    using namespace rdp_server::server::transport;
    if (!onOwnerThread())
        return false;
    if (state_ != MacConsoleAdmissionState::Prepared ||
        admissionAttempted_ || admittedSession_ != nullptr ||
        session.phase() != McsSessionPhase::AwaitVerifiedR2Admission)
    {
        session.close();
        revokeForAuthorityLoss(MacConsoleAdmissionRevocationReason::Explicit);
        return false;
    }

    // Enroll R3 before the partial R1 transition. After this point any
    // failure retires the exact R1 socket and R3 owner; no retry is possible.
    admittedSession_ = &session;
    admissionAttempted_ = true;
    struct CompletionContext final
    {
        MacConsoleAdmissionBroker *broker{};
        bool completed{};
    } completion{this};

    const auto complete = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<CompletionContext *>(context);
        auto &broker = *operation.broker;
        auto &connection = *broker.connection_;
        if (!broker.preparedAuthenticationCurrent() ||
            !connection.active() ||
            connection.stage() != PreauthStage::AwaitCredSsp ||
            connection.establishedTls() == nullptr ||
            !connection.securityNegotiationProvenance())
            return false;

        // The sole R1 owner verifies HYBRID/TLS/BIO, selected certificate
        // and absence of an unfinished SSL read/write. This is transport
        // linearization only, not a right to consume first-MCS bytes.
        operation.completed = connection.completeCredSspAdmission();
        return operation.completed &&
               broker.preparedAuthenticationCurrent();
    };

    if (!visitNativeAuthorization(kConsoleViewPermission, complete, &completion) ||
        !completion.completed ||
        state_ != MacConsoleAdmissionState::Prepared ||
        session.phase() != McsSessionPhase::AwaitVerifiedR2Admission ||
        !preparedAuthenticationCurrent() ||
        !connection_->active() ||
        connection_->stage() != PreauthStage::AwaitMcsConnectInitial)
    {
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::ProtectedCallbackLostAuthority);
        return false;
    }

    // R10 may now borrow first-MCS bytes from the same R1 TLS reader, only
    // after a fresh R2 revalidate() before each read. R3 remains unbound.
    state_ = MacConsoleAdmissionState::TransportAdmitted;
    return true;
}

rdp_server::server::transport::McsSessionIntake
MacConsoleAdmissionBroker::authorizeR3McsConnectInitial(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    if (!onOwnerThread())
        return McsSessionIntake::AdmissionDenied;
    if (state_ != MacConsoleAdmissionState::TransportAdmitted ||
        !admissionAttempted_ || admittedSession_ != &session ||
        session.phase() != McsSessionPhase::AwaitVerifiedR2Admission)
    {
        session.close();
        revokeForAuthorityLoss(MacConsoleAdmissionRevocationReason::Explicit);
        return McsSessionIntake::AdmissionDenied;
    }

    struct InitialContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        McsSessionIntake outcome{McsSessionIntake::AdmissionDenied};
    } initial{this, &session, completeTpkt};

    const auto issue = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<InitialContext *>(context);
        auto &broker = *operation.broker;
        auto &connection = *broker.connection_;
        if (!broker.preparedAuthenticationCurrent() ||
            !connection.active() ||
            connection.stage() != PreauthStage::AwaitMcsConnectInitial ||
            connection.establishedTls() == nullptr ||
            !connection.securityNegotiationProvenance())
            return false;

        // Bind exactly the original R2 native generation pair, once, inside
        // a fresh authorization visit. No caller can supply those scalars.
        operation.outcome = operation.session->onVerifiedR2ConnectInitial(
            broker.admissionGeneration_,
            broker.prepared_.authorizationGeneration,
            operation.completeTpkt);
        return operation.outcome == McsSessionIntake::AdmittedConnectInitial;
    };

    if (!visitNativeAuthorization(kConsoleViewPermission, issue, &initial) ||
        state_ != MacConsoleAdmissionState::TransportAdmitted ||
        session.phase() != McsSessionPhase::AwaitConnectResponse ||
        !preparedAuthenticationCurrent() ||
        !connection_->active() ||
        connection_->stage() != PreauthStage::AwaitMcsConnectInitial)
    {
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::ProtectedCallbackLostAuthority);
        return initial.outcome == McsSessionIntake::AdmittedConnectInitial
            ? McsSessionIntake::AdmissionDenied
            : initial.outcome;
    }

    state_ = MacConsoleAdmissionState::Admitted;
    return McsSessionIntake::AdmittedConnectInitial;
}

bool MacConsoleAdmissionBroker::visitR3ProtectedOperation(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint32_t requiredPermissions,
    MacNativeDesktopAuthorizationVisitor visitor,
    void *context) noexcept
{
    using namespace rdp_server::server::transport;
    if (!onOwnerThread())
        return false;
    if (state_ != MacConsoleAdmissionState::Admitted ||
        admittedSession_ != &session || visitor == nullptr)
    {
        session.close();
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::ProtectedCallbackLostAuthority);
        return false;
    }

    // R3's public scalar check can revoke only. Never use a numeric
    // generation to reconstruct or replace a real protected R2 visit.
    session.revokeUnlessAdmissionBindingMatches(
        admissionGeneration_, prepared_.authorizationGeneration);
    if (session.phase() == McsSessionPhase::Closed ||
        !preparedAuthenticationCurrent() ||
        connection_ == nullptr || !connection_->active() ||
        connection_->stage() != PreauthStage::AwaitMcsConnectInitial ||
        connection_->establishedTls() == nullptr ||
        !connection_->securityNegotiationProvenance() ||
        !visitNativeAuthorization(requiredPermissions, visitor, context) ||
        state_ != MacConsoleAdmissionState::Admitted ||
        session.phase() == McsSessionPhase::Closed ||
        !preparedAuthenticationCurrent())
    {
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::ProtectedCallbackLostAuthority);
        return false;
    }
    return true;
}

bool MacConsoleAdmissionBroker::authorizeR3ProtectedTransition(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint32_t requiredPermissions) noexcept
{
    return visitR3ProtectedOperation(
        session, requiredPermissions, &acceptPreparedLifetime, nullptr);
}

std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
MacConsoleAdmissionBroker::authorizeR3ConnectResponseWrite(
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    using namespace rdp_server::server::transport;
    struct ReplyContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<McsConnectResponseWriteView> pending{};
    } reply{this, &session};

    const auto prepare = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<ReplyContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.pending =
            operation.session->prepareConnectResponseWrite(*provenance);
        return operation.pending.has_value();
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, prepare, &reply))
        return std::nullopt;
    return reply.pending;
}

rdp_server::server::transport::McsConnectResponseWriteOutcome
MacConsoleAdmissionBroker::completeR3ConnectResponseWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence, std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct CompletionContext final
    {
        McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        McsConnectResponseWriteOutcome outcome{
            McsConnectResponseWriteOutcome::Rejected};
    } completion{&session, replySequence, writeSliceSequence, acceptedBytes};

    const auto complete = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<CompletionContext *>(context);
        operation.outcome = operation.session->completeConnectResponseWrite(
            operation.replySequence, operation.writeSliceSequence,
            operation.acceptedBytes);
        return operation.outcome != McsConnectResponseWriteOutcome::Rejected;
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, complete, &completion))
        return McsConnectResponseWriteOutcome::Rejected;
    return completion.outcome;
}

rdp_server::server::transport::McsSessionIntake
MacConsoleAdmissionBroker::authorizeR3ErectDomain(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct ErectContext final
    {
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        McsSessionIntake outcome{McsSessionIntake::AdmissionDenied};
    } erect{&session, completeTpkt};

    const auto accept = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<ErectContext *>(context);
        operation.outcome =
            operation.session->onVerifiedR2ErectDomain(operation.completeTpkt);
        return operation.outcome == McsSessionIntake::ErectDomainAccepted;
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, accept, &erect))
        return erect.outcome == McsSessionIntake::ErectDomainAccepted
            ? McsSessionIntake::AdmissionDenied
            : erect.outcome;
    return McsSessionIntake::ErectDomainAccepted;
}

rdp_server::server::transport::McsSessionIntake
MacConsoleAdmissionBroker::authorizeR3AttachUser(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        McsSessionIntake outcome{McsSessionIntake::AdmissionDenied};
    } operation{this, &session, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->onVerifiedR2AttachUser(
            *provenance, operation.completeTpkt);
        return operation.outcome == McsSessionIntake::AttachUserAccepted;
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return McsSessionIntake::AdmissionDenied;
    return operation.outcome;
}

std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
MacConsoleAdmissionBroker::authorizeR3AttachUserConfirmWrite(
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<McsConnectResponseWriteView> outcome{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->prepareAttachUserConfirmWrite(
            *provenance);
        return operation.outcome.has_value();
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return std::nullopt;
    return operation.outcome;
}

rdp_server::server::transport::McsConnectResponseWriteOutcome
MacConsoleAdmissionBroker::completeR3AttachUserConfirmWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence, std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        McsConnectResponseWriteOutcome outcome{McsConnectResponseWriteOutcome::Rejected};
    } operation{this, &session, replySequence, writeSliceSequence, acceptedBytes};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->completeAttachUserConfirmWrite(
            *provenance, operation.replySequence,
            operation.writeSliceSequence, operation.acceptedBytes);
        return operation.outcome != McsConnectResponseWriteOutcome::Rejected;
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return McsConnectResponseWriteOutcome::Rejected;
    return operation.outcome;
}

rdp_server::server::transport::McsJoinStartOutcome
MacConsoleAdmissionBroker::authorizeR3ChannelJoin(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        McsJoinStartOutcome outcome{McsJoinStartOutcome::Rejected};
    } operation{this, &session, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->onVerifiedR2ChannelJoin(
            *provenance, operation.completeTpkt);
        return operation.outcome != McsJoinStartOutcome::Rejected;
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return McsJoinStartOutcome::Rejected;
    return operation.outcome;
}

std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
MacConsoleAdmissionBroker::authorizeR3ChannelJoinConfirmWrite(
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<McsConnectResponseWriteView> outcome{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->prepareChannelJoinConfirmWrite(
            *provenance);
        return operation.outcome.has_value();
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return std::nullopt;
    return operation.outcome;
}

rdp_server::server::transport::McsJoinWriteOutcome
MacConsoleAdmissionBroker::completeR3ChannelJoinConfirmWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence, std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        McsJoinWriteOutcome outcome{McsJoinWriteOutcome::Rejected};
    } operation{this, &session, replySequence, writeSliceSequence, acceptedBytes};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->completeChannelJoinConfirmWrite(
            *provenance, operation.replySequence,
            operation.writeSliceSequence, operation.acceptedBytes);
        return operation.outcome != McsJoinWriteOutcome::Rejected;
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return McsJoinWriteOutcome::Rejected;
    return operation.outcome;
}

std::optional<rdp_server::server::transport::RdpClientInfoPacketSummary>
MacConsoleAdmissionBroker::authorizeR3ClientInfoPacket(
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        std::optional<RdpClientInfoPacketSummary> outcome{std::nullopt};
    } operation{this, &session, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->acceptVerifiedR2ClientInfoPacket(
            *provenance, operation.completeTpkt);
        return operation.outcome.has_value();
    };

    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, invoke, &operation))
        return std::nullopt;
    return operation.outcome;
}

bool MacConsoleAdmissionBroker::personalDesktopPolicyMatches(
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) const noexcept
{
    return personalDesktopPolicy_ == &deploymentPolicy &&
           deploymentPolicy.usesPersonalTerminalServerLicensingFlow() &&
           deploymentPolicy.requiresNativeSessionRevocation() &&
           deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() ==
               1U;
}

bool MacConsoleAdmissionBroker::visitPersonalDesktopR3Operation(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    MacNativeDesktopAuthorizationVisitor visitor,
    void *context,
    std::uint32_t requiredPermissions) noexcept
{
    if (!onOwnerThread())
        return false;
    if (!personalDesktopPolicyMatches(deploymentPolicy) ||
        !visitR3ProtectedOperation(
            session, requiredPermissions, visitor, context) ||
        !personalDesktopPolicyMatches(deploymentPolicy))
    {
        session.close();
        revokeForAuthorityLoss(
            MacConsoleAdmissionRevocationReason::ProtectedCallbackLostAuthority);
        return false;
    }
    return true;
}

bool MacConsoleAdmissionBroker::authorizeR3PersonalDesktopLicensingMode(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!onOwnerThread())
        return false;
    if (personalDesktopPolicy_ != nullptr ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U)
    {
        session.close();
        revokeForAuthorityLoss(MacConsoleAdmissionRevocationReason::Explicit);
        return false;
    }

    const auto select = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &session = *static_cast<
            rdp_server::server::transport::McsSessionLifecycle *>(context);
        return session.selectVerifiedR2PersonalDesktopLicensingMode();
    };
    if (!visitR3ProtectedOperation(
            session, kConsoleViewPermission, select, &session))
        return false;

    personalDesktopPolicy_ = &deploymentPolicy;
    return true;
}


std::optional<rdp_server::server::transport::RdpServerLicenseRequestWriteView>
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopServerLicenseRequestWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    const rdp_server::server::transport::RdpServerLicenseIdentity &identity,
    const rdp_server::server::transport::RdpLicensingServiceCredential &credential) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        rdp_server::server::transport::McsSessionLifecycle *session{};
        const RdpServerLicenseIdentity *identity{};
        const RdpLicensingServiceCredential *credential{};
        std::optional<RdpServerLicenseRequestWriteView> outcome{};
    } operation{this, &session, &identity, &credential};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->prepareServerLicenseRequestWrite(
            *provenance, *operation.identity, *operation.credential);
        return operation.outcome.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return std::nullopt;
    return operation.outcome;
}

rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome
MacConsoleAdmissionBroker::completeR3PersonalDesktopServerLicenseRequestWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        rdp_server::server::transport::McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        RdpServerLicenseRequestWriteOutcome outcome{RdpServerLicenseRequestWriteOutcome::Rejected};
    } operation{this, &session, replySequence, writeSliceSequence, acceptedBytes};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->completeServerLicenseRequestWrite(
            *provenance, operation.replySequence,
            operation.writeSliceSequence, operation.acceptedBytes);
        return operation.outcome != RdpServerLicenseRequestWriteOutcome::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpServerLicenseRequestWriteOutcome::Rejected;
    return operation.outcome;
}

std::optional<rdp_server::server::transport::RdpLicensingIntake>
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopClientLicensingMessage(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    const rdp_server::server::transport::RdpLicensingServiceCredential &credential,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        rdp_server::server::transport::McsSessionLifecycle *session{};
        const RdpLicensingServiceCredential *credential{};
        std::span<const std::uint8_t> completeTpkt{};
        std::optional<RdpLicensingIntake> outcome{};
    } operation{this, &session, &credential, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->acceptVerifiedR2ClientLicensingMessage(
            *provenance, *operation.credential,
            operation.completeTpkt);
        return operation.outcome.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return std::nullopt;
    return operation.outcome;
}

std::optional<rdp_server::server::transport::RdpPersonalDesktopValidClientWriteView>
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopValidClientWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        rdp_server::server::transport::McsSessionLifecycle *session{};
        std::optional<RdpPersonalDesktopValidClientWriteView> outcome{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->preparePersonalDesktopValidClientWrite(
            *provenance);
        return operation.outcome.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return std::nullopt;
    return operation.outcome;
}

rdp_server::server::transport::RdpPersonalDesktopValidClientWriteOutcome
MacConsoleAdmissionBroker::completeR3PersonalDesktopValidClientWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        rdp_server::server::transport::McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        RdpPersonalDesktopValidClientWriteOutcome outcome{RdpPersonalDesktopValidClientWriteOutcome::Rejected};
    } operation{this, &session, replySequence, writeSliceSequence, acceptedBytes};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->completePersonalDesktopValidClientWrite(
            *provenance, operation.replySequence,
            operation.writeSliceSequence, operation.acceptedBytes);
        return operation.outcome != RdpPersonalDesktopValidClientWriteOutcome::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpPersonalDesktopValidClientWriteOutcome::Rejected;
    return operation.outcome;
}

std::optional<rdp_server::server::transport::RdpDemandActiveProfileView>
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopMacDemandActiveProfile(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    rdp_server::server::transport::RdpDemandActiveFeature features) noexcept
{
    using namespace rdp_server::server::transport;
    struct ProfileContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        RdpDemandActiveFeature features{};
        std::optional<RdpDemandActiveProfileView> profile{};
    } operation{this, &session, features};

    const auto prepare = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<ProfileContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.profile =
            operation.session->prepareVerifiedR2MacDemandActiveProfile(
                *provenance, operation.features);
        return operation.profile.has_value();
    };

    std::uint32_t requiredPermissions = kConsoleViewPermission;
    if (hasRdpDemandActiveFeature(
            features, RdpDemandActiveFeature::SlowPathInput))
        requiredPermissions |= kConsoleInputPermission;
    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, prepare, &operation, requiredPermissions))
        return std::nullopt;
    return operation.profile;
}

std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopShareActivation(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    const rdp_server::server::transport::RdpDemandActiveProfileView &profile) noexcept
{
    using namespace rdp_server::server::transport;
    struct BeginContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        const RdpDemandActiveProfileView *profile{};
        std::optional<RdpShareActivationWriteView> pending{};
    } operation{this, &session, &profile};

    const auto begin = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<BeginContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.pending = operation.session->beginVerifiedR2ShareActivation(
            *provenance, *operation.profile);
        return operation.pending.has_value();
    };

    std::uint32_t requiredPermissions = kConsoleViewPermission;
    if (hasRdpDemandActiveFeature(
            profile.features(), RdpDemandActiveFeature::SlowPathInput))
        requiredPermissions |= kConsoleInputPermission;
    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, begin, &operation, requiredPermissions))
        return std::nullopt;
    return operation.pending;
}

std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopShareActivationWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct WriteContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<RdpShareActivationWriteView> pending{};
    } operation{this, &session};

    const auto prepare = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<WriteContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.pending =
            operation.session->pendingVerifiedR2ShareActivationWrite(*provenance);
        return operation.pending.has_value();
    };
    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, prepare, &operation))
        return std::nullopt;
    return operation.pending;
}

rdp_server::server::transport::RdpShareActivationWriteOutcome
MacConsoleAdmissionBroker::completeR3PersonalDesktopShareActivationWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct ReceiptContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        RdpShareActivationWriteOutcome outcome{
            RdpShareActivationWriteOutcome::Rejected};
    } operation{this, &session, replySequence, writeSliceSequence, acceptedBytes};

    const auto complete = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<ReceiptContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome =
            operation.session->completeVerifiedR2ShareActivationWrite(
                *provenance, operation.replySequence,
                operation.writeSliceSequence, operation.acceptedBytes);
        return operation.outcome != RdpShareActivationWriteOutcome::Rejected;
    };
    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, complete, &operation))
        return RdpShareActivationWriteOutcome::Rejected;
    return operation.outcome;
}

rdp_server::server::transport::RdpShareActivationClientIntake
MacConsoleAdmissionBroker::authorizeR3PersonalDesktopShareActivationPdu(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct IntakeContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        RdpShareActivationClientIntake outcome{
            RdpShareActivationClientIntake::Rejected};
    } operation{this, &session, completeTpkt};

    const auto accept = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<IntakeContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.outcome = operation.session->acceptVerifiedR2ShareActivationPdu(
            *provenance, operation.completeTpkt);
        return operation.outcome != RdpShareActivationClientIntake::Rejected &&
               operation.outcome != RdpShareActivationClientIntake::Closed;
    };
    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, accept, &operation))
        return RdpShareActivationClientIntake::Rejected;
    return operation.outcome;
}

bool
MacConsoleAdmissionBroker::authorizeR3ApplicationTrafficReady(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        bool result{false};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->verifiedR2ApplicationTrafficReady(
            *provenance);
        return operation.result;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleViewPermission))
        return false;
    return operation.result;
}

rdp_server::server::transport::RdpPostShareTpktRoute
MacConsoleAdmissionBroker::classifyR3PostShareTpkt(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        RdpPostShareTpktRoute result{RdpPostShareTpktRoute{}};
    } operation{this, &session, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->classifyVerifiedR2PostShareTpkt(
            *provenance, operation.completeTpkt);
        return operation.result.kind != RdpPostShareTpktRouteKind::UnsupportedOrMalformed;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleViewPermission))
        return RdpPostShareTpktRoute{};
    return operation.result;
}

std::optional<rdp_server::server::transport::RdpClipboardStaticChannelView>
MacConsoleAdmissionBroker::authorizeR3ActivatedClipboardChannel(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<RdpClipboardStaticChannelView> result{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->resolveVerifiedR2ActivatedClipboardChannel(
            *provenance);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleClipboardPermission))
        return std::nullopt;
    return operation.result;
}

rdp_server::server::transport::RdpClipboardChunkIntake
MacConsoleAdmissionBroker::authorizeR3ClipboardTpkt(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt,
    std::span<const std::uint8_t> &completePdu) noexcept
{
    using namespace rdp_server::server::transport;
    completePdu = {};
    struct IntakeContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        std::span<const std::uint8_t> completePdu{};
        RdpClipboardChunkIntake result{RdpClipboardChunkIntake::Rejected};
    } operation{this, &session, completeTpkt};

    const auto accept = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<IntakeContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->acceptVerifiedR2ClipboardTpkt(
            *provenance, operation.completeTpkt, operation.completePdu);
        return operation.result != RdpClipboardChunkIntake::Rejected;
    };
    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, accept, &operation,
            kConsoleClipboardPermission))
        return RdpClipboardChunkIntake::Rejected;
    // R3-owned completed PDU can only be borrowed on a Complete intake.
    completePdu = operation.result == RdpClipboardChunkIntake::Complete
        ? operation.completePdu
        : std::span<const std::uint8_t>{};
    return operation.result;
}


std::optional<rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
MacConsoleAdmissionBroker::queueR3ClipboardPdu(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completePdu{};
        std::optional<RdpClipboardStaticChannelWriteView> result{};
    } operation{this, &session, completePdu};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->queueVerifiedR2ClipboardPdu(
            *provenance, operation.completePdu);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleClipboardPermission))
        return std::nullopt;
    return operation.result;
}

std::optional<rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
MacConsoleAdmissionBroker::pendingR3ClipboardWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<RdpClipboardStaticChannelWriteView> result{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->pendingVerifiedR2ClipboardWrite(
            *provenance);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleClipboardPermission))
        return std::nullopt;
    return operation.result;
}

rdp_server::server::transport::RdpClipboardWriteOutcome
MacConsoleAdmissionBroker::completeR3ClipboardWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t generation, std::uint64_t replySequence,
    std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint64_t generation{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        RdpClipboardWriteOutcome result{RdpClipboardWriteOutcome::Rejected};
    } operation{this, &session, generation, replySequence, writeSliceSequence, acceptedBytes};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->completeVerifiedR2ClipboardWrite(
            *provenance, operation.generation,
            operation.replySequence, operation.writeSliceSequence,
            operation.acceptedBytes);
        return operation.result != RdpClipboardWriteOutcome::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleClipboardPermission))
        return RdpClipboardWriteOutcome::Rejected;
    return operation.result;
}

std::optional<rdp_server::server::transport::RdpSlowPathInputPdu>
MacConsoleAdmissionBroker::routeR3SlowPathInputPdu(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        std::optional<RdpSlowPathInputPdu> result{};
    } operation{this, &session, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->routeVerifiedR2SlowPathInputPdu(
            *provenance, operation.completeTpkt);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleInputPermission))
        return std::nullopt;
    return operation.result;
}

std::optional<std::uint16_t>
MacConsoleAdmissionBroker::authorizeR3ActivatedDynamicVirtualChannel(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<std::uint16_t> result{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->resolveVerifiedR2ActivatedDynamicVirtualChannel(
            *provenance);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation,
            kConsoleViewPermission))
        return std::nullopt;
    return operation.result;
}
std::optional<rdp_server::server::transport::RdpGraphicsDvcWriteView>
MacConsoleAdmissionBroker::authorizeR3GraphicsDynamicVirtualChannel(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<RdpGraphicsDvcWriteView> result{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->beginVerifiedR2GraphicsDynamicVirtualChannel(
            *provenance);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return std::nullopt;
    return operation.result;
}

std::optional<rdp_server::server::transport::RdpGraphicsDvcWriteView>
MacConsoleAdmissionBroker::pendingR3GraphicsDynamicVirtualChannelWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::optional<RdpGraphicsDvcWriteView> result{};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->pendingVerifiedR2GraphicsDynamicVirtualChannelWrite(
            *provenance);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return std::nullopt;
    return operation.result;
}

rdp_server::server::transport::RdpGraphicsDvcWriteOutcome
MacConsoleAdmissionBroker::completeR3GraphicsDynamicVirtualChannelWrite(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint64_t replySequence{};
        std::uint64_t writeSliceSequence{};
        std::size_t acceptedBytes{};
        RdpGraphicsDvcWriteOutcome result{RdpGraphicsDvcWriteOutcome::Rejected};
    } operation{this, &session, replySequence, writeSliceSequence, acceptedBytes};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->completeVerifiedR2GraphicsDynamicVirtualChannelWrite(
            *provenance, operation.replySequence,
            operation.writeSliceSequence, operation.acceptedBytes);
        return operation.result != RdpGraphicsDvcWriteOutcome::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpGraphicsDvcWriteOutcome::Rejected;
    return operation.result;
}

rdp_server::server::transport::RdpGraphicsDvcClientIntake
MacConsoleAdmissionBroker::authorizeR3GraphicsDynamicVirtualChannelPdu(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::span<const std::uint8_t> completeTpkt{};
        RdpGraphicsDvcClientIntake result{RdpGraphicsDvcClientIntake::Rejected};
    } operation{this, &session, completeTpkt};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->acceptVerifiedR2GraphicsDynamicVirtualChannelPdu(
            *provenance, operation.completeTpkt);
        return operation.result != RdpGraphicsDvcClientIntake::Rejected &&
               operation.result != RdpGraphicsDvcClientIntake::Closed;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpGraphicsDvcClientIntake::Rejected;
    return operation.result;
}

rdp_server::server::transport::RdpGraphicsFrameAcknowledgeIntake
MacConsoleAdmissionBroker::consumeR3GraphicsFrameAcknowledge(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        RdpGraphicsFrameAcknowledgeIntake result{RdpGraphicsFrameAcknowledgeIntake::Rejected};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->consumeVerifiedR2GraphicsFrameAcknowledge(
            *provenance);
        return operation.result != RdpGraphicsFrameAcknowledgeIntake::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpGraphicsFrameAcknowledgeIntake::Rejected;
    return operation.result;
}

rdp_server::server::transport::RdpGraphicsFramePublicationReadiness
MacConsoleAdmissionBroker::preflightR3GraphicsFramePublication(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint32_t frameId) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint32_t frameId{};
        RdpGraphicsFramePublicationReadiness result{RdpGraphicsFramePublicationReadiness::Rejected};
    } operation{this, &session, frameId};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->preflightVerifiedR2GraphicsFramePublication(
            *provenance, operation.frameId);
        return operation.result != RdpGraphicsFramePublicationReadiness::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpGraphicsFramePublicationReadiness::Rejected;
    return operation.result;
}

rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration
MacConsoleAdmissionBroker::beginR3GraphicsSurfaceReconfiguration(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    ::PixelSize desktopGeometry) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        ::PixelSize desktopGeometry{};
        RdpGraphicsSurfaceReconfiguration result{RdpGraphicsSurfaceReconfiguration::Rejected};
    } operation{this, &session, desktopGeometry};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->beginVerifiedR2GraphicsSurfaceReconfiguration(
            *provenance, operation.desktopGeometry);
        return operation.result != RdpGraphicsSurfaceReconfiguration::Rejected;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return RdpGraphicsSurfaceReconfiguration::Rejected;
    return operation.result;
}

std::optional<rdp_server::server::transport::RdpGraphicsDvcWriteView>
MacConsoleAdmissionBroker::beginR3GraphicsClearCodecFramePublication(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint32_t frameId,
    ::FramebufferView framebuffer) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        std::uint32_t frameId{};
        ::FramebufferView framebuffer{};
        std::optional<RdpGraphicsDvcWriteView> result{};
    } operation{this, &session, frameId, framebuffer};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->beginVerifiedR2GraphicsClearCodecFramePublication(
            *provenance, operation.frameId, operation.framebuffer);
        return operation.result.has_value();
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return std::nullopt;
    return operation.result;
}

bool
MacConsoleAdmissionBroker::cancelR3UnwrittenGraphicsFrame(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        bool result{false};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->cancelVerifiedR2UnwrittenGraphicsFrame(
            *provenance);
        return operation.result;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return false;
    return operation.result;
}

bool
MacConsoleAdmissionBroker::abortR3GraphicsFrame(
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using namespace rdp_server::server::transport;
    struct OperationContext final
    {
        MacConsoleAdmissionBroker *broker{};
        McsSessionLifecycle *session{};
        bool result{false};
    } operation{this, &session};

    const auto invoke = +[](
        const MacNativeDesktopAuthorizationView & /* authorization */,
        void *context) noexcept -> bool {
        auto &operation = *static_cast<OperationContext *>(context);
        const auto provenance =
            operation.broker->connection_->securityNegotiationProvenance();
        if (!provenance)
            return false;
        operation.result = operation.session->abortVerifiedR2GraphicsFrame(
            *provenance);
        return operation.result;
    };

    if (!visitPersonalDesktopR3Operation(
            session, deploymentPolicy, invoke, &operation))
        return false;
    return operation.result;
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
    // R3 first, then native lease and R1 SSL/BIO/socket. No retained receipt
    // may advance the retired generation after a callback revocation.
    if (admittedSession_ != nullptr)
    {
        admittedSession_->close();
        admittedSession_ = nullptr;
    }
    nativeAuthorization_.revoke();
    personalDesktopPolicy_ = nullptr;
    if (admissionAttempted_ && connection_ != nullptr)
        connection_->cancel();
    admissionAttempted_ = false;
    prepared_ = {};
    admissionGeneration_ = 0U;
    state_ = MacConsoleAdmissionState::Revoked;
    revocationReason_ =
        reason == MacConsoleAdmissionRevocationReason::None
            ? MacConsoleAdmissionRevocationReason::Explicit
            : reason;
}

} // namespace rdp_server::server::security
