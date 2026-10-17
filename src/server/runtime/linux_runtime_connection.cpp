// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_connection.h"

#include <algorithm>
#include <array>
#include <utility>

namespace rdp_server::server::runtime
{

LinuxRuntimeConnection::LinuxRuntimeConnection(
    LinuxRuntimeSecurityConfiguration &securityConfiguration,
    rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket)
    noexcept
    : securityConfiguration_(securityConfiguration),
      connection_(
          std::move(acceptedSocket),
          rdp_server::server::transport::SecurityNegotiationPolicy::HybridNla)
{
    const auto *const policy = securityConfiguration_.policy();
    if (!connection_.active() || policy == nullptr ||
        !securityConfiguration_.configureAcceptor(acceptor_))
    {
        session_.close();
        acceptor_.reject();
        connection_.cancel();
        return;
    }

    broker_.emplace(*policy);
    provisioned_ = true;
}

LinuxRuntimeConnection::~LinuxRuntimeConnection()
{
    revoke();
}

bool LinuxRuntimeConnection::ready() const noexcept
{
    if (!provisioned_ || !connection_.active())
    {
        return false;
    }
    if (credSspReplyPending())
    {
        return true;
    }
    return broker_.has_value() &&
           acceptor_.stage() !=
               rdp_server::server::security::SpnegoStage::Failed &&
           session_.phase() !=
               rdp_server::server::transport::McsSessionPhase::Closed;
}

bool LinuxRuntimeConnection::credSspReplyPending() const noexcept
{
    using rdp_server::server::security::TsRequestTlsWriteStatus;
    switch (credSspReplyWriter_.status())
    {
    case TsRequestTlsWriteStatus::Progress:
    case TsRequestTlsWriteStatus::NeedRead:
    case TsRequestTlsWriteStatus::NeedWrite:
    case TsRequestTlsWriteStatus::Complete:
        return true;
    case TsRequestTlsWriteStatus::Idle:
    case TsRequestTlsWriteStatus::Invalid:
    case TsRequestTlsWriteStatus::Closed:
        return false;
    }
    return false;
}

rdp_server::server::transport::TcpConnectionIoInterest
LinuxRuntimeConnection::ioInterest() const noexcept
{
    using rdp_server::server::security::TsRequestTlsWriteStatus;
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;

    if (!provisioned_ || !connection_.active())
    {
        return Interest::Closed;
    }
    switch (credSspReplyWriter_.status())
    {
    case TsRequestTlsWriteStatus::Progress:
    case TsRequestTlsWriteStatus::NeedWrite:
        return Interest::Write;
    case TsRequestTlsWriteStatus::NeedRead:
        return Interest::Read;
    case TsRequestTlsWriteStatus::Invalid:
    case TsRequestTlsWriteStatus::Closed:
        return Interest::Closed;
    case TsRequestTlsWriteStatus::Idle:
    case TsRequestTlsWriteStatus::Complete:
        break;
    }
    return ready() ? connection_.ioInterest() : Interest::Closed;
}

LinuxPreAdmissionStepResult LinuxRuntimeConnection::advancePreAdmission(
    bool readable, bool writable,
    const RuntimeServerTlsContext &tlsContext) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using Stage = rdp_server::server::transport::PreauthStage;
    using Step = LinuxPreAdmissionStepStatus;

    if (!ready())
    {
        return {0, 0, Step::Closed};
    }

    const auto required = ioInterest();
    if (required == Interest::Closed)
    {
        revoke();
        return {0, 0, Step::Closed};
    }

    // TLS configuration is not socket readiness. It is one explicit ownership
    // transfer after R1 proves the entire X.224 response has drained.
    if (required == Interest::ConfigureTls)
    {
        if (connection_.stage() != Stage::AwaitTls ||
            !attachServerTls(tlsContext))
        {
            return {0, 0, Step::Invalid};
        }
        return {0, 0, Step::Progress};
    }

    const bool bufferedTlsApplicationRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable &&
        !bufferedTlsApplicationRead)
    {
        return {0, 0, Step::NeedRead};
    }
    if (required == Interest::Write && !writable)
    {
        return {0, 0, Step::NeedWrite};
    }

    const auto stageBefore = connection_.stage();
    switch (stageBefore)
    {
    case Stage::AwaitConnectionRequest:
    case Stage::AwaitTls:
    {
        // R1 owns pending X.224 reply bytes and TLS network records. Its
        // bounded readiness dispatcher knows whether an AwaitTls write is
        // still the X.224 Confirm or an OpenSSL WANT_WRITE.
        const auto next = connection_.onSocketReady(readable, writable);
        if (!connection_.active() || next == Interest::Closed)
        {
            revoke();
            return {0, 0, Step::Closed};
        }

        if (next == Interest::ConfigureTls)
        {
            if (!attachServerTls(tlsContext))
            {
                return {0, 0, Step::Invalid};
            }
            return {0, 0, Step::Progress};
        }

        if (stageBefore == Stage::AwaitTls &&
            connection_.stage() == Stage::AwaitCredSsp)
        {
            return {0, 0, Step::TlsEstablished};
        }

        if (next == Interest::Read)
        {
            return {0, 0, Step::NeedRead};
        }
        if (next == Interest::Write)
        {
            return {0, 0, Step::NeedWrite};
        }

        revoke();
        return {0, 0, Step::Invalid};
    }

    case Stage::AwaitCredSsp:
    {
        const auto step = onCredSspIoReady();
        switch (step.status)
        {
        case LinuxCredSspStepStatus::Progress:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::Progress};
        case LinuxCredSspStepStatus::NeedRead:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::NeedRead};
        case LinuxCredSspStepStatus::NeedWrite:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::NeedWrite};
        case LinuxCredSspStepStatus::BindingVerified:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::BindingVerified};
        case LinuxCredSspStepStatus::CredentialsVerified:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::CredentialsVerified};
        case LinuxCredSspStepStatus::UnsupportedFinalCredentials:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::UnsupportedFinalCredentials};
        case LinuxCredSspStepStatus::Invalid:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::Invalid};
        case LinuxCredSspStepStatus::Closed:
            return {step.plaintextBytesRead, step.plaintextBytesWritten,
                    Step::Closed};
        }
        revoke();
        return {0, 0, Step::Invalid};
    }

    case Stage::AwaitMcsConnectInitial:
        // This API ends at the R2 admission boundary. Never fall through to
        // R1's legacy syntax-only MCS reader or create a second R3 path.
        revoke();
        return {0, 0, Step::Invalid};

    case Stage::Closed:
        revoke();
        return {0, 0, Step::Closed};
    }

    revoke();
    return {0, 0, Step::Invalid};
}

rdp_server::server::transport::TcpPreauthEvent
LinuxRuntimeConnection::onReadable() noexcept
{
    if (!ready())
    {
        return rdp_server::server::transport::TcpPreauthEvent::Closed;
    }

    const auto result = connection_.onReadable();
    if (result == rdp_server::server::transport::TcpPreauthEvent::Closed ||
        result == rdp_server::server::transport::TcpPreauthEvent::Invalid)
    {
        revoke();
    }
    return result;
}

rdp_server::server::transport::TcpPreauthEvent
LinuxRuntimeConnection::onWritable() noexcept
{
    if (!ready())
    {
        return rdp_server::server::transport::TcpPreauthEvent::Closed;
    }

    const auto result = connection_.onWritable();
    if (result == rdp_server::server::transport::TcpPreauthEvent::Closed ||
        result == rdp_server::server::transport::TcpPreauthEvent::Invalid)
    {
        revoke();
    }
    return result;
}

bool LinuxRuntimeConnection::attachServerTls(
    const RuntimeServerTlsContext &tlsContext) noexcept
{
    if (!ready())
    {
        return false;
    }

    auto serverTls = tlsContext.createServerTls();
    if (!serverTls ||
        !connection_.attachServerTls(std::move(serverTls)))
    {
        revoke();
        return false;
    }
    return true;
}

rdp_server::server::transport::TlsHandshakeStatus
LinuxRuntimeConnection::onTlsIoReady() noexcept
{
    if (!ready())
    {
        return rdp_server::server::transport::TlsHandshakeStatus::Closed;
    }

    const auto result = connection_.onTlsIoReady();
    if (result == rdp_server::server::transport::TlsHandshakeStatus::Invalid ||
        result == rdp_server::server::transport::TlsHandshakeStatus::Closed)
    {
        revoke();
    }
    return result;
}

LinuxCredSspStepResult LinuxRuntimeConnection::onCredSspIoReady() noexcept
{
    using HandshakeStatus =
        rdp_server::server::security::OwnedCredSspHandshakeStatus;

    if (!provisioned_ || !connection_.active())
    {
        return {0, 0, LinuxCredSspStepStatus::Closed};
    }

    const auto result = acceptor_.advanceOwnedCredSspHandshake(
        connection_, credSspFrameReader_, credSspReplyWriter_);
    switch (result.status)
    {
    case HandshakeStatus::Progress:
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::Progress};
    case HandshakeStatus::NeedRead:
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::NeedRead};
    case HandshakeStatus::NeedWrite:
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::NeedWrite};
    case HandshakeStatus::BindingVerified:
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::BindingVerified};
    case HandshakeStatus::CredentialsVerified:
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::CredentialsVerified};
    case HandshakeStatus::UnsupportedFinalCredentials:
        revoke();
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::UnsupportedFinalCredentials};
    case HandshakeStatus::Rejected:
        revoke();
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::Invalid};
    case HandshakeStatus::TransportClosed:
        revoke();
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::Closed};
    }
    revoke();
    return {0, 0, LinuxCredSspStepStatus::Invalid};
}

bool LinuxRuntimeConnection::issueAdmission(
    const rdp_server::server::security::ConsoleEvidenceRequest &request)
    noexcept
{
    if (!ready() || credSspReplyPending() || !broker_ || lease_ ||
        acceptor_.stage() !=
            rdp_server::server::security::SpnegoStage::ServerBindingPrepared)
    {
        revoke();
        return false;
    }

    auto issued = broker_->issue(acceptor_, connection_, request);
    if (!issued)
    {
        revoke();
        return false;
    }
    lease_.emplace(std::move(*issued));
    return true;
}

rdp_server::server::transport::McsSessionIntake
LinuxRuntimeConnection::authorizeMcsConnectInitial(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return rdp_server::server::transport::McsSessionIntake::
            AdmissionDenied;
    }

    const auto result = broker_->authorizeR3McsConnectInitial(
        *lease_, acceptor_, connection_, session_, completeTpkt);
    if (result !=
        rdp_server::server::transport::McsSessionIntake::
            AdmittedConnectInitial)
    {
        revoke();
    }
    return result;
}

int LinuxRuntimeConnection::nativeChangeFd() const noexcept
{
    return ready() && hasAdmissionLease() && broker_ &&
                   broker_->state() ==
                       rdp_server::server::security::LinuxConsoleAdmissionState::Active
               ? broker_->nativeChangeFd()
               : -1;
}

int LinuxRuntimeConnection::nativeChangeEvents() const noexcept
{
    return ready() && hasAdmissionLease() && broker_ &&
                   broker_->state() ==
                       rdp_server::server::security::LinuxConsoleAdmissionState::Active
               ? broker_->nativeChangeEvents()
               : -1;
}

bool LinuxRuntimeConnection::onNativeSessionChangeReady() noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return false;
    }

    const bool remainsAuthorized =
        broker_->onNativeSessionChangeReady(acceptor_, session_);
    if (!remainsAuthorized &&
        broker_->state() ==
            rdp_server::server::security::LinuxConsoleAdmissionState::Revoked)
    {
        revoke();
    }
    return remainsAuthorized;
}

bool LinuxRuntimeConnection::nativeChangeRegistrationMatches(
    const LinuxRuntimeNativeChangeRegistration &registration) const noexcept
{
    return nativeChangeRegistration_ &&
           registration.descriptor == nativeChangeRegistration_->descriptor &&
           registration.events == nativeChangeRegistration_->events &&
           registration.admissionGeneration ==
               nativeChangeRegistration_->admissionGeneration &&
           registration.sessionGeneration ==
               nativeChangeRegistration_->sessionGeneration;
}

std::optional<LinuxRuntimeNativeChangeRegistration>
LinuxRuntimeConnection::registerNativeChange() noexcept
{
    if (nativeChangeRegistration_ || !ready() || !broker_ || !lease_ ||
        lease_->isRevoked())
        return std::nullopt;

    LinuxRuntimeNativeChangeRegistration registration{
        nativeChangeFd(), nativeChangeEvents(),
        lease_->admissionGeneration(), lease_->sessionGeneration()};
    if (!registration)
        return std::nullopt;

    nativeChangeRegistration_ = registration;
    nativeChangeRegistrationUnregistered_ = false;
    return registration;
}

bool LinuxRuntimeConnection::unregisterNativeChange(
    const LinuxRuntimeNativeChangeRegistration &registration) noexcept
{
    if (nativeChangeRegistrationUnregistered_ ||
        !nativeChangeRegistrationMatches(registration))
        return false;

    // Caller has already removed this exact borrowed fd/generation record.
    nativeChangeRegistrationUnregistered_ = true;
    return true;
}

bool LinuxRuntimeConnection::dispatchNativeChangeReady(
    const LinuxRuntimeNativeChangeRegistration &registration) noexcept
{
    if (!nativeChangeRegistrationUnregistered_ ||
        !nativeChangeRegistrationMatches(registration))
        return false;

    const bool borrowStillMatches =
        ready() && lease_ && !lease_->isRevoked() &&
        nativeChangeFd() == registration.descriptor &&
        nativeChangeEvents() == registration.events &&
        lease_->admissionGeneration() == registration.admissionGeneration &&
        lease_->sessionGeneration() == registration.sessionGeneration;

    // Remove aggregate identity before R2 callback; R2 may revoke everything.
    nativeChangeRegistration_.reset();
    nativeChangeRegistrationUnregistered_ = false;
    if (!borrowStillMatches)
    {
        revoke();
        return false;
    }
    return onNativeSessionChangeReady();
}

bool LinuxRuntimeConnection::reauthorizeExistingCalValidation() noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        !broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        if (existingCalValidation_)
            existingCalValidation_->revoke();
        revoke();
        return false;
    }
    return true;
}

RuntimeLicensingExistingCalOperation
LinuxRuntimeConnection::beginExistingCalValidation(
    const RuntimeLicensingContext &licensingContext,
    RuntimeLicensingAuthority &authority) noexcept
{
    using Operation = RuntimeLicensingExistingCalOperation;
    if (existingCalValidation_)
        return Operation::Rejected;
    if (!reauthorizeExistingCalValidation())
        return Operation::Rejected;

    const auto *const identity = licensingContext.identity();
    if (identity == nullptr || !lease_)
    {
        revoke();
        return Operation::Rejected;
    }

    auto &binding = existingCalValidation_.emplace(authority);
    struct VisitContext
    {
        RuntimeExistingCalValidationBinding *binding{};
        const rdp_server::server::transport::RdpServerLicenseIdentity
            *identity{};
        std::uint64_t admissionGeneration{};
        std::uint64_t sessionGeneration{};
        Operation operation{Operation::Rejected};
        bool invoked{};
    } context{
        &binding, identity, lease_->admissionGeneration(),
        lease_->sessionGeneration(), Operation::Rejected, false};

    const bool visited = session_.visitExistingClientCalAuthorityRequest(
        [](const rdp_server::server::transport::
               RdpExistingClientCalAuthorityRequest &request,
           void *opaque) noexcept {
            auto *const visit = static_cast<VisitContext *>(opaque);
            visit->invoked = true;
            visit->operation = visit->binding->begin(
                request, *visit->identity, visit->admissionGeneration,
                visit->sessionGeneration);
        },
        &context);

    if (!visited || !context.invoked ||
        context.operation != Operation::InProgress)
    {
        const Operation operation = context.operation;
        revoke();
        return operation;
    }
    return Operation::InProgress;
}

RuntimeLicensingExistingCalOperation
LinuxRuntimeConnection::pollExistingCalValidation() noexcept
{
    using Operation = RuntimeLicensingExistingCalOperation;
    if (!existingCalValidation_ || !reauthorizeExistingCalValidation() ||
        !lease_)
        return Operation::Rejected;

    const Operation operation = existingCalValidation_->poll(
        lease_->admissionGeneration(), lease_->sessionGeneration());
    if (operation != Operation::InProgress &&
        operation != Operation::DecisionAvailable)
        revoke();
    return operation;
}

std::optional<RuntimeLicensingExistingCalDecision>
LinuxRuntimeConnection::authorizeExistingCalValidationDecision() noexcept
{
    if (!existingCalValidation_ || !reauthorizeExistingCalValidation() ||
        !lease_)
        return std::nullopt;

    const auto decision = existingCalValidation_->authorizeReleasedDecision(
        lease_->admissionGeneration(), lease_->sessionGeneration());
    if (!decision)
        revoke();
    return decision;
}

bool LinuxRuntimeConnection::retireExistingCalValidationDecision() noexcept
{
    if (!existingCalValidation_ || !reauthorizeExistingCalValidation() ||
        !lease_)
        return false;

    const bool retired = existingCalValidation_->retireReleasedDecision(
        lease_->admissionGeneration(), lease_->sessionGeneration());
    // R3 has no genuine positive completion consumer yet. Never turn a
    // test-only authority result into valid-client/Share state.
    revoke();
    return retired;
}

RuntimeLicensingExistingCalOperation
LinuxRuntimeConnection::cancelExistingCalValidation() noexcept
{
    using Operation = RuntimeLicensingExistingCalOperation;
    if (!existingCalValidation_)
        return Operation::Rejected;

    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes> correlation{};
    const auto currentCorrelation = existingCalValidation_->requestCorrelation();
    const bool haveCorrelation =
        currentCorrelation.size() == correlation.size();
    if (haveCorrelation)
        std::copy(currentCorrelation.begin(), currentCorrelation.end(),
                  correlation.begin());

    Operation operation = Operation::Cancelled;
    if (lease_ && !lease_->isRevoked())
    {
        operation = existingCalValidation_->cancel(
            lease_->admissionGeneration(), lease_->sessionGeneration());
    }
    else
    {
        existingCalValidation_->revoke();
    }

    if (haveCorrelation)
        (void)session_.cancelExistingClientCalAuthorityRequest(correlation);
    revoke();
    return operation;
}

void LinuxRuntimeConnection::revoke() noexcept
{
    // Never close R2's borrowed monitor fd. Real poller removal precedes any
    // registered callback/revocation; this discards only aggregate identity.
    nativeChangeRegistration_.reset();
    nativeChangeRegistrationUnregistered_ = false;

    // Retire the exact connection-bound authority operation before R3/R2
    // generations disappear.
    if (existingCalValidation_)
    {
        existingCalValidation_->revoke();
        existingCalValidation_.reset();
    }

    if (broker_)
    {
        broker_->revokeR3Session(acceptor_, session_);
    }
    else
    {
        session_.close();
        acceptor_.reject();
    }

    lease_.reset();
    broker_.reset();

    // R2 framing/reply state borrows the exact R1 owner; retire both before
    // R1 releases SSL/BIO/socket ownership.
    credSspReplyWriter_.close();
    credSspFrameReader_.close();

    // R1 is deliberately last: its SSL/BIO/socket may be borrowed
    // synchronously by every R2 check above.
    connection_.cancel();
    provisioned_ = false;
}

rdp_server::server::security::LinuxConsoleAdmissionState
LinuxRuntimeConnection::admissionState() const noexcept
{
    return broker_
        ? broker_->state()
        : rdp_server::server::security::LinuxConsoleAdmissionState::Revoked;
}

} // namespace rdp_server::server::runtime
