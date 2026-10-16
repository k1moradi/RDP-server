// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_connection.h"

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
    if (terminalCredSspFailureReplyPending_)
    {
        return credSspReplyPending();
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
    using rdp_server::server::security::TsRequestTlsReadStatus;
    using rdp_server::server::security::TsRequestTlsWriteStatus;

    if (!provisioned_ || !connection_.active())
    {
        return {0, 0, LinuxCredSspStepStatus::Closed};
    }

    const auto writerStatus = credSspReplyWriter_.status();
    if (writerStatus != TsRequestTlsWriteStatus::Idle)
    {
        if (writerStatus == TsRequestTlsWriteStatus::Closed)
        {
            revoke();
            return {0, 0, LinuxCredSspStepStatus::Closed};
        }
        if (writerStatus == TsRequestTlsWriteStatus::Invalid)
        {
            revoke();
            return {0, 0, LinuxCredSspStepStatus::Invalid};
        }
        return advanceCredSspReply();
    }

    if (!ready())
    {
        return {0, 0, LinuxCredSspStepStatus::Closed};
    }

    // Only the original R1 owner supplies selected HYBRID provenance.
    // A TLS handshake, principal string, or valid DER cannot substitute.
    if (!rdp_server::server::security::hasHybridNlaNegotiationProvenance(
            connection_.securityNegotiationProvenance()))
    {
        revoke();
        return {0, 0, LinuxCredSspStepStatus::Invalid};
    }

    const auto result = credSspFrameReader_.readOneTlsStep(connection_);
    switch (result.status)
    {
    case TsRequestTlsReadStatus::Progress:
        return {result.plaintextBytesRead, 0,
                LinuxCredSspStepStatus::Progress};
    case TsRequestTlsReadStatus::NeedRead:
        return {0, 0, LinuxCredSspStepStatus::NeedRead};
    case TsRequestTlsReadStatus::NeedWrite:
        return {0, 0, LinuxCredSspStepStatus::NeedWrite};
    case TsRequestTlsReadStatus::Complete:
        return consumeCompletedCredSspFrame(result.plaintextBytesRead);
    case TsRequestTlsReadStatus::Invalid:
        revoke();
        return {result.plaintextBytesRead, 0,
                LinuxCredSspStepStatus::Invalid};
    case TsRequestTlsReadStatus::Closed:
        revoke();
        return {0, 0, LinuxCredSspStepStatus::Closed};
    }
    revoke();
    return {0, 0, LinuxCredSspStepStatus::Invalid};
}

LinuxCredSspStepResult LinuxRuntimeConnection::consumeCompletedCredSspFrame(
    std::size_t plaintextBytesRead) noexcept
{
    using rdp_server::server::security::SpnegoStage;
    using rdp_server::server::security::SpnegoStatus;
    using rdp_server::server::security::TsRequestTlsWriteStatus;

    const auto parsed = rdp_server::server::security::parseCredSspTsRequest(
        credSspFrameReader_.completeDer());
    if (!parsed)
    {
        revoke();
        return {plaintextBytesRead, 0, LinuxCredSspStepStatus::Invalid};
    }

    const auto queuedReply = [this, &parsed]() noexcept {
        switch (acceptor_.stage())
        {
        case SpnegoStage::AwaitInitialToken:
            return acceptor_.acceptFramedNegoAndQueueReply(
                credSspFrameReader_, credSspReplyWriter_);
        case SpnegoStage::ContinueNeeded:
            if (parsed.value.finalNegoAndBindingOnly())
            {
                return acceptor_.processFinalFramedNegoAndQueueBindingReply(
                           credSspFrameReader_, credSspReplyWriter_)
                    ? SpnegoStatus::Continue
                    : SpnegoStatus::Rejected;
            }
            return acceptor_.acceptFramedNegoAndQueueReply(
                credSspFrameReader_, credSspReplyWriter_);
        case SpnegoStage::MechanismVerified:
            return acceptor_.processFramedProtectedBindingAndQueueReply(
                       credSspFrameReader_, credSspReplyWriter_)
                ? SpnegoStatus::Continue
                : SpnegoStatus::Rejected;
        case SpnegoStage::ServerBindingPrepared:
            acceptor_.consumeFramedAndDenyDelegatedCredentials(
                credSspFrameReader_);
            return SpnegoStatus::Rejected;
        case SpnegoStage::Unconfigured:
        case SpnegoStage::Failed:
            return SpnegoStatus::Rejected;
        }
        return SpnegoStatus::Rejected;
    }();

    if (queuedReply == SpnegoStatus::FailureQueued)
    {
        if (credSspReplyWriter_.status() !=
            TsRequestTlsWriteStatus::NeedWrite)
        {
            revoke();
            return {plaintextBytesRead, 0, LinuxCredSspStepStatus::Invalid};
        }

        // Authentication has already failed. Retire R3/native authority
        // before retaining the provider-generated terminal R2 reply long
        // enough for the exact R1 owner to flush it.
        revokeAdmissionAuthority();
        credSspFrameReader_.close();
        terminalCredSspFailureReplyPending_ = true;
        return {plaintextBytesRead, 0, LinuxCredSspStepStatus::NeedWrite};
    }

    if (queuedReply != SpnegoStatus::Continue ||
        credSspReplyWriter_.status() != TsRequestTlsWriteStatus::NeedWrite)
    {
        revoke();
        return {plaintextBytesRead, 0, LinuxCredSspStepStatus::Invalid};
    }
    return {plaintextBytesRead, 0, LinuxCredSspStepStatus::NeedWrite};
}

LinuxCredSspStepResult LinuxRuntimeConnection::advanceCredSspReply() noexcept
{
    using rdp_server::server::security::TsRequestTlsWriteStatus;

    const auto result = credSspReplyWriter_.writeOneTlsStep(connection_);
    switch (result.status)
    {
    case TsRequestTlsWriteStatus::Progress:
        return {0, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::Progress};
    case TsRequestTlsWriteStatus::NeedRead:
        return {0, 0, LinuxCredSspStepStatus::NeedRead};
    case TsRequestTlsWriteStatus::NeedWrite:
        return {0, 0, LinuxCredSspStepStatus::NeedWrite};
    case TsRequestTlsWriteStatus::Complete:
    {
        const bool terminalFailure = terminalCredSspFailureReplyPending_;
        if (!credSspReplyWriter_.releaseReply())
        {
            revoke();
            return {0, result.plaintextBytesWritten,
                    LinuxCredSspStepStatus::Invalid};
        }
        if (terminalFailure)
        {
            revoke();
            return {0, result.plaintextBytesWritten,
                    LinuxCredSspStepStatus::Closed};
        }

        // Reply completion is real R1 transport progress. Re-enter once
        // without waiting so already-buffered peer plaintext cannot stall;
        // that next bounded step will report WANT if no frame is available.
        return {0, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::Progress};
    }
    case TsRequestTlsWriteStatus::Invalid:
        revoke();
        return {0, 0, LinuxCredSspStepStatus::Invalid};
    case TsRequestTlsWriteStatus::Closed:
        revoke();
        return {0, 0, LinuxCredSspStepStatus::Closed};
    case TsRequestTlsWriteStatus::Idle:
        revoke();
        return {0, 0, LinuxCredSspStepStatus::Invalid};
    }
    revoke();
    return {0, 0, LinuxCredSspStepStatus::Invalid};
}

bool LinuxRuntimeConnection::issueAdmission(
    const rdp_server::server::security::ConsoleEvidenceRequest &request)
    noexcept
{
    if (!ready() || terminalCredSspFailureReplyPending_ || !broker_ ||
        lease_ ||
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

void LinuxRuntimeConnection::revokeAdmissionAuthority() noexcept
{
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
}

void LinuxRuntimeConnection::revoke() noexcept
{
    revokeAdmissionAuthority();

    // R2 framing/reply state borrows the exact R1 owner; retire both before
    // R1 releases SSL/BIO/socket ownership.
    credSspReplyWriter_.close();
    credSspFrameReader_.close();
    terminalCredSspFailureReplyPending_ = false;

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
