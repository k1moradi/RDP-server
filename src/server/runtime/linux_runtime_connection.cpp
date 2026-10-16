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

    if (required == Interest::Read && !readable)
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

void LinuxRuntimeConnection::revoke() noexcept
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
