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
    return provisioned_ && connection_.active() &&
           broker_.has_value() &&
           acceptor_.stage() !=
               rdp_server::server::security::SpnegoStage::Failed &&
           session_.phase() !=
               rdp_server::server::transport::McsSessionPhase::Closed;
}

rdp_server::server::transport::TcpConnectionIoInterest
LinuxRuntimeConnection::ioInterest() const noexcept
{
    return ready()
        ? connection_.ioInterest()
        : rdp_server::server::transport::TcpConnectionIoInterest::Closed;
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

rdp_server::server::security::TsRequestTlsReadResult
LinuxRuntimeConnection::onCredSspIoReady() noexcept
{
    using rdp_server::server::security::TsRequestTlsReadStatus;

    if (!ready())
        return {0, TsRequestTlsReadStatus::Closed};

    // Only the original R1 owner supplies selected HYBRID provenance.
    // A TLS handshake, principal string, or valid DER cannot substitute.
    if (!rdp_server::server::security::hasHybridNlaNegotiationProvenance(
            connection_.securityNegotiationProvenance()))
    {
        revoke();
        return {0, TsRequestTlsReadStatus::Invalid};
    }

    const auto result = credSspFrameReader_.readOneTlsStep(connection_);
    switch (result.status)
    {
    case TsRequestTlsReadStatus::Progress:
    case TsRequestTlsReadStatus::NeedRead:
    case TsRequestTlsReadStatus::NeedWrite:
        return result;
    case TsRequestTlsReadStatus::Complete:
        // R2 owns GSS and authentic CredSSP replies, neither of which is
        // aggregate-callable yet. Reject instead of granting admission.
        [[fallthrough]];
    case TsRequestTlsReadStatus::Invalid:
    case TsRequestTlsReadStatus::Closed:
        revoke();
        return {result.plaintextBytesRead, TsRequestTlsReadStatus::Invalid,
                result.error};
    }
    revoke();
    return {0, TsRequestTlsReadStatus::Invalid};
}

bool LinuxRuntimeConnection::issueAdmission(
    const rdp_server::server::security::ConsoleEvidenceRequest &request)
    noexcept
{
    if (!ready() || !broker_ || lease_)
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

    // R2 framing borrows the exact R1 owner; retire before R1 cancellation.
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
