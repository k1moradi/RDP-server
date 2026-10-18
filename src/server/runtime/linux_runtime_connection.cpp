// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_connection.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <limits>
#include <utility>

#include <poll.h>

namespace rdp_server::server::runtime
{

LinuxRuntimeMcsTpktFrameResult
LinuxRuntimeMcsTpktFrameReader::reject(
    std::size_t bytesConsumed) noexcept
{
    std::fill(buffer_.begin(), buffer_.begin() + bufferedBytes_, 0U);
    bufferedBytes_ = 0U;
    expectedBytes_ = 0U;
    status_ = LinuxRuntimeMcsTpktFrameStatus::Invalid;
    return {bytesConsumed, status_};
}

LinuxRuntimeMcsTpktFrameResult
LinuxRuntimeMcsTpktFrameReader::consume(
    std::span<const std::uint8_t> plaintext) noexcept
{
    if (status_ == LinuxRuntimeMcsTpktFrameStatus::Closed ||
        status_ == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
        status_ == LinuxRuntimeMcsTpktFrameStatus::Complete)
        return {0U, status_};

    std::size_t consumed = 0U;
    while (consumed < plaintext.size() &&
           status_ == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
    {
        const std::size_t needed = bytesNeeded();
        if (needed == 0U || needed > buffer_.size() - bufferedBytes_)
            return reject(consumed);

        const std::size_t count =
            (std::min)(needed, plaintext.size() - consumed);
        std::copy_n(
            plaintext.data() + consumed, count,
            buffer_.data() + bufferedBytes_);
        bufferedBytes_ += count;
        consumed += count;

        if (expectedBytes_ == 0U && bufferedBytes_ >= 4U)
        {
            const std::size_t length =
                (static_cast<std::size_t>(buffer_[2]) << 8U) |
                static_cast<std::size_t>(buffer_[3]);
            if (buffer_[0] != 3U || buffer_[1] != 0U ||
                length < 8U || length > buffer_.size())
                return reject(consumed);
            expectedBytes_ = length;
        }

        if (expectedBytes_ != 0U && bufferedBytes_ == expectedBytes_)
            status_ = LinuxRuntimeMcsTpktFrameStatus::Complete;
    }
    return {consumed, status_};
}

std::size_t LinuxRuntimeMcsTpktFrameReader::bytesNeeded() const noexcept
{
    if (status_ != LinuxRuntimeMcsTpktFrameStatus::NeedMore)
        return 0U;
    if (bufferedBytes_ < 4U)
        return 4U - bufferedBytes_;
    if (expectedBytes_ == 0U || expectedBytes_ <= bufferedBytes_)
        return 0U;
    return expectedBytes_ - bufferedBytes_;
}

std::span<const std::uint8_t>
LinuxRuntimeMcsTpktFrameReader::completeTpkt() const noexcept
{
    return status_ == LinuxRuntimeMcsTpktFrameStatus::Complete &&
                   expectedBytes_ == bufferedBytes_
               ? std::span<const std::uint8_t>{buffer_}.first(expectedBytes_)
               : std::span<const std::uint8_t>{};
}

bool LinuxRuntimeMcsTpktFrameReader::reset() noexcept
{
    if (status_ == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
        status_ == LinuxRuntimeMcsTpktFrameStatus::Closed)
        return false;

    std::fill(buffer_.begin(), buffer_.begin() + bufferedBytes_, 0U);
    bufferedBytes_ = 0U;
    expectedBytes_ = 0U;
    status_ = LinuxRuntimeMcsTpktFrameStatus::NeedMore;
    return true;
}

void LinuxRuntimeMcsTpktFrameReader::close() noexcept
{
    std::fill(buffer_.begin(), buffer_.begin() + bufferedBytes_, 0U);
    bufferedBytes_ = 0U;
    expectedBytes_ = 0U;
    status_ = LinuxRuntimeMcsTpktFrameStatus::Closed;
}

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
    const bool runtimeReady = ready();
    if (!runtimeReady)
        return Interest::Closed;

    const auto mcsPhase = session_.phase();
    if (mcsPhase ==
            rdp_server::server::transport::McsSessionPhase::AwaitConnectResponse ||
        mcsPhase ==
            rdp_server::server::transport::McsSessionPhase::AwaitAttachConfirm)
    {
        // R3 owns the pending reply. R1 owns retry direction after SSL WANT.
        const bool tlsWritePending =
            mcsPhase ==
                rdp_server::server::transport::McsSessionPhase::AwaitConnectResponse
                ? mcsConnectResponseTlsWritePending_
                : mcsAttachConfirmTlsWritePending_;
        if (!tlsWritePending)
            return Interest::Write;
        const auto required = connection_.ioInterest();
        return required == Interest::Read || required == Interest::Write
                   ? required : Interest::Closed;
    }

    if (mcsPhase ==
            rdp_server::server::transport::McsSessionPhase::AwaitChannelJoin &&
        mcsChannelJoinIoAction_ == McsChannelJoinIoAction::Write)
    {
        if (!mcsChannelJoinTlsWritePending_)
            return Interest::Write;
        const auto required = connection_.ioInterest();
        return required == Interest::Read || required == Interest::Write
                   ? required : Interest::Closed;
    }

    const bool tlsApplicationWriteOutstanding =
        personalLicenseRequestTlsWritePending_ ||
        personalValidClientTlsWritePending_ ||
        personalShareTlsWritePending_ ||
        personalGraphicsDvcTlsWritePending_;

    return detail::selectLinuxRuntimeConnectionIoInterest({
        .r1Interest = connection_.ioInterest(),
        .sessionPhase = session_.phase(),
        .runtimeReady = runtimeReady,
        .personalDesktopSelected = personalDesktopPolicy_ != nullptr,
        .tlsApplicationWriteOutstanding =
            tlsApplicationWriteOutstanding,
        .shareWritePending =
            personalShareIoAction_ == PersonalDesktopShareIoAction::Write,
        .graphicsWritePending =
            personalGraphicsDvcIoAction_ ==
            PersonalDesktopGraphicsDvcIoAction::Write,
    });
}

LinuxRuntimeSocketPollResult
LinuxRuntimeConnection::pollSocketReadinessOnce(
    std::chrono::steady_clock::time_point deadline,
    std::chrono::milliseconds maxWait) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using Status = LinuxRuntimeSocketPollStatus;
    using Clock = std::chrono::steady_clock;

    if (!ready())
        return {false, false, Status::Closed};

    const auto now = Clock::now();
    if (now >= deadline)
    {
        revoke();
        return {false, false, Status::Expired};
    }

    const Interest requested = ioInterest();
    if (requested == Interest::Closed)
    {
        revoke();
        return {false, false, Status::Closed};
    }
    if (requested == Interest::ConfigureTls)
    {
        // TLS configuration is an explicit owner transition, not socket I/O.
        return {false, false, Status::Ready};
    }

    const auto nativeSocket = connection_.nativeSocket();
    if (nativeSocket >
        static_cast<std::uintptr_t>((std::numeric_limits<int>::max)()))
    {
        revoke();
        return {false, false, Status::Failure};
    }

    const auto boundedMaximum =
        (std::max)(maxWait, std::chrono::milliseconds{0});
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    const auto wait =
        (std::min)(
            (std::min)(
                boundedMaximum,
                rdp_server::server::transport::kMaximumTcpPollWait),
            remaining);

    pollfd ready{};
    ready.fd = static_cast<int>(nativeSocket);
    ready.events = requested == Interest::Read ? POLLIN : POLLOUT;
    const int count =
        ::poll(&ready, static_cast<nfds_t>(1), static_cast<int>(wait.count()));
    if (count < 0)
    {
        if (errno == EINTR)
            return {false, false, Status::NoEvent};
        revoke();
        return {false, false, Status::Failure};
    }
    if (count == 0)
    {
        if (Clock::now() >= deadline)
        {
            revoke();
            return {false, false, Status::Expired};
        }
        return {false, false, Status::NoEvent};
    }

    if ((ready.revents & (POLLERR | POLLNVAL)) != 0)
    {
        revoke();
        return {false, false, Status::Failure};
    }

    // HUP is dispatched once in the currently requested direction so R1 sees
    // the real EOF/send failure through its existing recv/send/TLS owner.
    const bool hungUp = (ready.revents & POLLHUP) != 0;
    const bool readable = (ready.revents & POLLIN) != 0 || hungUp;
    const bool writable = (ready.revents & POLLOUT) != 0 || hungUp;
    if ((requested == Interest::Read && !readable) ||
        (requested == Interest::Write && !writable))
    {
        return {false, false, Status::NoEvent};
    }

    return {readable, writable, Status::Ready};
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

LinuxPostAdmissionMcsStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsConnectInitial(
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Stage = rdp_server::server::transport::PreauthStage;
    using Step = LinuxPostAdmissionMcsStepStatus;
    using Intake = rdp_server::server::transport::McsSessionIntake;

    if (!provisioned_ || !connection_.active())
        return {0U, Step::Closed};

    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() ||
        connection_.stage() != Stage::AwaitMcsConnectInitial ||
        session_.phase() !=
            rdp_server::server::transport::McsSessionPhase::
                AwaitVerifiedR2Admission)
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        revoke();
        return {0U, Step::Closed};
    }
    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        revoke();
        return {0U, Step::Invalid};
    }

    if (!broker_->revalidate(*lease_, acceptor_, connection_))
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed = mcsConnectInitialFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        revoke();
        return {0U, Step::Invalid};
    }
    const std::size_t requested = (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));

    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            revoke();
            return {0U, Step::Invalid};
        }
        const auto framed = mcsConnectInitialFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            revoke();
            return {io.bytes, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, Step::Progress};

        const auto completeTpkt =
            mcsConnectInitialFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            revoke();
            return {io.bytes, Step::Invalid};
        }

        const Intake intake = authorizeMcsConnectInitial(completeTpkt);
        mcsConnectInitialFrameReader_.close();
        if (intake == Intake::AdmittedConnectInitial)
            return {io.bytes, Step::AdmittedConnectInitial};
        return {
            io.bytes,
            intake == Intake::AdmissionDenied ? Step::AdmissionDenied
                                              : Step::Invalid};
    }
    case IoOutcome::NeedRead:
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsConnectInitialFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsConnectInitialFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    revoke();
    return {0U, Step::Invalid};
}

LinuxPostAdmissionMcsResponseStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsConnectResponseWrite(
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Phase = rdp_server::server::transport::McsSessionPhase;
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    using Step = LinuxPostAdmissionMcsResponseStepStatus;

    if (!ready())
        return {0U, Step::Closed};

    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() ||
        session_.phase() != Phase::AwaitConnectResponse)
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    if (mcsConnectResponseTlsWritePending_)
    {
        const Interest required = connection_.ioInterest();
        if (required == Interest::Read && !readable)
            return {0U, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            revoke();
            return {0U, Step::Invalid};
        }
    }
    else if (!writable)
    {
        return {0U, Step::NeedWrite};
    }

    const auto pending = broker_->authorizeR3ConnectResponseWrite(
        *lease_, acceptor_, connection_, session_);
    if (!pending || !*pending)
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const auto payload = pending->bytes.first((std::min)(
        pending->bytes.size(),
        rdp_server::server::transport::kMaximumTlsApplicationIoBytes));
    const auto io = connection_.writeTlsApplicationData(payload);
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        mcsConnectResponseTlsWritePending_ = false;
        if (io.bytes == 0U || io.bytes > payload.size())
        {
            revoke();
            return {0U, Step::Invalid};
        }

        // R1 progress alone is not an R3 delivery receipt. The concrete R2
        // lease, GSS/TLS owner and native generation are checked again.
        const auto outcome = broker_->completeR3ConnectResponseWrite(
            lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
            acceptor_, connection_, session_,
            pending->replySequence, pending->writeSliceSequence, io.bytes);
        if (outcome == Outcome::Pending)
            return {io.bytes, Step::Progress};
        if (outcome == Outcome::Delivered)
            return {io.bytes, Step::Delivered};
        revoke();
        return {io.bytes, Step::AdmissionDenied};
    }
    case IoOutcome::NeedRead:
        mcsConnectResponseTlsWritePending_ = true;
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        mcsConnectResponseTlsWritePending_ = true;
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsConnectResponseTlsWritePending_ = false;
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsConnectResponseTlsWritePending_ = false;
        revoke();
        return {0U, Step::Invalid};
    }
    revoke();
    return {0U, Step::Invalid};
}

LinuxPostAdmissionMcsErectStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsErectDomain(
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Phase = rdp_server::server::transport::McsSessionPhase;
    using Step = LinuxPostAdmissionMcsErectStepStatus;
    using Intake = rdp_server::server::transport::McsSessionIntake;

    if (!provisioned_ || !connection_.active())
        return {0U, Step::Closed};
    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() ||
        session_.phase() != Phase::AwaitErectDomain ||
        mcsConnectResponseTlsWritePending_)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    }

    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    // Every native admission and TLS/R1 assertion is fresh immediately
    // before the one bounded read, not inferred from TCP readiness alone.
    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed = mcsErectDomainFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    const std::size_t requested = (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {0U, Step::Invalid};
        }

        const auto framed = mcsErectDomainFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, Step::Progress};

        const auto completeTpkt = mcsErectDomainFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }

        const Intake intake = broker_->authorizeR3ErectDomain(
            *lease_, acceptor_, connection_, session_, completeTpkt);
        if (intake == Intake::ErectDomainAccepted)
        {
            if (!mcsErectDomainFrameReader_.reset())
            {
                revoke();
                return {io.bytes, Step::Invalid};
            }
            return {io.bytes, Step::ErectDomainAccepted};
        }
        mcsErectDomainFrameReader_.close();
        revoke();
        return {io.bytes,
                intake == Intake::AdmissionDenied
                    ? Step::AdmissionDenied : Step::Invalid};
    }
    case IoOutcome::NeedRead:
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    mcsErectDomainFrameReader_.close();
    revoke();
    return {0U, Step::Invalid};
}

// The immutable service policy is a product-mode input, never admission.
bool LinuxRuntimeConnection::postAdmissionMcsPolicyMatches(
    const RuntimeDeploymentPolicy &deploymentPolicy) const noexcept
{
    return deploymentPolicy.usesPersonalTerminalServerLicensingFlow() &&
           deploymentPolicy.requiresNativeSessionRevocation() &&
           deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() ==
               1U &&
           deploymentPolicy.loopbackListenerEnabled() &&
           (postAdmissionMcsPolicy_ == nullptr ||
            postAdmissionMcsPolicy_ == &deploymentPolicy);
}

bool LinuxRuntimeConnection::allNegotiatedMcsChannelsJoined() const noexcept
{
    const std::uint32_t allocatedUser = session_.allocatedUserId();
    const std::uint16_t allocatedIo = session_.allocatedIoChannelId();
    if (allocatedUser == 0U || allocatedUser > 65535U ||
        allocatedIo == 0U)
        return false;

    if (!session_.channelJoinConfirmed(
            static_cast<std::uint16_t>(allocatedUser)) ||
        !session_.channelJoinConfirmed(allocatedIo))
        return false;
    for (const std::uint16_t channel : session_.allocatedStaticChannelIds())
    {
        if (!session_.channelJoinConfirmed(channel))
            return false;
    }
    return true;
}

LinuxPostAdmissionMcsAttachStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsAttachUser(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Phase = rdp_server::server::transport::McsSessionPhase;
    using Step = LinuxPostAdmissionMcsAttachStepStatus;
    using Intake = rdp_server::server::transport::McsSessionIntake;

    if (!provisioned_ || !connection_.active())
        return {0U, Step::Closed};
    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() ||
        session_.phase() != Phase::AwaitAttachUser ||
        mcsConnectResponseTlsWritePending_ ||
        mcsAttachConfirmTlsWritePending_ ||
        !postAdmissionMcsPolicyMatches(deploymentPolicy))
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    // The service policy is single-assignment for this R2 connection.
    postAdmissionMcsPolicy_ = &deploymentPolicy;
    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    }

    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    // Every native admission and TLS/R1 assertion is fresh immediately
    // before the one bounded read, not inferred from TCP readiness alone.
    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed = mcsErectDomainFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    const std::size_t requested = (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {0U, Step::Invalid};
        }

        const auto framed = mcsErectDomainFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, Step::Progress};

        const auto completeTpkt = mcsErectDomainFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }

        const Intake intake = broker_->authorizeR3AttachUser(
            *lease_, acceptor_, connection_, session_, completeTpkt);
        if (intake == Intake::AttachUserAccepted)
        {
            if (!mcsErectDomainFrameReader_.reset())
            {
                revoke();
                return {io.bytes, Step::Invalid};
            }
            return {io.bytes, Step::AttachUserAccepted};
        }
        mcsErectDomainFrameReader_.close();
        revoke();
        return {io.bytes,
                intake == Intake::AdmissionDenied
                    ? Step::AdmissionDenied : Step::Invalid};
    }
    case IoOutcome::NeedRead:
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    mcsErectDomainFrameReader_.close();
    revoke();
    return {0U, Step::Invalid};
}

LinuxPostAdmissionMcsAttachConfirmStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsAttachConfirmWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Phase = rdp_server::server::transport::McsSessionPhase;
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    using Step = LinuxPostAdmissionMcsAttachConfirmStepStatus;

    if (!ready())
        return {0U, Step::Closed};

    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() ||
        session_.phase() != Phase::AwaitAttachConfirm ||
        postAdmissionMcsPolicy_ != &deploymentPolicy ||
        !postAdmissionMcsPolicyMatches(deploymentPolicy))
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    if (mcsAttachConfirmTlsWritePending_)
    {
        const Interest required = connection_.ioInterest();
        if (required == Interest::Read && !readable)
            return {0U, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            revoke();
            return {0U, Step::Invalid};
        }
    }
    else if (!writable)
    {
        return {0U, Step::NeedWrite};
    }

    const auto pending = broker_->authorizeR3AttachUserConfirmWrite(
        *lease_, acceptor_, connection_, session_);
    if (!pending || !*pending)
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const auto payload = pending->bytes.first((std::min)(
        pending->bytes.size(),
        rdp_server::server::transport::kMaximumTlsApplicationIoBytes));
    const auto io = connection_.writeTlsApplicationData(payload);
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        mcsAttachConfirmTlsWritePending_ = false;
        if (io.bytes == 0U || io.bytes > payload.size())
        {
            revoke();
            return {0U, Step::Invalid};
        }

        // R1 progress alone is not an R3 delivery receipt. The concrete R2
        // lease, GSS/TLS owner and native generation are checked again.
        if (!postAdmissionMcsPolicyMatches(deploymentPolicy))
        {
            revoke();
            return {io.bytes, Step::AdmissionDenied};
        }
        const auto outcome = broker_->completeR3AttachUserConfirmWrite(
            lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
            acceptor_, connection_, session_,
            pending->replySequence, pending->writeSliceSequence, io.bytes);
        if (outcome == Outcome::Pending)
            return {io.bytes, Step::Progress};
        if (outcome == Outcome::Delivered)
        {
            // A fully accepted Attach confirm is only the entry to the real
            // R3 join phase; not even one requested join is implied.
            mcsChannelJoinIoAction_ = McsChannelJoinIoAction::Read;
            return {io.bytes, Step::Delivered};
        }
        revoke();
        return {io.bytes, Step::AdmissionDenied};
    }
    case IoOutcome::NeedRead:
        mcsAttachConfirmTlsWritePending_ = true;
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        mcsAttachConfirmTlsWritePending_ = true;
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsAttachConfirmTlsWritePending_ = false;
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsAttachConfirmTlsWritePending_ = false;
        revoke();
        return {0U, Step::Invalid};
    }
    revoke();
    return {0U, Step::Invalid};
}

LinuxPostAdmissionMcsChannelJoinStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsChannelJoins(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Phase = rdp_server::server::transport::McsSessionPhase;
    using Action = McsChannelJoinIoAction;
    using Step = LinuxPostAdmissionMcsChannelJoinStepStatus;
    using Start = rdp_server::server::transport::McsJoinStartOutcome;
    using Written = rdp_server::server::transport::McsJoinWriteOutcome;

    if (!ready())
        return {0U, 0U, Step::Closed};
    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() || session_.phase() != Phase::AwaitChannelJoin ||
        postAdmissionMcsPolicy_ != &deploymentPolicy ||
        !postAdmissionMcsPolicyMatches(deploymentPolicy) ||
        mcsChannelJoinIoAction_ == Action::Idle)
    {
        revoke();
        return {0U, 0U, Step::AdmissionDenied};
    }

    if (mcsChannelJoinIoAction_ == Action::Read)
    {
        const Interest required = connection_.ioInterest();
        if (required == Interest::Closed)
        {
            revoke();
            return {0U, 0U, Step::Closed};
        }
        const bool bufferedRead =
            required == Interest::Read &&
            connection_.tlsApplicationReadReady();
        if (required == Interest::Read && !readable && !bufferedRead)
            return {0U, 0U, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, 0U, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            revoke();
            return {0U, 0U, Step::Invalid};
        }

        // The read is never an authorization cache: check exact admission,
        // native generation, TLS owner and R3 session immediately before it.
        if (!broker_->authorizeR3ProtectedTransition(
                *lease_, acceptor_, connection_, session_,
                rdp_server::server::security::kConsoleViewPermission))
        {
            revoke();
            return {0U, 0U, Step::AdmissionDenied};
        }

        constexpr std::size_t kReadChunkBytes = 512U;
        std::array<std::uint8_t, kReadChunkBytes> plaintext{};
        const std::size_t needed = mcsErectDomainFrameReader_.bytesNeeded();
        if (needed == 0U ||
            needed >
                rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
        {
            revoke();
            return {0U, 0U, Step::Invalid};
        }
        const std::size_t requested =
            (std::min)(plaintext.size(), needed);
        const auto io = connection_.readTlsApplicationData(
            std::span<std::uint8_t>{plaintext}.first(requested));
        switch (io.outcome)
        {
        case IoOutcome::Progress:
        {
            if (io.bytes == 0U || io.bytes > requested)
            {
                revoke();
                return {0U, 0U, Step::Invalid};
            }
            const auto framed = mcsErectDomainFrameReader_.consume(
                std::span<const std::uint8_t>{plaintext}.first(io.bytes));
            std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
            if (framed.bytesConsumed != io.bytes ||
                framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
                framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
            {
                revoke();
                return {io.bytes, 0U, Step::Invalid};
            }
            if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
                return {io.bytes, 0U, Step::Progress};
            const auto completeTpkt = mcsErectDomainFrameReader_.completeTpkt();
            if (completeTpkt.empty())
            {
                revoke();
                return {io.bytes, 0U, Step::Invalid};
            }
            const Start outcome = broker_->authorizeR3ChannelJoin(
                *lease_, acceptor_, connection_, session_, completeTpkt);
            if (!mcsErectDomainFrameReader_.reset())
            {
                revoke();
                return {io.bytes, 0U, Step::Invalid};
            }
            if (outcome == Start::ReplyPending)
            {
                mcsChannelJoinIoAction_ = Action::Write;
                return {io.bytes, 0U, Step::Progress};
            }
            if (outcome == Start::AlreadyJoined ||
                outcome == Start::AlreadyPending)
            {
                // T.125 duplicate requests never cause fabricated second
                // confirmations. Pending joins remain R3-owned.
                return {io.bytes, 0U, Step::Progress};
            }
            // This serial runtime never reads ahead with a queued reply.
            // An unexpected queue or unallocated channel is terminal.
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }
        case IoOutcome::NeedRead:
            return {0U, 0U, Step::NeedRead};
        case IoOutcome::NeedWrite:
            return {0U, 0U, Step::NeedWrite};
        case IoOutcome::TlsClosed:
        case IoOutcome::TransportClosed:
            revoke();
            return {0U, 0U, Step::Closed};
        case IoOutcome::FatalTlsFailure:
        case IoOutcome::Invalid:
            revoke();
            return {0U, 0U, Step::Invalid};
        }
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    if (mcsChannelJoinIoAction_ != Action::Write)
    {
        revoke();
        return {0U, 0U, Step::Invalid};
    }
    if (mcsChannelJoinTlsWritePending_)
    {
        const Interest required = connection_.ioInterest();
        if (required == Interest::Read && !readable)
            return {0U, 0U, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, 0U, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            revoke();
            return {0U, 0U, Step::Invalid};
        }
    }
    else if (!writable)
    {
        return {0U, 0U, Step::NeedWrite};
    }

    const auto pending = broker_->authorizeR3ChannelJoinConfirmWrite(
        *lease_, acceptor_, connection_, session_);
    if (!pending || !*pending)
    {
        revoke();
        return {0U, 0U, Step::AdmissionDenied};
    }
    const auto payload = pending->bytes.first((std::min)(
        pending->bytes.size(),
        rdp_server::server::transport::kMaximumTlsApplicationIoBytes));
    const auto io = connection_.writeTlsApplicationData(payload);
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        mcsChannelJoinTlsWritePending_ = false;
        if (io.bytes == 0U || io.bytes > payload.size())
        {
            revoke();
            return {0U, 0U, Step::Invalid};
        }
        // R1 TLS progress is not a channel confirmation until the exact R2
        // receipt validates the same R3-owned reply/slice identity.
        if (!postAdmissionMcsPolicyMatches(deploymentPolicy))
        {
            revoke();
            return {0U, io.bytes, Step::AdmissionDenied};
        }
        const Written outcome = broker_->completeR3ChannelJoinConfirmWrite(
            lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
            acceptor_, connection_, session_,
            pending->replySequence, pending->writeSliceSequence, io.bytes);
        if (outcome == Written::Pending)
            return {0U, io.bytes, Step::Progress};
        if (outcome != Written::Confirmed)
        {
            revoke();
            return {0U, io.bytes, Step::AdmissionDenied};
        }

        // R3 owns the expected negotiated user, I/O and static channel IDs.
        // Read its state only after the exact receipt and fresh R2 check.
        if (!broker_->authorizeR3ProtectedTransition(
                *lease_, acceptor_, connection_, session_,
                rdp_server::server::security::kConsoleViewPermission))
        {
            revoke();
            return {0U, io.bytes, Step::AdmissionDenied};
        }
        const bool allConfirmed = allNegotiatedMcsChannelsJoined();
        mcsChannelJoinIoAction_ = Action::Read;
        return {0U, io.bytes,
                allConfirmed ? Step::AllChannelsJoined : Step::Progress};
    }
    case IoOutcome::NeedRead:
        mcsChannelJoinTlsWritePending_ = true;
        return {0U, 0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        mcsChannelJoinTlsWritePending_ = true;
        return {0U, 0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsChannelJoinTlsWritePending_ = false;
        revoke();
        return {0U, 0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsChannelJoinTlsWritePending_ = false;
        revoke();
        return {0U, 0U, Step::Invalid};
    }
    revoke();
    return {0U, 0U, Step::Invalid};
}

LinuxPostAdmissionMcsClientInfoStepResult
LinuxRuntimeConnection::advancePostAdmissionMcsClientInfo(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Phase = rdp_server::server::transport::McsSessionPhase;
    using Step = LinuxPostAdmissionMcsClientInfoStepStatus;

    if (!provisioned_ || !connection_.active())
        return {0U, Step::Closed};
    if (!broker_ || !lease_ || lease_->isRevoked() ||
        credSspReplyPending() ||
        session_.phase() != Phase::AwaitChannelJoin ||
        mcsConnectResponseTlsWritePending_ ||
        mcsAttachConfirmTlsWritePending_ ||
        mcsChannelJoinTlsWritePending_ ||
        mcsChannelJoinIoAction_ != McsChannelJoinIoAction::Read ||
        postAdmissionMcsPolicy_ != &deploymentPolicy ||
        !postAdmissionMcsPolicyMatches(deploymentPolicy))
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    // The complete MCS join transcript is stored only by the R3 owner.
    // Revalidate that same R2 lease before reading R3 diagnostics.
    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission) ||
        !allNegotiatedMcsChannelsJoined())
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }
    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    }

    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    // Every native admission and TLS/R1 assertion is fresh immediately
    // before the one bounded read, not inferred from TCP readiness alone.
    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed = mcsErectDomainFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    const std::size_t requested = (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {0U, Step::Invalid};
        }

        const auto framed = mcsErectDomainFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, Step::Progress};

        const auto completeTpkt = mcsErectDomainFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            mcsErectDomainFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }

        // Real Client Info is private to the existing R2/R3 packet intake:
        // do not inspect, retain or substitute any credential or user field.
        const bool accepted = broker_->authorizeR3ClientInfoPacket(
            *lease_, acceptor_, connection_, session_, completeTpkt)
            .has_value();
        mcsErectDomainFrameReader_.close();
        if (accepted)
            return {io.bytes, Step::ClientInfoAccepted};
        revoke();
        return {io.bytes, Step::AdmissionDenied};
    }
    case IoOutcome::NeedRead:
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        mcsErectDomainFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }
    mcsErectDomainFrameReader_.close();
    revoke();
    return {0U, Step::Invalid};
}

bool LinuxRuntimeConnection::selectPersonalDesktopLicensingMode(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    if (personalDesktopPolicy_ != nullptr ||
        (postAdmissionMcsPolicy_ != nullptr &&
         postAdmissionMcsPolicy_ != &deploymentPolicy) ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        !broker_->authorizeR3PersonalDesktopLicensingMode(
            *lease_, acceptor_, connection_, session_, deploymentPolicy))
    {
        revoke();
        return false;
    }
    personalDesktopPolicy_ = &deploymentPolicy;
    return true;
}

LinuxPersonalDesktopLicenseWriteStepResult
LinuxRuntimeConnection::advancePersonalDesktopServerLicenseRequestWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    const RuntimeLicensingContext &licensingContext,
    bool readable, bool writable) noexcept
{
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using Outcome =
        rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome;
    using Step = LinuxPersonalDesktopLicenseWriteStepStatus;

    if (!ready())
        return {0U, Step::Closed};
    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const auto *const identity = licensingContext.identity();
    const auto *const credential = licensingContext.credential();
    if (identity == nullptr || credential == nullptr ||
        !licensingContext.configured() || !credential->matches(*identity))
    {
        revoke();
        return {0U, Step::Invalid};
    }

    if (personalLicenseRequestTlsWritePending_)
    {
        const Interest required = connection_.ioInterest();
        if (required == Interest::Read && !readable)
            return {0U, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            revoke();
            return {0U, Step::Invalid};
        }
    }
    else if (!writable)
    {
        return {0U, Step::NeedWrite};
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopServerLicenseRequestWrite(
            *lease_, acceptor_, connection_, session_, deploymentPolicy,
            *identity, *credential);
    if (!pending)
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const auto io = connection_.writeTlsApplicationData(pending->bytes);
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        personalLicenseRequestTlsWritePending_ = false;
        if (io.bytes == 0U || io.bytes > pending->bytes.size())
        {
            revoke();
            return {0U, Step::Invalid};
        }
        const auto outcome =
            broker_->completeR3PersonalDesktopServerLicenseRequestWrite(
                lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
                acceptor_, connection_, session_, deploymentPolicy,
                pending->replySequence, pending->writeSliceSequence,
                io.bytes);
        if (outcome == Outcome::Pending)
            return {io.bytes, Step::Progress};
        if (outcome == Outcome::Delivered)
            return {io.bytes, Step::Delivered};
        revoke();
        return {io.bytes, Step::AdmissionDenied};
    }
    case IoOutcome::NeedRead:
        personalLicenseRequestTlsWritePending_ = true;
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        personalLicenseRequestTlsWritePending_ = true;
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        personalLicenseRequestTlsWritePending_ = false;
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        personalLicenseRequestTlsWritePending_ = false;
        revoke();
        return {0U, Step::Invalid};
    }
    revoke();
    return {0U, Step::Invalid};
}

LinuxPersonalDesktopClientLicensingStepResult
LinuxRuntimeConnection::advancePersonalDesktopClientLicensingIntake(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    const RuntimeLicensingContext &licensingContext,
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using McsPhase =
        rdp_server::server::transport::McsSessionPhase;
    using Intake =
        rdp_server::server::transport::RdpLicensingIntake;
    using Step = LinuxPersonalDesktopClientLicensingStepStatus;

    if (!ready())
        return {0U, Step::Closed};

    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !broker_ || !lease_ || lease_->isRevoked())
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    // Do not consume following R1 plaintext until the exact preceding Server
    // License Request receipt has advanced R3 to this client-response phase.
    if (session_.phase() != McsPhase::AwaitClientLicenseResponse)
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    const auto *const identity = licensingContext.identity();
    const auto *const credential = licensingContext.credential();
    if (identity == nullptr || credential == nullptr ||
        !licensingContext.configured() || !credential->matches(*identity))
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    }

    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed =
        personalClientLicensingFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    const std::size_t requested =
        (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));

    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            personalClientLicensingFrameReader_.close();
            revoke();
            return {0U, Step::Invalid};
        }

        const auto framed = personalClientLicensingFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            personalClientLicensingFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, Step::Progress};

        const auto completeTpkt =
            personalClientLicensingFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            personalClientLicensingFrameReader_.close();
            revoke();
            return {io.bytes, Step::Invalid};
        }

        const auto intake =
            broker_->authorizeR3PersonalDesktopClientLicensingMessage(
                *lease_, acceptor_, connection_, session_,
                deploymentPolicy, *credential, completeTpkt);
        personalClientLicensingFrameReader_.close();
        if (!intake)
        {
            revoke();
            return {io.bytes, Step::AdmissionDenied};
        }

        switch (*intake)
        {
        case Intake::ClientLicenseInfoAccepted:
            return {io.bytes, Step::ClientLicenseInfoAccepted};
        case Intake::ClientNewLicenseRequestAccepted:
            return {io.bytes, Step::ClientNewLicenseRequestAccepted};
        case Intake::ClientPlatformChallengeResponseAccepted:
        case Intake::MalformedMessage:
        case Intake::UnexpectedMessage:
        case Intake::Failed:
        case Intake::Closed:
            revoke();
            return {io.bytes, Step::Invalid};
        }
        revoke();
        return {io.bytes, Step::Invalid};
    }
    case IoOutcome::NeedRead:
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        personalClientLicensingFrameReader_.close();
        revoke();
        return {0U, Step::Invalid};
    }

    personalClientLicensingFrameReader_.close();
    revoke();
    return {0U, Step::Invalid};
}

LinuxPersonalDesktopValidClientWriteStepResult
LinuxRuntimeConnection::advancePersonalDesktopValidClientWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Outcome = rdp_server::server::transport::
        RdpPersonalDesktopValidClientWriteOutcome;
    using Step = LinuxPersonalDesktopValidClientWriteStepStatus;

    if (!ready())
        return {0U, Step::Closed};

    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !broker_ || !lease_ || lease_->isRevoked())
    {
        personalValidClientTlsWritePending_ = false;
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    if (personalValidClientTlsWritePending_)
    {
        const Interest required = connection_.ioInterest();
        if (required == Interest::Read && !readable)
            return {0U, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            personalValidClientTlsWritePending_ = false;
            revoke();
            return {0U, Step::Invalid};
        }
    }
    else if (!writable)
    {
        return {0U, Step::NeedWrite};
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopValidClientWrite(
            *lease_, acceptor_, connection_, session_, deploymentPolicy);
    if (!pending)
    {
        personalValidClientTlsWritePending_ = false;
        revoke();
        return {0U, Step::AdmissionDenied};
    }

    const auto io = connection_.writeTlsApplicationData(pending->bytes);
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        personalValidClientTlsWritePending_ = false;
        if (io.bytes == 0U || io.bytes > pending->bytes.size())
        {
            revoke();
            return {0U, Step::Invalid};
        }

        const auto outcome =
            broker_->completeR3PersonalDesktopValidClientWrite(
                lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
                acceptor_, connection_, session_, deploymentPolicy,
                pending->replySequence, pending->writeSliceSequence,
                io.bytes);
        if (outcome == Outcome::Pending)
            return {io.bytes, Step::Progress};
        if (outcome == Outcome::Delivered)
            return {io.bytes, Step::Delivered};

        revoke();
        return {io.bytes, Step::AdmissionDenied};
    }
    case IoOutcome::NeedRead:
        personalValidClientTlsWritePending_ = true;
        return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        personalValidClientTlsWritePending_ = true;
        return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        personalValidClientTlsWritePending_ = false;
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        personalValidClientTlsWritePending_ = false;
        revoke();
        return {0U, Step::Invalid};
    }

    personalValidClientTlsWritePending_ = false;
    revoke();
    return {0U, Step::Invalid};
}

std::optional<
    rdp_server::server::transport::RdpPersonalDesktopValidClientWriteView>
LinuxRuntimeConnection::authorizePersonalDesktopValidClientWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return std::nullopt;
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopValidClientWrite(
            *lease_, acceptor_, connection_, session_, deploymentPolicy);
    if (!pending)
        revoke();
    return pending;
}

rdp_server::server::transport::RdpPersonalDesktopValidClientWriteOutcome
LinuxRuntimeConnection::completePersonalDesktopValidClientWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome = rdp_server::server::transport::
        RdpPersonalDesktopValidClientWriteOutcome;

    if (!broker_)
    {
        revoke();
        return Outcome::Rejected;
    }

    const rdp_server::server::security::LinuxConsoleAdmissionLease *lease =
        lease_ && !lease_->isRevoked() ? &*lease_ : nullptr;
    const auto outcome =
        broker_->completeR3PersonalDesktopValidClientWrite(
            lease, acceptor_, connection_, session_, deploymentPolicy,
            replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revoke();
    return outcome;
}

std::optional<rdp_server::server::transport::RdpDemandActiveProfileView>
LinuxRuntimeConnection::preparePersonalDesktopDemandActiveProfile(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    rdp_server::server::transport::RdpDemandActiveFeature features) noexcept
{
    if (personalShareIoAction_ != PersonalDesktopShareIoAction::Idle ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return std::nullopt;
    }

    const auto profile =
        broker_->authorizeR3PersonalDesktopDemandActiveProfile(
            *lease_, acceptor_, connection_, session_, deploymentPolicy,
            features);
    if (!profile)
        revoke();
    return profile;
}

bool LinuxRuntimeConnection::startPersonalDesktopShareActivation(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    const rdp_server::server::transport::RdpDemandActiveProfileView
        &profile) noexcept
{
    using Kind = rdp_server::server::transport::RdpShareServerWriteKind;

    if (personalShareIoAction_ != PersonalDesktopShareIoAction::Idle ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return false;
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopShareActivation(
            *lease_, acceptor_, connection_, session_, deploymentPolicy,
            profile);
    if (!pending || pending->kind != Kind::DemandActive ||
        !personalShareActivationFrameReader_.reset())
    {
        revoke();
        return false;
    }

    personalShareTlsWritePending_ = false;
    personalShareIoAction_ = PersonalDesktopShareIoAction::Write;
    return true;
}

LinuxPersonalDesktopShareActivationStepResult
LinuxRuntimeConnection::advancePersonalDesktopShareActivation(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Action = PersonalDesktopShareIoAction;
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Intake =
        rdp_server::server::transport::RdpShareActivationClientIntake;
    using Kind =
        rdp_server::server::transport::RdpShareServerWriteKind;
    using Outcome =
        rdp_server::server::transport::RdpShareActivationWriteOutcome;
    using Step = LinuxPersonalDesktopShareActivationStepStatus;

    if (!ready())
        return {0U, 0U, Step::Closed};

    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !broker_ || !lease_ || lease_->isRevoked())
    {
        personalShareActivationFrameReader_.close();
        personalShareTlsWritePending_ = false;
        revoke();
        return {0U, 0U, Step::AdmissionDenied};
    }

    if (personalShareIoAction_ == Action::Activated)
    {
        if (session_.phase() ==
            rdp_server::server::transport::McsSessionPhase::ShareActivated)
            return {0U, 0U, Step::Activated};

        revoke();
        return {0U, 0U, Step::Invalid};
    }
    if (personalShareIoAction_ == Action::Idle)
    {
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    if (personalShareIoAction_ == Action::Write)
    {
        if (personalShareTlsWritePending_)
        {
            const Interest required = connection_.ioInterest();
            if (required == Interest::Read && !readable)
                return {0U, 0U, Step::NeedRead};
            if (required == Interest::Write && !writable)
                return {0U, 0U, Step::NeedWrite};
            if (required != Interest::Read &&
                required != Interest::Write)
            {
                personalShareTlsWritePending_ = false;
                revoke();
                return {0U, 0U, Step::Invalid};
            }
        }
        else if (!writable)
        {
            return {0U, 0U, Step::NeedWrite};
        }

        const auto pending =
            broker_->authorizeR3PersonalDesktopShareActivationWrite(
                *lease_, acceptor_, connection_, session_, deploymentPolicy);
        if (!pending)
        {
            personalShareTlsWritePending_ = false;
            revoke();
            return {0U, 0U, Step::AdmissionDenied};
        }

        const Kind completedKind = pending->kind;
        const auto io = connection_.writeTlsApplicationData(pending->bytes);
        switch (io.outcome)
        {
        case IoOutcome::Progress:
        {
            personalShareTlsWritePending_ = false;
            if (io.bytes == 0U || io.bytes > pending->bytes.size())
            {
                revoke();
                return {0U, 0U, Step::Invalid};
            }

            const auto outcome =
                broker_->completeR3PersonalDesktopShareActivationWrite(
                    lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
                    acceptor_, connection_, session_, deploymentPolicy,
                    pending->replySequence, pending->writeSliceSequence,
                    io.bytes);
            if (outcome == Outcome::Pending)
                return {0U, io.bytes, Step::Progress};
            if (outcome == Outcome::Activated)
            {
                personalShareActivationFrameReader_.close();
                personalShareIoAction_ = Action::Activated;
                return {0U, io.bytes, Step::Activated};
            }
            if (outcome != Outcome::Delivered)
            {
                revoke();
                return {0U, io.bytes, Step::AdmissionDenied};
            }

            switch (completedKind)
            {
            case Kind::DemandActive:
                personalShareIoAction_ = Action::Read;
                break;
            case Kind::Synchronize:
                personalShareIoAction_ = Action::Write;
                break;
            case Kind::Cooperate:
            case Kind::GrantedControl:
                personalShareIoAction_ = Action::Read;
                break;
            case Kind::FontMap:
            case Kind::None:
                revoke();
                return {0U, io.bytes, Step::Invalid};
            }
            return {0U, io.bytes, Step::Progress};
        }
        case IoOutcome::NeedRead:
            personalShareTlsWritePending_ = true;
            return {0U, 0U, Step::NeedRead};
        case IoOutcome::NeedWrite:
            personalShareTlsWritePending_ = true;
            return {0U, 0U, Step::NeedWrite};
        case IoOutcome::TlsClosed:
        case IoOutcome::TransportClosed:
            personalShareTlsWritePending_ = false;
            personalShareActivationFrameReader_.close();
            revoke();
            return {0U, 0U, Step::Closed};
        case IoOutcome::FatalTlsFailure:
        case IoOutcome::Invalid:
            personalShareTlsWritePending_ = false;
            personalShareActivationFrameReader_.close();
            revoke();
            return {0U, 0U, Step::Invalid};
        }

        revoke();
        return {0U, 0U, Step::Invalid};
    }

    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        personalShareActivationFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Closed};
    }

    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, 0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, 0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        personalShareActivationFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        personalShareActivationFrameReader_.close();
        revoke();
        return {0U, 0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed =
        personalShareActivationFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        personalShareActivationFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    const std::size_t requested =
        (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));

    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            personalShareActivationFrameReader_.close();
            revoke();
            return {0U, 0U, Step::Invalid};
        }

        const auto framed = personalShareActivationFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            personalShareActivationFrameReader_.close();
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, 0U, Step::Progress};

        const auto completeTpkt =
            personalShareActivationFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            personalShareActivationFrameReader_.close();
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }

        const auto intake =
            broker_->authorizeR3PersonalDesktopShareActivationPdu(
                *lease_, acceptor_, connection_, session_, deploymentPolicy,
                completeTpkt);
        if (intake == Intake::Rejected || intake == Intake::Closed ||
            !personalShareActivationFrameReader_.reset())
        {
            personalShareActivationFrameReader_.close();
            revoke();
            return {
                io.bytes, 0U,
                intake == Intake::Closed ? Step::Closed : Step::Invalid};
        }

        switch (intake)
        {
        case Intake::ConfirmActiveAccepted:
        case Intake::RequestControlAccepted:
        case Intake::FontListAccepted:
            personalShareIoAction_ = Action::Write;
            break;
        case Intake::SynchronizeAccepted:
        case Intake::CooperateAccepted:
            personalShareIoAction_ = Action::Read;
            break;
        case Intake::Rejected:
        case Intake::Closed:
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }
        return {io.bytes, 0U, Step::Progress};
    }
    case IoOutcome::NeedRead:
        return {0U, 0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, 0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        personalShareActivationFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        personalShareActivationFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    personalShareActivationFrameReader_.close();
    revoke();
    return {0U, 0U, Step::Invalid};
}

std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
LinuxRuntimeConnection::beginPersonalDesktopShareActivation(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    const rdp_server::server::transport::RdpDemandActiveProfileView
        &profile) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return std::nullopt;
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopShareActivation(
            *lease_, acceptor_, connection_, session_, deploymentPolicy,
            profile);
    if (!pending)
        revoke();
    return pending;
}

std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
LinuxRuntimeConnection::authorizePersonalDesktopShareActivationWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return std::nullopt;
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopShareActivationWrite(
            *lease_, acceptor_, connection_, session_, deploymentPolicy);
    if (!pending)
        revoke();
    return pending;
}

rdp_server::server::transport::RdpShareActivationWriteOutcome
LinuxRuntimeConnection::completePersonalDesktopShareActivationWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::RdpShareActivationWriteOutcome;

    if (!broker_)
    {
        revoke();
        return Outcome::Rejected;
    }

    const rdp_server::server::security::LinuxConsoleAdmissionLease *lease =
        lease_ && !lease_->isRevoked() ? &*lease_ : nullptr;
    const auto outcome =
        broker_->completeR3PersonalDesktopShareActivationWrite(
            lease, acceptor_, connection_, session_, deploymentPolicy,
            replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revoke();
    return outcome;
}

rdp_server::server::transport::RdpShareActivationClientIntake
LinuxRuntimeConnection::acceptPersonalDesktopShareActivationPdu(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Intake =
        rdp_server::server::transport::RdpShareActivationClientIntake;

    if (!ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return Intake::Rejected;
    }

    const auto intake =
        broker_->authorizeR3PersonalDesktopShareActivationPdu(
            *lease_, acceptor_, connection_, session_, deploymentPolicy,
            completeTpkt);
    if (intake == Intake::Rejected || intake == Intake::Closed)
        revoke();
    return intake;
}

bool LinuxRuntimeConnection::
startPersonalDesktopGraphicsDynamicVirtualChannel(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    using Kind =
        rdp_server::server::transport::RdpGraphicsDvcWriteKind;

    if (personalGraphicsDvcIoAction_ !=
            PersonalDesktopGraphicsDvcIoAction::Idle ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return false;
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopGraphicsDynamicVirtualChannel(
            *lease_, acceptor_, connection_, session_, deploymentPolicy);
    if (!pending || pending->kind != Kind::CapabilitiesRequest ||
        !personalGraphicsDvcFrameReader_.reset())
    {
        revoke();
        return false;
    }

    personalGraphicsDvcTlsWritePending_ = false;
    personalGraphicsDvcIoAction_ =
        PersonalDesktopGraphicsDvcIoAction::Write;
    return true;
}


bool LinuxRuntimeConnection::
startPersonalDesktopGraphicsFramePublication(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    rdp_server::rdp::GfxPresentationLifecycle &presentationLifecycle,
    rdp_server::rdp::GfxAvc420SegmentedFrame &&frame,
    rdp_server::server::transport::RdpGraphicsFrameCodec codec) noexcept
{
    using Action = PersonalDesktopGraphicsDvcIoAction;
    using Kind =
        rdp_server::server::transport::RdpGraphicsDvcWriteKind;

    if (personalGraphicsDvcIoAction_ != Action::Ready ||
        personalGraphicsDvcTlsWritePending_ ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return false;
    }

    const auto pending =
        broker_->authorizeR3PersonalDesktopGraphicsFramePublication(
            *lease_, acceptor_, connection_, session_,
            deploymentPolicy, presentationLifecycle,
            std::move(frame), codec);
    if (!pending ||
        pending->kind != Kind::GraphicsFrameData)
    {
        revoke();
        return false;
    }

    personalGraphicsDvcTlsWritePending_ = false;
    personalGraphicsDvcIoAction_ = Action::Write;
    return true;
}

bool LinuxRuntimeConnection::
cancelUnwrittenPersonalDesktopGraphicsFrame(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    using Action = PersonalDesktopGraphicsDvcIoAction;

    if (personalGraphicsDvcIoAction_ != Action::Write ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return false;
    }

    if (!broker_->cancelR3PersonalDesktopUnwrittenGraphicsFrame(
            *lease_, acceptor_, connection_, session_,
            deploymentPolicy))
    {
        revoke();
        return false;
    }

    personalGraphicsDvcTlsWritePending_ = false;
    personalGraphicsDvcIoAction_ = Action::Ready;
    return true;
}

LinuxPersonalDesktopGraphicsDvcStepResult
LinuxRuntimeConnection::advancePersonalDesktopGraphicsDynamicVirtualChannel(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Action = PersonalDesktopGraphicsDvcIoAction;
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome =
        rdp_server::server::transport::TlsApplicationIoOutcome;
    using Intake =
        rdp_server::server::transport::RdpGraphicsDvcClientIntake;
    using Kind =
        rdp_server::server::transport::RdpGraphicsDvcWriteKind;
    using Outcome =
        rdp_server::server::transport::RdpGraphicsDvcWriteOutcome;
    using Step = LinuxPersonalDesktopGraphicsDvcStepStatus;

    if (!ready())
        return {0U, 0U, Step::Closed};

    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !broker_ || !lease_ || lease_->isRevoked())
    {
        personalGraphicsDvcFrameReader_.close();
        personalGraphicsDvcTlsWritePending_ = false;
        revoke();
        return {0U, 0U, Step::AdmissionDenied};
    }

    if (personalGraphicsDvcIoAction_ == Action::Ready)
        return {0U, 0U, Step::Ready};
    if (personalGraphicsDvcIoAction_ == Action::Idle)
    {
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    if (personalGraphicsDvcIoAction_ == Action::Write)
    {
        if (personalGraphicsDvcTlsWritePending_)
        {
            const Interest required = connection_.ioInterest();
            if (required == Interest::Read && !readable)
                return {0U, 0U, Step::NeedRead};
            if (required == Interest::Write && !writable)
                return {0U, 0U, Step::NeedWrite};
            if (required != Interest::Read &&
                required != Interest::Write)
            {
                personalGraphicsDvcTlsWritePending_ = false;
                revoke();
                return {0U, 0U, Step::Invalid};
            }
        }
        else if (!writable)
        {
            return {0U, 0U, Step::NeedWrite};
        }

        const auto pending =
            broker_->
                authorizeR3PersonalDesktopGraphicsDynamicVirtualChannelWrite(
                    *lease_, acceptor_, connection_, session_,
                    deploymentPolicy);
        if (!pending)
        {
            personalGraphicsDvcTlsWritePending_ = false;
            revoke();
            return {0U, 0U, Step::AdmissionDenied};
        }

        const Kind completedKind = pending->kind;
        const auto io = connection_.writeTlsApplicationData(pending->bytes);
        switch (io.outcome)
        {
        case IoOutcome::Progress:
        {
            personalGraphicsDvcTlsWritePending_ = false;
            if (io.bytes == 0U || io.bytes > pending->bytes.size())
            {
                revoke();
                return {0U, 0U, Step::Invalid};
            }

            const auto outcome =
                broker_->
                    completeR3PersonalDesktopGraphicsDynamicVirtualChannelWrite(
                        lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
                        acceptor_, connection_, session_, deploymentPolicy,
                        pending->replySequence,
                        pending->writeSliceSequence, io.bytes);
            if (outcome == Outcome::Pending)
                return {0U, io.bytes, Step::Progress};
            if (outcome != Outcome::Delivered)
            {
                revoke();
                return {0U, io.bytes, Step::AdmissionDenied};
            }

            switch (completedKind)
            {
            case Kind::CapabilitiesRequest:
            case Kind::CreateRequest:
                personalGraphicsDvcIoAction_ = Action::Read;
                return {0U, io.bytes, Step::Progress};
            case Kind::GraphicsCapabilitiesConfirm:
                personalGraphicsDvcFrameReader_.close();
                personalGraphicsDvcIoAction_ = Action::Ready;
                return {0U, io.bytes, Step::Ready};
            case Kind::GraphicsFrameData:
                personalGraphicsDvcIoAction_ = Action::Ready;
                return {0U, io.bytes, Step::Ready};
            case Kind::None:
                revoke();
                return {0U, io.bytes, Step::Invalid};
            }
            revoke();
            return {0U, io.bytes, Step::Invalid};
        }
        case IoOutcome::NeedRead:
            personalGraphicsDvcTlsWritePending_ = true;
            return {0U, 0U, Step::NeedRead};
        case IoOutcome::NeedWrite:
            personalGraphicsDvcTlsWritePending_ = true;
            return {0U, 0U, Step::NeedWrite};
        case IoOutcome::TlsClosed:
        case IoOutcome::TransportClosed:
            personalGraphicsDvcTlsWritePending_ = false;
            personalGraphicsDvcFrameReader_.close();
            revoke();
            return {0U, 0U, Step::Closed};
        case IoOutcome::FatalTlsFailure:
        case IoOutcome::Invalid:
            personalGraphicsDvcTlsWritePending_ = false;
            personalGraphicsDvcFrameReader_.close();
            revoke();
            return {0U, 0U, Step::Invalid};
        }

        revoke();
        return {0U, 0U, Step::Invalid};
    }

    const Interest required = connection_.ioInterest();
    if (required == Interest::Closed)
    {
        personalGraphicsDvcFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Closed};
    }

    const bool bufferedRead =
        required == Interest::Read &&
        connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, 0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, 0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        personalGraphicsDvcFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    if (!broker_->authorizeR3ProtectedTransition(
            *lease_, acceptor_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        personalGraphicsDvcFrameReader_.close();
        revoke();
        return {0U, 0U, Step::AdmissionDenied};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed =
        personalGraphicsDvcFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed >
            rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
    {
        personalGraphicsDvcFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    const std::size_t requested =
        (std::min)(plaintext.size(), needed);
    const auto io = connection_.readTlsApplicationData(
        std::span<std::uint8_t>{plaintext}.first(requested));

    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        if (io.bytes == 0U || io.bytes > requested)
        {
            personalGraphicsDvcFrameReader_.close();
            revoke();
            return {0U, 0U, Step::Invalid};
        }

        const auto framed = personalGraphicsDvcFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Invalid ||
            framed.status == LinuxRuntimeMcsTpktFrameStatus::Closed)
        {
            personalGraphicsDvcFrameReader_.close();
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }
        if (framed.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore)
            return {io.bytes, 0U, Step::Progress};

        const auto completeTpkt =
            personalGraphicsDvcFrameReader_.completeTpkt();
        if (completeTpkt.empty())
        {
            personalGraphicsDvcFrameReader_.close();
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }

        const auto intake =
            broker_->
                authorizeR3PersonalDesktopGraphicsDynamicVirtualChannelPdu(
                    *lease_, acceptor_, connection_, session_,
                    deploymentPolicy, completeTpkt);
        if (intake == Intake::Rejected ||
            intake == Intake::CreateRejected ||
            intake == Intake::Closed ||
            !personalGraphicsDvcFrameReader_.reset())
        {
            personalGraphicsDvcFrameReader_.close();
            revoke();
            return {
                io.bytes, 0U,
                intake == Intake::Closed ? Step::Closed : Step::Invalid};
        }

        switch (intake)
        {
        case Intake::CapabilitiesAccepted:
            personalGraphicsDvcIoAction_ = Action::Write;
            break;
        case Intake::CreateAccepted:
            personalGraphicsDvcIoAction_ = Action::Read;
            break;
        case Intake::GraphicsCapabilitiesAccepted:
            personalGraphicsDvcIoAction_ = Action::Write;
            break;
        case Intake::GraphicsDataFragmentAccepted:
            personalGraphicsDvcIoAction_ = Action::Read;
            break;
        case Intake::GraphicsDataAccepted:
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        case Intake::CreateRejected:
        case Intake::Rejected:
        case Intake::Closed:
            revoke();
            return {io.bytes, 0U, Step::Invalid};
        }
        return {io.bytes, 0U, Step::Progress};
    }
    case IoOutcome::NeedRead:
        return {0U, 0U, Step::NeedRead};
    case IoOutcome::NeedWrite:
        return {0U, 0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        personalGraphicsDvcFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        personalGraphicsDvcFrameReader_.close();
        revoke();
        return {0U, 0U, Step::Invalid};
    }

    personalGraphicsDvcFrameReader_.close();
    revoke();
    return {0U, 0U, Step::Invalid};
}

bool LinuxRuntimeConnection::dispatchPersonalDesktopSlowPathInputPdu(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt,
    rdp_server::server::transport::RdpSlowPathInputEventSink sink) noexcept
{
    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        completeTpkt.empty() || !sink ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        !broker_->dispatchR3PersonalDesktopSlowPathInputPdu(
            &*lease_, acceptor_, connection_, session_,
            deploymentPolicy, completeTpkt, sink))
    {
        revoke();
        return false;
    }
    return true;
}

bool LinuxRuntimeConnection::authorizePersonalDesktopApplicationTraffic(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        !broker_->authorizeR3PersonalDesktopApplicationTraffic(
            *lease_, acceptor_, connection_, session_, deploymentPolicy))
    {
        revoke();
        return false;
    }
    return true;
}

bool LinuxRuntimeConnection::visitPersonalDesktopClipboardChannel(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    rdp_server::server::transport::RdpClipboardChannelVisitor visitor) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !broker_->visitR3PersonalDesktopClipboardChannel(
            &*lease_, acceptor_, connection_, session_, deploymentPolicy,
            visitor))
    {
        revoke();
        return false;
    }
    return true;
}

bool LinuxRuntimeConnection::dispatchPersonalDesktopClipboardTpkt(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt,
    rdp_server::server::transport::RdpClipboardCompletePduSink sink) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !broker_->dispatchR3PersonalDesktopClipboardTpkt(
            &*lease_, acceptor_, connection_, session_, deploymentPolicy,
            completeTpkt, sink))
    {
        revoke();
        return false;
    }
    return true;
}

std::optional<
    rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
LinuxRuntimeConnection::queuePersonalDesktopClipboardPdu(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::span<const std::uint8_t> completePdu) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        personalDesktopPolicy_ != &deploymentPolicy)
    {
        revoke();
        return std::nullopt;
    }

    auto pending = broker_->queueR3PersonalDesktopClipboardPdu(
        &*lease_, acceptor_, connection_, session_, deploymentPolicy,
        completePdu);
    if (!pending)
        revoke();
    return pending;
}

std::optional<
    rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
LinuxRuntimeConnection::pendingPersonalDesktopClipboardWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        personalDesktopPolicy_ != &deploymentPolicy)
    {
        revoke();
        return std::nullopt;
    }

    auto pending = broker_->pendingR3PersonalDesktopClipboardWrite(
        &*lease_, acceptor_, connection_, session_, deploymentPolicy);
    if (!pending &&
        session_.phase() ==
            rdp_server::server::transport::McsSessionPhase::Closed)
        revoke();
    return pending;
}

rdp_server::server::transport::RdpClipboardWriteOutcome
LinuxRuntimeConnection::completePersonalDesktopClipboardWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::uint64_t routeGeneration, std::uint64_t replySequence,
    std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::RdpClipboardWriteOutcome;

    const auto outcome =
        broker_ != nullptr && personalDesktopPolicy_ == &deploymentPolicy
            ? broker_->completeR3PersonalDesktopClipboardWrite(
                  lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
                  acceptor_, connection_, session_, deploymentPolicy,
                  routeGeneration, replySequence, writeSliceSequence,
                  acceptedBytes)
            : Outcome::Rejected;
    if (outcome == Outcome::Rejected)
        revoke();
    return outcome;
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

bool LinuxRuntimeConnection::visitNativeDesktopSelection(
    rdp_server::server::security::LinuxNativeDesktopSelectionVisitor visitor,
    void *context) noexcept
{
    if (!ready() || !broker_ || !lease_ || lease_->isRevoked() ||
        !broker_->visitNativeDesktopSelection(
            *lease_, acceptor_, connection_, visitor, context))
    {
        revoke();
        return false;
    }
    return true;
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
    // Retire untrusted post-admission framing before any authority or transport
    // owner disappears. The complete span is never retained across R2/R3 use.
    mcsConnectInitialFrameReader_.close();
    mcsConnectResponseTlsWritePending_ = false;
    mcsErectDomainFrameReader_.close();
    postAdmissionMcsPolicy_ = nullptr;
    mcsAttachConfirmTlsWritePending_ = false;
    mcsChannelJoinIoAction_ = McsChannelJoinIoAction::Idle;
    mcsChannelJoinTlsWritePending_ = false;
    personalClientLicensingFrameReader_.close();
    personalShareActivationFrameReader_.close();
    personalGraphicsDvcFrameReader_.close();
    personalGraphicsDvcIoAction_ = PersonalDesktopGraphicsDvcIoAction::Idle;
    personalGraphicsDvcTlsWritePending_ = false;
    personalShareIoAction_ = PersonalDesktopShareIoAction::Idle;
    personalShareTlsWritePending_ = false;
    personalValidClientTlsWritePending_ = false;
    personalDesktopPolicy_ = nullptr;
    personalLicenseRequestTlsWritePending_ = false;

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
