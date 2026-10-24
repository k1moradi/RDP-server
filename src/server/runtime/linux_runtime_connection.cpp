// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_connection.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <limits>
#include <string_view>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <poll.h>

namespace rdp_server::server::runtime
{
namespace
{

[[nodiscard]] constexpr const char *yesNo(bool value) noexcept
{
    return value ? "yes" : "no";
}

template <std::size_t Size>
[[nodiscard]] bool mechanismOidEquals(
    const rdp_server::server::security::
        StandaloneSpnegoMechanismOidObservation &observation,
    const std::array<std::uint8_t, Size> &expected) noexcept
{
    return !observation.oidTruncated &&
           observation.oidBytes == expected.size() &&
           std::equal(
               expected.begin(), expected.end(),
               observation.oid.begin());
}

[[nodiscard]] std::string_view knownMechanismOid(
    const rdp_server::server::security::
        StandaloneSpnegoMechanismOidObservation &observation) noexcept
{
    constexpr std::array<std::uint8_t, 10> ntlm{
        0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};
    constexpr std::array<std::uint8_t, 10> negoEx{
        0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x1e};
    constexpr std::array<std::uint8_t, 9> kerberos{
        0x2a,0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02};
    constexpr std::array<std::uint8_t, 9> microsoftKerberos{
        0x2a,0x86,0x48,0x82,0xf7,0x12,0x01,0x02,0x02};

    if (mechanismOidEquals(observation, ntlm))
        return "1.3.6.1.4.1.311.2.2.10";
    if (mechanismOidEquals(observation, negoEx))
        return "1.3.6.1.4.1.311.2.2.30";
    if (mechanismOidEquals(observation, kerberos))
        return "1.2.840.113554.1.2.2";
    if (mechanismOidEquals(observation, microsoftKerberos))
        return "1.2.840.48018.1.2.2";
    return {};
}

[[nodiscard]] bool appendDiagnosticText(
    std::span<char> output,
    std::size_t &offset,
    std::string_view text) noexcept
{
    if (offset > output.size() ||
        text.size() > output.size() - offset)
        return false;
    std::copy(
        text.begin(), text.end(),
        output.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += text.size();
    return true;
}

[[nodiscard]] std::string_view formatMechanismOids(
    const rdp_server::server::security::
        StandaloneSpnegoInitialTokenObservation &observation,
    std::array<char, 2048> &storage) noexcept
{
    constexpr std::string_view hexDigits{"0123456789abcdef"};
    std::size_t offset = 0U;
    const std::size_t mechanismCount = std::min(
        observation.mechanismCount, observation.mechanisms.size());
    if (mechanismCount == 0U)
    {
        (void)appendDiagnosticText(storage, offset, "-");
        return {storage.data(), offset};
    }

    for (std::size_t index = 0U; index < mechanismCount; ++index)
    {
        if (index != 0U &&
            !appendDiagnosticText(storage, offset, ","))
            break;

        const auto &mechanism = observation.mechanisms[index];
        const std::string_view known = knownMechanismOid(mechanism);
        if (!known.empty())
        {
            if (!appendDiagnosticText(storage, offset, known))
                break;
            continue;
        }

        if (!appendDiagnosticText(storage, offset, "derhex:"))
            break;
        for (std::size_t byteIndex = 0U;
             byteIndex < mechanism.oidBytes;
             ++byteIndex)
        {
            if (offset > storage.size() ||
                2U > storage.size() - offset)
                return {storage.data(), offset};
            const std::uint8_t value = mechanism.oid[byteIndex];
            storage[offset++] =
                hexDigits[static_cast<std::size_t>(value >> 4U)];
            storage[offset++] =
                hexDigits[static_cast<std::size_t>(value & 0x0fU)];
        }
        if (mechanism.oidTruncated &&
            !appendDiagnosticText(storage, offset, "..."))
            break;
    }
    return {storage.data(), offset};
}

[[nodiscard]] constexpr const char *spnegoDiagnosticName(
    rdp_server::server::security::StandaloneSpnegoRejectionReason reason) noexcept
{
    return reason ==
            rdp_server::server::security::StandaloneSpnegoRejectionReason::None
        ? "accepted"
        : rdp_server::server::security::
              standaloneSpnegoRejectionReasonName(reason);
}

[[nodiscard]] constexpr const char *standaloneFailureStageName(
    rdp_server::server::security::StandaloneAuthenticationFailureStage
        stage) noexcept
{
    using Stage = rdp_server::server::security::
        StandaloneAuthenticationFailureStage;
    switch (stage)
    {
    case Stage::None: return "none";
    case Stage::NtlmNegotiation: return "ntlm-negotiation";
    case Stage::Mic: return "mic";
    case Stage::SignSeal: return "sign-seal";
    case Stage::Spnego: return "spnego";
    case Stage::PubKeyAuth: return "pubkeyauth";
    case Stage::AuthInfo: return "authinfo";
    case Stage::Admission: return "admission";
    }
    return "admission";
}

} // namespace

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
    rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket,
    rdp_server::server::security::AuthenticationAttemptLimiter *attemptLimiter,
    const rdp_server::server::security::CurrentOwnerSharingAuthority
        *ownerSharingAuthority) noexcept
    : LinuxRuntimeConnection(
          securityConfiguration, std::move(acceptedSocket), attemptLimiter,
          ownerSharingAuthority, LinuxRuntimeAuthenticationSelection{})
{
}

LinuxRuntimeConnection::LinuxRuntimeConnection(
    LinuxRuntimeSecurityConfiguration &securityConfiguration,
    rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket,
    rdp_server::server::security::AuthenticationAttemptLimiter *attemptLimiter,
    const rdp_server::server::security::CurrentOwnerSharingAuthority
        *ownerSharingAuthority,
    const LinuxRuntimeAuthenticationSelection &authenticationSelection) noexcept
    : securityConfiguration_(securityConfiguration),
      connection_(
          std::move(acceptedSocket),
          rdp_server::server::transport::SecurityNegotiationPolicy::HybridNla),
      authenticationMode_(authenticationSelection.mode)
{
    const auto *const policy = securityConfiguration_.policy();
    if (!connection_.active() || policy == nullptr)
    {
        session_.close();
        connection_.cancel();
        return;
    }

    using Mode = LinuxRuntimeAuthenticationMode;
    switch (authenticationMode_)
    {
    case Mode::ExistingOsAccount:
        principalProof_ = &acceptor_;
        if (!securityConfiguration_.configureAcceptor(acceptor_))
        {
            session_.close();
            acceptor_.reject();
            connection_.cancel();
            principalProof_ = nullptr;
            return;
        }

        // The real serialized listener always supplies the service-wide peer
        // and account budget. Offline fixtures may omit it, but no service
        // invocation can bypass it.
        if (attemptLimiter != nullptr &&
            !acceptor_.bindVerifiedAccountAttemptLimiter(*attemptLimiter))
        {
            session_.close();
            acceptor_.reject();
            connection_.cancel();
            principalProof_ = nullptr;
            return;
        }
        break;

    case Mode::StandalonePassword:
    {
        const auto *const credentialOwner =
            authenticationSelection.standaloneCredentialOwner;
        const std::uint64_t credentialGeneration =
            authenticationSelection.standaloneCredentialGeneration;
        const auto observation =
            credentialOwner != nullptr
                ? credentialOwner->observation()
                : rdp_server::server::security::
                      StandalonePasswordCredentialObservation{};
        if (credentialOwner == nullptr || credentialGeneration == 0 ||
            !observation.configured ||
            observation.generation != credentialGeneration ||
            !standaloneCredSspAcceptor_.configureChallenge(
                authenticationSelection.standaloneChallenge))
        {
            session_.close();
            standaloneCredSspAcceptor_.reset();
            connection_.cancel();
            return;
        }
        standaloneCredentialOwner_ = credentialOwner;
        standaloneCredentialGeneration_ = credentialGeneration;
        principalProof_ = &standalonePrincipalProof_;
        break;
    }
    }

    // The host-level R2 authority is borrowed for the complete connection
    // lifetime. nullptr deliberately preserves the legacy deny-only caller.
    broker_.emplace(*policy, ownerSharingAuthority);
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
    return broker_.has_value() && authenticationOwnerHealthy() &&
           session_.phase() !=
               rdp_server::server::transport::McsSessionPhase::Closed;
}

LinuxRuntimeConnectionAcceptanceDiagnostics
LinuxRuntimeConnection::acceptanceDiagnostics() const noexcept
{
    using Stage = rdp_server::server::transport::PreauthStage;
    LinuxRuntimeConnectionAcceptanceDiagnostics snapshot{};
    snapshot.preauthStage = connection_.stage();
    snapshot.negotiatedSecurityProtocol = negotiatedSecurityProtocol_;
    snapshot.negotiatedTlsProtocolVersion = negotiatedTlsProtocolVersion_;
    snapshot.credSspTransition = credSspDiagnosticTransition_;
    snapshot.standaloneNegotiationEnvelope =
        standaloneCredSspAcceptor_.initialNegoObservation()
            .spnego.negotiationEnvelope;
    snapshot.standalonePasswordSelected =
        authenticationMode_ ==
        LinuxRuntimeAuthenticationMode::StandalonePassword;
    snapshot.standaloneCredentialGeneration =
        snapshot.standalonePasswordSelected
            ? standaloneCredentialGeneration_
            : 0U;
    snapshot.standaloneAuthenticationFailureStage =
        standaloneAuthenticationFailureStage_;
    snapshot.mcsPhase = session_.phase();
    snapshot.shareActivated =
        snapshot.mcsPhase ==
        rdp_server::server::transport::McsSessionPhase::ShareActivated;
    snapshot.termination = connection_.termination();
    snapshot.tlsHandshake = connection_.tlsHandshakeDiagnostics();
    snapshot.certificateSha256 = negotiatedCertificateSha256_;
    snapshot.certificateFingerprintAvailable =
        negotiatedCertificateFingerprintAvailable_;
    snapshot.certificateExactIpSelfCheck = certificateExactIpSelfCheck_;
    snapshot.selectedCertificateIdentityChecked =
        selectedCertificateIdentityChecked_;
    snapshot.selectedCertificateMatchesRuntimeIdentity =
        selectedCertificateMatchesRuntimeIdentity_;

    if (!connection_.active())
        snapshot.tlsHandshakeStage =
            LinuxRuntimeTlsHandshakeDiagnosticStage::Closed;
    else if (tlsEverEstablished_)
        snapshot.tlsHandshakeStage =
            LinuxRuntimeTlsHandshakeDiagnosticStage::Established;
    else if (snapshot.preauthStage == Stage::AwaitTls)
        snapshot.tlsHandshakeStage =
            LinuxRuntimeTlsHandshakeDiagnosticStage::Handshaking;
    else
        snapshot.tlsHandshakeStage =
            LinuxRuntimeTlsHandshakeDiagnosticStage::NotStarted;
    return snapshot;
}

void LinuxRuntimeConnection::captureEstablishedTlsDiagnostics() noexcept
{
    const SSL *const tls = connection_.establishedTls();
    if (tls == nullptr)
        return;

    tlsEverEstablished_ = true;
    negotiatedTlsProtocolVersion_ = ::SSL_version(tls);
    if (const auto provenance = connection_.securityNegotiationProvenance())
        negotiatedSecurityProtocol_ = provenance->serverSelectedProtocol;

    X509 *const certificate = ::SSL_get_certificate(const_cast<SSL *>(tls));
    unsigned int fingerprintBytes = 0U;
    RuntimeTlsCertificateFingerprint fingerprint{};
    if (certificate != nullptr &&
        ::X509_digest(certificate, ::EVP_sha256(), fingerprint.data(),
                      &fingerprintBytes) == 1 &&
        fingerprintBytes == fingerprint.size())
    {
        negotiatedCertificateSha256_ = fingerprint;
        negotiatedCertificateFingerprintAvailable_ = true;
    }
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

bool LinuxRuntimeConnection::authenticationOwnerHealthy() const noexcept
{
    using Mode = LinuxRuntimeAuthenticationMode;
    if (principalProof_ == nullptr)
        return false;

    if (authenticationMode_ == Mode::ExistingOsAccount)
    {
        return acceptor_.stage() !=
            rdp_server::server::security::SpnegoStage::Failed;
    }

    if (standaloneCredentialOwner_ == nullptr ||
        standaloneCredentialGeneration_ == 0)
    {
        return false;
    }
    const auto observation = standaloneCredentialOwner_->observation();
    const auto stage = standaloneCredSspAcceptor_.stage();
    return observation.configured &&
           observation.generation == standaloneCredentialGeneration_ &&
           stage != rdp_server::server::security::StandaloneCredSspStage::Failed &&
           stage != rdp_server::server::security::StandaloneCredSspStage::Unconfigured;
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
        personalGraphicsDvcTlsWritePending_ ||
        personalClipboardTlsRetryPending_;

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
        .clipboardWritePending = personalClipboardWriteInProgress_,
    });
}

int LinuxRuntimeConnection::nativeSocketPollDescriptor() const noexcept
{
    if (!ready())
        return -1;
    const auto socket = connection_.nativeSocket();
    if (socket >
        static_cast<std::uintptr_t>((std::numeric_limits<int>::max)()))
        return -1;
    return static_cast<int>(socket);
}

bool LinuxRuntimeConnection::bufferedTlsApplicationReadReady() const noexcept
{
    using Interest = rdp_server::server::transport::TcpConnectionIoInterest;
    return ready() && ioInterest() == Interest::Read &&
           connection_.tlsApplicationReadReady();
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

    // Drain R1-owned decrypted plaintext before sleeping for a new POLLIN.
    // ioInterest() preserves a pending SSL WANT direction; R1's readiness
    // predicate declines pending writes and read-side WANT_WRITE. This is
    // readiness only: no TLS bytes, socket operation or R2 lease is created.
    if (detail::shouldDispatchBufferedTlsApplicationRead(
            requested, connection_.tlsApplicationReadReady()))
        return {true, false, Status::Ready};

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

    if ((ready.revents & POLLNVAL) != 0)
    {
        revoke();
        return {false, false, Status::Failure};
    }

    // HUP/POLLERR are dispatched once in the currently requested direction so
    // the sole R1 recv/send/TLS owner observes EOF/reset and records the real
    // terminal classification. The scheduler must not rewrite a peer reset as
    // generic cancellation before R1 consumes the native error.
    const bool terminalTransportEvent =
        (ready.revents & (POLLHUP | POLLERR)) != 0;
    const bool readable =
        (ready.revents & POLLIN) != 0 || terminalTransportEvent;
    const bool writable =
        (ready.revents & POLLOUT) != 0 || terminalTransportEvent;
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
            captureEstablishedTlsDiagnostics();
            credSspDiagnosticTransition_ =
                LinuxRuntimeCredSspDiagnosticTransition::AwaitingToken;
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

void LinuxRuntimeConnection::configureTlsIdentityDiagnostics(
    const RuntimeServerTlsContext &tlsContext,
    std::string_view numericEndpoint) noexcept
{
    certificateExactIpSelfCheck_ =
        tlsContext.validateEndpointIdentity(numericEndpoint);
    RuntimeTlsCertificateFingerprint fingerprint{};
    negotiatedCertificateFingerprintAvailable_ =
        tlsContext.certificateSha256Fingerprint(fingerprint);
    if (negotiatedCertificateFingerprintAvailable_)
        negotiatedCertificateSha256_ = fingerprint;
}

bool LinuxRuntimeConnection::attachServerTls(
    const RuntimeServerTlsContext &tlsContext) noexcept
{
    if (!ready())
    {
        return false;
    }

    // R1 certificate continuity is an attach invariant, not a hidden
    // prerequisite on configureTlsIdentityDiagnostics(). Compare the fresh
    // SSL leaf directly with this exact R10 context. If descriptive endpoint
    // diagnostics already projected a fingerprint, also require that snapshot
    // to still describe the same context.
    RuntimeTlsCertificateFingerprint runtimeFingerprint{};
    const bool runtimeFingerprintAvailable =
        tlsContext.certificateSha256Fingerprint(runtimeFingerprint);
    const bool projectedFingerprintMatchesRuntime =
        !negotiatedCertificateFingerprintAvailable_ ||
        (runtimeFingerprintAvailable &&
         ::CRYPTO_memcmp(
             runtimeFingerprint.data(),
             negotiatedCertificateSha256_.data(),
             runtimeFingerprint.size()) == 0);

    auto serverTls = tlsContext.createServerTls();
    if (serverTls)
    {
        selectedCertificateIdentityChecked_ = true;
        RuntimeTlsCertificateFingerprint selectedFingerprint{};
        unsigned int selectedFingerprintBytes = 0U;
        X509 *const selectedCertificate = ::SSL_get_certificate(serverTls.get());
        selectedCertificateMatchesRuntimeIdentity_ =
            runtimeFingerprintAvailable &&
            projectedFingerprintMatchesRuntime &&
            selectedCertificate != nullptr &&
            ::X509_digest(
                selectedCertificate, ::EVP_sha256(),
                selectedFingerprint.data(), &selectedFingerprintBytes) == 1 &&
            selectedFingerprintBytes == selectedFingerprint.size() &&
            ::CRYPTO_memcmp(
                selectedFingerprint.data(),
                runtimeFingerprint.data(),
                selectedFingerprint.size()) == 0;
        ::OPENSSL_cleanse(
            selectedFingerprint.data(), selectedFingerprint.size());
    }
    ::OPENSSL_cleanse(runtimeFingerprint.data(), runtimeFingerprint.size());

    if (!serverTls || !selectedCertificateMatchesRuntimeIdentity_ ||
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
    if (result ==
        rdp_server::server::transport::TlsHandshakeStatus::Established)
    {
        captureEstablishedTlsDiagnostics();
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::AwaitingToken;
    }
    else if (
        result == rdp_server::server::transport::TlsHandshakeStatus::Invalid ||
        result == rdp_server::server::transport::TlsHandshakeStatus::Closed)
    {
        revoke();
    }
    return result;
}

void LinuxRuntimeConnection::recordStandaloneAuthenticationFailure(
    rdp_server::server::security::StandaloneAuthenticationFailureStage
        failureStage) noexcept
{
    using Stage = rdp_server::server::security::
        StandaloneAuthenticationFailureStage;
    if (authenticationMode_ !=
            LinuxRuntimeAuthenticationMode::StandalonePassword ||
        failureStage == Stage::None ||
        standaloneAuthenticationFailureStage_ != Stage::None)
    {
        return;
    }

    standaloneAuthenticationFailureStage_ = failureStage;
    const auto initial =
        standaloneCredSspAcceptor_.initialNegoObservation();
    if (!initial.observed)
    {
        std::fprintf(
            stderr,
            "rdp-server: standalone authentication failed: stage=%s; "
            "tls=%s; credssp=spnego-initial; "
            "os-gss-fallback=disabled; spnego-initial=unobserved; "
            "spnego=%s\n",
            standaloneFailureStageName(failureStage),
            tlsEverEstablished_ ? "established" : "not-established",
            spnegoDiagnosticName(
                standaloneCredSspAcceptor_.spnegoRejectionReason()));
        return;
    }

    const auto &spnego = initial.spnego;
    if (spnego.negotiationEnvelope ==
        rdp_server::server::security::
            StandaloneNtlmNegotiationEnvelope::DirectNtlm)
    {
        std::fprintf(
            stderr,
            "rdp-server: standalone authentication failed: stage=%s; "
            "tls=%s; credssp=direct-ntlm; os-gss-fallback=disabled; "
            "tsrequest-version=%u; nego-token-count=%zu; token-bytes=%zu; "
            "top-tag=0x%02x; gss-initial-context-token=%s; "
            "mechanism-count=%zu; ntlm-offered=%s; "
            "direct-ntlm-type1=%s; spnego=not-used\n",
            standaloneFailureStageName(failureStage),
            tlsEverEstablished_ ? "established" : "not-established",
            static_cast<unsigned int>(initial.tsRequestVersion),
            initial.tokenCount,
            spnego.tokenBytes,
            static_cast<unsigned int>(spnego.topLevelTag),
            yesNo(spnego.gssInitialContextToken),
            spnego.mechanismCount,
            yesNo(spnego.ntlmOffered),
            spnego.directNtlmType1Accepted ? "accepted" : "rejected");
        return;
    }

    std::array<char, 2048> mechanismOidStorage{};
    const std::string_view mechanismOids =
        formatMechanismOids(spnego, mechanismOidStorage);
    const int ntlmMechanismIndex =
        spnego.ntlmMechanismIndex ==
                rdp_server::server::security::
                    kStandaloneSpnegoNoMechanismIndex
            ? -1
            : static_cast<int>(spnego.ntlmMechanismIndex);

    std::fprintf(
        stderr,
        "rdp-server: standalone authentication failed: stage=%s; "
        "tls=%s; credssp=spnego-initial; os-gss-fallback=disabled; "
        "nego-envelope=%s; tsrequest-version=%u; nego-token-count=%zu; "
        "token-bytes=%zu; "
        "top-tag=0x%02x; gss-initial-context-token=%s; "
        "neg-token-init=%s; neg-token-init2=%s; req-flags=%s; "
        "neg-hints=%s; mech-list-mic=%s; mechanism-count=%zu; "
        "mechanism-oids=%.*s; ntlm-offered=%s; ntlm-index=%d; "
        "optimistic-token=%s; optimistic-token-bytes=%zu; "
        "spnego=%s\n",
        standaloneFailureStageName(failureStage),
        tlsEverEstablished_ ? "established" : "not-established",
        rdp_server::server::security::standaloneNtlmNegotiationEnvelopeName(
            spnego.negotiationEnvelope),
        static_cast<unsigned int>(initial.tsRequestVersion),
        initial.tokenCount,
        spnego.tokenBytes,
        static_cast<unsigned int>(spnego.topLevelTag),
        yesNo(spnego.gssInitialContextToken),
        yesNo(spnego.negTokenInit),
        yesNo(spnego.negTokenInit2),
        yesNo(spnego.reqFlagsPresent),
        yesNo(spnego.negHintsPresent),
        yesNo(spnego.mechListMicPresent),
        spnego.mechanismCount,
        static_cast<int>(mechanismOids.size()),
        mechanismOids.data(),
        yesNo(spnego.ntlmOffered),
        ntlmMechanismIndex,
        yesNo(spnego.optimisticMechanismTokenPresent),
        spnego.optimisticMechanismTokenBytes,
        spnego.negotiationEnvelope ==
                rdp_server::server::security::
                    StandaloneNtlmNegotiationEnvelope::DirectNtlm
            ? "not-used"
            : spnegoDiagnosticName(spnego.rejectionReason));
}

LinuxCredSspStepResult LinuxRuntimeConnection::advanceStandaloneCredSsp() noexcept
{
    using FrameStatus =
        rdp_server::server::security::StandaloneCredSspFrameStatus;
    using ReadStatus =
        rdp_server::server::security::TsRequestTlsReadStatus;
    using WriteStatus =
        rdp_server::server::security::TsRequestTlsWriteStatus;
    using Step = LinuxCredSspStepStatus;

    auto fail = [&](Step status, std::size_t bytesRead = 0U,
                    std::size_t bytesWritten = 0U) noexcept {
        auto failureStage = standaloneCredSspAcceptor_.failureStage();
        if (failureStage ==
            rdp_server::server::security::
                StandaloneAuthenticationFailureStage::None)
        {
            failureStage =
                rdp_server::server::security::
                    StandaloneAuthenticationFailureStage::Admission;
        }
        recordStandaloneAuthenticationFailure(failureStage);
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::Failed;
        credSspFrameReader_.close();
        credSspReplyWriter_.close();
        if (principalProof_ != nullptr)
            principalProof_->revokeAuthenticatedProof();
        standaloneCredSspAcceptor_.reset();
        standaloneReplyPending_ = false;
        standaloneBindingReplyPending_ = false;
        return LinuxCredSspStepResult{bytesRead, bytesWritten, status};
    };

    if (!connection_.active())
        return fail(Step::Closed);
    if (standaloneCredentialOwner_ == nullptr ||
        standaloneCredentialGeneration_ == 0)
    {
        return fail(Step::Invalid);
    }
    const auto observation = standaloneCredentialOwner_->observation();
    if (!observation.configured ||
        observation.generation != standaloneCredentialGeneration_)
    {
        return fail(Step::Invalid);
    }

    if (standaloneReplyPending_)
    {
        const auto written = credSspReplyWriter_.writeOneTlsStep(connection_);
        switch (written.status)
        {
        case WriteStatus::Progress:
            return {0U, written.plaintextBytesWritten, Step::Progress};
        case WriteStatus::NeedRead:
            return {0U, 0U, Step::NeedRead};
        case WriteStatus::NeedWrite:
            return {0U, 0U, Step::NeedWrite};
        case WriteStatus::Complete:
        {
            if (!credSspReplyWriter_.releaseReply())
                return fail(Step::Invalid, 0U, written.plaintextBytesWritten);
            standaloneReplyPending_ = false;
            if (standaloneBindingReplyPending_)
            {
                standaloneBindingReplyPending_ = false;
                credSspDiagnosticTransition_ =
                    LinuxRuntimeCredSspDiagnosticTransition::BindingVerified;
                return {0U, written.plaintextBytesWritten,
                        Step::BindingVerified};
            }
            return {0U, written.plaintextBytesWritten, Step::Progress};
        }
        case WriteStatus::Invalid:
            return fail(Step::Invalid);
        case WriteStatus::Closed:
            return fail(connection_.active() ? Step::Invalid : Step::Closed);
        case WriteStatus::Idle:
            return fail(Step::Invalid);
        }
    }

    if (credSspReplyWriter_.status() != WriteStatus::Idle)
        return fail(Step::Invalid);

    // This one reader/writer pair is retained for the accepted connection.
    // SPNEGO and DirectNtlm therefore traverse the exact same R1 owner,
    // transport generation, established SSL and selected-certificate pin from
    // Type 1 through Type 2/Type 3, pubKeyAuth and final authInfo.
    std::size_t bytesRead = 0U;
    if (credSspFrameReader_.status() ==
        rdp_server::server::security::TsRequestFrameStatus::NeedMore)
    {
        const auto read = credSspFrameReader_.readOneTlsStep(connection_);
        bytesRead = read.plaintextBytesRead;
        switch (read.status)
        {
        case ReadStatus::Progress:
            return {bytesRead, 0U, Step::Progress};
        case ReadStatus::NeedRead:
            return {0U, 0U, Step::NeedRead};
        case ReadStatus::NeedWrite:
            return {0U, 0U, Step::NeedWrite};
        case ReadStatus::Complete:
            break;
        case ReadStatus::Closed:
            return fail(connection_.active() ? Step::Invalid : Step::Closed,
                        bytesRead, 0U);
        case ReadStatus::Invalid:
            return fail(Step::Invalid, bytesRead, 0U);
        }
    }
    else if (credSspFrameReader_.status() !=
             rdp_server::server::security::TsRequestFrameStatus::Complete)
    {
        return fail(Step::Invalid);
    }

    struct CredentialVisitContext final
    {
        rdp_server::server::security::StandaloneCredSspNtlmAcceptor *acceptor{};
        rdp_server::server::transport::OwnedPreauthTcpConnection *connection{};
        rdp_server::server::security::TsRequestFrameReader *reader{};
        rdp_server::server::security::TsRequestTlsReplyWriter *writer{};
        FrameStatus status{FrameStatus::Rejected};
    } visitContext{
        &standaloneCredSspAcceptor_, &connection_,
        &credSspFrameReader_, &credSspReplyWriter_};

    const auto visitor =
        +[](const rdp_server::server::security::EphemeralNtlmV2Credential
                &credential,
            void *opaque) noexcept -> bool {
            auto *context =
                static_cast<CredentialVisitContext *>(opaque);
            if (context == nullptr || context->acceptor == nullptr ||
                context->connection == nullptr || context->reader == nullptr ||
                context->writer == nullptr)
            {
                return false;
            }
            context->status = context->acceptor->processCompleteOwnedFrame(
                *context->connection, *context->reader, *context->writer,
                credential);
            return true;
        };

    if (!standaloneCredentialOwner_->visit(
            standaloneCredentialGeneration_, visitor, &visitContext))
    {
        return fail(Step::Invalid, bytesRead, 0U);
    }

    switch (visitContext.status)
    {
    case FrameStatus::NegoReplyQueued:
        if (credSspReplyWriter_.status() != WriteStatus::NeedWrite)
            return fail(Step::Invalid, bytesRead, 0U);
        standaloneReplyPending_ = true;
        return {bytesRead, 0U, Step::NeedWrite};
    case FrameStatus::BindingReplyQueued:
        if (credSspReplyWriter_.status() != WriteStatus::NeedWrite)
            return fail(Step::Invalid, bytesRead, 0U);
        standaloneReplyPending_ = true;
        standaloneBindingReplyPending_ = true;
        return {bytesRead, 0U, Step::NeedWrite};
    case FrameStatus::CredentialsVerified:
        if (!standalonePrincipalProof_.bind(
                standaloneCredSspAcceptor_, *standaloneCredentialOwner_,
                standaloneCredentialGeneration_, connection_))
        {
            return fail(Step::Invalid, bytesRead, 0U);
        }
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::CredentialsVerified;
        return {bytesRead, 0U, Step::CredentialsVerified};
    case FrameStatus::Rejected:
        return fail(Step::Invalid, bytesRead, 0U);
    }
    return fail(Step::Invalid, bytesRead, 0U);
}

LinuxCredSspStepResult LinuxRuntimeConnection::onCredSspIoReady() noexcept
{
    if (!provisioned_ || !connection_.active())
        return {0U, 0U, LinuxCredSspStepStatus::Closed};

    if (authenticationMode_ ==
        LinuxRuntimeAuthenticationMode::StandalonePassword)
    {
        return advanceStandaloneCredSsp();
    }

    using HandshakeStatus =
        rdp_server::server::security::OwnedCredSspHandshakeStatus;

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
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::BindingVerified;
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::BindingVerified};
    case HandshakeStatus::CredentialsVerified:
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::CredentialsVerified;
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::CredentialsVerified};
    case HandshakeStatus::UnsupportedFinalCredentials:
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::Failed;
        revoke();
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::UnsupportedFinalCredentials};
    case HandshakeStatus::Rejected:
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::Failed;
        revoke();
        return {result.plaintextBytesRead, result.plaintextBytesWritten,
                LinuxCredSspStepStatus::Invalid};
    case HandshakeStatus::TransportClosed:
        credSspDiagnosticTransition_ =
            LinuxRuntimeCredSspDiagnosticTransition::Closed;
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
    auto *const proof = authenticatedPrincipalProof();
    const bool mechanismReady =
        authenticationMode_ == LinuxRuntimeAuthenticationMode::ExistingOsAccount
            ? acceptor_.stage() ==
                  rdp_server::server::security::SpnegoStage::ServerBindingPrepared
            : standaloneCredSspAcceptor_.stage() ==
                  rdp_server::server::security::StandaloneCredSspStage::
                      CredentialsVerified;
    const auto expectedAuthenticationKind =
        authenticationMode_ == LinuxRuntimeAuthenticationMode::ExistingOsAccount
            ? rdp_server::server::security::
                  ConsoleEvidenceAuthenticationKind::KerberosPrincipal
            : rdp_server::server::security::
                  ConsoleEvidenceAuthenticationKind::StandalonePassword;
    if (!ready() || credSspReplyPending() || !broker_ || lease_ ||
        proof == nullptr || !mechanismReady ||
        request.authenticationKind != expectedAuthenticationKind)
    {
        if (authenticationMode_ ==
            LinuxRuntimeAuthenticationMode::StandalonePassword)
        {
            recordStandaloneAuthenticationFailure(
                rdp_server::server::security::
                    StandaloneAuthenticationFailureStage::Admission);
        }
        revoke();
        return false;
    }

    auto issued = broker_->issue(*proof, connection_, request);
    if (!issued)
    {
        if (authenticationMode_ ==
            LinuxRuntimeAuthenticationMode::StandalonePassword)
        {
            recordStandaloneAuthenticationFailure(
                rdp_server::server::security::
                    StandaloneAuthenticationFailureStage::Admission);
        }
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
        *lease_, *principalProof_, connection_, session_, completeTpkt);
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

    if (!broker_->revalidate(*lease_, *principalProof_, connection_))
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
        *lease_, *principalProof_, connection_, session_);
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
            *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_, completeTpkt);
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
            *lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_, completeTpkt);
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
        *lease_, *principalProof_, connection_, session_);
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
            *principalProof_, connection_, session_,
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
                *lease_, *principalProof_, connection_, session_,
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
                *lease_, *principalProof_, connection_, session_, completeTpkt);
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
        *lease_, *principalProof_, connection_, session_);
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
            *principalProof_, connection_, session_,
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
                *lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_, completeTpkt)
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy))
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
                *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_,
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
                *lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy);
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
                *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy);
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
            lease, *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
                *lease_, *principalProof_, connection_, session_, deploymentPolicy);
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
                    *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_,
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
                *lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
        case Intake::InputIgnoredUntilActivated:
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy);
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
            lease, *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy);
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


rdp_server::server::transport::RdpGraphicsFramePublicationReadiness
LinuxRuntimeConnection::preflightPersonalDesktopGraphicsFramePublication(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::uint32_t frameId) noexcept
{
    using Readiness =
        rdp_server::server::transport::RdpGraphicsFramePublicationReadiness;
    if (frameId == 0U ||
        personalGraphicsDvcIoAction_ != PersonalDesktopGraphicsDvcIoAction::Ready ||
        personalGraphicsDvcTlsWritePending_ ||
        personalClipboardWriteInProgress_ ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() != 1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return Readiness::Rejected;
    }

    // This R2-protected observation does not reserve R4 credit or authorize
    // subsequent capture. Frame start performs another fresh R2 transition.
    const auto readiness =
        broker_->preflightR3PersonalDesktopGraphicsFramePublication(
            *lease_, *principalProof_, connection_, session_, deploymentPolicy, frameId);
    if (readiness == Readiness::Rejected)
        revoke();
    return readiness;
}

rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration
LinuxRuntimeConnection::beginPersonalDesktopGraphicsSurfaceReconfiguration(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    ::PixelSize desktopGeometry) noexcept
{
    using Action = PersonalDesktopGraphicsDvcIoAction;
    using Decision =
        rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration;

    if (desktopGeometry.widthPixels == 0U ||
        desktopGeometry.heightPixels == 0U ||
        personalGraphicsDvcIoAction_ != Action::Ready ||
        personalGraphicsDvcTlsWritePending_ ||
        personalClipboardWriteInProgress_ ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return Decision::Rejected;
    }

    const Decision decision =
        broker_->beginR3PersonalDesktopGraphicsSurfaceReconfiguration(
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
            desktopGeometry);
    if (decision == Decision::Started)
    {
        // R3 has queued DELETE on its existing writer. CREATE and MAP are
        // chained only by exact accepted-byte receipts through advance...
        personalGraphicsDvcTlsWritePending_ = false;
        personalGraphicsDvcIoAction_ = Action::Write;
    }
    else if (decision == Decision::Rejected)
    {
        revoke();
    }
    return decision;
}

bool LinuxRuntimeConnection::
startPersonalDesktopClearCodecFramePublication(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::uint32_t frameId,
    ::FramebufferView framebuffer) noexcept
{
    using Action = PersonalDesktopGraphicsDvcIoAction;
    using Kind =
        rdp_server::server::transport::RdpGraphicsDvcWriteKind;

    if (personalGraphicsDvcIoAction_ != Action::Ready ||
        personalGraphicsDvcTlsWritePending_ ||
        personalClipboardWriteInProgress_ ||
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
        broker_->authorizeR3PersonalDesktopClearCodecFramePublication(
            *lease_, *principalProof_, connection_, session_,
            deploymentPolicy, frameId, framebuffer);
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
            *lease_, *principalProof_, connection_, session_,
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
                    *lease_, *principalProof_, connection_, session_,
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
                        *principalProof_, connection_, session_, deploymentPolicy,
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
            case Kind::GraphicsCreateSurface:
                personalGraphicsDvcIoAction_ = Action::Write;
                return {0U, io.bytes, Step::Progress};
            case Kind::GraphicsDeleteSurface:
                // R3 completes DELETE by queuing CREATE (Pending), never by
                // returning Delivered. This is only an exhaustive deny path;
                // R10 still owns any future native resize scheduling.
                break;
            case Kind::GraphicsMapSurfaceToOutput:
                // Retain the same bounded frame reader for serialized
                // post-Share application packets and client FRAME_ACK intake.
                if (!personalGraphicsDvcFrameReader_.reset())
                {
                    revoke();
                    return {0U, io.bytes, Step::Invalid};
                }
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
            *lease_, *principalProof_, connection_, session_,
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
                    *lease_, *principalProof_, connection_, session_,
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

rdp_server::server::transport::RdpPostShareTpktRoute
LinuxRuntimeConnection::classifyPersonalDesktopPostShareTpkt(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Kind = rdp_server::server::transport::RdpPostShareTpktRouteKind;
    using Action = PersonalDesktopGraphicsDvcIoAction;

    if (personalGraphicsDvcIoAction_ != Action::Ready ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        completeTpkt.empty() || !ready() || !broker_ || !lease_ ||
        lease_->isRevoked())
    {
        revoke();
        return {};
    }

    // R2 revalidates the native owner both before and after R3's read-only
    // route inspection. No route is an authorization grant to its consumer.
    const auto route = broker_->classifyR3PersonalDesktopPostShareTpkt(
        *lease_, *principalProof_, connection_, session_, deploymentPolicy,
        completeTpkt);
    if (route.kind == Kind::UnsupportedOrMalformed ||
        route.completeTpkt.data() != completeTpkt.data() ||
        route.completeTpkt.size() != completeTpkt.size())
    {
        revoke();
        return {};
    }
    return route;
}

LinuxPostShareApplicationReadResult
LinuxRuntimeConnection::advancePersonalDesktopPostShareApplicationRead(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable, LinuxPostShareTpktSink sink) noexcept
{
    using Step = LinuxPostShareApplicationReadStatus;
    using Action = PersonalDesktopGraphicsDvcIoAction;
    using Interest = rdp_server::server::transport::TcpConnectionIoInterest;
    using IoOutcome = rdp_server::server::transport::TlsApplicationIoOutcome;
    using FrameStatus = LinuxRuntimeMcsTpktFrameStatus;

    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !sink || !ready() || !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return {0U, Step::AdmissionDenied};
    }
    if (personalGraphicsDvcIoAction_ == Action::Write)
    {
        // R1's pending TLS write and R3 receipt must finish first. WANT_READ
        // is part of that same write, not permission to read another TPKT.
        return {0U, ioInterest() == Interest::Read
                         ? Step::NeedRead : Step::NeedWrite};
    }
    if (personalClipboardWriteInProgress_)
    {
        // A positive-partial static-VC TPKT or SSL WANT remains the sole R1
        // writer; reading a new application TPKT here would interleave it.
        return {0U, personalClipboardTlsRetryPending_ &&
                          ioInterest() == Interest::Read
                         ? Step::NeedRead : Step::NeedWrite};
    }
    if (personalGraphicsDvcIoAction_ != Action::Ready ||
        !broker_->authorizeR3ProtectedTransition(
            *lease_, *principalProof_, connection_, session_,
            rdp_server::server::security::kConsoleViewPermission))
    {
        personalGraphicsDvcFrameReader_.close();
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
        required == Interest::Read && connection_.tlsApplicationReadReady();
    if (required == Interest::Read && !readable && !bufferedRead)
        return {0U, Step::NeedRead};
    if (required == Interest::Write && !writable)
        return {0U, Step::NeedWrite};
    if (required != Interest::Read && required != Interest::Write)
    {
        revoke();
        return {0U, Step::Invalid};
    }

    constexpr std::size_t kReadChunkBytes = 512U;
    std::array<std::uint8_t, kReadChunkBytes> plaintext{};
    const std::size_t needed = personalGraphicsDvcFrameReader_.bytesNeeded();
    if (needed == 0U ||
        needed > rdp_server::server::transport::kMaximumInitialMcsTpktBytes)
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
        const auto framed = personalGraphicsDvcFrameReader_.consume(
            std::span<const std::uint8_t>{plaintext}.first(io.bytes));
        std::fill(plaintext.begin(), plaintext.begin() + io.bytes, 0U);
        if (framed.bytesConsumed != io.bytes ||
            framed.status == FrameStatus::Invalid ||
            framed.status == FrameStatus::Closed)
        {
            revoke();
            return {io.bytes, Step::Invalid};
        }
        if (framed.status == FrameStatus::NeedMore)
            return {io.bytes, Step::Progress};

        const auto completeTpkt = personalGraphicsDvcFrameReader_.completeTpkt();
        const auto route = classifyPersonalDesktopPostShareTpkt(
            deploymentPolicy, completeTpkt);
        if (!ready() ||
            route.kind == rdp_server::server::transport::
                              RdpPostShareTpktRouteKind::UnsupportedOrMalformed ||
            !sink.consume(sink.context, route.kind, route.completeTpkt) ||
            !ready() || !personalGraphicsDvcFrameReader_.reset())
        {
            revoke();
            return {io.bytes, Step::AdmissionDenied};
        }
        return {io.bytes, Step::Routed};
    }
    case IoOutcome::NeedRead: return {0U, Step::NeedRead};
    case IoOutcome::NeedWrite: return {0U, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        revoke();
        return {0U, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        revoke();
        return {0U, Step::Invalid};
    }
    revoke();
    return {0U, Step::Invalid};
}

bool LinuxRuntimeConnection::dispatchPersonalDesktopPostShareGraphicsTpkt(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Intake = rdp_server::server::transport::RdpGraphicsDvcClientIntake;
    using Ack = rdp_server::server::transport::RdpGraphicsFrameAcknowledgeIntake;

    if (personalGraphicsDvcIoAction_ != PersonalDesktopGraphicsDvcIoAction::Ready ||
        personalDesktopPolicy_ != &deploymentPolicy ||
        completeTpkt.empty() || !ready() || !broker_ || !lease_ ||
        lease_->isRevoked())
    {
        revoke();
        return false;
    }
    const auto intake =
        broker_->authorizeR3PersonalDesktopGraphicsDynamicVirtualChannelPdu(
            *lease_, *principalProof_, connection_, session_, deploymentPolicy,
            completeTpkt);
    if (intake == Intake::GraphicsDataFragmentAccepted)
        return ready();
    if (intake != Intake::GraphicsDataAccepted)
    {
        revoke();
        return false;
    }
    const auto ack = broker_->consumeR3PersonalDesktopGraphicsFrameAcknowledge(
        *lease_, *principalProof_, connection_, session_, deploymentPolicy);
    if (ack == Ack::Rejected || !ready())
    {
        revoke();
        return false;
    }
    return true;
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
            &*lease_, *principalProof_, connection_, session_,
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
            *lease_, *principalProof_, connection_, session_, deploymentPolicy))
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
            &*lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
            &*lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
        &*lease_, *principalProof_, connection_, session_, deploymentPolicy,
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
        &*lease_, *principalProof_, connection_, session_, deploymentPolicy);
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
        broker_.has_value() && personalDesktopPolicy_ == &deploymentPolicy
            ? broker_->completeR3PersonalDesktopClipboardWrite(
                  lease_ && !lease_->isRevoked() ? &*lease_ : nullptr,
                  *principalProof_, connection_, session_, deploymentPolicy,
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
        broker_->onNativeSessionChangeReady(*principalProof_, session_);
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
            *lease_, *principalProof_, connection_, visitor, context))
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

bool LinuxRuntimeConnection::releaseNativeChangeWithoutDispatch(
    const LinuxRuntimeNativeChangeRegistration &registration) noexcept
{
    if (!nativeChangeRegistrationUnregistered_ ||
        !nativeChangeRegistrationMatches(registration))
        return false;

    // The poll call is over and its stack descriptor set is gone. No native
    // event was delivered, so do not invoke R2's logind callback needlessly.
    nativeChangeRegistration_.reset();
    nativeChangeRegistrationUnregistered_ = false;
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
            *lease_, *principalProof_, connection_, session_,
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


LinuxClipboardTlsWriteResult
LinuxRuntimeConnection::advancePersonalDesktopClipboardTlsWrite(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    bool readable, bool writable) noexcept
{
    using Step = LinuxClipboardTlsWriteStatus;
    using Outcome = rdp_server::server::transport::RdpClipboardWriteOutcome;
    using IoOutcome = rdp_server::server::transport::TlsApplicationIoOutcome;
    using Interest = rdp_server::server::transport::TcpConnectionIoInterest;

    if (!ready())
        return {0U, Outcome::Rejected, Step::Closed};

    if (personalDesktopPolicy_ != &deploymentPolicy ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        personalGraphicsDvcIoAction_ !=
            PersonalDesktopGraphicsDvcIoAction::Ready ||
        personalGraphicsDvcTlsWritePending_ ||
        !broker_ || !lease_ || lease_->isRevoked())
    {
        revoke();
        return {0U, Outcome::Rejected, Step::AdmissionDenied};
    }

    // A current R2 lease and exact R3 route are mandatory before any R1 byte.
    const auto pending = pendingPersonalDesktopClipboardWrite(
        deploymentPolicy);
    if (!pending || !*pending || pending->wireBytes.empty() || !ready())
    {
        revoke();
        return {0U, Outcome::Rejected, Step::AdmissionDenied};
    }
    personalClipboardWriteInProgress_ = true;
    if (personalClipboardTlsRetryPending_)
    {
        // Reuse R1's existing WANT direction and the very same write suffix.
        const Interest required = connection_.ioInterest();
        if (required == Interest::Read && !readable)
            return {0U, Outcome::Pending, Step::NeedRead};
        if (required == Interest::Write && !writable)
            return {0U, Outcome::Pending, Step::NeedWrite};
        if (required != Interest::Read && required != Interest::Write)
        {
            revoke();
            return {0U, Outcome::Rejected, Step::Invalid};
        }
    }
    else if (!writable)
    {
        return {0U, Outcome::Pending, Step::NeedWrite};
    }

    const auto payload = pending->wireBytes.first((std::min)(
        pending->wireBytes.size(),
        rdp_server::server::transport::kMaximumTlsApplicationIoBytes));
    // R2/R3 completion can replace or close pendingPacket_ before returning.
    // Copy the accepted slice's identity before that mutating receipt.
    const auto routeGeneration = pending->routeGeneration;
    const auto replySequence = pending->replySequence;
    const auto writeSliceSequence = pending->writeSliceSequence;
    const auto offeredBytes = payload.size();
    const auto io = connection_.writeTlsApplicationData(payload);
    switch (io.outcome)
    {
    case IoOutcome::Progress:
    {
        personalClipboardTlsRetryPending_ = false;
        if (io.bytes == 0U || io.bytes > payload.size())
        {
            revoke();
            return {0U, Outcome::Rejected, Step::Invalid};
        }
        const auto receipt = completePersonalDesktopClipboardWrite(
            deploymentPolicy, routeGeneration, replySequence,
            writeSliceSequence, io.bytes);
        if (receipt == Outcome::Rejected || !ready())
        {
            revoke();
            return {io.bytes, Outcome::Rejected, Step::AdmissionDenied,
                    offeredBytes, routeGeneration, replySequence,
                    writeSliceSequence};
        }
        if (receipt == Outcome::Delivered)
        {
            personalClipboardWriteInProgress_ = false;
            return {io.bytes, receipt, Step::Delivered, offeredBytes,
                    routeGeneration, replySequence, writeSliceSequence};
        }
        return {io.bytes, receipt, Step::Progress, offeredBytes,
                routeGeneration, replySequence, writeSliceSequence};
    }
    case IoOutcome::NeedRead:
        personalClipboardTlsRetryPending_ = true;
        return {0U, Outcome::Pending, Step::NeedRead};
    case IoOutcome::NeedWrite:
        personalClipboardTlsRetryPending_ = true;
        return {0U, Outcome::Pending, Step::NeedWrite};
    case IoOutcome::TlsClosed:
    case IoOutcome::TransportClosed:
        revoke();
        return {0U, Outcome::Rejected, Step::Closed};
    case IoOutcome::FatalTlsFailure:
    case IoOutcome::Invalid:
        revoke();
        return {0U, Outcome::Rejected, Step::Invalid};
    }
    revoke();
    return {0U, Outcome::Rejected, Step::Invalid};
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
    personalClipboardWriteInProgress_ = false;
    personalClipboardTlsRetryPending_ = false;
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

    if (broker_ && principalProof_ != nullptr)
    {
        broker_->revokeR3Session(*principalProof_, session_);
    }
    else
    {
        session_.close();
        if (principalProof_ != nullptr)
            principalProof_->revokeAuthenticatedProof();
        else
            acceptor_.reject();
    }

    if (authenticationMode_ ==
        LinuxRuntimeAuthenticationMode::StandalonePassword)
    {
        if (principalProof_ != nullptr)
            principalProof_->revokeAuthenticatedProof();
        standaloneCredSspAcceptor_.reset();
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
    principalProof_ = nullptr;
    standaloneCredentialOwner_ = nullptr;
    // Preserve the non-secret generation only for terminal acceptance
    // diagnostics. With the owner/proof cleared, R1 cancelled and provisioned_
    // retired below, this scalar cannot authorize or resume authentication.
    standaloneReplyPending_ = false;
    standaloneBindingReplyPending_ = false;
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
