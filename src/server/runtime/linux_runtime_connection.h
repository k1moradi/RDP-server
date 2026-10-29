// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "linux_runtime_security.h"
#include "server/security/authentication_attempt_limiter.h"
#include "runtime_deployment_policy.h"
#include "runtime_licensing_authority.h"
#include "runtime_licensing_context.h"
#include "server/security/credssp_tsrequest.h"
#include "runtime_tls_context.h"
#include "server/security/linux_console_admission.h"
#include "server/security/standalone_credssp.h"
#include "server/transport/mcs_channel_connection.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::runtime
{

enum class LinuxCredSspStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    BindingVerified,
    CredentialsVerified,
    UnsupportedFinalCredentials,
    Invalid,
    Closed,
};

struct LinuxCredSspStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxCredSspStepStatus status{LinuxCredSspStepStatus::Closed};
};

enum class LinuxRuntimeAuthenticationMode : std::uint8_t
{
    ExistingOsAccount,
    StandalonePassword,
};

// R10's per-accepted-connection authentication selector. Standalone challenge
// string_views are consumed synchronously by the constructor and never retained.
// The credential owner must outlive the connection; its exact generation is
// revalidated for admission and every protected R3 operation.
struct LinuxRuntimeAuthenticationSelection final
{
    LinuxRuntimeAuthenticationMode mode{
        LinuxRuntimeAuthenticationMode::ExistingOsAccount};
    const rdp_server::server::security::StandalonePasswordCredentialOwner
        *standaloneCredentialOwner{};
    std::uint64_t standaloneCredentialGeneration{};
    rdp_server::server::security::StandaloneSpnegoChallengeConfiguration
        standaloneChallenge{};
};

enum class LinuxPreAdmissionStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    TlsEstablished,
    BindingVerified,
    CredentialsVerified,
    UnsupportedFinalCredentials,
    Invalid,
    Closed,
};

struct LinuxPreAdmissionStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxPreAdmissionStepStatus status{LinuxPreAdmissionStepStatus::Closed};
};

enum class LinuxRuntimeMcsTpktFrameStatus : std::uint8_t
{
    NeedMore,
    Complete,
    Invalid,
    Closed,
};

struct LinuxRuntimeMcsTpktFrameResult
{
    std::size_t bytesConsumed{};
    LinuxRuntimeMcsTpktFrameStatus status{
        LinuxRuntimeMcsTpktFrameStatus::NeedMore};
};

// R10-owned fixed-capacity framing only. It recognizes exactly one RFC1006
// TPKT boundary and never parses/admit MCS, reads TLS, or retains caller
// storage. R3 remains the sole MCS/GCC parser after R2 authorization.
class LinuxRuntimeMcsTpktFrameReader final
{
public:
    LinuxRuntimeMcsTpktFrameReader() noexcept = default;
    LinuxRuntimeMcsTpktFrameReader(
        const LinuxRuntimeMcsTpktFrameReader &) = delete;
    LinuxRuntimeMcsTpktFrameReader &operator=(
        const LinuxRuntimeMcsTpktFrameReader &) = delete;

    [[nodiscard]] LinuxRuntimeMcsTpktFrameResult consume(
        std::span<const std::uint8_t> plaintext) noexcept;
    [[nodiscard]] std::size_t bytesNeeded() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> completeTpkt() const noexcept;
    [[nodiscard]] LinuxRuntimeMcsTpktFrameStatus status() const noexcept
    {
        return status_;
    }
    // Reuse this bounded owner only after the previous complete TPKT has been
    // synchronously consumed by its R2/R3 owner. Invalid/closed state is not
    // recoverable through reset.
    [[nodiscard]] bool reset() noexcept;
    void close() noexcept;

private:
    [[nodiscard]] LinuxRuntimeMcsTpktFrameResult reject(
        std::size_t bytesConsumed) noexcept;

    std::array<std::uint8_t,
        rdp_server::server::transport::kMaximumInitialMcsTpktBytes> buffer_{};
    std::size_t bufferedBytes_{};
    std::size_t expectedBytes_{};
    LinuxRuntimeMcsTpktFrameStatus status_{
        LinuxRuntimeMcsTpktFrameStatus::NeedMore};
};

enum class LinuxPostAdmissionMcsStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    AdmittedConnectInitial,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPostAdmissionMcsStepResult
{
    std::size_t plaintextBytesRead{};
    LinuxPostAdmissionMcsStepStatus status{
        LinuxPostAdmissionMcsStepStatus::Closed};
};

// R2-only admitted Connect Response writer; exact accepted plaintext receipts
// are reauthorized before the R3 state machine can advance.
enum class LinuxPostAdmissionMcsResponseStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Delivered,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPostAdmissionMcsResponseStepResult
{
    std::size_t plaintextBytesWritten{};
    LinuxPostAdmissionMcsResponseStepStatus status{
        LinuxPostAdmissionMcsResponseStepStatus::Closed};
};

// A single post-response TPKT may advance R3 only through fresh R2
// authorization of the real Erect Domain intake. This grants no channel.
enum class LinuxPostAdmissionMcsErectStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    ErectDomainAccepted,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPostAdmissionMcsErectStepResult
{
    std::size_t plaintextBytesRead{};
    LinuxPostAdmissionMcsErectStepStatus status{
        LinuxPostAdmissionMcsErectStepStatus::Closed};
};

// One bounded R1 TLS read followed by the existing private R2/R3 Attach
// transition. No user/channel authority is exposed to the scheduler.
enum class LinuxPostAdmissionMcsAttachStepStatus : std::uint8_t
{
    Progress, NeedRead, NeedWrite, AttachUserAccepted,
    AdmissionDenied, Invalid, Closed,
};

struct LinuxPostAdmissionMcsAttachStepResult
{
    std::size_t plaintextBytesRead{};
    LinuxPostAdmissionMcsAttachStepStatus status{
        LinuxPostAdmissionMcsAttachStepStatus::Closed};
};

// One R3-owned Attach User Confirm suffix and exact R1 accepted-byte receipt.
enum class LinuxPostAdmissionMcsAttachConfirmStepStatus : std::uint8_t
{
    Progress, NeedRead, NeedWrite, Delivered,
    AdmissionDenied, Invalid, Closed,
};

struct LinuxPostAdmissionMcsAttachConfirmStepResult
{
    std::size_t plaintextBytesWritten{};
    LinuxPostAdmissionMcsAttachConfirmStepStatus status{
        LinuxPostAdmissionMcsAttachConfirmStepStatus::Closed};
};

// One real joined-channel handshake step. R3 alone stores negotiated IDs,
// ordering and per-reply accepted-byte sequence. No data channel privilege.
enum class LinuxPostAdmissionMcsChannelJoinStepStatus : std::uint8_t
{
    Progress, NeedRead, NeedWrite, AllChannelsJoined,
    AdmissionDenied, Invalid, Closed,
};

struct LinuxPostAdmissionMcsChannelJoinStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxPostAdmissionMcsChannelJoinStepStatus status{
        LinuxPostAdmissionMcsChannelJoinStepStatus::Closed};
};

// Client Info is an exact R1-owned TLS/TPKT intake only after every real
// negotiated MCS channel has a confirmed R3 reply. Privacy stays in R2/R3.
enum class LinuxPostAdmissionMcsClientInfoStepStatus : std::uint8_t
{
    Progress, NeedRead, NeedWrite, ClientInfoAccepted,
    AdmissionDenied, Invalid, Closed,
};

struct LinuxPostAdmissionMcsClientInfoStepResult
{
    std::size_t plaintextBytesRead{};
    LinuxPostAdmissionMcsClientInfoStepStatus status{
        LinuxPostAdmissionMcsClientInfoStepStatus::Closed};
};

enum class LinuxPersonalDesktopLicenseWriteStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Delivered,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPersonalDesktopLicenseWriteStepResult
{
    std::size_t plaintextBytesWritten{};
    LinuxPersonalDesktopLicenseWriteStepStatus status{
        LinuxPersonalDesktopLicenseWriteStepStatus::Closed};
};

enum class LinuxPersonalDesktopClientLicensingStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    ClientLicenseInfoAccepted,
    ClientNewLicenseRequestAccepted,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPersonalDesktopClientLicensingStepResult
{
    std::size_t plaintextBytesRead{};
    LinuxPersonalDesktopClientLicensingStepStatus status{
        LinuxPersonalDesktopClientLicensingStepStatus::Closed};
};

enum class LinuxPersonalDesktopValidClientWriteStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Delivered,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPersonalDesktopValidClientWriteStepResult
{
    std::size_t plaintextBytesWritten{};
    LinuxPersonalDesktopValidClientWriteStepStatus status{
        LinuxPersonalDesktopValidClientWriteStepStatus::Closed};
};

enum class LinuxPersonalDesktopShareActivationStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Activated,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPersonalDesktopShareActivationStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxPersonalDesktopShareActivationStepStatus status{
        LinuxPersonalDesktopShareActivationStepStatus::Closed};
};

enum class LinuxPersonalDesktopGraphicsDvcStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Ready,
    AdmissionDenied,
    Invalid,
    Closed,
};

struct LinuxPersonalDesktopGraphicsDvcStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxPersonalDesktopGraphicsDvcStepStatus status{
        LinuxPersonalDesktopGraphicsDvcStepStatus::Closed};
};

// Exact identity for one borrowed R2 logind watcher registration. R10 never
// duplicates or closes descriptor; R2 admission/session generations prevent
// stale reconnect reuse even if the kernel later reuses the fd number.
struct LinuxRuntimeNativeChangeRegistration
{
    int descriptor{-1};
    int events{-1};
    std::uint64_t admissionGeneration{};
    std::uint64_t sessionGeneration{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return descriptor >= 0 && events > 0 &&
               admissionGeneration != 0U && sessionGeneration != 0U;
    }
};


enum class LinuxRuntimeSocketPollStatus : std::uint8_t
{
    Ready,
    NoEvent,
    Expired,
    Closed,
    Failure,
};

struct LinuxRuntimeSocketPollResult
{
    bool readable{};
    bool writable{};
    LinuxRuntimeSocketPollStatus status{LinuxRuntimeSocketPollStatus::Closed};
};

enum class LinuxRuntimeTlsHandshakeDiagnosticStage : std::uint8_t
{
    NotStarted,
    Handshaking,
    Established,
    Closed,
};

enum class LinuxRuntimeCredSspDiagnosticTransition : std::uint8_t
{
    NotStarted,
    AwaitingToken,
    BindingVerified,
    CredentialsVerified,
    Failed,
    Closed,
};

// Last protocol/authentication boundary reached by this exact accepted
// connection. This scalar is diagnostic only and survives teardown solely so
// R10 can report the failure boundary without retaining any token/key bytes.
enum class LinuxRuntimeAuthenticationProgress : std::uint8_t
{
    Transport,
    Tls,
    CredSsp,
    CredSspSpnego,
    CredSspDirectNtlm,
    // Direct NTLM Type 2 was fully delivered; the peer owes Type 3.
    NtlmChallenge,
    // Direct NTLM Type 3 was observed; acceptor state owns verification detail.
    NtlmAuthenticate,
    // pubKeyAuth is being verified or its server binding reply is in flight.
    CredSspBinding,
    // Server binding reply was delivered; the peer owes protected authInfo.
    CredentialDelegation,
    // Final authInfo matched the configured credential. Admission has not run.
    Authenticated,
    Mcs,
};

// Last positive post-authentication boundary reached by this exact accepted
// connection. It is fail-only diagnostic state, never protocol authority.
enum class LinuxRuntimeProtocolDiagnosticStage : std::uint8_t
{
    PreAdmission,
    NativeAdmissionVerified,
    McsConnectInitialReceived,
    McsConnectResponseSent,
    McsErectDomainReceived,
    McsAttachUserReceived,
    McsChannelJoin,
    McsEstablished,
    ShareActivation,
    ShareActivated,
};

enum class LinuxRuntimeTlsClientSniClass : std::uint8_t
{
    None,
    Ip,
    Dns,
};

enum class LinuxRuntimeTlsCertificateCommonNameClass : std::uint8_t
{
    Unavailable,
    Generic,
    Endpoint,
    Other,
    Redacted,
};

inline constexpr std::size_t kLinuxRuntimeTlsDiagnosticTextCapacity = 128U;
inline constexpr std::size_t kLinuxRuntimeTlsSelectedEndpointCapacity = 64U;

// Bounded, non-authorizing first-client diagnostic snapshot. It contains only
// protocol/lifecycle scalars plus public TLS/certificate metadata; never
// passwords, NTLM/GSS responses, session keys, TLS secrets or delegated
// credentials. Text fields are fixed-capacity and may contain only printable
// public diagnostic text captured from the established connection.
struct LinuxRuntimeConnectionAcceptanceDiagnostics final
{
    rdp_server::server::transport::PreauthStage preauthStage{
        rdp_server::server::transport::PreauthStage::Closed};
    LinuxRuntimeTlsHandshakeDiagnosticStage tlsHandshakeStage{
        LinuxRuntimeTlsHandshakeDiagnosticStage::Closed};
    std::uint32_t negotiatedSecurityProtocol{};
    int negotiatedTlsProtocolVersion{};
    std::array<char, kLinuxRuntimeTlsDiagnosticTextCapacity>
        negotiatedTlsCipherSuite{};
    std::size_t negotiatedTlsCipherSuiteBytes{};
    bool clientSniPresent{};
    LinuxRuntimeTlsClientSniClass clientSniClass{
        LinuxRuntimeTlsClientSniClass::None};
    std::array<char, kLinuxRuntimeTlsDiagnosticTextCapacity>
        certificateSubjectCommonName{};
    std::size_t certificateSubjectCommonNameBytes{};
    LinuxRuntimeTlsCertificateCommonNameClass
        certificateSubjectCommonNameClass{
            LinuxRuntimeTlsCertificateCommonNameClass::Unavailable};
    bool certificateSanIpPresent{};
    bool certificateSanDnsPresent{};
    LinuxRuntimeCredSspDiagnosticTransition credSspTransition{
        LinuxRuntimeCredSspDiagnosticTransition::NotStarted};
    LinuxRuntimeAuthenticationProgress authenticationProgress{
        LinuxRuntimeAuthenticationProgress::Transport};
    LinuxRuntimeProtocolDiagnosticStage protocolStage{
        LinuxRuntimeProtocolDiagnosticStage::PreAdmission};
    rdp_server::server::security::StandaloneNtlmNegotiationEnvelope
        standaloneNegotiationEnvelope{
            rdp_server::server::security::
                StandaloneNtlmNegotiationEnvelope::Undetermined};
    // Structural Type-2 metadata only; no challenge, response or key bytes.
    rdp_server::server::security::NtlmChallengeMessageObservation
        standaloneNtlmChallenge{};
    bool standalonePasswordSelected{};
    // Exact non-secret service credential generation pinned when R10 selected
    // StandalonePassword for this accepted connection. Zero for every other
    // authentication mode. This is correlation evidence only, never authority.
    std::uint64_t standaloneCredentialGeneration{};
    rdp_server::server::security::StandaloneAuthenticationFailureStage
        standaloneAuthenticationFailureStage{
            rdp_server::server::security::
                StandaloneAuthenticationFailureStage::None};
    rdp_server::server::security::LinuxConsoleAdmissionFailureReason
        admissionFailureReason{
            rdp_server::server::security::
                LinuxConsoleAdmissionFailureReason::None};
    rdp_server::server::transport::McsSessionPhase mcsPhase{
        rdp_server::server::transport::McsSessionPhase::Closed};
    bool shareActivated{};
    rdp_server::server::transport::TcpConnectionTermination termination{
        rdp_server::server::transport::TcpConnectionTermination::Cancelled};
    rdp_server::server::transport::TlsHandshakeDiagnostics tlsHandshake{};
    RuntimeTlsCertificateFingerprint certificateSha256{};
    bool certificateFingerprintAvailable{};
    RuntimeTlsEndpointIdentityStatus certificateExactIpSelfCheck{
        RuntimeTlsEndpointIdentityStatus::CertificateUnavailable};
    bool selectedCertificateIdentityChecked{};
    bool selectedCertificateMatchesRuntimeIdentity{};
    // Connection-local, non-authorizing delivery receipts for the first
    // Direct NTLM challenge. Queued means the canonical Type-2-bearing
    // TSRequest is owned by the existing TLS writer. Delivered means every
    // plaintext byte was accepted by the exact R1 TLS write path and the
    // reply was released; neither state is evidence of peer receipt or Type 3.
    bool directNtlmTypeTwoQueued{};
    bool directNtlmTypeTwoDelivered{};

    // Appended fail-only observations preserve the established aggregate
    // layout. No token, identity payload, challenge response or key is kept.
    std::uint32_t negotiatedTlsCipherProtocolId{};
    bool standaloneNtlmTypeOneObserved{};
    rdp_server::server::security::NtlmNegotiateMessage
        standaloneNtlmTypeOne{};
    // Monotonic, connection-local timing observations. These are latched
    // diagnostics only and never influence authentication or timeout policy.
    bool directNtlmTypeTwoCreationToDeliveryAgeAvailable{};
    std::uint64_t directNtlmTypeTwoCreationToDeliveryMicroseconds{};
    bool preauthElapsedAtPeerEofAvailable{};
    std::uint64_t preauthElapsedAtPeerEofMicroseconds{};
    bool directNtlmTypeTwoToPeerEofAvailable{};
    std::uint64_t directNtlmTypeTwoToPeerEofMicroseconds{};
    bool postTypeTwoFirstClientTlsByteAvailable{};
    std::uint64_t postTypeTwoFirstClientTlsByteMicroseconds{};
    std::uint64_t postTypeTwoClientTlsBytes{};
    std::uint64_t postTypeTwoCompleteTsRequestCount{};
    std::uint64_t postTypeTwoPlaintextBytes{};
    std::size_t postTypeTwoPartialTsRequestBytes{};
    std::uint64_t postTypeTwoTlsAlertsReceived{};
    bool postTypeTwoTlsCloseNotifyReceived{};
    bool postTypeTwoTcpFinReceived{};
    bool postTypeTwoTcpResetReceived{};
    // These cached stages are connection-local steady-clock observations,
    // never R1/R2 authority or remote client-receipt evidence.
    bool acceptedToTlsEstablishedAvailable{};
    std::uint64_t acceptedToTlsEstablishedMicroseconds{};
    bool tlsEstablishedToTypeOneAvailable{};
    std::uint64_t tlsEstablishedToTypeOneMicroseconds{};
    bool typeOneToTypeTwoQueuedAvailable{};
    std::uint64_t typeOneToTypeTwoQueuedMicroseconds{};

    // One-clock R1/R10 attribution of the accepted -> established-TLS span.
    // Stage timestamps are first observations by the existing owner, not
    // packet timestamps. Zero-valued intervals are valid when available.
    bool preTlsTransportAttributionAvailable{};
    std::uint64_t acceptedToFirstClientTransportByteMicroseconds{};
    std::uint64_t firstClientTransportByteToX224CompleteMicroseconds{};
    std::uint64_t x224CompleteToFirstServerTransportByteMicroseconds{};
    std::uint64_t firstServerTransportByteToX224ConfirmCompleteMicroseconds{};
    std::uint64_t x224ConfirmCompleteToFirstTlsClientByteMicroseconds{};
    std::uint64_t firstTlsClientByteToFirstTlsServerByteMicroseconds{};
    std::uint64_t firstTlsServerByteToTlsEstablishedMicroseconds{};
    std::uint64_t preTlsReadWaitMicroseconds{};
    std::uint64_t preTlsWriteWaitMicroseconds{};
    std::uint64_t preTlsActiveWorkMicroseconds{};
    std::uint64_t tlsHandshakeActiveWorkMicroseconds{};
    std::uint64_t preTlsUnattributedMicroseconds{};
    // Read/Write wait is wall time for which that R1 readiness direction
    // remained authoritative. Socket-poll and ready-to-service ages are
    // non-additive subsets used to separate kernel wait from runtime service.
    std::uint64_t preTlsSocketPollMicroseconds{};
    std::uint64_t preTlsReadReadyToServiceMicroseconds{};
    std::uint64_t preTlsWriteReadyToServiceMicroseconds{};
    bool standaloneCredentialsRejected{};
};

namespace detail
{
// Derived scheduler snapshot only: this owns no protocol bytes, offsets,
// connection phase, or TLS operation. R3/R10 remain the authoritative owners
// of those facts. When an SSL_write_ex operation is outstanding, R1's
// WANT_READ/WANT_WRITE direction is authoritative. Otherwise a complete
// protocol-owned outbound slice must keep the poller writable even if R1's
// generic application fallback currently reports Read.
struct LinuxRuntimeIoInterestSnapshot final
{
    rdp_server::server::transport::TcpConnectionIoInterest r1Interest{
        rdp_server::server::transport::TcpConnectionIoInterest::Closed};
    rdp_server::server::transport::McsSessionPhase sessionPhase{
        rdp_server::server::transport::McsSessionPhase::
            AwaitVerifiedR2Admission};
    bool runtimeReady{};
    bool personalDesktopSelected{};
    bool tlsApplicationWriteOutstanding{};
    bool shareWritePending{};
    bool graphicsWritePending{};
    bool clipboardWritePending{};
};

[[nodiscard]] constexpr
rdp_server::server::transport::TcpConnectionIoInterest
selectLinuxRuntimeConnectionIoInterest(
    const LinuxRuntimeIoInterestSnapshot &snapshot) noexcept
{
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using Phase = rdp_server::server::transport::McsSessionPhase;

    if (!snapshot.runtimeReady)
        return Interest::Closed;

    if (snapshot.tlsApplicationWriteOutstanding)
    {
        if (snapshot.r1Interest == Interest::Read ||
            snapshot.r1Interest == Interest::Write)
        {
            return snapshot.r1Interest;
        }
        return Interest::Closed;
    }

    const bool licensingWritePending =
        snapshot.personalDesktopSelected &&
        (snapshot.sessionPhase == Phase::AwaitServerLicenseRequest ||
         snapshot.sessionPhase ==
             Phase::AwaitPersonalDesktopValidClientWrite);
    if (licensingWritePending || snapshot.shareWritePending ||
        snapshot.graphicsWritePending || snapshot.clipboardWritePending)
    {
        return Interest::Write;
    }

    return snapshot.r1Interest;
}

// One bounded serialized poll interval. Pending Graphics writes follow
// the R1 WANT_READ/WANT_WRITE socket direction, not an expired capture
// deadline. An active native-resize deadline also bounds the sleep so R10
// cannot overshoot its original elapsed-time retirement limit. Buffered TLS
// data and queued native events remain immediately serviceable; no ACK counter
// or second socket/protocol owner is introduced.
[[nodiscard]] constexpr std::chrono::milliseconds
selectLinuxPostSharePollWait(
    std::chrono::milliseconds pollQuantum,
    std::chrono::milliseconds remainingUntilCapture,
    bool frameWritePending,
    bool bufferedApplicationData,
    bool nativeWorkMayRemain,
    std::optional<std::chrono::milliseconds> remainingUntilResizeDeadline =
        std::nullopt) noexcept
{
    using namespace std::chrono_literals;
    if (bufferedApplicationData || nativeWorkMayRemain)
        return 0ms;
    const auto boundedQuantum = (std::max)(pollQuantum, 0ms);
    const auto captureWait =
        frameWritePending
            ? boundedQuantum
            : (std::min)(boundedQuantum,
                         (std::max)(remainingUntilCapture, 0ms));
    if (!remainingUntilResizeDeadline)
        return captureWait;
    return (std::min)(
        captureWait,
        (std::max)(*remainingUntilResizeDeadline, 0ms));
}

// The R1 SSL owner may already hold decrypted application data when its
// native socket is not readable. Only effective Read interest may dispatch it;
// an outstanding WANT_WRITE, outbound writer or terminal interest wins.
[[nodiscard]] constexpr bool shouldDispatchBufferedTlsApplicationRead(
    rdp_server::server::transport::TcpConnectionIoInterest required,
    bool bufferedApplicationReadReady) noexcept
{
    return required ==
               rdp_server::server::transport::TcpConnectionIoInterest::Read &&
           bufferedApplicationReadReady;
}

} // namespace detail

// One synchronous post-Share route is dispatched before its borrowed TPKT
// storage is reset. No callback may persist packet data or outlive the owner.
struct LinuxPostShareTpktSink final
{
    void *context{};
    bool (*consume)(void *,
                    rdp_server::server::transport::RdpPostShareTpktRouteKind,
                    std::span<const std::uint8_t>) noexcept{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context != nullptr && consume != nullptr;
    }
};

enum class LinuxPostShareApplicationReadStatus : std::uint8_t
{
    Progress, NeedRead, NeedWrite, Routed, AdmissionDenied, Invalid, Closed,
};

struct LinuxPostShareApplicationReadResult final
{
    std::size_t plaintextBytesRead{};
    LinuxPostShareApplicationReadStatus status{
        LinuxPostShareApplicationReadStatus::Closed};
};

// Scalar-only result of one authorized R3 clipboard write through R1 TLS.
enum class LinuxClipboardTlsWriteStatus : std::uint8_t
{
    Progress, NeedRead, NeedWrite, Delivered, AdmissionDenied, Invalid, Closed,
};
struct LinuxClipboardTlsWriteResult final
{
    std::size_t acceptedBytes{};
    rdp_server::server::transport::RdpClipboardWriteOutcome receipt{
        rdp_server::server::transport::RdpClipboardWriteOutcome::Rejected};
    LinuxClipboardTlsWriteStatus status{LinuxClipboardTlsWriteStatus::Closed};

    // Present only when R1 accepted positive bytes. These scalars are copied
    // before R2/R3 can invalidate the borrowed static-VC packet on receipt.
    std::size_t offeredBytes{};
    std::uint64_t routeGeneration{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    constexpr LinuxClipboardTlsWriteResult() noexcept = default;
    constexpr LinuxClipboardTlsWriteResult(
        std::size_t accepted,
        rdp_server::server::transport::RdpClipboardWriteOutcome outcome,
        LinuxClipboardTlsWriteStatus step,
        std::size_t offered = 0U, std::uint64_t route = 0U,
        std::uint64_t reply = 0U, std::uint64_t slice = 0U) noexcept
        : acceptedBytes(accepted), receipt(outcome), status(step),
          offeredBytes(offered), routeGeneration(route),
          replySequence(reply), writeSliceSequence(slice)
    {
    }
};

// One nonmoving Linux connection aggregate for the eventual R10 event loop.
// It does NOT bind/listen and it does not invent protocol/authentication state:
// R1 remains the sole socket/BIO/SSL owner, R2 remains the sole native
// admission authority, and R3 remains the sole MCS session owner.
//
// The service-lifetime LinuxRuntimeSecurityConfiguration and
// RuntimeServerTlsContext must outlive this object. All methods are confined
// to one event-loop thread. revoke() is the single terminal ownership barrier:
// close R3 first, revoke R2/GSS and its lease, then release R1 TLS/socket.
class LinuxRuntimeConnection final
{
public:
    LinuxRuntimeConnection(
        LinuxRuntimeSecurityConfiguration &securityConfiguration,
        rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket,
        rdp_server::server::security::AuthenticationAttemptLimiter
            *attemptLimiter = nullptr,
        const rdp_server::server::security::CurrentOwnerSharingAuthority
            *ownerSharingAuthority = nullptr) noexcept;

    LinuxRuntimeConnection(
        LinuxRuntimeSecurityConfiguration &securityConfiguration,
        rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket,
        rdp_server::server::security::AuthenticationAttemptLimiter
            *attemptLimiter,
        const rdp_server::server::security::CurrentOwnerSharingAuthority
            *ownerSharingAuthority,
        const LinuxRuntimeAuthenticationSelection &authenticationSelection)
        noexcept;
    ~LinuxRuntimeConnection();

    LinuxRuntimeConnection(const LinuxRuntimeConnection &) = delete;
    LinuxRuntimeConnection &operator=(const LinuxRuntimeConnection &) = delete;
    LinuxRuntimeConnection(LinuxRuntimeConnection &&) = delete;
    LinuxRuntimeConnection &operator=(LinuxRuntimeConnection &&) = delete;

    // True while this aggregate can make bounded protocol progress. A
    // provider-generated terminal CredSSP failure may remain writable after
    // GSS has failed but before aggregate teardown. This is never admission.
    [[nodiscard]] bool ready() const noexcept;

    [[nodiscard]] rdp_server::server::transport::TcpConnectionIoInterest
    ioInterest() const noexcept;

    // Wait for at most one native readiness event on R1's exact owned socket.
    // This method never reads, writes, accepts, duplicates or closes the
    // descriptor directly. R1/R2/R3 state advances only when the caller
    // subsequently invokes the corresponding bounded advance... method.
    // ConfigureTls is surfaced as Ready with no socket flags so the caller can
    // perform the explicit ownership transfer without polling. Expiry and
    // native poll failures are terminal and use the aggregate revoke order.
    [[nodiscard]] LinuxRuntimeSocketPollResult pollSocketReadinessOnce(
        std::chrono::steady_clock::time_point deadline,
        std::chrono::milliseconds maxWait =
            rdp_server::server::transport::kMaximumTcpPollWait) noexcept;

    // Borrow R1's exact native socket descriptor for a combined poll with
    // R2 logind and the single X11 connection. Never read, write or close it;
    // only R1 TLS application methods may consume socket readiness.
    [[nodiscard]] int nativeSocketPollDescriptor() const noexcept;
    [[nodiscard]] bool bufferedTlsApplicationReadReady() const noexcept;

    // One bounded pre-admission scheduler step derived from the existing R1
    // phase/interest plus R2 CredSSP writer readiness. Wrong-direction
    // readiness returns the required direction with zero I/O. For a read,
    // R1-owned buffered TLS plaintext may permit one bounded application step
    // even when the native socket reports no new readability. The method may
    // attach one fresh R10 server TLS object only after the X.224 reply is
    // completely delivered. It never invokes R1's legacy MCS reader: positive
    // MCS remains reachable only through R2 admission.
    [[nodiscard]] LinuxPreAdmissionStepResult advancePreAdmission(
        bool readable, bool writable,
        const RuntimeServerTlsContext &tlsContext) noexcept;

    // Phase-specific compatibility delegates. A production pre-admission
    // scheduler should prefer advancePreAdmission(), because these methods do
    // not dispatch CredSSP after HYBRID TLS. They never authenticate/authorize.
    [[nodiscard]] rdp_server::server::transport::TcpPreauthEvent
    onReadable() noexcept;
    [[nodiscard]] rdp_server::server::transport::TcpPreauthEvent
    onWritable() noexcept;

    // Snapshot only the public configured leaf fingerprint and exact numeric
    // endpoint self-check before TLS begins. This is descriptive listener
    // identity evidence only and never peer/user authorization.
    void configureTlsIdentityDiagnostics(
        const RuntimeServerTlsContext &tlsContext,
        std::string_view numericEndpoint) noexcept;

    // Create a fresh SSL from the service-owned R10 context and transfer it
    // exactly once into R1. The SSL_CTX remains service-owned by tlsContext.
    [[nodiscard]] bool attachServerTls(
        const RuntimeServerTlsContext &tlsContext) noexcept;
    [[nodiscard]] rdp_server::server::transport::TlsHandshakeStatus
    onTlsIoReady() noexcept;

    // Delegate one bounded event-loop step to R2's owner-driven CredSSP/GSS
    // progression. R1 remains the sole SSL_read_ex/SSL_write_ex owner; R10
    // maps readiness and owns lifetimes only. BindingVerified is transport/GSS
    // evidence. CredentialsVerified means exact delegated account + PAM passed,
    // but native desktop admission is still required. UnsupportedFinalCredentials
    // is terminal and means final authInfo was not authorized.
    [[nodiscard]] LinuxCredSspStepResult onCredSspIoReady() noexcept;

    // Positive R2 issuance consumes the private final-credential candidate,
    // samples fresh concrete NSS/logind owner evidence, installs its change
    // watch, and only then completes R1/R2 admission. The lease never escapes
    // this aggregate.
    [[nodiscard]] bool issueAdmission(
        const rdp_server::server::security::ConsoleEvidenceRequest &request)
        noexcept;

    // R2 is the only positive entry into R3. Failure is terminal and invokes
    // the same ordered aggregate teardown.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeMcsConnectInitial(
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // First post-admission application-data scheduler step. Only after a
    // genuine current R2 lease exists, read at most one bounded plaintext
    // chunk through the sole R1 SSL owner. Exact TPKT framing prevents
    // consuming bytes from the following PDU. Buffered OpenSSL plaintext may
    // progress without a fresh socket POLLIN; pending WANT direction wins.
    // A completed TPKT is synchronously passed to the existing R2-authorized
    // R3 Connect Initial entry and is never retained after that call.
    [[nodiscard]] LinuxPostAdmissionMcsStepResult
    advancePostAdmissionMcsConnectInitial(
        bool readable, bool writable) noexcept;

    // One bounded R1 TLS write of the R3-owned Connect Response suffix.
    // R2 reauthorizes both borrowed bytes and exact accepted-byte receipt.
    [[nodiscard]] LinuxPostAdmissionMcsResponseStepResult
    advancePostAdmissionMcsConnectResponseWrite(
        bool readable, bool writable) noexcept;

    // Consume only one exact TPKT following the completely delivered MCS
    // Connect Response. R1 owns TLS and plaintext progress, R2 freshly
    // reauthorizes each read and the final R3 Erect Domain transition.
    [[nodiscard]] LinuxPostAdmissionMcsErectStepResult
    advancePostAdmissionMcsErectDomain(
        bool readable, bool writable) noexcept;

    // Reuse the R2-consumed Erect frame buffer for exactly one following
    // Attach User request. Reauthorize PersonalDesktop policy and exact R2/R3
    // authority before every R1-owned TLS read.
    [[nodiscard]] LinuxPostAdmissionMcsAttachStepResult
    advancePostAdmissionMcsAttachUser(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    // Borrow the R3-owned confirm suffix after fresh R2 authorization; only
    // an exact R1 plaintext receipt may advance it through R2 a second time.
    [[nodiscard]] LinuxPostAdmissionMcsAttachConfirmStepResult
    advancePostAdmissionMcsAttachConfirmWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    // Consume exactly one genuine Channel Join Request TPKT at a time,
    // publish only the correlated R3 Join Confirm through R1 SSL, and require
    // fresh R2 checks before both TLS reads and accepted-byte receipts.
    // The same bounded reader is reset only after R2/R3 consumed a packet.
    [[nodiscard]] LinuxPostAdmissionMcsChannelJoinStepResult
    advancePostAdmissionMcsChannelJoins(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    // Read only actual peer Client Info bytes, after all R3-confirmed joins.
    // All sensitive fields are parsed privately by the existing R2/R3 API;
    // no username or password leaves this synchronous admitted transition.
    [[nodiscard]] LinuxPostAdmissionMcsClientInfoStepResult
    advancePostAdmissionMcsClientInfo(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    // R10-facing personal-desktop security boundary. The immutable policy is
    // the only product-mode input; R2 keeps the lease and generation pair
    // private and freshly reauthorizes every operation below. R1 remains the
    // sole TLS application-I/O owner and R3 remains the sole wire/session owner.
    [[nodiscard]] bool selectPersonalDesktopLicensingMode(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    [[nodiscard]] LinuxPersonalDesktopLicenseWriteStepResult
    advancePersonalDesktopServerLicenseRequestWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        const RuntimeLicensingContext &licensingContext,
        bool readable, bool writable) noexcept;

    // After the Server License Request is fully accepted, consume at most one
    // complete client licensing TPKT through the same R1 SSL owner. Every
    // actual read is preceded by fresh R2 reauthorization; the completed
    // packet is synchronously dispatched through the PersonalDesktop
    // policy-bound R2 wrapper into R3 and is never retained afterward.
    [[nodiscard]] LinuxPersonalDesktopClientLicensingStepResult
    advancePersonalDesktopClientLicensingIntake(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        const RuntimeLicensingContext &licensingContext,
        bool readable, bool writable) noexcept;

    // Publish STATUS_VALID_CLIENT only through the original R1 SSL owner.
    // R2 reauthorizes before every borrowed R3 slice and again before the
    // exact accepted plaintext-byte receipt is committed. The caller supplies
    // readiness only; it cannot supply or manufacture a completion count.
    [[nodiscard]] LinuxPersonalDesktopValidClientWriteStepResult
    advancePersonalDesktopValidClientWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::transport::
            RdpPersonalDesktopValidClientWriteView>
    authorizePersonalDesktopValidClientWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    [[nodiscard]]
    rdp_server::server::transport::
        RdpPersonalDesktopValidClientWriteOutcome
    completePersonalDesktopValidClientWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Ask R3 for one immutable, validated Demand Active profile after fresh
    // R2 authorization. R10 supplies only typed implemented feature bits; R3
    // derives geometry from the admitted GCC Client Core and owns all wire
    // capabilities, Share IDs and Demand session IDs.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpDemandActiveProfileView>
    preparePersonalDesktopDemandActiveProfile(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        rdp_server::server::transport::RdpDemandActiveFeature features) noexcept;

    // Begin R3's one Share transcript without publishing bytes. The profile
    // must be the exact view minted above by this connection's R3 owner.
    [[nodiscard]] bool startPersonalDesktopShareActivation(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        const rdp_server::server::transport::RdpDemandActiveProfileView
            &profile) noexcept;

    // Drive exactly one serialized Share I/O step. R10 owns only whether the
    // next scheduler operation is an R1 read or write; R3 owns Demand Active,
    // Confirm Active, Synchronize/Control/Font sequencing and all wire state.
    [[nodiscard]] LinuxPersonalDesktopShareActivationStepResult
    advancePersonalDesktopShareActivation(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpShareActivationWriteView>
    beginPersonalDesktopShareActivation(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        const rdp_server::server::transport::RdpDemandActiveProfileView
            &profile) noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpShareActivationWriteView>
    authorizePersonalDesktopShareActivationWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    [[nodiscard]]
    rdp_server::server::transport::RdpShareActivationWriteOutcome
    completePersonalDesktopShareActivationWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    [[nodiscard]]
    rdp_server::server::transport::RdpShareActivationClientIntake
    acceptPersonalDesktopShareActivationPdu(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Begin the existing R3 DRDYNVC/Graphics control transcript only after
    // genuine Share activation. The initial server borrow is not exposed;
    // advance... below owns every R1 read/write and R2 receipt boundary.
    [[nodiscard]] bool startPersonalDesktopGraphicsDynamicVirtualChannel(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    // Drive DRDYNVC capabilities, Graphics CREATE and RDPGFX CAPS control
    // through R1 while R3 remains the sole channel/protocol state owner.
    [[nodiscard]] LinuxPersonalDesktopGraphicsDvcStepResult
    advancePersonalDesktopGraphicsDynamicVirtualChannel(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    // Ephemeral, non-mutating R3/R4 ACK-credit observation via R2. No frame
    // is reserved here. Ready still requires fresh authorization on frame start;
    // DeferredForFrameAcknowledge is ordinary scheduler backpressure.
    [[nodiscard]]
    rdp_server::server::transport::RdpGraphicsFramePublicationReadiness
    preflightPersonalDesktopGraphicsFramePublication(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::uint32_t frameId) noexcept;

    // Begin R3's authenticated DELETE/CREATE/MAP remap from one fresh R5
    // geometry observation. Started transfers the existing Graphics writer
    // back to Write; Deferred and Unchanged consume no frame ID or TLS byte.
    [[nodiscard]]
    rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration
    beginPersonalDesktopGraphicsSurfaceReconfiguration(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        ::PixelSize desktopGeometry) noexcept;

    // Prepare and start one mandatory ClearCodec fallback publication. R10
    // supplies only a frame ID and a synchronous borrowed framebuffer. R3 owns
    // the current Graphics DVC generation, surface identity and R4 receipts.
    [[nodiscard]] bool startPersonalDesktopClearCodecFramePublication(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::uint32_t frameId,
        ::FramebufferView framebuffer) noexcept;

    // Legal only while R3 proves that R1 accepted zero outer plaintext bytes.
    // Positive or uncertain progress is never translated into cancellation.
    [[nodiscard]] bool cancelUnwrittenPersonalDesktopGraphicsFrame(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    [[nodiscard]] bool authorizePersonalDesktopApplicationTraffic(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    // Classify exactly one immutable, complete post-Share TPKT through the
    // current R2 lease and the existing R3 MCS/channel owner. The result
    // borrows caller bytes only until this synchronous call returns; R10
    // must immediately dispatch its single route, never trial-dispatch.
    // A missing authority, unsupported route or stale packet retires the
    // connection, and this method does not read another TLS byte.
    [[nodiscard]] rdp_server::server::transport::RdpPostShareTpktRoute
    classifyPersonalDesktopPostShareTpkt(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Reuse the already-owned Graphics DVC TPKT frame storage, and R1's sole
    // TLS application reader, after Graphics presentation becomes Ready.
    // Read at most one bounded TLS slice; classify each complete TPKT once
    // and deliver a borrowed route synchronously. The caller must dispatch
    // solely by that route; wrong/unsupported destinations are terminal.
    [[nodiscard]] LinuxPostShareApplicationReadResult
    advancePersonalDesktopPostShareApplicationRead(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable, LinuxPostShareTpktSink sink) noexcept;

    // Accept only the authenticated Graphics DVC DATA/FRAME_ACK path, under
    // fresh R2 authorization and R3's sole presentation ACK window. No
    // separate graphics socket reader, ACK cache or R4 state is created.
    [[nodiscard]] bool dispatchPersonalDesktopPostShareGraphicsTpkt(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // R2/R3 post-Share input gateway. R10 supplies one complete TPKT obtained
    // through the sole R1 TLS reader and a synchronous destination. Neither
    // bytes nor callback grant authority: the broker revalidates the concrete
    // lease, GSS/TLS provenance, native evidence, R3 generations and input
    // permission immediately before EACH decoded event callback.
    [[nodiscard]] bool dispatchPersonalDesktopSlowPathInputPdu(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt,
        rdp_server::server::transport::RdpSlowPathInputEventSink sink)
        noexcept;

    // R8-facing post-Share gateway only. These methods perform no TLS I/O,
    // native clipboard publication or scheduling. R10 must call them only from
    // the serialized connection loop; every operation re-enters R2 before R3.
    [[nodiscard]] bool visitPersonalDesktopClipboardChannel(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        rdp_server::server::transport::RdpClipboardChannelVisitor visitor)
        noexcept;
    [[nodiscard]] bool dispatchPersonalDesktopClipboardTpkt(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt,
        rdp_server::server::transport::RdpClipboardCompletePduSink sink)
        noexcept;
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
    queuePersonalDesktopClipboardPdu(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::span<const std::uint8_t> completePdu) noexcept;
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
    pendingPersonalDesktopClipboardWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpClipboardWriteOutcome
    completePersonalDesktopClipboardWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        std::uint64_t routeGeneration, std::uint64_t replySequence,
        std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept;

    // R10 calls this for one already queued CLIPRDR slice, before any
    // other socket operation. The R1 write and R2/R3 receipt share one
    // serialized invocation; no native publication or new SSL owner.
    [[nodiscard]] LinuxClipboardTlsWriteResult
    advancePersonalDesktopClipboardTlsWrite(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        bool readable, bool writable) noexcept;

    // Borrow the R2-owned logind monitor fd and libsystemd poll mask only
    // after genuine admission with a live lease. Both are -1 otherwise.
    // Neither value owns/duplicates a descriptor or grants authorization.
    // Confined to the aggregate's event-loop thread: unregister the fd from
    // epoll/poll before revoke(), connection destruction or any callback that
    // can revoke the lease. Never close the borrowed fd. No registration may
    // outlive the owner or be reused on reconnect; discard queued events and
    // check the current borrow before dispatching readiness.
    [[nodiscard]] int nativeChangeFd() const noexcept;
    [[nodiscard]] int nativeChangeEvents() const noexcept;

    // Dispatch the concrete logind revocation source owned by R2. False means
    // either a spurious readiness notification or terminal revocation.
    [[nodiscard]] bool onNativeSessionChangeReady() noexcept;

    // Synchronously expose only the native desktop selected by the current
    // genuine R2 lease. The callback receives a noncopyable borrowed view;
    // it must construct/refresh its native owner before returning and retain
    // only the generations for later R2 reauthorization. Configured DISPLAY,
    // principal text, UID values and caller-supplied session metadata never
    // enter this API. Any failure is terminal.
    [[nodiscard]] bool visitNativeDesktopSelection(
        rdp_server::server::security::LinuxNativeDesktopSelectionVisitor
            visitor,
        void *context) noexcept;

    // Register only the current R2 borrow. The serialized caller must remove
    // this exact record from its poller before acknowledging unregistration.
    [[nodiscard]] std::optional<LinuxRuntimeNativeChangeRegistration>
    registerNativeChange() noexcept;
    [[nodiscard]] bool unregisterNativeChange(
        const LinuxRuntimeNativeChangeRegistration &registration) noexcept;
    // Drop a polled, already-unregistered logind borrow when it did not signal
    // readiness. No R2 callback, descriptor close, or lease mutation occurs.
    // Allows another bounded poll registration without duplicating a watcher.
    [[nodiscard]] bool releaseNativeChangeWithoutDispatch(
        const LinuxRuntimeNativeChangeRegistration &registration) noexcept;
    // Dispatch is valid only after the exact record has been unregistered.
    // The aggregate drops registration identity before calling R2 because the
    // callback may synchronously revoke this whole connection.
    [[nodiscard]] bool dispatchNativeChangeReady(
        const LinuxRuntimeNativeChangeRegistration &registration) noexcept;

    // Consume the live R3 existing-CAL snapshot on this exact connection.
    // RuntimeLicensingContext product identity is checked before provider begin.
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    beginExistingCalValidation(
        const RuntimeLicensingContext &licensingContext,
        RuntimeLicensingAuthority &authority) noexcept;
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    pollExistingCalValidation() noexcept;
    [[nodiscard]] std::optional<RuntimeLicensingExistingCalDecision>
    authorizeExistingCalValidationDecision() noexcept;
    [[nodiscard]] bool retireExistingCalValidationDecision() noexcept;
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    cancelExistingCalValidation() noexcept;

    // Terminal and idempotent. No object can retain a positive R2/R3
    // capability after the R1 TLS/socket is released.
    void revoke() noexcept;

    [[nodiscard]] rdp_server::server::security::SpnegoStage
    gssStage() const noexcept
    {
        return acceptor_.stage();
    }
    [[nodiscard]] rdp_server::server::security::LinuxConsoleAdmissionState
    admissionState() const noexcept;
    [[nodiscard]] rdp_server::server::transport::McsSessionPhase
    mcsPhase() const noexcept
    {
        return session_.phase();
    }

    // Serialized R10 tests/logging may copy this bounded R3 snapshot. It is
    // non-authorizing and contains no wire bytes, peer/credential data or
    // protocol/native identity values.
    [[nodiscard]] rdp_server::server::transport::
        RdpFirstClientAcceptanceObservability
    firstClientAcceptanceObservability() const noexcept
    {
        return session_.firstClientAcceptanceObservability();
    }
    [[nodiscard]] bool hasAdmissionLease() const noexcept
    {
        return lease_.has_value() && !lease_->isRevoked();
    }

    [[nodiscard]] LinuxRuntimeConnectionAcceptanceDiagnostics
    acceptanceDiagnostics() const noexcept;

private:
    enum class PersonalDesktopGraphicsDvcIoAction : std::uint8_t
    {
        Idle,
        Write,
        Read,
        Ready,
    };

    enum class PersonalDesktopShareIoAction : std::uint8_t
    {
        Idle,
        Write,
        Read,
        Activated,
    };

private:
    [[nodiscard]] bool credSspReplyPending() const noexcept;
    [[nodiscard]] bool authenticationOwnerHealthy() const noexcept;
    [[nodiscard]] rdp_server::server::security::LinuxAuthenticatedPrincipalProof
        *authenticatedPrincipalProof() noexcept
    {
        return principalProof_;
    }
    [[nodiscard]] const
        rdp_server::server::security::LinuxAuthenticatedPrincipalProof
        *authenticatedPrincipalProof() const noexcept
    {
        return principalProof_;
    }
    [[nodiscard]] LinuxCredSspStepResult
        advanceStandaloneCredSsp() noexcept;
    void recordStandaloneAuthenticationFailure(
        rdp_server::server::security::StandaloneAuthenticationFailureStage
            failureStage) noexcept;
    [[nodiscard]] bool postAdmissionMcsPolicyMatches(
        const RuntimeDeploymentPolicy &deploymentPolicy) const noexcept;
    // Membership-only R3 inspection; call only after fresh R2 admission
    // authorization. This never grants channel or desktop access.
    [[nodiscard]] bool allNegotiatedMcsChannelsJoined() const noexcept;
    [[nodiscard]] bool reauthorizeExistingCalValidation() noexcept;
    [[nodiscard]] bool nativeChangeRegistrationMatches(
        const LinuxRuntimeNativeChangeRegistration &registration) const
        noexcept;
    void captureEstablishedTlsDiagnostics() noexcept;

    LinuxRuntimeSecurityConfiguration &securityConfiguration_;

    // Declaration order is deliberate. Explicit revoke() performs the
    // security ordering; reverse member destruction is also safe if a future
    // exception-free constructor path returns early: R3/lease/broker/GSS die
    // before R1's connection owner.
    rdp_server::server::transport::OwnedPreauthTcpConnection connection_;
    // Start the monotonic pre-auth clock with this exact accepted connection.
    // It is diagnostic-only and never drives timeout or authorization policy.
    const std::chrono::steady_clock::time_point preauthStartedAt_{
        std::chrono::steady_clock::now()};
    std::optional<std::chrono::steady_clock::time_point> tlsEstablishedAt_{};
    std::optional<std::chrono::steady_clock::time_point>
        directNtlmTypeOneObservedAt_{};
    bool acceptedToTlsEstablishedAvailable_{};
    std::uint64_t acceptedToTlsEstablishedMicroseconds_{};
    bool tlsEstablishedToTypeOneAvailable_{};
    std::uint64_t tlsEstablishedToTypeOneMicroseconds_{};
    bool typeOneToTypeTwoQueuedAvailable_{};
    std::uint64_t typeOneToTypeTwoQueuedMicroseconds_{};

    // These timestamps extend the existing accepted-connection steady-clock
    // timeline. They consume only R1 cumulative byte counts and stage changes.
    std::optional<std::chrono::steady_clock::time_point>
        firstClientTransportByteAt_{};
    std::optional<std::chrono::steady_clock::time_point>
        x224RequestCompletedAt_{};
    std::optional<std::chrono::steady_clock::time_point>
        firstX224ServerTransportByteAt_{};
    std::optional<std::chrono::steady_clock::time_point>
        x224ConfirmDeliveredAt_{};
    std::optional<std::chrono::steady_clock::time_point>
        firstTlsClientTransportByteAt_{};
    std::optional<std::chrono::steady_clock::time_point>
        firstTlsServerTransportByteAt_{};
    bool preTlsTransportAttributionAvailable_{};
    std::uint64_t acceptedToFirstClientTransportByteMicroseconds_{};
    std::uint64_t firstClientTransportByteToX224CompleteMicroseconds_{};
    std::uint64_t x224CompleteToFirstServerTransportByteMicroseconds_{};
    std::uint64_t firstServerTransportByteToX224ConfirmCompleteMicroseconds_{};
    std::uint64_t x224ConfirmCompleteToFirstTlsClientByteMicroseconds_{};
    std::uint64_t firstTlsClientByteToFirstTlsServerByteMicroseconds_{};
    std::uint64_t firstTlsServerByteToTlsEstablishedMicroseconds_{};
    std::uint64_t preTlsReadWaitMicroseconds_{};
    std::uint64_t preTlsWriteWaitMicroseconds_{};
    std::uint64_t preTlsActiveWorkMicroseconds_{};
    std::uint64_t tlsHandshakeActiveWorkMicroseconds_{};
    std::uint64_t preTlsUnattributedMicroseconds_{};
    std::uint64_t preTlsSocketPollMicroseconds_{};
    std::uint64_t preTlsReadReadyToServiceMicroseconds_{};
    std::uint64_t preTlsWriteReadyToServiceMicroseconds_{};
    // One connection-local interest timeline. It records only which existing
    // R1 readiness direction was required between bounded service calls.
    std::optional<std::chrono::steady_clock::time_point>
        preTlsInterestAccountedAt_{};
    rdp_server::server::transport::TcpConnectionIoInterest preTlsInterest_{
        rdp_server::server::transport::TcpConnectionIoInterest::Read};
    // Latched by the existing poller when readiness is observed, then consumed
    // by the next matching advancePreAdmission call. No descriptor is read.
    std::optional<std::chrono::steady_clock::time_point>
        preTlsReadinessObservedAt_{};
    rdp_server::server::transport::TcpConnectionIoInterest
        preTlsReadinessObservedInterest_{
            rdp_server::server::transport::TcpConnectionIoInterest::Closed};

    rdp_server::server::security::GssapiSpnegoAcceptor acceptor_{};
    rdp_server::server::security::StandaloneCredSspNtlmAcceptor
        standaloneCredSspAcceptor_{};
    rdp_server::server::security::StandalonePasswordAuthenticatedPrincipalProof
        standalonePrincipalProof_{};
    rdp_server::server::security::LinuxAuthenticatedPrincipalProof
        *principalProof_{};
    const rdp_server::server::security::StandalonePasswordCredentialOwner
        *standaloneCredentialOwner_{};
    std::uint64_t standaloneCredentialGeneration_{};
    LinuxRuntimeAuthenticationMode authenticationMode_{
        LinuxRuntimeAuthenticationMode::ExistingOsAccount};
    bool standaloneReplyPending_{};
    bool standaloneBindingReplyPending_{};
    // Diagnostic receipts only. They never authorize authentication,
    // admission or later protocol state.
    bool directNtlmTypeTwoQueued_{};
    bool directNtlmTypeTwoDelivered_{};
    std::optional<std::chrono::steady_clock::time_point>
        directNtlmTypeTwoCreatedAt_{};
    bool directNtlmTypeTwoCreationToDeliveryAgeAvailable_{};
    std::uint64_t directNtlmTypeTwoCreationToDeliveryMicroseconds_{};
    std::optional<std::chrono::steady_clock::time_point>
        directNtlmTypeTwoDeliveredAt_{};
    std::uint64_t directNtlmTypeTwoTransportBytesAtDelivery_{};
    std::uint64_t directNtlmTypeTwoTlsAlertsAtDelivery_{};
    bool preauthElapsedAtPeerEofAvailable_{};
    std::uint64_t preauthElapsedAtPeerEofMicroseconds_{};
    bool directNtlmTypeTwoToPeerEofAvailable_{};
    std::uint64_t directNtlmTypeTwoToPeerEofMicroseconds_{};
    bool postTypeTwoFirstClientTlsByteAvailable_{};
    std::uint64_t postTypeTwoFirstClientTlsByteMicroseconds_{};
    std::uint64_t postTypeTwoCompleteTsRequestCount_{};
    std::uint64_t postTypeTwoPlaintextBytes_{};
    std::size_t postTypeTwoPartialTsRequestBytes_{};
    std::optional<rdp_server::server::security::LinuxConsoleAdmissionBroker>
        broker_{};
    std::optional<rdp_server::server::security::LinuxConsoleAdmissionLease>
        lease_{};
    rdp_server::server::transport::McsSessionLifecycle session_{};
    LinuxRuntimeMcsTpktFrameReader mcsConnectInitialFrameReader_{};
    bool mcsConnectResponseTlsWritePending_{};
    enum class McsChannelJoinIoAction : std::uint8_t
    {
        Idle, Read, Write,
    };

    // One frame owner is reused sequentially; no second large buffer.
    LinuxRuntimeMcsTpktFrameReader mcsErectDomainFrameReader_{};
    const RuntimeDeploymentPolicy *postAdmissionMcsPolicy_{};
    bool mcsAttachConfirmTlsWritePending_{};
    McsChannelJoinIoAction mcsChannelJoinIoAction_{
        McsChannelJoinIoAction::Idle};
    bool mcsChannelJoinTlsWritePending_{};
    LinuxRuntimeMcsTpktFrameReader personalClientLicensingFrameReader_{};
    LinuxRuntimeMcsTpktFrameReader personalShareActivationFrameReader_{};
    LinuxRuntimeMcsTpktFrameReader personalGraphicsDvcFrameReader_{};
    const RuntimeDeploymentPolicy *personalDesktopPolicy_{};
    bool personalLicenseRequestTlsWritePending_{};
    bool personalValidClientTlsWritePending_{};
    PersonalDesktopShareIoAction personalShareIoAction_{
        PersonalDesktopShareIoAction::Idle};
    bool personalShareTlsWritePending_{};
    PersonalDesktopGraphicsDvcIoAction personalGraphicsDvcIoAction_{
        PersonalDesktopGraphicsDvcIoAction::Idle};
    bool personalGraphicsDvcTlsWritePending_{};
    bool personalClipboardWriteInProgress_{};
    bool personalClipboardTlsRetryPending_{};
    std::optional<RuntimeExistingCalValidationBinding>
        existingCalValidation_{};
    std::optional<LinuxRuntimeNativeChangeRegistration>
        nativeChangeRegistration_{};
    bool nativeChangeRegistrationUnregistered_{};
    LinuxRuntimeCredSspDiagnosticTransition credSspDiagnosticTransition_{
        LinuxRuntimeCredSspDiagnosticTransition::NotStarted};
    LinuxRuntimeAuthenticationProgress authenticationProgress_{
        LinuxRuntimeAuthenticationProgress::Transport};
    LinuxRuntimeProtocolDiagnosticStage protocolDiagnosticStage_{
        LinuxRuntimeProtocolDiagnosticStage::PreAdmission};
    // Redacted connection-scoped envelope survives terminal CredSSP cleanup so
    // R10/R7 can classify the failed peer without retaining token material.
    rdp_server::server::security::StandaloneNtlmNegotiationEnvelope
        standaloneNegotiationEnvelope_{
            rdp_server::server::security::
                StandaloneNtlmNegotiationEnvelope::Undetermined};
    // Redacted parser output survives R2 mechanism reset only for terminal
    // diagnostics. It is never consulted for authentication or Admission.
    bool standaloneNtlmTypeOneObserved_{};
    rdp_server::server::security::NtlmNegotiateMessage
        standaloneNtlmTypeOneObservation_{};
    rdp_server::server::security::NtlmChallengeMessageObservation
        standaloneNtlmChallengeObservation_{};
    rdp_server::server::security::StandaloneAuthenticationFailureStage
        standaloneAuthenticationFailureStage_{
            rdp_server::server::security::
                StandaloneAuthenticationFailureStage::None};
    // Latched from the existing SPNEGO/NTLM verifier before it is reset.
    // This carries only the typed rejection fact, never credential material.
    bool standaloneCredentialsRejected_{};
    rdp_server::server::security::LinuxConsoleAdmissionFailureReason
        admissionFailureReason_{
            rdp_server::server::security::
                LinuxConsoleAdmissionFailureReason::None};
    RuntimeTlsCertificateFingerprint negotiatedCertificateSha256_{};
    bool negotiatedCertificateFingerprintAvailable_{};
    std::array<char, kLinuxRuntimeTlsDiagnosticTextCapacity>
        negotiatedTlsCipherSuite_{};
    std::size_t negotiatedTlsCipherSuiteBytes_{};
    std::uint32_t negotiatedTlsCipherProtocolId_{};
    bool clientSniPresent_{};
    LinuxRuntimeTlsClientSniClass clientSniClass_{
        LinuxRuntimeTlsClientSniClass::None};
    std::array<char, kLinuxRuntimeTlsDiagnosticTextCapacity>
        certificateSubjectCommonName_{};
    std::size_t certificateSubjectCommonNameBytes_{};
    LinuxRuntimeTlsCertificateCommonNameClass
        certificateSubjectCommonNameClass_{
            LinuxRuntimeTlsCertificateCommonNameClass::Unavailable};
    bool certificateSanIpPresent_{};
    bool certificateSanDnsPresent_{};
    std::array<char, kLinuxRuntimeTlsSelectedEndpointCapacity>
        selectedTlsEndpoint_{};
    std::size_t selectedTlsEndpointBytes_{};
    RuntimeTlsEndpointIdentityStatus certificateExactIpSelfCheck_{
        RuntimeTlsEndpointIdentityStatus::CertificateUnavailable};
    bool selectedCertificateIdentityChecked_{};
    bool selectedCertificateMatchesRuntimeIdentity_{};
    std::uint32_t negotiatedSecurityProtocol_{};
    int negotiatedTlsProtocolVersion_{};
    bool tlsEverEstablished_{};
    // Retired explicitly before the exact borrowed R1 TLS owner is canceled.
    rdp_server::server::security::TsRequestFrameReader credSspFrameReader_{};
    rdp_server::server::security::TsRequestTlsReplyWriter credSspReplyWriter_{};
    bool provisioned_{};
};

} // namespace rdp_server::server::runtime
