// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "linux_runtime_security.h"
#include "runtime_deployment_policy.h"
#include "runtime_licensing_authority.h"
#include "runtime_licensing_context.h"
#include "server/security/credssp_tsrequest.h"
#include "runtime_tls_context.h"
#include "server/security/linux_console_admission.h"
#include "server/transport/mcs_channel_connection.h"
#include "server/transport/nonblocking_tcp_adapter.h"

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
        snapshot.graphicsWritePending)
    {
        return Interest::Write;
    }

    return snapshot.r1Interest;
}
} // namespace detail

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
        rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket)
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

    // Transfer one prepared R4 frame into the current R3 Graphics DVC. This
    // method owns no protocol IDs or receipt accounting; R2 reauthorizes the
    // move and R3 maps every frame byte to the R1 plaintext records driven by
    // advancePersonalDesktopGraphicsDynamicVirtualChannel().
    [[nodiscard]] bool startPersonalDesktopGraphicsFramePublication(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        rdp_server::rdp::GfxPresentationLifecycle &presentationLifecycle,
        rdp_server::rdp::GfxAvc420SegmentedFrame &&frame,
        rdp_server::server::transport::RdpGraphicsFrameCodec codec) noexcept;

    // Legal only while R3 proves that R1 accepted zero outer plaintext bytes.
    // Positive or uncertain progress is never translated into cancellation.
    [[nodiscard]] bool cancelUnwrittenPersonalDesktopGraphicsFrame(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

    [[nodiscard]] bool authorizePersonalDesktopApplicationTraffic(
        const RuntimeDeploymentPolicy &deploymentPolicy) noexcept;

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
    [[nodiscard]] bool hasAdmissionLease() const noexcept
    {
        return lease_.has_value() && !lease_->isRevoked();
    }

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
    [[nodiscard]] bool postAdmissionMcsPolicyMatches(
        const RuntimeDeploymentPolicy &deploymentPolicy) const noexcept;
    // Membership-only R3 inspection; call only after fresh R2 admission
    // authorization. This never grants channel or desktop access.
    [[nodiscard]] bool allNegotiatedMcsChannelsJoined() const noexcept;
    [[nodiscard]] bool reauthorizeExistingCalValidation() noexcept;
    [[nodiscard]] bool nativeChangeRegistrationMatches(
        const LinuxRuntimeNativeChangeRegistration &registration) const
        noexcept;

    LinuxRuntimeSecurityConfiguration &securityConfiguration_;

    // Declaration order is deliberate. Explicit revoke() performs the
    // security ordering; reverse member destruction is also safe if a future
    // exception-free constructor path returns early: R3/lease/broker/GSS die
    // before R1's connection owner.
    rdp_server::server::transport::OwnedPreauthTcpConnection connection_;
    rdp_server::server::security::GssapiSpnegoAcceptor acceptor_{};
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
    std::optional<RuntimeExistingCalValidationBinding>
        existingCalValidation_{};
    std::optional<LinuxRuntimeNativeChangeRegistration>
        nativeChangeRegistration_{};
    bool nativeChangeRegistrationUnregistered_{};
    // Retired explicitly before the exact borrowed R1 TLS owner is canceled.
    rdp_server::server::security::TsRequestFrameReader credSspFrameReader_{};
    rdp_server::server::security::TsRequestTlsReplyWriter credSspReplyWriter_{};
    bool provisioned_{};
};

} // namespace rdp_server::server::runtime
