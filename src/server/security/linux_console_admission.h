// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"
#include "gssapi_spnego_acceptor.h"
#include "linux_logind_console_evidence.h"
#include "linux_logind_session_change_watch.h"
#include "transport/mcs_channel_connection.h"
#include "transport/nonblocking_tcp_adapter.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

// Protocol-shape validation only. A true result is never an admission
// capability: positive R2 use accepts this snapshot only when it was obtained
// directly from the same live R1 OwnedPreauthTcpConnection that owns the
// established TLS object used by the GSS/CredSSP transcript.
[[nodiscard]] constexpr bool hasHybridNlaNegotiationProvenance(
    const std::optional<
        rdp_server::server::transport::SecurityNegotiationProvenance>
        &provenance) noexcept
{
    return provenance.has_value() &&
           (provenance->clientRequestedProtocols &
            rdp_server::server::transport::kRdpProtocolHybrid) != 0 &&
           provenance->serverSelectedProtocol ==
               rdp_server::server::transport::kRdpProtocolHybrid;
}

class LinuxConsoleAdmissionControl;
class LinuxConsoleAdmissionBroker;

// Ephemeral R2-only view of the native desktop selected by genuine admission.
// Construction is private and the view cannot be copied, moved or retained.
// It is valid only during LinuxConsoleAdmissionBroker's synchronous visitor.
// Session/display strings and generation numbers are selectors/freshness only;
// this object is never an independently reusable authorization capability.
class LinuxNativeDesktopSelectionView final
{
public:
    LinuxNativeDesktopSelectionView(
        const LinuxNativeDesktopSelectionView &) = delete;
    LinuxNativeDesktopSelectionView &operator=(
        const LinuxNativeDesktopSelectionView &) = delete;
    LinuxNativeDesktopSelectionView(
        LinuxNativeDesktopSelectionView &&) = delete;
    LinuxNativeDesktopSelectionView &operator=(
        LinuxNativeDesktopSelectionView &&) = delete;

    [[nodiscard]] std::string_view sessionId() const noexcept
    {
        return sessionId_;
    }
    [[nodiscard]] std::string_view seat() const noexcept { return seat_; }
    [[nodiscard]] std::string_view display() const noexcept
    {
        return display_;
    }
    [[nodiscard]] std::uint64_t admissionGeneration() const noexcept
    {
        return admissionGeneration_;
    }
    [[nodiscard]] std::uint64_t sessionGeneration() const noexcept
    {
        return sessionGeneration_;
    }

private:
    friend class LinuxConsoleAdmissionBroker;

    LinuxNativeDesktopSelectionView(
        std::string_view sessionId,
        std::string_view seat,
        std::string_view display,
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept
        : sessionId_(sessionId),
          seat_(seat),
          display_(display),
          admissionGeneration_(admissionGeneration),
          sessionGeneration_(sessionGeneration)
    {
    }

    std::string_view sessionId_{};
    std::string_view seat_{};
    std::string_view display_{};
    std::uint64_t admissionGeneration_{};
    std::uint64_t sessionGeneration_{};
};

using LinuxNativeDesktopSelectionVisitor = bool (*)(
    const LinuxNativeDesktopSelectionView &selection,
    void *context) noexcept;

enum class LinuxConsoleAdmissionState : std::uint8_t
{
    Ready,
    Active,
    Revoked,
};

// Move-only R2 capability. Ordinary callers cannot construct one: only the
// concrete LinuxConsoleAdmissionBroker can mint it after genuine GSS/TLS and
// native NSS/logind/session-watch checks. Metadata is bounded and contains no
// password, ticket, keytab or delegated credential plaintext.
//
// The service-owned ConsoleIdentityPolicy must outlive this lease. Dropping
// the lease revokes its shared control epoch. A lease is intentionally not
// self-sufficient for protected R3 transitions: use broker.authorizes(),
// which revalidates live GSS/TLS, policy, logind/NSS and change-watch state.
class LinuxConsoleAdmissionLease final
{
public:
    LinuxConsoleAdmissionLease() = delete;
    ~LinuxConsoleAdmissionLease();

    LinuxConsoleAdmissionLease(const LinuxConsoleAdmissionLease &) = delete;
    LinuxConsoleAdmissionLease &operator=(const LinuxConsoleAdmissionLease &) = delete;
    LinuxConsoleAdmissionLease(LinuxConsoleAdmissionLease &&other) noexcept;
    LinuxConsoleAdmissionLease &operator=(LinuxConsoleAdmissionLease &&other) noexcept;

    // Local revocation/expiry/policy-epoch status only. A false result from
    // isRevoked() does NOT replace broker.authorizes() for protected use.
    [[nodiscard]] bool isRevoked() const noexcept;

    [[nodiscard]] std::string_view kerberosPrincipal() const noexcept;
    [[nodiscard]] std::string_view unixAccount() const noexcept;
    [[nodiscard]] std::string_view sessionId() const noexcept;
    [[nodiscard]] std::uint32_t localUid() const noexcept;
    [[nodiscard]] std::uint64_t sessionGeneration() const noexcept;
    [[nodiscard]] std::uint32_t permissionMask() const noexcept;
    [[nodiscard]] std::uint64_t admissionGeneration() const noexcept;

private:
    friend class LinuxConsoleAdmissionBroker;

    LinuxConsoleAdmissionLease(
        std::shared_ptr<LinuxConsoleAdmissionControl> control,
        std::uint64_t admissionGeneration,
        std::string_view kerberosPrincipal,
        std::string_view unixAccount,
        const ConsoleCandidateSessionFingerprint &fingerprint,
        std::uint32_t permissions) noexcept;

    void revokeControl() noexcept;
    void clearMetadata() noexcept;

    std::shared_ptr<LinuxConsoleAdmissionControl> control_{};
    std::array<char, 129> kerberosPrincipal_{};
    std::array<char, 33> unixAccount_{};
    std::array<char, 65> sessionId_{};
    std::size_t kerberosPrincipalLength_{};
    std::size_t unixAccountLength_{};
    std::size_t sessionIdLength_{};
    std::uint32_t localUid_{};
    std::uint64_t sessionGeneration_{};
    std::uint32_t permissions_{};
    std::uint64_t admissionGeneration_{};
};

// Linux-first production authorization broker. There is deliberately no
// ConsoleOsEvidenceSource or ConsoleSessionChangeSource injection point:
// positive issuance always constructs and owns the concrete NSS/logind reader
// and concrete logind monitor after genuine TLS-bound GSS identity exists.
//
// Broker methods are single-threaded. Lease revocation/expiry observations use
// atomics so an R3 holder can observe terminal revocation safely. The broker
// owns no SSL/GSS object. R1/R2 owners must keep those alive during calls and
// call revoke() before transport teardown. A one-second lease deadline makes
// failure to continue revalidation fail closed.
class LinuxConsoleAdmissionBroker final
{
public:
    explicit LinuxConsoleAdmissionBroker(
        const ConsoleIdentityPolicy &policy) noexcept : policy_(policy) {}
    ~LinuxConsoleAdmissionBroker();

    LinuxConsoleAdmissionBroker(const LinuxConsoleAdmissionBroker &) = delete;
    LinuxConsoleAdmissionBroker &operator=(const LinuxConsoleAdmissionBroker &) = delete;

    // Positive issuance consumes the exact R1 connection owner. TLS and
    // immutable X.224 negotiation provenance are borrowed synchronously from
    // that owner; neither can be supplied independently by the caller.
    [[nodiscard]] std::optional<LinuxConsoleAdmissionLease> issue(
        GssapiSpnegoAcceptor &acceptor,
        rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
        const ConsoleEvidenceRequest &request) noexcept;

    // Legacy compatibility path is intentionally terminal deny-only. A raw
    // SSL pointer, even when genuinely established, cannot prove which X.224
    // security protocol the owning R1 connection actually selected.
    [[nodiscard]] std::optional<LinuxConsoleAdmissionLease> issue(
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls,
        const ConsoleEvidenceRequest &request) noexcept;

    [[nodiscard]] bool revalidate(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection) noexcept;

    // Required R3 consumption gate. Permission checks and all current
    // provenance checks happen immediately before a protected transition.
    // A native session event can still race after the final logind poll;
    // callers must monitor nativeChangeFd() and revoke on disconnect/teardown.
    [[nodiscard]] bool authorizes(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        std::uint32_t requiredPermissions) noexcept;

    // R3 Basic Settings handoff. This is the only positive entry into the
    // current McsSessionLifecycle: revalidate concrete native admission with
    // view permission immediately before letting R3 parse/retain state from
    // Connect Initial. No caller-supplied bool/proof can invoke the private
    // R3 transition. Any R3 parse/order failure revokes the whole lease.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3McsConnectInitial(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Reauthorization gate for every later protected R3 transition. The R3
    // owner first revokes itself unless its stored admission/native-session
    // generations still match this exact lease, then R2 repeats permission,
    // GSS/TLS, policy, NSS/logind and native-watch validation. This method
    // never advances R3 state or writes bytes. Any failure closes R3 and
    // revokes R2/GSS so a stale capability cannot be retried elsewhere.
    [[nodiscard]] bool authorizeR3ProtectedTransition(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint32_t requiredPermissions) noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::transport::McsConnectResponseWriteView>
    authorizeR3ConnectResponseWrite(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Accepted-byte completion is itself a protected R3 publication point.
    // Require the same concrete lease plus exact R1 owner, then revalidate
    // live TLS/provenance and native admission before R3 consumes a receipt.
    // A null lease is denial-only and exists so ordinary CI can execute the
    // fail-closed path without fabricating a positive production capability.
    [[nodiscard]]
    rdp_server::server::transport::McsConnectResponseWriteOutcome
    completeR3ConnectResponseWrite(
        const LinuxConsoleAdmissionLease *lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Protected input-only Erect transition. Derive TLS from the same R1
    // owner, freshly authorize, then let the sole R3 owner consume one PDU.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3ErectDomain(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Protected one-shot Attach User intake. A successful packet alone is not
    // a joined channel; the R3-owned 11-byte confirmation must still complete.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3AttachUser(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Each byte slice is borrowed from the sole R3 owner only after renewed
    // R2 and exact R1 TLS/HYBRID provenance authorization. R1 alone encrypts.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::McsConnectResponseWriteView>
    authorizeR3AttachUserConfirmWrite(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // A null lease is strictly denial-only for ordinary offline tests.
    // Completes only bytes already accepted by R1, after fresh R2 checks.
    [[nodiscard]]
    rdp_server::server::transport::McsConnectResponseWriteOutcome
    completeR3AttachUserConfirmWrite(
        const LinuxConsoleAdmissionLease *lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Post-Attach Channel Join still requires the original R1 owner and live
    // native R2 authorization. The existing gate handles only allocated
    // channel IDs and one reply at a time; it does not activate Send Data.
    [[nodiscard]] rdp_server::server::transport::McsJoinStartOutcome
    authorizeR3ChannelJoin(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::transport::McsConnectResponseWriteView>
    authorizeR3ChannelJoinConfirmWrite(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Null is denial-only, never an alternative positive admission source.
    [[nodiscard]] rdp_server::server::transport::McsJoinWriteOutcome
    completeR3ChannelJoinConfirmWrite(
        const LinuxConsoleAdmissionLease *lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Synchronous, non-capability CLIPRDR channel observation after
    // genuine R2 lease and exact R1-owned TLS reauthorization.
    // No licensing, Share or clipboard payload permission is granted.
    [[nodiscard]] std::optional<std::uint16_t>
    authorizeR3JoinedClipboardChannel(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Consume one fully routed and structurally valid TS_INFO_PACKET after
    // fresh R1/R2 authorization. Sensitive variable strings are not exposed.
    // Success moves only to AwaitServerLicenseRequest; licensing remains
    // NotStarted until a future receipt-bound server request completes.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpClientInfoPacketSummary>
    authorizeR3ClientInfoPacket(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Start or resume the sole R3-owned SERVER_LICENSE_REQUEST write only
    // after fresh view permission plus exact R1 HYBRID/TLS/GSS/native-session
    // reauthorization. The immutable identity supplies service provisioning;
    // R3 generates ServerRandom internally. Neither is R2/license authority.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpServerLicenseRequestWriteView>
    authorizeR3ServerLicenseRequestWrite(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::transport::RdpServerLicenseIdentity
            &identity,
        const rdp_server::server::transport::RdpLicensingServiceCredential
            &credential) noexcept;

    // Accepted bytes are not durable R3 progress until the same concrete
    // lease and owner reauthorize the receipt. A null lease is denial-only
    // for ordinary CI and can never advance licensing.
    [[nodiscard]]
    rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome
    completeR3ServerLicenseRequestWrite(
        const LinuxConsoleAdmissionLease *lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Publish/resume the one standards-required Server Platform Challenge
    // only after a fresh lease/R1-owner authorization. Challenge bytes and
    // derived licensing keys stay inside R3 and are never caller inputs.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpServerPlatformChallengeWriteView>
    authorizeR3ServerPlatformChallengeWrite(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    [[nodiscard]]
    rdp_server::server::transport::RdpServerPlatformChallengeWriteOutcome
    completeR3ServerPlatformChallengeWrite(
        const LinuxConsoleAdmissionLease *lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Consume exactly one complete client licensing response only after the
    // server request's full receipt and another fresh authorization of the
    // same native lease/R1 owner. R3 validates global-I/O/segmentation and
    // SEC_LICENSE_PKT before the licensing lifecycle sees the message.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpLicensingIntake>
    authorizeR3ClientLicensingMessage(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::transport::RdpLicensingServiceCredential
            &credential,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Consume exactly one response to the fully delivered Server Platform
    // Challenge after another fresh protected-transition authorization.
    // R3 verifies challenge/HWID/MAC with its retained keys and stops before
    // New License issuance.
    [[nodiscard]] std::optional<
        rdp_server::server::transport::RdpLicensingIntake>
    authorizeR3ClientPlatformChallengeResponse(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::transport::RdpLicensingServiceCredential
            &credential,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Ordered R3 -> R2/GSS cancellation barrier. The caller must stop protocol
    // buffers first, call this, and only then release R1 TLS/socket ownership.
    // Idempotent and safe when no positive lease was ever issued.
    void revokeR3Session(
        GssapiSpnegoAcceptor &acceptor,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Event-loop callback for readiness on nativeChangeFd(). A real logind
    // change or monitor failure closes R3 first, then revokes R2/GSS. A
    // spurious wake with no queued change leaves state untouched and grants
    // no permission; the caller must still call authorizes() immediately
    // before every later protected R3 transition.
    [[nodiscard]] bool onNativeSessionChangeReady(
        GssapiSpnegoAcceptor &acceptor,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Connection/R3 teardown path: terminally invalidates the capability and
    // clears the GSS context. Idempotent.
    void revoke(GssapiSpnegoAcceptor &acceptor) noexcept;

    // R10 may synchronously consume the admitted native desktop selection
    // only through this visitor. R2 revalidates TLS/GSS, PAM-derived account
    // binding, NSS/logind evidence and its change monitor immediately before
    // and after the visitor. The view must not escape the callback. A missing
    // lease, failed revalidation or consumer failure is terminal.
    [[nodiscard]] bool visitNativeDesktopSelection(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        LinuxNativeDesktopSelectionVisitor visitor,
        void *context) noexcept;

    [[nodiscard]] LinuxConsoleAdmissionState state() const noexcept;
    [[nodiscard]] int nativeChangeFd() const noexcept;
    [[nodiscard]] int nativeChangeEvents() const noexcept;

private:
    void revokeControl() noexcept;
    void clearRequest() noexcept;
    void deny(GssapiSpnegoAcceptor &acceptor) noexcept;
    [[nodiscard]] bool refreshDeadline(std::uint64_t generation) noexcept;
    [[nodiscard]] bool revalidationChecksPass(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls) noexcept;
    [[nodiscard]] bool authorizationChecksPass(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls,
        std::uint32_t requiredPermissions) noexcept;
    [[nodiscard]] bool authorizeR3ProtectedTransitionForEstablishedTls(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint32_t requiredPermissions) noexcept;
    [[nodiscard]] bool ownsActiveLease(
        const LinuxConsoleAdmissionLease &lease) const noexcept;
    [[nodiscard]] ConsoleEvidenceRequest requestView(
        const LinuxConsoleAdmissionLease &lease) const noexcept;

    const ConsoleIdentityPolicy &policy_;
    LinuxLogindReadOnlyEvidenceSource evidence_{};
    std::unique_ptr<LinuxLogindSessionChangeSource> changes_{};
    std::shared_ptr<LinuxConsoleAdmissionControl> control_{};
    std::array<char, 17> seat_{};
    std::array<char, 9> display_{};
    std::size_t seatLength_{};
    std::size_t displayLength_{};
    LinuxConsoleAdmissionState state_{LinuxConsoleAdmissionState::Ready};
};

} // namespace rdp_server::server::security
