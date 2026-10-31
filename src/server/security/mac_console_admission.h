// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "native_desktop_authorization.h"
#include "transport/mcs_channel_connection.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::transport
{
class OwnedPreauthTcpConnection;
}

namespace rdp_server::server::runtime
{
class RuntimeDeploymentPolicy;
}

namespace rdp_server::server::security
{

enum class MacConsoleAdmissionState : std::uint8_t
{
    Ready,
    Prepared,
    TransportAdmitted,
    Admitted,
    Revoked,
};

enum class MacConsoleAdmissionPrepareResult : std::uint8_t
{
    Prepared,
    InvalidState,
    InvalidPermissions,
    AuthenticationUnavailable,
    ConnectionMismatch,
    NativeAuthorizationUnavailable,
    AuthorizationChanged,
    GenerationExhausted,
};

enum class MacConsoleAdmissionRevocationReason : std::uint8_t
{
    None,
    Explicit,
    AuthenticationLost,
    OwnerStop,
    OwnerConsentReplacement,
    ConnectionExpired,
    NativeSessionChanged,
    ListenerReplacement,
    ProtectedCallbackLostAuthority,
};

// R2-owned macOS admission preparation gateway. It owns one native
// authorization lifetime bound to the exact authenticated proof and accepted
// R1 connection supplied at construction. Prepared is deliberately not an
// R1/R3 admitted state. R1 completion is protected first; R3 admission
// requires a later, distinct fresh native visit after the first MCS read. All calls are serialized
// on the existing host owner thread.
//
// The accepted R1 connection, authenticated proof, native evidence source and
// owner-consent authority are borrowed and MUST outlive this broker. The caller
// must revoke/destroy the broker before tearing down or replacing any of them.
class MacConsoleAdmissionBroker final
{
public:
    MacConsoleAdmissionBroker(
        NativeDesktopAuthenticatedSessionProof &authenticatedSession,
        rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
        MacNativeSessionEvidenceSource &nativeEvidence,
        CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept;
    ~MacConsoleAdmissionBroker();

    MacConsoleAdmissionBroker(const MacConsoleAdmissionBroker &) = delete;
    MacConsoleAdmissionBroker &operator=(const MacConsoleAdmissionBroker &) = delete;
    MacConsoleAdmissionBroker(MacConsoleAdmissionBroker &&) = delete;
    MacConsoleAdmissionBroker &operator=(MacConsoleAdmissionBroker &&) = delete;

    [[nodiscard]] MacConsoleAdmissionPrepareResult prepareAdmission(
        std::uint32_t requestedPermissions) noexcept;
    [[nodiscard]] bool revalidate(
        std::uint32_t requiredPermissions) noexcept;
    [[nodiscard]] bool visitNativeAuthorization(
        std::uint32_t requiredPermissions,
        MacNativeDesktopAuthorizationVisitor visitor,
        void *context) noexcept;

    // Finish R1 CredSSP inside the original native/consent visitor before
    // borrowing even the first MCS byte. This enrolls and binds the one R3
    // owner for terminal teardown but does not grant R3 protocol progression.
    [[nodiscard]] bool authorizeR1CredSspAdmission(
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Sole positive R3 Connect-Initial issuer after R1 admission and a fresh
    // native visit. Callers cannot supply generations, booleans or TLS owners.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3McsConnectInitial(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Receipt-bound initial MCS sequence; reauthorize inside each native
    // visitor and preserve R3's exact accepted-byte sequence ownership.
    [[nodiscard]] std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
    authorizeR3ConnectResponseWrite(
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;
    [[nodiscard]] rdp_server::server::transport::McsConnectResponseWriteOutcome
    completeR3ConnectResponseWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3ErectDomain(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Ordered post-Erect Attach and channel join. Every transition and
    // borrowed reply suffix stays inside the original R2 native visitor;
    // receipt tuples are accepted only by R3's sole bounded write owners.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3AttachUser(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
    authorizeR3AttachUserConfirmWrite(
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;
    [[nodiscard]] rdp_server::server::transport::McsConnectResponseWriteOutcome
    completeR3AttachUserConfirmWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] rdp_server::server::transport::McsJoinStartOutcome
    authorizeR3ChannelJoin(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
    authorizeR3ChannelJoinConfirmWrite(
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;
    [[nodiscard]] rdp_server::server::transport::McsJoinWriteOutcome
    completeR3ChannelJoinConfirmWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Client Info acceptance internally performs R3's syntax-only envelope
    // routing, then consumes its unique bounded packet under the same visit.
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpClientInfoPacketSummary>
    authorizeR3ClientInfoPacket(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // The immutable PersonalDesktop policy is borrowed by identity: never
    // let a replacement or AppServer policy alter the admitted R3 branch.
    [[nodiscard]] bool authorizeR3PersonalDesktopLicensingMode(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpServerLicenseRequestWriteView>
    authorizeR3PersonalDesktopServerLicenseRequestWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        const rdp_server::server::transport::RdpServerLicenseIdentity &identity,
        const rdp_server::server::transport::RdpLicensingServiceCredential
            &credential) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome
    completeR3PersonalDesktopServerLicenseRequestWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpLicensingIntake>
    authorizeR3PersonalDesktopClientLicensingMessage(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        const rdp_server::server::transport::RdpLicensingServiceCredential
            &credential,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpPersonalDesktopValidClientWriteView>
    authorizeR3PersonalDesktopValidClientWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpPersonalDesktopValidClientWriteOutcome
    completeR3PersonalDesktopValidClientWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Only the macOS General Capability identity is sent, with R3-owned
    // GCC dimensions and original R2 view/input scope; each activation
    // packet and accepted-byte Share receipt stays inside a fresh visitor.
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpDemandActiveProfileView>
    authorizeR3PersonalDesktopMacDemandActiveProfile(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        rdp_server::server::transport::RdpDemandActiveFeature features) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
    authorizeR3PersonalDesktopShareActivation(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        const rdp_server::server::transport::RdpDemandActiveProfileView
            &profile) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
    authorizeR3PersonalDesktopShareActivationWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpShareActivationWriteOutcome
    completeR3PersonalDesktopShareActivationWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpShareActivationClientIntake
    authorizeR3PersonalDesktopShareActivationPdu(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // One revocable post-Share classification; no readiness/view observation
    // transfers ownership of protected input, clipboard or Graphics actions.
    [[nodiscard]] bool authorizeR3ApplicationTrafficReady(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpPostShareTpktRoute
    classifyR3PostShareTpkt(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpClipboardStaticChannelView>
    authorizeR3ActivatedClipboardChannel(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpClipboardChunkIntake
    authorizeR3ClipboardTpkt(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt,
        std::span<const std::uint8_t> &completePdu) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
    queueR3ClipboardPdu(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::span<const std::uint8_t> completePdu) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
    pendingR3ClipboardWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;
    [[nodiscard]] rdp_server::server::transport::RdpClipboardWriteOutcome
    completeR3ClipboardWrite(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::uint64_t generation, std::uint64_t replySequence,
        std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept;
    [[nodiscard]] std::optional<rdp_server::server::transport::RdpSlowPathInputPdu>
    routeR3SlowPathInputPdu(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<std::uint16_t>
    authorizeR3ActivatedDynamicVirtualChannel(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept;

    // Read-only preflight, never a transfer of R3 mutation authority.
    [[nodiscard]] bool authorizeR3ProtectedTransition(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint32_t requiredPermissions) noexcept;

    // Idempotent terminal retirement. A reason describes the R10 composition
    // event but cannot supply or recreate admission authority.
    void revoke(
        MacConsoleAdmissionRevocationReason reason =
            MacConsoleAdmissionRevocationReason::Explicit) noexcept;

    [[nodiscard]] MacConsoleAdmissionState state() const noexcept
    {
        return state_;
    }
    [[nodiscard]] std::uint64_t admissionGeneration() const noexcept
    {
        return (state_ == MacConsoleAdmissionState::Prepared ||
                state_ == MacConsoleAdmissionState::TransportAdmitted ||
                state_ == MacConsoleAdmissionState::Admitted)
            ? admissionGeneration_
            : 0U;
    }
    [[nodiscard]] MacConsoleAdmissionRevocationReason revocationReason()
        const noexcept
    {
        return revocationReason_;
    }

private:
    struct PreparedLifetime final
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
        std::uint64_t credentialGeneration{};
        std::uint64_t authorizationGeneration{};
    };

    [[nodiscard]] bool personalDesktopPolicyMatches(
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) const noexcept;
    [[nodiscard]] bool visitPersonalDesktopR3Operation(
        rdp_server::server::transport::McsSessionLifecycle &session,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy,
        MacNativeDesktopAuthorizationVisitor visitor,
        void *context,
        std::uint32_t requiredPermissions = kConsoleViewPermission) noexcept;
    [[nodiscard]] bool authenticatedConnectionCurrent() const noexcept;
    [[nodiscard]] bool preparedAuthenticationCurrent() const noexcept;
    [[nodiscard]] bool viewMatchesPreparedLifetime(
        const MacNativeDesktopAuthorizationView &authorization) const noexcept;
    [[nodiscard]] bool validRequiredPermissions(
        std::uint32_t requiredPermissions) const noexcept;
    void revokeForAuthorityLoss(
        MacConsoleAdmissionRevocationReason reason) noexcept;
    [[nodiscard]] bool visitR3ProtectedOperation(
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::uint32_t requiredPermissions,
        MacNativeDesktopAuthorizationVisitor visitor,
        void *context) noexcept;

    NativeDesktopAuthenticatedSessionProof *authenticatedSession_{};
    rdp_server::server::transport::OwnedPreauthTcpConnection *connection_{};
    MacNativeDesktopAuthorization nativeAuthorization_;
    // Borrowed immutable R10 policy. R10 must outlive/revoke the broker before
    // replacing or destroying it; no scalar mode or identity is sufficient.
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        *personalDesktopPolicy_{};
    PreparedLifetime prepared_{};
    // R10 guarantees that both borrowed owners outlive the broker; any R1
    // admission attempt enrolls R3 before calling a callback-capable issuer.
    rdp_server::server::transport::McsSessionLifecycle *admittedSession_{};
    bool admissionAttempted_{};
    std::uint64_t admissionGeneration_{};
    std::uint64_t nextAdmissionGeneration_{};
    MacConsoleAdmissionState state_{MacConsoleAdmissionState::Ready};
    MacConsoleAdmissionRevocationReason revocationReason_{
        MacConsoleAdmissionRevocationReason::None};
    bool visitInProgress_{};
};

} // namespace rdp_server::server::security
