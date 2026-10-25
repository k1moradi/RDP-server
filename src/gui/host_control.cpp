// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_control.h"

#include <algorithm>

#include <string>
#include <string_view>
#include <utility>

namespace rdp::gui
{
namespace
{
using rdp_server::server::runtime::RuntimeHostStage;
using rdp_server::server::runtime::RuntimeHostError;

// A terminal R2/native ownership loss overrides a stale GUI snapshot.
// Transient per-peer authentication failures/limits do not revoke other
// already-authorized clients and must remain diagnostic-only.
[[nodiscard]] constexpr bool hasTerminalHostSessionError(
    RuntimeHostError error) noexcept
{
    return error == RuntimeHostError::HostSessionStale ||
           error == RuntimeHostError::AccessRevoked;
}

[[nodiscard]] QString toQString(std::string_view value)
{
    return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
}

[[nodiscard]] QString localDesktopAuthorizationDiagnosticText(
    const rdp_server::server::runtime::
        RuntimeAcceptedClientAdmissionFailureReason reason)
{
    using Reason = rdp_server::server::runtime::
        RuntimeAcceptedClientAdmissionFailureReason;
    switch (reason)
    {
    case Reason::SessionMonitorUnavailable:
        return QStringLiteral(
            "Local desktop authorization: session monitor unavailable");
    case Reason::SessionChangedBeforeSample:
    case Reason::PolicyGenerationChanged:
        return QStringLiteral(
            "Local desktop authorization: active session changed");
    case Reason::None:
    case Reason::OwnerConsentMissing:
    case Reason::HybridTlsProvenanceInvalid:
    case Reason::AuthenticationProofMismatch:
    case Reason::AdmissionRequestInvalid:
    case Reason::AccountEvidenceUnavailable:
    case Reason::AccountIdentityMismatch:
    case Reason::ConsoleSessionUnavailable:
    case Reason::ConsoleNotActive:
    case Reason::ConsoleNotPhysical:
    case Reason::ConsoleSessionInvalid:
    case Reason::SeatMismatch:
    case Reason::DisplayMismatch:
    case Reason::ConsoleOwnerMismatch:
    case Reason::EvidenceTooOld:
    case Reason::PolicyMismatch:
    case Reason::NativeProofCompletionFailed:
    case Reason::CredSspAdmissionCompletionFailed:
        return QStringLiteral("Local desktop authorization: unavailable");
    }
    return QStringLiteral("Local desktop authorization: unavailable");
}

[[nodiscard]] constexpr bool isConfirmedLocalDesktopAuthorizationFailure(
    const rdp_server::server::runtime::
        RuntimeAcceptedClientPreauthDiagnostics& diagnostics) noexcept
{
    using namespace rdp_server::server::runtime;
    return diagnostics.available &&
           diagnostics.credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::CredentialsVerified &&
           diagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::Admission &&
           diagnostics.admissionFailureReason !=
               RuntimeAcceptedClientAdmissionFailureReason::None;
}

[[nodiscard]] constexpr bool isRemoteAuthenticationIncompleteBeforeAdmission(
    const rdp_server::server::runtime::
        RuntimeAcceptedClientPreauthDiagnostics& diagnostics) noexcept
{
    using namespace rdp_server::server::runtime;
    if (!diagnostics.available ||
        diagnostics.ntlmEnvelope !=
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm ||
        diagnostics.admissionFailureReason !=
            RuntimeAcceptedClientAdmissionFailureReason::None ||
        diagnostics.termination != RuntimeAcceptedClientTermination::PeerEof)
    {
        return false;
    }

    const bool retainedChallengeBoundary =
        diagnostics.authenticationStage ==
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge &&
        diagnostics.credSspTransition ==
            RuntimeAcceptedClientCredSspTransition::Closed &&
        diagnostics.standaloneFailureStage ==
            RuntimeAcceptedClientStandaloneFailureStage::None;
    const bool legacyMisclassifiedBoundary =
        diagnostics.authenticationStage ==
            RuntimeAcceptedClientAuthenticationStage::Admission &&
        diagnostics.credSspTransition ==
            RuntimeAcceptedClientCredSspTransition::Failed &&
        diagnostics.standaloneFailureStage ==
            RuntimeAcceptedClientStandaloneFailureStage::Admission;
    return retainedChallengeBoundary || legacyMisclassifiedBoundary;
}

[[nodiscard]] QString authenticationDiagnosticText(
    const rdp_server::server::runtime::
        RuntimeAcceptedClientPreauthDiagnostics& diagnostics)
{
    using namespace rdp_server::server::runtime;
    if (!diagnostics.available)
        return {};

    if (isRemoteAuthenticationIncompleteBeforeAdmission(diagnostics))
    {
        return diagnostics.authenticationStage ==
                       RuntimeAcceptedClientAuthenticationStage::NtlmChallenge
            ? QStringLiteral(
                  "Authentication: NTLM challenge sent; "
                  "client disconnected before response.")
            : QStringLiteral(
                  "Authentication: Direct NTLM — "
                  "client disconnected before authentication completed.");
    }

    if (diagnostics.authenticationStage ==
            RuntimeAcceptedClientAuthenticationStage::Admission ||
        diagnostics.credSspTransition !=
            RuntimeAcceptedClientCredSspTransition::Failed)
    {
        return {};
    }

    QString envelope;
    switch (diagnostics.ntlmEnvelope)
    {
    case RuntimeAcceptedClientNtlmEnvelope::Undetermined:
        break;
    case RuntimeAcceptedClientNtlmEnvelope::Spnego:
        envelope = QStringLiteral("SPNEGO");
        break;
    case RuntimeAcceptedClientNtlmEnvelope::DirectNtlm:
        envelope = QStringLiteral("Direct NTLM");
        break;
    }

    QString failure;
    switch (diagnostics.standaloneFailureStage)
    {
    case RuntimeAcceptedClientStandaloneFailureStage::None:
        failure = QStringLiteral("authentication failed");
        break;
    case RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation:
    case RuntimeAcceptedClientStandaloneFailureStage::Spnego:
        failure = QStringLiteral("negotiation failed");
        break;
    case RuntimeAcceptedClientStandaloneFailureStage::Mic:
        failure = QStringLiteral("integrity check failed");
        break;
    case RuntimeAcceptedClientStandaloneFailureStage::SignSeal:
        failure = QStringLiteral("message protection failed");
        break;
    case RuntimeAcceptedClientStandaloneFailureStage::PubKeyAuth:
        failure = QStringLiteral("TLS binding failed");
        break;
    case RuntimeAcceptedClientStandaloneFailureStage::AuthInfo:
        failure = QStringLiteral("credential verification failed");
        break;
    case RuntimeAcceptedClientStandaloneFailureStage::Admission:
        failure = QStringLiteral("session admission failed");
        break;
    }

    return envelope.isEmpty()
        ? QStringLiteral("Authentication: CredSSP — ") + failure
        : QStringLiteral("Authentication: CredSSP — ") + envelope +
              QStringLiteral(" — ") + failure;
}

} // namespace

HostControl::HostControl(
    rdp_server::server::runtime::RuntimeHostControl& runtime) noexcept
    : runtime_(runtime)
{
}

HostStatus HostControl::status() const
{
    using namespace rdp_server::server::runtime;

    const RuntimeHostStatus runtimeStatus = runtime_.status();
    HostStatus view;
    view.stage = runtimeStatus.stage;
    view.productState = runtimeStatus.product.state;
    const bool terminalHostSession =
        hasTerminalHostSessionError(runtimeStatus.lastError) ||
        runtimeStatus.stage == RuntimeHostStage::Revoked;
    const bool productMayHost =
        runtimeProductStateMayHost(view.productState) && !terminalHostSession;
    // A stale/revoked R2 host session cannot prove listener readiness.
    // Preserve the raw R10 stage for explicit Stop/close retirement.
    view.listenerReady = (runtimeStatus.listenerAvailable || productMayHost) &&
                         !terminalHostSession &&
                         runtimeStatus.lastError != RuntimeHostError::ControlUnavailable;
    view.controlAvailable = runtimeStatus.product.controlAvailable;
    view.credentialsConfigured = runtimeStatus.product.credentialsConfigured;
    view.credentialEditingAllowed =
        runtimeStatus.product.credentialEditingAllowed;
    view.credentialCapabilities =
        runtimeStatus.product.credentialCapabilities;
    view.desktopAuthorized =
        runtimeStatus.product.ownerAuthorized && !terminalHostSession;
    // R10 has already reduced owner consent to product language facts.
    view.sharingPermission = runtimeStatus.product.sharingPermission;
    // Terminal ownership loss and unavailable control invalidate stale TLS
    // observations. A configured certificate is not permission to listen.
    const bool tlsObservationCurrent =
        !terminalHostSession &&
        runtimeStatus.lastError != RuntimeHostError::ControlUnavailable &&
        runtimeStatus.tlsIdentity.endpointGenerationIsCurrent(
            runtimeStatus.listenerGeneration);
    view.tlsReady =
        tlsObservationCurrent && runtimeStatus.product.tlsIdentityReady;
    if (tlsObservationCurrent)
        view.tlsIdentity = runtimeStatus.tlsIdentity;
    view.tlsFingerprint = runtimeStatus.product.tlsFingerprint;
    view.tlsFingerprintAvailable =
        runtimeStatus.product.tlsFingerprintAvailable && tlsObservationCurrent;

    view.graphicsReady =
        productMayHost && runtimeStatus.graphicsReady && !terminalHostSession;
    view.nativeDesktopReady =
        productMayHost && runtimeStatus.nativeDesktopReady && !terminalHostSession;
    view.nativeDesktopInitializing =
        productMayHost && runtimeStatus.nativeDesktopInitializing &&
        !view.nativeDesktopReady;
    view.captureInputReady = view.nativeDesktopReady;
    view.clientDisconnected =
        runtimeStatus.clientDisconnected && view.listenerReady &&
        view.productState == RuntimeProductHostState::Listening;
    view.sharing =
        runtimeProductStateSharingToggleOn(view.productState) &&
        !terminalHostSession;
    view.startPending =
        view.productState == RuntimeProductHostState::Starting &&
        !terminalHostSession;
    view.clipboardState = runtimeStatus.clipboardState;
    if (runtimeStatus.product.nativeDesktopTargetAvailable &&
        !runtimeStatus.product.nativeDesktopTarget.empty())
    {
        view.desktop =
            QStringLiteral("Physical X11 desktop ") +
            toQString(runtimeStatus.product.nativeDesktopTarget);
    }

    // R10 owns the exact native interface/endpoint selection policy.
    // Project only eligible choices; a GUI label or wildcard is not bind
    // authority. The selected user port is revalidated by R10 on Start.
    const std::vector<RuntimeHostInterface>& interfaces =
        runtimeStatus.product.eligibleLanInterfaces;
    for (const RuntimeHostInterface& interface : interfaces)
    {
        for (const std::string& address : interface.localAddresses)
        {
            const RuntimeHostOptions candidate{
                interface.stableId, address, 3389U, true, false};
            if (!assessRuntimeSelectedLanEndpoint(candidate, interfaces).succeeded())
                continue;

            view.approvedLanInterfaces.push_back({
                toQString(interface.stableId), toQString(interface.displayName),
                toQString(address)});
        }
    }

    view.recommendedInterfaceId =
        toQString(runtimeStatus.product.recommendedEndpoint.interfaceId);
    view.recommendedAddress =
        toQString(runtimeStatus.product.recommendedEndpoint.address);
    view.recommendedPort = runtimeStatus.product.recommendedEndpoint.port;
    view.recommendationSource =
        runtimeStatus.product.recommendedEndpoint.source;
    view.clientCount = runtimeStatus.product.clientCount;

    if (view.controlAvailable && productMayHost && !terminalHostSession)
    {
        view.lanAddress = toQString(runtimeStatus.product.boundEndpoint);
        for (const RuntimeHostClient& client : runtimeStatus.activeClients)
        {
            if (!std::ranges::any_of(
                    runtimeStatus.product.activeClientIds,
                    [id = client.opaqueId](std::uint64_t candidate) {
                        return candidate == id;
                    }))
                continue;

            const QString displayName = client.peerAddress.empty()
                ? QStringLiteral("Client %1").arg(client.opaqueId)
                : toQString(client.peerAddress);
            if (view.nativeDesktopReady &&
                view.productState == RuntimeProductHostState::Connected &&
                client.shareActivated && client.desktopVisible &&
                !client.authenticating)
            {
                view.clients.push_back(displayName);
            }
            else if (client.authenticating)
            {
                view.pendingClients.push_back(
                    QStringLiteral("Authenticating: ") + displayName);
            }
            else if (client.shareActivated)
            {
                if (view.nativeDesktopInitializing)
                    view.pendingClients.push_back(
                        QStringLiteral("Native desktop initializing: ") +
                        displayName);
                else if (view.graphicsReady)
                    view.pendingClients.push_back(
                        QStringLiteral("Graphics ready; native desktop pending: ") +
                        displayName);
                else
                    view.pendingClients.push_back(
                        QStringLiteral("Share activated; desktop pending: ") +
                        displayName);
            }
            else
            {
                view.pendingClients.push_back(
                    QStringLiteral("Desktop not confirmed: ") + displayName);
            }

            // R10 owns the lifetime of this opaque disconnect handle,
            // including for authentications which are still pending.
            if (client.opaqueId != 0)
                view.activeClients.push_back({client.opaqueId, displayName});
        }
    }

    const auto& authenticationDiagnostics =
        runtimeStatus.acceptedClientPreauthDiagnostics;
    const bool localDesktopAuthorizationFailed =
        runtimeStatus.lastError == RuntimeHostError::AuthenticationRejected &&
        isConfirmedLocalDesktopAuthorizationFailure(authenticationDiagnostics);
    view.localDesktopAuthorizationFailed =
        localDesktopAuthorizationFailed;
    view.remoteAuthenticationIncomplete =
        runtimeStatus.lastError == RuntimeHostError::AuthenticationRejected &&
        !localDesktopAuthorizationFailed &&
        isRemoteAuthenticationIncompleteBeforeAdmission(
            authenticationDiagnostics);

    if ((runtimeStatus.lastError == RuntimeHostError::AuthenticationRejected ||
         runtimeStatus.lastError == RuntimeHostError::AuthenticationRateLimited) &&
        !localDesktopAuthorizationFailed)
    {
        view.remoteAuthenticationFailed = true;
        view.authenticationFailures.push_back(
            view.remoteAuthenticationIncomplete
                ? QStringLiteral(
                      "Remote client authentication did not complete.")
                : QStringLiteral("Remote client authentication failed."));
    }

    view.authenticationDiagnostic =
        localDesktopAuthorizationFailed
            ? localDesktopAuthorizationDiagnosticText(
                  authenticationDiagnostics.admissionFailureReason)
            : authenticationDiagnosticText(authenticationDiagnostics);
    if (view.clientDisconnected)
        view.disconnected.push_back(
            QStringLiteral("Client disconnected; listener remains active"));
    if (runtimeStatus.stage == RuntimeHostStage::Revoked ||
        runtimeStatus.lastError == RuntimeHostError::AccessRevoked)
        view.revoked.push_back(QStringLiteral("Sharing access revoked"));
    if (!runtimeStatus.product.lastErrorMessage.empty())
        view.failure = toQString(runtimeStatus.product.lastErrorMessage);
    return view;
}

bool HostControl::requestExistingOsAccount()
{
    using rdp_server::server::security::LanCredentialChoice;
    return runtime_.requestCredentialSetup(
        LanCredentialChoice::ExistingOsAccount).succeeded();
}

bool HostControl::configureStandalonePassword(
    const QString& username, const QString& password)
{
    const std::u16string usernameUtf16 = username.toStdU16String();
    std::u16string mutablePassword = password.toStdU16String();
    return runtime_.configureStandaloneApplicationPassword(
        usernameUtf16, std::span<char16_t>{mutablePassword});
}

bool HostControl::requestHostPermission(
    const rdp_server::server::runtime::RuntimeHostPermissionRequest& request)
{
    return runtime_.requestHostPermissionSetup(request).succeeded();
}

bool HostControl::start(const HostRequest& request)
{
    using namespace rdp_server::server::runtime;

    // A GUI snapshot is an early denial gate, never R2/R1 authorization.
    // The concrete R10 owner must still reauthorize every native operation.
    const RuntimeHostStatus snapshot = runtime_.status();
    if (snapshot.lastError == RuntimeHostError::ControlUnavailable ||
        hasTerminalHostSessionError(snapshot.lastError) ||
        snapshot.stage == RuntimeHostStage::Revoked ||
        !snapshot.product.credentialsConfigured ||
        !snapshot.product.ownerAuthorized ||
        runtimeProductStateMayHost(snapshot.product.state) ||
        request.interfaceId.isEmpty() || request.interfaceAddress.isEmpty())
        return false;

    const RuntimeHostOptions options{
        request.interfaceId.toStdString(),
        request.interfaceAddress.toStdString(), request.port, true, false};
    // This pure preflight reduces duplicate UI/runtime selector policy; the
    // live R10 owner must still re-enumerate and prove its actual R1 bind.
    if (!assessRuntimeSelectedLanEndpoint(
             options, snapshot.product.eligibleLanInterfaces).succeeded() ||
        !runtime_.configure(options).succeeded())
        return false;

    // Endpoint-bound automatic TLS identity is prepared by R10/R1 configure,
    // before R1 may open a listener. Re-read authoritative state rather than
    // allowing the pre-configuration GUI snapshot to authorize Start.
    const RuntimeHostStatus prepared = runtime_.status();
    if (!prepared.product.credentialsConfigured ||
        !prepared.product.ownerAuthorized ||
        !prepared.product.tlsIdentityReady ||
        prepared.listenerAvailable)
        return false;
    return runtime_.startSharing().succeeded();
}

bool HostControl::disconnectClient(const std::uint64_t opaqueClientId)
{
    using namespace rdp_server::server::runtime;
    if (opaqueClientId == 0)
        return false;

    const RuntimeHostStatus snapshot = runtime_.status();
    if (snapshot.lastError == RuntimeHostError::ControlUnavailable ||
        hasTerminalHostSessionError(snapshot.lastError) ||
        snapshot.stage == RuntimeHostStage::Revoked ||
        !runtimeProductStateMayHost(snapshot.product.state) ||
        !std::ranges::any_of(
            snapshot.product.activeClientIds,
            [opaqueClientId](std::uint64_t clientId) {
                return clientId == opaqueClientId;
            }))
        return false;

    // R10 alone owns actual disconnect/revocation; this result is not proof.
    return runtime_.disconnectClient(opaqueClientId).succeeded();
}

void HostControl::stop()
{
    const auto snapshot = runtime_.status();
    (void)runtime_.stopSharing();

    // Ordinary Sharing OFF is not a security revoke. A terminal host-session
    // loss is different: force the runtime's full revoke path so credentials
    // cannot survive stale native ownership.
    if (hasTerminalHostSessionError(snapshot.lastError) ||
        snapshot.stage == RuntimeHostStage::Revoked)
    {
        (void)runtime_.revokeSharing();
    }
}

void HostControl::stopAndRevoke()
{
    (void)runtime_.stopSharing();
    (void)runtime_.revokeSharing();
}

} // namespace rdp::gui
