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
    // A stale/revoked R2 host session cannot prove listener readiness.
    // Preserve the raw R10 stage for explicit Stop/close retirement.
    view.listenerReady = runtimeStatus.listenerAvailable && !terminalHostSession &&
                         runtimeStatus.lastError != RuntimeHostError::ControlUnavailable;
    view.controlAvailable = runtimeStatus.product.controlAvailable;
    view.credentialsConfigured = runtimeStatus.product.credentialsConfigured;
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

    const bool productMayHost =
        runtimeProductStateMayHost(view.productState) && !terminalHostSession;
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

    if (runtimeStatus.lastError == RuntimeHostError::AuthenticationRejected ||
        runtimeStatus.lastError == RuntimeHostError::AuthenticationRateLimited)
        view.authenticationFailures.push_back(
            toQString(runtimeHostErrorMessage(runtimeStatus.lastError)));
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

void HostControl::stopAndRevoke()
{
    (void)runtime_.stopSharing();
    (void)runtime_.revokeSharing();
}

} // namespace rdp::gui
