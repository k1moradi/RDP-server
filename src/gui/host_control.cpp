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

[[nodiscard]] bool isSharingStage(RuntimeHostStage stage) noexcept
{
    switch (stage)
    {
    case RuntimeHostStage::ShareActivated:
    case RuntimeHostStage::DesktopVisible:
    case RuntimeHostStage::ClientConnected:
        return true;
    case RuntimeHostStage::Stopped:
    case RuntimeHostStage::PackageInstalled:
    case RuntimeHostStage::CredentialsConfigured:
    case RuntimeHostStage::ListenerAvailable:
    case RuntimeHostStage::ClientAuthenticating:
    case RuntimeHostStage::Revoked:
        return false;
    }
    return false;
}

[[nodiscard]] bool isPendingStage(RuntimeHostStage stage) noexcept
{
    return stage == RuntimeHostStage::ListenerAvailable ||
           stage == RuntimeHostStage::ClientAuthenticating;
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
    const bool terminalHostSession =
        hasTerminalHostSessionError(runtimeStatus.lastError) ||
        runtimeStatus.stage == RuntimeHostStage::Revoked;
    // A stale/revoked R2 host session cannot prove listener readiness.
    // Preserve the raw R10 stage for explicit Stop/close retirement.
    view.listenerReady = runtimeStatus.listenerAvailable && !terminalHostSession &&
                         runtimeStatus.lastError != RuntimeHostError::ControlUnavailable;
    view.controlAvailable =
        runtimeStatus.lastError != RuntimeHostError::ControlUnavailable;
    view.credentialsConfigured = runtimeStatus.credentialsConfigured;
    view.desktopAuthorized =
        runtimeStatus.hostOwnerAuthorized && !terminalHostSession;
    view.tlsReady = runtimeStatus.tlsIdentityReady;
    view.tlsIdentity = runtimeStatus.tlsIdentity;
    view.captureInputReady =
        runtimeStatus.nativeDesktopReady && !terminalHostSession;
    view.sharing =
        isSharingStage(runtimeStatus.stage) && !terminalHostSession;
    view.startPending =
        isPendingStage(runtimeStatus.stage) && !terminalHostSession;
    view.clipboardState = runtimeStatus.clipboardState;
    if (view.desktopAuthorized)
        view.desktop = QStringLiteral("Authorized logged-in desktop");

    // R10 owns the exact native interface/endpoint selection policy.
    // Project only eligible choices; a GUI label or wildcard is not bind
    // authority. The selected user port is revalidated by R10 on Start.
    const std::vector<RuntimeHostInterface> interfaces =
        runtime_.enumerateLocalInterfaces();
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

    // A stale or unavailable runtime snapshot cannot prove a bound endpoint
    // or client presence. Keep pending and connected clients distinct: an
    // R2 authentication attempt is not a visible, admitted R3 desktop.
    const bool sharingStage = isSharingStage(runtimeStatus.stage);
    const bool activeStage = sharingStage || isPendingStage(runtimeStatus.stage);
    if (view.controlAvailable && activeStage && !terminalHostSession)
    {
        view.lanAddress = toQString(runtimeStatus.boundEndpoint);
        for (const RuntimeHostClient& client : runtimeStatus.activeClients)
        {
            const QString displayName = client.peerAddress.empty()
                ? QStringLiteral("Client %1").arg(client.opaqueId)
                : toQString(client.peerAddress);
            if (sharingStage && client.shareActivated &&
                client.desktopVisible && !client.authenticating)
                view.clients.push_back(displayName);
            else if (client.authenticating)
                view.pendingClients.push_back(
                    QStringLiteral("Authenticating: ") + displayName);
            else if (client.shareActivated && !client.desktopVisible)
                view.pendingClients.push_back(
                    QStringLiteral("Share activated; desktop pending: ") +
                    displayName);
            else
                view.pendingClients.push_back(
                    QStringLiteral("Desktop not confirmed: ") + displayName);

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
    if (runtimeStatus.stage == RuntimeHostStage::Revoked ||
        runtimeStatus.lastError == RuntimeHostError::AccessRevoked)
        view.revoked.push_back(QStringLiteral("Sharing access revoked"));
    if (runtimeStatus.lastError != RuntimeHostError::None)
        view.failure = toQString(runtimeHostErrorMessage(runtimeStatus.lastError));
    return view;
}

bool HostControl::requestExistingOsAccount()
{
    using rdp_server::server::security::LanCredentialChoice;
    return runtime_.requestCredentialSetup(
        LanCredentialChoice::ExistingOsAccount).succeeded();
}

bool HostControl::requestHostPermission()
{
    return runtime_.requestHostPermissionSetup().succeeded();
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
        !snapshot.credentialsConfigured || !snapshot.hostOwnerAuthorized ||
        !snapshot.tlsIdentityReady || !snapshot.nativeDesktopReady ||
        isSharingStage(snapshot.stage) || isPendingStage(snapshot.stage) ||
        request.interfaceId.isEmpty() || request.interfaceAddress.isEmpty())
        return false;

    const RuntimeHostOptions options{
        request.interfaceId.toStdString(),
        request.interfaceAddress.toStdString(), request.port, true, false};
    // This pure preflight reduces duplicate UI/runtime selector policy; the
    // live R10 owner must still re-enumerate and prove its actual R1 bind.
    if (!assessRuntimeSelectedLanEndpoint(
             options, runtime_.enumerateLocalInterfaces()).succeeded() ||
        !runtime_.configure(options).succeeded())
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
        (!isSharingStage(snapshot.stage) && !isPendingStage(snapshot.stage)) ||
        !std::ranges::any_of(snapshot.activeClients,
            [opaqueClientId](const RuntimeHostClient& client) {
                return client.opaqueId == opaqueClientId;
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
