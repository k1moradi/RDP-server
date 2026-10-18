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
    view.controlAvailable =
        runtimeStatus.lastError != RuntimeHostError::ControlUnavailable;
    view.credentialsConfigured = runtimeStatus.credentialsConfigured;
    view.desktopAuthorized = runtimeStatus.hostOwnerAuthorized;
    view.tlsReady = runtimeStatus.tlsIdentityReady;
    view.captureInputReady = runtimeStatus.nativeDesktopReady;
    view.sharing = isSharingStage(runtimeStatus.stage);
    view.startPending = isPendingStage(runtimeStatus.stage);
    view.clipboardState = runtimeStatus.clipboardState;
    if (runtimeStatus.hostOwnerAuthorized)
        view.desktop = QStringLiteral("Authorized logged-in desktop");

    for (const RuntimeHostInterface& interface : runtime_.enumerateLocalInterfaces())
    {
        if (!interface.lanEligible || interface.loopback ||
            interface.stableId.empty())
            continue;
        for (const std::string& address : interface.localAddresses)
        {
            if (!address.empty())
                view.approvedLanInterfaces.push_back({
                    toQString(interface.stableId), toQString(interface.displayName),
                    toQString(address)});
        }
    }

    view.lanAddress = toQString(runtimeStatus.boundEndpoint);
    for (const RuntimeHostClient& client : runtimeStatus.activeClients)
    {
        const QString displayName = client.peerAddress.empty()
            ? QStringLiteral("Connected client %1").arg(client.opaqueId)
            : toQString(client.peerAddress);
        view.clients.push_back(displayName);
        if (client.opaqueId != 0)
            view.activeClients.push_back({client.opaqueId, displayName});
    }

    if (runtimeStatus.lastError == RuntimeHostError::AuthenticationRejected)
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
