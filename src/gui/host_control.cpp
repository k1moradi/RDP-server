// SPDX-License-Identifier: GPL-3.0-or-later
#include "host_control.h"

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
    if (runtimeStatus.hostOwnerAuthorized)
        view.desktop = QStringLiteral("Authorized logged-in desktop");

    for (const RuntimeHostInterface& interface : runtime_.enumerateLocalInterfaces())
    {
        if (!interface.lanEligible || interface.loopback)
            continue;
        for (const std::string& address : interface.localAddresses)
        {
            if (!address.empty())
                view.approvedLanInterfaces.push_back(toQString(address));
        }
    }

    view.lanAddress = toQString(runtimeStatus.boundEndpoint);
    for (const RuntimeHostClient& client : runtimeStatus.activeClients)
    {
        if (!client.peerAddress.empty())
            view.clients.push_back(toQString(client.peerAddress));
        else
            view.clients.push_back(
                QStringLiteral("Connected client %1").arg(client.opaqueId));
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

bool HostControl::start(const HostRequest& request)
{
    using namespace rdp_server::server::runtime;

    if (request.interfaceAddress.isEmpty())
        return false;

    const std::string selectedAddress = request.interfaceAddress.toStdString();
    std::string selectedInterfaceId;
    for (const RuntimeHostInterface& candidate : runtime_.enumerateLocalInterfaces())
    {
        if (!candidate.lanEligible || candidate.loopback)
            continue;

        bool containsAddress = false;
        for (const std::string& address : candidate.localAddresses)
        {
            if (address == selectedAddress)
            {
                containsAddress = true;
                break;
            }
        }
        if (!containsAddress)
            continue;
        if (!selectedInterfaceId.empty())
            return false; // R10 must disambiguate duplicate-address interfaces.
        selectedInterfaceId = candidate.stableId;
    }
    if (selectedInterfaceId.empty())
        return false;

    const RuntimeHostOptions options{
        std::move(selectedInterfaceId),
        selectedAddress,
        request.port,
        true,
        false};
    if (!runtime_.configure(options).succeeded())
        return false;
    return runtime_.startSharing().succeeded();
}

void HostControl::stopAndRevoke()
{
    (void)runtime_.stopSharing();
    (void)runtime_.revokeSharing();
}

} // namespace rdp::gui
