// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_host_control.h"
#include <cassert>
#include <string_view>
using namespace rdp_server::server::runtime;
using rdp_server::server::security::LanCredentialChoice;

int main(int argc, char** argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};
    LinuxRuntimeHostControl control;
    if (testCase == "linux-host-control-no-consent-start-denials")
    {
        assert(control.status().stage == RuntimeHostStage::Stopped);
        assert(!control.status().listenerAvailable);
        assert(!control.status().hostOwnerAuthorized);
        assert(!control.status().tlsIdentityReady);
        assert(!control.status().nativeDesktopReady);
        assert(control.startSharing().error ==
               RuntimeHostError::InvalidConfiguration);
        assert(control.requestHostPermissionSetup().error ==
               RuntimeHostError::HostConsentRequired);
        assert(control.requestCredentialSetup(
                   LanCredentialChoice::ExistingOsAccount).error ==
               RuntimeHostError::CredentialProviderUnavailable);
        assert(control.requestCredentialSetup(
                   LanCredentialChoice::IndependentApplicationPassword).error ==
               RuntimeHostError::UnsupportedIndependentPasswordNla);
        assert(control.status().activeClients.empty());
        return 0;
    }
    if (testCase == "linux-host-control-revalidated-interface-denials")
    {
        RuntimeHostOptions options{"missing#0", "0.0.0.0", 3389U, true, false};
        assert(control.configure(options).error ==
               RuntimeHostError::InvalidConfiguration);
        options.localAddress = "192.168.1.123";
        assert(control.configure(options).error ==
               RuntimeHostError::InterfaceUnavailable);
        options.afterLoginLaunchRequested = true;
        assert(control.configure(options).error ==
               RuntimeHostError::ListenerPolicyDenied);
        const auto interfaces = control.enumerateLocalInterfaces();
        if (!interfaces.empty() && !interfaces.front().localAddresses.empty())
        {
            const RuntimeHostOptions current{
                interfaces.front().stableId,
                interfaces.front().localAddresses.front(), 3389U, true, false};
            assert(control.configure(current).succeeded());
            assert(control.startSharing().error ==
                   RuntimeHostError::HostConsentRequired);
            assert(!control.status().listenerAvailable);
            assert(control.status().boundEndpoint.empty());
        }
        return 0;
    }
    if (testCase == "linux-host-control-rejected-selection-retires-previous")
    {
        // No synthetic interfaces or socket/credential setup. The host must
        // supply one currently eligible private LAN adapter for this case.
        const auto interfaces = control.enumerateLocalInterfaces();
        if (interfaces.empty() || interfaces.front().localAddresses.empty())
            return 77; // CTest SKIP_RETURN_CODE: no suitable native adapter.

        const RuntimeHostOptions selected{
            interfaces.front().stableId,
            interfaces.front().localAddresses.front(), 3389U, true, false};
        assert(control.configure(selected).succeeded());
        assert(control.startSharing().error ==
               RuntimeHostError::HostConsentRequired);

        RuntimeHostOptions removed = selected;
        removed.interfaceId += "#stale";
        assert(control.configure(removed).error ==
               RuntimeHostError::InterfaceUnavailable);
        assert(control.startSharing().error ==
               RuntimeHostError::InvalidConfiguration);
        assert(!control.status().listenerAvailable);
        assert(control.status().boundEndpoint.empty());

        assert(control.configure(selected).succeeded());
        RuntimeHostOptions forbidden = selected;
        forbidden.afterLoginLaunchRequested = true;
        assert(control.configure(forbidden).error ==
               RuntimeHostError::ListenerPolicyDenied);
        assert(control.startSharing().error ==
               RuntimeHostError::InvalidConfiguration);
        assert(!control.status().hostOwnerAuthorized);
        return 0;
    }
    if (testCase == "linux-host-control-stop-revoke-retirement")
    {
        assert(control.stopSharing().succeeded());
        assert(control.stopSharing().succeeded());
        assert(control.disconnectClient(1U).error ==
               RuntimeHostError::ClientNotFound);
        assert(control.revokeSharing().succeeded());
        assert(control.revokeSharing().succeeded());
        assert(control.status().stage == RuntimeHostStage::Revoked);
        assert(control.status().lastError == RuntimeHostError::AccessRevoked);
        assert(!control.status().listenerAvailable);
        assert(control.startSharing().error == RuntimeHostError::AccessRevoked);
        assert(control.stopSharing().succeeded());
        assert(control.status().stage == RuntimeHostStage::Revoked);
        return 0;
    }
    return 2;
}
