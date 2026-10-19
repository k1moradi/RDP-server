// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_host_control.h"

#include <cassert>
#include <cstdint>
#include <string_view>

using namespace rdp_server::server::runtime;
using rdp_server::server::security::LanCredentialChoice;

int main(int argumentCount, char** argumentValues)
{
    if (argumentCount != 2 || argumentValues[1] == nullptr)
        return 2;
    const std::string_view testCase{argumentValues[1]};
    UnavailableRuntimeHostControl unavailable;
    RuntimeHostControl& host = unavailable;

    if (testCase == "host-control-unavailable-denials")
    {
        const auto state = host.status();
        assert(state.stage == RuntimeHostStage::Stopped);
        assert(!state.packageInstalled && !state.credentialsConfigured);
        assert(!state.tlsIdentityReady && !state.hostOwnerAuthorized);
        assert(!state.listenerAvailable && !state.nativeDesktopReady);
        assert(state.clipboardState == RuntimeClipboardState::Unavailable);
        assert(state.boundEndpoint.empty() && state.activeClients.empty());
        assert(state.lastError == RuntimeHostError::ControlUnavailable);
        assert(host.enumerateLocalInterfaces().empty());

        const RuntimeHostOptions untrusted{
            "gui-interface", "0.0.0.0", 3389U, true, true};
        assert(!host.configure(untrusted).succeeded());
        assert(!host.requestHostPermissionSetup().succeeded());
        assert(!host.startSharing().succeeded());
        assert(!host.stopSharing().succeeded());
        assert(!host.disconnectClient(1U).succeeded());
        assert(!host.revokeSharing().succeeded());
        assert(host.status().stage == RuntimeHostStage::Stopped);
        assert(runtimeHostErrorMessage(RuntimeHostError::ListenerPolicyDenied) ==
               "Listener denied by network policy");
        assert(runtimeHostErrorMessage(
               static_cast<RuntimeHostError>(255U)) == "Host operation failed");
        return 0;
    }
    if (testCase == "host-control-authentication-outcome-denials")
    {
        // R2/R10 must not collapse independent reasons or return identity,
        // credential, token, keytab or path diagnostics in status text.
        assert(runtimeHostErrorMessage(RuntimeHostError::CredentialNotConfigured) ==
               "Credentials not configured");
        assert(runtimeHostErrorMessage(
                   RuntimeHostError::UnsupportedIndependentPasswordNla) ==
               "Independent application password is unsupported by RDP NLA");
        assert(runtimeHostErrorMessage(RuntimeHostError::HostConsentRequired) ==
               "Host-owner permission required");
        assert(runtimeHostErrorMessage(RuntimeHostError::AuthenticationRejected) ==
               "Client authentication rejected");
        assert(runtimeHostErrorMessage(RuntimeHostError::AuthenticationRateLimited) ==
               "Authentication temporarily rate-limited");
        assert(runtimeHostErrorMessage(RuntimeHostError::HostSessionStale) ==
               "Host desktop session changed; fresh authorization required");
        assert(runtimeHostErrorMessage(RuntimeHostError::AccessRevoked) ==
               "Sharing access revoked");
        assert(runtimeHostErrorMessage(RuntimeHostError::CredentialProviderUnavailable) ==
               "OS credential provider unavailable");
        assert(!RuntimeHostResult{RuntimeHostError::AuthenticationRateLimited, true}
                    .succeeded());
        assert(!RuntimeHostResult{RuntimeHostError::HostSessionStale, false}
                    .succeeded());
        assert(!host.status().credentialsConfigured);
        assert(!host.requestCredentialSetup(LanCredentialChoice::ExistingOsAccount)
                    .succeeded());
        assert(!host.startSharing().succeeded());
        assert(!host.status().listenerAvailable);
        return 0;
    }
    if (testCase == "host-control-clipboard-state-denials")
    {
        assert(host.status().clipboardState == RuntimeClipboardState::Unavailable);
        assert(!host.startSharing().succeeded());
        assert(!host.stopSharing().succeeded());
        assert(!host.revokeSharing().succeeded());
        assert(host.status().clipboardState == RuntimeClipboardState::Unavailable);
        return 0;
    }
    if (testCase == "host-control-credential-setup-denials")
    {
        assert(host.requestCredentialSetup(LanCredentialChoice::ExistingOsAccount).error ==
               RuntimeHostError::ControlUnavailable);
        assert(host.requestCredentialSetup(LanCredentialChoice::IndependentApplicationPassword).error ==
               RuntimeHostError::UnsupportedIndependentPasswordNla);
        assert(host.requestCredentialSetup(LanCredentialChoice::Unconfigured).error ==
               RuntimeHostError::CredentialNotConfigured);
        assert(host.requestCredentialSetup(static_cast<LanCredentialChoice>(255U)).error ==
               RuntimeHostError::CredentialNotConfigured);
        assert(!host.status().credentialsConfigured);
        assert(!host.startSharing().succeeded());
        return 0;
    }
    if (testCase == "host-control-selected-lan-interface-denials")
    {
        const std::vector<RuntimeHostInterface> interfaces{{
            "eth-stable", "Ethernet", {"192.168.2.21", "fe80::1234"},
            false, true}};
        const RuntimeHostOptions permitted{
            "eth-stable", "192.168.2.21", 3389U, true, false};
        assert(assessRuntimeSelectedLanEndpoint(
                   permitted, interfaces).succeeded());
        // A matching preference never grants the absent R2 lease or a bind.
        assert(!host.configure(permitted).succeeded());
        assert(!host.startSharing().succeeded());
        auto invalid = permitted;
        invalid.interfaceId = "Ethernet";
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        invalid = permitted;
        invalid.localAddress = "192.168.2.22";
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        invalid = permitted;
        invalid.localAddress = "0.0.0.0";
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        invalid.localAddress = "::";
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        invalid.localAddress = "[::]";
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        invalid = permitted;
        invalid.port = 0;
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        invalid = permitted;
        invalid.lanRequested = false;
        assert(!assessRuntimeSelectedLanEndpoint(
                    invalid, interfaces).succeeded());
        auto duplicates = interfaces;
        duplicates.push_back(interfaces.front());
        assert(!assessRuntimeSelectedLanEndpoint(
                    permitted, duplicates).succeeded());
        duplicates = interfaces;
        duplicates.front().loopback = true;
        assert(!assessRuntimeSelectedLanEndpoint(
                    permitted, duplicates).succeeded());
        duplicates = interfaces;
        duplicates.front().lanEligible = false;
        assert(!assessRuntimeSelectedLanEndpoint(
                    permitted, duplicates).succeeded());
        duplicates = interfaces;
        duplicates.front().stableId = "renamed";
        assert(!assessRuntimeSelectedLanEndpoint(
                    permitted, duplicates).succeeded());
        assert(host.status().boundEndpoint.empty());
        return 0;
    }
    return 2;
}
