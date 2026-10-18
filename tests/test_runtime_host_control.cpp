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
    return 2;
}
