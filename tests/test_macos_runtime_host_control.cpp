// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/mac_runtime_host_control.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

using namespace rdp_server::server::runtime;
using rdp_server::server::security::ConsoleAccountObservation;
using rdp_server::server::security::ConsoleDesktopLockState;
using rdp_server::server::security::ConsoleEvidenceReadStatus;
using rdp_server::server::security::ConsoleOsEvidenceSource;
using rdp_server::server::security::ConsoleSessionObservation;
using rdp_server::server::security::LanCredentialChoice;

namespace
{

struct StandaloneVisitObservation final
{
    bool visited{};
};

[[nodiscard]] bool observeStandaloneCredential(
    const rdp_server::server::security::EphemeralNtlmV2Credential& credential,
    void* rawContext) noexcept
{
    auto* observation = static_cast<StandaloneVisitObservation*>(rawContext);
    if (observation == nullptr)
        return false;
    observation->visited = credential.configured();
    return observation->visited;
}

[[nodiscard]] std::array<char16_t, 8> standalonePassword()
{
    return {u'P', u'a', u's', u's', u'w', u'o', u'r', u'd'};
}

class PortableBootstrapEvidence final : public ConsoleOsEvidenceSource
{
public:
    explicit PortableBootstrapEvidence(std::uint32_t uid) noexcept : uid_(uid) {}

    ConsoleAccountObservation readUnixAccount(std::string_view) noexcept override
    {
        return {};
    }

    ConsoleSessionObservation readActiveConsole() noexcept override
    {
        return {
            ConsoleEvidenceReadStatus::Observed,
            "mac-bootstrap-session",
            "seat0",
            ":0",
            uid_,
            91U,
            now_,
            true,
            true,
            uid_,
            ConsoleDesktopLockState::Unlocked,
            false};
    }

    std::optional<std::uint64_t> readMonotonicMilliseconds() noexcept override
    {
        return now_;
    }

private:
    std::uint32_t uid_{501U};
    std::uint64_t now_{10'000U};
};

void testInitialProductProjection()
{
    MacRuntimeHostControl control;
    const auto snapshot = control.status();
    assert(snapshot.stage == RuntimeHostStage::Stopped);
    assert(snapshot.product.controlAvailable);
    assert(snapshot.product.automaticRuntimeProvisioned);
    assert(snapshot.product.nativeDesktopTargetAvailable);
    assert(snapshot.product.nativeDesktopTarget == "macOS ScreenCaptureKit Desktop");
    assert(!snapshot.credentialsConfigured);
    assert(!snapshot.hostOwnerAuthorized);
    assert(!snapshot.listenerAvailable);
    assert(snapshot.product.state == RuntimeProductHostState::Stopped);
}

void testAutomaticLicensingPrestartNoListener()
{
    MacRuntimeHostControl control;

    const auto before = control.status();
    assert(before.product.automaticRuntimeProvisioned);
    assert(before.product.readinessStage ==
           RuntimeProductReadinessStage::Provisioned);
    assert(before.stage == RuntimeHostStage::Stopped);
    assert(!before.listenerAvailable);
    assert(before.boundEndpoint.empty());
    assert(before.activeClients.empty());

    const auto idleResult = control.serviceOnce();
    assert(idleResult.succeeded());

    const auto after = control.status();
    assert(after.product.automaticRuntimeProvisioned);
    assert(after.product.readinessStage ==
           RuntimeProductReadinessStage::Provisioned);
    assert(after.stage == RuntimeHostStage::Stopped);
    assert(!after.listenerAvailable);
    assert(after.boundEndpoint.empty());
    assert(after.activeClients.empty());
}

void testStandalonePasswordLifecycle()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));
    for (const char16_t codeUnit : password)
    {
        assert(codeUnit == u'\0');
    }

    const auto snapshot = control.status();
    assert(snapshot.credentialsConfigured);
    assert(snapshot.stage == RuntimeHostStage::CredentialsConfigured);
    assert(snapshot.product.readinessStage == RuntimeProductReadinessStage::CredentialsConfigured);

    StandaloneVisitObservation observed;
    assert(control.visitStandaloneApplicationPassword(
        control.standaloneApplicationPasswordObservation().generation,
        &observeStandaloneCredential, &observed));
    assert(observed.visited);
}

void testSharingPermissionLifecycle()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(result.succeeded());

    const auto snapshot = control.status();
    assert(snapshot.hostOwnerAuthorized);
    assert(snapshot.product.ownerAuthorized);
    assert(snapshot.product.sharingPermission.activeGrant);
    assert(snapshot.product.sharingPermission.viewAllowed);
    assert(snapshot.product.sharingPermission.inputAllowed);
    assert(snapshot.product.readinessStage == RuntimeProductReadinessStage::PermissionGranted);
}

void testStopRevokeRetirement()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    RuntimeHostPermissionRequest permission;
    assert(control.requestHostPermissionSetup(permission).succeeded());
    assert(control.status().hostOwnerAuthorized);

    assert(control.stopSharing().succeeded());
    assert(control.status().stage == RuntimeHostStage::Stopped);

    assert(control.revokeSharing().succeeded());
    assert(!control.status().hostOwnerAuthorized);
    assert(!control.status().product.ownerAuthorized);
}

void testPortableGuiBootstrapReadiness()
{
    MacPortableDesktopRuntime runtime;
    auto& control = runtime.hostControl();
    assert(control.status().product.controlAvailable);

    const auto idleResult = runtime.serviceOnce();
    assert(idleResult.succeeded());
}

} // namespace

int main(int argc, char** argv)
{
    assert(argc == 2);
    const std::string_view selected{argv[1]};
    if (selected == "macos-host-control-initial-product-projection")
    {
        testInitialProductProjection();
    }
    else if (selected == "macos-host-control-automatic-licensing-prestart-no-listener")
    {
        testAutomaticLicensingPrestartNoListener();
    }
    else if (selected == "macos-host-control-standalone-password-lifecycle")
    {
        testStandalonePasswordLifecycle();
    }
    else if (selected == "macos-host-control-sharing-permission-lifecycle")
    {
        testSharingPermissionLifecycle();
    }
    else if (selected == "macos-host-control-stop-revoke-retirement")
    {
        testStopRevokeRetirement();
    }
    else if (selected == "macos-portable-gui-bootstrap-readiness")
    {
        testPortableGuiBootstrapReadiness();
    }
    else
    {
        assert(false && "unknown test case");
    }
    return 0;
}
