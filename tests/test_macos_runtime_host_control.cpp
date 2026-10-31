// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/mac_runtime_host_control.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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
    assert(snapshot.product.credentialEditingAllowed);
    assert(snapshot.product.automaticRuntimeProvisioned);
    assert(snapshot.product.nativeDesktopTargetAvailable);
    assert(snapshot.product.nativeDesktopTarget == "macOS ScreenCaptureKit Desktop");
    assert(snapshot.product.credentialCapabilities
               .standalonePasswordConfigurationAvailable);
    assert(!snapshot.product.credentialCapabilities.standalonePassword);
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

    const auto before = control.status();
    assert(before.product.credentialCapabilities
               .standalonePasswordConfigurationAvailable);
    assert(!before.product.credentialCapabilities.standalonePassword);
    assert(!before.credentialsConfigured);
    assert(before.product.sharingPermission.canRequest);
    assert(!before.product.sharingPermission.activeGrant);
    assert(!before.listenerAvailable);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));
    for (const char16_t codeUnit : password)
    {
        assert(codeUnit == u'\0');
    }

    const auto snapshot = control.status();
    assert(snapshot.credentialsConfigured);
    assert(snapshot.stage == RuntimeHostStage::CredentialsConfigured);
    assert(snapshot.product.credentialEditingAllowed);
    assert(snapshot.product.readinessStage == RuntimeProductReadinessStage::CredentialsConfigured);
    assert(snapshot.product.sharingPermission.canRequest);
    assert(!snapshot.product.sharingPermission.activeGrant);
    assert(snapshot.product.sharingPermission.denial ==
           RuntimeSharingPermissionDenial::PermissionRequired);
    assert(!snapshot.listenerAvailable);

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
    const auto configuredCredential =
        control.standaloneApplicationPasswordObservation();
    assert(configuredCredential.configured);
    assert(configuredCredential.generation != 0U);

    RuntimeHostPermissionRequest permission;
    assert(control.requestHostPermissionSetup(permission).succeeded());
    assert(control.status().hostOwnerAuthorized);

    assert(control.stopSharing().succeeded());
    const auto stoppedCredential =
        control.standaloneApplicationPasswordObservation();
    const auto stopped = control.status();
    assert(stopped.stage == RuntimeHostStage::Stopped);
    assert(stopped.product.credentialEditingAllowed);
    assert(stopped.credentialsConfigured);
    assert(stopped.product.credentialsConfigured);
    assert(!stopped.hostOwnerAuthorized);
    assert(!stopped.product.ownerAuthorized);
    assert(stoppedCredential.configured);
    assert(stoppedCredential.generation == configuredCredential.generation);

    StandaloneVisitObservation observed;
    assert(control.visitStandaloneApplicationPassword(
        configuredCredential.generation,
        &observeStandaloneCredential, &observed));
    assert(observed.visited);

    assert(control.revokeSharing().succeeded());
    const auto revokedCredential =
        control.standaloneApplicationPasswordObservation();
    assert(!control.status().hostOwnerAuthorized);
    assert(!control.status().product.ownerAuthorized);
    assert(!control.status().credentialsConfigured);
    assert(!control.status().product.credentialsConfigured);
    assert(!revokedCredential.configured);
    assert(revokedCredential.generation > configuredCredential.generation);
    assert(!control.visitStandaloneApplicationPassword(
        configuredCredential.generation,
        &observeStandaloneCredential, &observed));
}

[[nodiscard]] bool testStopStartRetainsStandaloneCredential()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"rdp", password));
    assert(std::ranges::all_of(
        password, [](char16_t value) { return value == u'\0'; }));
    const auto original =
        control.standaloneApplicationPasswordObservation();
    assert(original.configured && original.generation != 0U);

    const auto recommendation =
        control.status().product.recommendedEndpoint;
    if (!recommendation.valid())
        return false;

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;

    std::uint16_t selectedPort = 0U;
    std::uint64_t previousListenerGeneration = 0U;
    for (std::size_t cycle = 0U; cycle < 3U; ++cycle)
    {
        const auto beforePermission = control.status();
        assert(beforePermission.credentialsConfigured);
        assert(beforePermission.product.credentialsConfigured);
        assert(!beforePermission.hostOwnerAuthorized);
        assert(!beforePermission.listenerAvailable);

        if (cycle == 0U)
        {
            // The first listener needs an owner grant before we can distinguish
            // a genuinely occupied candidate port from an authorization denial.
            assert(control.requestHostPermissionSetup(permission).succeeded());
            assert(control.status().hostOwnerAuthorized);

            for (std::uint16_t port = 34300U; port < 34330U; ++port)
            {
                const RuntimeHostOptions options{
                    recommendation.interfaceId, recommendation.address,
                    port, true, false};
                assert(control.configure(options).succeeded());
                const auto prepared = control.status();
                assert(prepared.tlsIdentityReady);
                assert(prepared.tlsIdentity.state ==
                       RuntimeTlsIdentityState::ConfiguredUnbound);
                assert(prepared.tlsIdentity.endpointGeneration == 0U);
                assert(!prepared.listenerAvailable);

                const auto start = control.startSharing();
                if (start.succeeded())
                {
                    selectedPort = port;
                    break;
                }
                assert(start.error == RuntimeHostError::PortUnavailable);
            }
            assert(selectedPort != 0U);
        }
        else
        {
            // Ordinary Stop must kill the previous consent grant. Prepare fresh
            // endpoint-bound TLS state on the same port, then prove that the
            // retained credential alone cannot authorize the next listener.
            const RuntimeHostOptions options{
                recommendation.interfaceId, recommendation.address,
                selectedPort, true, false};
            assert(control.configure(options).succeeded());
            const auto preparedWithoutConsent = control.status();
            assert(preparedWithoutConsent.credentialsConfigured);
            assert(!preparedWithoutConsent.hostOwnerAuthorized);
            assert(preparedWithoutConsent.tlsIdentityReady);
            assert(preparedWithoutConsent.tlsIdentity.state ==
                   RuntimeTlsIdentityState::ConfiguredUnbound);
            assert(preparedWithoutConsent.tlsIdentity.endpointGeneration == 0U);
            assert(!preparedWithoutConsent.listenerAvailable);

            const auto deniedWithoutFreshConsent = control.startSharing();
            assert(deniedWithoutFreshConsent.error ==
                   RuntimeHostError::HostConsentRequired);
            assert(!control.status().hostOwnerAuthorized);
            assert(!control.status().listenerAvailable);
            assert(control.standaloneApplicationPasswordObservation().generation ==
                   original.generation);

            // A2/A3 is explicit and fresh for this Start. The already-prepared
            // TLS identity remains non-authorizing until this grant exists.
            assert(control.requestHostPermissionSetup(permission).succeeded());
            assert(control.status().hostOwnerAuthorized);
            assert(control.startSharing().succeeded());
        }

        const auto live = control.status();
        assert(live.stage == RuntimeHostStage::ListenerAvailable);
        assert(live.listenerAvailable);
        assert(live.listenerGeneration != 0U);
        assert(live.listenerGeneration != previousListenerGeneration);
        assert(live.boundEndpoint == live.selectedEndpoint);
        assert(live.tlsIdentityReady);
        assert(live.tlsIdentity.boundIdentityMatchesGeneration(
            live.listenerGeneration));
        assert(live.hostOwnerAuthorized);
        assert(live.activeClients.empty());
        previousListenerGeneration = live.listenerGeneration;

        assert(control.stopSharing().succeeded());
        const auto stopped = control.status();
        assert(stopped.stage == RuntimeHostStage::Stopped);
        assert(stopped.credentialsConfigured);
        assert(stopped.product.credentialsConfigured);
        assert(!stopped.hostOwnerAuthorized);
        assert(!stopped.product.ownerAuthorized);
        assert(!stopped.listenerAvailable);
        assert(stopped.listenerGeneration == 0U);
        assert(stopped.boundEndpoint.empty());
        assert(stopped.activeClients.empty());
        // MacRuntimeNativeDesktop owns the capture/input capability. A false
        // aggregate readiness observation proves neither native nor input
        // ownership survived the ordinary Stop.
        assert(!stopped.nativeDesktopReady);
        assert(!stopped.tlsIdentityReady);
        assert(!stopped.product.tlsIdentityReady);
        assert(!stopped.tlsIdentity.fingerprintAvailable);

        const auto retained =
            control.standaloneApplicationPasswordObservation();
        assert(retained.configured);
        assert(retained.generation == original.generation);
        StandaloneVisitObservation visited;
        assert(control.visitStandaloneApplicationPassword(
            original.generation, &observeStandaloneCredential, &visited));
        assert(visited.visited);
    }

    assert(control.revokeSharing().succeeded());
    const auto revoked = control.status();
    assert(revoked.stage == RuntimeHostStage::Revoked);
    assert(!revoked.credentialsConfigured);
    assert(!revoked.product.credentialsConfigured);
    assert(!revoked.hostOwnerAuthorized);
    assert(!revoked.listenerAvailable);
    assert(!control.standaloneApplicationPasswordObservation().configured);
    return true;
}

// Only a synthetic local TCP peer is used. The production R10 accepted-client
// path must never construct a native desktop or consume first-MCS bytes from
// transport/TLS progress or a configured standalone credential alone.
// Full CredentialsVerified remains covered by the independent production R2
// CredSSP oracle; positive macOS R2 admission has not yet been published.
[[nodiscard]] bool testMacAcceptedClientPreAdmissionDormancy()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);
    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"rdp", password));

    const auto endpoint = control.status().product.recommendedEndpoint;
    if (!endpoint.valid() || endpoint.address.find(':') != std::string::npos)
        return false;

    RuntimeHostPermissionRequest permission;
    permission.allowClipboard = false;
    permission.allowInput = false;
    assert(control.requestHostPermissionSetup(permission).succeeded());

    std::uint16_t chosenPort = 0U;
    for (std::uint16_t port = 34350U; port < 34380U; ++port)
    {
        const RuntimeHostOptions options{
            endpoint.interfaceId, endpoint.address, port, true, false};
        assert(control.configure(options).succeeded());
        if (control.startSharing().succeeded())
        {
            chosenPort = port;
            break;
        }
    }
    if (chosenPort == 0U)
        return false;

    struct ScopedSocket final
    {
        int descriptor{-1};
        ~ScopedSocket()
        {
            if (descriptor >= 0)
                (void)::close(descriptor);
        }
    } client{::socket(AF_INET, SOCK_STREAM, 0)};
    if (client.descriptor < 0)
        return false;

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(chosenPort);
    if (::inet_pton(AF_INET, endpoint.address.c_str(),
                    &destination.sin_addr) != 1 ||
        ::connect(client.descriptor,
                  reinterpret_cast<const sockaddr*>(&destination),
                  static_cast<socklen_t>(sizeof(destination))) != 0)
        return false;

    assert(control.serviceOnce().succeeded());
    auto accepted = control.status();
    assert(accepted.stage == RuntimeHostStage::ClientAuthenticating);
    assert(accepted.activeClients.size() == 1U);
    assert(accepted.acceptedClientPreauthDiagnostics.available);
    assert(accepted.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    assert(!accepted.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(!accepted.nativeDesktopReady);
    assert(!accepted.graphicsReady);

    // A single incomplete TPKT header cannot advance TLS, MCS or Share.
    constexpr std::array<std::uint8_t, 1U> partialTpkt{0x03U};
    assert(::send(client.descriptor, partialTpkt.data(),
                  partialTpkt.size(), 0) ==
           static_cast<ssize_t>(partialTpkt.size()));
    for (std::size_t index = 0U; index < 4U; ++index)
        assert(control.serviceOnce().succeeded());

    accepted = control.status();
    assert(accepted.stage == RuntimeHostStage::ClientAuthenticating);
    assert(accepted.acceptedClientPreauthDiagnostics.preauthStage ==
           RuntimeAcceptedClientPreauthStage::AwaitConnectionRequest);
    assert(accepted.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    assert(!accepted.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(!accepted.acceptedClientPreauthDiagnostics.shareActivated);
    assert(!accepted.nativeDesktopReady);

    // Stop must free the borrowed R2 frame/SSL in the reverse of their
    // attachment order and cannot retain a client from the old listener.
    assert(control.stopSharing().succeeded());
    const auto stopped = control.status();
    assert(stopped.stage == RuntimeHostStage::Stopped);
    assert(!stopped.listenerAvailable);
    assert(stopped.activeClients.empty());
    assert(!stopped.nativeDesktopReady);
    assert(stopped.acceptedClientPreauthDiagnostics.preauthStage ==
           RuntimeAcceptedClientPreauthStage::Closed);
    assert(!stopped.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(stopped.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    return true;
}

void testPortableGuiBootstrapReadiness()
{
    MacPortableDesktopRuntime runtime;
    auto& control = runtime.hostControl();
    assert(control.status().product.controlAvailable);

    const auto idleResult = runtime.serviceOnce();
    assert(idleResult.succeeded());
}

void testMacLanEndpointRecommendation()
{
    RuntimeHostInterface en0Interface;
    en0Interface.stableId = "en0#15";
    en0Interface.displayName = "en0";
    en0Interface.lanEligible = true;
    en0Interface.localAddresses = {"192.168.1.6"};

    RuntimeHostInterface bridgeInterface;
    bridgeInterface.stableId = "bridge100#24";
    bridgeInterface.displayName = "bridge100";
    bridgeInterface.lanEligible = true;
    bridgeInterface.localAddresses = {"192.168.43.1"};

    const std::vector<RuntimeHostInterface> interfaces{en0Interface, bridgeInterface};

    const std::vector<MacRuntimeDefaultRoutePreference> defaultRoutes{
        {"en0#15", RuntimeHostAddressFamily::Ipv4, 10U}
    };

    const auto withRoute = recommendMacPrivateLanEndpoint(interfaces, defaultRoutes, 3389U);
    assert(!withRoute.ambiguous);
    assert(withRoute.address == "192.168.1.6");
    assert(withRoute.source == RuntimeHostRecommendationSource::PreferredRoute);

    const auto withoutRoute = recommendMacPrivateLanEndpoint(interfaces, {}, 3389U);
    assert(!withoutRoute.ambiguous);
    assert(withoutRoute.address == "192.168.1.6");
}

[[nodiscard]] bool testMacNativeLanEndpointObservation()
{
    MacRuntimeHostControl hostControl;
    const auto status = hostControl.status();
    const auto& recommended = status.product.recommendedEndpoint;
    if (status.product.eligibleLanInterfaces.empty() || !recommended.valid())
        return false;

    assert(!recommended.ambiguous);
    const RuntimeHostOptions selection{
        recommended.interfaceId, recommended.address, recommended.port,
        true, false};
    assert(assessRuntimeSelectedLanEndpoint(
               selection, status.product.eligibleLanInterfaces).succeeded());
    return true;
}

void testScreenRecordingPermissionDenial()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    control.setScreenCaptureProbeForTesting([]() noexcept {
        return rdp::macos::ScreenCapturePreflightStatus::NotGranted;
    });

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(!result.succeeded());
    assert(result.error == RuntimeHostError::NativeAuthorizationDenied);

    const auto status = control.status();
    assert(!status.hostOwnerAuthorized);
    assert(!status.product.ownerAuthorized);
    assert(status.product.lastErrorMessage.find("Screen Recording permission required") != std::string::npos);
}

void testAccessibilityPermissionDenial()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    control.setScreenCaptureProbeForTesting([]() noexcept {
        return rdp::macos::ScreenCapturePreflightStatus::Granted;
    });
    control.setInputPermissionProbeForTesting([]() noexcept {
        return rdp::macos::MacInputPermissionStatus::NotTrusted;
    });

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(!result.succeeded());
    assert(result.error == RuntimeHostError::NativeAuthorizationDenied);

    const auto status = control.status();
    assert(!status.hostOwnerAuthorized);
    assert(!status.product.ownerAuthorized);
    assert(status.product.lastErrorMessage.find("Accessibility permission required") != std::string::npos);
}

void testPermissionRevocationRetiresSharing()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    control.setScreenCaptureProbeForTesting([]() noexcept {
        return rdp::macos::ScreenCapturePreflightStatus::Granted;
    });
    control.setInputPermissionProbeForTesting([]() noexcept {
        return rdp::macos::MacInputPermissionStatus::Trusted;
    });

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(result.succeeded());
    assert(control.status().hostOwnerAuthorized);

    assert(control.revokeSharing().succeeded());
    assert(!control.status().hostOwnerAuthorized);
    assert(!control.status().product.ownerAuthorized);
    assert(control.status().stage == RuntimeHostStage::Revoked);
}

void testNoPromptOnAppLaunch()
{
    MacRuntimeHostControl control;
    const auto status = control.status();
    assert(status.stage == RuntimeHostStage::Stopped);
    assert(!status.listenerAvailable);
    assert(status.lastError == RuntimeHostError::None);
    assert(control.serviceOnce().succeeded());
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
    else if (selected == "macos-host-control-stop-start-retains-standalone-credential")
    {
        if (!testStopStartRetainsStandaloneCredential())
            return 77;
    }
    else if (selected == "macos-host-control-accepted-pre-admission-dormancy")
    {
        if (!testMacAcceptedClientPreAdmissionDormancy())
            return 77;
    }
    else if (selected == "macos-portable-gui-bootstrap-readiness")
    {
        testPortableGuiBootstrapReadiness();
    }
    else if (selected == "macos-host-control-lan-endpoint-recommendation")
    {
        testMacLanEndpointRecommendation();
    }
    else if (selected == "macos-host-control-native-lan-endpoint-observation")
    {
        if (!testMacNativeLanEndpointObservation())
            return 77;
    }
    else if (selected == "macos-host-control-screen-recording-permission-denial")
    {
        testScreenRecordingPermissionDenial();
    }
    else if (selected == "macos-host-control-accessibility-permission-denial")
    {
        testAccessibilityPermissionDenial();
    }
    else if (selected == "macos-host-control-permission-revocation-retires-sharing")
    {
        testPermissionRevocationRetiresSharing();
    }
    else if (selected == "macos-host-control-no-prompt-on-app-launch")
    {
        testNoPromptOnAppLaunch();
    }
    else
    {
        assert(false && "unknown test case");
    }
    return 0;
}
