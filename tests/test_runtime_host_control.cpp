// SPDX-License-Identifier: GPL-3.0-or-later
// Simulate the Windows RPC header macro that production R10 linkage exposes.
#ifndef interface
#define interface struct
#define RDP_SERVER_TEST_DEFINED_RPC_INTERFACE_MACRO 1
#endif
#include "server/runtime/runtime_host_control.h"
#ifdef RDP_SERVER_TEST_DEFINED_RPC_INTERFACE_MACRO
#undef interface
#undef RDP_SERVER_TEST_DEFINED_RPC_INTERFACE_MACRO
#endif

#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <vector>

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
        assert(!state.product.credentialCapabilities
                    .standalonePasswordConfigurationAvailable);
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
    if (testCase == "host-control-standalone-deny-fallback-cleanses")
    {
        std::array<char16_t, 5> password{
            u's', u'e', u'c', u'r', u't'};
        assert(!host.configureStandaloneApplicationPassword(
            u"owner", std::span<char16_t>{password}));
        assert(std::ranges::all_of(
            password, [](const char16_t codeUnit) { return codeUnit == u'\0'; }));
        assert(!host.status().credentialsConfigured);
        assert(!host.status().listenerAvailable);
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
               "Sharing permission required");
        assert(runtimeHostErrorMessage(RuntimeHostError::AuthenticationRejected) ==
               "Client authentication rejected");
        assert(runtimeHostErrorMessage(
                   RuntimeHostError::AuthenticationIncompletePeerClosed) ==
               "Client authentication did not complete");
        assert(runtimeHostErrorMessage(RuntimeHostError::AuthenticationRateLimited) ==
               "Authentication temporarily rate-limited");
        assert(runtimeHostErrorMessage(RuntimeHostError::HostSessionStale) ==
               "Host desktop session changed; fresh authorization required");
        assert(runtimeHostErrorMessage(RuntimeHostError::AccessRevoked) ==
               "Sharing access revoked");
        assert(runtimeHostErrorMessage(RuntimeHostError::CredentialProviderUnavailable) ==
               "OS credential provider unavailable");
        const RuntimeHostResult rateLimited{
            RuntimeHostError::AuthenticationRateLimited, true};
        const RuntimeHostResult staleSession{
            RuntimeHostError::HostSessionStale, false};
        assert(!rateLimited.succeeded());
        assert(!staleSession.succeeded());
        assert(!host.status().credentialsConfigured);
        assert(!host.requestCredentialSetup(LanCredentialChoice::ExistingOsAccount)
                    .succeeded());
        assert(!host.startSharing().succeeded());
        assert(!host.status().listenerAvailable);
        return 0;
    }
    if (testCase == "host-control-incomplete-peer-product-state")
    {
        // An interrupted peer before credential verification is not a product
        // error state and must not become one merely because the diagnostic
        // RuntimeHostError enum grew. Listener ownership still dominates the
        // presentation state while Sharing remains active.
        assert(runtimeProductStateFor(
                   RuntimeHostStage::Stopped,
                   RuntimeHostError::AuthenticationIncompletePeerClosed,
                   false) == RuntimeProductHostState::Stopped);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::ListenerAvailable,
                   RuntimeHostError::AuthenticationIncompletePeerClosed,
                   false) == RuntimeProductHostState::Listening);
        return 0;
    }
    if (testCase == "host-control-windows-rpc-interface-macro-compatibility")
    {
        const std::vector<RuntimeHostInterface> interfaces{{
            "rpc-safe", "RPC-safe", {"192.168.50.10"}, false, true}};
        const auto recommended =
            recommendRuntimePrivateLanEndpoint(interfaces, 3389U);
        assert(recommended.valid());
        assert(recommended.interfaceId == "rpc-safe");
        assert(recommended.address == "192.168.50.10");
        return 0;
    }
    if (testCase == "host-control-route-aware-recommendation-non-authority")
    {
        using Family = RuntimeHostAddressFamily;
        using Source = RuntimeHostRecommendationSource;

        const std::vector<RuntimeHostInterface> recommendationSnapshot{
            {"eth-main#2", "Ethernet", {"192.168.1.5"}, false, true},
            {"tun-vpn#8", "VPN", {"10.180.105.86"}, false, true},
            {"br-lab#9", "Bridge", {"172.20.0.1"}, false, true}};

        const auto optionsFor =
            [](const RuntimeHostRecommendedEndpoint& recommendation) {
                return RuntimeHostOptions{
                    recommendation.interfaceId,
                    recommendation.address,
                    recommendation.port,
                    true,
                    false};
            };

        // Consume the real route-aware R10 API. The default-route physical LAN
        // wins recommendation, but R1 receives only its exact tuple.
        const std::vector<RuntimeHostLanEndpointCandidate> physicalPreferred{
            {"eth-main#2", "192.168.1.5", Family::Ipv4,
             true, true, 25U},
            {"tun-vpn#8", "10.180.105.86", Family::Ipv4,
             true, false, 1U},
            {"br-lab#9", "172.20.0.1", Family::Ipv4,
             true, false, 1U}};
        const auto physicalRecommendation =
            recommendRuntimePrivateLanEndpoint(physicalPreferred, 3389U);
        assert(physicalRecommendation.valid());
        assert(physicalRecommendation.source == Source::PreferredRoute);
        assert(physicalRecommendation.preferredRoute);
        assert(physicalRecommendation.routeMetric == 25U);
        assert(physicalRecommendation.interfaceId == "eth-main#2");
        assert(physicalRecommendation.address == "192.168.1.5");

        const RuntimeHostOptions physicalSelection =
            optionsFor(physicalRecommendation);
        assert(assessRuntimeSelectedLanEndpoint(
                   physicalSelection, recommendationSnapshot).succeeded());

        // VPN/virtual or bridge routing may legitimately win recommendation.
        // That changes only which tuple is suggested; the same R1 preflight
        // remains mandatory for the selected exact interface/address.
        auto vpnPreferred = physicalPreferred;
        vpnPreferred[0].preferredRoute = false;
        vpnPreferred[1].preferredRoute = true;
        const auto vpnRecommendation =
            recommendRuntimePrivateLanEndpoint(vpnPreferred, 3389U);
        assert(vpnRecommendation.valid());
        assert(vpnRecommendation.source == Source::PreferredRoute);
        assert(vpnRecommendation.interfaceId == "tun-vpn#8");
        assert(vpnRecommendation.address == "10.180.105.86");
        assert(assessRuntimeSelectedLanEndpoint(
                   optionsFor(vpnRecommendation),
                   recommendationSnapshot).succeeded());

        auto bridgePreferred = physicalPreferred;
        bridgePreferred[0].preferredRoute = false;
        bridgePreferred[2].preferredRoute = true;
        const auto bridgeRecommendation =
            recommendRuntimePrivateLanEndpoint(bridgePreferred, 3389U);
        assert(bridgeRecommendation.valid());
        assert(bridgeRecommendation.source == Source::PreferredRoute);
        assert(bridgeRecommendation.interfaceId == "br-lab#9");
        assert(bridgeRecommendation.address == "172.20.0.1");
        assert(assessRuntimeSelectedLanEndpoint(
                   optionsFor(bridgeRecommendation),
                   recommendationSnapshot).succeeded());

        // A stale recommendation is rechecked against the current snapshot.
        auto interfaceRemoved = recommendationSnapshot;
        interfaceRemoved.erase(interfaceRemoved.begin());
        assert(assessRuntimeSelectedLanEndpoint(
                   physicalSelection, interfaceRemoved).error ==
               RuntimeHostError::InterfaceUnavailable);

        auto addressReplaced = recommendationSnapshot;
        addressReplaced.front().localAddresses = {"192.168.1.6"};
        assert(assessRuntimeSelectedLanEndpoint(
                   physicalSelection, addressReplaced).error ==
               RuntimeHostError::InterfaceUnavailable);

        auto identityReplaced = recommendationSnapshot;
        identityReplaced.front().stableId = "eth-main#3";
        assert(assessRuntimeSelectedLanEndpoint(
                   physicalSelection, identityReplaced).error ==
               RuntimeHostError::InterfaceUnavailable);

        auto wildcard = physicalSelection;
        wildcard.localAddress = "0.0.0.0";
        assert(assessRuntimeSelectedLanEndpoint(
                   wildcard, recommendationSnapshot).error ==
               RuntimeHostError::InvalidConfiguration);
        wildcard.localAddress = "::";
        assert(assessRuntimeSelectedLanEndpoint(
                   wildcard, recommendationSnapshot).error ==
               RuntimeHostError::InvalidConfiguration);

        const std::vector<RuntimeHostInterface> publicSnapshot{{
            "eth-public#5", "Public", {"8.8.8.8"}, false, false}};
        const RuntimeHostOptions publicSelection{
            "eth-public#5", "8.8.8.8", 3389U, true, false};
        assert(assessRuntimeSelectedLanEndpoint(
                   publicSelection, publicSnapshot).error ==
               RuntimeHostError::InterfaceUnavailable);

        // Recommendation metadata never promotes the deny-only host into a
        // listener or bypasses the normal R1/R2 Start gates.
        assert(!host.configure(physicalSelection).succeeded());
        assert(!host.startSharing().succeeded());
        assert(host.status().boundEndpoint.empty());
        return 0;
    }
    if (testCase == "host-control-cross-platform-lan-recommendation-contract")
    {
        using Family = RuntimeHostAddressFamily;

        const std::vector<RuntimeHostLanEndpointCandidate> windowsStyle{
            {"adapter-guid:42", "192.168.50.10", Family::Ipv4,
             true, true, 25U},
            {"eth0", "10.0.0.8", Family::Ipv4,
             true, false, 1U}};
        const auto defaultRoute =
            recommendRuntimePrivateLanEndpoint(windowsStyle, 3389U);
        assert(defaultRoute.valid());
        assert(!defaultRoute.ambiguous);
        assert(defaultRoute.interfaceId == "adapter-guid:42");
        assert(defaultRoute.address == "192.168.50.10");
        assert(defaultRoute.family == Family::Ipv4);
        assert(defaultRoute.privateLanEligible);
        assert(defaultRoute.preferredRoute);
        assert(defaultRoute.source ==
               RuntimeHostRecommendationSource::PreferredRoute);
        assert(defaultRoute.routeMetric.has_value());
        assert(*defaultRoute.routeMetric == 25U);

        // Metric, not an interface/display name, ranks comparable routes.
        const std::vector<RuntimeHostLanEndpointCandidate> metrics{
            {"wlan0", "192.168.1.20", Family::Ipv4, true, true, 5U},
            {"eth0", "192.168.1.10", Family::Ipv4, true, true, 50U}};
        const auto lowerMetric =
            recommendRuntimePrivateLanEndpoint(metrics);
        assert(lowerMetric.valid());
        assert(lowerMetric.interfaceId == "wlan0");
        assert(lowerMetric.source ==
               RuntimeHostRecommendationSource::PreferredRoute);
        assert(lowerMetric.routeMetric.has_value());
        assert(*lowerMetric.routeMetric == 5U);

        // Equal route evidence is ambiguous in either input order. Never use
        // eth0/wlan0/en0 or address text as a portable tie breaker.
        const std::vector<RuntimeHostLanEndpointCandidate> ambiguousA{
            {"eth0", "192.168.2.10", Family::Ipv4, true, true, 10U},
            {"wlan0", "192.168.2.20", Family::Ipv4, true, true, 10U}};
        const std::vector<RuntimeHostLanEndpointCandidate> ambiguousB{
            ambiguousA[1], ambiguousA[0]};
        for (const auto* candidates : {&ambiguousA, &ambiguousB})
        {
            const auto ambiguous =
                recommendRuntimePrivateLanEndpoint(*candidates);
            assert(!ambiguous.valid());
            assert(ambiguous.ambiguous);
            assert(ambiguous.source ==
                   RuntimeHostRecommendationSource::Ambiguous);
            assert(ambiguous.interfaceId.empty());
            assert(ambiguous.address.empty());
        }

        // Address family is explicit metadata, not a portable preference.
        const std::vector<RuntimeHostLanEndpointCandidate> familyTie{
            {"platform-v4", "192.168.3.10", Family::Ipv4,
             true, true, 12U},
            {"platform-v6", "fd00::10", Family::Ipv6,
             true, true, 12U}};
        const auto familyAmbiguity =
            recommendRuntimePrivateLanEndpoint(familyTie);
        assert(!familyAmbiguity.valid());
        assert(familyAmbiguity.ambiguous);

        // A missing metric is valid platform evidence, but it cannot silently
        // outrank a different endpoint whose metric happens to be available.
        const std::vector<RuntimeHostLanEndpointCandidate> incomparable{
            {"platform-a", "10.1.0.4", Family::Ipv4, true, true, 7U},
            {"platform-b", "10.1.0.5", Family::Ipv4, true, true, {}}};
        const auto incomparableResult =
            recommendRuntimePrivateLanEndpoint(incomparable);
        assert(!incomparableResult.valid());
        assert(incomparableResult.ambiguous);

        const std::vector<RuntimeHostLanEndpointCandidate> ipv6Only{{
            "opaque-interface-6", "fd12:3456::9", Family::Ipv6,
            true, true, {}}};
        const auto ipv6 = recommendRuntimePrivateLanEndpoint(ipv6Only);
        assert(ipv6.valid());
        assert(ipv6.family == Family::Ipv6);
        assert(!ipv6.routeMetric.has_value());

        const std::vector<RuntimeHostLanEndpointCandidate> soleDualStack{
            {"single-interface", "fd12:3456::10", Family::Ipv6,
             true, false, {}},
            {"single-interface", "192.168.60.10", Family::Ipv4,
             true, false, {}}};
        const auto sole =
            recommendRuntimePrivateLanEndpoint(soleDualStack);
        assert(sole.valid());
        assert(sole.interfaceId == "single-interface");
        assert(sole.address == "192.168.60.10");
        assert(sole.source ==
               RuntimeHostRecommendationSource::SoleEligibleInterface);

        const std::vector<RuntimeHostLanEndpointCandidate> denied{{
            "opaque-interface", "192.168.77.8", Family::Ipv4,
            false, true, 2U}};
        const auto deniedResult =
            recommendRuntimePrivateLanEndpoint(denied);
        assert(!deniedResult.valid());
        assert(!deniedResult.ambiguous);
        assert(deniedResult.source ==
               RuntimeHostRecommendationSource::Unavailable);
        return 0;
    }
    if (testCase == "host-control-gui-round2-endpoint-recommendation")
    {
        using Family = RuntimeHostAddressFamily;
        const std::vector<RuntimeHostLanEndpointCandidate> preferredLan{
            {"lan-default", "192.168.1.5", Family::Ipv4,
             true, true, {}},
            {"vpn-virtual", "10.180.105.86", Family::Ipv4,
             true, false, {}}};
        const auto actualLan =
            recommendRuntimePrivateLanEndpoint(preferredLan, 3389U);
        assert(actualLan.valid());
        assert(!actualLan.ambiguous);
        assert(actualLan.interfaceId == "lan-default");
        assert(actualLan.address == "192.168.1.5");
        assert(actualLan.port == 3389U);
        assert(actualLan.source ==
               RuntimeHostRecommendationSource::PreferredRoute);

        const std::vector<RuntimeHostLanEndpointCandidate> solePrivate{{
            "only-private", "172.20.4.8", Family::Ipv4,
            true, false, {}}};
        const auto automatic =
            recommendRuntimePrivateLanEndpoint(solePrivate, 3389U);
        assert(automatic.valid());
        assert(automatic.interfaceId == "only-private");
        assert(automatic.address == "172.20.4.8");
        assert(automatic.source ==
               RuntimeHostRecommendationSource::SoleEligibleInterface);

        const std::vector<RuntimeHostLanEndpointCandidate> ambiguous{
            {"private-a", "192.168.20.9", Family::Ipv4,
             true, false, {}},
            {"private-b", "10.50.0.6", Family::Ipv4,
             true, false, {}}};
        const auto noPreference =
            recommendRuntimePrivateLanEndpoint(ambiguous, 3389U);
        assert(!noPreference.valid());
        assert(noPreference.ambiguous);
        assert(noPreference.source ==
               RuntimeHostRecommendationSource::Ambiguous);
        assert(noPreference.interfaceId.empty());
        assert(noPreference.address.empty());

        auto preferenceDisappeared = preferredLan;
        preferenceDisappeared.front().preferredRoute = false;
        const auto refreshed =
            recommendRuntimePrivateLanEndpoint(preferenceDisappeared, 3389U);
        assert(!refreshed.valid());
        assert(refreshed.ambiguous);
        assert(refreshed.interfaceId.empty());
        assert(refreshed.address.empty());

        auto replacementPreference = preferredLan;
        replacementPreference.front().preferredRoute = false;
        replacementPreference.back().preferredRoute = true;
        const auto replacement =
            recommendRuntimePrivateLanEndpoint(replacementPreference, 3389U);
        assert(replacement.valid());
        assert(replacement.interfaceId == "vpn-virtual");
        assert(replacement.address == "10.180.105.86");
        return 0;
    }
    if (testCase == "host-control-product-status-projection")
    {
        const std::vector<RuntimeHostInterface> interfaces{
            {"z-ipv6", "IPv6", {"fd00::20"}, false, true},
            {"b-ipv4", "IPv4 B", {"192.168.2.22"}, false, true},
            {"a-ipv4", "IPv4 A", {"10.0.0.7"}, false, true}};
        const auto recommended =
            recommendRuntimePrivateLanEndpoint(interfaces, 3390U);
        // Interface-only inventory has no route ownership or metric. R10 must
        // not turn Linux-shaped stable IDs into a hidden tie-break policy.
        assert(!recommended.valid());
        assert(recommended.ambiguous);
        assert(recommended.source ==
               RuntimeHostRecommendationSource::Ambiguous);
        assert(recommended.interfaceId.empty());
        assert(recommended.address.empty());
        assert(recommended.port == 3390U);

        assert(runtimeProductStateFor(
                   RuntimeHostStage::Stopped, RuntimeHostError::None,
                   false) == RuntimeProductHostState::Stopped);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::ListenerAvailable, RuntimeHostError::None,
                   false) == RuntimeProductHostState::Listening);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::ClientAuthenticating,
                   RuntimeHostError::None,
                   false) == RuntimeProductHostState::Authenticating);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::ShareActivated, RuntimeHostError::None,
                   false) == RuntimeProductHostState::DesktopInitializing);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::ClientConnected, RuntimeHostError::None,
                   true) == RuntimeProductHostState::Connected);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::Revoked, RuntimeHostError::AccessRevoked,
                   false) == RuntimeProductHostState::Stopped);
        assert(runtimeProductStateFor(
                   RuntimeHostStage::Revoked,
                   RuntimeHostError::HostSessionStale,
                   false) == RuntimeProductHostState::Error);

        assert(runtimeProductStateMayHost(
            RuntimeProductHostState::Starting));
        assert(runtimeProductStateMayHost(
            RuntimeProductHostState::Stopping));
        assert(!runtimeProductStateSharingToggleOn(
            RuntimeProductHostState::Starting));
        assert(runtimeProductStateSharingToggleOn(
            RuntimeProductHostState::Listening));
        assert(runtimeProductStateSharingToggleOn(
            RuntimeProductHostState::Stopping));
        assert(!kStandalonePasswordProductCapabilityApproved);

        const auto unavailableStatus = host.status();
        assert(unavailableStatus.product.state ==
               RuntimeProductHostState::Error);
        assert(!unavailableStatus.product.controlAvailable);
        assert(!unavailableStatus.product.sharingPermission.canRequest);
        assert(!unavailableStatus.product.sharingPermission.activeGrant);
        assert(!unavailableStatus.product.sharingPermission.viewAllowed);
        assert(!unavailableStatus.product.sharingPermission.inputAllowed);
        assert(unavailableStatus.product.sharingPermission.remainingMilliseconds ==
               0U);
        assert(unavailableStatus.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);
        assert(unavailableStatus.product.lastErrorMessage ==
               "Host control unavailable");
        return 0;
    }

    if (testCase == "host-control-credential-editing-lifecycle-policy")
    {
        assert(runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::Stopped, RuntimeProductHostState::Stopped));
        assert(runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::PackageInstalled,
            RuntimeProductHostState::Stopped));
        assert(runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::CredentialsConfigured,
            RuntimeProductHostState::Stopped));
        assert(runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::Stopped, RuntimeProductHostState::Error));

        for (const auto state : {
                 RuntimeProductHostState::Starting,
                 RuntimeProductHostState::Listening,
                 RuntimeProductHostState::Authenticating,
                 RuntimeProductHostState::DesktopInitializing,
                 RuntimeProductHostState::Connected,
                 RuntimeProductHostState::Stopping})
            assert(!runtimeProductCredentialEditingAllowed(
                RuntimeHostStage::Stopped, state));

        assert(!runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::ListenerAvailable,
            RuntimeProductHostState::Listening));
        assert(!runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::ClientAuthenticating,
            RuntimeProductHostState::Authenticating));
        assert(!runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::ShareActivated,
            RuntimeProductHostState::DesktopInitializing));
        assert(!runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::DesktopVisible,
            RuntimeProductHostState::Connected));
        assert(!runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::ClientConnected,
            RuntimeProductHostState::Connected));
        assert(!runtimeProductCredentialEditingAllowed(
            RuntimeHostStage::Revoked, RuntimeProductHostState::Stopped));
        return 0;
    }
    if (testCase == "host-control-endpoint-bound-preauth-identity-consistency")
    {
        RuntimePreauthConnectionIdentityView identity;
        identity.available = true;
        identity.selectedLanNumericAddress = "192.168.1.5";
        identity.selectedLanPort = 3389U;
        identity.tlsCertificateIdentity = "192.168.1.5";
        identity.certificateFingerprintAvailable = true;
        identity.certificateSha256[0] = 0x5aU;
        identity.rdpServiceTargetIdentity = "TERMSRV/192.168.1.5";
        identity.endpointBoundProfileConsistent =
            runtimeEndpointBoundIdentityConsistent(identity);
        assert(identity.endpointBoundProfileConsistent);

        auto mismatchedCertificate = identity;
        mismatchedCertificate.tlsCertificateIdentity = "192.168.1.6";
        assert(!runtimeEndpointBoundIdentityConsistent(
            mismatchedCertificate));

        auto mismatchedServiceTarget = identity;
        mismatchedServiceTarget.rdpServiceTargetIdentity =
            "TERMSRV/RDP-SERVER";
        assert(!runtimeEndpointBoundIdentityConsistent(
            mismatchedServiceTarget));

        auto missingFingerprint = identity;
        missingFingerprint.certificateFingerprintAvailable = false;
        assert(!runtimeEndpointBoundIdentityConsistent(
            missingFingerprint));

        auto ipv6 = identity;
        ipv6.selectedLanNumericAddress = "fd00::15";
        ipv6.tlsCertificateIdentity = "fd00::15";
        ipv6.rdpServiceTargetIdentity = "TERMSRV/fd00::15";
        assert(runtimeEndpointBoundIdentityConsistent(ipv6));
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
