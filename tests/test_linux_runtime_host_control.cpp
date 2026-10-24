// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_host_control.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <net/if.h>
#include <optional>
#include <string>
#include <string_view>
#include <unistd.h>
using namespace rdp_server::server::runtime;
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
    auto* observation =
        static_cast<StandaloneVisitObservation*>(rawContext);
    if (observation == nullptr)
        return false;
    observation->visited = credential.configured();
    return observation->visited;
}

[[nodiscard]] std::array<char16_t, 8> standalonePassword()
{
    return {u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
}

[[nodiscard]] bool isExpectedUnprovisionedPrelistenerDenial(
    RuntimeHostError error) noexcept
{
    // R5's native desktop gate intentionally precedes R2 credential-provider
    // checks. Headless/offline hosts therefore fail at native authorization,
    // while an eligible physical X11 owner session reaches the still-
    // unprovisioned credential-provider gate. Both are pre-listener denials.
    return error == RuntimeHostError::NativeAuthorizationDenied ||
           error == RuntimeHostError::CredentialProviderUnavailable;
}

class PortableBootstrapEvidence final
    : public rdp_server::server::security::ConsoleOsEvidenceSource
{
public:
    explicit PortableBootstrapEvidence(std::uint32_t uid) noexcept : uid_(uid) {}

    rdp_server::server::security::ConsoleAccountObservation readUnixAccount(
        std::string_view) noexcept override
    {
        return {};
    }

    rdp_server::server::security::ConsoleSessionObservation
    readActiveConsole() noexcept override
    {
        using namespace rdp_server::server::security;
        return {ConsoleEvidenceReadStatus::Observed, "portable-bootstrap",
                "seat0", ":42", uid_, 91U, now_, true, true, uid_,
                ConsoleDesktopLockState::Unlocked, false};
    }

    std::optional<std::uint64_t> readMonotonicMilliseconds() noexcept override
    {
        return now_;
    }

private:
    std::uint32_t uid_{};
    std::uint64_t now_{10'000U};
};
} // namespace

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
        assert(control.status().selectedEndpoint.empty());
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
    if (testCase == "linux-host-control-product-status-projection")
    {
        const auto status = control.status();
        assert(status.product.state == RuntimeProductHostState::Stopped);
        assert(status.product.controlAvailable);
        assert(!status.product.credentialCapabilities.existingOsAccount);
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        assert(!status.product.credentialCapabilities.standalonePassword);
        assert(status.product.automaticRuntimeProvisioned);
        assert(status.product.readinessStage ==
               RuntimeProductReadinessStage::Provisioned);
#else
        assert(!status.product.credentialCapabilities.standalonePassword);
        assert(!status.product.automaticRuntimeProvisioned);
        assert(status.product.readinessStage ==
               RuntimeProductReadinessStage::Stopped);
#endif
        assert(!status.product.credentialsConfigured);
        assert(!status.product.ownerAuthorized);
        assert(!status.product.sharingPermission.canRequest);
        assert(!status.product.sharingPermission.activeGrant);
        assert(!status.product.sharingPermission.viewAllowed);
        assert(!status.product.sharingPermission.inputAllowed);
        assert(status.product.sharingPermission.remainingMilliseconds == 0U);
        assert(status.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);
        assert(status.product.clientCount == 0U);
        assert(status.product.activeClientIds.empty());
        assert(status.product.boundEndpoint.empty());
        assert(!status.firstLiveGraphicsTrace.firstFramebufferAvailable);
        assert(!status.firstLiveGraphicsTrace.firstClearCodecFramePrepared);
        assert(!status.firstLiveGraphicsTrace.firstExactTlsWriteCommitted);
        assert(status.firstLiveGraphicsTrace.outstandingFrameAcknowledgements == 0U);
        assert(!status.firstLiveGraphicsTrace.firstGenuineMatchingFrameAcknowledge);
        assert(status.product.lastErrorMessage ==
               "Sharing permission required");

        const auto& recommended = status.product.recommendedEndpoint;
        if (recommended.valid())
        {
            assert(recommended.source ==
                       RuntimeHostRecommendationSource::PreferredRoute ||
                   recommended.source ==
                       RuntimeHostRecommendationSource::SoleEligibleInterface);
            const RuntimeHostOptions selection{
                recommended.interfaceId, recommended.address,
                recommended.port, true, false};
            assert(assessRuntimeSelectedLanEndpoint(
                       selection,
                       status.product.eligibleLanInterfaces).succeeded());
        }
        else
        {
            assert(recommended.interfaceId.empty());
            assert(recommended.address.empty());
            assert(recommended.source ==
                       RuntimeHostRecommendationSource::Ambiguous ||
                   recommended.source ==
                       RuntimeHostRecommendationSource::Unavailable);
        }
        return 0;
    }

    if (testCase ==
        "linux-host-control-sharing-permission-product-projection")
    {
        auto status = control.status();
        assert(status.product.controlAvailable);
        assert(!status.product.sharingPermission.canRequest);
        assert(!status.product.sharingPermission.activeGrant);
        assert(status.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);

        assert(control.requestHostPermissionSetup().error ==
               RuntimeHostError::HostConsentRequired);
        status = control.status();
        assert(!status.product.sharingPermission.canRequest);
        assert(!status.product.sharingPermission.activeGrant);
        assert(status.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);
        assert(status.product.lastErrorMessage ==
               "Sharing permission required");
        return 0;
    }

    if (testCase == "linux-host-control-first-live-graphics-trace-projection")
    {
        const auto framebufferOnly = projectRuntimeFirstLiveGraphicsTrace(
            true, false, false, 0U, false);
        assert(framebufferOnly.firstFramebufferAvailable);
        assert(!framebufferOnly.firstClearCodecFramePrepared);
        assert(!framebufferOnly.firstExactTlsWriteCommitted);
        assert(framebufferOnly.outstandingFrameAcknowledgements == 0U);
        assert(!framebufferOnly.firstGenuineMatchingFrameAcknowledge);

        const auto awaitingAck = projectRuntimeFirstLiveGraphicsTrace(
            true, true, true, 1U, false);
        assert(awaitingAck.firstFramebufferAvailable);
        assert(awaitingAck.firstClearCodecFramePrepared);
        assert(awaitingAck.firstExactTlsWriteCommitted);
        assert(awaitingAck.outstandingFrameAcknowledgements == 1U);
        assert(!awaitingAck.firstGenuineMatchingFrameAcknowledge);

        const auto acknowledged = projectRuntimeFirstLiveGraphicsTrace(
            true, true, true, 0U, true);
        assert(acknowledged.firstFramebufferAvailable);
        assert(acknowledged.firstClearCodecFramePrepared);
        assert(acknowledged.firstExactTlsWriteCommitted);
        assert(acknowledged.outstandingFrameAcknowledgements == 0U);
        assert(acknowledged.firstGenuineMatchingFrameAcknowledge);
        return 0;
    }

    if (testCase == "linux-host-control-route-aware-lan-recommendation")
    {
        using Family = RuntimeHostAddressFamily;
        using Source = RuntimeHostRecommendationSource;
        const std::vector<RuntimeHostInterface> interfaces{
            {"physical#2", "Physical LAN", {"192.168.1.5"}, false, true},
            {"vpn#7", "VPN", {"10.180.105.86"}, false, true}};

        {
            const std::vector<LinuxRuntimeDefaultRoutePreference> routes{
                {"physical#2", Family::Ipv4, 100U},
                {"vpn#7", Family::Ipv4, 600U}};
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(interfaces, routes);
            assert(recommended.valid());
            assert(recommended.interfaceId == "physical#2");
            assert(recommended.address == "192.168.1.5");
            assert(recommended.source == Source::PreferredRoute);
            assert(recommended.routeMetric == 100U);
        }

        {
            const std::vector<LinuxRuntimeDefaultRoutePreference> routes{
                {"physical#2", Family::Ipv4, 100U},
                {"vpn#7", Family::Ipv4, 25U}};
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(interfaces, routes);
            assert(recommended.valid());
            assert(recommended.interfaceId == "vpn#7");
            assert(recommended.address == "10.180.105.86");
            assert(recommended.source == Source::PreferredRoute);
            assert(recommended.routeMetric == 25U);
        }

        {
            const std::vector<LinuxRuntimeDefaultRoutePreference> routes{
                {"physical#2", Family::Ipv4, 100U},
                {"vpn#7", Family::Ipv4, 100U}};
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(interfaces, routes);
            assert(!recommended.valid());
            assert(recommended.ambiguous);
            assert(recommended.source == Source::Ambiguous);
        }

        {
            const std::vector<RuntimeHostInterface> sole{{
                "wifi#4", "Wi-Fi",
                {"fd12:3456::5", "192.168.50.5"}, false, true}};
            const std::vector<LinuxRuntimeDefaultRoutePreference> noRoutes;
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(sole, noRoutes, 3390U);
            assert(recommended.valid());
            assert(recommended.interfaceId == "wifi#4");
            assert(recommended.address == "192.168.50.5");
            assert(recommended.port == 3390U);
            assert(recommended.source == Source::SoleEligibleInterface);
        }

        {
            const std::vector<RuntimeHostInterface> mixedFamily{
                {"ipv4#3", "IPv4 LAN", {"192.168.70.3"}, false, true},
                {"ipv6#8", "IPv6 LAN", {"fd70::8"}, false, true}};
            const std::vector<LinuxRuntimeDefaultRoutePreference> routes{
                {"ipv4#3", Family::Ipv4, 200U},
                {"ipv6#8", Family::Ipv6, 20U}};
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(mixedFamily, routes);
            assert(recommended.valid());
            assert(recommended.interfaceId == "ipv6#8");
            assert(recommended.address == "fd70::8");
            assert(recommended.family == Family::Ipv6);
            assert(recommended.source == Source::PreferredRoute);
        }

        {
            const std::vector<LinuxRuntimeDefaultRoutePreference> noRoutes;
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(interfaces, noRoutes);
            assert(!recommended.valid());
            assert(recommended.ambiguous);
            assert(recommended.source == Source::Ambiguous);
        }

        {
            const std::vector<LinuxRuntimeDefaultRoutePreference> routes{
                {"physical#2", Family::Ipv4, 10U},
                {"vpn#7", Family::Ipv4, 100U}};
            const auto recommended =
                recommendLinuxPrivateLanEndpoint(interfaces, routes);
            assert(recommended.valid());
            const RuntimeHostOptions staleSelection{
                recommended.interfaceId, recommended.address,
                recommended.port, true, false};
            const std::vector<RuntimeHostInterface> afterRemoval{
                {"vpn#7", "VPN", {"10.180.105.86"}, false, true}};
            assert(assessRuntimeSelectedLanEndpoint(
                       staleSelection, afterRemoval).error ==
                   RuntimeHostError::InterfaceUnavailable);
        }
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
            const auto configured = control.status();
            assert(!configured.selectedEndpoint.empty());
            assert(configured.listenerGeneration == 0U);
            assert(configured.boundEndpoint.empty());
            const auto start = control.startSharing();
            assert(isExpectedUnprovisionedPrelistenerDenial(start.error));
            assert(!control.status().listenerAvailable);
            assert(control.status().boundEndpoint.empty());
        }
        return 0;
    }
    if (testCase == "linux-host-control-automatic-tls-identity-lifecycle")
    {
        const auto interfaces = control.enumerateLocalInterfaces();
        if (interfaces.empty() || interfaces.front().localAddresses.empty())
            return 77;

        const RuntimeHostOptions selected{
            interfaces.front().stableId,
            interfaces.front().localAddresses.front(), 3389U, true, false};
        assert(control.configure(selected).succeeded());
        const auto prepared = control.status();
        assert(prepared.tlsIdentityReady);
        assert(prepared.tlsIdentity.fingerprintAvailable);
        assert(prepared.tlsIdentity.state ==
               RuntimeTlsIdentityState::ConfiguredUnbound);
        assert(prepared.listenerGeneration == 0U);
        assert(!prepared.listenerAvailable);
        assert(prepared.boundEndpoint.empty());

        RuntimeHostOptions stale = selected;
        stale.localAddress = "203.0.113.250";
        assert(!control.configure(stale).succeeded());
        const auto rejected = control.status();
        assert(!rejected.tlsIdentityReady);
        assert(!rejected.tlsIdentity.fingerprintAvailable);
        assert(!rejected.listenerAvailable);

        assert(control.configure(selected).succeeded());
        assert(control.status().tlsIdentityReady);
        assert(!control.status().listenerAvailable);

        // This R1 lifecycle case owns endpoint preparation/retirement only.
        // Native desktop and R2 credential gates are independently covered
        // elsewhere and must not make TLS Stop retirement host-dependent.
        assert(control.stopSharing().succeeded());
        const auto stopped = control.status();
        assert(!stopped.tlsIdentityReady);
        assert(!stopped.tlsIdentity.fingerprintAvailable);
        assert(!stopped.listenerAvailable);
        assert(stopped.listenerGeneration == 0U);
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
        const auto initialStart = control.startSharing();
        assert(isExpectedUnprovisionedPrelistenerDenial(initialStart.error));
        assert(!control.status().listenerAvailable);

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
    if (testCase == "linux-host-control-native-interface-id-verification")
    {
        for (const std::string_view malformed : {
                 std::string_view{}, std::string_view{"lo"},
                 std::string_view{"#1"}, std::string_view{"lo#"},
                 std::string_view{"lo#0"}, std::string_view{"lo#01"},
                 std::string_view{"lo#+1"}, std::string_view{"lo#-1"},
                 std::string_view{"lo#1tail"},
                 std::string_view{"lo#42949672960"},
                 std::string_view{"lo#1#1"},
                 std::string_view{"interface-name-long#1"}})
            assert(!resolveCurrentLinuxNativeLanInterface(malformed));
        const std::string embeddedNul("lo#1\0suffix", 11U);
        assert(!resolveCurrentLinuxNativeLanInterface(embeddedNul));
        const unsigned int index = ::if_nametoindex("lo");
        if (index != 0U)
        {
            const std::string id = "lo#" + std::to_string(index);
            const auto identity = resolveCurrentLinuxNativeLanInterface(id);
            assert(identity.has_value());
            assert(identity->nativeName == "lo");
            assert(identity->nativeIndex == index);
            const unsigned int changed = index ==
                std::numeric_limits<unsigned int>::max() ? index-1U : index+1U;
            assert(!resolveCurrentLinuxNativeLanInterface(
                "lo#" + std::to_string(changed)));
        }
        // Valid native identity is not valid LAN authorization.
        assert(!control.status().listenerAvailable);
        assert(!control.status().hostOwnerAuthorized);
        assert(!control.status().tlsIdentityReady);
        return 0;
    }
    if (testCase == "linux-host-control-standalone-password-lifecycle")
    {
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        const auto processUid = static_cast<std::uint32_t>(::getuid());
        if (processUid == 0U)
            return 77;
        PortableBootstrapEvidence evidence(processUid);
        // The production standalone path now requires the same fresh native
        // X11 evidence used by normal no-config composition. Inject only that
        // read-only evidence while keeping the real R2 credential owner.
        LinuxRuntimeHostControl control(evidence);
#endif
        auto password = standalonePassword();
        assert(control.configureStandaloneApplicationPassword(
            u"User", password));
        assert(std::ranges::all_of(
            password,
            [](char16_t value) { return value == u'\0'; }));

        const auto first =
            control.standaloneApplicationPasswordObservation();
        assert(first.configured && first.generation != 0U);
        assert(!control.status().credentialsConfigured);
        assert(control.status().stage == RuntimeHostStage::Stopped);

        StandaloneVisitObservation observed;
        assert(control.visitStandaloneApplicationPassword(
            first.generation, &observeStandaloneCredential, &observed));
        assert(observed.visited);
        assert(!control.visitStandaloneApplicationPassword(
            first.generation + 1U,
            &observeStandaloneCredential, &observed));

        // Switching to any product credential mode revokes the alternate
        // standalone credential even when that product request later denies.
        assert(control.requestCredentialSetup(
                   LanCredentialChoice::IndependentApplicationPassword).error ==
               RuntimeHostError::UnsupportedIndependentPasswordNla);
        const auto afterModeRequest =
            control.standaloneApplicationPasswordObservation();
        assert(!afterModeRequest.configured);
        assert(afterModeRequest.generation > first.generation);
        assert(!control.visitStandaloneApplicationPassword(
            first.generation, &observeStandaloneCredential, &observed));

        auto secondPassword = standalonePassword();
        assert(control.configureStandaloneApplicationPassword(
            u"User", secondPassword));
        const auto second =
            control.standaloneApplicationPasswordObservation();
        assert(second.configured);
        assert(second.generation > afterModeRequest.generation);

        assert(control.stopSharing().succeeded());
        const auto afterStop =
            control.standaloneApplicationPasswordObservation();
        assert(!afterStop.configured);
        assert(afterStop.generation > second.generation);
        assert(!control.visitStandaloneApplicationPassword(
            second.generation, &observeStandaloneCredential, &observed));

        auto thirdPassword = standalonePassword();
        assert(control.configureStandaloneApplicationPassword(
            u"User", thirdPassword));
        const auto third =
            control.standaloneApplicationPasswordObservation();
        assert(third.configured && third.generation > afterStop.generation);

        assert(control.revokeSharing().succeeded());
        const auto afterRevoke =
            control.standaloneApplicationPasswordObservation();
        assert(!afterRevoke.configured);
        assert(afterRevoke.generation > third.generation);

        auto deniedPassword = standalonePassword();
        assert(!control.configureStandaloneApplicationPassword(
            u"User", deniedPassword));
        assert(std::ranges::all_of(
            deniedPassword,
            [](char16_t value) { return value == u'\0'; }));
        assert(!control.standaloneApplicationPasswordObservation().configured);
        return 0;
    }

    if (testCase == "linux-portable-gui-bootstrap-listener-acceptance")
    {
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        return 2;
#else
        const auto processUid = static_cast<std::uint32_t>(::getuid());
        assert(processUid != 0U);
        PortableBootstrapEvidence evidence(processUid);
        LinuxRuntimeHostControl bootstrap(evidence);

        const auto initial = bootstrap.status();
        assert(initial.product.automaticRuntimeProvisioned);
        assert(initial.product.recommendedEndpoint.valid());
        assert(initial.product.boundEndpoint.empty());
        assert(!initial.listenerAvailable && initial.listenerGeneration == 0U);

        auto firstPassword = standalonePassword();
        assert(bootstrap.configureStandaloneApplicationPassword(u"rdp", firstPassword));
        assert(std::ranges::all_of(firstPassword,
            [](char16_t value) { return value == u'\0'; }));
        const auto firstCredential = bootstrap.standaloneApplicationPasswordObservation();
        assert(firstCredential.configured && firstCredential.generation != 0U);

        auto replacementPassword = standalonePassword();
        replacementPassword.back() = u'2';
        assert(bootstrap.configureStandaloneApplicationPassword(
            u"rdp", replacementPassword));
        const auto replacementCredential =
            bootstrap.standaloneApplicationPasswordObservation();
        assert(replacementCredential.configured);
        assert(replacementCredential.generation > firstCredential.generation);
        StandaloneVisitObservation obsoleteVisit;
        assert(!bootstrap.visitStandaloneApplicationPassword(
            firstCredential.generation, &observeStandaloneCredential,
            &obsoleteVisit));

        RuntimeHostPermissionRequest permission;
        permission.allowInput = true;
        permission.allowClipboard = false;
        permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;
        assert(bootstrap.requestHostPermissionSetup(permission).succeeded());
        assert(bootstrap.status().hostOwnerAuthorized);
        assert(!bootstrap.status().listenerAvailable);

        const auto recommendation = bootstrap.status().product.recommendedEndpoint;
        assert(recommendation.valid());
        bool listenerStarted = false;
        for (std::uint16_t port = 33950U; port <= 33979U; ++port)
        {
            const RuntimeHostOptions options{
                recommendation.interfaceId, recommendation.address,
                port, true, false};
            assert(bootstrap.configure(options).succeeded());
            const auto prepared = bootstrap.status();
            assert(prepared.tlsIdentityReady);
            assert(!prepared.listenerAvailable);
            assert(prepared.boundEndpoint.empty());

            const RuntimeHostResult start = bootstrap.startSharing();
            if (start.succeeded())
            {
                listenerStarted = true;
                break;
            }
            assert(start.error == RuntimeHostError::PortUnavailable);
        }
        assert(listenerStarted);

        const auto listening = bootstrap.status();
        assert(listening.listenerAvailable);
        assert(listening.listenerGeneration != 0U);
        assert(!listening.boundEndpoint.empty());
        assert(listening.product.boundEndpoint == listening.boundEndpoint);
        assert(listening.product.state == RuntimeProductHostState::Listening);

        assert(bootstrap.stopSharing().succeeded());
        const auto stopped = bootstrap.status();
        assert(!stopped.listenerAvailable && stopped.listenerGeneration == 0U);
        assert(stopped.boundEndpoint.empty());
        assert(!stopped.hostOwnerAuthorized);
        assert(!stopped.product.ownerAuthorized);
        return 0;
#endif
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
