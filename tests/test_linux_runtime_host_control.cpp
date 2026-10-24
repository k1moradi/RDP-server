// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_host_control.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
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

class OfflineUnavailableEvidence final
    : public rdp_server::server::security::ConsoleOsEvidenceSource
{
public:
    rdp_server::server::security::ConsoleAccountObservation readUnixAccount(
        std::string_view) noexcept override
    {
        return {};
    }

    rdp_server::server::security::ConsoleSessionObservation
    readActiveConsole() noexcept override
    {
        return {};
    }

    std::optional<std::uint64_t> readMonotonicMilliseconds() noexcept override
    {
        return 10'000U;
    }
};

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
// R9's peer drives the actual owned LAN socket and X.224 HYBRID negotiation.
// It deliberately does not exchange CredSSP credentials or claim R2 admission.
[[nodiscard]] bool probeHybridTls(std::string_view ipAddress,
                                  std::uint16_t port,
                                  std::atomic<bool>& completed) noexcept
{
    const auto finish = [&completed](bool passed) noexcept {
        completed.store(true, std::memory_order_release);
        return passed;
    };
    const int descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0)
        return finish(false);
    const auto closeDescriptor = [&]() noexcept { ::close(descriptor); };
    timeval deadline{3, 0};
    (void)::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                       &deadline, sizeof(deadline));
    (void)::setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO,
                       &deadline, sizeof(deadline));
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(port);
    const std::string address(ipAddress);
    if (::inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) != 1 ||
        ::connect(descriptor, reinterpret_cast<sockaddr*>(&endpoint),
                  sizeof(endpoint)) != 0)
    {
        closeDescriptor();
        return finish(false);
    }
    constexpr std::array<unsigned char, 19> hybridRequest{
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0,
        0x01, 0x00, 0x08, 0x00, 0x02, 0, 0, 0};
    std::array<unsigned char, 19> confirmation{};
    const bool negotiated =
        ::send(descriptor, hybridRequest.data(), hybridRequest.size(), 0) ==
            static_cast<ssize_t>(hybridRequest.size()) &&
        ::recv(descriptor, confirmation.data(), confirmation.size(),
               MSG_WAITALL) == static_cast<ssize_t>(confirmation.size()) &&
        confirmation[0] == 0x03 && confirmation[1] == 0x00 &&
        confirmation[5] == 0xd0 && confirmation[11] == 0x02 &&
        confirmation[12] == 0x00 && confirmation[13] == 0x08 &&
        confirmation[14] == 0x00 && confirmation[15] == 0x02;
    if (!negotiated)
    {
        closeDescriptor();
        return finish(false);
    }

    SSL_CTX* context = ::SSL_CTX_new(::TLS_client_method());
    if (context == nullptr)
    {
        closeDescriptor();
        return finish(false);
    }
    // The server identity is intentionally self-signed. Validate the exact
    // selected IP SAN instead of disabling certificate identity checking.
    ::SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
    SSL* tls = ::SSL_new(context);
    const bool established = tls != nullptr &&
        ::SSL_set_fd(tls, descriptor) == 1 &&
        ::SSL_connect(tls) == 1;
    X509* certificate = established ? ::SSL_get1_peer_certificate(tls) : nullptr;
    const bool endpointMatches =
        certificate != nullptr &&
        ::X509_check_ip_asc(certificate, address.c_str(), 0) == 1;
    if (certificate != nullptr)
        ::X509_free(certificate);
    // Successful SSL_connect plus an open TLS record layer is the R1 gate.
    // Do not send TSRequest, SPNEGO or NTLM from this fixture.
    const bool passed = established && endpointMatches &&
        ::SSL_is_init_finished(tls) == 1;
    if (tls != nullptr)
        ::SSL_free(tls);
    ::SSL_CTX_free(context);
    closeDescriptor();
    return finish(passed);
}
#endif
} // namespace

int main(int argc, char** argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};
    if (testCase == "linux-host-control-no-consent-start-denials")
    {
        OfflineUnavailableEvidence evidence;
        LinuxRuntimeHostControl control(evidence);
        assert(control.status().stage == RuntimeHostStage::Stopped);
        assert(!control.status().listenerAvailable);
        assert(control.status().selectedEndpoint.empty());
        assert(!control.status().hostOwnerAuthorized);
        assert(!control.status().tlsIdentityReady);
        assert(!control.status().nativeDesktopReady);
        assert(control.status().clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert(control.startSharing().error ==
               RuntimeHostError::InvalidConfiguration);
        assert(control.requestHostPermissionSetup().error ==
               RuntimeHostError::HostConsentRequired);
        assert(control.status().clipboardState ==
               RuntimeClipboardState::Unavailable);
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
        OfflineUnavailableEvidence evidence;
        LinuxRuntimeHostControl control(evidence);
        const auto status = control.status();
        assert(status.product.state == RuntimeProductHostState::Stopped);
        assert(status.product.controlAvailable);
        assert(status.product.credentialEditingAllowed);
        assert(!status.product.credentialCapabilities.existingOsAccount);
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        assert(!status.product.credentialCapabilities.standalonePassword);
        assert(status.product.credentialCapabilities
                   .standalonePasswordConfigurationAvailable);
        assert(status.product.automaticRuntimeProvisioned);
        assert(status.product.readinessStage ==
               RuntimeProductReadinessStage::Provisioned);
#else
        assert(!status.product.credentialCapabilities.standalonePassword);
        assert(!status.product.credentialCapabilities
                    .standalonePasswordConfigurationAvailable);
        assert(!status.product.automaticRuntimeProvisioned);
        assert(status.product.readinessStage ==
               RuntimeProductReadinessStage::Stopped);
#endif
        assert(!status.product.credentialsConfigured);
        assert(!status.product.ownerAuthorized);
        assert(status.clipboardState == RuntimeClipboardState::Unavailable);
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
        OfflineUnavailableEvidence evidence;
        LinuxRuntimeHostControl control(evidence);
        auto status = control.status();
        assert(status.product.controlAvailable);
        assert(status.clipboardState == RuntimeClipboardState::Unavailable);
        assert(!status.product.sharingPermission.canRequest);
        assert(!status.product.sharingPermission.activeGrant);
        assert(status.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);

        assert(control.requestHostPermissionSetup().error ==
               RuntimeHostError::HostConsentRequired);
        status = control.status();
        assert(status.clipboardState == RuntimeClipboardState::Unavailable);
        assert(!status.product.sharingPermission.canRequest);
        assert(!status.product.sharingPermission.activeGrant);
        assert(status.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);
        assert(status.product.lastErrorMessage ==
               "Sharing permission required");
        return 0;
    }

    if (testCase ==
        "linux-host-control-injected-owner-evidence-permission-determinism")
    {
        RuntimeHostPermissionRequest permission;
        permission.allowInput = true;
        permission.allowClipboard = false;
        permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;

        OfflineUnavailableEvidence unavailableEvidence;
        LinuxRuntimeHostControl unavailable(unavailableEvidence);
        auto unavailableStatus = unavailable.status();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        assert(unavailableStatus.product.automaticRuntimeProvisioned);
#endif
        assert(!unavailableStatus.product.sharingPermission.canRequest);
        assert(!unavailableStatus.product.sharingPermission.activeGrant);
        assert(unavailableStatus.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);
        assert(!unavailableStatus.hostOwnerAuthorized);
        assert(unavailableStatus.clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert(!unavailableStatus.listenerAvailable);
        assert(unavailableStatus.boundEndpoint.empty());
        assert(unavailable.requestHostPermissionSetup(permission).error ==
               RuntimeHostError::HostConsentRequired);
        assert(unavailable.startSharing().error ==
               RuntimeHostError::InvalidConfiguration);
        assert(!unavailable.status().listenerAvailable);

        // This branch is fully synthetic: permissionObservation()/requestConsent()
        // consume only the injected evidence, so the fixture UID must not
        // depend on the user running CTest.
        PortableBootstrapEvidence eligibleEvidence(1000U);
        LinuxRuntimeHostControl eligible(eligibleEvidence);
        auto eligibleStatus = eligible.status();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        assert(eligibleStatus.product.automaticRuntimeProvisioned);
#endif
        assert(eligibleStatus.product.sharingPermission.canRequest);
        assert(!eligibleStatus.product.sharingPermission.activeGrant);
        assert(eligibleStatus.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::PermissionRequired);
        assert(!eligibleStatus.hostOwnerAuthorized);
        assert(eligibleStatus.clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert(!eligibleStatus.listenerAvailable);
        assert(eligibleStatus.boundEndpoint.empty());

        assert(eligible.requestHostPermissionSetup(permission).succeeded());
        eligibleStatus = eligible.status();
        assert(eligibleStatus.product.sharingPermission.canRequest);
        assert(eligibleStatus.product.sharingPermission.activeGrant);
        assert(eligibleStatus.product.sharingPermission.viewAllowed);
        assert(eligibleStatus.product.sharingPermission.inputAllowed);
        assert(eligibleStatus.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::None);
        assert(eligibleStatus.hostOwnerAuthorized);
        assert(eligibleStatus.clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert((eligibleStatus.ownerGrant.effectivePermissionMask &
                rdp_server::server::security::kConsoleClipboardPermission) == 0U);
        assert(!eligibleStatus.listenerAvailable);
        assert(eligibleStatus.boundEndpoint.empty());
        assert(eligible.startSharing().error ==
               RuntimeHostError::InvalidConfiguration);
        assert(!eligible.status().listenerAvailable);
        return 0;
    }

    if (testCase ==
        "linux-host-control-standalone-credential-native-admission-separation")
    {
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        return 77;
#else
        OfflineUnavailableEvidence evidence;
        LinuxRuntimeHostControl control(evidence);
        const auto before = control.status();
        assert(before.product.credentialCapabilities
                   .standalonePasswordConfigurationAvailable);
        assert(!before.product.credentialCapabilities.standalonePassword);
        assert(!before.credentialsConfigured);
        assert(!before.product.credentialsConfigured);
        assert(!before.product.sharingPermission.canRequest);
        assert(!before.product.sharingPermission.activeGrant);
        assert(!before.listenerAvailable);

        auto password = standalonePassword();
        assert(control.configureStandaloneApplicationPassword(u"User", password));
        assert(std::ranges::all_of(
            password, [](char16_t value) { return value == u'\0'; }));

        const auto credential =
            control.standaloneApplicationPasswordObservation();
        const auto configured = control.status();
        assert(credential.configured && credential.generation != 0U);
        assert(configured.credentialsConfigured);
        assert(configured.product.credentialsConfigured);
        assert(configured.stage == RuntimeHostStage::CredentialsConfigured);
        assert(!configured.product.sharingPermission.canRequest);
        assert(!configured.product.sharingPermission.activeGrant);
        assert(configured.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::Unavailable);
        assert(!configured.hostOwnerAuthorized);
        assert(!configured.listenerAvailable);
        assert(configured.boundEndpoint.empty());

        assert(control.requestHostPermissionSetup().error ==
               RuntimeHostError::HostConsentRequired);
        assert(control.status().credentialsConfigured);
        assert(!control.status().listenerAvailable);
        return 0;
#endif
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

    if (testCase ==
        "linux-host-control-default-native-evidence-projection")
    {
        LinuxRuntimeHostControl productionControl;
        const auto status = productionControl.status();
        if (!status.product.nativeDesktopTargetAvailable)
            return 77;

        // This is the separate production/default evidence observation gate.
        // It performs no consent request, listener bind, capture or input.
        assert(status.product.sharingPermission.canRequest);
        assert(!status.product.sharingPermission.activeGrant);
        assert(status.product.sharingPermission.denial ==
               RuntimeSharingPermissionDenial::PermissionRequired);
        assert(!status.product.ownerAuthorized);
        assert(!status.listenerAvailable);
        assert(status.boundEndpoint.empty());

        // Native evidence alone cannot manufacture any R4/live-client state.
        assert(!status.firstLiveGraphicsTrace.firstFramebufferAvailable);
        assert(!status.firstLiveGraphicsTrace.firstClearCodecFramePrepared);
        assert(!status.firstLiveGraphicsTrace.firstExactTlsWriteCommitted);
        assert(status.firstLiveGraphicsTrace.outstandingFrameAcknowledgements == 0U);
        assert(!status.firstLiveGraphicsTrace.firstGenuineMatchingFrameAcknowledge);
        return 0;
    }

    if (testCase == "linux-host-control-revalidated-interface-denials")
    {
        LinuxRuntimeHostControl control;
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
        LinuxRuntimeHostControl control;
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
        LinuxRuntimeHostControl control;
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
        LinuxRuntimeHostControl control;
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
#else
        LinuxRuntimeHostControl control;
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
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        // Credential validity is independent of the later native-admission
        // and owner-consent Start prerequisites.
        assert(control.status().credentialsConfigured);
        assert(control.status().stage ==
               RuntimeHostStage::CredentialsConfigured);
        assert(control.status().product.credentialEditingAllowed);
        assert(!control.status().hostOwnerAuthorized);
        assert(!control.status().listenerAvailable);
#else
        assert(!control.status().credentialsConfigured);
        assert(control.status().stage == RuntimeHostStage::Stopped);
#endif

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
        assert(!control.status().product.credentialEditingAllowed);
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

    if (testCase ==
        "linux-host-control-standalone-owner-grant-authoritative-listener")
    {
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        return 77;
#else
        const auto processUid = static_cast<std::uint32_t>(::getuid());
        if (processUid == 0U)
            return 77;
        PortableBootstrapEvidence evidence(processUid);
        LinuxRuntimeHostControl control(evidence);

        // R1 must remain dormant while R10 owns only a valid standalone
        // credential plus an active local-owner grant.
        auto password = standalonePassword();
        assert(control.configureStandaloneApplicationPassword(u"rdp", password));
        assert(std::ranges::all_of(
            password, [](char16_t value) { return value == u'\0'; }));

        RuntimeHostPermissionRequest permission;
        permission.allowInput = true;
        permission.allowClipboard = false;
        permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;
        assert(control.requestHostPermissionSetup(permission).succeeded());

        const auto granted = control.status();
        assert(granted.credentialsConfigured);
        assert(granted.hostOwnerAuthorized);
        assert(granted.product.ownerAuthorized);
        assert(granted.product.credentialEditingAllowed);
        assert(!granted.listenerAvailable);
        assert(granted.listenerGeneration == 0U);
        assert(granted.boundEndpoint.empty());
        assert(!granted.tlsIdentityReady);

        const auto recommendation = granted.product.recommendedEndpoint;
        if (!recommendation.valid())
            return 77;
        assert(recommendation.address != "0.0.0.0");
        assert(recommendation.address != "::");
        assert(recommendation.address != "[::]");

        bool listenerStarted = false;
        std::string selectedEndpoint;
        for (std::uint16_t port = 34000U; port <= 34029U; ++port)
        {
            const RuntimeHostOptions options{
                recommendation.interfaceId, recommendation.address,
                port, true, false};
            assert(control.configure(options).succeeded());

            const auto prepared = control.status();
            assert(prepared.credentialsConfigured);
            assert(prepared.hostOwnerAuthorized);
            assert(prepared.tlsIdentityReady);
            assert(prepared.tlsIdentity.state ==
                   RuntimeTlsIdentityState::ConfiguredUnbound);
            assert(prepared.tlsIdentity.endpointGeneration == 0U);
            assert(!prepared.listenerAvailable);
            assert(prepared.listenerGeneration == 0U);
            assert(prepared.boundEndpoint.empty());
            assert(!prepared.selectedEndpoint.empty());

            const RuntimeHostResult start = control.startSharing();
            if (start.succeeded())
            {
                listenerStarted = true;
                selectedEndpoint = prepared.selectedEndpoint;
                break;
            }
            assert(start.error == RuntimeHostError::PortUnavailable);
            const auto denied = control.status();
            assert(!denied.listenerAvailable);
            assert(denied.listenerGeneration == 0U);
            assert(denied.boundEndpoint.empty());
        }
        assert(listenerStarted);

        const auto listening = control.status();
        assert(listening.listenerAvailable);
        assert(listening.listenerGeneration != 0U);
        assert(!selectedEndpoint.empty());
        assert(listening.selectedEndpoint == selectedEndpoint);
        assert(listening.boundEndpoint == selectedEndpoint);
        assert(listening.product.boundEndpoint == selectedEndpoint);
        assert(listening.product.state == RuntimeProductHostState::Listening);
        assert(!listening.product.credentialEditingAllowed);
        assert(listening.product.readinessStage ==
               RuntimeProductReadinessStage::Listening);
        assert(listening.activeClients.empty());

        // R1's authoritative listener evidence is inseparable from the
        // generated certificate matching this exact bound numeric address.
        assert(listening.tlsIdentityReady);
        assert(listening.product.tlsIdentityReady);
        assert(listening.tlsIdentity.state ==
               RuntimeTlsIdentityState::BoundAndMatched);
        assert(listening.tlsIdentity.endpointGeneration ==
               listening.listenerGeneration);
        assert(listening.tlsIdentity.boundIdentityMatchesGeneration(
            listening.listenerGeneration));

        assert(control.stopSharing().succeeded());
        const auto stopped = control.status();
        assert(stopped.stage == RuntimeHostStage::Stopped);
        assert(stopped.product.credentialEditingAllowed);
        assert(!stopped.listenerAvailable);
        assert(stopped.listenerGeneration == 0U);
        assert(stopped.boundEndpoint.empty());
        assert(stopped.product.boundEndpoint.empty());
        assert(!stopped.tlsIdentityReady);
        assert(!stopped.product.tlsIdentityReady);
        assert(stopped.tlsIdentity.state ==
               RuntimeTlsIdentityState::Unavailable);
        assert(!stopped.tlsIdentity.fingerprintAvailable);
        assert(stopped.tlsIdentity.endpointGeneration == 0U);
        assert(!stopped.hostOwnerAuthorized);
        assert(!stopped.product.ownerAuthorized);
        return 0;
#endif
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


    if (testCase == "r9-start-stop-start-and-tls-interop")
    {
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        return 77;
#else
        const auto processUid = static_cast<std::uint32_t>(::getuid());
        if (processUid == 0U)
            return 77;
        PortableBootstrapEvidence evidence(processUid);
        LinuxRuntimeHostControl control(evidence);
        const auto recommendation = control.status().product.recommendedEndpoint;
        if (!recommendation.valid())
            return 77;
        // The fixture uses AF_INET; IPv6 deployment requires its own peer.
        in_addr parsedAddress{};
        if (::inet_pton(AF_INET, recommendation.address.c_str(),
                        &parsedAddress) != 1)
            return 77;

        auto password = standalonePassword();
        assert(control.configureStandaloneApplicationPassword(u"rdp", password));
        assert(std::ranges::all_of(password,
            [](char16_t value) { return value == u'\0'; }));
        const auto original = control.standaloneApplicationPasswordObservation();
        assert(original.configured && original.generation != 0U);

        RuntimeHostPermissionRequest permission;
        permission.allowInput = true;
        permission.allowClipboard = false;
        permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;
        std::uint16_t selectedPort = 0U;
        std::uint64_t previousListenerGeneration = 0U;
        for (int cycle = 0; cycle < 3; ++cycle)
        {
            // Stop must not make consent sticky. Every Start is a fresh local
            // owner authorization, even with an unchanged credential.
            assert(!control.status().hostOwnerAuthorized);
            assert(control.requestHostPermissionSetup(permission).succeeded());
            assert(control.status().hostOwnerAuthorized);
            if (cycle == 0)
            {
                for (std::uint16_t port = 34100U; port < 34130U; ++port)
                {
                    const RuntimeHostOptions options{
                        recommendation.interfaceId, recommendation.address,
                        port, true, false};
                    assert(control.configure(options).succeeded());
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
                const RuntimeHostOptions options{
                    recommendation.interfaceId, recommendation.address,
                    selectedPort, true, false};
                assert(control.configure(options).succeeded());
                assert(control.startSharing().succeeded());
            }
            const auto live = control.status();
            assert(live.listenerAvailable && live.listenerGeneration != 0U);
            assert(live.listenerGeneration != previousListenerGeneration);
            assert(live.tlsIdentityReady);
            assert(live.tlsIdentity.boundIdentityMatchesGeneration(
                live.listenerGeneration));
            previousListenerGeneration = live.listenerGeneration;

            if (cycle == 0)
            {
                // Pump only the production owning thread; the peer thread owns
                // its socket and TLS context, never HostControl or native UI.
                std::atomic<bool> completed{false};
                bool probePassed = false;
                std::thread peer([&] {
                    probePassed = probeHybridTls(recommendation.address,
                                                selectedPort, completed);
                });
                const auto limit = std::chrono::steady_clock::now() +
                                    std::chrono::seconds(5);
                while (!completed.load(std::memory_order_acquire) &&
                       std::chrono::steady_clock::now() < limit)
                {
                    (void)control.serviceOnce();
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                peer.join();
                assert(probePassed);
            }
            assert(control.stopSharing().succeeded());
            const auto stopped = control.status();
            assert(stopped.stage == RuntimeHostStage::Stopped);
            assert(!stopped.listenerAvailable);
            assert(stopped.listenerGeneration == 0U);
            assert(stopped.boundEndpoint.empty());
            assert(stopped.activeClients.empty());
            assert(!stopped.nativeDesktopReady);
            assert(!stopped.tlsIdentityReady);
            assert(!stopped.tlsIdentity.fingerprintAvailable);
            assert(!stopped.hostOwnerAuthorized);
            assert(!stopped.product.ownerAuthorized);
            const auto retained = control.standaloneApplicationPasswordObservation();
            assert(retained.configured &&
                   retained.generation == original.generation);
            StandaloneVisitObservation visited;
            assert(control.visitStandaloneApplicationPassword(
                original.generation, &observeStandaloneCredential, &visited));
            assert(visited.visited);
        }
        assert(control.revokeSharing().succeeded());
        assert(!control.standaloneApplicationPasswordObservation().configured);
        return 0;
#endif
    }
    if (testCase == "linux-host-control-stop-revoke-retirement")
    {
        LinuxRuntimeHostControl control;
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
