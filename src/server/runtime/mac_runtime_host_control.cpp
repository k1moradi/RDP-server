// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_runtime_host_control.h"
#include "server/security/standalone_credential_consent.h"

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#if defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#endif

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>

namespace rdp_server::server::runtime
{
namespace
{

void cleansePassword(std::span<char16_t> password) noexcept
{
    for (char16_t& codeUnit : password)
    {
        volatile char16_t* const volatileCodeUnit = &codeUnit;
        *volatileCodeUnit = u'\0';
    }
}

[[nodiscard]] bool validateStandaloneCredentialVisit(
    const rdp_server::server::security::EphemeralNtlmV2Credential& credential,
    void* context) noexcept
{
    auto* visited = static_cast<bool*>(context);
    if (visited == nullptr)
        return false;
    *visited = credential.configured();
    return *visited;
}

[[nodiscard]] constexpr RuntimeHostError listenerRuntimeError(
    rdp_server::server::transport::LanListenerError error) noexcept
{
    using Error = rdp_server::server::transport::LanListenerError;
    switch (error)
    {
    case Error::None: return RuntimeHostError::None;
    case Error::InvalidSelection: return RuntimeHostError::InvalidConfiguration;
    case Error::InterfaceUnavailable: return RuntimeHostError::InterfaceUnavailable;
    case Error::PermissionDenied: return RuntimeHostError::ListenerPolicyDenied;
    case Error::PortOccupied: return RuntimeHostError::PortUnavailable;
    case Error::ListenerNotReady: return RuntimeHostError::InternalFailure;
    case Error::TerminalDisconnect: return RuntimeHostError::InternalFailure;
    case Error::CertificateMismatch: return RuntimeHostError::TlsIdentityUnavailable;
    }
    return RuntimeHostError::InternalFailure;
}

[[nodiscard]] bool isEligibleAddress(const sockaddr* address)
{
    if (address == nullptr)
        return false;
    if (address->sa_family == AF_INET)
    {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        const auto bytes =
            reinterpret_cast<const std::uint8_t*>(&ipv4->sin_addr);
        return (bytes[0] == 10U) ||
               (bytes[0] == 172U && bytes[1] >= 16U && bytes[1] <= 31U) ||
               (bytes[0] == 192U && bytes[1] == 168U);
    }
    if (address->sa_family == AF_INET6)
    {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        const auto* bytes = ipv6->sin6_addr.s6_addr;
        const bool linkLocal =
            bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
        const bool ula = (bytes[0] & 0xfe) == 0xfc;
        return linkLocal || ula;
    }
    return false;
}

[[nodiscard]] std::string numericAddress(const sockaddr* address)
{
    if (!isEligibleAddress(address))
        return {};
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (address->sa_family == AF_INET)
    {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, address, sizeof(ipv4));
        if (::inet_ntop(AF_INET, &ipv4.sin_addr,
                        buffer.data(), buffer.size()) == nullptr)
            return {};
    }
    else
    {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, address, sizeof(ipv6));
        if (::inet_ntop(AF_INET6, &ipv6.sin6_addr,
                        buffer.data(), buffer.size()) == nullptr)
            return {};
    }
    return buffer.data();
}

[[nodiscard]] std::string endpointText(
    std::string_view address, std::uint16_t port)
{
    if (address.empty() || port == 0U)
        return {};
    const bool ipv6 = address.find(':') != std::string_view::npos;
    std::string endpoint;
    endpoint.reserve(address.size() + 8U);
    if (ipv6)
        endpoint.push_back('[');
    endpoint.append(address);
    if (ipv6)
        endpoint.push_back(']');
    endpoint.push_back(':');
    endpoint.append(std::to_string(port));
    return endpoint;
}

[[nodiscard]] std::string boundEndpointText(
    const rdp_server::server::transport::TcpPeerEndpoint &endpoint)
{
    if (!endpoint.valid() || endpoint.port == 0U)
        return {};

    int family = 0;
    if (endpoint.family ==
        rdp_server::server::transport::TcpPeerAddressFamily::Ipv4)
        family = AF_INET;
    else if (endpoint.family ==
             rdp_server::server::transport::TcpPeerAddressFamily::Ipv6)
        family = AF_INET6;
    if (family == 0)
        return {};

    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (::inet_ntop(family, endpoint.address.data(),
                    buffer.data(), buffer.size()) == nullptr)
        return {};
    return endpointText(buffer.data(), endpoint.port);
}

[[nodiscard]] RuntimeSharingPermissionStatus sharingPermissionStatus(
    const rdp_server::server::security::OwnerSharingPermissionObservation&
        observation) noexcept
{
    using rdp_server::server::security::OwnerSharingReadOnlyDenial;
    RuntimeSharingPermissionStatus status;
    status.canRequest = observation.canRequest;
    status.activeGrant = observation.activeGrant;
    status.viewAllowed =
        (observation.effectivePermissionMask &
         rdp_server::server::security::kConsoleViewPermission) != 0U;
    status.inputAllowed =
        (observation.effectivePermissionMask &
         rdp_server::server::security::kConsoleInputPermission) != 0U;
    status.remainingMilliseconds = observation.remainingMilliseconds;
    switch (observation.denial)
    {
    case OwnerSharingReadOnlyDenial::None:
        status.denial = RuntimeSharingPermissionDenial::None;
        break;
    case OwnerSharingReadOnlyDenial::PermissionRequired:
        status.denial = RuntimeSharingPermissionDenial::PermissionRequired;
        break;
    case OwnerSharingReadOnlyDenial::PermissionExpired:
        status.denial = RuntimeSharingPermissionDenial::PermissionExpired;
        break;
    case OwnerSharingReadOnlyDenial::ComputerLocked:
        status.denial = RuntimeSharingPermissionDenial::ComputerLocked;
        break;
    case OwnerSharingReadOnlyDenial::LoggedInDesktopChanged:
        status.denial = RuntimeSharingPermissionDenial::LoggedInDesktopChanged;
        break;
    case OwnerSharingReadOnlyDenial::PermissionRevoked:
        status.denial = RuntimeSharingPermissionDenial::PermissionRevoked;
        break;
    case OwnerSharingReadOnlyDenial::EvidenceUnavailable:
        status.denial = RuntimeSharingPermissionDenial::Unavailable;
        break;
    }
    return status;
}

} // namespace

MacRuntimeHostControl::MacRuntimeHostControl() noexcept
    : ownerThread_(std::this_thread::get_id()),
      ownerEvidenceSource_(&defaultOwnerEvidence_),
      ownerSharingAuthority_(*ownerEvidenceSource_)
{
    (void)licensingContext_.configureGeneratedApplicationIdentity();
}

MacRuntimeHostControl::MacRuntimeHostControl(
    rdp_server::server::security::ConsoleOsEvidenceSource& ownerEvidence) noexcept
    : ownerThread_(std::this_thread::get_id()),
      ownerEvidenceSource_(&ownerEvidence),
      ownerSharingAuthority_(*ownerEvidenceSource_)
{
    (void)licensingContext_.configureGeneratedApplicationIdentity();
}

MacRuntimeHostControl::~MacRuntimeHostControl()
{
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
}

void MacRuntimeHostControl::setScreenCaptureProbeForTesting(
    ScreenCaptureProbe probe) noexcept
{
    screenCaptureProbe_ = probe;
}

void MacRuntimeHostControl::setInputPermissionProbeForTesting(
    InputPermissionProbe probe) noexcept
{
    inputPermissionProbe_ = probe;
}

bool MacRuntimeHostControl::onOwnerThread() const noexcept
{
    return ownerThread_ == std::this_thread::get_id();
}

RuntimeHostResult MacRuntimeHostControl::deny(RuntimeHostError error) noexcept
{
    lastError_ = error;
    return {error, false};
}

bool MacRuntimeHostControl::prepareTlsIdentityForSelection(
    std::string_view numericIpAddress) noexcept
{
    retireGeneratedTlsIdentity();
    RuntimeServerTlsContext generated =
        RuntimeServerTlsContext::fromGeneratedIpAddress(numericIpAddress);
    if (!generated)
        return false;

    generatedTlsContext_.emplace(std::move(generated));
    tlsContext_ = &*generatedTlsContext_;
    return true;
}

void MacRuntimeHostControl::retireGeneratedTlsIdentity() noexcept
{
    tlsContext_ = nullptr;
    generatedTlsContext_.reset();
}

bool MacRuntimeHostControl::selectedStandaloneCredentialReady() const noexcept
{
    if (standaloneCredentialGeneration_ == 0U)
        return false;

    const auto observation = standalonePasswordCredential_.observation();
    if (!observation.configured ||
        observation.generation != standaloneCredentialGeneration_)
    {
        return false;
    }

    bool visited = false;
    return standalonePasswordCredential_.visit(
               standaloneCredentialGeneration_,
               &validateStandaloneCredentialVisit, &visited) &&
           visited;
}

void MacRuntimeHostControl::retireStoppedRuntime(
    rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept
{
    ownerSharingAuthority_.revoke(reason);
    // Match Linux service-lifetime semantics: ordinary Stop retains the
    // memory-only credential, while terminal authority loss/destruction
    // securely retires the exact generation.
    if (reason !=
        rdp_server::server::security::OwnerConsentRevocationReason::Stop)
    {
        standalonePasswordCredential_.revoke();
        standaloneCredentialGeneration_ = 0U;
        credentialsConfigured_ = false;
    }
    if (activeConnection_ != nullptr)
    {
        activeConnection_->cancel();
        activeConnection_.reset();
        activeClientId_ = 0U;
        clientDisconnected_ = true;
    }
    (void)nativeDesktop_.retireAfterAuthorizationLoss();
    listener_.close();
    retireGeneratedTlsIdentity();
    deploymentPolicy_.reset();
}

std::vector<MacRuntimeDefaultRoutePreference>
readMacDefaultRoutePreferences()
{
    std::vector<MacRuntimeDefaultRoutePreference> routes;
    SCDynamicStoreRef store = SCDynamicStoreCreate(
        kCFAllocatorDefault, CFSTR("rdp_default_route_preference"), nullptr, nullptr);
    if (store == nullptr)
        return routes;

    const std::unique_ptr<const __SCDynamicStore, decltype(&CFRelease)>
        storeOwner(store, &CFRelease);

    const void* patternList[] = {
        CFSTR("State:/Network/Service/.*/IPv4"),
        CFSTR("State:/Network/Service/.*/IPv6")
    };
    CFArrayRef patterns = CFArrayCreate(
        kCFAllocatorDefault, patternList, 2, &kCFTypeArrayCallBacks);
    if (patterns == nullptr)
        return routes;
    const std::unique_ptr<const __CFArray, decltype(&CFRelease)>
        patternsOwner(patterns, &CFRelease);

    CFDictionaryRef matches = SCDynamicStoreCopyMultiple(store, nullptr, patterns);
    if (matches == nullptr)
        return routes;
    const std::unique_ptr<const __CFDictionary, decltype(&CFRelease)>
        matchesOwner(matches, &CFRelease);

    const CFIndex count = CFDictionaryGetCount(matches);
    if (count <= 0)
        return routes;

    std::vector<const void*> keys(static_cast<std::size_t>(count));
    std::vector<const void*> values(static_cast<std::size_t>(count));
    CFDictionaryGetKeysAndValues(matches, keys.data(), values.data());

    for (CFIndex i = 0; i < count; ++i)
    {
        auto dict = static_cast<CFDictionaryRef>(values[i]);
        if (dict == nullptr || CFGetTypeID(dict) != CFDictionaryGetTypeID())
            continue;

        auto ifNameRef = static_cast<CFStringRef>(
            CFDictionaryGetValue(dict, CFSTR("InterfaceName")));
        auto routerRef = static_cast<CFStringRef>(
            CFDictionaryGetValue(dict, CFSTR("Router")));
        if (ifNameRef == nullptr || routerRef == nullptr)
            continue;

        char ifNameBuf[IFNAMSIZ]{};
        if (!CFStringGetCString(ifNameRef, ifNameBuf, sizeof(ifNameBuf),
                                kCFStringEncodingUTF8))
            continue;

        const unsigned int index = ::if_nametoindex(ifNameBuf);
        if (index == 0U)
            continue;

        const std::string stableId =
            std::string(ifNameBuf) + "#" + std::to_string(index);

        auto keyRef = static_cast<CFStringRef>(keys[i]);
        char keyBuf[128]{};
        CFStringGetCString(keyRef, keyBuf, sizeof(keyBuf),
                           kCFStringEncodingUTF8);
        const bool isIpv6 = (std::strstr(keyBuf, "IPv6") != nullptr);
        const auto family = isIpv6 ? RuntimeHostAddressFamily::Ipv6
                                   : RuntimeHostAddressFamily::Ipv4;

        if (std::ranges::any_of(
                routes,
                [&](const MacRuntimeDefaultRoutePreference& route) {
                    return route.interfaceId == stableId &&
                           route.family == family;
                }))
            continue;

        routes.push_back({stableId, family, 10U});
    }
    return routes;
}

RuntimeHostRecommendedEndpoint
recommendMacPrivateLanEndpoint(
    const std::vector<RuntimeHostInterface>& interfaces,
    const std::span<const MacRuntimeDefaultRoutePreference> defaultRoutes,
    const std::uint16_t port)
{
    std::vector<RuntimeHostLanEndpointCandidate> candidates;
    for (const RuntimeHostInterface& runtimeInterface : interfaces)
    {
        for (const std::string& address : runtimeInterface.localAddresses)
        {
            const RuntimeHostOptions selection{
                runtimeInterface.stableId, address, port, true, false};
            if (!assessRuntimeSelectedLanEndpoint(
                    selection, interfaces).succeeded())
                continue;

            RuntimeHostLanEndpointCandidate candidate;
            candidate.interfaceId = runtimeInterface.stableId;
            candidate.address = address;
            candidate.family = address.find(':') == std::string::npos
                ? RuntimeHostAddressFamily::Ipv4
                : RuntimeHostAddressFamily::Ipv6;
            candidate.privateLanEligible = true;

            bool matchedDefaultRoute = false;
            for (const MacRuntimeDefaultRoutePreference& route : defaultRoutes)
            {
                if (route.interfaceId != candidate.interfaceId ||
                    route.family != candidate.family)
                    continue;
                candidate.preferredRoute = true;
                matchedDefaultRoute = true;
                if (!candidate.routeMetric.has_value() ||
                    route.metric < *candidate.routeMetric)
                    candidate.routeMetric = route.metric;
            }

            // In absence of an explicit default route from SCDynamicStore,
            // physical Ethernet/Wi-Fi interfaces (en*) outrank virtual bridges.
            if (!matchedDefaultRoute)
            {
                if (runtimeInterface.displayName.starts_with("en"))
                {
                    candidate.preferredRoute = true;
                    candidate.routeMetric = 50U;
                }
                else
                {
                    candidate.routeMetric = 100U;
                }
            }

            candidates.emplace_back(std::move(candidate));
        }
    }
    return recommendRuntimePrivateLanEndpoint(candidates, port);
}

std::vector<RuntimeHostInterface>
MacRuntimeHostControl::enumerateLocalInterfaces() const
{
    if (!onOwnerThread())
        return {};
    ifaddrs* addressList = nullptr;
    if (::getifaddrs(&addressList) != 0 || addressList == nullptr)
        return {};
    const std::unique_ptr<ifaddrs, decltype(&::freeifaddrs)>
        addressOwner(addressList, &::freeifaddrs);
    std::vector<RuntimeHostInterface> interfaces;
    for (const ifaddrs* current = addressOwner.get(); current != nullptr;
         current = current->ifa_next)
    {
        if (current->ifa_name == nullptr ||
            (current->ifa_flags & (IFF_UP | IFF_RUNNING)) !=
                (IFF_UP | IFF_RUNNING) ||
            (current->ifa_flags & IFF_LOOPBACK) != 0 ||
            (current->ifa_flags & IFF_POINTOPOINT) != 0 ||
            !isEligibleAddress(current->ifa_addr))
            continue;
        const unsigned index = ::if_nametoindex(current->ifa_name);
        if (index == 0U)
            continue;
        std::string address = numericAddress(current->ifa_addr);
        if (address.empty())
            continue;
        const std::string interfaceName(current->ifa_name);
        const std::string stableId =
            interfaceName + "#" + std::to_string(index);
        auto found = std::find_if(interfaces.begin(), interfaces.end(),
            [&stableId](const RuntimeHostInterface& candidate) {
                return candidate.stableId == stableId;
            });
        if (found == interfaces.end())
        {
            RuntimeHostInterface candidate;
            candidate.stableId = stableId;
            candidate.displayName = interfaceName;
            candidate.lanEligible = true;
            interfaces.emplace_back(std::move(candidate));
            found = std::prev(interfaces.end());
        }
        if (std::find(found->localAddresses.begin(),
                      found->localAddresses.end(), address) ==
            found->localAddresses.end())
            found->localAddresses.emplace_back(std::move(address));
    }
    return interfaces;
}

RuntimeHostStatus MacRuntimeHostControl::status() const
{
    RuntimeHostStatus snapshot;
    snapshot.product.lastErrorMessage =
        std::string(runtimeHostErrorMessage(snapshot.lastError));
    if (!onOwnerThread())
        return snapshot;
    snapshot.stage = stage_;
    snapshot.lastError = lastError_;
    const bool listenerCurrent =
        listener_.valid() && listener_.interfaceStillMatches();
    snapshot.listenerAvailable = listenerCurrent;
    snapshot.listenerGeneration =
        listenerCurrent ? listener_.generation() : 0U;
    if (selectionConfigured_)
        snapshot.selectedEndpoint =
            endpointText(selection_.localAddress, selection_.port);
    if (listenerCurrent)
        snapshot.boundEndpoint = boundEndpointText(listener_.boundEndpoint());

    const auto ownerGrant = ownerSharingAuthority_.grantObservation();
    using rdp_server::server::security::OwnerSharingGrantExpiryState;
    switch (ownerGrant.expiryState)
    {
    case OwnerSharingGrantExpiryState::Active:
        snapshot.ownerGrant.state = RuntimeOwnerGrantState::Active;
        snapshot.ownerGrant.effectivePermissionMask =
            ownerGrant.effectivePermissionMask;
        snapshot.ownerGrant.remainingMilliseconds =
            ownerGrant.remainingMilliseconds;
        break;
    case OwnerSharingGrantExpiryState::Expired:
        snapshot.ownerGrant.state = RuntimeOwnerGrantState::Expired;
        break;
    case OwnerSharingGrantExpiryState::Unavailable:
        break;
    }
    snapshot.hostOwnerAuthorized =
        ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission);
    const auto ownerPermission =
        ownerSharingAuthority_.permissionObservation();

    snapshot.product.nativeDesktopTargetAvailable = true;
    snapshot.product.nativeDesktopTarget = "macOS ScreenCaptureKit Desktop";

    snapshot.credentialsConfigured = credentialsConfigured_ && selectedStandaloneCredentialReady();

    if (tlsContext_ != nullptr)
    {
        if (listener_.valid())
        {
            snapshot.tlsIdentity = tlsContext_->boundIdentityStatus(listener_);
            snapshot.tlsIdentityReady =
                listenerCurrent &&
                snapshot.tlsIdentity.boundIdentityMatchesGeneration(
                    snapshot.listenerGeneration);
        }
        else
        {
            snapshot.tlsIdentity = tlsContext_->identityStatus();
            snapshot.tlsIdentityReady =
                snapshot.tlsIdentity.fingerprintAvailable &&
                snapshot.tlsIdentity.state ==
                    RuntimeTlsIdentityState::ConfiguredUnbound;
        }
    }

    snapshot.graphicsReady = nativeDesktop_.ready();
    snapshot.nativeDesktopReady = nativeDesktop_.ready();
    snapshot.nativeDesktopInitializing = !nativeDesktop_.ready() && activeConnection_ != nullptr;

    snapshot.clientDisconnected = listenerCurrent && activeConnection_ == nullptr && clientDisconnected_;
    if (activeConnection_ != nullptr && activeClientId_ != 0U)
    {
        RuntimeHostClient client;
        client.opaqueId = activeClientId_;
        client.peerAddress = activeClientPeer_;
        client.authenticating = (stage_ == RuntimeHostStage::ClientAuthenticating);
        client.shareActivated = (stage_ == RuntimeHostStage::ShareActivated ||
                                 stage_ == RuntimeHostStage::DesktopVisible ||
                                 stage_ == RuntimeHostStage::ClientConnected);
        client.desktopVisible = snapshot.nativeDesktopReady &&
            (stage_ == RuntimeHostStage::DesktopVisible || stage_ == RuntimeHostStage::ClientConnected);
        snapshot.activeClients.emplace_back(std::move(client));
    }

    snapshot.product.controlAvailable = true;
    snapshot.product.eligibleLanInterfaces = enumerateLocalInterfaces();
    const std::uint16_t recommendedPort =
        selectionConfigured_ ? selection_.port : 3389U;
    const std::vector<MacRuntimeDefaultRoutePreference> defaultRoutes =
        readMacDefaultRoutePreferences();
    snapshot.product.recommendedEndpoint =
        recommendMacPrivateLanEndpoint(
            snapshot.product.eligibleLanInterfaces, defaultRoutes,
            recommendedPort);
    snapshot.product.boundEndpoint = snapshot.boundEndpoint;
    snapshot.product.clientCount = snapshot.activeClients.size();
    snapshot.product.activeClientIds.reserve(snapshot.activeClients.size());
    for (const RuntimeHostClient& client : snapshot.activeClients)
    {
        if (client.opaqueId != 0U)
            snapshot.product.activeClientIds.emplace_back(client.opaqueId);
    }

    snapshot.product.credentialCapabilities.existingOsAccount = false;
    snapshot.product.credentialCapabilities.standalonePassword =
        kStandalonePasswordProductCapabilityApproved;
    snapshot.product.credentialCapabilities
        .standalonePasswordConfigurationAvailable = true;
    snapshot.product.automaticRuntimeProvisioned =
        licensingContext_.configured();

    snapshot.product.credentialsConfigured = snapshot.credentialsConfigured;
    snapshot.product.ownerAuthorized = snapshot.hostOwnerAuthorized;
    snapshot.product.sharingPermission =
        sharingPermissionStatus(ownerPermission);
    if (snapshot.stage == RuntimeHostStage::Revoked)
        snapshot.product.sharingPermission.canRequest = false;
    snapshot.product.tlsIdentityReady = snapshot.tlsIdentityReady;
    if (snapshot.tlsIdentity.fingerprintAvailable)
    {
        snapshot.product.tlsFingerprint =
            snapshot.tlsIdentity.certificateSha256;
        snapshot.product.tlsFingerprintAvailable = true;
    }
    snapshot.product.state = runtimeProductStateFor(
        snapshot.stage, snapshot.lastError, snapshot.nativeDesktopReady);
    snapshot.product.credentialEditingAllowed =
        snapshot.product.controlAvailable &&
        runtimeProductCredentialEditingAllowed(
            snapshot.stage, snapshot.product.state);

    using Readiness = RuntimeProductReadinessStage;
    if (snapshot.nativeDesktopReady &&
        (snapshot.stage == RuntimeHostStage::DesktopVisible ||
         snapshot.stage == RuntimeHostStage::ClientConnected))
        snapshot.product.readinessStage = Readiness::Connected;
    else if (snapshot.stage == RuntimeHostStage::ClientAuthenticating ||
             snapshot.stage == RuntimeHostStage::ShareActivated ||
             snapshot.stage == RuntimeHostStage::DesktopVisible ||
             snapshot.stage == RuntimeHostStage::ClientConnected)
        snapshot.product.readinessStage = Readiness::Authenticating;
    else if (listenerCurrent)
        snapshot.product.readinessStage = Readiness::Listening;
    else if (selectionConfigured_ && snapshot.product.credentialsConfigured &&
             snapshot.product.ownerAuthorized &&
             snapshot.product.tlsIdentityReady)
        snapshot.product.readinessStage = Readiness::Starting;
    else if (snapshot.product.ownerAuthorized)
        snapshot.product.readinessStage = Readiness::PermissionGranted;
    else if (snapshot.product.credentialsConfigured)
        snapshot.product.readinessStage = Readiness::CredentialsConfigured;
    else if (snapshot.product.automaticRuntimeProvisioned)
        snapshot.product.readinessStage = Readiness::Provisioned;
    else
        snapshot.product.readinessStage = Readiness::Stopped;

    if (!customErrorMessage_.empty())
        snapshot.product.lastErrorMessage = customErrorMessage_;
    else
        snapshot.product.lastErrorMessage =
            std::string(runtimeHostErrorMessage(snapshot.lastError));
    return snapshot;
}

RuntimeHostResult MacRuntimeHostControl::configure(
    const RuntimeHostOptions& options)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (listener_.valid())
        return deny(RuntimeHostError::InvalidConfiguration);

    const auto preflight = assessRuntimeSelectedLanEndpoint(
        options, enumerateLocalInterfaces());
    if (!preflight.succeeded())
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(preflight.error);
    }

    if (!prepareTlsIdentityForSelection(options.localAddress))
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    }

    selection_ = options;
    selectionConfigured_ = true;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::requestCredentialSetup(
    rdp_server::server::security::LanCredentialChoice choice)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    ownerSharingAuthority_.revoke(
        rdp_server::server::security::OwnerConsentRevocationReason::CredentialChange);
    standalonePasswordCredential_.revoke();
    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;

    const auto decision = rdp_server::server::security::assessLanCredentialChoice(choice);
    if (decision == rdp_server::server::security::LanCredentialDecision::UnsupportedIndependentPasswordCredSsp)
        return deny(RuntimeHostError::UnsupportedIndependentPasswordNla);
    if (decision == rdp_server::server::security::LanCredentialDecision::CredentialNotConfigured)
        return deny(RuntimeHostError::CredentialNotConfigured);

    return deny(RuntimeHostError::CredentialProviderUnavailable);
}

bool MacRuntimeHostControl::configureStandaloneApplicationPassword(
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    if (!onOwnerThread() ||
        stage_ == RuntimeHostStage::Revoked ||
        listener_.valid())
    {
        cleansePassword(password);
        return false;
    }

    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;

    const auto observation =
        rdp_server::server::security::replaceStandaloneApplicationCredential(
            standalonePasswordCredential_, ownerSharingAuthority_,
            username, password);
    if (!observation.configured || observation.generation == 0U)
    {
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

    standaloneCredentialGeneration_ = observation.generation;
    credentialsConfigured_ = true;
    if (!selectedStandaloneCredentialReady())
    {
        standaloneCredentialGeneration_ = 0U;
        credentialsConfigured_ = false;
        standalonePasswordCredential_.revoke();
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

    stage_ = RuntimeHostStage::CredentialsConfigured;
    lastError_ = RuntimeHostError::None;
    return true;
}

rdp_server::server::security::StandalonePasswordCredentialObservation
MacRuntimeHostControl::standaloneApplicationPasswordObservation() const noexcept
{
    return standalonePasswordCredential_.observation();
}

bool MacRuntimeHostControl::visitStandaloneApplicationPassword(
    std::uint64_t expectedGeneration,
    rdp_server::server::security::StandalonePasswordCredentialVisitor visitor,
    void* context) const noexcept
{
    return standalonePasswordCredential_.visit(
        expectedGeneration, visitor, context);
}

RuntimeHostResult MacRuntimeHostControl::requestHostPermissionSetup(
    const RuntimeHostPermissionRequest& request)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);

    const bool enforceTcc = (ownerEvidenceSource_ == &defaultOwnerEvidence_) ||
                            (screenCaptureProbe_ != nullptr) ||
                            (inputPermissionProbe_ != nullptr);
    if (enforceTcc)
    {
#if defined(__APPLE__)
        const auto captureStatus = screenCaptureProbe_ != nullptr
            ? screenCaptureProbe_()
            : ::rdp::macos::queryNativeScreenCapturePreflight();
        if (captureStatus == ::rdp::macos::ScreenCapturePreflightStatus::NotGranted)
        {
            if (!screenCapturePromptRequested_)
            {
                screenCapturePromptRequested_ = true;
                (void)::CGRequestScreenCaptureAccess();
            }
            customErrorMessage_ =
                "Screen Recording permission required. Enable Screen Recording in System Settings > Privacy & Security.";
            lastError_ = RuntimeHostError::NativeAuthorizationDenied;
            return {RuntimeHostError::NativeAuthorizationDenied, false};
        }

        if (request.allowInput)
        {
            const auto inputStatus = inputPermissionProbe_ != nullptr
                ? inputPermissionProbe_()
                : ::rdp::macos::queryNativeMacInputPermissionStatus();
            if (inputStatus != ::rdp::macos::MacInputPermissionStatus::Trusted)
            {
                if (!accessibilityPromptRequested_)
                {
                    accessibilityPromptRequested_ = true;
                    const void* keys[] = { kAXTrustedCheckOptionPrompt };
                    const void* values[] = { kCFBooleanTrue };
                    CFDictionaryRef options = CFDictionaryCreate(
                        kCFAllocatorDefault, keys, values, 1,
                        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                    if (options != nullptr)
                    {
                        (void)::AXIsProcessTrustedWithOptions(options);
                        ::CFRelease(options);
                    }
                }
                customErrorMessage_ =
                    "Accessibility permission required for remote control. Enable Accessibility in System Settings > Privacy & Security.";
                lastError_ = RuntimeHostError::NativeAuthorizationDenied;
                return {RuntimeHostError::NativeAuthorizationDenied, false};
            }
        }
#endif
    }
    customErrorMessage_.clear();

    std::uint32_t permissions =
        rdp_server::server::security::kConsoleViewPermission;
    if (request.allowInput)
        permissions |= rdp_server::server::security::kConsoleInputPermission;
    if (request.allowClipboard)
        permissions |= rdp_server::server::security::kConsoleClipboardPermission;
    const auto result = ownerSharingAuthority_.requestConsent(
        {permissions, request.requestedLifetimeMilliseconds});
    using rdp_server::server::security::OwnerConsentRequestResult;
    switch (result)
    {
    case OwnerConsentRequestResult::Granted:
        lastError_ = RuntimeHostError::None;
        return {RuntimeHostError::None, false};
    case OwnerConsentRequestResult::InvalidIntent:
        return deny(RuntimeHostError::InvalidConfiguration);
    case OwnerConsentRequestResult::GenerationExhausted:
        return deny(RuntimeHostError::InternalFailure);
    case OwnerConsentRequestResult::TrustedOwnerProofUnavailable:
    case OwnerConsentRequestResult::NativeSessionUnavailable:
    case OwnerConsentRequestResult::LockStateNotUnlocked:
        lastError_ = RuntimeHostError::HostConsentRequired;
        return {RuntimeHostError::HostConsentRequired, true};
    }
    return deny(RuntimeHostError::HostConsentRequired);
}

RuntimeHostResult MacRuntimeHostControl::startSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (!selectionConfigured_)
        return deny(RuntimeHostError::InvalidConfiguration);
    if (!licensingContext_.configured())
        return deny(RuntimeHostError::InternalFailure);
    if (!credentialsConfigured_ || !selectedStandaloneCredentialReady())
        return deny(RuntimeHostError::CredentialNotConfigured);

    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    const auto current = assessRuntimeSelectedLanEndpoint(
        selection_, enumerateLocalInterfaces());
    if (!current.succeeded())
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(current.error);
    }

    if (tlsContext_ == nullptr)
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    const RuntimeTlsIdentityStatus unboundIdentity =
        tlsContext_->identityStatus();
    if (!unboundIdentity.fingerprintAvailable ||
        unboundIdentity.state != RuntimeTlsIdentityState::ConfiguredUnbound)
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    std::string_view nativeName = selection_.interfaceId;
    const auto hashPos = nativeName.find('#');
    if (hashPos != std::string_view::npos)
        nativeName = nativeName.substr(0, hashPos);

    auto listenerResult =
        rdp_server::server::transport::openLanListener({
            nativeName, selection_.localAddress, selection_.port});
    if (listenerResult.error !=
        rdp_server::server::transport::LanListenerError::None)
        return deny(listenerRuntimeError(listenerResult.error));

    auto candidate = std::move(listenerResult.listener);
    const RuntimeTlsIdentityStatus boundIdentity =
        tlsContext_->boundIdentityStatus(candidate);
    if (!boundIdentity.boundIdentityMatchesGeneration(candidate.generation()))
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    if (deploymentPolicy_.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);
    deploymentPolicy_.emplace();
    if (!deploymentPolicy_->configurePersonalDesktopPrivateLan(selection_.port))
    {
        deploymentPolicy_.reset();
        return deny(RuntimeHostError::InvalidConfiguration);
    }

    listener_ = std::move(candidate);
    stage_ = RuntimeHostStage::ListenerAvailable;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::serviceOnce() noexcept
{
    if (!onOwnerThread())
        return deny(RuntimeHostError::ControlUnavailable);
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (!listener_.valid())
        return {RuntimeHostError::None, true};

    if (stage_ == RuntimeHostStage::ListenerAvailable ||
        stage_ == RuntimeHostStage::ClientAuthenticating ||
        stage_ == RuntimeHostStage::ClientConnected)
    {
        const bool enforceTcc = (ownerEvidenceSource_ == &defaultOwnerEvidence_) ||
                                (screenCaptureProbe_ != nullptr);
        if (enforceTcc)
        {
#if defined(__APPLE__)
            const auto currentCapture = screenCaptureProbe_ != nullptr
                ? screenCaptureProbe_()
                : ::rdp::macos::queryNativeScreenCapturePreflight();
            if (currentCapture == ::rdp::macos::ScreenCapturePreflightStatus::NotGranted)
            {
                retireStoppedRuntime(
                    rdp_server::server::security::OwnerConsentRevocationReason::
                        NativeAuthorizationLost);
                stage_ = RuntimeHostStage::Revoked;
                customErrorMessage_ =
                    "Screen Recording permission was revoked in System Settings.";
                lastError_ = RuntimeHostError::AccessRevoked;
                return {lastError_, false};
            }
#endif
        }

        if (!ownerSharingAuthority_.authorizes(
                rdp_server::server::security::kConsoleViewPermission))
        {
            retireStoppedRuntime(
                rdp_server::server::security::OwnerConsentRevocationReason::AuthorityExpired);
            stage_ = RuntimeHostStage::Revoked;
            lastError_ = RuntimeHostError::HostConsentRequired;
            return {lastError_, false};
        }
    }

    const auto now = std::chrono::steady_clock::now();

    if (activeConnection_ == nullptr)
    {
        auto accepted = rdp_server::server::transport::acceptNonblockingTcpConnection(
            listener_.nativeSocket());
        if (accepted.outcome == rdp_server::server::transport::TcpAcceptOutcome::WouldBlock)
        {
            return {RuntimeHostError::None, true};
        }
        if (accepted.outcome != rdp_server::server::transport::TcpAcceptOutcome::Accepted ||
            !accepted.connection.valid())
        {
            return {RuntimeHostError::None, true};
        }

        const auto peer = accepted.connection.peerEndpoint();
        std::span<const std::uint8_t> peerAddr;
        if (peer.family == rdp_server::server::transport::TcpPeerAddressFamily::Ipv4)
            peerAddr = std::span<const std::uint8_t>{peer.address}.first(4U);
        else if (peer.family == rdp_server::server::transport::TcpPeerAddressFamily::Ipv6)
            peerAddr = std::span<const std::uint8_t>{peer.address};
        else
            return {RuntimeHostError::None, true};

        if (deploymentPolicy_.has_value() &&
            !deploymentPolicy_->permitsPrivateLanTransportCandidate(peerAddr))
        {
            return {RuntimeHostError::None, true};
        }

        if (!authAttempts_.reservePeerAuthenticationAttempt(peerAddr, now))
        {
            lastError_ = RuntimeHostError::AuthenticationRateLimited;
            return {lastError_, true};
        }

        activeClientId_ = nextClientId_++;
        activeClientDeadline_ = now + std::chrono::seconds{30};
        char peerStr[64]{};
        std::snprintf(peerStr, sizeof(peerStr), "%u.%u.%u.%u:%u",
            peer.address[0], peer.address[1], peer.address[2], peer.address[3], peer.port);
        activeClientPeer_ = peerStr;

        activeConnection_ = std::make_unique<rdp_server::server::transport::OwnedPreauthTcpConnection>(
            std::move(accepted.connection),
            rdp_server::server::transport::SecurityNegotiationPolicy::HybridNla);
        stage_ = RuntimeHostStage::ClientAuthenticating;
    }

    if (activeConnection_ != nullptr)
    {
        if (activeConnection_->cancelIfExpired(now, activeClientDeadline_))
        {
            activeConnection_->cancel();
            activeConnection_.reset();
            activeClientId_ = 0U;
            clientDisconnected_ = true;
            (void)nativeDesktop_.retireAfterAuthorizationLoss();
            stage_ = RuntimeHostStage::ListenerAvailable;
            return {RuntimeHostError::None, false};
        }

        if (nativeDesktop_.ready())
        {
            const auto nativeRes = nativeDesktop_.serviceOnce();
            if (!nativeRes.succeeded())
            {
                (void)nativeDesktop_.retireAfterAuthorizationLoss();
            }
        }
    }

    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::stopSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::Stop);
    stage_ = RuntimeHostStage::Stopped;
    lastError_ = RuntimeHostError::None;
    customErrorMessage_.clear();
    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::disconnectClient(
    std::uint64_t opaqueClientId)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (activeConnection_ != nullptr && activeClientId_ == opaqueClientId)
    {
        activeConnection_->cancel();
        activeConnection_.reset();
        activeClientId_ = 0U;
        clientDisconnected_ = true;
        (void)nativeDesktop_.retireAfterAuthorizationLoss();
        stage_ = RuntimeHostStage::ListenerAvailable;
        return {RuntimeHostError::None, false};
    }
    return deny(RuntimeHostError::ClientNotFound);
}

RuntimeHostResult MacRuntimeHostControl::revokeSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
    stage_ = RuntimeHostStage::Revoked;
    lastError_ = RuntimeHostError::AccessRevoked;
    customErrorMessage_.clear();
    return {RuntimeHostError::None, false};
}

} // namespace rdp_server::server::runtime
