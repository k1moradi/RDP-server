// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_host_control.h"
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
#include "linux_runtime_connection.h"
#include "linux_runtime_security.h"
#include "runtime_licensing_context.h"
#include "runtime_tls_context.h"
#endif
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace rdp_server::server::runtime
{
namespace
{
// Mirror R1's private-LAN selection filter; R1 remains the bind authority.
[[nodiscard]] bool isEligibleAddress(const sockaddr* address) noexcept
{
    if (address == nullptr)
        return false;
    if (address->sa_family == AF_INET)
    {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, address, sizeof(ipv4));
        const std::uint32_t numeric = ntohl(ipv4.sin_addr.s_addr);
        return (numeric & 0xff000000U) == 0x0a000000U ||
               (numeric & 0xfff00000U) == 0xac100000U ||
               (numeric & 0xffff0000U) == 0xc0a80000U;
    }
    if (address->sa_family == AF_INET6)
    {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, address, sizeof(ipv6));
        const auto* bytes = ipv6.sin6_addr.s6_addr;
        return (bytes[0] & 0xfeU) == 0xfcU ||
               (bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U);
    }
    return false;
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
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
[[nodiscard]] RuntimeHostError listenerRuntimeError(
    rdp_server::server::transport::LanListenerError error) noexcept
{
    using rdp_server::server::transport::LanListenerError;
    switch (error)
    {
    case LanListenerError::None:
        return RuntimeHostError::None;
    case LanListenerError::InvalidSelection:
        return RuntimeHostError::InvalidConfiguration;
    case LanListenerError::InterfaceUnavailable:
        return RuntimeHostError::InterfaceUnavailable;
    case LanListenerError::PermissionDenied:
    case LanListenerError::PortOccupied:
        return RuntimeHostError::PortUnavailable;
    case LanListenerError::CertificateMismatch:
        return RuntimeHostError::TlsIdentityUnavailable;
    case LanListenerError::ListenerNotReady:
    case LanListenerError::TerminalDisconnect:
        return RuntimeHostError::InternalFailure;
    }
    return RuntimeHostError::InternalFailure;
}
#endif
} // namespace

std::optional<LinuxNativeLanInterfaceIdentity>
resolveCurrentLinuxNativeLanInterface(std::string_view stableId) noexcept
{
    // R10's GUI stable ID is not R1's native interface name. Validate its
    // exact present kernel index before taking the name; R1 will recheck at
    // the eventual authorized bind. No allocation or network side effects.
    const auto separator = stableId.rfind('#');
    if (separator == std::string_view::npos || separator == 0U ||
        separator >= IFNAMSIZ || separator + 1U == stableId.size() ||
        stableId.substr(0, separator).find('#') != std::string_view::npos ||
        stableId.find('\0') != std::string_view::npos ||
        stableId.find('/') != std::string_view::npos)
        return std::nullopt;

    const std::string_view digits = stableId.substr(separator + 1U);
    if (digits.front() == '0')
        return std::nullopt;
    unsigned int index{};
    const auto [end, error] = std::from_chars(
        digits.data(), digits.data() + digits.size(), index);
    if (error != std::errc{} || end != digits.data() + digits.size() ||
        index == 0U)
        return std::nullopt;

    std::array<char, IFNAMSIZ> nativeName{};
    std::memcpy(nativeName.data(), stableId.data(), separator);
    if (::if_nametoindex(nativeName.data()) != index)
        return std::nullopt;
    return LinuxNativeLanInterfaceIdentity{
        stableId.substr(0, separator), index};
}

LinuxRuntimeHostControl::LinuxRuntimeHostControl() noexcept
    : ownerThread_(std::this_thread::get_id()) {}
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
LinuxRuntimeHostControl::LinuxRuntimeHostControl(
    LinuxRuntimeSecurityConfiguration& securityConfiguration,
    const RuntimeServerTlsContext& tlsContext,
    const LinuxRuntimeAdmissionConfiguration& admissionConfiguration,
    const RuntimeLicensingContext& licensingContext) noexcept
    : ownerThread_(std::this_thread::get_id()),
      securityConfiguration_(&securityConfiguration),
      tlsContext_(&tlsContext),
      admissionConfiguration_(&admissionConfiguration),
      licensingContext_(&licensingContext)
{
}
#endif
LinuxRuntimeHostControl::~LinuxRuntimeHostControl()
{
    // The owning event-loop thread destroys this after GUI shutdown. R2 is
    // invalidated before any later-stage R1 listener retirement.
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::Stop);
}

bool LinuxRuntimeHostControl::onOwnerThread() const noexcept
{
    return ownerThread_ == std::this_thread::get_id();
}
RuntimeHostResult LinuxRuntimeHostControl::deny(RuntimeHostError error) noexcept
{
    lastError_ = error;
    return {error, false};
}
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
bool LinuxRuntimeHostControl::serviceCredentialsReady() const noexcept
{
    if (securityConfiguration_ == nullptr ||
        !securityConfiguration_->configured() ||
        admissionConfiguration_ == nullptr ||
        licensingContext_ == nullptr ||
        !licensingContext_->configured())
        return false;
    const auto* policy = securityConfiguration_->policy();
    return policy != nullptr && policy->size() != 0U &&
           policy->generation() != 0U &&
           admissionConfiguration_->request(
               *securityConfiguration_).has_value();
}
#endif

std::vector<RuntimeHostInterface>
LinuxRuntimeHostControl::enumerateLocalInterfaces() const
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

RuntimeHostStatus LinuxRuntimeHostControl::status() const
{
    RuntimeHostStatus snapshot;
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
    // Status observes the same R2 owner used by admission. A GUI Boolean can
    // never replace this production authority.
    snapshot.hostOwnerAuthorized =
        ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission);
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    snapshot.credentialsConfigured =
        credentialsConfigured_ && serviceCredentialsReady();
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
#endif
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (acceptedClient_ != nullptr && acceptedClientId_ != 0U)
    {
        RuntimeHostClient client;
        client.opaqueId = acceptedClientId_;
        client.peerAddress = acceptedClientPeer_;
        client.authenticating =
            stage_ == RuntimeHostStage::ClientAuthenticating;
        client.shareActivated =
            stage_ == RuntimeHostStage::ShareActivated ||
            stage_ == RuntimeHostStage::DesktopVisible ||
            stage_ == RuntimeHostStage::ClientConnected;
        client.desktopVisible =
            stage_ == RuntimeHostStage::DesktopVisible ||
            stage_ == RuntimeHostStage::ClientConnected;
        snapshot.activeClients.emplace_back(std::move(client));
    }
#endif
    // nativeDesktopReady remains false until the accepted client reaches the
    // R2-selected native owner, which is intentionally the next composition.
    return snapshot;
}

RuntimeHostResult LinuxRuntimeHostControl::configure(
    const RuntimeHostOptions& options)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (listener_.valid())
        return deny(RuntimeHostError::InvalidConfiguration);

    // A rejected new selection must not retain a previously approved
    // interface/address preference for a later independent Start request.
    // Never invalidate an already-owned live listener during reconfiguration.
    selection_ = {};
    selectionConfigured_ = false;
    if (options.afterLoginLaunchRequested)
        return deny(RuntimeHostError::ListenerPolicyDenied);
    const auto preflight = assessRuntimeSelectedLanEndpoint(
        options, enumerateLocalInterfaces());
    if (!preflight.succeeded())
        return deny(preflight.error);
    if (!resolveCurrentLinuxNativeLanInterface(options.interfaceId))
        return deny(RuntimeHostError::InterfaceUnavailable);
    selection_ = options;
    selectionConfigured_ = true;
    lastError_ = RuntimeHostError::HostConsentRequired;
    return {RuntimeHostError::None, false};
}

bool LinuxRuntimeHostControl::configureStandaloneApplicationPassword(
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    using namespace rdp_server::server::security;
    if (!onOwnerThread() ||
        stage_ == RuntimeHostStage::Revoked ||
        listener_.valid())
    {
        cleanseStandalonePasswordInput(password);
        return false;
    }

    // Credential replacement invalidates prior owner approval even though this
    // prototype is still hidden from the product credential selector.
    ownerSharingAuthority_.revoke(
        OwnerConsentRevocationReason::CredentialChange);
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    credentialsConfigured_ = false;
#endif

    const bool configured =
        standalonePasswordCredential_.configure(username, password);
    if (!configured)
    {
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

    // Do not project product readiness. Only the future same-owner accepted
    // socket service may consume this generation after standalone CredSSP and
    // fresh current-owner authorization both succeed.
    stage_ = RuntimeHostStage::Stopped;
    lastError_ = RuntimeHostError::None;
    return true;
}

rdp_server::server::security::StandalonePasswordCredentialObservation
LinuxRuntimeHostControl::standaloneApplicationPasswordObservation()
    const noexcept
{
    if (!onOwnerThread())
        return {};
    return standalonePasswordCredential_.observation();
}

bool LinuxRuntimeHostControl::visitStandaloneApplicationPassword(
    std::uint64_t expectedGeneration,
    rdp_server::server::security::StandalonePasswordCredentialVisitor visitor,
    void* context) const noexcept
{
    return onOwnerThread() &&
           standalonePasswordCredential_.visit(
               expectedGeneration, visitor, context);
}

RuntimeHostResult LinuxRuntimeHostControl::requestCredentialSetup(
    rdp_server::server::security::LanCredentialChoice choice)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    using namespace rdp_server::server::security;
    // Any credential-mode/configuration action invalidates prior consent and
    // retires the alternate standalone credential mode before evaluating the
    // requested product credential choice.
    ownerSharingAuthority_.revoke(
        OwnerConsentRevocationReason::CredentialChange);
    standalonePasswordCredential_.revoke();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    credentialsConfigured_ = false;
#endif
    const auto decision = assessLanCredentialChoice(choice);
    if (decision == LanCredentialDecision::UnsupportedIndependentPasswordCredSsp)
        return deny(RuntimeHostError::UnsupportedIndependentPasswordNla);
    if (decision == LanCredentialDecision::CredentialNotConfigured)
        return deny(RuntimeHostError::CredentialNotConfigured);
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (securityConfiguration_ == nullptr ||
        !securityConfiguration_->configured())
        return deny(RuntimeHostError::CredentialProviderUnavailable);
    if (!serviceCredentialsReady())
        return deny(RuntimeHostError::CredentialNotConfigured);
    credentialsConfigured_ = true;
    stage_ = RuntimeHostStage::CredentialsConfigured;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
#else
    return deny(RuntimeHostError::CredentialProviderUnavailable);
#endif
}

RuntimeHostResult LinuxRuntimeHostControl::requestHostPermissionSetup(
    const RuntimeHostPermissionRequest& request)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);

    // This call is reachable from the locally running GUI, never from an
    // accepted peer. M1 trusts that explicit click, then R2 binds it to fresh
    // process-UID/physical-seat0/session/unlocked native evidence.
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

RuntimeHostResult LinuxRuntimeHostControl::startSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (!selectionConfigured_)
        return deny(RuntimeHostError::InvalidConfiguration);
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    return deny(RuntimeHostError::CredentialProviderUnavailable);
#else
    if (securityConfiguration_ == nullptr ||
        !securityConfiguration_->configured())
        return deny(RuntimeHostError::CredentialProviderUnavailable);
    if (!credentialsConfigured_ || !serviceCredentialsReady())
        return deny(RuntimeHostError::CredentialNotConfigured);

    // R2 owner consent precedes the fresh native interface/address check.
    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    const auto current = assessRuntimeSelectedLanEndpoint(
        selection_, enumerateLocalInterfaces());
    const auto nativeIdentity =
        resolveCurrentLinuxNativeLanInterface(selection_.interfaceId);
    if (!current.succeeded() || !nativeIdentity)
    {
        selection_ = {};
        selectionConfigured_ = false;
        return deny(current.succeeded()
            ? RuntimeHostError::InterfaceUnavailable : current.error);
    }

    if (tlsContext_ == nullptr)
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    const RuntimeTlsIdentityStatus unboundIdentity =
        tlsContext_->identityStatus();
    if (!unboundIdentity.fingerprintAvailable ||
        unboundIdentity.state != RuntimeTlsIdentityState::ConfiguredUnbound)
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    auto listenerResult =
        rdp_server::server::transport::openLanListener({
            nativeIdentity->nativeName, selection_.localAddress,
            selection_.port});
    if (listenerResult.error !=
        rdp_server::server::transport::LanListenerError::None)
        return deny(listenerRuntimeError(listenerResult.error));

    auto candidate = std::move(listenerResult.listener);
    const RuntimeTlsIdentityStatus boundIdentity =
        tlsContext_->boundIdentityStatus(candidate);
    if (!boundIdentity.boundIdentityMatchesGeneration(
            candidate.generation()))
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    if (deploymentPolicy_.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);
    deploymentPolicy_.emplace();
    if (!deploymentPolicy_->configurePersonalDesktopPrivateLan(
            selection_.port))
    {
        deploymentPolicy_.reset();
        return deny(RuntimeHostError::InvalidConfiguration);
    }

    listener_ = std::move(candidate);
    stage_ = RuntimeHostStage::ListenerAvailable;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
#endif
}


#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
void LinuxRuntimeHostControl::clearAcceptedClient() noexcept
{
    acceptedClient_.reset();
    acceptedClientDeadline_ = {};
    acceptedClientPhase_ = AcceptedClientPhase::None;
    acceptedClientId_ = 0U;
    acceptedClientPeer_.clear();
    acceptedClientReadable_ = false;
    acceptedClientWritable_ = false;
}

void LinuxRuntimeHostControl::retireAcceptedClient(
    RuntimeHostError error) noexcept
{
    if (acceptedClient_ != nullptr)
        acceptedClient_->revoke();
    clearAcceptedClient();
    stage_ = listener_.valid()
        ? RuntimeHostStage::ListenerAvailable
        : RuntimeHostStage::Stopped;
    lastError_ = error;
}

RuntimeHostResult LinuxRuntimeHostControl::pollAcceptedClientReadiness() noexcept
{
    if (acceptedClient_ == nullptr)
        return deny(RuntimeHostError::ClientNotFound);

    const auto ready = acceptedClient_->pollSocketReadinessOnce(
        acceptedClientDeadline_, std::chrono::milliseconds{0});
    using PollStatus = LinuxRuntimeSocketPollStatus;
    switch (ready.status)
    {
    case PollStatus::Ready:
        acceptedClientReadable_ = ready.readable;
        acceptedClientWritable_ = ready.writable;
        return {RuntimeHostError::None, false};
    case PollStatus::NoEvent:
        return {RuntimeHostError::None, true};
    case PollStatus::Expired:
    case PollStatus::Closed:
    case PollStatus::Failure:
        retireAcceptedClient(RuntimeHostError::AuthenticationRejected);
        return {RuntimeHostError::AuthenticationRejected, false};
    }
    retireAcceptedClient(RuntimeHostError::InternalFailure);
    return {RuntimeHostError::InternalFailure, false};
}

RuntimeHostResult LinuxRuntimeHostControl::acceptClientOnce(
    std::chrono::steady_clock::time_point now) noexcept
{
    using namespace rdp_server::server::transport;
    if (acceptedClient_ != nullptr || !listener_.valid() ||
        securityConfiguration_ == nullptr || tlsContext_ == nullptr ||
        admissionConfiguration_ == nullptr || licensingContext_ == nullptr ||
        !deploymentPolicy_.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);

    auto accepted =
        acceptNonblockingTcpConnection(listener_.nativeSocket());
    if (accepted.outcome == TcpAcceptOutcome::WouldBlock)
        return {RuntimeHostError::None, true};
    if (accepted.outcome != TcpAcceptOutcome::Accepted ||
        !accepted.connection.valid())
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::InternalFailure;
        return {lastError_, false};
    }

    const TcpPeerEndpoint peer = accepted.connection.peerEndpoint();
    std::span<const std::uint8_t> peerAddress;
    if (peer.family == TcpPeerAddressFamily::Ipv4)
        peerAddress = std::span<const std::uint8_t>{peer.address}.first(4U);
    else if (peer.family == TcpPeerAddressFamily::Ipv6)
        peerAddress = std::span<const std::uint8_t>{peer.address};
    else
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::ListenerPolicyDenied;
        return {lastError_, false};
    }

    if (!deploymentPolicy_->permitsPrivateLanTransportCandidate(peerAddress))
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::ListenerPolicyDenied;
        return {lastError_, false};
    }

    if (!authAttempts_.reservePeerAuthenticationAttempt(peerAddress, now))
    {
        lastError_ = RuntimeHostError::AuthenticationRateLimited;
        return {lastError_, true};
    }

    if (nextClientId_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::InternalFailure;
        return {lastError_, false};
    }

    auto connection = std::make_unique<LinuxRuntimeConnection>(
        *securityConfiguration_, std::move(accepted.connection),
        &authAttempts_, &ownerSharingAuthority_);
    if (!connection->ready())
    {
        lastError_ = RuntimeHostError::AuthenticationRejected;
        return {lastError_, false};
    }

    acceptedClient_ = std::move(connection);
    acceptedClientDeadline_ = now + std::chrono::seconds{30};
    acceptedClientPhase_ = AcceptedClientPhase::PreAdmission;
    acceptedClientId_ = nextClientId_++;
    acceptedClientPeer_ = boundEndpointText(peer);
    acceptedClientReadable_ = false;
    acceptedClientWritable_ = false;
    stage_ = RuntimeHostStage::ClientAuthenticating;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult LinuxRuntimeHostControl::advanceAcceptedClientOnce() noexcept
{
    if (acceptedClient_ == nullptr || !acceptedClient_->ready() ||
        !deploymentPolicy_.has_value() || securityConfiguration_ == nullptr ||
        tlsContext_ == nullptr || admissionConfiguration_ == nullptr ||
        licensingContext_ == nullptr)
    {
        retireAcceptedClient(RuntimeHostError::AuthenticationRejected);
        return {RuntimeHostError::AuthenticationRejected, false};
    }

    const bool readable = std::exchange(acceptedClientReadable_, false);
    const bool writable = std::exchange(acceptedClientWritable_, false);

    const auto hostSessionStale = [this]() noexcept {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::HostSessionStale;
        return RuntimeHostResult{lastError_, false};
    };
    const auto peerFailure = [this](RuntimeHostError error) noexcept {
        retireAcceptedClient(error);
        return RuntimeHostResult{error, false};
    };

    switch (acceptedClientPhase_)
    {
    case AcceptedClientPhase::None:
        return peerFailure(RuntimeHostError::ClientNotFound);

    case AcceptedClientPhase::PreAdmission:
    {
        const auto step = acceptedClient_->advancePreAdmission(
            readable, writable, *tlsContext_);
        using Step = LinuxPreAdmissionStepStatus;
        switch (step.status)
        {
        case Step::Progress:
        case Step::TlsEstablished:
        case Step::BindingVerified:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::CredentialsVerified:
        {
            const auto request =
                admissionConfiguration_->request(*securityConfiguration_);
            if (!request)
                return hostSessionStale();
            if (!acceptedClient_->issueAdmission(*request))
            {
                if (!ownerSharingAuthority_.authorizes(
                        rdp_server::server::security::
                            kConsoleViewPermission))
                    return hostSessionStale();
                return peerFailure(RuntimeHostError::AuthenticationRejected);
            }
            acceptedClientPhase_ = AcceptedClientPhase::McsConnectInitial;
            return {RuntimeHostError::None, false};
        }
        case Step::UnsupportedFinalCredentials:
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsConnectInitial:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsConnectInitial(
                readable, writable);
        using Step = LinuxPostAdmissionMcsStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::AdmittedConnectInitial:
            acceptedClientPhase_ = AcceptedClientPhase::McsConnectResponse;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsConnectResponse:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsConnectResponseWrite(
                readable, writable);
        using Step = LinuxPostAdmissionMcsResponseStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
            acceptedClientPhase_ = AcceptedClientPhase::McsErectDomain;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsErectDomain:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsErectDomain(
                readable, writable);
        using Step = LinuxPostAdmissionMcsErectStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::ErectDomainAccepted:
            acceptedClientPhase_ = AcceptedClientPhase::McsAttachUser;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsAttachUser:
    {
        const auto step = acceptedClient_->advancePostAdmissionMcsAttachUser(
            *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsAttachStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::AttachUserAccepted:
            acceptedClientPhase_ = AcceptedClientPhase::McsAttachConfirm;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsAttachConfirm:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsAttachConfirmWrite(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsAttachConfirmStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
            acceptedClientPhase_ = AcceptedClientPhase::McsChannelJoins;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsChannelJoins:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsChannelJoins(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsChannelJoinStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::AllChannelsJoined:
            acceptedClientPhase_ = AcceptedClientPhase::ClientInfo;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::ClientInfo:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsClientInfo(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsClientInfoStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::ClientInfoAccepted:
            if (!acceptedClient_->selectPersonalDesktopLicensingMode(
                    *deploymentPolicy_))
                return peerFailure(
                    RuntimeHostError::ShareActivationUnavailable);
            acceptedClientPhase_ = AcceptedClientPhase::LicenseRequest;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::LicenseRequest:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopServerLicenseRequestWrite(
                *deploymentPolicy_, *licensingContext_,
                readable, writable);
        using Step = LinuxPersonalDesktopLicenseWriteStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
            acceptedClientPhase_ = AcceptedClientPhase::ClientLicensing;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::ClientLicensing:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopClientLicensingIntake(
                *deploymentPolicy_, *licensingContext_,
                readable, writable);
        using Step = LinuxPersonalDesktopClientLicensingStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::ClientLicenseInfoAccepted:
        case Step::ClientNewLicenseRequestAccepted:
            acceptedClientPhase_ = AcceptedClientPhase::ValidClient;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::ValidClient:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopValidClientWrite(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPersonalDesktopValidClientWriteStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
        {
            const auto request =
                admissionConfiguration_->request(*securityConfiguration_);
            if (!request)
                return hostSessionStale();

            using Feature =
                rdp_server::server::transport::RdpDemandActiveFeature;
            auto features = Feature::DynamicVirtualChannels;
            if ((request->requestedPermissions &
                 rdp_server::server::security::
                    kConsoleInputPermission) != 0U)
                features = features | Feature::SlowPathInput;

            const auto profile =
                acceptedClient_->preparePersonalDesktopDemandActiveProfile(
                    *deploymentPolicy_, features);
            if (!profile ||
                !acceptedClient_->startPersonalDesktopShareActivation(
                    *deploymentPolicy_, *profile))
                return peerFailure(
                    RuntimeHostError::ShareActivationUnavailable);

            acceptedClientPhase_ = AcceptedClientPhase::ShareActivation;
            return {RuntimeHostError::None, false};
        }
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::ShareActivation:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopShareActivation(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPersonalDesktopShareActivationStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Activated:
            stage_ = RuntimeHostStage::ShareActivated;
            if (!acceptedClient_->
                    startPersonalDesktopGraphicsDynamicVirtualChannel(
                        *deploymentPolicy_))
                return peerFailure(RuntimeHostError::GraphicsUnavailable);
            acceptedClientPhase_ = AcceptedClientPhase::GraphicsControl;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::GraphicsControl:
    {
        const auto step =
            acceptedClient_->
                advancePersonalDesktopGraphicsDynamicVirtualChannel(
                    *deploymentPolicy_, readable, writable);
        using Step = LinuxPersonalDesktopGraphicsDvcStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Ready:
            if (!acceptedClient_->authorizePersonalDesktopApplicationTraffic(
                    *deploymentPolicy_))
                return hostSessionStale();
            acceptedClientPhase_ = AcceptedClientPhase::GraphicsReady;
            stage_ = RuntimeHostStage::ShareActivated;
            lastError_ = RuntimeHostError::None;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::GraphicsUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::GraphicsReady:
        if (!acceptedClient_->authorizePersonalDesktopApplicationTraffic(
                *deploymentPolicy_))
            return hostSessionStale();
        return {RuntimeHostError::None, true};
    }

    return peerFailure(RuntimeHostError::InternalFailure);
}
#endif

RuntimeHostResult LinuxRuntimeHostControl::serviceOnce() noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return {RuntimeHostError::AccessRevoked, false};
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    return {RuntimeHostError::CredentialProviderUnavailable, false};
#else
    if (!listener_.valid())
        return {RuntimeHostError::None, true};
    if (!listener_.interfaceStillMatches())
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::InterfaceUnavailable;
        return {lastError_, false};
    }
    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::HostSessionStale;
        return {lastError_, false};
    }

    if (acceptedClient_ == nullptr)
        return acceptClientOnce(std::chrono::steady_clock::now());
    return advanceAcceptedClientOnce();
#endif
}

void LinuxRuntimeHostControl::retireStoppedRuntime(
    rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept
{
    // Security-significant host teardown order: invalidate host-owner R2
    // first, then retire the accepted R3/R2/R1 aggregate, then close R1's
    // listener. No accepted TLS/socket or later native owner may outlive Stop.
    ownerSharingAuthority_.revoke(reason);
    standalonePasswordCredential_.revoke();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (acceptedClient_ != nullptr)
        acceptedClient_->revoke();
    clearAcceptedClient();
#endif
    listener_.close();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    deploymentPolicy_.reset();
#endif
}
RuntimeHostResult LinuxRuntimeHostControl::stopSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::Stop);
    if (stage_ != RuntimeHostStage::Revoked)
    {
        stage_ = RuntimeHostStage::Stopped;
        lastError_ = RuntimeHostError::None;
    }
    return {RuntimeHostError::None, false};
}
RuntimeHostResult LinuxRuntimeHostControl::disconnectClient(
    std::uint64_t opaqueClientId)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (opaqueClientId == 0U || acceptedClient_ == nullptr ||
        acceptedClientId_ != opaqueClientId)
        return deny(RuntimeHostError::ClientNotFound);

    retireAcceptedClient(RuntimeHostError::None);
    return {RuntimeHostError::None, false};
#else
    (void)opaqueClientId;
    return deny(RuntimeHostError::ClientNotFound);
#endif
}
RuntimeHostResult LinuxRuntimeHostControl::revokeSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
    selection_ = {};
    selectionConfigured_ = false;
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    credentialsConfigured_ = false;
#endif
    stage_ = RuntimeHostStage::Revoked;
    lastError_ = RuntimeHostError::AccessRevoked;
    return {RuntimeHostError::None, false};
}

} // namespace rdp_server::server::runtime
