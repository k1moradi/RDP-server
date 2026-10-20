// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_host_control.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iterator>
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
    // Status observes the same R2 owner used by admission. This remains false
    // today; a future positive provider cannot be replaced by a GUI Boolean.
    snapshot.hostOwnerAuthorized =
        ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission);
    // Credentials, TLS identity and native desktop remain unproven.
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

RuntimeHostResult LinuxRuntimeHostControl::requestCredentialSetup(
    rdp_server::server::security::LanCredentialChoice choice)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    using namespace rdp_server::server::security;
    // Any credential-mode/configuration action invalidates prior consent.
    ownerSharingAuthority_.revoke(
        OwnerConsentRevocationReason::CredentialChange);
    const auto decision = assessLanCredentialChoice(choice);
    if (decision == LanCredentialDecision::UnsupportedIndependentPasswordCredSsp)
        return deny(RuntimeHostError::UnsupportedIndependentPasswordNla);
    if (decision == LanCredentialDecision::CredentialNotConfigured)
        return deny(RuntimeHostError::CredentialNotConfigured);
    return deny(RuntimeHostError::CredentialProviderUnavailable);
}

RuntimeHostResult LinuxRuntimeHostControl::requestHostPermissionSetup()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);

    // This call is reachable from the locally running GUI, never from an
    // accepted peer. M1 trusts that explicit click, then R2 binds it to fresh
    // process-UID/physical-seat0/session/unlocked native evidence.
    constexpr std::uint64_t kDefaultOwnerLifetimeMilliseconds =
        15U * 60U * 1000U;
    const auto result = ownerSharingAuthority_.requestConsent({
        rdp_server::server::security::kConsoleAllowedPermissions,
        kDefaultOwnerLifetimeMilliseconds});
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
    const auto current = assessRuntimeSelectedLanEndpoint(
        selection_, enumerateLocalInterfaces());
    if (!current.succeeded() ||
        !resolveCurrentLinuxNativeLanInterface(selection_.interfaceId))
    {
        // The native interface/address changed since Configure. Discard the
        // stale preference rather than letting a subsequent Start reuse it.
        selection_ = {};
        selectionConfigured_ = false;
        return deny(current.succeeded()
            ? RuntimeHostError::InterfaceUnavailable : current.error);
    }
    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    // Owner consent is positive. Later credential/TLS/listener/native-desktop
    // composition remains intentionally fail-closed in this GUI controller.
    return deny(RuntimeHostError::CredentialProviderUnavailable);
}

void LinuxRuntimeHostControl::retireStoppedRuntime(
    rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept
{
    // Security-significant host teardown order: invalidate R2 first so no
    // protected operation can escape while later R3/R5/R1 owners retire.
    // Accepted clients/native desktop are not owned here yet; they must be
    // inserted between this revocation and the final listener close.
    ownerSharingAuthority_.revoke(reason);
    listener_.close();
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
    (void)opaqueClientId;
    return deny(RuntimeHostError::ClientNotFound);
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
    stage_ = RuntimeHostStage::Revoked;
    lastError_ = RuntimeHostError::AccessRevoked;
    return {RuntimeHostError::None, false};
}

} // namespace rdp_server::server::runtime
