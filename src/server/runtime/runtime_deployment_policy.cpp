// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_deployment_policy.h"

#include <algorithm>
#include <array>

namespace rdp_server::server::runtime
{

bool RuntimeDeploymentPolicy::configureAppServerIssuerBacked() noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;
    mode_ = RuntimeDeploymentMode::AppServerIssuerBacked;
    return true;
}

bool RuntimeDeploymentPolicy::configurePersonalDesktop(
    bool listenerEnabled, std::uint16_t listenPort) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;

    if ((listenerEnabled && listenPort == 0U) ||
        (!listenerEnabled && listenPort != 0U))
        return false;

    mode_ = RuntimeDeploymentMode::PersonalDesktop;
    listenerEnabled_ = listenerEnabled;
    listenPort_ = listenPort;
    return true;
}

bool RuntimeDeploymentPolicy::configurePersonalDesktopPrivateLan(
    std::uint16_t listenPort) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;

    if (listenPort == 0U)
        return false;

    mode_ = RuntimeDeploymentMode::PersonalDesktop;
    privateLanListenerEnabled_ = true;
    listenPort_ = listenPort;
    return true;
}

bool RuntimeDeploymentPolicy::permitsLoopbackTransportCandidate(
    std::span<const std::uint8_t> peerAddress) const noexcept
{
    if (!loopbackListenerEnabled())
        return false;

    constexpr std::array<std::uint8_t, 4U> ipv4Loopback{
        127U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 16U> ipv6Loopback{
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};

    return (peerAddress.size() == ipv4Loopback.size() &&
            std::equal(
                peerAddress.begin(), peerAddress.end(), ipv4Loopback.begin())) ||
           (peerAddress.size() == ipv6Loopback.size() &&
            std::equal(
                peerAddress.begin(), peerAddress.end(), ipv6Loopback.begin()));
}

bool RuntimeDeploymentPolicy::permitsPrivateLanTransportCandidate(
    std::span<const std::uint8_t> peerAddress) const noexcept
{
    if (!privateLanListenerEnabled())
        return false;

    if (peerAddress.size() == 4U)
    {
        const std::uint8_t first = peerAddress[0];
        const std::uint8_t second = peerAddress[1];
        return first == 10U ||
               (first == 172U && second >= 16U && second <= 31U) ||
               (first == 192U && second == 168U);
    }

    if (peerAddress.size() == 16U)
    {
        return (peerAddress[0] & 0xfeU) == 0xfcU ||
               (peerAddress[0] == 0xfeU &&
                (peerAddress[1] & 0xc0U) == 0x80U);
    }

    return false;
}

} // namespace rdp_server::server::runtime
