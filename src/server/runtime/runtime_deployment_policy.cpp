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

} // namespace rdp_server::server::runtime
