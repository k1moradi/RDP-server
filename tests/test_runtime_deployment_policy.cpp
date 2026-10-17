// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_deployment_policy.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>

using rdp_server::server::runtime::RuntimeDeploymentMode;
using rdp_server::server::runtime::RuntimeDeploymentPolicy;

namespace
{

void testImmutablePolicyDenials()
{
    RuntimeDeploymentPolicy personal;
    assert(!personal.configured());
    assert(personal.mode() == RuntimeDeploymentMode::Unconfigured);
    assert(!personal.usesPersonalTerminalServerLicensingFlow());
    assert(!personal.requiresIssuerBackedCalValidation());
    assert(!personal.loopbackListenerEnabled());
    assert(personal.maximumInteractiveConsoleSessionsPerConnection() == 0U);

    assert(personal.configurePersonalDesktop(false, 0U));
    assert(personal.configured());
    assert(personal.mode() == RuntimeDeploymentMode::PersonalDesktop);
    assert(personal.usesPersonalTerminalServerLicensingFlow());
    assert(!personal.requiresIssuerBackedCalValidation());
    assert(personal.requiresNativeSessionRevocation());
    assert(personal.maximumInteractiveConsoleSessionsPerConnection() == 1U);
    assert(!personal.loopbackListenerEnabled());
    assert(personal.loopbackListenerPort() == 0U);

    // Product mode is immutable after the first configuration attempt.
    assert(!personal.configureAppServerIssuerBacked());
    assert(!personal.configurePersonalDesktop(true, 3389U));

    RuntimeDeploymentPolicy invalidEnabled;
    assert(!invalidEnabled.configurePersonalDesktop(true, 0U));
    assert(!invalidEnabled.configured());
    assert(!invalidEnabled.configurePersonalDesktop(true, 3389U));

    RuntimeDeploymentPolicy invalidDisabled;
    assert(!invalidDisabled.configurePersonalDesktop(false, 3389U));
    assert(!invalidDisabled.configured());
    assert(!invalidDisabled.configureAppServerIssuerBacked());

    RuntimeDeploymentPolicy appServer;
    assert(appServer.configureAppServerIssuerBacked());
    assert(appServer.mode() == RuntimeDeploymentMode::AppServerIssuerBacked);
    assert(appServer.requiresIssuerBackedCalValidation());
    assert(!appServer.usesPersonalTerminalServerLicensingFlow());
    assert(!appServer.requiresNativeSessionRevocation());
    assert(appServer.maximumInteractiveConsoleSessionsPerConnection() == 0U);
    assert(!appServer.loopbackListenerEnabled());
    assert(!appServer.configurePersonalDesktop(true, 3389U));
}

void testLoopbackListenerDenials()
{
    constexpr std::array<std::uint8_t, 4U> ipv4Loopback{
        127U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 4U> ipv4OtherLoopback{
        127U, 0U, 0U, 2U};
    constexpr std::array<std::uint8_t, 4U> ipv4Any{
        0U, 0U, 0U, 0U};
    constexpr std::array<std::uint8_t, 4U> ipv4External{
        192U, 0U, 2U, 10U};
    constexpr std::array<std::uint8_t, 16U> ipv6Loopback{
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 16U> ipv6Any{};

    RuntimeDeploymentPolicy disabled;
    assert(disabled.configurePersonalDesktop(false, 0U));
    assert(!disabled.permitsLoopbackTransportCandidate(ipv4Loopback));
    assert(!disabled.permitsLoopbackTransportCandidate(ipv6Loopback));

    RuntimeDeploymentPolicy appServer;
    assert(appServer.configureAppServerIssuerBacked());
    assert(!appServer.permitsLoopbackTransportCandidate(ipv4Loopback));

    RuntimeDeploymentPolicy enabled;
    assert(enabled.configurePersonalDesktop(true, 3389U));
    assert(enabled.loopbackListenerEnabled());
    assert(enabled.loopbackListenerPort() == 3389U);
    assert(enabled.permitsLoopbackTransportCandidate(ipv4Loopback));
    assert(enabled.permitsLoopbackTransportCandidate(ipv6Loopback));
    assert(!enabled.permitsLoopbackTransportCandidate(ipv4OtherLoopback));
    assert(!enabled.permitsLoopbackTransportCandidate(ipv4Any));
    assert(!enabled.permitsLoopbackTransportCandidate(ipv4External));
    assert(!enabled.permitsLoopbackTransportCandidate(ipv6Any));
    assert(!enabled.permitsLoopbackTransportCandidate(
        std::span<const std::uint8_t>{}));
}

} // namespace

int main(int argumentCount, char **argumentValues)
{
    assert(argumentCount == 2);
    const std::string_view testCase{argumentValues[1]};
    if (testCase == "personal-desktop-policy-immutable-denials")
    {
        testImmutablePolicyDenials();
        return 0;
    }
    if (testCase == "personal-desktop-loopback-listener-denials")
    {
        testLoopbackListenerDenials();
        return 0;
    }
    assert(false);
    return 1;
}
