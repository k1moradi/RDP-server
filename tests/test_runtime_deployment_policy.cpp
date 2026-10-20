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

void testPrivateLanListenerDenials()
{
    constexpr std::array<std::uint8_t, 4U> ipv4Private10{
        10U, 1U, 2U, 3U};
    constexpr std::array<std::uint8_t, 4U> ipv4Private172{
        172U, 31U, 255U, 254U};
    constexpr std::array<std::uint8_t, 4U> ipv4Private192{
        192U, 168U, 1U, 9U};
    constexpr std::array<std::uint8_t, 4U> ipv4BeforePrivate172{
        172U, 15U, 1U, 1U};
    constexpr std::array<std::uint8_t, 4U> ipv4AfterPrivate172{
        172U, 32U, 1U, 1U};
    constexpr std::array<std::uint8_t, 4U> ipv4Loopback{
        127U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 4U> ipv4Public{
        203U, 0U, 113U, 10U};
    constexpr std::array<std::uint8_t, 16U> ipv6UniqueLocal{
        0xfdU, 0x12U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 16U> ipv6LinkLocal{
        0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 16U> ipv6Loopback{
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 16U> ipv6Global{
        0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};

    RuntimeDeploymentPolicy invalid;
    assert(!invalid.configurePersonalDesktopPrivateLan(0U));
    assert(!invalid.configured());

    RuntimeDeploymentPolicy lan;
    assert(lan.configurePersonalDesktopPrivateLan(3389U));
    assert(lan.privateLanListenerEnabled());
    assert(lan.privateLanListenerPort() == 3389U);
    assert(!lan.loopbackListenerEnabled());
    assert(lan.permitsPrivateLanTransportCandidate(ipv4Private10));
    assert(lan.permitsPrivateLanTransportCandidate(ipv4Private172));
    assert(lan.permitsPrivateLanTransportCandidate(ipv4Private192));
    assert(lan.permitsPrivateLanTransportCandidate(ipv6UniqueLocal));
    assert(lan.permitsPrivateLanTransportCandidate(ipv6LinkLocal));
    assert(!lan.permitsPrivateLanTransportCandidate(ipv4BeforePrivate172));
    assert(!lan.permitsPrivateLanTransportCandidate(ipv4AfterPrivate172));
    assert(!lan.permitsPrivateLanTransportCandidate(ipv4Loopback));
    assert(!lan.permitsPrivateLanTransportCandidate(ipv4Public));
    assert(!lan.permitsPrivateLanTransportCandidate(ipv6Loopback));
    assert(!lan.permitsPrivateLanTransportCandidate(ipv6Global));
    assert(!lan.permitsPrivateLanTransportCandidate(
        std::span<const std::uint8_t>{}));
    assert(!lan.permitsLoopbackTransportCandidate(ipv4Loopback));
    assert(!lan.configurePersonalDesktop(true, 3389U));
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
    if (testCase == "personal-desktop-private-lan-candidate-denials")
    {
        testPrivateLanListenerDenials();
        return 0;
    }
    assert(false);
    return 1;
}
