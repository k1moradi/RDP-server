// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::runtime
{

enum class RuntimeDeploymentMode : std::uint8_t
{
    Unconfigured,
    AppServerIssuerBacked,
    PersonalDesktop,
};

// Immutable service-lifetime R10 product policy. Selecting PersonalDesktop
// changes only licensing/service composition policy; it never authenticates a
// principal, mints an R2 lease, activates R3 Share, or authorizes desktop/input.
//
// AppServerIssuerBacked deliberately preserves the existing
// RuntimeLicensingAuthority NoVerifiedIssuer fail-closed behavior unless a
// separately supported provider is configured in the future.
//
// PersonalDesktop is the MS-RDPELE personal-terminal-server product mode:
// R3 must own the normative licensing PDU transition, while R10 merely exposes
// the immutable product-mode fact. The mode is limited to one interactive
// console session per connection and requires native-session revocation.
class RuntimeDeploymentPolicy final
{
public:
    RuntimeDeploymentPolicy() noexcept = default;

    RuntimeDeploymentPolicy(const RuntimeDeploymentPolicy &) = delete;
    RuntimeDeploymentPolicy &operator=(const RuntimeDeploymentPolicy &) = delete;
    RuntimeDeploymentPolicy(RuntimeDeploymentPolicy &&) = delete;
    RuntimeDeploymentPolicy &operator=(RuntimeDeploymentPolicy &&) = delete;

    [[nodiscard]] bool configureAppServerIssuerBacked() noexcept;

    // listenerEnabled is an explicit future acceptance-policy opt-in only.
    // No socket is opened or accepted here. When enabled, listenPort must be
    // nonzero and only exact IPv4 127.0.0.1 / IPv6 ::1 peer addresses can be
    // admitted as transport candidates. R2/R3 authorization is still required
    // later and is intentionally not represented by booleans in this API.
    [[nodiscard]] bool configurePersonalDesktop(
        bool listenerEnabled, std::uint16_t listenPort) noexcept;

    [[nodiscard]] bool configured() const noexcept
    {
        return mode_ != RuntimeDeploymentMode::Unconfigured;
    }
    [[nodiscard]] RuntimeDeploymentMode mode() const noexcept { return mode_; }
    [[nodiscard]] bool usesPersonalTerminalServerLicensingFlow() const noexcept
    {
        return mode_ == RuntimeDeploymentMode::PersonalDesktop;
    }
    [[nodiscard]] bool requiresIssuerBackedCalValidation() const noexcept
    {
        return mode_ == RuntimeDeploymentMode::AppServerIssuerBacked;
    }
    [[nodiscard]] bool requiresNativeSessionRevocation() const noexcept
    {
        return mode_ == RuntimeDeploymentMode::PersonalDesktop;
    }
    [[nodiscard]] std::uint32_t
    maximumInteractiveConsoleSessionsPerConnection() const noexcept
    {
        return mode_ == RuntimeDeploymentMode::PersonalDesktop ? 1U : 0U;
    }
    [[nodiscard]] bool loopbackListenerEnabled() const noexcept
    {
        return mode_ == RuntimeDeploymentMode::PersonalDesktop &&
               listenerEnabled_;
    }
    [[nodiscard]] std::uint16_t loopbackListenerPort() const noexcept
    {
        return loopbackListenerEnabled() ? listenPort_ : 0U;
    }

    // Network-location policy only. A true result does not establish TLS,
    // CredSSP, native admission, licensing completion, Share, input or desktop
    // authority.
    [[nodiscard]] bool permitsLoopbackTransportCandidate(
        std::span<const std::uint8_t> peerAddress) const noexcept;

private:
    RuntimeDeploymentMode mode_{RuntimeDeploymentMode::Unconfigured};
    std::uint16_t listenPort_{};
    bool attempted_{};
    bool listenerEnabled_{};
};

} // namespace rdp_server::server::runtime
