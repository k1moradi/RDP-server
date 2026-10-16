// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/security/console_identity_policy.h"
#include "server/security/gssapi_spnego_acceptor.h"

#include <array>
#include <cstddef>
#include <string_view>

namespace rdp_server::server::runtime
{

// Linux-only pre-listener security provisioning. The object owns one sealed,
// anonymous snapshot of the securely opened keytab plus one immutable
// ConsoleIdentityPolicy. It does not own a connection, TLS, GSS context or R3
// session. Keep it alive for every GssapiSpnegoAcceptor configured from it so
// FILE:/proc/self/fd/<n> continues to identify the exact immutable snapshot
// accepted during startup.
//
// All methods are externally serialized. Configuration is one-shot: a failed
// attempt cannot be retried on the same object, and successful configuration
// cannot be mutated in place. This prevents policy/keytab replacement under
// active connections.
class LinuxRuntimeSecurityConfiguration final
{
public:
    LinuxRuntimeSecurityConfiguration() noexcept = default;
    ~LinuxRuntimeSecurityConfiguration();

    LinuxRuntimeSecurityConfiguration(
        const LinuxRuntimeSecurityConfiguration &) = delete;
    LinuxRuntimeSecurityConfiguration &operator=(
        const LinuxRuntimeSecurityConfiguration &) = delete;
    LinuxRuntimeSecurityConfiguration(
        LinuxRuntimeSecurityConfiguration &&) = delete;
    LinuxRuntimeSecurityConfiguration &operator=(
        LinuxRuntimeSecurityConfiguration &&) = delete;

    // keytabUri must be an explicit FILE:/ absolute path. The opened object
    // must be a nonempty bounded regular file, owned by the current effective
    // uid, owner-readable, and inaccessible to group/other. Parent/final
    // symlinks and . / .. components are rejected. The bounded contents are
    // copied into an anonymous memfd and sealed against write/grow/shrink
    // before any credential is exposed. A temporary R2 acceptor then proves
    // that MIT GSS can acquire the exact requested TERMSRV credential through
    // this sealed descriptor. No KDC or client ticket is contacted/required.
    //
    // The rule is validated by the existing R2 ConsoleIdentityPolicy. Success
    // therefore prepares one explicit service identity and one native mapping,
    // but does not authenticate a user or authorize any session.
    [[nodiscard]] bool configure(
        std::string_view servicePrincipal,
        std::string_view keytabUri,
        const rdp_server::server::security::ConsoleIdentityRuleInput &rule)
        noexcept;

    // Configure one existing per-connection R2 acceptor from the retained
    // sealed keytab snapshot. The configuration object must outlive it.
    // False is terminal for the supplied acceptor.
    [[nodiscard]] bool configureAcceptor(
        rdp_server::server::security::GssapiSpnegoAcceptor &acceptor)
        const noexcept;

    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] std::string_view servicePrincipal() const noexcept;
    [[nodiscard]]
    const rdp_server::server::security::ConsoleIdentityPolicy *policy()
        const noexcept;

private:
    void closeKeytab() noexcept;
    void clearServicePrincipal() noexcept;

    std::array<char, 513> servicePrincipal_{};
    std::size_t servicePrincipalLength_{};
    rdp_server::server::security::ConsoleIdentityPolicy policy_{};
    int keytabDescriptor_{-1};
    bool attempted_{};
    bool configured_{};
};

} // namespace rdp_server::server::runtime
