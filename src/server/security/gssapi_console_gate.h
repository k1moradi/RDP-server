// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_identity_policy.h"
#include "gssapi_spnego_acceptor.h"

namespace rdp_server::server::security
{

enum class ConsoleAdmissionState : std::uint8_t
{
    NotRequested,
    Denied,
};

// Runtime bridge has NO way to return an authorized desktop capability.
// Policy matching is necessary but never sufficient; the upstream CredSSP
// delegate handler unconditionally rejects credentials in M1.13.
// Repeated attempts are permanently denied for this gate instance.
class ConsoleAdmissionGate final
{
public:
    explicit ConsoleAdmissionGate(
        const ConsoleIdentityPolicy &policy) noexcept : policy_(policy) {}

    ConsoleAdmissionGate(const ConsoleAdmissionGate &) = delete;
    ConsoleAdmissionGate &operator=(const ConsoleAdmissionGate &) = delete;

    void request(GssapiSpnegoAcceptor &acceptor,
                 const ConsoleIdentityRequest &snapshot) noexcept;

    [[nodiscard]] ConsoleAdmissionState state() const noexcept
    {
        return state_;
    }

private:
    const ConsoleIdentityPolicy &policy_;
    ConsoleAdmissionState state_{ConsoleAdmissionState::NotRequested};
};

} // namespace rdp_server::server::security
