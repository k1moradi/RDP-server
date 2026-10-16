// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"
#include "gssapi_spnego_acceptor.h"

namespace rdp_server::server::security
{

enum class ConsoleAdmissionState : std::uint8_t
{
    NotRequested,
    Denied,
};

// Runtime bridge has NO way to return an authorized desktop capability.
// Real GSS + CredSSP public-key binding is necessary but insufficient;
// OS candidate observations (including a matching fake source) cannot
// provide authentication, delegated credentials or a session lease.
// The existing credential handler terminally denies after decryption.
// Repeated calls are permanently denied for this gate instance.
class ConsoleAdmissionGate final
{
public:
    explicit ConsoleAdmissionGate(
        const ConsoleIdentityPolicy &policy) noexcept : policy_(policy) {}

    ConsoleAdmissionGate(const ConsoleAdmissionGate &) = delete;
    ConsoleAdmissionGate &operator=(const ConsoleAdmissionGate &) = delete;

    // Historical untrusted snapshot path has no native OS provenance.
    // Never even run a candidate policy match on caller-attested identity.
    void request(GssapiSpnegoAcceptor &acceptor,
                 const ConsoleIdentityRequest &snapshot) noexcept;

    // New synchronous, deny-only GSS-to-OS consistency boundary.
    // A caller-supplied principal is never a substitute for a completed
    // genuine GSS + pinned TLS certificate/public-key proof. Only AFTER
    // matching that provider-derived principal may an OS evidence source
    // be sampled using the existing read-only inspector. Fake providers
    // can produce CandidateOnly, but cannot grant any permission here.
    // Do not invoke a potentially blocking native source on the event
    // loop; future code must isolate its lifetime and deadline.
    // Always destroys the GSS context and records terminal denial.
    void requestWithOsEvidence(
        GssapiSpnegoAcceptor &acceptor,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &source) noexcept;

    [[nodiscard]] ConsoleAdmissionState state() const noexcept
    {
        return state_;
    }

private:
    const ConsoleIdentityPolicy &policy_;
    ConsoleAdmissionState state_{ConsoleAdmissionState::NotRequested};
};

} // namespace rdp_server::server::security
