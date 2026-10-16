// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_console_gate.h"

namespace rdp_server::server::security
{

void ConsoleAdmissionGate::request(
    GssapiSpnegoAcceptor &acceptor,
    const ConsoleIdentityRequest &snapshot) noexcept
{
    // A caller-constructed snapshot provides neither a GSS identity
    // nor an OS-attested login session. Never evaluate it as policy
    // evidence, even if a different, real GSS provider was configured.
    (void)snapshot;
    acceptor.reject();
    state_ = ConsoleAdmissionState::Denied;
}

void ConsoleAdmissionGate::requestWithOsEvidence(
    GssapiSpnegoAcceptor &acceptor,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &source) noexcept
{
    // Only the real GSS provider can disclose this principal; its
    // accessor rechecks CredSSP public-key proof and the selected
    // active TLS X.509 on every call. Never trust the caller's claim.
    const std::string_view proven = acceptor.verifiedPrincipal();
    if (state_ != ConsoleAdmissionState::Denied &&
        !proven.empty() && proven == request.kerberosPrincipal)
    {
        // A fresh, independent OS sample is a *candidate* only.
        // No result (even CandidateOnly) may escape this gate or
        // become an OS-admission, MCS or desktop capability.
        const auto candidate =
            ConsoleOsEvidenceInspector{}.inspect(policy_, request, source);
        (void)candidate;
    }

    // Tear down GSS for success, failure, mismatch, timeout or
    // repeated use. No replay or reconfiguration after this point.
    acceptor.reject();
    state_ = ConsoleAdmissionState::Denied;
}

} // namespace rdp_server::server::security
