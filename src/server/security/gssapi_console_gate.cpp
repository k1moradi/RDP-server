// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_console_gate.h"

namespace rdp_server::server::security
{

void ConsoleAdmissionGate::request(
    GssapiSpnegoAcceptor &acceptor,
    const ConsoleIdentityRequest &snapshot) noexcept
{
    // Evaluate for audit/testability, but NEVER issue a session token on
    // this milestone. The provided snapshot is not independently attested:
    // no logind/X11/PAM/NSS ownership adapter exists, and M1.13 denies
    // all delegated credentials. Fabricated attributes cannot bypass it.
    if (state_ != ConsoleAdmissionState::Denied &&
        acceptor.stage() == SpnegoStage::ServerBindingPrepared)
    {
        const auto match = policy_.matchCandidate(snapshot);
        (void)match;
    }

    acceptor.reject(); // terminal cleanup of any GSS context/credential.
    state_ = ConsoleAdmissionState::Denied;
}

} // namespace rdp_server::server::security
