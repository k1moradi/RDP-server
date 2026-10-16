// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_authorized_input_route.h"

using rdp_server::server::security::kConsoleInputPermission;

bool
X11AuthorizedInputRoute::dispatch(
    rdp_server::server::security::LinuxConsoleAdmissionBroker &broker,
    const rdp_server::server::security::LinuxConsoleAdmissionLease *lease,
    rdp_server::server::security::GssapiSpnegoAcceptor &acceptor,
    const SSL *activeServerTls,
    rdp_server::server::transport::McsSessionLifecycle &session,
    X11DesktopResources &desktop,
    const X11InputEvent &event) noexcept
{
    // Missing concrete admission or a dead native owner is terminal for this
    // protected path. Close R3 before R2/GSS and revoke native input state.
    if (lease == nullptr || !desktop.valid())
    {
        desktop.disconnect();
        broker.revokeR3Session(acceptor, session);
        return false;
    }

    // Revalidate the exact lease generation, native session generation,
    // GSS/TLS provenance, policy and input permission immediately before
    // native injection. The broker closes R3/R2/GSS on any denial.
    if (!broker.authorizeR3ProtectedTransition(
            *lease, acceptor, activeServerTls, session,
            kConsoleInputPermission))
    {
        desktop.disconnect();
        return false;
    }

    if (!desktop.handleAuthorizedInput(event))
    {
        // A native XTEST failure is terminal for the admitted session too:
        // do not leave R3 live after its sole native input endpoint died.
        broker.revokeR3Session(acceptor, session);
        return false;
    }

    return true;
}
