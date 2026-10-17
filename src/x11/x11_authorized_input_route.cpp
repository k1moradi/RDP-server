// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_authorized_input_route.h"

using rdp_server::server::security::kConsoleInputPermission;

bool
X11AuthorizedInputRoute::dispatch(
    rdp_server::server::security::LinuxConsoleAdmissionBroker &broker,
    const rdp_server::server::security::LinuxConsoleAdmissionLease *lease,
    rdp_server::server::security::GssapiSpnegoAcceptor &acceptor,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    X11DesktopResources &desktop,
    std::uint64_t expectedNativeGeneration,
    const X11InputEvent &event) noexcept
{
    // Capture and XTEST are geometry-bound children of the same R5 owner.
    // Reuse that existing epoch so a decoded event queued before RandR cannot
    // reach the replacement input controller. This scalar is freshness only;
    // matching it cannot substitute for the concrete R2/R3 authorization.
    if (!desktop.valid() || expectedNativeGeneration == 0 ||
        desktop.captureGeneration() != expectedNativeGeneration)
    {
        desktop.retireAfterAuthorizationLoss();
        broker.revokeR3Session(acceptor, session);
        return false;
    }

    // Missing concrete admission is terminal even when native freshness
    // matches. Retire native input without any cleanup XTEST request, then
    // close R3/R2/GSS.
    if (lease == nullptr)
    {
        desktop.retireAfterAuthorizationLoss();
        broker.revokeR3Session(acceptor, session);
        return false;
    }

    // Revalidate the exact lease generation, native session generation,
    // R1-owned GSS/TLS/NLA provenance, policy and input permission
    // immediately before native injection. The broker closes R3/R2/GSS on
    // any denial; a caller-selected SSL pointer is not an authority input.
    if (!broker.authorizeR3ProtectedTransition(
            *lease, acceptor, connection, session, kConsoleInputPermission))
    {
        desktop.retireAfterAuthorizationLoss();
        return false;
    }

    if (!desktop.handleAuthorizedInput(expectedNativeGeneration, event))
    {
        desktop.disconnect();
        // A native XTEST failure or unexpected generation loss is terminal
        // for the admitted session too:
        // do not leave R3 live after its sole native input endpoint died.
        broker.revokeR3Session(acceptor, session);
        return false;
    }

    return true;
}
