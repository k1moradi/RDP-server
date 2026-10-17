// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>

#include "x11_desktop_resources.h"
#include "../server/security/linux_console_admission.h"

/**
 * Stateless R3/R2 -> R5 input dispatch boundary.
 *
 * This owns no session, authorization cache or native input state. A request
 * reaches XTEST only after its expected native geometry generation still
 * matches the desktop owner and the concrete Linux admission broker revalidates
 * the exact lease/R1 owner/GSS/R3 generation for kConsoleInputPermission.
 * The native generation is freshness provenance only, never authorization.
 */
class X11AuthorizedInputRoute final
{
public:
    X11AuthorizedInputRoute() = delete;

    [[nodiscard]] static bool dispatch(
        rdp_server::server::security::LinuxConsoleAdmissionBroker &broker,
        const rdp_server::server::security::LinuxConsoleAdmissionLease *lease,
        rdp_server::server::security::GssapiSpnegoAcceptor &acceptor,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        rdp_server::server::transport::McsSessionLifecycle &session,
        X11DesktopResources &desktop,
        std::uint64_t expectedNativeGeneration,
        const X11InputEvent &event) noexcept;
};
