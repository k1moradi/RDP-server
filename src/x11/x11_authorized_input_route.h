// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <span>

#include "x11_desktop_resources.h"
#include "../server/security/linux_console_admission.h"

namespace rdp_server::server::runtime
{
class LinuxRuntimeConnection;
class RuntimeDeploymentPolicy;
}


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

    // Runtime-facing R2-protected decoded input gateway. Only R10's sole
    // serialized R1/TLS reader supplies complete TPKTs; this adapter never
    // reads sockets or acquires a second X11 owner. R2 invokes the private
    // sink synchronously after fresh kConsoleInputPermission authorization
    // for EACH decoded input event. Unsupported formats retire fail closed.
    [[nodiscard]] static bool dispatchAuthenticatedSlowPathTpkt(
        rdp_server::server::runtime::LinuxRuntimeConnection &connection,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy &policy,
        X11DesktopResources &desktop,
        std::uint64_t expectedNativeGeneration,
        std::span<const std::uint8_t> completeTpkt) noexcept;

private:
    [[nodiscard]] static bool onAuthenticatedInput(
        void *context,
        const rdp_server::server::transport::RdpSlowPathInputEvent &event)
        noexcept;
};
