// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_authorized_input_route.h"

#include <cassert>
#include <cstdlib>
#include <string_view>
#include <type_traits>

using rdp_server::server::security::ConsoleIdentityPolicy;
using rdp_server::server::security::ConsoleRuleError;
using rdp_server::server::security::GssapiSpnegoAcceptor;
using rdp_server::server::security::LinuxConsoleAdmissionBroker;
using rdp_server::server::security::LinuxConsoleAdmissionLease;
using rdp_server::server::security::LinuxConsoleAdmissionState;
using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;
using rdp_server::server::transport::McsSessionLifecycle;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::OwnedNativeTcpSocket;
using rdp_server::server::transport::OwnedPreauthTcpConnection;

namespace
{

using Dispatch = decltype(&X11AuthorizedInputRoute::dispatch);

static_assert(std::is_invocable_r_v<
              bool,
              Dispatch,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease *,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              X11DesktopResources &,
              const X11InputEvent &>);
static_assert(!std::is_invocable_v<
              Dispatch,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease *,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              X11DesktopResources &,
              const X11InputEvent &>);
static_assert(!std::is_invocable_v<
              Dispatch,
              LinuxConsoleAdmissionBroker &,
              bool,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              X11DesktopResources &,
              const X11InputEvent &>);

const char *
syntheticDisplay()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');
    return display;
}

void
missingAdmissionRevokesInputPath()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission |
                                 kConsoleInputPermission}) ==
           ConsoleRuleError::None);

    LinuxConsoleAdmissionBroker broker(policy);
    GssapiSpnegoAcceptor acceptor;
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};
    X11DesktopResources desktop(syntheticDisplay(), 256U * 1024U);
    assert(desktop.valid());
    assert(broker.state() == LinuxConsoleAdmissionState::Ready);
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);

    const X11InputEvent event = X11PointerMoveInput{16, 16};

    // A native desktop plus a policy that *could* grant input is insufficient.
    // Without the unforgeable broker-issued lease no XTEST call is reachable.
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop, event));
    assert(!desktop.valid());
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);

    // Late/replayed input cannot revive any owner after revocation.
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop, event));
    assert(!desktop.valid());
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

} // namespace

int main()
{
    missingAdmissionRevokesInputPath();
    return 0;
}
