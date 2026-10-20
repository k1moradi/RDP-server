// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_authorized_input_route.h"
#include "server/security/gssapi_spnego_acceptor.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <limits>
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
              std::uint64_t,
              const X11InputEvent &>);
static_assert(!std::is_invocable_v<
              Dispatch,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease *,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              X11DesktopResources &,
              std::uint64_t,
              const X11InputEvent &>);
static_assert(!std::is_invocable_v<
              Dispatch,
              LinuxConsoleAdmissionBroker &,
              bool,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              X11DesktopResources &,
              std::uint64_t,
              const X11InputEvent &>);
static_assert(!std::is_invocable_v<
              Dispatch,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease *,
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
    const std::uint64_t nativeGeneration = desktop.captureGeneration();
    assert(nativeGeneration != 0);

    // A native desktop plus a policy that *could* grant input is insufficient.
    // Without the unforgeable broker-issued lease no XTEST call is reachable.
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop,
        nativeGeneration, event));
    assert(!desktop.valid());
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);

    // Late/replayed input cannot revive any owner after revocation.
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop,
        nativeGeneration, event));
    assert(!desktop.valid());
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

void
mismatchedNativeGenerationRevokesInputPath()
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

    const std::uint64_t nativeGeneration = desktop.captureGeneration();
    assert(nativeGeneration != 0);
    const std::uint64_t mismatchedGeneration =
        nativeGeneration == (std::numeric_limits<std::uint64_t>::max)()
            ? nativeGeneration - 1U
            : nativeGeneration + 1U;
    assert(mismatchedGeneration != 0);
    assert(mismatchedGeneration != nativeGeneration);

    const X11InputEvent event = X11PointerMoveInput{16, 16};

    // A caller-supplied generation is never authorization, and a stale/future
    // geometry epoch is rejected before a missing lease could reach XTEST.
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop,
        mismatchedGeneration, event));
    assert(!desktop.valid());
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

void
policyReplacementDeniesStaleKeyboard()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission |
                                 kConsoleInputPermission}) ==
           ConsoleRuleError::None);
    const std::uint64_t originalPolicyGeneration = policy.generation();
    assert(originalPolicyGeneration != 0);

    LinuxConsoleAdmissionBroker broker(policy);
    GssapiSpnegoAcceptor acceptor;
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};
    X11DesktopResources desktop(syntheticDisplay(), 256U * 1024U);
    assert(desktop.valid());

    const std::uint64_t nativeGeneration = desktop.captureGeneration();
    assert(nativeGeneration != 0);
    // Replacing the service policy removes input permission and advances R2.
    // This is NOT a fabricated lease or positive native OS admission.
    assert(policy.replaceSingle({"alice@EXAMPLE.TEST", "alice",
                                 "seat0", ":0", 1001,
                                 kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.generation() != originalPolicyGeneration);

    const X11InputEvent press = X11KeyInput{
        0xffe3U, 0x1dU, false, true};
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop,
        nativeGeneration, press));
    assert(!desktop.valid());
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    // Replayed key-up after policy replacement also has no native sink.
    const X11InputEvent release = X11KeyInput{
        0xffe3U, 0x1dU, false, false, true};
    assert(!X11AuthorizedInputRoute::dispatch(
        broker, nullptr, acceptor, connection, session, desktop,
        nativeGeneration, release));
}

} // namespace

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        missingAdmissionRevokesInputPath();
        return 0;
    }
    if (argc == 2 && std::string_view{argv[1]} ==
                            "policy-replacement-keyboard")
    {
        policyReplacementDeniesStaleKeyboard();
        return 0;
    }
    if (argc == 2 && std::string_view{argv[1]} == "generation-mismatch")
    {
        mismatchedNativeGenerationRevokesInputPath();
        return 0;
    }
    return 2;
}
