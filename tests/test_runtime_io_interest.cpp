// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_connection.h"

#include <cassert>
#include <string_view>

namespace
{
using rdp_server::server::runtime::detail::LinuxRuntimeIoInterestSnapshot;
using rdp_server::server::runtime::detail::
    selectLinuxRuntimeConnectionIoInterest;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::TcpConnectionIoInterest;

void testOutboundWriteReadiness() noexcept
{
    LinuxRuntimeIoInterestSnapshot snapshot{};
    snapshot.r1Interest = TcpConnectionIoInterest::Read;
    snapshot.runtimeReady = true;
    snapshot.personalDesktopSelected = true;

    snapshot.sessionPhase = McsSessionPhase::AwaitServerLicenseRequest;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Write);

    // Positive short-write completion keeps the same R3 phase while its
    // authoritative writer owns a nonempty suffix.
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Write);

    snapshot.sessionPhase =
        McsSessionPhase::AwaitPersonalDesktopValidClientWrite;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Write);

    snapshot.sessionPhase = McsSessionPhase::ShareActivation;
    snapshot.shareWritePending = true;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Write);

    snapshot.shareWritePending = false;
    snapshot.sessionPhase = McsSessionPhase::ShareActivated;
    snapshot.graphicsWritePending = true;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Write);

    snapshot.graphicsWritePending = false;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Read);
}

void testTlsWantPrecedence() noexcept
{
    LinuxRuntimeIoInterestSnapshot snapshot{};
    snapshot.r1Interest = TcpConnectionIoInterest::Read;
    snapshot.runtimeReady = true;
    snapshot.personalDesktopSelected = true;
    snapshot.sessionPhase = McsSessionPhase::AwaitServerLicenseRequest;
    snapshot.shareWritePending = true;
    snapshot.graphicsWritePending = true;
    snapshot.tlsApplicationWriteOutstanding = true;

    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Read);

    snapshot.r1Interest = TcpConnectionIoInterest::Write;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Write);

    snapshot.r1Interest = TcpConnectionIoInterest::ConfigureTls;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Closed);
}

void testCancellationAndRevocation() noexcept
{
    LinuxRuntimeIoInterestSnapshot snapshot{};
    snapshot.runtimeReady = true;
    snapshot.r1Interest = TcpConnectionIoInterest::Closed;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Closed);

    snapshot.runtimeReady = false;
    snapshot.personalDesktopSelected = true;
    snapshot.sessionPhase = McsSessionPhase::AwaitServerLicenseRequest;
    snapshot.r1Interest = TcpConnectionIoInterest::Write;
    snapshot.shareWritePending = true;
    snapshot.graphicsWritePending = true;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           TcpConnectionIoInterest::Closed);
}

} // namespace

int main(int argumentCount, char **argumentValues)
{
    if (argumentCount != 2 || argumentValues[1] == nullptr)
        return 2;

    const std::string_view testCase{argumentValues[1]};
    if (testCase == "outbound-write-readiness")
    {
        testOutboundWriteReadiness();
        return 0;
    }
    if (testCase == "outbound-tls-want-precedence")
    {
        testTlsWantPrecedence();
        return 0;
    }
    if (testCase == "outbound-cancellation-revocation")
    {
        testCancellationAndRevocation();
        return 0;
    }
    return 2;
}
