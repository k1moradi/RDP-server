// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_connection.h"

#include <array>
#include <cassert>
#include <chrono>
#include <poll.h>
#include <string_view>
#include <unistd.h>

namespace
{
using rdp_server::server::runtime::detail::LinuxRuntimeIoInterestSnapshot;
using rdp_server::server::runtime::detail::
    selectLinuxRuntimeConnectionIoInterest;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::TcpConnectionIoInterest;

void testStalledGraphicsTlsWriteBoundedPolling() noexcept
{
    using namespace std::chrono_literals;
    using rdp_server::server::runtime::detail::selectLinuxPostSharePollWait;

    constexpr auto pollQuantum = 25ms;
    constexpr auto expiredCapture = 0ms;
    assert(selectLinuxPostSharePollWait(
               pollQuantum, expiredCapture, true, false, false) == pollQuantum);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, expiredCapture, false, false, false) == 0ms);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, 100ms, false, false, false) == pollQuantum);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, 9ms, false, false, false) == 9ms);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, expiredCapture, true, false, true) == 0ms);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, expiredCapture, false, true, false) == 0ms);

    std::array<int, 2> quietPipe{-1, -1};
    assert(::pipe(quietPipe.data()) == 0);
    pollfd ready{quietPipe[0], POLLIN, 0};
    const auto start = std::chrono::steady_clock::now();
    for (int iteration = 0; iteration < 4; ++iteration)
    {
        ready.revents = 0;
        const auto wait = selectLinuxPostSharePollWait(
            pollQuantum, expiredCapture, true, false, false);
        assert(::poll(&ready, static_cast<nfds_t>(1),
                      static_cast<int>(wait.count())) == 0);
    }
    assert(std::chrono::steady_clock::now() - start >= 70ms);
    assert(::close(quietPipe[1]) == 0);
    assert(::close(quietPipe[0]) == 0);
}

void testResizeDeadlineBoundsPolling() noexcept
{
    using namespace std::chrono_literals;
    using rdp_server::server::runtime::detail::selectLinuxPostSharePollWait;

    constexpr auto pollQuantum = 25ms;
    const std::optional<std::chrono::milliseconds> sevenMilliseconds{7ms};
    const std::optional<std::chrono::milliseconds> expired{0ms};

    // A remap deadline is authoritative even while R1 owns a stalled
    // WANT_READ/WANT_WRITE retry; R10 may not sleep beyond retirement.
    assert(selectLinuxPostSharePollWait(
               pollQuantum, 100ms, true, false, false,
               sevenMilliseconds) == 7ms);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, 100ms, true, false, false,
               expired) == 0ms);

    // Native work and buffered R1 plaintext retain immediate precedence.
    assert(selectLinuxPostSharePollWait(
               pollQuantum, 100ms, true, false, true,
               sevenMilliseconds) == 0ms);
    assert(selectLinuxPostSharePollWait(
               pollQuantum, 100ms, false, true, false,
               sevenMilliseconds) == 0ms);
}

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

void testClipboardOutboundWantPrecedence() noexcept
{
    using Interest = TcpConnectionIoInterest;
    using rdp_server::server::runtime::detail::
        shouldDispatchBufferedTlsApplicationRead;

    LinuxRuntimeIoInterestSnapshot snapshot{};
    snapshot.runtimeReady = true;
    snapshot.personalDesktopSelected = true;
    snapshot.sessionPhase = McsSessionPhase::ShareActivated;
    snapshot.r1Interest = Interest::Read;

    // R3 owns the pending CLIPRDR suffix; an idle inbound SSL owner must
    // not prevent its next outbound plaintext slice.
    snapshot.clipboardWritePending = true;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Write);
    assert(!shouldDispatchBufferedTlsApplicationRead(
        selectLinuxRuntimeConnectionIoInterest(snapshot), true));

    // R1 owns the retry direction after SSL_write_ex WANT_READ/WANT_WRITE.
    snapshot.tlsApplicationWriteOutstanding = true;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Read);
    snapshot.r1Interest = Interest::Write;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Write);
    snapshot.r1Interest = Interest::Closed;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Closed);

    // A positive-short receipt leaves an R3 suffix to write next.
    snapshot.tlsApplicationWriteOutstanding = false;
    snapshot.r1Interest = Interest::Read;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Write);
    snapshot.clipboardWritePending = false;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Read);
    snapshot.clipboardWritePending = true;
    snapshot.runtimeReady = false;
    assert(selectLinuxRuntimeConnectionIoInterest(snapshot) ==
           Interest::Closed);
}

void testBufferedTlsReadDispatch() noexcept
{
    using Interest = TcpConnectionIoInterest;
    using rdp_server::server::runtime::detail::
        shouldDispatchBufferedTlsApplicationRead;

    // A complete packet can remain decrypted inside the sole R1 SSL owner
    // after an earlier bounded read; native POLLIN is not needed to advance.
    assert(shouldDispatchBufferedTlsApplicationRead(Interest::Read, true));
    assert(!shouldDispatchBufferedTlsApplicationRead(Interest::Read, false));

    // Outbound slices and SSL WANT_WRITE must never be converted into a
    // read callback, even when OpenSSL has unrelated buffered plaintext.
    assert(!shouldDispatchBufferedTlsApplicationRead(Interest::Write, true));
    assert(!shouldDispatchBufferedTlsApplicationRead(
        Interest::ConfigureTls, true));
    assert(!shouldDispatchBufferedTlsApplicationRead(Interest::Closed, true));

    LinuxRuntimeIoInterestSnapshot snapshot{};
    snapshot.runtimeReady = true;
    snapshot.personalDesktopSelected = true;
    snapshot.r1Interest = Interest::Read;
    snapshot.sessionPhase = McsSessionPhase::ShareActivated;
    assert(shouldDispatchBufferedTlsApplicationRead(
        selectLinuxRuntimeConnectionIoInterest(snapshot), true));

    snapshot.graphicsWritePending = true;
    assert(!shouldDispatchBufferedTlsApplicationRead(
        selectLinuxRuntimeConnectionIoInterest(snapshot), true));

    snapshot.graphicsWritePending = false;
    snapshot.tlsApplicationWriteOutstanding = true;
    snapshot.r1Interest = Interest::Write;
    assert(!shouldDispatchBufferedTlsApplicationRead(
        selectLinuxRuntimeConnectionIoInterest(snapshot), true));

    snapshot.runtimeReady = false;
    assert(!shouldDispatchBufferedTlsApplicationRead(
        selectLinuxRuntimeConnectionIoInterest(snapshot), true));
}

} // namespace

int main(int argumentCount, char **argumentValues)
{
    if (argumentCount != 2 || argumentValues[1] == nullptr)
        return 2;

    const std::string_view testCase{argumentValues[1]};
    if (testCase == "stalled-graphics-tls-write-bounded-poll")
    {
        testStalledGraphicsTlsWriteBoundedPolling();
        return 0;
    }
    if (testCase == "resize-deadline-bounded-poll")
    {
        testResizeDeadlineBoundsPolling();
        return 0;
    }
    if (testCase == "clipboard-outbound-want-precedence")
    {
        testClipboardOutboundWantPrecedence();
        return 0;
    }
    if (testCase == "buffered-tls-read-dispatch")
    {
        testBufferedTlsReadDispatch();
        return 0;
    }
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
