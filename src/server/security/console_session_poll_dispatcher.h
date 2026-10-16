// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_session_change_watch.h"

namespace rdp_server::server::security
{

// Non-privileged Linux event-loop integration boundary. Watches ONE
// BORROWED session-change fd (e.g. a logind monitor), never closes it,
// and synchronously dispatches notification/cancellation into M1.19.
// No worker, socket listener, X11 handle, GSS authorization, desktop
// capability, session lease or access grant. Single-threaded use only.
//
// A single poll step is bounded to 250 ms; on timeout it still revalidates
// OS evidence so inactivity never substitutes for a continuing login.
// The check/use gap remains: passing CandidateOnly is NOT safe access.
class ConsoleSessionPollDispatcher final
{
public:
    ConsoleSessionPollDispatcher() noexcept = default;
    ~ConsoleSessionPollDispatcher() { shutdown(); }
    ConsoleSessionPollDispatcher(const ConsoleSessionPollDispatcher &) = delete;
    ConsoleSessionPollDispatcher &operator=(const ConsoleSessionPollDispatcher &) = delete;

    // The change source and fd must be established BEFORE first observe.
    // Only POLLIN/POLLPRI readiness masks are accepted. A missing fd or
    // watcher causes terminal denial. No descriptor ownership transferred.
    [[nodiscard]] ConsoleLifecycleState observe(
        const ConsoleIdentityPolicy &policy,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &evidence,
        ConsoleSessionChangeSource &changes,
        int watchFd, int watchEvents) noexcept;

    // Drive at most one poll(2) readiness/timeout dispatch. Any error,
    // HUP, unsupported readiness, or OS/policy mismatch terminally revokes.
    [[nodiscard]] ConsoleLifecycleState pumpOnce(
        const ConsoleIdentityPolicy &policy,
        ConsoleOsEvidenceSource &evidence,
        ConsoleSessionChangeSource &changes,
        int timeoutMilliseconds = 0) noexcept;

    // Always terminal, including when called before observe() or twice.
    // Watch fd is borrowed and remains owned by the caller.
    void shutdown() noexcept;

    [[nodiscard]] ConsoleLifecycleState state() const noexcept
    {
        return boundary_.state();
    }

    [[nodiscard]] bool isShutDown() const noexcept { return shutDown_; }

private:
    ConsoleSessionCancellationBoundary boundary_{};
    int watchFd_{-1};
    short watchEvents_{};
    bool shutDown_{};
};

} // namespace rdp_server::server::security
