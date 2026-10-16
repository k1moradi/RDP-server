// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_session_poll_dispatcher.h"

#include <cstdint>

namespace rdp_server::server::security
{

enum class ConsoleSupervisorExit : std::uint8_t
{
    Refused,           // Invalid monitor, changed session or OS failure.
    Cancelled,         // A cancellation notification was observed.
    StepBudgetReached, // Finite test budget ended; still terminally denied.
};

struct ConsoleSupervisorReport
{
    ConsoleSupervisorExit reason{ConsoleSupervisorExit::Refused};
    std::uint32_t completedChecks{};
};

// Linux-only, non-privileged, foreground, single-owner supervisor.
// This is deliberately NOT a background worker or privileged broker.
// The caller provides two BORROWED fds: a logind-style event source fd
// and an independent readable cancellation fd (e.g. a local pipe).
// Neither fd is read/closed/owned here; cancellation is level-triggered.
//
// run() owns the M1.20 dispatcher for a bounded sequence of polls and
// rechecks (1..128 iterations, 0..50 ms each). It ALWAYS shuts down and
// revokes the candidate before returning, including errors and timeouts.
// No callback runs untrusted code or performs desktop I/O; no token,
// GSS authentication, X11 permission, or authorized session is issued.
// A cancellation signal during synthetic evidence sampling is caught by
// the post-sampling control check. A later event can never retroactively
// cancel real I/O: live session admission is STILL permanently denied.
//
// Run/destroy on ONE thread only, with all borrowed sources serialized;
// to request cancellation from another thread, signal the caller-owned
// stop fd, NOT this instance. This is a finite integration harness,
// not a continuously deployed service or atomic revocation protocol.
class ForegroundConsoleSessionSupervisor final
{
public:
    ForegroundConsoleSessionSupervisor() noexcept = default;
    ForegroundConsoleSessionSupervisor(
        const ForegroundConsoleSessionSupervisor &) = delete;
    ForegroundConsoleSessionSupervisor &operator=(
        const ForegroundConsoleSessionSupervisor &) = delete;

    [[nodiscard]] ConsoleSupervisorReport run(
        const ConsoleIdentityPolicy &policy,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &evidence,
        ConsoleSessionChangeSource &changes,
        int changeFd, int changeEvents, int cancellationFd,
        std::uint32_t stepBudget, int timeoutMilliseconds = 0) noexcept;

    void shutdown() noexcept;

    [[nodiscard]] bool finished() const noexcept { return finished_; }

    [[nodiscard]] ConsoleLifecycleState state() const noexcept
    {
        return dispatcher_.state();
    }

private:
    ConsoleSessionPollDispatcher dispatcher_{};
    bool finished_{};
};

} // namespace rdp_server::server::security
