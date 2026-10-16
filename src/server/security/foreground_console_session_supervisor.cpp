// SPDX-License-Identifier: GPL-3.0-or-later
#include "foreground_console_session_supervisor.h"

#include <poll.h>

namespace rdp_server::server::security
{
namespace
{

inline constexpr std::uint32_t kMaximumSupervisorSteps = 128;
inline constexpr int kMaximumSupervisorWaitMilliseconds = 50;

enum class CancellationObservation : std::uint8_t
{
    Quiet,
    Requested,
    Invalid,
};

[[nodiscard]] CancellationObservation checkCancellationFd(int fd) noexcept
{
    if (fd < 0)
    {
        return CancellationObservation::Invalid;
    }
    pollfd cancellation{fd, POLLIN, 0};
    const int result = ::poll(&cancellation, 1, 0);
    if (result == 0)
    {
        return CancellationObservation::Quiet;
    }
    if (result != 1 ||
        (cancellation.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
        (cancellation.revents & ~static_cast<int>(
            POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
    {
        return CancellationObservation::Invalid;
    }
    return (cancellation.revents & POLLIN) != 0
               ? CancellationObservation::Requested
               : CancellationObservation::Invalid;
}

} // namespace

ConsoleSupervisorReport ForegroundConsoleSessionSupervisor::run(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &evidence,
    ConsoleSessionChangeSource &changes,
    int changeFd, int changeEvents, int cancellationFd,
    std::uint32_t stepBudget, int timeoutMilliseconds) noexcept
{
    if (finished_)
    {
        return {}; // Never re-run a terminated supervisor.
    }
    finished_ = true; // This object cannot be restarted after this call.

    ConsoleSupervisorReport report{};
    if (changeFd < 0 || cancellationFd < 0 ||
        changeFd == cancellationFd ||
        stepBudget == 0 || stepBudget > kMaximumSupervisorSteps ||
        timeoutMilliseconds < 0 ||
        timeoutMilliseconds > kMaximumSupervisorWaitMilliseconds)
    {
        shutdown();
        return report;
    }

    // Check control BEFORE adopting any candidate (the dispatcher also
    // refuses a pre-signaled, invalid or hung-up change watch).
    const auto initialControl = checkCancellationFd(cancellationFd);
    if (initialControl != CancellationObservation::Quiet)
    {
        report.reason = initialControl == CancellationObservation::Requested
                            ? ConsoleSupervisorExit::Cancelled
                            : ConsoleSupervisorExit::Refused;
        shutdown();
        return report;
    }

    const auto observed = dispatcher_.observe(
        policy, request, evidence, changes, changeFd, changeEvents);
    // A cancellation arriving DURING initial account/session reads is
    // still observed before entering any subsequent dispatch step.
    const auto postObserveControl = checkCancellationFd(cancellationFd);
    if (postObserveControl != CancellationObservation::Quiet)
    {
        report.reason = postObserveControl == CancellationObservation::Requested
                            ? ConsoleSupervisorExit::Cancelled
                            : ConsoleSupervisorExit::Refused;
        shutdown();
        return report;
    }
    if (observed != ConsoleLifecycleState::CandidateOnly)
    {
        shutdown();
        return report;
    }

    for (std::uint32_t step = 0; step < stepBudget; ++step)
    {
        // Poll the caller-owned cancellation channel before and after
        // EVERY M1.20 step. This can catch cancellation during the
        // synthetic OS evidence probe, but is not an atomic I/O lease.
        const auto before = checkCancellationFd(cancellationFd);
        if (before != CancellationObservation::Quiet)
        {
            report.reason = before == CancellationObservation::Requested
                                ? ConsoleSupervisorExit::Cancelled
                                : ConsoleSupervisorExit::Refused;
            shutdown();
            return report;
        }

        const auto state = dispatcher_.pumpOnce(
            policy, evidence, changes, timeoutMilliseconds);

        const auto after = checkCancellationFd(cancellationFd);
        if (after != CancellationObservation::Quiet)
        {
            report.reason = after == CancellationObservation::Requested
                                ? ConsoleSupervisorExit::Cancelled
                                : ConsoleSupervisorExit::Refused;
            shutdown();
            return report;
        }
        if (state != ConsoleLifecycleState::CandidateOnly)
        {
            shutdown();
            return report;
        }
        ++report.completedChecks;
    }

    // A finite test budget never turns into continued remote access.
    report.reason = ConsoleSupervisorExit::StepBudgetReached;
    shutdown();
    return report;
}

void ForegroundConsoleSessionSupervisor::shutdown() noexcept
{
    finished_ = true;
    dispatcher_.shutdown(); // Idempotent terminal denial, does NOT close fd.
}

} // namespace rdp_server::server::security
