// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_session_poll_dispatcher.h"

#include <poll.h>

namespace rdp_server::server::security
{
namespace
{

inline constexpr int kMaximumPollTimeoutMilliseconds = 250;
inline constexpr int kSupportedReadiness = POLLIN | POLLPRI;
inline constexpr int kInvalidReadiness = POLLERR | POLLHUP | POLLNVAL;

} // namespace

ConsoleLifecycleState ConsoleSessionPollDispatcher::observe(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &evidence,
    ConsoleSessionChangeSource &changes,
    int watchFd, int watchEvents) noexcept
{
    if (shutDown_ || boundary_.state() != ConsoleLifecycleState::NotObserved ||
        watchFd < 0 || (watchEvents & kSupportedReadiness) == 0 ||
        (watchEvents & ~kSupportedReadiness) != 0)
    {
        boundary_.cancel();
        return boundary_.state();
    }

    // Refuse invalid, already-hung-up or already-ready monitors BEFORE
    // adopting a candidate. The watch must be established and quiet
    // before initial OS sampling; queued changes cannot be skipped.
    pollfd initial{watchFd, static_cast<short>(watchEvents), 0};
    if (::poll(&initial, 1, 0) != 0 || initial.revents != 0)
    {
        boundary_.cancel();
        return boundary_.state();
    }

    watchFd_ = watchFd;
    watchEvents_ = static_cast<short>(watchEvents);
    // The existing M1.19 boundary brackets the first evidence read with
    // two synchronous event checks. A queued event revokes immediately.
    return boundary_.observe(policy, request, evidence, changes);
}

ConsoleLifecycleState ConsoleSessionPollDispatcher::pumpOnce(
    const ConsoleIdentityPolicy &policy,
    ConsoleOsEvidenceSource &evidence,
    ConsoleSessionChangeSource &changes,
    int timeoutMilliseconds) noexcept
{
    if (shutDown_ || boundary_.state() != ConsoleLifecycleState::CandidateOnly)
    {
        boundary_.cancel();
        return boundary_.state();
    }
    if (timeoutMilliseconds < 0 ||
        timeoutMilliseconds > kMaximumPollTimeoutMilliseconds)
    {
        boundary_.cancel();
        return boundary_.state();
    }

    pollfd watcher{watchFd_, watchEvents_, 0};
    const int ready = ::poll(&watcher, 1, timeoutMilliseconds);
    if (ready < 0 || ready > 1)
    {
        // EINTR is also terminal: no unchecked continuation after a signal.
        boundary_.cancel();
        return boundary_.state();
    }

    if (ready == 1)
    {
        if ((watcher.revents & kInvalidReadiness) != 0 ||
            (watcher.revents & watchEvents_) == 0 ||
            (watcher.revents & ~static_cast<int>(watchEvents_ |
                                                kInvalidReadiness)) != 0)
        {
            boundary_.cancel();
            return boundary_.state();
        }
        // The wake may be spurious. The M1.19 source classifies its own
        // notification and will revoke on Changed or Unavailable.
        if (boundary_.onWake(changes) != ConsoleLifecycleState::CandidateOnly)
        {
            return boundary_.state();
        }
    }

    // Also revalidate on timeout or spurious wake; bracket the OS
    // sampling with event checks to reject changes delivered DURING it.
    return boundary_.check(policy, evidence, changes);
}

void ConsoleSessionPollDispatcher::shutdown() noexcept
{
    shutDown_ = true;
    boundary_.cancel();
    watchFd_ = -1; // Never close the borrowed descriptor.
    watchEvents_ = 0;
}

} // namespace rdp_server::server::security
