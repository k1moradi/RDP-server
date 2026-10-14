// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_session_change_watch.h"

namespace rdp_server::server::security
{

bool ConsoleSessionCancellationBoundary::unchanged(
    ConsoleSessionChangeSource &changes) noexcept
{
    if (changes.pollChange() != ConsoleSessionChange::None)
    {
        lifecycle_.revoke();
        return false;
    }
    return true;
}

ConsoleLifecycleState ConsoleSessionCancellationBoundary::observe(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &evidence,
    ConsoleSessionChangeSource &changes) noexcept
{
    if (lifecycle_.state() != ConsoleLifecycleState::NotObserved)
    {
        // Re-observation is not a refresh: refusing it prevents callers
        // from bypassing a fresh check() and its event-source sampling.
        if (lifecycle_.state() == ConsoleLifecycleState::CandidateOnly)
        {
            lifecycle_.revoke();
        }
        return lifecycle_.state();
    }
    if (!unchanged(changes))
    {
        return lifecycle_.state();
    }
    if (lifecycle_.observe(policy, request, evidence) !=
        ConsoleLifecycleState::CandidateOnly)
    {
        return lifecycle_.state();
    }
    // An event between the initial probe and this final poll revokes.
    (void)unchanged(changes);
    return lifecycle_.state();
}

ConsoleLifecycleState ConsoleSessionCancellationBoundary::check(
    const ConsoleIdentityPolicy &policy,
    ConsoleOsEvidenceSource &evidence,
    ConsoleSessionChangeSource &changes) noexcept
{
    if (lifecycle_.state() != ConsoleLifecycleState::CandidateOnly)
    {
        lifecycle_.revoke();
        return lifecycle_.state();
    }
    if (!unchanged(changes))
    {
        return lifecycle_.state();
    }
    if (lifecycle_.revalidate(policy, evidence) !=
        ConsoleLifecycleState::CandidateOnly)
    {
        return lifecycle_.state();
    }
    // Recheck notification delivery after the read-only OS sampling.
    (void)unchanged(changes);
    return lifecycle_.state();
}

ConsoleLifecycleState ConsoleSessionCancellationBoundary::onWake(
    ConsoleSessionChangeSource &changes) noexcept
{
    if (lifecycle_.state() == ConsoleLifecycleState::Revoked)
    {
        return lifecycle_.state(); // No further platform calls.
    }
    // Event callbacks do not open any session or extend a lease.
    // A spurious wake with no data is harmless; a real event revokes.
    if (lifecycle_.state() == ConsoleLifecycleState::NotObserved)
    {
        lifecycle_.revoke(); // Wake before initialization is fail-closed.
    }
    else
    {
        (void)unchanged(changes);
    }
    return lifecycle_.state();
}

} // namespace rdp_server::server::security
