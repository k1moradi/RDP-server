// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_session_lifecycle.h"

#include <cstdint>

namespace rdp_server::server::security
{

// Untrusted notification by itself grants no rights. A monitor must be
// established BEFORE its first candidate observation to reduce missed
// events. Notification failure is terminal for this candidate.
enum class ConsoleSessionChange : std::uint8_t
{
    None,
    Changed,
    Unavailable,
};

// Borrowed synchronous event source. A returned None says only that no
// notification was observed NOW, never that the seat remains locked.
// Implementations MUST fail closed on event queue errors and shutdown.
class ConsoleSessionChangeSource
{
public:
    virtual ~ConsoleSessionChangeSource() = default;
    ConsoleSessionChangeSource() = default;
    ConsoleSessionChangeSource(const ConsoleSessionChangeSource &) = delete;
    ConsoleSessionChangeSource &operator=(const ConsoleSessionChangeSource &) = delete;

    [[nodiscard]] virtual ConsoleSessionChange pollChange() noexcept = 0;
};

// No worker thread, callbacks, X11 resources, session permissions, GSS
// identity, or authorization. Caller must serialize the full sequence.
// Observe/check double-poll around a fresh M1.18 evidence check so an
// event delivered DURING the check invalidates the candidate too.
// The unavoidable check/use gap remains; this is not a session lease.
class ConsoleSessionCancellationBoundary final
{
public:
    ConsoleSessionCancellationBoundary() noexcept = default;
    ConsoleSessionCancellationBoundary(
        const ConsoleSessionCancellationBoundary &) = delete;
    ConsoleSessionCancellationBoundary &operator=(
        const ConsoleSessionCancellationBoundary &) = delete;

    [[nodiscard]] ConsoleLifecycleState observe(
        const ConsoleIdentityPolicy &policy,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &evidence,
        ConsoleSessionChangeSource &changes) noexcept;

    [[nodiscard]] ConsoleLifecycleState check(
        const ConsoleIdentityPolicy &policy,
        ConsoleOsEvidenceSource &evidence,
        ConsoleSessionChangeSource &changes) noexcept;

    // Event-loop wakeup entry point. Any state change, source failure,
    // or absent initial observation terminates the candidate.
    [[nodiscard]] ConsoleLifecycleState onWake(
        ConsoleSessionChangeSource &changes) noexcept;

    // Synchronous connection cancellation, including before observation.
    void cancel() noexcept { lifecycle_.revoke(); }

    [[nodiscard]] ConsoleLifecycleState state() const noexcept
    {
        return lifecycle_.state();
    }

private:
    [[nodiscard]] bool unchanged(ConsoleSessionChangeSource &changes) noexcept;

    ConsoleSessionLifecycleMonitor lifecycle_{};
};

} // namespace rdp_server::server::security
