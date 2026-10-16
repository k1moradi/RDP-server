// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_session_change_watch.h"

struct sd_login_monitor;

namespace rdp_server::server::security
{

// Linux-only, read-only RAII wrapper around sd_login_monitor_new(NULL).
// Watches all logind seat/user/session changes conservatively; any
// notification revokes the active candidate, regardless of the actor.
// The caller's existing event loop MAY watch nativeFd(), then invoke
// ConsoleSessionCancellationBoundary::onWake() on readiness. No thread
// or host service is started. This class does not authenticate a user.
// A missing libsystemd or missing/inaccessible logind returns Unavailable.
class LinuxLogindSessionChangeSource final : public ConsoleSessionChangeSource
{
public:
    LinuxLogindSessionChangeSource() noexcept;
    ~LinuxLogindSessionChangeSource() override;

    LinuxLogindSessionChangeSource(
        const LinuxLogindSessionChangeSource &) = delete;
    LinuxLogindSessionChangeSource &operator=(
        const LinuxLogindSessionChangeSource &) = delete;

    [[nodiscard]] int nativeFd() const noexcept;
    // Poll mask for the fd above, as published by libsystemd. Both return
    // negative values when the watch is unavailable; never own/close fd.
    [[nodiscard]] int nativeEvents() const noexcept;
    [[nodiscard]] ConsoleSessionChange pollChange() noexcept override;

private:
    sd_login_monitor *monitor_{};
};

} // namespace rdp_server::server::security
