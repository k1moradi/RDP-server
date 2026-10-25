// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_session_change_watch.h"

#include <cstdint>
#include <string_view>

struct sd_login_monitor;

namespace rdp_server::server::security
{

enum class LinuxLogindMonitorState : std::uint8_t
{
    Unavailable,
    Unchanged,
    Changed,
};

[[nodiscard]] constexpr std::string_view linuxLogindMonitorStateName(
    LinuxLogindMonitorState state) noexcept
{
    switch (state)
    {
    case LinuxLogindMonitorState::Unavailable: return "unavailable";
    case LinuxLogindMonitorState::Unchanged: return "unchanged";
    case LinuxLogindMonitorState::Changed: return "changed";
    }
    return "unavailable";
}

struct LinuxLogindMonitorDiagnostics final
{
    bool systemdAvailable{};
    bool monitorCreated{};
    bool monitorAvailable{};
    bool descriptorAvailable{};
    bool eventsAvailable{};
    LinuxLogindMonitorState initialState{LinuxLogindMonitorState::Unavailable};
    bool initialFlushSucceeded{};
    LinuxLogindMonitorState baselineState{LinuxLogindMonitorState::Unavailable};
};

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
    [[nodiscard]] const LinuxLogindMonitorDiagnostics&
    diagnostics() const noexcept
    {
        return diagnostics_;
    }

private:
    sd_login_monitor *monitor_{};
    LinuxLogindMonitorDiagnostics diagnostics_{};
};

} // namespace rdp_server::server::security
