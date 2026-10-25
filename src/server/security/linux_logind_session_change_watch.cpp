// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_logind_session_change_watch.h"

#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
#include <systemd/sd-daemon.h>
#include <systemd/sd-login.h>

#include <limits>
#include <poll.h>
#endif

namespace rdp_server::server::security
{
namespace
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
[[nodiscard]] LinuxLogindMonitorState observeMonitor(
    sd_login_monitor *monitor) noexcept
{
    if (monitor == nullptr)
        return LinuxLogindMonitorState::Unavailable;
    const int fd = ::sd_login_monitor_get_fd(monitor);
    const int events = ::sd_login_monitor_get_events(monitor);
    if (fd < 0 || events <= 0 ||
        events > std::numeric_limits<short>::max())
        return LinuxLogindMonitorState::Unavailable;

    pollfd descriptor{fd, static_cast<short>(events), 0};
    const int status = ::poll(&descriptor, 1, 0);
    if (status < 0)
        return LinuxLogindMonitorState::Unavailable;
    if (status == 0)
        return LinuxLogindMonitorState::Unchanged;
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
        (descriptor.revents & static_cast<short>(events)) == 0)
        return LinuxLogindMonitorState::Unavailable;
    return LinuxLogindMonitorState::Changed;
}
#endif
} // namespace

LinuxLogindSessionChangeSource::LinuxLogindSessionChangeSource() noexcept
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    // Establish the watch before the first session sample. Watching NULL
    // means all categories: no missed logout due to over-narrow filtering.
    diagnostics_.systemdAvailable = ::sd_booted() > 0;
    if (!diagnostics_.systemdAvailable)
        return;

    sd_login_monitor *source = nullptr;
    if (::sd_login_monitor_new(nullptr, &source) < 0 || source == nullptr)
    {
        if (source != nullptr)
            ::sd_login_monitor_unref(source);
        return;
    }

    diagnostics_.monitorCreated = true;
    monitor_ = source;
    const int fd = ::sd_login_monitor_get_fd(monitor_);
    const int events = ::sd_login_monitor_get_events(monitor_);
    diagnostics_.descriptorAvailable = fd >= 0;
    diagnostics_.eventsAvailable =
        events > 0 && events <= std::numeric_limits<short>::max();
    diagnostics_.initialState = observeMonitor(monitor_);
    if (!diagnostics_.descriptorAvailable ||
        !diagnostics_.eventsAvailable ||
        diagnostics_.initialState == LinuxLogindMonitorState::Unavailable)
    {
        monitor_ = ::sd_login_monitor_unref(monitor_);
        return;
    }

    // A monitor can carry readiness accumulated before there is an admission
    // candidate to protect. Flush exactly once before the first candidate,
    // then preserve every later wake for normal revocation.
    diagnostics_.initialFlushSucceeded =
        ::sd_login_monitor_flush(monitor_) >= 0;
    if (!diagnostics_.initialFlushSucceeded)
    {
        monitor_ = ::sd_login_monitor_unref(monitor_);
        return;
    }
    diagnostics_.baselineState = observeMonitor(monitor_);
    if (diagnostics_.baselineState == LinuxLogindMonitorState::Unavailable)
    {
        monitor_ = ::sd_login_monitor_unref(monitor_);
        return;
    }
    diagnostics_.monitorAvailable = true;
#endif
}

LinuxLogindSessionChangeSource::~LinuxLogindSessionChangeSource()
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    if (monitor_ != nullptr)
    {
        monitor_ = ::sd_login_monitor_unref(monitor_);
    }
#endif
}

int LinuxLogindSessionChangeSource::nativeFd() const noexcept
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    return monitor_ != nullptr ? ::sd_login_monitor_get_fd(monitor_) : -1;
#else
    return -1;
#endif
}

int LinuxLogindSessionChangeSource::nativeEvents() const noexcept
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    return monitor_ != nullptr ? ::sd_login_monitor_get_events(monitor_) : -1;
#else
    return -1;
#endif
}

ConsoleSessionChange LinuxLogindSessionChangeSource::pollChange() noexcept
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    const LinuxLogindMonitorState state = observeMonitor(monitor_);
    if (state == LinuxLogindMonitorState::Unavailable)
        return ConsoleSessionChange::Unavailable;
    if (state == LinuxLogindMonitorState::Unchanged)
        return ConsoleSessionChange::None;

    // Reset event readiness after reporting a real post-baseline change.
    return ::sd_login_monitor_flush(monitor_) >= 0
               ? ConsoleSessionChange::Changed
               : ConsoleSessionChange::Unavailable;
#else
    return ConsoleSessionChange::Unavailable;
#endif
}

} // namespace rdp_server::server::security
