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

LinuxLogindSessionChangeSource::LinuxLogindSessionChangeSource() noexcept
{
#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    // Establish the watch before the first session sample. Watching NULL
    // means all categories: no missed logout due to over-narrow filtering.
    if (::sd_booted() > 0)
    {
        sd_login_monitor *source = nullptr;
        if (::sd_login_monitor_new(nullptr, &source) >= 0 &&
            source != nullptr)
        {
            monitor_ = source;
        }
        else if (source != nullptr)
        {
            ::sd_login_monitor_unref(source);
        }
    }
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
    if (monitor_ == nullptr)
    {
        return ConsoleSessionChange::Unavailable;
    }
    const int fd = ::sd_login_monitor_get_fd(monitor_);
    const int events = ::sd_login_monitor_get_events(monitor_);
    if (fd < 0 || events <= 0 ||
        events > std::numeric_limits<short>::max())
    {
        return ConsoleSessionChange::Unavailable;
    }

    pollfd descriptor{fd, static_cast<short>(events), 0};
    // Zero timeout, no worker. The caller drives polling synchronously,
    // including after any external event-loop wakeup.
    const int status = ::poll(&descriptor, 1, 0);
    if (status < 0)
    {
        return ConsoleSessionChange::Unavailable;
    }
    if (status == 0)
    {
        return ConsoleSessionChange::None;
    }
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
        (descriptor.revents & static_cast<short>(events)) == 0)
    {
        return ConsoleSessionChange::Unavailable;
    }

    // Reset kernel event readiness even when all we need is revocation.
    // Failed flush is itself a terminal uncertainty.
    return ::sd_login_monitor_flush(monitor_) >= 0
               ? ConsoleSessionChange::Changed
               : ConsoleSessionChange::Unavailable;
#else
    return ConsoleSessionChange::Unavailable;
#endif
}

} // namespace rdp_server::server::security
