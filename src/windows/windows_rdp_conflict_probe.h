// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace rdp_server::windows
{

enum class WindowsRdpConflictStatus : std::uint8_t
{
    Unavailable,
    Clear,
    TermServiceActive,
    RequestedPortInUse,
};

struct WindowsRdpConflictObservation final
{
    bool termServiceObserved{};
    bool termServiceActive{};
    bool requestedPortObserved{};
    bool requestedPortInUse{};
};

[[nodiscard]] constexpr WindowsRdpConflictStatus classifyWindowsRdpConflict(
    const WindowsRdpConflictObservation &observation) noexcept
{
    if (!observation.termServiceObserved)
        return WindowsRdpConflictStatus::Unavailable;
    if (observation.termServiceActive)
        return WindowsRdpConflictStatus::TermServiceActive;
    if (!observation.requestedPortObserved)
        return WindowsRdpConflictStatus::Unavailable;
    return observation.requestedPortInUse
        ? WindowsRdpConflictStatus::RequestedPortInUse
        : WindowsRdpConflictStatus::Clear;
}

// Read-only host preflight. It observes the existing Windows Remote Desktop
// service and TCP listener tables but never binds a socket or mutates service,
// firewall, registry or Remote Desktop configuration.
class WindowsRdpConflictProbe final
{
public:
    [[nodiscard]] WindowsRdpConflictStatus probe(
        std::uint16_t requestedPort) const noexcept;
};

} // namespace rdp_server::windows
