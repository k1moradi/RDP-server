// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_rdp_conflict_probe.h"

#include <cassert>

using namespace rdp_server::windows;

void windowsRdpConflictTermServiceActiveDenial()
{
    constexpr WindowsRdpConflictObservation observation{
        .termServiceObserved = true,
        .termServiceActive = true,
        .requestedPortObserved = false,
        .requestedPortInUse = false,
    };
    static_assert(classifyWindowsRdpConflict(observation) ==
                  WindowsRdpConflictStatus::TermServiceActive);
}

void windowsRdpConflictRequestedPortOccupiedDenial()
{
    constexpr WindowsRdpConflictObservation observation{
        .termServiceObserved = true,
        .termServiceActive = false,
        .requestedPortObserved = true,
        .requestedPortInUse = true,
    };
    static_assert(classifyWindowsRdpConflict(observation) ==
                  WindowsRdpConflictStatus::RequestedPortInUse);
}

void windowsRdpConflictObservationUnavailableDenial()
{
    constexpr WindowsRdpConflictObservation missingService{
        .termServiceObserved = false,
    };
    constexpr WindowsRdpConflictObservation missingPort{
        .termServiceObserved = true,
        .termServiceActive = false,
        .requestedPortObserved = false,
    };
    static_assert(classifyWindowsRdpConflict(missingService) ==
                  WindowsRdpConflictStatus::Unavailable);
    static_assert(classifyWindowsRdpConflict(missingPort) ==
                  WindowsRdpConflictStatus::Unavailable);
}

void windowsRdpConflictClearPreflight()
{
    constexpr WindowsRdpConflictObservation observation{
        .termServiceObserved = true,
        .termServiceActive = false,
        .requestedPortObserved = true,
        .requestedPortInUse = false,
    };
    static_assert(classifyWindowsRdpConflict(observation) ==
                  WindowsRdpConflictStatus::Clear);
}

void windowsRdpConflictNativeReadonlyObservation()
{
    WindowsRdpConflictProbe probe;
    assert(probe.probe(0) == WindowsRdpConflictStatus::Unavailable);

    const auto status = probe.probe(3389);
    assert(status == WindowsRdpConflictStatus::Unavailable ||
           status == WindowsRdpConflictStatus::Clear ||
           status == WindowsRdpConflictStatus::TermServiceActive ||
           status == WindowsRdpConflictStatus::RequestedPortInUse);
}
