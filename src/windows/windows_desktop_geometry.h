// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/rectangle.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::windows
{

// WinGDI also exports a function named Rectangle. Bind the portable type
// by elaborated type so including windows.h first cannot hide it.
using PortableRectangle = struct ::Rectangle;

inline constexpr std::size_t kMaximumWindowsDesktopMonitors = 16;

struct WindowsDesktopPoint
{
    std::uint32_t x{};
    std::uint32_t y{};

    friend bool operator==(const WindowsDesktopPoint &,
                           const WindowsDesktopPoint &) = default;
};

struct WindowsNativePoint
{
    std::int32_t x{};
    std::int32_t y{};

    friend bool operator==(const WindowsNativePoint &,
                           const WindowsNativePoint &) = default;
};

// Monitor and virtual bounds use the existing portable Rectangle contract:
// signed native virtual-desktop origins, unsigned sizes, exclusive right/bottom.
// The array is owned and bounded; no Win32 types cross the adapter boundary.
struct WindowsDesktopLayout
{
    PortableRectangle virtualBounds{};
    std::array<PortableRectangle, kMaximumWindowsDesktopMonitors> monitors{};
    std::size_t monitorCount{};

    // Canonical monitor order makes equality a stable topology-change test.
    friend bool operator==(const WindowsDesktopLayout &,
                           const WindowsDesktopLayout &) = default;
};

// Native monitor identity is a borrowed HMONITOR encoded without ownership.
// The identity and rectangle must come from the same synchronous enumeration.
struct WindowsNativeMonitorSnapshot
{
    std::uintptr_t monitor{};
    PortableRectangle bounds{};
};

struct WindowsSingleMonitorDesktopTarget
{
    WindowsDesktopLayout layout{};
    std::uintptr_t monitor{};
};

// R6 currently owns one DXGI duplication output. Keep that constraint explicit
// so a rectangle alone can never be substituted for HMONITOR identity.
[[nodiscard]] bool makeWindowsSingleMonitorDesktopTarget(
    std::span<const WindowsNativeMonitorSnapshot> nativeMonitors,
    WindowsSingleMonitorDesktopTarget &output) noexcept;

// Validates all monitor rectangles, sorts them into a stable order, computes
// their bounding virtual desktop, and leaves output unchanged on failure. The display
// snapshot is not an OS-access permission, and does not outlive layout changes.
[[nodiscard]] bool makeWindowsDesktopLayout(
    std::span<const PortableRectangle> nativeMonitorBounds,
    WindowsDesktopLayout &output) noexcept;

// Reject coordinates in gaps between monitors, including the bounding
// rectangle's otherwise-unoccupied pixels. Callers must resample after a
// topology change. No clipping or input injection occurs here.
[[nodiscard]] std::optional<WindowsDesktopPoint> nativeToDesktopPoint(
    const WindowsDesktopLayout &layout, WindowsNativePoint point) noexcept;

[[nodiscard]] std::optional<WindowsNativePoint> desktopToNativePoint(
    const WindowsDesktopLayout &layout, WindowsDesktopPoint point) noexcept;

// Read-only EnumDisplayMonitors/GetMonitorInfoW sampling of the current
// calling thread's display context. It neither changes desktop/session nor
// proves an RDP user is authorized. No desktop is captured or input injected.
// Returns false and does not modify output on API/geometry failures.
[[nodiscard]] bool readWindowsDesktopLayout(
    WindowsDesktopLayout &output) noexcept;

[[nodiscard]] bool readWindowsSingleMonitorDesktopTarget(
    WindowsSingleMonitorDesktopTarget &output) noexcept;

} // namespace rdp_server::windows
