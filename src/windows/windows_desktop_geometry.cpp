// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_desktop_geometry.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <tuple>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rdp_server::windows
{
namespace
{

struct WideRectangle
{
    std::int64_t left{};
    std::int64_t top{};
    std::int64_t right{};
    std::int64_t bottom{};
};

[[nodiscard]] bool checkedMonitorBounds(
    PortableRectangle rectangle, WideRectangle &bounds) noexcept
{
    if (rectangle.widthPixels == 0 || rectangle.heightPixels == 0)
    {
        return false;
    }
    const std::int64_t right =
        static_cast<std::int64_t>(rectangle.x) + rectangle.widthPixels;
    const std::int64_t bottom =
        static_cast<std::int64_t>(rectangle.y) + rectangle.heightPixels;
    // Win32 RECT edges are signed LONGs. Reject impossible native edges,
    // not merely arithmetic overflow or a nonsensical enormous layout.
    if (right > std::numeric_limits<std::int32_t>::max() ||
        bottom > std::numeric_limits<std::int32_t>::max())
    {
        return false;
    }
    bounds = {rectangle.x, rectangle.y, right, bottom};
    return true;
}

[[nodiscard]] bool pointInMonitor(const WindowsDesktopLayout &layout,
                                  std::int64_t x, std::int64_t y) noexcept
{
    if (layout.monitorCount == 0 ||
        layout.monitorCount > layout.monitors.size())
    {
        return false;
    }
    bool insideMonitor = false;
    for (std::size_t index = 0; index < layout.monitorCount; ++index)
    {
        WideRectangle monitor{};
        if (!checkedMonitorBounds(layout.monitors[index], monitor))
        {
            return false;
        }
        if (x >= monitor.left && x < monitor.right &&
            y >= monitor.top && y < monitor.bottom)
        {
            insideMonitor = true;
        }
    }
    return insideMonitor;
}

#ifdef _WIN32
struct MonitorEnumerator
{
    std::array<PortableRectangle, kMaximumWindowsDesktopMonitors> monitors{};
    std::array<WindowsNativeMonitorSnapshot, kMaximumWindowsDesktopMonitors>
        nativeMonitors{};
    std::size_t count{};
    bool failed{};
};

BOOL CALLBACK enumerateMonitor(HMONITOR nativeMonitor, HDC, LPRECT,
                               LPARAM context) noexcept
{
    // Win32 callbacks have one opaque LPARAM; the pointer is borrowed only
    // during the synchronous EnumDisplayMonitors call on this same thread.
    auto &enumerator = *reinterpret_cast<MonitorEnumerator *>(context);
    if (enumerator.count == enumerator.monitors.size())
    {
        enumerator.failed = true;
        return FALSE;
    }

    MONITORINFO info{};
    info.cbSize = static_cast<DWORD>(sizeof(info));
    if (!GetMonitorInfoW(nativeMonitor, &info))
    {
        enumerator.failed = true;
        return FALSE;
    }

    const auto &bounds = info.rcMonitor;
    const std::int64_t width =
        static_cast<std::int64_t>(bounds.right) - bounds.left;
    const std::int64_t height =
        static_cast<std::int64_t>(bounds.bottom) - bounds.top;
    if (width <= 0 || height <= 0 ||
        width > std::numeric_limits<std::uint32_t>::max() ||
        height > std::numeric_limits<std::uint32_t>::max())
    {
        enumerator.failed = true;
        return FALSE;
    }

    const PortableRectangle rectangle{
        bounds.left, bounds.top, static_cast<std::uint32_t>(width),
        static_cast<std::uint32_t>(height)};
    enumerator.monitors[enumerator.count] = rectangle;
    enumerator.nativeMonitors[enumerator.count] = {
        reinterpret_cast<std::uintptr_t>(nativeMonitor), rectangle};
    ++enumerator.count;
    return TRUE;
}
#endif

} // namespace

bool makeWindowsSingleMonitorDesktopTarget(
    std::span<const WindowsNativeMonitorSnapshot> nativeMonitors,
    WindowsSingleMonitorDesktopTarget &output) noexcept
{
    if (nativeMonitors.size() != 1 || nativeMonitors.front().monitor == 0)
        return false;

    WindowsDesktopLayout layout{};
    const PortableRectangle bounds = nativeMonitors.front().bounds;
    if (!makeWindowsDesktopLayout(std::span{&bounds, 1U}, layout) ||
        layout.monitorCount != 1 || layout.virtualBounds != bounds ||
        layout.monitors[0] != bounds)
    {
        return false;
    }

    WindowsSingleMonitorDesktopTarget candidate{};
    candidate.layout = layout;
    candidate.monitor = nativeMonitors.front().monitor;
    output = candidate;
    return true;
}

bool makeWindowsDesktopLayout(std::span<const PortableRectangle> nativeMonitorBounds,
                              WindowsDesktopLayout &output) noexcept
{
    if (nativeMonitorBounds.empty() ||
        nativeMonitorBounds.size() > kMaximumWindowsDesktopMonitors)
    {
        return false;
    }

    WideRectangle first{};
    if (!checkedMonitorBounds(nativeMonitorBounds.front(), first))
    {
        return false;
    }
    std::int64_t minimumX = first.left;
    std::int64_t minimumY = first.top;
    std::int64_t maximumX = first.right;
    std::int64_t maximumY = first.bottom;

    // Compute in 64 bits before narrowing. Win32 monitor coordinates can be
    // negative, and multi-monitor unions may be wider than a signed LONG.
    for (const PortableRectangle rectangle : nativeMonitorBounds.subspan(1))
    {
        WideRectangle current{};
        if (!checkedMonitorBounds(rectangle, current))
        {
            return false;
        }
        minimumX = (std::min)(minimumX, current.left);
        minimumY = (std::min)(minimumY, current.top);
        maximumX = (std::max)(maximumX, current.right);
        maximumY = (std::max)(maximumY, current.bottom);
    }
    const std::int64_t width = maximumX - minimumX;
    const std::int64_t height = maximumY - minimumY;
    if (width <= 0 || height <= 0 ||
        width > std::numeric_limits<std::uint32_t>::max() ||
        height > std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }

    WindowsDesktopLayout candidate{};
    candidate.virtualBounds = {static_cast<std::int32_t>(minimumX),
                               static_cast<std::int32_t>(minimumY),
                               static_cast<std::uint32_t>(width),
                               static_cast<std::uint32_t>(height)};
    candidate.monitorCount = nativeMonitorBounds.size();
    std::copy(nativeMonitorBounds.begin(), nativeMonitorBounds.end(),
              candidate.monitors.begin());
    // Win32 does not promise monitor callback order. A canonical snapshot
    // avoids spurious display-resize events when enumeration is reordered.
    std::sort(candidate.monitors.begin(),
              candidate.monitors.begin() + candidate.monitorCount,
              [](const PortableRectangle &left, const PortableRectangle &right) noexcept {
                  return std::tie(left.x, left.y, left.widthPixels,
                                  left.heightPixels) <
                         std::tie(right.x, right.y, right.widthPixels,
                                  right.heightPixels);
              });
    output = candidate;
    return true;
}

std::optional<WindowsDesktopPoint> nativeToDesktopPoint(
    const WindowsDesktopLayout &layout, WindowsNativePoint point) noexcept
{
    const std::int64_t translatedX =
        static_cast<std::int64_t>(point.x) - layout.virtualBounds.x;
    const std::int64_t translatedY =
        static_cast<std::int64_t>(point.y) - layout.virtualBounds.y;
    if (translatedX < 0 || translatedY < 0 ||
        static_cast<std::uint64_t>(translatedX) >=
            layout.virtualBounds.widthPixels ||
        static_cast<std::uint64_t>(translatedY) >=
            layout.virtualBounds.heightPixels ||
        !pointInMonitor(layout, point.x, point.y))
    {
        return std::nullopt;
    }
    return WindowsDesktopPoint{static_cast<std::uint32_t>(translatedX),
                               static_cast<std::uint32_t>(translatedY)};
}

std::optional<WindowsNativePoint> desktopToNativePoint(
    const WindowsDesktopLayout &layout, WindowsDesktopPoint point) noexcept
{
    if (point.x >= layout.virtualBounds.widthPixels ||
        point.y >= layout.virtualBounds.heightPixels)
    {
        return std::nullopt;
    }
    const std::int64_t translatedX =
        static_cast<std::int64_t>(layout.virtualBounds.x) + point.x;
    const std::int64_t translatedY =
        static_cast<std::int64_t>(layout.virtualBounds.y) + point.y;
    if (translatedX > std::numeric_limits<std::int32_t>::max() ||
        translatedY > std::numeric_limits<std::int32_t>::max() ||
        !pointInMonitor(layout, translatedX, translatedY))
    {
        return std::nullopt;
    }
    return WindowsNativePoint{static_cast<std::int32_t>(translatedX),
                              static_cast<std::int32_t>(translatedY)};
}

bool readWindowsDesktopLayout(WindowsDesktopLayout &output) noexcept
{
#ifdef _WIN32
    MonitorEnumerator enumerator{};
    if (!EnumDisplayMonitors(nullptr, nullptr, enumerateMonitor,
                             reinterpret_cast<LPARAM>(&enumerator)) ||
        enumerator.failed)
    {
        return false;
    }
    return makeWindowsDesktopLayout(
        std::span<const PortableRectangle>(enumerator.monitors.data(),
                                   enumerator.count),
        output);
#else
    (void)output;
    return false;
#endif
}

bool readWindowsSingleMonitorDesktopTarget(
    WindowsSingleMonitorDesktopTarget &output) noexcept
{
#ifdef _WIN32
    MonitorEnumerator enumerator{};
    if (!EnumDisplayMonitors(nullptr, nullptr, enumerateMonitor,
                             reinterpret_cast<LPARAM>(&enumerator)) ||
        enumerator.failed)
    {
        return false;
    }
    return makeWindowsSingleMonitorDesktopTarget(
        std::span<const WindowsNativeMonitorSnapshot>{
            enumerator.nativeMonitors.data(), enumerator.count},
        output);
#else
    (void)output;
    return false;
#endif
}

} // namespace rdp_server::windows
