// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_damage.h"

#include <algorithm>
#include <array>
#include <limits>

namespace rdp_server::windows
{
namespace
{

[[nodiscard]] bool checkedRectangle(
    WindowsDxgiRectangle nativeRectangle, PixelSize bounds,
    Rectangle &rectangle) noexcept
{
    // RECT uses exclusive right/bottom. Reject malformed native metadata
    // rather than silently clipping, which could hide a stale DXGI surface.
    if (nativeRectangle.left < 0 || nativeRectangle.top < 0 ||
        nativeRectangle.right <= nativeRectangle.left ||
        nativeRectangle.bottom <= nativeRectangle.top ||
        static_cast<std::uint32_t>(nativeRectangle.right) > bounds.widthPixels ||
        static_cast<std::uint32_t>(nativeRectangle.bottom) > bounds.heightPixels)
    {
        return false;
    }

    rectangle = {
        nativeRectangle.left, nativeRectangle.top,
        static_cast<std::uint32_t>(nativeRectangle.right - nativeRectangle.left),
        static_cast<std::uint32_t>(nativeRectangle.bottom - nativeRectangle.top)};
    return true;
}

} // namespace

bool normalizeWindowsDxgiDamage(
    PixelSize outputDimensions,
    std::span<const WindowsDxgiMoveRectangle> moveRectangles,
    std::span<const WindowsDxgiRectangle> dirtyRectangles,
    std::span<Rectangle> destination,
    std::size_t &writtenCount) noexcept
{
    // The shared Rectangle format uses signed 32-bit origins. Reject
    // nonrepresentable output coordinates before making R4 rectangles.
    constexpr std::uint32_t maximumCoordinate =
        static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max());
    if (outputDimensions.widthPixels == 0 ||
        outputDimensions.heightPixels == 0 ||
        outputDimensions.widthPixels > maximumCoordinate ||
        outputDimensions.heightPixels > maximumCoordinate ||
        moveRectangles.size() > kMaximumWindowsDxgiDamageRectangles ||
        dirtyRectangles.size() >
            kMaximumWindowsDxgiDamageRectangles - moveRectangles.size())
    {
        return false;
    }

    const std::size_t rectangleCount =
        moveRectangles.size() + dirtyRectangles.size();
    if (destination.size() < rectangleCount)
    {
        return false;
    }

    // One finite stack buffer supports aliased input/output spans and avoids
    // partial published damage on a late malformed dirty or move rectangle.
    std::array<Rectangle, kMaximumWindowsDxgiDamageRectangles> normalized{};
    std::size_t nextIndex = 0;
    for (const WindowsDxgiMoveRectangle &move : moveRectangles)
    {
        Rectangle destinationRectangle{};
        if (!checkedRectangle(move.destination, outputDimensions,
                              destinationRectangle) ||
            move.source.x < 0 || move.source.y < 0 ||
            static_cast<std::uint32_t>(move.source.x) >
                outputDimensions.widthPixels - destinationRectangle.widthPixels ||
            static_cast<std::uint32_t>(move.source.y) >
                outputDimensions.heightPixels - destinationRectangle.heightPixels)
        {
            return false;
        }
        normalized[nextIndex++] = destinationRectangle;
    }
    for (const WindowsDxgiRectangle dirty : dirtyRectangles)
    {
        Rectangle rectangle{};
        if (!checkedRectangle(dirty, outputDimensions, rectangle))
        {
            return false;
        }
        normalized[nextIndex++] = rectangle;
    }

    std::copy_n(normalized.begin(), rectangleCount, destination.begin());
    writtenCount = rectangleCount;
    return true;
}

} // namespace rdp_server::windows
