// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_damage.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <dxgi1_2.h>
#endif
#include <algorithm>
#include <array>
#include <limits>

namespace rdp_server::windows
{
namespace
{

[[nodiscard]] bool checkedRectangle(
    WindowsDxgiRectangle nativeRectangle, PixelSize bounds,
    PortableRectangle &rectangle) noexcept
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
    std::span<PortableRectangle> destination,
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
    std::array<PortableRectangle, kMaximumWindowsDxgiDamageRectangles> normalized{};
    std::size_t nextIndex = 0;
    for (const WindowsDxgiMoveRectangle &move : moveRectangles)
    {
        PortableRectangle destinationRectangle{};
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
        PortableRectangle rectangle{};
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

WindowsDxgiDamageReadResult readWindowsDxgiFrameDamage(
    WindowsDxgiDamageReadCallbacks callbacks, PixelSize dimensions,
    std::span<PortableRectangle> destination,
    std::size_t &writtenCount) noexcept
{
    if (callbacks.context == nullptr || callbacks.read == nullptr)
        return WindowsDxgiDamageReadResult::failed;
    std::array<WindowsDxgiMoveRectangle,kMaximumWindowsDxgiDamageRectangles> moves{};
    std::array<WindowsDxgiRectangle,kMaximumWindowsDxgiDamageRectangles> dirties{};
    std::size_t moveCount = 0, dirtyCount = 0;
    const auto status = callbacks.read(callbacks.context, moves, dirties,
                                       moveCount, dirtyCount);
    if (status != WindowsDxgiDamageReadResult::ready)
        return status;
    if (moveCount > moves.size() || dirtyCount > dirties.size() ||
        dirtyCount > kMaximumWindowsDxgiDamageRectangles - moveCount)
        return WindowsDxgiDamageReadResult::invalid;
    if (!normalizeWindowsDxgiDamage(
            dimensions, std::span(moves).first(moveCount),
            std::span(dirties).first(dirtyCount), destination, writtenCount))
        return WindowsDxgiDamageReadResult::invalid;
    return WindowsDxgiDamageReadResult::ready;
}

#ifdef _WIN32
namespace
{
WindowsDxgiDamageReadResult nativeReadWindowsDamage(
    void *raw, std::span<WindowsDxgiMoveRectangle> moves,
    std::span<WindowsDxgiRectangle> dirties,
    std::size_t &moveCount, std::size_t &dirtyCount) noexcept
{
    auto &duplication = *static_cast<IDXGIOutputDuplication *>(raw);
    std::array<DXGI_OUTDUPL_MOVE_RECT,kMaximumWindowsDxgiDamageRectangles> nativeMoves{};
    std::array<RECT,kMaximumWindowsDxgiDamageRectangles> nativeDirties{};
    UINT moveBytes = 0;
    const HRESULT moveResult = duplication.GetFrameMoveRects(
        static_cast<UINT>(sizeof(nativeMoves)),nativeMoves.data(),&moveBytes);
    if (moveResult == DXGI_ERROR_ACCESS_LOST)
        return WindowsDxgiDamageReadResult::accessLost;
    if (moveResult == DXGI_ERROR_MORE_DATA)
        return WindowsDxgiDamageReadResult::invalid;
    if (FAILED(moveResult))
        return WindowsDxgiDamageReadResult::failed;
    if (moveBytes > sizeof(nativeMoves) ||
        moveBytes % sizeof(DXGI_OUTDUPL_MOVE_RECT) != 0)
        return WindowsDxgiDamageReadResult::invalid;
    const std::size_t count = moveBytes / sizeof(DXGI_OUTDUPL_MOVE_RECT);
    if (count > moves.size())
        return WindowsDxgiDamageReadResult::invalid;
    // Combined move+dirty cap; metadata overflow requires full-frame recovery.
    const auto available = static_cast<UINT>(
        (kMaximumWindowsDxgiDamageRectangles-count)*sizeof(RECT));
    UINT dirtyBytes = 0;
    const HRESULT dirtyResult = duplication.GetFrameDirtyRects(
        available,nativeDirties.data(),&dirtyBytes);
    if (dirtyResult == DXGI_ERROR_ACCESS_LOST)
        return WindowsDxgiDamageReadResult::accessLost;
    if (dirtyResult == DXGI_ERROR_MORE_DATA)
        return WindowsDxgiDamageReadResult::invalid;
    if (FAILED(dirtyResult))
        return WindowsDxgiDamageReadResult::failed;
    if (dirtyBytes > available || dirtyBytes % sizeof(RECT) != 0)
        return WindowsDxgiDamageReadResult::invalid;
    const std::size_t dirtyCountLocal = dirtyBytes / sizeof(RECT);
    if (dirtyCountLocal > dirties.size())
        return WindowsDxgiDamageReadResult::invalid;
    for (std::size_t i=0;i<count;++i)
    {
        const auto &m=nativeMoves[i];
        moves[i]={{m.SourcePoint.x,m.SourcePoint.y},
                  {m.DestinationRect.left,m.DestinationRect.top,
                   m.DestinationRect.right,m.DestinationRect.bottom}};
    }
    for (std::size_t i=0;i<dirtyCountLocal;++i)
    {
        const auto &d=nativeDirties[i];
        dirties[i]={d.left,d.top,d.right,d.bottom};
    }
    moveCount=count;
    dirtyCount=dirtyCountLocal;
    return WindowsDxgiDamageReadResult::ready;
}
} // namespace

WindowsDxgiDamageReadCallbacks windowsDxgiDamageReadCallbacks(
    IDXGIOutputDuplication &duplication) noexcept
{
    return {&duplication,&nativeReadWindowsDamage};
}
#endif

} // namespace rdp_server::windows
