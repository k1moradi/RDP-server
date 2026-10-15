// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/geometry.h"
#include "core/rectangle.h"
#include "windows_desktop_geometry.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::windows
{

// Layout-neutral equivalents of the RECT/POINT fields returned by
// IDXGIOutputDuplication::GetFrameDirtyRects/GetFrameMoveRects. The native
// acquisition owner must validate native metadata byte counts before making
// these spans; Windows types stay out of the portable R4 interface.
struct WindowsDxgiRectangle
{
    std::int32_t left{};
    std::int32_t top{};
    std::int32_t right{};
    std::int32_t bottom{};
};

struct WindowsDxgiMoveRectangle
{
    WindowsNativePoint source{};
    WindowsDxgiRectangle destination{};
};

inline constexpr std::size_t kMaximumWindowsDxgiDamageRectangles = 1024;

// Normalize one acquired DXGI output's local damage into caller-owned
// portable rectangles. Move destinations are emitted BEFORE dirty rectangles
// (as required by Desktop Duplication), without a frame copy, region cache
// or graphics schedule. The acquired frame must already contain all moved
// pixels: R4 can repaint the returned destinations from that frame.
//
// Input coordinates are per-output pixels, not virtual-desktop positions.
// Reject malformed/out-of-bounds metadata, oversized lists and short output
// capacity. Output bytes, unused capacity and writtenCount remain unchanged
// on failure. Overlapping input/output storage is safe because normalization
// completes into a bounded stack array before any destination write.
//
// No OS access or RDP admission occurs here. Call only from an R2/R3-
// authorized capture owner while its DXGI frame/metadata remain alive.
[[nodiscard]] bool normalizeWindowsDxgiDamage(
    PixelSize outputDimensions,
    std::span<const WindowsDxgiMoveRectangle> moveRectangles,
    std::span<const WindowsDxgiRectangle> dirtyRectangles,
    std::span<Rectangle> destination,
    std::size_t &writtenCount) noexcept;

} // namespace rdp_server::windows
