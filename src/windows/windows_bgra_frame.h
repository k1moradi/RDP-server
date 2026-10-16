// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/framebuffer_view.h"
#include "core/geometry.h"

#include <cstddef>
#include <span>

namespace rdp_server::windows
{

// DXGI Desktop Duplication returns top-down DXGI_FORMAT_B8G8R8A8_UNORM:
// memory order is Blue, Green, Red, Alpha. This is NOT an RGBA converter.
// Row padding is not guaranteed initialized: consumers must process or send
// only widthPixels * 4 component bytes from each row, never the padding.
inline constexpr std::size_t kWindowsBgraBytesPerPixel = 4;
inline constexpr std::size_t kMaximumWindowsCaptureFrameBytes =
    512ULL * 1024ULL * 1024ULL;

// Produce the existing portable framebuffer view without copying pixels.
// The entire pitched allocation (including the final row's padding) must
// be readable. Reject invalid dimensions, truncated rows, oversized frames
// and arithmetic overflow; leave output unchanged on every failure.
//
// Ownership: the returned view borrows mappedPixels. Consume it synchronously
// while the owning DXGI resource remains mapped and the frame is acquired;
// an asynchronous R4 consumer must first arrange its own owned frame bytes.
// Call this only after R2/R3 authorized the native session and an actual
// capture owner acquired/mapped a DXGI frame; this helper grants no access.
[[nodiscard]] bool makeWindowsBgraFrameView(
    std::span<const std::byte> mappedPixels,
    PixelSize dimensions,
    std::size_t rowPitchBytes,
    FramebufferView &output) noexcept;

} // namespace rdp_server::windows
