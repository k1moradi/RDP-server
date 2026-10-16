// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server
{

constexpr std::uint32_t kCursorOutputDimension = 32;

// XFixes GetCursorImage length counts 32-bit words after its fixed reply
// header. Validate the reply before constructing a borrowed pixel span.
// The current classic cursor consumer supports at most 32x32 pixels.
[[nodiscard]] constexpr bool valid_xfixes_cursor_reply(
    std::uint32_t width, std::uint32_t height,
    std::uint32_t hotspotX, std::uint32_t hotspotY,
    std::uint32_t replyPixelWords) noexcept
{
    return width != 0 && height != 0 &&
           width <= kCursorOutputDimension &&
           height <= kCursorOutputDimension &&
           hotspotX < width && hotspotY < height &&
           static_cast<std::uint64_t>(width) * height <= replyPixelWords;
}

/**
 * Convert an XFixes ARGB32 cursor into the classic xrdp pointer layout.
 *
 * XFixes supplies scanlines from top to bottom.  The classic xrdp pointer
 * callback consumes the 32x32 rows in the opposite order, so both the pixel
 * data and the transparency mask are vertically flipped here.  The hotspot
 * is deliberately not part of this conversion; it remains a logical,
 * top-left-relative coordinate.
 */
[[nodiscard]] bool convert_cursor_image(
    std::span<const std::uint32_t> argb, std::uint32_t width,
    std::uint32_t height, std::span<std::byte> pixels,
    std::span<std::byte> mask) noexcept;

} // namespace rdp_server
