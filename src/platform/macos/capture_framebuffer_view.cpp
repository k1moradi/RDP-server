// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/capture_framebuffer_view.h"

#include <cstdint>
#include <limits>

namespace rdp::macos {

bool makeMacBgraFramebufferView(
    const BgraPixelLayout& layout,
    const std::span<const std::byte> storage,
    FramebufferView& output) noexcept {
    // FramebufferView uses 32-bit physical dimensions. validateBgraPixelLayout
    // currently caps them more tightly, but keep the narrowing rule explicit at
    // this cross-road boundary.
    if (layout.width_pixels > std::numeric_limits<std::uint32_t>::max() ||
        layout.height_pixels > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    const auto validated = validateBgraPixelLayout(
        layout.width_pixels, layout.height_pixels, layout.bytes_per_row,
        storage.size());
    if (!validated || validated->byte_count != layout.byte_count) {
        return false;
    }

    const FramebufferView candidate{
        storage.first(layout.byte_count),
        static_cast<std::uint32_t>(layout.width_pixels),
        static_cast<std::uint32_t>(layout.height_pixels),
        layout.bytes_per_row,
    };
    if (!candidate.valid()) {
        return false;
    }

    output = candidate;
    return true;
}

} // namespace rdp::macos
