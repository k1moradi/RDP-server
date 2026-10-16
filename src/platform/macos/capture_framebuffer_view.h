// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/framebuffer_view.h"
#include "platform/macos/capture_pixel_layout.h"

#include <cstddef>
#include <span>

namespace rdp::macos {

// Transactionally expose one already-validated CoreVideo-style BGRA layout as
// the portable R4 framebuffer envelope. The returned view borrows the caller
// storage; no bytes are copied or retained. Row padding remains part of the
// pitched allocation but is not visible pixel data. On failure output is unchanged.
[[nodiscard]] bool makeMacBgraFramebufferView(
    const BgraPixelLayout& layout,
    std::span<const std::byte> storage,
    FramebufferView& output) noexcept;

} // namespace rdp::macos
