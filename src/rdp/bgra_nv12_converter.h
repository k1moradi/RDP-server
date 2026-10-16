// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/framebuffer_view.h"
#include "gfx_avc420_picture.h"
#include "x264_avc420_encoder.h"

namespace rdp_server::rdp
{

// One synchronous R4 BGRA/XRGB -> NV12 scratch owner. FramebufferView is
// borrowed only while convert() runs. The returned NV12 planes borrow this
// allocation until the next convert() or reset(); never retain them beyond
// the existing producer's synchronous prepare() call. Reset invalidates the
// view but retains initialized scratch for same-geometry reuse.
// Not thread-safe: the R4 presentation thread serializes this owner.
class BgraNv12Converter final
{
public:
    [[nodiscard]] bool convert(const FramebufferView &framebuffer,
                               PixelSize visibleGeometry,
                               PixelSize codedGeometry,
                               std::int64_t pts) noexcept;
    [[nodiscard]] X264Nv12PictureView picture() const noexcept;
    void reset() noexcept;

    [[nodiscard]] std::size_t capacityBytes() const noexcept
    {
        return pixels_.capacity();
    }

private:
    std::vector<std::byte> pixels_{};
    PixelSize codedGeometry_{};
    std::size_t yBytes_{};
    std::int64_t pts_{};
    bool ready_{};
};

} // namespace rdp_server::rdp
