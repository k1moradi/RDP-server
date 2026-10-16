// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_bgra_frame.h"

#include <cstddef>
#include <cstdint>

namespace rdp_server::windows
{

bool makeWindowsBgraFrameView(std::span<const std::byte> mappedPixels,
                              PixelSize dimensions,
                              std::size_t rowPitchBytes,
                              FramebufferView &output) noexcept
{
    if (dimensions.widthPixels == 0 || dimensions.heightPixels == 0)
    {
        return false;
    }

    // Multiplication is performed before narrowing and below the explicit
    // frame cap; it is safe on both 32-bit and 64-bit targets.
    const std::uint64_t minimumRowBytes =
        static_cast<std::uint64_t>(dimensions.widthPixels) *
        kWindowsBgraBytesPerPixel;
    if (rowPitchBytes < minimumRowBytes ||
        rowPitchBytes > kMaximumWindowsCaptureFrameBytes ||
        dimensions.heightPixels >
            kMaximumWindowsCaptureFrameBytes / rowPitchBytes)
    {
        return false;
    }

    const std::size_t requiredBytes =
        rowPitchBytes * static_cast<std::size_t>(dimensions.heightPixels);
    if (mappedPixels.size() < requiredBytes)
    {
        return false;
    }

    // Keep only the complete pitched image; ignore excess unrelated backing
    // bytes. The caller must retain the mapped resource for this view's life.
    output = {mappedPixels.first(requiredBytes), dimensions.widthPixels,
              dimensions.heightPixels, rowPitchBytes};
    return true;
}

} // namespace rdp_server::windows
