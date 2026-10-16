// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/capture_pixel_layout.h"

#include <limits>

namespace rdp::macos {

std::expected<BgraPixelLayout, BgraBufferError> validateBgraPixelLayout(
    const std::size_t width_pixels,
    const std::size_t height_pixels,
    const std::size_t bytes_per_row,
    const std::size_t available_bytes) noexcept {
    constexpr std::size_t kBytesPerPixel = 4;
    constexpr std::size_t kMaximumDimension = 32'768;
    constexpr std::size_t kMaximumFrameBytes = 512U * 1024U * 1024U;
    constexpr std::size_t kMaximumSize = std::numeric_limits<std::size_t>::max();

    if (width_pixels == 0 || height_pixels == 0 ||
        width_pixels > kMaximumDimension || height_pixels > kMaximumDimension ||
        width_pixels > kMaximumSize / kBytesPerPixel) {
        return std::unexpected(BgraBufferError::invalid_layout);
    }
    const std::size_t minimum_row_bytes = width_pixels * kBytesPerPixel;
    if (bytes_per_row < minimum_row_bytes ||
        bytes_per_row > kMaximumFrameBytes / height_pixels) {
        return std::unexpected(BgraBufferError::invalid_layout);
    }
    const std::size_t required_bytes = bytes_per_row * height_pixels;
    if (available_bytes < required_bytes) {
        return std::unexpected(BgraBufferError::invalid_layout);
    }
    return BgraPixelLayout{width_pixels, height_pixels, bytes_per_row, required_bytes};
}

} // namespace rdp::macos
