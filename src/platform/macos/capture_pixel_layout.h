// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>

namespace rdp::macos {

// Describes a read-only, chunky 8-bit BGRA surface in physical pixels.
// The last row's padding is included in byte_count; consumers must only
// interpret width * 4 bytes per row as pixels.
struct BgraPixelLayout {
    std::size_t width_pixels{};
    std::size_t height_pixels{};
    std::size_t bytes_per_row{};
    std::size_t byte_count{};
};

enum class BgraBufferError : std::uint8_t {
    missing_buffer,
    unsupported_format,
    invalid_layout,
    lock_failed,
    missing_base_address,
};

// Validates metadata before any pointer arithmetic, memory access or copy.
// byte_count is the amount that must be accessible starting at the first
// pixel, including row padding. 512 MiB is a safety limit per frame; it is
// not a limit on aggregate multi-monitor memory usage.
[[nodiscard]] std::expected<BgraPixelLayout, BgraBufferError>
validateBgraPixelLayout(std::size_t width_pixels,
                        std::size_t height_pixels,
                        std::size_t bytes_per_row,
                        std::size_t available_bytes) noexcept;

} // namespace rdp::macos
