// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/capture_framebuffer_view.h"
#include "platform/macos/capture_pixel_layout.h"

#include <CoreVideo/CoreVideo.h>

#include <cstddef>
#include <expected>
#include <span>

namespace rdp::macos {

// Move-only retained CoreVideo buffer, locked for CPU read access.
// Use and destruction are confined to the capture callback's thread; do not
// publish the borrowed span to an asynchronous encoder or outlive this owner.
// Does not grant screen-capture permission or start native capture.
class LockedBgraPixelBuffer final {
public:
    LockedBgraPixelBuffer(const LockedBgraPixelBuffer&) = delete;
    LockedBgraPixelBuffer& operator=(const LockedBgraPixelBuffer&) = delete;
    LockedBgraPixelBuffer(LockedBgraPixelBuffer&& other) noexcept;
    LockedBgraPixelBuffer& operator=(LockedBgraPixelBuffer&& other) noexcept;
    ~LockedBgraPixelBuffer();

    // The caller owns the input pixel buffer during this call. A successful
    // result retains it and unlocks/releases it exactly once at teardown.
    [[nodiscard]] static std::expected<LockedBgraPixelBuffer, BgraBufferError>
    lock(CVPixelBufferRef borrowed_pixel_buffer) noexcept;

    [[nodiscard]] const BgraPixelLayout& layout() const noexcept { return layout_; }
    // The full span includes native row padding; never transmit padding as pixels.
    [[nodiscard]] std::span<const std::byte> pixels() const noexcept;
    // Portable R4 borrow-only envelope. The returned view is valid only while
    // this CoreVideo owner remains locked and alive; no pixel copy occurs.
    [[nodiscard]] FramebufferView framebufferView() const noexcept;
    // Only the width * 4 initialized pixel bytes of a valid row.
    // Returns empty for moved-from owners or out-of-range rows.
    [[nodiscard]] std::span<const std::byte> pixelRow(std::size_t row_index) const noexcept;

private:
    explicit LockedBgraPixelBuffer(CVPixelBufferRef retained_buffer,
                                   const std::byte* base_address,
                                   const BgraPixelLayout layout) noexcept
        : retained_buffer_(retained_buffer), base_address_(base_address), layout_(layout) {}
    void reset() noexcept;

    CVPixelBufferRef retained_buffer_ = nullptr;
    const std::byte* base_address_ = nullptr;
    BgraPixelLayout layout_{};
};

} // namespace rdp::macos
