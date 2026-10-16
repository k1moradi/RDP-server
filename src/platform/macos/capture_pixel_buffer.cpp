// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/capture_pixel_buffer.h"

#include <utility>

namespace rdp::macos {

std::expected<LockedBgraPixelBuffer, BgraBufferError>
LockedBgraPixelBuffer::lock(CVPixelBufferRef const borrowed_pixel_buffer) noexcept {
    if (borrowed_pixel_buffer == nullptr) {
        return std::unexpected(BgraBufferError::missing_buffer);
    }
    if (CVPixelBufferIsPlanar(borrowed_pixel_buffer) ||
        CVPixelBufferGetPixelFormatType(borrowed_pixel_buffer) != kCVPixelFormatType_32BGRA) {
        return std::unexpected(BgraBufferError::unsupported_format);
    }

    // Reject invalid dimensions and short backing storage before attempting
    // a CPU mapping. CoreVideo is responsible for supplying truthful memory
    // metadata; there is no unchecked integer multiplication here.
    const auto layout = validateBgraPixelLayout(
        CVPixelBufferGetWidth(borrowed_pixel_buffer),
        CVPixelBufferGetHeight(borrowed_pixel_buffer),
        CVPixelBufferGetBytesPerRow(borrowed_pixel_buffer),
        CVPixelBufferGetDataSize(borrowed_pixel_buffer));
    if (!layout) {
        return std::unexpected(layout.error());
    }

    CVPixelBufferRef const retained_buffer = CVPixelBufferRetain(borrowed_pixel_buffer);
    if (CVPixelBufferLockBaseAddress(retained_buffer, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess) {
        CVPixelBufferRelease(retained_buffer);
        return std::unexpected(BgraBufferError::lock_failed);
    }
    const void* const base_address = CVPixelBufferGetBaseAddress(retained_buffer);
    if (base_address == nullptr) {
        CVPixelBufferUnlockBaseAddress(retained_buffer, kCVPixelBufferLock_ReadOnly);
        CVPixelBufferRelease(retained_buffer);
        return std::unexpected(BgraBufferError::missing_base_address);
    }
    return LockedBgraPixelBuffer(retained_buffer,
                                 static_cast<const std::byte*>(base_address), *layout);
}

LockedBgraPixelBuffer::LockedBgraPixelBuffer(LockedBgraPixelBuffer&& other) noexcept
    : retained_buffer_(std::exchange(other.retained_buffer_, nullptr)),
      base_address_(std::exchange(other.base_address_, nullptr)),
      layout_(std::exchange(other.layout_, {})) {}

LockedBgraPixelBuffer& LockedBgraPixelBuffer::operator=(LockedBgraPixelBuffer&& other) noexcept {
    if (this != &other) {
        reset();
        retained_buffer_ = std::exchange(other.retained_buffer_, nullptr);
        base_address_ = std::exchange(other.base_address_, nullptr);
        layout_ = std::exchange(other.layout_, {});
    }
    return *this;
}

LockedBgraPixelBuffer::~LockedBgraPixelBuffer() {
    reset();
}

std::span<const std::byte> LockedBgraPixelBuffer::pixels() const noexcept {
    if (retained_buffer_ == nullptr) {
        return {};
    }
    return {base_address_, layout_.byte_count};
}

FramebufferView LockedBgraPixelBuffer::framebufferView() const noexcept {
    if (retained_buffer_ == nullptr) {
        return {};
    }
    FramebufferView output{};
    if (!makeMacBgraFramebufferView(layout_, pixels(), output)) {
        return {};
    }
    return output;
}

std::span<const std::byte> LockedBgraPixelBuffer::pixelRow(
    const std::size_t row_index) const noexcept {
    if (retained_buffer_ == nullptr || row_index >= layout_.height_pixels) {
        return {};
    }
    // Validated layout bounds both products, including the padded row stride.
    const std::size_t row_offset = row_index * layout_.bytes_per_row;
    const std::size_t pixel_bytes = layout_.width_pixels * 4U;
    return {base_address_ + row_offset, pixel_bytes};
}

void LockedBgraPixelBuffer::reset() noexcept {
    if (retained_buffer_ != nullptr) {
        CVPixelBufferUnlockBaseAddress(retained_buffer_, kCVPixelBufferLock_ReadOnly);
        CVPixelBufferRelease(retained_buffer_);
        retained_buffer_ = nullptr;
        base_address_ = nullptr;
        layout_ = {};
    }
}

} // namespace rdp::macos
