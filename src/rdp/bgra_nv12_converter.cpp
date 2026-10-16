// SPDX-License-Identifier: GPL-3.0-or-later
#include "bgra_nv12_converter.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

namespace rdp_server::rdp
{
namespace
{
constexpr std::uint64_t kMaximumNv12Bytes = 64ULL * 1024ULL * 1024ULL;

struct Rgb final
{
    std::int32_t red{};
    std::int32_t green{};
    std::int32_t blue{};
};

// Reject shared allocation ranges before changing scratch or reading pixels.
// uintptr_t arithmetic is checked so forged/wrapped address ranges fail closed.
[[nodiscard]] bool overlaps(std::span<const std::byte> source,
                            std::span<const std::byte> scratch) noexcept
{
    if (source.empty() || scratch.empty())
        return false;

    const auto sourceAddress =
        reinterpret_cast<std::uintptr_t>(source.data());
    const auto scratchAddress =
        reinterpret_cast<std::uintptr_t>(scratch.data());
    constexpr auto maximumAddress =
        std::numeric_limits<std::uintptr_t>::max();
    if (source.size() > maximumAddress - sourceAddress ||
        scratch.size() > maximumAddress - scratchAddress)
        return true;

    return sourceAddress < scratchAddress + scratch.size() &&
           scratchAddress < sourceAddress + source.size();
}

[[nodiscard]] Rgb readPixel(const FramebufferView &source,
                            std::size_t rowOffset,
                            std::uint32_t column) noexcept
{
    const std::size_t offset =
        rowOffset + static_cast<std::size_t>(column) * 4U;
    // XRGB/BGRA desktop memory is B,G,R,ignored-alpha. No premultiplication.
    return {std::to_integer<std::uint8_t>(source.pixels[offset + 2U]),
            std::to_integer<std::uint8_t>(source.pixels[offset + 1U]),
            std::to_integer<std::uint8_t>(source.pixels[offset])};
}

// Q16 full-range BT.709; signed nearest-integer, ties away from zero.
// Y  = (13933 R + 46871 G + 4732 B) / 65536.
// Cb = 128 + (-7509 R - 25259 G + 32768 B) / 65536.
// Cr = 128 + (32768 R - 29763 G - 3005 B) / 65536.
// These coefficients sum to the exact black/white/neutral endpoints.
[[nodiscard]] int roundQ16(std::int32_t value) noexcept
{
    constexpr std::int32_t half = 32768;
    constexpr std::int32_t divisor = 65536;
    return value >= 0 ? (value + half) / divisor
                      : -((-value + half) / divisor);
}

[[nodiscard]] std::byte clampChannel(int value) noexcept
{
    return static_cast<std::byte>(std::clamp(value, 0, 255));
}

[[nodiscard]] std::byte luma(Rgb pixel) noexcept
{
    return clampChannel(roundQ16(13933 * pixel.red +
                                46871 * pixel.green +
                                4732 * pixel.blue));
}

[[nodiscard]] std::byte chromaBlue(Rgb pixel) noexcept
{
    return clampChannel(128 + roundQ16(-7509 * pixel.red -
                                       25259 * pixel.green +
                                       32768 * pixel.blue));
}

[[nodiscard]] std::byte chromaRed(Rgb pixel) noexcept
{
    return clampChannel(128 + roundQ16(32768 * pixel.red -
                                       29763 * pixel.green -
                                       3005 * pixel.blue));
}
} // namespace

bool BgraNv12Converter::convert(const FramebufferView &framebuffer,
                                PixelSize visibleGeometry,
                                PixelSize codedGeometry,
                                std::int64_t pts) noexcept
{
    // A failed attempt must never publish the previous or a partial picture.
    ready_ = false;

    if (visibleGeometry.widthPixels == 0 ||
        visibleGeometry.heightPixels == 0 ||
        (visibleGeometry.widthPixels & 1U) != 0 ||
        (visibleGeometry.heightPixels & 1U) != 0 ||
        framebuffer.widthPixels != visibleGeometry.widthPixels ||
        framebuffer.heightPixels != visibleGeometry.heightPixels ||
        gfxAvc420CodedGeometry(visibleGeometry) != codedGeometry)
        return false;

    // FramebufferView::valid() alone does not validate BGRA bytes per pixel,
    // full pitched rows, or the exact visible whole-frame geometry.
    const std::size_t visibleWidth = visibleGeometry.widthPixels;
    const std::size_t visibleHeight = visibleGeometry.heightPixels;
    if (visibleWidth > std::numeric_limits<std::size_t>::max() / 4U)
        return false;
    const std::size_t minimumStride = visibleWidth * 4U;
    if (framebuffer.strideBytes < minimumStride ||
        visibleHeight > std::numeric_limits<std::size_t>::max() /
                            framebuffer.strideBytes)
        return false;
    const std::size_t sourceBytes =
        visibleHeight * framebuffer.strideBytes;
    if (framebuffer.pixels.size() < sourceBytes)
        return false;

    const std::uint64_t pixelCount =
        static_cast<std::uint64_t>(codedGeometry.widthPixels) *
        codedGeometry.heightPixels;
    if (pixelCount > kMaximumNv12Bytes * 2U / 3U)
        return false;
    const std::size_t yBytes = static_cast<std::size_t>(pixelCount);
    const std::size_t requiredBytes =
        static_cast<std::size_t>(pixelCount + pixelCount / 2U);

    if (overlaps(framebuffer.pixels, pixels_))
        return false;
    try
    {
        if (pixels_.size() != requiredBytes)
        {
            // Geometries change infrequently. Allocate exact contiguous
            // storage only on a size change; reuse it for every same-size
            // frame, with no allocations in the conversion loops.
            std::vector<std::byte> replacement(requiredBytes);
            pixels_.swap(replacement);
        }
    }
    catch (...)
    {
        return false;
    }

    const std::size_t codedStride = codedGeometry.widthPixels;
    const std::size_t yPlaneBytes = yBytes;
    // Process one 2x2 macro-pixel at a time. Edge-clamped source reads
    // replicate right/bottom borders before luma and chroma conversion.
    // Mean RGB rounds (sum + 2) / 4 before the BT.709 chroma transform.
    for (std::uint32_t row = 0; row < codedGeometry.heightPixels; row += 2U)
    {
        const std::uint32_t top = std::min(
            row, visibleGeometry.heightPixels - 1U);
        const std::uint32_t bottom = std::min(
            row + 1U, visibleGeometry.heightPixels - 1U);
        const std::size_t sourceTop =
            static_cast<std::size_t>(top) * framebuffer.strideBytes;
        const std::size_t sourceBottom =
            static_cast<std::size_t>(bottom) * framebuffer.strideBytes;
        const std::size_t lumaTop =
            static_cast<std::size_t>(row) * codedStride;
        const std::size_t lumaBottom = lumaTop + codedStride;
        const std::size_t uvRow =
            yPlaneBytes + static_cast<std::size_t>(row / 2U) * codedStride;

        for (std::uint32_t column = 0;
             column < codedGeometry.widthPixels; column += 2U)
        {
            const std::uint32_t left = std::min(
                column, visibleGeometry.widthPixels - 1U);
            const std::uint32_t right = std::min(
                column + 1U, visibleGeometry.widthPixels - 1U);
            const Rgb topLeft = readPixel(framebuffer, sourceTop, left);
            const Rgb topRight = readPixel(framebuffer, sourceTop, right);
            const Rgb bottomLeft = readPixel(framebuffer, sourceBottom, left);
            const Rgb bottomRight = readPixel(framebuffer, sourceBottom, right);

            pixels_[lumaTop + column] = luma(topLeft);
            pixels_[lumaTop + column + 1U] = luma(topRight);
            pixels_[lumaBottom + column] = luma(bottomLeft);
            pixels_[lumaBottom + column + 1U] = luma(bottomRight);

            const Rgb mean{
                (topLeft.red + topRight.red + bottomLeft.red +
                 bottomRight.red + 2) / 4,
                (topLeft.green + topRight.green + bottomLeft.green +
                 bottomRight.green + 2) / 4,
                (topLeft.blue + topRight.blue + bottomLeft.blue +
                 bottomRight.blue + 2) / 4};
            pixels_[uvRow + column] = chromaBlue(mean);
            pixels_[uvRow + column + 1U] = chromaRed(mean);
        }
    }

    codedGeometry_ = codedGeometry;
    yBytes_ = yBytes;
    pts_ = pts;
    ready_ = true;
    return true;
}

X264Nv12PictureView BgraNv12Converter::picture() const noexcept
{
    if (!ready_)
        return {};
    return {codedGeometry_,
            std::span<const std::byte>(pixels_.data(), yBytes_),
            std::span<const std::byte>(pixels_.data() + yBytes_,
                                       pixels_.size() - yBytes_),
            codedGeometry_.widthPixels, codedGeometry_.widthPixels, pts_};
}

void BgraNv12Converter::reset() noexcept
{
    ready_ = false;
    codedGeometry_ = {};
    yBytes_ = 0;
    pts_ = 0;
    // Keep bounded capacity across frames/generations; no native borrow.
    pixels_.clear();
}

} // namespace rdp_server::rdp
