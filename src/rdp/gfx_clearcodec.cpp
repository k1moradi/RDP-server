// SPDX-License-Identifier: GPL-3.0-or-later
#include "gfx_clearcodec.h"

#include <cstddef>
#include <cstdint>
#include <limits>

namespace rdp_server::rdp
{
namespace
{
// MS-RDPEGFX 2.2.2.1, 2.2.2.11/.12 and 2.2.4.1/.1.1/.1.1.1.
constexpr std::size_t kStartFrameBytes = 16U;
constexpr std::size_t kWireToSurfaceFixedBytes = 25U;
constexpr std::size_t kClearCodecStreamHeaderBytes = 14U;
constexpr std::size_t kEndFrameBytes = 12U;
constexpr std::size_t kResidualBytesPerPixel = 4U;
constexpr std::uint16_t kWireToSurface1Command = 0x0001U;
constexpr std::uint16_t kStartFrameCommand = 0x000BU;
constexpr std::uint16_t kEndFrameCommand = 0x000CU;
constexpr std::uint16_t kClearCodec = 0x0008U;
constexpr std::uint8_t kXrgb8888 = 0x20U;

struct ClearCodecLayout final
{
    std::size_t rowBytes{};
    std::size_t sourceBytes{};
    std::size_t pixelCount{};
    std::size_t residualBytes{};
    std::size_t bitmapBytes{};
    std::size_t wireBytes{};
    std::size_t totalBytes{};
};

[[nodiscard]] bool computeLayout(
    const FramebufferView &framebuffer,
    ClearCodecLayout &layout) noexcept
{
    constexpr std::size_t maxSize =
        std::numeric_limits<std::size_t>::max();
    constexpr std::size_t maxWire =
        std::numeric_limits<std::uint32_t>::max();

    if (!framebuffer.valid() ||
        framebuffer.widthPixels >
            std::numeric_limits<std::uint16_t>::max() ||
        framebuffer.heightPixels >
            std::numeric_limits<std::uint16_t>::max() ||
        framebuffer.widthPixels > maxSize / 4U)
    {
        return false;
    }

    layout.rowBytes =
        static_cast<std::size_t>(framebuffer.widthPixels) * 4U;
    if (framebuffer.strideBytes < layout.rowBytes)
        return false;

    // FramebufferView::valid() already proves this multiplication and extent.
    layout.sourceBytes =
        framebuffer.strideBytes *
        static_cast<std::size_t>(framebuffer.heightPixels);

    const std::size_t width = framebuffer.widthPixels;
    const std::size_t height = framebuffer.heightPixels;
    if (height > maxSize / width)
        return false;

    layout.pixelCount = width * height;
    if (layout.pixelCount > maxSize / kResidualBytesPerPixel)
        return false;
    layout.residualBytes =
        layout.pixelCount * kResidualBytesPerPixel;

    if (layout.residualBytes > maxWire ||
        layout.residualBytes >
            maxSize - kClearCodecStreamHeaderBytes)
    {
        return false;
    }
    layout.bitmapBytes =
        kClearCodecStreamHeaderBytes + layout.residualBytes;

    if (layout.bitmapBytes >
        maxWire - kWireToSurfaceFixedBytes)
    {
        return false;
    }
    layout.wireBytes =
        kWireToSurfaceFixedBytes + layout.bitmapBytes;

    constexpr std::size_t fixedFrameBytes =
        kStartFrameBytes + kEndFrameBytes;
    if (layout.wireBytes > maxWire - fixedFrameBytes ||
        layout.wireBytes > maxSize - fixedFrameBytes)
    {
        return false;
    }
    layout.totalBytes = fixedFrameBytes + layout.wireBytes;
    return true;
}

[[nodiscard]] bool rangesOverlap(
    std::span<const std::byte> source,
    std::span<std::byte> output) noexcept
{
    if (source.empty() || output.empty())
        return false;

    const auto sourceAddress =
        reinterpret_cast<std::uintptr_t>(source.data());
    const auto outputAddress =
        reinterpret_cast<std::uintptr_t>(output.data());
    constexpr auto maxAddress =
        std::numeric_limits<std::uintptr_t>::max();

    if (source.size() > maxAddress - sourceAddress ||
        output.size() > maxAddress - outputAddress)
    {
        return true;
    }
    return sourceAddress < outputAddress + output.size() &&
           outputAddress < sourceAddress + source.size();
}

void write16(
    std::span<std::byte> output,
    std::size_t offset,
    std::uint16_t value) noexcept
{
    output[offset] = static_cast<std::byte>(value);
    output[offset + 1U] =
        static_cast<std::byte>(value >> 8U);
}

void write32(
    std::span<std::byte> output,
    std::size_t offset,
    std::uint32_t value) noexcept
{
    write16(output, offset, static_cast<std::uint16_t>(value));
    write16(
        output, offset + 2U,
        static_cast<std::uint16_t>(value >> 16U));
}

void writeHeader(
    std::span<std::byte> output,
    std::size_t offset,
    std::uint16_t command,
    std::uint32_t length) noexcept
{
    write16(output, offset, command);
    write16(output, offset + 2U, 0U);
    write32(output, offset + 4U, length);
}
} // namespace

std::size_t gfxClearCodecFrameBytes(
    const GfxClearCodecFrameRequest &request) noexcept
{
    ClearCodecLayout layout{};
    return computeLayout(request.framebuffer, layout)
               ? layout.totalBytes
               : 0U;
}

std::size_t buildGfxClearCodecFrame(
    const GfxClearCodecFrameRequest &request,
    std::uint8_t sequenceNumber,
    std::span<std::byte> output) noexcept
{
    ClearCodecLayout layout{};
    if (!computeLayout(request.framebuffer, layout) ||
        output.size() < layout.totalBytes)
    {
        return 0U;
    }

    const auto source =
        request.framebuffer.pixels.first(layout.sourceBytes);
    const auto destination = output.first(layout.totalBytes);
    if (rangesOverlap(source, destination))
        return 0U;

    writeHeader(
        destination, 0U, kStartFrameCommand,
        static_cast<std::uint32_t>(kStartFrameBytes));
    write32(destination, 8U, 0U); // No UTC timestamp available.
    write32(destination, 12U, request.frameId);

    const std::size_t wireOffset = kStartFrameBytes;
    writeHeader(
        destination, wireOffset, kWireToSurface1Command,
        static_cast<std::uint32_t>(layout.wireBytes));
    write16(destination, wireOffset + 8U, request.surfaceId);
    write16(destination, wireOffset + 10U, kClearCodec);
    destination[wireOffset + 12U] =
        static_cast<std::byte>(kXrgb8888);
    write16(destination, wireOffset + 13U, 0U);
    write16(destination, wireOffset + 15U, 0U);
    write16(
        destination, wireOffset + 17U,
        static_cast<std::uint16_t>(
            request.framebuffer.widthPixels));
    write16(
        destination, wireOffset + 19U,
        static_cast<std::uint16_t>(
            request.framebuffer.heightPixels));
    write32(
        destination, wireOffset + 21U,
        static_cast<std::uint32_t>(layout.bitmapBytes));

    std::size_t at =
        wireOffset + kWireToSurfaceFixedBytes;
    destination[at++] = std::byte{}; // No glyph/cache flags.
    destination[at++] =
        static_cast<std::byte>(sequenceNumber);

    // One optional residual layer, no bands or subcodec layers.
    write32(
        destination, at,
        static_cast<std::uint32_t>(layout.residualBytes));
    at += 4U;
    write32(destination, at, 0U);
    at += 4U;
    write32(destination, at, 0U);
    at += 4U;

    const std::size_t height =
        request.framebuffer.heightPixels;
    const std::size_t width =
        request.framebuffer.widthPixels;
    const std::size_t stride =
        request.framebuffer.strideBytes;
    for (std::size_t row = 0; row < height; ++row)
    {
        const std::size_t rowOffset = row * stride;
        for (std::size_t column = 0; column < width; ++column)
        {
            const std::size_t pixelOffset =
                rowOffset + column * 4U;
            destination[at++] = source[pixelOffset];
            destination[at++] = source[pixelOffset + 1U];
            destination[at++] = source[pixelOffset + 2U];
            // MS-RDPEGFX requires a nonzero run factor. One means this
            // segment contributes exactly this one source pixel.
            destination[at++] = std::byte{1};
        }
    }

    const std::size_t endOffset =
        layout.totalBytes - kEndFrameBytes;
    if (at != endOffset)
        return 0U; // Internal invariant; all writes above were preflighted.

    writeHeader(
        destination, endOffset, kEndFrameCommand,
        static_cast<std::uint32_t>(kEndFrameBytes));
    write32(destination, endOffset + 8U, request.frameId);
    return layout.totalBytes;
}

} // namespace rdp_server::rdp
