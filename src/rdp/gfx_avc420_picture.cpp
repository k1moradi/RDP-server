// SPDX-License-Identifier: GPL-3.0-or-later
#include "gfx_avc420_picture.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace rdp_server::rdp
{
namespace
{
// MS-RDPEGFX 2.2.2.1, 2.2.2.11/12 and 2.2.4.4/.4.1/.4.2.
constexpr std::size_t kStart = 16U;
constexpr std::size_t kWireFixed = 25U; // 8-byte header, 17-byte body
constexpr std::size_t kMetaCount = 4U;
constexpr std::size_t kPerRegion = 10U; // RECT16 + QUANT_QUALITY
constexpr std::size_t kEnd = 12U;
constexpr std::uint16_t kWireToSurface1 = 0x0001;
constexpr std::uint16_t kStartFrame = 0x000B;
constexpr std::uint16_t kEndFrame = 0x000C;
constexpr std::uint16_t kAvc420Codec = 0x000B;
constexpr std::uint8_t kXrgb8888 = 0x20;

void write16(std::span<std::byte> to, std::size_t at,
             std::uint16_t value) noexcept
{
    to[at] = static_cast<std::byte>(value);
    to[at + 1U] = static_cast<std::byte>(value >> 8U);
}
void write32(std::span<std::byte> to, std::size_t at,
             std::uint32_t value) noexcept
{
    write16(to, at, static_cast<std::uint16_t>(value));
    write16(to, at + 2U, static_cast<std::uint16_t>(value >> 16U));
}
void header(std::span<std::byte> out, std::size_t at,
            std::uint16_t cmd, std::uint32_t length) noexcept
{
    write16(out, at, cmd);
    write16(out, at + 2U, 0);
    write32(out, at + 4U, length);
}
[[nodiscard]] bool hasAnnexBPicture(std::span<const std::byte> bytes) noexcept
{
    // Format preflight, not a substitute for an x264 encoder/decoder.
    const std::size_t prefix =
        bytes.size() >= 4 && bytes[0] == std::byte{} &&
        bytes[1] == std::byte{} && bytes[2] == std::byte{} &&
        bytes[3] == std::byte{1}
            ? 4U
            : 3U;
    if (bytes.size() <= prefix ||
        bytes[0] != std::byte{} || bytes[1] != std::byte{} ||
        (prefix == 3U && bytes[2] != std::byte{1}))
    {
        return false;
    }
    const auto nalHeader = std::to_integer<std::uint8_t>(bytes[prefix]);
    return (nalHeader & 0x80U) == 0 && (nalHeader & 0x1FU) != 0 &&
           (nalHeader & 0x1FU) < 24U;
}
[[nodiscard]] bool rectangleFits(Rectangle rect, PixelSize geometry) noexcept
{
    if (rect.x < 0 || rect.y < 0 || rect.widthPixels == 0 ||
        rect.heightPixels == 0)
        return false;
    const auto right = static_cast<std::uint64_t>(rect.x) + rect.widthPixels;
    const auto bottom = static_cast<std::uint64_t>(rect.y) + rect.heightPixels;
    return right <= geometry.widthPixels && bottom <= geometry.heightPixels &&
           right <= std::numeric_limits<std::uint16_t>::max() &&
           bottom <= std::numeric_limits<std::uint16_t>::max();
}
[[nodiscard]] PixelSize resolvedVisibleGeometry(
    const GfxAvc420Picture &picture) noexcept
{
    return picture.visibleGeometry.widthPixels == 0 &&
                   picture.visibleGeometry.heightPixels == 0
               ? picture.codedGeometry
               : picture.visibleGeometry;
}
} // namespace

PixelSize gfxAvc420CodedGeometry(PixelSize visible) noexcept
{
    constexpr std::uint32_t maxAligned =
        std::numeric_limits<std::uint16_t>::max() & ~15U;
    if (visible.widthPixels == 0 || visible.heightPixels == 0 ||
        visible.widthPixels > maxAligned ||
        visible.heightPixels > maxAligned)
        return {};
    return {(visible.widthPixels + 15U) & ~15U,
            (visible.heightPixels + 15U) & ~15U};
}

std::size_t gfxAvc420PictureBytes(
    std::size_t regionCount, std::size_t annexBBytes) noexcept
{
    if (regionCount == 0 || regionCount > kGfxMaximumAvc420Regions ||
        annexBBytes < 4U || annexBBytes > kGfxMaximumAnnexBPictureBytes)
        return 0;
    // The picture and total frame must fit both size_t and protocol u32.
    constexpr std::size_t base = kStart + kWireFixed + kMetaCount + kEnd;
    if (regionCount > (std::numeric_limits<std::size_t>::max() - base) /
                          kPerRegion)
        return 0;
    const std::size_t frameBase = base + kPerRegion * regionCount;
    if (annexBBytes > std::numeric_limits<std::uint32_t>::max() -
                          frameBase)
        return 0;
    return frameBase + annexBBytes;
}

bool gfxAvc420PictureMetadataValid(
    const GfxAvc420Picture &picture) noexcept
{
    const std::size_t count = picture.regions.size();
    const PixelSize coded = picture.codedGeometry;
    const PixelSize visible = resolvedVisibleGeometry(picture);
    if (count == 0 || count > kGfxMaximumAvc420Regions ||
        picture.surfaceId == 0 || picture.frameId == 0 ||
        coded.widthPixels == 0 || coded.heightPixels == 0 ||
        (coded.widthPixels & 15U) != 0 ||
        (coded.heightPixels & 15U) != 0 ||
        coded.widthPixels > std::numeric_limits<std::uint16_t>::max() ||
        coded.heightPixels > std::numeric_limits<std::uint16_t>::max() ||
        visible.widthPixels == 0 || visible.heightPixels == 0 ||
        visible.widthPixels > coded.widthPixels ||
        visible.heightPixels > coded.heightPixels ||
        picture.quantQualities.size() != count)
    {
        return false;
    }
    for (std::size_t i = 0; i < count; ++i)
    {
        if (!rectangleFits(picture.regions[i], visible) ||
            picture.quantQualities[i].qp > 51U ||
            picture.quantQualities[i].quality > 100U)
        {
            return false;
        }
    }
    return true;
}

std::size_t buildGfxAvc420Picture(
    const GfxAvc420Picture &picture, std::span<std::byte> output) noexcept
{
    const std::size_t count = picture.regions.size();
    const std::size_t total = gfxAvc420PictureBytes(
        count, picture.annexBPicture.size());
    if (total == 0 || output.size() < total ||
        !gfxAvc420PictureMetadataValid(picture) ||
        !hasAnnexBPicture(picture.annexBPicture))
    {
        return 0;
    }
    const PixelSize visible = resolvedVisibleGeometry(picture);

    // Copy payload FIRST using memmove. Source may overlap the output
    // buffer; metadata/header writes after copying cannot corrupt it.
    const std::size_t meta = kStart + kWireFixed;
    const std::size_t nalStart = meta + kMetaCount + count * kPerRegion;
    std::memmove(output.data() + nalStart, picture.annexBPicture.data(),
                 picture.annexBPicture.size());

    header(output, 0, kStartFrame, kStart);
    write32(output, 8, 0); // No UTC timestamp available.
    write32(output, 12, picture.frameId);

    const auto wireBytes = static_cast<std::uint32_t>(
        kWireFixed + kMetaCount + count * kPerRegion +
        picture.annexBPicture.size());
    header(output, kStart, kWireToSurface1, wireBytes);
    write16(output, kStart + 8U, picture.surfaceId);
    write16(output, kStart + 10U, kAvc420Codec);
    output[kStart + 12U] = static_cast<std::byte>(kXrgb8888);
    // destRect is left, top, right, bottom (not width/height).
    write16(output, kStart + 13U, 0);
    write16(output, kStart + 15U, 0);
    write16(output, kStart + 17U,
            static_cast<std::uint16_t>(visible.widthPixels));
    write16(output, kStart + 19U,
            static_cast<std::uint16_t>(visible.heightPixels));
    write32(output, kStart + 21U, static_cast<std::uint32_t>(
        kMetaCount + count * kPerRegion + picture.annexBPicture.size()));

    write32(output, meta, static_cast<std::uint32_t>(count));
    std::size_t at = meta + kMetaCount;
    for (const Rectangle rect : picture.regions)
    {
        write16(output, at, static_cast<std::uint16_t>(rect.x));
        write16(output, at + 2U, static_cast<std::uint16_t>(rect.y));
        write16(output, at + 4U,
                static_cast<std::uint16_t>(
                    static_cast<std::uint64_t>(rect.x) + rect.widthPixels));
        write16(output, at + 6U,
                static_cast<std::uint16_t>(
                    static_cast<std::uint64_t>(rect.y) + rect.heightPixels));
        at += 8U;
    }
    for (const GfxAvc420QuantQuality q : picture.quantQualities)
    {
        output[at++] = static_cast<std::byte>(q.qp);
        output[at++] = static_cast<std::byte>(q.quality);
    }
    const std::size_t endOffset = total - kEnd;
    header(output, endOffset, kEndFrame, kEnd);
    write32(output, endOffset + 8U, picture.frameId);
    return total;
}

} // namespace rdp_server::rdp
