// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/gfx_avc420_picture.h"
#include "rdp/x264_avc420_encoder.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::rdp;

namespace
{
struct Nv12Frame final
{
    PixelSize geometry{};
    std::size_t stride{};
    std::vector<std::byte> y{};
    std::vector<std::byte> uv{};

    X264Nv12PictureView view(std::int64_t pts) const noexcept
    {
        return {geometry, y, uv, stride, stride, pts};
    }
};

Nv12Frame makeFrame(PixelSize geometry, std::size_t stride, std::uint8_t phase)
{
    Nv12Frame frame{geometry, stride};
    frame.y.resize(stride * geometry.heightPixels);
    frame.uv.resize(stride * (geometry.heightPixels / 2U));
    for (std::uint32_t row = 0; row < geometry.heightPixels; ++row)
        for (std::uint32_t column = 0; column < geometry.widthPixels; ++column)
            frame.y[row * stride + column] = static_cast<std::byte>(
                16U + ((row * 3U + column * 5U + phase) % 220U));
    for (std::uint32_t row = 0; row < geometry.heightPixels / 2U; ++row)
        for (std::uint32_t column = 0; column < geometry.widthPixels;
             column += 2U)
        {
            frame.uv[row * stride + column] =
                static_cast<std::byte>(96U + phase);
            frame.uv[row * stride + column + 1U] =
                static_cast<std::byte>(160U - phase);
        }
    return frame;
}

struct NalRange final
{
    std::size_t header{};
    std::size_t end{};
};

std::optional<NalRange> findNal(std::span<const std::byte> bytes,
                                std::uint8_t type)
{
    for (std::size_t index = 0; index + 4U < bytes.size(); ++index)
    {
        std::size_t header = 0;
        if (bytes[index] == std::byte{} && bytes[index + 1U] == std::byte{} &&
            bytes[index + 2U] == std::byte{1})
            header = index + 3U;
        else if (index + 5U < bytes.size() && bytes[index] == std::byte{} &&
                 bytes[index + 1U] == std::byte{} &&
                 bytes[index + 2U] == std::byte{} &&
                 bytes[index + 3U] == std::byte{1})
            header = index + 4U;
        if (header == 0 ||
            (std::to_integer<std::uint8_t>(bytes[header]) & 0x1fU) != type)
            continue;

        std::size_t end = bytes.size();
        for (std::size_t next = header + 1U; next + 3U < bytes.size(); ++next)
        {
            if (bytes[next] == std::byte{} &&
                bytes[next + 1U] == std::byte{} &&
                (bytes[next + 2U] == std::byte{1} ||
                 (next + 3U < bytes.size() &&
                  bytes[next + 2U] == std::byte{} &&
                  bytes[next + 3U] == std::byte{1})))
            {
                end = next;
                break;
            }
        }
        return NalRange{header, end};
    }
    return std::nullopt;
}

bool hasNal(std::span<const std::byte> bytes, std::uint8_t type)
{
    return findNal(bytes, type).has_value();
}

class BitReader final
{
public:
    explicit BitReader(std::span<const std::uint8_t> bytes) noexcept
        : bytes_(bytes)
    {
    }

    bool readBit(std::uint32_t &value) noexcept
    {
        if (bitOffset_ >= bytes_.size() * 8U)
            return false;
        const std::size_t byteOffset = bitOffset_ / 8U;
        const std::size_t bitInByte = 7U - (bitOffset_ % 8U);
        value = (bytes_[byteOffset] >> bitInByte) & 1U;
        ++bitOffset_;
        return true;
    }

    bool readBits(std::uint32_t count, std::uint32_t &value) noexcept
    {
        if (count > 32U)
            return false;
        value = 0;
        for (std::uint32_t index = 0; index < count; ++index)
        {
            std::uint32_t bit = 0;
            if (!readBit(bit))
                return false;
            value = (value << 1U) | bit;
        }
        return true;
    }

    bool readUe(std::uint32_t &value) noexcept
    {
        std::uint32_t leadingZeroBits = 0;
        std::uint32_t bit = 0;
        while (true)
        {
            if (!readBit(bit))
                return false;
            if (bit != 0)
                break;
            if (++leadingZeroBits > 31U)
                return false;
        }
        std::uint32_t suffix = 0;
        if (!readBits(leadingZeroBits, suffix))
            return false;
        const std::uint64_t decoded =
            ((std::uint64_t{1} << leadingZeroBits) - 1U) + suffix;
        if (decoded > std::numeric_limits<std::uint32_t>::max())
            return false;
        value = static_cast<std::uint32_t>(decoded);
        return true;
    }

    bool readSe(std::int32_t &value) noexcept
    {
        std::uint32_t code = 0;
        if (!readUe(code))
            return false;
        const std::int64_t magnitude =
            static_cast<std::int64_t>((code + 1U) / 2U);
        const std::int64_t decoded = (code & 1U) != 0 ? magnitude : -magnitude;
        if (decoded < std::numeric_limits<std::int32_t>::min() ||
            decoded > std::numeric_limits<std::int32_t>::max())
            return false;
        value = static_cast<std::int32_t>(decoded);
        return true;
    }

private:
    std::span<const std::uint8_t> bytes_{};
    std::size_t bitOffset_{};
};

struct SpsGeometry final
{
    std::uint32_t profile{};
    PixelSize coded{};
    PixelSize visible{};
};

std::optional<SpsGeometry>
readBaselineSpsGeometry(std::span<const std::byte> annexB)
{
    const auto nal = findNal(annexB, 7);
    if (!nal || nal->header + 1U >= nal->end)
        return std::nullopt;

    std::vector<std::uint8_t> rbsp;
    rbsp.reserve(nal->end - nal->header - 1U);
    unsigned zeroCount = 0;
    for (std::size_t index = nal->header + 1U; index < nal->end; ++index)
    {
        const std::uint8_t value =
            std::to_integer<std::uint8_t>(annexB[index]);
        if (zeroCount >= 2U && value == 0x03U)
        {
            zeroCount = 0;
            continue;
        }
        rbsp.push_back(value);
        zeroCount = value == 0 ? zeroCount + 1U : 0U;
    }

    BitReader reader(rbsp);
    std::uint32_t profile = 0;
    std::uint32_t ignored = 0;
    std::uint32_t value = 0;
    if (!reader.readBits(8, profile) || profile != 66U ||
        !reader.readBits(8, ignored) || !reader.readBits(8, ignored) ||
        !reader.readUe(ignored) || !reader.readUe(ignored) ||
        !reader.readUe(value))
        return std::nullopt;

    const std::uint32_t pictureOrderCountType = value;
    if (pictureOrderCountType == 0)
    {
        if (!reader.readUe(ignored))
            return std::nullopt;
    }
    else if (pictureOrderCountType == 1)
    {
        if (!reader.readBit(ignored))
            return std::nullopt;
        std::int32_t signedValue = 0;
        if (!reader.readSe(signedValue) || !reader.readSe(signedValue) ||
            !reader.readUe(value))
            return std::nullopt;
        for (std::uint32_t index = 0; index < value; ++index)
            if (!reader.readSe(signedValue))
                return std::nullopt;
    }
    else if (pictureOrderCountType != 2)
        return std::nullopt;

    std::uint32_t widthInMacroblocksMinusOne = 0;
    std::uint32_t heightInMapUnitsMinusOne = 0;
    std::uint32_t frameMacroblocksOnly = 0;
    if (!reader.readUe(ignored) || !reader.readBit(ignored) ||
        !reader.readUe(widthInMacroblocksMinusOne) ||
        !reader.readUe(heightInMapUnitsMinusOne) ||
        !reader.readBit(frameMacroblocksOnly))
        return std::nullopt;
    if (frameMacroblocksOnly == 0 && !reader.readBit(ignored))
        return std::nullopt;
    if (!reader.readBit(ignored))
        return std::nullopt;

    std::uint32_t cropping = 0;
    if (!reader.readBit(cropping))
        return std::nullopt;
    std::uint32_t cropLeft = 0;
    std::uint32_t cropRight = 0;
    std::uint32_t cropTop = 0;
    std::uint32_t cropBottom = 0;
    if (cropping != 0 &&
        (!reader.readUe(cropLeft) || !reader.readUe(cropRight) ||
         !reader.readUe(cropTop) || !reader.readUe(cropBottom)))
        return std::nullopt;

    const std::uint32_t codedWidth = (widthInMacroblocksMinusOne + 1U) * 16U;
    const std::uint32_t codedHeight =
        (2U - frameMacroblocksOnly) *
        (heightInMapUnitsMinusOne + 1U) * 16U;
    const std::uint32_t cropUnitX = 2U;
    const std::uint32_t cropUnitY = 2U * (2U - frameMacroblocksOnly);
    const std::uint64_t horizontalCrop =
        static_cast<std::uint64_t>(cropLeft + cropRight) * cropUnitX;
    const std::uint64_t verticalCrop =
        static_cast<std::uint64_t>(cropTop + cropBottom) * cropUnitY;
    if (horizontalCrop >= codedWidth || verticalCrop >= codedHeight)
        return std::nullopt;

    return SpsGeometry{
        profile,
        {codedWidth, codedHeight},
        {codedWidth - static_cast<std::uint32_t>(horizontalCrop),
         codedHeight - static_cast<std::uint32_t>(verticalCrop)}};
}

void annexBPicture()
{
    constexpr PixelSize coded{320, 192};
    constexpr PixelSize visible{320, 180};
    X264Avc420Encoder encoder;
    assert(encoder.open(coded, visible));
    const auto frame = makeFrame(coded, coded.widthPixels + 32U, 3U);
    X264EncodedPicture encoded;
    assert(encoder.encode(frame.view(0), encoded));
    assert(!encoded.annexB.empty());
    assert(encoded.annexB.size() <=
           X264Avc420Encoder::kMaximumEncodedPictureBytes);
    assert(encoded.keyFrame);
    assert(hasNal(encoded.annexB, 7)); // SPS
    assert(hasNal(encoded.annexB, 8)); // PPS
    assert(hasNal(encoded.annexB, 5)); // IDR
    const auto sps = readBaselineSpsGeometry(encoded.annexB);
    assert(sps.has_value());
    assert(sps->profile == 66U);
    assert(sps->coded == coded);
    assert(sps->visible == visible);

    const std::array<Rectangle, 1> regions{{
        {0, 0, visible.widthPixels, visible.heightPixels}}};
    const std::array<GfxAvc420QuantQuality, 1> quality{{{23, 80}}};
    const GfxAvc420Picture picture{7, 1, coded, regions, quality,
                                   encoded.annexB, visible};
    std::vector<std::byte> wire(gfxAvc420PictureBytes(
        regions.size(), encoded.annexB.size()));
    assert(!wire.empty());
    assert(buildGfxAvc420Picture(picture, wire) == wire.size());
}

void inputRejections()
{
    X264Avc420Encoder encoder;
    assert(!encoder.open({}, {320, 180}));
    assert(!encoder.open({319, 192}, {318, 180}));
    assert(!encoder.open({320, 192}, {321, 180}));
    assert(!encoder.open({320, 192}, {320, 179}));
    assert(encoder.open({320, 192}, {320, 180}));
    auto frame = makeFrame({320, 192}, 352, 1);
    X264EncodedPicture output;
    auto view = frame.view(0);
    view.yStrideBytes = 319;
    assert(!encoder.encode(view, output));
    view = frame.view(0);
    view.uvStrideBytes = 319;
    assert(!encoder.encode(view, output));
    view = frame.view(0);
    view.yPlane = view.yPlane.first(100);
    assert(!encoder.encode(view, output));
    view = frame.view(0);
    view.uvPlane = view.uvPlane.first(100);
    assert(!encoder.encode(view, output));
    view = frame.view(0);
    view.codedGeometry = {336, 192};
    assert(!encoder.encode(view, output));
    encoder.reset();
    assert(!encoder.encode(frame.view(0), output));
}

void visibleCropSequence()
{
    X264Avc420Encoder encoder;
    assert(encoder.open({1920, 1088}, {1920, 1080}));
    assert(encoder.codedGeometry() == (PixelSize{1920, 1088}));
    assert(encoder.visibleGeometry() == (PixelSize{1920, 1080}));
    encoder.reset();
    assert(!encoder.valid());
}

void resetReferenceLifecycle()
{
    constexpr PixelSize coded{320, 192};
    constexpr PixelSize visible{320, 180};
    X264Avc420Encoder encoder;
    assert(encoder.open(coded, visible));
    auto firstFrame = makeFrame(coded, 320, 7);
    auto secondFrame = makeFrame(coded, 320, 11);
    X264EncodedPicture first;
    X264EncodedPicture second;
    assert(encoder.encode(firstFrame.view(10), first));
    const auto firstCopy = first.annexB;
    assert(encoder.encode(secondFrame.view(11), second));
    assert(first.annexB == firstCopy);
    assert(second.pts == 11);
    assert(hasNal(second.annexB, 1)); // reference-continuous P slice

    encoder.reset();
    assert(encoder.open({336, 192}, {336, 190}));
    auto resized = makeFrame({336, 192}, 352, 19);
    X264EncodedPicture afterReset;
    assert(encoder.encode(resized.view(0), afterReset));
    assert(afterReset.keyFrame);
    assert(hasNal(afterReset.annexB, 7));
    assert(hasNal(afterReset.annexB, 8));
    assert(hasNal(afterReset.annexB, 5));
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view behavior{argv[1]};
    if (behavior == "x264-nv12-annexb-picture")
    {
        annexBPicture();
        return 0;
    }
    if (behavior == "x264-input-rejections")
    {
        inputRejections();
        return 0;
    }
    if (behavior == "x264-visible-crop-sequence")
    {
        visibleCropSequence();
        return 0;
    }
    if (behavior == "x264-reset-reference-lifecycle")
    {
        resetReferenceLifecycle();
        return 0;
    }
    return 2;
}
