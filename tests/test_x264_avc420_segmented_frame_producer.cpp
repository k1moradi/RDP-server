// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/x264_avc420_segmented_frame_producer.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
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

    [[nodiscard]] X264Nv12PictureView view(std::int64_t pts) const noexcept
    {
        return {geometry, y, uv, stride, stride, pts};
    }
};

Nv12Frame makeFrame(PixelSize geometry, std::uint8_t phase)
{
    Nv12Frame frame{geometry, geometry.widthPixels};
    frame.y.resize(frame.stride * geometry.heightPixels);
    frame.uv.resize(frame.stride * (geometry.heightPixels / 2U));
    for (std::uint32_t row = 0; row < geometry.heightPixels; ++row)
    {
        for (std::uint32_t column = 0; column < geometry.widthPixels; ++column)
        {
            frame.y[row * frame.stride + column] = static_cast<std::byte>(
                16U + ((row * 3U + column * 5U + phase) % 220U));
        }
    }
    for (std::uint32_t row = 0; row < geometry.heightPixels / 2U; ++row)
    {
        for (std::uint32_t column = 0; column < geometry.widthPixels;
             column += 2U)
        {
            frame.uv[row * frame.stride + column] =
                static_cast<std::byte>(96U + phase);
            frame.uv[row * frame.stride + column + 1U] =
                static_cast<std::byte>(160U - phase);
        }
    }
    return frame;
}

std::array<std::byte, 22> advertisement()
{
    return {std::byte{0x12}, {}, {}, {}, std::byte{22}, {}, {}, {},
            std::byte{1}, {}, std::byte{5}, std::byte{1}, std::byte{8}, {},
            std::byte{4}, {}, {}, {}, std::byte{0x10}, {}, {}, {}};
}

GfxPresentationReceipt emit(GfxPresentationLifecycle &lifecycle,
                            std::uint64_t generation)
{
    std::array<std::byte, 24> bytes{};
    GfxPresentationReceipt receipt{};
    assert(lifecycle.prepareCommand(generation, bytes, receipt));
    return receipt;
}

void mapSurface(GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
                PixelSize visible, std::uint16_t surfaceId = 7)
{
    assert(lifecycle.open(generation));
    assert(lifecycle.acceptCapabilities(generation, advertisement()));
    auto receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.configureSurface(generation, surfaceId, visible));
    receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
}

std::array<std::byte, 20> acknowledge(std::uint32_t frameId)
{
    std::array<std::byte, 20> pdu{
        std::byte{13}, {}, {}, {}, std::byte{20}, {}, {}, {}};
    for (unsigned index = 0; index != 4; ++index)
        pdu[12U + index] =
            static_cast<std::byte>(frameId >> (8U * index));
    return pdu;
}

[[nodiscard]] bool hasNalType(std::span<const std::byte> wire,
                              std::uint8_t wantedType) noexcept
{
    // Producer fixtures are intentionally small enough to use RDP8 SINGLE,
    // so the H.264 Annex-B access unit remains contiguous after two bytes of
    // segmented-data framing.
    if (wire.size() < 3U || wire[0] != std::byte{0xE0} ||
        wire[1] != std::byte{0x04})
    {
        return false;
    }
    wire = wire.subspan(2U);
    for (std::size_t index = 0; index + 4U < wire.size(); ++index)
    {
        std::size_t header = 0;
        if (wire[index] == std::byte{} &&
            wire[index + 1U] == std::byte{} &&
            wire[index + 2U] == std::byte{1})
        {
            header = index + 3U;
        }
        else if (index + 4U < wire.size() &&
                 wire[index] == std::byte{} &&
                 wire[index + 1U] == std::byte{} &&
                 wire[index + 2U] == std::byte{} &&
                 wire[index + 3U] == std::byte{1})
        {
            header = index + 4U;
        }
        if (header != 0 && header < wire.size() &&
            (std::to_integer<std::uint8_t>(wire[header]) & 0x1fU) ==
                wantedType)
        {
            return true;
        }
    }
    return false;
}

constexpr PixelSize kCoded{160, 96};
constexpr PixelSize kVisible{160, 90};
constexpr std::array<Rectangle, 1> kRegions{
    Rectangle{0, 0, kVisible.widthPixels, kVisible.heightPixels}};
constexpr std::array<GfxAvc420QuantQuality, 1> kQuality{{{23, 80}}};

X264Avc420FrameRequest request(std::uint32_t frameId,
                               const Nv12Frame &frame,
                               std::int64_t pts,
                               std::uint16_t surfaceId = 7) noexcept
{
    return {surfaceId, frameId, frame.view(pts), kRegions, kQuality};
}

void encodedDeliveryContinuity()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 4001, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(4001, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 3);
    const auto secondPixels = makeFrame(kCoded, 11);

    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, 4001, request(1, firstPixels, 10), first));
    assert(first.valid() && first.generation() == 4001 && first.frameId() == 1);
    assert(hasNalType(first.wireBytes(), 7));
    assert(hasNalType(first.wireBytes(), 8));
    assert(hasNalType(first.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));

    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(4001, acknowledge(1), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);

    GfxAvc420SegmentedFrame second;
    assert(producer.prepare(
        lifecycle, 4001, request(2, secondPixels, 11), second));
    assert(hasNalType(second.wireBytes(), 1));
    assert(!hasNalType(second.wireBytes(), 5));
}

void backpressureDoesNotAdvanceEncoder()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 4002, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(4002, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 5);
    const auto secondPixels = makeFrame(kCoded, 9);
    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, 4002, request(10, firstPixels, 0), first));

    GfxAvc420SegmentedFrame denied;
    assert(!producer.prepare(
        lifecycle, 4002, request(11, secondPixels, 1), denied));
    assert(!denied.valid());

    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(4002, acknowledge(10), result));

    GfxAvc420SegmentedFrame second;
    assert(producer.prepare(
        lifecycle, 4002, request(11, secondPixels, 1), second));
    assert(hasNalType(second.wireBytes(), 1));
    assert(!hasNalType(second.wireBytes(), 5));
}

void ownedOutputReusePreflightPreservesReferences()
{
    constexpr std::uint64_t subjectGeneration = 6101;
    constexpr std::uint64_t controlGeneration = 6102;
    constexpr std::uint64_t foreignGeneration = 6103;

    GfxPresentationLifecycle subjectLifecycle;
    GfxPresentationLifecycle controlLifecycle;
    GfxPresentationLifecycle foreignLifecycle;
    mapSurface(subjectLifecycle, subjectGeneration, kVisible);
    mapSurface(controlLifecycle, controlGeneration, kVisible);
    mapSurface(foreignLifecycle, foreignGeneration, kVisible);

    X264Avc420SegmentedFrameProducer subject;
    X264Avc420SegmentedFrameProducer control;
    X264Avc420SegmentedFrameProducer foreign;
    assert(subject.open(subjectGeneration, kCoded, kVisible));
    assert(control.open(controlGeneration, kCoded, kVisible));
    assert(foreign.open(foreignGeneration, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 5);
    const auto deniedPixels = makeFrame(kCoded, 97);
    const auto nextPixels = makeFrame(kCoded, 19);

    auto establishReference = [&](GfxPresentationLifecycle &lifecycle,
                                  X264Avc420SegmentedFrameProducer &producer,
                                  std::uint64_t generation)
    {
        GfxAvc420SegmentedFrame frame;
        assert(producer.prepare(
            lifecycle, generation, request(40U, firstPixels, 0), frame));
        assert(hasNalType(frame.wireBytes(), 5));
        assert(producer.completeDelivery(
            lifecycle, frame, frame.wireBytes().size()));
        GfxFrameAckWindowResult result{};
        assert(lifecycle.onFrameAcknowledge(
            generation, acknowledge(40U), result));
        assert(result == GfxFrameAckWindowResult::Acknowledged);
    };
    establishReference(subjectLifecycle, subject, subjectGeneration);
    establishReference(controlLifecycle, control, controlGeneration);

    GfxAvc420SegmentedFrame occupiedOutput;
    assert(foreign.prepare(
        foreignLifecycle, foreignGeneration,
        request(90U, deniedPixels, 0), occupiedOutput));
    const std::vector<std::byte> foreignBytes(
        occupiedOutput.wireBytes().begin(), occupiedOutput.wireBytes().end());

    assert(!subject.prepare(
        subjectLifecycle, subjectGeneration,
        request(41U, deniedPixels, 1), occupiedOutput));
    assert(occupiedOutput.generation() == foreignGeneration);
    assert(occupiedOutput.frameId() == 90U);
    assert(std::vector<std::byte>(occupiedOutput.wireBytes().begin(),
                                  occupiedOutput.wireBytes().end()) ==
           foreignBytes);
    assert(subjectLifecycle.canReserveFrame(subjectGeneration, 41U));

    GfxAvc420SegmentedFrame subjectNext;
    GfxAvc420SegmentedFrame controlNext;
    assert(subject.prepare(
        subjectLifecycle, subjectGeneration,
        request(41U, nextPixels, 1), subjectNext));
    assert(control.prepare(
        controlLifecycle, controlGeneration,
        request(41U, nextPixels, 1), controlNext));
    assert(hasNalType(subjectNext.wireBytes(), 1));
    assert(!hasNalType(subjectNext.wireBytes(), 5));

    const std::vector<std::byte> subjectBytes(
        subjectNext.wireBytes().begin(), subjectNext.wireBytes().end());
    const std::vector<std::byte> controlBytes(
        controlNext.wireBytes().begin(), controlNext.wireBytes().end());
    assert(subjectBytes == controlBytes);

    assert(subject.completeDelivery(
        subjectLifecycle, subjectNext, subjectNext.wireBytes().size()));
    assert(control.completeDelivery(
        controlLifecycle, controlNext, controlNext.wireBytes().size()));
    assert(foreign.cancelUnwrittenDelivery(
        foreignLifecycle, occupiedOutput));
}

void retirementReusePreservesReferenceContinuity()
{
    constexpr std::uint64_t firstGeneration = 6104;
    constexpr std::uint64_t secondGeneration = 6105;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, firstGeneration, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(firstGeneration, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 31);
    const auto secondPixels = makeFrame(kCoded, 47);
    const auto thirdPixels = makeFrame(kCoded, 63);

    GfxAvc420SegmentedFrame output;
    assert(producer.prepare(
        lifecycle, firstGeneration, request(42U, firstPixels, 0), output));
    assert(hasNalType(output.wireBytes(), 5));
    const std::size_t firstWireBytes = output.wireBytes().size();
    assert(!producer.completeDelivery(
        lifecycle, output, firstWireBytes - 1U));
    assert(output.valid());
    assert(producer.completeDelivery(
        lifecycle, output, firstWireBytes));
    assert(!output.valid());
    assert(output.wireBytes().empty());
    assert(producer.valid());

    assert(producer.prepare(
        lifecycle, firstGeneration, request(43U, secondPixels, 1), output));
    assert(hasNalType(output.wireBytes(), 1));
    assert(!hasNalType(output.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, output, output.wireBytes().size()));
    assert(!output.valid());

    assert(producer.prepare(
        lifecycle, firstGeneration, request(44U, thirdPixels, 2), output));
    assert(output.valid());
    assert(producer.abortDelivery(lifecycle, output));
    assert(!output.valid());
    assert(output.wireBytes().empty());
    assert(!producer.valid());
    assert(lifecycle.stage() == GfxPresentationStage::Inactive);

    mapSurface(lifecycle, secondGeneration, kVisible);
    assert(producer.open(secondGeneration, kCoded, kVisible));
    assert(producer.prepare(
        lifecycle, secondGeneration, request(45U, firstPixels, 0), output));
    assert(hasNalType(output.wireBytes(), 5));
    assert(producer.cancelUnwrittenDelivery(lifecycle, output));
    assert(!output.valid());
}

void metadataPreflightPreservesReferences()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 4003, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(4003, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 7);
    const auto secondPixels = makeFrame(kCoded, 17);
    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, 4003, request(20, firstPixels, 0), first));
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(4003, acknowledge(20), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);

    auto malformed = request(21, secondPixels, 1);
    const std::array<GfxAvc420QuantQuality, 1> badQuality{{{52, 80}}};
    malformed.quantQualities = badQuality;
    GfxAvc420SegmentedFrame denied;
    assert(!producer.prepare(lifecycle, 4003, malformed, denied));
    assert(!denied.valid());
    assert(lifecycle.canSubmitFrame(4003));
    assert(producer.valid());

    const std::array<Rectangle, 1> outside{
        Rectangle{0, 0, kVisible.widthPixels, kVisible.heightPixels + 2U}};
    malformed = request(21, secondPixels, 1);
    malformed.regions = outside;
    assert(!producer.prepare(lifecycle, 4003, malformed, denied));
    assert(lifecycle.canSubmitFrame(4003));

    GfxAvc420SegmentedFrame second;
    assert(producer.prepare(
        lifecycle, 4003, request(21, secondPixels, 1), second));
    assert(hasNalType(second.wireBytes(), 1));
    assert(!hasNalType(second.wireBytes(), 5));
}

void abortAndGenerationReset()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 4004, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(4004, kCoded, kVisible));

    const auto pixels = makeFrame(kCoded, 13);
    GfxAvc420SegmentedFrame aborted;
    assert(producer.prepare(
        lifecycle, 4004, request(30, pixels, 0), aborted));
    assert(producer.abortDelivery(lifecycle, aborted));
    assert(!producer.valid());
    assert(lifecycle.stage() == GfxPresentationStage::Inactive);

    mapSurface(lifecycle, 4005, kVisible);
    assert(producer.open(4005, kCoded, kVisible));
    GfxAvc420SegmentedFrame fresh;
    assert(producer.prepare(
        lifecycle, 4005, request(30, pixels, 0), fresh));
    assert(hasNalType(fresh.wireBytes(), 7));
    assert(hasNalType(fresh.wireBytes(), 8));
    assert(hasNalType(fresh.wireBytes(), 5));
    assert(!producer.completeDelivery(
        lifecycle, aborted, aborted.wireBytes().size()));
}


struct BgraFrame final
{
    PixelSize visible{};
    std::size_t stride{};
    std::vector<std::byte> pixels{};

    [[nodiscard]] FramebufferView view() const noexcept
    {
        return {pixels, visible.widthPixels, visible.heightPixels, stride};
    }

    void paint(std::uint32_t column, std::uint32_t row,
               std::uint8_t red, std::uint8_t green,
               std::uint8_t blue, std::uint8_t alpha) noexcept
    {
        const std::size_t at =
            static_cast<std::size_t>(row) * stride +
            static_cast<std::size_t>(column) * 4U;
        pixels[at] = static_cast<std::byte>(blue);
        pixels[at + 1U] = static_cast<std::byte>(green);
        pixels[at + 2U] = static_cast<std::byte>(red);
        pixels[at + 3U] = static_cast<std::byte>(alpha);
    }

    void solid(std::uint8_t red, std::uint8_t green,
               std::uint8_t blue, std::uint8_t alpha) noexcept
    {
        for (std::uint32_t row = 0; row < visible.heightPixels; ++row)
            for (std::uint32_t column = 0; column < visible.widthPixels;
                 ++column)
                paint(column, row, red, green, blue, alpha);
    }
};

BgraFrame makeBgraFrame(PixelSize visible, std::size_t rowPadding = 0)
{
    const std::size_t stride =
        static_cast<std::size_t>(visible.widthPixels) * 4U + rowPadding;
    BgraFrame frame{visible, stride,
                    std::vector<std::byte>(
                        stride * visible.heightPixels, std::byte{0xA5})};
    frame.solid(0, 0, 0, 0);
    return frame;
}

X264BgraFrameRequest bgraRequest(std::uint32_t frameId,
                                 const BgraFrame &frame,
                                 std::int64_t pts) noexcept
{
    return {7, frameId, frame.view(), pts, kRegions, kQuality};
}

void bgraBt709PixelOracle()
{
    BgraNv12Converter converter;
    auto input = makeBgraFrame({2, 2});
    constexpr PixelSize visible{2, 2};
    constexpr PixelSize coded{16, 16};

    // Independently tabulated Q16 full-range BT.709 primary oracles.
    struct Expected final
    {
        std::uint8_t red;
        std::uint8_t green;
        std::uint8_t blue;
        std::uint8_t y;
        std::uint8_t u;
        std::uint8_t v;
    };
    constexpr std::array<Expected, 6> colors{{
        {0, 0, 0, 0, 128, 128},
        {255, 255, 255, 255, 128, 128},
        {255, 0, 0, 54, 99, 255},
        {0, 255, 0, 182, 30, 12},
        {0, 0, 255, 18, 255, 116},
        {128, 64, 32, 75, 105, 161},
    }};
    for (const auto expected : colors)
    {
        input.solid(expected.red, expected.green, expected.blue, 0);
        assert(converter.convert(input.view(), visible, coded, 9));
        const auto result = converter.picture();
        assert(result.codedGeometry == coded && result.pts == 9);
        assert(result.yStrideBytes == 16 && result.uvStrideBytes == 16);
        assert(result.yPlane.size() == 256 && result.uvPlane.size() == 128);
        assert(result.yPlane[0] == static_cast<std::byte>(expected.y));
        assert(result.yPlane[17] == static_cast<std::byte>(expected.y));
        assert(result.yPlane[255] == static_cast<std::byte>(expected.y));
        assert(result.uvPlane[0] == static_cast<std::byte>(expected.u));
        assert(result.uvPlane[1] == static_cast<std::byte>(expected.v));

        // Alpha is ignored, including fully transparent vs opaque desktop.
        input.solid(expected.red, expected.green, expected.blue, 255);
        assert(converter.convert(input.view(), visible, coded, 9));
        assert(converter.picture().yPlane[0] ==
               static_cast<std::byte>(expected.y));
        assert(converter.picture().uvPlane[0] ==
               static_cast<std::byte>(expected.u));
    }

    input.paint(0, 0, 255, 0, 0, 0);
    input.paint(1, 0, 0, 255, 0, 64);
    input.paint(0, 1, 0, 0, 255, 128);
    input.paint(1, 1, 255, 255, 255, 255);
    assert(converter.convert(input.view(), visible, coded, 10));
    const auto result = converter.picture();
    assert(result.yPlane[0] == std::byte{54});
    assert(result.yPlane[1] == std::byte{182});
    assert(result.yPlane[16] == std::byte{18});
    assert(result.yPlane[17] == std::byte{255});
    // Mean RGB of the 2x2 block is neutral 128,128,128.
    assert(result.uvPlane[0] == std::byte{128});
    assert(result.uvPlane[1] == std::byte{128});
}

void bgraStridePaddingLifetime()
{
    BgraNv12Converter converter;
    constexpr PixelSize visible{18, 18};
    constexpr PixelSize coded{32, 32};
    auto input = makeBgraFrame(visible, 11);
    input.paint(0, 0, 0, 0, 255, 0);
    input.paint(17, 17, 255, 0, 0, 0);
    assert(converter.convert(input.view(), visible, coded, 30));
    const auto picture = converter.picture();
    assert(picture.yStrideBytes == 32 && picture.uvStrideBytes == 32);
    assert(picture.yPlane.size() == 1024 && picture.uvPlane.size() == 512);
    assert(picture.yPlane[0] == std::byte{18});
    assert(picture.yPlane[31U * 32U + 31U] == std::byte{54});
    const std::size_t bottomChroma = 15U * 32U + 30U;
    assert(picture.uvPlane[bottomChroma] == std::byte{99});
    assert(picture.uvPlane[bottomChroma + 1U] == std::byte{255});
    const auto *const originalStorage = picture.yPlane.data();
    const std::size_t originalCapacity = converter.capacityBytes();

    // A native owner may unmap/free its capture immediately after convert.
    input.pixels.clear();
    input.pixels.shrink_to_fit();
    assert(converter.picture().yPlane[0] == std::byte{18});
    assert(converter.picture().yPlane[31U * 32U + 31U] == std::byte{54});

    auto next = makeBgraFrame(visible, 3);
    next.solid(0, 255, 0, 255);
    assert(converter.convert(next.view(), visible, coded, 31));
    assert(converter.capacityBytes() == originalCapacity);
    assert(converter.picture().yPlane.data() == originalStorage);
    assert(converter.picture().yPlane[0] == std::byte{182});
    assert(converter.picture().yPlane.back() == std::byte{182});
    assert(converter.picture().uvPlane.back() == std::byte{12});
}

void bgraInvalidFrameDenials()
{
    BgraNv12Converter converter;
    auto input = makeBgraFrame({2, 2});
    constexpr PixelSize visible{2, 2};
    constexpr PixelSize coded{16, 16};
    assert(converter.convert(input.view(), visible, coded, 0));

    auto reject = [&](FramebufferView invalid,
                      PixelSize invalidVisible = PixelSize{2, 2},
                      PixelSize invalidCoded = PixelSize{16, 16})
    {
        assert(!converter.convert(invalid, invalidVisible,
                                  invalidCoded, 0));
        assert(converter.picture().yPlane.empty());
        assert(converter.picture().uvPlane.empty());
    };

    reject({input.pixels, 0, 2, 8});
    reject({input.pixels, 2, 0, 8});
    reject({input.pixels, 2, 2, 7});
    reject({std::span<const std::byte>(input.pixels).first(15), 2, 2, 8});
    reject({input.pixels, 2, 2,
            std::numeric_limits<std::size_t>::max()});
    reject(input.view(), {3, 2}, coded);
    reject(input.view(), {2, 3}, coded);
    reject(input.view(), visible, {32, 16});
    reject(input.view(), {65520, 65520}, {65520, 65520});

    // Reinterpret converter-owned luma as a source to prove overlap denial.
    assert(converter.convert(input.view(), visible, coded, 1));
    const auto published = converter.picture();
    reject({published.yPlane.first(16), 2, 2, 8});
    assert(converter.convert(input.view(), visible, coded, 2));
    assert(!converter.picture().yPlane.empty());
}

void bgraResetRetainsScratchReuse()
{
    BgraNv12Converter converter;
    constexpr PixelSize visible{2, 2};
    constexpr PixelSize coded{16, 16};
    auto first = makeBgraFrame(visible, 7);
    first.solid(255, 0, 0, 0);
    assert(converter.convert(first.view(), visible, coded, 1));

    const auto before = converter.picture();
    const std::byte *const scratchAddress = before.yPlane.data();
    const std::size_t scratchCapacity = converter.capacityBytes();
    assert(scratchAddress != nullptr && scratchCapacity >= 384U);
    assert(before.yPlane[0] == std::byte{54});

    converter.reset();
    // Reset must invalidate both planes and metadata, not release scratch.
    assert(converter.picture().yPlane.empty());
    assert(converter.picture().uvPlane.empty());
    assert(converter.picture().codedGeometry == PixelSize{});
    assert(converter.capacityBytes() == scratchCapacity);

    // No BGRA input may alias retained scratch, including after reset.
    const FramebufferView overlapping{
        std::span<const std::byte>(scratchAddress, 16U), 2, 2, 8};
    assert(!converter.convert(overlapping, visible, coded, 2));
    assert(converter.picture().yPlane.empty());
    assert(converter.capacityBytes() == scratchCapacity);

    auto second = makeBgraFrame(visible, 5);
    second.solid(0, 255, 0, 255);
    assert(converter.convert(second.view(), visible, coded, 3));
    const auto after = converter.picture();
    assert(after.yPlane.data() == scratchAddress);
    assert(converter.capacityBytes() == scratchCapacity);
    assert(after.pts == 3 && after.yPlane[0] == std::byte{182});
    assert(after.uvPlane[0] == std::byte{30});
    assert(after.uvPlane[1] == std::byte{12});
}

void x264BgraSegmentedProductionChain()
{
    GfxPresentationLifecycle lifecycle;
    constexpr std::uint64_t generation = 6001;
    mapSurface(lifecycle, generation, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));
    auto firstPixels = makeBgraFrame(kVisible, 9);
    firstPixels.solid(64, 128, 192, 0);
    GfxAvc420SegmentedFrame first;
    assert(producer.prepareBgra(
        lifecycle, generation, bgraRequest(1, firstPixels, 0), first));
    assert(first.valid() && first.wireBytes().size() > 64U);
    assert(first.wireBytes()[0] == std::byte{0xE0});
    assert(first.wireBytes()[1] == std::byte{0x04});
    assert(hasNalType(first.wireBytes(), 7));
    assert(hasNalType(first.wireBytes(), 8));
    assert(hasNalType(first.wireBytes(), 5));
    assert(lifecycle.outstandingFrames() == 0);
    assert(!producer.completeDelivery(
        lifecycle, first, first.wireBytes().size() - 1U));
    assert(lifecycle.outstandingFrames() == 0);
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    assert(lifecycle.outstandingFrames() == 1);
    GfxFrameAckWindowResult acknowledgment{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(1), acknowledgment));
    assert(acknowledgment == GfxFrameAckWindowResult::Acknowledged);

    auto nextPixels = makeBgraFrame(kVisible, 5);
    nextPixels.solid(65, 128, 191, 255);
    GfxAvc420SegmentedFrame second;
    assert(producer.prepareBgra(
        lifecycle, generation, bgraRequest(2, nextPixels, 1), second));
    assert(hasNalType(second.wireBytes(), 1));
    assert(!hasNalType(second.wireBytes(), 5));
    GfxAvc420SegmentedFrame stale;
    assert(!producer.prepareBgra(
        lifecycle, generation - 1U,
        bgraRequest(3, nextPixels, 2), stale));
    assert(producer.abortDelivery(lifecycle, second));
    assert(!producer.valid());
    assert(lifecycle.stage() == GfxPresentationStage::Inactive);
    assert(!producer.prepareBgra(
        lifecycle, generation, bgraRequest(3, nextPixels, 2), stale));
}

void x264BgraBackpressureReferenceDenials()
{
    GfxPresentationLifecycle lifecycle;
    constexpr std::uint64_t generation = 6002;
    mapSurface(lifecycle, generation, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));
    auto pixels = makeBgraFrame(kVisible);
    pixels.solid(70, 90, 110, 0);

    GfxAvc420SegmentedFrame first;
    assert(producer.prepareBgra(
        lifecycle, generation, bgraRequest(4, pixels, 0), first));
    GfxAvc420SegmentedFrame denied;
    assert(!producer.prepareBgra(
        lifecycle, generation, bgraRequest(5, pixels, 1), denied));
    assert(!denied.valid());
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    GfxFrameAckWindowResult acknowledgment{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(4), acknowledgment));
    assert(acknowledgment == GfxFrameAckWindowResult::Acknowledged);

    const std::array<GfxAvc420QuantQuality, 1> malformedQuality{{{52, 80}}};
    auto badMetadata = bgraRequest(5, pixels, 1);
    badMetadata.quantQualities = malformedQuality;
    assert(!producer.prepareBgra(
        lifecycle, generation, badMetadata, denied));
    auto badSource = bgraRequest(5, pixels, 1);
    badSource.framebuffer.strideBytes = 2;
    assert(!producer.prepareBgra(
        lifecycle, generation, badSource, denied));
    badSource = bgraRequest(5, pixels, 1);
    badSource.framebuffer.pixels =
        badSource.framebuffer.pixels.first(4);
    assert(!producer.prepareBgra(
        lifecycle, generation, badSource, denied));
    assert(producer.valid() && lifecycle.canSubmitFrame(generation));

    pixels.solid(72, 91, 112, 255);
    GfxAvc420SegmentedFrame second;
    assert(producer.prepareBgra(
        lifecycle, generation, bgraRequest(5, pixels, 1), second));
    assert(hasNalType(second.wireBytes(), 1));
    assert(!hasNalType(second.wireBytes(), 5));
}

void duplicatePendingFrameIdPreservesReferences()
{
    // An ACK-pending ID collides in the one authoritative R4 ACK window,
    // even after its full wire send has completed. Refuse it before x264
    // runs so the next distinct picture remains an inter-frame P slice.
    {
        constexpr std::uint64_t generation = 6201;
        GfxPresentationLifecycle lifecycle;
        mapSurface(lifecycle, generation, kVisible);
        X264Avc420SegmentedFrameProducer producer;
        assert(producer.open(generation, kCoded, kVisible));

        const auto firstPixels = makeFrame(kCoded, 4);
        const auto duplicatePixels = makeFrame(kCoded, 15);
        const auto secondPixels = makeFrame(kCoded, 23);
        GfxAvc420SegmentedFrame first;
        assert(producer.prepare(
            lifecycle, generation, request(51, firstPixels, 0), first));
        assert(hasNalType(first.wireBytes(), 5));
        assert(producer.completeDelivery(
            lifecycle, first, first.wireBytes().size()));
        assert(lifecycle.outstandingFrames() == 1);
        assert(lifecycle.canSubmitFrame(generation));
        assert(!lifecycle.canReserveFrame(generation, 51));
        assert(lifecycle.canReserveFrame(generation, 52));

        GfxAvc420SegmentedFrame denied;
        assert(!producer.prepare(
            lifecycle, generation, request(51, duplicatePixels, 1), denied));
        assert(!denied.valid());
        assert(producer.valid());
        assert(lifecycle.outstandingFrames() == 1);

        GfxAvc420SegmentedFrame second;
        assert(producer.prepare(
            lifecycle, generation, request(52, secondPixels, 2), second));
        assert(hasNalType(second.wireBytes(), 1));
        assert(!hasNalType(second.wireBytes(), 5));
    }

    // The same duplicate-ID preflight must also run before BGRA conversion,
    // without moving pixels into a second codec or ACK bookkeeping owner.
    {
        constexpr std::uint64_t generation = 6202;
        GfxPresentationLifecycle lifecycle;
        mapSurface(lifecycle, generation, kVisible);
        X264Avc420SegmentedFrameProducer producer;
        assert(producer.open(generation, kCoded, kVisible));

        auto firstPixels = makeBgraFrame(kVisible, 7);
        firstPixels.solid(70, 100, 140, 0);
        GfxAvc420SegmentedFrame first;
        assert(producer.prepareBgra(
            lifecycle, generation, bgraRequest(61, firstPixels, 0), first));
        assert(hasNalType(first.wireBytes(), 5));
        assert(producer.completeDelivery(
            lifecycle, first, first.wireBytes().size()));
        assert(lifecycle.outstandingFrames() == 1);

        auto nextPixels = makeBgraFrame(kVisible, 5);
        nextPixels.solid(90, 120, 150, 255);
        GfxAvc420SegmentedFrame denied;
        assert(!producer.prepareBgra(
            lifecycle, generation, bgraRequest(61, nextPixels, 1), denied));
        assert(!denied.valid());
        assert(lifecycle.canReserveFrame(generation, 62));
        assert(producer.valid());

        GfxAvc420SegmentedFrame second;
        assert(producer.prepareBgra(
            lifecycle, generation, bgraRequest(62, nextPixels, 2), second));
        assert(hasNalType(second.wireBytes(), 1));
        assert(!hasNalType(second.wireBytes(), 5));
    }
}


void malformedNv12PreflightPreservesReferences()
{
    constexpr std::uint64_t generation = 6301;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, generation, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));

    const auto initialPixels = makeFrame(kCoded, 9);
    const auto laterPixels = makeFrame(kCoded, 24);
    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, generation, request(70, initialPixels, 0), first));
    assert(hasNalType(first.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));

    GfxFrameAckWindowResult acknowledged{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(70), acknowledged));
    assert(acknowledged == GfxFrameAckWindowResult::Acknowledged);
    assert(lifecycle.outstandingFrames() == 0);

    // Each malformed span or stride is rejected by the real encoder's
    // shared extent validator before x264 can consume a reference picture.
    const auto valid = request(71, laterPixels, 1);
    const auto reject = [&](const X264Nv12PictureView &invalidPicture)
    {
        X264Avc420FrameRequest invalid = valid;
        invalid.picture = invalidPicture;
        GfxAvc420SegmentedFrame rejected;
        assert(!producer.prepare(lifecycle, generation, invalid, rejected));
        assert(!rejected.valid());
        assert(producer.valid());
        assert(lifecycle.canReserveFrame(generation, 71));
        assert(lifecycle.outstandingFrames() == 0);
    };

    {
        auto malformed = valid.picture;
        malformed.yPlane = malformed.yPlane.first(malformed.yPlane.size() - 1U);
        reject(malformed);
    }
    {
        auto malformed = valid.picture;
        malformed.uvPlane =
            malformed.uvPlane.first(malformed.uvPlane.size() - 1U);
        reject(malformed);
    }
    {
        auto malformed = valid.picture;
        malformed.yStrideBytes = kCoded.widthPixels - 1U;
        reject(malformed);
    }
    {
        auto malformed = valid.picture;
        malformed.uvStrideBytes =
            std::numeric_limits<std::size_t>::max();
        reject(malformed);
    }
    {
        auto malformed = valid.picture;
        malformed.codedGeometry = {kCoded.widthPixels + 16U,
                                   kCoded.heightPixels};
        reject(malformed);
    }
    {
        auto malformed = valid.picture;
        malformed.yPlane = {};
        reject(malformed);
    }

    // No deterministic denial may force an IDR in the next valid frame.
    GfxAvc420SegmentedFrame second;
    assert(producer.prepare(lifecycle, generation, valid, second));
    assert(hasNalType(second.wireBytes(), 1));
    assert(!hasNalType(second.wireBytes(), 5));
}



void x264SegmentedUnsentCancelIdr()
{
    constexpr std::uint64_t generation = 6701;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, generation, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 5);
    const auto canceledPixels = makeFrame(kCoded, 17);
    const auto recoveryPixels = makeFrame(kCoded, 29);
    const auto continuationPixels = makeFrame(kCoded, 41);

    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, generation, request(110U, firstPixels, 7), first));
    assert(hasNalType(first.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    assert(lifecycle.outstandingFrames() == 1U);

    GfxAvc420SegmentedFrame canceled;
    assert(producer.prepare(
        lifecycle, generation, request(111U, canceledPixels, -4), canceled));
    assert(hasNalType(canceled.wireBytes(), 1));
    assert(!hasNalType(canceled.wireBytes(), 5));
    assert(producer.cancelUnwrittenDelivery(lifecycle, canceled));
    assert(!canceled.valid());
    assert(producer.valid());
    assert(producer.generation() == generation);
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
    assert(lifecycle.outstandingFrames() == 1U);
    assert(lifecycle.canReserveFrame(generation, 111U));

    // The canceled frame is not in the ACK window and cannot retire frame A.
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(111U), result));
    assert(result == GfxFrameAckWindowResult::Unmatched);
    assert(lifecycle.outstandingFrames() == 1U);
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(110U), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);

    GfxAvc420SegmentedFrame recovery;
    assert(producer.prepare(
        lifecycle, generation,
        request(112U, recoveryPixels,
                std::numeric_limits<std::int64_t>::min()),
        recovery));
    assert(hasNalType(recovery.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, recovery, recovery.wireBytes().size()));
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(112U), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);

    // Duplicate/stale cancellation is rejected without resetting the healthy
    // post-recovery reference chain. The completed recovery object remains
    // structurally valid but no longer owns the pending lifecycle receipt.
    assert(!producer.cancelUnwrittenDelivery(lifecycle, canceled));
    assert(!producer.cancelUnwrittenDelivery(lifecycle, recovery));
    GfxAvc420SegmentedFrame continuation;
    assert(producer.prepare(
        lifecycle, generation,
        request(113U, continuationPixels,
                std::numeric_limits<std::int64_t>::max()),
        continuation));
    assert(hasNalType(continuation.wireBytes(), 1));
    assert(!hasNalType(continuation.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, continuation, continuation.wireBytes().size()));
}

void x264BgraUnsentCancelIdr()
{
    constexpr std::uint64_t generation = 6702;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, generation, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));

    // Padded stride exercises the native-framebuffer conversion boundary.
    auto pixels = makeBgraFrame(kVisible, 13);
    pixels.solid(80, 110, 140, 0);

    GfxAvc420SegmentedFrame first;
    assert(producer.prepareBgra(
        lifecycle, generation, bgraRequest(120U, pixels, 9), first));
    assert(hasNalType(first.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(120U), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);

    pixels.solid(90, 120, 150, 255);
    GfxAvc420SegmentedFrame canceled;
    assert(producer.prepareBgra(
        lifecycle, generation, bgraRequest(121U, pixels, -11), canceled));
    assert(hasNalType(canceled.wireBytes(), 1));
    assert(!hasNalType(canceled.wireBytes(), 5));
    assert(producer.cancelUnwrittenDelivery(lifecycle, canceled));
    assert(!canceled.valid());
    assert(producer.valid());
    assert(producer.generation() == generation);
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);

    pixels.solid(100, 130, 160, 64);
    GfxAvc420SegmentedFrame recovery;
    assert(producer.prepareBgra(
        lifecycle, generation,
        bgraRequest(122U, pixels,
                    std::numeric_limits<std::int64_t>::min()),
        recovery));
    assert(hasNalType(recovery.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, recovery, recovery.wireBytes().size()));
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(122U), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);

    pixels.solid(110, 140, 170, 192);
    GfxAvc420SegmentedFrame continuation;
    assert(producer.prepareBgra(
        lifecycle, generation,
        bgraRequest(123U, pixels,
                    std::numeric_limits<std::int64_t>::max()),
        continuation));
    assert(hasNalType(continuation.wireBytes(), 1));
    assert(!hasNalType(continuation.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, continuation, continuation.wireBytes().size()));
}

void zeroFrameIdDelivery()
{
    constexpr std::uint64_t generation = 6501;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, generation, kVisible);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 6);
    const auto duplicatePixels = makeFrame(kCoded, 14);
    const auto nextPixels = makeFrame(kCoded, 22);

    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, generation, request(0, firstPixels, 0), first));
    assert(first.valid() && first.frameId() == 0U);
    assert(hasNalType(first.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));
    assert(lifecycle.outstandingFrames() == 1U);

    // Zero participates in the same duplicate-pending gate as every other
    // uint32 frame ID, and the denial must occur before x264 advances.
    assert(!lifecycle.canReserveFrame(generation, 0U));
    GfxAvc420SegmentedFrame denied;
    assert(!producer.prepare(
        lifecycle, generation, request(0, duplicatePixels, 1), denied));
    assert(!denied.valid());
    assert(producer.valid());
    assert(lifecycle.outstandingFrames() == 1U);

    GfxFrameAckWindowResult acknowledged{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(0U), acknowledged));
    assert(acknowledged == GfxFrameAckWindowResult::Acknowledged);
    assert(lifecycle.outstandingFrames() == 0U);

    // The rejected duplicate zero did not touch codec history: the next
    // distinct frame remains reference-continuous instead of forcing IDR.
    GfxAvc420SegmentedFrame next;
    assert(producer.prepare(
        lifecycle, generation, request(1U, nextPixels, 2), next));
    assert(hasNalType(next.wireBytes(), 1));
    assert(!hasNalType(next.wireBytes(), 5));
    assert(producer.completeDelivery(
        lifecycle, next, next.wireBytes().size()));
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(1U), acknowledged));
    assert(acknowledged == GfxFrameAckWindowResult::Acknowledged);
}


void zeroSurfaceIdDelivery()
{
    constexpr std::uint64_t generation = 6601;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, generation, kVisible, 0);
    X264Avc420SegmentedFrameProducer producer;
    assert(producer.open(generation, kCoded, kVisible));

    const auto firstPixels = makeFrame(kCoded, 8);
    const auto nextPixels = makeFrame(kCoded, 19);
    GfxAvc420SegmentedFrame first;
    assert(producer.prepare(
        lifecycle, generation, request(10, firstPixels, 0, 0), first));
    assert(first.valid());
    assert(hasNalType(first.wireBytes(), 5));
    assert(first.wireBytes().size() > 27U);
    assert(first.wireBytes()[26] == std::byte{} &&
           first.wireBytes()[27] == std::byte{});
    assert(producer.completeDelivery(
        lifecycle, first, first.wireBytes().size()));

    GfxFrameAckWindowResult acknowledged{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(10), acknowledged));
    assert(acknowledged == GfxFrameAckWindowResult::Acknowledged);

    GfxAvc420SegmentedFrame next;
    assert(producer.prepare(
        lifecycle, generation, request(11, nextPixels, 1, 0), next));
    assert(hasNalType(next.wireBytes(), 1));
    assert(!hasNalType(next.wireBytes(), 5));
}

void fixedCfrPtsPreserveReferenceContinuity()
{
    // NV12: arbitrary caller PTS values must not become a second ordering
    // authority beside frame IDs and the ACK window.
    {
        constexpr std::uint64_t generation = 6401;
        GfxPresentationLifecycle lifecycle;
        mapSurface(lifecycle, generation, kVisible);
        X264Avc420SegmentedFrameProducer producer;
        assert(producer.open(generation, kCoded, kVisible));
        const auto pixels = makeFrame(kCoded, 31);
        constexpr std::array<std::int64_t, 6> ptsValues{
            3,
            3,
            -2,
            9000,
            std::numeric_limits<std::int64_t>::min(),
            std::numeric_limits<std::int64_t>::max(),
        };

        for (std::size_t index = 0; index < ptsValues.size(); ++index)
        {
            const auto frameId = static_cast<std::uint32_t>(80U + index);
            GfxAvc420SegmentedFrame frame;
            assert(producer.prepare(
                lifecycle, generation, request(frameId, pixels, ptsValues[index]),
                frame));
            if (index == 0)
            {
                assert(hasNalType(frame.wireBytes(), 5));
            }
            else
            {
                assert(hasNalType(frame.wireBytes(), 1));
                assert(!hasNalType(frame.wireBytes(), 5));
            }
            assert(producer.completeDelivery(
                lifecycle, frame, frame.wireBytes().size()));
            GfxFrameAckWindowResult acknowledged{};
            assert(lifecycle.onFrameAcknowledge(
                generation, acknowledge(frameId), acknowledged));
            assert(acknowledged == GfxFrameAckWindowResult::Acknowledged);
            assert(lifecycle.outstandingFrames() == 0);
        }
    }

    // BGRA uses the same contract after synchronous conversion. This also
    // proves no timestamp history is hidden in the retained NV12 scratch.
    {
        constexpr std::uint64_t generation = 6402;
        GfxPresentationLifecycle lifecycle;
        mapSurface(lifecycle, generation, kVisible);
        X264Avc420SegmentedFrameProducer producer;
        assert(producer.open(generation, kCoded, kVisible));
        auto pixels = makeBgraFrame(kVisible, 13);
        pixels.solid(94, 121, 149, 255);
        constexpr std::array<std::int64_t, 5> ptsValues{
            std::numeric_limits<std::int64_t>::max(),
            std::numeric_limits<std::int64_t>::min(),
            std::numeric_limits<std::int64_t>::min(),
            -17,
            6000,
        };

        for (std::size_t index = 0; index < ptsValues.size(); ++index)
        {
            const auto frameId = static_cast<std::uint32_t>(90U + index);
            GfxAvc420SegmentedFrame frame;
            assert(producer.prepareBgra(
                lifecycle, generation,
                bgraRequest(frameId, pixels, ptsValues[index]), frame));
            if (index == 0)
            {
                assert(hasNalType(frame.wireBytes(), 5));
            }
            else
            {
                assert(hasNalType(frame.wireBytes(), 1));
                assert(!hasNalType(frame.wireBytes(), 5));
            }
            assert(producer.completeDelivery(
                lifecycle, frame, frame.wireBytes().size()));
            GfxFrameAckWindowResult acknowledged{};
            assert(lifecycle.onFrameAcknowledge(
                generation, acknowledge(frameId), acknowledged));
            assert(acknowledged == GfxFrameAckWindowResult::Acknowledged);
            assert(lifecycle.outstandingFrames() == 0);
        }
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view behavior{argv[1]};
    if (behavior == "x264-segmented-delivery-continuity")
    {
        encodedDeliveryContinuity();
        return 0;
    }
    if (behavior == "x264-segmented-backpressure-preflight")
    {
        backpressureDoesNotAdvanceEncoder();
        return 0;
    }
    if (behavior == "x264-segmented-metadata-preflight")
    {
        metadataPreflightPreservesReferences();
        return 0;
    }
    if (behavior == "x264-segmented-owned-output-reuse-preflight")
    {
        ownedOutputReusePreflightPreservesReferences();
        return 0;
    }
    if (behavior == "x264-segmented-retirement-reuse")
    {
        retirementReusePreservesReferenceContinuity();
        return 0;
    }
    if (behavior == "x264-segmented-malformed-nv12-reference-continuity")
    {
        malformedNv12PreflightPreservesReferences();
        return 0;
    }
    if (behavior == "x264-segmented-duplicate-id-reference-continuity")
    {
        duplicatePendingFrameIdPreservesReferences();
        return 0;
    }
    if (behavior == "x264-segmented-abort-generation-reset")
    {
        abortAndGenerationReset();
        return 0;
    }
    if (behavior == "x264-segmented-unsent-cancel-idr")
    {
        x264SegmentedUnsentCancelIdr();
        return 0;
    }
    if (behavior == "x264-bgra-unsent-cancel-idr")
    {
        x264BgraUnsentCancelIdr();
        return 0;
    }
    if (behavior == "x264-segmented-zero-frame-id-delivery")
    {
        zeroFrameIdDelivery();
        return 0;
    }
    if (behavior == "x264-segmented-zero-surface-id-delivery")
    {
        zeroSurfaceIdDelivery();
        return 0;
    }
    if (behavior == "x264-segmented-cfr-pts-reference-continuity")
    {
        fixedCfrPtsPreserveReferenceContinuity();
        return 0;
    }
    if (behavior == "bgra-nv12-bt709-pixel-oracle")
    {
        bgraBt709PixelOracle();
        return 0;
    }
    if (behavior == "bgra-nv12-stride-padding-lifetime")
    {
        bgraStridePaddingLifetime();
        return 0;
    }
    if (behavior == "bgra-nv12-invalid-frame-denials")
    {
        bgraInvalidFrameDenials();
        return 0;
    }
    if (behavior == "bgra-nv12-reset-scratch-reuse")
    {
        bgraResetRetainsScratchReuse();
        return 0;
    }
    if (behavior == "x264-bgra-segmented-production-chain")
    {
        x264BgraSegmentedProductionChain();
        return 0;
    }
    if (behavior == "x264-bgra-backpressure-reference-denials")
    {
        x264BgraBackpressureReferenceDenials();
        return 0;
    }
    return 2;
}
