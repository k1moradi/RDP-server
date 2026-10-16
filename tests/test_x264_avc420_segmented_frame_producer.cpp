// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/x264_avc420_segmented_frame_producer.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
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
                PixelSize visible)
{
    assert(lifecycle.open(generation));
    assert(lifecycle.acceptCapabilities(generation, advertisement()));
    auto receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.configureSurface(generation, 7, visible));
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
                               std::int64_t pts) noexcept
{
    return {7, frameId, frame.view(pts), kRegions, kQuality};
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
    if (behavior == "x264-segmented-abort-generation-reset")
    {
        abortAndGenerationReset();
        return 0;
    }
    return 2;
}
