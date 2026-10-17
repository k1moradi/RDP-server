// SPDX-License-Identifier: GPL-3.0-or-later

#include "rdp/gfx_avc420_capabilities.h"
#include "rdp/gfx_avc420_segmented_frame.h"
#include "rdp/gfx_clearcodec.h"
#include "rdp/gfx_presentation_lifecycle.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace rdp_server::rdp;

namespace
{

struct TestCapability final
{
    std::uint32_t version{};
    std::uint32_t flags{};
};

void appendU16(
    std::vector<std::byte> &bytes,
    std::uint16_t value)
{
    bytes.emplace_back(static_cast<std::byte>(value));
    bytes.emplace_back(
        static_cast<std::byte>(value >> 8U));
}

void appendU32(
    std::vector<std::byte> &bytes,
    std::uint32_t value)
{
    appendU16(
        bytes, static_cast<std::uint16_t>(value));
    appendU16(
        bytes,
        static_cast<std::uint16_t>(value >> 16U));
}

void overwriteU32(
    std::vector<std::byte> &bytes,
    std::size_t offset,
    std::uint32_t value)
{
    for (std::size_t index = 0; index != 4U; ++index)
    {
        bytes[offset + index] =
            static_cast<std::byte>(
                value >> (8U * index));
    }
}

[[nodiscard]] std::vector<std::byte>
makeAdvertisement(
    std::initializer_list<TestCapability> capabilities)
{
    std::vector<std::byte> bytes;
    bytes.reserve(10U + capabilities.size() * 12U);
    appendU16(bytes, 0x0012U);
    appendU16(bytes, 0U);
    appendU32(bytes, 0U);
    appendU16(
        bytes,
        static_cast<std::uint16_t>(
            capabilities.size()));
    for (const TestCapability capability : capabilities)
    {
        appendU32(bytes, capability.version);
        appendU32(bytes, 4U);
        appendU32(bytes, capability.flags);
    }
    overwriteU32(
        bytes, 4U,
        static_cast<std::uint32_t>(bytes.size()));
    return bytes;
}

[[nodiscard]] std::uint16_t readU16(
    std::span<const std::byte> bytes,
    std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(
             std::to_integer<std::uint8_t>(
                 bytes[offset + 1U]))
         << 8U));
}

[[nodiscard]] std::uint32_t readU32(
    std::span<const std::byte> bytes,
    std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(
               readU16(bytes, offset)) |
           (static_cast<std::uint32_t>(
                readU16(bytes, offset + 2U))
            << 16U);
}

void completeNextCommand(
    GfxPresentationLifecycle &lifecycle,
    std::uint64_t generation)
{
    std::array<std::byte, 64> bytes{};
    GfxPresentationReceipt receipt{};
    assert(lifecycle.prepareCommand(
        generation, bytes, receipt));
    assert(receipt.bytes != 0U);
    assert(lifecycle.completeCommand(
        receipt, receipt.bytes));
}

void mapClearCodecSurface(
    GfxPresentationLifecycle &lifecycle,
    std::uint64_t generation,
    PixelSize geometry)
{
    assert(lifecycle.open(generation));
    const auto advertisement = makeAdvertisement(
        {{kGfxCapabilityVersion8, 0U}});
    assert(lifecycle.acceptCapabilities(
        generation, advertisement));
    assert(!lifecycle.avc420Enabled());
    completeNextCommand(lifecycle, generation);

    assert(lifecycle.configureSurface(
        generation, 7U, geometry));
    completeNextCommand(lifecycle, generation);
    completeNextCommand(lifecycle, generation);
    assert(
        lifecycle.stage() ==
        GfxPresentationStage::Mapped);
}

[[nodiscard]] std::array<std::byte, 20>
acknowledge(std::uint32_t frameId)
{
    std::array<std::byte, 20> pdu{
        std::byte{13}, {}, {}, {},
        std::byte{20}, {}, {}, {}};
    for (unsigned index = 0; index != 4U; ++index)
    {
        pdu[12U + index] =
            static_cast<std::byte>(
                frameId >> (8U * index));
    }
    return pdu;
}

[[nodiscard]] std::uint8_t
segmentedClearCodecSequence(
    const GfxAvc420SegmentedFrame &frame)
{
    const auto wire = frame.wireBytes();
    // This tiny fixture fits one RDP8 SINGLE segment. The ClearCodec sequence
    // lives at graphics offset 42 after START_FRAME + WIRE_TO_SURFACE_1 flags.
    assert(wire.size() > 44U);
    assert(wire[0] == std::byte{0xE0});
    assert(wire[1] == std::byte{0x04});
    return std::to_integer<std::uint8_t>(wire[44U]);
}

void residualFrameWire()
{
    // Three visible pixels plus four bytes of native pitch padding.
    const std::array<std::byte, 16> pixels{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{0xA1},
        std::byte{4}, std::byte{5}, std::byte{6}, std::byte{0xA2},
        std::byte{7}, std::byte{8}, std::byte{9}, std::byte{0xA3},
        std::byte{0xEE}, std::byte{0xEE},
        std::byte{0xEE}, std::byte{0xEE},
    };
    const GfxClearCodecFrameRequest request{
        7U, 0x11223344U,
        FramebufferView{pixels, 3U, 1U, 16U}};

    std::array<std::byte, 96> output{};
    output.fill(std::byte{0xCC});
    assert(gfxClearCodecFrameBytes(request) == 79U);
    assert(buildGfxClearCodecFrame(
               request, 0x5AU, output) == 79U);

    assert(readU16(output, 0U) == 0x000BU);
    assert(readU32(output, 4U) == 16U);
    assert(readU32(output, 12U) == request.frameId);

    assert(readU16(output, 16U) == 0x0001U);
    assert(readU32(output, 20U) == 51U);
    assert(readU16(output, 24U) == 7U);
    assert(readU16(output, 26U) == 0x0008U);
    assert(output[28U] == std::byte{0x20});
    assert(readU16(output, 29U) == 0U);
    assert(readU16(output, 31U) == 0U);
    assert(readU16(output, 33U) == 3U);
    assert(readU16(output, 35U) == 1U);
    assert(readU32(output, 37U) == 26U);

    // CLEARCODEC_BITMAP_STREAM: no cache/glyph flags, explicit sequence,
    // residual-only composite payload of three one-pixel RGB runs.
    assert(output[41U] == std::byte{0});
    assert(output[42U] == std::byte{0x5A});
    assert(readU32(output, 43U) == 12U);
    assert(readU32(output, 47U) == 0U);
    assert(readU32(output, 51U) == 0U);
    const std::array<std::byte, 12> expectedResidual{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{1},
        std::byte{4}, std::byte{5}, std::byte{6}, std::byte{1},
        std::byte{7}, std::byte{8}, std::byte{9}, std::byte{1},
    };
    for (std::size_t index = 0;
         index != expectedResidual.size();
         ++index)
    {
        assert(
            output[55U + index] ==
            expectedResidual[index]);
    }

    assert(readU16(output, 67U) == 0x000CU);
    assert(readU32(output, 71U) == 12U);
    assert(readU32(output, 75U) == request.frameId);
    for (std::size_t index = 79U;
         index != output.size();
         ++index)
    {
        assert(output[index] == std::byte{0xCC});
    }
}

void capabilityFallback()
{
    const auto clearCodec81 = makeAdvertisement(
        {{kGfxCapabilityVersion81, 0U}});
    const auto selected81 =
        negotiateGfxCapabilities(clearCodec81);
    assert(selected81.accepted());
    assert(
        selected81.selectedVersion ==
        kGfxCapabilityVersion81);
    assert(selected81.selectedFlags == 0U);
    assert(!selected81.avc420Enabled);
    assert(readU32(selected81.confirmation, 8U) ==
           kGfxCapabilityVersion81);
    assert(!negotiateGfxAvc420(clearCodec81).accepted());

    const auto clearCodec8 = makeAdvertisement(
        {{kGfxCapabilityVersion8, 0x02U}});
    const auto selected8 =
        negotiateGfxCapabilities(clearCodec8);
    assert(selected8.accepted());
    assert(
        selected8.selectedVersion ==
        kGfxCapabilityVersion8);
    assert(selected8.selectedFlags == 0x02U);
    assert(!selected8.avc420Enabled);
    assert(!negotiateGfxAvc420(clearCodec8).accepted());

    // Highest supported advertised profile wins. AVC420 becomes usable only
    // because the selected 8.1 set explicitly contains AVC420_ENABLED.
    const auto avcAndFallback = makeAdvertisement({
        {kGfxCapabilityVersion8, 0U},
        {0x000A0701U, 0x20U},
        {kGfxCapabilityVersion81, 0x10U},
    });
    const auto selectedAvc =
        negotiateGfxCapabilities(avcAndFallback);
    assert(selectedAvc.accepted());
    assert(
        selectedAvc.selectedVersion ==
        kGfxCapabilityVersion81);
    assert(selectedAvc.avc420Enabled);
    assert(negotiateGfxAvc420(avcAndFallback).accepted());

    // An 8.1 set with an unknown flag is not reflected. A valid lower 8.0
    // set remains a legal ClearCodec fallback.
    const auto lowerFallback = makeAdvertisement({
        {kGfxCapabilityVersion81, 0x10000U},
        {kGfxCapabilityVersion8, 0U},
    });
    const auto selectedLower =
        negotiateGfxCapabilities(lowerFallback);
    assert(selectedLower.accepted());
    assert(
        selectedLower.selectedVersion ==
        kGfxCapabilityVersion8);
    assert(!selectedLower.avc420Enabled);

    // R4 deliberately does not claim VERSION10+ support until its additional
    // protocol requirements, including QoE acknowledgement handling, exist.
    assert(!negotiateGfxCapabilities(
                makeAdvertisement(
                    {{0x000A0701U, 0x20U}}))
                .accepted());
}

void ownedDeliveryRecovery()
{
    static_assert(
        std::is_move_constructible_v<
            GfxAvc420SegmentedFrame>);
    static_assert(
        !std::is_move_assignable_v<
            GfxAvc420SegmentedFrame>);

    // Odd geometry proves the shared lifecycle no longer imposes AVC420's
    // even-dimension restriction on the mandatory ClearCodec fallback.
    constexpr PixelSize geometry{3U, 1U};
    const std::array<std::byte, 12> pixels{
        std::byte{10}, std::byte{20}, std::byte{30}, std::byte{0xFF},
        std::byte{40}, std::byte{50}, std::byte{60}, std::byte{0xFF},
        std::byte{70}, std::byte{80}, std::byte{90}, std::byte{0xFF},
    };
    const FramebufferView framebuffer{
        pixels, geometry.widthPixels,
        geometry.heightPixels, 12U};

    constexpr std::uint64_t firstGeneration = 9401U;
    GfxPresentationLifecycle lifecycle;
    mapClearCodecSurface(
        lifecycle, firstGeneration, geometry);

    GfxClearCodecFrameRequest request{
        7U, 91U, framebuffer};
    GfxAvc420SegmentedFrame frame;
    assert(prepareGfxClearCodecSegmentedFrame(
        lifecycle, firstGeneration,
        request, frame));
    assert(segmentedClearCodecSequence(frame) == 0U);

    // Conclusive zero publication consumes the same move-only owner but does
    // not consume ClearCodec sequence state. R3 must retire all borrows first.
    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame));
    assert(!frame.valid());

    assert(prepareGfxClearCodecSegmentedFrame(
        lifecycle, firstGeneration,
        request, frame));
    assert(segmentedClearCodecSequence(frame) == 0U);
    const std::size_t deliveredBytes =
        frame.wireBytes().size();
    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, deliveredBytes));
    assert(!frame.valid());
    assert(lifecycle.outstandingFrames() == 1U);

    GfxFrameAckWindowResult result{};
    const auto ack = acknowledge(request.frameId);
    assert(lifecycle.onFrameAcknowledge(
        firstGeneration, ack, result));
    assert(
        result ==
        GfxFrameAckWindowResult::Acknowledged);

    // Sequence advances only after complete R4-span delivery, never merely
    // after encoding. FRAME_ACKNOWLEDGE remains a later independent event.
    request.frameId = 92U;
    assert(prepareGfxClearCodecSegmentedFrame(
        lifecycle, firstGeneration,
        request, frame));
    assert(segmentedClearCodecSequence(frame) == 1U);

    // R3 maps header-only or any other positive/uncertain outer publication
    // to terminal abort; it must not manufacture an inner delivered count.
    assert(abortGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame));
    assert(!frame.valid());
    assert(
        lifecycle.stage() ==
        GfxPresentationStage::Inactive);

    // A fresh authenticated graphics generation restarts the remote-session
    // ClearCodec sequence from zero.
    constexpr std::uint64_t secondGeneration = 9402U;
    mapClearCodecSurface(
        lifecycle, secondGeneration, geometry);
    request.frameId = 93U;
    assert(prepareGfxClearCodecSegmentedFrame(
        lifecycle, secondGeneration,
        request, frame));
    assert(segmentedClearCodecSequence(frame) == 0U);
    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame));
}

void denials()
{
    const std::array<std::byte, 16> pixels{};
    const GfxClearCodecFrameRequest valid{
        7U, 5U,
        FramebufferView{pixels, 2U, 2U, 8U}};

    std::array<std::byte, 96> output{};
    output.fill(std::byte{0xA5});
    const std::size_t required =
        gfxClearCodecFrameBytes(valid);
    assert(required == 83U);
    assert(buildGfxClearCodecFrame(
               valid, 0U,
               std::span<std::byte>{output}
                   .first(required - 1U)) == 0U);
    for (const std::byte value : output)
        assert(value == std::byte{0xA5});

    auto badStride = valid;
    badStride.framebuffer.strideBytes = 7U;
    assert(gfxClearCodecFrameBytes(badStride) == 0U);

    auto truncated = valid;
    truncated.framebuffer.pixels =
        std::span<const std::byte>{pixels}.first(15U);
    assert(gfxClearCodecFrameBytes(truncated) == 0U);

    // Source/output aliasing is denied before the first output byte changes.
    std::vector<std::byte> overlap(128U, std::byte{0xCC});
    for (std::size_t index = 0; index != 16U; ++index)
        overlap[index] = static_cast<std::byte>(index);
    const auto before = overlap;
    const GfxClearCodecFrameRequest overlapping{
        7U, 6U,
        FramebufferView{
            std::span<const std::byte>{overlap}.first(16U),
            2U, 2U, 8U}};
    assert(buildGfxClearCodecFrame(
               overlapping, 0U, overlap) == 0U);
    assert(overlap == before);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;

    const std::string_view behavior{argv[1]};
    if (behavior == "clearcodec-residual-frame-wire")
    {
        residualFrameWire();
        return 0;
    }
    if (behavior == "clearcodec-capability-fallback")
    {
        capabilityFallback();
        return 0;
    }
    if (behavior == "clearcodec-owned-delivery-recovery")
    {
        ownedDeliveryRecovery();
        return 0;
    }
    if (behavior == "clearcodec-denials")
    {
        denials();
        return 0;
    }
    return 2;
}
