// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/gfx_avc420_segmented_frame.h"
#include "rdp/gfx_segmented_data.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace rdp_server::rdp;

namespace
{

using CommandReceipt = GfxPresentationReceipt;

std::array<std::byte, 22> advertisement()
{
    return {std::byte{0x12}, {}, {}, {}, std::byte{22}, {}, {}, {},
            std::byte{1}, {}, std::byte{5}, std::byte{1}, std::byte{8}, {},
            std::byte{4}, {}, {}, {}, std::byte{0x10}, {}, {}, {}};
}

CommandReceipt emit(GfxPresentationLifecycle &lifecycle,
                    std::uint64_t generation)
{
    std::array<std::byte, 24> bytes{};
    CommandReceipt receipt{};
    assert(lifecycle.prepareCommand(generation, bytes, receipt));
    return receipt;
}

void mapSurface(GfxPresentationLifecycle &lifecycle, std::uint64_t generation)
{
    assert(lifecycle.open(generation));
    assert(lifecycle.acceptCapabilities(generation, advertisement()));
    auto receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.configureSurface(generation, 7, {640, 480}));
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

constexpr std::array<std::byte, 7> kAnnexB{
    std::byte{}, std::byte{}, std::byte{}, std::byte{1},
    std::byte{0x65}, std::byte{0xA1}, std::byte{0xB2}};
constexpr std::array<Rectangle, 1> kRegion{
    Rectangle{0, 0, 640, 480}};
constexpr std::array<GfxAvc420QuantQuality, 1> kQuality{{{22, 80}}};

GfxAvc420Picture picture(std::uint32_t frameId,
                         std::span<const std::byte> annexB = kAnnexB)
{
    return {7, frameId, {640, 480}, kRegion, kQuality, annexB};
}

void singleWire()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 3001);
    const auto source = picture(41);
    const std::size_t graphicsBytes =
        gfxAvc420PictureBytes(source.regions.size(),
                              source.annexBPicture.size());
    assert(graphicsBytes == 74);

    GfxAvc420SegmentedFrame frame;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, 3001, source, frame));
    assert(frame.valid());
    assert(frame.generation() == 3001);
    assert(frame.frameId() == 41);
    assert(frame.wireBytes().size() == gfxSegmentedDataBytes(graphicsBytes));
    assert(frame.wireBytes()[0] == std::byte{0xE0});
    assert(frame.wireBytes()[1] == std::byte{0x04});
    assert(frame.wireBytes()[2] == std::byte{0x0B});
    assert(frame.wireBytes()[18] == std::byte{0x01});
    assert(lifecycle.outstandingFrames() == 0);

    assert(!completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, frame.wireBytes().size() - 1U));
    assert(lifecycle.outstandingFrames() == 0);
    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, frame.wireBytes().size()));
    assert(lifecycle.outstandingFrames() == 1);
}

void multipartWire()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 3002);

    std::vector<std::byte> annexB(kGfxRdp8MaximumRawSegmentBytes,
                                  std::byte{0x55});
    annexB[0] = std::byte{};
    annexB[1] = std::byte{};
    annexB[2] = std::byte{};
    annexB[3] = std::byte{1};
    annexB[4] = std::byte{0x65};
    const auto source = picture(42, annexB);
    const std::size_t graphicsBytes =
        gfxAvc420PictureBytes(source.regions.size(), annexB.size());
    assert(graphicsBytes > kGfxRdp8MaximumRawSegmentBytes);

    GfxAvc420SegmentedFrame frame;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, 3002, source, frame));
    assert(frame.wireBytes()[0] == std::byte{0xE1});
    assert(frame.wireBytes().size() == gfxSegmentedDataBytes(graphicsBytes));
    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, frame.wireBytes().size()));
}

void denialsAndReconnect()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 3003);

    GfxAvc420SegmentedFrame untouched;
    auto invalid = picture(51);
    invalid.surfaceId = 8;
    assert(!prepareGfxAvc420SegmentedFrame(
        lifecycle, 3003, invalid, untouched));
    assert(!untouched.valid());
    assert(lifecycle.canSubmitFrame(3003));

    assert(!prepareGfxAvc420SegmentedFrame(
        lifecycle, 3004, picture(51), untouched));
    assert(!untouched.valid());
    assert(lifecycle.canSubmitFrame(3003));

    GfxAvc420SegmentedFrame old;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, 3003, picture(51), old));
    assert(!lifecycle.canSubmitFrame(3003));
    lifecycle.disconnect();
    assert(!completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, old, old.wireBytes().size()));
    assert(!abortGfxAvc420SegmentedFrameDelivery(lifecycle, old));

    mapSurface(lifecycle, 3004);
    GfxAvc420SegmentedFrame current;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, 3004, picture(51), current));
    assert(!completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, old, old.wireBytes().size()));
    assert(abortGfxAvc420SegmentedFrameDelivery(lifecycle, current));
    assert(lifecycle.stage() == GfxPresentationStage::Inactive);
}

void deliveryAcknowledgement()
{
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, 3005);
    GfxAvc420SegmentedFrame frame;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, 3005, picture(61), frame));
    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, frame.wireBytes().size()));

    GfxFrameAckWindowResult result{};
    const auto ack = acknowledge(61);
    assert(lifecycle.onFrameAcknowledge(3005, ack, result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
    assert(lifecycle.outstandingFrames() == 0);
    assert(!completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, frame.wireBytes().size()));
}


void unsentCancellation()
{
    constexpr std::uint64_t generation = 3006;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, generation);

    GfxAvc420SegmentedFrame delivered;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, generation, picture(70U), delivered));
    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, delivered, delivered.wireBytes().size()));
    assert(lifecycle.outstandingFrames() == 1U);

    GfxAvc420SegmentedFrame pending;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, generation, picture(0U), pending));
    assert(pending.valid());
    assert(pending.wireBytes()[0] == std::byte{0xE0});
    assert(pending.wireBytes()[1] == std::byte{0x04});
    const std::size_t canceledWireBytes = pending.wireBytes().size();

    GfxAvc420SegmentedFrame moved = std::move(pending);
    assert(!pending.valid());
    assert(moved.valid());
    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        lifecycle, moved));
    assert(!moved.valid());
    assert(moved.wireBytes().empty());
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
    assert(lifecycle.surfaceId() == 7U);
    assert(lifecycle.outstandingFrames() == 1U);
    assert(lifecycle.canReserveFrame(generation, 0U));

    assert(!completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, moved, canceledWireBytes));
    assert(!abortGfxAvc420SegmentedFrameDelivery(lifecycle, moved));
    assert(!cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        lifecycle, moved));

    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(0U), result));
    assert(result == GfxFrameAckWindowResult::Unmatched);
    assert(lifecycle.outstandingFrames() == 1U);

    // Reusing the same numeric frame ID creates a fresh reservation. The old
    // invalidated object cannot abort that unrelated reservation.
    GfxAvc420SegmentedFrame replacement;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, generation, picture(0U), replacement));
    assert(replacement.valid());
    assert(!abortGfxAvc420SegmentedFrameDelivery(lifecycle, moved));
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, replacement, replacement.wireBytes().size()));
    assert(lifecycle.outstandingFrames() == 2U);
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(70U), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
    assert(lifecycle.onFrameAcknowledge(
        generation, acknowledge(0U), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
    assert(lifecycle.outstandingFrames() == 0U);

    // A frame from another generation cannot cancel either lifecycle's
    // current reservation, and rejection leaves both publication objects
    // byte-for-byte unchanged.
    GfxPresentationLifecycle leftLifecycle;
    GfxPresentationLifecycle rightLifecycle;
    mapSurface(leftLifecycle, 3007);
    mapSurface(rightLifecycle, 3008);
    GfxAvc420SegmentedFrame leftFrame;
    GfxAvc420SegmentedFrame rightFrame;
    assert(prepareGfxAvc420SegmentedFrame(
        leftLifecycle, 3007, picture(80U), leftFrame));
    assert(prepareGfxAvc420SegmentedFrame(
        rightLifecycle, 3008, picture(81U), rightFrame));
    const std::vector<std::byte> leftBytes(
        leftFrame.wireBytes().begin(), leftFrame.wireBytes().end());
    const std::vector<std::byte> rightBytes(
        rightFrame.wireBytes().begin(), rightFrame.wireBytes().end());

    assert(!cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        leftLifecycle, rightFrame));
    assert(rightFrame.valid());
    assert(std::equal(
        rightFrame.wireBytes().begin(), rightFrame.wireBytes().end(),
        rightBytes.begin(), rightBytes.end()));
    assert(!cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        rightLifecycle, leftFrame));
    assert(leftFrame.valid());
    assert(std::equal(
        leftFrame.wireBytes().begin(), leftFrame.wireBytes().end(),
        leftBytes.begin(), leftBytes.end()));

    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        leftLifecycle, leftFrame));
    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        rightLifecycle, rightFrame));
}

void ownedOutputReuseDenials()
{
    static_assert(std::is_move_constructible_v<GfxAvc420SegmentedFrame>);
    static_assert(!std::is_move_assignable_v<GfxAvc420SegmentedFrame>);

    constexpr std::uint64_t firstGeneration = 3009;
    constexpr std::uint64_t secondGeneration = 3010;
    GfxPresentationLifecycle firstLifecycle;
    GfxPresentationLifecycle secondLifecycle;
    mapSurface(firstLifecycle, firstGeneration);
    mapSurface(secondLifecycle, secondGeneration);

    GfxAvc420SegmentedFrame output;
    assert(prepareGfxAvc420SegmentedFrame(
        firstLifecycle, firstGeneration, picture(90U), output));
    const std::vector<std::byte> originalBytes(
        output.wireBytes().begin(), output.wireBytes().end());

    assert(!prepareGfxAvc420SegmentedFrame(
        secondLifecycle, secondGeneration, picture(91U), output));
    assert(output.valid());
    assert(output.generation() == firstGeneration);
    assert(output.frameId() == 90U);
    assert(std::equal(output.wireBytes().begin(), output.wireBytes().end(),
                      originalBytes.begin(), originalBytes.end()));
    assert(secondLifecycle.canReserveFrame(secondGeneration, 91U));

    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        firstLifecycle, output));
    assert(!output.valid());
    assert(prepareGfxAvc420SegmentedFrame(
        secondLifecycle, secondGeneration, picture(91U), output));
    assert(output.generation() == secondGeneration);
    assert(output.frameId() == 91U);
    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        secondLifecycle, output));
}

void retirementReuse()
{
    constexpr std::uint64_t firstGeneration = 3011;
    constexpr std::uint64_t secondGeneration = 3012;
    GfxPresentationLifecycle lifecycle;
    mapSurface(lifecycle, firstGeneration);

    GfxAvc420SegmentedFrame output;
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, firstGeneration, picture(92U), output));
    const std::size_t firstWireBytes = output.wireBytes().size();

    assert(!completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, output, firstWireBytes - 1U));
    assert(output.valid());
    assert(output.generation() == firstGeneration);
    assert(output.frameId() == 92U);
    assert(output.wireBytes().size() == firstWireBytes);

    assert(completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, output, firstWireBytes));
    assert(!output.valid());
    assert(output.wireBytes().empty());
    assert(lifecycle.outstandingFrames() == 1U);

    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, firstGeneration, picture(93U), output));
    assert(output.valid());
    assert(output.frameId() == 93U);
    assert(abortGfxAvc420SegmentedFrameDelivery(lifecycle, output));
    assert(!output.valid());
    assert(output.wireBytes().empty());
    assert(lifecycle.stage() == GfxPresentationStage::Inactive);

    mapSurface(lifecycle, secondGeneration);
    assert(prepareGfxAvc420SegmentedFrame(
        lifecycle, secondGeneration, picture(94U), output));
    assert(output.valid());
    assert(output.generation() == secondGeneration);
    assert(cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        lifecycle, output));
    assert(!output.valid());
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view behavior{argv[1]};
    if (behavior == "avc420-segmented-frame-single")
    {
        singleWire();
        return 0;
    }
    if (behavior == "avc420-segmented-frame-multipart")
    {
        multipartWire();
        return 0;
    }
    if (behavior == "avc420-segmented-frame-denials-reconnect")
    {
        denialsAndReconnect();
        return 0;
    }
    if (behavior == "avc420-segmented-frame-delivery-ack")
    {
        deliveryAcknowledgement();
        return 0;
    }
    if (behavior == "avc420-segmented-frame-unsent-cancellation")
    {
        unsentCancellation();
        return 0;
    }
    if (behavior == "avc420-segmented-frame-owned-output-reuse-denials")
    {
        ownedOutputReuseDenials();
        return 0;
    }
    if (behavior == "avc420-segmented-frame-retirement-reuse")
    {
        retirementReuse();
        return 0;
    }
    return 2;
}
