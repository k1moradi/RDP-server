// SPDX-License-Identifier: GPL-3.0-or-later

#include "rdp/gfx_frame_acknowledge.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

using namespace rdp_server::rdp;

namespace
{

using Pdu = std::array<std::byte, kGfxFrameAcknowledgePduBytes>;

void writeU32(std::span<std::byte> bytes, std::size_t position,
              std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index)
    {
        bytes[position + index] = static_cast<std::byte>(value >> (index * 8U));
    }
}

[[nodiscard]] Pdu makeAck(std::uint32_t depth, std::uint32_t frameId,
                          std::uint32_t decodedCount)
{
    Pdu result{std::byte{0x0D}, std::byte{0x00}, std::byte{0x00},
               std::byte{0x00}, std::byte{0x14}, std::byte{0x00},
               std::byte{0x00}, std::byte{0x00}};
    writeU32(result, 8, depth);
    writeU32(result, 12, frameId);
    writeU32(result, 16, decodedCount);
    return result;
}

void testWire()
{
    const Pdu bytes = makeAck(0x01020304U, 0x11223344U, 0x55667788U);
    const Pdu golden{std::byte{0x0D}, std::byte{0x00}, std::byte{0x00},
                     std::byte{0x00}, std::byte{0x14}, std::byte{0x00},
                     std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
                     std::byte{0x03}, std::byte{0x02}, std::byte{0x01},
                     std::byte{0x44}, std::byte{0x33}, std::byte{0x22},
                     std::byte{0x11}, std::byte{0x88}, std::byte{0x77},
                     std::byte{0x66}, std::byte{0x55}};
    assert(bytes == golden);
    GfxFrameAcknowledgement output{};
    assert(parseGfxFrameAcknowledge(bytes, output));
    assert(output.queueDepth == 0x01020304U);
    assert(output.frameId == 0x11223344U);
    assert(output.totalFramesDecoded == 0x55667788U);
    assert(!output.acknowledgementsSuspended());

    // No alignment requirement on the start of the command data.
    std::array<std::byte, 21> unaligned{};
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        unaligned[i + 1U] = bytes[i];
    }
    assert(parseGfxFrameAcknowledge(
        std::span<const std::byte>(unaligned).subspan(1), output));
    assert((output == GfxFrameAcknowledgement{0x01020304U, 0x11223344U,
                                              0x55667788U}));
}

void testSuspension()
{
    GfxFrameAcknowledgement output{};
    // Zero signals unavailable backlog, not ACK suspension.
    assert(parseGfxFrameAcknowledge(makeAck(0, 0, 0), output));
    assert(!output.acknowledgementsSuspended());
    assert(output.queueDepth == 0U);
    assert(output.frameId == 0U);

    assert(parseGfxFrameAcknowledge(
        makeAck(0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFFU), output));
    assert(!output.acknowledgementsSuspended());
    assert(output.queueDepth == 0xFFFFFFFEU);

    // The suspension sentinel clears the caller's outstanding-frame set;
    // the parser does not impose a false byte count or own frame state.
    assert(parseGfxFrameAcknowledge(
        makeAck(kGfxSuspendFrameAcknowledgement, 123, 45), output));
    assert(output.acknowledgementsSuspended());
    assert(output.frameId == 123U);
    assert(output.totalFramesDecoded == 45U);

    // A later finite depth opts back into regular acknowledgements.
    assert(parseGfxFrameAcknowledge(makeAck(1U, 124U, 46U), output));
    assert(!output.acknowledgementsSuspended());
    assert(output.queueDepth == 1U);
}

void testRejections()
{
    const Pdu good = makeAck(10, 11, 12);
    const GfxFrameAcknowledgement sentinel{7, 8, 9};
    GfxFrameAcknowledgement output = sentinel;
    for (std::size_t length = 0; length < good.size(); ++length)
    {
        assert(!parseGfxFrameAcknowledge(
            std::span<const std::byte>(good).first(length), output));
        assert(output == sentinel);
    }
    const auto bad = [&](std::size_t offset, std::byte changed)
    {
        Pdu broken = good;
        broken[offset] = changed;
        assert(!parseGfxFrameAcknowledge(broken, output));
        assert(output == sentinel);
    };
    bad(0, std::byte{0x0C}); // Wrong command ID
    bad(1, std::byte{0x01});
    bad(2, std::byte{0x01}); // Nonzero transport flags
    bad(3, std::byte{0x80});
    bad(4, std::byte{0x13}); // Declared PDU length differs
    bad(5, std::byte{0x01});
    bad(6, std::byte{0x01});
    bad(7, std::byte{0x80});
    auto extra = std::vector<std::byte>(good.begin(), good.end());
    extra.insert(extra.end(), 2048, std::byte{0});
    for (std::size_t n : {21U, 22U, 100U, 2068U})
    {
        assert(!parseGfxFrameAcknowledge(
            std::span<const std::byte>(extra).first(n), output));
        assert(output == sentinel);
    }
    assert(!parseGfxFrameAcknowledge({}, output));
    assert(output == sentinel);
}

void testAckCorrelation()
{
    GfxFrameAckWindow window;
    const auto ack = [&](std::uint64_t generation, std::uint32_t depth,
                         std::uint32_t frameId) {
        return window.onFrameAcknowledge(generation, makeAck(depth, frameId, 1U));
    };
    using Result = GfxFrameAckWindowResult;
    assert(!window.noteFrameSent(0U, 4U));
    assert(ack(0U, 0U, 4U) == Result::StaleGeneration);
    window.reset(100U);
    assert(window.noteFrameSent(100U, 0U)); // Frame ID zero is a wire value.
    assert(window.noteFrameSent(100U, 4U));
    assert(window.noteFrameSent(100U, 5U));
    assert(!window.noteFrameSent(100U, 4U)); // Duplicate cannot be tracked.
    assert(window.outstandingFrames() == 3U);
    // ACK ordering need not match send ordering; an ACK is not cumulative.
    assert(ack(100U, 12U, 5U) == Result::Acknowledged);
    assert(window.outstandingFrames() == 2U);
    assert(window.clientQueueDepthBytes() == 12U);
    assert(ack(100U, 0U, 5U) == Result::Unmatched);
    assert(window.outstandingFrames() == 2U);
    assert(ack(100U, 0U, 0U) == Result::Acknowledged);
    assert(ack(100U, 0U, 4U) == Result::Acknowledged);
    assert(window.outstandingFrames() == 0U);
    assert(window.expectingAcknowledgements());
    assert(ack(100U, 0U, 4U) == Result::Unmatched);
}

void testAckBoundedBackpressure()
{
    using Result = GfxFrameAckWindowResult;
    GfxFrameAckWindow window;
    window.reset(200U);
    for (std::size_t i = 0; i < window.kMaximumPendingFrames; ++i)
    {
        assert(window.noteFrameSent(200U, static_cast<std::uint32_t>(i + 1U)));
    }
    assert(window.outstandingFrames() == window.kMaximumPendingFrames);
    assert(!window.noteFrameSent(200U, 65U));
    assert(window.outstandingFrames() == window.kMaximumPendingFrames);
    assert(window.onFrameAcknowledge(200U, makeAck(9U, 20U, 20U)) ==
           Result::Acknowledged);
    assert(window.noteFrameSent(200U, 65U));
    assert(window.outstandingFrames() == window.kMaximumPendingFrames);
    // Client suspension MUST clear all outstanding frame IDs and unblock
    // submissions, even though it is not an ACK for each individual ID.
    assert(window.onFrameAcknowledge(200U, makeAck(0xFFFFFFFFU, 33U, 22U)) ==
           Result::Suspended);
    assert(window.outstandingFrames() == 0U);
    assert(window.clientQueueDepthBytes() == 0U);
    assert(!window.expectingAcknowledgements());
    assert(window.noteFrameSent(200U, 66U));
    assert(window.outstandingFrames() == 0U);
    // A finite queue depth resumes ACK tracking; past suspended frames stay
    // forgotten and cannot accidentally release new pending work.
    assert(window.onFrameAcknowledge(200U, makeAck(7U, 66U, 23U)) ==
           Result::Unmatched);
    assert(window.expectingAcknowledgements());
    assert(window.clientQueueDepthBytes() == 7U);
    assert(window.noteFrameSent(200U, 67U));
    assert(window.outstandingFrames() == 1U);
    assert(window.onFrameAcknowledge(200U, makeAck(0U, 67U, 24U)) ==
           Result::Acknowledged);
    assert(window.outstandingFrames() == 0U);
}

void testAckDecodeProgress()
{
    using Result = GfxFrameAckWindowResult;
    GfxFrameAckWindow window;
    window.reset(300U);
    assert(!window.clientTotalFramesDecodedAvailable());
    assert(window.clientTotalFramesDecoded() == 0U);

    assert(window.noteFrameSent(300U, 1U));
    const auto malformed = makeAck(8U, 1U, 7U);
    assert(window.onFrameAcknowledge(
               300U, std::span<const std::byte>(malformed).first(19U)) ==
           Result::InvalidPdu);
    assert(!window.clientTotalFramesDecodedAvailable());
    assert(window.onFrameAcknowledge(299U, makeAck(8U, 1U, 9U)) ==
           Result::StaleGeneration);
    assert(!window.clientTotalFramesDecodedAvailable());

    // Unmatched ACKs are still valid client telemetry. Zero is a real count.
    assert(window.onFrameAcknowledge(300U, makeAck(8U, 99U, 0U)) ==
           Result::Unmatched);
    assert(window.clientTotalFramesDecodedAvailable());
    assert(window.clientTotalFramesDecoded() == 0U);

    assert(window.onFrameAcknowledge(
               300U, makeAck(4U, 1U, 0xFFFFFFFFU)) ==
           Result::Acknowledged);
    assert(window.clientTotalFramesDecoded() == 0xFFFFFFFFU);

    // Keep the raw uint32 value; do not create wrap/ordering semantics.
    assert(window.onFrameAcknowledge(
               300U, makeAck(kGfxSuspendFrameAcknowledgement, 1U, 17U)) ==
           Result::Suspended);
    assert(window.clientTotalFramesDecodedAvailable());
    assert(window.clientTotalFramesDecoded() == 17U);
    assert(!window.expectingAcknowledgements());

    window.reset(301U);
    assert(!window.clientTotalFramesDecodedAvailable());
    assert(window.clientTotalFramesDecoded() == 0U);
}

void testAckGenerationAndMalformed()
{
    using Result = GfxFrameAckWindowResult;
    GfxFrameAckWindow window;
    window.reset(9U);
    assert(window.noteFrameSent(9U, 501U));
    const auto malformed = makeAck(1U, 501U, 1U);
    assert(window.onFrameAcknowledge(9U,
           std::span<const std::byte>(malformed).first(19U)) ==
           Result::InvalidPdu);
    assert(window.outstandingFrames() == 1U);
    assert(window.clientQueueDepthBytes() == 0U);
    assert(window.expectingAcknowledgements());
    const auto suspend = makeAck(0xFFFFFFFFU, 501U, 1U);
    assert(window.onFrameAcknowledge(8U, suspend) == Result::StaleGeneration);
    assert(window.outstandingFrames() == 1U);
    assert(window.noteFrameSent(8U, 502U) == false);
    // Resize/reconnect opens a new channel generation. Late callbacks MUST
    // not clear an identical frame ID in the replacement generation.
    window.reset(10U);
    assert(window.outstandingFrames() == 0U);
    assert(window.expectingAcknowledgements());
    assert(window.noteFrameSent(10U, 501U));
    assert(window.onFrameAcknowledge(9U, makeAck(0U, 501U, 2U)) ==
           Result::StaleGeneration);
    assert(window.onFrameAcknowledge(9U, suspend) == Result::StaleGeneration);
    assert(window.outstandingFrames() == 1U);
    assert(window.onFrameAcknowledge(10U, makeAck(0U, 501U, 3U)) ==
           Result::Acknowledged);
    assert(window.outstandingFrames() == 0U);
    window.reset(0U); // Explicit disconnect.
    assert(!window.expectingAcknowledgements());
    assert(!window.noteFrameSent(0U, 1U));
    assert(window.onFrameAcknowledge(10U, makeAck(0U, 501U, 3U)) ==
           Result::StaleGeneration);
    assert(window.outstandingFrames() == 0U);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        return 2;
    }
    const std::string_view behavior{argv[1]};
    if (behavior == "frame-ack-wire")
    {
        testWire();
    }
    else if (behavior == "frame-ack-suspension")
    {
        testSuspension();
    }
    else if (behavior == "frame-ack-rejections")
    {
        testRejections();
    }
    else if (behavior == "frame-ack-correlation")
    {
        testAckCorrelation();
    }
    else if (behavior == "frame-ack-bounded-backpressure")
    {
        testAckBoundedBackpressure();
    }
    else if (behavior == "frame-ack-decode-progress")
    {
        testAckDecodeProgress();
    }
    else if (behavior == "frame-ack-stale-generation")
    {
        testAckGenerationAndMalformed();
    }
    else
    {
        return 2;
    }
    return 0;
}
