// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/transport/rdp_clipboard_static_channel.h"
#include "clipboard/clipboard_protocol.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::server::transport;

namespace
{
[[nodiscard]] std::vector<std::uint8_t> pdu(std::size_t payloadLength)
{
    std::vector<std::uint8_t> payload(payloadLength, 0x5aU);
    std::vector<std::uint8_t> wire;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatDataResponse,
        rdp_server::clipboard::kResponseOk, payload, wire));
    return wire;
}

[[nodiscard]] std::vector<std::uint8_t> chunk(
    std::span<const std::uint8_t> message, std::size_t offset,
    std::size_t length, std::uint32_t flags,
    std::size_t declaredLength = 0U)
{
    assert(offset <= message.size() && length <= message.size() - offset);
    const std::uint32_t totalLength = static_cast<std::uint32_t>(
        declaredLength == 0U ? message.size() : declaredLength);
    std::vector<std::uint8_t> result(8U + length);
    for (std::size_t index = 0U; index < 4U; ++index)
    {
        result[index] = static_cast<std::uint8_t>(
            totalLength >> (8U * index));
        result[index + 4U] = static_cast<std::uint8_t>(
            flags >> (8U * index));
    }
    std::copy_n(message.begin() + static_cast<std::ptrdiff_t>(offset),
                length, result.begin() + 8U);
    return result;
}

constexpr std::uint32_t first = 0x11U;
constexpr std::uint32_t middle = 0x10U;
constexpr std::uint32_t last = 0x12U;
constexpr std::uint32_t complete = 0x13U;

void fragmentReassembly()
{
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, 1008U, 1U, 1600U));
    const auto message = pdu(3500U);
    std::span<const std::uint8_t> decoded;
    const auto a = chunk(message, 0U, 1600U, first);
    const auto b = chunk(message, 1600U, 1600U, middle);
    const auto c = chunk(message, 3200U, message.size() - 3200U, last);
    assert(route.receive(1008U, 1U, a, decoded) ==
           RdpClipboardChunkIntake::NeedMore && decoded.empty());
    assert(route.receive(1008U, 1U, b, decoded) ==
           RdpClipboardChunkIntake::NeedMore && decoded.empty());
    assert(route.receive(1008U, 1U, c, decoded) ==
           RdpClipboardChunkIntake::Complete);
    assert(std::ranges::equal(decoded, message));
    rdp_server::clipboard::PduView parsed{};
    assert(rdp_server::clipboard::decodePdu(decoded, parsed));
    assert(parsed.payload.size() == 3500U);
    assert(route.view().generation == 1U);
}

void generationReplacement()
{
    RdpClipboardStaticChannelRoute route;
    assert(!route.start(1005U, 1008U, 0U, 1600U));
    assert(route.start(1005U, 1008U, 9U, 1600U));
    assert(!route.start(1005U, 1008U, 10U, 1600U));
    route.close();
    assert(route.view().generation == 0U);
    assert(!route.start(1005U, 1008U, 9U, 1600U));
    assert(route.start(1005U, 1008U, 10U, 1600U));
    const auto message = pdu(5U);
    const auto wire = chunk(message, 0U, message.size(), complete);
    std::span<const std::uint8_t> decoded;
    assert(route.receive(1008U, 9U, wire, decoded) ==
           RdpClipboardChunkIntake::Rejected);
    assert(!route.view());
}

void wrongRoleOrCompression()
{
    const auto message = pdu(8U);
    const auto wire = chunk(message, 0U, message.size(), complete);
    RdpClipboardStaticChannelRoute wrongRole;
    assert(wrongRole.start(1005U, 1008U, 1U, 1600U));
    std::span<const std::uint8_t> decoded;
    assert(wrongRole.receive(1009U, 1U, wire, decoded) ==
           RdpClipboardChunkIntake::Rejected);
    RdpClipboardStaticChannelRoute compression;
    assert(compression.start(1005U, 1008U, 1U, 1600U));
    const auto compressed = chunk(
        message, 0U, message.size(), complete | 0x00200000U);
    assert(compression.receive(1008U, 1U, compressed, decoded) ==
           RdpClipboardChunkIntake::Rejected);
}

void fragmentAbortConditions()
{
    const auto message = pdu(2000U);
    const auto a = chunk(message, 0U, 1600U, first);
    const auto b = chunk(message, 1600U, message.size() - 1600U, last);
    std::span<const std::uint8_t> decoded;

    RdpClipboardStaticChannelRoute duplicateFirst;
    assert(duplicateFirst.start(1005U, 1008U, 1U, 1600U));
    assert(duplicateFirst.receive(1008U, 1U, a, decoded) ==
           RdpClipboardChunkIntake::NeedMore);
    assert(duplicateFirst.receive(1008U, 1U, a, decoded) ==
           RdpClipboardChunkIntake::Rejected);
    assert(duplicateFirst.receive(1008U, 1U, b, decoded) ==
           RdpClipboardChunkIntake::Rejected);

    RdpClipboardStaticChannelRoute missingFirst;
    assert(missingFirst.start(1005U, 1008U, 1U, 1600U));
    assert(missingFirst.receive(1008U, 1U, b, decoded) ==
           RdpClipboardChunkIntake::Rejected);

    RdpClipboardStaticChannelRoute missingLast;
    assert(missingLast.start(1005U, 1008U, 1U, 1600U));
    assert(missingLast.receive(1008U, 1U, a, decoded) ==
           RdpClipboardChunkIntake::NeedMore);
    const auto wrongEnd = chunk(message, 1600U, message.size() - 1600U, middle);
    assert(missingLast.receive(1008U, 1U, wrongEnd, decoded) ==
           RdpClipboardChunkIntake::Rejected);

    RdpClipboardStaticChannelRoute lengthMismatch;
    assert(lengthMismatch.start(1005U, 1008U, 1U, 1600U));
    assert(lengthMismatch.receive(1008U, 1U, a, decoded) ==
           RdpClipboardChunkIntake::NeedMore);
    const auto wrongLength = chunk(message, 1600U, message.size() - 1600U, last, 2001U);
    assert(lengthMismatch.receive(1008U, 1U, wrongLength, decoded) ==
           RdpClipboardChunkIntake::Rejected);

    RdpClipboardStaticChannelRoute oversize;
    assert(oversize.start(1005U, 1008U, 1U, 1600U));
    const auto huge = chunk(message, 0U, 1600U, first,
                            rdp_server::clipboard::kMaximumPduBytes + 1U);
    assert(oversize.receive(1008U, 1U, huge, decoded) ==
           RdpClipboardChunkIntake::Rejected);
}

void outboundReceipts()
{
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, 1008U, 1U, 1600U));
    const auto message = pdu(3300U);
    assert(route.queue(message));
    std::size_t packets = 0U;
    std::size_t totalAccepted = 0U;
    while (auto write = route.pending())
    {
        ++packets;
        const auto bytes = write.wireBytes;
        assert(bytes.size() > 22U);
        assert(bytes[0] == 3U && bytes[1] == 0U);
        const auto packetBytes = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[2]) << 8U) | bytes[3]);
        assert(packetBytes == bytes.size());
        assert(bytes[4] == 2U && bytes[5] == 0xf0U &&
               bytes[6] == 0x80U && bytes[7] == 0x68U);
        const auto half = bytes.size() / 2U;
        const auto partial = route.onAcceptedBytes(
            write.routeGeneration, write.replySequence,
            write.writeSliceSequence, half);
        assert(partial == RdpClipboardWriteOutcome::Pending);
        totalAccepted += half;
        const auto suffix = route.pending();
        assert(suffix && suffix.writeSliceSequence != write.writeSliceSequence);
        assert(suffix.wireBytes.size() == bytes.size() - half);
        const auto result = route.onAcceptedBytes(
            suffix.routeGeneration, suffix.replySequence,
            suffix.writeSliceSequence, suffix.wireBytes.size());
        totalAccepted += suffix.wireBytes.size();
        if (result == RdpClipboardWriteOutcome::Delivered)
            break;
        assert(result == RdpClipboardWriteOutcome::Pending);
    }
    assert(packets == 3U);
    assert(totalAccepted > message.size());
    assert(!route.pending());
    assert(route.idle());
}

void staleReceiptAbort()
{
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, 1008U, 42U, 1600U));
    assert(route.queue(pdu(20U)));
    const auto pending = route.pending();
    assert(pending);
    assert(route.onAcceptedBytes(
        pending.routeGeneration, pending.replySequence,
        pending.writeSliceSequence, 1U) == RdpClipboardWriteOutcome::Pending);
    const auto suffix = route.pending();
    assert(suffix && suffix.writeSliceSequence != pending.writeSliceSequence);
    assert(route.onAcceptedBytes(
        pending.routeGeneration, pending.replySequence,
        pending.writeSliceSequence, 1U) == RdpClipboardWriteOutcome::Rejected);
    assert(!route.pending());
    assert(!route.view());
    assert(route.start(1005U, 1008U, 43U, 1600U));
    assert(route.queue(pdu(20U)));
    assert(route.onAcceptedBytes(
        pending.routeGeneration, pending.replySequence,
        pending.writeSliceSequence, 1U) == RdpClipboardWriteOutcome::Rejected);
    assert(!route.view());
}

void terminalAbort()
{
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, 1008U, 1U, 1600U));
    assert(route.queue(pdu(100U)));
    const auto pending = route.pending();
    assert(pending);
    assert(route.onAcceptedBytes(
        pending.routeGeneration, pending.replySequence,
        pending.writeSliceSequence, 1U) == RdpClipboardWriteOutcome::Pending);
    route.close(); // revoked R2/Share after a partial R1 plaintext accept
    assert(!route.pending());
    assert(!route.view());
    assert(route.onAcceptedBytes(
        pending.routeGeneration, pending.replySequence,
        pending.writeSliceSequence, pending.wireBytes.size()) ==
           RdpClipboardWriteOutcome::Rejected);
    assert(!route.start(1005U, 1008U, 1U, 1600U));
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view testName{argv[1]};
    if (testName == "fragment-reassembly")
        fragmentReassembly();
    else if (testName == "generation-replacement")
        generationReplacement();
    else if (testName == "wrong-role-compression")
        wrongRoleOrCompression();
    else if (testName == "fragment-abort-conditions")
        fragmentAbortConditions();
    else if (testName == "outbound-write-receipts")
        outboundReceipts();
    else if (testName == "stale-receipt-abort")
        staleReceiptAbort();
    else if (testName == "terminal-partial-abort")
        terminalAbort();
    else
        return 2;
    return 0;
}
