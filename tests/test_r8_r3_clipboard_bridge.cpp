// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "server/clipboard/r3_clipboard_transfer_bridge.h"

#include <algorithm>
#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::server::clipboard;
using namespace rdp_server::server::transport;

namespace
{

void put32(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint32_t value)
{
    assert(offset + 4U <= bytes.size());
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

std::vector<std::uint8_t> pdu(
    std::uint16_t type, std::uint16_t flags,
    std::span<const std::uint8_t> payload = {})
{
    std::vector<std::uint8_t> wire;
    assert(rdp_server::clipboard::encodePdu(type, flags, payload, wire));
    return wire;
}

std::vector<std::uint8_t> capabilitiesPdu(std::uint32_t generalFlags)
{
    const std::array<std::uint8_t, 16> payload{
        1, 0, 0, 0,
        1, 0, 12, 0,
        2, 0, 0, 0,
        static_cast<std::uint8_t>(generalFlags),
        static_cast<std::uint8_t>(generalFlags >> 8U),
        static_cast<std::uint8_t>(generalFlags >> 16U),
        static_cast<std::uint8_t>(generalFlags >> 24U),
    };
    return pdu(rdp_server::clipboard::kClipCaps, 0U, payload);
}

void appendLongFormat(
    std::vector<std::uint8_t> &payload, std::uint32_t formatId,
    std::string_view name)
{
    const std::size_t offset = payload.size();
    payload.resize(offset + 4U);
    put32(payload, offset, formatId);
    for (const char character : name)
    {
        payload.push_back(static_cast<std::uint8_t>(character));
        payload.push_back(0U);
    }
    payload.push_back(0U);
    payload.push_back(0U);
}

std::vector<std::uint8_t> longFormatListPdu(
    std::span<const std::uint8_t> payload)
{
    return pdu(rdp_server::clipboard::kFormatList, 0U, payload);
}

std::vector<std::uint8_t> shortUnicodeFormatListPdu()
{
    std::array<std::uint8_t, 36> payload{};
    put32(payload, 0U, rdp_server::clipboard::kFormatUnicodeText);
    return pdu(rdp_server::clipboard::kFormatList, 0U, payload);
}

std::vector<std::uint8_t> formatDataResponse(
    std::span<const std::uint8_t> payload)
{
    return pdu(
        rdp_server::clipboard::kFormatDataResponse,
        rdp_server::clipboard::kResponseOk, payload);
}

std::vector<std::uint8_t> fileContentsResponse(
    std::uint32_t streamId, std::span<const std::uint8_t> payload)
{
    std::vector<std::uint8_t> body(4U + payload.size(), 0U);
    put32(body, 0U, streamId);
    std::copy(payload.begin(), payload.end(), body.begin() + 4U);
    return pdu(
        rdp_server::clipboard::kFileContentsResponse,
        rdp_server::clipboard::kResponseOk, body);
}

void deliverPendingApplicationPdu(
    R3ClipboardTransferBridge &bridge,
    RdpClipboardStaticChannelRoute &route)
{
    const auto applicationPdu = bridge.pendingApplicationPdu();
    assert(!applicationPdu.empty());
    assert(route.queue(applicationPdu));

    bool delivered = false;
    while (const auto write = route.pending())
    {
        assert(bridge.bindQueuedWrite(write));
        const std::size_t acceptedBytes = write.wireBytes.size();
        const auto outcome = route.onAcceptedBytes(
            write.routeGeneration, write.replySequence,
            write.writeSliceSequence, acceptedBytes);
        assert(outcome != RdpClipboardWriteOutcome::Rejected);
        assert(bridge.recordAcceptedWrite(
            write, acceptedBytes, outcome));
        if (outcome == RdpClipboardWriteOutcome::Delivered)
        {
            delivered = true;
            break;
        }
    }
    assert(delivered);
    assert(route.idle());
    assert(bridge.pendingApplicationPdu().empty());
}

void sourceRequestReceipt()
{
    constexpr RdpClipboardStaticChannelView view{1008U, 7U};
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, view.channelId, view.generation, 1600U));

    R3ClipboardTransferBridge bridge(0U, true);
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(bridge.transfer().generation() == 1U);
    deliverPendingApplicationPdu(bridge, route);

    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginFormatDataRequest(
        rdp_server::clipboard::kFormatUnicodeText));
    deliverPendingApplicationPdu(bridge, route);

    assert(visitor.visit(visitor.context, view));
    const std::array<std::uint8_t, 4> text{'A', 0U, 0U, 0U};
    assert(sink.consume(sink.context, formatDataResponse(text)));
    const auto verified = bridge.transfer().verifiedUnicodeText();
    assert(verified && *verified == "A");
}

void missingActivatedRouteDenial()
{
    R3ClipboardTransferBridge bridge(0U, true);
    auto sink = bridge.completePduSink();

    // The R2 post-Share visitor is the only source of an R3 route generation.
    // A complete application PDU alone cannot activate or populate R8 state.
    assert(!sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(!bridge.active());
    assert(bridge.transfer().generation() == 0U);
    assert(!bridge.beginFormatDataRequest(
        rdp_server::clipboard::kFormatUnicodeText));
}

void oldRouteGenerationRetirement()
{
    R3ClipboardTransferBridge bridge(0U, true);
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    constexpr RdpClipboardStaticChannelView first{1008U, 20U};
    assert(visitor.visit(visitor.context, first));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    const std::uint64_t firstSourceEpoch = bridge.transfer().sourceEpoch();

    // Same generation with another channel cannot be the exact cliprdr role.
    assert(!visitor.visit(
        visitor.context, RdpClipboardStaticChannelView{1009U, 20U}));
    assert(!bridge.active());
    assert(bridge.transfer().generation() == 0U);

    constexpr RdpClipboardStaticChannelView replacement{1008U, 21U};
    assert(visitor.visit(visitor.context, replacement));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(bridge.transfer().generation() == 1U);
    assert(bridge.transfer().sourceEpoch() > firstSourceEpoch);

    // A stale generation observed while replacement state is live retires the
    // replacement before the stale callback can consume or publish anything.
    assert(!visitor.visit(visitor.context, first));
    assert(!bridge.active());
    assert(bridge.transfer().generation() == 0U);

    constexpr RdpClipboardStaticChannelView reconnect{1008U, 22U};
    assert(visitor.visit(visitor.context, reconnect));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(bridge.transfer().generation() == 1U);
}

void partialPositiveReceiptRetirement()
{
    constexpr RdpClipboardStaticChannelView view{1008U, 30U};
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, view.channelId, view.generation, 1600U));

    R3ClipboardTransferBridge bridge(0U, true);
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    deliverPendingApplicationPdu(bridge, route);

    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginFormatDataRequest(
        rdp_server::clipboard::kFormatUnicodeText));
    assert(route.queue(bridge.pendingApplicationPdu()));
    const auto first = route.pending();
    assert(first);
    assert(bridge.bindQueuedWrite(first));
    const auto partial = route.onAcceptedBytes(
        first.routeGeneration, first.replySequence,
        first.writeSliceSequence, 1U);
    assert(partial == RdpClipboardWriteOutcome::Pending);
    assert(bridge.recordAcceptedWrite(first, 1U, partial));

    // R2/Share loss after a positive partial plaintext receipt is terminal.
    bridge.retireR3ChannelState();
    route.close();
    assert(!bridge.active());
    assert(bridge.transfer().generation() == 0U);
    assert(!bridge.transfer().verifiedUnicodeText());
    assert(!bridge.recordAcceptedWrite(
        first, 1U, RdpClipboardWriteOutcome::Rejected));

    constexpr RdpClipboardStaticChannelView reconnect{1008U, 31U};
    assert(visitor.visit(visitor.context, reconnect));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(bridge.transfer().generation() == 1U);
}

struct FileSink final
{
    bool called{};
    RemoteTransfer::FileContentsStatus status{
        RemoteTransfer::FileContentsStatus::Invalid};
    std::uint64_t fileSize{};

    static bool consume(
        void *context,
        const RemoteTransfer::FileContentsResult &result) noexcept
    {
        auto &self = *static_cast<FileSink *>(context);
        self.called = true;
        self.status = result.status;
        self.fileSize = result.fileSize;
        return true;
    }
};

void fileContentsRequestReceipt()
{
    constexpr std::uint32_t flags =
        rdp_server::clipboard::kUseLongFormatNames |
        rdp_server::clipboard::kStreamFileclipEnabled |
        rdp_server::clipboard::kFileclipNoFilePaths |
        rdp_server::clipboard::kHugeFileSupportEnabled;
    constexpr std::uint32_t fileListFormat = 0xc701U;
    constexpr RdpClipboardStaticChannelView view{1008U, 40U};
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, view.channelId, view.generation, 1600U));

    FileSink fileSink;
    R3ClipboardTransferBridge bridge(
        flags, true, {&fileSink, &FileSink::consume});
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, capabilitiesPdu(flags)));

    std::vector<std::uint8_t> formatPayload;
    appendLongFormat(
        formatPayload, fileListFormat, "FileGroupDescriptorW");
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(
        sink.context, longFormatListPdu(formatPayload)));
    deliverPendingApplicationPdu(bridge, route);

    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginFormatDataRequest(fileListFormat));
    deliverPendingApplicationPdu(bridge, route);

    constexpr std::size_t descriptorBytes = 592U;
    std::vector<std::uint8_t> descriptorList(
        4U + descriptorBytes, 0U);
    put32(descriptorList, 0U, 1U);
    auto descriptor =
        std::span(descriptorList).subspan(4U, descriptorBytes);
    put32(descriptor, 0U, 0x00000040U);
    put32(descriptor, 64U, 0U);
    put32(descriptor, 68U, 64U);
    constexpr std::u16string_view name = u"stream.bin";
    for (std::size_t index = 0U; index < name.size(); ++index)
    {
        const auto codeUnit = static_cast<std::uint16_t>(name[index]);
        descriptor[72U + index * 2U] =
            static_cast<std::uint8_t>(codeUnit);
        descriptor[72U + index * 2U + 1U] =
            static_cast<std::uint8_t>(codeUnit >> 8U);
    }

    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(
        sink.context, formatDataResponse(descriptorList)));
    assert(bridge.transfer().remoteFileCount() == 1U);

    assert(visitor.visit(visitor.context, view));
    const auto request = bridge.beginFileSizeRequest(0U);
    assert(request);
    deliverPendingApplicationPdu(bridge, route);

    std::array<std::uint8_t, 8> sizePayload{};
    put32(sizePayload, 0U, 64U);
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(
        sink.context,
        fileContentsResponse(request->streamId, sizePayload)));
    assert(fileSink.called);
    assert(fileSink.status ==
           RemoteTransfer::FileContentsStatus::ReceivedSize);
    assert(fileSink.fileSize == 64U);
}

} // namespace

int main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "source-request-receipt")
        sourceRequestReceipt();
    else if (behavior == "missing-activated-route-denial")
        missingActivatedRouteDenial();
    else if (behavior == "old-route-generation-retirement")
        oldRouteGenerationRetirement();
    else if (behavior == "partial-positive-receipt-retirement")
        partialPositiveReceiptRetirement();
    else if (behavior == "filecontents-request-receipt")
        fileContentsRequestReceipt();
    else
        return 2;
    return 0;
}
