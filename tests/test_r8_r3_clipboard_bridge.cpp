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

std::uint16_t read16(
    std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    assert(offset + 2U <= bytes.size());
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t read32(
    std::span<const std::uint8_t> bytes, const std::size_t offset)
{
    assert(offset + 4U <= bytes.size());
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

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

std::vector<std::uint8_t> temporaryDirectoryPdu()
{
    std::array<std::uint8_t, 520> payload{};
    constexpr std::u16string_view path = u"C:\\Temp";
    for (std::size_t index = 0U; index < path.size(); ++index)
    {
        const auto codeUnit = static_cast<std::uint16_t>(path[index]);
        payload[index * 2U] = static_cast<std::uint8_t>(codeUnit);
        payload[index * 2U + 1U] =
            static_cast<std::uint8_t>(codeUnit >> 8U);
    }
    return pdu(rdp_server::clipboard::kTempDirectory, 0U, payload);
}

std::vector<std::uint8_t> formatListResponsePdu(
    const std::uint16_t responseFlag)
{
    return pdu(
        rdp_server::clipboard::kFormatListResponse, responseFlag);
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

void deliverPendingSinglePacketWithFraming(
    R3ClipboardTransferBridge &bridge,
    RdpClipboardStaticChannelRoute &route)
{
    const auto applicationPdu = bridge.pendingApplicationPdu();
    assert(!applicationPdu.empty());
    assert(route.queue(applicationPdu));

    const auto write = route.pending();
    assert(write);
    const auto wire = write.wireBytes;
    assert(wire.size() == applicationPdu.size() + 22U);
    assert(wire[0] == 0x03U && wire[1] == 0x00U);
    assert((static_cast<std::size_t>(wire[2]) << 8U | wire[3]) ==
           wire.size());
    assert(wire[4] == 0x02U && wire[5] == 0xf0U &&
           wire[6] == 0x80U && wire[7] == 0x68U);
    assert(read32(wire, 14U) == applicationPdu.size());
    assert(read32(wire, 18U) == 0x00000013U);
    assert(std::equal(
        applicationPdu.begin(), applicationPdu.end(), wire.begin() + 22U));

    assert(bridge.bindQueuedWrite(write));
    const std::size_t acceptedBytes = wire.size();
    const auto outcome = route.onAcceptedBytes(
        write.routeGeneration, write.replySequence,
        write.writeSliceSequence, acceptedBytes);
    assert(outcome == RdpClipboardWriteOutcome::Delivered);
    assert(bridge.recordAcceptedWrite(write, acceptedBytes, outcome));
    assert(route.idle());
    assert(bridge.pendingApplicationPdu().empty());
}

void completeServerInitialization(
    R3ClipboardTransferBridge &bridge,
    RdpClipboardStaticChannelRoute &route,
    const RdpClipboardStaticChannelView view,
    const std::uint32_t peerGeneralFlags)
{
    using Stage = R3ClipboardTransferBridge::ServerInitializationStage;
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerCapabilities());
    assert(bridge.serverInitializationStage() ==
           Stage::ServerCapabilitiesWritePending);
    deliverPendingSinglePacketWithFraming(bridge, route);
    assert(bridge.serverInitializationStage() == Stage::AwaitMonitorReady);

    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerMonitorReady());
    rdp_server::clipboard::PduView monitor{};
    assert(rdp_server::clipboard::decodePdu(
        bridge.pendingApplicationPdu(), monitor));
    assert(monitor.type == rdp_server::clipboard::kMonitorReady);
    assert(monitor.flags == 0U && monitor.payload.empty());
    deliverPendingSinglePacketWithFraming(bridge, route);
    assert(bridge.serverInitializationStage() ==
           Stage::AwaitClientInitialization);

    // MS-RDPECLIP requires the server to accept a client Format List after
    // Monitor Ready even when client capabilities/temp-directory follow it.
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(!bridge.serverInitializationReady());

    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(
        sink.context, capabilitiesPdu(peerGeneralFlags)));
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, temporaryDirectoryPdu()));
    assert(!bridge.serverInitializationReady());

    deliverPendingSinglePacketWithFraming(bridge, route);
    assert(bridge.serverInitializationReady());
    assert(bridge.serverInitializationStage() == Stage::Ready);
}

void acknowledgeServerFormatList(
    R3ClipboardTransferBridge &bridge,
    const RdpClipboardStaticChannelView view,
    const std::uint16_t responseFlag)
{
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(
        sink.context, formatListResponsePdu(responseFlag)));
}

void expectLongFormat(
    std::span<const std::uint8_t> payload, std::size_t &offset,
    const R3ClipboardTransferBridge::OutboundFormat &expected)
{
    assert(offset + 6U <= payload.size());
    assert(read32(payload, offset) == expected.formatId);
    offset += 4U;
    for (const char16_t codeUnit : expected.name)
    {
        assert(offset + 2U <= payload.size());
        assert(read16(payload, offset) ==
               static_cast<std::uint16_t>(codeUnit));
        offset += 2U;
    }
    assert(read16(payload, offset) == 0U);
    offset += 2U;
}

void serverOutboundCapabilitiesAndFormatLists()
{
    using namespace rdp_server::clipboard;
    constexpr std::uint32_t localFlags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;
    constexpr std::uint32_t configuredLocalFlags =
        localFlags | kCanLockClipdata | 0x80000000U;
    constexpr std::array<R3ClipboardTransferBridge::OutboundFormat, 3> formats{{
        {kFormatUnicodeText, u""},
        {0xc001U, u"PNG"},
        {0xc002U, u"FileGroupDescriptorW"},
    }};

    constexpr RdpClipboardStaticChannelView longView{1008U, 51U};
    RdpClipboardStaticChannelRoute longRoute;
    assert(longRoute.start(1005U, longView.channelId, longView.generation,
                           1600U));
    R3ClipboardTransferBridge longBridge(configuredLocalFlags, true);
    auto longVisitor = longBridge.channelVisitor();

    completeServerInitialization(
        longBridge, longRoute, longView, localFlags);
    assert(longBridge.transfer().negotiatedGeneralFlags() == localFlags);
    assert(longBridge.observeServerClipboardGeneration(1U));
    assert(longVisitor.visit(longVisitor.context, longView));
    assert(longBridge.beginServerFormatList(1U, formats));

    PduView decoded{};
    assert(decodePdu(longBridge.pendingApplicationPdu(), decoded));
    assert(decoded.type == kFormatList && decoded.flags == 0U);
    std::size_t longOffset = 0U;
    for (const auto &format : formats)
        expectLongFormat(decoded.payload, longOffset, format);
    assert(longOffset == decoded.payload.size());
    deliverPendingSinglePacketWithFraming(longBridge, longRoute);
    acknowledgeServerFormatList(longBridge, longView, kResponseOk);
    const auto longReceipt = longBridge.lastServerFormatListReceipt();
    assert(longReceipt &&
           longReceipt->clipboardGeneration == 1U &&
           longReceipt->status ==
               R3ClipboardTransferBridge::ServerFormatListStatus::Accepted);

    std::array<R3ClipboardTransferBridge::OutboundFormat,
               RemoteTransfer::kMaximumFormats + 1U> tooManyFormats{};
    for (std::size_t index = 0U; index < tooManyFormats.size(); ++index)
        tooManyFormats[index].formatId = static_cast<std::uint32_t>(index + 1U);
    assert(longBridge.observeServerClipboardGeneration(2U));
    assert(longVisitor.visit(longVisitor.context, longView));
    assert(!longBridge.beginServerFormatList(2U, tooManyFormats));
    assert(longBridge.active());
    assert(longBridge.pendingApplicationPdu().empty());

    constexpr std::array<R3ClipboardTransferBridge::OutboundFormat, 2>
        duplicateFormats{{
            {0xc010U, u"PNG"},
            {0xc010U, u"FileGroupDescriptorW"},
        }};
    assert(longBridge.observeServerClipboardGeneration(3U));
    assert(longVisitor.visit(longVisitor.context, longView));
    assert(!longBridge.beginServerFormatList(3U, duplicateFormats));
    assert(longBridge.active());
    assert(longBridge.pendingApplicationPdu().empty());

    R3ClipboardTransferBridge dormant(localFlags, true);
    assert(!dormant.beginServerCapabilities());
    assert(!dormant.beginServerMonitorReady());
    assert(!dormant.observeServerClipboardGeneration(1U));
    assert(!dormant.beginServerFormatList(1U, formats));

    constexpr std::uint32_t shortLocalFlags =
        kStreamFileclipEnabled | kFileclipNoFilePaths;
    constexpr RdpClipboardStaticChannelView shortView{1008U, 52U};
    RdpClipboardStaticChannelRoute shortRoute;
    assert(shortRoute.start(1005U, shortView.channelId, shortView.generation,
                            1600U));
    R3ClipboardTransferBridge shortBridge(shortLocalFlags, true);
    auto shortVisitor = shortBridge.channelVisitor();

    completeServerInitialization(
        shortBridge, shortRoute, shortView, localFlags);
    assert((shortBridge.transfer().negotiatedGeneralFlags() &
            kUseLongFormatNames) == 0U);
    assert(shortBridge.observeServerClipboardGeneration(1U));
    assert(shortVisitor.visit(shortVisitor.context, shortView));
    assert(shortBridge.beginServerFormatList(1U, formats));
    assert(decodePdu(shortBridge.pendingApplicationPdu(), decoded));
    assert(decoded.type == kFormatList && decoded.flags == kAsciiNames);
    assert(decoded.payload.size() == formats.size() * 36U);
    for (std::size_t index = 0U; index < formats.size(); ++index)
    {
        const std::size_t entryOffset = index * 36U;
        assert(read32(decoded.payload, entryOffset) == formats[index].formatId);
        for (std::size_t nameIndex = 0U;
             nameIndex < formats[index].name.size(); ++nameIndex)
        {
            assert(decoded.payload[
                       entryOffset + 4U + nameIndex] ==
                   static_cast<std::uint8_t>(formats[index].name[nameIndex]));
        }
        assert(std::all_of(
            decoded.payload.begin() +
                static_cast<std::ptrdiff_t>(
                    entryOffset + 4U + formats[index].name.size()),
            decoded.payload.begin() +
                static_cast<std::ptrdiff_t>(entryOffset + 36U),
            [](const std::uint8_t byte) { return byte == 0U; }));
    }
    deliverPendingSinglePacketWithFraming(shortBridge, shortRoute);
    acknowledgeServerFormatList(shortBridge, shortView, kResponseFail);
    const auto shortReceipt = shortBridge.lastServerFormatListReceipt();
    assert(shortReceipt &&
           shortReceipt->clipboardGeneration == 1U &&
           shortReceipt->status ==
               R3ClipboardTransferBridge::ServerFormatListStatus::Rejected);
}

void serverInitializationOrdering()
{
    using namespace rdp_server::clipboard;
    using Stage = R3ClipboardTransferBridge::ServerInitializationStage;
    constexpr std::uint32_t flags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;
    constexpr RdpClipboardStaticChannelView view{1008U, 60U};

    R3ClipboardTransferBridge bridge(flags, true);
    assert(!bridge.beginServerCapabilities());
    assert(!bridge.beginServerMonitorReady());

    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, view.channelId, view.generation, 1600U));
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    assert(visitor.visit(visitor.context, view));
    assert(!bridge.beginServerMonitorReady());
    assert(bridge.beginServerCapabilities());
    assert(bridge.serverInitializationStage() ==
           Stage::ServerCapabilitiesWritePending);
    assert(!bridge.beginServerCapabilities());
    deliverPendingSinglePacketWithFraming(bridge, route);
    assert(bridge.serverInitializationStage() == Stage::AwaitMonitorReady);

    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerMonitorReady());
    PduView monitor{};
    assert(decodePdu(bridge.pendingApplicationPdu(), monitor));
    assert(monitor.type == kMonitorReady && monitor.flags == 0U &&
           monitor.payload.empty());
    assert(!bridge.beginServerMonitorReady());
    deliverPendingSinglePacketWithFraming(bridge, route);
    assert(bridge.serverInitializationStage() ==
           Stage::AwaitClientInitialization);

    // A client offer can precede its capabilities/temp-directory once Monitor
    // Ready is delivered. The response write, not parsing alone, completes the
    // initial format synchronization.
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(!bridge.serverInitializationReady());

    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, capabilitiesPdu(flags)));
    assert(bridge.transfer().negotiatedGeneralFlags() == flags);
    assert(visitor.visit(visitor.context, view));
    assert(sink.consume(sink.context, temporaryDirectoryPdu()));
    assert(!bridge.serverInitializationReady());

    deliverPendingSinglePacketWithFraming(bridge, route);
    assert(bridge.serverInitializationReady());

    assert(visitor.visit(visitor.context, view));
    assert(!bridge.beginServerMonitorReady());
    assert(bridge.serverInitializationReady());
}

void serverInitializationGenerationReplacement()
{
    using namespace rdp_server::clipboard;
    constexpr std::uint32_t flags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;
    constexpr std::array<R3ClipboardTransferBridge::OutboundFormat, 2> formats{{
        {kFormatUnicodeText, u""},
        {0xc001U, u"PNG"},
    }};

    R3ClipboardTransferBridge bridge(flags, true);
    auto visitor = bridge.channelVisitor();

    constexpr RdpClipboardStaticChannelView first{1008U, 61U};
    RdpClipboardStaticChannelRoute firstRoute;
    assert(firstRoute.start(
        1005U, first.channelId, first.generation, 1600U));
    completeServerInitialization(bridge, firstRoute, first, flags);

    assert(bridge.observeServerClipboardGeneration(100U));
    assert(visitor.visit(visitor.context, first));
    assert(bridge.beginServerFormatList(100U, formats));
    deliverPendingSinglePacketWithFraming(bridge, firstRoute);

    // Local ownership changes while the old response has no request ID. Drain
    // that response as stale before the replacement generation may publish.
    assert(bridge.observeServerClipboardGeneration(101U));
    acknowledgeServerFormatList(bridge, first, kResponseOk);
    const auto stale = bridge.lastServerFormatListReceipt();
    assert(stale && stale->clipboardGeneration == 100U);
    assert(stale->status ==
           R3ClipboardTransferBridge::ServerFormatListStatus::Superseded);

    assert(visitor.visit(visitor.context, first));
    assert(!bridge.beginServerFormatList(100U, formats));
    assert(visitor.visit(visitor.context, first));
    assert(bridge.beginServerFormatList(101U, formats));
    deliverPendingSinglePacketWithFraming(bridge, firstRoute);
    acknowledgeServerFormatList(bridge, first, kResponseOk);
    const auto accepted = bridge.lastServerFormatListReceipt();
    assert(accepted && accepted->clipboardGeneration == 101U);
    assert(accepted->status ==
           R3ClipboardTransferBridge::ServerFormatListStatus::Accepted);

    // An R2/R3 route observation that predates a new local clipboard
    // generation cannot authorize that replacement offer.
    assert(visitor.visit(visitor.context, first));
    assert(bridge.observeServerClipboardGeneration(102U));
    assert(!bridge.beginServerFormatList(102U, formats));
    assert(visitor.visit(visitor.context, first));
    assert(bridge.beginServerFormatList(102U, formats));
    deliverPendingSinglePacketWithFraming(bridge, firstRoute);
    acknowledgeServerFormatList(bridge, first, kResponseOk);

    bridge.retireR3ChannelState();
    firstRoute.close();
    assert(!bridge.active());

    // Numeric channel-ID reuse cannot revive an old route or local clipboard
    // generation; the new route repeats initialization and requires a newer
    // native generation before any server Format List can be staged.
    constexpr RdpClipboardStaticChannelView replacement{1008U, 62U};
    RdpClipboardStaticChannelRoute replacementRoute;
    assert(replacementRoute.start(
        1005U, replacement.channelId, replacement.generation, 1600U));
    assert(visitor.visit(visitor.context, replacement));
    assert(!bridge.beginServerFormatList(101U, formats));
    completeServerInitialization(
        bridge, replacementRoute, replacement, flags);
    assert(!bridge.observeServerClipboardGeneration(102U));
    assert(bridge.observeServerClipboardGeneration(103U));
    assert(visitor.visit(visitor.context, replacement));
    assert(!bridge.beginServerFormatList(102U, formats));
    assert(visitor.visit(visitor.context, replacement));
    assert(bridge.beginServerFormatList(103U, formats));
}

void serverLocalSourceRevocationResponseDrain()
{
    using namespace rdp_server::clipboard;
    using Status = R3ClipboardTransferBridge::ServerFormatListStatus;
    constexpr std::uint32_t flags = kUseLongFormatNames;
    constexpr std::array<R3ClipboardTransferBridge::OutboundFormat, 2> formats{{
        {kFormatUnicodeText, u""}, {0xc001U, u"PNG"},
    }};
    constexpr RdpClipboardStaticChannelView view{1008U, 64U};
    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, view.channelId, view.generation, 1600U));
    R3ClipboardTransferBridge bridge(flags, true);
    auto visitor = bridge.channelVisitor();
    completeServerInitialization(bridge, route, view, flags);

    assert(bridge.observeServerClipboardGeneration(300U));
    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerFormatList(300U, formats));
    deliverPendingSinglePacketWithFraming(bridge, route);
    // Native owner loss has no successor; delayed OK must drain as stale.
    assert(bridge.revokeServerClipboardGeneration(300U));
    assert(bridge.serverClipboardGeneration() == 0U);
    assert(!bridge.lastServerFormatListReceipt());
    acknowledgeServerFormatList(bridge, view, kResponseOk);
    const auto obsolete = bridge.lastServerFormatListReceipt();
    assert(obsolete && obsolete->clipboardGeneration == 300U &&
           obsolete->status == Status::Superseded);
    assert(bridge.active());
    assert(!bridge.observeServerClipboardGeneration(300U));

    assert(bridge.observeServerClipboardGeneration(301U));
    assert(!bridge.lastServerFormatListReceipt());
    assert(!bridge.revokeServerClipboardGeneration(300U));
    assert(bridge.serverClipboardGeneration() == 301U);
    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerFormatList(301U, formats));
    deliverPendingSinglePacketWithFraming(bridge, route);
    acknowledgeServerFormatList(bridge, view, kResponseOk);
    const auto accepted = bridge.lastServerFormatListReceipt();
    assert(accepted && accepted->clipboardGeneration == 301U &&
           accepted->status == Status::Accepted);

    // Accepted receipts must not survive native ownership revocation.
    assert(bridge.revokeServerClipboardGeneration(301U));
    assert(!bridge.lastServerFormatListReceipt());
    assert(bridge.observeServerClipboardGeneration(302U));
    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerFormatList(302U, formats));
    assert(!bridge.pendingApplicationPdu().empty());
    assert(bridge.revokeServerClipboardGeneration(302U));
    assert(bridge.pendingApplicationPdu().empty());
    assert(bridge.active());
    assert(bridge.observeServerClipboardGeneration(303U));
    assert(!bridge.beginServerFormatList(303U, formats));
    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerFormatList(303U, formats));
    deliverPendingSinglePacketWithFraming(bridge, route);
    acknowledgeServerFormatList(bridge, view, kResponseFail);
    assert(bridge.lastServerFormatListReceipt() &&
           bridge.lastServerFormatListReceipt()->status == Status::Rejected);

    // A queued offer has R3 write ownership, including partial R1 receipts.
    constexpr RdpClipboardStaticChannelView queuedView{1008U, 65U};
    RdpClipboardStaticChannelRoute queuedRoute;
    assert(queuedRoute.start(
        1005U, queuedView.channelId, queuedView.generation, 1600U));
    R3ClipboardTransferBridge queuedBridge(flags, true);
    auto queuedVisitor = queuedBridge.channelVisitor();
    completeServerInitialization(queuedBridge, queuedRoute, queuedView, flags);
    assert(queuedBridge.observeServerClipboardGeneration(500U));
    assert(queuedVisitor.visit(queuedVisitor.context, queuedView));
    assert(queuedBridge.beginServerFormatList(500U, formats));
    assert(queuedRoute.queue(queuedBridge.pendingApplicationPdu()));
    const auto pending = queuedRoute.pending();
    assert(pending && queuedBridge.bindQueuedWrite(pending));
    const auto routeGeneration = pending.routeGeneration;
    const auto replySequence = pending.replySequence;
    const auto writeSliceSequence = pending.writeSliceSequence;
    const auto offeredBytes = pending.wireBytes.size();
    const auto outcome = queuedRoute.onAcceptedBytes(
        routeGeneration, replySequence, writeSliceSequence, 1U);
    assert(outcome == RdpClipboardWriteOutcome::Pending);
    // The accepted-byte callback can advance/reuse R3's borrowed packet
    // view. Observe only the pre-copied scalar receipt after R3 commits.
    assert(queuedBridge.recordAcceptedWriteReceipt(
        routeGeneration, replySequence, writeSliceSequence,
        offeredBytes, 1U, outcome));
    assert(!queuedBridge.revokeServerClipboardGeneration(500U));
    assert(!queuedBridge.active());
    assert(queuedBridge.pendingApplicationPdu().empty());
    queuedRoute.close();
    assert(!queuedBridge.recordAcceptedWriteReceipt(
        routeGeneration, replySequence, writeSliceSequence,
        offeredBytes, 1U, outcome));
}

void serverInitializationPendingWriteRetirement()
{
    using namespace rdp_server::clipboard;
    constexpr std::uint32_t flags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;
    constexpr std::array<R3ClipboardTransferBridge::OutboundFormat, 1> formats{{
        {kFormatUnicodeText, u""},
    }};
    constexpr RdpClipboardStaticChannelView view{1008U, 63U};

    RdpClipboardStaticChannelRoute route;
    assert(route.start(1005U, view.channelId, view.generation, 1600U));
    R3ClipboardTransferBridge bridge(flags, true);
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();
    completeServerInitialization(bridge, route, view, flags);

    assert(bridge.observeServerClipboardGeneration(200U));
    assert(visitor.visit(visitor.context, view));
    assert(bridge.beginServerFormatList(200U, formats));
    assert(route.queue(bridge.pendingApplicationPdu()));
    const auto first = route.pending();
    assert(first && bridge.bindQueuedWrite(first));
    const std::uint64_t routeGeneration = first.routeGeneration;
    const std::uint64_t replySequence = first.replySequence;
    const std::uint64_t writeSliceSequence = first.writeSliceSequence;
    const std::size_t offeredBytes = first.wireBytes.size();
    const auto partial = route.onAcceptedBytes(
        routeGeneration, replySequence, writeSliceSequence, 1U);
    assert(partial == RdpClipboardWriteOutcome::Pending);
    assert(bridge.recordAcceptedWriteReceipt(
        routeGeneration, replySequence, writeSliceSequence,
        offeredBytes, 1U, partial));

    // Capabilities are single-shot. A replacement attempt while the server
    // offer has a positive partial R1 receipt is ambiguous and retires R8.
    assert(visitor.visit(visitor.context, view));
    assert(!sink.consume(sink.context, capabilitiesPdu(0U)));
    assert(!bridge.active());
    assert(bridge.serverInitializationStage() ==
           R3ClipboardTransferBridge::ServerInitializationStage::Dormant);
    route.close();

    assert(!bridge.recordAcceptedWriteReceipt(
        routeGeneration, replySequence, writeSliceSequence,
        offeredBytes, 1U, partial));
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

void stableScalarReceiptAfterR3Mutation()
{
    // R1's positive receipt can mutate R3's pending packet before R10 can
    // notify R8. No borrowed span survives either R3 onAcceptedBytes call.
    constexpr RdpClipboardStaticChannelView view{1008U, 53U};
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
    const auto firstRoute = first.routeGeneration;
    const auto firstReply = first.replySequence;
    const auto firstSlice = first.writeSliceSequence;
    const auto firstOffered = first.wireBytes.size();
    assert(firstOffered > 1U);
    const auto partial = route.onAcceptedBytes(
        firstRoute, firstReply, firstSlice, 1U);
    assert(partial == RdpClipboardWriteOutcome::Pending);
    assert(bridge.recordAcceptedWriteReceipt(
        firstRoute, firstReply, firstSlice, firstOffered, 1U, partial));

    const auto last = route.pending();
    assert(last);
    assert(bridge.bindQueuedWrite(last));
    const auto lastRoute = last.routeGeneration;
    const auto lastReply = last.replySequence;
    const auto lastSlice = last.writeSliceSequence;
    const auto lastOffered = last.wireBytes.size();
    assert(lastSlice != firstSlice);
    const auto delivered = route.onAcceptedBytes(
        lastRoute, lastReply, lastSlice, lastOffered);
    assert(delivered == RdpClipboardWriteOutcome::Delivered);
    assert(bridge.recordAcceptedWriteReceipt(
        lastRoute, lastReply, lastSlice, lastOffered,
        lastOffered, delivered));
    assert(route.idle());
    assert(bridge.pendingApplicationPdu().empty());

    assert(visitor.visit(visitor.context, view));
    const std::array<std::uint8_t, 4> text{'B', 0U, 0U, 0U};
    assert(sink.consume(sink.context, formatDataResponse(text)));
    const auto verified = bridge.transfer().verifiedUnicodeText();
    assert(verified && *verified == "B");

    bridge.retireR3ChannelState();
    route.close();
    constexpr RdpClipboardStaticChannelView reconnect{1008U, 54U};
    assert(visitor.visit(visitor.context, reconnect));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    // A late rejected receipt cannot retire an unrelated new R3 route.
    assert(!bridge.recordAcceptedWriteReceipt(
        firstRoute, firstReply, firstSlice, firstOffered,
        1U, RdpClipboardWriteOutcome::Rejected));
    assert(bridge.active() && bridge.routeGeneration() == reconnect.generation);

    // Zero accepted bytes can never masquerade as an R2-committed receipt.
    RdpClipboardStaticChannelRoute fresh;
    assert(fresh.start(1005U, reconnect.channelId,
                       reconnect.generation, 1600U));
    assert(fresh.queue(bridge.pendingApplicationPdu()));
    const auto zero = fresh.pending();
    assert(zero && bridge.bindQueuedWrite(zero));
    assert(!bridge.recordAcceptedWriteReceipt(
        zero.routeGeneration, zero.replySequence,
        zero.writeSliceSequence, zero.wireBytes.size(),
        0U, RdpClipboardWriteOutcome::Pending));
    assert(!bridge.active());
}


void retiredRoutePositiveReceiptIsolation()
{
    // R3 commits exact accepted bytes while R8 still holds the old request.
    // Delayed scalar observations can arrive after Stop and reconnect.
    constexpr RdpClipboardStaticChannelView original{1008U, 70U};
    RdpClipboardStaticChannelRoute oldRoute;
    assert(oldRoute.start(1005U, original.channelId,
                          original.generation, 1600U));

    R3ClipboardTransferBridge bridge(0U, true);
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();
    assert(visitor.visit(visitor.context, original));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    deliverPendingApplicationPdu(bridge, oldRoute);

    assert(visitor.visit(visitor.context, original));
    assert(bridge.beginFormatDataRequest(
        rdp_server::clipboard::kFormatUnicodeText));
    assert(oldRoute.queue(bridge.pendingApplicationPdu()));

    const auto first = oldRoute.pending();
    assert(first && bridge.bindQueuedWrite(first));
    const auto oldGeneration = first.routeGeneration;
    const auto oldReplySequence = first.replySequence;
    const auto oldPartialSlice = first.writeSliceSequence;
    const auto oldPartialOffered = first.wireBytes.size();
    assert(oldPartialOffered > 1U);
    const auto partialOutcome = oldRoute.onAcceptedBytes(
        oldGeneration, oldReplySequence, oldPartialSlice, 1U);
    assert(partialOutcome == RdpClipboardWriteOutcome::Pending);

    const auto last = oldRoute.pending();
    assert(last && bridge.bindQueuedWrite(last));
    const auto oldFinalSlice = last.writeSliceSequence;
    const auto oldFinalOffered = last.wireBytes.size();
    const auto finalOutcome = oldRoute.onAcceptedBytes(
        oldGeneration, oldReplySequence, oldFinalSlice, oldFinalOffered);
    assert(finalOutcome == RdpClipboardWriteOutcome::Delivered);
    assert(oldRoute.idle());

    bridge.retireR3ChannelState();
    oldRoute.close();
    const auto retiredSourceEpoch = bridge.transfer().sourceEpoch();
    assert(!bridge.recordAcceptedWriteReceipt(
        oldGeneration, oldReplySequence, oldPartialSlice,
        oldPartialOffered, 1U, partialOutcome));
    assert(bridge.transfer().sourceEpoch() == retiredSourceEpoch);

    // A replacement has its own outstanding FORMAT_LIST acknowledgment.
    constexpr RdpClipboardStaticChannelView replacement{1008U, 71U};
    assert(visitor.visit(visitor.context, replacement));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    RdpClipboardStaticChannelRoute currentRoute;
    assert(currentRoute.start(1005U, replacement.channelId,
                              replacement.generation, 1600U));
    assert(currentRoute.queue(bridge.pendingApplicationPdu()));
    const auto current = currentRoute.pending();
    assert(current && bridge.bindQueuedWrite(current));
    const auto currentGeneration = current.routeGeneration;
    const auto currentReplySequence = current.replySequence;
    const auto currentSlice = current.writeSliceSequence;
    const auto currentOffered = current.wireBytes.size();
    const auto currentSourceEpoch = bridge.transfer().sourceEpoch();
    const auto currentPduBytes = bridge.pendingApplicationPdu().size();
    assert(currentSourceEpoch > retiredSourceEpoch && currentPduBytes != 0U);

    assert(!bridge.recordAcceptedWriteReceipt(
        oldGeneration, oldReplySequence, oldPartialSlice,
        oldPartialOffered, 1U, partialOutcome));
    assert(!bridge.recordAcceptedWriteReceipt(
        oldGeneration, oldReplySequence, oldFinalSlice,
        oldFinalOffered, oldFinalOffered, finalOutcome));
    assert(bridge.active());
    assert(bridge.routeGeneration() == replacement.generation);
    assert(bridge.transfer().sourceEpoch() == currentSourceEpoch);
    assert(bridge.pendingApplicationPdu().size() == currentPduBytes);

    const auto currentOutcome = currentRoute.onAcceptedBytes(
        currentGeneration, currentReplySequence,
        currentSlice, currentOffered);
    assert(currentOutcome == RdpClipboardWriteOutcome::Delivered);
    assert(bridge.recordAcceptedWriteReceipt(
        currentGeneration, currentReplySequence, currentSlice,
        currentOffered, currentOffered, currentOutcome));
    assert(currentRoute.idle() && bridge.pendingApplicationPdu().empty());
}


struct DeferredWriteReceipt final
{
    std::uint64_t routeGeneration{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};
    std::size_t offeredBytes{};
    std::size_t acceptedBytes{};
    RdpClipboardWriteOutcome outcome{RdpClipboardWriteOutcome::Rejected};
};

DeferredWriteReceipt commitDeliveredWithoutBridgeObservation(
    RdpClipboardStaticChannelRoute &route,
    R3ClipboardTransferBridge &bridge)
{
    DeferredWriteReceipt deliveredReceipt{};
    bool delivered = false;
    while (const auto write = route.pending())
    {
        assert(bridge.bindQueuedWrite(write));
        DeferredWriteReceipt current{
            write.routeGeneration,
            write.replySequence,
            write.writeSliceSequence,
            write.wireBytes.size(),
            write.wireBytes.size(),
            RdpClipboardWriteOutcome::Rejected};
        current.outcome = route.onAcceptedBytes(
            current.routeGeneration, current.replySequence,
            current.writeSliceSequence, current.acceptedBytes);
        assert(current.outcome != RdpClipboardWriteOutcome::Rejected);
        if (current.outcome == RdpClipboardWriteOutcome::Delivered)
        {
            deliveredReceipt = current;
            delivered = true;
            break;
        }
        assert(current.outcome == RdpClipboardWriteOutcome::Pending);
    }
    assert(delivered);
    assert(route.idle());
    return deliveredReceipt;
}

void repeatedRestartReceiptIsolation()
{
    R3ClipboardTransferBridge bridge(0U, true);
    auto visitor = bridge.channelVisitor();
    auto sink = bridge.completePduSink();

    constexpr RdpClipboardStaticChannelView firstView{1008U, 80U};
    RdpClipboardStaticChannelRoute firstRoute;
    assert(firstRoute.start(
        1005U, firstView.channelId, firstView.generation, 1600U));
    assert(visitor.visit(visitor.context, firstView));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    assert(firstRoute.queue(bridge.pendingApplicationPdu()));
    const DeferredWriteReceipt firstReceipt =
        commitDeliveredWithoutBridgeObservation(firstRoute, bridge);
    bridge.retireR3ChannelState();
    firstRoute.close();
    const std::uint64_t firstRetiredSourceEpoch =
        bridge.transfer().sourceEpoch();
    assert(!bridge.active());

    constexpr RdpClipboardStaticChannelView secondView{1008U, 81U};
    RdpClipboardStaticChannelRoute secondRoute;
    assert(secondRoute.start(
        1005U, secondView.channelId, secondView.generation, 1600U));
    assert(visitor.visit(visitor.context, secondView));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    const std::uint64_t secondSourceEpoch = bridge.transfer().sourceEpoch();
    const std::size_t secondPendingBytes =
        bridge.pendingApplicationPdu().size();
    assert(secondSourceEpoch > firstRetiredSourceEpoch);
    assert(secondPendingBytes != 0U);

    assert(!bridge.recordAcceptedWriteReceipt(
        firstReceipt.routeGeneration, firstReceipt.replySequence,
        firstReceipt.writeSliceSequence, firstReceipt.offeredBytes,
        firstReceipt.acceptedBytes, firstReceipt.outcome));
    assert(bridge.active());
    assert(bridge.routeGeneration() == secondView.generation);
    assert(bridge.transfer().sourceEpoch() == secondSourceEpoch);
    assert(bridge.pendingApplicationPdu().size() == secondPendingBytes);

    assert(secondRoute.queue(bridge.pendingApplicationPdu()));
    const DeferredWriteReceipt secondReceipt =
        commitDeliveredWithoutBridgeObservation(secondRoute, bridge);
    bridge.retireR3ChannelState();
    secondRoute.close();
    const std::uint64_t secondRetiredSourceEpoch =
        bridge.transfer().sourceEpoch();
    assert(!bridge.active());

    constexpr RdpClipboardStaticChannelView thirdView{1008U, 82U};
    RdpClipboardStaticChannelRoute thirdRoute;
    assert(thirdRoute.start(
        1005U, thirdView.channelId, thirdView.generation, 1600U));
    assert(visitor.visit(visitor.context, thirdView));
    assert(sink.consume(sink.context, shortUnicodeFormatListPdu()));
    const std::uint64_t thirdSourceEpoch = bridge.transfer().sourceEpoch();
    const std::size_t thirdPendingBytes =
        bridge.pendingApplicationPdu().size();
    assert(thirdSourceEpoch > secondRetiredSourceEpoch);
    assert(thirdPendingBytes != 0U);

    for (const DeferredWriteReceipt &stale :
         std::array{firstReceipt, secondReceipt})
    {
        assert(!bridge.recordAcceptedWriteReceipt(
            stale.routeGeneration, stale.replySequence,
            stale.writeSliceSequence, stale.offeredBytes,
            stale.acceptedBytes, stale.outcome));
        assert(bridge.active());
        assert(bridge.routeGeneration() == thirdView.generation);
        assert(bridge.transfer().sourceEpoch() == thirdSourceEpoch);
        assert(bridge.pendingApplicationPdu().size() == thirdPendingBytes);
    }

    deliverPendingApplicationPdu(bridge, thirdRoute);
    assert(thirdRoute.idle());
    assert(bridge.pendingApplicationPdu().empty());
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
    if (behavior == "server-outbound-capabilities-format-lists")
        serverOutboundCapabilitiesAndFormatLists();
    else if (behavior == "server-initialization-ordering")
        serverInitializationOrdering();
    else if (behavior == "server-initialization-generation-replacement")
        serverInitializationGenerationReplacement();
    else if (behavior == "server-initialization-pending-write-retirement")
        serverInitializationPendingWriteRetirement();
    else if (behavior == "server-local-source-revocation-response-drain")
        serverLocalSourceRevocationResponseDrain();
    else if (behavior == "source-request-receipt")
        sourceRequestReceipt();
    else if (behavior == "missing-activated-route-denial")
        missingActivatedRouteDenial();
    else if (behavior == "old-route-generation-retirement")
        oldRouteGenerationRetirement();
    else if (behavior == "partial-positive-receipt-retirement")
        partialPositiveReceiptRetirement();
    else if (behavior == "stable-scalar-receipt-after-r3-mutation")
        stableScalarReceiptAfterR3Mutation();
    else if (behavior == "retired-route-positive-receipt-isolation")
        retiredRoutePositiveReceiptIsolation();
    else if (behavior == "repeated-restart-receipt-isolation")
        repeatedRestartReceiptIsolation();
    else if (behavior == "filecontents-request-receipt")
        fileContentsRequestReceipt();
    else
        return 2;
    return 0;
}
