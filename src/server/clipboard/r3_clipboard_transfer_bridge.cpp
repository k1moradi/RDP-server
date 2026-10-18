// SPDX-License-Identifier: GPL-3.0-or-later
#include "r3_clipboard_transfer_bridge.h"

#include "clipboard/clipboard_protocol.h"

#include <algorithm>
#include <array>
#include <utility>

namespace rdp_server::server::clipboard
{

R3ClipboardTransferBridge::R3ClipboardTransferBridge(
    const std::uint32_t localAdvertisedGeneralFlags,
    const bool nativeOfferAccepted,
    R3ClipboardFileContentsSink fileContentsSink) noexcept
    : fileContentsSink_(fileContentsSink),
      localAdvertisedGeneralFlags_(localAdvertisedGeneralFlags),
      nativeOfferAccepted_(nativeOfferAccepted)
{
}

transport::RdpClipboardChannelVisitor
R3ClipboardTransferBridge::channelVisitor() noexcept
{
    return {this, &R3ClipboardTransferBridge::visitRouteThunk};
}

transport::RdpClipboardCompletePduSink
R3ClipboardTransferBridge::completePduSink() noexcept
{
    return {this, &R3ClipboardTransferBridge::consumePduThunk};
}

bool R3ClipboardTransferBridge::visitRouteThunk(
    void *context, const transport::RdpClipboardStaticChannelView view) noexcept
{
    return context != nullptr &&
           static_cast<R3ClipboardTransferBridge *>(context)->observeRoute(view);
}

bool R3ClipboardTransferBridge::consumePduThunk(
    void *context, const std::span<const std::uint8_t> completePdu) noexcept
{
    return context != nullptr &&
           static_cast<R3ClipboardTransferBridge *>(context)
               ->consumeCompletePdu(completePdu);
}

bool R3ClipboardTransferBridge::observeRoute(
    const transport::RdpClipboardStaticChannelView view) noexcept
{
    if (!view)
        return failCurrentRoute();

    if (active())
    {
        if (view.channelId == channelId_ &&
            view.generation == routeGeneration_)
        {
            routeObservationAvailable_ = true;
            return true;
        }

        if (view.generation <= routeGeneration_)
            return failCurrentRoute();

        retireR3ChannelState();
    }

    if (view.generation <= lastRouteGeneration_)
        return false;

    channelId_ = view.channelId;
    routeGeneration_ = view.generation;
    routeObservationAvailable_ = true;
    return true;
}

bool R3ClipboardTransferBridge::stageOutbound(
    const OutboundKind kind, std::vector<std::uint8_t> pdu) noexcept
{
    if (!active() || kind == OutboundKind::None || pdu.empty() ||
        outboundKind_ != OutboundKind::None)
    {
        return false;
    }

    outboundPdu_ = std::move(pdu);
    outboundRouteGeneration_ = routeGeneration_;
    outboundReplySequence_ = 0U;
    outboundKind_ = kind;
    outboundBound_ = false;
    return true;
}

bool R3ClipboardTransferBridge::stageFormatListResponse(
    const std::array<std::uint8_t, 8> &response) noexcept
{
    try
    {
        std::vector<std::uint8_t> pdu(response.begin(), response.end());
        return stageOutbound(OutboundKind::FormatListResponse, std::move(pdu));
    }
    catch (...)
    {
        return false;
    }
}

void R3ClipboardTransferBridge::clearOutbound() noexcept
{
    outboundPdu_.clear();
    outboundRouteGeneration_ = 0U;
    outboundReplySequence_ = 0U;
    outboundKind_ = OutboundKind::None;
    outboundBound_ = false;
}

bool R3ClipboardTransferBridge::failCurrentRoute() noexcept
{
    retireR3ChannelState();
    return false;
}

bool R3ClipboardTransferBridge::consumeCompletePdu(
    const std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;

    // The caller must synchronously visit the exact R2/R3 route before each
    // dispatch. The callback itself receives only a whole application PDU and
    // therefore cannot manufacture or infer a channel generation.
    if (!active() || !routeObservationAvailable_)
        return failCurrentRoute();
    routeObservationAvailable_ = false;

    PduView pdu{};
    if (!decodePdu(completePdu, pdu))
        return failCurrentRoute();

    switch (pdu.type)
    {
    case kClipCaps:
        if (!transfer_.receiveCapabilitiesPdu(
                completePdu, localAdvertisedGeneralFlags_))
        {
            return failCurrentRoute();
        }
        return true;

    case kTempDirectory:
        if (!transfer_.receiveTemporaryDirectoryPdu(completePdu))
            return failCurrentRoute();
        return true;

    case kFormatList:
    {
        // Do not supersede a source while a server-to-client clipboard PDU is
        // only partially accepted by R1. R3 retirement owns ambiguous writes.
        if (outboundKind_ != OutboundKind::None)
            return failCurrentRoute();

        std::array<std::uint8_t, 8> acknowledgment{};
        const bool accepted = transfer_.receiveNegotiatedFormatListWithResponse(
            completePdu, nativeOfferAccepted_, acknowledgment);
        if (!transfer_.synchronized())
            return failCurrentRoute();
        if (!stageFormatListResponse(acknowledgment))
            return failCurrentRoute();

        // Native refusal is represented by CB_RESPONSE_FAIL and remains a
        // valid protocol exchange; it does not create clipboard authority.
        (void)accepted;
        return true;
    }

    case kFormatDataResponse:
    {
        if (!formatRequestDelivered_)
            return failCurrentRoute();
        formatRequestDelivered_ = false;

        const auto response = transfer_.receiveResponse(completePdu);
        if (response.status == RemoteTransfer::ResponseStatus::ProtocolError)
            return failCurrentRoute();
        if (response.status != RemoteTransfer::ResponseStatus::Received)
            return true;

        if (response.formatId == kFormatUnicodeText)
        {
            (void)transfer_.storeVerifiedUnicodeText(response);
            return true;
        }

        const std::uint32_t pngFormatId = transfer_.namedFormatId("PNG");
        if (response.formatId == pngFormatId ||
            response.formatId == 17U || response.formatId == 8U)
        {
            (void)transfer_.storeVerifiedImage(response);
            return true;
        }

        if (response.formatId ==
            transfer_.namedFormatId("FileGroupDescriptorW"))
        {
            (void)transfer_.storeFileGroupDescriptors(response);
        }
        return true;
    }

    case kFileContentsResponse:
    {
        if (!fileContentsRequestDelivered_)
            return failCurrentRoute();
        fileContentsRequestDelivered_ = false;

        const auto result = transfer_.receiveFileContentsResponse(completePdu);
        if (result.status == RemoteTransfer::FileContentsStatus::ProtocolError)
            return failCurrentRoute();
        if (fileContentsSink_ &&
            !fileContentsSink_.consume(fileContentsSink_.context, result))
        {
            return failCurrentRoute();
        }
        return true;
    }

    default:
        // R3 already validated framing. Unexpected CLIPRDR application PDUs are
        // ignored here rather than being reinterpreted as an offer or response.
        return true;
    }
}

bool R3ClipboardTransferBridge::beginFormatDataRequest(
    const std::uint32_t formatId) noexcept
{
    if (!active() || !routeObservationAvailable_ ||
        outboundKind_ != OutboundKind::None ||
        formatRequestDelivered_ || fileContentsRequestDelivered_)
    {
        return false;
    }
    routeObservationAvailable_ = false;

    std::vector<std::uint8_t> pdu;
    if (!transfer_.beginRequest(formatId, pdu))
        return false;
    if (!stageOutbound(OutboundKind::FormatDataRequest, std::move(pdu)))
        return failCurrentRoute();
    return true;
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
R3ClipboardTransferBridge::beginFileSizeRequest(
    const std::size_t fileIndex) noexcept
{
    if (!active() || !routeObservationAvailable_ ||
        outboundKind_ != OutboundKind::None ||
        formatRequestDelivered_ || fileContentsRequestDelivered_)
    {
        return std::nullopt;
    }
    routeObservationAvailable_ = false;

    std::vector<std::uint8_t> pdu;
    const auto receipt = transfer_.beginFileSizeRequest(fileIndex, pdu);
    if (!receipt)
        return std::nullopt;
    if (!stageOutbound(OutboundKind::FileContentsRequest, std::move(pdu)))
    {
        (void)failCurrentRoute();
        return std::nullopt;
    }
    return receipt;
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
R3ClipboardTransferBridge::beginFileRangeRequest(
    const std::size_t fileIndex, const std::uint64_t offset,
    const std::size_t requestedBytes) noexcept
{
    if (!active() || !routeObservationAvailable_ ||
        outboundKind_ != OutboundKind::None ||
        formatRequestDelivered_ || fileContentsRequestDelivered_)
    {
        return std::nullopt;
    }
    routeObservationAvailable_ = false;

    std::vector<std::uint8_t> pdu;
    const auto receipt = transfer_.beginFileRangeRequest(
        fileIndex, offset, requestedBytes, pdu);
    if (!receipt)
        return std::nullopt;
    if (!stageOutbound(OutboundKind::FileContentsRequest, std::move(pdu)))
    {
        (void)failCurrentRoute();
        return std::nullopt;
    }
    return receipt;
}

std::span<const std::uint8_t>
R3ClipboardTransferBridge::pendingApplicationPdu() const noexcept
{
    if (!active() || outboundKind_ == OutboundKind::None ||
        outboundRouteGeneration_ != routeGeneration_)
    {
        return {};
    }
    return outboundPdu_;
}

bool R3ClipboardTransferBridge::bindQueuedWrite(
    const transport::RdpClipboardStaticChannelWriteView &write) noexcept
{
    if (!active() || outboundKind_ == OutboundKind::None || !write ||
        write.routeGeneration != routeGeneration_ ||
        write.routeGeneration != outboundRouteGeneration_)
    {
        return false;
    }

    if (outboundBound_ && outboundReplySequence_ != write.replySequence)
        return failCurrentRoute();

    outboundReplySequence_ = write.replySequence;
    outboundBound_ = true;
    return true;
}

bool R3ClipboardTransferBridge::recordAcceptedWrite(
    const transport::RdpClipboardStaticChannelWriteView &write,
    const std::size_t acceptedBytes,
    const transport::RdpClipboardWriteOutcome outcome) noexcept
{
    using transport::RdpClipboardWriteOutcome;

    if (outcome == RdpClipboardWriteOutcome::Rejected)
    {
        if (write.routeGeneration == routeGeneration_)
            retireR3ChannelState();
        return false;
    }

    if (!active() || !outboundBound_ ||
        outboundKind_ == OutboundKind::None || !write ||
        write.routeGeneration != routeGeneration_ ||
        write.routeGeneration != outboundRouteGeneration_ ||
        write.replySequence != outboundReplySequence_ ||
        acceptedBytes == 0U ||
        acceptedBytes > write.wireBytes.size())
    {
        return failCurrentRoute();
    }

    if (outcome == RdpClipboardWriteOutcome::Pending)
        return true;

    if (outcome != RdpClipboardWriteOutcome::Delivered ||
        acceptedBytes != write.wireBytes.size())
    {
        return failCurrentRoute();
    }

    const OutboundKind completedKind = outboundKind_;
    clearOutbound();
    if (completedKind == OutboundKind::FormatDataRequest)
        formatRequestDelivered_ = true;
    else if (completedKind == OutboundKind::FileContentsRequest)
        fileContentsRequestDelivered_ = true;
    return true;
}

void R3ClipboardTransferBridge::retireR3ChannelState() noexcept
{
    lastRouteGeneration_ = (std::max)(lastRouteGeneration_, routeGeneration_);
    channelId_ = 0U;
    routeGeneration_ = 0U;
    routeObservationAvailable_ = false;
    clearOutbound();
    formatRequestDelivered_ = false;
    fileContentsRequestDelivered_ = false;
    transfer_.retireR3ChannelState();
}

} // namespace rdp_server::server::clipboard
