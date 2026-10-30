// SPDX-License-Identifier: GPL-3.0-or-later
#include "r3_clipboard_transfer_bridge.h"

#include "clipboard/clipboard_protocol.h"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace rdp_server::server::clipboard
{

namespace
{
constexpr std::uint16_t kGeneralCapabilitySetType = 1U;
constexpr std::uint16_t kGeneralCapabilitySetBytes = 12U;
constexpr std::uint32_t kCapabilitiesVersion2 = 2U;
constexpr std::size_t kMaximumFormatNameCodeUnits = 256U;
constexpr std::size_t kShortFormatNameBytes = 32U;
constexpr std::size_t kShortFormatEntryBytes =
    sizeof(std::uint32_t) + kShortFormatNameBytes;

void write16(std::span<std::uint8_t> bytes, const std::size_t offset,
             const std::uint16_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void write32(std::span<std::uint8_t> bytes, const std::size_t offset,
             const std::uint32_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

[[nodiscard]] bool validFormatName(
    const std::u16string_view name) noexcept
{
    if (name.size() > kMaximumFormatNameCodeUnits)
        return false;

    bool pendingHighSurrogate = false;
    for (const char16_t rawCodeUnit : name)
    {
        const auto codeUnit = static_cast<std::uint16_t>(rawCodeUnit);
        if (codeUnit == 0U)
            return false;
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (pendingHighSurrogate)
                return false;
            pendingHighSurrogate = true;
        }
        else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
        {
            if (!pendingHighSurrogate)
                return false;
            pendingHighSurrogate = false;
        }
        else if (pendingHighSurrogate)
        {
            return false;
        }
    }
    return !pendingHighSurrogate;
}

[[nodiscard]] bool validFormats(
    const std::span<const R3ClipboardTransferBridge::OutboundFormat> formats)
    noexcept
{
    if (formats.size() > RemoteTransfer::kMaximumFormats)
        return false;

    for (std::size_t index = 0U; index < formats.size(); ++index)
    {
        if (formats[index].formatId == 0U ||
            !validFormatName(formats[index].name))
        {
            return false;
        }
        for (std::size_t previous = 0U; previous < index; ++previous)
        {
            if (formats[previous].formatId == formats[index].formatId)
                return false;
        }
    }
    return true;
}

[[nodiscard]] bool encodeServerCapabilities(
    const std::uint32_t localAdvertisedGeneralFlags,
    std::vector<std::uint8_t> &pdu) noexcept
{
    using namespace rdp_server::clipboard;
    std::array<std::uint8_t, 16U> payload{};
    write16(payload, 0U, 1U);
    write16(payload, 2U, 0U);
    write16(payload, 4U, kGeneralCapabilitySetType);
    write16(payload, 6U, kGeneralCapabilitySetBytes);
    write32(payload, 8U, kCapabilitiesVersion2);
    write32(payload, 12U,
            localAdvertisedGeneralFlags & RemoteTransfer::kSupportedGeneralFlags);
    return encodePdu(kClipCaps, 0U, payload, pdu);
}

[[nodiscard]] bool encodeServerLongFormatList(
    const std::span<const R3ClipboardTransferBridge::OutboundFormat> formats,
    std::vector<std::uint8_t> &pdu) noexcept
{
    using namespace rdp_server::clipboard;
    std::size_t payloadBytes = 0U;
    for (const auto &format : formats)
    {
        const std::size_t nameBytes = (format.name.size() + 1U) * 2U;
        if (payloadBytes > kMaximumPduBytes - 8U - sizeof(std::uint32_t) ||
            nameBytes > kMaximumPduBytes - 8U - payloadBytes -
                            sizeof(std::uint32_t))
        {
            return false;
        }
        payloadBytes += sizeof(std::uint32_t) + nameBytes;
    }

    try
    {
        std::vector<std::uint8_t> payload(payloadBytes, 0U);
        std::size_t offset = 0U;
        for (const auto &format : formats)
        {
            write32(payload, offset, format.formatId);
            offset += sizeof(std::uint32_t);
            for (const char16_t rawCodeUnit : format.name)
            {
                write16(payload, offset,
                        static_cast<std::uint16_t>(rawCodeUnit));
                offset += 2U;
            }
            write16(payload, offset, 0U);
            offset += 2U;
        }
        return offset == payload.size() &&
               encodePdu(kFormatList, 0U, payload, pdu);
    }
    catch (...)
    {
        pdu.clear();
        return false;
    }
}

[[nodiscard]] bool encodeServerShortFormatList(
    const std::span<const R3ClipboardTransferBridge::OutboundFormat> formats,
    std::vector<std::uint8_t> &pdu) noexcept
{
    using namespace rdp_server::clipboard;
    bool useAsciiNames = true;
    for (const auto &format : formats)
    {
        if (format.name.size() > kShortFormatNameBytes)
        {
            useAsciiNames = false;
            break;
        }
        for (const char16_t rawCodeUnit : format.name)
        {
            if (static_cast<std::uint16_t>(rawCodeUnit) > 0x7fU)
            {
                useAsciiNames = false;
                break;
            }
        }
        if (!useAsciiNames)
            break;
    }

    if (!useAsciiNames)
    {
        constexpr std::size_t kMaximumShortUnicodeCodeUnits =
            kShortFormatNameBytes / 2U;
        for (const auto &format : formats)
        {
            if (format.name.size() > kMaximumShortUnicodeCodeUnits)
                return false;
        }
    }

    if (formats.size() >
        (std::numeric_limits<std::size_t>::max)() / kShortFormatEntryBytes)
    {
        return false;
    }

    try
    {
        std::vector<std::uint8_t> payload(
            formats.size() * kShortFormatEntryBytes, 0U);
        for (std::size_t index = 0U; index < formats.size(); ++index)
        {
            const std::size_t entryOffset = index * kShortFormatEntryBytes;
            write32(payload, entryOffset, formats[index].formatId);
            if (useAsciiNames)
            {
                for (std::size_t nameIndex = 0U;
                     nameIndex < formats[index].name.size(); ++nameIndex)
                {
                    payload[entryOffset + sizeof(std::uint32_t) + nameIndex] =
                        static_cast<std::uint8_t>(
                            formats[index].name[nameIndex]);
                }
            }
            else
            {
                for (std::size_t nameIndex = 0U;
                     nameIndex < formats[index].name.size(); ++nameIndex)
                {
                    write16(
                        payload,
                        entryOffset + sizeof(std::uint32_t) + nameIndex * 2U,
                        static_cast<std::uint16_t>(
                            formats[index].name[nameIndex]));
                }
            }
        }
        return encodePdu(
            kFormatList, useAsciiNames ? kAsciiNames : 0U, payload, pdu);
    }
    catch (...)
    {
        pdu.clear();
        return false;
    }
}

[[nodiscard]] bool encodeServerFormatList(
    const std::span<const R3ClipboardTransferBridge::OutboundFormat> formats,
    const bool useLongFormatNames,
    std::vector<std::uint8_t> &pdu) noexcept
{
    if (!validFormats(formats))
    {
        pdu.clear();
        return false;
    }
    return useLongFormatNames ?
        encodeServerLongFormatList(formats, pdu) :
        encodeServerShortFormatList(formats, pdu);
}
} // namespace

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

bool R3ClipboardTransferBridge::beginServerCapabilities() noexcept
{
    if (!active() || !routeObservationAvailable_ ||
        outboundKind_ != OutboundKind::None ||
        formatRequestDelivered_ || fileContentsRequestDelivered_)
    {
        return false;
    }
    routeObservationAvailable_ = false;

    std::vector<std::uint8_t> pdu;
    if (!encodeServerCapabilities(localAdvertisedGeneralFlags_, pdu))
        return failCurrentRoute();
    if (!stageOutbound(OutboundKind::ServerCapabilities, std::move(pdu)))
        return failCurrentRoute();
    return true;
}

bool R3ClipboardTransferBridge::beginServerFormatList(
    const std::span<const OutboundFormat> formats) noexcept
{
    if (!active() || !routeObservationAvailable_ ||
        outboundKind_ != OutboundKind::None ||
        formatRequestDelivered_ || fileContentsRequestDelivered_)
    {
        return false;
    }
    routeObservationAvailable_ = false;

    std::vector<std::uint8_t> pdu;
    const bool useLongFormatNames =
        (transfer_.negotiatedGeneralFlags() &
         rdp_server::clipboard::kUseLongFormatNames) != 0U;
    if (!encodeServerFormatList(formats, useLongFormatNames, pdu))
        return false;
    if (!stageOutbound(OutboundKind::ServerFormatList, std::move(pdu)))
        return failCurrentRoute();
    return true;
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
    return recordAcceptedWriteReceipt(
        write.routeGeneration, write.replySequence, write.writeSliceSequence,
        write.wireBytes.size(), acceptedBytes, outcome);
}

bool R3ClipboardTransferBridge::recordAcceptedWriteReceipt(
    const std::uint64_t routeGeneration,
    const std::uint64_t replySequence,
    const std::uint64_t writeSliceSequence,
    const std::size_t offeredBytes,
    const std::size_t acceptedBytes,
    const transport::RdpClipboardWriteOutcome outcome) noexcept
{
    using transport::RdpClipboardWriteOutcome;

    // A previously committed R3 positive receipt may arrive after Stop or
    // reconnect. It must not retire the replacement route or its source epoch.
    // A zero/future generation against a live route remains fail-closed.
    if (routeGeneration_ == 0U ||
        (routeGeneration != 0U && routeGeneration < routeGeneration_))
    {
        return false;
    }

    if (outcome == RdpClipboardWriteOutcome::Rejected)
    {
        if (routeGeneration == routeGeneration_)
            retireR3ChannelState();
        return false;
    }

    // R3 alone has already validated the exact writeSliceSequence and
    // advanced accepted plaintext; R8 never duplicates that write offset.
    if (!active() || !outboundBound_ ||
        outboundKind_ == OutboundKind::None ||
        routeGeneration != routeGeneration_ ||
        routeGeneration != outboundRouteGeneration_ ||
        replySequence == 0U ||
        replySequence != outboundReplySequence_ ||
        writeSliceSequence == 0U || offeredBytes == 0U ||
        acceptedBytes == 0U || acceptedBytes > offeredBytes)
    {
        return failCurrentRoute();
    }

    if (outcome == RdpClipboardWriteOutcome::Pending)
        return true;

    if (outcome != RdpClipboardWriteOutcome::Delivered ||
        acceptedBytes != offeredBytes)
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
