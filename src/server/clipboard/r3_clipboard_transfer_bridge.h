// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "remote_transfer.h"
#include "server/transport/mcs_channel_connection.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace rdp_server::server::clipboard
{

struct R3ClipboardFileContentsSink final
{
    void *context{};
    bool (*consume)(
        void *, const RemoteTransfer::FileContentsResult &) noexcept{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context != nullptr && consume != nullptr;
    }
};

// R8 application-state bridge for R3's authenticated post-Share CLIPRDR route.
//
// This object is not an RDP session owner. It never authenticates, parses
// MCS/static-VC framing, mints channel generations, or performs transport I/O.
// The live caller obtains channelVisitor() observations only from R2's protected
// R3 visitor and delivers completePduSink() only through R2's fully reassembled
// R3 dispatch. Outbound complete CLIPRDR PDUs are copied/framed by R3; exact R1
// accepted-byte receipts remain R3/R2-owned and are only observed here to gate
// when an R8 request may consume its response.
//
// Thread-safety: serialized connection event-loop only. The span returned by
// pendingApplicationPdu() is invalidated by every mutating call.
class R3ClipboardTransferBridge final
{
public:
    R3ClipboardTransferBridge(
        std::uint32_t localAdvertisedGeneralFlags,
        bool nativeOfferAccepted,
        R3ClipboardFileContentsSink fileContentsSink = {}) noexcept;

    R3ClipboardTransferBridge(const R3ClipboardTransferBridge &) = delete;
    R3ClipboardTransferBridge &operator=(
        const R3ClipboardTransferBridge &) = delete;
    R3ClipboardTransferBridge(R3ClipboardTransferBridge &&) = delete;
    R3ClipboardTransferBridge &operator=(
        R3ClipboardTransferBridge &&) = delete;

    [[nodiscard]] transport::RdpClipboardChannelVisitor
    channelVisitor() noexcept;
    [[nodiscard]] transport::RdpClipboardCompletePduSink
    completePduSink() noexcept;

    [[nodiscard]] RemoteTransfer &transfer() noexcept
    {
        return transfer_;
    }
    [[nodiscard]] const RemoteTransfer &transfer() const noexcept
    {
        return transfer_;
    }

    [[nodiscard]] bool active() const noexcept
    {
        return channelId_ != 0U && routeGeneration_ != 0U;
    }
    [[nodiscard]] std::uint16_t channelId() const noexcept
    {
        return active() ? channelId_ : 0U;
    }
    [[nodiscard]] std::uint64_t routeGeneration() const noexcept
    {
        return active() ? routeGeneration_ : 0U;
    }

    enum class ServerInitializationStage : std::uint8_t
    {
        Dormant,
        ServerCapabilitiesWritePending,
        AwaitMonitorReady,
        MonitorReadyWritePending,
        AwaitClientInitialization,
        Ready,
    };

    enum class ServerFormatListStatus : std::uint8_t
    {
        Accepted,
        Rejected,
        Superseded,
    };

    struct ServerFormatListReceipt final
    {
        std::uint64_t clipboardGeneration{};
        ServerFormatListStatus status{ServerFormatListStatus::Rejected};
    };

    [[nodiscard]] ServerInitializationStage
    serverInitializationStage() const noexcept
    {
        return serverInitializationStage_;
    }
    [[nodiscard]] bool serverInitializationReady() const noexcept
    {
        return serverInitializationStage_ == ServerInitializationStage::Ready;
    }
    [[nodiscard]] std::uint64_t serverClipboardGeneration() const noexcept
    {
        return serverClipboardGeneration_;
    }
    [[nodiscard]] std::optional<ServerFormatListReceipt>
    lastServerFormatListReceipt() const noexcept
    {
        return lastServerFormatListReceipt_;
    }

    struct OutboundFormat final
    {
        std::uint32_t formatId{};
        // Borrowed only for beginServerFormatList(); serialization copies it
        // into outboundPdu_ before returning.
        std::u16string_view name{};
    };

    // Offline/reusable server-originated CLIPRDR seam. These methods only
    // serialize and stage a complete application PDU on the already-observed
    // authenticated R3 route; they do not activate CLIPRDR or own transport.
    // The live scheduler must still honor the MS-RDPECLIP initialization
    // sequence and use R3/R2's sole queue/write-receipt path.
    [[nodiscard]] bool beginServerCapabilities() noexcept;
    [[nodiscard]] bool beginServerMonitorReady() noexcept;

    // Local/native clipboard generations are monotonic over this bridge
    // lifetime. Replacing the local generation while a Format List response is
    // outstanding marks that response stale; it is drained but cannot accept
    // the replacement generation.
    [[nodiscard]] bool observeServerClipboardGeneration(
        std::uint64_t clipboardGeneration) noexcept;
    // Native source loss is not a new clipboard generation. A false result
    // for a queued offer requires R2/R3 to retire the sole writer/route.
    [[nodiscard]] bool revokeServerClipboardGeneration(
        std::uint64_t clipboardGeneration) noexcept;
    [[nodiscard]] bool beginServerFormatList(
        std::uint64_t clipboardGeneration,
        std::span<const OutboundFormat> formats) noexcept;

    // Requires a fresh channelVisitor() observation from R2/R3. The generated
    // PDU has no transport authority until R2 successfully queues it through
    // queueR3PersonalDesktopClipboardPdu().
    [[nodiscard]] bool beginFormatDataRequest(
        std::uint32_t formatId) noexcept;
    [[nodiscard]] std::optional<RemoteTransfer::FileContentsRequestReceipt>
    beginFileSizeRequest(std::size_t fileIndex) noexcept;
    [[nodiscard]] std::optional<RemoteTransfer::FileContentsRequestReceipt>
    beginFileRangeRequest(
        std::size_t fileIndex, std::uint64_t offset,
        std::size_t requestedBytes) noexcept;

    [[nodiscard]] std::span<const std::uint8_t>
    pendingApplicationPdu() const noexcept;

    // Bind the exact R3 route/reply returned by the R2-protected queue call.
    // Each accepted-byte callback must first be committed by R2/R3; Pending
    // never completes the R8 request. Delivered is the sole send completion.
    [[nodiscard]] bool bindQueuedWrite(
        const transport::RdpClipboardStaticChannelWriteView &write) noexcept;
    [[nodiscard]] bool recordAcceptedWrite(
        const transport::RdpClipboardStaticChannelWriteView &write,
        std::size_t acceptedBytes,
        transport::RdpClipboardWriteOutcome outcome) noexcept;

    // R2/R3 may invalidate the borrowed R3 span during the R1 write
    // receipt. Observe copied scalars after R2 committed those bytes;
    // this bridge never creates a second write-offset or receipt owner.
    [[nodiscard]] bool recordAcceptedWriteReceipt(
        std::uint64_t routeGeneration, std::uint64_t replySequence,
        std::uint64_t writeSliceSequence, std::size_t offeredBytes,
        std::size_t acceptedBytes,
        transport::RdpClipboardWriteOutcome outcome) noexcept;

    // Call before discarding/replacing the authenticated R3 route. Monotonic
    // route/source/request identities are preserved by their respective owners.
    void retireR3ChannelState() noexcept;

private:
    enum class OutboundKind : std::uint8_t
    {
        None,
        ServerCapabilities,
        ServerMonitorReady,
        ServerFormatList,
        FormatListResponse,
        FormatDataRequest,
        FileContentsRequest,
    };

    [[nodiscard]] static bool visitRouteThunk(
        void *context,
        transport::RdpClipboardStaticChannelView view) noexcept;
    [[nodiscard]] static bool consumePduThunk(
        void *context, std::span<const std::uint8_t> completePdu) noexcept;

    [[nodiscard]] bool observeRoute(
        transport::RdpClipboardStaticChannelView view) noexcept;
    [[nodiscard]] bool consumeCompletePdu(
        std::span<const std::uint8_t> completePdu) noexcept;
    [[nodiscard]] bool stageOutbound(
        OutboundKind kind, std::vector<std::uint8_t> pdu) noexcept;
    [[nodiscard]] bool stageFormatListResponse(
        const std::array<std::uint8_t, 8> &response) noexcept;
    void maybeCompleteServerInitialization() noexcept;
    void resetServerInitializationForRoute() noexcept;
    void clearOutbound() noexcept;
    [[nodiscard]] bool failCurrentRoute() noexcept;

    RemoteTransfer transfer_{};
    R3ClipboardFileContentsSink fileContentsSink_{};
    std::vector<std::uint8_t> outboundPdu_{};
    std::uint32_t localAdvertisedGeneralFlags_{};
    std::uint16_t channelId_{};
    std::uint64_t routeGeneration_{};
    std::uint64_t lastRouteGeneration_{};
    std::uint64_t outboundRouteGeneration_{};
    std::uint64_t outboundReplySequence_{};
    OutboundKind outboundKind_{OutboundKind::None};
    ServerInitializationStage serverInitializationStage_{
        ServerInitializationStage::Dormant};
    std::optional<ServerFormatListReceipt> lastServerFormatListReceipt_{};
    std::uint64_t serverClipboardGeneration_{};
    std::uint64_t lastServerClipboardGeneration_{};
    std::uint64_t pendingServerFormatListGeneration_{};
    std::uint64_t lastServerFormatListOfferedGeneration_{};
    bool nativeOfferAccepted_{};
    bool routeObservationAvailable_{};
    bool clientInitialFormatListResponseDelivered_{};
    bool formatListResponseInitial_{};
    bool serverFormatListAwaitingResponse_{};
    bool outboundBound_{};
    bool formatRequestDelivered_{};
    bool fileContentsRequestDelivered_{};
};

} // namespace rdp_server::server::clipboard
