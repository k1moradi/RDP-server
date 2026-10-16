// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace rdp_server::server::transport
{
class McsChannelJoinWriteGate;
struct McsChannelRequest;
}

namespace rdp_server::server::clipboard
{

// A source-owned, single-session CLIPRDR response coordinator.
// The channel transports one Format Data Request at a time: responses have
// no wire request ID. A new Format List cannot make an in-flight response
// belong to a new generation. All methods are session-event-loop confined;
// callers must not access this object concurrently.
class RemoteTransfer final
{
public:
    static constexpr std::size_t kMaximumFormats = 64;
    static constexpr std::size_t kMaximumCapabilitySets = 16;
    // MS-RDPECLIP generalFlags: capability version is informational only.
    static constexpr std::uint32_t kSupportedGeneralFlags = 0x0000003eU;

    enum class ResponseStatus : std::uint8_t
    {
        Received,
        RemoteFailure,
        DiscardedPreviousGeneration,
        ProtocolError,
    };

    struct Response
    {
        ResponseStatus status{ResponseStatus::ProtocolError};
        std::uint64_t generation{};
        std::uint32_t formatId{};
        // Borrowed from the caller's immutable PDU input. Consume or copy
        // immediately, before the supplied PDU buffer is released.
        std::span<const std::uint8_t> payload{};
    };

    // A valid new list supersedes earlier offers. Invalid or overflowing
    // lists poison this channel; only resetAfterDisconnect() permits reuse.
    [[nodiscard]] bool receiveFormatList(
        std::span<const std::uint32_t> advertisedFormatIds) noexcept;

    // Consume a complete CB_FORMAT_LIST only after both peers negotiate
    // CB_USE_LONG_FORMAT_NAMES. No borrowed names survive this call.
    // Malformed wire input closes this coordinator until disconnect.
    [[nodiscard]] bool receiveLongFormatListPdu(
        std::span<const std::uint8_t> completePdu) noexcept;

    // Consume the fallback fixed-width (36-byte/format) representation only
    // when CB_USE_LONG_FORMAT_NAMES was not negotiated by both endpoints.
    // CB_ASCII_NAMES selects 32 single-byte characters, otherwise 16 UTF-16LE
    // code units. A full name field may be truncated without a terminator.
    [[nodiscard]] bool receiveShortFormatListPdu(
        std::span<const std::uint8_t> completePdu) noexcept;

    // Process an authorized, complete Format List using the R3-negotiated
    // name layout, then encode its eight-byte MS-RDPECLIP response. The
    // native adapter must have accepted the new offer before the caller
    // passes nativeOfferAccepted=true; if acceptance is asynchronous, defer
    // this call until completion. A rejected offer advances the generation
    // but advertises nothing, so old data cannot be requested accidentally.
    // A failed parse poisons the session until actual disconnect. A negative
    // reply must only be transmitted through R3's admitted CLIPRDR channel.
    // The caller owns transport/send completion; this method does no I/O.
    [[nodiscard]] bool receiveFormatListWithResponse(
        std::span<const std::uint8_t> completePdu,
        bool negotiatedLongFormatNames, bool nativeOfferAccepted,
        std::array<std::uint8_t, 8> &response) noexcept;

    // Called on the session event loop after R3 admits the CLIPRDR channel.
    // The caller supplies the server's actually advertised generalFlags.
    // Missing capabilities imply zero flags; duplicates/malformed sets
    // poison this channel until resetAfterDisconnect().
    [[nodiscard]] bool receiveCapabilitiesPdu(
        std::span<const std::uint8_t> completePdu,
        std::uint32_t localGeneralFlags) noexcept;

    [[nodiscard]] std::uint32_t negotiatedGeneralFlags() const noexcept;

    // Select long/short names using jointly supported capabilities, not a
    // caller-supplied format mode. Native acceptance must precede CB_OK.
    [[nodiscard]] bool receiveNegotiatedFormatListWithResponse(
        std::span<const std::uint8_t> completePdu,
        bool nativeOfferAccepted,
        std::array<std::uint8_t, 8> &response) noexcept;

    // OFFLINE R3/R8 boundary: wrap the already-created 8-byte Format List
    // Response in one uncompressed CHANNEL_PDU_HEADER (FIRST|LAST), then
    // ask R3's joined-channel gate to encode the T.125 SendDataIndication.
    // The caller must additionally authorize the authenticated RDP session,
    // negotiated CLIPRDR channel ID, security-header rules, and one TLS writer.
    // Successful serialization is NEVER permission to transmit.
    // The supplied acknowledgment must match this owner's latest generated
    // Format List response; disconnect/replacement revokes older replies.
    // No output bytes change on error; no raw response span is retained.
    [[nodiscard]] std::optional<std::size_t>
    encodeJoinedFormatListResponse(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId,
        std::span<const std::uint8_t> completeResponse,
        std::span<std::uint8_t> output) const noexcept;

    // OFFLINE inbound R3/R8 dispatch boundary. The caller MUST already
    // validate TLS/NLA, OS-session admission, security headers and the
    // negotiated CLIPRDR channel role; a joined MCS channel is not authority.
    // request is a previously parsed complete T.125 SendDataRequest.
    // This path accepts ONE complete, uncompressed static VC chunk only:
    // fragmented MCS or VC traffic must be reassembled by R3/R9 first.
    // It never owns an MCS session, opens TLS, or touches an OS clipboard.
    enum class JoinedReceiveStatus : std::uint8_t
    {
        Denied,
        Ignored,
        CapabilitiesAccepted,
        FormatListAccepted,
        FormatListDeclined,
        DataReceived,
        DataFailed,
        ObsoleteDataDiscarded,
        ProtocolError,
    };

    struct JoinedReceiveResult
    {
        JoinedReceiveStatus status{JoinedReceiveStatus::Denied};
        Response data{};
        // Generated only for a CLIPRDR Format List, including FAIL.
        // Caller must send it through the existing R3 writer after admission.
        std::array<std::uint8_t, 8> acknowledgment{};
        bool acknowledgmentReady{};
    };

    [[nodiscard]] JoinedReceiveResult receiveJoinedStaticChannelPdu(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        const transport::McsChannelRequest &request,
        std::uint16_t expectedCliprdrChannelId,
        bool authenticatedOsSessionAdmitted,
        std::uint32_t localAdvertisedGeneralFlags,
        bool nativeOfferAccepted) noexcept;

    // Known registered format names are resolved from this generation's offer.
    [[nodiscard]] std::uint32_t namedFormatId(std::string_view name) const noexcept;

    // Encode a CLIPRDR Format Data Request only for the current generation.
    // On success, output owns a complete PDU; on rejection output is empty.
    // Call only after the previous request has completed or been retired.
    [[nodiscard]] bool beginRequest(
        std::uint32_t formatId, std::vector<std::uint8_t> &output) noexcept;

    // OFFLINE wire-only preparation. A confirmed R3 MCS join and the
    // expected CLIPRDR role ID are necessary but NOT TLS/NLA/OS authority.
    // R3 must independently admit the session/channel and serialize the
    // exact caller-owned output through its single TLS writer.
    // On failure output and pending request are unchanged (no phantom slot).
    // The returned receipt is generation/lifetime scoped and monotonic
    // even across resetAfterDisconnect(), to reject stale writer callbacks.
    struct JoinedRequestReceipt
    {
        std::uint64_t sequence{};
        std::uint64_t generation{};
        std::size_t bytes{};
    };

    [[nodiscard]] std::optional<JoinedRequestReceipt>
    prepareJoinedFormatDataRequest(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::uint32_t formatId,
        std::span<std::uint8_t> output) noexcept;

    // The R3 session owner must recheck this before queuing bytes, on
    // the same event loop as clipboard generation changes. Serialization
    // or membership does NOT itself grant permission to send.
    [[nodiscard]] bool joinedRequestMayWrite(
        std::uint64_t sequence) const noexcept;

    // Cumulative bytes *actually accepted by the one connection writer*.
    // Only a complete write allows the corresponding reply to be consumed.
    // Wrong/stale receipts are ignored; impossible progress fails closed.
    [[nodiscard]] bool recordJoinedRequestWritten(
        std::uint64_t sequence, std::size_t cumulativeBytes) noexcept;

    // Revoke a prepared request only when no byte was submitted. Once any
    // part might have been sent, failure/timeout is ambiguous and the
    // coordinator must remain poisoned until a genuine disconnect.
    [[nodiscard]] bool cancelUnwrittenJoinedRequest(
        std::uint64_t sequence) noexcept;
    [[nodiscard]] bool abandonJoinedRequest(
        std::uint64_t sequence) noexcept;

    // Optional bounded eager-retrieval planner for one clipboard generation.
    // Text selects CF_UNICODETEXT only; images prefer registered PNG, then
    // CF_DIBV5 (17) and CF_DIB (8). IDs are matched to THIS format list,
    // never inferred from a registered name's previous-generation ID.
    // Each candidate can be attempted once per generation. Call again only
    // after a failed or caller-rejected response to try the next fallback.
    // Does not cache, validate, render, publish, or perform transport I/O.
    // The same single-flight pending reply must finish/drain before another
    // request can begin. A live paste can use beginRequest directly.
    enum class PrefetchKind : std::uint8_t { UnicodeText, Image };
    [[nodiscard]] bool beginNextPrefetch(
        PrefetchKind kind,
        std::uint32_t &selectedFormatId,
        std::vector<std::uint8_t> &output) noexcept;

    // Exactly one response is consumed for each outstanding request. A
    // response to a retired generation is drained, never reassigned.
    [[nodiscard]] Response receiveResponse(
        std::span<const std::uint8_t> completePdu) noexcept;

    // A lost, timed-out or ambiguous response cannot be correlated with
    // subsequent traffic. Fail closed until an actual channel disconnect.
    void abandonRequest() noexcept;
    void resetAfterDisconnect() noexcept;

    [[nodiscard]] bool synchronized() const noexcept;
    [[nodiscard]] bool hasOutstandingRequest() const noexcept;
    [[nodiscard]] bool waitingForObsoleteResponse() const noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept;
    [[nodiscard]] bool advertises(std::uint32_t formatId) const noexcept;

private:
    struct PendingRequest
    {
        std::uint64_t generation{};
        std::uint32_t formatId{};
    };

    std::array<std::uint8_t, 8> lastFormatListResponse_{};
    bool lastFormatListResponseValid_{};
    std::array<std::uint32_t, kMaximumFormats> advertisedFormats_{};
    std::size_t advertisedCount_{};
    std::uint32_t pngFormatId_{};
    std::uint32_t fileGroupDescriptorFormatId_{};
    std::array<std::uint32_t, 4> attemptedPrefetchIds_{};
    std::uint64_t generation_{};
    std::uint32_t negotiatedGeneralFlags_{};
    bool capabilitiesReceived_{};
    PendingRequest pending_{};
    bool pendingValid_{};
    std::uint64_t joinedRequestSequence_{}; // Never reset: no receipt ABA.
    std::uint64_t joinedRequestActiveSequence_{};
    std::size_t joinedRequestFrameBytes_{};
    std::size_t joinedRequestWrittenBytes_{};
    bool joinedRequestActive_{};
    bool poisoned_{};
};

} // namespace rdp_server::server::clipboard
