// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rdp_server::server::transport
{
class McsChannelJoinWriteGate;
struct McsChannelRequest;
}

namespace rdp_server::server::clipboard
{

class RemoteFileDestinationPlan;

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
    static constexpr std::size_t kMaximumRemoteFiles = 64;
    static constexpr std::size_t kMaximumRemoteHierarchyDepth = 16U;
    static constexpr std::size_t kMaximumFileContentsChunkBytes = 64U * 1024U;
    // MS-RDPECLIP generalFlags: capability version is informational only.
    // The bounded lock/unlock boundary below is intentionally offline until
    // the server initialization/authorization route can truthfully advertise
    // CB_CAN_LOCK_CLIPDATA.
    static constexpr std::uint32_t kSupportedGeneralFlags = 0x0000002eU;

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

    // Consume the client's fixed-size Temporary Directory PDU after its
    // capabilities and before the first Format List. The path is validated
    // structurally but never retained or dereferenced by this owner.
    [[nodiscard]] bool receiveTemporaryDirectoryPdu(
        std::span<const std::uint8_t> completePdu) noexcept;

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
        TemporaryDirectoryAccepted,
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

    // OFFLINE lock/unlock transport boundary. A usable lock requires the raw
    // peer/local capability exchange to include CB_CAN_LOCK_CLIPDATA and a
    // valid client Temporary Directory PDU. kSupportedGeneralFlags still masks
    // the capability, so this does not claim negotiated interoperability.
    // One fully delivered Lock snapshots only fixed-capacity descriptor
    // metadata for its exact generation; file bodies are never cached here.
    enum class FileLockOperation : std::uint8_t { Lock, Unlock };
    struct JoinedFileLockReceipt
    {
        std::uint64_t sequence{};
        std::uint64_t generation{};
        std::uint32_t clipDataId{};
        std::size_t bytes{};
        FileLockOperation operation{FileLockOperation::Lock};
    };

    [[nodiscard]] std::optional<JoinedFileLockReceipt>
    prepareJoinedFileLock(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] std::optional<JoinedFileLockReceipt>
    prepareJoinedFileUnlock(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::uint32_t clipDataId,
        std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] bool joinedFileLockMayWrite(
        std::uint64_t sequence) const noexcept;
    [[nodiscard]] bool recordJoinedFileLockWritten(
        std::uint64_t sequence, std::size_t cumulativeBytes) noexcept;
    [[nodiscard]] bool cancelUnwrittenJoinedFileLock(
        std::uint64_t sequence) noexcept;
    [[nodiscard]] bool abandonJoinedFileLock(
        std::uint64_t sequence) noexcept;

    // Stream-file capability and FileGroupDescriptorW are both generation
    // scoped. Descriptor storage is fixed-capacity metadata only; no remote
    // file body is retained here.
    struct RemoteFileView
    {
        // Safe leaf only. Relative hierarchy components are intentionally not
        // exposed as a pathname or filesystem-placement hint.
        std::span<const char16_t> name{};
        std::uint64_t size{};
        std::uint32_t attributes{};
        bool sizeKnown{};
        bool directory{};
    };

    enum class RemoteHierarchyStatus : std::uint8_t
    {
        Unavailable,
        VerifiedRelativePaths,
        UnsupportedSourcePathsAllowed,
        UnsupportedDuplicateNode,
        UnsupportedMissingParent,
        UnsupportedParentNotDirectory,
        UnsupportedParentCycle,
        UnsupportedDepthExceeded,
    };

    struct RemoteHierarchyNodeView
    {
        std::size_t remoteFileIndex{};
        std::optional<std::size_t> parentRemoteFileIndex{};
        std::uint16_t depth{};
        bool directory{};
    };

    // Non-authorizing CLIPRDR structure only. A verified node is bound to the
    // current FileGroupDescriptorW generation and exact descriptor index.
    // No relative path string is exposed, opened or converted into a local
    // path. Missing/ambiguous parents make the whole hierarchy unavailable
    // transactionally while flat file streaming remains usable.
    [[nodiscard]] RemoteHierarchyStatus remoteHierarchyStatus() const noexcept;
    [[nodiscard]] std::optional<RemoteHierarchyNodeView>
    remoteHierarchyNode(std::size_t fileIndex) const noexcept;

    [[nodiscard]] bool fileStreamingAvailable() const noexcept;
    [[nodiscard]] bool beginFileGroupDescriptorRequest(
        std::vector<std::uint8_t> &output) noexcept;
    [[nodiscard]] bool storeFileGroupDescriptors(
        const Response &response) noexcept;
    [[nodiscard]] std::size_t remoteFileCount() const noexcept;
    [[nodiscard]] std::optional<RemoteFileView> remoteFile(
        std::size_t fileIndex) const noexcept;

    enum class FileContentsKind : std::uint8_t { Size, Range };
    enum class FileContentsStatus : std::uint8_t
    {
        Invalid,
        ReceivedSize,
        ReceivedRange,
        RemoteFailure,
        DiscardedPreviousGeneration,
        ProtocolError,
    };
    struct FileContentsRequestReceipt
    {
        std::uint64_t sequence{};
        std::uint64_t generation{};
        std::uint32_t streamId{};
        // Zero selects the current generation. Nonzero identifies the exact
        // retained generation from a completely delivered Lock PDU.
        std::uint32_t clipDataId{};
        std::size_t fileIndex{};
        std::uint64_t offset{};
        std::size_t requestedBytes{};
        FileContentsKind kind{FileContentsKind::Size};
    };
    struct FileContentsResult
    {
        FileContentsStatus status{FileContentsStatus::Invalid};
        std::uint64_t sequence{};
        std::uint64_t generation{};
        std::uint32_t streamId{};
        std::uint32_t clipDataId{};
        std::size_t fileIndex{};
        std::uint64_t offset{};
        std::uint64_t fileSize{};
        // Borrowed from the complete response PDU for ReceivedRange only.
        std::span<const std::uint8_t> bytes{};
    };

    [[nodiscard]] std::optional<FileContentsRequestReceipt>
    beginFileSizeRequest(
        std::size_t fileIndex,
        std::vector<std::uint8_t> &output) noexcept;
    [[nodiscard]] std::optional<FileContentsRequestReceipt>
    beginFileRangeRequest(
        std::size_t fileIndex, std::uint64_t offset,
        std::size_t requestedBytes,
        std::vector<std::uint8_t> &output) noexcept;
    [[nodiscard]] std::optional<FileContentsRequestReceipt>
    beginLockedFileSizeRequest(
        std::uint32_t clipDataId, std::size_t fileIndex,
        std::vector<std::uint8_t> &output) noexcept;
    [[nodiscard]] std::optional<FileContentsRequestReceipt>
    beginLockedFileRangeRequest(
        std::uint32_t clipDataId, std::size_t fileIndex,
        std::uint64_t offset, std::size_t requestedBytes,
        std::vector<std::uint8_t> &output) noexcept;

    // OFFLINE wire-only FileContents preparation. This reuses the same
    // generation-scoped stream receipt as beginFile*Request(), then adds the
    // static-VC/MCS envelope only after the expected CLIPRDR channel is joined.
    // A confirmed join is membership, NOT R2/R3 authorization or TLS write
    // permission; the authoritative session owner must still gate every write.
    struct JoinedFileContentsRequestReceipt
    {
        FileContentsRequestReceipt request{};
        std::size_t bytes{};
    };

    [[nodiscard]] std::optional<JoinedFileContentsRequestReceipt>
    prepareJoinedFileSizeRequest(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::size_t fileIndex, std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] std::optional<JoinedFileContentsRequestReceipt>
    prepareJoinedFileRangeRequest(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::size_t fileIndex, std::uint64_t offset,
        std::size_t requestedBytes, std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] std::optional<JoinedFileContentsRequestReceipt>
    prepareJoinedLockedFileSizeRequest(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::uint32_t clipDataId, std::size_t fileIndex,
        std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] std::optional<JoinedFileContentsRequestReceipt>
    prepareJoinedLockedFileRangeRequest(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        std::uint32_t clipDataId, std::size_t fileIndex,
        std::uint64_t offset, std::size_t requestedBytes,
        std::span<std::uint8_t> output) noexcept;

    [[nodiscard]] bool joinedFileContentsRequestMayWrite(
        std::uint64_t sequence) const noexcept;
    [[nodiscard]] bool recordJoinedFileContentsRequestWritten(
        std::uint64_t sequence, std::size_t cumulativeBytes) noexcept;
    [[nodiscard]] bool cancelUnwrittenJoinedFileContentsRequest(
        std::uint64_t sequence) noexcept;
    [[nodiscard]] bool abandonJoinedFileContentsRequest(
        std::uint64_t sequence) noexcept;
    [[nodiscard]] FileContentsResult receiveFileContentsResponse(
        std::span<const std::uint8_t> completePdu) noexcept;
    [[nodiscard]] bool cancelUnsentFileContentsRequest(
        std::uint64_t sequence) noexcept;
    [[nodiscard]] bool hasOutstandingFileContentsRequest() const noexcept;

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

    // Only a validated current-generation CF_UNICODETEXT reply can make an
    // owned UTF-8 clipboard snapshot ready for native adapters. This accepts
    // the borrowed Response synchronously before its PDU buffer expires.
    // Invalid content clears readiness but does not poison sound PDU framing.
    [[nodiscard]] bool storeVerifiedUnicodeText(
        const Response &response) noexcept;
    [[nodiscard]] std::optional<std::string_view>
    verifiedUnicodeText() const noexcept;

    // A verified image remains in its negotiated wire representation: named
    // PNG stays compressed PNG; CF_DIBV5/CF_DIB stay packed DIB. The returned
    // span borrows owner storage and is invalidated by a new offer/disconnect.
    enum class VerifiedImageFormat : std::uint8_t { Png, DibV5, Dib };
    struct VerifiedImage
    {
        VerifiedImageFormat format{VerifiedImageFormat::Png};
        std::uint64_t generation{};
        std::uint32_t sourceFormatId{};
        std::span<const std::uint8_t> bytes{};
    };
    [[nodiscard]] bool storeVerifiedImage(const Response &response) noexcept;
    [[nodiscard]] std::optional<VerifiedImage> verifiedImage() const noexcept;

    // Native clipboard adapters register at most one waiting paste on this
    // session event loop. Time is caller-supplied from a monotonic clock:
    // RemoteTransfer never sleeps, waits, starts a thread, or polls the OS.
    using PasteClock = std::chrono::steady_clock;
    // Png is native-target-specific: unlike Image, it must never become
    // ready from a validated DIB/DIBV5 fallback.
    enum class PasteKind : std::uint8_t { UnicodeText, Image, Png };
    enum class PasteStatus : std::uint8_t
    {
        InvalidSequence,
        Pending,
        ReadyUnicodeText,
        ReadyImage,
        TimedOut,
        ClipboardReplaced,
        OwnerLost,
        Disconnected,
        ChannelError,
    };
    struct PasteRequestReceipt
    {
        std::uint64_t sequence{};
        std::uint64_t generation{};
    };
    struct PasteResult
    {
        PasteStatus status{PasteStatus::InvalidSequence};
        std::uint64_t sequence{};
        std::uint64_t generation{};
        std::string_view text{};
        std::optional<VerifiedImage> image{};
    };

    // Register the SAME native paste request that must later be completed or
    // rejected. This does no transport I/O. A valid current offer for the
    // requested content kind is required, but already-verified data may make
    // the next poll immediately ready. The deadline must be strictly future.
    [[nodiscard]] std::optional<PasteRequestReceipt> beginPasteRequest(
        PasteKind kind, PasteClock::time_point now,
        PasteClock::time_point deadline) noexcept;

    // Event-loop poll/dispatch point. Pending is nonterminal. Every other
    // returned status consumes this receipt exactly once; ready views borrow
    // RemoteTransfer-owned current-generation storage.
    [[nodiscard]] PasteResult pollPasteRequest(
        std::uint64_t sequence, PasteClock::time_point now) noexcept;

    // Native adapter owner loss rejects the same waiting request but does not
    // poison the CLIPRDR session. Stale receipt callbacks are ignored.
    [[nodiscard]] bool cancelPasteRequestForOwnerLoss(
        std::uint64_t sequence) noexcept;
    [[nodiscard]] bool hasPendingPasteRequest() const noexcept;

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
    friend class RemoteFileDestinationPlan;

    struct PendingRequest
    {
        std::uint64_t generation{};
        std::uint32_t formatId{};
    };

    struct RemoteFileDescriptor
    {
        // The protocol can carry a bounded relative name such as
        // "folder\\child.bin". Keep it as untrusted structural metadata only;
        // native adapters continue to see name/nameLength as a safe leaf.
        std::array<char16_t, 260> relativePath{};
        std::array<char16_t, 260> name{};
        std::uint16_t relativePathLength{};
        std::uint16_t nameLength{};
        std::uint16_t hierarchyDepth{};
        std::size_t hierarchyParentIndex{};
        std::uint64_t size{};
        std::uint32_t attributes{};
        bool hierarchyParentPresent{};
        bool sizeKnown{};
        bool directory{};
    };

    struct PendingFileContentsRequest
    {
        std::uint64_t sequence{};
        std::uint64_t generation{};
        std::uint32_t streamId{};
        std::uint32_t clipDataId{};
        std::size_t fileIndex{};
        std::uint64_t offset{};
        std::size_t requestedBytes{};
        FileContentsKind kind{FileContentsKind::Size};
    };

    [[nodiscard]] std::optional<FileContentsRequestReceipt>
    beginFileContentsRequest(
        FileContentsKind kind, std::uint32_t clipDataId,
        std::size_t fileIndex, std::uint64_t offset,
        std::size_t requestedBytes,
        std::vector<std::uint8_t> &output) noexcept;
    [[nodiscard]] std::optional<JoinedFileContentsRequestReceipt>
    prepareJoinedFileContentsRequest(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        FileContentsKind kind, std::uint32_t clipDataId,
        std::size_t fileIndex, std::uint64_t offset,
        std::size_t requestedBytes,
        std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] std::optional<JoinedFileLockReceipt>
    prepareJoinedFileLockOperation(
        const transport::McsChannelJoinWriteGate &joinedChannels,
        std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
        FileLockOperation operation, std::uint32_t clipDataId,
        std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] bool fileLockSessionPrerequisitesMet() const noexcept;
    [[nodiscard]] bool fileLockWriteSourceStillValid() const noexcept;
    [[nodiscard]] bool fileContentsRequestSourceStillValid(
        const PendingFileContentsRequest &request) const noexcept;

    std::string verifiedTextUtf8_{};
    bool verifiedTextReady_{};
    std::vector<std::uint8_t> verifiedImageBytes_{};
    VerifiedImageFormat verifiedImageFormat_{VerifiedImageFormat::Png};
    std::uint64_t verifiedImageGeneration_{};
    std::uint32_t verifiedImageSourceFormatId_{};
    bool verifiedImageReady_{};
    PasteClock::time_point pasteRequestDeadline_{};
    std::uint64_t pasteRequestSequence_{}; // Never reset: no native receipt ABA.
    std::uint64_t pasteRequestActiveSequence_{};
    std::uint64_t pasteRequestGeneration_{};
    PasteKind pasteRequestKind_{PasteKind::UnicodeText};
    PasteStatus pasteRequestStatus_{PasteStatus::InvalidSequence};
    bool pasteRequestPresent_{};
    std::array<std::uint8_t, 8> lastFormatListResponse_{};
    bool lastFormatListResponseValid_{};
    std::array<std::uint32_t, kMaximumFormats> advertisedFormats_{};
    std::size_t advertisedCount_{};
    std::uint32_t pngFormatId_{};
    std::uint32_t fileGroupDescriptorFormatId_{};
    std::array<RemoteFileDescriptor, kMaximumRemoteFiles> remoteFiles_{};
    std::size_t remoteFileCount_{};
    std::uint64_t remoteFileGeneration_{};
    std::uint64_t remoteHierarchyGeneration_{};
    RemoteHierarchyStatus remoteHierarchyStatus_{
        RemoteHierarchyStatus::Unavailable};

    // One retained generation, fixed to the same 64-descriptor bound as the
    // current offer. Receipt and clipDataId counters never reset or recycle.
    std::array<RemoteFileDescriptor, kMaximumRemoteFiles> lockedRemoteFiles_{};
    std::size_t lockedRemoteFileCount_{};
    std::uint64_t lockedRemoteFileGeneration_{};
    std::uint32_t lockedClipDataId_{};
    bool fileLockPresent_{};
    std::uint64_t fileLockReceiptSequence_{};
    std::uint64_t clipDataIdSequence_{};
    JoinedFileLockReceipt pendingFileLockWrite_{};
    std::size_t fileLockWrittenBytes_{};
    bool fileLockWriteActive_{};

    std::uint64_t fileContentsSequence_{}; // Never reset: no stream receipt ABA.
    PendingFileContentsRequest pendingFileContents_{};
    std::uint64_t joinedFileContentsActiveSequence_{};
    std::size_t joinedFileContentsFrameBytes_{};
    std::size_t joinedFileContentsWrittenBytes_{};
    bool pendingFileContentsValid_{};
    bool joinedFileContentsActive_{};
    std::array<std::uint32_t, 4> attemptedPrefetchIds_{};
    std::uint64_t generation_{};
    // Monotonic accepted-offer identity. Unlike generation_, this never resets
    // on disconnect, so generation-number reuse cannot revive stale mappings.
    std::uint64_t sourceEpoch_{};
    std::uint32_t negotiatedGeneralFlags_{};
    // Keep the raw exchange only to prove the offline Lock prerequisite;
    // negotiatedGeneralFlags_ still masks CB_CAN_LOCK_CLIPDATA.
    std::uint32_t peerGeneralFlags_{};
    std::uint32_t localAdvertisedGeneralFlags_{};
    bool capabilitiesReceived_{};
    bool temporaryDirectoryReceived_{};
    PendingRequest pending_{};
    bool pendingValid_{};
    std::uint64_t joinedRequestSequence_{}; // Never reset: no receipt ABA.
    std::uint64_t joinedRequestActiveSequence_{};
    std::size_t joinedRequestFrameBytes_{};
    std::size_t joinedRequestWrittenBytes_{};
    bool joinedRequestActive_{};
    bool poisoned_{};
};

// Fixed-capacity, non-authorizing association metadata for one exact remote
// clipboard offer generation. It never opens, creates, writes, flushes or
// publishes a local filesystem object. localSelectionIdentity is caller-owned
// stable metadata used only to detect conflicting selections; it is NOT a
// native filesystem capability. Actual materialization still requires an
// independently supplied open descriptor/HANDLE in the platform destination.
//
// Thread-safety: event-loop/thread confined, like RemoteTransfer. A committed
// plan must not outlive its bound RemoteTransfer object.
class RemoteFileDestinationPlan final
{
public:
    static constexpr std::size_t kMaximumAssociations =
        RemoteTransfer::kMaximumRemoteFiles;
    static constexpr std::size_t kMaximumPlacementDepth = 16U;

    enum class RemoteEntryRole : std::uint8_t
    {
        File,
        Directory,
    };

    struct Selection
    {
        std::size_t remoteFileIndex{};
        std::uint64_t localSelectionIdentity{};
        // Explicit caller-selected local placement relation only. This is not
        // evidence that the remote source advertised the same hierarchy.
        std::optional<std::size_t> parentRemoteFileIndex{};
    };

    struct Association
    {
        std::size_t remoteFileIndex{};
        std::uint64_t localSelectionIdentity{};
        // Caller-selected local placement metadata; never remote authority.
        std::optional<std::size_t> parentRemoteFileIndex{};
        // Wire-provenance metadata, present only for a fully verified relative
        // hierarchy. Still not a local filesystem capability.
        std::optional<std::size_t> verifiedRemoteParentFileIndex{};
        std::uint16_t verifiedRemoteDepth{};
        RemoteEntryRole remoteRole{RemoteEntryRole::File};
    };

    enum class PrepareStatus : std::uint8_t
    {
        Prepared,
        AlreadyCommitted,
        Cancelled,
        Closed,
        SourceNotSynchronized,
        GenerationRequired,
        StaleGeneration,
        NoRemoteDescriptors,
        EmptyManifest,
        TooManySelections,
        IncompleteManifest,
        RemoteIndexOutOfRange,
        DuplicateRemoteIndex,
        AmbiguousPlacement,
        MissingDestination,
        DuplicateDestination,
        DescriptorUnavailable,
        MissingParent,
        SelfParent,
        ParentNotDirectory,
        ParentCycle,
        PlacementDepthExceeded,
    };

    enum class AssociationStatus : std::uint8_t
    {
        CurrentFile,
        UnsupportedDirectoryMaterialization,
        NotCommitted,
        Cancelled,
        Closed,
        StaleSource,
        MissingAssociation,
    };

    enum class RemoteHierarchyStatus : std::uint8_t
    {
        UnsupportedWithRetainedMetadata,
        VerifiedRelativePaths,
    };

    RemoteFileDestinationPlan() noexcept = default;
    ~RemoteFileDestinationPlan() noexcept = default;
    RemoteFileDestinationPlan(const RemoteFileDestinationPlan &) = delete;
    RemoteFileDestinationPlan &operator=(
        const RemoteFileDestinationPlan &) = delete;
    RemoteFileDestinationPlan(RemoteFileDestinationPlan &&) = delete;
    RemoteFileDestinationPlan &operator=(
        RemoteFileDestinationPlan &&) = delete;

    [[nodiscard]] PrepareStatus prepare(
        const RemoteTransfer &source, std::uint64_t expectedGeneration,
        std::span<const Selection> selections) noexcept;

    // Returns metadata only while the exact source object, offer epoch and
    // generation remain current. No native capability is returned or implied.
    [[nodiscard]] std::optional<Association> association(
        const RemoteTransfer &source,
        std::size_t remoteFileIndex) const noexcept;
    [[nodiscard]] AssociationStatus associationStatus(
        const RemoteTransfer &source,
        std::size_t remoteFileIndex) const noexcept;
    [[nodiscard]] bool current(const RemoteTransfer &source) const noexcept;

    [[nodiscard]] bool committed() const noexcept
    {
        return state_ == State::Committed;
    }
    [[nodiscard]] std::size_t size() const noexcept
    {
        return associationCount_;
    }
    [[nodiscard]] std::uint64_t generation() const noexcept
    {
        return generation_;
    }
    [[nodiscard]] RemoteHierarchyStatus hierarchyStatus() const noexcept
    {
        if (state_ != State::Committed || source_ == nullptr ||
            !current(*source_))
        {
            return RemoteHierarchyStatus::UnsupportedWithRetainedMetadata;
        }
        return source_->remoteHierarchyStatus() ==
                       RemoteTransfer::RemoteHierarchyStatus::VerifiedRelativePaths
                   ? RemoteHierarchyStatus::VerifiedRelativePaths
                   : RemoteHierarchyStatus::UnsupportedWithRetainedMetadata;
    }

    // Cancellation is terminal. close() is idempotent and preserves an
    // already-cancelled terminal state.
    void cancel() noexcept;
    void close() noexcept;

private:
    enum class State : std::uint8_t
    {
        Empty,
        Committed,
        Cancelled,
        Closed,
    };

    void retireMetadata(State terminalState) noexcept;

    std::array<Association, kMaximumAssociations> associations_{};
    std::size_t associationCount_{};
    std::uint64_t generation_{};
    std::uint64_t sourceEpoch_{};
    const RemoteTransfer *source_{};
    State state_{State::Empty};
};

} // namespace rdp_server::server::clipboard
