// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "gcc_conference_create.h"
#include "mcs_connect_response.h"
#include "rdp_clipboard_static_channel.h"
#include "rdp_demand_active_profile.h"
#include "rdp_licensing.h"
#include "rdp/gfx_avc420_segmented_frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace rdp_server::server::security
{
class LinuxConsoleAdmissionBroker;
}

namespace rdp_server::server::transport
{

// Syntax-only, bounded T.125 DomainMCSPDU parsing for the RDP
// Channel Connection, Send Data Request and Disconnect Provider
// Ultimatum phases. No user, channel or session is admitted or joined.
// The authenticated owner alone can close its TLS connection.
// MS-RDPBCGR 2.2.1.5, 2.2.1.6 and 2.2.1.8.
enum class McsChannelRequestKind : std::uint8_t
{
    None,
    ErectDomain,
    AttachUser,
    ChannelJoin,
    DisconnectProviderUltimatum,
    SendDataRequest,
};

enum class McsChannelParseError : std::uint8_t
{
    None,
    InvalidTransport,
    InvalidDomainPdu,
    InvalidPerValue,
};

struct McsChannelRequest
{
    McsChannelRequestKind kind{McsChannelRequestKind::None};
    // Present only in ErectDomain (PER unsigned INTEGER fields).
    std::uint32_t subHeight{};
    std::uint32_t subInterval{};
    // Present only in ChannelJoin. 'initiator' is the decoded
    // T.125 UserId (PER on-wire offset + 1001); channelId is the
    // requested channel, NOT a verified allocated channel.
    std::uint32_t initiator{};
    std::uint16_t channelId{};
    // Only for SendDataRequest. T.125 aligned-PER two-bit DataPriority
    // (0..3) and Segmentation flags (0..3); these are syntax, NOT
    // proof of any negotiated/attached session or complete message.
    std::uint8_t dataPriority{};
    std::uint8_t segmentation{};
    // Zero-copy borrowed view into the caller-owned COMPLETE TPKT.
    // Valid only while its input backing bytes remain alive and unchanged;
    // never retain across a TLS read, thread handoff, or buffer reuse.
    std::span<const std::uint8_t> userData{};
};

struct McsChannelParseResult
{
    McsChannelRequest request{};
    McsChannelParseError error{McsChannelParseError::InvalidTransport};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == McsChannelParseError::None;
    }
};

// A complete single TPKT is required. Validate its declared size,
// X.224 Class 0 Data TPDU and all PER fields before returning a value.
// Received disconnect reasons are ignored as MS-RDPBCGR requires.
// SendDataRequest accepts 7-bit and 14-bit PER userData lengths,
// including the commonly emitted two-octet length for short payloads;
// fragmented PER lengths are unsupported and rejected. The complete
// TPKT is bounded by RFC1006; the maximum single PER payload is 16383.
// A syntactically recognized request does NOT establish channel state,
// domain ownership or authorization, nor does it allow a response.
[[nodiscard]] McsChannelParseResult parseMcsChannelRequest(
    std::span<const std::uint8_t> completeTpkt) noexcept;

// OFFLINE server confirmation serializers from MS-RDPBCGR 2.2.1.7
// and 2.2.1.9. Producing a value never assigns a UserId, accepts a
// credential, attaches a domain, or sends an MCS confirmation over TLS.
// A future *single authenticated domain owner* must approve identifiers,
// ordering and actual emission; a caller-provided list is not proof.
struct McsChannelConfirm
{
    std::array<std::uint8_t, 15> packet{};
    std::size_t length{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return length != 0;
    }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
    {
        return std::span(packet).first(length);
    }
};

// Offline positional CS_NET / SC_NET static-channel identity only.
// MS-RDPBCGR 2.2.1.3.4 and 2.2.1.4.4. NOT a permission or a join.
enum class McsStaticChannelRole : std::uint8_t
{
    Clipboard,
    DeviceRedirection,
    Sound,
    DynamicVirtualChannels,
};

[[nodiscard]] std::optional<std::uint16_t> resolveMcsStaticChannelRole(
    const GccClientSettings &settings,
    const McsConnectResponseAllocation &allocation,
    McsStaticChannelRole role) noexcept;

// Enhanced RDP Security still carries a 4-byte Basic Security Header
// on Client Info even though R1/TLS already decrypted and authenticated
// the complete outer PDU. This syntax-only view never authenticates
// TS_INFO_PACKET fields, creates admission or advances session state.
enum class RdpClientInfoEnvelopeError : std::uint8_t
{
    None,
    TruncatedSecurityHeader,
    InvalidSecurityFlags,
    TruncatedInfoPacket,
};

struct RdpClientInfoEnvelopeView
{
    std::uint16_t flags{};
    std::uint16_t flagsHi{};
    std::span<const std::uint8_t> infoPacket{};
};

struct RdpClientInfoEnvelopeParseResult
{
    RdpClientInfoEnvelopeView value{};
    RdpClientInfoEnvelopeError error{
        RdpClientInfoEnvelopeError::TruncatedSecurityHeader};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpClientInfoEnvelopeError::None;
    }
};

// MS-RDPBCGR 2.2.1.11 / 2.2.8.1.1.2.1 for PROTOCOL_HYBRID.
// Require SEC_INFO_PKT and reject every packet-kind/encryption flag that
// would imply a different RDP security path. RESET/IGNORE sequence bits
// and flagsHi are ignored as required by the specification.
// The returned TS_INFO_PACKET bytes remain caller-owned and unparsed.
[[nodiscard]] RdpClientInfoEnvelopeParseResult
parseEnhancedSecurityClientInfoEnvelope(
    std::span<const std::uint8_t> mcsUserData) noexcept;

// Enhanced RDP Security licensing envelope: the 4-byte Basic Security Header
// remains mandatory even though TLS already protects the transport. This
// parser accepts only SEC_LICENSE_PKT plus the spec-ignored sequence/flagsHi
// bits. Standard-Security encryption/exchange and competing packet-kind flags
// fail closed before licensing bytes reach the stateful lifecycle.
enum class RdpLicensingEnvelopeError : std::uint8_t
{
    None,
    TruncatedSecurityHeader,
    InvalidSecurityFlags,
    TruncatedLicensingMessage,
};

struct RdpLicensingEnvelopeView
{
    std::uint16_t flags{};
    std::uint16_t flagsHi{};
    // Borrowed complete TS_LICENSING_PDU after the Basic Security Header.
    std::span<const std::uint8_t> licensingMessage{};
};

struct RdpLicensingEnvelopeParseResult
{
    RdpLicensingEnvelopeView value{};
    RdpLicensingEnvelopeError error{
        RdpLicensingEnvelopeError::TruncatedSecurityHeader};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingEnvelopeError::None;
    }
};

[[nodiscard]] RdpLicensingEnvelopeParseResult
parseEnhancedSecurityLicensingEnvelope(
    std::span<const std::uint8_t> mcsUserData) noexcept;

// Bounded structural validation for MS-RDPBCGR TS_INFO_PACKET plus optional
// TS_EXTENDED_INFO_PACKET. Sensitive Domain/UserName/Password/Shell/WorkingDir
// bytes are never returned, copied or logged. Only scalar shape metadata is
// published. All length arithmetic is checked against the caller-owned span.
enum class RdpClientInfoPacketError : std::uint8_t
{
    None,
    TruncatedFixedFields,
    InvalidStringLength,
    MissingStringTerminator,
    InvalidExtendedInfo,
    InvalidExtendedTerminator,
    InvalidOptionalOrdering,
};

struct RdpClientInfoPacketSummary
{
    std::uint32_t codePage{};
    std::uint32_t flags{};
    bool unicode{};
    bool hasExtendedInfo{};
    std::uint16_t domainBytes{};
    std::uint16_t userNameBytes{};
    std::uint16_t passwordBytes{};
    std::uint16_t alternateShellBytes{};
    std::uint16_t workingDirBytes{};
};

struct RdpClientInfoPacketParseResult
{
    RdpClientInfoPacketSummary value{};
    RdpClientInfoPacketError error{
        RdpClientInfoPacketError::TruncatedFixedFields};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpClientInfoPacketError::None;
    }
};

[[nodiscard]] RdpClientInfoPacketParseResult parseRdpClientInfoPacket(
    std::span<const std::uint8_t> infoPacket) noexcept;

// T.125 AttachUserConfirm rt-successful with initiator present.
// 'assignedUserId' is an explicit external allocation, never
// chosen or reserved by this pure encoder.
[[nodiscard]] McsChannelConfirm encodeMcsAttachUserConfirm(
    std::uint32_t assignedUserId) noexcept;

// Fixed-size, one-shot outbound receipt owner for an Attach User Confirm.
// This offline component never grants R2 admission or MCS membership.
// All publication and completions are gated separately by the R2 broker.
class McsAttachUserConfirmWriteGate final
{
public:
    McsAttachUserConfirmWriteGate() noexcept = default;
    McsAttachUserConfirmWriteGate(const McsAttachUserConfirmWriteGate &) = delete;
    McsAttachUserConfirmWriteGate &operator=(const McsAttachUserConfirmWriteGate &) = delete;
    [[nodiscard]] bool queue(std::uint32_t assignedUserId) noexcept;
    [[nodiscard]] McsConnectResponseWriteView pendingWrite() const noexcept;
    [[nodiscard]] McsConnectResponseWriteOutcome onBytesWritten(
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;

private:
    McsChannelConfirm pending_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool delivered_{};
    bool closed_{};
};

// ChannelJoinConfirm rt-successful with optional channelId present.
// Inputs must describe a checked Join REQUEST, matching assigned user,
// and exactly one matching entry in a bounded caller-supplied list.
// The list cannot confer authorization. A real owner must check
// OS/NLA identity and MCS channel state before sending any bytes.
[[nodiscard]] McsChannelConfirm encodeMcsChannelJoinConfirm(
    const McsChannelRequest &joinRequest,
    std::uint32_t assignedUserId,
    std::span<const std::uint16_t> assignedChannelIds) noexcept;

// The sole future authenticated session owner can embed this bounded gate
// after MCS Connect Response and Attach User completion. This component is
// NOT an admission token, an authorization decision or an RDP session owner.
// It tracks only which JOIN replies the caller's single outbound writer has
// completely accepted; the caller must still check R2 admission, TLS identity,
// protocol stage and channel permissions before routing ANY application data.
// Serialized event-loop use only. A borrowed pendingBytes() span is invalidated
// by every mutating call. The gate is non-copyable to prevent state forks.
enum class McsJoinStartOutcome : std::uint8_t
{
    ReplyPending,
    Buffered,
    AlreadyJoined,
    AlreadyPending,
    Rejected,
};

enum class McsJoinWriteOutcome : std::uint8_t
{
    Pending,
    Confirmed,
    Rejected,
};

class McsChannelJoinWriteGate final
{
public:
    McsChannelJoinWriteGate() noexcept = default;
    McsChannelJoinWriteGate(const McsChannelJoinWriteGate &) = delete;
    McsChannelJoinWriteGate &operator=(const McsChannelJoinWriteGate &) = delete;

    // Caller-supplied IDs are a bounded configuration snapshot, NOT proof
    // of negotiation, genuine authentication or OS session authorization.
    // The sole authorized owner must configure exactly once after attachment.
    [[nodiscard]] bool configure(
        std::uint32_t assignedUserId,
        std::span<const std::uint16_t> assignedChannels) noexcept
    {
        if (configured_ || closed_ || assignedUserId < 1001U ||
            assignedUserId > 65536U || assignedChannels.empty() ||
            assignedChannels.size() > assignedChannelIds_.size())
        {
            close();
            return false;
        }
        for (std::size_t index = 0; index < assignedChannels.size(); ++index)
        {
            if (assignedChannels[index] == 0)
            {
                close();
                return false;
            }
            for (std::size_t previous = 0; previous < index; ++previous)
            {
                if (assignedChannels[previous] == assignedChannels[index])
                {
                    close();
                    return false;
                }
            }
        }
        assignedUserId_ = assignedUserId;
        channelCount_ = assignedChannels.size();
        for (std::size_t index = 0; index < channelCount_; ++index)
            assignedChannelIds_[index] = assignedChannels[index];
        configured_ = true;
        return true;
    }

    // Call for validated post-attach requests in arrival order. Some
    // Microsoft clients batch every ChannelJoinRequest before receiving
    // the first confirmation. Queue only distinct, assigned channel IDs in
    // this SAME bounded gate, never an unbounded borrowed input span.
    // A single outbound writer still owns all actual TLS write progress.
    [[nodiscard]] McsJoinStartOutcome beginJoin(const McsChannelRequest &request) noexcept
    {
        if (!configured_ || closed_ ||
            request.kind != McsChannelRequestKind::ChannelJoin ||
            request.initiator != assignedUserId_ ||
            request.subHeight != 0 || request.subInterval != 0 ||
            request.channelId == 0)
        {
            close();
            return McsJoinStartOutcome::Rejected;
        }
        for (std::size_t index = 0; index < channelCount_; ++index)
        {
            if (assignedChannelIds_[index] != request.channelId)
                continue;
            // Already-joined channels never receive a second confirmation.
            if (confirmedChannels_[index])
                return McsJoinStartOutcome::AlreadyJoined;
            if (pendingConfirm_.length != 0 && pendingAssignedIndex_ == index)
                return McsJoinStartOutcome::AlreadyPending;
            for (std::size_t queued = 0; queued < queuedCount_; ++queued)
            {
                if (queuedAssignedIndices_[queued] == index)
                    return McsJoinStartOutcome::AlreadyPending;
            }
            const auto response = encodeMcsChannelJoinConfirm(
                request, assignedUserId_,
                std::span(assignedChannelIds_).first(channelCount_));
            if (!response)
                break;
            if (pendingConfirm_.length == 0)
            {
                // Each complete reply owns one stable write receipt. A stale
                // callback must never advance a different queued reply.
                if (!advanceReplySequence() || !advanceWriteSliceSequence())
                {
                    close();
                    return McsJoinStartOutcome::Rejected;
                }
                pendingConfirm_ = response;
                pendingAssignedIndex_ = index;
                return McsJoinStartOutcome::ReplyPending;
            }
            // Every allocated channel can appear at most once in the
            // pending reply plus this queue. Saturation is terminal.
            if (queuedCount_ == queuedAssignedIndices_.size())
                break;
            queuedAssignedIndices_[queuedCount_++] = index;
            return McsJoinStartOutcome::Buffered;
        }
        close();
        return McsJoinStartOutcome::Rejected;
    }

    // Only hand this suffix to the connection's existing writer.
    [[nodiscard]] std::span<const std::uint8_t> pendingBytes() const noexcept
    {
        if (!configured_ || closed_ || pendingConfirm_.length == 0)
            return {};
        return pendingConfirm_.bytes().subspan(bytesWritten_);
    }

    // The writer must snapshot this nonzero receipt together with the
    // borrowed byte suffix, not query it later from an asynchronous callback.
    // A new queued reply always gets a different receipt. Zero means none.
    [[nodiscard]] std::uint64_t pendingReplySequence() const noexcept
    {
        return configured_ && !closed_ && pendingConfirm_.length != 0
                   ? replySequence_ : 0;
    }

    // A separate nonzero slice receipt binds ONE outstanding writer call.
    // Partial progress advances it while keeping pendingReplySequence stable:
    // the same confirmation can require several distinct socket writes.
    // Snapshot both receipts with pendingBytes() at write submission time.
    // A zero-byte backpressure callback does not consume the slice receipt.
    [[nodiscard]] std::uint64_t pendingWriteSliceSequence() const noexcept
    {
        return configured_ && !closed_ && pendingConfirm_.length != 0
                   ? writeSliceSequence_ : 0;
    }

    // Report ONLY bytes actually accepted by the exact outbound adapter.
    // Zero means backpressure. Over-report, unsolicited/duplicate completion,
    // or disconnected writer irrevocably close the gate and clear membership.
    [[nodiscard]] McsJoinWriteOutcome onReplyBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept
    {
        if (!configured_ || closed_ || pendingConfirm_.length == 0 ||
            replySequence == 0 || replySequence != replySequence_ ||
            writeSliceSequence == 0 || writeSliceSequence != writeSliceSequence_ ||
            acceptedBytes > pendingConfirm_.length - bytesWritten_)
        {
            close();
            return McsJoinWriteOutcome::Rejected;
        }
        bytesWritten_ += acceptedBytes;
        if (bytesWritten_ != pendingConfirm_.length)
        {
            // Duplicate/late callbacks for the prior submitted suffix
            // cannot consume a second part of this SAME confirmation.
            if (acceptedBytes != 0 && !advanceWriteSliceSequence())
            {
                close();
                return McsJoinWriteOutcome::Rejected;
            }
            return McsJoinWriteOutcome::Pending;
        }
        confirmedChannels_[pendingAssignedIndex_] = true;
        pendingConfirm_ = {};
        pendingAssignedIndex_ = 0;
        bytesWritten_ = 0;
        // Publish exactly one next immutable reply after the previous
        // writer completion. Never interleave the two confirmation bytes.
        if (queuedCount_ != 0)
        {
            const std::size_t nextIndex = queuedAssignedIndices_[0];
            for (std::size_t index = 1; index < queuedCount_; ++index)
                queuedAssignedIndices_[index - 1] = queuedAssignedIndices_[index];
            queuedAssignedIndices_[--queuedCount_] = 0;
            if (!advanceReplySequence() || !advanceWriteSliceSequence())
            {
                close();
                return McsJoinWriteOutcome::Rejected;
            }
            McsChannelRequest nextRequest{};
            nextRequest.kind = McsChannelRequestKind::ChannelJoin;
            nextRequest.initiator = assignedUserId_;
            nextRequest.channelId = assignedChannelIds_[nextIndex];
            pendingConfirm_ = encodeMcsChannelJoinConfirm(
                nextRequest, assignedUserId_,
                std::span(assignedChannelIds_).first(channelCount_));
            if (!pendingConfirm_)
            {
                close();
                return McsJoinWriteOutcome::Rejected;
            }
            pendingAssignedIndex_ = nextIndex;
        }
        // Confirmed refers to the completed previous reply. A new
        // pendingBytes() may already be ready for the sole writer.
        return McsJoinWriteOutcome::Confirmed;
    }

    // Necessary bookkeeping only, NEVER sufficient for channel access.
    [[nodiscard]] bool channelJoinConfirmed(std::uint16_t channelId) const noexcept
    {
        if (!configured_ || closed_)
            return false;
        for (std::size_t index = 0; index < channelCount_; ++index)
        {
            if (assignedChannelIds_[index] == channelId)
                return confirmedChannels_[index];
        }
        return false;
    }

    // Connection-sequence diagnostic only: all configured UserId/I/O/static
    // channels have had their own complete confirmation bytes accepted.
    // This does not license, activate a share or authorize channel payloads.
    [[nodiscard]] bool allConfiguredChannelsJoined() const noexcept
    {
        if (!configured_ || closed_ || channelCount_ == 0U)
            return false;
        for (std::size_t index = 0; index < channelCount_; ++index)
        {
            if (!confirmedChannels_[index])
                return false;
        }
        return true;
    }

    // Membership-only check on an ALREADY parsed, complete client MCS
    // SendDataRequest. This never retains borrowed userData, decrypts TLS,
    // reassembles PER segmentation, licenses/activates a share, or permits
    // OS/session data dispatch. The sole R3 session owner must enforce those
    // independent gates even when this predicate returns true.
    [[nodiscard]] bool matchesJoinedInboundSendData(
        const McsChannelRequest &request) const noexcept
    {
        return configured_ && !closed_ &&
               request.kind == McsChannelRequestKind::SendDataRequest &&
               request.initiator == assignedUserId_ &&
               request.channelId != 0 &&
               request.subHeight == 0 && request.subInterval == 0 &&
               request.dataPriority <= 3 && request.segmentation <= 3 &&
               channelJoinConfirmed(request.channelId);
    }

    // Membership-only outbound envelope construction. The eventual R3
    // owner MUST separately verify TLS-bound R2 admission, OS permission,
    // license, negotiated channel role and session stage before emission.
    [[nodiscard]] std::optional<std::size_t> encodeJoinedSendDataIndication(
        std::uint16_t channelId, std::uint8_t dataPriority,
        std::uint8_t segmentation, std::span<const std::uint8_t> userData,
        std::span<std::uint8_t> output) const noexcept;

    // TLS error, authentication revocation, protocol violation, timeout,
    // disconnect and reconnect all require a fresh session-owned gate.
    void close() noexcept
    {
        closed_ = true;
        configured_ = false;
        assignedUserId_ = 0;
        channelCount_ = 0;
        assignedChannelIds_.fill(0);
        confirmedChannels_.fill(false);
        queuedAssignedIndices_.fill(0);
        queuedCount_ = 0;
        pendingConfirm_ = {};
        pendingAssignedIndex_ = 0;
        bytesWritten_ = 0;
    }

private:
    // No reply generation can alias an earlier completion in this gate.
    // Overflow is terminal rather than reusing zero or a prior receipt.
    [[nodiscard]] bool advanceReplySequence() noexcept
    {
        if (replySequence_ == UINT64_MAX)
            return false;
        ++replySequence_;
        return true;
    }

    // Both counters remain monotonic for the lifetime of this gate, even
    // through close(). Exhaustion is terminal (no token reuse).
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept
    {
        if (writeSliceSequence_ == UINT64_MAX)
            return false;
        ++writeSliceSequence_;
        return true;
    }

    std::uint64_t writeSliceSequence_{};
    std::uint64_t replySequence_{};
    std::array<std::uint16_t, kMaximumStaticChannelCount + 2U>
        assignedChannelIds_{};
    std::array<bool, kMaximumStaticChannelCount + 2U> confirmedChannels_{};
    std::array<std::size_t, kMaximumStaticChannelCount + 2U>
        queuedAssignedIndices_{};
    std::size_t queuedCount_{};
    McsChannelConfirm pendingConfirm_{};
    std::uint32_t assignedUserId_{};
    std::size_t channelCount_{};
    std::size_t pendingAssignedIndex_{};
    std::size_t bytesWritten_{};
    bool configured_{};
    bool closed_{};
};

// R3 is the sole MCS session owner. The public Connect-Initial entry remains
// denial-only: syntax, a caller Boolean, a user ID or candidate identity cannot
// unlock protected MCS state. Linux positive admission enters only through the
// concrete R2 LinuxConsoleAdmissionBroker friend after its native lease has
// been revalidated against the exact TLS/GSS identity, policy and logind state.
//
// The first positive transition deliberately stops before any outbound bytes:
// an admitted, validated Connect Initial advances to AwaitConnectResponse.
// Every later protected transition must be re-authorized against the same R2
// admission/session generations before state or writer progress changes.
// A second envelope, wrong-order domain PDU, revocation or teardown closes the
// same owner; reconnect constructs a fresh instance. No second MCS controller.
inline constexpr std::size_t
    kRdpPersonalDesktopValidClientPacketBytes = 34U;
inline constexpr std::size_t kMaximumRdpShareActivationPduBytes = 4096U;
inline constexpr std::size_t kMaximumRdpShareActivationPacketBytes =
    kMaximumRdpShareActivationPduBytes + 15U;

struct RdpPersonalDesktopValidClientWriteView
{
    std::span<const std::uint8_t> bytes{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !bytes.empty() && replySequence != 0U &&
               writeSliceSequence != 0U;
    }
};

enum class RdpPersonalDesktopValidClientWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

// Owns the complete Enhanced-Security Valid Client packet:
// TPKT/X.224/MCS SDin + Basic Security Header + 16-byte ERROR_ALERT.
// It is protocol mechanics only. The live McsSessionLifecycle exposes it
// solely after its private R2-authorized personal-policy selection.
class RdpPersonalDesktopValidClientWriteGate final
{
public:
    explicit RdpPersonalDesktopValidClientWriteGate(
        RdpLicensingLifecycle &licensing) noexcept
        : licensing_(&licensing)
    {
    }
    RdpPersonalDesktopValidClientWriteGate(
        const RdpPersonalDesktopValidClientWriteGate &) = delete;
    RdpPersonalDesktopValidClientWriteGate &operator=(
        const RdpPersonalDesktopValidClientWriteGate &) = delete;

    [[nodiscard]] bool queue(std::uint16_t ioChannelId) noexcept;
    [[nodiscard]] RdpPersonalDesktopValidClientWriteView
    pendingWrite() const noexcept;
    [[nodiscard]] RdpPersonalDesktopValidClientWriteOutcome onBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;

private:
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;

    std::array<std::uint8_t, kRdpPersonalDesktopValidClientPacketBytes>
        pending_{};
    RdpLicensingLifecycle *licensing_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool queued_{};
    bool delivered_{};
    bool closed_{};
};

enum class RdpShareActivationPhase : std::uint8_t
{
    NotStarted,
    DemandActivePending,
    AwaitConfirmActive,
    Finalizing,
    Activated,
    Failed,
    Closed,
};

enum class RdpShareServerWriteKind : std::uint8_t
{
    None,
    DemandActive,
    Synchronize,
    Cooperate,
    GrantedControl,
    FontMap,
};

struct RdpShareActivationWriteView
{
    std::span<const std::uint8_t> bytes{};
    RdpShareServerWriteKind kind{RdpShareServerWriteKind::None};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !bytes.empty() && kind != RdpShareServerWriteKind::None &&
               replySequence != 0U && writeSliceSequence != 0U;
    }
};

enum class RdpShareActivationWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Activated,
    Rejected,
};

enum class RdpShareActivationClientIntake : std::uint8_t
{
    ConfirmActiveAccepted,
    SynchronizeAccepted,
    CooperateAccepted,
    RequestControlAccepted,
    FontListAccepted,
    // MS-RDPBCGR permits input after Confirm Active. R3 validates these
    // packets against negotiated Input capability state but intentionally
    // discards them until Share/native activation is complete.
    InputIgnoredUntilActivated,
    Rejected,
    Closed,
};

inline constexpr std::size_t kRdpStaticVirtualChannelDefaultChunkBytes = 1600U;
inline constexpr std::size_t kRdpStaticVirtualChannelMaximumChunkBytes = 16256U;
// One unfragmented MCS SendData payload is bounded to 16383 bytes. Keep the
// Confirm Active capability store contiguous and owned by R3 so R10 may
// immediately recycle its TPKT framing buffer after synchronous intake.
inline constexpr std::size_t kMaximumRdpClientCapabilityBytes = 16383U;

// Serialized, allocation-free Share activation transcript owner. It owns no
// R2 authority; the live R3 session invokes it only after licensing completes.
// Client ingress is exact MCS I/O-channel SendDataRequest framing. Server
// output is complete MCS SendDataIndication packets with receipt-bound slices.
class RdpShareActivationLifecycle final
{
public:
    RdpShareActivationLifecycle() noexcept = default;
    RdpShareActivationLifecycle(const RdpShareActivationLifecycle &) = delete;
    RdpShareActivationLifecycle &operator=(
        const RdpShareActivationLifecycle &) = delete;

    [[nodiscard]] RdpShareActivationPhase phase() const noexcept
    {
        return phase_;
    }
    [[nodiscard]] bool activated() const noexcept
    {
        return phase_ == RdpShareActivationPhase::Activated;
    }
    [[nodiscard]] bool matchesActivatedClientShare(
        std::uint32_t shareId, std::uint16_t pduSource) const noexcept
    {
        return activated() && shareId_ != 0U && clientUserId_ != 0U &&
               shareId == shareId_ && pduSource == clientUserId_;
    }
    [[nodiscard]] std::size_t
    serverToClientVirtualChannelChunkBytes() const noexcept
    {
        return activated()
                   ? negotiatedVirtualChannelChunkBytes_
                   : 0U;
    }
    // Immutable observations of the exact capability bytes accepted from the
    // client's Confirm Active PDU. They are protocol state, not authorization.
    [[nodiscard]] std::span<const std::uint8_t>
    confirmedClientCapabilitySets() const noexcept
    {
        return clientCapabilitiesConfirmed_
                   ? std::span<const std::uint8_t>{clientCapabilitySets_}.first(
                         clientCapabilityBytes_)
                   : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] std::uint16_t
    confirmedClientCapabilityCount() const noexcept
    {
        return clientCapabilitiesConfirmed_ ? clientCapabilityCount_ : 0U;
    }
    [[nodiscard]] std::uint16_t
    negotiatedSlowPathInputFlags() const noexcept
    {
        return clientCapabilitiesConfirmed_
                   ? negotiatedSlowPathInputFlags_
                   : 0U;
    }
    [[nodiscard]] bool begin(
        std::uint32_t clientUserId,
        std::uint16_t ioChannelId,
        std::uint32_t shareId,
        std::uint32_t sessionId,
        std::span<const std::uint8_t> sourceDescriptor,
        std::uint16_t capabilityCount,
        std::span<const std::uint8_t> capabilitySets) noexcept;
    [[nodiscard]] RdpShareActivationWriteView
    pendingServerWrite() const noexcept;
    [[nodiscard]] RdpShareActivationWriteOutcome onServerBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] RdpShareActivationClientIntake onClientTpkt(
        std::span<const std::uint8_t> completeTpkt) noexcept;
    void close() noexcept;

private:
    enum class ClientStage : std::uint8_t
    {
        ConfirmActive,
        Synchronize,
        Cooperate,
        RequestControl,
        FontList,
        Complete,
    };

    [[nodiscard]] bool queueSharePdu(
        RdpShareServerWriteKind kind,
        std::span<const std::uint8_t> sharePdu) noexcept;
    [[nodiscard]] bool queueSynchronize() noexcept;
    [[nodiscard]] bool queueCooperate() noexcept;
    [[nodiscard]] bool queueGrantedControl() noexcept;
    [[nodiscard]] bool queueFontMap() noexcept;
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;
    void fail() noexcept;

    std::array<std::uint8_t, kMaximumRdpShareActivationPduBytes>
        demandSharePdu_{};
    std::array<std::uint8_t, kMaximumRdpShareActivationPacketBytes>
        pending_{};
    std::array<std::uint8_t, kMaximumRdpClientCapabilityBytes>
        clientCapabilitySets_{};
    std::size_t demandShareLength_{};
    std::size_t pendingLength_{};
    std::size_t bytesWritten_{};
    std::size_t clientCapabilityBytes_{};
    std::uint32_t clientUserId_{};
    std::uint16_t ioChannelId_{};
    std::uint32_t shareId_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    std::uint16_t clientCapabilityCount_{};
    std::uint16_t serverSlowPathInputFlags_{};
    std::uint16_t clientSlowPathInputFlags_{};
    std::uint16_t negotiatedSlowPathInputFlags_{};
    RdpShareActivationPhase phase_{RdpShareActivationPhase::NotStarted};
    RdpShareServerWriteKind pendingKind_{RdpShareServerWriteKind::None};
    ClientStage clientStage_{ClientStage::ConfirmActive};
    bool demandDelivered_{};
    bool serverSynchronizeDelivered_{};
    bool serverCooperateDelivered_{};
    bool clientRequestControlSeen_{};
    bool serverGrantedControlDelivered_{};
    bool clientFontListSeen_{};
    std::size_t serverVirtualChannelChunkBytes_{
        kRdpStaticVirtualChannelDefaultChunkBytes};
    std::size_t negotiatedVirtualChannelChunkBytes_{
        kRdpStaticVirtualChannelDefaultChunkBytes};
    bool serverVirtualChannelChunkFieldPresent_{};
    bool clientCapabilitiesConfirmed_{};
};

// One allocation domain for all dynamic virtual channels on this static
// drdynvc connection. Allocation is protocol identity/freshness only and
// never admission. IDs/generations are monotonic and never reused by this
// owner, which lets future R8 DVCs share the same R3 allocation source.
struct RdpDynamicVirtualChannelAllocation
{
    std::uint32_t channelId{};
    std::uint64_t generation{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return channelId != 0U && generation != 0U;
    }
};

class RdpDynamicVirtualChannelAllocator final
{
public:
    [[nodiscard]] std::optional<RdpDynamicVirtualChannelAllocation>
    allocate() noexcept;
    void close() noexcept
    {
        nextChannelId_ = 0U;
        nextGeneration_ = 0U;
        closed_ = true;
    }

private:
    std::uint32_t nextChannelId_{1U};
    std::uint64_t nextGeneration_{1U};
    bool closed_{};
};

inline constexpr std::string_view kRdpGraphicsDynamicVirtualChannelName =
    "Microsoft::Windows::RDS::Graphics";
inline constexpr std::size_t kMaximumRdpDynamicVirtualChannelControlPacketBytes =
    96U;
// MS-RDPBCGR CHANNEL_CHUNK_LENGTH and the optional server-advertised
// VCChunkSize bound the static virtual-channel payload. An extended server
// value is negotiated only when both endpoints include the optional field;
// the client's numeric value is not a server-to-client size authority.
// MS-RDPEDYC further bounds each uncompressed DVC DATA/DATA_FIRST block to
// 1,600 bytes including its DVC header, so a 1,590-byte application slice
// always fits the default static-channel chunk.
inline constexpr std::size_t kMaximumRdpDynamicVirtualChannelDataPayloadBytes =
    1590U;
inline constexpr std::size_t kMaximumRdpGraphicsDvcClientMessageBytes =
    1024U * 1024U;
inline constexpr std::size_t kMaximumRdpDynamicVirtualChannelPacketBytes =
    1632U;

enum class RdpGraphicsDvcPhase : std::uint8_t
{
    NotStarted,
    CapabilitiesRequestPending,
    AwaitCapabilitiesResponse,
    CreateRequestPending,
    AwaitCreateResponse,
    Created,
    GraphicsCapabilitiesConfirmPending,
    GraphicsCreateSurfacePending,
    GraphicsMapSurfacePending,
    Ready,
    Failed,
    Closed,
};

enum class RdpGraphicsDvcWriteKind : std::uint8_t
{
    None,
    CapabilitiesRequest,
    CreateRequest,
    GraphicsCapabilitiesConfirm,
    GraphicsCreateSurface,
    GraphicsMapSurfaceToOutput,
    GraphicsFrameData,
};

struct RdpGraphicsDvcWriteView
{
    std::span<const std::uint8_t> bytes{};
    RdpGraphicsDvcWriteKind kind{RdpGraphicsDvcWriteKind::None};
    std::uint64_t channelGeneration{};
    std::uint32_t dynamicChannelId{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !bytes.empty() &&
               kind != RdpGraphicsDvcWriteKind::None &&
               channelGeneration != 0U && dynamicChannelId != 0U &&
               replySequence != 0U && writeSliceSequence != 0U;
    }
};

enum class RdpGraphicsDvcWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

enum class RdpGraphicsDvcClientIntake : std::uint8_t
{
    CapabilitiesAccepted,
    CreateAccepted,
    CreateRejected,
    GraphicsCapabilitiesAccepted,
    GraphicsDataFragmentAccepted,
    GraphicsDataAccepted,
    Rejected,
    Closed,
};

enum class RdpGraphicsFrameCodec : std::uint8_t
{
    ClearCodec,
    Avc420,
};

struct RdpGraphicsDvcOuterRecordMapEntry
{
    std::size_t frameOffset{};
    std::size_t frameBytes{};
    std::size_t tpktHeaderBytes{};
    std::size_t x224HeaderBytes{};
    std::size_t mcsHeaderBytes{};
    std::size_t staticChannelHeaderBytes{};
    std::size_t dvcHeaderBytes{};
    std::size_t outerPlaintextBytes{};
    bool dataFirst{};
};


// Allocation-free MS-RDPEDYC v1 server-manager lifecycle for exactly the
// RDPGFX listener. This class proves protocol mechanics only: a joined
// drdynvc static channel, a successful CREATE response, or matching
// generations do not authenticate a connection or authorize graphics.
// The live McsSessionLifecycle invokes it only through its private post-Share
// R2 boundary.
class RdpGraphicsDynamicVirtualChannelLifecycle final
{
public:
    RdpGraphicsDynamicVirtualChannelLifecycle() noexcept = default;
    RdpGraphicsDynamicVirtualChannelLifecycle(
        const RdpGraphicsDynamicVirtualChannelLifecycle &) = delete;
    RdpGraphicsDynamicVirtualChannelLifecycle &operator=(
        const RdpGraphicsDynamicVirtualChannelLifecycle &) = delete;

    [[nodiscard]] bool begin(
        std::uint32_t clientUserId,
        std::uint16_t staticChannelId,
        RdpDynamicVirtualChannelAllocation allocation,
        rdp_server::rdp::PixelSize desktopGeometry) noexcept;
    [[nodiscard]] RdpGraphicsDvcWriteView pendingServerWrite() const noexcept;
    [[nodiscard]] RdpGraphicsDvcWriteOutcome onServerBytesWritten(
        std::uint64_t channelGeneration,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] RdpGraphicsDvcClientIntake onClientTpkt(
        std::uint64_t channelGeneration,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Prepare the mandatory ClearCodec fallback only against this R3-owned
    // mapped presentation. The caller supplies pixels/frame ID, never a
    // graphics generation or surface ID.
    [[nodiscard]] bool prepareClearCodecFrame(
        std::uint32_t frameId,
        rdp_server::rdp::FramebufferView framebuffer,
        rdp_server::rdp::GfxAvc420SegmentedFrame &output) noexcept;
    [[nodiscard]] bool beginFramePublication(
        rdp_server::rdp::GfxAvc420SegmentedFrame &&frame,
        RdpGraphicsFrameCodec codec,
        std::size_t staticChannelChunkBytes) noexcept;
    [[nodiscard]] std::span<const RdpGraphicsDvcOuterRecordMapEntry>
    frameRecordMap() const noexcept
    {
        return frameRecordMap_;
    }
    [[nodiscard]] std::span<const std::uint8_t>
    pendingClientGraphicsData() const noexcept
    {
        return clientGraphicsDataReady_
                   ? std::span<const std::uint8_t>{clientDvcMessage_}
                   : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] bool consumeClientGraphicsData(
        std::uint64_t channelGeneration) noexcept;
    [[nodiscard]] bool cancelUnwrittenFramePublication(
        std::uint64_t channelGeneration) noexcept;
    [[nodiscard]] bool abortFramePublication(
        std::uint64_t channelGeneration) noexcept;

    void revokeUnlessChannelGenerationMatches(
        std::uint64_t channelGeneration) noexcept;
    void close() noexcept;

    [[nodiscard]] RdpGraphicsDvcPhase phase() const noexcept
    {
        return phase_;
    }
    [[nodiscard]] bool created() const noexcept
    {
        return phase_ == RdpGraphicsDvcPhase::Created ||
               phase_ ==
                   RdpGraphicsDvcPhase::GraphicsCapabilitiesConfirmPending ||
               phase_ == RdpGraphicsDvcPhase::GraphicsCreateSurfacePending ||
               phase_ == RdpGraphicsDvcPhase::GraphicsMapSurfacePending ||
               phase_ == RdpGraphicsDvcPhase::Ready;
    }
    [[nodiscard]] std::uint32_t dynamicChannelId() const noexcept
    {
        return allocation_.channelId;
    }
    [[nodiscard]] std::uint64_t channelGeneration() const noexcept
    {
        return allocation_.generation;
    }
    [[nodiscard]] std::uint16_t negotiatedVersion() const noexcept
    {
        return negotiatedVersion_;
    }
    // Codec capability values become consumable only after CAPS_CONFIRM has
    // been completely accepted by the existing writer. This prevents x264
    // activation from racing a short or canceled confirmation write.
    [[nodiscard]] bool graphicsCapabilitiesConfirmed() const noexcept
    {
        return graphicsCapabilitiesConfirmed_;
    }
    [[nodiscard]] std::uint32_t
    confirmedGraphicsCapabilityVersion() const noexcept
    {
        return graphicsCapabilitiesConfirmed()
                   ? selectedGraphicsCapabilityVersion_
                   : 0U;
    }
    [[nodiscard]] std::uint32_t
    confirmedGraphicsCapabilityFlags() const noexcept
    {
        return graphicsCapabilitiesConfirmed()
                   ? selectedGraphicsCapabilityFlags_
                   : 0U;
    }
    [[nodiscard]] bool graphicsClearCodecEnabled() const noexcept
    {
        // R4 accepts only profiles for which mandatory ClearCodec exists.
        return graphicsCapabilitiesConfirmed();
    }
    [[nodiscard]] bool graphicsAvc420Enabled() const noexcept
    {
        return graphicsCapabilitiesConfirmed() &&
               selectedGraphicsAvc420Enabled_;
    }
    [[nodiscard]] bool presentationMapped() const noexcept
    {
        return phase_ == RdpGraphicsDvcPhase::Ready &&
               presentationLifecycle_.stage() ==
                   rdp_server::rdp::GfxPresentationStage::Mapped;
    }
    [[nodiscard]] std::size_t outstandingGraphicsFrames() const noexcept
    {
        return presentationMapped()
                   ? presentationLifecycle_.outstandingFrames()
                   : 0U;
    }

private:
    [[nodiscard]] bool queueCapabilitiesRequest() noexcept;
    [[nodiscard]] bool queueCreateRequest() noexcept;
    [[nodiscard]] bool queueGraphicsApplicationPdu(
        RdpGraphicsDvcWriteKind kind,
        std::span<const std::byte> graphicsPdu) noexcept;
    [[nodiscard]] bool queuePresentationCommand(
        rdp_server::rdp::GfxPresentationCommand expectedCommand,
        RdpGraphicsDvcWriteKind kind) noexcept;
    [[nodiscard]] bool queueControlPdu(
        RdpGraphicsDvcWriteKind kind,
        std::span<const std::uint8_t> dvcPdu) noexcept;
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;
    [[nodiscard]] bool buildFrameRecordMap(
        std::span<const std::byte> frameBytes,
        std::size_t staticChannelChunkBytes) noexcept;
    [[nodiscard]] bool queueFrameRecord() noexcept;
    [[nodiscard]] bool acceptClientDvcData(
        std::span<const std::uint8_t> dvcPdu,
        std::span<const std::uint8_t> &completeMessage) noexcept;
    void clearClientDvcReassembly() noexcept;
    void clearFramePublication() noexcept;
    void abortActiveFramePublication() noexcept;
    void fail() noexcept;

    std::array<std::uint8_t,
               kMaximumRdpDynamicVirtualChannelPacketBytes>
        pending_{};
    std::size_t pendingLength_{};
    std::size_t bytesWritten_{};
    std::uint32_t clientUserId_{};
    std::uint16_t staticChannelId_{};
    RdpDynamicVirtualChannelAllocation allocation_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    std::uint16_t negotiatedVersion_{};
    std::uint32_t selectedGraphicsCapabilityVersion_{};
    std::uint32_t selectedGraphicsCapabilityFlags_{};
    bool selectedGraphicsAvc420Enabled_{};
    bool graphicsCapabilitiesConfirmed_{};
    rdp_server::rdp::PixelSize presentationGeometry_{};
    rdp_server::rdp::GfxPresentationLifecycle presentationLifecycle_{};
    rdp_server::rdp::GfxPresentationReceipt presentationReceipt_{};
    std::optional<rdp_server::rdp::GfxAvc420SegmentedFrame> frame_{};
    std::vector<RdpGraphicsDvcOuterRecordMapEntry> frameRecordMap_{};
    std::size_t frameRecordIndex_{};
    std::size_t framePayloadAcceptedBytes_{};
    std::size_t frameOuterAcceptedBytes_{};
    std::vector<std::uint8_t> clientDvcMessage_{};
    std::size_t clientDvcExpectedBytes_{};
    bool clientDvcFragmented_{};
    bool clientGraphicsDataReady_{};
    RdpGraphicsDvcPhase phase_{RdpGraphicsDvcPhase::NotStarted};
    RdpGraphicsDvcWriteKind pendingKind_{RdpGraphicsDvcWriteKind::None};
};

enum class McsSessionPhase : std::uint8_t
{
    AwaitVerifiedR2Admission,
    AwaitConnectResponse,
    AwaitErectDomain,
    AwaitAttachUser,
    AwaitAttachConfirm,
    AwaitChannelJoin,
    AwaitServerLicenseRequest,
    AwaitClientLicenseResponse,
    AwaitServerLicenseDecision,
    AwaitClientPlatformChallengeResponse,
    AwaitPersonalDesktopValidClientWrite,
    AwaitDemandActive,
    ShareActivation,
    ShareActivated,
    Closed,
};

enum class McsSessionIntake : std::uint8_t
{
    ValidButNotAdmitted,
    AdmittedConnectInitial,
    ErectDomainAccepted,
    AttachUserAccepted,
    AdmissionDenied,
    InvalidOrdering,
    PeerDisconnected,
    InvalidEnvelope,
    OversizedEnvelope,
    Closed,
    InvalidDomainParameters,
    InvalidGccUserData,
    InvalidResourceAllocation,
    InvalidDomainTransport,
    InvalidDomainPdu,
    InvalidDomainPerValue,
};

// MS-RDPBCGR 2.2.8.1.1.3.1 slow-path TS_INPUT_PDU_DATA. Every
// TS_INPUT_EVENT occupies exactly 12 bytes (eventTime, messageType and
// six event-specific bytes). The outer MCS PER payload is at most 16383
// bytes, so a count-derived exact-length check bounds iteration without
// allocation. These values are decoded protocol data only: no event, flag,
// coordinate, count, generation or callback grants native input authority.
inline constexpr std::size_t kRdpSlowPathInputEventBytes = 12U;
inline constexpr std::size_t kMaximumRdpSlowPathInputPduBytes = 16383U;
inline constexpr std::size_t kMaximumRdpSlowPathInputEvents =
    (kMaximumRdpSlowPathInputPduBytes - 22U) /
    kRdpSlowPathInputEventBytes;

enum class RdpSlowPathInputEventKind : std::uint8_t
{
    Synchronize,
    Unused,
    ScancodeKeyboard,
    UnicodeKeyboard,
    Mouse,
    ExtendedMouse,
    RelativeMouse,
};

struct RdpSlowPathInputEvent
{
    RdpSlowPathInputEventKind kind{RdpSlowPathInputEventKind::Unused};
    std::uint32_t eventTime{};
    std::uint16_t keyboardFlags{};
    std::uint16_t keyCode{};
    std::uint16_t unicodeCode{};
    std::uint16_t pointerFlags{};
    std::uint16_t xPos{};
    std::uint16_t yPos{};
    std::int32_t xDelta{};
    std::int32_t yDelta{};
    std::uint32_t toggleFlags{};
};

struct RdpSlowPathInputPdu
{
    std::uint16_t pduSource{};
    std::uint32_t shareId{};
    std::uint16_t eventCount{};
    // Borrowed exact event bytes after numEvents/pad2Octets.
    std::span<const std::uint8_t> eventBytes{};

    [[nodiscard]] bool eventAt(
        std::size_t index, RdpSlowPathInputEvent &event) const noexcept;
};

enum class RdpSlowPathInputError : std::uint8_t
{
    None,
    InvalidShareData,
    WrongDataPduType,
    InvalidBodyLength,
    TooManyEvents,
    UnknownEventType,
};

struct RdpSlowPathInputParseResult
{
    RdpSlowPathInputPdu value{};
    RdpSlowPathInputError error{RdpSlowPathInputError::InvalidShareData};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpSlowPathInputError::None;
    }
};

[[nodiscard]] RdpSlowPathInputParseResult parseRdpSlowPathInputPdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// Synchronous destination supplied by the sole runtime owner. R2 invokes it
// only after fresh concrete input authorization immediately before EACH
// event. The callback is deliberately not an authorization token.
struct RdpSlowPathInputEventSink
{
    void *context{};
    bool (*dispatch)(
        void *, const RdpSlowPathInputEvent &) noexcept{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context != nullptr && dispatch != nullptr;
    }
};


// R8 callbacks borrow only a validated PDU or an ephemeral route observation.
// No callback or caller-owned Boolean serves as an authentication capability.
struct RdpClipboardCompletePduSink
{
    void *context{};
    bool (*consume)(void *, std::span<const std::uint8_t>) noexcept{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context != nullptr && consume != nullptr;
    }
};

struct RdpClipboardChannelVisitor
{
    void *context{};
    bool (*visit)(void *, RdpClipboardStaticChannelView) noexcept{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context != nullptr && visit != nullptr;
    }
};

class McsSessionLifecycle final
{
public:
    McsSessionLifecycle() noexcept = default;
    ~McsSessionLifecycle();
    McsSessionLifecycle(const McsSessionLifecycle &) = delete;
    McsSessionLifecycle &operator=(const McsSessionLifecycle &) = delete;
    McsSessionLifecycle(McsSessionLifecycle &&) = delete;
    McsSessionLifecycle &operator=(McsSessionLifecycle &&) = delete;

    [[nodiscard]] McsSessionPhase phase() const noexcept { return phase_; }
    [[nodiscard]] RdpLicensingPhase licensingPhase() const noexcept
    {
        return licensing_.phase();
    }
    // Diagnostic allocation only: not an admitted user/channel permission.
    [[nodiscard]] std::uint32_t allocatedUserId() const noexcept
    { return allocatedUserId_; }
    [[nodiscard]] std::uint32_t allocatedGccNodeId() const noexcept
    { return connectResponseAllocation_ ? connectResponseAllocation_.gccNodeId : 0U; }
    [[nodiscard]] std::uint16_t allocatedIoChannelId() const noexcept
    { return connectResponseAllocation_ ? connectResponseAllocation_.ioChannelId : 0U; }
    [[nodiscard]] std::span<const std::uint16_t> allocatedStaticChannelIds() const noexcept
    {
        return connectResponseAllocation_ ? connectResponseAllocation_.staticChannels()
                                          : std::span<const std::uint16_t>{};
    }

    // Denial-only diagnostic entry. Exactly one *already decrypted* complete
    // MCS Connect-Initial TPKT from R1 is validated, but this public method can
    // NEVER produce admission or advance toward a Connect Response.
    [[nodiscard]] McsSessionIntake onConnectInitial(
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Any Erect, Attach, Join or SendData PDU before admission, or before the
    // admitted Connect Response has been completely delivered, is terminal.
    // A valid peer Disconnect remains acknowledged as teardown in either
    // open phase, including while the admitted Connect Response is pending.
    [[nodiscard]] McsSessionIntake onDomainPdu(
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Revocation-only generation fence for R2. Caller-supplied scalar values
    // can only leave a genuinely admitted matching owner unchanged or close
    // it; they can never advance a phase, create admission, or authorize I/O.
    // R2 invokes this immediately before each later protected transition.
    void revokeUnlessAdmissionBindingMatches(
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept;

    // Revocation-only hook for a cancelled R10 existing-CAL validation
    // request. Exact correlation and the live R2 generation pair must match
    // the active snapshot; either exact cancellation or any mismatch closes
    // the R3 owner. No caller can use cancellation to advance licensing.
    void cancelExistingClientCalAuthorityRequest(
        std::span<const std::uint8_t> requestCorrelation) noexcept
    {
        const bool retired = existingCalAuthorityRequest_.retireRequest(
            requestCorrelation, admissionGeneration_, sessionGeneration_);
        close();
        (void)retired;
    }

    // One synchronous read-only inspection of the live existing-CAL request.
    // The caller must not retain any borrowed reference/span or reenter the
    // serialized R3 owner. The callback has no authority to grant a license,
    // advance Share, or publish a channel. R3 owns all request bytes.
    using ExistingCalRequestVisitor = void (*)(
        const RdpExistingClientCalAuthorityRequest &, void *) noexcept;

    [[nodiscard]] bool visitExistingClientCalAuthorityRequest(
        ExistingCalRequestVisitor visitor, void *context) const noexcept
    {
        if (visitor == nullptr ||
            phase_ != McsSessionPhase::AwaitServerLicenseDecision ||
            acceptedInitialLicensingIntake_ !=
                RdpLicensingIntake::ClientLicenseInfoAccepted ||
            licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
            !existingCalAuthorityRequest_.active() ||
            !existingCalAuthorityRequest_.productIdentityBound() ||
            admissionGeneration_ == 0 || sessionGeneration_ == 0 ||
            !existingCalAuthorityRequest_.matchesRequest(
                existingCalAuthorityRequest_.requestCorrelation(),
                admissionGeneration_, sessionGeneration_))
            return false;
        visitor(existingCalAuthorityRequest_, context);
        return true;
    }

    [[nodiscard]] bool channelJoinConfirmed(
        std::uint16_t channelId) const noexcept
    {
        return joins_.channelJoinConfirmed(channelId);
    }
    [[nodiscard]] std::span<const std::uint8_t>
    pendingJoinConfirmation() const noexcept
    {
        return joins_.pendingBytes();
    }

    void close() noexcept
    {
        admissionGeneration_ = 0;
        sessionGeneration_ = 0;
        connectResponseDomain_ = {};
        connectResponseClientSettings_ = {};
        connectResponseAllocation_ = {};
        allocatedUserId_ = 0;
        attachConfirmWrite_.close();
        connectResponseBoundProvenance_ = {};
        connectResponseProvenanceBound_ = false;
        connectResponseWrite_.close();
        serverLicenseRequestWrite_.close();
        serverPlatformChallengeWrite_.close();
        personalDesktopValidClientWrite_.close();
        demandActiveProfileProvider_.close();
        shareActivation_.close();
        clipboardStaticChannel_.close();
        graphicsDynamicVirtualChannel_.close();
        dynamicVirtualChannels_.close();
        licensingCredentialFingerprint_.fill(0U);
        licensingCredentialBound_ = false;
        cleanseRdpLicensingKeyMaterial(licensingKeyMaterial_);
        licensingKeyMaterialReady_ = false;
        acceptedInitialLicensingIntake_.reset();
        existingCalAuthorityRequest_.retire();
        personalDesktopPolicySelected_ = false;
        licensing_.close();
        joins_.close();
        phase_ = McsSessionPhase::Closed;
    }

private:
    friend class rdp_server::server::security::LinuxConsoleAdmissionBroker;
    friend class McsSessionLifecycleTestAccess;

    // Private positive R2 -> R3 handoff. Only the concrete Linux broker can
    // call this immediately after authorizes(kConsoleViewPermission) succeeds.
    // The generation pair is bound into this R3 owner for all later checks.
    [[nodiscard]] McsSessionIntake onVerifiedR2ConnectInitial(
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<McsConnectResponseWriteView>
    prepareConnectResponseWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] McsConnectResponseWriteOutcome completeConnectResponseWrite(
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Positive Erect Domain progression is private: only the concrete R2
    // broker may invoke it after fresh generation/TLS/native authorization.
    // No reply bytes exist for this protocol step.
    [[nodiscard]] McsSessionIntake onVerifiedR2ErectDomain(
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Positive Attach intake and all outbound progress remain private to the
    // concrete broker after full R1/R2 reauthorization of each transition.
    [[nodiscard]] McsSessionIntake onVerifiedR2AttachUser(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<McsConnectResponseWriteView>
    prepareAttachUserConfirmWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] McsConnectResponseWriteOutcome completeAttachUserConfirmWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] std::optional<std::uint32_t> allocateAttachUserId() const noexcept;

    // After complete Attach confirmation, the existing bounded join gate is
    // the only channel-join writer. These private methods require a fresh
    // concrete R2 authorization before every intake, slice and completion.
    [[nodiscard]] McsJoinStartOutcome onVerifiedR2ChannelJoin(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    [[nodiscard]] std::optional<McsConnectResponseWriteView>
    prepareChannelJoinConfirmWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] McsJoinWriteOutcome completeChannelJoinConfirmWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Privately classify only an R2-revalidated, fully joined channel.
    // The result is not license/Share authorization or an input dispatcher.
    [[nodiscard]] std::optional<std::uint16_t>
    resolveVerifiedR2JoinedClipboardChannel(
        const SecurityNegotiationProvenance &provenance) noexcept;

    // First protected post-join message route. This remains a syntax-only
    // helper: it validates exact MCS/I/O/security-envelope provenance but
    // leaves TS_INFO_PACKET interpretation to the stateful acceptance below.
    [[nodiscard]] std::optional<RdpClientInfoEnvelopeView>
    routeVerifiedR2ClientInfoEnvelope(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Validate the routed TS_INFO_PACKET without exposing credentials, then
    // consume this one connection-sequence message and stop at the next
    // explicit state: a future receipt-bound Server License Request writer.
    [[nodiscard]] std::optional<RdpClientInfoPacketSummary>
    acceptVerifiedR2ClientInfoPacket(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Select the personal-desktop protocol branch only after the concrete R2
    // broker has freshly authorized the same admitted connection and R10 has
    // supplied its explicit immutable deployment policy. This is private so
    // an arbitrary Boolean/generation cannot turn an app-server session into
    // the personal branch.
    [[nodiscard]] bool
    selectVerifiedR2PersonalDesktopLicensingMode() noexcept;

    // R3 remains the sole licensing writer owner. The concrete R2 broker
    // reauthorizes the exact lease/R1 owner before every borrowed slice and
    // every accepted-byte receipt. Provisioned fields are sampled only when
    // the one stable request is first queued; later calls return its suffix.
    [[nodiscard]] std::optional<RdpServerLicenseRequestWriteView>
    prepareServerLicenseRequestWrite(
        const SecurityNegotiationProvenance &provenance,
        const RdpServerLicenseIdentity &identity,
        const RdpLicensingServiceCredential &credential) noexcept;
    [[nodiscard]] RdpServerLicenseRequestWriteOutcome
    completeServerLicenseRequestWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // First client licensing response after the request has been fully
    // delivered. The concrete R2 broker reauthorizes the same lease/R1 owner;
    // R3 proves joined global-I/O routing and SEC_LICENSE_PKT, unwraps the
    // premaster with the bound service credential, derives the session's
    // licensing keys, then invokes the bounded lifecycle. CAL/HWID/MAC
    // validation and every positive server licensing decision remain later.
    [[nodiscard]] std::optional<RdpLicensingIntake>
    acceptVerifiedR2ClientLicensingMessage(
        const SecurityNegotiationProvenance &provenance,
        const RdpLicensingServiceCredential &credential,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Personal desktop completion is a separate branch: both structurally
    // valid CLIENT_NEW_LICENSE_REQUEST and CLIENT_LICENSE_INFO terminate with
    // exact STATUS_VALID_CLIENT/ST_NO_TRANSITION. No CAL validation or
    // issuance occurs here, and the app-server authority branch is unchanged.
    [[nodiscard]] std::optional<RdpPersonalDesktopValidClientWriteView>
    preparePersonalDesktopValidClientWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] RdpPersonalDesktopValidClientWriteOutcome
    completePersonalDesktopValidClientWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Standards-required outbound branch after a successfully prepared
    // CLIENT_NEW_LICENSE_REQUEST. R3 owns challenge generation, keys and
    // receipt state; the concrete R2 broker must reauthorize before every
    // exposed slice and accepted-byte completion.
    [[nodiscard]] std::optional<RdpServerPlatformChallengeWriteView>
    prepareServerPlatformChallengeWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] RdpServerPlatformChallengeWriteOutcome
    completeServerPlatformChallengeWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // First response to the fully delivered Server Platform Challenge.
    // The R2 broker reauthorizes the same lease/R1 owner; R3 then proves
    // global-I/O routing and cryptographically correlates the retained
    // challenge, response data, HWID and MAC before returning to a server
    // decision. No New License bytes are created here.
    [[nodiscard]] std::optional<RdpLicensingIntake>
    acceptVerifiedR2ClientPlatformChallengeResponse(
        const SecurityNegotiationProvenance &provenance,
        const RdpLicensingServiceCredential &credential,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // R3 alone creates the immutable server Demand Active profile after
    // selected-mode licensing. R10 supplies only implemented feature bits;
    // R3 derives bitmap dimensions from the exact admitted GCC Client Core
    // settings. No caller supplies wire bytes, Share IDs or session IDs.
    // Production callers reach this only through the freshly reauthorizing R2
    // broker.
    [[nodiscard]] std::optional<RdpDemandActiveProfileView>
    prepareVerifiedR2DemandActiveProfile(
        const SecurityNegotiationProvenance &provenance,
        RdpDemandActiveFeature features) noexcept;

    // Share activation accepts only the view minted by this exact session's
    // R3 provider. An offline provider or stale view cannot enter live Share.
    [[nodiscard]] std::optional<RdpShareActivationWriteView>
    beginVerifiedR2ShareActivation(
        const SecurityNegotiationProvenance &provenance,
        const RdpDemandActiveProfileView &profile) noexcept;
    [[nodiscard]] std::optional<RdpShareActivationWriteView>
    pendingVerifiedR2ShareActivationWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] RdpShareActivationWriteOutcome
    completeVerifiedR2ShareActivationWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] RdpShareActivationClientIntake
    acceptVerifiedR2ShareActivationPdu(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Sole future DVC/Graphics/input publication gate. It grants nothing by
    // itself and is intentionally private: only a freshly reauthorized R2
    // transition may query it immediately before protocol application I/O.
    [[nodiscard]] bool verifiedR2ApplicationTrafficReady(
        const SecurityNegotiationProvenance &provenance) const noexcept;

    // Sole post-Share static-VC CLIPRDR route. Private: the concrete R2
    // broker first verifies the same live lease, R1 HYBRID provenance,
    // PersonalDesktop policy and clipboard permission for every operation.
    // The result is a revocable observation, not a transferable capability.
    [[nodiscard]] std::optional<RdpClipboardStaticChannelView>
    resolveVerifiedR2ActivatedClipboardChannel(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] RdpClipboardChunkIntake acceptVerifiedR2ClipboardTpkt(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt,
        std::span<const std::uint8_t> &completePdu) noexcept;
    [[nodiscard]] std::optional<RdpClipboardStaticChannelWriteView>
    queueVerifiedR2ClipboardPdu(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completePdu) noexcept;
    [[nodiscard]] std::optional<RdpClipboardStaticChannelWriteView>
    pendingVerifiedR2ClipboardWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] RdpClipboardWriteOutcome completeVerifiedR2ClipboardWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t generation, std::uint64_t replySequence,
        std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept;

    // Route exactly one already decrypted slow-path Input Event PDU through
    // the joined global-I/O channel and current activated Share. The returned
    // view borrows completeTpkt and is usable only synchronously by the R2
    // broker, which reauthorizes input permission before each event callback.
    [[nodiscard]] std::optional<RdpSlowPathInputPdu>
    routeVerifiedR2SlowPathInputPdu(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // The negotiated drdynvc static channel becomes routable only after the
    // same post-Share gate. This alone still does not create a DVC.
    [[nodiscard]] std::optional<std::uint16_t>
    resolveVerifiedR2ActivatedDynamicVirtualChannel(
        const SecurityNegotiationProvenance &provenance) noexcept;

    // Private live path: start v1 DRDYNVC capabilities negotiation, then
    // create exactly Microsoft::Windows::RDS::Graphics. R2 must freshly
    // reauthorize the same lease/R1 owner before every call and accepted-byte
    // receipt. Offline protocol tests call the lower lifecycle directly and
    // therefore never mint production admission.
    [[nodiscard]] std::optional<RdpGraphicsDvcWriteView>
    beginVerifiedR2GraphicsDynamicVirtualChannel(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] std::optional<RdpGraphicsDvcWriteView>
    pendingVerifiedR2GraphicsDynamicVirtualChannelWrite(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] RdpGraphicsDvcWriteOutcome
    completeVerifiedR2GraphicsDynamicVirtualChannelWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    [[nodiscard]] RdpGraphicsDvcClientIntake
    acceptVerifiedR2GraphicsDynamicVirtualChannelPdu(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;
    // R3 mints the mandatory ClearCodec fallback against its own current
    // Graphics DVC generation and mapped surface. Callers supply only the
    // frame ID and borrowed pixels; neither is an authorization capability.
    [[nodiscard]] std::optional<RdpGraphicsDvcWriteView>
    beginVerifiedR2GraphicsClearCodecFramePublication(
        const SecurityNegotiationProvenance &provenance,
        std::uint32_t frameId,
        rdp_server::rdp::FramebufferView framebuffer) noexcept;
    [[nodiscard]] bool cancelVerifiedR2UnwrittenGraphicsFrame(
        const SecurityNegotiationProvenance &provenance) noexcept;
    [[nodiscard]] bool abortVerifiedR2GraphicsFrame(
        const SecurityNegotiationProvenance &provenance) noexcept;

    McsDomainParameters connectResponseDomain_{};
    GccClientSettings connectResponseClientSettings_{};
    McsConnectResponseAllocation connectResponseAllocation_{};
    SecurityNegotiationProvenance connectResponseBoundProvenance_{};
    bool connectResponseProvenanceBound_{};
    McsConnectResponseWriteGate connectResponseWrite_{};
    McsAttachUserConfirmWriteGate attachConfirmWrite_{};
    std::uint32_t allocatedUserId_{};
    RdpLicensingLifecycle licensing_{};
    RdpServerLicenseRequestWriteGate serverLicenseRequestWrite_{licensing_};
    RdpServerPlatformChallengeWriteGate
        serverPlatformChallengeWrite_{licensing_};
    RdpPersonalDesktopValidClientWriteGate
        personalDesktopValidClientWrite_{licensing_};
    RdpDemandActiveProfileProvider demandActiveProfileProvider_{};
    RdpShareActivationLifecycle shareActivation_{};
    RdpClipboardStaticChannelRoute clipboardStaticChannel_{};
    RdpDynamicVirtualChannelAllocator dynamicVirtualChannels_{};
    RdpGraphicsDynamicVirtualChannelLifecycle
        graphicsDynamicVirtualChannel_{};
    std::array<std::uint8_t, 32> licensingCredentialFingerprint_{};
    bool licensingCredentialBound_{};
    RdpLicensingKeyMaterial licensingKeyMaterial_{};
    bool licensingKeyMaterialReady_{};
    RdpExistingClientCalAuthorityRequest existingCalAuthorityRequest_{};
    std::optional<RdpLicensingIntake> acceptedInitialLicensingIntake_{};
    McsChannelJoinWriteGate joins_{};
    std::uint64_t admissionGeneration_{};
    std::uint64_t sessionGeneration_{};
    bool personalDesktopPolicySelected_{};
    McsSessionPhase phase_{McsSessionPhase::AwaitVerifiedR2Admission};
};

// Per MS-RDPBCGR 3.1.5.1.1, servers send only these two reasons.
enum class McsDisconnectReason : std::uint8_t
{
    ProviderInitiated = 1,
    UserRequested = 3,
};

// Offline nine-byte TPKT/X.224/T.125 aligned-PER encoder.
// No allocation, SSL write, session admission or socket close.
// A future authenticated session owner must encrypt the whole packet,
// finish sending, and only then close the connection.
[[nodiscard]] std::optional<std::array<std::uint8_t, 9>>
encodeMcsDisconnectProviderUltimatum(McsDisconnectReason reason) noexcept;

// MS-RDPBCGR 2.2.6.1 / T.125 11.33: server-to-client Send Data
// Indication (DomainMCSPDU choice 26). OFFLINE serializer: the one
// authenticated MCS/session owner must independently authorize the
// assigned UserId and joined channel before encrypting/sending bytes.
// Values are T.125 2-bit priority and segmentation fields (0..3);
// this function does not reassemble or govern fragmentation.
//
// Write one full RFC1006/X.224/PER packet to caller-owned contiguous
// output; return its exact byte length or nullopt without modifying
// output on failure. userData may overlap output: data is moved
// safely BEFORE the header is installed. Unused output suffix remains
// unchanged. Maximum userData is 16383 bytes (one unfragmented PER
// determinant). No heap allocation, TLS write, or session admission.
[[nodiscard]] std::optional<std::size_t> encodeMcsSendDataIndication(
    std::uint32_t assignedUserId,
    std::uint16_t channelId,
    std::uint8_t dataPriority,
    std::uint8_t segmentation,
    std::span<const std::uint8_t> userData,
    std::span<std::uint8_t> output) noexcept;

// Use the existing checked offline encoder, but never construct outbound
// data on an unjoined channel. This does not transmit or authorize traffic.
inline std::optional<std::size_t>
McsChannelJoinWriteGate::encodeJoinedSendDataIndication(
    std::uint16_t channelId, std::uint8_t dataPriority,
    std::uint8_t segmentation, std::span<const std::uint8_t> userData,
    std::span<std::uint8_t> output) const noexcept
{
    if (!channelJoinConfirmed(channelId))
        return std::nullopt;
    return encodeMcsSendDataIndication(
        assignedUserId_, channelId, dataPriority, segmentation,
        userData, output);
}

// MS-RDPBCGR 2.2.8.1.1.1.1, TS_SHARECONTROLHEADER.
// The caller must ALREADY have isolated one complete, unencrypted,
// uncompressed Share Control PDU from the appropriate MCS channel,
// handling any optional Security Header separately. An MCS userData
// span is NOT automatically a Share Control PDU: it can be a license,
// client-info, channel, or other security/application message.
// Parsing this header grants no MCS channel or session authorization.
enum class RdpShareControlKind : std::uint8_t
{
    None,
    DemandActive = 1,
    ConfirmActive = 3,
    DeactivateAll = 6,
    Data = 7,
    ServerRedirection = 10,
};

enum class RdpShareControlError : std::uint8_t
{
    None,
    InvalidLength,
    InvalidType,
    FlowPduIgnored,
};

struct RdpShareControlHeader
{
    RdpShareControlKind kind{RdpShareControlKind::None};
    std::uint16_t pduSource{};
    // Borrowed inner bytes after exactly six Share Control Header
    // bytes; no Data/Active/Redirection payload validation here.
    // Lifetime is bounded by the caller's unchanged input.
    std::span<const std::uint8_t> body{};
};

struct RdpShareControlParseResult
{
    RdpShareControlHeader value{};
    RdpShareControlError error{RdpShareControlError::InvalidLength};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpShareControlError::None;
    }
};

// Exact-length little-endian TS_SHARECONTROLHEADER, protocol version 1,
// five normative PDU types. If totalLength is 0x8000, return
// FlowPduIgnored (not success) with no borrowed body, as Microsoft
// requires. A malformed/truncated/coalesced input is never successful.
// This function performs NO security, license, MCS or share admission.
[[nodiscard]] RdpShareControlParseResult parseRdpShareControlHeader(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// MS-RDPBCGR 2.2.8.1.1.1.2 TS_SHAREDATAHEADER, ONLY for an
// explicitly isolated, complete Share Control kind=Data packet.
// The caller must already enforce TLS, license/security-header,
// MCS channel/segmentation and independent OS session authority.
// This is a pure syntax check, never an input/graphics admission.
enum class RdpShareDataError : std::uint8_t
{
    None,
    InvalidShareControl,
    FlowPduIgnored,
    NotDataPdu,
    IncompleteHeader,
    InvalidDataPduType,
    InvalidStream,
    UnsupportedCompression,
};

struct RdpShareDataHeader
{
    std::uint16_t pduSource{};
    std::uint32_t shareId{};
    std::uint8_t streamId{};
    std::uint16_t reportedUncompressedLength{};
    std::uint8_t pduType2{};
    std::uint8_t compressedType{};
    std::uint16_t compressedLength{};
    // Borrowed, read-only body AFTER the 18-byte combined headers.
    // Caller must retain the original complete input unchanged.
    std::span<const std::uint8_t> body{};
};

struct RdpShareDataParseResult
{
    RdpShareDataHeader value{};
    RdpShareDataError error{RdpShareDataError::InvalidShareControl};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpShareDataError::None;
    }
};

// Read the existing Share Control parser's exact-length result before
// decoding the 12 following bytes. Accept standard Data PDU type2
// values and stream IDs 1/2/4, plus stream 0 ONLY for Synchronize
// (documented Windows compatibility exception). Ignore pad1; retain
// reportedUncompressedLength without using it as a trustworthy bound
// because real client Font List packets may contain an uninitialized
// value. Nonzero compressedType is UNSUPPORTED, not a plaintext body.
// No decompression, nested message dispatch, or heap allocation.
[[nodiscard]] RdpShareDataParseResult parseRdpShareDataHeader(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// MS-RDPBCGR 2.2.1.14.1/2.2.1.15.1 connection finalization.
// Only pure OFFLINE syntax: caller has already isolated one entire,
// plaintext Share Control Data PDU after TLS/security/MCS routing.
// These decoders do NOT advance activation, grant control, admit a
// channel/OS user, transmit TLS, or parse a nested input PDU.
enum class RdpFinalizationError : std::uint8_t
{
    None,
    InvalidShareData,
    WrongDataPduType,
    InvalidBodyLength,
    InvalidValue,
};

struct RdpSynchronizePdu
{
    std::uint16_t pduSource{};
    std::uint32_t shareId{};
    std::uint16_t targetUser{};
};

struct RdpSynchronizeParseResult
{
    RdpSynchronizePdu value{};
    RdpFinalizationError error{RdpFinalizationError::InvalidShareData};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpFinalizationError::None;
    }
};

// TS_SYNCHRONIZE_PDU: exactly 18+4 bytes, pduType2=0x1f,
// little-endian messageType MUST be 1 and targetUser is the
// untrusted MCS channel ID (not evidence of a joined channel).
[[nodiscard]] RdpSynchronizeParseResult parseRdpSynchronizePdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

enum class RdpControlAction : std::uint16_t
{
    RequestControl = 1,
    GrantedControl = 2,
    Detach = 3,
    Cooperate = 4,
};

struct RdpControlPdu
{
    std::uint16_t pduSource{};
    std::uint32_t shareId{};
    RdpControlAction action{RdpControlAction::RequestControl};
    std::uint16_t grantId{};
    std::uint32_t controlId{};
};

struct RdpControlParseResult
{
    RdpControlPdu value{};
    RdpFinalizationError error{RdpFinalizationError::InvalidShareData};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpFinalizationError::None;
    }
};

// TS_CONTROL_PDU: exactly 18+8 bytes, pduType2=0x14,
// action 1..4, little-endian grantId/controlId. Client Request/
// Cooperate zero IDs and server Granted user/channel IDs are
// DIRECTIONAL, session-owned requirements: preserve raw values,
// never interpret an incoming GrantedControl as authority.
[[nodiscard]] RdpControlParseResult parseRdpControlPdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

enum class RdpFontListError : std::uint8_t
{
    None,
    InvalidShareData,
    WrongDataPduType,
    InvalidBodyLength,
};

struct RdpFontListPdu
{
    std::uint16_t pduSource{};
    std::uint32_t shareId{};
    std::uint16_t numberFonts{};
    std::uint16_t totalNumFonts{};
    std::uint16_t listFlags{};
    std::uint16_t entrySize{};
};

struct RdpFontListParseResult
{
    RdpFontListPdu value{};
    RdpFontListError error{RdpFontListError::InvalidShareData};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpFontListError::None;
    }
};

// Exact 8-byte TS_FONT_LIST_PDU body. The legacy count/flags/entry-size
// fields are preserved as protocol metadata because the specification marks
// their canonical values as SHOULD, not authorization requirements.
[[nodiscard]] RdpFontListParseResult parseRdpClientFontListPdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// MS-RDPBCGR 2.2.1.13.1.1 / 2.2.1.13.2.1, capability-exchange
// TS_DEMAND_ACTIVE_PDU and TS_CONFIRM_ACTIVE_PDU. The caller MUST first
// isolate exactly one decrypted, intact Share Control PDU from the
// authenticated/authorized MCS session. Syntax alone never activates
// the share, authorizes the OS identity or negotiates a codec.
enum class RdpActivePduError : std::uint8_t
{
    None,
    InvalidShareControl,
    WrongPduType,
    InvalidLayout,
    InvalidOriginator,
    InvalidCapabilitySet,
};

struct RdpActivePdu
{
    RdpShareControlKind kind{RdpShareControlKind::None};
    std::uint16_t pduSource{};
    std::uint32_t shareId{};
    std::uint16_t originatorId{}; // Confirm Active only, MUST be 1002.
    std::uint32_t sessionId{};    // Demand Active only, uninterpreted.
    std::uint16_t capabilityCount{};
    // Read-only views into caller's unchanged completeSharePdu.
    // The original backing buffer MUST outlive both borrowed spans.
    std::span<const std::uint8_t> sourceDescriptor{};
    // Concatenated TS_CAPS_SET envelopes (LE16 type, LE16 length,
    // then raw opaque bytes); each length includes its four-byte
    // header. No capability type is trusted or semantically enabled.
    std::span<const std::uint8_t> capabilitySets{};
};

struct RdpActivePduParseResult
{
    RdpActivePdu value{};
    RdpActivePduError error{RdpActivePduError::InvalidShareControl};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpActivePduError::None;
    }
};

// Validate exact Share Control size and version, mandatory Confirm
// Active originatorId=1002, sourceDescriptor and combined-capability
// byte counts, numberCapabilities and every nested capability's
// minimum 4-byte length; require exact consumption and the final
// 4-byte Demand Active sessionId. Unknown capability IDs and pad2Octets
// remain opaque per Microsoft. No copy/heap, TLS write or activation.
[[nodiscard]] RdpActivePduParseResult parseRdpActivePdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// OFFLINE General Capability Set intake, MS-RDPBCGR 2.2.7.1.1.
// Parse exactly one *complete* Demand/Confirm Active Share Control PDU
// with the existing strict outer/envelope validator, then locate ONE
// 24-byte CAPSTYPE_GENERAL (1). Missing, repeated, malformed, invalid
// protocol version and unsupported Boolean encodings fail separately.
// Unknown sibling capability types are skipped without interpretation.
// Ignored padding and other uninterpreted fields retain raw values.
// No borrowed views are retained, no heap allocation or state mutation.
// This does NOT prove TLS, OS/GSS identity, MCS sender, licensing,
// capability agreement, fast-path support, graphics or share activation.
enum class RdpGeneralCapabilityError : std::uint8_t
{
    None,
    InvalidActivePdu,
    Missing,
    Duplicate,
    InvalidLayout,
    InvalidProtocolVersion,
    InvalidBoolean,
};

struct RdpGeneralCapability
{
    std::uint16_t osMajorType{};
    std::uint16_t osMinorType{};
    std::uint16_t generalCompressionTypes{}; // Raw: ignored by receiver.
    std::uint16_t extraFlags{}; // Advertisement, NOT negotiated support.
    std::uint16_t updateCapabilityFlag{}; // Raw, not a permission.
    std::uint16_t remoteUnshareFlag{};
    std::uint16_t generalCompressionLevel{};
    bool refreshRectSupported{};
    bool suppressOutputSupported{};
};

struct RdpGeneralCapabilityParseResult
{
    RdpGeneralCapability value{};
    RdpGeneralCapabilityError error{RdpGeneralCapabilityError::InvalidActivePdu};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpGeneralCapabilityError::None;
    }
};

[[nodiscard]] RdpGeneralCapabilityParseResult parseRdpGeneralCapabilityFromActive(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// OFFLINE MS-RDPBCGR 2.2.7.1.2 Bitmap Capability Set, exactly 28
// bytes. Reuse the same complete Demand/Confirm Active validator and
// counted TS_CAPS_SET envelopes. Require exactly ONE bitmap set and
// the spec's required compression and multiple-rectangle support,
// valid desktop dimensions and 0/1 desktopResizeFlag.
// Ignored receive-depth fields, highColorFlags and both pads remain
// ignored; unknown drawingFlags bits remain raw advertisements.
// This is NOT a negotiated graphics mode, codec, OS authorization,
// connected desktop or authenticated/ordered MCS session.
enum class RdpBitmapCapabilityError : std::uint8_t
{
    None,
    InvalidActivePdu,
    Missing,
    Duplicate,
    InvalidLayout,
    InvalidDesktopSize,
    InvalidResizeFlag,
    MissingRequiredSupport,
};

struct RdpBitmapCapability
{
    std::uint16_t preferredBitsPerPixel{}; // Raw desired/session depth.
    std::uint16_t desktopWidth{};          // Raw advertised dimensions.
    std::uint16_t desktopHeight{};
    bool desktopResizeSupported{};
    std::uint8_t drawingFlags{}; // Not negotiated or enabled by parsing.
};

struct RdpBitmapCapabilityParseResult
{
    RdpBitmapCapability value{};
    RdpBitmapCapabilityError error{RdpBitmapCapabilityError::InvalidActivePdu};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpBitmapCapabilityError::None;
    }
};

// No allocation, views retained, screen-buffer sizing or TLS emission.
// Bounds come solely from parseRdpActivePdu and its shared validator;
// a returned rectangle size MUST NOT be used to allocate a desktop.
[[nodiscard]] RdpBitmapCapabilityParseResult parseRdpBitmapCapabilityFromActive(
    std::span<const std::uint8_t> completeSharePdu) noexcept;

// OFFLINE server-side MS-RDPBCGR 2.2.1.13.1.1 Demand Active writer.
// Emits a single exact-length Share Control PDU (NOT TLS/MCS framing).
// Source and capability buffers must NOT intersect the output region
// being written; overlapping inputs are rejected without any mutation.
// Capability envelopes are validated with the SAME rules as the parser.
// Source may be opaque and capability IDs unknown; successful encoding
// never means the server selected a working license, graphics codec,
// joined channel or authenticated/OS-authorized session.
//
// pduSource is the normative server MCS channel ID 1002, NOT a
// caller-supplied principal. All field lengths and the special
// FlowPDU length 0x8000 are checked before writes. No allocations.
[[nodiscard]] std::optional<std::size_t> encodeRdpDemandActivePdu(
    std::uint32_t shareId,
    std::uint32_t sessionId,
    std::span<const std::uint8_t> sourceDescriptor,
    std::uint16_t capabilityCount,
    std::span<const std::uint8_t> capabilitySets,
    std::span<std::uint8_t> output) noexcept;

// OFFLINE MS-RDPBCGR 2.2.1.19 / 2.2.1.20 / 2.2.1.21
// server finalization Share Control + Share Data PDU writers.
// Exactly one plaintext, uncompressed PDU into caller-owned storage:
// no MCS wrapping, TLS, active sharing, control grant or OS admission.
// Both use fixed server pduSource=1002 and canonical ignored pad=0.
// The Synchronize targetUser field is deliberately uninterpreted,
// since historical Microsoft Server examples contain an uninitialized
// value. Only the authenticated session owner can check target/channel
// identity before any packet is sent.
[[nodiscard]] std::optional<std::size_t> encodeRdpServerSynchronizePdu(
    std::uint32_t shareId,
    std::uint16_t targetUser,
    std::span<std::uint8_t> output) noexcept;

// Server Control only: Cooperate requires assignedClientUserId=0
// and emits grantId/controlId=0; Granted Control requires an assigned
// client user-channel ID 1001..65535, emits that as grantId and the
// normative MCS server channel 1002 as controlId. Request Control and
// Detach are not server emissions and are rejected atomically.
// A valid encoded Granted Control message DOES NOT grant authority;
// that check belongs solely to a future authenticated session owner.
[[nodiscard]] std::optional<std::size_t> encodeRdpServerControlPdu(
    std::uint32_t shareId,
    RdpControlAction action,
    std::uint32_t assignedClientUserId,
    std::span<std::uint8_t> output) noexcept;

// MS-RDPBCGR 2.2.1.22.1 Server Font Map, the final server PDU in the
// connection finalization sequence. Emit the empty FIRST|LAST map used by
// current Microsoft clients: numberEntries=0, totalNumEntries=0,
// mapFlags=0x0003, entrySize=0x0004. Pure Share PDU; no activation authority.
[[nodiscard]] std::optional<std::size_t> encodeRdpServerFontMapPdu(
    std::uint32_t shareId,
    std::span<std::uint8_t> output) noexcept;

// OFFLINE transcript-correlation check for the single Demand Active
// server PDU followed by the client Confirm Active PDU. It reuses
// parseRdpActivePdu and compares the exact share ID and the two
// independently assigned MCS sender channels. The expected client
// user ID MUST be supplied from separate authenticated MCS ownership;
// this function does NOT establish that ownership or authenticate it.
//
// A successful result is ONLY a syntax correlation: it does NOT
// verify capability contents, security headers, TLS/Kerberos identity,
// licensing, OS session rights, receipt order, or activate a share.
enum class RdpActiveExchangeCorrelation : std::uint8_t
{
    Rejected,
    ConsistentSyntaxOnly,
};

[[nodiscard]] RdpActiveExchangeCorrelation correlateRdpActiveExchange(
    std::span<const std::uint8_t> serverDemandSharePdu,
    std::span<const std::uint8_t> clientConfirmSharePdu,
    std::uint32_t expectedClientUserId) noexcept;


// Pure OFFLINE MS-RDPBCGR 2.2.1.14-2.2.1.21 finalization
// comparison of six complete, decrypted Share Control PDUs.
// The borrowed spans must remain live throughout the call.
// Slots describe roles, NOT verified wire arrival ordering.
// Actual TLS/MCS sender provenance, authorized identity, channel
// membership, licensing, capability activation and event ordering
// remain responsibilities of the future single session owner.
struct RdpFinalizationTranscript
{
    std::span<const std::uint8_t> clientSynchronize{};
    std::span<const std::uint8_t> clientCooperate{};
    std::span<const std::uint8_t> clientRequestControl{};
    std::span<const std::uint8_t> serverSynchronize{};
    std::span<const std::uint8_t> serverCooperate{};
    std::span<const std::uint8_t> serverGrantedControl{};
};

enum class RdpFinalizationCorrelation : std::uint8_t
{
    Rejected,
    ConsistentSyntaxOnly,
};

// Reuse the authoritative exact-length Share Data parsers.
// expectedClientUserId must be an independently assigned MCS channel
// in 1001..65535; server channel is 1002. Even a consistent syntax
// result MUST NOT be used to admit or activate a desktop.
[[nodiscard]] RdpFinalizationCorrelation correlateRdpFinalizationExchange(
    const RdpFinalizationTranscript &transcript,
    std::uint32_t expectedShareId,
    std::uint32_t expectedClientUserId) noexcept;

} // namespace rdp_server::server::transport
