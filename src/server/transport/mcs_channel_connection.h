// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "gcc_conference_create.h"
#include "mcs_connect_response.h"
#include "rdp_licensing.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

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

class McsSessionLifecycle final
{
public:
    McsSessionLifecycle() noexcept = default;
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
        licensing_.close();
        joins_.close();
        phase_ = McsSessionPhase::Closed;
    }

private:
    friend class rdp_server::server::security::LinuxConsoleAdmissionBroker;

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

    // R3 remains the sole licensing writer owner. The concrete R2 broker
    // reauthorizes the exact lease/R1 owner before every borrowed slice and
    // every accepted-byte receipt. Provisioned fields are sampled only when
    // the one stable request is first queued; later calls return its suffix.
    [[nodiscard]] std::optional<RdpServerLicenseRequestWriteView>
    prepareServerLicenseRequestWrite(
        const SecurityNegotiationProvenance &provenance,
        const RdpServerLicenseIdentity &identity) noexcept;
    [[nodiscard]] RdpServerLicenseRequestWriteOutcome
    completeServerLicenseRequestWrite(
        const SecurityNegotiationProvenance &provenance,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // First client licensing response after the request has been fully
    // delivered. The concrete R2 broker reauthorizes the same lease/R1 owner;
    // R3 then proves joined global-I/O MCS routing, complete begin|end
    // segmentation and SEC_LICENSE_PKT before invoking the bounded licensing
    // lifecycle. No client license cryptography is decided here.
    [[nodiscard]] std::optional<RdpLicensingIntake>
    acceptVerifiedR2ClientLicensingMessage(
        const SecurityNegotiationProvenance &provenance,
        std::span<const std::uint8_t> completeTpkt) noexcept;

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
    McsChannelJoinWriteGate joins_{};
    std::uint64_t admissionGeneration_{};
    std::uint64_t sessionGeneration_{};
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
