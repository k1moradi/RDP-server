// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

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

// T.125 AttachUserConfirm rt-successful with initiator present.
// 'assignedUserId' is an explicit external allocation, never
// chosen or reserved by this pure encoder.
[[nodiscard]] McsChannelConfirm encodeMcsAttachUserConfirm(
    std::uint32_t assignedUserId) noexcept;

// ChannelJoinConfirm rt-successful with optional channelId present.
// Inputs must describe a checked Join REQUEST, matching assigned user,
// and exactly one matching entry in a bounded caller-supplied list.
// The list cannot confer authorization. A real owner must check
// OS/NLA identity and MCS channel state before sending any bytes.
[[nodiscard]] McsChannelConfirm encodeMcsChannelJoinConfirm(
    const McsChannelRequest &joinRequest,
    std::uint32_t assignedUserId,
    std::span<const std::uint16_t> assignedChannelIds) noexcept;

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

} // namespace rdp_server::server::transport
