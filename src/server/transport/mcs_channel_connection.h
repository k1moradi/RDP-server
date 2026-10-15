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

} // namespace rdp_server::server::transport
