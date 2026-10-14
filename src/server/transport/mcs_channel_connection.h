// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// Syntax-only, bounded T.125 DomainMCSPDU parsing for the RDP
// Channel Connection phase. No user, channel or session is admitted,
// registered, attached or joined by these pure parsing functions.
// MS-RDPBCGR 2.2.1.5, 2.2.1.6 and 2.2.1.8.
enum class McsChannelRequestKind : std::uint8_t
{
    None,
    ErectDomain,
    AttachUser,
    ChannelJoin,
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
// A syntactically recognized request does NOT establish channel state,
// domain ownership or authorization, nor does it allow a response.
[[nodiscard]] McsChannelParseResult parseMcsChannelRequest(
    std::span<const std::uint8_t> completeTpkt) noexcept;

} // namespace rdp_server::server::transport
