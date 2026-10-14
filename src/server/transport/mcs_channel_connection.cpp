// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_channel_connection.h"
#include "mcs_connect_initial.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{
namespace
{
// T.125 aligned BASIC-PER nonnegative unconstrained INTEGER for
// ErectDomainRequest subHeight/subInterval. One short length octet
// followed by exactly 1..4 significant bytes. No fragmented PER
// length determinant and no nonminimal leading-zero encodings.
[[nodiscard]] bool readPerInteger(std::span<const std::uint8_t> payload,
                                  std::size_t &offset,
                                  std::uint32_t &output) noexcept
{
    if (offset == payload.size())
        return false;
    const std::size_t size = payload[offset++];
    if (size == 0 || size > sizeof(std::uint32_t) ||
        size > payload.size() - offset ||
        (size > 1 && payload[offset] == 0))
        return false;

    std::uint32_t value = 0;
    for (std::size_t i = 0; i < size; ++i)
        value = (value << 8U) | payload[offset++];
    output = value;
    return true;
}
} // namespace

McsChannelParseResult parseMcsChannelRequest(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    // Reuse the existing owned RFC1006/X.224 validation, including
    // rejection of truncated and coalesced trailing TPKT bytes.
    std::span<const std::uint8_t> payload;
    if (!parseDataTpdu(completeTpkt, payload))
        return {};
    if (payload.empty())
        return {{}, McsChannelParseError::InvalidDomainPdu};

    if (payload[0] == 0x04)
    {
        McsChannelRequest request{};
        std::size_t pos = 1;
        if (!readPerInteger(payload, pos, request.subHeight) ||
            !readPerInteger(payload, pos, request.subInterval) ||
            pos != payload.size())
            return {{}, McsChannelParseError::InvalidPerValue};
        request.kind = McsChannelRequestKind::ErectDomain;
        return {request, McsChannelParseError::None};
    }

    if (payload[0] == 0x28)
    {
        if (payload.size() != 1)
            return {{}, McsChannelParseError::InvalidDomainPdu};
        McsChannelRequest request{};
        request.kind = McsChannelRequestKind::AttachUser;
        return {request, McsChannelParseError::None};
    }

    if (payload[0] == 0x38)
    {
        // T.125 ChannelJoinRequest ::= initiator UserId,
        // channelId ChannelId. The PER initiator is offset by 1001;
        // no user identity or channel allocation is implied.
        if (payload.size() != 5)
            return {{}, McsChannelParseError::InvalidDomainPdu};
        const auto encodedInitiator =
            (static_cast<std::uint32_t>(payload[1]) << 8U) | payload[2];
        constexpr std::uint32_t kFirstUserId = 1001;
        constexpr std::uint32_t kMaxUserId = 65536;
        if (encodedInitiator > kMaxUserId - kFirstUserId)
            return {{}, McsChannelParseError::InvalidPerValue};
        McsChannelRequest request{};
        request.kind = McsChannelRequestKind::ChannelJoin;
        request.initiator = encodedInitiator + kFirstUserId;
        request.channelId = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(payload[3]) << 8U) | payload[4]);
        return {request, McsChannelParseError::None};
    }

    // Unknown DomainMCSPDU types, T.125 extension bits/flags, and
    // response/opposite-direction types must not be accepted as requests.
    return {{}, McsChannelParseError::InvalidDomainPdu};
}

} // namespace rdp_server::server::transport
