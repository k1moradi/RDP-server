// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_channel_connection.h"
#include "mcs_connect_initial.h"
#include "gcc_conference_create.h"

#include <array>
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

namespace
{
constexpr std::uint32_t kFirstMcsUserId = 1001;
constexpr std::uint32_t kLastMcsUserId = 65536;

[[nodiscard]] bool validMcsUser(std::uint32_t value) noexcept
{
    return value >= kFirstMcsUserId && value <= kLastMcsUserId;
}

[[nodiscard]] std::uint8_t highByte(std::uint32_t value) noexcept
{
    return static_cast<std::uint8_t>(value >> 8U);
}
[[nodiscard]] std::uint8_t lowByte(std::uint32_t value) noexcept
{
    return static_cast<std::uint8_t>(value);
}
}

// MS-RDPBCGR 4.1.7: 03 00 00 0b 02 f0 80 2e 00 00 06 for user 1007.
// 0x2e is attachUserConfirm with the optional initiator present.
// 0x00 represents rt-successful. All writes are bounded fixed-size.
McsChannelConfirm encodeMcsAttachUserConfirm(
    std::uint32_t assignedUserId) noexcept
{
    if (!validMcsUser(assignedUserId))
        return {};
    const auto offset = assignedUserId - kFirstMcsUserId;
    McsChannelConfirm result{};
    result.packet = {0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80,
                     0x2e, 0x00, highByte(offset), lowByte(offset)};
    result.length = 11;
    return result;
}

// MS-RDPBCGR 4.1.8.2.2: 03 00 00 0f 02 f0 80 3e 00 00 06
// 03 eb 03 eb for joined I/O channel 1003 and user 1007.
McsChannelConfirm encodeMcsChannelJoinConfirm(
    const McsChannelRequest &joinRequest,
    std::uint32_t assignedUserId,
    std::span<const std::uint16_t> assignedChannelIds) noexcept
{
    if (joinRequest.kind != McsChannelRequestKind::ChannelJoin ||
        !validMcsUser(assignedUserId) ||
        joinRequest.initiator != assignedUserId ||
        joinRequest.subHeight != 0 || joinRequest.subInterval != 0 ||
        joinRequest.channelId == 0 ||
        assignedChannelIds.empty() ||
        assignedChannelIds.size() > kMaximumStaticChannelCount + 2U)
        return {};

    // The authenticated owner, NOT this encoder, is responsible
    // for proving assignedChannelIds are real allocations. Require
    // exactly one matching entry; fail closed on any duplicates.
    std::size_t matches = 0;
    for (std::size_t i = 0; i < assignedChannelIds.size(); ++i)
    {
        const auto channel = assignedChannelIds[i];
        if (channel == 0)
            return {};
        if (channel == joinRequest.channelId)
            ++matches;
        for (std::size_t j = 0; j < i; ++j)
        {
            if (assignedChannelIds[j] == channel)
                return {};
        }
    }
    if (matches != 1)
        return {};

    const auto userOffset = assignedUserId - kFirstMcsUserId;
    const auto channel = joinRequest.channelId;
    McsChannelConfirm result{};
    result.packet = {0x03, 0x00, 0x00, 0x0f, 0x02, 0xf0, 0x80,
                     0x3e, 0x00, highByte(userOffset),
                     lowByte(userOffset), highByte(channel),
                     lowByte(channel), highByte(channel),
                     lowByte(channel)};
    result.length = 15;
    return result;
}

} // namespace rdp_server::server::transport
