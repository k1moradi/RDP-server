// SPDX-License-Identifier: GPL-3.0-or-later
#include "gcc_conference_create.h"

#include <algorithm>
#include <array>

namespace rdp_server::server::transport
{
namespace
{

[[nodiscard]] std::uint16_t readLe16(
    std::span<const std::uint8_t> bytes) noexcept
{
    return static_cast<std::uint16_t>(bytes[0]) |
           (static_cast<std::uint16_t>(bytes[1]) << 8U);
}

[[nodiscard]] std::uint32_t readLe32(
    std::span<const std::uint8_t> bytes) noexcept
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

// PER length determinant. Reject fragmented 11xxxxxx form, nonminimal
// two-byte lengths and overreads. This is NOT BER or a generic PER parser.
[[nodiscard]] bool readPerLength(std::span<const std::uint8_t> input,
                                 std::size_t &offset,
                                 std::size_t &length) noexcept
{
    if (offset >= input.size())
    {
        return false;
    }
    const std::uint8_t first = input[offset++];
    if ((first & 0x80U) == 0)
    {
        length = first;
        return true;
    }
    if ((first & 0xc0U) != 0x80U || offset >= input.size())
    {
        return false;
    }
    length = (static_cast<std::size_t>(first & 0x3fU) << 8U) |
             input[offset++];
    return length >= 128;
}

[[nodiscard]] bool parseChannelName(
    std::span<const std::uint8_t> encoded,
    std::array<char, 8> &name) noexcept
{
    // CHANNEL_DEF is seven ANSI bytes followed by NUL, with zero padding.
    bool terminated = false;
    bool hasCharacter = false;
    for (std::size_t index = 0; index < 8; ++index)
    {
        const std::uint8_t value = encoded[index];
        if (value == 0)
        {
            terminated = true;
        }
        else if (terminated || value < 0x21U || value > 0x7eU)
        {
            return false;
        }
        else
        {
            hasCharacter = true;
            name[index] = static_cast<char>(value);
        }
    }
    return terminated && hasCharacter;
}

[[nodiscard]] char lowerAscii(char value) noexcept
{
    return value >= 'A' && value <= 'Z'
               ? static_cast<char>(value + ('a' - 'A'))
               : value;
}

[[nodiscard]] bool equalName(
    const std::array<char, 8> &left,
    const std::array<char, 8> &right) noexcept
{
    for (std::size_t index = 0; index < left.size(); ++index)
    {
        if (lowerAscii(left[index]) != lowerAscii(right[index]))
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool parseNetwork(
    std::span<const std::uint8_t> block,
    GccClientSettings &settings) noexcept
{
    if (block.size() < 4)
    {
        return false;
    }
    const std::uint32_t count = readLe32(block.first(4));
    if (count > kMaximumStaticChannelCount ||
        block.size() != 4U + static_cast<std::size_t>(count) * 12U)
    {
        return false;
    }
    settings.channelCount = static_cast<std::uint8_t>(count);
    settings.hasNetworkData = true;
    for (std::size_t index = 0; index < count; ++index)
    {
        const auto item = block.subspan(4 + index * 12, 12);
        auto &channel = settings.channels[index];
        if (!parseChannelName(item.first(8), channel.name))
        {
            return false;
        }
        for (std::size_t previous = 0; previous < index; ++previous)
        {
            if (equalName(settings.channels[previous].name, channel.name))
            {
                return false;
            }
        }
        channel.options = readLe32(item.subspan(8, 4));
    }
    return true;
}

[[nodiscard]] GccParseResult fail(GccError error) noexcept
{
    return {{}, error};
}

} // namespace

GccParseResult parseGccConferenceCreate(
    std::span<const std::uint8_t> input) noexcept
{
    if (input.size() < 7 || input.size() > kMaximumBasicGccBytes)
    {
        return fail(GccError::InvalidConnectData);
    }
    // T.124 ConnectData: initial choice, length=5 and the RDP
    // t124Identifier OBJECT IDENTIFIER 0.0.20.124.0.1.
    constexpr std::array<std::uint8_t, 7> kConnectHeader{
        0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01};
    if (!std::equal(kConnectHeader.begin(), kConnectHeader.end(),
                    input.begin()))
    {
        return fail(GccError::InvalidConnectData);
    }
    std::size_t offset = kConnectHeader.size();
    std::size_t conferenceLength = 0;
    if (!readPerLength(input, offset, conferenceLength) ||
        conferenceLength > input.size() - offset ||
        conferenceLength != input.size() - offset)
    {
        return fail(GccError::InvalidConnectData);
    }
    const auto conference = input.subspan(offset, conferenceLength);

    // Canonical T.124 RDP ConferenceCreateRequest: conferenceName "1",
    // one UserData set, H221NonStandard key, no optional fields.
    constexpr std::array<std::uint8_t, 8> kConferenceHeader{
        0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00};
    if (conference.size() < kConferenceHeader.size() + 4 ||
        !std::equal(kConferenceHeader.begin(), kConferenceHeader.end(),
                    conference.begin()))
    {
        return fail(GccError::InvalidConference);
    }
    constexpr std::array<std::uint8_t, 4> kH221ClientKey{
        'D', 'u', 'c', 'a'};
    if (!std::equal(kH221ClientKey.begin(), kH221ClientKey.end(),
                    conference.begin() + kConferenceHeader.size()))
    {
        return fail(GccError::InvalidH221Key);
    }
    offset = kConferenceHeader.size() + kH221ClientKey.size();
    std::size_t settingsLength = 0;
    if (!readPerLength(conference, offset, settingsLength) ||
        settingsLength == 0 ||
        settingsLength != conference.size() - offset)
    {
        return fail(GccError::InvalidSettings);
    }
    const auto settingsBytes = conference.subspan(offset, settingsLength);
    GccClientSettings settings{};
    bool hasCore = false;
    bool hasSecurity = false;
    std::size_t position = 0;
    while (position < settingsBytes.size())
    {
        if (settingsBytes.size() - position < 4)
        {
            return fail(GccError::InvalidSettings);
        }
        const auto rest = settingsBytes.subspan(position);
        const std::uint16_t type = readLe16(rest.first(2));
        const std::size_t blockLength = readLe16(rest.subspan(2, 2));
        if (blockLength < 4 || blockLength > rest.size())
        {
            return fail(GccError::InvalidSettings);
        }
        const auto body = rest.subspan(4, blockLength - 4);
        switch (type)
        {
            case 0xc001: // CS_CORE: fixed portion, then optional extensions
                if (hasCore || body.size() < 128)
                {
                    return fail(GccError::InvalidCore);
                }
                settings.clientVersion = readLe32(body.first(4));
                settings.requestedWidth = readLe16(body.subspan(4, 2));
                settings.requestedHeight = readLe16(body.subspan(6, 2));
                if (settings.requestedWidth == 0 ||
                    settings.requestedHeight == 0)
                {
                    return fail(GccError::InvalidCore);
                }
                hasCore = true;
                break;

            case 0xc002: // CS_SECURITY
                if (hasSecurity || body.size() != 8)
                {
                    return fail(GccError::InvalidSecurity);
                }
                settings.encryptionMethods = readLe32(body.first(4));
                settings.extEncryptionMethods = readLe32(body.subspan(4, 4));
                hasSecurity = true;
                break;

            case 0xc003: // CS_NET is optional when no static channels
                if (settings.hasNetworkData ||
                    !parseNetwork(body, settings))
                {
                    return fail(GccError::InvalidNetwork);
                }
                break;

            case 0xc004: // CS_CLUSTER, optionally 8 bytes of payload
                if (settings.hasClusterData || body.size() != 8)
                {
                    return fail(GccError::InvalidSettings);
                }
                settings.hasClusterData = true;
                break;

            default:
                // Extended Client Data Blocks were never advertised.
                // Reject rather than partially processing unknown blocks.
                return fail(GccError::InvalidSettings);
        }
        position += blockLength;
    }
    if (!hasCore || !hasSecurity)
    {
        return fail(GccError::InvalidSettings);
    }
    return {settings, GccError::None};
}

} // namespace rdp_server::server::transport
