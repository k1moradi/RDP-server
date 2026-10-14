// SPDX-License-Identifier: GPL-3.0-or-later
#include "tpkt_x224.h"

#include <algorithm>

namespace rdp_server::server::transport
{
namespace
{
[[nodiscard]] constexpr std::uint16_t read16Le(
    std::span<const std::uint8_t> bytes) noexcept
{
    return static_cast<std::uint16_t>(bytes[0]) |
           (static_cast<std::uint16_t>(bytes[1]) << 8U);
}

[[nodiscard]] constexpr std::uint32_t read32Le(
    std::span<const std::uint8_t> bytes) noexcept
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

[[nodiscard]] constexpr ConnectionParseResult invalid(
    ConnectionError error) noexcept
{
    return {{}, error};
}
} // namespace

std::optional<std::size_t> connectionRequestLength(
    std::span<const std::uint8_t> header) noexcept
{
    if (header.size() != 4 || header[0] != 3 || header[1] != 0)
    {
        return std::nullopt;
    }
    const std::size_t packetBytes =
        (static_cast<std::size_t>(header[2]) << 8U) | header[3];
    if (packetBytes < 11 || packetBytes > kMaximumConnectionRequestBytes)
    {
        return std::nullopt;
    }
    return packetBytes;
}

ConnectionParseResult parseConnectionRequest(
    std::span<const std::uint8_t> packet) noexcept
{
    if (packet.size() < 11)
    {
        return invalid(ConnectionError::InvalidTpkt);
    }
    const auto length = connectionRequestLength(packet.first(4));
    if (!length || *length != packet.size())
    {
        return invalid(ConnectionError::InvalidTpkt);
    }
    // The X.224 CR TPDU has a fixed six-byte header after its LI.
    // Both optional cookie/routing and negotiation data count toward LI.
    if (packet[4] < 6 || static_cast<std::size_t>(packet[4]) + 5 != *length ||
        packet[5] != 0xe0 || packet[10] != 0)
    {
        return invalid(ConnectionError::InvalidX224);
    }

    ConnectionRequest request{};
    std::span<const std::uint8_t> optional = packet.subspan(11);
    if (!optional.empty() && optional[0] != 0x01)
    {
        // Ignore optional routing token or mstshash cookie, but require the
        // CRLF terminator. Neither value is used to authorize a session.
        std::size_t prefixLength = 0;
        while (prefixLength + 1 < optional.size() &&
               !(optional[prefixLength] == '\r' &&
                 optional[prefixLength + 1] == '\n'))
        {
            // Routing tokens are ANSI; reject embedded controls/NUL.
            if (optional[prefixLength] < 0x20 ||
                optional[prefixLength] > 0x7e)
            {
                return invalid(ConnectionError::InvalidPrefix);
            }
            ++prefixLength;
        }
        if (prefixLength == 0 || prefixLength + 1 >= optional.size())
        {
            return invalid(ConnectionError::InvalidPrefix);
        }
        optional = optional.subspan(prefixLength + 2);
        request.hasClientPrefix = true;
    }
    if (optional.empty())
    {
        // Legacy standard RDP security: recorded, NEVER negotiated here.
        return {request, ConnectionError::None};
    }
    if (optional.size() < 8 || optional[0] != 0x01 ||
        read16Le(optional.subspan(2, 2)) != 8)
    {
        return invalid(ConnectionError::InvalidNegotiation);
    }

    request.hasNegotiation = true;
    request.negotiationFlags = optional[1];
    request.requestedProtocols = read32Le(optional.subspan(4, 4));
    optional = optional.subspan(8);

    constexpr std::uint8_t kCorrelationPresent = 0x08;
    if ((request.negotiationFlags & kCorrelationPresent) == 0)
    {
        return optional.empty()
                   ? ConnectionParseResult{request, ConnectionError::None}
                   : invalid(ConnectionError::InvalidNegotiation);
    }

    // MS-RDPBCGR 2.2.1.1.2: type=0x06, length=36, 16-byte correlation
    // identifier and 16 reserved zero bytes. Never persist the identifier.
    if (optional.size() != 36 || optional[0] != 0x06 ||
        optional[1] != 0 || read16Le(optional.subspan(2, 2)) != 36 ||
        !std::all_of(optional.begin() + 20, optional.end(),
                     [](std::uint8_t value) { return value == 0; }))
    {
        return invalid(ConnectionError::InvalidCorrelation);
    }
    request.hasCorrelation = true;
    return {request, ConnectionError::None};
}

} // namespace rdp_server::server::transport
