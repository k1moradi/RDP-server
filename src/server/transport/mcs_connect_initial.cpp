// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_connect_initial.h"

#include <cstddef>

namespace rdp_server::server::transport
{
namespace
{
struct BerReader
{
    std::span<const std::uint8_t> bytes{};
    std::size_t offset{};

    // Definite, minimal BER lengths only. The TPKT 16-bit limit makes a
    // 3-byte length prefix sufficient; indefinite BER is not accepted.
    [[nodiscard]] bool readLength(std::size_t &length) noexcept
    {
        if (offset == bytes.size())
        {
            return false;
        }
        const std::uint8_t first = bytes[offset++];
        if ((first & 0x80U) == 0)
        {
            length = first;
            return true;
        }
        const std::size_t octets = first & 0x7fU;
        if (octets == 0 || octets > 2 || octets > bytes.size() - offset)
        {
            return false;
        }
        std::size_t result = 0;
        for (std::size_t index = 0; index < octets; ++index)
        {
            result = (result << 8U) | bytes[offset++];
        }
        if ((octets == 1 && result < 128) ||
            (octets == 2 && result < 256))
        {
            return false;
        }
        length = result;
        return true;
    }

    [[nodiscard]] bool readValue(
        std::uint8_t expectedTag,
        std::span<const std::uint8_t> &value) noexcept
    {
        if (offset == bytes.size() || bytes[offset++] != expectedTag)
        {
            return false;
        }
        std::size_t length = 0;
        if (!readLength(length) || length > bytes.size() - offset)
        {
            return false;
        }
        value = bytes.subspan(offset, length);
        offset += length;
        return true;
    }

    [[nodiscard]] bool exhausted() const noexcept
    {
        return offset == bytes.size();
    }
};

[[nodiscard]] bool parseUnsignedDomainInteger(
    std::span<const std::uint8_t> bytes, std::uint32_t &value) noexcept
{
    // T.125/RDP DomainParameters are nonnegative, but Microsoft's 4.1.3
    // fixture uses BER 02 02 FF FF for the unsigned value 65535 without
    // an ASN.1 sign-padding octet. Respect that RDP wire representation.
    if (bytes.empty() || bytes.size() > 5 ||
        (bytes.size() == 5 && bytes.front() != 0) ||
        (bytes.size() > 1 && bytes.front() == 0 &&
         (bytes[1] & 0x80U) == 0))
    {
        return false;
    }
    std::uint32_t result = 0;
    for (std::uint8_t byte : bytes)
    {
        result = (result << 8U) | byte;
    }
    value = result;
    return true;
}

[[nodiscard]] bool readDomainParameters(
    BerReader &reader, McsDomainParameters &parameters) noexcept
{
    std::span<const std::uint8_t> sequence;
    if (!reader.readValue(0x30, sequence))
    {
        return false;
    }
    BerReader integers{sequence};
    for (auto &number : parameters.values)
    {
        std::span<const std::uint8_t> encoded;
        if (!integers.readValue(0x02, encoded) ||
            !parseUnsignedDomainInteger(encoded, number))
        {
            return false;
        }
    }
    // Minimum/maximum protocolVersion may bracket 2, even when
    // individual parameter sets do not equal 2. Enforce the
    // negotiated result in mergeMcsDomainParameters(), not here.
    return integers.exhausted();
}

} // namespace

bool parseDataTpdu(std::span<const std::uint8_t> completeTpkt,
                   std::span<const std::uint8_t> &payload) noexcept
{
    payload = {};
    if (completeTpkt.size() < 8 || completeTpkt.size() > 65535U ||
        completeTpkt[0] != 3 || completeTpkt[1] != 0)
    {
        return false;
    }
    const std::size_t packetLength =
        (static_cast<std::size_t>(completeTpkt[2]) << 8U) |
        completeTpkt[3];
    if (packetLength != completeTpkt.size() ||
        completeTpkt[4] != 2 || completeTpkt[5] != 0xf0 ||
        completeTpkt[6] != 0x80)
    {
        return false;
    }
    payload = completeTpkt.subspan(7);
    return true;
}

McsParseResult parseMcsConnectInitial(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    McsParseResult result{};
    std::span<const std::uint8_t> data;
    if (!parseDataTpdu(completeTpkt, data))
    {
        result.error = McsError::InvalidDataTpdu;
        return result;
    }
    // BER APPLICATION 101, constructed: two-octet tag (0x7F,0x65).
    if (data.size() < 4 || data[0] != 0x7f || data[1] != 0x65)
    {
        result.error = McsError::InvalidConnectInitial;
        return result;
    }
    BerReader envelope{data.subspan(2)};
    std::size_t bodyLength = 0;
    if (!envelope.readLength(bodyLength) ||
        bodyLength != envelope.bytes.size() - envelope.offset)
    {
        result.error = McsError::InvalidConnectInitial;
        return result;
    }
    BerReader body{envelope.bytes.subspan(envelope.offset, bodyLength)};
    std::span<const std::uint8_t> selector;
    if (!body.readValue(0x04, selector) || selector.empty() ||
        selector.size() > 16 ||
        !body.readValue(0x04, selector) || selector.empty() ||
        selector.size() > 16)
    {
        result.error = McsError::InvalidConnectInitial;
        return result;
    }
    std::span<const std::uint8_t> upward;
    if (!body.readValue(0x01, upward) || upward.size() != 1 ||
        upward[0] == 0)
    {
        result.error = McsError::InvalidConnectInitial;
        return result;
    }
    if (!readDomainParameters(body, result.value.target) ||
        !readDomainParameters(body, result.value.minimum) ||
        !readDomainParameters(body, result.value.maximum))
    {
        result.error = McsError::InvalidDomainParameters;
        result.value = {};
        return result;
    }
    if (!body.readValue(0x04, result.value.gccUserData) ||
        result.value.gccUserData.empty() || !body.exhausted())
    {
        result.error = McsError::InvalidUserData;
        result.value = {};
        return result;
    }
    return result;
}

McsDomainMergeResult mergeMcsDomainParameters(
    const McsConnectInitial &requested) noexcept
{
    // MS-RDPBCGR 3.3.5.3.3, MergeDomainParameters. Use no untrusted
    // parameter to allocate buffers, register channels or admit users.
    const auto &target = requested.target.values;
    const auto &minimum = requested.minimum.values;
    const auto &maximum = requested.maximum.values;
    McsDomainMergeResult result{};
    auto &out = result.value.values;

    // maxChannelIds
    if (target[0] >= 4)
        out[0] = target[0];
    else if (maximum[0] >= 4)
        out[0] = 4;
    else
        return {};

    // maxUserIds
    if (target[1] >= 3)
        out[1] = target[1];
    else if (maximum[1] >= 3)
        out[1] = 3;
    else
        return {};

    out[2] = target[2]; // maxTokenIds

    // numPriorities (RDP uses one).
    if (minimum[3] > 1)
        return {};
    out[3] = 1;

    out[4] = target[4]; // minThroughput

    // maxHeight (RDP uses one).
    if (target[5] != 1 && minimum[5] > 1)
        return {};
    out[5] = 1;

    // maxMCSPDUsize
    if (target[6] >= 124)
    {
        if (target[6] <= 65528)
            out[6] = target[6];
        else if (minimum[6] >= 124 && minimum[6] <= 65528)
            out[6] = 65528;
        else
            return {};
    }
    else if (maximum[6] >= 124)
        out[6] = maximum[6];
    else
        return {};

    // protocolVersion: only version 2 is supported, either requested
    // directly or bracketed by client's minimum and maximum.
    if (target[7] != 2 && (minimum[7] > 2 || maximum[7] < 2))
        return {};
    out[7] = 2;
    result.accepted = true;
    return result;
}

} // namespace rdp_server::server::transport
