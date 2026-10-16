// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_connect_response.h"
#include "gcc_conference_create.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>

namespace rdp_server::server::transport
{
namespace
{
// Tiny checked, allocation-free encoder. Never emit a partly constructed
// response on error; only the final successful result exposes bytes.
class Writer
{
public:
    explicit Writer(std::span<std::uint8_t> buffer) noexcept : buffer_(buffer) {}

    [[nodiscard]] bool byte(std::uint8_t value) noexcept
    {
        if (size_ == buffer_.size())
            return false;
        buffer_[size_++] = value;
        return true;
    }

    [[nodiscard]] bool raw(std::initializer_list<std::uint8_t> values) noexcept
    {
        if (values.size() > buffer_.size() - size_)
            return false;
        for (const auto value : values)
            buffer_[size_++] = value;
        return true;
    }

    [[nodiscard]] bool bytes(std::span<const std::uint8_t> values) noexcept
    {
        if (values.size() > buffer_.size() - size_)
            return false;
        for (const auto value : values)
            buffer_[size_++] = value;
        return true;
    }

    [[nodiscard]] bool le16(std::uint16_t value) noexcept
    {
        return byte(static_cast<std::uint8_t>(value)) &&
               byte(static_cast<std::uint8_t>(value >> 8U));
    }

    [[nodiscard]] bool le32(std::uint32_t value) noexcept
    {
        return le16(static_cast<std::uint16_t>(value)) &&
               le16(static_cast<std::uint16_t>(value >> 16U));
    }

    [[nodiscard]] bool berLength(std::size_t length) noexcept
    {
        if (length < 128)
            return byte(static_cast<std::uint8_t>(length));
        if (length < 256)
            return raw({0x81, static_cast<std::uint8_t>(length)});
        if (length < 65536)
            return raw({0x82, static_cast<std::uint8_t>(length >> 8U),
                        static_cast<std::uint8_t>(length)});
        return false;
    }

    [[nodiscard]] bool perLength(std::size_t length) noexcept
    {
        if (length < 128)
            return byte(static_cast<std::uint8_t>(length));
        if (length < 16384)
            return raw({static_cast<std::uint8_t>(0x80U | (length >> 8U)),
                        static_cast<std::uint8_t>(length)});
        return false; // refuse PER fragmentation.
    }

    // ASN.1 BER INTEGER: nonnegative, minimal, include sign octet if
    // high-order content bit would otherwise indicate a negative value.
    [[nodiscard]] bool unsignedInteger(std::uint32_t value) noexcept
    {
        std::array<std::uint8_t, 5> data{};
        std::size_t start = data.size();
        do
        {
            data[--start] = static_cast<std::uint8_t>(value);
            value >>= 8U;
        } while (value != 0);
        if ((data[start] & 0x80U) != 0)
            data[--start] = 0;
        return byte(0x02) && byte(static_cast<std::uint8_t>(
                   data.size() - start)) &&
               bytes(std::span(data).subspan(start));
    }

    [[nodiscard]] std::span<const std::uint8_t> written() const noexcept
    {
        return buffer_.first(size_);
    }

private:
    std::span<std::uint8_t> buffer_;
    std::size_t size_{};
};

[[nodiscard]] bool supportedEnhancedSecurityRequest(
    std::uint32_t clientRequestedProtocols) noexcept
{
    constexpr std::uint32_t supported =
        kRdpProtocolSsl | kRdpProtocolHybrid;
    return clientRequestedProtocols != 0U &&
           (clientRequestedProtocols & ~supported) == 0U;
}

[[nodiscard]] bool encodeServerSettings(
    Writer &out, std::span<const std::uint16_t> channels,
    std::uint32_t clientRequestedProtocols) noexcept
{
    // MS-RDPBCGR 2.2.1.4.2: SC_CORE replays the client's COMPLETE
    // requestedProtocols mask; it is not the server's selected protocol.
    if (!out.le16(0x0c01) || !out.le16(12) ||
        !out.le32(0x00080004) || !out.le32(clientRequestedProtocols))
        return false;

    // MS-RDPBCGR 2.2.1.4.4: SC_NET, I/O channel 1003; ordered
    // independently supplied static channel IDs and mandatory odd pad.
    const auto count = channels.size();
    const auto length = static_cast<std::uint16_t>(
        8U + 2U * count + (count % 2U == 0 ? 0U : 2U));
    if (!out.le16(0x0c03) || !out.le16(length) ||
        !out.le16(1003) || !out.le16(static_cast<std::uint16_t>(count)))
        return false;
    for (const auto id : channels)
    {
        if (!out.le16(id))
            return false;
    }
    if ((count % 2U) != 0 && !out.le16(0))
        return false;

    // MS-RDPBCGR 2.2.1.4.3: Enhanced Security (TLS).
    // NO RC4, serverRandom or proprietary RDP certificate in SC_SECURITY.
    return out.le16(0x0c02) && out.le16(12) &&
           out.le32(0) && out.le32(0);
}
} // namespace

bool matchesMcsSecurityNegotiationReplay(
    const McsConnectInitial &client,
    std::uint32_t clientRequestedProtocols,
    std::uint32_t serverSelectedProtocol) noexcept
{
    const auto gcc = parseGccConferenceCreate(client.gccUserData);
    if (!gcc ||
        !supportedEnhancedSecurityRequest(clientRequestedProtocols) ||
        (serverSelectedProtocol != kRdpProtocolSsl &&
         serverSelectedProtocol != kRdpProtocolHybrid) ||
        (clientRequestedProtocols & serverSelectedProtocol) == 0U ||
        !gcc.settings.hasServerSelectedProtocol)
    {
        return false;
    }
    return gcc.settings.serverSelectedProtocol == serverSelectedProtocol;
}

McsConnectResponse encodeMcsConnectResponse(
    const McsConnectInitial &client,
    std::span<const std::uint16_t> staticChannelIds,
    std::uint32_t gccNodeId,
    std::uint32_t clientRequestedProtocols) noexcept
{
    const auto domain = mergeMcsDomainParameters(client);
    const auto gcc = parseGccConferenceCreate(client.gccUserData);
    if (!domain || !gcc || gccNodeId < 1001 || gccNodeId > 65536 ||
        !supportedEnhancedSecurityRequest(clientRequestedProtocols) ||
        staticChannelIds.size() != gcc.settings.channelCount ||
        staticChannelIds.size() > kMaximumStaticChannelCount ||
        staticChannelIds.size() + 3U > domain.value.values[0])
        return {};

    // IDs belong to an eventual, independently authorized MCS domain.
    // Reject duplicates and reserved/user/I/O channel identifiers.
    for (std::size_t i = 0; i < staticChannelIds.size(); ++i)
    {
        if (staticChannelIds[i] < 1004)
            return {};
        for (std::size_t j = 0; j < i; ++j)
        {
            if (staticChannelIds[j] == staticChannelIds[i])
                return {};
        }
    }

    std::array<std::uint8_t, 256> settingBuffer{};
    Writer settings(settingBuffer);
    if (!encodeServerSettings(
            settings, staticChannelIds, clientRequestedProtocols))
        return {};

    // T.124 GCC ConferenceCreateResponse, one H.221 server userData
    // set with key "McDn", PER nodeID offset by 1001. The 0x2a
    // connectPDU length is the value used in MS-RDPBCGR 4.1.4;
    // clients explicitly ignore this outer field.
    std::array<std::uint8_t, 512> gccBuffer{};
    Writer gccResponse(gccBuffer);
    const auto nodeOffset = gccNodeId - 1001U;
    if (!gccResponse.raw({0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x2a,
                          0x14,
                          static_cast<std::uint8_t>(nodeOffset >> 8U),
                          static_cast<std::uint8_t>(nodeOffset),
                          0x01, 0x01, 0x00, 0x01, 0xc0, 0x00,
                          'M', 'c', 'D', 'n'}) ||
        !gccResponse.perLength(settings.written().size()) ||
        !gccResponse.bytes(settings.written()))
        return {};

    std::array<std::uint8_t, 128> domainBuffer{};
    Writer encodedDomain(domainBuffer);
    for (const auto value : domain.value.values)
    {
        if (!encodedDomain.unsignedInteger(value))
            return {};
    }

    std::array<std::uint8_t, 1024> bodyBuffer{};
    Writer body(bodyBuffer);
    if (!body.raw({0x0a, 0x01, 0x00, 0x02, 0x01, 0x00}) ||
        !body.byte(0x30) ||
        !body.berLength(encodedDomain.written().size()) ||
        !body.bytes(encodedDomain.written()) ||
        !body.byte(0x04) ||
        !body.berLength(gccResponse.written().size()) ||
        !body.bytes(gccResponse.written()))
        return {};

    McsConnectResponse output{};
    Writer tpkt(output.packet);
    const auto bodySize = body.written().size();
    const std::size_t berHeader = bodySize < 128 ? 1 :
                                  bodySize < 256 ? 2 : 3;
    const auto total = 4U + 3U + 2U + berHeader + bodySize;
    if (total > output.packet.size() || total > 65535 ||
        !tpkt.raw({0x03, 0x00, static_cast<std::uint8_t>(total >> 8U),
                   static_cast<std::uint8_t>(total),
                   0x02, 0xf0, 0x80, 0x7f, 0x66}) ||
        !tpkt.berLength(bodySize) ||
        !tpkt.bytes(body.written()))
        return {};
    output.length = tpkt.written().size();
    return output;
}

} // namespace rdp_server::server::transport
