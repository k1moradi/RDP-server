// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_connect_response.h"
#include "gcc_conference_create.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
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

constexpr std::uint32_t kAllocatedGccNodeId = 1001U;
constexpr std::uint16_t kAllocatedIoChannelId = 1003U;
constexpr std::uint16_t kFirstAllocatedStaticChannelId = 1004U;

[[nodiscard]] bool validNegotiatedDomainForAllocation(
    const McsDomainParameters &domain) noexcept
{
    const auto &v = domain.values;
    return v[0] >= 4U && v[1] >= 3U && v[3] == 1U && v[5] == 1U &&
           v[6] >= 124U && v[6] <= 65528U && v[7] == 2U;
}

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


std::optional<McsConnectResponseAllocation>
planMcsConnectResponseAllocation(
    const McsDomainParameters &domain,
    const GccClientSettings &settings) noexcept
{
    static_assert(static_cast<std::uint32_t>(kFirstAllocatedStaticChannelId) +
                      kMaximumStaticChannelCount - 1U <=
                  std::numeric_limits<std::uint16_t>::max());
    const std::size_t count = settings.channelCount;
    if (!validNegotiatedDomainForAllocation(domain) ||
        count > kMaximumStaticChannelCount ||
        count + 3U > domain.values[0])
        return std::nullopt;
    McsConnectResponseAllocation out{};
    out.gccNodeId = kAllocatedGccNodeId;
    out.ioChannelId = kAllocatedIoChannelId;
    out.staticChannelCount = static_cast<std::uint8_t>(count);
    for (std::size_t i=0;i<count;++i)
        out.staticChannelIds[i] =
            static_cast<std::uint16_t>(kFirstAllocatedStaticChannelId+i);
    return out;
}

std::optional<McsConnectResponseAllocation>
planMcsConnectResponseAllocation(const McsConnectInitial &client) noexcept
{
    const auto d=mergeMcsDomainParameters(client);
    const auto g=parseGccConferenceCreate(client.gccUserData);
    if(!d||!g) return std::nullopt;
    return planMcsConnectResponseAllocation(d.value,g.settings);
}

bool matchesMcsSecurityNegotiationReplay(
    const GccClientSettings &settings,
    const SecurityNegotiationProvenance &p) noexcept
{
    return supportedEnhancedSecurityRequest(p.clientRequestedProtocols) &&
           (p.serverSelectedProtocol==kRdpProtocolSsl ||
            p.serverSelectedProtocol==kRdpProtocolHybrid) &&
           (p.clientRequestedProtocols & p.serverSelectedProtocol)!=0U &&
           settings.hasServerSelectedProtocol &&
           settings.serverSelectedProtocol==p.serverSelectedProtocol;
}

bool matchesMcsSecurityNegotiationReplay(
    const McsConnectInitial &client,
    std::uint32_t requested,
    std::uint32_t selected) noexcept
{
    const auto g=parseGccConferenceCreate(client.gccUserData);
    return g && matchesMcsSecurityNegotiationReplay(
        g.settings, SecurityNegotiationProvenance{requested,selected});
}

McsConnectResponse encodeMcsConnectResponseFromNegotiatedState(
    const McsDomainParameters &domain,
    std::size_t expectedCount,
    std::span<const std::uint16_t> channels,
    std::uint32_t nodeId,
    std::uint32_t requested) noexcept
{
    if (!validNegotiatedDomainForAllocation(domain) ||
        nodeId<1001U || nodeId>65536U ||
        !supportedEnhancedSecurityRequest(requested) ||
        channels.size()!=expectedCount ||
        channels.size()>kMaximumStaticChannelCount ||
        channels.size()+3U>domain.values[0]) return {};
    for(std::size_t i=0;i<channels.size();++i){
        if(channels[i]<1004U) return {};
        for(std::size_t j=0;j<i;++j) if(channels[j]==channels[i]) return {};
    }
    std::array<std::uint8_t,256> sb{}; Writer settings(sb);
    if(!encodeServerSettings(settings,channels,requested)) return {};
    std::array<std::uint8_t,512> gb{}; Writer gcc(gb);
    const auto off=nodeId-1001U;
    if(!gcc.raw({0x00,0x05,0x00,0x14,0x7c,0x00,0x01,0x2a,0x14,
                 static_cast<std::uint8_t>(off>>8U),
                 static_cast<std::uint8_t>(off),
                 0x01,0x01,0x00,0x01,0xc0,0x00,'M','c','D','n'}) ||
       !gcc.perLength(settings.written().size()) ||
       !gcc.bytes(settings.written())) return {};
    std::array<std::uint8_t,128> db{}; Writer dom(db);
    for(const auto v:domain.values) if(!dom.unsignedInteger(v)) return {};
    std::array<std::uint8_t,1024> bb{}; Writer body(bb);
    if(!body.raw({0x0a,0x01,0x00,0x02,0x01,0x00}) ||
       !body.byte(0x30) || !body.berLength(dom.written().size()) ||
       !body.bytes(dom.written()) || !body.byte(0x04) ||
       !body.berLength(gcc.written().size()) || !body.bytes(gcc.written()))
        return {};
    McsConnectResponse out{}; Writer tpkt(out.packet);
    const auto bs=body.written().size();
    const std::size_t bh=bs<128U?1U:bs<256U?2U:3U;
    const auto total=4U+3U+2U+bh+bs;
    if(total>out.packet.size()||total>65535U ||
       !tpkt.raw({0x03,0x00,static_cast<std::uint8_t>(total>>8U),
                  static_cast<std::uint8_t>(total),0x02,0xf0,0x80,0x7f,0x66}) ||
       !tpkt.berLength(bs) || !tpkt.bytes(body.written())) return {};
    out.length=tpkt.written().size();
    return out;
}

McsConnectResponse encodeMcsConnectResponse(
    const McsConnectInitial &client,
    std::span<const std::uint16_t> channels,
    std::uint32_t nodeId,
    std::uint32_t requested) noexcept
{
    const auto d=mergeMcsDomainParameters(client);
    const auto g=parseGccConferenceCreate(client.gccUserData);
    if(!d||!g) return {};
    return encodeMcsConnectResponseFromNegotiatedState(
        d.value,g.settings.channelCount,channels,nodeId,requested);
}

bool McsConnectResponseWriteGate::advanceReplySequence() noexcept
{
    if(replySequence_==std::numeric_limits<std::uint64_t>::max()) return false;
    ++replySequence_; return true;
}
bool McsConnectResponseWriteGate::advanceWriteSliceSequence() noexcept
{
    if(writeSliceSequence_==std::numeric_limits<std::uint64_t>::max()) return false;
    ++writeSliceSequence_; return true;
}
bool McsConnectResponseWriteGate::queue(const McsConnectResponse &r) noexcept
{
    if(closed_||delivered_||pending_||!r||
       !advanceReplySequence()||!advanceWriteSliceSequence()){
        close(); return false;
    }
    pending_=r; bytesWritten_=0U; return true;
}
McsConnectResponseWriteView McsConnectResponseWriteGate::pendingWrite() const noexcept
{
    if(closed_||delivered_||!pending_) return {};
    const auto b=pending_.bytes().subspan(bytesWritten_);
    return b.empty()?McsConnectResponseWriteView{}:
        McsConnectResponseWriteView{b,replySequence_,writeSliceSequence_};
}
McsConnectResponseWriteOutcome McsConnectResponseWriteGate::onBytesWritten(
    std::uint64_t reply,std::uint64_t slice,std::size_t accepted) noexcept
{
    if(closed_||delivered_||!pending_||reply==0U||reply!=replySequence_||
       slice==0U||slice!=writeSliceSequence_||
       accepted>pending_.length-bytesWritten_){
        close(); return McsConnectResponseWriteOutcome::Rejected;
    }
    bytesWritten_+=accepted;
    if(bytesWritten_!=pending_.length){
        if(accepted!=0U&&!advanceWriteSliceSequence()){
            close(); return McsConnectResponseWriteOutcome::Rejected;
        }
        return McsConnectResponseWriteOutcome::Pending;
    }
    pending_={}; bytesWritten_=0U; delivered_=true;
    return McsConnectResponseWriteOutcome::Delivered;
}
void McsConnectResponseWriteGate::close() noexcept
{
    pending_={}; bytesWritten_=0U; delivered_=false; closed_=true;
}

} // namespace rdp_server::server::transport
