// SPDX-License-Identifier: GPL-3.0-or-later
// Real MS-RDPBCGR connection-request fixture + negative wire-boundary tests.
#include "transport/tpkt_x224.h"

#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <vector>

using namespace rdp_server::server::transport;

namespace
{
std::vector<std::uint8_t> basicRequest()
{
    return {0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00};
}

void testBasicAndLegacy()
{
    const auto packet = basicRequest();
    const auto parsed = parseConnectionRequest(packet);
    assert(parsed);
    assert(parsed.request.hasNegotiation);
    assert(parsed.request.requestedProtocols == 3);
    assert(!parsed.request.hasCorrelation);
    assert(!parsed.request.hasClientPrefix);
    assert(connectionRequestLength(std::span(packet).first(4)) == packet.size());

    const std::array<std::uint8_t, 11> legacy{
        3, 0, 0, 11, 6, 0xe0, 0, 0, 0, 0, 0};
    const auto old = parseConnectionRequest(legacy);
    assert(old && !old.request.hasNegotiation);
    // The legacy handshake parses but MUST NOT be permitted to authenticate.
}

void testOfficialCookieExample()
{
    // MS-RDPBCGR section 4.1.1, 44 bytes: Cookie: mstshash=eltons
    const std::array<std::uint8_t, 44> withCookie{
        0x03,0x00,0x00,0x2c,0x27,0xe0,0,0,0,0,0,
        'C','o','o','k','i','e',':',' ','m','s','t','s','h','a','s','h',
        '=','e','l','t','o','n','s','\r','\n',
        0x01,0x00,0x08,0x00,0,0,0,0};
    const auto result = parseConnectionRequest(withCookie);
    assert(result);
    assert(result.request.hasClientPrefix);
    assert(result.request.hasNegotiation);
    assert(result.request.requestedProtocols == 0);
}

void testCorrelationAndPrefix()
{
    auto packet = basicRequest();
    packet.resize(55, 0);
    packet[3] = 55;
    packet[4] = 50;
    packet[12] = 0x08; // CORRELATION_INFO_PRESENT
    packet[19] = 0x06;
    packet[21] = 36;  // RDP_NEG_CORRELATION_INFO length
    packet[23] = 0x10; // Non-sensitive synthetic correlation identifier
    const auto parsed = parseConnectionRequest(packet);
    assert(parsed && parsed.request.hasCorrelation);
    packet[54] = 1; // reserved bytes must be zero
    assert(parseConnectionRequest(packet).error ==
           ConnectionError::InvalidCorrelation);
    packet[54] = 0;
    packet[12] = 0;
    assert(parseConnectionRequest(packet).error ==
           ConnectionError::InvalidNegotiation);
}

void testInvalidLengths()
{
    auto p = basicRequest();
    for (std::size_t length = 0; length < p.size(); ++length)
    {
        assert(!parseConnectionRequest(
            std::span(p.data(), length)));
    }
    p[0] = 4;
    assert(parseConnectionRequest(p).error ==
           ConnectionError::InvalidTpkt);
    p = basicRequest();
    p[3] = 0x12;
    assert(parseConnectionRequest(p).error ==
           ConnectionError::InvalidTpkt);
    p = basicRequest();
    p[4] = 6;
    assert(parseConnectionRequest(p).error ==
           ConnectionError::InvalidX224);
    p = basicRequest();
    p[5] = 0xf0;
    assert(parseConnectionRequest(p).error ==
           ConnectionError::InvalidX224);
    p = basicRequest();
    p[13] = 0x09;
    assert(parseConnectionRequest(p).error ==
           ConnectionError::InvalidNegotiation);
    p = basicRequest();
    p[18] = 0x01;
    const auto parsed = parseConnectionRequest(p);
    assert(parsed && parsed.request.requestedProtocols == 0x01000003);
    // Unknown protocol bits are preserved, never accepted by the probe.

    p = basicRequest();
    p[11] = 'C'; // No CRLF.
    assert(parseConnectionRequest(p).error ==
           ConnectionError::InvalidPrefix);
}

void testBoundedAdversarialMutation()
{
    const auto reference = basicRequest();
    for (std::size_t index = 0; index < reference.size(); ++index)
    {
        for (unsigned value = 0; value <= 255; ++value)
        {
            auto changed = reference;
            changed[index] = static_cast<std::uint8_t>(value);
            const auto result = parseConnectionRequest(changed);
            if (result)
            {
                // Every accepted input has an internally consistent header.
                assert(connectionRequestLength(
                    std::span(changed).first(4)) == changed.size());
            }
        }
    }
    const std::array<std::uint8_t, 4> oversized{3, 0, 1, 5};
    assert(!connectionRequestLength(oversized));
}
} // namespace

int main()
{
    testBasicAndLegacy();
    testOfficialCookieExample();
    testCorrelationAndPrefix();
    testInvalidLengths();
    testBoundedAdversarialMutation();
}
