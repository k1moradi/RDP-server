// SPDX-License-Identifier: GPL-3.0-or-later
// Byte-for-byte MCS Connect-Initial example from Microsoft MS-RDPBCGR 4.1.3:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151
#include "transport/mcs_connect_initial.h"
#include "transport/mcs_connect_response.h"
#include "transport/mcs_channel_connection.h"

#include <algorithm>
#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace rdp_server::server::transport;

namespace
{
// Shared verbatim Microsoft wire fixture used by the C++ unit tests and
// encrypted Python socket tests. Never fetch protocol fixtures at test time.
#ifndef OWNED_MCS_FIXTURE_PATH
#error OWNED_MCS_FIXTURE_PATH must point to the checked-in byte fixture
#endif

[[nodiscard]] std::vector<std::uint8_t> publishedFixture()
{
    std::ifstream fixture{OWNED_MCS_FIXTURE_PATH};
    assert(fixture.good());
    std::vector<std::uint8_t> result;
    std::string line;
    while (std::getline(fixture, line))
    {
        if (line.empty() || line.front() == '#')
        {
            continue;
        }
        std::istringstream input{line};
        unsigned int value = 0;
        while (input >> std::hex >> value)
        {
            assert(value <= 255);
            result.push_back(static_cast<std::uint8_t>(value));
        }
        assert(input.eof());
    }
    assert(result.size() == 416);
    return result;
}

void testRealMicrosoftConnectionEnvelope()
{
    const auto packet = publishedFixture();
    std::span<const std::uint8_t> userData;
    assert(parseDataTpdu(packet, userData));
    assert(userData.size() == 409);
    assert(userData[0] == 0x7f && userData[1] == 0x65);
    const auto parsed = parseMcsConnectInitial(packet);
    assert(parsed);
    assert(parsed.value.target.values[0] == 34);
    assert(parsed.value.target.values[6] == 65535);
    assert(parsed.value.target.values[7] == 2);
    assert(parsed.value.minimum.values[0] == 1);
    assert(parsed.value.minimum.values[6] == 1056);
    assert(parsed.value.maximum.values[0] == 65535);
    assert(parsed.value.maximum.values[7] == 2);
    assert(parsed.value.gccUserData.size() == 307);
    assert(parsed.value.gccUserData[0] == 0x00);
    assert(parsed.value.gccUserData[1] == 0x05);
}

void testInvalidOuterTransport()
{
    auto packet = publishedFixture();
    for (std::size_t offset = 0; offset < 8; ++offset)
    {
        assert(!parseMcsConnectInitial(std::span(packet).first(offset)));
    }
    auto corrupt = packet;
    corrupt[2] = 0;
    assert(!parseMcsConnectInitial(corrupt));
    corrupt = packet;
    corrupt[4] = 3;
    assert(!parseMcsConnectInitial(corrupt));
    corrupt = packet;
    corrupt[5] = 0xe0;
    assert(!parseMcsConnectInitial(corrupt));
    corrupt = packet;
    corrupt[6] = 0; // missing X.224 EOT
    assert(!parseMcsConnectInitial(corrupt));
    corrupt = packet;
    corrupt.push_back(0);
    assert(!parseMcsConnectInitial(corrupt));
}

void testBerLengthsAndType()
{
    auto packet = publishedFixture();
    packet[7] = 0x7e;
    assert(parseMcsConnectInitial(packet).error ==
           McsError::InvalidConnectInitial);
    packet = publishedFixture();
    packet[9] = 0x80; // indefinite BER length never allowed
    assert(!parseMcsConnectInitial(packet));
    packet = publishedFixture();
    packet[9] = 0x83; // exceeds 2 BER length octets allowed by TPKT
    assert(!parseMcsConnectInitial(packet));
    packet = publishedFixture();
    packet[11] ^= 1; // inconsistent declared outer BER body length
    assert(!parseMcsConnectInitial(packet));
    packet = publishedFixture();
    packet[12] = 0x05; // invalid domain selector tag
    assert(!parseMcsConnectInitial(packet));
    packet = publishedFixture();
    packet[21] = 0x31; // invalid DomainParameters tag
    assert(!parseMcsConnectInitial(packet));
    packet = publishedFixture();
    packet[24] = 0x80; // forbidden indefinite BER integer length
    assert(!parseMcsConnectInitial(packet));
}


void testMicrosoftDomainNegotiation()
{
    const auto packet = publishedFixture();
    const auto parsed = parseMcsConnectInitial(packet);
    assert(parsed);
    const auto result = mergeMcsDomainParameters(parsed.value);
    assert(result);
    // Published client target: 34 channels, 2 users, 65535 MCS PDU.
    // MS-RDPBCGR requires at least 3 users and clamps PDU to 65528
    // when the client's minimum permits it.
    const std::array<std::uint32_t, 8> expected{
        34, 3, 0, 1, 0, 1, 65528, 2};
    assert(result.value.values == expected);

    // Successful fallback to target/min/max rules, without allocating
    // or registering any domain/channel from the merged 32-bit values.
    McsConnectInitial client{};
    client.target.values = {3, 2, 9, 7, 17, 2, 123, 3};
    client.minimum.values = {0, 0, 0, 1, 0, 1, 124, 1};
    client.maximum.values = {4, 3, 0, 1, 0, 1, 1056, 4};
    const auto fallback = mergeMcsDomainParameters(client);
    assert(fallback);
    const std::array<std::uint32_t, 8> fallbackExpected{
        4, 3, 9, 1, 17, 1, 1056, 2};
    assert(fallback.value.values == fallbackExpected);

    // A valid BER Connect-Initial can carry min/max protocol versions
    // other than 2, provided the final negotiated version is 2.
    auto varied = packet;
    varied[47] = 3;  // target protocolVersion
    varied[74] = 1;  // minimum protocolVersion
    varied[104] = 3; // maximum protocolVersion
    const auto parsedVaried = parseMcsConnectInitial(varied);
    assert(parsedVaried);
    assert(mergeMcsDomainParameters(parsedVaried.value));
    assert(mergeMcsDomainParameters(parsedVaried.value).value.values[7] == 2);
}

void testMcsDomainNegotiationRejections()
{
    McsConnectInitial valid{};
    valid.target.values = {34, 3, 0, 1, 0, 1, 65528, 2};
    valid.minimum.values = {1, 1, 0, 1, 0, 1, 124, 1};
    valid.maximum.values = {34, 3, 0, 1, 0, 1, 65528, 3};
    assert(mergeMcsDomainParameters(valid));

    // Every normative failure branch rejects with an empty result,
    // never a partially initialized domain configuration.
    auto mustReject = [&](const McsConnectInitial &invalid)
    {
        const auto rejected = mergeMcsDomainParameters(invalid);
        assert(!rejected);
        assert((rejected.value.values ==
                std::array<std::uint32_t, 8>{}));
    };
    auto v = valid;
    v.target.values[0] = 3;
    v.maximum.values[0] = 3;
    mustReject(v);
    v = valid;
    v.target.values[1] = 2;
    v.maximum.values[1] = 2;
    mustReject(v);
    v = valid;
    v.minimum.values[3] = 2;
    mustReject(v);
    v = valid;
    v.target.values[5] = 2;
    v.minimum.values[5] = 2;
    mustReject(v);
    v = valid;
    v.target.values[6] = 65529;
    v.minimum.values[6] = 123;
    mustReject(v);
    v = valid;
    v.target.values[6] = 123;
    v.maximum.values[6] = 123;
    mustReject(v);
    v = valid;
    v.target.values[7] = 3;
    v.minimum.values[7] = 3;
    mustReject(v);
    v = valid;
    v.target.values[7] = 3;
    v.maximum.values[7] = 1;
    mustReject(v);

    // Out-of-target versions are syntactically BER-valid but must not
    // become an accepted RDP version after domain negotiation.
    auto packet = publishedFixture();
    packet[47] = 3;
    packet[74] = 3;
    packet[104] = 3;
    const auto parsed = parseMcsConnectInitial(packet);
    assert(parsed);
    mustReject(parsed.value);
}


void testMcsResponseWire()
{
    // Independent golden packet from MS-RDPBCGR 4.1.4: same GCC/MCS
    // envelope, but legal Enhanced TLS SC_SECURITY (zero/no RC4 cert).
    const auto fixture = publishedFixture();
    const auto parsed = parseMcsConnectInitial(fixture);
    assert(parsed);
    constexpr std::array<std::uint16_t, 3> ids{1004, 1005, 1006};
    const auto encoded = encodeMcsConnectResponse(parsed.value, ids, 31219, 1);
    assert(encoded);
    constexpr std::array<std::uint8_t, 108> golden{
        0x03, 0x00, 0x00, 0x6c, 0x02, 0xf0, 0x80,
        0x7f, 0x66, 0x62,
        0x0a, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x30, 0x1a,
        0x02, 0x01, 0x22, 0x02, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
        0x02, 0x03, 0x00, 0xff, 0xf8, 0x02, 0x01, 0x02,
        0x04, 0x3e,
        0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x2a,
        0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0,
        0x00, 'M', 'c', 'D', 'n', 0x28,
        0x01, 0x0c, 0x0c, 0x00,
        0x04, 0x00, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x03, 0x0c, 0x10, 0x00,
        0xeb, 0x03, 0x03, 0x00,
        0xec, 0x03, 0xed, 0x03, 0xee, 0x03, 0x00, 0x00,
        0x02, 0x0c, 0x0c, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    assert(encoded.length == golden.size());
    assert(std::equal(encoded.bytes().begin(), encoded.bytes().end(),
                      golden.begin()));
    std::span<const std::uint8_t> mcsPayload;
    assert(parseDataTpdu(encoded.bytes(), mcsPayload));
    assert(mcsPayload[0] == 0x7f && mcsPayload[1] == 0x66);

    const auto upperNode =
        encodeMcsConnectResponse(parsed.value, ids, 65536, 1);
    assert(upperNode);
    assert(upperNode.bytes()[55] == 0xfc);
    assert(upperNode.bytes()[56] == 0x17);

    // Positive BER integer >= 2^31 MUST include a leading sign octet.
    auto modified = parsed.value;
    modified.target.values[2] = 0x80000000U;
    const auto highToken =
        encodeMcsConnectResponse(modified, ids, 31219, 1);
    assert(highToken);
    constexpr std::array<std::uint8_t, 7> encodedToken{
        0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00};
    assert(std::search(highToken.bytes().begin(), highToken.bytes().end(),
                       encodedToken.begin(), encodedToken.end()) !=
           highToken.bytes().end());
    assert(parseDataTpdu(highToken.bytes(), mcsPayload));
}

void testMcsResponseRejectInvalidInputs()
{
    const auto fixture = publishedFixture();
    const auto parsed = parseMcsConnectInitial(fixture);
    assert(parsed);
    constexpr std::array<std::uint16_t, 3> ids{1004, 1005, 1006};
    const auto reject = [](const McsConnectResponse &r)
    {
        assert(!r);
        assert(r.length == 0 && r.bytes().empty());
    };
    reject(encodeMcsConnectResponse(parsed.value, ids, 1000, 1));
    reject(encodeMcsConnectResponse(parsed.value, ids, 65537, 1));
    reject(encodeMcsConnectResponse(parsed.value, ids, 31219, 0));
    reject(encodeMcsConnectResponse(parsed.value, ids, 31219, 2));
    reject(encodeMcsConnectResponse(parsed.value, ids, 31219, 3));
    reject(encodeMcsConnectResponse(parsed.value,
                                    std::span(ids).first(2), 31219, 1));
    constexpr std::array<std::uint16_t, 3> duplicate{1004, 1004, 1006};
    constexpr std::array<std::uint16_t, 3> reserved{1003, 1005, 1006};
    reject(encodeMcsConnectResponse(parsed.value, duplicate, 31219, 1));
    reject(encodeMcsConnectResponse(parsed.value, reserved, 31219, 1));

    McsConnectInitial bad = parsed.value;
    bad.minimum.values[3] = 2; // unsupported priority count
    reject(encodeMcsConnectResponse(bad, ids, 31219, 1));
    bad = parsed.value;
    bad.target.values[7] = 3;
    bad.minimum.values[7] = 3;
    reject(encodeMcsConnectResponse(bad, ids, 31219, 1));
    bad = parsed.value;
    bad.gccUserData = {}; // invalid GCC
    reject(encodeMcsConnectResponse(bad, ids, 31219, 1));
    bad = parsed.value;
    bad.target.values[0] = 4; // cannot represent 3 channels + 3 IDs
    reject(encodeMcsConnectResponse(bad, ids, 31219, 1));
}

[[nodiscard]] std::vector<std::uint8_t> frameDomainPdu(
    std::span<const std::uint8_t> payload)
{
    assert(payload.size() <= 65528);
    const auto length = payload.size() + 7U;
    std::vector<std::uint8_t> frame{
        3, 0, static_cast<std::uint8_t>(length >> 8U),
        static_cast<std::uint8_t>(length),
        2, 0xf0, 0x80};
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

void testMcsErectDomainRequest()
{
    // MS-RDPBCGR 4.1.5 exact published Client MCS Erect Domain PDU.
    constexpr std::array<std::uint8_t, 12> golden{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x04, 0x01, 0x00, 0x01, 0x00};
    const auto parsed = parseMcsChannelRequest(golden);
    assert(parsed);
    assert(parsed.request.kind == McsChannelRequestKind::ErectDomain);
    assert(parsed.request.subHeight == 0 && parsed.request.subInterval == 0);
    assert(parsed.request.initiator == 0 && parsed.request.channelId == 0);

    // Aligned PER unconstrained INTEGERs can use 1..4 octets; do not
    // invent a rule limiting valid ErectDomain values to zero.
    constexpr std::array<std::uint8_t, 8> wider{
        0x04, 0x02, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03};
    const auto expanded = parseMcsChannelRequest(frameDomainPdu(wider));
    assert(expanded);
    assert(expanded.request.subHeight == 256);
    assert(expanded.request.subInterval == 0x010203U);

    for (std::size_t size = 0; size < golden.size(); ++size)
        assert(!parseMcsChannelRequest(std::span(golden).first(size)));
    auto appended = frameDomainPdu(
        std::span(golden).subspan(7));
    appended.push_back(0);
    assert(!parseMcsChannelRequest(appended));

    constexpr std::array<std::uint8_t, 5> zeroLength{
        0x04, 0x00, 0x00, 0x01, 0x00};
    constexpr std::array<std::uint8_t, 5> exceedsRemaining{
        0x04, 0x03, 0x00, 0x01, 0x00};
    constexpr std::array<std::uint8_t, 7> nonminimal{
        0x04, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00};
    constexpr std::array<std::uint8_t, 5> oversized{
        0x04, 0x05, 0x00, 0x01, 0x00};
    constexpr std::array<std::uint8_t, 4> missingSecond{
        0x04, 0x01, 0x00, 0x01};
    for (auto bytes : {
             frameDomainPdu(zeroLength),
             frameDomainPdu(exceedsRemaining),
             frameDomainPdu(nonminimal),
             frameDomainPdu(oversized),
             frameDomainPdu(missingSecond)})
    {
        const auto failure = parseMcsChannelRequest(bytes);
        assert(!failure);
        assert(failure.error == McsChannelParseError::InvalidPerValue);
        assert(failure.request.kind == McsChannelRequestKind::None);
    }
}

void testMcsAttachUserRequest()
{
    // MS-RDPBCGR 4.1.6 published TPKT/X.224/AttachUserRequest.
    constexpr std::array<std::uint8_t, 8> golden{
        0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, 0x28};
    const auto parsed = parseMcsChannelRequest(golden);
    assert(parsed);
    assert(parsed.request.kind == McsChannelRequestKind::AttachUser);
    assert(parsed.request.subHeight == 0 && parsed.request.initiator == 0);

    for (std::size_t size = 0; size < golden.size(); ++size)
        assert(!parseMcsChannelRequest(std::span(golden).first(size)));
    const std::array<std::uint8_t, 2> surplus{0x28, 0x00};
    const auto invalid = parseMcsChannelRequest(frameDomainPdu(surplus));
    assert(!invalid);
    assert(invalid.error == McsChannelParseError::InvalidDomainPdu);

    auto corrupted = golden;
    corrupted[3] = 9; // mismatched declared TPKT length
    assert(parseMcsChannelRequest(corrupted).error ==
           McsChannelParseError::InvalidTransport);
    corrupted = golden;
    corrupted[5] = 0xe0; // X.224 CR, not Data TPDU
    assert(parseMcsChannelRequest(corrupted).error ==
           McsChannelParseError::InvalidTransport);
    corrupted = golden;
    corrupted[7] = 0x29; // nonzero choice padding/extension bit
    assert(parseMcsChannelRequest(corrupted).error ==
           McsChannelParseError::InvalidDomainPdu);
}

void testMcsChannelJoinRequest()
{
    // MS-RDPBCGR 4.1.8.2.1 exact published Channel 1003 packet.
    constexpr std::array<std::uint8_t, 12> golden{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    const auto parsed = parseMcsChannelRequest(golden);
    assert(parsed);
    assert(parsed.request.kind == McsChannelRequestKind::ChannelJoin);
    assert(parsed.request.initiator == 1007);
    assert(parsed.request.channelId == 1003);
    assert(parsed.request.subHeight == 0);

    constexpr std::array<std::uint8_t, 5> rdpsnd{
        0x38, 0x00, 0x06, 0x03, 0xee};
    const auto sound = parseMcsChannelRequest(frameDomainPdu(rdpsnd));
    assert(sound && sound.request.channelId == 1006);
    assert(sound.request.initiator == 1007);

    // Largest offset representable by a T.125 UserId (65536)
    // matches the limit used by the existing GCC response encoder.
    constexpr std::array<std::uint8_t, 5> topUser{
        0x38, 0xfc, 0x17, 0x03, 0xeb};
    const auto maximum = parseMcsChannelRequest(frameDomainPdu(topUser));
    assert(maximum && maximum.request.initiator == 65536);

    // This is syntax only. A wire request to join channel 0 can be
    // decoded, but is NOT proof the channel is allocated or joinable.
    constexpr std::array<std::uint8_t, 5> unassigned{
        0x38, 0x00, 0x06, 0x00, 0x00};
    const auto zeroChannel =
        parseMcsChannelRequest(frameDomainPdu(unassigned));
    assert(zeroChannel && zeroChannel.request.channelId == 0);

    for (std::size_t size = 0; size < golden.size(); ++size)
        assert(!parseMcsChannelRequest(std::span(golden).first(size)));
    constexpr std::array<std::uint8_t, 5> overflowInitiator{
        0x38, 0xff, 0xff, 0x03, 0xeb};
    assert(parseMcsChannelRequest(frameDomainPdu(overflowInitiator)).error ==
           McsChannelParseError::InvalidPerValue);

    constexpr std::array<std::uint8_t, 4> shortJoin{
        0x38, 0x00, 0x06, 0x03};
    constexpr std::array<std::uint8_t, 6> trailingJoin{
        0x38, 0x00, 0x06, 0x03, 0xeb, 0x00};
    for (const auto frame : {frameDomainPdu(shortJoin),
                             frameDomainPdu(trailingJoin)})
        assert(parseMcsChannelRequest(frame).error ==
               McsChannelParseError::InvalidDomainPdu);
    constexpr std::array<std::uint8_t, 5> confirmWrongDirection{
        0x3e, 0x00, 0x06, 0x03, 0xeb};
    assert(parseMcsChannelRequest(frameDomainPdu(confirmWrongDirection)).error
           == McsChannelParseError::InvalidDomainPdu);
}

void testInputMutationsRemainBounded()
{
    const auto baseline = publishedFixture();
    for (std::size_t position = 0; position < baseline.size(); ++position)
    {
        auto mutated = baseline;
        mutated[position] ^= 0x80;
        const auto result = parseMcsConnectInitial(mutated);
        if (result)
        {
            assert(result.value.gccUserData.data() >= mutated.data());
            assert(result.value.gccUserData.size() <= mutated.size());
        }
    }
}

} // namespace

struct McsTestCase
{
    std::string_view name;
    void (*run)();
};

// No new executable or fixture owner; expose independent behaviors in
// the canonical CTest registry. Unknown case names must not pass.
constexpr std::array<McsTestCase, 11> kMcsTestCases{{
    {"mcs-envelope-microsoft", &testRealMicrosoftConnectionEnvelope},
    {"mcs-envelope-tpkt-errors", &testInvalidOuterTransport},
    {"mcs-envelope-ber-errors", &testBerLengthsAndType},
    {"mcs-envelope-mutations", &testInputMutationsRemainBounded},
    {"mcs-domain-merge", &testMicrosoftDomainNegotiation},
    {"mcs-domain-rejections", &testMcsDomainNegotiationRejections},
    {"mcs-response-wire", &testMcsResponseWire},
    {"mcs-response-rejections", &testMcsResponseRejectInvalidInputs},
    {"mcs-erect-request", &testMcsErectDomainRequest},
    {"mcs-attach-request", &testMcsAttachUserRequest},
    {"mcs-channel-join-request", &testMcsChannelJoinRequest},
}};

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        for (const auto &test : kMcsTestCases)
            test.run();
        return 0;
    }
    if (argc != 2)
        return 2;
    for (const auto &test : kMcsTestCases)
    {
        if (std::string_view{argv[1]} == test.name)
        {
            test.run();
            return 0;
        }
    }
    return 2;
}
