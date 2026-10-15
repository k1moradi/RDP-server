// SPDX-License-Identifier: GPL-3.0-or-later
// Byte-for-byte MCS Connect-Initial example from Microsoft MS-RDPBCGR 4.1.3:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151
#include "transport/mcs_connect_initial.h"
#include "transport/mcs_connect_response.h"
#include "transport/mcs_channel_connection.h"
#include "transport/gcc_conference_create.h"

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
        0x04, 0x02, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03};
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


void testMcsAttachConfirmWire()
{
    // Independent published Microsoft MS-RDPBCGR 4.1.7 example.
    constexpr std::array<std::uint8_t, 11> golden{
        0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80,
        0x2e, 0x00, 0x00, 0x06};
    const auto reply = encodeMcsAttachUserConfirm(1007);
    assert(reply && reply.length == golden.size());
    assert(std::equal(reply.bytes().begin(), reply.bytes().end(),
                      golden.begin()));
    std::span<const std::uint8_t> payload;
    assert(parseDataTpdu(reply.bytes(), payload));
    assert(payload.size() == 4);
    // Confirm direction can never be interpreted as AttachUserRequest.
    assert(!parseMcsChannelRequest(reply.bytes()));

    const auto min = encodeMcsAttachUserConfirm(1001);
    assert(min && min.bytes()[9] == 0 && min.bytes()[10] == 0);
    const auto max = encodeMcsAttachUserConfirm(65536);
    assert(max && max.bytes()[9] == 0xfc && max.bytes()[10] == 0x17);
    for (const auto id : {0U, 1U, 1000U, 65537U, 0xffffffffU})
    {
        const auto invalid = encodeMcsAttachUserConfirm(id);
        assert(!invalid && invalid.bytes().empty() &&
               invalid.length == 0);
    }
}

void testMcsChannelJoinConfirmWireAndRejections()
{
    // MS-RDPBCGR 4.1.8.2.1 client request and 4.1.8.2.2
    // independently specified server Join Confirm for I/O 1003.
    constexpr std::array<std::uint8_t, 12> requestBytes{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 15> golden{
        0x03, 0x00, 0x00, 0x0f, 0x02, 0xf0, 0x80,
        0x3e, 0x00, 0x00, 0x06, 0x03, 0xeb, 0x03, 0xeb};
    const auto request = parseMcsChannelRequest(requestBytes);
    assert(request && request.request.kind ==
           McsChannelRequestKind::ChannelJoin);
    constexpr std::array<std::uint16_t, 5> permitted{
        1007, 1003, 1004, 1005, 1006};
    const auto reply =
        encodeMcsChannelJoinConfirm(request.request, 1007, permitted);
    assert(reply && reply.length == golden.size());
    assert(std::equal(reply.bytes().begin(), reply.bytes().end(),
                      golden.begin()));
    std::span<const std::uint8_t> payload;
    assert(parseDataTpdu(reply.bytes(), payload));
    assert(payload.size() == 8);
    assert(!parseMcsChannelRequest(reply.bytes()));

    // MS-RDPBCGR 4.1.8.3.2 rdpdr channel 1004.
    auto different = request.request;
    different.channelId = 1004;
    const auto rdpdr = encodeMcsChannelJoinConfirm(different, 1007, permitted);
    assert(rdpdr && rdpdr.bytes()[12] == 0xec &&
           rdpdr.bytes()[14] == 0xec);
    // The maximum encodable UserId is 65536, consistent with
    // the request decoder's 16-bit PER UserId offset.
    different.initiator = 65536;
    const auto maximum = encodeMcsChannelJoinConfirm(different, 65536,
                                                      permitted);
    assert(maximum && maximum.bytes()[9] == 0xfc &&
           maximum.bytes()[10] == 0x17);

    const auto reject = [](const McsChannelConfirm &response)
    {
        assert(!response && response.bytes().empty() &&
               response.length == 0);
    };
    reject(encodeMcsChannelJoinConfirm(request.request, 1006, permitted));
    reject(encodeMcsChannelJoinConfirm(request.request, 1000, permitted));
    reject(encodeMcsChannelJoinConfirm(request.request, 65537, permitted));
    reject(encodeMcsChannelJoinConfirm(
        request.request, 1007, std::span(permitted).first(1)));
    reject(encodeMcsChannelJoinConfirm(
        request.request, 1007, std::span<const std::uint16_t>{}));
    constexpr std::array<std::uint16_t, 2> duplicated{1003, 1003};
    reject(encodeMcsChannelJoinConfirm(request.request, 1007, duplicated));
    constexpr std::array<std::uint16_t, 3> unrelatedDuplicate{
        1003, 1004, 1004};
    reject(encodeMcsChannelJoinConfirm(request.request, 1007,
                                       unrelatedDuplicate));
    constexpr std::array<std::uint16_t, 2> zeroAllocation{1003, 0};
    reject(encodeMcsChannelJoinConfirm(request.request, 1007,
                                       zeroAllocation));
    std::array<std::uint16_t, kMaximumStaticChannelCount + 3> overbudget{};
    overbudget.fill(1003);
    reject(encodeMcsChannelJoinConfirm(request.request, 1007, overbudget));

    auto invalid = request.request;
    invalid.kind = McsChannelRequestKind::AttachUser;
    reject(encodeMcsChannelJoinConfirm(invalid, 1007, permitted));
    invalid = request.request;
    invalid.channelId = 0;
    reject(encodeMcsChannelJoinConfirm(invalid, 1007, permitted));
    invalid = request.request;
    invalid.subHeight = 1; // contradictory request fields
    reject(encodeMcsChannelJoinConfirm(invalid, 1007, permitted));
}
void testMcsDisconnectProviderWire()
{
    // Independent MS-RDPBCGR 4.2.3 example: user-requested.
    constexpr std::array<std::uint8_t, 9> userRequested{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};
    constexpr std::array<std::uint8_t, 9> providerInitiated{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x20, 0x80};
    const auto user = encodeMcsDisconnectProviderUltimatum(
        McsDisconnectReason::UserRequested);
    const auto provider = encodeMcsDisconnectProviderUltimatum(
        McsDisconnectReason::ProviderInitiated);
    assert(user && *user == userRequested);
    assert(provider && *provider == providerInitiated);

    std::span<const std::uint8_t> payload;
    assert(parseDataTpdu(*user, payload));
    assert(payload.size() == 2 && payload[0] == 0x21 &&
           payload[1] == 0x80);
    assert(parseDataTpdu(*provider, payload));
    assert(payload.size() == 2 && payload[0] == 0x20 &&
           payload[1] == 0x80);
    for (const auto &packet : {userRequested, providerInitiated})
    {
        const auto parsed = parseMcsChannelRequest(packet);
        assert(parsed);
        assert(parsed.request.kind ==
               McsChannelRequestKind::DisconnectProviderUltimatum);
        assert(parsed.request.initiator == 0 && parsed.request.channelId == 0);
    }
}

void testMcsDisconnectProviderRejections()
{
    // Only reason 1 and 3 may be emitted; test every possible enum byte.
    for (unsigned int rawReason = 0; rawReason < 256; ++rawReason)
    {
        const auto encoded = encodeMcsDisconnectProviderUltimatum(
            static_cast<McsDisconnectReason>(rawReason));
        assert(encoded.has_value() ==
               (rawReason == 1 || rawReason == 3));
    }

    constexpr std::array<std::uint8_t, 9> baseline{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};
    // Receiving servers MUST ignore even reserved peer reason values.
    for (const auto first : {0x20U, 0x21U})
    {
        for (const auto second : {0x00U, 0x80U})
        {
            auto received = baseline;
            received[7] = static_cast<std::uint8_t>(first);
            received[8] = static_cast<std::uint8_t>(second);
            const auto parsed = parseMcsChannelRequest(received);
            assert(parsed && parsed.request.kind ==
                   McsChannelRequestKind::DisconnectProviderUltimatum);
            assert(parsed.request.subHeight == 0 &&
                   parsed.request.subInterval == 0);
        }
    }

    // Never admit partial or coalesced TPKT records.
    for (std::size_t size = 0; size < baseline.size(); ++size)
        assert(!parseMcsChannelRequest(std::span(baseline).first(size)));
    for (const auto invalidPayload :
         {std::array<std::uint8_t, 2>{0x21, 0x01},
          std::array<std::uint8_t, 2>{0x21, 0x7f},
          std::array<std::uint8_t, 2>{0x22, 0x80},
          std::array<std::uint8_t, 2>{0x23, 0x80},
          std::array<std::uint8_t, 2>{0x28, 0x80}})
    {
        const auto parsed = parseMcsChannelRequest(
            frameDomainPdu(invalidPayload));
        assert(!parsed);
        assert(parsed.error == McsChannelParseError::InvalidDomainPdu);
        assert(parsed.request.kind == McsChannelRequestKind::None);
    }
    assert(!parseMcsChannelRequest(
        frameDomainPdu(std::array<std::uint8_t, 1>{0x21})));
    assert(!parseMcsChannelRequest(
        frameDomainPdu(std::array<std::uint8_t, 3>{0x21, 0x80, 0x00})));

    auto corrupt = baseline;
    corrupt[3] = 10; // Inconsistent TPKT size.
    assert(parseMcsChannelRequest(corrupt).error ==
           McsChannelParseError::InvalidTransport);
    corrupt = baseline;
    corrupt[5] = 0xe0; // X.224 Connection Request, not Data.
    assert(parseMcsChannelRequest(corrupt).error ==
           McsChannelParseError::InvalidTransport);
    corrupt = baseline;
    corrupt[6] = 0x81; // Invalid X.224 EOT.
    assert(parseMcsChannelRequest(corrupt).error ==
           McsChannelParseError::InvalidTransport);
}

void testMcsSendDataWire()
{
    // MS-RDPBCGR 4.1.16 published 14-byte SendDataRequest
    // header (52-byte TPKT, 38-byte payload). The opaque data below
    // is synthetic: only this framing header is a Microsoft wire oracle.
    constexpr std::array<std::uint8_t, 14> microsoftHeader{
        0x03, 0x00, 0x00, 0x34, 0x02, 0xf0, 0x80,
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x26};
    std::vector<std::uint8_t> microsoftShape{
        microsoftHeader.begin(), microsoftHeader.end()};
    microsoftShape.insert(microsoftShape.end(), 38, 0x42);
    const auto parsed = parseMcsChannelRequest(microsoftShape);
    assert(parsed);
    assert(parsed.request.kind == McsChannelRequestKind::SendDataRequest);
    assert(parsed.request.initiator == 1007);
    assert(parsed.request.channelId == 1003);
    assert(parsed.request.dataPriority == 1);
    assert(parsed.request.segmentation == 3);
    assert(parsed.request.userData.size() == 38);
    assert(parsed.request.userData.data() ==
           microsoftShape.data() + microsoftHeader.size());
    assert(std::all_of(parsed.request.userData.begin(),
                       parsed.request.userData.end(),
                       [](std::uint8_t value) { return value == 0x42; }));

    // Support exactly one complete PER OCTET STRING (0..16383 bytes)
    // with no heap copy inside the parser. Preserve valid 7-bit and
    // 14-bit length forms at their wire boundaries.
    for (const std::size_t payloadBytes :
         {std::size_t{0}, std::size_t{1}, std::size_t{127},
          std::size_t{128}, std::size_t{16383}})
    {
        std::vector<std::uint8_t> mcs{
            0x64, 0x00, 0x06, 0x03, 0xeb, 0x70};
        if (payloadBytes < 128)
            mcs.push_back(static_cast<std::uint8_t>(payloadBytes));
        else
        {
            mcs.push_back(static_cast<std::uint8_t>(
                0x80U | (payloadBytes >> 8U)));
            mcs.push_back(static_cast<std::uint8_t>(payloadBytes));
        }
        const auto payloadOffset = mcs.size();
        mcs.insert(mcs.end(), payloadBytes, 0x51);
        auto frame = frameDomainPdu(mcs);
        const auto result = parseMcsChannelRequest(frame);
        assert(result);
        assert(result.request.kind == McsChannelRequestKind::SendDataRequest);
        assert(result.request.userData.size() == payloadBytes);
        assert(result.request.userData.data() ==
               frame.data() + 7 + payloadOffset);
        assert(std::all_of(result.request.userData.begin(),
                           result.request.userData.end(),
                           [](std::uint8_t value) { return value == 0x51; }));
    }

    // Actual peers may encode short lengths with TWO PER octets:
    // do not insist on DER-like minimality in aligned BASIC-PER.
    constexpr std::array<std::uint8_t, 9> longShort{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x80, 0x01, 0xa5};
    const auto longShortFrame = frameDomainPdu(longShort);
    const auto longShortResult = parseMcsChannelRequest(longShortFrame);
    assert(longShortResult && longShortResult.request.userData.size() == 1);
    assert(longShortResult.request.userData[0] == 0xa5);

    // All four T.125 priority and segmentation two-bit values are
    // decoded but do not mean that fragmented/low-priority data has
    // been reassembled or admitted to a channel.
    for (unsigned int priority = 0; priority < 4; ++priority)
    {
        for (unsigned int segmentation = 0; segmentation < 4;
             ++segmentation)
        {
            std::array<std::uint8_t, 8> mcs{
                0x64, 0x00, 0x06, 0x03, 0xeb,
                static_cast<std::uint8_t>(
                    (priority << 6U) | (segmentation << 4U)),
                0x01, 0x33};
            // Keep the whole TPKT alive while examining its borrowed
            // userData span; parsing a temporary frame would dangle.
            const auto frame = frameDomainPdu(mcs);
            const auto result = parseMcsChannelRequest(frame);
            assert(result);
            assert(result.request.dataPriority == priority);
            assert(result.request.segmentation == segmentation);
            assert(result.request.userData.size() == 1);
            assert(result.request.userData.data() == frame.data() + 14);
            assert(result.request.userData[0] == 0x33);
        }
    }
}

void testMcsSendDataRejections()
{
    constexpr std::array<std::uint8_t, 10> baseline{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x03,
        0x41, 0x42, 0x43};
    const auto validFrame = frameDomainPdu(baseline);
    assert(parseMcsChannelRequest(validFrame));

    // A truncated TPKT must never expose a borrowed payload.
    for (std::size_t length = 0; length < validFrame.size(); ++length)
    {
        const auto rejected = parseMcsChannelRequest(
            std::span(validFrame).first(length));
        assert(!rejected);
        assert(rejected.request.userData.empty());
    }

    const auto invalidPer = [](std::span<const std::uint8_t> mcs)
    {
        const auto outcome = parseMcsChannelRequest(frameDomainPdu(mcs));
        assert(!outcome);
        assert(outcome.error == McsChannelParseError::InvalidPerValue);
        assert(outcome.request.userData.empty());
    };
    const auto invalidChoice = [](std::span<const std::uint8_t> mcs)
    {
        const auto outcome = parseMcsChannelRequest(frameDomainPdu(mcs));
        assert(!outcome);
        assert(outcome.error == McsChannelParseError::InvalidDomainPdu);
        assert(outcome.request.userData.empty());
    };

    // No implicit PER fragmentation, no missing 14-bit second length,
    // and no length mismatch, wraparound or trailing bytes.
    invalidPer(std::array<std::uint8_t, 7>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x80});
    invalidPer(std::array<std::uint8_t, 8>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x80, 0x02});
    invalidPer(std::array<std::uint8_t, 9>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x80, 0x00, 0xaa});
    invalidPer(std::array<std::uint8_t, 9>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x03, 0x41, 0x42});
    invalidPer(std::array<std::uint8_t, 8>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x02, 0x41});
    invalidPer(std::array<std::uint8_t, 8>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0xc0, 0x00});
    invalidPer(std::array<std::uint8_t, 8>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0xff, 0xff});
    invalidPer(std::array<std::uint8_t, 7>{
        0x64, 0xff, 0xff, 0x03, 0xeb, 0x70, 0x00});

    // No extra choice/extension bit or nonzero low PER padding.
    invalidChoice(std::array<std::uint8_t, 7>{
        0x65, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x00});
    invalidChoice(std::array<std::uint8_t, 7>{
        0x66, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x00});
    invalidChoice(std::array<std::uint8_t, 7>{
        0x68, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x00});
    invalidChoice(std::array<std::uint8_t, 7>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x71, 0x00});
    invalidChoice(std::array<std::uint8_t, 6>{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70});

    auto corrupted = validFrame;
    corrupted[3] = static_cast<std::uint8_t>(corrupted[3] + 1);
    assert(parseMcsChannelRequest(corrupted).error ==
           McsChannelParseError::InvalidTransport);
    corrupted = validFrame;
    corrupted[5] = 0xe0; // Not X.224 Data TPDU.
    assert(parseMcsChannelRequest(corrupted).error ==
           McsChannelParseError::InvalidTransport);
    corrupted = validFrame;
    corrupted.push_back(0); // Coalesced trailing TPKT is not consumed.
    assert(parseMcsChannelRequest(corrupted).error ==
           McsChannelParseError::InvalidTransport);
}

void testMcsSendDataIndicationWire()
{
    // Independently specified T.125 SDin choice 26 envelope for
    // user 1007, I/O channel 1003, priority 1, segmentation 3.
    // Three opaque bytes are synthetic, NOT an authorized RDP PDU.
    constexpr std::array<std::uint8_t, 17> golden{
        0x03, 0x00, 0x00, 0x11, 0x02, 0xf0, 0x80,
        0x68, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x03,
        0xde, 0xad, 0xbe};
    constexpr std::array<std::uint8_t, 3> payload{0xde, 0xad, 0xbe};
    std::array<std::uint8_t, 20> output{};
    output.fill(0xa5);
    const auto written = encodeMcsSendDataIndication(
        1007, 1003, 1, 3, payload, output);
    assert(written && *written == golden.size());
    assert(std::equal(output.begin(), output.begin() + *written,
                      golden.begin()));
    assert(std::all_of(output.begin() + *written, output.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));

    std::span<const std::uint8_t> mcsPayload;
    assert(parseDataTpdu(std::span(output).first(*written), mcsPayload));
    assert(mcsPayload.size() == 10 && mcsPayload[0] == 0x68);
    // The existing incoming parser rejects server-only SDin as a
    // CLIENT Send Data Request; neither direction grants admission.
    assert(parseMcsChannelRequest(std::span(output).first(*written)).error ==
           McsChannelParseError::InvalidDomainPdu);

    for (const auto size : {std::size_t{0}, std::size_t{1},
                            std::size_t{127}, std::size_t{128},
                            std::size_t{16383}})
    {
        const std::vector<std::uint8_t> data(size, 0x42);
        const std::size_t headerSize = size >= 128 ? 15 : 14;
        std::vector<std::uint8_t> encoded(headerSize + size + 2U, 0xa7);
        const auto length = encodeMcsSendDataIndication(
            1001, 1003, 1, 3, data, encoded);
        assert(length && *length == headerSize + size);
        assert(encoded[0] == 3 && encoded[1] == 0);
        assert(encoded[2] == static_cast<std::uint8_t>(*length >> 8U));
        assert(encoded[3] == static_cast<std::uint8_t>(*length));
        assert(encoded[7] == 0x68 && encoded[8] == 0 &&
               encoded[9] == 0 && encoded[10] == 0x03 &&
               encoded[11] == 0xeb && encoded[12] == 0x70);
        if (size >= 128)
        {
            assert(encoded[13] ==
                   static_cast<std::uint8_t>(0x80U | (size >> 8U)));
            assert(encoded[14] == static_cast<std::uint8_t>(size));
        }
        else
        {
            assert(encoded[13] == size);
        }
        assert(std::equal(data.begin(), data.end(),
                          encoded.begin() + headerSize));
        assert(encoded[*length] == 0xa7 && encoded[*length + 1] == 0xa7);
        assert(parseDataTpdu(std::span(encoded).first(*length), mcsPayload));
    }

    for (unsigned int priority = 0; priority < 4; ++priority)
    {
        for (unsigned int segment = 0; segment < 4; ++segment)
        {
            std::array<std::uint8_t, 14> wire{};
            const auto count = encodeMcsSendDataIndication(
                65536, 65535,
                static_cast<std::uint8_t>(priority),
                static_cast<std::uint8_t>(segment),
                {}, wire);
            assert(count && *count == wire.size());
            assert(wire[7] == 0x68 &&
                   wire[8] == 0xfc && wire[9] == 0x17 &&
                   wire[10] == 0xff && wire[11] == 0xff);
            assert(wire[12] == ((priority << 6U) | (segment << 4U)));
            assert(wire[13] == 0);
        }
    }

    // userData aliasing the output header is explicitly supported:
    // the encoder moves data first, then overwrites the header.
    std::array<std::uint8_t, 32> alias{};
    std::copy(payload.begin(), payload.end(), alias.begin());
    const auto aliased = encodeMcsSendDataIndication(
        1007, 1003, 1, 3, std::span(alias).first(payload.size()), alias);
    assert(aliased && *aliased == golden.size());
    assert(std::equal(alias.begin(), alias.begin() + *aliased,
                      golden.begin()));
}

void testMcsSendDataIndicationRejections()
{
    constexpr std::array<std::uint8_t, 2> payload{0x41, 0x42};
    const auto rejectWithoutWriting =
        [&](std::uint32_t user, std::uint16_t channel,
            std::uint8_t priority, std::uint8_t segment,
            std::span<const std::uint8_t> data)
    {
        std::array<std::uint8_t, 24> output{};
        output.fill(0xdd);
        const auto result = encodeMcsSendDataIndication(
            user, channel, priority, segment, data, output);
        assert(!result);
        assert(std::all_of(output.begin(), output.end(),
                           [](std::uint8_t value) { return value == 0xdd; }));
    };

    for (std::uint32_t invalidUser :
         {0U, 1U, 1000U, 65537U, 0xffffffffU})
        rejectWithoutWriting(invalidUser, 1003, 1, 3, payload);
    rejectWithoutWriting(1007, 0, 1, 3, payload);
    for (std::uint8_t priority : {std::uint8_t{4}, std::uint8_t{255}})
        rejectWithoutWriting(1007, 1003, priority, 3, payload);
    for (std::uint8_t segment : {std::uint8_t{4}, std::uint8_t{255}})
        rejectWithoutWriting(1007, 1003, 1, segment, payload);

    std::vector<std::uint8_t> tooLarge(16384, 0x11);
    rejectWithoutWriting(1007, 1003, 1, 3, tooLarge);

    // Every insufficient capacity, including a header-only payload,
    // must leave the entire caller buffer unchanged.
    for (const auto data : {std::vector<std::uint8_t>{},
                            std::vector<std::uint8_t>(127, 0x42),
                            std::vector<std::uint8_t>(128, 0x42)})
    {
        const std::size_t needed = (data.size() >= 128 ? 15 : 14) +
                                    data.size();
        std::vector<std::uint8_t> destination(needed + 2U, 0xca);
        for (std::size_t capacity = 0; capacity < needed; ++capacity)
        {
            assert(!encodeMcsSendDataIndication(
                1007, 1003, 1, 3, data,
                std::span(destination).first(capacity)));
            assert(std::all_of(destination.begin(), destination.end(),
                               [](std::uint8_t byte) { return byte == 0xca; }));
        }
    }
}

void testRdpShareControlHeaderWire()
{
    // Independent MS-RDPBCGR Server Control PDU (Granted Control)
    // decrypted share bytes: 26 bytes, pduType=0x0017 (Data),
    // pduSource=1002 and a 20-byte Share Data body.
    constexpr std::array<std::uint8_t, 26> microsoftControl{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x12, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x02, 0x00, 0xef, 0x03, 0xea, 0x03, 0x00, 0x00};
    const auto parsed = parseRdpShareControlHeader(microsoftControl);
    assert(parsed && parsed.error == RdpShareControlError::None);
    assert(parsed.value.kind == RdpShareControlKind::Data);
    assert(parsed.value.pduSource == 1002);
    assert(parsed.value.body.size() == 20);
    assert(parsed.value.body.data() == microsoftControl.data() + 6);
    assert(parsed.value.body[8] == 0x14); // Share Data pduType2=CONTROL
    assert(parsed.value.body[12] == 0x02); // Granted Control action.

    // T.128 permits all five header types. Accepting their six-byte
    // header alone does NOT validate their required application bodies.
    for (const auto [type, expected] :
         {std::pair{0x01U, RdpShareControlKind::DemandActive},
          std::pair{0x03U, RdpShareControlKind::ConfirmActive},
          std::pair{0x06U, RdpShareControlKind::DeactivateAll},
          std::pair{0x07U, RdpShareControlKind::Data},
          std::pair{0x0aU, RdpShareControlKind::ServerRedirection}})
    {
        const std::array<std::uint8_t, 6> frame{
            6, 0, static_cast<std::uint8_t>(0x10U | type), 0,
            0xff, 0xff};
        const auto result = parseRdpShareControlHeader(frame);
        assert(result && result.value.kind == expected);
        assert(result.value.pduSource == 65535);
        assert(result.value.body.empty());
    }

    // Caller must strip any security header and isolate the Share
    // PDU. This test supplies that isolation deliberately, without
    // treating MCS syntax as evidence of a joined channel.
    std::vector<std::uint8_t> mcs{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70,
        static_cast<std::uint8_t>(microsoftControl.size())};
    mcs.insert(mcs.end(), microsoftControl.begin(), microsoftControl.end());
    const auto outer = frameDomainPdu(mcs);
    const auto transport = parseMcsChannelRequest(outer);
    assert(transport &&
           transport.request.kind == McsChannelRequestKind::SendDataRequest);
    assert(transport.request.userData.size() == microsoftControl.size());
    const auto inner =
        parseRdpShareControlHeader(transport.request.userData);
    assert(inner && inner.value.kind == RdpShareControlKind::Data);
    assert(inner.value.body.data() ==
           outer.data() + 7 + 7 + 6);
    assert(inner.value.body.size() == 20);
}

void testRdpShareControlHeaderRejections()
{
    constexpr std::array<std::uint8_t, 26> valid{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x12, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x02, 0x00, 0xef, 0x03, 0xea, 0x03, 0x00, 0x00};

    const auto invalidLength = [](std::span<const std::uint8_t> bytes)
    {
        const auto outcome = parseRdpShareControlHeader(bytes);
        assert(!outcome);
        assert(outcome.error == RdpShareControlError::InvalidLength);
        assert(outcome.value.kind == RdpShareControlKind::None);
        assert(outcome.value.body.empty());
    };
    for (std::size_t length = 0; length < valid.size(); ++length)
        invalidLength(std::span(valid).first(length));

    auto surplus = std::vector<std::uint8_t>(valid.begin(), valid.end());
    surplus.push_back(0x00);
    invalidLength(surplus);
    auto inconsistent = valid;
    inconsistent[0] = 25;
    invalidLength(inconsistent);
    inconsistent = valid;
    inconsistent[0] = 27;
    invalidLength(inconsistent);
    inconsistent = valid;
    inconsistent[0] = 0;
    invalidLength(inconsistent);
    inconsistent = valid;
    inconsistent[0] = 0xff;
    inconsistent[1] = 0xff;
    invalidLength(inconsistent);

    const auto invalidType = [](std::uint16_t typeAndVersion)
    {
        std::array<std::uint8_t, 6> bytes{
            6, 0, static_cast<std::uint8_t>(typeAndVersion),
            static_cast<std::uint8_t>(typeAndVersion >> 8U), 0, 0};
        const auto outcome = parseRdpShareControlHeader(bytes);
        assert(!outcome);
        assert(outcome.error == RdpShareControlError::InvalidType);
        assert(outcome.value.body.empty());
    };
    for (std::uint16_t bad : {std::uint16_t{0x0007},
                              std::uint16_t{0x0027},
                              std::uint16_t{0x0117},
                              std::uint16_t{0x0010},
                              std::uint16_t{0x0012},
                              std::uint16_t{0x0018},
                              std::uint16_t{0x001f},
                              std::uint16_t{0xffff}})
        invalidType(bad);

    // A totalLength of 0x8000 designates a T.128 FlowPDU and MUST
    // be ignored, NOT treated as a 32768-byte allocation or a valid
    // Share Control header. Never expose its opaque body.
    auto flow = valid;
    flow[0] = 0;
    flow[1] = 0x80;
    for (const auto bytes :
         {std::span<const std::uint8_t>(flow),
          std::span<const std::uint8_t>(flow).first(6)})
    {
        const auto ignored = parseRdpShareControlHeader(bytes);
        assert(!ignored);
        assert(ignored.error == RdpShareControlError::FlowPduIgnored);
        assert(ignored.value.kind == RdpShareControlKind::None);
        assert(ignored.value.body.empty());
    }
    // Even FlowPDU has no valid six-byte Share Control envelope when
    // the input itself is incomplete.
    invalidLength(std::span(flow).first(5));
}

void testRdpShareDataHeaderWire()
{
    // Exact Microsoft MS-RDPBCGR Server Control (Granted Control):
    // full 26-byte Share PDU, not a fabricated authorization or input.
    constexpr std::array<std::uint8_t, 26> grantedControl{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x12, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x02, 0x00, 0xef, 0x03, 0xea, 0x03, 0x00, 0x00};
    const auto parsed = parseRdpShareDataHeader(grantedControl);
    assert(parsed && parsed.error == RdpShareDataError::None);
    assert(parsed.value.pduSource == 1002);
    assert(parsed.value.shareId == 0x000103eaU);
    assert(parsed.value.streamId == 2);
    assert(parsed.value.reportedUncompressedLength == 26);
    assert(parsed.value.pduType2 == 0x14);
    assert(parsed.value.compressedType == 0);
    assert(parsed.value.compressedLength == 0);
    assert(parsed.value.body.size() == 8);
    assert(parsed.value.body.data() == grantedControl.data() + 18);
    assert(parsed.value.body[0] == 0x02); // Granted Control action.

    // Microsoft Client Font List: a documented buggy client sends an
    // uninitialized 0xda3b as uncompressedLength, not the 26-byte
    // frame size. Never allocate from or reject based on that field.
    constexpr std::array<std::uint8_t, 26> fontList{
        0x1a, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x3b, 0xda, 0x27, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x32, 0x00};
    const auto buggy = parseRdpShareDataHeader(fontList);
    assert(buggy && buggy.value.pduSource == 1007);
    assert(buggy.value.reportedUncompressedLength == 0xda3b);
    assert(buggy.value.pduType2 == 0x27);
    assert(buggy.value.streamId == 1);
    assert(buggy.value.body.data() == fontList.data() + 18);
    assert(buggy.value.body.size() == 8);

    // Microsoft Server Font Map also proves pad1 is arbitrary
    // (0x45) and STREAM_MED (2) is legal.
    constexpr std::array<std::uint8_t, 26> fontMap{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x45, 0x02,
        0x1a, 0x00, 0x28, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00};
    const auto font = parseRdpShareDataHeader(fontMap);
    assert(font && font.value.pduType2 == 0x28);
    assert(font.value.streamId == 2);
    assert(font.value.body.data() == fontMap.data() + 18);

    // Every documented Data pduType2 is syntactically recognizable;
    // payload interpretation remains a later authorized phase.
    constexpr std::array<std::uint8_t, 24> types{
        0x02, 0x14, 0x1b, 0x1c, 0x1f, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x36, 0x37};
    for (const auto type : types)
    {
        auto frame = grantedControl;
        frame[14] = type;
        const auto result = parseRdpShareDataHeader(frame);
        assert(result && result.value.pduType2 == type);
        assert(result.value.body.data() == frame.data() + 18);
    }

    // Windows Server Synchronize can use STREAM_UNDEFINED (0).
    auto sync = grantedControl;
    sync[11] = 0;
    sync[14] = 0x1f;
    const auto compat = parseRdpShareDataHeader(sync);
    assert(compat && compat.value.streamId == 0);
    assert(compat.value.pduType2 == 0x1f);

    // In uncompressed mode, compressedLength is retained as metadata,
    // never an allocation or body-size authority.
    auto staleLength = grantedControl;
    staleLength[16] = 0xff;
    staleLength[17] = 0xff;
    const auto stale = parseRdpShareDataHeader(staleLength);
    assert(stale && stale.value.compressedLength == 65535);
    assert(stale.value.body.size() == 8);

    // Deliberate MCS -> Share Control -> Share Data handoff. The
    // backing TPKT outlives all three borrowed data views.
    std::vector<std::uint8_t> mcs{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70,
        static_cast<std::uint8_t>(grantedControl.size())};
    mcs.insert(mcs.end(), grantedControl.begin(), grantedControl.end());
    const auto outer = frameDomainPdu(mcs);
    const auto parsedMcs = parseMcsChannelRequest(outer);
    assert(parsedMcs &&
           parsedMcs.request.kind == McsChannelRequestKind::SendDataRequest);
    const auto shared = parseRdpShareDataHeader(parsedMcs.request.userData);
    assert(shared && shared.value.pduType2 == 0x14);
    assert(shared.value.body.data() == outer.data() + 7 + 7 + 18);
}

void testRdpShareDataHeaderRejections()
{
    constexpr std::array<std::uint8_t, 26> valid{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x12, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x02, 0x00, 0xef, 0x03, 0xea, 0x03, 0x00, 0x00};
    const auto denied = [](std::span<const std::uint8_t> frame,
                           RdpShareDataError expected)
    {
        const auto result = parseRdpShareDataHeader(frame);
        assert(!result && result.error == expected);
        assert(result.value.body.empty());
        assert(result.value.pduType2 == 0);
    };

    // Every byte-short prefix rejects before yielding a borrowed view.
    for (std::size_t size = 0; size < valid.size(); ++size)
        denied(std::span(valid).first(size),
               RdpShareDataError::InvalidShareControl);
    auto extra = std::vector<std::uint8_t>(valid.begin(), valid.end());
    extra.push_back(0);
    denied(extra, RdpShareDataError::InvalidShareControl);

    // Syntactically valid outer Data headers still need all 12
    // inner bytes. No speculative field access or borrowing.
    for (std::size_t size = 6; size < 18; ++size)
    {
        auto prefix = std::vector<std::uint8_t>(
            valid.begin(), valid.begin() + size);
        prefix[0] = static_cast<std::uint8_t>(size);
        denied(prefix, RdpShareDataError::IncompleteHeader);
    }

    auto frame = valid;
    frame[2] = 0x16; // Deactivate All, not Share Data.
    denied(frame, RdpShareDataError::NotDataPdu);
    frame = valid;
    frame[2] = 0x27; // Wrong protocol version.
    denied(frame, RdpShareDataError::InvalidShareControl);
    frame = valid;
    frame[0] = 0;
    frame[1] = 0x80; // T.128 FlowPDU must be ignored.
    denied(frame, RdpShareDataError::FlowPduIgnored);

    for (const std::uint8_t type :
         {std::uint8_t{0}, std::uint8_t{1},
          std::uint8_t{3}, std::uint8_t{0x1d},
          std::uint8_t{0x2a}, std::uint8_t{0x33},
          std::uint8_t{0x35}, std::uint8_t{0xff}})
    {
        frame = valid;
        frame[14] = type;
        denied(frame, RdpShareDataError::InvalidDataPduType);
    }

    for (const std::uint8_t stream :
         {std::uint8_t{0}, std::uint8_t{3},
          std::uint8_t{5}, std::uint8_t{255}})
    {
        frame = valid; // Control must never use STREAM_UNDEFINED.
        frame[11] = stream;
        denied(frame, RdpShareDataError::InvalidStream);
    }
    for (const std::uint8_t compressed :
         {std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{0x20},
          std::uint8_t{0x40}, std::uint8_t{0x80},
          std::uint8_t{0xff}})
    {
        frame = valid;
        frame[15] = compressed;
        denied(frame, RdpShareDataError::UnsupportedCompression);
    }
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
constexpr std::array<McsTestCase, 23> kMcsTestCases{{
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
    {"mcs-attach-confirm-wire", &testMcsAttachConfirmWire},
    {"mcs-channel-join-confirm", &testMcsChannelJoinConfirmWireAndRejections},
    {"mcs-disconnect-wire", &testMcsDisconnectProviderWire},
    {"mcs-disconnect-rejections", &testMcsDisconnectProviderRejections},
    {"mcs-send-data-wire", &testMcsSendDataWire},
    {"mcs-send-data-rejections", &testMcsSendDataRejections},
    {"mcs-send-indication-wire", &testMcsSendDataIndicationWire},
    {"mcs-send-indication-rejections", &testMcsSendDataIndicationRejections},
    {"share-control-header-wire", &testRdpShareControlHeaderWire},
    {"share-control-header-rejections", &testRdpShareControlHeaderRejections},
    {"share-data-header-wire", &testRdpShareDataHeaderWire},
    {"share-data-header-rejections", &testRdpShareDataHeaderRejections},
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
