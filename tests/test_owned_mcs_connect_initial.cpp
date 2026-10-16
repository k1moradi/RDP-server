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

void testRdpSynchronizeFinalizationWire()
{
    // MS-RDPBCGR 4.1.14 published decrypted client Synchronize
    // (22 bytes). Caller has already performed security-header
    // processing; this is not a received/authenticated session.
    constexpr std::array<std::uint8_t, 22> microsoftSync{
        0x16, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x08, 0x00, 0x1f, 0x00, 0x00, 0x00,
        0x01, 0x00, 0xea, 0x03};
    const auto sync = parseRdpSynchronizePdu(microsoftSync);
    assert(sync && sync.error == RdpFinalizationError::None);
    assert(sync.value.pduSource == 1007);
    assert(sync.value.shareId == 0x000103eaU);
    assert(sync.value.targetUser == 1002);

    // Documented Windows Server Synchronize may use stream 0 rather
    // than the nominal 1. Do not disallow the compatibility exception.
    auto streamZero = microsoftSync;
    streamZero[11] = 0;
    assert(parseRdpSynchronizePdu(streamZero));
    streamZero[10] = 0xf7; // pad1 ignored, including nonzero octets.
    assert(parseRdpSynchronizePdu(streamZero));

    // The parser retains an uninterpreted channel ID. The future
    // authenticated session owner must check assignment/membership.
    streamZero[20] = 0;
    streamZero[21] = 0;
    assert(parseRdpSynchronizePdu(streamZero).value.targetUser == 0);

    // Complete MCS SendDataRequest framing is not proof that the
    // embedded Share Control/Sync packet is authorized.
    std::vector<std::uint8_t> mcs{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70,
        static_cast<std::uint8_t>(microsoftSync.size())};
    mcs.insert(mcs.end(), microsoftSync.begin(), microsoftSync.end());
    const auto frame = frameDomainPdu(mcs);
    const auto outer = parseMcsChannelRequest(frame);
    assert(outer && outer.request.userData.size() == microsoftSync.size());
    assert(outer.request.userData.data() == frame.data() + 14);
    const auto nested = parseRdpSynchronizePdu(outer.request.userData);
    assert(nested && nested.value.targetUser == 1002);
}

void testRdpSynchronizeFinalizationRejections()
{
    constexpr std::array<std::uint8_t, 22> valid{
        0x16, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x08, 0x00, 0x1f, 0x00, 0x00, 0x00,
        0x01, 0x00, 0xea, 0x03};
    const auto denied = [](std::span<const std::uint8_t> bytes,
                           RdpFinalizationError expected)
    {
        const auto parsed = parseRdpSynchronizePdu(bytes);
        assert(!parsed && parsed.error == expected);
        assert(parsed.value.shareId == 0);
        assert(parsed.value.targetUser == 0);
    };
    for (std::size_t len = 0; len < valid.size(); ++len)
        denied(std::span(valid).first(len),
               RdpFinalizationError::InvalidShareData);
    auto coalesced = std::vector<std::uint8_t>(valid.begin(), valid.end());
    coalesced.push_back(0xaa);
    denied(coalesced, RdpFinalizationError::InvalidShareData);

    auto mutation = valid;
    mutation[0] = 21;
    denied(std::span(mutation).first(21),
           RdpFinalizationError::InvalidBodyLength);
    mutation = valid;
    mutation[0] = 23;
    auto tooLong = std::vector<std::uint8_t>(mutation.begin(), mutation.end());
    tooLong.push_back(0);
    denied(tooLong, RdpFinalizationError::InvalidBodyLength);

    mutation = valid;
    mutation[14] = 0x14; // Share Data Control, not Synchronize.
    denied(mutation, RdpFinalizationError::WrongDataPduType);
    for (const std::uint16_t bad : {std::uint16_t{0},
                                    std::uint16_t{2},
                                    std::uint16_t{0x0101},
                                    std::uint16_t{0xffff}})
    {
        mutation = valid;
        mutation[18] = static_cast<std::uint8_t>(bad);
        mutation[19] = static_cast<std::uint8_t>(bad >> 8U);
        denied(mutation, RdpFinalizationError::InvalidValue);
    }
    mutation = valid;
    mutation[15] = 0x20; // No decompression/session history available.
    denied(mutation, RdpFinalizationError::InvalidShareData);
    mutation = valid;
    mutation[2] = 0x27; // Bad Share Control version.
    denied(mutation, RdpFinalizationError::InvalidShareData);
    mutation = valid;
    mutation[0] = 0;
    mutation[1] = 0x80; // T.128 FlowPDU is ignored by parent.
    denied(mutation, RdpFinalizationError::InvalidShareData);
    mutation = valid;
    mutation[11] = 3; // Invalid stream ID.
    denied(mutation, RdpFinalizationError::InvalidShareData);
}

void testRdpControlFinalizationWire()
{
    // MS-RDPBCGR 4.1.15, 4.1.16 and 4.1.18 full decrypted
    // Control PDUs: Client Cooperate, Client Request and
    // Server Granted, respectively. No actual control is granted.
    constexpr std::array<std::uint8_t, 26> clientCooperate{
        0x1a, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x0c, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const auto cooperate = parseRdpControlPdu(clientCooperate);
    assert(cooperate && cooperate.error == RdpFinalizationError::None);
    assert(cooperate.value.pduSource == 1007);
    assert(cooperate.value.shareId == 0x000103eaU);
    assert(cooperate.value.action == RdpControlAction::Cooperate);
    assert(cooperate.value.grantId == 0);
    assert(cooperate.value.controlId == 0);

    auto clientRequest = clientCooperate;
    clientRequest[18] = 0x01;
    const auto requested = parseRdpControlPdu(clientRequest);
    assert(requested && requested.value.action ==
           RdpControlAction::RequestControl);

    constexpr std::array<std::uint8_t, 26> serverGranted{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x12, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x02, 0x00, 0xef, 0x03, 0xea, 0x03, 0x00, 0x00};
    const auto granted = parseRdpControlPdu(serverGranted);
    assert(granted && granted.value.pduSource == 1002);
    assert(granted.value.action == RdpControlAction::GrantedControl);
    assert(granted.value.grantId == 1007);
    assert(granted.value.controlId == 1002);

    auto detach = clientCooperate;
    detach[18] = 0x03;
    const auto parsedDetach = parseRdpControlPdu(detach);
    assert(parsedDetach && parsedDetach.value.action ==
           RdpControlAction::Detach);

    // Decoding an action/ID is syntax, not permission. Even a
    // client-shaped packet with forged GrantedControl remains
    // syntactically decoded; real direction/state checks are
    // REQUIRED before its action could be applied.
    auto untrustedGrant = clientCooperate;
    untrustedGrant[18] = 2;
    untrustedGrant[20] = 0xff;
    untrustedGrant[21] = 0xff;
    const auto forged = parseRdpControlPdu(untrustedGrant);
    assert(forged &&
           forged.value.action == RdpControlAction::GrantedControl);
    assert(forged.value.grantId == 65535);
    assert(forged.value.controlId == 0);
}

void testRdpControlFinalizationRejections()
{
    constexpr std::array<std::uint8_t, 26> valid{
        0x1a, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x0c, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const auto denied = [](std::span<const std::uint8_t> bytes,
                           RdpFinalizationError expected)
    {
        const auto parsed = parseRdpControlPdu(bytes);
        assert(!parsed && parsed.error == expected);
        assert(parsed.value.shareId == 0);
        assert(parsed.value.grantId == 0);
        assert(parsed.value.controlId == 0);
    };
    for (std::size_t len = 0; len < valid.size(); ++len)
        denied(std::span(valid).first(len),
               RdpFinalizationError::InvalidShareData);
    auto coalesced = std::vector<std::uint8_t>(valid.begin(), valid.end());
    coalesced.push_back(0x00);
    denied(coalesced, RdpFinalizationError::InvalidShareData);

    auto mutation = valid;
    mutation[0] = 25;
    denied(std::span(mutation).first(25),
           RdpFinalizationError::InvalidBodyLength);
    mutation = valid;
    mutation[0] = 27;
    auto tooLong = std::vector<std::uint8_t>(mutation.begin(), mutation.end());
    tooLong.push_back(0);
    denied(tooLong, RdpFinalizationError::InvalidBodyLength);

    mutation = valid;
    mutation[14] = 0x1f; // Not a Control Data PDU.
    denied(mutation, RdpFinalizationError::WrongDataPduType);
    for (const std::uint16_t invalid : {std::uint16_t{0},
                                        std::uint16_t{5},
                                        std::uint16_t{0x0104},
                                        std::uint16_t{0xffff}})
    {
        mutation = valid;
        mutation[18] = static_cast<std::uint8_t>(invalid);
        mutation[19] = static_cast<std::uint8_t>(invalid >> 8U);
        denied(mutation, RdpFinalizationError::InvalidValue);
    }
    mutation = valid;
    mutation[15] = 0x20; // Compressed payload not allowed.
    denied(mutation, RdpFinalizationError::InvalidShareData);
    mutation = valid;
    mutation[11] = 3; // Invalid stream ID.
    denied(mutation, RdpFinalizationError::InvalidShareData);
    mutation = valid;
    mutation[2] = 0x27; // Bad protocol version.
    denied(mutation, RdpFinalizationError::InvalidShareData);
    mutation = valid;
    mutation[0] = 0;
    mutation[1] = 0x80; // Must-ignore T.128 FlowPDU.
    denied(mutation, RdpFinalizationError::InvalidShareData);
}

// MS-RDPBCGR 2.2.1.13.1.1 and 2.2.1.13.2.1 synthetic
// complete Share Control PDUs with two independently defined
// TS_CAPS_SET envelopes: SHARE length 8 and FONT length 4.
// The latter is a real published server compatibility case,
// but this is NOT claimed to be a captured 38-byte RDP session.
constexpr std::array<std::uint8_t, 38> kOfflineDemandActive{{
    0x26, 0x00, 0x11, 0x00, 0xea, 0x03,
    0xea, 0x03, 0x01, 0x00, 0x04, 0x00, 0x10, 0x00,
    0x52, 0x44, 0x50, 0x00, 0x02, 0x00, 0x17, 0xf0,
    0x09, 0x00, 0x08, 0x00, 0xea, 0x03, 0xdc, 0xe2,
    0x0e, 0x00, 0x04, 0x00, 0x44, 0x33, 0x22, 0x11
}};
constexpr std::array<std::uint8_t, 36> kOfflineConfirmActive{{
    0x24, 0x00, 0x13, 0x00, 0xef, 0x03,
    0xea, 0x03, 0x01, 0x00, 0xea, 0x03,
    0x04, 0x00, 0x10, 0x00,
    0x52, 0x44, 0x50, 0x00, 0x02, 0x00, 0x34, 0x12,
    0x09, 0x00, 0x08, 0x00, 0xea, 0x03, 0xdc, 0xe2,
    0x0e, 0x00, 0x04, 0x00
}};

// Normative Microsoft MS-RDPBCGR 4.1.15 server General Capability Set,
// 24 bytes as published: V1 0x0200, extraFlags 0x041d. It is a
// reference *capability*, not a captured authenticated session.
constexpr std::array<std::uint8_t, 24> kMicrosoftGeneralCapability{{
    0x01, 0x00, 0x18, 0x00, 0x01, 0x00, 0x03, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01
}};

[[nodiscard]] std::array<std::uint8_t, 32> generalWithShareCapability()
{
    // The published Share Capability Set precedes General in the
    // Microsoft Demand Active example. Preserve its ignored pad bytes.
    std::array<std::uint8_t, 32> capabilitySets{{
        0x09, 0x00, 0x08, 0x00, 0xea, 0x03, 0xdc, 0xe2
    }};
    std::copy(kMicrosoftGeneralCapability.begin(),
              kMicrosoftGeneralCapability.end(),
              capabilitySets.begin() + 8);
    return capabilitySets;
}

// MS-RDPBCGR 4.1.15 server Demand Active published Bitmap
// Capability Set (28 bytes). This is a wire oracle, not a live
// server/session; no framebuffer allocation follows the dimensions.
constexpr std::array<std::uint8_t, 28> kMicrosoftBitmapCapability{{
    0x02, 0x00, 0x1c, 0x00, 0x18, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x04,
    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00
}};

void testRdpBitmapCapabilityWire()
{
    constexpr std::array<std::uint8_t, 4> descriptor{{'R', 'D', 'P', 0}};
    std::array<std::uint8_t, 54> demand{};
    assert(encodeRdpDemandActivePdu(
        0x000103eaU, 0x11223344U, descriptor, 1U,
        kMicrosoftBitmapCapability, demand) == demand.size());
    const auto parsed = parseRdpBitmapCapabilityFromActive(demand);
    assert(parsed && parsed.error == RdpBitmapCapabilityError::None);
    assert(parsed.value.preferredBitsPerPixel == 24U);
    assert(parsed.value.desktopWidth == 1280U);
    assert(parsed.value.desktopHeight == 1024U);
    assert(parsed.value.desktopResizeSupported);
    assert(parsed.value.drawingFlags == 0U);

    // Confirm Active is assembled independently, with exact 6-byte
    // Share Control, 10-byte body prefix and 4-byte caps count/pad.
    constexpr std::array<std::uint8_t, 24> confirmPrefix{{
        0x34, 0x00, 0x13, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0xea, 0x03,
        0x04, 0x00, 0x20, 0x00, 'R', 'D', 'P', 0,
        0x01, 0x00, 0x00, 0x00
    }};
    std::array<std::uint8_t, 52> confirm{};
    std::copy(confirmPrefix.begin(), confirmPrefix.end(), confirm.begin());
    std::copy(kMicrosoftBitmapCapability.begin(),
              kMicrosoftBitmapCapability.end(),
              confirm.begin() + confirmPrefix.size());
    assert(parseRdpActivePdu(confirm));
    const auto client = parseRdpBitmapCapabilityFromActive(confirm);
    assert(client && client.value.desktopWidth == 1280U);
    assert(client.value.desktopHeight == 1024U);

    // Preserve ignored fields and unknown drawing advertisements.
    auto compatible = demand;
    compatible[22U + 6U] = 0xff;  // receive1BitPerPixel ignored.
    compatible[22U + 8U] = 0xfe;  // receive4BitsPerPixel ignored.
    compatible[22U + 10U] = 0xfd; // receive8BitsPerPixel ignored.
    compatible[22U + 16U] = 0xaa; // pad2octets ignored.
    compatible[22U + 17U] = 0xbb;
    compatible[22U + 22U] = 0xff; // highColorFlags ignored.
    compatible[22U + 23U] = 0x81; // unknown drawing flags preserved.
    compatible[22U + 26U] = 0xcc; // pad2octetsB ignored.
    compatible[22U + 27U] = 0xdd;
    const auto accepted = parseRdpBitmapCapabilityFromActive(compatible);
    assert(accepted && accepted.value.drawingFlags == 0x81U);

    // An unimplemented sibling capability must remain opaque.
    std::array<std::uint8_t, 36> sets{};
    std::copy(kMicrosoftBitmapCapability.begin(),
              kMicrosoftBitmapCapability.end(), sets.begin());
    constexpr std::array<std::uint8_t, 8> unknown{{
        0xfe, 0x7f, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04
    }};
    std::copy(unknown.begin(), unknown.end(), sets.begin() + 28);
    std::array<std::uint8_t, 62> withUnknown{};
    assert(encodeRdpDemandActivePdu(
        0x000103eaU, 0x11223344U, descriptor, 2U,
        sets, withUnknown) == withUnknown.size());
    const auto sibling = parseRdpBitmapCapabilityFromActive(withUnknown);
    assert(sibling && sibling.value.desktopWidth == 1280U);
}

void testRdpBitmapCapabilityRejections()
{
    constexpr auto invalid = RdpBitmapCapabilityError::InvalidActivePdu;
    constexpr auto missing = RdpBitmapCapabilityError::Missing;
    constexpr auto layout = RdpBitmapCapabilityError::InvalidLayout;
    constexpr auto size = RdpBitmapCapabilityError::InvalidDesktopSize;
    constexpr auto resize = RdpBitmapCapabilityError::InvalidResizeFlag;
    constexpr auto required = RdpBitmapCapabilityError::MissingRequiredSupport;
    constexpr auto duplicate = RdpBitmapCapabilityError::Duplicate;
    assert(parseRdpBitmapCapabilityFromActive(kOfflineDemandActive).error ==
           missing);
    assert(parseRdpBitmapCapabilityFromActive(kOfflineConfirmActive).error ==
           missing);

    // A generic envelope remains legal even if Bitmap is the wrong
    // size. Specialized validation rejects it without altering outer.
    auto shortBitmap = kOfflineDemandActive;
    shortBitmap[22U] = 2U; // Change Share type to Bitmap (length=8).
    assert(parseRdpActivePdu(shortBitmap));
    assert(parseRdpBitmapCapabilityFromActive(shortBitmap).error == layout);

    constexpr std::array<std::uint8_t, 4> descriptor{{'R', 'D', 'P', 0}};
    const auto encode = [&](std::span<const std::uint8_t> sets,
                            std::uint16_t count,
                            std::span<std::uint8_t> output)
    {
        return encodeRdpDemandActivePdu(
            0x000103eaU, 0x11223344U, descriptor, count, sets, output);
    };
    std::array<std::uint8_t, 54> demand{};
    assert(encode(kMicrosoftBitmapCapability, 1U, demand) == demand.size());
    for (std::size_t n = 0; n < demand.size(); ++n)
    {
        assert(parseRdpBitmapCapabilityFromActive(
                   std::span(demand).first(n)).error == invalid);
    }
    auto appended = std::vector<std::uint8_t>(demand.begin(), demand.end());
    appended.push_back(0);
    assert(parseRdpBitmapCapabilityFromActive(appended).error == invalid);

    auto mutation = demand;
    mutation[22U + 12U] = 0;
    mutation[22U + 13U] = 0;
    assert(parseRdpBitmapCapabilityFromActive(mutation).error == size);
    mutation = demand;
    mutation[22U + 14U] = 0;
    mutation[22U + 15U] = 0;
    assert(parseRdpBitmapCapabilityFromActive(mutation).error == size);
    mutation = demand;
    mutation[22U + 18U] = 2;
    assert(parseRdpBitmapCapabilityFromActive(mutation).error == resize);
    mutation = demand;
    mutation[22U + 19U] = 1;
    assert(parseRdpBitmapCapabilityFromActive(mutation).error == resize);

    for (const std::size_t offset : {20U, 24U})
    {
        for (const std::uint8_t invalidFlag : {std::uint8_t{0}, std::uint8_t{2}})
        {
            mutation = demand;
            mutation[22U + offset] = invalidFlag;
            assert(parseRdpBitmapCapabilityFromActive(mutation).error ==
                   required);
        }
    }

    std::array<std::uint8_t, 56> duplicates{};
    std::copy(kMicrosoftBitmapCapability.begin(),
              kMicrosoftBitmapCapability.end(), duplicates.begin());
    std::copy(kMicrosoftBitmapCapability.begin(),
              kMicrosoftBitmapCapability.end(), duplicates.begin() + 28);
    std::array<std::uint8_t, 82> duplicateDemand{};
    assert(encode(duplicates, 2U, duplicateDemand) ==
           duplicateDemand.size());
    assert(parseRdpActivePdu(duplicateDemand));
    assert(parseRdpBitmapCapabilityFromActive(duplicateDemand).error ==
           duplicate);

    // No live screen, TLS certificate or GSS/OS identity can be inferred
    // from a complete and syntactically consistent Bitmap capability.
    assert(parseRdpActivePdu(demand));
}

void testRdpGeneralCapabilityWire()
{
    const auto capabilitySets = generalWithShareCapability();
    constexpr std::array<std::uint8_t, 4> descriptor{{'R', 'D', 'P', 0}};
    std::array<std::uint8_t, 58> demand{};
    assert(encodeRdpDemandActivePdu(
        0x000103eaU, 0x11223344U, descriptor, 2U,
        capabilitySets, demand) == demand.size());
    const auto result = parseRdpGeneralCapabilityFromActive(demand);
    assert(result && result.error == RdpGeneralCapabilityError::None);
    assert(result.value.osMajorType == 1U);
    assert(result.value.osMinorType == 3U);
    assert(result.value.generalCompressionTypes == 0U);
    assert(result.value.extraFlags == 0x041dU);
    assert(result.value.updateCapabilityFlag == 0U);
    assert(result.value.remoteUnshareFlag == 0U);
    assert(result.value.generalCompressionLevel == 0U);
    assert(result.value.refreshRectSupported);
    assert(result.value.suppressOutputSupported);

    // Independent complete client Confirm Active header; this test
    // intentionally checks syntax, not client capability negotiation.
    constexpr std::array<std::uint8_t, 24> confirmPrefix{{
        0x38, 0x00, 0x13, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0xea, 0x03,
        0x04, 0x00, 0x24, 0x00, 'R', 'D', 'P', 0,
        0x02, 0x00, 0x00, 0x00
    }};
    std::array<std::uint8_t, 56> confirm{};
    std::copy(confirmPrefix.begin(), confirmPrefix.end(), confirm.begin());
    std::copy(capabilitySets.begin(), capabilitySets.end(),
              confirm.begin() + confirmPrefix.size());
    assert(parseRdpActivePdu(confirm));
    const auto clientResult = parseRdpGeneralCapabilityFromActive(confirm);
    assert(clientResult && clientResult.value.extraFlags == 0x041dU);

    // Ignored padding and unknown extraFlags must not be misread as
    // authorizing an unsupported codec or rejected as envelope syntax.
    auto future = demand;
    future[22U] = 0xfe; // Unknown sibling capability.
    future[23U] = 0x7f;
    future[40U] = 0xa5; // General pad2OctetsA, ignored.
    future[41U] = 0x5a;
    future[45U] = 0x80; // Unknown extra flag bit, preserved.
    const auto preserved = parseRdpGeneralCapabilityFromActive(future);
    assert(preserved && preserved.value.extraFlags == 0x801dU);
}

void testRdpGeneralCapabilityRejections()
{
    constexpr auto invalidActive = RdpGeneralCapabilityError::InvalidActivePdu;
    constexpr auto missing = RdpGeneralCapabilityError::Missing;
    constexpr auto invalidLayout = RdpGeneralCapabilityError::InvalidLayout;
    constexpr auto invalidVersion =
        RdpGeneralCapabilityError::InvalidProtocolVersion;
    constexpr auto invalidBoolean = RdpGeneralCapabilityError::InvalidBoolean;
    constexpr auto duplicate = RdpGeneralCapabilityError::Duplicate;
    assert(parseRdpGeneralCapabilityFromActive(kOfflineDemandActive).error ==
           missing);
    assert(parseRdpGeneralCapabilityFromActive(kOfflineConfirmActive).error ==
           missing);

    auto wrongLength = kOfflineDemandActive;
    wrongLength[22] = 1U; // General envelope only 8, not 24 bytes.
    assert(parseRdpActivePdu(wrongLength));
    assert(parseRdpGeneralCapabilityFromActive(wrongLength).error ==
           invalidLayout);

    auto capabilitySets = generalWithShareCapability();
    constexpr std::array<std::uint8_t, 4> descriptor{{'R', 'D', 'P', 0}};
    std::array<std::uint8_t, 58> demand{};
    const auto encode = [&](std::span<const std::uint8_t> sets,
                            std::uint16_t count,
                            std::span<std::uint8_t> target)
    {
        return encodeRdpDemandActivePdu(
            0x000103eaU, 0x11223344U, descriptor, count, sets, target);
    };
    assert(encode(capabilitySets, 2U, demand) == demand.size());
    for (std::size_t length = 0; length < demand.size(); ++length)
    {
        assert(parseRdpGeneralCapabilityFromActive(
                   std::span(demand).first(length)).error == invalidActive);
    }
    auto extended = std::vector<std::uint8_t>(demand.begin(), demand.end());
    extended.push_back(0);
    assert(parseRdpGeneralCapabilityFromActive(extended).error ==
           invalidActive);

    auto mutation = demand;
    mutation[38] = 0x01; // General protocolVersion low byte 0x0201.
    assert(parseRdpActivePdu(mutation));
    assert(parseRdpGeneralCapabilityFromActive(mutation).error ==
           invalidVersion);

    mutation = demand;
    mutation[52] = 2; // refreshRectSupport must be Boolean.
    assert(parseRdpGeneralCapabilityFromActive(mutation).error ==
           invalidBoolean);
    mutation = demand;
    mutation[53] = 2; // suppressOutputSupport must be Boolean.
    assert(parseRdpGeneralCapabilityFromActive(mutation).error ==
           invalidBoolean);

    std::array<std::uint8_t, 48> repeated{};
    std::copy(kMicrosoftGeneralCapability.begin(),
              kMicrosoftGeneralCapability.end(), repeated.begin());
    std::copy(kMicrosoftGeneralCapability.begin(),
              kMicrosoftGeneralCapability.end(), repeated.begin() + 24);
    std::array<std::uint8_t, 74> repeatedDemand{};
    assert(encode(repeated, 2U, repeatedDemand) == repeatedDemand.size());
    assert(parseRdpActivePdu(repeatedDemand));
    assert(parseRdpGeneralCapabilityFromActive(repeatedDemand).error ==
           duplicate);

    // The count/envelope parser remains generic; it does NOT suddenly
    // require General from every artificial or partial capability list.
    assert(parseRdpActivePdu(kOfflineDemandActive));
}

void testRdpActivePduWire()
{
    const auto demand = parseRdpActivePdu(kOfflineDemandActive);
    assert(demand && demand.value.kind ==
           RdpShareControlKind::DemandActive);
    assert(demand.value.pduSource == 1002);
    assert(demand.value.shareId == 0x000103eaU);
    assert(demand.value.sessionId == 0x11223344U);
    assert(demand.value.originatorId == 0);
    assert(demand.value.capabilityCount == 2);
    assert(demand.value.sourceDescriptor.size() == 4);
    assert(demand.value.sourceDescriptor.data() ==
           kOfflineDemandActive.data() + 14);
    assert(demand.value.sourceDescriptor[0] == 'R');
    assert(demand.value.sourceDescriptor[3] == 0);
    assert(demand.value.capabilitySets.size() == 12);
    assert(demand.value.capabilitySets.data() ==
           kOfflineDemandActive.data() + 22);
    assert(demand.value.capabilitySets[0] == 9);
    assert(demand.value.capabilitySets[2] == 8);
    assert(demand.value.capabilitySets[8] == 14);
    assert(demand.value.capabilitySets[10] == 4);

    const auto confirm = parseRdpActivePdu(kOfflineConfirmActive);
    assert(confirm && confirm.value.kind ==
           RdpShareControlKind::ConfirmActive);
    assert(confirm.value.pduSource == 1007);
    assert(confirm.value.shareId == 0x000103eaU);
    assert(confirm.value.originatorId == 1002);
    assert(confirm.value.sessionId == 0);
    assert(confirm.value.capabilityCount == 2);
    assert(confirm.value.sourceDescriptor.data() ==
           kOfflineConfirmActive.data() + 16);
    assert(confirm.value.capabilitySets.data() ==
           kOfflineConfirmActive.data() + 24);
    assert(confirm.value.capabilitySets.size() == 12);

    // Different pad2Octets and unknown capabilitySetType are legal
    // envelope syntax, not automatically supported features.
    auto differentPad = kOfflineConfirmActive;
    differentPad[22] = 0xff;
    differentPad[23] = 0xff;
    differentPad[24] = 0xfe;
    differentPad[25] = 0x7f;
    assert(parseRdpActivePdu(differentPad));

    // Zero capability sets are a syntactically exact count/length
    // combination; no later capability negotiation can succeed
    // merely because this offline parser accepted the envelope.
    std::vector<std::uint8_t> demandNone(
        kOfflineDemandActive.begin(),
        kOfflineDemandActive.begin() + 22);
    demandNone.insert(demandNone.end(),
                      kOfflineDemandActive.begin() + 34,
                      kOfflineDemandActive.end());
    demandNone[0] = static_cast<std::uint8_t>(demandNone.size());
    demandNone[12] = 4;
    demandNone[18] = 0;
    const auto emptyDemand = parseRdpActivePdu(demandNone);
    assert(emptyDemand && emptyDemand.value.capabilityCount == 0);
    assert(emptyDemand.value.capabilitySets.empty());
    assert(emptyDemand.value.sessionId == 0x11223344U);

    std::vector<std::uint8_t> confirmNone(
        kOfflineConfirmActive.begin(),
        kOfflineConfirmActive.begin() + 24);
    confirmNone[0] = static_cast<std::uint8_t>(confirmNone.size());
    confirmNone[14] = 4;
    confirmNone[20] = 0;
    const auto emptyConfirm = parseRdpActivePdu(confirmNone);
    assert(emptyConfirm && emptyConfirm.value.capabilityCount == 0);
    assert(emptyConfirm.value.capabilitySets.empty());

    // Compose one complete TPKT/MCS client request with the confirmed
    // Share Control PDU; preserve outer storage for borrowed views.
    std::vector<std::uint8_t> mcs{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70,
        static_cast<std::uint8_t>(kOfflineConfirmActive.size())};
    mcs.insert(mcs.end(), kOfflineConfirmActive.begin(),
               kOfflineConfirmActive.end());
    const auto framed = frameDomainPdu(mcs);
    const auto outer = parseMcsChannelRequest(framed);
    assert(outer && outer.request.kind ==
           McsChannelRequestKind::SendDataRequest);
    const auto inner = parseRdpActivePdu(outer.request.userData);
    assert(inner && inner.value.kind ==
           RdpShareControlKind::ConfirmActive);
    assert(inner.value.sourceDescriptor.data() == framed.data() + 14 + 16);
    assert(inner.value.capabilitySets.data() == framed.data() + 14 + 24);
}

void testRdpActivePduRejections()
{
    const auto denied = [](std::span<const std::uint8_t> bytes,
                           RdpActivePduError expected)
    {
        const auto parsed = parseRdpActivePdu(bytes);
        assert(!parsed && parsed.error == expected);
        assert(parsed.value.kind == RdpShareControlKind::None);
        assert(parsed.value.capabilityCount == 0);
        assert(parsed.value.sourceDescriptor.empty());
        assert(parsed.value.capabilitySets.empty());
    };

    // Strict Share Control length means any truncation or coalesced
    // bytes are denied BEFORE reading nested lengths.
    for (std::size_t length = 0; length < kOfflineDemandActive.size();
         ++length)
        denied(std::span(kOfflineDemandActive).first(length),
               RdpActivePduError::InvalidShareControl);
    for (std::size_t length = 0; length < kOfflineConfirmActive.size();
         ++length)
        denied(std::span(kOfflineConfirmActive).first(length),
               RdpActivePduError::InvalidShareControl);

    auto surplus = std::vector<std::uint8_t>(
        kOfflineDemandActive.begin(), kOfflineDemandActive.end());
    surplus.push_back(0);
    denied(surplus, RdpActivePduError::InvalidShareControl);

    auto demand = kOfflineDemandActive;
    demand[2] = 0x17; // Correct frame size but Share Data, not Active.
    denied(demand, RdpActivePduError::WrongPduType);
    demand = kOfflineDemandActive;
    demand[2] = 0x21; // Invalid Share Control version.
    denied(demand, RdpActivePduError::InvalidShareControl);
    demand = kOfflineDemandActive;
    demand[0] = 0;
    demand[1] = 0x80; // Must-ignore T.128 FlowPDU.
    denied(demand, RdpActivePduError::InvalidShareControl);

    auto confirm = kOfflineConfirmActive;
    confirm[10] = 0xeb; // Must be server channel 1002, not 1003.
    denied(confirm, RdpActivePduError::InvalidOriginator);
    confirm = kOfflineConfirmActive;
    confirm[11] = 0;
    denied(confirm, RdpActivePduError::InvalidOriginator);

    // Declared lengths cannot cross the caller-owned packet boundary
    // or leave even one unaccounted octet before/after capabilities.
    demand = kOfflineDemandActive;
    demand[10] = 0xff; demand[11] = 0xff;
    denied(demand, RdpActivePduError::InvalidLayout);
    demand = kOfflineDemandActive;
    demand[12] = 3; // combinedCaps must include count + pad.
    denied(demand, RdpActivePduError::InvalidLayout);
    demand = kOfflineDemandActive;
    demand[12] = 17;
    denied(demand, RdpActivePduError::InvalidLayout);
    demand = kOfflineDemandActive;
    demand[12] = 15;
    denied(demand, RdpActivePduError::InvalidLayout);
    confirm = kOfflineConfirmActive;
    confirm[12] = 0xff; confirm[13] = 0xff;
    denied(confirm, RdpActivePduError::InvalidLayout);
    confirm = kOfflineConfirmActive;
    confirm[14] = 17;
    denied(confirm, RdpActivePduError::InvalidLayout);

    for (std::uint16_t count : {std::uint16_t{0},
                                std::uint16_t{1},
                                std::uint16_t{3},
                                std::uint16_t{65535}})
    {
        demand = kOfflineDemandActive;
        demand[18] = static_cast<std::uint8_t>(count);
        demand[19] = static_cast<std::uint8_t>(count >> 8U);
        denied(demand, RdpActivePduError::InvalidCapabilitySet);
    }
    for (std::uint16_t size : {std::uint16_t{0},
                               std::uint16_t{1},
                               std::uint16_t{3},
                               std::uint16_t{9},
                               std::uint16_t{65535}})
    {
        confirm = kOfflineConfirmActive;
        confirm[26] = static_cast<std::uint8_t>(size);
        confirm[27] = static_cast<std::uint8_t>(size >> 8U);
        denied(confirm, RdpActivePduError::InvalidCapabilitySet);
    }
    confirm = kOfflineConfirmActive;
    confirm[34] = 0; // FONT set length 0, invalid despite known ID.
    denied(confirm, RdpActivePduError::InvalidCapabilitySet);

    // Parent header remains valid after removing bytes, but the
    // nested layout must still be rejected. No side effects.
    for (std::size_t length = 6; length < kOfflineConfirmActive.size();
         ++length)
    {
        std::vector<std::uint8_t> trimmed(
            kOfflineConfirmActive.begin(),
            kOfflineConfirmActive.begin() + length);
        trimmed[0] = static_cast<std::uint8_t>(length);
        const auto result = parseRdpActivePdu(trimmed);
        assert(!result);
        assert(result.value.sourceDescriptor.empty());
        assert(result.value.capabilitySets.empty());
    }
}

void testRdpDemandActiveEncodeWire()
{
    // The independent specification-derived fixture is 38 bytes.
    // The serializer must reproduce the complete Share Control PDU,
    // not wrap it in TLS/MCS or activate a session.
    const auto source = std::span(kOfflineDemandActive).subspan(14, 4);
    const auto capabilities =
        std::span(kOfflineDemandActive).subspan(22, 12);
    std::array<std::uint8_t, 40> output{};
    output.fill(0xa5);
    const auto result = encodeRdpDemandActivePdu(
        0x000103eaU, 0x11223344U, source, 2, capabilities, output);
    assert(result && *result == kOfflineDemandActive.size());
    // The prior parser fixture intentionally uses ignored pad2Octets
    // 0xf017. This writer emits canonical zero padding; compare
    // against the same packet with ONLY those two pad bytes zeroed.
    auto canonical = kOfflineDemandActive;
    canonical[20] = 0;
    canonical[21] = 0;
    assert(std::equal(output.begin(), output.begin() + *result,
                      canonical.begin()));
    assert(output[*result] == 0xa5 && output[*result + 1U] == 0xa5);
    const auto roundtrip = parseRdpActivePdu(
        std::span(output).first(*result));
    assert(roundtrip &&
           roundtrip.value.kind == RdpShareControlKind::DemandActive);
    assert(roundtrip.value.pduSource == 1002 &&
           roundtrip.value.shareId == 0x000103eaU);
    assert(roundtrip.value.capabilityCount == 2);
    assert(roundtrip.value.sourceDescriptor.data() ==
           output.data() + 14);
    assert(roundtrip.value.capabilitySets.data() ==
           output.data() + 22);
    assert(roundtrip.value.sessionId == 0x11223344U);

    // Legal empty capability list is envelope syntax ONLY. It
    // does not make a useful server capability negotiation.
    std::array<std::uint8_t, 25> empty{};
    empty.fill(0xba);
    const auto minimal = encodeRdpDemandActivePdu(
        0U, 0U, {}, 0U, {}, empty);
    assert(minimal && *minimal == 22);
    assert(empty[0] == 22 && empty[1] == 0);
    assert(empty[2] == 0x11 && empty[3] == 0);
    assert(empty[4] == 0xea && empty[5] == 0x03);
    assert(empty[12] == 4 && empty[13] == 0);
    assert(empty[14] == 0 && empty[15] == 0);
    assert(empty[16] == 0 && empty[17] == 0);
    assert(empty[22] == 0xba);
    const auto roundtripEmpty =
        parseRdpActivePdu(std::span(empty).first(*minimal));
    assert(roundtripEmpty && roundtripEmpty.value.capabilityCount == 0);
    assert(roundtripEmpty.value.capabilitySets.empty());
    assert(roundtripEmpty.value.sourceDescriptor.empty());

    // 0x8000 must not be emitted: the existing receiving decoder
    // interprets it as an ignored legacy FlowPDU. Adjacent lengths
    // are structurally valid when backed by sufficient caller memory.
    for (const auto len : {std::size_t{32745}, std::size_t{32747},
                           std::size_t{65513}})
    {
        std::vector<std::uint8_t> descriptor(len, 0x4d);
        std::vector<std::uint8_t> frame(len + 24, 0xa5);
        const auto n = encodeRdpDemandActivePdu(
            0x01020304U, 0xaabbccddU, descriptor, 0U, {}, frame);
        assert(n && *n == len + 22U);
        assert(frame[*n] == 0xa5 && frame[*n + 1U] == 0xa5);
        assert(frame[0] == static_cast<std::uint8_t>(*n));
        assert(frame[1] == static_cast<std::uint8_t>(*n >> 8U));
        const auto parsed = parseRdpActivePdu(
            std::span(frame).first(*n));
        assert(parsed && parsed.value.sourceDescriptor.size() == len);
        assert(parsed.value.capabilitySets.empty());
        assert(parsed.value.shareId == 0x01020304U);
        assert(parsed.value.sessionId == 0xaabbccddU);
    }

    // The encoder accepts unknown capability IDs as opaque
    // envelopes but does not claim to negotiate their semantics.
    auto custom = std::array<std::uint8_t, 12>{};
    std::copy(capabilities.begin(), capabilities.end(), custom.begin());
    custom[0] = 0xff;
    custom[1] = 0x7f;
    const auto foreign = encodeRdpDemandActivePdu(
        5, 6, source, 2, custom, output);
    assert(foreign && *foreign == 38);
    const auto parsedForeign =
        parseRdpActivePdu(std::span(output).first(*foreign));
    assert(parsedForeign && parsedForeign.value.capabilityCount == 2);
    assert(parsedForeign.value.capabilitySets[0] == 0xff);
}

void testRdpDemandActiveEncodeRejections()
{
    const auto source = std::span(kOfflineDemandActive).subspan(14, 4);
    const auto caps = std::span(kOfflineDemandActive).subspan(22, 12);
    const auto denied = [&source](std::uint16_t count,
                                  std::span<const std::uint8_t> capset)
    {
        std::array<std::uint8_t, 40> dest{};
        dest.fill(0xdd);
        assert(!encodeRdpDemandActivePdu(
            7, 8, source, count, capset, dest));
        assert(std::all_of(dest.begin(), dest.end(),
                           [](std::uint8_t byte) { return byte == 0xdd; }));
    };
    for (const auto count : {std::uint16_t{0}, std::uint16_t{1},
                             std::uint16_t{3}, std::uint16_t{65535}})
        denied(count, caps);
    for (std::size_t len = 0; len < caps.size(); ++len)
        denied(2U, caps.first(len));

    // Short, zero, overflowing and trailing-nonconsumed capability
    // envelope sizes all fail without modifying caller storage.
    for (const auto bad : {std::uint16_t{0}, std::uint16_t{1},
                           std::uint16_t{3}, std::uint16_t{9},
                           std::uint16_t{0xffff}})
    {
        auto mutated = std::array<std::uint8_t, 12>{};
        std::copy(caps.begin(), caps.end(), mutated.begin());
        mutated[2] = static_cast<std::uint8_t>(bad);
        mutated[3] = static_cast<std::uint8_t>(bad >> 8U);
        denied(2, mutated);
    }
    auto badLast = std::array<std::uint8_t, 12>{};
    std::copy(caps.begin(), caps.end(), badLast.begin());
    badLast[10] = 0;
    badLast[11] = 0;
    denied(2, badLast);

    // All insufficient destination capacities must fail atomically,
    // including 0 bytes and one byte short of a complete packet.
    std::array<std::uint8_t, 42> guarded{};
    for (std::size_t capacity = 0; capacity < 38; ++capacity)
    {
        guarded.fill(0xcc);
        assert(!encodeRdpDemandActivePdu(
            7, 8, source, 2, caps,
            std::span(guarded).first(capacity)));
        assert(std::all_of(guarded.begin(), guarded.end(),
                           [](std::uint8_t b) { return b == 0xcc; }));
    }

    // 22 + 32746 = 0x8000: reject the special FlowPDU marker
    // even though it would otherwise fit in the 16-bit field.
    std::vector<std::uint8_t> flowDescriptor(32746, 0x42);
    std::vector<std::uint8_t> flowDest(32768, 0xee);
    assert(!encodeRdpDemandActivePdu(
        7, 8, flowDescriptor, 0, {}, flowDest));
    assert(std::all_of(flowDest.begin(), flowDest.end(),
                       [](std::uint8_t b) { return b == 0xee; }));

    // Reject totalLength >65535 and sourceDescriptor LE16 overflow
    // before writing. Large synthetic sources never allocate INSIDE
    // production code.
    std::vector<std::uint8_t> overMax(65514, 0x41);
    std::vector<std::uint8_t> largeDest(65540, 0xee);
    assert(!encodeRdpDemandActivePdu(
        7, 8, overMax, 0, {}, largeDest));
    std::vector<std::uint8_t> over16(65536, 0x41);
    assert(!encodeRdpDemandActivePdu(
        7, 8, over16, 0, {}, largeDest));
    assert(std::all_of(largeDest.begin(), largeDest.end(),
                       [](std::uint8_t b) { return b == 0xee; }));

    // Fail when source or capability input aliases the written
    // output region; otherwise the two independent copies could
    // corrupt a yet-unread input buffer.
    std::array<std::uint8_t, 50> aliases{};
    aliases.fill(0x55);
    std::copy(source.begin(), source.end(), aliases.begin() + 14);
    const auto beforeSource = aliases;
    assert(!encodeRdpDemandActivePdu(
        7, 8, std::span(aliases).subspan(14, 4), 0, {},
        aliases));
    assert(aliases == beforeSource);
    std::copy(caps.begin(), caps.end(), aliases.begin() + 22);
    const auto beforeCaps = aliases;
    assert(!encodeRdpDemandActivePdu(
        7, 8, {}, 2, std::span(aliases).subspan(22, 12),
        aliases));
    assert(aliases == beforeCaps);
}

void testRdpServerFinalizationEncodeWire()
{
    // Microsoft Server Synchronize (MS-RDPBCGR 4.1.19), with the
    // independently documented fixed 18+4-byte layout, canonical
    // ignored pad=0 and an explicit caller-supplied targetUser.
    constexpr std::array<std::uint8_t, 22> goldenSync{
        0x16, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x00,
        0x16, 0x00, 0x1f, 0x00, 0x00, 0x00,
        0x01, 0x00, 0xef, 0x03};
    std::array<std::uint8_t, 30> sync{};
    sync.fill(0xa5);
    const auto syncSize =
        encodeRdpServerSynchronizePdu(0x000103eaU, 1007U, sync);
    assert(syncSize && *syncSize == goldenSync.size());
    assert(std::equal(sync.begin(), sync.begin() + *syncSize,
                      goldenSync.begin()));
    assert(std::all_of(sync.begin() + *syncSize, sync.end(),
                       [](std::uint8_t v) { return v == 0xa5; }));
    const auto parsedSync = parseRdpSynchronizePdu(
        std::span(sync).first(*syncSize));
    assert(parsedSync && parsedSync.value.pduSource == 1002);
    assert(parsedSync.value.shareId == 0x000103eaU);
    assert(parsedSync.value.targetUser == 1007U);

    // Microsoft Server Control (Cooperate / Granted Control),
    // MS-RDPBCGR 4.1.20-21, with ignored pad1 canonicalized
    // to zero. Syntax must never imply the grant occurred.
    constexpr std::array<std::uint8_t, 26> goldenCooperate{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    constexpr std::array<std::uint8_t, 26> goldenGranted{
        0x1a, 0x00, 0x17, 0x00, 0xea, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x02,
        0x1a, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x02, 0x00, 0xef, 0x03, 0xea, 0x03, 0x00, 0x00};
    std::array<std::uint8_t, 30> control{};
    control.fill(0xbb);
    const auto cooperateSize = encodeRdpServerControlPdu(
        0x000103eaU, RdpControlAction::Cooperate, 0U, control);
    assert(cooperateSize && *cooperateSize == goldenCooperate.size());
    assert(std::equal(control.begin(), control.begin() + *cooperateSize,
                      goldenCooperate.begin()));
    assert(control[*cooperateSize] == 0xbb &&
           control[*cooperateSize + 1U] == 0xbb);
    const auto coop = parseRdpControlPdu(
        std::span(control).first(*cooperateSize));
    assert(coop && coop.value.action == RdpControlAction::Cooperate);
    assert(coop.value.pduSource == 1002);
    assert(coop.value.shareId == 0x000103eaU);
    assert(coop.value.grantId == 0 && coop.value.controlId == 0);

    control.fill(0xcc);
    const auto grantedSize = encodeRdpServerControlPdu(
        0x000103eaU, RdpControlAction::GrantedControl, 1007U, control);
    assert(grantedSize && *grantedSize == goldenGranted.size());
    assert(std::equal(control.begin(), control.begin() + *grantedSize,
                      goldenGranted.begin()));
    assert(control[*grantedSize] == 0xcc);
    const auto granted = parseRdpControlPdu(
        std::span(control).first(*grantedSize));
    assert(granted && granted.value.action ==
           RdpControlAction::GrantedControl);
    assert(granted.value.grantId == 1007);
    assert(granted.value.controlId == 1002);

    // The historical Microsoft Server Synchronize example has an
    // uninitialized targetUser. Preserve every raw LE16 value rather
    // than misidentifying syntax decoding as channel authorization.
    for (const auto id : {std::uint16_t{0}, std::uint16_t{1001},
                          std::uint16_t{0x4463}, std::uint16_t{65535}})
    {
        std::array<std::uint8_t, 22> packet{};
        const auto n = encodeRdpServerSynchronizePdu(
            0xfedcba98U, id, packet);
        assert(n && *n == packet.size());
        const auto parsed = parseRdpSynchronizePdu(packet);
        assert(parsed && parsed.value.targetUser == id);
        assert(parsed.value.shareId == 0xfedcba98U);
        assert(packet[20] == static_cast<std::uint8_t>(id));
        assert(packet[21] == static_cast<std::uint8_t>(id >> 8U));
    }

    for (const auto id : {1001U, 1007U, 65535U})
    {
        std::array<std::uint8_t, 26> packet{};
        const auto n = encodeRdpServerControlPdu(
            0xffffffffU, RdpControlAction::GrantedControl, id, packet);
        assert(n && *n == packet.size());
        const auto parsed = parseRdpControlPdu(packet);
        assert(parsed && parsed.value.grantId == id);
        assert(parsed.value.controlId == 1002);
        assert(parsed.value.shareId == 0xffffffffU);
    }
}

void testRdpServerFinalizationEncodeRejections()
{
    // Every incomplete destination must remain entirely unchanged.
    std::array<std::uint8_t, 32> packet{};
    for (std::size_t capacity = 0; capacity < 22U; ++capacity)
    {
        packet.fill(0xdd);
        assert(!encodeRdpServerSynchronizePdu(
            42U, 1002U, std::span(packet).first(capacity)));
        assert(std::all_of(packet.begin(), packet.end(),
                           [](std::uint8_t v) { return v == 0xdd; }));
    }
    for (std::size_t capacity = 0; capacity < 26U; ++capacity)
    {
        packet.fill(0xdd);
        assert(!encodeRdpServerControlPdu(
            42U, RdpControlAction::Cooperate, 0U,
            std::span(packet).first(capacity)));
        assert(std::all_of(packet.begin(), packet.end(),
                           [](std::uint8_t v) { return v == 0xdd; }));
    }

    const auto rejectAtomic = [&](RdpControlAction action,
                                  std::uint32_t assignedId)
    {
        packet.fill(0xef);
        assert(!encodeRdpServerControlPdu(42U, action, assignedId,
                                          packet));
        assert(std::all_of(packet.begin(), packet.end(),
                           [](std::uint8_t v) { return v == 0xef; }));
    };
    // Client-only actions are never server-side emissions.
    rejectAtomic(RdpControlAction::RequestControl, 0U);
    rejectAtomic(RdpControlAction::Detach, 0U);
    rejectAtomic(static_cast<RdpControlAction>(0), 1007U);
    rejectAtomic(static_cast<RdpControlAction>(5), 1007U);
    rejectAtomic(static_cast<RdpControlAction>(65535), 1007U);

    // Cooperate must have zero grant/control IDs; Granted must
    // encode an assigned 16-bit MCS client user channel only.
    for (const auto nonzero : {1U, 1001U, 1007U, 65535U, 65536U})
        rejectAtomic(RdpControlAction::Cooperate, nonzero);
    for (const auto invalid : {0U, 1U, 1000U, 65536U, 0xffffffffU})
        rejectAtomic(RdpControlAction::GrantedControl, invalid);

    // Minimal valid buffers still leave no opportunity for silent
    // overrun or hidden second Share Data record.
    std::array<std::uint8_t, 22> sync{};
    assert(encodeRdpServerSynchronizePdu(0U, 0U, sync) == sync.size());
    assert(parseRdpSynchronizePdu(sync));
    std::array<std::uint8_t, 26> control{};
    assert(encodeRdpServerControlPdu(
        0U, RdpControlAction::Cooperate, 0U, control) ==
           control.size());
    assert(parseRdpControlPdu(control));
}

void testRdpActiveExchangeCorrelation()
{
    // Both fixtures already independently pass the strict T.128
    // Demand/Confirm Active parsers. Correlation here is NOT the
    // separate GSS, MCS channel or OS authorization proof.
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, kOfflineConfirmActive, 1007U) ==
           RdpActiveExchangeCorrelation::ConsistentSyntaxOnly);

    // A freshly serialized Demand Active with canonical ignored pad
    // must correlate with a syntactically valid client Confirm.
    std::array<std::uint8_t, 38> demand{};
    const auto source = std::span(kOfflineDemandActive).subspan(14, 4);
    const auto caps = std::span(kOfflineDemandActive).subspan(22, 12);
    const auto size = encodeRdpDemandActivePdu(
        0x000103eaU, 0x11223344U, source, 2, caps, demand);
    assert(size && *size == demand.size());
    assert(correlateRdpActiveExchange(
               demand, kOfflineConfirmActive, 1007U) ==
           RdpActiveExchangeCorrelation::ConsistentSyntaxOnly);

    // The server's sessionId is NOT an authentication token.
    // Changing it does not alter the shared shareID correlation.
    demand[34] = 0;
    demand[35] = 0;
    demand[36] = 0;
    demand[37] = 0;
    assert(correlateRdpActiveExchange(
               demand, kOfflineConfirmActive, 1007U) ==
           RdpActiveExchangeCorrelation::ConsistentSyntaxOnly);

    // A new MCS user channel can be represented by the client's
    // Share Control source when it matches an independently supplied
    // expected ID. This does NOT actually assign or join the channel.
    auto client = kOfflineConfirmActive;
    client[4] = 0xff;
    client[5] = 0xff;
    assert(correlateRdpActiveExchange(
               demand, client, 65535U) ==
           RdpActiveExchangeCorrelation::ConsistentSyntaxOnly);

    // Source-descriptor and capability bytes remain opaque. A
    // syntactically correlated exchange may advertise disjoint,
    // incompatible sets; the future owner MUST validate all
    // mandatory capability values before any live activation.
    client = kOfflineConfirmActive;
    client[16] = 'X';
    client[24] = 0xff;
    client[25] = 0x7f;
    assert(correlateRdpActiveExchange(
               demand, client, 1007U) ==
           RdpActiveExchangeCorrelation::ConsistentSyntaxOnly);
}

void testRdpActiveExchangeDenials()
{
    constexpr auto rejected = RdpActiveExchangeCorrelation::Rejected;
    for (const auto id : {0U, 1U, 1000U, 65536U, 0xffffffffU})
        assert(correlateRdpActiveExchange(
                   kOfflineDemandActive, kOfflineConfirmActive, id) ==
               rejected);

    for (std::size_t i = 0; i < kOfflineDemandActive.size(); ++i)
        assert(correlateRdpActiveExchange(
                   std::span(kOfflineDemandActive).first(i),
                   kOfflineConfirmActive, 1007U) == rejected);
    for (std::size_t i = 0; i < kOfflineConfirmActive.size(); ++i)
        assert(correlateRdpActiveExchange(
                   kOfflineDemandActive,
                   std::span(kOfflineConfirmActive).first(i),
                   1007U) == rejected);

    auto demandSurplus = std::vector<std::uint8_t>(
        kOfflineDemandActive.begin(), kOfflineDemandActive.end());
    demandSurplus.push_back(0);
    assert(correlateRdpActiveExchange(
               demandSurplus, kOfflineConfirmActive, 1007U) ==
           rejected);
    auto confirmSurplus = std::vector<std::uint8_t>(
        kOfflineConfirmActive.begin(), kOfflineConfirmActive.end());
    confirmSurplus.push_back(0);
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, confirmSurplus, 1007U) ==
           rejected);

    auto demand = kOfflineDemandActive;
    auto confirm = kOfflineConfirmActive;
    // Valid Share Control but the wrong role, or an unexpected
    // source user channel, cannot be correlated as Demand->Confirm.
    assert(correlateRdpActiveExchange(
               kOfflineConfirmActive, kOfflineDemandActive, 1007U) ==
           rejected);
    demand[4] = 0xeb; // User channel, NOT normative server source 1002.
    assert(correlateRdpActiveExchange(
               demand, kOfflineConfirmActive, 1007U) ==
           rejected);
    confirm[4] = 0xea; // Claimed server as client.
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, confirm, 1007U) == rejected);
    confirm = kOfflineConfirmActive;
    confirm[5] = 0xff; // Different client user source.
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, confirm, 1007U) == rejected);

    confirm = kOfflineConfirmActive;
    confirm[6] ^= 0x01; // ShareID mismatch, though both valid PDUs.
    assert(parseRdpActivePdu(confirm));
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, confirm, 1007U) == rejected);
    confirm = kOfflineConfirmActive;
    confirm[10] = 0xeb; // originatorID must identify server channel.
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, confirm, 1007U) == rejected);

    demand = kOfflineDemandActive;
    demand[2] = 0x13; // Confirm instead of Demand.
    assert(correlateRdpActiveExchange(
               demand, kOfflineConfirmActive, 1007U) == rejected);
    demand = kOfflineDemandActive;
    demand[12] = 0x03; // combinedCapabilities < count/pad.
    assert(correlateRdpActiveExchange(
               demand, kOfflineConfirmActive, 1007U) == rejected);
    confirm = kOfflineConfirmActive;
    confirm[26] = 0x00; // Capability envelope has zero length.
    assert(correlateRdpActiveExchange(
               kOfflineDemandActive, confirm, 1007U) == rejected);

    // A legacy FlowPDU marker MUST be ignored by the shared
    // Share Control validator; never mistaken for an active PDU.
    demand = kOfflineDemandActive;
    demand[0] = 0;
    demand[1] = 0x80;
    assert(correlateRdpActiveExchange(
               demand, kOfflineConfirmActive, 1007U) == rejected);
}


void testRdpFinalizationExchangeCorrelation()
{
    // Microsoft MS-RDPBCGR 4.1.14-16 plaintext client examples.
    constexpr std::array<std::uint8_t, 22> clientSync{
        0x16, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x08, 0x00, 0x1f, 0x00, 0x00, 0x00,
        0x01, 0x00, 0xea, 0x03};
    constexpr std::array<std::uint8_t, 26> clientCooperate{
        0x1a, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x0c, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto clientRequest = clientCooperate;
    clientRequest[18] = 1U;
    constexpr std::uint32_t shareId = 0x000103eaU;
    std::array<std::uint8_t, 22> serverSync{};
    std::array<std::uint8_t, 26> serverCooperate{};
    std::array<std::uint8_t, 26> serverGranted{};
    assert(encodeRdpServerSynchronizePdu(
        shareId, 0x4463U, serverSync) == serverSync.size());
    assert(encodeRdpServerControlPdu(
        shareId, RdpControlAction::Cooperate, 0U, serverCooperate) ==
           serverCooperate.size());
    assert(encodeRdpServerControlPdu(
        shareId, RdpControlAction::GrantedControl, 1007U, serverGranted) ==
           serverGranted.size());
    const RdpFinalizationTranscript transcript{
        clientSync, clientCooperate, clientRequest, serverSync,
        serverCooperate, serverGranted};
    constexpr auto consistent =
        RdpFinalizationCorrelation::ConsistentSyntaxOnly;
    assert(correlateRdpFinalizationExchange(
               transcript, shareId, 1007U) == consistent);

    // The documented Server Synchronize targetUser can be
    // uninitialized and is never evidence of authenticated identity.
    for (std::uint16_t target : {std::uint16_t{0}, std::uint16_t{1002},
                                 std::uint16_t{1007}, std::uint16_t{65535}})
    {
        assert(encodeRdpServerSynchronizePdu(
            shareId, target, serverSync) == serverSync.size());
        assert(correlateRdpFinalizationExchange(
                   transcript, shareId, 1007U) == consistent);
    }
}

void testRdpFinalizationExchangeDenials()
{
    constexpr std::uint32_t shareId = 0x000103eaU;
    std::array<std::uint8_t, 22> clientSync{
        0x16, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x08, 0x00, 0x1f, 0x00, 0x00, 0x00,
        0x01, 0x00, 0xea, 0x03};
    std::array<std::uint8_t, 26> clientCooperate{
        0x1a, 0x00, 0x17, 0x00, 0xef, 0x03,
        0xea, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x0c, 0x00, 0x14, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto clientRequest = clientCooperate;
    clientRequest[18] = 1U;
    std::array<std::uint8_t, 22> serverSync{};
    std::array<std::uint8_t, 26> serverCooperate{};
    std::array<std::uint8_t, 26> serverGranted{};
    assert(encodeRdpServerSynchronizePdu(
        shareId, 0U, serverSync) == serverSync.size());
    assert(encodeRdpServerControlPdu(
        shareId, RdpControlAction::Cooperate, 0U, serverCooperate) ==
           serverCooperate.size());
    assert(encodeRdpServerControlPdu(
        shareId, RdpControlAction::GrantedControl, 1007U, serverGranted) ==
           serverGranted.size());
    const RdpFinalizationTranscript transcript{
        clientSync, clientCooperate, clientRequest, serverSync,
        serverCooperate, serverGranted};
    const auto check = [&]() {
        return correlateRdpFinalizationExchange(
            transcript, shareId, 1007U);
    };
    constexpr auto denied = RdpFinalizationCorrelation::Rejected;
    constexpr auto consistent =
        RdpFinalizationCorrelation::ConsistentSyntaxOnly;
    assert(check() == consistent);
    for (const auto invalid : {0U, 1U, 1000U, 65536U, 0xffffffffU})
        assert(correlateRdpFinalizationExchange(
                   transcript, shareId, invalid) == denied);
    assert(correlateRdpFinalizationExchange(
               transcript, shareId ^ 1U, 1007U) == denied);

    // Six independent whole-message boundaries, with exact length
    // enforced by the existing underlying parsers.
    for (std::size_t position = 0; position < 6U; ++position)
    {
        const std::array<std::span<const std::uint8_t>, 6> packets{
            transcript.clientSynchronize, transcript.clientCooperate,
            transcript.clientRequestControl, transcript.serverSynchronize,
            transcript.serverCooperate, transcript.serverGrantedControl};
        const auto packet = packets[position];
        for (std::size_t bytes = 0; bytes < packet.size(); ++bytes)
        {
            auto incomplete = transcript;
            const auto clipped = packet.first(bytes);
            switch (position)
            {
            case 0: incomplete.clientSynchronize = clipped; break;
            case 1: incomplete.clientCooperate = clipped; break;
            case 2: incomplete.clientRequestControl = clipped; break;
            case 3: incomplete.serverSynchronize = clipped; break;
            case 4: incomplete.serverCooperate = clipped; break;
            default: incomplete.serverGrantedControl = clipped; break;
            }
            assert(correlateRdpFinalizationExchange(
                       incomplete, shareId, 1007U) == denied);
        }
    }
    std::vector<std::uint8_t> extended(clientSync.begin(), clientSync.end());
    extended.push_back(0);
    auto trailing = transcript;
    trailing.clientSynchronize = extended;
    assert(correlateRdpFinalizationExchange(
               trailing, shareId, 1007U) == denied);

    // Restore each field before checking the next independent error.
    clientSync[4] = 0xea; assert(check() == denied); clientSync[4] = 0xef;
    clientSync[20] = 0xef; assert(check() == denied); clientSync[20] = 0xea;
    clientCooperate[18] = 1; assert(check() == denied); clientCooperate[18] = 4;
    clientCooperate[20] = 1; assert(check() == denied); clientCooperate[20] = 0;
    clientRequest[24] = 1; assert(check() == denied); clientRequest[24] = 0;
    clientRequest[18] = 3; assert(check() == denied); clientRequest[18] = 1;
    serverSync[4] = 0xef; assert(check() == denied); serverSync[4] = 0xea;
    serverCooperate[6] ^= 1; assert(check() == denied); serverCooperate[6] ^= 1;
    serverCooperate[22] = 1; assert(check() == denied); serverCooperate[22] = 0;
    serverGranted[18] = 4; assert(check() == denied); serverGranted[18] = 2;
    serverGranted[20] ^= 1; assert(check() == denied); serverGranted[20] ^= 1;
    serverGranted[22] ^= 1; assert(check() == denied); serverGranted[22] ^= 1;
    serverGranted[15] = 0x20; assert(check() == denied); serverGranted[15] = 0;
    assert(check() == consistent);
}

void testMcsJoinWriteCompletion()
{
    // MS-RDPBCGR 4.1.8.2.1: exact client ChannelJoinRequest for
    // assigned user 1007 and I/O channel 1003.
    constexpr std::array<std::uint8_t, 12> joinWire{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    const auto parsed = parseMcsChannelRequest(joinWire);
    assert(parsed && parsed.request.kind == McsChannelRequestKind::ChannelJoin);
    McsChannelJoinWriteGate gate;
    assert(!gate.channelJoinConfirmed(1003));
    assert(gate.pendingBytes().empty());
    assert(gate.configure(1007, channels));
    assert(gate.beginJoin(parsed.request) == McsJoinStartOutcome::ReplyPending);
    const auto exactResponse = encodeMcsChannelJoinConfirm(
        parsed.request, 1007, channels);
    assert(exactResponse);
    assert(std::equal(gate.pendingBytes().begin(), gate.pendingBytes().end(),
                      exactResponse.bytes().begin(), exactResponse.bytes().end()));
    assert(!gate.channelJoinConfirmed(1003));
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 0) == McsJoinWriteOutcome::Pending);
    for (std::size_t index = 0; index + 1 < exactResponse.length; ++index)
    {
        assert(gate.pendingBytes().size() == exactResponse.length - index);
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 1) == McsJoinWriteOutcome::Pending);
        assert(!gate.channelJoinConfirmed(1003));
    }
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 1) == McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1003));
    assert(!gate.channelJoinConfirmed(1007));
    assert(!gate.channelJoinConfirmed(1005));
    assert(gate.pendingBytes().empty());

    // A subsequent, separately serialized join can then be confirmed.
    auto userJoin = parsed.request;
    userJoin.channelId = 1007;
    assert(gate.beginJoin(userJoin) == McsJoinStartOutcome::ReplyPending);
    const auto remainder = gate.pendingBytes().size();
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), remainder) ==
           McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1007));
    gate.close();
    assert(!gate.channelJoinConfirmed(1003));
    assert(!gate.channelJoinConfirmed(1007));
    assert(gate.pendingBytes().empty());
}

void testMcsJoinWriteDenials()
{
    constexpr std::array<std::uint16_t, 2> channels{1007, 1003};
    constexpr std::array<std::uint16_t, 2> duplicate{1003, 1003};
    constexpr std::array<std::uint16_t, 2> zero{1003, 0};
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    for (const auto invalid : {0U, 1000U, 65537U, 0xffffffffU})
    {
        McsChannelJoinWriteGate gate;
        assert(!gate.configure(invalid, channels));
        assert(!gate.configure(1007, channels)); // terminal denial
    }
    // The existing production MCS encoder accepts the final T.125 UserId
    // 65536; the join-delivery guard must not disagree at that boundary.
    {
        McsChannelJoinWriteGate gate;
        auto finalUserJoin = join;
        finalUserJoin.initiator = 65536U;
        assert(gate.configure(65536U, channels));
        assert(gate.beginJoin(finalUserJoin) == McsJoinStartOutcome::ReplyPending);
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), gate.pendingBytes().size()) ==
               McsJoinWriteOutcome::Confirmed);
        assert(gate.channelJoinConfirmed(1003));
    }
    {
        McsChannelJoinWriteGate gate;
        assert(!gate.configure(1007, duplicate));
        assert(gate.beginJoin(join) == McsJoinStartOutcome::Rejected);
    }
    {
        McsChannelJoinWriteGate gate;
        assert(!gate.configure(1007, zero));
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        assert(!gate.configure(1007, channels)); // no identity replacement
        assert(gate.beginJoin(join) == McsJoinStartOutcome::Rejected);
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 0) == McsJoinWriteOutcome::Rejected);
        assert(!gate.configure(1007, channels));
    }
    for (const auto invalidChannel : {0U, 1004U, 65535U})
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        auto bad = join;
        bad.channelId = static_cast<std::uint16_t>(invalidChannel);
        assert(gate.beginJoin(bad) == McsJoinStartOutcome::Rejected);
        assert(!gate.channelJoinConfirmed(1003));
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        auto bad = join;
        bad.initiator = 1008;
        assert(gate.beginJoin(bad) == McsJoinStartOutcome::Rejected);
        assert(!gate.configure(1007, channels));
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 4) == McsJoinWriteOutcome::Pending);
        assert(gate.beginJoin(join) == McsJoinStartOutcome::AlreadyPending);
        assert(!gate.channelJoinConfirmed(1003));
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), gate.pendingBytes().size()) ==
               McsJoinWriteOutcome::Confirmed);
        assert(gate.channelJoinConfirmed(1003));
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), gate.pendingBytes().size() + 1) ==
               McsJoinWriteOutcome::Rejected); // over-reported write
        assert(!gate.channelJoinConfirmed(1003));
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), gate.pendingBytes().size()) ==
               McsJoinWriteOutcome::Confirmed);
        assert(gate.beginJoin(join) == McsJoinStartOutcome::AlreadyJoined);
        assert(gate.channelJoinConfirmed(1003));
        assert(gate.pendingBytes().empty());
    }
    {
        McsChannelJoinWriteGate gate;
        assert(gate.configure(1007, channels));
        assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 2) == McsJoinWriteOutcome::Pending);
        gate.close(); // disconnect cancels pending and prior membership
        assert(gate.pendingBytes().empty());
        assert(!gate.channelJoinConfirmed(1003));
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 0) == McsJoinWriteOutcome::Rejected);
        assert(!gate.configure(1007, channels));
    }
}

void testMcsJoinDuplicateIgnored()
{
    // MS-RDPBCGR 3.3.5.3.8: a fully joined channel must not be
    // reconfirmed or cause the server to terminate an otherwise live domain.
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), gate.pendingBytes().size()) ==
           McsJoinWriteOutcome::Confirmed);
    for (int repeated = 0; repeated < 3; ++repeated)
    {
        assert(gate.beginJoin(join) == McsJoinStartOutcome::AlreadyJoined);
        assert(gate.pendingBytes().empty());
        assert(gate.channelJoinConfirmed(1003));
    }
    join.channelId = 1005;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(!gate.channelJoinConfirmed(1005));
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), gate.pendingBytes().size()) ==
           McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1003));
    assert(gate.channelJoinConfirmed(1005));
    gate.close();
    assert(!gate.channelJoinConfirmed(1003));
    assert(!gate.channelJoinConfirmed(1005));
}

void testMcsJoinBatchedRequests()
{
    // RDP 8.1/10.0/10.1 can batch user, I/O and all static-channel joins
    // before the first confirmation. Bound the complete pending batch to
    // one record per allocated channel; never retain borrowed packet spans.
    std::array<std::uint16_t, kMaximumStaticChannelCount + 2U> channels{};
    channels[0] = 1007;
    for (std::size_t i = 1; i < channels.size(); ++i)
        channels[i] = static_cast<std::uint16_t>(1200U + i);
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    McsChannelRequest request{};
    request.kind = McsChannelRequestKind::ChannelJoin;
    request.initiator = 1007;
    for (std::size_t i = 0; i < channels.size(); ++i)
    {
        request.channelId = channels[i];
        assert(gate.beginJoin(request) == (i == 0
            ? McsJoinStartOutcome::ReplyPending
            : McsJoinStartOutcome::Buffered));
        assert(gate.beginJoin(request) == McsJoinStartOutcome::AlreadyPending);
        assert(!gate.channelJoinConfirmed(channels[i]));
    }
    // A queued channel is not joined before its OWN confirmation bytes.
    for (std::size_t i = 0; i < channels.size(); ++i)
    {
        request.channelId = channels[i];
        const auto expected = encodeMcsChannelJoinConfirm(request, 1007, channels);
        assert(expected);
        const auto bytes = gate.pendingBytes();
        assert(bytes.size() == expected.length);
        assert(std::equal(bytes.begin(), bytes.end(),
                          expected.bytes().begin(), expected.bytes().end()));
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 1) == McsJoinWriteOutcome::Pending);
        assert(!gate.channelJoinConfirmed(channels[i]));
        assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), expected.length - 1) ==
               McsJoinWriteOutcome::Confirmed);
        assert(gate.channelJoinConfirmed(channels[i]));
        assert(gate.beginJoin(request) == McsJoinStartOutcome::AlreadyJoined);
        if (i + 1 < channels.size())
            assert(gate.pendingBytes().size() == expected.length);
    }
    assert(gate.pendingBytes().empty());
    gate.close();
    for (const auto id : channels)
        assert(!gate.channelJoinConfirmed(id));

    // Cancellation erases both a pending partial reply and every queued ID.
    McsChannelJoinWriteGate cancelled;
    assert(cancelled.configure(1007, channels));
    request.channelId = channels[0];
    assert(cancelled.beginJoin(request) == McsJoinStartOutcome::ReplyPending);
    assert(cancelled.onReplyBytesWritten(cancelled.pendingReplySequence(), cancelled.pendingWriteSliceSequence(), 3) == McsJoinWriteOutcome::Pending);
    request.channelId = channels[1];
    assert(cancelled.beginJoin(request) == McsJoinStartOutcome::Buffered);
    cancelled.close();
    assert(cancelled.pendingBytes().empty());
    assert(!cancelled.channelJoinConfirmed(channels[0]));
    assert(!cancelled.channelJoinConfirmed(channels[1]));
    assert(cancelled.onReplyBytesWritten(cancelled.pendingReplySequence(), cancelled.pendingWriteSliceSequence(), 0) == McsJoinWriteOutcome::Rejected);

    // Foreign IDs are terminal even while a legitimate batch is waiting.
    McsChannelJoinWriteGate denied;
    assert(denied.configure(1007, channels));
    request.channelId = channels[0];
    assert(denied.beginJoin(request) == McsJoinStartOutcome::ReplyPending);
    request.channelId = channels[1];
    assert(denied.beginJoin(request) == McsJoinStartOutcome::Buffered);
    request.channelId = 65535;
    assert(denied.beginJoin(request) == McsJoinStartOutcome::Rejected);
    assert(denied.pendingBytes().empty());
    for (const auto id : channels)
        assert(!denied.channelJoinConfirmed(id));

    // 31 static + two base channels is the fixed maximum.
    std::array<std::uint16_t, kMaximumStaticChannelCount + 3U> tooMany{};
    for (std::size_t i = 0; i < tooMany.size(); ++i)
        tooMany[i] = static_cast<std::uint16_t>(1300U + i);
    McsChannelJoinWriteGate oversized;
    assert(!oversized.configure(1007, tooMany));
    assert(!oversized.configure(1007, channels));
}

void testMcsJoinedSendDataMembership()
{
    // Parse the genuine T.125 SendDataRequest envelope before consulting
    // this offline join-membership gate. No TLS/OS admission is asserted.
    constexpr std::array<std::uint8_t, 9> sendMcs{
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x02, 0x55, 0xaa};
    const auto frame = frameDomainPdu(sendMcs);
    const auto parsed = parseMcsChannelRequest(frame);
    assert(parsed);
    assert(parsed.request.kind == McsChannelRequestKind::SendDataRequest);
    assert(parsed.request.initiator == 1007);
    assert(parsed.request.channelId == 1003);
    assert(parsed.request.userData.size() == 2);
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    McsChannelJoinWriteGate gate;
    assert(!gate.matchesJoinedInboundSendData(parsed.request));
    assert(gate.configure(1007, channels));
    assert(!gate.matchesJoinedInboundSendData(parsed.request));

    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 14) == McsJoinWriteOutcome::Pending);
    assert(!gate.matchesJoinedInboundSendData(parsed.request));
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 1) == McsJoinWriteOutcome::Confirmed);
    assert(gate.matchesJoinedInboundSendData(parsed.request));

    auto unjoined = parsed.request;
    unjoined.channelId = 1005;
    assert(!gate.matchesJoinedInboundSendData(unjoined));
    join.channelId = 1005;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(!gate.matchesJoinedInboundSendData(unjoined));
    assert(gate.matchesJoinedInboundSendData(parsed.request));
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 15) == McsJoinWriteOutcome::Confirmed);
    assert(gate.matchesJoinedInboundSendData(unjoined));
    gate.close();
    assert(!gate.matchesJoinedInboundSendData(parsed.request));
    assert(!gate.matchesJoinedInboundSendData(unjoined));
}

void testMcsJoinedSendDataDenials()
{
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 15) == McsJoinWriteOutcome::Confirmed);
    McsChannelRequest request{};
    request.kind = McsChannelRequestKind::SendDataRequest;
    request.initiator = 1007;
    request.channelId = 1003;
    assert(gate.matchesJoinedInboundSendData(request));
    auto bad = request;
    bad.kind = McsChannelRequestKind::ChannelJoin;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.initiator = 1008;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.channelId = 0;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.channelId = 999;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.channelId = 1005; // allocated, but not yet joined
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.subHeight = 1;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.subInterval = 1;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.dataPriority = 4;
    assert(!gate.matchesJoinedInboundSendData(bad));
    bad = request;
    bad.segmentation = 4;
    assert(!gate.matchesJoinedInboundSendData(bad));
    // Denied probes cannot corrupt an independently completed join.
    assert(gate.matchesJoinedInboundSendData(request));
    gate.close();
    assert(!gate.matchesJoinedInboundSendData(request));
}

void testMcsJoinStaleWriteReceipts()
{
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto firstReceipt = gate.pendingReplySequence();
    assert(firstReceipt != 0);
    assert(gate.onReplyBytesWritten(firstReceipt, gate.pendingWriteSliceSequence(), 7) ==
           McsJoinWriteOutcome::Pending);
    assert(gate.pendingReplySequence() == firstReceipt);
    join.channelId = 1005;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::Buffered);
    assert(gate.onReplyBytesWritten(firstReceipt, gate.pendingWriteSliceSequence(), 8) ==
           McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1003));
    assert(!gate.channelJoinConfirmed(1005));
    const auto nextReceipt = gate.pendingReplySequence();
    assert(nextReceipt != 0 && nextReceipt != firstReceipt);
    assert(gate.pendingBytes().size() == 15);
    // An earlier, duplicated write callback must not complete the next
    // channel's response; close all joined and pending membership.
    assert(gate.onReplyBytesWritten(firstReceipt, gate.pendingWriteSliceSequence(), 15) ==
           McsJoinWriteOutcome::Rejected);
    assert(gate.pendingReplySequence() == 0);
    assert(gate.pendingBytes().empty());
    assert(!gate.channelJoinConfirmed(1003));
    assert(!gate.channelJoinConfirmed(1005));
    assert(gate.onReplyBytesWritten(nextReceipt, gate.pendingWriteSliceSequence(), 1) ==
           McsJoinWriteOutcome::Rejected);

    McsChannelJoinWriteGate forged;
    assert(forged.configure(1007, channels));
    join.channelId = 1003;
    assert(forged.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto correct = forged.pendingReplySequence();
    assert(correct != 0);
    assert(forged.onReplyBytesWritten(0, forged.pendingWriteSliceSequence(), 0) ==
           McsJoinWriteOutcome::Rejected);
    assert(forged.pendingBytes().empty());

    McsChannelJoinWriteGate future;
    assert(future.configure(1007, channels));
    assert(future.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto current = future.pendingReplySequence();
    assert(current != 0);
    assert(future.onReplyBytesWritten(current + 1U, future.pendingWriteSliceSequence(), 1) ==
           McsJoinWriteOutcome::Rejected);
    assert(future.pendingReplySequence() == 0);

    McsChannelJoinWriteGate cancelled;
    assert(cancelled.configure(1007, channels));
    assert(cancelled.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto abandoned = cancelled.pendingReplySequence();
    cancelled.close();
    assert(cancelled.onReplyBytesWritten(abandoned, cancelled.pendingWriteSliceSequence(), 15) ==
           McsJoinWriteOutcome::Rejected);
}

void testMcsJoinStalePartialWriteSlices()
{
    // A reply ID alone cannot distinguish two writes of the SAME
    // 15-byte confirmation. Duplicate callbacks must not double-count.
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto reply = gate.pendingReplySequence();
    const auto firstSlice = gate.pendingWriteSliceSequence();
    assert(reply != 0 && firstSlice != 0);
    assert(gate.pendingBytes().size() == 15);
    assert(gate.onReplyBytesWritten(reply, firstSlice, 0) ==
           McsJoinWriteOutcome::Pending);
    assert(gate.pendingWriteSliceSequence() == firstSlice);
    assert(gate.onReplyBytesWritten(reply, firstSlice, 4) ==
           McsJoinWriteOutcome::Pending);
    const auto secondSlice = gate.pendingWriteSliceSequence();
    assert(secondSlice != 0 && secondSlice != firstSlice);
    assert(gate.pendingReplySequence() == reply);
    assert(gate.pendingBytes().size() == 11);
    // Duplicated first callback must revoke, not consume four extra bytes.
    assert(gate.onReplyBytesWritten(reply, firstSlice, 4) ==
           McsJoinWriteOutcome::Rejected);
    assert(gate.pendingBytes().empty());
    assert(gate.pendingWriteSliceSequence() == 0);
    assert(!gate.channelJoinConfirmed(1003));
    assert(gate.onReplyBytesWritten(reply, secondSlice, 11) ==
           McsJoinWriteOutcome::Rejected);

    McsChannelJoinWriteGate progress;
    assert(progress.configure(1007, channels));
    assert(progress.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto sameReply = progress.pendingReplySequence();
    const auto partOne = progress.pendingWriteSliceSequence();
    assert(progress.onReplyBytesWritten(sameReply, partOne, 14) ==
           McsJoinWriteOutcome::Pending);
    const auto partTwo = progress.pendingWriteSliceSequence();
    assert(partTwo != partOne);
    assert(progress.onReplyBytesWritten(sameReply, partTwo, 1) ==
           McsJoinWriteOutcome::Confirmed);
    assert(progress.channelJoinConfirmed(1003));

    // A callback with no write-slice identity must terminally revoke.
    McsChannelJoinWriteGate missing;
    assert(missing.configure(1007, channels));
    assert(missing.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(missing.onReplyBytesWritten(missing.pendingReplySequence(), 0, 1) ==
           McsJoinWriteOutcome::Rejected);
    assert(!missing.channelJoinConfirmed(1003));

    // A future slice ID must also fail closed, never skip progress.
    McsChannelJoinWriteGate futureSlice;
    assert(futureSlice.configure(1007, channels));
    assert(futureSlice.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(futureSlice.onReplyBytesWritten(
               futureSlice.pendingReplySequence(),
               futureSlice.pendingWriteSliceSequence() + 1U, 1) ==
           McsJoinWriteOutcome::Rejected);
}

void testMcsJoinedSendIndicationWire()
{
    // MS-RDPBCGR 2.2.6.1: server SendDataIndication, MCS choice 26.
    constexpr std::array<std::uint16_t, 3> channels{1007, 1003, 1005};
    constexpr std::array<std::uint8_t, 2> payload{0xde, 0xad};
    constexpr std::array<std::uint8_t, 16> golden{
        0x03, 0x00, 0x00, 0x10, 0x02, 0xf0, 0x80, 0x68,
        0x00, 0x06, 0x03, 0xeb, 0x70, 0x02, 0xde, 0xad};
    std::array<std::uint8_t, 24> output{};
    output.fill(0xa5);
    McsChannelJoinWriteGate gate;
    assert(!gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output));
    assert(gate.configure(1007, channels));
    assert(!gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(),
               gate.pendingWriteSliceSequence(), 14) == McsJoinWriteOutcome::Pending);
    assert(!gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output));
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(),
               gate.pendingWriteSliceSequence(), 1) == McsJoinWriteOutcome::Confirmed);
    const auto result =
        gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output);
    assert(result && *result == golden.size());
    assert(std::equal(golden.begin(), golden.end(), output.begin()));
    for (std::size_t i = *result; i < output.size(); ++i)
        assert(output[i] == 0xa5);

    join.channelId = 1005;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(!gate.encodeJoinedSendDataIndication(1005, 1, 3, payload, output));
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(),
               gate.pendingWriteSliceSequence(), 15) == McsJoinWriteOutcome::Confirmed);
    const auto second =
        gate.encodeJoinedSendDataIndication(1005, 1, 3, payload, output);
    assert(second && *second == golden.size());
    assert(output[10] == 0x03 && output[11] == 0xed);
    gate.close();
    assert(!gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output));
    assert(!gate.encodeJoinedSendDataIndication(1005, 1, 3, payload, output));
}

void testMcsJoinedSendIndicationDenials()
{
    constexpr std::array<std::uint16_t, 2> channels{1007, 1003};
    constexpr std::array<std::uint8_t, 2> payload{0xa5, 0x5a};
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(gate.pendingReplySequence(),
               gate.pendingWriteSliceSequence(), 15) == McsJoinWriteOutcome::Confirmed);
    std::array<std::uint8_t, 20> output{};
    const auto deny = [&](std::uint16_t channelId,
                          std::uint8_t priority,
                          std::uint8_t segmentation,
                          std::span<const std::uint8_t> data,
                          std::span<std::uint8_t> destination)
    {
        output.fill(0x6c);
        assert(!gate.encodeJoinedSendDataIndication(
            channelId, priority, segmentation, data, destination));
        assert(std::all_of(output.begin(), output.end(),
                           [](std::uint8_t byte) { return byte == 0x6c; }));
    };
    deny(0, 1, 3, payload, output);
    deny(1007, 1, 3, payload, output);
    deny(1004, 1, 3, payload, output);
    deny(1003, 4, 3, payload, output);
    deny(1003, 1, 4, payload, output);
    deny(1003, 1, 3, payload, std::span(output).first(15));
    std::array<std::uint8_t, 16384> oversized{};
    deny(1003, 1, 3, oversized, output);
    assert(gate.channelJoinConfirmed(1003));
    const auto valid =
        gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output);
    assert(valid && *valid == 16);
    gate.close();
    output.fill(0x6c);
    assert(!gate.encodeJoinedSendDataIndication(1003, 1, 3, payload, output));
    assert(std::all_of(output.begin(), output.end(),
                       [](std::uint8_t byte) { return byte == 0x6c; }));
}

void testMcsSessionUnverifiedConnectDenials()
{
    // Real Microsoft Connect-Initial can be completely well-formed, but
    // TLS framing, GCC and domain negotiation are not R2 OS admission.
    const auto valid = publishedFixture();
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(!session.channelJoinConfirmed(1003));
    assert(session.pendingJoinConfirmation().empty());
    assert(session.onConnectInitial(valid) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(!session.channelJoinConfirmed(1003));
    assert(session.pendingJoinConfirmation().empty());
    assert(session.onConnectInitial(valid) == McsSessionIntake::Closed);
    session.close();
    session.close();
    assert(session.phase() == McsSessionPhase::Closed);

    // Invalid framing is terminal and cannot be replaced with a later
    // legitimate packet on the same session identity.
    McsSessionLifecycle malformed;
    assert(malformed.onConnectInitial(std::span(valid).first(7)) ==
           McsSessionIntake::InvalidEnvelope);
    assert(malformed.onConnectInitial(valid) == McsSessionIntake::Closed);
    assert(malformed.pendingJoinConfirmation().empty());
    McsSessionLifecycle reconnect;
    assert(reconnect.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(!reconnect.channelJoinConfirmed(1003));
    assert(reconnect.onConnectInitial(valid) ==
           McsSessionIntake::ValidButNotAdmitted);
}

void testMcsSessionUnverifiedDomainOrdering()
{
    // These valid complete envelopes come from existing production parsers.
    // No Erect/Attach/Join can advance before genuine R2 admission, even
    // when no TLS error was observed by an upstream diagnostic.
    constexpr std::array<std::uint8_t, 12> erect{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x04, 0x01, 0x00, 0x01, 0x00};
    constexpr std::array<std::uint8_t, 8> attach{
        0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, 0x28};
    constexpr std::array<std::uint8_t, 12> join{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 15> send{
        0x03, 0x00, 0x00, 0x0f, 0x02, 0xf0, 0x80,
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x01, 0x51};
    for (const auto request : {
             std::span<const std::uint8_t>{erect},
             std::span<const std::uint8_t>{attach},
             std::span<const std::uint8_t>{join},
             std::span<const std::uint8_t>{send}})
    {
        const auto parsed = parseMcsChannelRequest(request);
        assert(parsed);
        McsSessionLifecycle session;
        assert(session.onDomainPdu(request) ==
               McsSessionIntake::ValidButNotAdmitted);
        assert(session.phase() == McsSessionPhase::Closed);
        assert(!session.channelJoinConfirmed(1003));
        assert(session.pendingJoinConfirmation().empty());
        assert(session.onDomainPdu(request) == McsSessionIntake::Closed);
    }

    // Before authorization a peer Disconnect is a clean terminal event;
    // it cannot revive a previously closed session or permit a join.
    constexpr std::array<std::uint8_t, 9> disconnect{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};
    McsSessionLifecycle peerClosed;
    assert(peerClosed.onDomainPdu(disconnect) ==
           McsSessionIntake::PeerDisconnected);
    assert(peerClosed.onDomainPdu(join) == McsSessionIntake::Closed);

    McsSessionLifecycle bad;
    assert(bad.onDomainPdu(std::span(join).first(6)) ==
           McsSessionIntake::InvalidEnvelope);
    assert(bad.onDomainPdu(disconnect) == McsSessionIntake::Closed);
    bad.close();
    assert(bad.pendingJoinConfirmation().empty());
}

void testMcsSessionFirstEnvelopeSizeBounds()
{
    // 8 KiB is the project's existing bounded first decrypted TPKT
    // intake policy, not a substitute for the spec's GCC field limits.
    // The sole R3 owner must independently enforce it even when called
    // directly rather than through R1's exact-length TLS reader.
    constexpr std::size_t maximum = kMaximumInitialMcsTpktBytes;
    static_assert(maximum == 8192U);
    const auto valid = publishedFixture();

    McsSessionLifecycle validDiagnostic;
    assert(validDiagnostic.onConnectInitial(valid) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(validDiagnostic.phase() == McsSessionPhase::Closed);
    assert(validDiagnostic.pendingJoinConfirmation().empty());

    for (const std::size_t size : {0U, 1U, 7U, 8U,
                                  static_cast<unsigned>(maximum)})
    {
        std::vector<std::uint8_t> packet(size, 0);
        McsSessionLifecycle malformed;
        assert(malformed.onConnectInitial(packet) ==
               McsSessionIntake::InvalidEnvelope);
        assert(malformed.phase() == McsSessionPhase::Closed);
        assert(malformed.onConnectInitial(valid) == McsSessionIntake::Closed);
        assert(malformed.pendingJoinConfirmation().empty());
        assert(!malformed.channelJoinConfirmed(1003));
    }

    // Exact over-limit status proves that R3 rejects before BER/GCC
    // parsing, even if the attacker supplies a larger borrowed buffer.
    for (const std::size_t size : {
             maximum + 1U, maximum + 4096U,
             static_cast<std::size_t>(65536U)})
    {
        std::vector<std::uint8_t> packet(size, 0);
        McsSessionLifecycle overLimit;
        assert(overLimit.onConnectInitial(packet) ==
               McsSessionIntake::OversizedEnvelope);
        assert(overLimit.phase() == McsSessionPhase::Closed);
        assert(overLimit.pendingJoinConfirmation().empty());
        assert(!overLimit.channelJoinConfirmed(1003));
        assert(overLimit.onConnectInitial(valid) == McsSessionIntake::Closed);
        overLimit.close();
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
constexpr std::array<McsTestCase, 54> kMcsTestCases{{
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
    {"mcs-join-write-completion", &testMcsJoinWriteCompletion},
    {"mcs-join-write-denials", &testMcsJoinWriteDenials},
    {"mcs-join-duplicate-ignored", &testMcsJoinDuplicateIgnored},
    {"mcs-join-batched-requests", &testMcsJoinBatchedRequests},
    {"mcs-send-data-joined-membership", &testMcsJoinedSendDataMembership},
    {"mcs-send-data-joined-denials", &testMcsJoinedSendDataDenials},
    {"mcs-join-stale-write-receipts", &testMcsJoinStaleWriteReceipts},
    {"mcs-join-stale-partial-write-slices", &testMcsJoinStalePartialWriteSlices},
    {"mcs-send-indication-joined-wire", &testMcsJoinedSendIndicationWire},
    {"mcs-send-indication-joined-denials", &testMcsJoinedSendIndicationDenials},
    {"mcs-session-unverified-connect", &testMcsSessionUnverifiedConnectDenials},
    {"mcs-session-unverified-ordering", &testMcsSessionUnverifiedDomainOrdering},
    {"mcs-session-first-envelope-size-bounds", &testMcsSessionFirstEnvelopeSizeBounds},
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
    {"share-sync-finalization-wire", &testRdpSynchronizeFinalizationWire},
    {"share-sync-finalization-rejections", &testRdpSynchronizeFinalizationRejections},
    {"share-control-finalization-wire", &testRdpControlFinalizationWire},
    {"share-control-finalization-rejections", &testRdpControlFinalizationRejections},
    {"share-active-capabilities-wire", &testRdpActivePduWire},
    {"share-active-capabilities-rejections", &testRdpActivePduRejections},
    {"share-general-capability-wire", &testRdpGeneralCapabilityWire},
    {"share-general-capability-rejections", &testRdpGeneralCapabilityRejections},
    {"share-bitmap-capability-wire", &testRdpBitmapCapabilityWire},
    {"share-bitmap-capability-rejections", &testRdpBitmapCapabilityRejections},
    {"share-demand-active-encode-wire", &testRdpDemandActiveEncodeWire},
    {"share-demand-active-encode-rejections", &testRdpDemandActiveEncodeRejections},
    {"share-server-finalization-encode-wire", &testRdpServerFinalizationEncodeWire},
    {"share-server-finalization-encode-rejections", &testRdpServerFinalizationEncodeRejections},
    {"share-active-exchange-correlation", &testRdpActiveExchangeCorrelation},
    {"share-active-exchange-denials", &testRdpActiveExchangeDenials},
    {"share-finalization-exchange-correlation", &testRdpFinalizationExchangeCorrelation},
    {"share-finalization-exchange-denials", &testRdpFinalizationExchangeDenials},
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
