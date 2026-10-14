// SPDX-License-Identifier: GPL-3.0-or-later
// Byte-for-byte MCS Connect-Initial example from Microsoft MS-RDPBCGR 4.1.3:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151
#include "transport/mcs_connect_initial.h"

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
constexpr std::array<McsTestCase, 6> kMcsTestCases{{
    {"mcs-envelope-microsoft", &testRealMicrosoftConnectionEnvelope},
    {"mcs-envelope-tpkt-errors", &testInvalidOuterTransport},
    {"mcs-envelope-ber-errors", &testBerLengthsAndType},
    {"mcs-envelope-mutations", &testInputMutationsRemainBounded},
    {"mcs-domain-merge", &testMicrosoftDomainNegotiation},
    {"mcs-domain-rejections", &testMcsDomainNegotiationRejections},
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
