// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport/gcc_conference_create.h"
#include "transport/mcs_connect_initial.h"
#include "transport/preauth_session.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef OWNED_MCS_FIXTURE_PATH
#error OWNED_MCS_FIXTURE_PATH must point to the checked-in Microsoft fixture
#endif

using namespace rdp_server::server::transport;

namespace
{

[[nodiscard]] std::vector<std::uint8_t> realMicrosoftMcsFixture()
{
    std::ifstream file{OWNED_MCS_FIXTURE_PATH};
    assert(file.good());
    std::vector<std::uint8_t> bytes;
    std::string line;
    while (std::getline(file, line))
    {
        if (line.empty() || line.front() == '#')
        {
            continue;
        }
        std::istringstream input{line};
        unsigned int octet = 0;
        while (input >> std::hex >> octet)
        {
            assert(octet <= 255);
            bytes.push_back(static_cast<std::uint8_t>(octet));
        }
        assert(input.eof());
    }
    assert(bytes.size() == 416);
    return bytes;
}

[[nodiscard]] std::span<std::uint8_t> gccData(
    std::vector<std::uint8_t> &packet)
{
    const auto mcs = parseMcsConnectInitial(packet);
    assert(mcs);
    const auto offset = static_cast<std::size_t>(
        mcs.value.gccUserData.data() - packet.data());
    return std::span(packet).subspan(
        offset, mcs.value.gccUserData.size());
}

template <std::size_t Size>
[[nodiscard]] std::size_t locate(
    std::span<const std::uint8_t> haystack,
    const std::array<std::uint8_t, Size> &needle)
{
    const auto start = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end());
    assert(start != haystack.end());
    return static_cast<std::size_t>(start - haystack.begin());
}

[[nodiscard]] ConnectionParseResult connectionRequest()
{
    const std::array<std::uint8_t, 19> bytes{
        3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0,
        1, 0, 8, 0, 1, 0, 0, 0,
    };
    return parseConnectionRequest(bytes);
}

[[nodiscard]] bool intake(std::span<const std::uint8_t> packet)
{
    PreauthSession state;
    assert(state.onConnectionRequest(connectionRequest()).decision ==
           SecurityDecision::Tls);
    assert(state.onTlsHandshake(true));
    const bool result = state.onEncryptedMcsConnectInitial(packet);
    assert(state.stage() == PreauthStage::Closed);
    return result;
}

void testPublishedGccSettings()
{
    auto packet = realMicrosoftMcsFixture();
    const auto gcc = gccData(packet);
    assert(gcc.size() == 307);
    const auto parsed = parseGccConferenceCreate(gcc);
    assert(parsed);
    const auto &settings = parsed.settings;
    assert(settings.clientVersion == 0x00080004U);
    assert(settings.requestedWidth == 1280);
    assert(settings.requestedHeight == 1024);
    assert(settings.encryptionMethods == 0x1bU);
    assert(settings.extEncryptionMethods == 0);
    assert(settings.hasClusterData);
    assert(settings.hasNetworkData);
    assert(settings.channelCount == 3);
    assert(std::string_view(settings.channels[0].name.data()) == "rdpdr");
    assert(settings.channels[0].options == 0x80800000U);
    assert(std::string_view(settings.channels[1].name.data()) == "cliprdr");
    assert(settings.channels[1].options == 0xc0a00000U);
    assert(std::string_view(settings.channels[2].name.data()) == "rdpsnd");
    assert(settings.channels[2].options == 0xc0000000U);
    assert(intake(packet));
}

void testStrictConferenceLengthsAndKey()
{
    auto packet = realMicrosoftMcsFixture();
    auto gcc = gccData(packet);
    gcc[3] = 0; // t124Identifier must be the correct OID
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidConnectData);
    assert(!intake(packet));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    gcc[7] = 0x80; // Nonminimal PER two-octet length
    assert(!parseGccConferenceCreate(gcc));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    gcc[7] = 0xc0; // Fragmented PER determinant unsupported
    assert(!parseGccConferenceCreate(gcc));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    gcc[9] = 0x01; // Unknown ConferenceCreateRequest choice/flags
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidConference);

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    gcc[17] = 'X'; // H.221 nonstandard key is not "Duca"
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidH221Key);
    assert(!intake(packet));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    gcc[21] = 0x81;
    gcc[22] = 0x1d; // One byte too many in UserData::value
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidSettings);

    const std::vector<std::uint8_t> tooLarge(
        kMaximumBasicGccBytes + 1U, 0);
    assert(parseGccConferenceCreate(tooLarge).error ==
           GccError::InvalidConnectData);
    const std::array<std::uint8_t, 2> tiny{0, 5};
    assert(!parseGccConferenceCreate(tiny));
}

void testDataBlockValidation()
{
    auto packet = realMicrosoftMcsFixture();
    auto gcc = gccData(packet);
    constexpr std::array<std::uint8_t, 4> core{0x01, 0xc0, 0xd8, 0x00};
    const auto coreOffset = locate(gcc, core);
    gcc[coreOffset + 2] = 0; // zero-length block
    assert(!parseGccConferenceCreate(gcc));
    assert(!intake(packet));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    const auto corePosition = locate(gcc, core);
    gcc[corePosition] = 0x09; // unknown/unsupported extended block type
    assert(!parseGccConferenceCreate(gcc));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    constexpr std::array<std::uint8_t, 4> security{
        0x02, 0xc0, 0x0c, 0x00};
    const auto sec = locate(gcc, security);
    gcc[sec] = 0x01; // duplicate core type; missing security
    assert(!parseGccConferenceCreate(gcc));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    const auto secSize = locate(gcc, security);
    gcc[secSize + 2] = 0x0b; // security header shortened
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidSecurity);

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    constexpr std::array<std::uint8_t, 8> network{
        0x03, 0xc0, 0x2c, 0x00, 0x03, 0x00, 0x00, 0x00};
    const auto net = locate(gcc, network);
    gcc[net + 4] = 32; // max allowed is 31, without a large allocation
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidNetwork);
    assert(!intake(packet));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    const auto netLength = locate(gcc, network);
    gcc[netLength + 2] = 0x2b; // incomplete CHANNEL_DEF array
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidNetwork);

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    constexpr std::array<std::uint8_t, 8> clipName{
        'c', 'l', 'i', 'p', 'r', 'd', 'r', 0};
    const auto nameOffset = locate(gcc, clipName);
    // Copy first channel's ANSI name into the second (case-insensitive dup).
    constexpr std::array<std::uint8_t, 8> duplicate{
        'R', 'D', 'P', 'D', 'R', 0, 0, 0};
    std::copy(duplicate.begin(), duplicate.end(),
              gcc.begin() + nameOffset);
    assert(parseGccConferenceCreate(gcc).error ==
           GccError::InvalidNetwork);

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    const auto nameIndex = locate(gcc, clipName);
    gcc[nameIndex + 7] = 'A'; // non-terminated name
    assert(!parseGccConferenceCreate(gcc));

    packet = realMicrosoftMcsFixture();
    gcc = gccData(packet);
    const auto coreDims = locate(gcc, core);
    gcc[coreDims + 8] = 0;
    gcc[coreDims + 9] = 0; // desktopWidth zero
    assert(parseGccConferenceCreate(gcc).error == GccError::InvalidCore);
}

void testAllTruncationsAndSingleByteMutations()
{
    auto packet = realMicrosoftMcsFixture();
    const auto view = gccData(packet);
    const std::vector<std::uint8_t> baseline(view.begin(), view.end());
    for (std::size_t length = 0; length < baseline.size(); ++length)
    {
        const auto result = parseGccConferenceCreate(
            std::span(baseline).first(length));
        // Nested PER lengths must never accept a truncated UserData set.
        assert(!result);
        assert(result.settings.channelCount == 0);
    }
    for (std::size_t index = 0; index < baseline.size(); ++index)
    {
        auto mutated = baseline;
        mutated[index] ^= 0xffU;
        const auto result = parseGccConferenceCreate(mutated);
        if (result)
        {
            assert(result.settings.channelCount <=
                   kMaximumStaticChannelCount);
            for (std::size_t channel = 0;
                 channel < result.settings.channelCount; ++channel)
            {
                const auto &name = result.settings.channels[channel].name;
                assert(std::find(name.begin(), name.end(), '\0') != name.end());
            }
        }
        else
        {
            // Transactional parse: no unvalidated channel metadata escapes.
            assert(result.settings.channelCount == 0);
        }
    }
}

} // namespace

int main()
{
    testAllTruncationsAndSingleByteMutations();
    testPublishedGccSettings();
    testStrictConferenceLengthsAndKey();
    testDataBlockValidation();
}
