// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport/preauth_session.h"
#include "transport/tpkt_x224.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef OWNED_MCS_FIXTURE_PATH
#error OWNED_MCS_FIXTURE_PATH must point to the checked-in Microsoft fixture
#endif

using namespace rdp_server::server::transport;

namespace
{

[[nodiscard]] std::vector<std::uint8_t> validMcsPacket()
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

[[nodiscard]] ConnectionParseResult validRequest()
{
    const std::array<std::uint8_t, 19> packet{
        3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0,
        1, 0, 8, 0, 1, 0, 0, 0,
    };
    return parseConnectionRequest(packet);
}

} // namespace

int main()
{
    const auto frame = validMcsPacket();
    const auto request = validRequest();
    assert(request);

    PreauthSession normal;
    assert(normal.stage() == PreauthStage::AwaitConnectionRequest);
    assert(normal.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(normal.stage() == PreauthStage::AwaitTls);
    assert(normal.onTlsHandshake(true));
    assert(normal.stage() == PreauthStage::AwaitMcsConnectInitial);
    assert(normal.onEncryptedMcsConnectInitial(frame));
    assert(normal.stage() == PreauthStage::Closed);
    assert(!normal.onEncryptedMcsConnectInitial(frame));
    assert(!normal.onTlsHandshake(true));

    PreauthSession noNegotiation;
    assert(!noNegotiation.onTlsHandshake(true));
    assert(noNegotiation.stage() == PreauthStage::Closed);
    assert(noNegotiation.onConnectionRequest(request).decision ==
           SecurityDecision::Reject);

    PreauthSession tlsFailure;
    assert(tlsFailure.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(!tlsFailure.onTlsHandshake(false));
    assert(tlsFailure.stage() == PreauthStage::Closed);

    PreauthSession invalidFrame;
    assert(invalidFrame.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(invalidFrame.onTlsHandshake(true));
    auto malformed = frame;
    malformed[5] = 0xe0; // invalid X.224 Data TPDU
    assert(!invalidFrame.onEncryptedMcsConnectInitial(malformed));
    assert(invalidFrame.stage() == PreauthStage::Closed);

    PreauthSession oversized;
    assert(oversized.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(oversized.onTlsHandshake(true));
    const std::vector<std::uint8_t> huge(
        kMaximumInitialMcsTpktBytes + 1, 0);
    assert(!oversized.onEncryptedMcsConnectInitial(huge));
    assert(oversized.stage() == PreauthStage::Closed);

    PreauthSession prematureMcs;
    assert(!prematureMcs.onEncryptedMcsConnectInitial(frame));
    assert(prematureMcs.stage() == PreauthStage::Closed);

    PreauthSession explicitClose;
    assert(explicitClose.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    explicitClose.close();
    assert(!explicitClose.onTlsHandshake(true));
}
