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


void testFragmentedConnectionRequestIntake()
{
    const std::array<std::uint8_t, 19> request{
        3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0,
        1, 0, 8, 0, 1, 0, 0, 0,
    };
    for (std::size_t split = 0; split < request.size(); ++split)
    {
        PreauthConnectionStream connection;
        const auto first = connection.consumeConnectionRequest(
            std::span(request).first(split));
        assert(first.bytesConsumed == split);
        assert(first.status == ConnectionIntakeStatus::NeedMore);
        assert(connection.stage() == PreauthStage::AwaitConnectionRequest);

        const auto second = connection.consumeConnectionRequest(
            std::span(request).subspan(split));
        assert(second.bytesConsumed == request.size() - split);
        assert(second.status == ConnectionIntakeStatus::ReplyThenTls);
        assert(second.reply.decision == SecurityDecision::Tls);
        assert(second.reply.packet[11] == 0x02);
        assert(connection.stage() == PreauthStage::AwaitTls);

        // A valid request is never accepted twice.
        assert(connection.consumeConnectionRequest(request).status ==
               ConnectionIntakeStatus::Closed);
        assert(connection.onTlsHandshake(false) == false);
        assert(connection.stage() == PreauthStage::Closed);
    }

    PreauthConnectionStream bytewise;
    for (std::size_t index = 0; index < request.size(); ++index)
    {
        const auto result = bytewise.consumeConnectionRequest(
            std::span(request).subspan(index, 1));
        assert(result.bytesConsumed == 1);
        assert(result.status ==
               (index + 1 == request.size()
                    ? ConnectionIntakeStatus::ReplyThenTls
                    : ConnectionIntakeStatus::NeedMore));
    }
    assert(bytewise.stage() == PreauthStage::AwaitTls);
}

void testConnectionRequestByteBoundaryAndFailure()
{
    const std::array<std::uint8_t, 19> request{
        3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0,
        1, 0, 8, 0, 1, 0, 0, 0,
    };
    // A receive can already contain TLS data. Never consume beyond the
    // first complete X.224 request before the Security Reply is sent.
    std::vector<std::uint8_t> coalesced(request.begin(), request.end());
    coalesced.insert(coalesced.end(), {0x16, 0x03, 0x03, 0x00, 0x05});
    PreauthConnectionStream withTrailingTls;
    const auto result = withTrailingTls.consumeConnectionRequest(coalesced);
    assert(result.status == ConnectionIntakeStatus::ReplyThenTls);
    assert(result.bytesConsumed == request.size());
    assert(withTrailingTls.consumeConnectionRequest(
               std::span(coalesced).subspan(request.size())).bytesConsumed == 0);
    assert(withTrailingTls.stage() == PreauthStage::AwaitTls);
    assert(withTrailingTls.onTlsHandshake(true));
    assert(withTrailingTls.stage() == PreauthStage::AwaitMcsConnectInitial);
    withTrailingTls.close();

    auto unsupported = request;
    unsupported[15] = 0; // Client did not offer TLS.
    PreauthConnectionStream noTls;
    const auto rejection = noTls.consumeConnectionRequest(unsupported);
    assert(rejection.status == ConnectionIntakeStatus::ReplyThenClose);
    assert(rejection.bytesConsumed == unsupported.size());
    assert(rejection.reply.decision == SecurityDecision::Reject);
    assert(rejection.reply.packet[11] == 0x03);
    assert(noTls.stage() == PreauthStage::Closed);

    auto invalid = request;
    invalid[5] = 0xf0; // Not an X.224 Connection Request TPDU.
    PreauthConnectionStream malformed;
    const auto bad = malformed.consumeConnectionRequest(invalid);
    assert(bad.status == ConnectionIntakeStatus::Invalid);
    assert(bad.bytesConsumed == invalid.size());
    assert(malformed.stage() == PreauthStage::Closed);
    assert(malformed.consumeConnectionRequest(request).bytesConsumed == 0);
}

void testConnectionRequestLengthRejectionAndClose()
{
    const std::array<std::array<std::uint8_t, 4>, 4> invalidHeaders{{
        {4, 0, 0, 19},   // TPKT version
        {3, 1, 0, 19},   // Reserved byte
        {3, 0, 0, 10},   // Shorter than an X.224 CR
        {3, 0, 1, 5},    // Larger than X.224's maximum CR
    }};
    for (const auto &header : invalidHeaders)
    {
        PreauthConnectionStream connection;
        const auto result = connection.consumeConnectionRequest(header);
        assert(result.bytesConsumed == header.size());
        assert(result.status == ConnectionIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
        assert(connection.consumeConnectionRequest(header).status ==
               ConnectionIntakeStatus::Closed);
    }

    PreauthConnectionStream interrupted;
    const std::array<std::uint8_t, 3> fragment{3, 0, 0};
    assert(interrupted.consumeConnectionRequest(fragment).status ==
           ConnectionIntakeStatus::NeedMore);
    interrupted.close();
    assert(interrupted.stage() == PreauthStage::Closed);
    assert(interrupted.consumeConnectionRequest(fragment).bytesConsumed == 0);

    // The diagnostic does not grant authorization even when given a
    // complete handshake and a valid fixture later in the sequence.
    PreauthConnectionStream prematureTls;
    assert(!prematureTls.onTlsHandshake(true));
    assert(prematureTls.stage() == PreauthStage::Closed);
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

    testFragmentedConnectionRequestIntake();
    testConnectionRequestByteBoundaryAndFailure();
    testConnectionRequestLengthRejectionAndClose();
}
