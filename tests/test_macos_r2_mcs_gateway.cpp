// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/transport/mcs_channel_connection.h"
#include "server/transport/mcs_connect_initial.h"

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
#include <vector>

using namespace rdp_server::server::transport;

namespace rdp_server::server::transport
{
// R2-scoped fixture for the exact private transition contract. It deliberately
// does not fabricate a macOS native proof; MacConsoleAdmissionBroker remains
// the only production friend that may perform these calls.
class MacConsoleAdmissionR3TestAccess final
{
public:
    [[nodiscard]] static McsSessionIntake acceptConnectInitial(
        McsSessionLifecycle &session,
        std::uint64_t admissionGeneration,
        std::uint64_t authorizationGeneration,
        std::span<const std::uint8_t> completeTpkt) noexcept
    {
        return session.onVerifiedR2ConnectInitial(
            admissionGeneration, authorizationGeneration, completeTpkt);
    }

    [[nodiscard]] static std::optional<McsConnectResponseWriteView>
    prepareConnectResponse(
        McsSessionLifecycle &session,
        std::uint64_t admissionGeneration,
        std::uint64_t authorizationGeneration,
        const SecurityNegotiationProvenance &provenance) noexcept
    {
        session.revokeUnlessAdmissionBindingMatches(
            admissionGeneration, authorizationGeneration);
        return session.prepareConnectResponseWrite(provenance);
    }

    [[nodiscard]] static McsConnectResponseWriteOutcome
    completeConnectResponse(
        McsSessionLifecycle &session,
        std::uint64_t admissionGeneration,
        std::uint64_t authorizationGeneration,
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept
    {
        session.revokeUnlessAdmissionBindingMatches(
            admissionGeneration, authorizationGeneration);
        return session.completeConnectResponseWrite(
            replySequence, writeSliceSequence, acceptedBytes);
    }

    [[nodiscard]] static McsSessionIntake acceptErectDomain(
        McsSessionLifecycle &session,
        std::uint64_t admissionGeneration,
        std::uint64_t authorizationGeneration,
        std::span<const std::uint8_t> completeTpkt) noexcept
    {
        session.revokeUnlessAdmissionBindingMatches(
            admissionGeneration, authorizationGeneration);
        return session.onVerifiedR2ErectDomain(completeTpkt);
    }
};
} // namespace rdp_server::server::transport

namespace
{
#ifndef OWNED_MCS_FIXTURE_PATH
#error OWNED_MCS_FIXTURE_PATH must point to the checked-in MCS fixture
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
            continue;
        std::istringstream input{line};
        unsigned int value = 0U;
        while (input >> std::hex >> value)
        {
            assert(value <= 0xffU);
            result.push_back(static_cast<std::uint8_t>(value));
        }
        assert(input.eof());
    }
    assert(result.size() == 416U);
    return result;
}

[[nodiscard]] std::vector<std::uint8_t> hybridConnectInitial()
{
    auto packet = publishedFixture();
    const auto parsed = parseMcsConnectInitial(packet);
    assert(parsed);

    constexpr std::array<std::uint8_t, 4> coreHeader{
        0x01U, 0xc0U, 0xd8U, 0x00U};
    const auto core = std::search(
        parsed.value.gccUserData.begin(), parsed.value.gccUserData.end(),
        coreHeader.begin(), coreHeader.end());
    assert(core != parsed.value.gccUserData.end());

    const std::size_t selectedProtocolOffset =
        static_cast<std::size_t>(
            parsed.value.gccUserData.data() - packet.data()) +
        static_cast<std::size_t>(
            core - parsed.value.gccUserData.begin()) + 212U;
    assert(selectedProtocolOffset + 4U <= packet.size());
    std::fill_n(
        packet.begin() + selectedProtocolOffset, 4U, std::uint8_t{0});
    packet[selectedProtocolOffset] =
        static_cast<std::uint8_t>(kRdpProtocolHybrid);
    return packet;
}

[[nodiscard]] constexpr SecurityNegotiationProvenance
hybridProvenance() noexcept
{
    return {kRdpProtocolSsl | kRdpProtocolHybrid, kRdpProtocolHybrid};
}

void assertTerminal(const McsSessionLifecycle &session)
{
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.allocatedUserId() == 0U);
    assert(session.allocatedStaticChannelIds().empty());
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(!session.channelJoinConfirmed(1003U));
    assert(!session.firstClientAcceptanceObservability().shareActivated);
}

void testPublicConnectInitialRemainsDenialOnly()
{
    const auto packet = hybridConnectInitial();
    McsSessionLifecycle session;
    assert(session.onConnectInitial(packet) ==
           McsSessionIntake::ValidButNotAdmitted);
    assertTerminal(session);
}

void testRevocationRejectsZeroAndPartialWriteCompletion()
{
    constexpr std::uint64_t admissionGeneration = 41U;
    constexpr std::uint64_t authorizationGeneration = 43U;
    constexpr auto provenance = hybridProvenance();
    const auto packet = hybridConnectInitial();

    McsSessionLifecycle zeroByte;
    assert(MacConsoleAdmissionR3TestAccess::acceptConnectInitial(
               zeroByte, admissionGeneration, authorizationGeneration,
               packet) == McsSessionIntake::AdmittedConnectInitial);
    const auto zeroPending =
        MacConsoleAdmissionR3TestAccess::prepareConnectResponse(
            zeroByte, admissionGeneration, authorizationGeneration,
            provenance);
    assert(zeroPending);
    assert(MacConsoleAdmissionR3TestAccess::completeConnectResponse(
               zeroByte, admissionGeneration, authorizationGeneration,
               zeroPending->replySequence, zeroPending->writeSliceSequence,
               0U) == McsConnectResponseWriteOutcome::Pending);

    const auto zeroRetry =
        MacConsoleAdmissionR3TestAccess::prepareConnectResponse(
            zeroByte, admissionGeneration, authorizationGeneration,
            provenance);
    assert(zeroRetry);
    assert(MacConsoleAdmissionR3TestAccess::completeConnectResponse(
               zeroByte, admissionGeneration, authorizationGeneration + 1U,
               zeroRetry->replySequence, zeroRetry->writeSliceSequence,
               zeroRetry->bytes.size()) ==
           McsConnectResponseWriteOutcome::Rejected);
    assertTerminal(zeroByte);

    McsSessionLifecycle partial;
    assert(MacConsoleAdmissionR3TestAccess::acceptConnectInitial(
               partial, admissionGeneration, authorizationGeneration,
               packet) == McsSessionIntake::AdmittedConnectInitial);
    const auto firstSlice =
        MacConsoleAdmissionR3TestAccess::prepareConnectResponse(
            partial, admissionGeneration, authorizationGeneration,
            provenance);
    assert(firstSlice && firstSlice->bytes.size() > 1U);
    assert(MacConsoleAdmissionR3TestAccess::completeConnectResponse(
               partial, admissionGeneration, authorizationGeneration,
               firstSlice->replySequence, firstSlice->writeSliceSequence,
               1U) == McsConnectResponseWriteOutcome::Pending);

    const auto remaining =
        MacConsoleAdmissionR3TestAccess::prepareConnectResponse(
            partial, admissionGeneration, authorizationGeneration,
            provenance);
    assert(remaining);
    assert(MacConsoleAdmissionR3TestAccess::completeConnectResponse(
               partial, 0U, authorizationGeneration,
               remaining->replySequence, remaining->writeSliceSequence,
               remaining->bytes.size()) ==
           McsConnectResponseWriteOutcome::Rejected);
    assertTerminal(partial);
}

void testRetiredBindingCannotReachNextMcsTransition()
{
    constexpr std::uint64_t admissionGeneration = 51U;
    constexpr std::uint64_t authorizationGeneration = 53U;
    constexpr auto provenance = hybridProvenance();
    constexpr std::array<std::uint8_t, 12> erect{
        0x03U,0x00U,0x00U,0x0cU,0x02U,0xf0U,
        0x80U,0x04U,0x01U,0x00U,0x01U,0x00U};
    const auto packet = hybridConnectInitial();

    McsSessionLifecycle session;
    assert(MacConsoleAdmissionR3TestAccess::acceptConnectInitial(
               session, admissionGeneration, authorizationGeneration,
               packet) == McsSessionIntake::AdmittedConnectInitial);
    const auto pending =
        MacConsoleAdmissionR3TestAccess::prepareConnectResponse(
            session, admissionGeneration, authorizationGeneration,
            provenance);
    assert(pending);
    assert(MacConsoleAdmissionR3TestAccess::completeConnectResponse(
               session, admissionGeneration, authorizationGeneration,
               pending->replySequence, pending->writeSliceSequence,
               pending->bytes.size()) ==
           McsConnectResponseWriteOutcome::Delivered);
    assert(session.phase() == McsSessionPhase::AwaitErectDomain);

    assert(MacConsoleAdmissionR3TestAccess::acceptErectDomain(
               session, admissionGeneration + 1U, authorizationGeneration,
               erect) == McsSessionIntake::Closed);
    assertTerminal(session);
}
} // namespace

int main()
{
    testPublicConnectInitialRemainsDenialOnly();
    testRevocationRejectsZeroAndPartialWriteCompletion();
    testRetiredBindingCannotReachNextMcsTransition();
    return 0;
}
