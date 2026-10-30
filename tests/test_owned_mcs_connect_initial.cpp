// SPDX-License-Identifier: GPL-3.0-or-later
// Byte-for-byte MCS Connect-Initial example from Microsoft MS-RDPBCGR 4.1.3:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151
#include "transport/mcs_connect_initial.h"
#include "transport/mcs_connect_response.h"
#include "transport/mcs_channel_connection.h"
#include "transport/rdp_licensing.h"
#include "transport/gcc_conference_create.h"
#include "server/runtime/runtime_licensing_context.h"

#include <algorithm>
#include <array>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace rdp_server::server::transport;
using rdp_server::server::runtime::RuntimeLicensingContext;

namespace rdp_server::server::transport
{
class RdpExistingClientCalAuthorityRequestTestAccess final
{
public:
    [[nodiscard]] static RdpExistingClientCalAuthorityRequestError
    bindProductIdentity(
        RdpExistingClientCalAuthorityRequest &request,
        const RdpServerLicenseIdentity &identity) noexcept
    {
        return request.bindProductIdentity(identity);
    }

    [[nodiscard]] static RdpExistingClientCalAuthorityRequestError complete(
        RdpExistingClientCalAuthorityRequest &request,
        RdpClientLicenseInfoHardwareIdProof &&hardwareIdProof,
        std::span<const std::uint8_t> licenseInfo,
        std::int64_t verificationUnixSeconds,
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept
    {
        return request.complete(
            std::move(hardwareIdProof),
            licenseInfo,
            verificationUnixSeconds,
            admissionGeneration,
            sessionGeneration);
    }
};
// Fixture-only access stages an already MAC-verified CAL through the real
// R3 request owner and licensing state machine; never a production admission.
class McsSessionLifecycleTestAccess final
{
public:
    [[nodiscard]] static bool stage(
        McsSessionLifecycle &session,
        const RdpServerLicenseIdentity &identity,
        RdpClientLicenseInfoHardwareIdProof &&proof,
        std::span<const std::uint8_t> cal,
        std::span<const std::uint8_t> licenseMessage,
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept
    {
        RdpServerLicenseRequestWriteGate writer{session.licensing_};
        if (!writer.queue(identity))
            return false;
        const auto pending = writer.pendingWrite();
        if (!pending ||
            writer.onBytesWritten(pending.replySequence,
                                  pending.writeSliceSequence,
                                  pending.bytes.size()) !=
                RdpServerLicenseRequestWriteOutcome::Delivered ||
            session.licensing_.onClientMessage(licenseMessage) !=
                RdpLicensingIntake::ClientLicenseInfoAccepted ||
            RdpExistingClientCalAuthorityRequestTestAccess::
                bindProductIdentity(
                    session.existingCalAuthorityRequest_, identity) !=
                RdpExistingClientCalAuthorityRequestError::None ||
            RdpExistingClientCalAuthorityRequestTestAccess::complete(
                session.existingCalAuthorityRequest_,
                std::move(proof), cal, 1780315200LL,
                admissionGeneration, sessionGeneration) !=
                RdpExistingClientCalAuthorityRequestError::None)
            return false;
        session.admissionGeneration_ = admissionGeneration;
        session.sessionGeneration_ = sessionGeneration;
        session.acceptedInitialLicensingIntake_ =
            RdpLicensingIntake::ClientLicenseInfoAccepted;
        session.phase_ = McsSessionPhase::AwaitServerLicenseDecision;
        return true;
    }
    static void stale(McsSessionLifecycle &session) noexcept
    {
        ++session.sessionGeneration_;
    }
    static void phaseMismatch(McsSessionLifecycle &session) noexcept
    {
        session.phase_ = McsSessionPhase::AwaitClientLicenseResponse;
    }
    static void restorePhase(McsSessionLifecycle &session) noexcept
    {
        session.phase_ = McsSessionPhase::AwaitServerLicenseDecision;
    }
    static void consumed(McsSessionLifecycle &session) noexcept
    {
        session.acceptedInitialLicensingIntake_.reset();
    }

    // Denial-only fixture access. It never stages admission or Share state;
    // it merely proves that the live private Graphics DVC path cannot start
    // from an unauthenticated/default session.
    [[nodiscard]] static bool beginGraphicsDvcWithoutAdmission(
        McsSessionLifecycle &session) noexcept
    {
        const SecurityNegotiationProvenance provenance{};
        return session.beginVerifiedR2GraphicsDynamicVirtualChannel(
            provenance).has_value();
    }

    [[nodiscard]] static bool routeClipboardWithoutAdmission(
        McsSessionLifecycle &session) noexcept
    {
        const SecurityNegotiationProvenance provenance{};
        return session.resolveVerifiedR2ActivatedClipboardChannel(
            provenance).has_value();
    }

    // Offline-only routed state fixture. This bypasses real R2 admission
    // deliberately and is never exposed outside the test executable.
    [[nodiscard]] static bool stagePostShareClassifier(
        McsSessionLifecycle &session) noexcept
    {
        session.allocatedUserId_ = 1007U;
        session.admissionGeneration_ = 41U;
        session.sessionGeneration_ = 43U;
        session.phase_ = McsSessionPhase::ShareActivated;
        session.connectResponseProvenanceBound_ = true;
        session.connectResponseBoundProvenance_ =
            {kRdpProtocolHybrid, kRdpProtocolHybrid};
        session.licensing_.phase_ = RdpLicensingPhase::Licensed;
        session.shareActivation_.phase_ = RdpShareActivationPhase::Activated;
        session.shareActivation_.shareId_ = 0x000103eaU;
        session.shareActivation_.clientUserId_ = 1007U;
        session.shareActivation_.clientCapabilitiesConfirmed_ = true;
        session.shareActivation_.negotiatedSlowPathInputFlags_ = 0x0015U;
        session.connectResponseAllocation_.gccNodeId = 1002U;
        session.connectResponseAllocation_.ioChannelId = 1003U;
        session.connectResponseAllocation_.staticChannelCount = 2U;
        session.connectResponseAllocation_.staticChannelIds[0] = 1004U;
        session.connectResponseAllocation_.staticChannelIds[1] = 1005U;
        auto &settings = session.connectResponseClientSettings_;
        settings.hasNetworkData = true;
        settings.channelCount = 2U;
        settings.channels[0].name = {'c','l','i','p','r','d','r',0};
        settings.channels[1].name = {'d','r','d','y','n','v','c',0};
        constexpr std::array<std::uint16_t, 4> channels{
            1007U, 1003U, 1004U, 1005U};
        if (!session.joins_.configure(1007U, channels))
            return false;
        McsChannelRequest join{};
        join.kind = McsChannelRequestKind::ChannelJoin;
        join.initiator = 1007U;
        for (auto channelId : channels)
        {
            join.channelId = channelId;
            if (session.joins_.beginJoin(join) !=
                McsJoinStartOutcome::ReplyPending)
                return false;
            const auto pending = session.joins_.pendingBytes();
            if (session.joins_.onReplyBytesWritten(
                    session.joins_.pendingReplySequence(),
                    session.joins_.pendingWriteSliceSequence(),
                    pending.size()) != McsJoinWriteOutcome::Confirmed)
                return false;
        }
        if (!session.joins_.allConfiguredChannelsJoined() ||
            !session.clipboardStaticChannel_.start(
                1007U, 1004U, 47U,
                kRdpStaticVirtualChannelDefaultChunkBytes) ||
            !session.graphicsDynamicVirtualChannel_.begin(
                1007U, 1005U, {9U, 91U}, {64U, 64U}))
            return false;
        const auto graphicsWrite =
            session.graphicsDynamicVirtualChannel_.pendingServerWrite();
        return graphicsWrite &&
            session.graphicsDynamicVirtualChannel_.onServerBytesWritten(
                graphicsWrite.channelGeneration,
                graphicsWrite.replySequence,
                graphicsWrite.writeSliceSequence,
                graphicsWrite.bytes.size()) ==
                RdpGraphicsDvcWriteOutcome::Delivered;
    }

    [[nodiscard]] static RdpPostShareTpktRoute classifyPostShare(
        const McsSessionLifecycle &session,
        std::span<const std::uint8_t> packet) noexcept
    {
        return session.classifyVerifiedR2PostShareTpkt(
            {kRdpProtocolHybrid, kRdpProtocolHybrid}, packet);
    }
    [[nodiscard]] static RdpGraphicsDynamicVirtualChannelLifecycle &
    graphicsForClassifierTest(McsSessionLifecycle &session) noexcept
    {
        return session.graphicsDynamicVirtualChannel_;
    }
    static void wrongDynamicRole(McsSessionLifecycle &session) noexcept
    {
        session.connectResponseClientSettings_.channels[1].name =
            {'r','d','p','s','n','d',0,0};
    }
    static void staleGraphics(McsSessionLifecycle &session) noexcept
    {
        session.graphicsDynamicVirtualChannel_.close();
    }
    static void staleClipboard(McsSessionLifecycle &session) noexcept
    {
        session.clipboardStaticChannel_.close();
    }
    static void replaceShare(McsSessionLifecycle &session) noexcept
    {
        session.shareActivation_.shareId_ ^= 1U;
    }

    [[nodiscard]] static bool routeSlowPathInputWithoutAdmission(
        McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept
    {
        const SecurityNegotiationProvenance provenance{};
        return session.routeVerifiedR2SlowPathInputPdu(
            provenance, completeTpkt).has_value();
    }

    [[nodiscard]] static bool stageMcsEstablishedForObservability(
        McsSessionLifecycle &session) noexcept
    {
        session.phase_ = McsSessionPhase::AwaitChannelJoin;
        session.allocatedUserId_ = 1007U;
        session.connectResponseProvenanceBound_ = true;
        session.connectResponseBoundProvenance_ =
            {kRdpProtocolHybrid, kRdpProtocolHybrid};
        constexpr std::array<std::uint16_t, 4> channels{
            1007U, 1003U, 1004U, 1005U};
        if (!session.joins_.configure(1007U, channels))
            return false;

        McsChannelRequest join{};
        join.kind = McsChannelRequestKind::ChannelJoin;
        join.initiator = 1007U;
        for (const auto channelId : channels)
        {
            join.channelId = channelId;
            if (session.joins_.beginJoin(join) !=
                McsJoinStartOutcome::ReplyPending)
                return false;
            const auto pending = session.joins_.pendingBytes();
            if (session.completeChannelJoinConfirmWrite(
                    session.connectResponseBoundProvenance_,
                    session.joins_.pendingReplySequence(),
                    session.joins_.pendingWriteSliceSequence(),
                    pending.size()) != McsJoinWriteOutcome::Confirmed)
                return false;
        }
        return session.joins_.allConfiguredChannelsJoined();
    }

    static void stageFirstClientAcceptanceFoundations(
        McsSessionLifecycle &session) noexcept
    {
        // stagePostShareClassifier() deliberately bypasses the real R2/MCS/
        // Share transcript. Seed only those already-completed milestones so
        // this offline fixture can exercise production Graphics hooks.
        session.recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::McsEstablished);
        session.recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::ShareActivated);
    }

    [[nodiscard]] static RdpGraphicsDvcClientIntake acceptGraphics(
        McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept
    {
        return session.acceptVerifiedR2GraphicsDynamicVirtualChannelPdu(
            {kRdpProtocolHybrid, kRdpProtocolHybrid}, completeTpkt);
    }

    [[nodiscard]] static std::optional<RdpGraphicsDvcWriteView>
    pendingGraphics(McsSessionLifecycle &session) noexcept
    {
        return session.pendingVerifiedR2GraphicsDynamicVirtualChannelWrite(
            {kRdpProtocolHybrid, kRdpProtocolHybrid});
    }

    [[nodiscard]] static RdpGraphicsDvcWriteOutcome completeGraphics(
        McsSessionLifecycle &session,
        const RdpGraphicsDvcWriteView &write) noexcept
    {
        return session.completeVerifiedR2GraphicsDynamicVirtualChannelWrite(
            {kRdpProtocolHybrid, kRdpProtocolHybrid},
            write.replySequence, write.writeSliceSequence,
            write.bytes.size());
    }

    [[nodiscard]] static std::optional<RdpGraphicsDvcWriteView>
    beginClearCodecFrame(
        McsSessionLifecycle &session,
        std::uint32_t frameId,
        ::FramebufferView framebuffer) noexcept
    {
        return session.beginVerifiedR2GraphicsClearCodecFramePublication(
            {kRdpProtocolHybrid, kRdpProtocolHybrid},
            frameId, framebuffer);
    }

    [[nodiscard]] static RdpGraphicsFrameAcknowledgeIntake
    consumeFrameAcknowledge(McsSessionLifecycle &session) noexcept
    {
        return session.consumeVerifiedR2GraphicsFrameAcknowledge(
            {kRdpProtocolHybrid, kRdpProtocolHybrid});
    }

    [[nodiscard]] static RdpGraphicsSurfaceReconfiguration
    beginSurfaceReconfiguration(
        McsSessionLifecycle &session,
        ::PixelSize geometry) noexcept
    {
        return session.beginVerifiedR2GraphicsSurfaceReconfiguration(
            {kRdpProtocolHybrid, kRdpProtocolHybrid}, geometry);
    }

    static void recordAcceptanceEvent(
        McsSessionLifecycle &session,
        RdpFirstClientAcceptanceEventKind kind) noexcept
    {
        session.recordFirstClientAcceptanceEvent(kind);
    }
};
} // namespace rdp_server::server::transport

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

[[nodiscard]] std::vector<std::uint8_t> frameDomainPdu(
    std::span<const std::uint8_t> payload);

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

    // MS-RDPBCGR's RDP nodeID profile permits 65536 (PER offset 0xFC17).
    const auto upperNode =
        encodeMcsConnectResponse(parsed.value, ids, 65536, 1);
    assert(upperNode);
    assert(upperNode.bytes()[55] == 0xfc);
    assert(upperNode.bytes()[56] == 0x17);
    assert(!encodeMcsConnectResponse(parsed.value, ids, 65537, 1));

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


void testMcsGccFirstExchangeConformance()
{
    // Protocol-only qualification of the first Basic Settings exchange.
    // This fixture never creates R2/native admission and never enters a live
    // MCS session; positive R3 progression remains broker-only.
    constexpr std::array<std::uint8_t, 4> coreHeader{
        0x01, 0xc0, 0xd8, 0x00};
    constexpr std::array<std::uint8_t, 4> clusterHeader{
        0x04, 0xc0, 0x0c, 0x00};
    constexpr std::array<std::uint8_t, 4> securityHeader{
        0x02, 0xc0, 0x0c, 0x00};
    constexpr std::array<std::uint8_t, 4> networkHeader{
        0x03, 0xc0, 0x2c, 0x00};

    const auto published = publishedFixture();
    const auto connectInitial = parseMcsConnectInitial(published);
    assert(connectInitial);
    const auto domain = mergeMcsDomainParameters(connectInitial.value);
    assert(domain);
    const std::array<std::uint32_t, 8> expectedDomain{
        34U, 3U, 0U, 1U, 0U, 1U, 65528U, 2U};
    assert(domain.value.values == expectedDomain);

    std::vector<std::uint8_t> gccBytes(
        connectInitial.value.gccUserData.begin(),
        connectInitial.value.gccUserData.end());
    const auto locateBlock =
        [&gccBytes](const std::array<std::uint8_t, 4> &header)
        {
            const auto found = std::search(
                gccBytes.begin(), gccBytes.end(),
                header.begin(), header.end());
            assert(found != gccBytes.end());
            return static_cast<std::size_t>(found - gccBytes.begin());
        };
    const auto blockLengthAt =
        [&gccBytes](std::size_t offset)
        {
            assert(offset + 4U <= gccBytes.size());
            return static_cast<std::size_t>(gccBytes[offset + 2U]) |
                   (static_cast<std::size_t>(gccBytes[offset + 3U]) << 8U);
        };

    const std::size_t coreOffset = locateBlock(coreHeader);
    const std::size_t clusterOffset = locateBlock(clusterHeader);
    const std::size_t securityOffset = locateBlock(securityHeader);
    const std::size_t networkOffset = locateBlock(networkHeader);
    assert(coreOffset < clusterOffset);
    assert(clusterOffset < securityOffset);
    assert(securityOffset < networkOffset);
    assert(blockLengthAt(coreOffset) == 216U);
    assert(blockLengthAt(clusterOffset) == 12U);
    assert(blockLengthAt(securityOffset) == 12U);
    assert(blockLengthAt(networkOffset) == 44U);
    assert(networkOffset + blockLengthAt(networkOffset) == gccBytes.size());

    const auto gcc = parseGccConferenceCreate(gccBytes);
    assert(gcc);
    assert(gcc.settings.channelCount == 3U);
    assert(std::string_view(gcc.settings.channels[0].name.data()) == "rdpdr");
    assert(std::string_view(gcc.settings.channels[1].name.data()) == "cliprdr");
    assert(std::string_view(gcc.settings.channels[2].name.data()) == "rdpsnd");

    const auto allocation =
        planMcsConnectResponseAllocation(domain.value, gcc.settings);
    assert(allocation && *allocation);
    assert(allocation->gccNodeId == 1001U);
    assert(allocation->ioChannelId == 1003U);
    constexpr std::array<std::uint16_t, 3> expectedChannelIds{
        1004U, 1005U, 1006U};
    assert(std::equal(
        allocation->staticChannels().begin(),
        allocation->staticChannels().end(),
        expectedChannelIds.begin(), expectedChannelIds.end()));

    // GCC Client Data Blocks are type-tagged and may arrive in a different
    // order. Reorder all four blocks without changing any encoded length.
    std::vector<std::uint8_t> reordered;
    reordered.reserve(gccBytes.size());
    reordered.insert(
        reordered.end(), gccBytes.begin(), gccBytes.begin() + coreOffset);
    const auto appendBlock =
        [&gccBytes, &reordered, &blockLengthAt](std::size_t offset)
        {
            const std::size_t length = blockLengthAt(offset);
            assert(offset + length <= gccBytes.size());
            reordered.insert(
                reordered.end(), gccBytes.begin() + offset,
                gccBytes.begin() + offset + length);
        };
    appendBlock(securityOffset);
    appendBlock(networkOffset);
    appendBlock(coreOffset);
    appendBlock(clusterOffset);
    assert(reordered.size() == gccBytes.size());
    const auto reorderedGcc = parseGccConferenceCreate(reordered);
    assert(reorderedGcc);
    assert(reorderedGcc.settings.channelCount == gcc.settings.channelCount);
    for (std::size_t index = 0U; index < gcc.settings.channelCount; ++index)
    {
        assert(reorderedGcc.settings.channels[index].name ==
               gcc.settings.channels[index].name);
        assert(reorderedGcc.settings.channels[index].options ==
               gcc.settings.channels[index].options);
    }

    // Independently derive an Enhanced-Security representative from the
    // published fixture by replaying the HYBRID selection in Client Core.
    auto hybridPacket = published;
    const std::size_t gccPacketOffset = static_cast<std::size_t>(
        connectInitial.value.gccUserData.data() - published.data());
    const std::size_t selectedProtocolOffset =
        gccPacketOffset + coreOffset + 4U + 208U;
    assert(selectedProtocolOffset + 4U <= hybridPacket.size());
    hybridPacket[selectedProtocolOffset] =
        static_cast<std::uint8_t>(kRdpProtocolHybrid);
    hybridPacket[selectedProtocolOffset + 1U] = 0U;
    hybridPacket[selectedProtocolOffset + 2U] = 0U;
    hybridPacket[selectedProtocolOffset + 3U] = 0U;
    const auto hybridConnectInitial = parseMcsConnectInitial(hybridPacket);
    assert(hybridConnectInitial);
    const auto hybridGcc =
        parseGccConferenceCreate(hybridConnectInitial.value.gccUserData);
    assert(hybridGcc);
    const SecurityNegotiationProvenance provenance{
        kRdpProtocolSsl | kRdpProtocolHybrid,
        kRdpProtocolHybrid};
    assert(matchesMcsSecurityNegotiationReplay(
        hybridGcc.settings, provenance));
    const auto response = encodeMcsConnectResponse(
        hybridConnectInitial.value, allocation->staticChannels(),
        allocation->gccNodeId, provenance.clientRequestedProtocols);
    assert(response);

    // Client Security Data must contain at least one recognized encryption
    // method across the ordinary/French-locale fields. Unknown-only input is
    // not a capability. A valid flag may coexist with unknown future bits.
    auto zeroSecurity = gccBytes;
    std::fill(
        zeroSecurity.begin() + securityOffset + 4U,
        zeroSecurity.begin() + securityOffset + 12U, 0U);
    assert(parseGccConferenceCreate(zeroSecurity).error ==
           GccError::InvalidSecurity);

    auto unknownOnly = zeroSecurity;
    unknownOnly[securityOffset + 4U] = 0x04U;
    assert(parseGccConferenceCreate(unknownOnly).error ==
           GccError::InvalidSecurity);

    auto frenchLocale = zeroSecurity;
    frenchLocale[securityOffset + 8U] = 0x02U;
    assert(parseGccConferenceCreate(frenchLocale));

    auto validPlusUnknown = zeroSecurity;
    validPlusUnknown[securityOffset + 4U] = 0x05U;
    assert(parseGccConferenceCreate(validPlusUnknown));

    // Same-length CS_CLUSTER -> CS_SECURITY mutation creates a duplicate
    // Security block and must be rejected transactionally.
    auto duplicateSecurity = gccBytes;
    duplicateSecurity[clusterOffset] = 0x02U;
    duplicateSecurity[clusterOffset + 1U] = 0xc0U;
    assert(parseGccConferenceCreate(duplicateSecurity).error ==
           GccError::InvalidSecurity);

    // The complete production R3 validation path must surface the malformed
    // security block while remaining denial-only: no synthetic admission.
    auto invalidPacket = published;
    std::fill(
        invalidPacket.begin() + gccPacketOffset + securityOffset + 4U,
        invalidPacket.begin() + gccPacketOffset + securityOffset + 12U,
        0U);
    McsSessionLifecycle denied;
    assert(denied.onConnectInitial(invalidPacket) ==
           McsSessionIntake::InvalidGccUserData);
    assert(denied.phase() == McsSessionPhase::Closed);
}


void testMcsResponseSecurityReplay()
{
    // This case is already in the hosted R3 sanitizer selection. Reuse the
    // focused conformance routine so the new parser rejection is sanitized
    // without adding a second CI selector owner.
    testMcsGccFirstExchangeConformance();

    constexpr std::array<std::uint16_t, 3> ids{1004, 1005, 1006};
    constexpr std::array<std::uint8_t, 4> coreHeader{
        0x01, 0xc0, 0xd8, 0x00};

    auto packet = publishedFixture();
    auto parsed = parseMcsConnectInitial(packet);
    assert(parsed);
    const auto legacyGcc =
        parseGccConferenceCreate(parsed.value.gccUserData);
    assert(legacyGcc);
    assert(legacyGcc.settings.hasServerSelectedProtocol);
    assert(legacyGcc.settings.serverSelectedProtocol == 0U);
    // The published example predates Enhanced Security negotiation replay.
    assert(!matchesMcsSecurityNegotiationReplay(
        parsed.value, kRdpProtocolSsl, kRdpProtocolSsl));

    const auto core = std::search(
        parsed.value.gccUserData.begin(), parsed.value.gccUserData.end(),
        coreHeader.begin(), coreHeader.end());
    assert(core != parsed.value.gccUserData.end());
    const std::size_t gccOffset = static_cast<std::size_t>(
        parsed.value.gccUserData.data() - packet.data());
    const std::size_t coreOffset = static_cast<std::size_t>(
        core - parsed.value.gccUserData.begin());
    // Four-byte block header + 208-byte offset in the Client Core body.
    const std::size_t selectedProtocolOffset =
        gccOffset + coreOffset + 212U;
    assert(selectedProtocolOffset + 4U <= packet.size());

    packet[selectedProtocolOffset] =
        static_cast<std::uint8_t>(kRdpProtocolHybrid);
    packet[selectedProtocolOffset + 1U] = 0U;
    packet[selectedProtocolOffset + 2U] = 0U;
    packet[selectedProtocolOffset + 3U] = 0U;
    parsed = parseMcsConnectInitial(packet);
    assert(parsed);
    const auto hybridGcc =
        parseGccConferenceCreate(parsed.value.gccUserData);
    assert(hybridGcc);
    assert(hybridGcc.settings.hasServerSelectedProtocol);
    assert(hybridGcc.settings.serverSelectedProtocol ==
           kRdpProtocolHybrid);

    assert(matchesMcsSecurityNegotiationReplay(
        parsed.value, kRdpProtocolHybrid, kRdpProtocolHybrid));
    assert(matchesMcsSecurityNegotiationReplay(
        parsed.value,
        kRdpProtocolSsl | kRdpProtocolHybrid,
        kRdpProtocolHybrid));
    assert(!matchesMcsSecurityNegotiationReplay(
        parsed.value, kRdpProtocolSsl, kRdpProtocolHybrid));
    assert(!matchesMcsSecurityNegotiationReplay(
        parsed.value,
        kRdpProtocolSsl | kRdpProtocolHybrid,
        kRdpProtocolSsl));
    assert(!matchesMcsSecurityNegotiationReplay(
        parsed.value, 0x00000008U, kRdpProtocolHybrid));
    assert(!matchesMcsSecurityNegotiationReplay(
        parsed.value,
        kRdpProtocolSsl | kRdpProtocolHybrid,
        0x00000004U));

    const auto sslOnly =
        encodeMcsConnectResponse(
            parsed.value, ids, 31219, kRdpProtocolSsl);
    const auto hybridOnly =
        encodeMcsConnectResponse(
            parsed.value, ids, 31219, kRdpProtocolHybrid);
    const auto hybridAndSsl =
        encodeMcsConnectResponse(
            parsed.value, ids, 31219,
            kRdpProtocolSsl | kRdpProtocolHybrid);
    assert(sslOnly && hybridOnly && hybridAndSsl);
    assert(sslOnly.length == hybridOnly.length);
    assert(sslOnly.length == hybridAndSsl.length);

    // SC_CORE = type, length, version, exact clientRequestedProtocols.
    constexpr std::array<std::uint8_t, 8> serverCorePrefix{
        0x01, 0x0c, 0x0c, 0x00, 0x04, 0x00, 0x08, 0x00};
    const auto locateRequestMask =
        [&serverCorePrefix](const McsConnectResponse &response)
        {
            const auto found = std::search(
                response.bytes().begin(), response.bytes().end(),
                serverCorePrefix.begin(), serverCorePrefix.end());
            assert(found != response.bytes().end());
            return static_cast<std::size_t>(
                       found - response.bytes().begin()) +
                   serverCorePrefix.size();
        };
    const std::size_t sslOffset = locateRequestMask(sslOnly);
    const std::size_t hybridOffset = locateRequestMask(hybridOnly);
    const std::size_t combinedOffset = locateRequestMask(hybridAndSsl);
    assert(sslOnly.bytes()[sslOffset] == kRdpProtocolSsl);
    assert(hybridOnly.bytes()[hybridOffset] == kRdpProtocolHybrid);
    assert(hybridAndSsl.bytes()[combinedOffset] ==
           (kRdpProtocolSsl | kRdpProtocolHybrid));
    for (std::size_t byte = 1; byte < 4U; ++byte)
    {
        assert(sslOnly.bytes()[sslOffset + byte] == 0U);
        assert(hybridOnly.bytes()[hybridOffset + byte] == 0U);
        assert(hybridAndSsl.bytes()[combinedOffset + byte] == 0U);
    }

    // These request masks change only the four-byte SC_CORE replay field.
    for (std::size_t index = 0; index < sslOnly.length; ++index)
    {
        const bool requestMaskByte =
            index >= sslOffset && index < sslOffset + 4U;
        if (!requestMaskByte)
        {
            assert(sslOnly.bytes()[index] == hybridOnly.bytes()[index]);
            assert(sslOnly.bytes()[index] == hybridAndSsl.bytes()[index]);
        }
    }
}


void testMcsResponseSessionAllocationPlan()
{
    const auto fixture = publishedFixture();
    const auto parsed = parseMcsConnectInitial(fixture);
    assert(parsed);
    const auto domain = mergeMcsDomainParameters(parsed.value);
    const auto gcc = parseGccConferenceCreate(parsed.value.gccUserData);
    assert(domain && gcc && gcc.settings.channelCount == 3U);
    const auto plan =
        planMcsConnectResponseAllocation(domain.value, gcc.settings);
    assert(plan && *plan);
    assert(plan->gccNodeId == 1001U);
    assert(plan->ioChannelId == 1003U);
    constexpr std::array<std::uint16_t, 3> expected{1004U,1005U,1006U};
    assert(std::equal(plan->staticChannels().begin(),
                      plan->staticChannels().end(),
                      expected.begin(), expected.end()));
    assert(encodeMcsConnectResponseFromNegotiatedState(
        domain.value, gcc.settings.channelCount, plan->staticChannels(),
        plan->gccNodeId, kRdpProtocolSsl));
    auto insufficient=domain.value;
    insufficient.values[0]=static_cast<std::uint32_t>(
        gcc.settings.channelCount)+2U;
    assert(!planMcsConnectResponseAllocation(insufficient,gcc.settings));
    auto invalid=domain.value; invalid.values[7]=3U;
    assert(!planMcsConnectResponseAllocation(invalid,gcc.settings));
    auto tooMany=gcc.settings;
    tooMany.channelCount=static_cast<std::uint8_t>(
        kMaximumStaticChannelCount+1U);
    assert(!planMcsConnectResponseAllocation(domain.value,tooMany));
    McsSessionLifecycle unadmitted;
    assert(unadmitted.allocatedGccNodeId()==0U);
    assert(unadmitted.allocatedIoChannelId()==0U);
    assert(unadmitted.allocatedStaticChannelIds().empty());
}

[[nodiscard]] McsConnectResponse testPlannedConnectResponse()
{
    const auto fixture=publishedFixture();
    const auto parsed=parseMcsConnectInitial(fixture);
    assert(parsed);
    const auto plan=planMcsConnectResponseAllocation(parsed.value);
    assert(plan);
    const auto response=encodeMcsConnectResponse(
        parsed.value,plan->staticChannels(),plan->gccNodeId,kRdpProtocolSsl);
    assert(response);
    return response;
}

void testMcsStaticChannelRoleBinding()
{
    // Microsoft MS-RDPBCGR 4.1.3 negotiated CS_NET has rdpdr,
    // cliprdr and rdpsnd in that order; SC_NET IDs are positional.
    const auto fixture = publishedFixture();
    const auto client = parseMcsConnectInitial(fixture);
    assert(client);
    const auto gcc = parseGccConferenceCreate(client.value.gccUserData);
    const auto domain = mergeMcsDomainParameters(client.value);
    assert(gcc && domain && gcc.settings.channelCount == 3U);
    const auto allocation =
        planMcsConnectResponseAllocation(domain.value, gcc.settings);
    assert(allocation);
    assert(resolveMcsStaticChannelRole(
        gcc.settings, *allocation, McsStaticChannelRole::DeviceRedirection)
           == 1004U);
    assert(resolveMcsStaticChannelRole(
        gcc.settings, *allocation, McsStaticChannelRole::Clipboard) == 1005U);
    assert(resolveMcsStaticChannelRole(
        gcc.settings, *allocation, McsStaticChannelRole::Sound) == 1006U);
    assert(!resolveMcsStaticChannelRole(
        gcc.settings, *allocation, McsStaticChannelRole::DynamicVirtualChannels));

    // Never guess "1005" from the name alone: the mapping belongs to the
    // same negotiated reply ID array and preserves exact client ordering.
    auto reordered = *allocation;
    std::swap(reordered.staticChannelIds[0], reordered.staticChannelIds[1]);
    assert(resolveMcsStaticChannelRole(
        gcc.settings, reordered, McsStaticChannelRole::Clipboard) == 1004U);
    assert(resolveMcsStaticChannelRole(
        gcc.settings, reordered, McsStaticChannelRole::DeviceRedirection)
           == 1005U);
    McsSessionLifecycle unadmitted;
    assert(unadmitted.allocatedUserId() == 0U);
    assert(!unadmitted.channelJoinConfirmed(1005U));
}

void testMcsStaticChannelRoleDenials()
{
    const auto fixture = publishedFixture();
    const auto client = parseMcsConnectInitial(fixture);
    assert(client);
    const auto gcc = parseGccConferenceCreate(client.value.gccUserData);
    const auto domain = mergeMcsDomainParameters(client.value);
    assert(gcc && domain);
    const auto allocation =
        planMcsConnectResponseAllocation(domain.value, gcc.settings);
    assert(allocation);

    auto duplicate = gcc.settings;
    duplicate.channels[0].name = duplicate.channels[1].name;
    assert(!resolveMcsStaticChannelRole(
        duplicate, *allocation, McsStaticChannelRole::Clipboard));
    auto unknown = gcc.settings;
    unknown.channels[1].name = {};
    assert(!resolveMcsStaticChannelRole(
        unknown, *allocation, McsStaticChannelRole::Clipboard));
    auto nonterminated = gcc.settings;
    nonterminated.channels[1].name.back() = 'X';
    assert(!resolveMcsStaticChannelRole(
        nonterminated, *allocation, McsStaticChannelRole::Clipboard));
    auto nonnetwork = gcc.settings;
    nonnetwork.hasNetworkData = false;
    assert(!resolveMcsStaticChannelRole(
        nonnetwork, *allocation, McsStaticChannelRole::Clipboard));
    auto truncated = gcc.settings;
    truncated.channelCount = 2U;
    assert(!resolveMcsStaticChannelRole(
        truncated, *allocation, McsStaticChannelRole::Clipboard));
    auto oversized = gcc.settings;
    oversized.channelCount =
        static_cast<std::uint8_t>(kMaximumStaticChannelCount + 1U);
    assert(!resolveMcsStaticChannelRole(
        oversized, *allocation, McsStaticChannelRole::Clipboard));

    auto bad = *allocation;
    bad.staticChannelIds[1] = bad.staticChannelIds[0];
    assert(!resolveMcsStaticChannelRole(
        gcc.settings, bad, McsStaticChannelRole::Clipboard));
    bad = *allocation;
    bad.staticChannelIds[1] = bad.ioChannelId;
    assert(!resolveMcsStaticChannelRole(
        gcc.settings, bad, McsStaticChannelRole::Clipboard));
    bad = *allocation;
    bad.gccNodeId = bad.ioChannelId;
    assert(!resolveMcsStaticChannelRole(
        gcc.settings, bad, McsStaticChannelRole::Clipboard));
    bad = *allocation;
    bad.staticChannelCount =
        static_cast<std::uint8_t>(kMaximumStaticChannelCount + 1U);
    assert(!resolveMcsStaticChannelRole(
        gcc.settings, bad, McsStaticChannelRole::Clipboard));
    assert(!resolveMcsStaticChannelRole(
        gcc.settings, *allocation, static_cast<McsStaticChannelRole>(255)));

    // A guessed static ID or role cannot advance the public R3 owner.
    McsSessionLifecycle early;
    assert(early.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    early.revokeUnlessAdmissionBindingMatches(1002U, 1005U);
    assert(early.phase() == McsSessionPhase::Closed);
    assert(!early.channelJoinConfirmed(1005U));
}

void testMcsClientInfoProtectedRoute()
{
    // Under PROTOCOL_HYBRID the post-join Client Info still begins with
    // the Basic Security Header. Keep a fixed-size minimum TS_INFO_PACKET
    // body here: this test proves routing only, not TS_INFO semantics.
    std::array<std::uint8_t, 29> mcs{};
    mcs[0] = 0x64U; // client SendDataRequest
    mcs[1] = 0x00U;
    mcs[2] = 0x01U; // UserId 1002 => PER offset 1
    mcs[3] = 0x03U;
    mcs[4] = 0xebU; // I/O 1003
    mcs[5] = 0x70U; // priority high, begin|end segmentation
    mcs[6] = 22U;   // 4-byte security header + 18-byte TS_INFO fixed prefix
    mcs[7] = 0x40U; // SEC_INFO_PKT
    mcs[8] = 0x00U;
    mcs[9] = 0xa5U; // flagsHi ignored unless/future even when marked valid
    mcs[10] = 0x5aU;

    const auto frame = frameDomainPdu(mcs);
    const auto parsed = parseMcsChannelRequest(frame);
    assert(parsed);
    assert(parsed.request.kind == McsChannelRequestKind::SendDataRequest);
    assert(parsed.request.initiator == 1002U);
    assert(parsed.request.channelId == 1003U);
    assert(parsed.request.segmentation == 3U);
    assert(parsed.request.userData.size() == 22U);

    constexpr std::array<std::uint16_t, 3> channels{
        1002U, 1003U, 1005U};
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1002U, channels));
    assert(!gate.allConfiguredChannelsJoined());
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1002U;
    for (const auto channel : channels)
    {
        join.channelId = channel;
        assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
        const auto bytes = gate.pendingBytes();
        assert(bytes.size() == 15U);
        assert(gate.onReplyBytesWritten(
            gate.pendingReplySequence(), gate.pendingWriteSliceSequence(),
            bytes.size()) == McsJoinWriteOutcome::Confirmed);
    }
    assert(gate.allConfiguredChannelsJoined());
    assert(gate.matchesJoinedInboundSendData(parsed.request));

    const auto envelope =
        parseEnhancedSecurityClientInfoEnvelope(parsed.request.userData);
    assert(envelope);
    assert(envelope.value.flags == 0x0040U);
    assert(envelope.value.flagsHi == 0x5aa5U);
    assert(envelope.value.infoPacket.size() == 18U);
    assert(envelope.value.infoPacket.data() ==
           parsed.request.userData.data() + 4U);

    // Sequence-number flags are explicitly ignored by MS-RDPBCGR.
    auto ignoredFlags = parsed.request.userData;
    std::array<std::uint8_t, 22> allowed{};
    std::copy(ignoredFlags.begin(), ignoredFlags.end(), allowed.begin());
    allowed[0] = 0x70U; // INFO | RESET_SEQNO | IGNORE_SEQNO
    allowed[1] = 0x80U; // FLAGSHI_VALID
    allowed[2] = 0xfeU;
    allowed[3] = 0xcaU;
    const auto ignored = parseEnhancedSecurityClientInfoEnvelope(allowed);
    assert(ignored);
    assert(ignored.value.flags == 0x8070U);
    assert(ignored.value.flagsHi == 0xcafeU);
}

void testMcsClientInfoProtectedRouteDenials()
{
    constexpr std::array<std::uint8_t, 22> valid{
        0x40, 0x00, 0x34, 0x12, // SEC_INFO_PKT + ignored flagsHi
        0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    for (std::size_t size = 0; size < 4U; ++size)
    {
        const auto result =
            parseEnhancedSecurityClientInfoEnvelope(
                std::span(valid).first(size));
        assert(!result);
        assert(result.error ==
               RdpClientInfoEnvelopeError::TruncatedSecurityHeader);
    }
    for (std::size_t size = 4U; size < valid.size(); ++size)
    {
        const auto result =
            parseEnhancedSecurityClientInfoEnvelope(
                std::span(valid).first(size));
        assert(!result);
        assert(result.error ==
               RdpClientInfoEnvelopeError::TruncatedInfoPacket);
    }

    const auto rejectFlags = [valid](std::uint16_t flags)
    {
        auto packet = valid;
        packet[0] = static_cast<std::uint8_t>(flags);
        packet[1] = static_cast<std::uint8_t>(flags >> 8U);
        const auto result = parseEnhancedSecurityClientInfoEnvelope(packet);
        assert(!result);
        assert(result.error ==
               RdpClientInfoEnvelopeError::InvalidSecurityFlags);
    };
    rejectFlags(0x0000U); // missing SEC_INFO_PKT
    rejectFlags(0x0041U); // Standard-Security exchange ambiguity
    rejectFlags(0x0048U); // inner Standard-Security encryption unsupported
    rejectFlags(0x00c0U); // simultaneous INFO + LICENSE
    rejectFlags(0x0840U); // secure-checksum flag without Standard security
    rejectFlags(0x4040U); // heartbeat is a different packet kind

    constexpr std::array<std::uint16_t, 3> channels{
        1002U, 1003U, 1005U};
    McsChannelJoinWriteGate partial;
    assert(partial.configure(1002U, channels));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1002U;
    join.channelId = 1002U;
    assert(partial.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(partial.onReplyBytesWritten(
        partial.pendingReplySequence(), partial.pendingWriteSliceSequence(),
        partial.pendingBytes().size()) == McsJoinWriteOutcome::Confirmed);
    assert(!partial.allConfiguredChannelsJoined());

    // Even after all joins, a joined static channel is not the I/O route
    // for Client Info. MCS membership alone is deliberately insufficient.
    McsChannelJoinWriteGate joined;
    assert(joined.configure(1002U, channels));
    for (const auto channel : channels)
    {
        join.channelId = channel;
        assert(joined.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
        assert(joined.onReplyBytesWritten(
            joined.pendingReplySequence(), joined.pendingWriteSliceSequence(),
            joined.pendingBytes().size()) == McsJoinWriteOutcome::Confirmed);
    }
    assert(joined.allConfiguredChannelsJoined());

    McsChannelRequest request{};
    request.kind = McsChannelRequestKind::SendDataRequest;
    request.initiator = 1002U;
    request.channelId = 1005U;
    request.segmentation = 3U;
    request.userData = valid;
    assert(joined.matchesJoinedInboundSendData(request));
    assert(request.channelId != 1003U);

    request.channelId = 1003U;
    request.segmentation = 2U; // incomplete PER/MCS segment
    assert(joined.matchesJoinedInboundSendData(request));
    assert(request.segmentation != 3U);

    request.segmentation = 3U;
    request.initiator = 1001U;
    assert(!joined.matchesJoinedInboundSendData(request));

    joined.close();
    assert(!joined.allConfiguredChannelsJoined());
}

void testRdpClientInfoPacketStructure()
{
    // Unicode TS_INFO_PACKET with five empty strings. Each cb* field excludes
    // its mandatory UTF-16 NUL, so the structural packet is 18 + 5*2 bytes.
    std::vector<std::uint8_t> unicode(28U, 0U);
    unicode[4] = 0x10U; // INFO_UNICODE
    const auto basic = parseRdpClientInfoPacket(unicode);
    assert(basic);
    assert(basic.value.unicode);
    assert(!basic.value.hasExtendedInfo);
    assert(basic.value.flags == 0x10U);
    assert(basic.value.domainBytes == 0U);
    assert(basic.value.userNameBytes == 0U);
    assert(basic.value.passwordBytes == 0U);
    assert(basic.value.alternateShellBytes == 0U);
    assert(basic.value.workingDirBytes == 0U);

    // ANSI shape uses one-byte terminators. Code-page interpretation remains
    // outside this structural boundary.
    std::vector<std::uint8_t> ansi(23U, 0U);
    const auto ansiParsed = parseRdpClientInfoPacket(ansi);
    assert(ansiParsed && !ansiParsed.value.unicode);
    assert(!ansiParsed.value.hasExtendedInfo);

    // Minimal TS_EXTENDED_INFO_PACKET: AF_INET, empty terminated address and
    // clientDir. No later optional fields are required merely by its presence.
    auto extended = unicode;
    constexpr std::array<std::uint8_t, 10> minimalExtended{
        0x02,0x00, // AF_INET
        0x02,0x00, 0x00,0x00, // cbClientAddress + UTF-16 NUL
        0x02,0x00, 0x00,0x00  // cbClientDir + UTF-16 NUL
    };
    extended.insert(
        extended.end(), minimalExtended.begin(), minimalExtended.end());
    const auto extendedParsed = parseRdpClientInfoPacket(extended);
    assert(extendedParsed);
    assert(extendedParsed.value.hasExtendedInfo);

    // Full optional suffix through Dynamic DST with empty key name.
    auto full = extended;
    full.resize(full.size() + 172U, 0U); // clientTimeZone
    full.resize(full.size() + 4U, 0U);   // clientSessionId
    full.resize(full.size() + 4U, 0U);   // performanceFlags
    full.push_back(0U);                  // cbAutoReconnectCookie = 0
    full.push_back(0U);
    full.insert(full.end(), 4U, 0U);     // reserved1/reserved2
    full.push_back(0U);                  // cbDynamicDSTTimeZoneKeyName = 0
    full.push_back(0U);
    full.push_back(0U);                  // dynamicDaylightTimeDisabled = false
    full.push_back(0U);
    const auto fullParsed = parseRdpClientInfoPacket(full);
    assert(fullParsed && fullParsed.value.hasExtendedInfo);
}

void testRdpClientInfoPacketDenials()
{
    std::vector<std::uint8_t> valid(28U, 0U);
    valid[4] = 0x10U; // INFO_UNICODE

    for (std::size_t size = 0U; size < 18U; ++size)
    {
        const auto parsed =
            parseRdpClientInfoPacket(std::span(valid).first(size));
        assert(!parsed);
        assert(parsed.error ==
               RdpClientInfoPacketError::TruncatedFixedFields);
    }

    auto odd = valid;
    odd[8] = 1U; // cbDomain must be even in Unicode form.
    assert(parseRdpClientInfoPacket(odd).error ==
           RdpClientInfoPacketError::InvalidStringLength);

    auto tooLarge = valid;
    tooLarge[8] = 0x00U;
    tooLarge[9] = 0x02U; // 512 data bytes + 2 terminator exceeds max 512.
    assert(parseRdpClientInfoPacket(tooLarge).error ==
           RdpClientInfoPacketError::InvalidStringLength);

    auto nonterminated = valid;
    nonterminated[19] = 1U; // second byte of empty Domain UTF-16 NUL.
    assert(parseRdpClientInfoPacket(nonterminated).error ==
           RdpClientInfoPacketError::MissingStringTerminator);

    auto extended = valid;
    constexpr std::array<std::uint8_t, 10> minimalExtended{
        0x02,0x00, 0x02,0x00, 0x00,0x00,
        0x02,0x00, 0x00,0x00};
    extended.insert(
        extended.end(), minimalExtended.begin(), minimalExtended.end());

    auto badFamily = extended;
    badFamily[28] = 3U;
    assert(parseRdpClientInfoPacket(badFamily).error ==
           RdpClientInfoPacketError::InvalidExtendedInfo);

    auto badAddressNul = extended;
    badAddressNul[33] = 1U;
    assert(parseRdpClientInfoPacket(badAddressNul).error ==
           RdpClientInfoPacketError::InvalidExtendedTerminator);

    auto badDirNul = extended;
    badDirNul[37] = 1U;
    assert(parseRdpClientInfoPacket(badDirNul).error ==
           RdpClientInfoPacketError::InvalidExtendedTerminator);

    auto partialTimeZone = extended;
    partialTimeZone.push_back(0U);
    assert(parseRdpClientInfoPacket(partialTimeZone).error ==
           RdpClientInfoPacketError::InvalidOptionalOrdering);

    auto full = extended;
    full.resize(full.size() + 172U, 0U);
    full.resize(full.size() + 4U, 0U);
    full.resize(full.size() + 4U, 0U);
    const std::size_t autoReconnectOffset = full.size();
    full.push_back(0U);
    full.push_back(0U);
    const std::size_t reservedOffset = full.size();
    full.insert(full.end(), 4U, 0U);
    const std::size_t dynamicKeyLengthOffset = full.size();
    full.push_back(0U);
    full.push_back(0U);
    const std::size_t dynamicDisabledOffset = full.size();
    full.push_back(0U);
    full.push_back(0U);
    assert(parseRdpClientInfoPacket(full));

    auto invalidAuto = full;
    invalidAuto[autoReconnectOffset] = 1U;
    assert(parseRdpClientInfoPacket(invalidAuto).error ==
           RdpClientInfoPacketError::InvalidExtendedInfo);

    auto invalidReserved2 = full;
    invalidReserved2[reservedOffset + 2U] = 1U;
    assert(parseRdpClientInfoPacket(invalidReserved2).error ==
           RdpClientInfoPacketError::InvalidExtendedInfo);

    auto oddDynamicKey = full;
    oddDynamicKey[dynamicKeyLengthOffset] = 1U;
    assert(parseRdpClientInfoPacket(oddDynamicKey).error ==
           RdpClientInfoPacketError::InvalidExtendedInfo);

    auto invalidDynamicDisabled = full;
    invalidDynamicDisabled[dynamicDisabledOffset] = 2U;
    assert(parseRdpClientInfoPacket(invalidDynamicDisabled).error ==
           RdpClientInfoPacketError::InvalidExtendedInfo);

    auto trailing = full;
    trailing.push_back(0U);
    assert(parseRdpClientInfoPacket(trailing).error ==
           RdpClientInfoPacketError::InvalidExtendedInfo);
}

void testMcsResponseWriteReceipts()
{
    const auto response=testPlannedConnectResponse();
    McsConnectResponseWriteGate gate;
    assert(gate.queue(response));
    const auto first=gate.pendingWrite();
    assert(first && first.bytes.size()==response.length);
    assert(gate.onBytesWritten(
        first.replySequence,first.writeSliceSequence,0U)==
        McsConnectResponseWriteOutcome::Pending);
    const auto backpressure=gate.pendingWrite();
    assert(backpressure.replySequence==first.replySequence);
    assert(backpressure.writeSliceSequence==first.writeSliceSequence);
    constexpr std::size_t progress=7U;
    assert(gate.onBytesWritten(
        first.replySequence,first.writeSliceSequence,progress)==
        McsConnectResponseWriteOutcome::Pending);
    const auto second=gate.pendingWrite();
    assert(second && second.replySequence==first.replySequence);
    assert(second.writeSliceSequence!=first.writeSliceSequence);
    assert(second.bytes.size()==response.length-progress);
    assert(std::equal(second.bytes.begin(),second.bytes.end(),
                      response.bytes().begin()+progress,response.bytes().end()));
    assert(gate.onBytesWritten(
        second.replySequence,second.writeSliceSequence,second.bytes.size())==
        McsConnectResponseWriteOutcome::Delivered);
    assert(!gate.pendingWrite());
    assert(!gate.queue(response));
}

void testMcsResponseWriteDenials()
{
    const auto response=testPlannedConnectResponse();
    McsConnectResponse fabricated{};
    fabricated.length=fabricated.packet.size()+1U;
    assert(!fabricated && fabricated.bytes().empty());
    McsConnectResponseWriteGate bad;
    assert(!bad.queue(fabricated));
    assert(!bad.queue(response));

    McsConnectResponseAllocation badAllocation{};
    badAllocation.gccNodeId=1001U;
    badAllocation.ioChannelId=1003U;
    badAllocation.staticChannelCount=static_cast<std::uint8_t>(
        badAllocation.staticChannelIds.size()+1U);
    assert(!badAllocation && badAllocation.staticChannels().empty());

    McsConnectResponseWriteGate staleReply;
    assert(staleReply.queue(response));
    auto write=staleReply.pendingWrite();
    assert(staleReply.onBytesWritten(
        write.replySequence+1U,write.writeSliceSequence,1U)==
        McsConnectResponseWriteOutcome::Rejected);
    assert(!staleReply.pendingWrite());

    McsConnectResponseWriteGate staleSlice;
    assert(staleSlice.queue(response));
    const auto old=staleSlice.pendingWrite();
    assert(staleSlice.onBytesWritten(
        old.replySequence,old.writeSliceSequence,1U)==
        McsConnectResponseWriteOutcome::Pending);
    const auto current=staleSlice.pendingWrite();
    assert(current.writeSliceSequence!=old.writeSliceSequence);
    assert(staleSlice.onBytesWritten(
        old.replySequence,old.writeSliceSequence,1U)==
        McsConnectResponseWriteOutcome::Rejected);

    McsConnectResponseWriteGate overreport;
    assert(overreport.queue(response));
    write=overreport.pendingWrite();
    assert(overreport.onBytesWritten(
        write.replySequence,write.writeSliceSequence,write.bytes.size()+1U)==
        McsConnectResponseWriteOutcome::Rejected);

    McsConnectResponseWriteGate closed;
    assert(closed.queue(response)); closed.close();
    assert(!closed.pendingWrite());
    assert(closed.onBytesWritten(1U,1U,0U)==
           McsConnectResponseWriteOutcome::Rejected);
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
    reject(encodeMcsConnectResponse(parsed.value, ids, 31219, 4));
    reject(encodeMcsConnectResponse(parsed.value, ids, 31219, 8));
    reject(encodeMcsConnectResponse(
        parsed.value, ids, 31219, 0x80000003U));
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

    // MS-RDPBCGR's RDP User Channel ID profile permits 65536, encoded
    // as offset 64535 (0xFC17) from the T.125 first UserId 1001.
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
    constexpr std::array<std::uint8_t, 5> onePastUser{
        0x38, 0xfc, 0x18, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 5> overflowInitiator{
        0x38, 0xff, 0xff, 0x03, 0xeb};
    for (const auto &invalid : {onePastUser, overflowInitiator})
        assert(parseMcsChannelRequest(frameDomainPdu(invalid)).error ==
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



void testMcsRdpUserIdRangeConformance()
{
    // The generic T.124/T.125 ASN.1 text ends DynamicChannelId/UserId at
    // 65535, but MS-RDPBCGR explicitly profiles the RDP User Channel ID and
    // GCC nodeID as 1001..65536 inclusive. Follow the RDP specification:
    // offset 0xFC17 is valid and 0xFC18 is the first rejected value.
    constexpr std::uint32_t maxUserId = 65536U;
    constexpr std::uint32_t onePastUserId = 65537U;
    constexpr std::array<std::uint8_t, 5> maxJoinPayload{
        0x38, 0xfc, 0x17, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 5> onePastJoinPayload{
        0x38, 0xfc, 0x18, 0x03, 0xeb};

    const auto maxJoin =
        parseMcsChannelRequest(frameDomainPdu(maxJoinPayload));
    assert(maxJoin);
    assert(maxJoin.request.initiator == maxUserId);
    assert(parseMcsChannelRequest(frameDomainPdu(onePastJoinPayload)).error ==
           McsChannelParseError::InvalidPerValue);

    constexpr std::array<std::uint8_t, 8> maxSendPayload{
        0x64, 0xfc, 0x17, 0x03, 0xeb, 0x70, 0x01, 0x42};
    constexpr std::array<std::uint8_t, 8> onePastSendPayload{
        0x64, 0xfc, 0x18, 0x03, 0xeb, 0x70, 0x01, 0x42};
    // McsChannelRequest::userData is a borrowed span into the complete TPKT.
    // Keep the backing frame alive until every borrowed byte is inspected.
    const auto maxSendFrame = frameDomainPdu(maxSendPayload);
    const auto maxSend = parseMcsChannelRequest(maxSendFrame);
    assert(maxSend);
    assert(maxSend.request.initiator == maxUserId);
    assert(maxSend.request.userData.size() == 1U &&
           maxSend.request.userData[0] == 0x42U);
    assert(parseMcsChannelRequest(frameDomainPdu(onePastSendPayload)).error ==
           McsChannelParseError::InvalidPerValue);

    const auto attach = encodeMcsAttachUserConfirm(maxUserId);
    assert(attach && attach.bytes()[9] == 0xfcU &&
           attach.bytes()[10] == 0x17U);
    assert(!encodeMcsAttachUserConfirm(onePastUserId));

    constexpr std::array<std::uint16_t, 1> joinedChannel{1003U};
    const auto joinConfirm = encodeMcsChannelJoinConfirm(
        maxJoin.request, maxUserId, joinedChannel);
    assert(joinConfirm && joinConfirm.bytes()[9] == 0xfcU &&
           joinConfirm.bytes()[10] == 0x17U);
    assert(!encodeMcsChannelJoinConfirm(
        maxJoin.request, onePastUserId, joinedChannel));

    McsChannelJoinWriteGate maxGate;
    assert(maxGate.configure(maxUserId, joinedChannel));
    assert(maxGate.beginJoin(maxJoin.request) ==
           McsJoinStartOutcome::ReplyPending);
    McsChannelJoinWriteGate invalidGate;
    assert(!invalidGate.configure(onePastUserId, joinedChannel));

    std::array<std::uint8_t, 14> indication{};
    const auto indicationBytes = encodeMcsSendDataIndication(
        maxUserId, 1003U, 1U, 3U, {}, indication);
    assert(indicationBytes && *indicationBytes == indication.size());
    assert(indication[8] == 0xfcU && indication[9] == 0x17U);
    assert(!encodeMcsSendDataIndication(
        onePastUserId, 1003U, 1U, 3U, {}, indication));

    const auto fixture = publishedFixture();
    const auto connectInitial = parseMcsConnectInitial(fixture);
    assert(connectInitial);
    constexpr std::array<std::uint16_t, 3> ids{1004U, 1005U, 1006U};
    const auto response = encodeMcsConnectResponse(
        connectInitial.value, ids, maxUserId, kRdpProtocolSsl);
    assert(response && response.bytes()[55] == 0xfcU &&
           response.bytes()[56] == 0x17U);
    assert(!encodeMcsConnectResponse(
        connectInitial.value, ids, onePastUserId, kRdpProtocolSsl));

    RdpGraphicsDynamicVirtualChannelLifecycle graphics;
    assert(graphics.begin(
        maxUserId, 1005U,
        RdpDynamicVirtualChannelAllocation{1U, 1U}, {64U, 64U}));
    RdpGraphicsDynamicVirtualChannelLifecycle rejectedGraphics;
    assert(!rejectedGraphics.begin(
        onePastUserId, 1005U,
        RdpDynamicVirtualChannelAllocation{1U, 1U}, {64U, 64U}));
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


void testMcsSessionAttachConfirmWriteReceipts()
{
    using Outcome = McsConnectResponseWriteOutcome;
    constexpr std::array<std::uint8_t, 11> expected{
        0x03,0x00,0x00,0x0b,0x02,0xf0,0x80,0x2e,0x00,0x00,0x01};
    for (std::size_t firstAccepted = 0; firstAccepted <= expected.size();
         ++firstAccepted)
    {
        McsAttachUserConfirmWriteGate writer;
        assert(writer.queue(1002U));
        const auto first = writer.pendingWrite();
        assert(first && first.bytes.size() == expected.size());
        assert(std::equal(first.bytes.begin(), first.bytes.end(), expected.begin()));
        assert(writer.onBytesWritten(
            first.replySequence, first.writeSliceSequence, 0U) == Outcome::Pending);
        const auto retry = writer.pendingWrite();
        assert(retry.bytes.data() == first.bytes.data());
        assert(retry.replySequence == first.replySequence);
        assert(retry.writeSliceSequence == first.writeSliceSequence);
        const auto result = writer.onBytesWritten(
            first.replySequence, first.writeSliceSequence, firstAccepted);
        if (firstAccepted == expected.size())
        {
            assert(result == Outcome::Delivered);
        }
        else
        {
            assert(result == Outcome::Pending);
            const auto suffix = writer.pendingWrite();
            assert(suffix && suffix.bytes.size() == expected.size()-firstAccepted);
            assert(suffix.replySequence == first.replySequence);
            assert(suffix.writeSliceSequence ==
                   first.writeSliceSequence + (firstAccepted != 0U ? 1U : 0U));
            assert(std::equal(suffix.bytes.begin(), suffix.bytes.end(),
                              expected.begin() + firstAccepted));
            assert(writer.onBytesWritten(
                suffix.replySequence, suffix.writeSliceSequence,
                suffix.bytes.size()) == Outcome::Delivered);
        }
        assert(!writer.pendingWrite());
        assert(!writer.queue(1002U));
    }
    // A standalone writer cannot grant an R3 phase or user membership.
    McsSessionLifecycle unadmitted;
    assert(unadmitted.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(unadmitted.allocatedUserId() == 0U);
    assert(!unadmitted.channelJoinConfirmed(1002U));
}

void testMcsSessionAttachConfirmDenials()
{
    using Outcome = McsConnectResponseWriteOutcome;
    for (const auto userId : {0U,1000U,65537U,UINT32_MAX})
    {
        McsAttachUserConfirmWriteGate invalid;
        assert(!invalid.queue(userId));
        assert(!invalid.pendingWrite());
        assert(!invalid.queue(1002U));
    }
    McsAttachUserConfirmWriteGate duplicate;
    assert(duplicate.queue(1002U));
    assert(!duplicate.queue(1002U));
    assert(!duplicate.pendingWrite());

    for (std::size_t denial = 0; denial < 4U; ++denial)
    {
        McsAttachUserConfirmWriteGate writer;
        assert(writer.queue(1002U));
        const auto pending = writer.pendingWrite();
        const std::uint64_t reply = denial == 0 ? 0U :
            denial == 1 ? pending.replySequence+1U : pending.replySequence;
        const std::uint64_t slice = denial == 2 ? 0U :
            pending.writeSliceSequence;
        const std::size_t count = denial == 3 ? pending.bytes.size()+1U : 1U;
        assert(writer.onBytesWritten(reply,slice,count) == Outcome::Rejected);
        assert(!writer.pendingWrite());
    }
    McsAttachUserConfirmWriteGate stale;
    assert(stale.queue(1002U));
    const auto old = stale.pendingWrite();
    assert(stale.onBytesWritten(old.replySequence,old.writeSliceSequence,3U) ==
           Outcome::Pending);
    const auto now = stale.pendingWrite();
    assert(now.writeSliceSequence > old.writeSliceSequence);
    assert(stale.onBytesWritten(old.replySequence,old.writeSliceSequence,1U) ==
           Outcome::Rejected);

    McsAttachUserConfirmWriteGate cancelled;
    assert(cancelled.queue(1002U));
    const auto initial = cancelled.pendingWrite();
    assert(cancelled.onBytesWritten(
        initial.replySequence,initial.writeSliceSequence,2U) == Outcome::Pending);
    const auto suffix = cancelled.pendingWrite();
    cancelled.close();
    assert(!cancelled.pendingWrite());
    assert(cancelled.onBytesWritten(
        suffix.replySequence,suffix.writeSliceSequence,suffix.bytes.size()) ==
        Outcome::Rejected);
    assert(!cancelled.queue(1002U));

    McsSessionLifecycle session;
    session.revokeUnlessAdmissionBindingMatches(1U,1U);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.allocatedUserId() == 0U);
    session.revokeUnlessAdmissionBindingMatches(UINT64_MAX,UINT64_MAX);
    assert(session.pendingJoinConfirmation().empty());
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
    // MS-RDPBCGR's maximum RDP User Channel ID is 65536 (offset 0xFC17).
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

std::vector<std::uint8_t> makeSlowPathInputSharePdu()
{
    std::vector<std::uint8_t> pdu(22U, 0U);
    const auto write16 = [&pdu](std::size_t offset, std::uint16_t value)
    {
        pdu[offset] = static_cast<std::uint8_t>(value);
        pdu[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    };
    const auto write32 = [&write16](std::size_t offset, std::uint32_t value)
    {
        write16(offset, static_cast<std::uint16_t>(value));
        write16(offset + 2U, static_cast<std::uint16_t>(value >> 16U));
    };
    const auto appendEvent =
        [&pdu](std::uint32_t time, std::uint16_t type,
               std::uint16_t a, std::uint16_t b, std::uint16_t c)
    {
        const std::size_t offset = pdu.size();
        pdu.resize(offset + kRdpSlowPathInputEventBytes, 0U);
        pdu[offset] = static_cast<std::uint8_t>(time);
        pdu[offset + 1U] = static_cast<std::uint8_t>(time >> 8U);
        pdu[offset + 2U] = static_cast<std::uint8_t>(time >> 16U);
        pdu[offset + 3U] = static_cast<std::uint8_t>(time >> 24U);
        pdu[offset + 4U] = static_cast<std::uint8_t>(type);
        pdu[offset + 5U] = static_cast<std::uint8_t>(type >> 8U);
        pdu[offset + 6U] = static_cast<std::uint8_t>(a);
        pdu[offset + 7U] = static_cast<std::uint8_t>(a >> 8U);
        pdu[offset + 8U] = static_cast<std::uint8_t>(b);
        pdu[offset + 9U] = static_cast<std::uint8_t>(b >> 8U);
        pdu[offset + 10U] = static_cast<std::uint8_t>(c);
        pdu[offset + 11U] = static_cast<std::uint8_t>(c >> 8U);
    };

    appendEvent(11U, 0x0004U, 0x0100U, 0x001dU, 0U);
    appendEvent(12U, 0x8001U, 0x0800U, 640U, 480U);
    appendEvent(13U, 0x0000U, 0xa5a5U, 0x0006U, 0U);
    appendEvent(14U, 0x8002U, 0x8001U, 641U, 481U);
    appendEvent(15U, 0x8004U, 0x0800U, 0xfffeU, 3U);
    appendEvent(16U, 0x0005U, 0x8000U, 0x20acU, 0U);
    appendEvent(17U, 0x0002U, 0x1111U, 0x2222U, 0x3333U);

    write16(0U, static_cast<std::uint16_t>(pdu.size()));
    write16(2U, 0x0017U);
    write16(4U, 1002U);
    write32(6U, 0x11223344U);
    pdu[11U] = 2U;
    write16(12U, static_cast<std::uint16_t>(pdu.size()));
    pdu[14U] = 0x1cU;
    write16(18U, 7U);
    write16(20U, 0xbeefU);
    return pdu;
}

void testRdpSlowPathInputWire()
{
    const auto pdu = makeSlowPathInputSharePdu();
    const auto parsed = parseRdpSlowPathInputPdu(pdu);
    assert(parsed);
    assert(parsed.value.pduSource == 1002U);
    assert(parsed.value.shareId == 0x11223344U);
    assert(parsed.value.eventCount == 7U);
    assert(parsed.value.eventBytes.size() ==
           7U * kRdpSlowPathInputEventBytes);

    RdpSlowPathInputEvent event{};
    assert(parsed.value.eventAt(0U, event));
    assert(event.kind == RdpSlowPathInputEventKind::ScancodeKeyboard);
    assert(event.eventTime == 11U);
    assert(event.keyboardFlags == 0x0100U);
    assert(event.keyCode == 0x1dU);

    assert(parsed.value.eventAt(1U, event));
    assert(event.kind == RdpSlowPathInputEventKind::Mouse);
    assert(event.pointerFlags == 0x0800U);
    assert(event.xPos == 640U && event.yPos == 480U);

    assert(parsed.value.eventAt(2U, event));
    assert(event.kind == RdpSlowPathInputEventKind::Synchronize);
    assert(event.toggleFlags == 0x00000006U);

    assert(parsed.value.eventAt(3U, event));
    assert(event.kind == RdpSlowPathInputEventKind::ExtendedMouse);
    assert(event.pointerFlags == 0x8001U);
    assert(event.xPos == 641U && event.yPos == 481U);

    assert(parsed.value.eventAt(4U, event));
    assert(event.kind == RdpSlowPathInputEventKind::RelativeMouse);
    assert(event.xDelta == -2);
    assert(event.yDelta == 3);

    assert(parsed.value.eventAt(5U, event));
    assert(event.kind == RdpSlowPathInputEventKind::UnicodeKeyboard);
    assert(event.keyboardFlags == 0x8000U);
    assert(event.unicodeCode == 0x20acU);

    assert(parsed.value.eventAt(6U, event));
    assert(event.kind == RdpSlowPathInputEventKind::Unused);
    assert(!parsed.value.eventAt(7U, event));
}

void testRdpSlowPathInputRejections()
{
    const auto valid = makeSlowPathInputSharePdu();

    auto wrongType = valid;
    wrongType[14U] = 0x14U;
    const auto typeDenied = parseRdpSlowPathInputPdu(wrongType);
    assert(!typeDenied);
    assert(typeDenied.error == RdpSlowPathInputError::WrongDataPduType);

    auto countMismatch = valid;
    countMismatch[18U] = 8U;
    const auto countDenied = parseRdpSlowPathInputPdu(countMismatch);
    assert(!countDenied);
    assert(countDenied.error == RdpSlowPathInputError::InvalidBodyLength);

    auto unknown = valid;
    unknown[26U] = 0x99U;
    unknown[27U] = 0x99U;
    const auto unknownDenied = parseRdpSlowPathInputPdu(unknown);
    assert(!unknownDenied);
    assert(unknownDenied.error == RdpSlowPathInputError::UnknownEventType);

    auto wideScancode = valid;
    wideScancode[30U] = 0x34U;
    wideScancode[31U] = 0x12U;
    const auto scanDenied = parseRdpSlowPathInputPdu(wideScancode);
    assert(!scanDenied);
    assert(scanDenied.error == RdpSlowPathInputError::UnknownEventType);

    auto shortBody = valid;
    shortBody.pop_back();
    const std::uint16_t shortSize =
        static_cast<std::uint16_t>(shortBody.size());
    shortBody[0U] = static_cast<std::uint8_t>(shortSize);
    shortBody[1U] = static_cast<std::uint8_t>(shortSize >> 8U);
    const auto shortDenied = parseRdpSlowPathInputPdu(shortBody);
    assert(!shortDenied);
    assert(shortDenied.error == RdpSlowPathInputError::InvalidBodyLength);

    std::vector<std::uint8_t> oversized(
        22U + (kMaximumRdpSlowPathInputEvents + 1U) *
                  kRdpSlowPathInputEventBytes,
        0U);
    const std::uint16_t oversizedSize =
        static_cast<std::uint16_t>(oversized.size());
    oversized[0U] = static_cast<std::uint8_t>(oversizedSize);
    oversized[1U] = static_cast<std::uint8_t>(oversizedSize >> 8U);
    oversized[2U] = 0x17U;
    oversized[4U] = 0xeaU;
    oversized[5U] = 0x03U;
    oversized[11U] = 2U;
    oversized[14U] = 0x1cU;
    const std::uint16_t oversizedCount =
        static_cast<std::uint16_t>(kMaximumRdpSlowPathInputEvents + 1U);
    oversized[18U] = static_cast<std::uint8_t>(oversizedCount);
    oversized[19U] = static_cast<std::uint8_t>(oversizedCount >> 8U);
    const auto oversizedDenied = parseRdpSlowPathInputPdu(oversized);
    assert(!oversizedDenied);
    assert(oversizedDenied.error == RdpSlowPathInputError::TooManyEvents);

    // Pure syntax success cannot cross the private post-Share route from a
    // default/unadmitted R3 owner.
    McsSessionLifecycle session;
    assert(!McsSessionLifecycleTestAccess::
        routeSlowPathInputWithoutAdmission(session, valid));
    assert(session.phase() == McsSessionPhase::Closed);
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

[[nodiscard]] std::vector<std::uint8_t> makeClientShareTpkt(
    std::uint32_t clientUserId,
    std::uint16_t ioChannelId,
    std::span<const std::uint8_t> sharePdu)
{
    assert(clientUserId >= 1001U && clientUserId <= 65536U);
    assert(ioChannelId != 0U);
    assert(sharePdu.size() <= 16383U);
    const bool longLength = sharePdu.size() >= 128U;
    const std::size_t headerBytes = longLength ? 15U : 14U;
    const std::size_t totalBytes = headerBytes + sharePdu.size();
    assert(totalBytes <= UINT16_MAX);

    std::vector<std::uint8_t> packet(totalBytes);
    packet[0] = 0x03U;
    packet[1] = 0x00U;
    packet[2] = static_cast<std::uint8_t>(totalBytes >> 8U);
    packet[3] = static_cast<std::uint8_t>(totalBytes);
    packet[4] = 0x02U;
    packet[5] = 0xf0U;
    packet[6] = 0x80U;
    packet[7] = 0x64U;
    const auto offset = clientUserId - 1001U;
    packet[8] = static_cast<std::uint8_t>(offset >> 8U);
    packet[9] = static_cast<std::uint8_t>(offset);
    packet[10] = static_cast<std::uint8_t>(ioChannelId >> 8U);
    packet[11] = static_cast<std::uint8_t>(ioChannelId);
    packet[12] = 0x70U;
    if (longLength)
    {
        packet[13] = static_cast<std::uint8_t>(
            0x80U | (sharePdu.size() >> 8U));
        packet[14] = static_cast<std::uint8_t>(sharePdu.size());
    }
    else
    {
        packet[13] = static_cast<std::uint8_t>(sharePdu.size());
    }
    std::copy(
        sharePdu.begin(), sharePdu.end(),
        packet.begin() + static_cast<std::ptrdiff_t>(headerBytes));
    return packet;
}

[[nodiscard]] std::array<std::uint8_t, 96>
makeShareAndInputCapabilities(std::uint16_t inputFlags)
{
    std::array<std::uint8_t, 96> capabilities{};
    capabilities[0U] = 0x09U;
    capabilities[2U] = 0x08U;
    capabilities[4U] = 0xeaU;
    capabilities[5U] = 0x03U;
    capabilities[8U] = 0x0dU;
    capabilities[10U] = 0x58U;
    capabilities[12U] = static_cast<std::uint8_t>(inputFlags);
    capabilities[13U] = static_cast<std::uint8_t>(inputFlags >> 8U);
    return capabilities;
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientConfirmActiveSharePdu(
    std::span<const std::uint8_t> capabilitySets,
    std::uint16_t capabilityCount)
{
    assert(capabilitySets.size() <= UINT16_MAX - 4U);
    const std::size_t totalBytes = 24U + capabilitySets.size();
    assert(totalBytes <= UINT16_MAX);
    std::vector<std::uint8_t> pdu(totalBytes, 0U);
    const auto write16 = [&pdu](std::size_t offset, std::uint16_t value)
    {
        pdu[offset] = static_cast<std::uint8_t>(value);
        pdu[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    };
    const auto write32 = [&write16](std::size_t offset, std::uint32_t value)
    {
        write16(offset, static_cast<std::uint16_t>(value));
        write16(offset + 2U, static_cast<std::uint16_t>(value >> 16U));
    };

    write16(0U, static_cast<std::uint16_t>(totalBytes));
    write16(2U, 0x0013U);
    write16(4U, 1007U);
    write32(6U, 0x000103eaU);
    write16(10U, 1002U);
    write16(12U, 4U);
    write16(14U, static_cast<std::uint16_t>(capabilitySets.size() + 4U));
    pdu[16U] = 'R';
    pdu[17U] = 'D';
    pdu[18U] = 'P';
    write16(20U, capabilityCount);
    std::copy(
        capabilitySets.begin(), capabilitySets.end(),
        pdu.begin() + 24);
    return pdu;
}

[[nodiscard]] std::vector<std::uint8_t>
makeActivationScancodeInputSharePdu()
{
    auto pdu = makeSlowPathInputSharePdu();
    pdu.resize(22U + kRdpSlowPathInputEventBytes);
    const auto size = static_cast<std::uint16_t>(pdu.size());
    pdu[0U] = static_cast<std::uint8_t>(size);
    pdu[1U] = static_cast<std::uint8_t>(size >> 8U);
    pdu[4U] = 0xefU;
    pdu[5U] = 0x03U;
    pdu[6U] = 0xeaU;
    pdu[7U] = 0x03U;
    pdu[8U] = 0x01U;
    pdu[9U] = 0x00U;
    pdu[12U] = static_cast<std::uint8_t>(size);
    pdu[13U] = static_cast<std::uint8_t>(size >> 8U);
    pdu[18U] = 1U;
    pdu[19U] = 0U;
    return pdu;
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

void testPersonalDesktopShareActivationOrdering()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t ioChannelId = 1003U;
    constexpr std::uint32_t shareId = 0x000103eaU;
    constexpr std::uint32_t sessionId = 0x11223344U;
    const auto source = std::span(kOfflineDemandActive).subspan(14U, 4U);
    const auto capabilities =
        std::span(kOfflineDemandActive).subspan(22U, 12U);

    RdpShareActivationLifecycle share;
    assert(share.begin(
        clientUserId, ioChannelId, shareId, sessionId,
        source, 2U, capabilities));
    auto write = share.pendingServerWrite();
    assert(write && write.kind == RdpShareServerWriteKind::DemandActive);
    assert(share.phase() ==
           RdpShareActivationPhase::DemandActivePending);
    assert(share.onServerBytesWritten(
               write.replySequence,
               write.writeSliceSequence,
               write.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);
    assert(share.phase() == RdpShareActivationPhase::AwaitConfirmActive);

    const auto confirm = makeClientShareTpkt(
        clientUserId, ioChannelId, kOfflineConfirmActive);
    assert(share.onClientTpkt(confirm) ==
           RdpShareActivationClientIntake::ConfirmActiveAccepted);
    write = share.pendingServerWrite();
    assert(write && write.kind == RdpShareServerWriteKind::Synchronize);

    constexpr std::array<std::uint8_t, 22> clientSync{{
        0x16,0x00,0x17,0x00,0xef,0x03,
        0xea,0x03,0x01,0x00,0x00,0x01,
        0x08,0x00,0x1f,0x00,0x00,0x00,
        0x01,0x00,0xea,0x03
    }};
    constexpr std::array<std::uint8_t, 26> clientCooperate{{
        0x1a,0x00,0x17,0x00,0xef,0x03,
        0xea,0x03,0x01,0x00,0x00,0x01,
        0x0c,0x00,0x14,0x00,0x00,0x00,
        0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }};
    auto clientRequest = clientCooperate;
    clientRequest[18] = 0x01U;
    constexpr std::array<std::uint8_t, 26> clientFontList{{
        0x1a,0x00,0x17,0x00,0xef,0x03,
        0xea,0x03,0x01,0x00,0x00,0x01,
        0x1a,0x00,0x27,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x03,0x00,0x32,0x00
    }};

    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, clientSync)) ==
           RdpShareActivationClientIntake::SynchronizeAccepted);
    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, clientCooperate)) ==
           RdpShareActivationClientIntake::CooperateAccepted);
    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, clientRequest)) ==
           RdpShareActivationClientIntake::RequestControlAccepted);
    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, clientFontList)) ==
           RdpShareActivationClientIntake::FontListAccepted);

    write = share.pendingServerWrite();
    assert(write && write.kind == RdpShareServerWriteKind::Synchronize);
    assert(share.onServerBytesWritten(
               write.replySequence, write.writeSliceSequence,
               write.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);

    write = share.pendingServerWrite();
    assert(write && write.kind == RdpShareServerWriteKind::Cooperate);
    assert(share.onServerBytesWritten(
               write.replySequence, write.writeSliceSequence,
               write.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);

    write = share.pendingServerWrite();
    assert(write && write.kind == RdpShareServerWriteKind::GrantedControl);
    assert(share.onServerBytesWritten(
               write.replySequence, write.writeSliceSequence,
               write.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);

    write = share.pendingServerWrite();
    assert(write && write.kind == RdpShareServerWriteKind::FontMap);
    assert(write.bytes.size() == 40U);
    const auto fontMap =
        parseRdpShareDataHeader(write.bytes.subspan(14U));
    assert(fontMap && fontMap.value.pduType2 == 0x28U);
    assert(fontMap.value.pduSource == 1002U);
    assert(fontMap.value.shareId == shareId);
    assert(share.onServerBytesWritten(
               write.replySequence, write.writeSliceSequence,
               write.bytes.size()) ==
           RdpShareActivationWriteOutcome::Activated);
    assert(share.activated());
    assert(!share.pendingServerWrite());
}

void testPersonalDesktopConfirmActiveCapabilityStore()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t ioChannelId = 1003U;
    constexpr std::uint32_t shareId = 0x000103eaU;
    constexpr std::array<std::uint8_t, 4> source{{'R', 'D', 'P', 0U}};
    const auto serverCapabilities = makeShareAndInputCapabilities(0x0015U);
    const auto clientCapabilities = makeShareAndInputCapabilities(0x0011U);

    RdpShareActivationLifecycle share;
    assert(share.begin(
        clientUserId, ioChannelId, shareId, 0U,
        source, 2U, serverCapabilities));
    auto pending = share.pendingServerWrite();
    assert(pending && pending.kind == RdpShareServerWriteKind::DemandActive);
    assert(share.onServerBytesWritten(
               pending.replySequence, pending.writeSliceSequence,
               pending.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);

    const auto confirmPdu =
        makeClientConfirmActiveSharePdu(clientCapabilities, 2U);
    auto confirmTpkt =
        makeClientShareTpkt(clientUserId, ioChannelId, confirmPdu);
    assert(share.onClientTpkt(confirmTpkt) ==
           RdpShareActivationClientIntake::ConfirmActiveAccepted);
    assert(share.confirmedClientCapabilityCount() == 2U);
    assert(share.negotiatedSlowPathInputFlags() == 0x0011U);
    const auto owned = share.confirmedClientCapabilitySets();
    assert(owned.size() == clientCapabilities.size());
    assert(std::equal(
        owned.begin(), owned.end(), clientCapabilities.begin()));

    std::fill(confirmTpkt.begin(), confirmTpkt.end(), 0xa5U);
    assert(std::equal(
        owned.begin(), owned.end(), clientCapabilities.begin()));

    const auto invalidClientCapabilities =
        makeShareAndInputCapabilities(0x0010U);
    RdpShareActivationLifecycle invalid;
    assert(invalid.begin(
        clientUserId, ioChannelId, shareId + 1U, 0U,
        source, 2U, serverCapabilities));
    pending = invalid.pendingServerWrite();
    assert(pending);
    assert(invalid.onServerBytesWritten(
               pending.replySequence, pending.writeSliceSequence,
               pending.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);
    auto invalidConfirm =
        makeClientConfirmActiveSharePdu(invalidClientCapabilities, 2U);
    invalidConfirm[6U] = 0xebU;
    assert(invalid.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, invalidConfirm)) ==
           RdpShareActivationClientIntake::Rejected);
    assert(invalid.phase() == RdpShareActivationPhase::Failed);
}

void testPersonalDesktopShareEarlyInputIgnored()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t ioChannelId = 1003U;
    constexpr std::uint32_t shareId = 0x000103eaU;
    constexpr std::array<std::uint8_t, 4> source{{'R', 'D', 'P', 0U}};
    const auto capabilities = makeShareAndInputCapabilities(0x0015U);

    RdpShareActivationLifecycle share;
    assert(share.begin(
        clientUserId, ioChannelId, shareId, 0U,
        source, 2U, capabilities));
    auto write = share.pendingServerWrite();
    assert(write);
    assert(share.onServerBytesWritten(
               write.replySequence, write.writeSliceSequence,
               write.bytes.size()) ==
           RdpShareActivationWriteOutcome::Delivered);

    const auto confirmPdu =
        makeClientConfirmActiveSharePdu(capabilities, 2U);
    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, confirmPdu)) ==
           RdpShareActivationClientIntake::ConfirmActiveAccepted);
    const auto serverSynchronize = share.pendingServerWrite();
    assert(serverSynchronize &&
           serverSynchronize.kind == RdpShareServerWriteKind::Synchronize);

    const auto earlyInput = makeActivationScancodeInputSharePdu();
    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, earlyInput)) ==
           RdpShareActivationClientIntake::InputIgnoredUntilActivated);
    const auto unchangedSynchronize = share.pendingServerWrite();
    assert(unchangedSynchronize.replySequence ==
           serverSynchronize.replySequence);
    assert(unchangedSynchronize.writeSliceSequence ==
           serverSynchronize.writeSliceSequence);
    assert(unchangedSynchronize.bytes.size() ==
           serverSynchronize.bytes.size());
    assert(std::equal(
        unchangedSynchronize.bytes.begin(), unchangedSynchronize.bytes.end(),
        serverSynchronize.bytes.begin()));

    constexpr std::array<std::uint8_t, 22> clientSync{{
        0x16,0x00,0x17,0x00,0xef,0x03,
        0xea,0x03,0x01,0x00,0x00,0x01,
        0x08,0x00,0x1f,0x00,0x00,0x00,
        0x01,0x00,0xea,0x03
    }};
    assert(share.onClientTpkt(makeClientShareTpkt(
               clientUserId, ioChannelId, clientSync)) ==
           RdpShareActivationClientIntake::SynchronizeAccepted);
    assert(share.phase() == RdpShareActivationPhase::Finalizing);
}

void testPersonalDesktopShareActivationDenials()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t ioChannelId = 1003U;
    constexpr std::uint32_t shareId = 0x000103eaU;
    const auto source = std::span(kOfflineDemandActive).subspan(14U, 4U);
    const auto capabilities =
        std::span(kOfflineDemandActive).subspan(22U, 12U);
    const auto confirm = makeClientShareTpkt(
        clientUserId, ioChannelId, kOfflineConfirmActive);

    {
        RdpShareActivationLifecycle share;
        assert(share.begin(
            clientUserId, ioChannelId, shareId, 1U,
            source, 2U, capabilities));
        assert(share.onClientTpkt(confirm) ==
               RdpShareActivationClientIntake::Rejected);
        assert(share.phase() == RdpShareActivationPhase::Failed);
    }

    {
        RdpShareActivationLifecycle share;
        assert(share.begin(
            clientUserId, ioChannelId, shareId, 1U,
            source, 2U, capabilities));
        auto write = share.pendingServerWrite();
        assert(share.onServerBytesWritten(
                   write.replySequence, write.writeSliceSequence,
                   write.bytes.size()) ==
               RdpShareActivationWriteOutcome::Delivered);
        assert(share.onClientTpkt(makeClientShareTpkt(
                   clientUserId,
                   static_cast<std::uint16_t>(ioChannelId + 1U),
                   kOfflineConfirmActive)) ==
               RdpShareActivationClientIntake::Rejected);
    }

    {
        RdpShareActivationLifecycle share;
        assert(share.begin(
            clientUserId, ioChannelId, shareId, 1U,
            source, 2U, capabilities));
        auto write = share.pendingServerWrite();
        assert(share.onServerBytesWritten(
                   write.replySequence, write.writeSliceSequence,
                   write.bytes.size()) ==
               RdpShareActivationWriteOutcome::Delivered);
        assert(share.onClientTpkt(confirm) ==
               RdpShareActivationClientIntake::ConfirmActiveAccepted);
        assert(share.onClientTpkt(confirm) ==
               RdpShareActivationClientIntake::Rejected);
        assert(share.phase() == RdpShareActivationPhase::Failed);
    }

    {
        RdpShareActivationLifecycle share;
        assert(share.begin(
            clientUserId, ioChannelId, shareId, 1U,
            source, 2U, capabilities));
        const auto first = share.pendingServerWrite();
        assert(first);
        assert(share.onServerBytesWritten(
                   first.replySequence, first.writeSliceSequence, 5U) ==
               RdpShareActivationWriteOutcome::Pending);
        const auto remaining = share.pendingServerWrite();
        assert(remaining);
        assert(remaining.writeSliceSequence != first.writeSliceSequence);
        share.close();
        assert(share.onServerBytesWritten(
                   remaining.replySequence,
                   remaining.writeSliceSequence,
                   remaining.bytes.size()) ==
               RdpShareActivationWriteOutcome::Rejected);
        assert(share.phase() == RdpShareActivationPhase::Failed);
    }
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientDynamicVirtualChannelTpkt(
    std::uint32_t clientUserId,
    std::uint16_t staticChannelId,
    std::span<const std::uint8_t> dvcPdu,
    std::uint32_t channelFlags = 0x00000003U)
{
    assert(!dvcPdu.empty() &&
           dvcPdu.size() <=
               kRdpStaticVirtualChannelDefaultChunkBytes);
    std::vector<std::uint8_t> staticPdu(8U + dvcPdu.size());
    const auto writeLe32 = [&staticPdu](
        std::size_t offset, std::uint32_t value)
    {
        staticPdu[offset] = static_cast<std::uint8_t>(value);
        staticPdu[offset + 1U] =
            static_cast<std::uint8_t>(value >> 8U);
        staticPdu[offset + 2U] =
            static_cast<std::uint8_t>(value >> 16U);
        staticPdu[offset + 3U] =
            static_cast<std::uint8_t>(value >> 24U);
    };
    writeLe32(0U, static_cast<std::uint32_t>(dvcPdu.size()));
    writeLe32(4U, channelFlags);
    std::copy(dvcPdu.begin(), dvcPdu.end(), staticPdu.begin() + 8U);
    return makeClientShareTpkt(
        clientUserId, staticChannelId, staticPdu);
}

[[nodiscard]] std::span<const std::uint8_t>
serverDynamicVirtualChannelControl(
    const RdpGraphicsDvcWriteView &write)
{
    // All control PDUs in this lifecycle fit the short PER determinant.
    assert(write && write.bytes.size() >= 23U);
    assert(write.bytes[0] == 0x03U);
    assert(write.bytes[4] == 0x02U);
    assert(write.bytes[5] == 0xf0U);
    assert(write.bytes[6] == 0x80U);
    assert(write.bytes[7] == 0x68U);
    assert(write.bytes[13] == write.bytes.size() - 14U);

    const auto staticPdu = write.bytes.subspan(14U);
    assert(staticPdu.size() >= 9U);
    const auto readLe32 = [](std::span<const std::uint8_t> bytes,
                             std::size_t offset)
    {
        return static_cast<std::uint32_t>(bytes[offset]) |
               (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
               (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
               (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    };
    assert(readLe32(staticPdu, 0U) == staticPdu.size() - 8U);
    assert(readLe32(staticPdu, 4U) == 0x00000003U);
    return staticPdu.subspan(8U);
}

[[nodiscard]] std::span<const std::uint8_t>
serverGraphicsDynamicVirtualChannelData(
    const RdpGraphicsDvcWriteView &write)
{
    const auto dvcPdu = serverDynamicVirtualChannelControl(write);
    assert(!dvcPdu.empty() && (dvcPdu[0] & 0xf0U) == 0x30U);
    const std::uint8_t cbId = static_cast<std::uint8_t>(dvcPdu[0] & 0x03U);
    assert(cbId != 3U);
    const std::size_t channelIdBytes =
        cbId == 0U ? 1U : (cbId == 1U ? 2U : 4U);
    assert(dvcPdu.size() > 1U + channelIdBytes);
    std::uint32_t channelId = 0U;
    for (std::size_t index = 0U; index < channelIdBytes; ++index)
        channelId |= static_cast<std::uint32_t>(
            dvcPdu[1U + index]) << (index * 8U);
    assert(channelId == write.dynamicChannelId);
    return dvcPdu.subspan(1U + channelIdBytes);
}

void completeGraphicsDynamicVirtualChannelCreate(
    RdpGraphicsDynamicVirtualChannelLifecycle &dvc,
    RdpDynamicVirtualChannelAllocation allocation,
    std::uint32_t clientUserId,
    std::uint16_t drdynvcChannelId)
{
    assert(allocation && allocation.channelId <= 0xffU);
    assert(dvc.begin(clientUserId, drdynvcChannelId, allocation, {64U, 64U}));

    auto write = dvc.pendingServerWrite();
    assert(write &&
           write.kind ==
               RdpGraphicsDvcWriteKind::CapabilitiesRequest);
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               write.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Delivered);

    constexpr std::array<std::uint8_t, 4> capsResponse{
        0x50U, 0x00U, 0x01U, 0x00U};
    assert(dvc.onClientTpkt(
               allocation.generation,
               makeClientDynamicVirtualChannelTpkt(
                   clientUserId, drdynvcChannelId,
                   capsResponse)) ==
           RdpGraphicsDvcClientIntake::CapabilitiesAccepted);

    write = dvc.pendingServerWrite();
    assert(write &&
           write.kind == RdpGraphicsDvcWriteKind::CreateRequest);
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               write.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Delivered);

    const std::array<std::uint8_t, 6> createResponse{
        0x10U,
        static_cast<std::uint8_t>(allocation.channelId),
        0x00U, 0x00U, 0x00U, 0x00U};
    assert(dvc.onClientTpkt(
               allocation.generation,
               makeClientDynamicVirtualChannelTpkt(
                   clientUserId, drdynvcChannelId,
                   createResponse)) ==
           RdpGraphicsDvcClientIntake::CreateAccepted);
    assert(dvc.created());
}


void completeGraphicsPresentationSurfaceInitialization(
    RdpGraphicsDynamicVirtualChannelLifecycle &dvc)
{
    auto write = dvc.pendingServerWrite();
    assert(write && write.kind ==
                        RdpGraphicsDvcWriteKind::GraphicsCreateSurface);
    constexpr std::array<std::uint8_t, 15> expectedCreate{
        0x09U,0x00U,0x00U,0x00U,0x0fU,0x00U,0x00U,0x00U,
        0x00U,0x00U,0x40U,0x00U,0x40U,0x00U,0x20U};
    const auto create = serverGraphicsDynamicVirtualChannelData(write);
    assert(create.size() == expectedCreate.size());
    assert(std::equal(create.begin(), create.end(), expectedCreate.begin()));
    assert(dvc.onServerBytesWritten(
               write.channelGeneration, write.replySequence,
               write.writeSliceSequence, write.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Pending);

    write = dvc.pendingServerWrite();
    assert(write && write.kind ==
                        RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput);
    constexpr std::array<std::uint8_t, 20> expectedMap{
        0x0fU,0x00U,0x00U,0x00U,0x14U,0x00U,0x00U,0x00U,
        0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x00U,0x00U,0x00U,0x00U};
    const auto map = serverGraphicsDynamicVirtualChannelData(write);
    assert(map.size() == expectedMap.size());
    assert(std::equal(map.begin(), map.end(), expectedMap.begin()));
    assert(dvc.onServerBytesWritten(
               write.channelGeneration, write.replySequence,
               write.writeSliceSequence, write.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.phase() == RdpGraphicsDvcPhase::Ready);
    assert(dvc.presentationMapped());
}

void completeGraphicsDynamicVirtualChannelReady(
    RdpGraphicsDynamicVirtualChannelLifecycle &dvc,
    RdpDynamicVirtualChannelAllocation allocation,
    std::uint32_t clientUserId,
    std::uint16_t drdynvcChannelId,
    bool enableAvc420 = false)
{
    completeGraphicsDynamicVirtualChannelCreate(
        dvc, allocation, clientUserId, drdynvcChannelId);

    std::array<std::uint8_t, 22> advertise{
        0x12U, 0x00U, 0x00U, 0x00U, 0x16U, 0x00U, 0x00U, 0x00U,
        0x01U, 0x00U,
        0x04U, 0x00U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U};
    if (enableAvc420)
    {
        advertise[10U] = 0x05U; // VERSION81 (0x00080105)
        advertise[11U] = 0x01U;
        advertise[18U] = 0x10U; // AVC420_ENABLED
    }
    std::vector<std::uint8_t> data{
        0x30U, static_cast<std::uint8_t>(allocation.channelId)};
    data.insert(data.end(), advertise.begin(), advertise.end());
    assert(dvc.onClientTpkt(
               allocation.generation,
               makeClientDynamicVirtualChannelTpkt(
                   clientUserId, drdynvcChannelId, data)) ==
           RdpGraphicsDvcClientIntake::GraphicsCapabilitiesAccepted);

    auto write = dvc.pendingServerWrite();
    assert(write &&
           write.kind ==
               RdpGraphicsDvcWriteKind::GraphicsCapabilitiesConfirm);
    std::array<std::uint8_t, 20> expectedConfirm{
        0x13U,0x00U,0x00U,0x00U,0x14U,0x00U,0x00U,0x00U,
        0x04U,0x00U,0x08U,0x00U,0x04U,0x00U,0x00U,0x00U,
        0x00U,0x00U,0x00U,0x00U};
    if (enableAvc420)
    {
        expectedConfirm[8U] = 0x05U;
        expectedConfirm[9U] = 0x01U;
        expectedConfirm[16U] = 0x10U;
    }
    const auto confirm = serverGraphicsDynamicVirtualChannelData(write);
    assert(confirm.size() == expectedConfirm.size());
    assert(std::equal(confirm.begin(), confirm.end(), expectedConfirm.begin()));
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               write.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Pending);
    assert(dvc.graphicsCapabilitiesConfirmed());
    assert(dvc.graphicsClearCodecEnabled());
    assert(dvc.graphicsAvc420Enabled() == enableAvc420);

    completeGraphicsPresentationSurfaceInitialization(dvc);
}

void prepareTestClearCodecFrame(
    RdpGraphicsDynamicVirtualChannelLifecycle &dvc,
    std::uint32_t frameId,
    rdp_server::rdp::GfxAvc420SegmentedFrame &frame)
{
    constexpr PixelSize geometry{64U, 64U};
    std::vector<std::byte> pixels(
        static_cast<std::size_t>(geometry.widthPixels) *
        geometry.heightPixels * 4U);
    for (std::size_t index = 0U; index < pixels.size(); ++index)
        pixels[index] = static_cast<std::byte>(
            (index * 17U + 3U) & 0xffU);

    const FramebufferView framebuffer{
        std::span<const std::byte>{pixels},
        geometry.widthPixels,
        geometry.heightPixels,
        static_cast<std::size_t>(geometry.widthPixels) * 4U};
    assert(dvc.prepareClearCodecFrame(frameId, framebuffer, frame));
    assert(frame.wireBytes().size() >
           kMaximumRdpDynamicVirtualChannelDataPayloadBytes);
}


[[nodiscard]] std::array<std::uint8_t, 20>
makeR3FrameAcknowledge(
    std::uint32_t frameId, std::uint32_t queueDepth,
    std::uint32_t totalDecoded) noexcept
{
    // MS-RDPEGFX 2.2.2.13 exact FRAME_ACKNOWLEDGE, no second parser.
    std::array<std::uint8_t, 20> result{
        0x0dU,0x00U,0x00U,0x00U,0x14U,0x00U,0x00U,0x00U};
    const auto write = [&result](std::size_t offset, std::uint32_t value)
    {
        for (std::size_t byteIndex = 0U; byteIndex < 4U; ++byteIndex)
            result[offset + byteIndex] = static_cast<std::uint8_t>(
                value >> (byteIndex * 8U));
    };
    write(8U, queueDepth);
    write(12U, frameId);
    write(16U, totalDecoded);
    return result;
}

[[nodiscard]] std::vector<std::uint8_t>
makeR3GraphicsFrameAcknowledgeTpkt(
    std::uint32_t channelId,
    std::uint32_t frameId,
    std::uint32_t queueDepth,
    std::uint32_t totalDecoded)
{
    assert(channelId != 0U && channelId <= 0xffU);
    std::vector<std::uint8_t> dvcPdu{
        0x30U, static_cast<std::uint8_t>(channelId)};
    const auto ack = makeR3FrameAcknowledge(
        frameId, queueDepth, totalDecoded);
    dvcPdu.insert(dvcPdu.end(), ack.begin(), ack.end());
    return makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, dvcPdu);
}

void testGraphicsFrameAcknowledgeHandoffWire()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{9U, 201U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(dvc, 712U, frame);
    assert(dvc.beginFramePublication(
        std::move(frame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    RdpGraphicsDvcWriteOutcome completion =
        RdpGraphicsDvcWriteOutcome::Pending;
    for (std::size_t count = 0U; count < 256U &&
         completion == RdpGraphicsDvcWriteOutcome::Pending; ++count)
    {
        const auto write = dvc.pendingServerWrite();
        assert(write &&
               write.kind == RdpGraphicsDvcWriteKind::GraphicsFrameData);
        completion = dvc.onServerBytesWritten(
            write.channelGeneration, write.replySequence,
            write.writeSliceSequence, write.bytes.size());
    }
    assert(completion == RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.outstandingGraphicsFrames() == 1U);
    assert(dvc.onClientTpkt(
        allocation.generation,
        makeR3GraphicsFrameAcknowledgeTpkt(
            allocation.channelId, 712U, 4096U, 7U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.pendingClientGraphicsData().size() ==
           rdp_server::rdp::kGfxFrameAcknowledgePduBytes);
    assert(dvc.outstandingGraphicsFrames() == 1U);
    assert(dvc.consumePendingClientFrameAcknowledge(
        allocation.generation) ==
        RdpGraphicsFrameAcknowledgeIntake::Acknowledged);
    assert(dvc.outstandingGraphicsFrames() == 0U);
    assert(dvc.pendingClientGraphicsData().empty());
    assert(dvc.phase() == RdpGraphicsDvcPhase::Ready);
    // Replayed completion without fresh DATA cannot consume another ACK.
}

void testGraphicsFrameAcknowledgeHandoffMalformed()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{9U, 202U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);
    auto malformed = makeR3GraphicsFrameAcknowledgeTpkt(
        allocation.channelId, 712U, 0U, 1U);
    // DVC carries an exact ACK-sized payload, but R4's PDU signature is bad.
    malformed[24U] = 0xffU;
    assert(dvc.onClientTpkt(
        allocation.generation, malformed) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.consumePendingClientFrameAcknowledge(
        allocation.generation) ==
        RdpGraphicsFrameAcknowledgeIntake::Rejected);
    assert(dvc.pendingClientGraphicsData().empty());
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
}

void testGraphicsFrameAcknowledgeHandoffStale()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{9U, 203U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);
    assert(dvc.onClientTpkt(
        allocation.generation,
        makeR3GraphicsFrameAcknowledgeTpkt(
            allocation.channelId, 712U, 0U, 1U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.consumePendingClientFrameAcknowledge(
        allocation.generation - 1U) ==
        RdpGraphicsFrameAcknowledgeIntake::Rejected);
    assert(dvc.pendingClientGraphicsData().empty());
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
}


void testGraphicsFrameCreditPreflight()
{
    using Readiness = RdpGraphicsFramePublicationReadiness;
    constexpr RdpDynamicVirtualChannelAllocation allocation{10U, 204U};
    constexpr std::uint32_t firstFrameId = 1000U;

    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);
    assert(dvc.preflightFramePublication(firstFrameId) ==
           Readiness::Ready);

    const auto deliverFrame = [&dvc](std::uint32_t frameId)
    {
        rdp_server::rdp::GfxAvc420SegmentedFrame frame;
        prepareTestClearCodecFrame(dvc, frameId, frame);
        assert(dvc.beginFramePublication(
            std::move(frame), RdpGraphicsFrameCodec::ClearCodec,
            kRdpStaticVirtualChannelDefaultChunkBytes));

        RdpGraphicsDvcWriteOutcome completion =
            RdpGraphicsDvcWriteOutcome::Pending;
        for (std::size_t count = 0U;
             count < 256U &&
             completion == RdpGraphicsDvcWriteOutcome::Pending;
             ++count)
        {
            const auto write = dvc.pendingServerWrite();
            assert(write &&
                   write.kind ==
                       RdpGraphicsDvcWriteKind::GraphicsFrameData);
            completion = dvc.onServerBytesWritten(
                write.channelGeneration, write.replySequence,
                write.writeSliceSequence, write.bytes.size());
        }
        assert(completion == RdpGraphicsDvcWriteOutcome::Delivered);
    };

    for (std::size_t index = 0U;
         index < rdp_server::rdp::GfxFrameAckWindow::kMaximumPendingFrames;
         ++index)
    {
        deliverFrame(
            firstFrameId + static_cast<std::uint32_t>(index));
    }

    assert(dvc.outstandingGraphicsFrames() ==
           rdp_server::rdp::GfxFrameAckWindow::kMaximumPendingFrames);
    assert(!dvc.pendingServerWrite());
    assert(dvc.frameRecordMap().empty());

    constexpr std::uint32_t deferredFrameId = 2000U;
    assert(dvc.preflightFramePublication(deferredFrameId) ==
           Readiness::DeferredForFrameAcknowledge);
    assert(dvc.outstandingGraphicsFrames() ==
           rdp_server::rdp::GfxFrameAckWindow::kMaximumPendingFrames);
    assert(!dvc.pendingServerWrite());
    assert(dvc.frameRecordMap().empty());
    assert(dvc.phase() == RdpGraphicsDvcPhase::Ready);
    assert(dvc.presentationMapped());

    // A duplicate at all 64 R4 ACK slots is terminally rejected, not deferred.
    assert(dvc.preflightFramePublication(firstFrameId + 1U) ==
           Readiness::Rejected);
    assert(dvc.outstandingGraphicsFrames() ==
           rdp_server::rdp::GfxFrameAckWindow::kMaximumPendingFrames);
    assert(!dvc.pendingServerWrite());

    assert(dvc.onClientTpkt(
        allocation.generation,
        makeR3GraphicsFrameAcknowledgeTpkt(
            allocation.channelId, firstFrameId, 4096U, 1U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.consumePendingClientFrameAcknowledge(
        allocation.generation) ==
        RdpGraphicsFrameAcknowledgeIntake::Acknowledged);
    assert(dvc.outstandingGraphicsFrames() + 1U ==
           rdp_server::rdp::GfxFrameAckWindow::kMaximumPendingFrames);
    assert(dvc.preflightFramePublication(deferredFrameId) ==
           Readiness::Ready);

    assert(dvc.preflightFramePublication(firstFrameId + 1U) ==
           Readiness::Rejected);
    assert(dvc.phase() == RdpGraphicsDvcPhase::Ready);
    assert(dvc.presentationMapped());

    dvc.close();
    assert(dvc.preflightFramePublication(deferredFrameId + 1U) ==
           Readiness::Rejected);
}

void testGraphicsSurfaceRemap()
{
    using Decision = RdpGraphicsSurfaceReconfiguration;
    using Kind = RdpGraphicsDvcWriteKind;
    constexpr PixelSize resized{32U, 16U};
    constexpr RdpDynamicVirtualChannelAllocation allocation{9U, 205U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);
    assert(dvc.beginSurfaceReconfiguration(
        204U, resized) == Decision::Rejected);
    assert(dvc.beginSurfaceReconfiguration(
        205U, PixelSize{0U, 16U}) == Decision::Rejected);
    assert(dvc.beginSurfaceReconfiguration(
        205U, PixelSize{64U, 64U}) == Decision::Unchanged);

    // A complete old frame must retire through R4's existing ACK owner.
    rdp_server::rdp::GfxAvc420SegmentedFrame oldFrame;
    prepareTestClearCodecFrame(dvc, 100U, oldFrame);
    assert(dvc.beginFramePublication(
        std::move(oldFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    RdpGraphicsDvcWriteOutcome outcome = RdpGraphicsDvcWriteOutcome::Pending;
    for (std::size_t attempts = 0U;
         attempts < 256U && outcome == RdpGraphicsDvcWriteOutcome::Pending;
         ++attempts)
    {
        const auto write = dvc.pendingServerWrite();
        assert(write);
        outcome = dvc.onServerBytesWritten(
            write.channelGeneration, write.replySequence,
            write.writeSliceSequence, write.bytes.size());
    }
    assert(outcome == RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Deferred);
    assert(dvc.onClientTpkt(
        205U, makeR3GraphicsFrameAcknowledgeTpkt(
            9U, 100U, 4096U, 1U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Deferred); // Client Graphics DATA still pending.
    assert(dvc.consumePendingClientFrameAcknowledge(205U) ==
           RdpGraphicsFrameAcknowledgeIntake::Acknowledged);

    // A delayed duplicate ACK for the still-mapped original surface is
    // nonterminal Unmatched until that surface has actually been retired.
    assert(dvc.onClientTpkt(
        205U, makeR3GraphicsFrameAcknowledgeTpkt(
            9U, 100U, 4096U, 2U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.consumePendingClientFrameAcknowledge(205U) ==
           RdpGraphicsFrameAcknowledgeIntake::Unmatched);
    assert(dvc.presentationMapped());
    assert(dvc.outstandingGraphicsFrames() == 0U);

    // A prepared frame with zero accepted outer bytes can be cancelled.
    rdp_server::rdp::GfxAvc420SegmentedFrame unwritten;
    prepareTestClearCodecFrame(dvc, 101U, unwritten);
    assert(dvc.beginFramePublication(
        std::move(unwritten), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Deferred);
    assert(dvc.cancelUnwrittenFramePublication(205U));
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Started);
    auto write = dvc.pendingServerWrite();
    assert(write && write.kind == Kind::GraphicsDeleteSurface);
    constexpr std::array<std::uint8_t, 10> expectedDelete{
        0x0aU,0x00U,0x00U,0x00U,0x0aU,0x00U,0x00U,0x00U,
        0x00U,0x00U};
    auto payload = serverGraphicsDynamicVirtualChannelData(write);
    assert(std::equal(
        payload.begin(), payload.end(),
        expectedDelete.begin(), expectedDelete.end()));

    // R1's positive partial TLS receipt keeps the identical command/suffix.
    const std::vector<std::uint8_t> offered(
        write.bytes.begin(), write.bytes.end());
    assert(dvc.onServerBytesWritten(
        write.channelGeneration, write.replySequence,
        write.writeSliceSequence, 1U) ==
        RdpGraphicsDvcWriteOutcome::Pending);
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Deferred);
    write = dvc.pendingServerWrite();
    assert(write && write.bytes.size() + 1U == offered.size());
    assert(std::equal(
        write.bytes.begin(), write.bytes.end(),
        offered.begin() + 1U, offered.end()));
    assert(dvc.onServerBytesWritten(
        write.channelGeneration, write.replySequence,
        write.writeSliceSequence, write.bytes.size()) ==
        RdpGraphicsDvcWriteOutcome::Pending);

    write = dvc.pendingServerWrite();
    assert(write && write.kind == Kind::GraphicsCreateSurface);
    constexpr std::array<std::uint8_t, 15> expectedCreate{
        0x09U,0x00U,0x00U,0x00U,0x0fU,0x00U,0x00U,0x00U,
        0x01U,0x00U,0x20U,0x00U,0x10U,0x00U,0x20U};
    payload = serverGraphicsDynamicVirtualChannelData(write);
    assert(std::equal(
        payload.begin(), payload.end(),
        expectedCreate.begin(), expectedCreate.end()));
    assert(dvc.onServerBytesWritten(
        write.channelGeneration, write.replySequence,
        write.writeSliceSequence, write.bytes.size()) ==
        RdpGraphicsDvcWriteOutcome::Pending);

    write = dvc.pendingServerWrite();
    assert(write && write.kind == Kind::GraphicsMapSurfaceToOutput);
    constexpr std::array<std::uint8_t, 20> expectedMap{
        0x0fU,0x00U,0x00U,0x00U,0x14U,0x00U,0x00U,0x00U,
        0x01U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x00U,0x00U,0x00U,0x00U};
    payload = serverGraphicsDynamicVirtualChannelData(write);
    assert(std::equal(
        payload.begin(), payload.end(),
        expectedMap.begin(), expectedMap.end()));
    assert(dvc.onServerBytesWritten(
        write.channelGeneration, write.replySequence,
        write.writeSliceSequence, write.bytes.size()) ==
        RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.presentationMapped());
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Unchanged);
    assert(dvc.preflightFramePublication(100U) ==
           RdpGraphicsFramePublicationReadiness::Rejected);

    std::array<std::byte, 64U * 64U * 4U> oldPixels{};
    const FramebufferView wrongGeometry{oldPixels, 64U, 64U, 64U * 4U};
    rdp_server::rdp::GfxAvc420SegmentedFrame rejectedFrame;
    assert(!dvc.prepareClearCodecFrame(
        101U, wrongGeometry, rejectedFrame));
    assert(!dvc.pendingServerWrite());

    std::array<std::byte, 32U * 16U * 4U> newPixels{};
    const FramebufferView currentGeometry{newPixels, 32U, 16U, 32U * 4U};
    rdp_server::rdp::GfxAvc420SegmentedFrame currentFrame;
    assert(dvc.prepareClearCodecFrame(
        101U, currentGeometry, currentFrame));
    assert(dvc.beginFramePublication(
        std::move(currentFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    // Prove first post-remap ClearCodec completes and its current ACK works.
    auto currentOutcome = RdpGraphicsDvcWriteOutcome::Pending;
    for (std::size_t attempt = 0U;
         attempt < 256U &&
             currentOutcome == RdpGraphicsDvcWriteOutcome::Pending;
         ++attempt)
    {
        const auto frameWrite = dvc.pendingServerWrite();
        assert(frameWrite && frameWrite.kind == Kind::GraphicsFrameData);
        currentOutcome = dvc.onServerBytesWritten(
            frameWrite.channelGeneration, frameWrite.replySequence,
            frameWrite.writeSliceSequence, frameWrite.bytes.size());
    }
    assert(currentOutcome == RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.outstandingGraphicsFrames() == 1U);
    assert(dvc.onClientTpkt(
        205U, makeR3GraphicsFrameAcknowledgeTpkt(
            9U, 101U, 4096U, 3U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.consumePendingClientFrameAcknowledge(205U) ==
           RdpGraphicsFrameAcknowledgeIntake::Acknowledged);
    assert(dvc.preflightFramePublication(102U) ==
           RdpGraphicsFramePublicationReadiness::Ready);
    // Stale ACKs can no longer acknowledge a newly published frame ID.
    assert(dvc.onClientTpkt(
        205U, makeR3GraphicsFrameAcknowledgeTpkt(
            9U, 100U, rdp_server::rdp::kGfxSuspendFrameAcknowledgement, 2U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(dvc.consumePendingClientFrameAcknowledge(205U) ==
           RdpGraphicsFrameAcknowledgeIntake::Rejected);
    assert(!dvc.presentationMapped());
    assert(dvc.preflightFramePublication(101U) ==
           RdpGraphicsFramePublicationReadiness::Rejected);

    dvc.close();
    assert(dvc.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Rejected);

    // R4 ACK suspension clears authoritative pending membership. With no
    // pending delivery/partial TLS or client DATA, resize must not await
    // an ACK that the client is no longer obligated to send.
    RdpGraphicsDynamicVirtualChannelLifecycle suspended;
    completeGraphicsDynamicVirtualChannelReady(
        suspended, RdpDynamicVirtualChannelAllocation{12U, 208U},
        1007U, 1005U);
    // A genuine complete frame is outstanding before R4 suspension.
    rdp_server::rdp::GfxAvc420SegmentedFrame suspendedFrame;
    prepareTestClearCodecFrame(suspended, 20U, suspendedFrame);
    assert(suspended.beginFramePublication(
        std::move(suspendedFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    auto suspendedOutcome = RdpGraphicsDvcWriteOutcome::Pending;
    for (std::size_t attempt = 0U;
         attempt < 256U &&
             suspendedOutcome == RdpGraphicsDvcWriteOutcome::Pending;
         ++attempt)
    {
        const auto frameWrite = suspended.pendingServerWrite();
        assert(frameWrite);
        suspendedOutcome = suspended.onServerBytesWritten(
            frameWrite.channelGeneration, frameWrite.replySequence,
            frameWrite.writeSliceSequence, frameWrite.bytes.size());
    }
    assert(suspendedOutcome == RdpGraphicsDvcWriteOutcome::Delivered);
    assert(suspended.outstandingGraphicsFrames() == 1U);
    assert(suspended.beginSurfaceReconfiguration(208U, resized) ==
           Decision::Deferred);
    // Only R4 may clear outstanding membership on the real suspension.
    assert(suspended.onClientTpkt(
        208U, makeR3GraphicsFrameAcknowledgeTpkt(
            12U, 0U, rdp_server::rdp::kGfxSuspendFrameAcknowledgement, 1U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(suspended.consumePendingClientFrameAcknowledge(208U) ==
           RdpGraphicsFrameAcknowledgeIntake::Suspended);
    assert(suspended.outstandingGraphicsFrames() == 0U);
    assert(suspended.beginSurfaceReconfiguration(208U, resized) ==
           Decision::Started);
    auto suspendedWrite = suspended.pendingServerWrite();
    assert(suspendedWrite &&
           suspendedWrite.kind == Kind::GraphicsDeleteSurface);
    suspended.close();

    // Bounded draining: no genuine ACK for an old surface means 63 safe
    // deferrals, then a terminal reconnect rather than invented receipts.
    RdpGraphicsDynamicVirtualChannelLifecycle stalled;
    completeGraphicsDynamicVirtualChannelReady(
        stalled, RdpDynamicVirtualChannelAllocation{14U, 210U},
        1007U, 1005U);
    rdp_server::rdp::GfxAvc420SegmentedFrame stalledFrame;
    prepareTestClearCodecFrame(stalled, 11U, stalledFrame);
    assert(stalled.beginFramePublication(
        std::move(stalledFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    auto stalledOutcome = RdpGraphicsDvcWriteOutcome::Pending;
    for (std::size_t attempt = 0U;
         attempt < 256U &&
             stalledOutcome == RdpGraphicsDvcWriteOutcome::Pending;
         ++attempt)
    {
        const auto frameWrite = stalled.pendingServerWrite();
        assert(frameWrite);
        stalledOutcome = stalled.onServerBytesWritten(
            frameWrite.channelGeneration, frameWrite.replySequence,
            frameWrite.writeSliceSequence, frameWrite.bytes.size());
    }
    assert(stalledOutcome == RdpGraphicsDvcWriteOutcome::Delivered);
    assert(stalled.outstandingGraphicsFrames() == 1U);
    for (std::size_t attempt = 0U; attempt < 63U; ++attempt)
    {
        assert(stalled.beginSurfaceReconfiguration(210U, resized) ==
               Decision::Deferred);
        assert(stalled.presentationMapped());
        assert(!stalled.pendingServerWrite());
    }
    assert(stalled.beginSurfaceReconfiguration(210U, resized) ==
           Decision::Rejected);
    assert(!stalled.presentationMapped());
    assert(!stalled.pendingServerWrite());
    RdpGraphicsDynamicVirtualChannelLifecycle replacement;
    completeGraphicsDynamicVirtualChannelReady(
        replacement, RdpDynamicVirtualChannelAllocation{15U, 211U},
        1007U, 1005U);
    assert(replacement.beginSurfaceReconfiguration(210U, resized) ==
           Decision::Rejected);
    assert(replacement.beginSurfaceReconfiguration(211U, resized) ==
           Decision::Started);
    replacement.close();

    // A normal retired ACK is also terminal (not only a SUSPEND ACK).
    RdpGraphicsDynamicVirtualChannelLifecycle normalStale;
    completeGraphicsDynamicVirtualChannelReady(
        normalStale, RdpDynamicVirtualChannelAllocation{16U, 212U},
        1007U, 1005U);
    rdp_server::rdp::GfxAvc420SegmentedFrame normalFrame;
    prepareTestClearCodecFrame(normalStale, 12U, normalFrame);
    assert(normalStale.beginFramePublication(
        std::move(normalFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    auto normalOutcome = RdpGraphicsDvcWriteOutcome::Pending;
    for (std::size_t attempt = 0U;
         attempt < 256U &&
             normalOutcome == RdpGraphicsDvcWriteOutcome::Pending;
         ++attempt)
    {
        const auto frameWrite = normalStale.pendingServerWrite();
        assert(frameWrite);
        normalOutcome = normalStale.onServerBytesWritten(
            frameWrite.channelGeneration, frameWrite.replySequence,
            frameWrite.writeSliceSequence, frameWrite.bytes.size());
    }
    assert(normalOutcome == RdpGraphicsDvcWriteOutcome::Delivered);
    assert(normalStale.onClientTpkt(
        212U, makeR3GraphicsFrameAcknowledgeTpkt(
            16U, 12U, 4096U, 1U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(normalStale.consumePendingClientFrameAcknowledge(212U) ==
           RdpGraphicsFrameAcknowledgeIntake::Acknowledged);
    assert(normalStale.beginSurfaceReconfiguration(212U, resized) ==
           Decision::Started);
    for (std::size_t command = 0U; command < 3U; ++command)
    {
        const auto write = normalStale.pendingServerWrite();
        assert(write);
        const auto completion = normalStale.onServerBytesWritten(
            write.channelGeneration, write.replySequence,
            write.writeSliceSequence, write.bytes.size());
        assert(completion ==
               (command == 2U ? RdpGraphicsDvcWriteOutcome::Delivered
                              : RdpGraphicsDvcWriteOutcome::Pending));
    }
    assert(normalStale.presentationMapped());
    assert(normalStale.onClientTpkt(
        212U, makeR3GraphicsFrameAcknowledgeTpkt(
            16U, 12U, 4096U, 2U)) ==
        RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(normalStale.consumePendingClientFrameAcknowledge(212U) ==
           RdpGraphicsFrameAcknowledgeIntake::Rejected);
    assert(!normalStale.presentationMapped());

    // Even with negotiated AVC420 the remapped surface must not reuse
    // R4's old x264 P-reference chain. ClearCodec remains publishable.
    // R4 must prove explicit producer rebind + first IDR before AVC resumes.
    RdpGraphicsDynamicVirtualChannelLifecycle avcRemap;
    completeGraphicsDynamicVirtualChannelReady(
        avcRemap, RdpDynamicVirtualChannelAllocation{17U, 213U},
        1007U, 1005U, true);
    assert(avcRemap.graphicsAvc420Enabled());
    assert(avcRemap.beginSurfaceReconfiguration(213U, resized) ==
           Decision::Started);
    for (std::size_t command = 0U; command < 3U; ++command)
    {
        const auto pendingCommand = avcRemap.pendingServerWrite();
        assert(pendingCommand);
        const auto completion = avcRemap.onServerBytesWritten(
            pendingCommand.channelGeneration, pendingCommand.replySequence,
            pendingCommand.writeSliceSequence, pendingCommand.bytes.size());
        assert(completion ==
               (command == 2U ? RdpGraphicsDvcWriteOutcome::Delivered
                              : RdpGraphicsDvcWriteOutcome::Pending));
    }
    assert(avcRemap.presentationMapped());
    std::array<std::byte, 32U * 16U * 4U> avcFallbackPixels{};
    const FramebufferView avcFallbackGeometry{
        avcFallbackPixels, 32U, 16U, 32U * 4U};
    rdp_server::rdp::GfxAvc420SegmentedFrame avcFallbackFrame;
    assert(avcRemap.prepareClearCodecFrame(
        1U, avcFallbackGeometry, avcFallbackFrame));
    assert(!avcRemap.beginFramePublication(
        std::move(avcFallbackFrame), RdpGraphicsFrameCodec::Avc420,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    assert(avcFallbackFrame.valid());
    assert(!avcRemap.pendingServerWrite());
    assert(avcRemap.beginFramePublication(
        std::move(avcFallbackFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    assert(avcRemap.cancelUnwrittenFramePublication(213U));
    avcRemap.close();

    // An accepted frame byte cannot be erased by a zero-write cancel.
    RdpGraphicsDynamicVirtualChannelLifecycle partial;
    completeGraphicsDynamicVirtualChannelReady(
        partial, RdpDynamicVirtualChannelAllocation{10U, 206U},
        1007U, 1005U);
    rdp_server::rdp::GfxAvc420SegmentedFrame partialFrame;
    prepareTestClearCodecFrame(partial, 1U, partialFrame);
    assert(partial.beginFramePublication(
        std::move(partialFrame), RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    const auto partialWrite = partial.pendingServerWrite();
    assert(partialWrite);
    assert(partial.onServerBytesWritten(
        partialWrite.channelGeneration, partialWrite.replySequence,
        partialWrite.writeSliceSequence, 1U) ==
        RdpGraphicsDvcWriteOutcome::Pending);
    assert(!partial.cancelUnwrittenFramePublication(206U));
    assert(partial.beginSurfaceReconfiguration(206U, resized) ==
           Decision::Deferred);
    assert(partial.abortFramePublication(206U));
    assert(partial.beginSurfaceReconfiguration(206U, resized) ==
           Decision::Rejected);

    RdpGraphicsDynamicVirtualChannelLifecycle reconnected;
    completeGraphicsDynamicVirtualChannelReady(
        reconnected, RdpDynamicVirtualChannelAllocation{11U, 207U},
        1007U, 1005U);
    assert(reconnected.beginSurfaceReconfiguration(205U, resized) ==
           Decision::Rejected);
    assert(!reconnected.pendingServerWrite());
}


void testFirstClientAcceptanceObservability()
{
    using Kind = RdpFirstClientAcceptanceEventKind;
    using WriteKind = RdpGraphicsDvcWriteKind;
    using WriteOutcome = RdpGraphicsDvcWriteOutcome;

    McsSessionLifecycle mcsSession;
    assert(McsSessionLifecycleTestAccess::
        stageMcsEstablishedForObservability(mcsSession));
    {
        const auto observed =
            mcsSession.firstClientAcceptanceObservability();
        assert(observed.mcsEstablished);
        assert(observed.eventCount == 1U);
        assert(observed.events[0].kind == Kind::McsEstablished);
        assert(observed.events[0].sequence == 1U);
    }

    McsSessionLifecycle session;
    McsSessionLifecycle reconnect;
    const auto empty = session.firstClientAcceptanceObservability();
    const auto reconnectEmpty =
        reconnect.firstClientAcceptanceObservability();
    assert(empty.reconnectGeneration != 0U);
    assert(reconnectEmpty.reconnectGeneration != 0U);
    assert(empty.reconnectGeneration != reconnectEmpty.reconnectGeneration);
    assert(empty.eventView().empty());
    assert(empty.latestEventSequence == 0U);
    assert(empty.droppedEventCount == 0U);
    assert(!empty.firstClearCodecFramePrepared);
    assert(!empty.firstExactFrameWriteCommitted);
    assert(empty.outstandingFrameAcknowledgements == 0U);
    assert(!empty.firstGenuineFrameAcknowledge);

    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(session));
    McsSessionLifecycleTestAccess::stageFirstClientAcceptanceFoundations(
        session);
    McsSessionLifecycleTestAccess::stageFirstClientAcceptanceFoundations(
        session);

    constexpr std::array<std::uint8_t, 4> dvcCapabilities{
        0x50U, 0x00U, 0x03U, 0x00U};
    assert(McsSessionLifecycleTestAccess::acceptGraphics(
               session,
               makeClientDynamicVirtualChannelTpkt(
                   1007U, 1005U, dvcCapabilities)) ==
           RdpGraphicsDvcClientIntake::CapabilitiesAccepted);

    auto write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write && write->kind == WriteKind::CreateRequest);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Delivered);

    constexpr std::array<std::uint8_t, 6> createResponse{
        0x10U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U};
    assert(McsSessionLifecycleTestAccess::acceptGraphics(
               session,
               makeClientDynamicVirtualChannelTpkt(
                   1007U, 1005U, createResponse)) ==
           RdpGraphicsDvcClientIntake::CreateAccepted);

    constexpr std::array<std::uint8_t, 22> gfxCapabilities{
        0x12U,0x00U,0x00U,0x00U,0x16U,0x00U,0x00U,0x00U,
        0x01U,0x00U,
        0x04U,0x00U,0x08U,0x00U,0x04U,0x00U,0x00U,0x00U,
        0x00U,0x00U,0x00U,0x00U};
    std::vector<std::uint8_t> gfxData{0x30U, 0x09U};
    gfxData.insert(
        gfxData.end(), gfxCapabilities.begin(), gfxCapabilities.end());
    assert(McsSessionLifecycleTestAccess::acceptGraphics(
               session,
               makeClientDynamicVirtualChannelTpkt(
                   1007U, 1005U, gfxData)) ==
           RdpGraphicsDvcClientIntake::GraphicsCapabilitiesAccepted);
    assert(!session.firstClientAcceptanceObservability().graphicsControlReady);

    write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write &&
           write->kind == WriteKind::GraphicsCapabilitiesConfirm);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Pending);
    assert(session.firstClientAcceptanceObservability().graphicsControlReady);
    write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write && write->kind == WriteKind::GraphicsCreateSurface);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Pending);
    write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write && write->kind == WriteKind::GraphicsMapSurfaceToOutput);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Delivered);

    constexpr PixelSize geometry{64U, 64U};
    constexpr std::size_t bytesPerPixel = 4U;
    const std::size_t pixelBytes =
        static_cast<std::size_t>(geometry.widthPixels) *
        geometry.heightPixels * bytesPerPixel;
    auto pixels = std::make_unique_for_overwrite<std::byte[]>(pixelBytes);
    for (std::size_t index = 0U; index < pixelBytes; ++index)
        pixels[index] =
            static_cast<std::byte>((index * 17U + 3U) & 0xffU);
    const FramebufferView framebuffer{
        std::span<const std::byte>{pixels.get(), pixelBytes},
        geometry.widthPixels,
        geometry.heightPixels,
        static_cast<std::size_t>(geometry.widthPixels) * bytesPerPixel};
    assert(McsSessionLifecycleTestAccess::beginClearCodecFrame(
        session, 100U, framebuffer));
    const auto prepared =
        session.firstClientAcceptanceObservability();
    assert(prepared.firstClearCodecFramePrepared);
    assert(!prepared.firstExactFrameWriteCommitted);
    assert(prepared.outstandingFrameAcknowledgements == 0U);
    assert(!prepared.firstGenuineFrameAcknowledge);

    WriteOutcome frameOutcome = WriteOutcome::Pending;
    for (std::size_t attempt = 0U;
         attempt < 256U && frameOutcome == WriteOutcome::Pending;
         ++attempt)
    {
        write = McsSessionLifecycleTestAccess::pendingGraphics(session);
        assert(write && write->kind == WriteKind::GraphicsFrameData);
        frameOutcome =
            McsSessionLifecycleTestAccess::completeGraphics(
                session, *write);
    }
    assert(frameOutcome == WriteOutcome::Delivered);
    const auto committed =
        session.firstClientAcceptanceObservability();
    assert(committed.firstClearCodecFramePrepared);
    assert(committed.firstFramePublicationAccepted);
    assert(committed.firstExactFrameWriteCommitted);
    assert(committed.outstandingFrameAcknowledgements == 1U);
    assert(!committed.firstFrameAcknowledge);
    assert(!committed.firstGenuineFrameAcknowledge);

    assert(McsSessionLifecycleTestAccess::acceptGraphics(
               session,
               makeR3GraphicsFrameAcknowledgeTpkt(
                   9U, 100U, 4096U, 1U)) ==
           RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
    assert(McsSessionLifecycleTestAccess::consumeFrameAcknowledge(session) ==
           RdpGraphicsFrameAcknowledgeIntake::Acknowledged);
    const auto acknowledged =
        session.firstClientAcceptanceObservability();
    assert(acknowledged.firstFramePublicationAccepted);
    assert(acknowledged.firstExactFrameWriteCommitted);
    assert(acknowledged.firstFrameAcknowledge);
    assert(acknowledged.firstGenuineFrameAcknowledge);
    assert(acknowledged.outstandingFrameAcknowledgements == 0U);

    assert(McsSessionLifecycleTestAccess::beginSurfaceReconfiguration(
               session, {80U, 64U}) ==
           RdpGraphicsSurfaceReconfiguration::Started);
    assert(session.firstClientAcceptanceObservability().
        resizeRemapInProgress);
    write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write && write->kind == WriteKind::GraphicsDeleteSurface);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Pending);
    write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write && write->kind == WriteKind::GraphicsCreateSurface);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Pending);
    write = McsSessionLifecycleTestAccess::pendingGraphics(session);
    assert(write && write->kind == WriteKind::GraphicsMapSurfaceToOutput);
    assert(McsSessionLifecycleTestAccess::completeGraphics(
               session, *write) == WriteOutcome::Delivered);
    assert(!session.firstClientAcceptanceObservability().
        resizeRemapInProgress);
    assert(McsSessionLifecycleTestAccess::beginSurfaceReconfiguration(
               session, {0U, 64U}) ==
           RdpGraphicsSurfaceReconfiguration::Rejected);

    constexpr std::array<Kind, 13> expected{
        Kind::McsEstablished,
        Kind::ShareActivated,
        Kind::GraphicsDynamicVirtualChannelActivated,
        Kind::GraphicsControlReady,
        Kind::SurfaceCreated,
        Kind::SurfaceMapped,
        Kind::FirstFramePublicationAccepted,
        Kind::FirstFrameAcknowledge,
        Kind::ResizeRemapStarted,
        Kind::SurfaceCreated,
        Kind::SurfaceMapped,
        Kind::ResizeRemapCompleted,
        Kind::ResizeRemapRejected};
    const auto observed = session.firstClientAcceptanceObservability();
    assert(observed.reconnectGeneration == empty.reconnectGeneration);
    assert(observed.eventCount == expected.size());
    assert(observed.latestEventSequence == expected.size());
    assert(observed.droppedEventCount == 0U);
    assert(observed.mcsEstablished);
    assert(observed.shareActivated);
    assert(observed.graphicsDynamicVirtualChannelActivated);
    assert(observed.graphicsControlReady);
    assert(observed.surfaceCreated);
    assert(observed.surfaceMapped);
    assert(observed.firstFramePublicationAccepted);
    assert(observed.firstFrameAcknowledge);
    assert(observed.firstClearCodecFramePrepared);
    assert(!observed.resizeRemapInProgress);
    for (std::size_t index = 0U; index < expected.size(); ++index)
    {
        assert(observed.events[index].kind == expected[index]);
        assert(observed.events[index].sequence == index + 1U);
    }

    McsSessionLifecycle bounded;
    for (std::size_t index = 0U;
         index < kMaximumRdpFirstClientAcceptanceEvents + 8U; ++index)
    {
        McsSessionLifecycleTestAccess::recordAcceptanceEvent(
            bounded, Kind::ResizeRemapRejected);
    }
    const auto boundedObserved =
        bounded.firstClientAcceptanceObservability();
    assert(boundedObserved.eventCount ==
           kMaximumRdpFirstClientAcceptanceEvents);
    assert(boundedObserved.droppedEventCount == 8U);
    assert(boundedObserved.latestEventSequence ==
           kMaximumRdpFirstClientAcceptanceEvents + 8U);
    assert(boundedObserved.events.front().sequence == 9U);
    assert(boundedObserved.events[
               kMaximumRdpFirstClientAcceptanceEvents - 1U].sequence ==
           kMaximumRdpFirstClientAcceptanceEvents + 8U);
}

void testGraphicsPresentationInitializationWire()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{9U, 901U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);
    assert(dvc.presentationMapped());
    assert(dvc.graphicsCapabilitiesConfirmed());
}

void testGraphicsFrameZeroPublication()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;
    constexpr RdpDynamicVirtualChannelAllocation allocation{1U, 81U};

    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, clientUserId, drdynvcChannelId);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(
        dvc, 101U, frame);
    assert(dvc.beginFramePublication(
        std::move(frame),
        RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    assert(!frame.valid());
    assert(dvc.pendingServerWrite());
    assert(dvc.cancelUnwrittenFramePublication(
        allocation.generation));
    assert(!dvc.pendingServerWrite());
    assert(dvc.frameRecordMap().empty());
    assert(dvc.phase() == RdpGraphicsDvcPhase::Ready);
    assert(dvc.presentationMapped());
}

void testGraphicsFrameMultiFragmentDelivery()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;
    constexpr RdpDynamicVirtualChannelAllocation allocation{2U, 82U};

    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, clientUserId, drdynvcChannelId);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(
        dvc, 102U, frame);
    const std::vector<std::byte> expected(
        frame.wireBytes().begin(), frame.wireBytes().end());

    assert(dvc.beginFramePublication(
        std::move(frame),
        RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    const auto mapping = dvc.frameRecordMap();
    const std::size_t recordCount = mapping.size();
    assert(recordCount > 1U);
    assert(mapping.front().dataFirst);
    assert(mapping.front().frameOffset == 0U);

    std::size_t expectedOffset = 0U;
    for (std::size_t recordIndex = 0U;
         recordIndex < recordCount; ++recordIndex)
    {
        const auto record = mapping[recordIndex];
        assert(record.frameOffset == expectedOffset);
        assert(record.frameBytes != 0U);
        assert(record.frameBytes <=
               kMaximumRdpDynamicVirtualChannelDataPayloadBytes);
        assert(record.dataFirst == (recordIndex == 0U));
        const std::size_t payloadOffset =
            record.tpktHeaderBytes +
            record.x224HeaderBytes +
            record.mcsHeaderBytes +
            record.staticChannelHeaderBytes +
            record.dvcHeaderBytes;
        assert(payloadOffset + record.frameBytes ==
               record.outerPlaintextBytes);

        const auto write = dvc.pendingServerWrite();
        assert(write &&
               write.kind ==
                   RdpGraphicsDvcWriteKind::GraphicsFrameData);
        assert(write.bytes.size() ==
               record.outerPlaintextBytes);
        assert(write.bytes[payloadOffset -
                           record.dvcHeaderBytes] ==
               static_cast<std::uint8_t>(
                   recordIndex == 0U ? 0x24U : 0x30U));

        for (std::size_t index = 0U;
             index < record.frameBytes; ++index)
        {
            assert(write.bytes[payloadOffset + index] ==
                   std::to_integer<std::uint8_t>(
                       expected[record.frameOffset + index]));
        }

        const auto outcome = dvc.onServerBytesWritten(
            write.channelGeneration,
            write.replySequence,
            write.writeSliceSequence,
            write.bytes.size());
        if (recordIndex + 1U == recordCount)
            assert(outcome ==
                   RdpGraphicsDvcWriteOutcome::Delivered);
        else
            assert(outcome ==
                   RdpGraphicsDvcWriteOutcome::Pending);

        expectedOffset += record.frameBytes;
    }

    assert(expectedOffset == expected.size());
    assert(!dvc.pendingServerWrite());
    assert(dvc.phase() == RdpGraphicsDvcPhase::Ready);
    assert(dvc.outstandingGraphicsFrames() == 1U);
}

void testGraphicsFrameHeaderPartialAbort()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{3U, 83U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(
        dvc, 103U, frame);
    assert(dvc.beginFramePublication(
        std::move(frame),
        RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));

    const auto record = dvc.frameRecordMap().front();
    const std::size_t headerBytes =
        record.outerPlaintextBytes - record.frameBytes;
    const auto write = dvc.pendingServerWrite();
    assert(headerBytes > 0U &&
           headerBytes < write.bytes.size());
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               headerBytes) ==
           RdpGraphicsDvcWriteOutcome::Pending);
    assert(dvc.abortFramePublication(
        allocation.generation));
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    assert(!dvc.presentationMapped());
}

void testGraphicsFramePayloadPartialAbort()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{4U, 84U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(
        dvc, 104U, frame);
    assert(dvc.beginFramePublication(
        std::move(frame),
        RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));

    const auto record = dvc.frameRecordMap().front();
    const std::size_t headerBytes =
        record.outerPlaintextBytes - record.frameBytes;
    const auto write = dvc.pendingServerWrite();
    assert(record.frameBytes > 1U);
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               headerBytes + 1U) ==
           RdpGraphicsDvcWriteOutcome::Pending);
    assert(dvc.abortFramePublication(
        allocation.generation));
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    assert(!dvc.presentationMapped());
}

void testGraphicsFrameStaleReceiptAbort()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{5U, 85U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(
        dvc, 105U, frame);
    assert(dvc.beginFramePublication(
        std::move(frame),
        RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));

    const auto write = dvc.pendingServerWrite();
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence + 1U,
               1U) ==
           RdpGraphicsDvcWriteOutcome::Rejected);
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    assert(!dvc.presentationMapped());
}

void testGraphicsFrameShareLossAbort()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{6U, 86U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    prepareTestClearCodecFrame(
        dvc, 106U, frame);
    assert(dvc.beginFramePublication(
        std::move(frame),
        RdpGraphicsFrameCodec::ClearCodec,
        kRdpStaticVirtualChannelDefaultChunkBytes));
    dvc.close();
    assert(dvc.phase() == RdpGraphicsDvcPhase::Closed);
    assert(!dvc.presentationMapped());
}

void testGraphicsDataFirstMalformed()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{7U, 87U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    const std::array<std::uint8_t, 5> malformed{
        0x2cU, 0x07U, 0x41U, 0x06U, 0xaaU};
    assert(dvc.onClientTpkt(
               allocation.generation,
               makeClientDynamicVirtualChannelTpkt(
                   1007U, 1005U, malformed)) ==
           RdpGraphicsDvcClientIntake::Rejected);
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
}

void testGraphicsDataWrongChannel()
{
    constexpr RdpDynamicVirtualChannelAllocation allocation{8U, 88U};
    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    completeGraphicsDynamicVirtualChannelReady(
        dvc, allocation, 1007U, 1005U);

    const std::array<std::uint8_t, 5> wrongChannel{
        0x24U, 0x09U, 0x41U, 0x06U, 0xaaU};
    assert(dvc.onClientTpkt(
               allocation.generation,
               makeClientDynamicVirtualChannelTpkt(
                   1007U, 1005U, wrongChannel)) ==
           RdpGraphicsDvcClientIntake::Rejected);
    assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
}

void testGraphicsDataFragmentOrdering()
{
    const auto makeFirst =
        [](std::uint8_t channelId, std::size_t payloadBytes)
    {
        std::vector<std::uint8_t> pdu(
            4U + payloadBytes, 0x11U);
        pdu[0] = 0x24U;
        pdu[1] = channelId;
        pdu[2] = 0x41U;
        pdu[3] = 0x06U; // 1,601 total application bytes.
        return pdu;
    };
    const auto makeData =
        [](std::uint8_t channelId,
           std::size_t payloadBytes,
           std::uint8_t value)
    {
        std::vector<std::uint8_t> pdu(
            2U + payloadBytes, value);
        pdu[0] = 0x30U;
        pdu[1] = channelId;
        return pdu;
    };

    {
        constexpr RdpDynamicVirtualChannelAllocation allocation{9U, 89U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelReady(
            dvc, allocation, 1007U, 1005U);

        const auto first = makeFirst(9U, 100U);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, first)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsDataFragmentAccepted);
        assert(dvc.pendingClientGraphicsData().empty());

        const auto middle = makeData(9U, 1000U, 0x22U);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, middle)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsDataFragmentAccepted);
        assert(dvc.pendingClientGraphicsData().empty());

        const auto last = makeData(9U, 501U, 0x33U);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, last)) ==
               RdpGraphicsDvcClientIntake::GraphicsDataAccepted);
        const auto complete = dvc.pendingClientGraphicsData();
        assert(complete.size() == 1601U);
        assert(complete[0] == 0x11U);
        assert(complete[99U] == 0x11U);
        assert(complete[100U] == 0x22U);
        assert(complete[1099U] == 0x22U);
        assert(complete[1100U] == 0x33U);
        assert(complete.back() == 0x33U);
        assert(dvc.consumeClientGraphicsData(
            allocation.generation));
        assert(dvc.pendingClientGraphicsData().empty());
    }

    {
        // A dropped tail remains incomplete and is never surfaced.
        constexpr RdpDynamicVirtualChannelAllocation allocation{10U, 90U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelReady(
            dvc, allocation, 1007U, 1005U);
        const auto first = makeFirst(10U, 100U);
        const auto middle = makeData(10U, 1000U, 0x44U);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, first)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsDataFragmentAccepted);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, middle)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsDataFragmentAccepted);
        assert(dvc.pendingClientGraphicsData().empty());
        dvc.close();
        assert(dvc.pendingClientGraphicsData().empty());
    }

    {
        // Replaying a continuation that would exceed the advertised total is
        // detected as a duplicate/ordering failure and retires the channel.
        constexpr RdpDynamicVirtualChannelAllocation allocation{11U, 91U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelReady(
            dvc, allocation, 1007U, 1005U);
        const auto first = makeFirst(11U, 100U);
        const auto repeated = makeData(11U, 800U, 0x55U);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, first)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsDataFragmentAccepted);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, repeated)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsDataFragmentAccepted);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       1007U, 1005U, repeated)) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    }
}

void testGraphicsDynamicVirtualChannelCapabilitiesSelection()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;
    constexpr std::uint32_t version81 = 0x00080105U;

    {
        // Offer VERSION8 and VERSION81 without AVC420. R4 must pick the
        // highest supported profile while preserving ClearCodec fallback.
        constexpr RdpDynamicVirtualChannelAllocation allocation{1U, 31U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelCreate(
            dvc, allocation, clientUserId, drdynvcChannelId);

        constexpr std::array<std::uint8_t, 34> advertise{
            0x12U, 0x00U, 0x00U, 0x00U, 0x22U, 0x00U, 0x00U, 0x00U,
            0x02U, 0x00U,
            0x04U, 0x00U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x03U, 0x00U, 0x00U, 0x00U,
            0x05U, 0x01U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x02U, 0x00U, 0x00U, 0x00U};
        std::vector<std::uint8_t> data{
            0x30U, static_cast<std::uint8_t>(allocation.channelId)};
        data.insert(data.end(), advertise.begin(), advertise.end());

        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId, data)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsCapabilitiesAccepted);
        assert(dvc.created());
        assert(!dvc.graphicsCapabilitiesConfirmed());
        assert(!dvc.graphicsClearCodecEnabled());
        assert(!dvc.graphicsAvc420Enabled());
        assert(dvc.confirmedGraphicsCapabilityVersion() == 0U);
        assert(dvc.confirmedGraphicsCapabilityFlags() == 0U);

        auto write = dvc.pendingServerWrite();
        assert(write &&
               write.kind ==
                   RdpGraphicsDvcWriteKind::
                       GraphicsCapabilitiesConfirm);
        const auto confirmation =
            serverDynamicVirtualChannelControl(write);
        constexpr std::array<std::uint8_t, 22> expected{
            0x30U, 0x01U,
            0x13U, 0x00U, 0x00U, 0x00U, 0x14U, 0x00U, 0x00U, 0x00U,
            0x05U, 0x01U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x02U, 0x00U, 0x00U, 0x00U};
        assert(confirmation.size() == expected.size());
        assert(std::equal(
            confirmation.begin(), confirmation.end(),
            expected.begin(), expected.end()));

        // Zero publication cannot activate a codec. Positive short progress
        // rotates only the exact write-slice receipt.
        assert(dvc.onServerBytesWritten(
                   write.channelGeneration,
                   write.replySequence,
                   write.writeSliceSequence, 0U) ==
               RdpGraphicsDvcWriteOutcome::Pending);
        assert(dvc.pendingServerWrite().writeSliceSequence ==
               write.writeSliceSequence);
        assert(!dvc.graphicsClearCodecEnabled());

        constexpr std::size_t firstAcceptedBytes = 7U;
        assert(dvc.onServerBytesWritten(
                   write.channelGeneration,
                   write.replySequence,
                   write.writeSliceSequence,
                   firstAcceptedBytes) ==
               RdpGraphicsDvcWriteOutcome::Pending);
        const auto remainder = dvc.pendingServerWrite();
        assert(remainder &&
               remainder.replySequence == write.replySequence &&
               remainder.writeSliceSequence !=
                   write.writeSliceSequence);
        assert(!dvc.graphicsClearCodecEnabled());
        assert(dvc.onServerBytesWritten(
                   remainder.channelGeneration,
                   remainder.replySequence,
                   remainder.writeSliceSequence,
                   remainder.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Pending);

        assert(dvc.graphicsCapabilitiesConfirmed());
        assert(dvc.graphicsClearCodecEnabled());
        assert(!dvc.graphicsAvc420Enabled());
        assert(dvc.confirmedGraphicsCapabilityVersion() == version81);
        assert(dvc.confirmedGraphicsCapabilityFlags() == 0x00000002U);
        completeGraphicsPresentationSurfaceInitialization(dvc);
    }

    {
        // AVC420 becomes consumable only after the VERSION81 confirmation
        // that explicitly carries AVC420_ENABLED is fully delivered.
        constexpr RdpDynamicVirtualChannelAllocation allocation{2U, 32U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelCreate(
            dvc, allocation, clientUserId, drdynvcChannelId);

        constexpr std::array<std::uint8_t, 22> advertise{
            0x12U, 0x00U, 0x00U, 0x00U, 0x16U, 0x00U, 0x00U, 0x00U,
            0x01U, 0x00U,
            0x05U, 0x01U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x10U, 0x00U, 0x00U, 0x00U};
        std::vector<std::uint8_t> data{
            0x30U, static_cast<std::uint8_t>(allocation.channelId)};
        data.insert(data.end(), advertise.begin(), advertise.end());
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId, data)) ==
               RdpGraphicsDvcClientIntake::
                   GraphicsCapabilitiesAccepted);
        assert(!dvc.graphicsAvc420Enabled());

        const auto write = dvc.pendingServerWrite();
        assert(write);
        assert(dvc.onServerBytesWritten(
                   write.channelGeneration,
                   write.replySequence,
                   write.writeSliceSequence,
                   write.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Pending);
        assert(dvc.graphicsCapabilitiesConfirmed());
        assert(dvc.graphicsClearCodecEnabled());
        assert(dvc.graphicsAvc420Enabled());
        assert(dvc.confirmedGraphicsCapabilityVersion() == version81);
        assert(dvc.confirmedGraphicsCapabilityFlags() == 0x00000010U);
        completeGraphicsPresentationSurfaceInitialization(dvc);
    }
}

void testGraphicsDynamicVirtualChannelCapabilitiesUnsupportedDenial()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;

    {
        // VERSION81 with an unknown flag is not a profile R4 implements.
        // There is no lower supported offer, so no CAPS_CONFIRM is queued.
        constexpr RdpDynamicVirtualChannelAllocation allocation{3U, 41U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelCreate(
            dvc, allocation, clientUserId, drdynvcChannelId);

        constexpr std::array<std::uint8_t, 22> unsupported{
            0x12U, 0x00U, 0x00U, 0x00U, 0x16U, 0x00U, 0x00U, 0x00U,
            0x01U, 0x00U,
            0x05U, 0x01U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x20U, 0x00U, 0x00U, 0x00U};
        std::vector<std::uint8_t> data{
            0x30U, static_cast<std::uint8_t>(allocation.channelId)};
        data.insert(data.end(), unsupported.begin(), unsupported.end());
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId, data)) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
        assert(!dvc.created());
        assert(!dvc.pendingServerWrite());
        assert(!dvc.graphicsClearCodecEnabled());
        assert(!dvc.graphicsAvc420Enabled());
    }

    {
        // Fragmented Graphics DATA is not silently treated as a complete
        // CAPS_ADVERTISE before DATA_FIRST/DATA reassembly exists.
        constexpr RdpDynamicVirtualChannelAllocation allocation{4U, 42U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelCreate(
            dvc, allocation, clientUserId, drdynvcChannelId);

        constexpr std::array<std::uint8_t, 22> advertise{
            0x12U, 0x00U, 0x00U, 0x00U, 0x16U, 0x00U, 0x00U, 0x00U,
            0x01U, 0x00U,
            0x04U, 0x00U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U};
        std::vector<std::uint8_t> dataFirst{
            0x20U, static_cast<std::uint8_t>(allocation.channelId)};
        dataFirst.insert(
            dataFirst.end(), advertise.begin(), advertise.end());
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId, dataFirst)) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    }

    {
        // A stale channel generation cannot deliver a valid advertisement.
        constexpr RdpDynamicVirtualChannelAllocation allocation{5U, 43U};
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        completeGraphicsDynamicVirtualChannelCreate(
            dvc, allocation, clientUserId, drdynvcChannelId);

        constexpr std::array<std::uint8_t, 22> advertise{
            0x12U, 0x00U, 0x00U, 0x00U, 0x16U, 0x00U, 0x00U, 0x00U,
            0x01U, 0x00U,
            0x04U, 0x00U, 0x08U, 0x00U, 0x04U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U};
        std::vector<std::uint8_t> data{
            0x30U, static_cast<std::uint8_t>(allocation.channelId)};
        data.insert(data.end(), advertise.begin(), advertise.end());
        assert(dvc.onClientTpkt(
                   allocation.generation + 1U,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId, data)) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
        assert(!dvc.pendingServerWrite());
    }
}

void testRdpGraphicsClientCoreCapabilityGate()
{
    GccClientSettings settings{};
    assert(!gccClientSupportsDynamicVirtualChannelGraphics(settings));

    settings.hasEarlyCapabilityFlags = true;
    assert(!gccClientSupportsDynamicVirtualChannelGraphics(settings));
    settings.earlyCapabilityFlags = 0x0018U;
    assert(!gccClientSupportsDynamicVirtualChannelGraphics(settings));
    settings.earlyCapabilityFlags =
        kGccClientCoreSupportsDynamicVirtualChannelGraphics;
    assert(gccClientSupportsDynamicVirtualChannelGraphics(settings));
    settings.earlyCapabilityFlags |= 0x0018U;
    assert(gccClientSupportsDynamicVirtualChannelGraphics(settings));
    settings.hasEarlyCapabilityFlags = false;
    assert(!gccClientSupportsDynamicVirtualChannelGraphics(settings));

    // Microsoft's checked-in 4.1.3 Basic Settings fixture predates the
    // Graphics Pipeline bit. It remains valid MCS/GCC evidence, but it must
    // not be promoted into RDPGFX capability evidence.
    const auto published = publishedFixture();
    const auto connectInitial = parseMcsConnectInitial(published);
    assert(connectInitial);
    const auto gcc =
        parseGccConferenceCreate(connectInitial.value.gccUserData);
    assert(gcc);
    assert(gcc.settings.hasEarlyCapabilityFlags);
    assert(gcc.settings.earlyCapabilityFlags == 0x0018U);
    assert(!gccClientSupportsDynamicVirtualChannelGraphics(gcc.settings));
}

void testGraphicsDynamicVirtualChannelCreateSuccess()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;

    RdpDynamicVirtualChannelAllocator allocator;
    const auto first = allocator.allocate();
    const auto second = allocator.allocate();
    assert(first && second);
    assert(first->channelId == 1U && first->generation == 1U);
    assert(second->channelId == 2U && second->generation == 2U);
    assert(first->channelId != second->channelId);
    assert(first->generation != second->generation);

    RdpGraphicsDynamicVirtualChannelLifecycle dvc;
    assert(dvc.begin(clientUserId, drdynvcChannelId, *first, {64U, 64U}));
    auto write = dvc.pendingServerWrite();
    assert(write);
    assert(write.kind ==
           RdpGraphicsDvcWriteKind::CapabilitiesRequest);
    assert(write.dynamicChannelId == first->channelId);
    assert(write.channelGeneration == first->generation);
    assert(write.bytes[10] ==
           static_cast<std::uint8_t>(drdynvcChannelId >> 8U));
    assert(write.bytes[11] ==
           static_cast<std::uint8_t>(drdynvcChannelId));
    constexpr std::array<std::uint8_t, 4> capsRequest{
        0x50U, 0x00U, 0x01U, 0x00U};
    const auto capsWire = serverDynamicVirtualChannelControl(write);
    assert(std::equal(
        capsWire.begin(), capsWire.end(), capsRequest.begin(),
        capsRequest.end()));

    // R1-style accepted-byte progress is cumulative at this owner: a
    // positive short write rotates only the slice receipt and retains bytes.
    constexpr std::size_t firstAcceptedBytes = 5U;
    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               firstAcceptedBytes) ==
           RdpGraphicsDvcWriteOutcome::Pending);
    const auto remainingCaps = dvc.pendingServerWrite();
    assert(remainingCaps);
    assert(remainingCaps.replySequence == write.replySequence);
    assert(remainingCaps.writeSliceSequence !=
           write.writeSliceSequence);
    assert(remainingCaps.bytes.size() ==
           write.bytes.size() - firstAcceptedBytes);
    assert(dvc.onServerBytesWritten(
               remainingCaps.channelGeneration,
               remainingCaps.replySequence,
               remainingCaps.writeSliceSequence,
               remainingCaps.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.phase() ==
           RdpGraphicsDvcPhase::AwaitCapabilitiesResponse);

    // A modern client can report its highest supported level (v3) even
    // though this server advertises only v1. The common negotiated level
    // remains v1.
    constexpr std::array<std::uint8_t, 4> capsResponse{
        0x50U, 0x00U, 0x03U, 0x00U};
    assert(dvc.onClientTpkt(
               first->generation,
               makeClientDynamicVirtualChannelTpkt(
                   clientUserId, drdynvcChannelId, capsResponse)) ==
           RdpGraphicsDvcClientIntake::CapabilitiesAccepted);
    assert(dvc.negotiatedVersion() == 1U);

    write = dvc.pendingServerWrite();
    assert(write);
    assert(write.kind == RdpGraphicsDvcWriteKind::CreateRequest);
    const auto create = serverDynamicVirtualChannelControl(write);
    assert(create.size() ==
           2U + kRdpGraphicsDynamicVirtualChannelName.size() + 1U);
    assert(create[0] == 0x10U);
    assert(create[1] == first->channelId);
    assert(std::equal(
        kRdpGraphicsDynamicVirtualChannelName.begin(),
        kRdpGraphicsDynamicVirtualChannelName.end(),
        create.begin() + 2U));
    assert(create.back() == 0U);

    assert(dvc.onServerBytesWritten(
               write.channelGeneration,
               write.replySequence,
               write.writeSliceSequence,
               write.bytes.size()) ==
           RdpGraphicsDvcWriteOutcome::Delivered);
    assert(dvc.phase() == RdpGraphicsDvcPhase::AwaitCreateResponse);

    constexpr std::array<std::uint8_t, 6> createResponse{
        0x10U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U};
    assert(dvc.onClientTpkt(
               first->generation,
               makeClientDynamicVirtualChannelTpkt(
                   clientUserId, drdynvcChannelId,
                   createResponse)) ==
           RdpGraphicsDvcClientIntake::CreateAccepted);
    assert(dvc.created());
    assert(dvc.dynamicChannelId() == first->channelId);
    assert(!dvc.pendingServerWrite());
}

void testGraphicsDynamicVirtualChannelResponseDenials()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;
    constexpr std::array<std::uint8_t, 4> capsResponse{
        0x50U, 0x00U, 0x01U, 0x00U};

    const auto stageAwaitCreateResponse =
        [&](RdpGraphicsDynamicVirtualChannelLifecycle &dvc,
            RdpDynamicVirtualChannelAllocation allocation)
    {
        assert(dvc.begin(clientUserId, drdynvcChannelId, allocation, {64U, 64U}));
        auto write = dvc.pendingServerWrite();
        assert(dvc.onServerBytesWritten(
                   write.channelGeneration,
                   write.replySequence,
                   write.writeSliceSequence,
                   write.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Delivered);
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId,
                       capsResponse)) ==
               RdpGraphicsDvcClientIntake::CapabilitiesAccepted);
        write = dvc.pendingServerWrite();
        assert(write.kind == RdpGraphicsDvcWriteKind::CreateRequest);
        assert(dvc.onServerBytesWritten(
                   write.channelGeneration,
                   write.replySequence,
                   write.writeSliceSequence,
                   write.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Delivered);
        assert(dvc.phase() == RdpGraphicsDvcPhase::AwaitCreateResponse);
    };

    // Zero and out-of-range capability versions are malformed. A client
    // version 2 or 3 is legal and negotiates down to this server's v1.
    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        const RdpDynamicVirtualChannelAllocation allocation{1U, 1U};
        assert(dvc.begin(clientUserId, drdynvcChannelId, allocation, {64U, 64U}));
        const auto write = dvc.pendingServerWrite();
        assert(dvc.onServerBytesWritten(
                   write.channelGeneration, write.replySequence,
                   write.writeSliceSequence, write.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Delivered);
        constexpr std::array<std::uint8_t, 4> invalidVersion{
            0x50U, 0x00U, 0x04U, 0x00U};
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId,
                       invalidVersion)) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    }

    // A negative HRESULT is a correlated remote refusal, not success.
    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        const RdpDynamicVirtualChannelAllocation allocation{7U, 9U};
        stageAwaitCreateResponse(dvc, allocation);
        constexpr std::array<std::uint8_t, 6> rejected{
            0x10U, 0x07U, 0x05U, 0x40U, 0x00U, 0x80U};
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId,
                       rejected)) ==
               RdpGraphicsDvcClientIntake::CreateRejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
        assert(!dvc.created());
    }

    // Wrong ChannelId cannot acknowledge this CREATE.
    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        const RdpDynamicVirtualChannelAllocation allocation{7U, 10U};
        stageAwaitCreateResponse(dvc, allocation);
        constexpr std::array<std::uint8_t, 6> wrongChannel{
            0x10U, 0x08U, 0x00U, 0x00U, 0x00U, 0x00U};
        assert(dvc.onClientTpkt(
                   allocation.generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId,
                       wrongChannel)) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    }

    // A successful response is single-consumption. Replaying it retires the
    // protocol owner instead of creating a second endpoint.
    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        const RdpDynamicVirtualChannelAllocation allocation{7U, 11U};
        stageAwaitCreateResponse(dvc, allocation);
        constexpr std::array<std::uint8_t, 6> accepted{
            0x10U, 0x07U, 0x00U, 0x00U, 0x00U, 0x00U};
        const auto packet = makeClientDynamicVirtualChannelTpkt(
            clientUserId, drdynvcChannelId, accepted);
        assert(dvc.onClientTpkt(allocation.generation, packet) ==
               RdpGraphicsDvcClientIntake::CreateAccepted);
        assert(dvc.created());
        assert(dvc.onClientTpkt(allocation.generation, packet) ==
               RdpGraphicsDvcClientIntake::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    }
}

void testGraphicsDynamicVirtualChannelGenerationCancellation()
{
    constexpr std::uint32_t clientUserId = 1007U;
    constexpr std::uint16_t drdynvcChannelId = 1005U;

    RdpDynamicVirtualChannelAllocator allocator;
    const auto first = allocator.allocate();
    const auto second = allocator.allocate();
    const auto third = allocator.allocate();
    assert(first && second && third);

    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        assert(dvc.begin(clientUserId, drdynvcChannelId, *first, {64U, 64U}));
        const auto write = dvc.pendingServerWrite();
        assert(dvc.onServerBytesWritten(
                   second->generation,
                   write.replySequence,
                   write.writeSliceSequence,
                   write.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Failed);
    }

    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        assert(dvc.begin(clientUserId, drdynvcChannelId, *second, {64U, 64U}));
        const auto firstWrite = dvc.pendingServerWrite();
        assert(dvc.onServerBytesWritten(
                   second->generation,
                   firstWrite.replySequence,
                   firstWrite.writeSliceSequence, 7U) ==
               RdpGraphicsDvcWriteOutcome::Pending);
        const auto remainder = dvc.pendingServerWrite();
        assert(remainder &&
               remainder.writeSliceSequence !=
                   firstWrite.writeSliceSequence);
        dvc.close();
        assert(dvc.phase() == RdpGraphicsDvcPhase::Closed);
        assert(!dvc.pendingServerWrite());
        assert(dvc.onServerBytesWritten(
                   second->generation,
                   remainder.replySequence,
                   remainder.writeSliceSequence,
                   remainder.bytes.size()) ==
               RdpGraphicsDvcWriteOutcome::Rejected);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Closed);
    }

    {
        RdpGraphicsDynamicVirtualChannelLifecycle dvc;
        assert(dvc.begin(clientUserId, drdynvcChannelId, *third, {64U, 64U}));
        dvc.revokeUnlessChannelGenerationMatches(second->generation);
        assert(dvc.phase() == RdpGraphicsDvcPhase::Closed);
        constexpr std::array<std::uint8_t, 4> capsResponse{
            0x50U, 0x00U, 0x01U, 0x00U};
        assert(dvc.onClientTpkt(
                   third->generation,
                   makeClientDynamicVirtualChannelTpkt(
                       clientUserId, drdynvcChannelId,
                       capsResponse)) ==
               RdpGraphicsDvcClientIntake::Closed);
    }

    allocator.close();
    assert(!allocator.allocate());
}

void testClipboardPreShareDenial()
{
    McsSessionLifecycle session;
    assert(!McsSessionLifecycleTestAccess::
               routeClipboardWithoutAdmission(session));
    assert(session.phase() == McsSessionPhase::Closed);
}


void testPostShareClassifierJoinedRoutes()
{
    McsSessionLifecycle session;
    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(session));
    const auto slowPdu = makeActivationScancodeInputSharePdu();
    const auto slowPacket = makeClientShareTpkt(1007U, 1003U, slowPdu);
    constexpr std::array<std::uint8_t, 4> dvcCaps{
        0x50U, 0x00U, 0x01U, 0x00U};
    const auto graphics = makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, dvcCaps);
    constexpr std::array<std::uint8_t, 8> clipboardPdu{
        0x08U, 0x00U, 0x00U, 0x00U, 0x01U, 0x00U, 0x08U, 0x00U};
    const auto clipboardPacket = makeClientDynamicVirtualChannelTpkt(
        1007U, 1004U, clipboardPdu);
    const auto slow = McsSessionLifecycleTestAccess::classifyPostShare(
        session, slowPacket);
    const auto gfx = McsSessionLifecycleTestAccess::classifyPostShare(
        session, graphics);
    const auto clip = McsSessionLifecycleTestAccess::classifyPostShare(
        session, clipboardPacket);
    assert(slow.kind == RdpPostShareTpktRouteKind::SlowPathInput);
    assert(gfx.kind ==
           RdpPostShareTpktRouteKind::GraphicsDynamicVirtualChannel);
    assert(clip.kind ==
           RdpPostShareTpktRouteKind::ClipboardStaticChannel);
    assert(slow.completeTpkt.data() == slowPacket.data());
    assert(slow.completeTpkt.size() == slowPacket.size());
    assert(gfx.completeTpkt.data() == graphics.data());
    assert(clip.completeTpkt.data() == clipboardPacket.data());
    assert(session.phase() == McsSessionPhase::ShareActivated);
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        session, slowPacket).kind == RdpPostShareTpktRouteKind::SlowPathInput);
    assert(session.phase() == McsSessionPhase::ShareActivated);
}

void testPostShareClassifierMalformedAndWrongJoinedRole()
{
    McsSessionLifecycle session;
    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(session));
    constexpr std::array<std::uint8_t, 4> caps{
        0x50U, 0x00U, 0x01U, 0x00U};
    const auto graphics = makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, caps);
    auto malformed = graphics;
    malformed[3] ^= 1U;
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        session, malformed).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);
    std::vector<std::uint8_t> oversized(65536U);
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        session, oversized).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);
    McsSessionLifecycleTestAccess::wrongDynamicRole(session);
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        session, graphics).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);
    assert(session.phase() == McsSessionPhase::ShareActivated);
}

void testPostShareClassifierGraphicsDynamicIdAndPhase()
{
    McsSessionLifecycle session;
    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(session));
    auto &dvc = McsSessionLifecycleTestAccess::
        graphicsForClassifierTest(session);
    constexpr auto denied =
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed;
    constexpr auto graphics =
        RdpPostShareTpktRouteKind::GraphicsDynamicVirtualChannel;
    const auto classify = [&](std::span<const std::uint8_t> payload)
    {
        const auto packet = makeClientDynamicVirtualChannelTpkt(
            1007U, 1005U, payload);
        return McsSessionLifecycleTestAccess::classifyPostShare(
            session, packet).kind;
    };

    constexpr std::array<std::uint8_t, 4> caps{
        0x50U, 0x00U, 0x01U, 0x00U};
    constexpr std::array<std::uint8_t, 4> unsupportedCaps{
        0x50U, 0x00U, 0x00U, 0x00U};
    constexpr std::array<std::uint8_t, 6> create{
        0x10U, 0x09U, 0U, 0U, 0U, 0U};
    constexpr std::array<std::uint8_t, 6> wrongCreate{
        0x10U, 0x08U, 0U, 0U, 0U, 0U};
    constexpr std::array<std::uint8_t, 3> data{
        0x30U, 0x09U, 0x01U};
    constexpr std::array<std::uint8_t, 3> otherChannel{
        0x30U, 0x08U, 0x01U};
    constexpr std::array<std::uint8_t, 4> dataFirst{
        0x20U, 0x09U, 0x04U, 0x01U};
    constexpr std::array<std::uint8_t, 3> unsupportedCommand{
        0x40U, 0x09U, 0x01U};
    constexpr std::array<std::uint8_t, 3> reserved{
        0x3cU, 0x09U, 0x01U};

    assert(classify(unsupportedCaps) == denied);
    assert(classify(data) == denied);
    assert(classify(create) == denied);
    assert(classify(caps) == graphics);
    assert(dvc.onClientTpkt(91U, makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, caps)) ==
        RdpGraphicsDvcClientIntake::CapabilitiesAccepted);
    const auto write = dvc.pendingServerWrite();
    assert(write && dvc.onServerBytesWritten(
        write.channelGeneration, write.replySequence,
        write.writeSliceSequence, write.bytes.size()) ==
        RdpGraphicsDvcWriteOutcome::Delivered);
    assert(classify(wrongCreate) == denied);
    assert(classify(data) == denied);
    assert(classify(create) == graphics);
    assert(dvc.onClientTpkt(91U, makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, create)) ==
        RdpGraphicsDvcClientIntake::CreateAccepted);
    assert(classify(otherChannel) == denied);
    assert(classify(create) == denied);
    assert(classify(unsupportedCommand) == denied);
    assert(classify(reserved) == denied);
    assert(classify(data) == graphics);
    assert(classify(dataFirst) == graphics);
    assert(classify(data) == graphics);
    assert(session.phase() == McsSessionPhase::ShareActivated);
    const auto packet = makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, data);
    const auto route = McsSessionLifecycleTestAccess::classifyPostShare(
        session, packet);
    assert(route.kind == graphics &&
           route.completeTpkt.data() == packet.data() &&
           route.completeTpkt.size() == packet.size());
}

void testPostShareClassifierGenerationShareAndDisconnect()
{
    McsSessionLifecycle graphicsSession;
    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(
        graphicsSession));
    constexpr std::array<std::uint8_t, 4> caps{
        0x50U, 0x00U, 0x01U, 0x00U};
    const auto graphics = makeClientDynamicVirtualChannelTpkt(
        1007U, 1005U, caps);
    McsSessionLifecycleTestAccess::staleGraphics(graphicsSession);
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        graphicsSession, graphics).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);

    McsSessionLifecycle clipboardSession;
    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(
        clipboardSession));
    constexpr std::array<std::uint8_t, 8> clipboardBytes{
        0x08U,0U,0U,0U, 0x01U,0U,0x08U,0U};
    const auto clipboardPacket = makeClientDynamicVirtualChannelTpkt(
        1007U, 1004U, clipboardBytes);
    McsSessionLifecycleTestAccess::staleClipboard(clipboardSession);
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        clipboardSession, clipboardPacket).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);

    McsSessionLifecycle shareSession;
    assert(McsSessionLifecycleTestAccess::stagePostShareClassifier(
        shareSession));
    const auto input = makeClientShareTpkt(
        1007U, 1003U, makeActivationScancodeInputSharePdu());
    McsSessionLifecycleTestAccess::replaceShare(shareSession);
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        shareSession, input).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);
    shareSession.close();
    assert(McsSessionLifecycleTestAccess::classifyPostShare(
        shareSession, graphics).kind ==
        RdpPostShareTpktRouteKind::UnsupportedOrMalformed);
}

void testGraphicsDynamicVirtualChannelPreShareDenial()
{
    McsSessionLifecycle session;
    assert(!McsSessionLifecycleTestAccess::
               beginGraphicsDvcWithoutAdmission(session));
    assert(session.phase() == McsSessionPhase::Closed);
}

void testMcsSessionJoinConfirmReceipts()
{
    // The production join gate owns exact 15-byte responses and per-slice
    // receipts, but the offline test does NOT construct R2 session admission.
    constexpr std::array<std::uint16_t, 3> channels{1002U, 1003U, 1004U};
    constexpr std::array<std::uint8_t, 12> joinIo{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x01, 0x03, 0xeb};
    auto parsed = parseMcsChannelRequest(joinIo);
    assert(parsed && parsed.request.initiator == 1002U);
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1002U, channels));
    assert(gate.beginJoin(parsed.request) == McsJoinStartOutcome::ReplyPending);
    const auto expected = encodeMcsChannelJoinConfirm(
        parsed.request, 1002U, channels);
    assert(expected && expected.length == 15U);

    const auto initialBytes = gate.pendingBytes();
    const auto firstReply = gate.pendingReplySequence();
    const auto firstSlice = gate.pendingWriteSliceSequence();
    assert(initialBytes.size() == expected.length);
    assert(std::equal(initialBytes.begin(), initialBytes.end(),
                      expected.bytes().begin()));
    assert(firstReply != 0U && firstSlice != 0U);
    assert(gate.onReplyBytesWritten(firstReply, firstSlice, 0U) ==
           McsJoinWriteOutcome::Pending);
    assert(gate.pendingBytes().data() == initialBytes.data());
    assert(gate.pendingWriteSliceSequence() == firstSlice);
    assert(!gate.channelJoinConfirmed(1003U));

    auto next = parsed.request;
    next.channelId = 1004U;
    assert(gate.beginJoin(next) == McsJoinStartOutcome::Buffered);
    assert(gate.onReplyBytesWritten(firstReply, firstSlice, 7U) ==
           McsJoinWriteOutcome::Pending);
    assert(gate.pendingReplySequence() == firstReply);
    const auto secondSlice = gate.pendingWriteSliceSequence();
    assert(secondSlice > firstSlice);
    assert(gate.pendingBytes().size() == expected.length - 7U);
    assert(gate.onReplyBytesWritten(
        firstReply, secondSlice, expected.length - 7U) ==
        McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1003U));
    assert(!gate.channelJoinConfirmed(1004U));

    // Batching retires one confirmation before exposing the next.
    const auto nextReply = gate.pendingReplySequence();
    const auto nextSlice = gate.pendingWriteSliceSequence();
    assert(nextReply > firstReply && nextSlice > secondSlice);
    assert(gate.pendingBytes().size() == 15U);
    assert(gate.onReplyBytesWritten(
        nextReply, nextSlice, gate.pendingBytes().size()) ==
        McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1004U));
    assert(gate.pendingBytes().empty());
    assert(gate.beginJoin(parsed.request) == McsJoinStartOutcome::AlreadyJoined);

    McsSessionLifecycle notAdmitted;
    assert(notAdmitted.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(notAdmitted.allocatedUserId() == 0U);
    assert(!notAdmitted.channelJoinConfirmed(1003U));
    assert(notAdmitted.pendingJoinConfirmation().empty());
}

void testMcsSessionJoinConfirmDenials()
{
    constexpr std::array<std::uint16_t, 3> channels{1002U, 1003U, 1004U};
    constexpr std::array<std::uint8_t, 12> joinIo{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x01, 0x03, 0xeb};
    const auto parsed = parseMcsChannelRequest(joinIo);
    assert(parsed);
    McsChannelJoinWriteGate stale;
    assert(stale.configure(1002U, channels));
    assert(stale.beginJoin(parsed.request) == McsJoinStartOutcome::ReplyPending);
    const auto previousReply = stale.pendingReplySequence();
    const auto previousSlice = stale.pendingWriteSliceSequence();
    assert(stale.onReplyBytesWritten(previousReply, previousSlice, 5U) ==
           McsJoinWriteOutcome::Pending);
    assert(stale.onReplyBytesWritten(previousReply, previousSlice, 1U) ==
           McsJoinWriteOutcome::Rejected);
    assert(stale.pendingBytes().empty());
    assert(!stale.channelJoinConfirmed(1003U));

    McsChannelJoinWriteGate cancelled;
    assert(cancelled.configure(1002U, channels));
    assert(cancelled.beginJoin(parsed.request) == McsJoinStartOutcome::ReplyPending);
    auto other = parsed.request;
    other.channelId = 1004U;
    assert(cancelled.beginJoin(other) == McsJoinStartOutcome::Buffered);
    const auto reply = cancelled.pendingReplySequence();
    const auto slice = cancelled.pendingWriteSliceSequence();
    cancelled.close();
    assert(cancelled.onReplyBytesWritten(reply, slice, 15U) ==
           McsJoinWriteOutcome::Rejected);
    assert(!cancelled.channelJoinConfirmed(1003U));
    assert(!cancelled.channelJoinConfirmed(1004U));

    for (const auto invalidChannel : {0U, 1001U, 65535U})
    {
        McsChannelJoinWriteGate invalid;
        assert(invalid.configure(1002U, channels));
        auto request = parsed.request;
        request.channelId = static_cast<std::uint16_t>(invalidChannel);
        assert(invalid.beginJoin(request) == McsJoinStartOutcome::Rejected);
        assert(invalid.pendingBytes().empty());
    }

    // No positive public path: even well-formed Join is terminal before R2.
    McsSessionLifecycle early;
    assert(early.onDomainPdu(joinIo) == McsSessionIntake::ValidButNotAdmitted);
    assert(early.phase() == McsSessionPhase::Closed);
    assert(early.allocatedUserId() == 0U);
    assert(early.pendingJoinConfirmation().empty());
    assert(early.onDomainPdu(joinIo) == McsSessionIntake::Closed);
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
    {
        McsChannelJoinWriteGate gate;
        auto finalUserJoin = join;
        finalUserJoin.initiator = 65536U;
        assert(gate.configure(65536U, channels));
        assert(gate.beginJoin(finalUserJoin) ==
               McsJoinStartOutcome::ReplyPending);
        assert(gate.onReplyBytesWritten(
                   gate.pendingReplySequence(),
                   gate.pendingWriteSliceSequence(),
                   gate.pendingBytes().size()) ==
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
    // This behavior is selected by the sanitizer lane. Reuse the focused
    // UserId-range conformance routine so every corrected production branch
    // receives ASan/UBSan coverage without adding another CI selector owner.
    testMcsRdpUserIdRangeConformance();

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
    const auto truncated = std::span(join).first(6);
    assert(parseMcsChannelRequest(truncated).error ==
           McsChannelParseError::InvalidTransport);
    assert(bad.onDomainPdu(truncated) ==
           McsSessionIntake::InvalidDomainTransport);
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

void testMcsSessionUnadmittedDomainSizeBounds()
{
    // The R1 first-MCS intake budget also bounds unsolicited domain PDUs
    // before any genuine R2 OS admission. Unlike a malformed TPKT,
    // these are VALID client SendDataRequest envelopes; the denial must
    // happen before full PER parsing in this one R3 session owner.
    constexpr std::size_t maximum = kMaximumInitialMcsTpktBytes;
    static_assert(maximum == 8192U);
    const auto makeSendData = [](std::size_t packetLength)
    {
        assert(packetLength >= 15U && packetLength <= 16398U);
        const std::size_t dataLength = packetLength - 15U;
        std::vector<std::uint8_t> packet(packetLength, 0x5a);
        packet[0] = 0x03;
        packet[1] = 0x00;
        packet[2] = static_cast<std::uint8_t>(packetLength >> 8U);
        packet[3] = static_cast<std::uint8_t>(packetLength);
        packet[4] = 0x02;
        packet[5] = 0xf0;
        packet[6] = 0x80;
        packet[7] = 0x64; // T.125 client SendDataRequest
        packet[8] = 0x00;
        packet[9] = 0x06; // UserId 1007 minus PER first UserId 1001
        packet[10] = 0x03;
        packet[11] = 0xeb; // channel 1003, not an authorized join
        packet[12] = 0x70; // priority 1, segmentation 3, reserved 0
        packet[13] = static_cast<std::uint8_t>(
            0x80U | (dataLength >> 8U)); // 14-bit PER length
        packet[14] = static_cast<std::uint8_t>(dataLength);
        return packet;
    };

    for (const std::size_t size : std::array<std::size_t, 4>{
             maximum - 1U, maximum, maximum + 1U, 16398U})
    {
        const auto wire = makeSendData(size);
        // A complete syntactically valid PDU cannot authorize an R3
        // channel, regardless of whether it exceeds the intake budget.
        const auto decoded = parseMcsChannelRequest(wire);
        assert(decoded);
        assert(decoded.request.kind == McsChannelRequestKind::SendDataRequest);
        assert(decoded.request.userData.size() == size - 15U);

        McsSessionLifecycle session;
        const auto outcome = session.onDomainPdu(wire);
        assert(outcome == (size > maximum
                              ? McsSessionIntake::OversizedEnvelope
                              : McsSessionIntake::ValidButNotAdmitted));
        assert(session.phase() == McsSessionPhase::Closed);
        assert(session.pendingJoinConfirmation().empty());
        assert(!session.channelJoinConfirmed(1003));
        assert(session.onDomainPdu(wire) == McsSessionIntake::Closed);
        assert(session.onConnectInitial(publishedFixture()) ==
               McsSessionIntake::Closed);
    }

    // Even a large frame with invalid TPKT syntax is rejected at the
    // outer R3 budget boundary, not passed to the borrowed PER parser.
    std::vector<std::uint8_t> invalidHuge(65536U, 0xff);
    McsSessionLifecycle huge;
    assert(huge.onDomainPdu(invalidHuge) ==
           McsSessionIntake::OversizedEnvelope);
    assert(huge.phase() == McsSessionPhase::Closed);

    constexpr std::array<std::uint8_t, 9> disconnect{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};
    McsSessionLifecycle peer;
    assert(peer.onDomainPdu(disconnect) ==
           McsSessionIntake::PeerDisconnected);
    assert(peer.onDomainPdu(disconnect) == McsSessionIntake::Closed);
}

void testMcsSessionFirstFailureBoundaries()
{
    // The one R3 owner reports the FIRST failing Connect-Initial layer
    // without exposing borrowed GCC bytes or granting R2 admission.
    // Reuse the checked-in Microsoft 4.1.3 packet and production decoders.
    const auto valid = publishedFixture();
    const auto expectTerminal = [&](std::span<const std::uint8_t> packet,
                                    McsSessionIntake expected)
    {
        McsSessionLifecycle session;
        assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
        assert(session.onConnectInitial(packet) == expected);
        assert(session.phase() == McsSessionPhase::Closed);
        assert(session.pendingJoinConfirmation().empty());
        assert(!session.channelJoinConfirmed(1003));
        assert(session.onConnectInitial(valid) == McsSessionIntake::Closed);
        assert(session.pendingJoinConfirmation().empty());
    };

    expectTerminal(valid, McsSessionIntake::ValidButNotAdmitted);

    auto syntax = valid;
    syntax[7] = 0x7e; // wrong BER Connect-Initial tag
    assert(!parseMcsConnectInitial(syntax));
    expectTerminal(syntax, McsSessionIntake::InvalidEnvelope);

    auto negotiation = valid;
    negotiation[47] = 3;  // target protocol version
    negotiation[74] = 3;  // minimum protocol version
    negotiation[104] = 3; // maximum protocol version
    const auto syntacticallyValid = parseMcsConnectInitial(negotiation);
    assert(syntacticallyValid);
    assert(!mergeMcsDomainParameters(syntacticallyValid.value));
    expectTerminal(negotiation, McsSessionIntake::InvalidDomainParameters);

    auto gccCorrupt = valid;
    const auto parsedValid = parseMcsConnectInitial(gccCorrupt);
    assert(parsedValid);
    const auto gccOffset = static_cast<std::size_t>(
        parsedValid.value.gccUserData.data() - gccCorrupt.data());
    assert(gccOffset + 3U < gccCorrupt.size());
    gccCorrupt[gccOffset + 3U] = 0; // invalid GCC t124Identifier
    const auto parsedGccCorrupt = parseMcsConnectInitial(gccCorrupt);
    assert(parsedGccCorrupt);
    assert(mergeMcsDomainParameters(parsedGccCorrupt.value));
    assert(!parseGccConferenceCreate(parsedGccCorrupt.value.gccUserData));
    expectTerminal(gccCorrupt, McsSessionIntake::InvalidGccUserData);

    // R3's independent size guard wins before any BER, merge or GCC
    // inspection, and late callbacks cannot replace the denial result.
    std::vector<std::uint8_t> large(8193U, 0xff);
    expectTerminal(large, McsSessionIntake::OversizedEnvelope);
}


void testMcsSessionDomainFailureBoundaries()
{
    constexpr std::array<std::uint8_t, 12> validJoin{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 9> disconnect{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};

    const auto expectTerminal = [&](std::span<const std::uint8_t> packet,
                                    McsSessionIntake expected)
    {
        McsSessionLifecycle session;
        assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
        assert(session.onDomainPdu(packet) == expected);
        assert(session.phase() == McsSessionPhase::Closed);
        assert(session.pendingJoinConfirmation().empty());
        assert(!session.channelJoinConfirmed(1003));
        assert(session.onDomainPdu(validJoin) == McsSessionIntake::Closed);
    };

    assert(parseMcsChannelRequest(validJoin));
    expectTerminal(validJoin, McsSessionIntake::ValidButNotAdmitted);

    auto badTransport = validJoin;
    badTransport[5] = 0xe0;
    assert(parseMcsChannelRequest(badTransport).error ==
           McsChannelParseError::InvalidTransport);
    expectTerminal(badTransport, McsSessionIntake::InvalidDomainTransport);

    auto badDomain = validJoin;
    badDomain[7] = 0x28;
    assert(parseMcsChannelRequest(badDomain).error ==
           McsChannelParseError::InvalidDomainPdu);
    expectTerminal(badDomain, McsSessionIntake::InvalidDomainPdu);

    auto badPer = validJoin;
    badPer[8] = 0xff;
    badPer[9] = 0xff;
    assert(parseMcsChannelRequest(badPer).error ==
           McsChannelParseError::InvalidPerValue);
    expectTerminal(badPer, McsSessionIntake::InvalidDomainPerValue);

    std::vector<std::uint8_t> oversized(kMaximumInitialMcsTpktBytes + 1U,
                                        0xff);
    expectTerminal(oversized, McsSessionIntake::OversizedEnvelope);

    McsSessionLifecycle peer;
    assert(peer.onDomainPdu(disconnect) ==
           McsSessionIntake::PeerDisconnected);
    assert(peer.phase() == McsSessionPhase::Closed);
    assert(peer.onDomainPdu(validJoin) == McsSessionIntake::Closed);
}

void testInputMutationsRemainBounded()
{
    const auto baseline = publishedFixture();

    // The parser contract is one complete TPKT. Every fragmented/truncated
    // prefix must remain incomplete; R10's fixed-capacity frame reader owns
    // cross-read assembly before this R3 parser is invoked.
    for (std::size_t length = 0U; length < baseline.size(); ++length)
    {
        assert(!parseMcsConnectInitial(std::span(baseline).first(length)));
    }

    // A coalesced duplicate packet is not one complete TPKT and must not be
    // silently consumed as the first packet. The frame reader is responsible
    // for splitting coalesced TLS plaintext at exact TPKT boundaries.
    auto coalesced = baseline;
    coalesced.insert(coalesced.end(), baseline.begin(), baseline.end());
    assert(!parseMcsConnectInitial(coalesced));

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


void appendLicensingLe16(std::vector<std::uint8_t> &bytes,
                         std::uint16_t value)
{
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void appendLicensingLe32(std::vector<std::uint8_t> &bytes,
                         std::uint32_t value)
{
    appendLicensingLe16(bytes, static_cast<std::uint16_t>(value));
    appendLicensingLe16(bytes, static_cast<std::uint16_t>(value >> 16U));
}

void appendLicensingBlob(std::vector<std::uint8_t> &bytes,
                         std::uint16_t type,
                         std::span<const std::uint8_t> payload)
{
    assert(payload.size() <= 65535U);
    appendLicensingLe16(bytes, type);
    appendLicensingLe16(
        bytes, static_cast<std::uint16_t>(payload.size()));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
}

void appendLicensingBlob(std::vector<std::uint8_t> &bytes,
                         std::uint16_t type,
                         std::initializer_list<std::uint8_t> payload)
{
    appendLicensingBlob(
        bytes, type,
        std::span<const std::uint8_t>{payload.begin(), payload.size()});
}

void finishLicensingMessageSize(std::vector<std::uint8_t> &bytes)
{
    assert(bytes.size() >= 4U && bytes.size() <= 65535U);
    const auto length = static_cast<std::uint16_t>(bytes.size());
    bytes[2] = static_cast<std::uint8_t>(length);
    bytes[3] = static_cast<std::uint8_t>(length >> 8U);
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientNewLicenseRequest()
{
    std::vector<std::uint8_t> message{0x13, 0x83, 0x00, 0x00};
    appendLicensingLe32(message, 1U);          // KEY_EXCHANGE_ALG_RSA
    appendLicensingLe32(message, 0x04010000U); // Microsoft WinNT platform
    for (std::uint8_t value = 0; value < 32U; ++value)
        message.push_back(value);

    appendLicensingBlob(message, 0x0002U, {0x11, 0x22, 0x33});
    appendLicensingBlob(
        message, 0x000fU, {0x75, 0x73, 0x65, 0x72, 0x00});
    appendLicensingBlob(
        message, 0x0010U, {0x68, 0x6f, 0x73, 0x74, 0x00});
    finishLicensingMessageSize(message);
    return message;
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientNewLicenseRequestWithKeyExchange(
    std::span<const std::uint8_t> clientRandom,
    std::span<const std::uint8_t> encryptedPreMasterSecret)
{
    assert(clientRandom.size() == kRdpLicensingRandomBytes);
    std::vector<std::uint8_t> message{0x13, 0x83, 0x00, 0x00};
    appendLicensingLe32(message, 1U);
    appendLicensingLe32(message, 0x04010000U);
    message.insert(
        message.end(), clientRandom.begin(), clientRandom.end());
    appendLicensingBlob(message, 0x0002U, encryptedPreMasterSecret);
    appendLicensingBlob(
        message, 0x000fU, {0x75, 0x73, 0x65, 0x72, 0x00});
    appendLicensingBlob(
        message, 0x0010U, {0x68, 0x6f, 0x73, 0x74, 0x00});
    finishLicensingMessageSize(message);
    return message;
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientLicenseInfoWithHardwareProof(
    std::span<const std::uint8_t> encryptedHardwareId,
    std::span<const std::uint8_t> macData,
    std::span<const std::uint8_t> licenseInfo)
{
    assert(encryptedHardwareId.size() == kRdpLicensingHardwareIdBytes);
    assert(macData.size() == kRdpLicensingMacBytes);
    assert(!licenseInfo.empty() && licenseInfo.size() <= 65535U);

    std::vector<std::uint8_t> message{0x12, 0x03, 0x00, 0x00};
    appendLicensingLe32(message, 1U);
    appendLicensingLe32(message, 0x04010000U);
    for (std::uint8_t value = 0; value < 32U; ++value)
        message.push_back(static_cast<std::uint8_t>(0xa0U + value));

    appendLicensingBlob(message, 0x0002U, {0x31, 0x32});
    appendLicensingBlob(message, 0x0001U, licenseInfo);
    appendLicensingBlob(message, 0x0001U, encryptedHardwareId);
    message.insert(message.end(), macData.begin(), macData.end());
    finishLicensingMessageSize(message);
    return message;
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientLicenseInfoWithHardwareProof(
    std::span<const std::uint8_t> encryptedHardwareId,
    std::span<const std::uint8_t> macData)
{
    constexpr std::array<std::uint8_t, 3> placeholderLicenseInfo{
        0x41, 0x42, 0x43};
    return makeClientLicenseInfoWithHardwareProof(
        encryptedHardwareId, macData, placeholderLicenseInfo);
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientLicenseInfo()
{
    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> encryptedHardwareId{};
    std::array<std::uint8_t, kRdpLicensingMacBytes> macData{};
    for (std::size_t index = 0U; index < encryptedHardwareId.size(); ++index)
        encryptedHardwareId[index] =
            static_cast<std::uint8_t>(0x40U + index);
    for (std::size_t index = 0U; index < macData.size(); ++index)
        macData[index] = static_cast<std::uint8_t>(0x80U + index);
    return makeClientLicenseInfoWithHardwareProof(
        encryptedHardwareId, macData);
}

[[nodiscard]] std::vector<std::uint8_t>
makeEnhancedSecurityClientLicensingEnvelope(
    std::span<const std::uint8_t> licensingMessage,
    std::uint16_t flags = 0x0080U,
    std::uint16_t flagsHi = 0U)
{
    std::vector<std::uint8_t> envelope{
        static_cast<std::uint8_t>(flags),
        static_cast<std::uint8_t>(flags >> 8U),
        static_cast<std::uint8_t>(flagsHi),
        static_cast<std::uint8_t>(flagsHi >> 8U)};
    envelope.insert(
        envelope.end(), licensingMessage.begin(), licensingMessage.end());
    return envelope;
}

void testRdpClientLicensingEnvelopeWire()
{
    const auto newRequest = makeClientNewLicenseRequest();
    const auto newEnvelope =
        makeEnhancedSecurityClientLicensingEnvelope(newRequest, 0x0080U, 0x5aa5U);
    const auto parsed = parseEnhancedSecurityLicensingEnvelope(newEnvelope);
    assert(parsed);
    assert(parsed.value.flags == 0x0080U);
    assert(parsed.value.flagsHi == 0x5aa5U);
    assert(parsed.value.licensingMessage.size() == newRequest.size());
    assert(parsed.value.licensingMessage.data() == newEnvelope.data() + 4U);
    const auto parsedRequest =
        parseRdpLicensingMessage(parsed.value.licensingMessage);
    assert(parsedRequest);
    assert(parsedRequest.value.type ==
           RdpLicensingMessageType::ClientNewLicenseRequest);

    const auto licenseInfo = makeClientLicenseInfo();
    const auto infoEnvelope =
        makeEnhancedSecurityClientLicensingEnvelope(licenseInfo);
    const auto parsedInfo =
        parseEnhancedSecurityLicensingEnvelope(infoEnvelope);
    assert(parsedInfo);
    assert(parseRdpLicensingMessage(parsedInfo.value.licensingMessage)
               .value.type == RdpLicensingMessageType::ClientLicenseInfo);

    // RESET/IGNORE and FLAGSHI_VALID are permitted/ignored by the Basic
    // Security Header rules; flagsHi remains opaque.
    const auto ignored = makeEnhancedSecurityClientLicensingEnvelope(
        newRequest, 0x80b0U, 0xcafeU);
    const auto parsedIgnored =
        parseEnhancedSecurityLicensingEnvelope(ignored);
    assert(parsedIgnored);
    assert(parsedIgnored.value.flags == 0x80b0U);
    assert(parsedIgnored.value.flagsHi == 0xcafeU);
}

void testRdpClientLicensingEnvelopeDenials()
{
    const auto request = makeClientNewLicenseRequest();
    const auto valid = makeEnhancedSecurityClientLicensingEnvelope(request);

    for (std::size_t size = 0U; size < 4U; ++size)
    {
        const auto parsed = parseEnhancedSecurityLicensingEnvelope(
            std::span(valid).first(size));
        assert(!parsed);
        assert(parsed.error ==
               RdpLicensingEnvelopeError::TruncatedSecurityHeader);
    }
    for (std::size_t size = 4U; size < 8U; ++size)
    {
        const auto parsed = parseEnhancedSecurityLicensingEnvelope(
            std::span(valid).first(size));
        assert(!parsed);
        assert(parsed.error ==
               RdpLicensingEnvelopeError::TruncatedLicensingMessage);
    }

    const auto rejectsFlags = [&](std::uint16_t flags)
    {
        const auto envelope =
            makeEnhancedSecurityClientLicensingEnvelope(request, flags);
        const auto parsed =
            parseEnhancedSecurityLicensingEnvelope(envelope);
        assert(!parsed);
        assert(parsed.error ==
               RdpLicensingEnvelopeError::InvalidSecurityFlags);
    };

    rejectsFlags(0x0000U); // missing SEC_LICENSE_PKT
    rejectsFlags(0x0040U); // SEC_INFO_PKT instead of licensing
    rejectsFlags(0x00c0U); // conflicting INFO + LICENSE packet kinds
    rejectsFlags(0x0088U); // Standard-Security SEC_ENCRYPT
    rejectsFlags(0x0081U); // Security Exchange mixed with licensing
    rejectsFlags(0x0280U); // client licensing-encryption ability is not a PDU flag
    rejectsFlags(0x0480U); // redirection/competing packet kind
    rejectsFlags(0x0880U); // secure-checksum path is unsupported here
}

constexpr std::array<std::uint8_t, 32> kServerLicenseRandom{
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20};
constexpr std::array<std::uint8_t, 8> kServerLicenseCompany{
    0x52,0x00,0x44,0x00,0x50,0x00,0x00,0x00};
constexpr std::array<std::uint8_t, 8> kServerLicenseProduct{
    0x41,0x00,0x30,0x00,0x32,0x00,0x00,0x00};
// Opaque serializer fixture only. It is deliberately not presented as a
// genuine licensing certificate/private-key pair.
constexpr std::array<std::uint8_t, 4> kServerLicenseCertificate{
    0xde,0xad,0xbe,0xef};
constexpr std::array<std::uint8_t, 6> kServerLicenseScope{
    0x73,0x63,0x6f,0x70,0x65,0x00};

[[nodiscard]] RdpServerLicenseRequestFields serverLicenseFields() noexcept
{
    return {
        kServerLicenseRandom,
        0x00060001U,
        kServerLicenseCompany,
        kServerLicenseProduct,
        kServerLicenseCertificate,
        kServerLicenseScope};
}

[[nodiscard]] bool configureServerLicenseIdentity(
    RdpServerLicenseIdentity &identity) noexcept
{
    return identity.configure(
        0x00060001U,
        kServerLicenseCompany,
        kServerLicenseProduct,
        kServerLicenseCertificate,
        kServerLicenseScope);
}

[[nodiscard]] bool deliverServerLicenseRequest(
    RdpLicensingLifecycle &lifecycle) noexcept
{
    RdpServerLicenseIdentity identity;
    if (!configureServerLicenseIdentity(identity))
        return false;
    RdpServerLicenseRequestWriteGate writer{lifecycle};
    if (!writer.queue(identity))
        return false;
    const auto pending = writer.pendingWrite();
    return pending &&
           writer.onBytesWritten(
               pending.replySequence,
               pending.writeSliceSequence,
               pending.bytes.size()) ==
               RdpServerLicenseRequestWriteOutcome::Delivered;
}

void testPersonalDesktopNoCalValidClientCompletion()
{
    RdpLicensingLifecycle lifecycle{
        RdpLicensingProtocolMode::PersonalDesktop};
    assert(deliverServerLicenseRequest(lifecycle));
    assert(lifecycle.onClientMessage(makeClientNewLicenseRequest()) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::
               PersonalDesktopCompletionRequired);

    RdpPersonalDesktopValidClientWriteGate gate{lifecycle};
    assert(gate.queue(1003U));
    const auto pending = gate.pendingWrite();
    assert(pending);
    constexpr std::array<std::uint8_t,
        kRdpPersonalDesktopValidClientPacketBytes> expected{{
        0x03,0x00,0x00,0x22,0x02,0xf0,0x80,
        0x68,0x00,0x01,0x03,0xeb,0x70,0x14,
        0x80,0x00,0x00,0x00,
        0xff,0x03,0x10,0x00,
        0x07,0x00,0x00,0x00,
        0x02,0x00,0x00,0x00,
        0x04,0x00,0x00,0x00
    }};
    assert(pending.bytes.size() == expected.size());
    assert(std::equal(
        pending.bytes.begin(), pending.bytes.end(), expected.begin()));

    assert(gate.onBytesWritten(
               pending.replySequence,
               pending.writeSliceSequence, 0U) ==
           RdpPersonalDesktopValidClientWriteOutcome::Pending);
    const auto retry = gate.pendingWrite();
    assert(retry);
    assert(retry.replySequence == pending.replySequence);
    assert(retry.writeSliceSequence == pending.writeSliceSequence);
    assert(retry.bytes.data() == pending.bytes.data());

    assert(gate.onBytesWritten(
               retry.replySequence,
               retry.writeSliceSequence,
               retry.bytes.size()) ==
           RdpPersonalDesktopValidClientWriteOutcome::Delivered);
    assert(!gate.pendingWrite());
    assert(lifecycle.phase() == RdpLicensingPhase::Licensed);
}

void testPersonalDesktopPresentedCalValidClientCompletion()
{
    const auto presented = makeClientLicenseInfo();
    RdpLicensingLifecycle lifecycle{
        RdpLicensingProtocolMode::PersonalDesktop};
    assert(deliverServerLicenseRequest(lifecycle));
    assert(lifecycle.onClientMessage(presented) ==
           RdpLicensingIntake::ClientLicenseInfoAccepted);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::
               PersonalDesktopCompletionRequired);

    RdpPersonalDesktopValidClientWriteGate gate{lifecycle};
    assert(gate.queue(1003U));
    const auto pending = gate.pendingWrite();
    assert(pending);
    assert(gate.onBytesWritten(
               pending.replySequence,
               pending.writeSliceSequence,
               pending.bytes.size()) ==
           RdpPersonalDesktopValidClientWriteOutcome::Delivered);
    assert(lifecycle.phase() == RdpLicensingPhase::Licensed);
}

void testPersonalDesktopModeAndMalformedDenials()
{
    {
        RdpLicensingLifecycle applicationServer;
        assert(deliverServerLicenseRequest(applicationServer));
        assert(applicationServer.onClientMessage(
                   makeClientNewLicenseRequest()) ==
               RdpLicensingIntake::ClientNewLicenseRequestAccepted);
        assert(applicationServer.decisionBranch() ==
               RdpLicensingDecisionBranch::PlatformChallengeRequired);
        RdpPersonalDesktopValidClientWriteGate wrongMode{
            applicationServer};
        assert(!wrongMode.queue(1003U));
        assert(applicationServer.phase() == RdpLicensingPhase::Closed);
    }

    {
        RdpLicensingLifecycle personal{
            RdpLicensingProtocolMode::PersonalDesktop};
        assert(deliverServerLicenseRequest(personal));
        auto malformed = makeClientNewLicenseRequest();
        malformed.pop_back();
        assert(personal.onClientMessage(malformed) ==
               RdpLicensingIntake::MalformedMessage);
        assert(personal.phase() == RdpLicensingPhase::Failed);
        RdpPersonalDesktopValidClientWriteGate denied{personal};
        assert(!denied.queue(1003U));
    }
}

void testPersonalDesktopDuplicateAndPartialRevocation()
{
    {
        RdpLicensingLifecycle lifecycle{
            RdpLicensingProtocolMode::PersonalDesktop};
        assert(deliverServerLicenseRequest(lifecycle));
        assert(lifecycle.onClientMessage(
                   makeClientNewLicenseRequest()) ==
               RdpLicensingIntake::ClientNewLicenseRequestAccepted);
        RdpPersonalDesktopValidClientWriteGate gate{lifecycle};
        assert(gate.queue(1003U));
        const auto pending = gate.pendingWrite();
        assert(gate.onBytesWritten(
                   pending.replySequence,
                   pending.writeSliceSequence,
                   pending.bytes.size()) ==
               RdpPersonalDesktopValidClientWriteOutcome::Delivered);
        assert(lifecycle.phase() == RdpLicensingPhase::Licensed);

        RdpPersonalDesktopValidClientWriteGate duplicate{lifecycle};
        assert(!duplicate.queue(1003U));
        assert(lifecycle.phase() == RdpLicensingPhase::Closed);
    }

    {
        RdpLicensingLifecycle lifecycle{
            RdpLicensingProtocolMode::PersonalDesktop};
        assert(deliverServerLicenseRequest(lifecycle));
        assert(lifecycle.onClientMessage(
                   makeClientNewLicenseRequest()) ==
               RdpLicensingIntake::ClientNewLicenseRequestAccepted);
        RdpPersonalDesktopValidClientWriteGate gate{lifecycle};
        assert(gate.queue(1003U));
        const auto first = gate.pendingWrite();
        constexpr std::size_t partialBytes = 7U;
        assert(gate.onBytesWritten(
                   first.replySequence,
                   first.writeSliceSequence,
                   partialBytes) ==
               RdpPersonalDesktopValidClientWriteOutcome::Pending);
        const auto remaining = gate.pendingWrite();
        assert(remaining);
        assert(remaining.replySequence == first.replySequence);
        assert(remaining.writeSliceSequence !=
               first.writeSliceSequence);
        assert(remaining.bytes.size() ==
               first.bytes.size() - partialBytes);

        gate.close();
        assert(lifecycle.phase() == RdpLicensingPhase::Closed);
        assert(gate.onBytesWritten(
                   remaining.replySequence,
                   remaining.writeSliceSequence,
                   remaining.bytes.size()) ==
               RdpPersonalDesktopValidClientWriteOutcome::Rejected);
        assert(!gate.pendingWrite());
    }
}

void testRdpServerLicenseRequestWire()
{
    constexpr std::array<std::uint8_t, 94> expected{
        0x01,0x83,0x5e,0x00,
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
        0x01,0x00,0x06,0x00,
        0x08,0x00,0x00,0x00,
        0x52,0x00,0x44,0x00,0x50,0x00,0x00,0x00,
        0x08,0x00,0x00,0x00,
        0x41,0x00,0x30,0x00,0x32,0x00,0x00,0x00,
        0x0d,0x00,0x04,0x00,0x01,0x00,0x00,0x00,
        0x03,0x00,0x04,0x00,0xde,0xad,0xbe,0xef,
        0x01,0x00,0x00,0x00,
        0x0e,0x00,0x06,0x00,0x73,0x63,0x6f,0x70,0x65,0x00};

    std::array<std::uint8_t, kMaximumRdpServerLicenseRequestBytes> output{};
    const auto encoded =
        encodeEnhancedSecurityServerLicenseRequest(serverLicenseFields(), output);
    assert(encoded);
    assert(encoded.bytesWritten == expected.size());
    assert(std::equal(expected.begin(), expected.end(), output.begin()));

    const auto parsed = parseRdpLicensingMessage(
        std::span(output).first(encoded.bytesWritten));
    assert(parsed);
    assert(parsed.value.type == RdpLicensingMessageType::ServerLicenseRequest);
    assert(parsed.value.protocolVersion == 3U);
    assert(parsed.value.extendedErrorSupported);
}

void testRdpServerLicenseIdentityConfiguration()
{
    auto company = kServerLicenseCompany;
    auto product = kServerLicenseProduct;
    auto certificate = kServerLicenseCertificate;
    auto scope = kServerLicenseScope;

    RdpServerLicenseIdentity identity;
    assert(identity.configure(
        0x00060001U, company, product, certificate, scope));
    assert(identity.configured());
    assert(identity.productVersion() == 0x00060001U);
    assert(std::equal(
        identity.companyNameUtf16().begin(),
        identity.companyNameUtf16().end(),
        kServerLicenseCompany.begin()));
    assert(std::equal(
        identity.productIdUtf16().begin(),
        identity.productIdUtf16().end(),
        kServerLicenseProduct.begin()));
    assert(std::equal(
        identity.serverCertificate().begin(),
        identity.serverCertificate().end(),
        kServerLicenseCertificate.begin()));
    assert(std::equal(
        identity.scopeAnsi().begin(),
        identity.scopeAnsi().end(),
        kServerLicenseScope.begin()));

    // Caller storage is not retained and cannot mutate live provisioning.
    company[0] = 0xffU;
    product[0] = 0xeeU;
    certificate[0] = 0xccU;
    scope[0] = 0xddU;
    assert(identity.companyNameUtf16().front() ==
           kServerLicenseCompany.front());
    assert(identity.productIdUtf16().front() ==
           kServerLicenseProduct.front());
    assert(identity.serverCertificate().front() ==
           kServerLicenseCertificate.front());
    assert(identity.scopeAnsi().front() == kServerLicenseScope.front());

    assert(!identity.configure(
        0x00070001U, kServerLicenseCompany,
        kServerLicenseProduct, kServerLicenseCertificate,
        kServerLicenseScope));
    assert(identity.productVersion() == 0x00060001U);

    RdpServerLicenseIdentity zeroVersion;
    assert(!zeroVersion.configure(
        0U, kServerLicenseCompany,
        kServerLicenseProduct, kServerLicenseCertificate,
        kServerLicenseScope));

    RdpServerLicenseIdentity oddCompany;
    assert(!oddCompany.configure(
        0x00060001U,
        std::span(kServerLicenseCompany).first(
            kServerLicenseCompany.size() - 1U),
        kServerLicenseProduct, kServerLicenseCertificate,
        kServerLicenseScope));

    auto embeddedZeroCompany = kServerLicenseCompany;
    embeddedZeroCompany[2] = 0U;
    embeddedZeroCompany[3] = 0U;
    RdpServerLicenseIdentity embeddedZero;
    assert(!embeddedZero.configure(
        0x00060001U, embeddedZeroCompany,
        kServerLicenseProduct, kServerLicenseCertificate,
        kServerLicenseScope));

    RdpServerLicenseIdentity missingScopeTerminator;
    assert(!missingScopeTerminator.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        kServerLicenseCertificate,
        std::span(kServerLicenseScope).first(
            kServerLicenseScope.size() - 1U)));

    std::array<std::uint8_t,
               kMaximumRdpServerLicenseIdentityTextBytes + 2U>
        oversizedCompany{};
    oversizedCompany[0] = 0x41U;
    oversizedCompany[1] = 0x00U;
    RdpServerLicenseIdentity oversized;
    assert(!oversized.configure(
        0x00060001U, oversizedCompany,
        kServerLicenseProduct, kServerLicenseCertificate,
        kServerLicenseScope));
}

void testRdpServerLicenseRequestCertificateRequired()
{
    std::array<std::uint8_t, 128> output{};
    output.fill(0xa5U);
    auto fields = serverLicenseFields();
    fields.serverCertificate = {};
    assert(encodeEnhancedSecurityServerLicenseRequest(fields, output).error ==
           RdpServerLicenseRequestEncodeError::InvalidServerCertificate);
    assert(std::all_of(
        output.begin(), output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));

    // In this Enhanced-Security path SC_SECURITY contains no certificate, so
    // live provisioning may not rely on an absent fallback certificate.
    RdpServerLicenseIdentity missingCertificate;
    assert(!missingCertificate.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        {}, kServerLicenseScope));
    assert(!missingCertificate.configured());

    RdpLicensingLifecycle lifecycle;
    RdpServerLicenseRequestWriteGate writer{lifecycle};
    assert(!writer.queue(missingCertificate));
    assert(lifecycle.phase() == RdpLicensingPhase::Closed);

    std::array<std::uint8_t,
               kMaximumRdpServerLicenseCertificateBytes + 1U>
        oversizedCertificate{};
    RdpServerLicenseIdentity oversized;
    assert(!oversized.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        oversizedCertificate, kServerLicenseScope));
}

void testRdpNewLicenseInformationWire()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    constexpr std::array<std::uint8_t, 5> issuedCal{
        0x30,0x03,0x02,0x01,0x01};
    constexpr std::array<std::uint8_t, 47> expected{
        0x01,0x00,0x06,0x00,
        0x06,0x00,0x00,0x00,
        0x73,0x63,0x6f,0x70,0x65,0x00,
        0x08,0x00,0x00,0x00,
        0x52,0x00,0x44,0x00,0x50,0x00,0x00,0x00,
        0x08,0x00,0x00,0x00,
        0x41,0x00,0x30,0x00,0x32,0x00,0x00,0x00,
        0x05,0x00,0x00,0x00,
        0x30,0x03,0x02,0x01,0x01};

    std::array<std::uint8_t, 64> output{};
    output.fill(0xa5U);
    const auto encoded =
        encodeRdpNewLicenseInformation(identity, issuedCal, output);
    assert(encoded);
    assert(encoded.bytesWritten == expected.size());
    assert(std::equal(expected.begin(), expected.end(), output.begin()));
    assert(std::all_of(
        output.begin() + static_cast<std::ptrdiff_t>(expected.size()),
        output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));
}

void testRdpNewLicenseInformationDenials()
{
    constexpr std::array<std::uint8_t, 5> issuedCal{
        0x30,0x03,0x02,0x01,0x01};
    std::array<std::uint8_t, 64> output{};
    output.fill(0xa5U);

    RdpServerLicenseIdentity unconfigured;
    assert(encodeRdpNewLicenseInformation(
               unconfigured, issuedCal, output).error ==
           RdpNewLicenseInfoEncodeError::IdentityNotConfigured);
    assert(std::all_of(
        output.begin(), output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));

    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    assert(encodeRdpNewLicenseInformation(
               identity, {}, output).error ==
           RdpNewLicenseInfoEncodeError::InvalidLicense);

    std::vector<std::uint8_t> oversized(
        kMaximumRdpIssuedCalBytes + 1U, 0x42U);
    assert(encodeRdpNewLicenseInformation(
               identity, oversized, output).error ==
           RdpNewLicenseInfoEncodeError::Oversized);

    std::array<std::uint8_t, 46> tooSmall{};
    tooSmall.fill(0x5aU);
    assert(encodeRdpNewLicenseInformation(
               identity, issuedCal, tooSmall).error ==
           RdpNewLicenseInfoEncodeError::OutputTooSmall);
    assert(std::all_of(
        tooSmall.begin(), tooSmall.end(),
        [](std::uint8_t value) { return value == 0x5aU; }));

    // The serializer deliberately treats CAL bytes as opaque authority output.
    // Structural packaging must neither reinterpret nor manufacture them.
    constexpr std::array<std::uint8_t, 5> opaqueWithZeros{
        0x00,0xff,0x00,0x7f,0x00};
    const auto opaque =
        encodeRdpNewLicenseInformation(identity, opaqueWithZeros, output);
    assert(opaque);
    assert(std::equal(
        opaqueWithZeros.begin(), opaqueWithZeros.end(),
        output.begin() +
            static_cast<std::ptrdiff_t>(
                opaque.bytesWritten - opaqueWithZeros.size())));
}

[[nodiscard]] RdpLicensingKeyMaterial
platformChallengeKeys() noexcept;

void testRdpLicensingAuthorityGrantBoundary()
{
    static_assert(!std::is_copy_constructible_v<RdpLicensingAuthorityGrant>);
    static_assert(!std::is_copy_assignable_v<RdpLicensingAuthorityGrant>);
    static_assert(!std::is_move_constructible_v<RdpLicensingAuthorityGrant>);
    static_assert(!std::is_move_assignable_v<RdpLicensingAuthorityGrant>);

    constexpr std::uint64_t authorityGeneration = 7U;
    std::array<std::uint8_t, kRdpLicensingAuthorityFingerprintBytes>
        authorityFingerprint{};
    for (std::size_t index = 0U; index < authorityFingerprint.size(); ++index)
        authorityFingerprint[index] =
            static_cast<std::uint8_t>(0x40U + index);

    std::array<std::uint8_t, 5> issuedCal{
        0x30,0x03,0x02,0x01,0x01};
    const auto expectedFingerprint = authorityFingerprint;
    const auto expectedCal = issuedCal;

    RdpLicensingAuthorityGrant grant;
    assert(grant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               authorityGeneration,
               authorityFingerprint,
               issuedCal) ==
           RdpLicensingAuthorityGrantError::None);
    assert(grant.configured());
    assert(grant.kind() == RdpServerLicenseGrantKind::NewLicense);
    assert(grant.authorityGeneration() == authorityGeneration);
    assert(grant.matchesAuthority(
        authorityGeneration, authorityFingerprint));
    assert(!grant.matchesAuthority(
        authorityGeneration + 1U, authorityFingerprint));

    auto wrongFingerprint = authorityFingerprint;
    wrongFingerprint.back() ^= 0x01U;
    assert(!grant.matchesAuthority(
        authorityGeneration, wrongFingerprint));

    // The authority snapshot owns its correlation token and CAL.
    authorityFingerprint.fill(0U);
    issuedCal.fill(0U);
    assert(std::equal(
        grant.authorityFingerprint().begin(),
        grant.authorityFingerprint().end(),
        expectedFingerprint.begin()));
    assert(std::equal(
        grant.issuedCal().begin(), grant.issuedCal().end(),
        expectedCal.begin()));

    // It composes with the existing pure grant encoder but still has no live
    // R3/R2 publication path or licensing-state side effect.
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();
    std::array<std::uint8_t, 96> encoded{};
    const auto wire = encodeRdpServerLicenseGrant(
        grant.kind(), identity, grant.issuedCal(), keys, encoded);
    assert(wire);
    assert(wire.bytesWritten == 71U);
    cleanseRdpLicensingKeyMaterial(keys);

    RdpLicensingLifecycle lifecycle;
    assert(lifecycle.phase() == RdpLicensingPhase::NotStarted);

    // Authority rotation cannot replace a previously returned result.
    assert(grant.configure(
               RdpServerLicenseGrantKind::UpgradeLicense,
               authorityGeneration + 1U,
               expectedFingerprint,
               expectedCal) ==
           RdpLicensingAuthorityGrantError::AlreadyConfigured);

    RdpLicensingAuthorityGrant zeroGeneration;
    assert(zeroGeneration.configure(
               RdpServerLicenseGrantKind::NewLicense,
               0U, expectedFingerprint, expectedCal) ==
           RdpLicensingAuthorityGrantError::InvalidAuthorityGeneration);

    std::array<std::uint8_t, kRdpLicensingAuthorityFingerprintBytes>
        zeroFingerprint{};
    RdpLicensingAuthorityGrant zeroFingerprintGrant;
    assert(zeroFingerprintGrant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               authorityGeneration, zeroFingerprint, expectedCal) ==
           RdpLicensingAuthorityGrantError::InvalidAuthorityFingerprint);

    RdpLicensingAuthorityGrant shortFingerprint;
    assert(shortFingerprint.configure(
               RdpServerLicenseGrantKind::NewLicense,
               authorityGeneration,
               std::span(expectedFingerprint).first(
                   expectedFingerprint.size() - 1U),
               expectedCal) ==
           RdpLicensingAuthorityGrantError::InvalidAuthorityFingerprint);

    RdpLicensingAuthorityGrant emptyCal;
    assert(emptyCal.configure(
               RdpServerLicenseGrantKind::NewLicense,
               authorityGeneration, expectedFingerprint, {}) ==
           RdpLicensingAuthorityGrantError::InvalidLicense);

    std::vector<std::uint8_t> oversizedCal(
        kMaximumRdpServerLicenseGrantCalBytes + 1U, 0x42U);
    RdpLicensingAuthorityGrant oversized;
    assert(oversized.configure(
               RdpServerLicenseGrantKind::UpgradeLicense,
               authorityGeneration, expectedFingerprint, oversizedCal) ==
           RdpLicensingAuthorityGrantError::Oversized);

    RdpLicensingAuthorityGrant invalidKind;
    assert(invalidKind.configure(
               static_cast<RdpServerLicenseGrantKind>(0x7fU),
               authorityGeneration, expectedFingerprint, expectedCal) ==
           RdpLicensingAuthorityGrantError::InvalidLicense);
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientPlatformChallengeResponse(
    std::span<const std::uint8_t> challenge,
    const RdpLicensingKeyMaterial &keys,
    std::uint16_t version,
    std::uint16_t clientType,
    std::uint16_t detailLevel);

[[nodiscard]] bool advanceToNewLicenseIssuance(
    RdpLicensingLifecycle &lifecycle,
    const RdpLicensingKeyMaterial &keys)
{
    if (!deliverServerLicenseRequest(lifecycle) ||
        lifecycle.onClientMessage(makeClientNewLicenseRequest()) !=
            RdpLicensingIntake::ClientNewLicenseRequestAccepted)
        return false;

    RdpServerPlatformChallengeWriteGate challengeWriter{lifecycle};
    if (!challengeWriter.queue(keys))
        return false;
    const auto challengeWrite = challengeWriter.pendingWrite();
    if (!challengeWrite ||
        challengeWriter.onBytesWritten(
            challengeWrite.replySequence,
            challengeWrite.writeSliceSequence,
            challengeWrite.bytes.size()) !=
            RdpServerPlatformChallengeWriteOutcome::Delivered)
        return false;

    const auto response = makeClientPlatformChallengeResponse(
        lifecycle.platformChallenge(), keys,
        0x0100U, 0x0100U, 0x0003U);
    return lifecycle.onClientPlatformChallengeResponse(response, keys) ==
               RdpLicensingIntake::ClientPlatformChallengeResponseAccepted &&
           lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision &&
           lifecycle.decisionBranch() ==
               RdpLicensingDecisionBranch::NewLicenseIssuanceRequired;
}

void testRdpServerLicenseGrantWriteReceipts()
{
    constexpr std::uint64_t authorityGeneration = 9U;
    std::array<std::uint8_t, kRdpLicensingAuthorityFingerprintBytes>
        authorityFingerprint{};
    for (std::size_t index = 0U; index < authorityFingerprint.size(); ++index)
        authorityFingerprint[index] =
            static_cast<std::uint8_t>(0x20U + index);
    constexpr std::array<std::uint8_t, 5> issuedCal{
        0x30,0x03,0x02,0x01,0x01};

    RdpLicensingAuthorityGrant grant;
    assert(grant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               authorityGeneration,
               authorityFingerprint,
               issuedCal) ==
           RdpLicensingAuthorityGrantError::None);
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    RdpLicensingLifecycle lifecycle;
    assert(advanceToNewLicenseIssuance(lifecycle, keys));
    RdpServerLicenseGrantWriteGate writer{lifecycle};
    assert(writer.queue(
        grant, identity, keys,
        authorityGeneration, authorityFingerprint));

    const auto first = writer.pendingWrite();
    assert(first);
    const auto parsed = parseRdpLicensingMessage(first.bytes);
    assert(parsed);
    assert(parsed.value.type == RdpLicensingMessageType::ServerNewLicense);

    assert(writer.onBytesWritten(
               first.replySequence, first.writeSliceSequence, 0U) ==
           RdpServerLicenseGrantWriteOutcome::Pending);
    const auto afterWant = writer.pendingWrite();
    assert(afterWant.bytes.data() == first.bytes.data());
    assert(afterWant.bytes.size() == first.bytes.size());
    assert(afterWant.replySequence == first.replySequence);
    assert(afterWant.writeSliceSequence == first.writeSliceSequence);
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);

    constexpr std::size_t firstAccepted = 13U;
    assert(writer.onBytesWritten(
               first.replySequence,
               first.writeSliceSequence,
               firstAccepted) ==
           RdpServerLicenseGrantWriteOutcome::Pending);
    const auto remainder = writer.pendingWrite();
    assert(remainder);
    assert(remainder.replySequence == first.replySequence);
    assert(remainder.writeSliceSequence != first.writeSliceSequence);
    assert(remainder.bytes.data() == first.bytes.data() + firstAccepted);
    assert(remainder.bytes.size() == first.bytes.size() - firstAccepted);
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);

    assert(writer.onBytesWritten(
               remainder.replySequence,
               remainder.writeSliceSequence,
               remainder.bytes.size()) ==
           RdpServerLicenseGrantWriteOutcome::Delivered);
    assert(!writer.pendingWrite());
    assert(lifecycle.phase() == RdpLicensingPhase::Licensed);
    assert(lifecycle.decisionBranch() == RdpLicensingDecisionBranch::None);

    cleanseRdpLicensingKeyMaterial(keys);
}

void testRdpServerLicenseGrantWriteDenials()
{
    constexpr std::uint64_t authorityGeneration = 11U;
    std::array<std::uint8_t, kRdpLicensingAuthorityFingerprintBytes>
        authorityFingerprint{};
    for (std::size_t index = 0U; index < authorityFingerprint.size(); ++index)
        authorityFingerprint[index] =
            static_cast<std::uint8_t>(0x60U + index);
    constexpr std::array<std::uint8_t, 5> issuedCal{
        0x30,0x03,0x02,0x01,0x01};

    RdpLicensingAuthorityGrant grant;
    assert(grant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               authorityGeneration,
               authorityFingerprint,
               issuedCal) ==
           RdpLicensingAuthorityGrantError::None);
    RdpLicensingAuthorityGrant upgradeGrant;
    assert(upgradeGrant.configure(
               RdpServerLicenseGrantKind::UpgradeLicense,
               authorityGeneration,
               authorityFingerprint,
               issuedCal) ==
           RdpLicensingAuthorityGrantError::None);
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    // A snapshot is not authority unless the current owner correlation matches.
    RdpLicensingLifecycle staleAuthority;
    assert(advanceToNewLicenseIssuance(staleAuthority, keys));
    RdpServerLicenseGrantWriteGate staleAuthorityWriter{staleAuthority};
    auto wrongFingerprint = authorityFingerprint;
    wrongFingerprint[0] ^= 0x80U;
    assert(!staleAuthorityWriter.queue(
        grant, identity, keys,
        authorityGeneration, wrongFingerprint));
    assert(staleAuthority.phase() == RdpLicensingPhase::Closed);

    // Upgrade License cannot use the New-License issuance branch.
    RdpLicensingLifecycle wrongKind;
    assert(advanceToNewLicenseIssuance(wrongKind, keys));
    RdpServerLicenseGrantWriteGate wrongKindWriter{wrongKind};
    assert(!wrongKindWriter.queue(
        upgradeGrant, identity, keys,
        authorityGeneration, authorityFingerprint));
    assert(wrongKind.phase() == RdpLicensingPhase::Closed);

    // A plausible authority result cannot skip the licensing decision state.
    RdpLicensingLifecycle wrongPhase;
    RdpServerLicenseGrantWriteGate wrongPhaseWriter{wrongPhase};
    assert(!wrongPhaseWriter.queue(
        grant, identity, keys,
        authorityGeneration, authorityFingerprint));
    assert(wrongPhase.phase() == RdpLicensingPhase::Closed);

    // Positive progress rotates the slice receipt; stale reuse is terminal.
    RdpLicensingLifecycle staleReceipt;
    assert(advanceToNewLicenseIssuance(staleReceipt, keys));
    RdpServerLicenseGrantWriteGate staleWriter{staleReceipt};
    assert(staleWriter.queue(
        grant, identity, keys,
        authorityGeneration, authorityFingerprint));
    const auto first = staleWriter.pendingWrite();
    assert(staleWriter.onBytesWritten(
               first.replySequence, first.writeSliceSequence, 1U) ==
           RdpServerLicenseGrantWriteOutcome::Pending);
    const auto remainder = staleWriter.pendingWrite();
    assert(remainder.writeSliceSequence != first.writeSliceSequence);
    assert(staleWriter.onBytesWritten(
               first.replySequence, first.writeSliceSequence, 1U) ==
           RdpServerLicenseGrantWriteOutcome::Rejected);
    assert(staleReceipt.phase() == RdpLicensingPhase::Closed);

    RdpLicensingLifecycle overReport;
    assert(advanceToNewLicenseIssuance(overReport, keys));
    RdpServerLicenseGrantWriteGate overWriter{overReport};
    assert(overWriter.queue(
        grant, identity, keys,
        authorityGeneration, authorityFingerprint));
    const auto overPending = overWriter.pendingWrite();
    assert(overWriter.onBytesWritten(
               overPending.replySequence,
               overPending.writeSliceSequence,
               overPending.bytes.size() + 1U) ==
           RdpServerLicenseGrantWriteOutcome::Rejected);
    assert(overReport.phase() == RdpLicensingPhase::Closed);

    // Completion is one-shot; copied receipts cannot license twice.
    RdpLicensingLifecycle duplicate;
    assert(advanceToNewLicenseIssuance(duplicate, keys));
    RdpServerLicenseGrantWriteGate duplicateWriter{duplicate};
    assert(duplicateWriter.queue(
        grant, identity, keys,
        authorityGeneration, authorityFingerprint));
    const auto complete = duplicateWriter.pendingWrite();
    assert(duplicateWriter.onBytesWritten(
               complete.replySequence,
               complete.writeSliceSequence,
               complete.bytes.size()) ==
           RdpServerLicenseGrantWriteOutcome::Delivered);
    assert(duplicate.phase() == RdpLicensingPhase::Licensed);
    assert(duplicateWriter.onBytesWritten(
               complete.replySequence,
               complete.writeSliceSequence,
               0U) ==
           RdpServerLicenseGrantWriteOutcome::Rejected);
    assert(duplicate.phase() == RdpLicensingPhase::Closed);

    cleanseRdpLicensingKeyMaterial(keys);
}

constexpr std::array<std::uint8_t, 5> kSyntheticIssuedCal{
    0x30,0x03,0x02,0x01,0x01};

// Independent NEW_LICENSE_INFO oracle for the small synthetic CAL above.
// These bytes are test material only and are not a legitimate issued CAL.
constexpr std::array<std::uint8_t, 47> kSyntheticNewLicenseInfoPlaintext{
    0x01,0x00,0x06,0x00,
    0x06,0x00,0x00,0x00,
    0x73,0x63,0x6f,0x70,0x65,0x00,
    0x08,0x00,0x00,0x00,
    0x52,0x00,0x44,0x00,0x50,0x00,0x00,0x00,
    0x08,0x00,0x00,0x00,
    0x41,0x00,0x30,0x00,0x32,0x00,0x00,0x00,
    0x05,0x00,0x00,0x00,
    0x30,0x03,0x02,0x01,0x01};

constexpr std::array<std::uint8_t, 71> kExpectedServerNewLicense{
    0x03,0x03,0x47,0x00,0x09,0x00,0x2f,0x00,
    0x4a,0xb0,0x06,0xcc,0xfb,0x00,0x1b,0xf2,
    0x44,0xdd,0x8a,0xa7,0xe9,0x3b,0xf4,0xa2,
    0xb2,0x46,0xf9,0x34,0x1f,0xec,0x8b,0xe4,
    0xdc,0xe2,0x02,0x83,0x37,0x3b,0xfa,0x39,
    0xf3,0xdb,0x00,0x5a,0x1a,0x19,0x9c,0x50,
    0x27,0x42,0xfd,0x66,0xa4,0xa7,0xd3,
    0x60,0x0d,0x43,0x63,0xda,0x09,0xe7,0xff,
    0xb2,0x4b,0xd6,0x5c,0x2b,0x1e,0xc7,0x00};

void verifySyntheticGrantPayload(
    std::span<const std::uint8_t> packet,
    RdpLicensingMessageType expectedType,
    const RdpLicensingKeyMaterial &keys)
{
    assert(packet.size() == kExpectedServerNewLicense.size());
    const auto parsed = parseRdpLicensingMessage(packet);
    assert(parsed);
    assert(parsed.value.type == expectedType);
    assert(parsed.value.protocolVersion == 3U);
    assert(!parsed.value.extendedErrorSupported);

    // One BB_ENCRYPTED_DATA_BLOB, then exactly 16 MAC bytes.
    assert(packet[4] == 0x09U && packet[5] == 0x00U);
    assert(packet[6] == 0x2fU && packet[7] == 0x00U);
    constexpr std::size_t encryptedOffset = 8U;
    constexpr std::size_t encryptedBytes =
        kSyntheticNewLicenseInfoPlaintext.size();
    constexpr std::size_t macOffset = encryptedOffset + encryptedBytes;
    static_assert(macOffset + kRdpLicensingMacBytes ==
                  kExpectedServerNewLicense.size());

    std::array<std::uint8_t, encryptedBytes> decrypted{};
    assert(cryptRdpLicensingData(
        keys.encryptionKey,
        packet.subspan(encryptedOffset, encryptedBytes),
        decrypted));
    assert(decrypted == kSyntheticNewLicenseInfoPlaintext);

    auto expectedMac =
        generateRdpLicensingMac(keys.macSaltKey, decrypted);
    assert(expectedMac);
    assert(std::equal(
        expectedMac.value.begin(), expectedMac.value.end(),
        packet.begin() + static_cast<std::ptrdiff_t>(macOffset)));
    OPENSSL_cleanse(decrypted.data(), decrypted.size());
    OPENSSL_cleanse(expectedMac.value.data(), expectedMac.value.size());
}

void testRdpServerNewLicenseWire()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    std::array<std::uint8_t, 96> output{};
    output.fill(0xa5U);
    const auto encoded = encodeRdpServerLicenseGrant(
        RdpServerLicenseGrantKind::NewLicense,
        identity, kSyntheticIssuedCal, keys, output);
    assert(encoded);
    assert(encoded.bytesWritten == kExpectedServerNewLicense.size());
    assert(std::equal(
        kExpectedServerNewLicense.begin(),
        kExpectedServerNewLicense.end(),
        output.begin()));
    assert(std::all_of(
        output.begin() +
            static_cast<std::ptrdiff_t>(encoded.bytesWritten),
        output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));

    verifySyntheticGrantPayload(
        std::span(output).first(encoded.bytesWritten),
        RdpLicensingMessageType::ServerNewLicense, keys);
    cleanseRdpLicensingKeyMaterial(keys);
}

void testRdpServerUpgradeLicenseWire()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    auto expected = kExpectedServerNewLicense;
    expected[0] = static_cast<std::uint8_t>(
        RdpLicensingMessageType::ServerUpgradeLicense);

    std::array<std::uint8_t, 96> output{};
    output.fill(0xa5U);
    const auto encoded = encodeRdpServerLicenseGrant(
        RdpServerLicenseGrantKind::UpgradeLicense,
        identity, kSyntheticIssuedCal, keys, output);
    assert(encoded);
    assert(encoded.bytesWritten == expected.size());
    assert(std::equal(expected.begin(), expected.end(), output.begin()));
    assert(std::all_of(
        output.begin() +
            static_cast<std::ptrdiff_t>(encoded.bytesWritten),
        output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));

    verifySyntheticGrantPayload(
        std::span(output).first(encoded.bytesWritten),
        RdpLicensingMessageType::ServerUpgradeLicense, keys);
    cleanseRdpLicensingKeyMaterial(keys);
}

void testRdpServerLicenseGrantEncodeDenials()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    std::array<std::uint8_t, 96> output{};
    output.fill(0x5aU);

    RdpServerLicenseIdentity unconfigured;
    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::NewLicense,
               unconfigured, kSyntheticIssuedCal, keys, output).error ==
           RdpServerLicenseGrantEncodeError::IdentityNotConfigured);

    assert(encodeRdpServerLicenseGrant(
               static_cast<RdpServerLicenseGrantKind>(0xffU),
               identity, kSyntheticIssuedCal, keys, output).error ==
           RdpServerLicenseGrantEncodeError::InvalidGrantKind);

    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::NewLicense,
               identity, {}, keys, output).error ==
           RdpServerLicenseGrantEncodeError::InvalidLicense);

    std::array<std::uint8_t,
               kMaximumRdpServerLicenseGrantCalBytes + 1U>
        oversizedCal{};
    oversizedCal.fill(0x42U);
    assert(oversizedCal.size() <= kMaximumRdpIssuedCalBytes);
    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::UpgradeLicense,
               identity, oversizedCal, keys, output).error ==
           RdpServerLicenseGrantEncodeError::Oversized);

    const RdpLicensingKeyMaterialView shortMac{
        std::span(keys.macSaltKey).first(kRdpLicensingKeyBytes - 1U),
        keys.encryptionKey};
    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::NewLicense,
               identity, kSyntheticIssuedCal, shortMac, output).error ==
           RdpServerLicenseGrantEncodeError::InvalidKeyMaterial);

    const RdpLicensingKeyMaterialView shortEncryption{
        keys.macSaltKey,
        std::span(keys.encryptionKey).first(kRdpLicensingKeyBytes - 1U)};
    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::NewLicense,
               identity, kSyntheticIssuedCal, shortEncryption, output).error ==
           RdpServerLicenseGrantEncodeError::InvalidKeyMaterial);

    const RdpLicensingKeyMaterialView missingKeys{
        std::span<const std::uint8_t>{},
        std::span<const std::uint8_t>{}};
    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::NewLicense,
               identity, kSyntheticIssuedCal, missingKeys, output).error ==
           RdpServerLicenseGrantEncodeError::InvalidKeyMaterial);

    std::array<std::uint8_t, 70> tooSmall{};
    tooSmall.fill(0xa5U);
    assert(encodeRdpServerLicenseGrant(
               RdpServerLicenseGrantKind::NewLicense,
               identity, kSyntheticIssuedCal, keys, tooSmall).error ==
           RdpServerLicenseGrantEncodeError::OutputTooSmall);
    assert(std::all_of(
        tooSmall.begin(), tooSmall.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));

    // The conservative CAL ceiling proves worst-case identity strings still
    // fit one unfragmented 16,383-byte MCS userData field.
    std::array<std::uint8_t,
               kMaximumRdpServerLicenseIdentityTextBytes>
        maximumCompany{};
    std::array<std::uint8_t,
               kMaximumRdpServerLicenseIdentityTextBytes>
        maximumProduct{};
    for (std::size_t offset = 0U;
         offset + 2U < maximumCompany.size(); offset += 2U)
    {
        maximumCompany[offset] = 0x41U;
        maximumProduct[offset] = 0x42U;
    }
    std::array<std::uint8_t,
               kMaximumRdpServerLicenseIdentityTextBytes>
        maximumScope{};
    maximumScope.fill(0x73U);
    maximumScope.back() = 0U;

    RdpServerLicenseIdentity maximumIdentity;
    assert(maximumIdentity.configure(
        0x00060001U, maximumCompany, maximumProduct,
        kServerLicenseCertificate, maximumScope));

    std::array<std::uint8_t, kMaximumRdpServerLicenseGrantCalBytes>
        maximumCal{};
    maximumCal.fill(0x42U);
    std::array<std::uint8_t, kMaximumRdpServerLicenseGrantBytes>
        maximumPacket{};
    const auto maximum = encodeRdpServerLicenseGrant(
        RdpServerLicenseGrantKind::NewLicense,
        maximumIdentity, maximumCal, keys, maximumPacket);
    assert(maximum);
    assert(maximum.bytesWritten == kMaximumRdpServerLicenseGrantBytes);
    assert(maximum.bytesWritten +
               kRdpLicensingBasicSecurityHeaderBytes ==
           kMaximumRdpLicensingUnfragmentedMcsUserDataBytes);
    assert(kMaximumRdpServerLicenseGrantTlsApplicationBytes <
           18U * 1024U);

    assert(std::all_of(
        output.begin(), output.end(),
        [](std::uint8_t value) { return value == 0x5aU; }));
    cleanseRdpLicensingKeyMaterial(keys);
}

void testRdpServerLicenseGrantTransactionalOutput()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    std::array<std::uint8_t, 128> output{};
    output.fill(0xc3U);
    const auto original = output;

    const RdpLicensingKeyMaterialView invalidKeys{
        std::span(keys.macSaltKey).first(kRdpLicensingKeyBytes - 1U),
        keys.encryptionKey};
    assert(!encodeRdpServerLicenseGrant(
        RdpServerLicenseGrantKind::NewLicense,
        identity, kSyntheticIssuedCal, invalidKeys, output));
    assert(output == original);

    assert(!encodeRdpServerLicenseGrant(
        static_cast<RdpServerLicenseGrantKind>(0x7fU),
        identity, kSyntheticIssuedCal, keys, output));
    assert(output == original);

    const auto encoded = encodeRdpServerLicenseGrant(
        RdpServerLicenseGrantKind::NewLicense,
        identity, kSyntheticIssuedCal, keys, output);
    assert(encoded);
    assert(std::equal(
        kExpectedServerNewLicense.begin(),
        kExpectedServerNewLicense.end(),
        output.begin()));
    assert(std::all_of(
        output.begin() +
            static_cast<std::ptrdiff_t>(encoded.bytesWritten),
        output.end(),
        [](std::uint8_t value) { return value == 0xc3U; }));

    cleanseRdpLicensingKeyMaterial(keys);
}

void testRdpServerGrantNoLivePublication()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    auto keys = platformChallengeKeys();

    RdpLicensingLifecycle licensing;
    McsSessionLifecycle session;
    assert(licensing.phase() == RdpLicensingPhase::NotStarted);
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);

    std::array<std::uint8_t, 96> output{};
    const auto encoded = encodeRdpServerLicenseGrant(
        RdpServerLicenseGrantKind::NewLicense,
        identity, kSyntheticIssuedCal, keys, output);
    assert(encoded);

    // Serialization has no licensing/session authority or side effect.
    assert(licensing.phase() == RdpLicensingPhase::NotStarted);
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);

    // Treating the pure server packet as a client licensing message is
    // out-of-order and terminal; it cannot become a reusable grant token.
    RdpLicensingLifecycle licensingMisuse;
    assert(licensingMisuse.onClientMessage(
               std::span(output).first(encoded.bytesWritten)) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(licensingMisuse.phase() == RdpLicensingPhase::Failed);

    // Nor can the bare encoded bytes bypass the public MCS admission boundary.
    McsSessionLifecycle sessionMisuse;
    assert(sessionMisuse.onDomainPdu(
               std::span(output).first(encoded.bytesWritten)) ==
           McsSessionIntake::InvalidDomainTransport);
    assert(sessionMisuse.phase() == McsSessionPhase::Closed);
    assert(sessionMisuse.licensingPhase() == RdpLicensingPhase::Closed);

    cleanseRdpLicensingKeyMaterial(keys);
}

void testRdpServerLicenseRequestGeneratedRandom()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));

    RdpLicensingLifecycle lifecycle;
    RdpServerLicenseRequestWriteGate writer{lifecycle};
    assert(writer.queue(identity));
    const auto pending = writer.pendingWrite();
    assert(pending);
    assert(pending.bytes.size() == 94U);

    const auto parsed = parseRdpLicensingMessage(pending.bytes);
    assert(parsed);
    assert(parsed.value.type ==
           RdpLicensingMessageType::ServerLicenseRequest);
    const auto random = pending.bytes.subspan(4U, 32U);
    assert(!std::all_of(
        random.begin(), random.end(),
        [](std::uint8_t value) { return value == 0U; }));

    assert(std::equal(
        pending.bytes.begin() + 44U,
        pending.bytes.begin() + 52U,
        kServerLicenseCompany.begin()));
    assert(std::equal(
        pending.bytes.end() - kServerLicenseScope.size(),
        pending.bytes.end(),
        kServerLicenseScope.begin()));
    assert(lifecycle.phase() == RdpLicensingPhase::NotStarted);
}

[[nodiscard]] RdpLicensingKeyMaterial platformChallengeKeys() noexcept
{
    RdpLicensingKeyMaterial keys{};
    for (std::size_t index = 0U; index < kRdpLicensingKeyBytes; ++index)
    {
        keys.macSaltKey[index] = static_cast<std::uint8_t>(index);
        keys.encryptionKey[index] =
            static_cast<std::uint8_t>(0x10U + index);
    }
    return keys;
}

[[nodiscard]] std::array<std::uint8_t, kRdpPlatformChallengePlaintextBytes>
platformChallengePlaintext() noexcept
{
    constexpr std::string_view text{"00112233445566778899AABBCCDDEEFF"};
    std::array<std::uint8_t, kRdpPlatformChallengePlaintextBytes> out{};
    std::size_t offset = 0U;
    for (const char value : text)
    {
        out[offset++] = static_cast<std::uint8_t>(value);
        out[offset++] = 0U;
    }
    assert(offset + 2U == out.size());
    return out;
}

void testRdpServerPlatformChallengeWire()
{
    const auto keys = platformChallengeKeys();
    const auto plaintext = platformChallengePlaintext();
    constexpr std::array<std::uint8_t, kRdpServerPlatformChallengeBytes>
        expected{
            0x02,0x03,0x5e,0x00,0xff,0xff,0xff,0xff,
            0x00,0x00,0x42,0x00,0x7b,0xb0,0x30,0xcc,
            0xcc,0x00,0x2a,0xf2,0x05,0xbe,0xd7,0xd7,
            0xbf,0x3b,0xcf,0xa2,0x86,0x46,0x9f,0x34,
            0x6e,0xec,0xee,0xe4,0xea,0xe2,0x3c,0x83,
            0x00,0x3b,0x8c,0x39,0xfb,0xdb,0x0a,0x5a,
            0x23,0x19,0xa0,0x50,0x66,0x42,0x8c,0x65,
            0xe4,0xa6,0x90,0xcf,0x90,0xfc,0x8f,0xe8,
            0x1b,0x16,0x4e,0xba,0x60,0xa8,0x78,0x64,
            0xdf,0x37,0x4e,0x3b,0x3c,0x5a,0xcd,0x6c,
            0x27,0x1f,0x93,0x71,0x0b,0x84,0x36,0x41,
            0xd3,0x56,0xa1,0x66,0xcb,0xdf};

    std::array<std::uint8_t, kRdpServerPlatformChallengeBytes> output{};
    const auto encoded =
        encodeRdpServerPlatformChallenge(plaintext, keys, output);
    assert(encoded);
    assert(encoded.bytesWritten == expected.size());
    assert(output == expected);

    const auto parsed = parseRdpLicensingMessage(output);
    assert(parsed);
    assert(parsed.value.type ==
           RdpLicensingMessageType::ServerPlatformChallenge);
    assert(parsed.value.protocolVersion == 3U);
    assert(parsed.value.body.size() == output.size() - 4U);

    // Failure is transactional: malformed plaintext cannot alter output.
    output.fill(0xa5U);
    auto malformed = plaintext;
    malformed[2] = 0U;
    malformed[3] = 0U;
    assert(encodeRdpServerPlatformChallenge(
               malformed, keys, output).error ==
           RdpServerPlatformChallengeEncodeError::InvalidChallenge);
    assert(std::all_of(
        output.begin(), output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));
}

void testRdpServerPlatformChallengeWriteReceipts()
{
    RdpLicensingLifecycle lifecycle;
    assert(deliverServerLicenseRequest(lifecycle));
    assert(lifecycle.onClientMessage(makeClientNewLicenseRequest()) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::PlatformChallengeRequired);

    const auto keys = platformChallengeKeys();
    RdpServerPlatformChallengeWriteGate writer{lifecycle};
    assert(writer.queue(keys));

    const auto first = writer.pendingWrite();
    assert(first);
    assert(first.bytes.size() == kRdpServerPlatformChallengeBytes);
    assert(lifecycle.platformChallenge().empty());

    assert(writer.onBytesWritten(
               first.replySequence, first.writeSliceSequence, 0U) ==
           RdpServerPlatformChallengeWriteOutcome::Pending);
    const auto afterWant = writer.pendingWrite();
    assert(afterWant.bytes.data() == first.bytes.data());
    assert(afterWant.bytes.size() == first.bytes.size());
    assert(afterWant.replySequence == first.replySequence);
    assert(afterWant.writeSliceSequence == first.writeSliceSequence);

    constexpr std::size_t firstAccepted = 23U;
    assert(writer.onBytesWritten(
               first.replySequence, first.writeSliceSequence, firstAccepted) ==
           RdpServerPlatformChallengeWriteOutcome::Pending);
    const auto remainder = writer.pendingWrite();
    assert(remainder);
    assert(remainder.replySequence == first.replySequence);
    assert(remainder.writeSliceSequence != first.writeSliceSequence);
    assert(remainder.bytes.data() == first.bytes.data() + firstAccepted);
    assert(remainder.bytes.size() == first.bytes.size() - firstAccepted);
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);

    // Snapshot the encrypted challenge before final delivery zeroes the gate.
    std::array<std::uint8_t, kRdpPlatformChallengePlaintextBytes> decrypted{};
    const auto encrypted = first.bytes.subspan(
        12U, kRdpPlatformChallengePlaintextBytes);
    assert(cryptRdpLicensingData(
        keys.encryptionKey, encrypted, decrypted));

    assert(writer.onBytesWritten(
               remainder.replySequence,
               remainder.writeSliceSequence,
               remainder.bytes.size()) ==
           RdpServerPlatformChallengeWriteOutcome::Delivered);
    assert(!writer.pendingWrite());
    assert(lifecycle.phase() ==
           RdpLicensingPhase::AwaitClientPlatformChallengeResponse);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::AwaitPlatformChallengeResponse);
    assert(lifecycle.platformChallenge().size() ==
           kRdpPlatformChallengePlaintextBytes);
    assert(std::equal(
        decrypted.begin(), decrypted.end(),
        lifecycle.platformChallenge().begin()));

    auto mac = generateRdpLicensingMac(
        keys.macSaltKey, lifecycle.platformChallenge());
    assert(mac);
    const auto sentMac = first.bytes.last(kRdpLicensingMacBytes);
    assert(std::equal(mac.value.begin(), mac.value.end(), sentMac.begin()));

    // Concrete profile: 32 uppercase hex UTF-16LE chars and terminator.
    const auto challenge = lifecycle.platformChallenge();
    for (std::size_t offset = 0U; offset + 2U < challenge.size(); offset += 2U)
    {
        const auto value = challenge[offset];
        assert(challenge[offset + 1U] == 0U);
        assert((value >= '0' && value <= '9') ||
               (value >= 'A' && value <= 'F'));
    }
    assert(challenge[challenge.size() - 2U] == 0U);
    assert(challenge.back() == 0U);
}

void testRdpServerPlatformChallengeWriteDenials()
{
    const auto keys = platformChallengeKeys();

    // CLIENT_LICENSE_INFO is a different server-decision branch.
    RdpLicensingLifecycle licenseInfoLifecycle;
    assert(deliverServerLicenseRequest(licenseInfoLifecycle));
    assert(licenseInfoLifecycle.onClientMessage(makeClientLicenseInfo()) ==
           RdpLicensingIntake::ClientLicenseInfoAccepted);
    assert(licenseInfoLifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::ClientLicenseInfoValidation);
    RdpServerPlatformChallengeWriteGate wrongBranch{licenseInfoLifecycle};
    assert(!wrongBranch.queue(keys));
    assert(licenseInfoLifecycle.phase() == RdpLicensingPhase::Closed);

    // Challenge cannot be emitted before a client licensing response.
    RdpLicensingLifecycle earlyLifecycle;
    assert(deliverServerLicenseRequest(earlyLifecycle));
    RdpServerPlatformChallengeWriteGate early{earlyLifecycle};
    assert(!early.queue(keys));
    assert(earlyLifecycle.phase() == RdpLicensingPhase::Closed);

    // Stale partial-write receipt is terminal.
    RdpLicensingLifecycle staleLifecycle;
    assert(deliverServerLicenseRequest(staleLifecycle));
    assert(staleLifecycle.onClientMessage(makeClientNewLicenseRequest()) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    RdpServerPlatformChallengeWriteGate stale{staleLifecycle};
    assert(stale.queue(keys));
    const auto staleFirst = stale.pendingWrite();
    assert(stale.onBytesWritten(
               staleFirst.replySequence,
               staleFirst.writeSliceSequence,
               1U) == RdpServerPlatformChallengeWriteOutcome::Pending);
    const auto staleRemainder = stale.pendingWrite();
    assert(staleRemainder.writeSliceSequence !=
           staleFirst.writeSliceSequence);
    assert(stale.onBytesWritten(
               staleFirst.replySequence,
               staleFirst.writeSliceSequence,
               1U) == RdpServerPlatformChallengeWriteOutcome::Rejected);
    assert(staleLifecycle.phase() == RdpLicensingPhase::Closed);

    // Over-report cannot manufacture delivery.
    RdpLicensingLifecycle overLifecycle;
    assert(deliverServerLicenseRequest(overLifecycle));
    assert(overLifecycle.onClientMessage(makeClientNewLicenseRequest()) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    RdpServerPlatformChallengeWriteGate over{overLifecycle};
    assert(over.queue(keys));
    const auto overPending = over.pendingWrite();
    assert(over.onBytesWritten(
               overPending.replySequence,
               overPending.writeSliceSequence,
               overPending.bytes.size() + 1U) ==
           RdpServerPlatformChallengeWriteOutcome::Rejected);
    assert(overLifecycle.phase() == RdpLicensingPhase::Closed);
}

[[nodiscard]] std::vector<std::uint8_t>
makeClientPlatformChallengeResponse(
    std::span<const std::uint8_t> challenge,
    const RdpLicensingKeyMaterial &keys,
    std::uint16_t version = 0x0100U,
    std::uint16_t clientType = 0x0100U,
    std::uint16_t detailLevel = 0x0003U)
{
    assert(challenge.size() == kRdpPlatformChallengePlaintextBytes);
    std::array<std::uint8_t, kRdpPlatformChallengeResponseDataBytes>
        responseData{};
    const auto putLe16 =
        [&](std::size_t offset, std::uint16_t value)
        {
            responseData[offset] = static_cast<std::uint8_t>(value);
            responseData[offset + 1U] =
                static_cast<std::uint8_t>(value >> 8U);
        };
    putLe16(0U, version);
    putLe16(2U, clientType);
    putLe16(4U, detailLevel);
    putLe16(6U, static_cast<std::uint16_t>(challenge.size()));
    std::copy(
        challenge.begin(), challenge.end(),
        responseData.begin() +
            static_cast<std::ptrdiff_t>(
                kRdpPlatformChallengeResponseHeaderBytes));

    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> hardwareId{};
    for (std::size_t index = 0U; index < hardwareId.size(); ++index)
        hardwareId[index] = static_cast<std::uint8_t>(0x40U + index);

    std::array<std::uint8_t, kRdpPlatformChallengeResponseDataBytes>
        encryptedResponse{};
    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes>
        encryptedHardwareId{};
    assert(cryptRdpLicensingData(
        keys.encryptionKey, responseData, encryptedResponse));
    assert(cryptRdpLicensingData(
        keys.encryptionKey, hardwareId, encryptedHardwareId));

    std::array<std::uint8_t,
               kRdpPlatformChallengeResponseDataBytes +
                   kRdpLicensingHardwareIdBytes> macInput{};
    std::copy(responseData.begin(), responseData.end(), macInput.begin());
    std::copy(
        hardwareId.begin(), hardwareId.end(),
        macInput.begin() +
            static_cast<std::ptrdiff_t>(responseData.size()));
    auto mac = generateRdpLicensingMac(keys.macSaltKey, macInput);
    assert(mac);

    std::vector<std::uint8_t> message{0x15, 0x03, 0x00, 0x00};
    appendLicensingBlob(message, 0x0009U, encryptedResponse);
    appendLicensingBlob(message, 0x0009U, encryptedHardwareId);
    message.insert(message.end(), mac.value.begin(), mac.value.end());
    finishLicensingMessageSize(message);
    return message;
}

void testRdpClientPlatformChallengeResponseProof()
{
    const auto keys = platformChallengeKeys();
    const auto challenge = platformChallengePlaintext();
    const auto message =
        makeClientPlatformChallengeResponse(challenge, keys);

    const auto verified = verifyRdpClientPlatformChallengeResponse(
        message, keys, challenge);
    assert(verified);
    assert(verified.clientType == 0x0100U);
    assert(verified.licenseDetailLevel == 0x0003U);

    RdpLicensingLifecycle lifecycle;
    assert(deliverServerLicenseRequest(lifecycle));
    assert(lifecycle.onClientMessage(makeClientNewLicenseRequest()) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    RdpServerPlatformChallengeWriteGate writer{lifecycle};
    assert(writer.queue(keys));
    const auto pending = writer.pendingWrite();
    assert(pending);
    assert(writer.onBytesWritten(
               pending.replySequence,
               pending.writeSliceSequence,
               pending.bytes.size()) ==
           RdpServerPlatformChallengeWriteOutcome::Delivered);
    const auto retained = lifecycle.platformChallenge();
    const auto response =
        makeClientPlatformChallengeResponse(retained, keys);
    assert(lifecycle.onClientPlatformChallengeResponse(response, keys) ==
           RdpLicensingIntake::ClientPlatformChallengeResponseAccepted);
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::NewLicenseIssuanceRequired);
    assert(lifecycle.platformChallenge().empty());

    // A duplicate response cannot be replayed as a second issuance decision.
    assert(lifecycle.onClientPlatformChallengeResponse(response, keys) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(lifecycle.phase() == RdpLicensingPhase::Failed);
}

void testRdpClientPlatformChallengeResponseDenials()
{
    const auto keys = platformChallengeKeys();
    const auto challenge = platformChallengePlaintext();

    auto expectError =
        [&](std::vector<std::uint8_t> message,
            RdpClientPlatformChallengeResponseError expected)
        {
            const auto verified = verifyRdpClientPlatformChallengeResponse(
                message, keys, challenge);
            assert(!verified);
            assert(verified.error == expected);
        };

    auto wrongBlob =
        makeClientPlatformChallengeResponse(challenge, keys);
    wrongBlob[4] = 0x01U;
    expectError(
        std::move(wrongBlob),
        RdpClientPlatformChallengeResponseError::InvalidBlob);

    expectError(
        makeClientPlatformChallengeResponse(
            challenge, keys, 0x0200U),
        RdpClientPlatformChallengeResponseError::InvalidResponseData);
    expectError(
        makeClientPlatformChallengeResponse(
            challenge, keys, 0x0100U, 0x0400U),
        RdpClientPlatformChallengeResponseError::InvalidResponseData);
    expectError(
        makeClientPlatformChallengeResponse(
            challenge, keys, 0x0100U, 0x0100U, 0x0004U),
        RdpClientPlatformChallengeResponseError::InvalidResponseData);

    auto differentChallenge = challenge;
    differentChallenge[0] =
        differentChallenge[0] == '0' ? '1' : '0';
    expectError(
        makeClientPlatformChallengeResponse(differentChallenge, keys),
        RdpClientPlatformChallengeResponseError::ChallengeMismatch);

    auto badMac =
        makeClientPlatformChallengeResponse(challenge, keys);
    badMac.back() ^= 0x80U;
    expectError(
        std::move(badMac),
        RdpClientPlatformChallengeResponseError::MacMismatch);

    auto truncated =
        makeClientPlatformChallengeResponse(challenge, keys);
    truncated.pop_back();
    finishLicensingMessageSize(truncated);
    expectError(
        std::move(truncated),
        RdpClientPlatformChallengeResponseError::InvalidBlob);

    const auto initial = makeClientNewLicenseRequest();
    const auto unexpected = verifyRdpClientPlatformChallengeResponse(
        initial, keys, challenge);
    assert(!unexpected);
    assert(unexpected.error ==
           RdpClientPlatformChallengeResponseError::InvalidMessage);
}

void testRdpServerLicenseRequestWriteReceipts()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    RdpLicensingLifecycle lifecycle;
    RdpServerLicenseRequestWriteGate writer{lifecycle};
    assert(writer.queue(identity));

    const auto first = writer.pendingWrite();
    assert(first);
    assert(first.bytes.size() == 94U);
    std::array<std::uint8_t, kRdpLicensingRandomBytes> sentServerRandom{};
    std::copy_n(
        first.bytes.begin() + 4U, sentServerRandom.size(),
        sentServerRandom.begin());

    assert(writer.onBytesWritten(
               first.replySequence, first.writeSliceSequence, 0U) ==
           RdpServerLicenseRequestWriteOutcome::Pending);
    const auto afterWant = writer.pendingWrite();
    assert(afterWant.bytes.data() == first.bytes.data());
    assert(afterWant.bytes.size() == first.bytes.size());
    assert(afterWant.replySequence == first.replySequence);
    assert(afterWant.writeSliceSequence == first.writeSliceSequence);
    assert(lifecycle.phase() == RdpLicensingPhase::NotStarted);

    constexpr std::size_t firstAccepted = 17U;
    assert(writer.onBytesWritten(
               first.replySequence, first.writeSliceSequence, firstAccepted) ==
           RdpServerLicenseRequestWriteOutcome::Pending);
    const auto remainder = writer.pendingWrite();
    assert(remainder.replySequence == first.replySequence);
    assert(remainder.writeSliceSequence != first.writeSliceSequence);
    assert(remainder.bytes.data() == first.bytes.data() + firstAccepted);
    assert(remainder.bytes.size() == first.bytes.size() - firstAccepted);
    assert(lifecycle.phase() == RdpLicensingPhase::NotStarted);

    assert(writer.onBytesWritten(
               remainder.replySequence,
               remainder.writeSliceSequence,
               remainder.bytes.size()) ==
           RdpServerLicenseRequestWriteOutcome::Delivered);
    assert(!writer.pendingWrite());
    assert(lifecycle.phase() ==
           RdpLicensingPhase::AwaitClientLicenseResponse);
    assert(lifecycle.serverRandom().size() == sentServerRandom.size());
    assert(std::equal(
        lifecycle.serverRandom().begin(), lifecycle.serverRandom().end(),
        sentServerRandom.begin()));
    lifecycle.close();
    assert(lifecycle.serverRandom().empty());
}

void testRdpServerLicenseRequestWriteDenials()
{
    std::array<std::uint8_t, 128> output{};
    output.fill(0xa5U);
    auto invalid = serverLicenseFields();
    constexpr std::array<std::uint8_t, 32> zeroRandom{};
    invalid.serverRandom = zeroRandom;
    assert(encodeEnhancedSecurityServerLicenseRequest(invalid, output).error ==
           RdpServerLicenseRequestEncodeError::InvalidRandom);
    assert(std::all_of(
        output.begin(), output.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));

    invalid = serverLicenseFields();
    invalid.productVersion = 0U;
    assert(encodeEnhancedSecurityServerLicenseRequest(invalid, output).error ==
           RdpServerLicenseRequestEncodeError::InvalidProductInfo);

    invalid = serverLicenseFields();
    invalid.companyNameUtf16 =
        std::span(kServerLicenseCompany).first(
            kServerLicenseCompany.size() - 1U);
    assert(encodeEnhancedSecurityServerLicenseRequest(invalid, output).error ==
           RdpServerLicenseRequestEncodeError::InvalidProductInfo);

    invalid = serverLicenseFields();
    invalid.scopeAnsi =
        std::span(kServerLicenseScope).first(kServerLicenseScope.size() - 1U);
    assert(encodeEnhancedSecurityServerLicenseRequest(invalid, output).error ==
           RdpServerLicenseRequestEncodeError::InvalidScope);

    std::array<std::uint8_t, 16> tooSmall{};
    assert(encodeEnhancedSecurityServerLicenseRequest(
               serverLicenseFields(), tooSmall).error ==
           RdpServerLicenseRequestEncodeError::OutputTooSmall);

    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));

    RdpLicensingLifecycle overwriteLifecycle;
    RdpServerLicenseRequestWriteGate overwrite{overwriteLifecycle};
    assert(overwrite.queue(identity));
    assert(!overwrite.queue(identity));
    assert(overwriteLifecycle.phase() == RdpLicensingPhase::Closed);

    RdpLicensingLifecycle staleLifecycle;
    RdpServerLicenseRequestWriteGate stale{staleLifecycle};
    assert(stale.queue(identity));
    const auto staleFirst = stale.pendingWrite();
    assert(stale.onBytesWritten(
               staleFirst.replySequence,
               staleFirst.writeSliceSequence,
               1U) == RdpServerLicenseRequestWriteOutcome::Pending);
    const auto staleRemainder = stale.pendingWrite();
    assert(staleRemainder.writeSliceSequence != staleFirst.writeSliceSequence);
    assert(stale.onBytesWritten(
               staleFirst.replySequence,
               staleFirst.writeSliceSequence,
               1U) == RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(staleLifecycle.phase() == RdpLicensingPhase::Closed);

    RdpLicensingLifecycle overLifecycle;
    RdpServerLicenseRequestWriteGate over{overLifecycle};
    assert(over.queue(identity));
    const auto overPending = over.pendingWrite();
    assert(over.onBytesWritten(
               overPending.replySequence,
               overPending.writeSliceSequence,
               overPending.bytes.size() + 1U) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(overLifecycle.phase() == RdpLicensingPhase::Closed);

    RdpLicensingLifecycle duplicateLifecycle;
    RdpServerLicenseRequestWriteGate duplicate{duplicateLifecycle};
    assert(duplicate.queue(identity));
    const auto duplicatePending = duplicate.pendingWrite();
    assert(duplicate.onBytesWritten(
               duplicatePending.replySequence,
               duplicatePending.writeSliceSequence,
               duplicatePending.bytes.size()) ==
           RdpServerLicenseRequestWriteOutcome::Delivered);
    assert(duplicateLifecycle.phase() ==
           RdpLicensingPhase::AwaitClientLicenseResponse);
    assert(duplicate.onBytesWritten(
               duplicatePending.replySequence,
               duplicatePending.writeSliceSequence,
               0U) == RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(duplicateLifecycle.phase() == RdpLicensingPhase::Closed);

    // Production R3 still has no API that can invent CSPRNG/product/scope
    // provisioning merely to escape this boundary.
    McsSessionLifecycle fresh;
    assert(fresh.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(fresh.licensingPhase() == RdpLicensingPhase::NotStarted);
}


void testRdpClientResponseBeforeRequestDelivery()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    const auto response = makeClientNewLicenseRequest();

    // A queued packet and a zero-byte transport receipt are not delivery.
    RdpLicensingLifecycle zeroByteLifecycle;
    RdpServerLicenseRequestWriteGate zeroByteWriter{zeroByteLifecycle};
    assert(zeroByteWriter.queue(identity));
    std::uint64_t zeroReplySequence{};
    std::uint64_t zeroSliceSequence{};
    std::size_t zeroPendingBytes{};
    {
        const auto pending = zeroByteWriter.pendingWrite();
        assert(pending);
        zeroReplySequence = pending.replySequence;
        zeroSliceSequence = pending.writeSliceSequence;
        zeroPendingBytes = pending.bytes.size();
        assert(zeroByteWriter.onBytesWritten(
                   zeroReplySequence, zeroSliceSequence, 0U) ==
               RdpServerLicenseRequestWriteOutcome::Pending);
        const auto unchanged = zeroByteWriter.pendingWrite();
        assert(unchanged.replySequence == zeroReplySequence);
        assert(unchanged.writeSliceSequence == zeroSliceSequence);
        assert(unchanged.bytes.size() == zeroPendingBytes);
    }
    assert(zeroByteLifecycle.phase() == RdpLicensingPhase::NotStarted);
    assert(zeroByteLifecycle.onClientMessage(response) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(zeroByteLifecycle.phase() == RdpLicensingPhase::Failed);
    assert(zeroByteWriter.onBytesWritten(
               zeroReplySequence, zeroSliceSequence, zeroPendingBytes) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(!zeroByteWriter.pendingWrite());
    assert(zeroByteLifecycle.phase() == RdpLicensingPhase::Closed);
    assert(zeroByteLifecycle.onClientMessage(response) ==
           RdpLicensingIntake::Closed);

    // A real, positive short write rotates its slice but still grants no
    // client-response authority or server-decision/Share transition.
    RdpLicensingLifecycle partialLifecycle;
    RdpServerLicenseRequestWriteGate partialWriter{partialLifecycle};
    assert(partialWriter.queue(identity));
    std::uint64_t partialReplySequence{};
    std::uint64_t remainingSliceSequence{};
    std::size_t remainingBytes{};
    {
        const auto initial = partialWriter.pendingWrite();
        assert(initial);
        const std::size_t acceptedBytes = initial.bytes.size() / 2U;
        assert(acceptedBytes > 0U && acceptedBytes < initial.bytes.size());
        assert(partialWriter.onBytesWritten(
                   initial.replySequence, initial.writeSliceSequence,
                   acceptedBytes) == RdpServerLicenseRequestWriteOutcome::Pending);
        const auto remaining = partialWriter.pendingWrite();
        assert(remaining);
        assert(remaining.replySequence == initial.replySequence);
        assert(remaining.writeSliceSequence != initial.writeSliceSequence);
        assert(remaining.bytes.size() == initial.bytes.size() - acceptedBytes);
        partialReplySequence = remaining.replySequence;
        remainingSliceSequence = remaining.writeSliceSequence;
        remainingBytes = remaining.bytes.size();
    }
    assert(partialLifecycle.phase() == RdpLicensingPhase::NotStarted);
    assert(partialLifecycle.onClientMessage(response) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(partialLifecycle.phase() == RdpLicensingPhase::Failed);
    assert(partialWriter.onBytesWritten(
               partialReplySequence, remainingSliceSequence, remainingBytes) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(!partialWriter.pendingWrite());
    assert(partialLifecycle.phase() == RdpLicensingPhase::Closed);
    assert(partialLifecycle.onClientMessage(response) ==
           RdpLicensingIntake::Closed);
}

void testRdpGeneratedRequestCancellationReplay()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    const auto response = makeClientLicenseInfo();

    RdpLicensingLifecycle lifecycle;
    RdpServerLicenseRequestWriteGate writer{lifecycle};
    assert(writer.queue(identity));
    std::uint64_t replySequence{};
    std::uint64_t oldSliceSequence{};
    std::uint64_t currentSliceSequence{};
    std::size_t currentPendingBytes{};
    {
        const auto initial = writer.pendingWrite();
        assert(initial);
        replySequence = initial.replySequence;
        oldSliceSequence = initial.writeSliceSequence;
        constexpr std::size_t acceptedBytes = 7U;
        assert(initial.bytes.size() > acceptedBytes);
        assert(writer.onBytesWritten(
                   replySequence, oldSliceSequence, acceptedBytes) ==
               RdpServerLicenseRequestWriteOutcome::Pending);

        const auto remaining = writer.pendingWrite();
        assert(remaining);
        assert(remaining.replySequence == replySequence);
        assert(remaining.writeSliceSequence != oldSliceSequence);
        assert(remaining.bytes.size() == initial.bytes.size() - acceptedBytes);
        currentSliceSequence = remaining.writeSliceSequence;
        currentPendingBytes = remaining.bytes.size();
    }

    // Capture only receipt values, never a borrowed buffer across close.
    assert(lifecycle.phase() == RdpLicensingPhase::NotStarted);
    writer.close();
    assert(!writer.pendingWrite());
    assert(lifecycle.phase() == RdpLicensingPhase::Closed);
    assert(writer.onBytesWritten(
               replySequence, currentSliceSequence, currentPendingBytes) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(writer.onBytesWritten(
               replySequence, oldSliceSequence, 7U) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(writer.onBytesWritten(
               replySequence, currentSliceSequence, 0U) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(writer.onBytesWritten(
               replySequence + 1U, currentSliceSequence, 1U) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    writer.close();
    assert(!writer.pendingWrite());
    assert(!writer.queue(identity));
    assert(lifecycle.onClientMessage(response) ==
           RdpLicensingIntake::Closed);
    assert(lifecycle.phase() == RdpLicensingPhase::Closed);
}

void testRdpClientResponseSingleConsumption()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    const auto newRequest = makeClientNewLicenseRequest();
    const auto licenseInfo = makeClientLicenseInfo();

    // Both legitimate first-message forms stop at a server decision. An
    // alternate second response cannot be accepted or revive that phase.
    for (bool firstIsLicenseInfo : {false, true})
    {
        RdpLicensingLifecycle lifecycle;
        RdpServerLicenseRequestWriteGate writer{lifecycle};
        assert(writer.queue(identity));
        {
            const auto pending = writer.pendingWrite();
            assert(pending);
            assert(writer.onBytesWritten(
                       pending.replySequence, pending.writeSliceSequence,
                       pending.bytes.size()) ==
                   RdpServerLicenseRequestWriteOutcome::Delivered);
        }
        assert(!writer.pendingWrite());
        assert(lifecycle.phase() == RdpLicensingPhase::AwaitClientLicenseResponse);

        const auto &first = firstIsLicenseInfo ? licenseInfo : newRequest;
        const auto &alternate = firstIsLicenseInfo ? newRequest : licenseInfo;
        const auto expected = firstIsLicenseInfo
            ? RdpLicensingIntake::ClientLicenseInfoAccepted
            : RdpLicensingIntake::ClientNewLicenseRequestAccepted;
        assert(lifecycle.onClientMessage(first) == expected);
        assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);
        assert(lifecycle.onClientMessage(alternate) ==
               RdpLicensingIntake::UnexpectedMessage);
        assert(lifecycle.phase() == RdpLicensingPhase::Failed);
        assert(lifecycle.onClientMessage(first) == RdpLicensingIntake::Failed);
        lifecycle.close();
        assert(lifecycle.onClientMessage(alternate) ==
               RdpLicensingIntake::Closed);
    }

    RdpLicensingLifecycle malformedLifecycle;
    assert(deliverServerLicenseRequest(malformedLifecycle));
    assert(malformedLifecycle.onClientMessage(
               std::span(licenseInfo).first(licenseInfo.size() - 1U)) ==
           RdpLicensingIntake::MalformedMessage);
    assert(malformedLifecycle.phase() == RdpLicensingPhase::Failed);
    assert(malformedLifecycle.onClientMessage(newRequest) ==
           RdpLicensingIntake::Failed);
}

void testRdpClientLicensingKeyExchangeViews()
{
    const auto newRequest = makeClientNewLicenseRequest();
    const auto newExchange = parseRdpClientLicensingKeyExchange(newRequest);
    assert(newExchange);
    assert(newExchange.value.type ==
           RdpLicensingMessageType::ClientNewLicenseRequest);
    assert(newExchange.value.clientRandom.size() == kRdpLicensingRandomBytes);
    for (std::size_t index = 0; index < kRdpLicensingRandomBytes; ++index)
        assert(newExchange.value.clientRandom[index] ==
               static_cast<std::uint8_t>(index));
    constexpr std::array<std::uint8_t, 3> expectedNewEncrypted{
        0x11, 0x22, 0x33};
    assert(std::equal(newExchange.value.encryptedPreMasterSecret.begin(),
                      newExchange.value.encryptedPreMasterSecret.end(),
                      expectedNewEncrypted.begin()));

    const auto licenseInfo = makeClientLicenseInfo();
    const auto existingExchange =
        parseRdpClientLicensingKeyExchange(licenseInfo);
    assert(existingExchange);
    assert(existingExchange.value.type ==
           RdpLicensingMessageType::ClientLicenseInfo);
    for (std::size_t index = 0; index < kRdpLicensingRandomBytes; ++index)
        assert(existingExchange.value.clientRandom[index] ==
               static_cast<std::uint8_t>(0xa0U + index));
    constexpr std::array<std::uint8_t, 2> expectedExistingEncrypted{
        0x31, 0x32};
    assert(std::equal(existingExchange.value.encryptedPreMasterSecret.begin(),
                      existingExchange.value.encryptedPreMasterSecret.end(),
                      expectedExistingEncrypted.begin()));
}

void testRdpClientLicensingKeyExchangeDenials()
{
    const auto valid = makeClientNewLicenseRequest();
    for (std::size_t size = 0; size < valid.size(); ++size)
        assert(!parseRdpClientLicensingKeyExchange(
            std::span(valid).first(size)));

    auto wrongAlgorithm = valid;
    wrongAlgorithm[4U] = 2U;
    const auto algorithmDenied =
        parseRdpClientLicensingKeyExchange(wrongAlgorithm);
    assert(!algorithmDenied);
    assert(algorithmDenied.error ==
           RdpClientLicensingKeyExchangeError::MalformedBody);

    auto wrongBlob = valid;
    wrongBlob[44U] = 1U;
    const auto blobDenied =
        parseRdpClientLicensingKeyExchange(wrongBlob);
    assert(!blobDenied);
    assert(blobDenied.error ==
           RdpClientLicensingKeyExchangeError::MalformedBody);

    constexpr std::array<std::uint8_t, 4> challengeResponse{
        0x15, 0x03, 0x04, 0x00};
    const auto unexpected =
        parseRdpClientLicensingKeyExchange(challengeResponse);
    assert(!unexpected);
    assert(unexpected.error ==
           RdpClientLicensingKeyExchangeError::UnexpectedMessage);
}

void testRdpLicensingKeyDerivation()
{
    std::array<std::uint8_t, kRdpLicensingPreMasterSecretBytes> preMaster{};
    std::array<std::uint8_t, kRdpLicensingRandomBytes> clientRandom{};
    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom{};
    for (std::size_t index = 0; index < preMaster.size(); ++index)
        preMaster[index] = static_cast<std::uint8_t>(index);
    for (std::size_t index = 0; index < clientRandom.size(); ++index)
    {
        clientRandom[index] = static_cast<std::uint8_t>(0xa0U + index);
        serverRandom[index] = static_cast<std::uint8_t>(index + 1U);
    }

    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> expectedMac{
        0xf0,0x06,0xe2,0xb6,0x29,0x7c,0x71,0x85,
        0xc0,0x03,0xde,0x89,0x95,0x6c,0x00,0xe9};
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes>
        expectedEncryption{
        0x24,0x40,0x04,0x1d,0xf7,0x5e,0x84,0x2f,
        0x16,0xa7,0x90,0xc1,0xe0,0x4f,0xb4,0xb4};

    const auto result =
        deriveRdpLicensingKeys(preMaster, clientRandom, serverRandom);
    assert(result);
    assert(result.value.macSaltKey == expectedMac);
    assert(result.value.encryptionKey == expectedEncryption);

    const auto shortPreMaster = deriveRdpLicensingKeys(
        std::span(preMaster).first(preMaster.size() - 1U),
        clientRandom, serverRandom);
    assert(!shortPreMaster);
    assert(shortPreMaster.error ==
           RdpLicensingKeyDerivationError::InvalidInput);
}

void testRdpLicensingRc4Wire()
{
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> plain{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
        0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};

    std::array<std::uint8_t, plain.size()> output{};
    assert(cryptRdpLicensingData(key, plain, output));
    assert(output == cipher);
    assert(cryptRdpLicensingData(key, output, output));
    assert(output == plain);

    // memmove staging makes partial overlap deterministic and safe.
    std::array<std::uint8_t, plain.size() + 2U> overlap{};
    std::copy(plain.begin(), plain.end(), overlap.begin());
    assert(cryptRdpLicensingData(
        key,
        std::span<const std::uint8_t>{overlap.data(), plain.size()},
        std::span<std::uint8_t>{overlap.data() + 2U, plain.size()}));
    assert(std::equal(
        overlap.begin() + 2U, overlap.end(), cipher.begin()));

    std::array<std::uint8_t, plain.size()> guarded{};
    guarded.fill(0xa5U);
    assert(!cryptRdpLicensingData(
        std::span(key).first(key.size() - 1U), plain, guarded));
    assert(std::all_of(
        guarded.begin(), guarded.end(),
        [](std::uint8_t value) { return value == 0xa5U; }));
    assert(!cryptRdpLicensingData(
        key, plain, std::span(guarded).first(guarded.size() - 1U)));
}

void testRdpLicensingMacWire()
{
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> data{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
        0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13};
    // Independent MS-RDPELE 5.1.5 oracle:
    // MD5(key || pad2 || SHA1(key || pad1 || LE32(20) || data)).
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> expected{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    const auto result = generateRdpLicensingMac(key, data);
    assert(result);
    assert(result.value == expected);

    const auto badKey = generateRdpLicensingMac(
        std::span(key).first(key.size() - 1U), data);
    assert(!badKey);
    assert(badKey.error == RdpLicensingMacError::InvalidKey);
    assert(std::all_of(
        badKey.value.begin(), badKey.value.end(),
        [](std::uint8_t value) { return value == 0U; }));
}

void testRdpClientLicenseInfoHardwareIdProof()
{
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> mac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    const auto message =
        makeClientLicenseInfoWithHardwareProof(cipher, mac);
    const auto view = parseRdpClientLicenseInfo(message);
    assert(view);
    assert(view.value.licenseInfo.size() == 3U);
    assert(std::equal(
        view.value.encryptedHardwareId.begin(),
        view.value.encryptedHardwareId.end(), cipher.begin()));
    assert(std::equal(
        view.value.macData.begin(), view.value.macData.end(), mac.begin()));

    RdpLicensingKeyMaterial material{};
    material.macSaltKey = key;
    material.encryptionKey = key;
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));
    cleanseRdpLicensingKeyMaterial(material);
}

void testRdpClientLicenseInfoHardwareIdDenials()
{
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> mac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    RdpLicensingKeyMaterial material{};
    material.macSaltKey = key;
    material.encryptionKey = key;

    auto badMac = mac;
    badMac[0] ^= 0x01U;
    const auto macMessage =
        makeClientLicenseInfoWithHardwareProof(cipher, badMac);
    const auto macDenied =
        verifyRdpClientLicenseInfoHardwareId(macMessage, material);
    assert(!macDenied);
    assert(macDenied.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);

    auto badCipher = cipher;
    badCipher[3] ^= 0x80U;
    const auto cipherMessage =
        makeClientLicenseInfoWithHardwareProof(badCipher, mac);
    const auto cipherDenied =
        verifyRdpClientLicenseInfoHardwareId(cipherMessage, material);
    assert(!cipherDenied);
    assert(cipherDenied.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);

    auto wrongKey = material;
    wrongKey.encryptionKey[0] ^= 0x01U;
    const auto wrongKeyDenied =
        verifyRdpClientLicenseInfoHardwareId(
            makeClientLicenseInfoWithHardwareProof(cipher, mac), wrongKey);
    assert(!wrongKeyDenied);
    assert(wrongKeyDenied.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);
    cleanseRdpLicensingKeyMaterial(wrongKey);

    const auto unexpected =
        verifyRdpClientLicenseInfoHardwareId(
            makeClientNewLicenseRequest(), material);
    assert(!unexpected);
    assert(unexpected.error ==
           RdpClientLicenseInfoHardwareIdError::InvalidMessage);

    // Exact CLIENT_HARDWARE_ID length is structural, not merely cryptographic.
    auto malformed = makeClientLicenseInfoWithHardwareProof(cipher, mac);
    // Packet offsets: 4-byte preamble + 40-byte fixed client prefix,
    // premaster BLOB (4+2), LicenseInfo BLOB (4+3), then the EncryptedHWID
    // BLOB header. Its little-endian length therefore begins at offset 59.
    constexpr std::size_t encryptedHardwareLengthOffset = 59U;
    assert(malformed.size() > encryptedHardwareLengthOffset + 1U);
    malformed[encryptedHardwareLengthOffset] =
        static_cast<std::uint8_t>(kRdpLicensingHardwareIdBytes - 1U);
    malformed[encryptedHardwareLengthOffset + 1U] = 0U;
    const auto malformedDenied =
        verifyRdpClientLicenseInfoHardwareId(malformed, material);
    assert(!malformedDenied);
    assert(malformedDenied.error ==
           RdpClientLicenseInfoHardwareIdError::InvalidMessage);

    cleanseRdpLicensingKeyMaterial(material);
}


void testRdpClientLicenseInfoHardwareIdFreshVerification()
{
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> mac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    RdpLicensingKeyMaterial material{};
    material.macSaltKey = key;
    material.encryptionKey = key;
    const RdpLicensingKeyMaterial originalMaterial = material;

    auto message = makeClientLicenseInfoWithHardwareProof(cipher, mac);
    const auto parsed = parseRdpClientLicenseInfo(message);
    assert(parsed);
    const auto macOffset = static_cast<std::size_t>(
        parsed.value.macData.data() - message.data());
    const auto hardwareOffset = static_cast<std::size_t>(
        parsed.value.encryptedHardwareId.data() - message.data());
    assert(macOffset < message.size());
    assert(hardwareOffset + 7U < message.size());

    // A previous success is not a reusable proof. The verifier must parse and
    // authenticate the bytes presented by each call without mutating its keys.
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));
    assert(material.macSaltKey == originalMaterial.macSaltKey);
    assert(material.encryptionKey == originalMaterial.encryptionKey);

    message[macOffset] ^= 0x01U;
    const auto staleMac =
        verifyRdpClientLicenseInfoHardwareId(message, material);
    assert(!staleMac);
    assert(staleMac.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);
    assert(material.macSaltKey == originalMaterial.macSaltKey);
    assert(material.encryptionKey == originalMaterial.encryptionKey);

    // Restoring the caller-owned bytes permits a new stateless verification;
    // this is not session/licensing authority and does not revive R3 state.
    message[macOffset] ^= 0x01U;
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));

    message[hardwareOffset + 7U] ^= 0x80U;
    const auto staleCipher =
        verifyRdpClientLicenseInfoHardwareId(message, material);
    assert(!staleCipher);
    assert(staleCipher.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);
    assert(material.macSaltKey == originalMaterial.macSaltKey);
    assert(material.encryptionKey == originalMaterial.encryptionKey);

    message[hardwareOffset + 7U] ^= 0x80U;
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));

    cleanseRdpLicensingKeyMaterial(material);
    assert(std::all_of(
        material.macSaltKey.begin(), material.macSaltKey.end(),
        [](std::uint8_t value) { return value == 0U; }));
    assert(std::all_of(
        material.encryptionKey.begin(), material.encryptionKey.end(),
        [](std::uint8_t value) { return value == 0U; }));
}

constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes>
    kExistingCalProofKey{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes>
    kExistingCalEncryptedHardwareId{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
constexpr std::array<std::uint8_t, kRdpLicensingMacBytes>
    kExistingCalHardwareIdMac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};
constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes>
    kExistingCalPlainHardwareId{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
        0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13};

[[nodiscard]] RdpLicensingKeyMaterial
existingCalProofKeys() noexcept
{
    RdpLicensingKeyMaterial keys{};
    keys.macSaltKey = kExistingCalProofKey;
    keys.encryptionKey = kExistingCalProofKey;
    return keys;
}

[[nodiscard]] RdpClientLicenseInfoHardwareIdProofResult
makeExistingCalHardwareIdProof(
    std::span<const std::uint8_t> licenseInfo)
{
    auto keys = existingCalProofKeys();
    const auto message = makeClientLicenseInfoWithHardwareProof(
        kExistingCalEncryptedHardwareId,
        kExistingCalHardwareIdMac,
        licenseInfo);
    auto result = verifyAndRetainRdpClientLicenseInfoHardwareId(
        message, keys);
    cleanseRdpLicensingKeyMaterial(keys);
    return result;
}

void testExistingCalAuthorityRequestOwnership()
{
    static_assert(
        !std::is_copy_constructible_v<
            RdpExistingClientCalAuthorityRequest>);
    static_assert(
        std::is_move_constructible_v<
            RdpExistingClientCalAuthorityRequest>);
    static_assert(
        !std::is_move_assignable_v<
            RdpExistingClientCalAuthorityRequest>);

    std::vector<std::uint8_t> exactMaximumCal(
        kMaximumRdpClientCalBytes, 0x42U);
    auto hardwareProof =
        makeExistingCalHardwareIdProof(exactMaximumCal);
    assert(hardwareProof);

    RdpExistingClientCalAuthorityRequest request;
    {
        RdpServerLicenseIdentity identity;
        assert(configureServerLicenseIdentity(identity));
        assert(
            RdpExistingClientCalAuthorityRequestTestAccess::
                bindProductIdentity(request, identity) ==
            RdpExistingClientCalAuthorityRequestError::None);
        assert(request.productIdentityBound());
        assert(request.matchesProductIdentity(identity));
    }

    constexpr std::int64_t verificationUnixSeconds = 1780315200LL;
    constexpr std::uint64_t admissionGeneration = 0x1020304050607080ULL;
    constexpr std::uint64_t sessionGeneration = 0x8877665544332211ULL;
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(hardwareProof.proof),
            exactMaximumCal, verificationUnixSeconds,
            admissionGeneration, sessionGeneration) ==
        RdpExistingClientCalAuthorityRequestError::None);
    assert(request.active());
    assert(request.productVersion() == 0x00060001U);
    assert(std::equal(
        request.companyNameUtf16().begin(),
        request.companyNameUtf16().end(),
        kServerLicenseCompany.begin()));
    assert(std::equal(
        request.productIdUtf16().begin(),
        request.productIdUtf16().end(),
        kServerLicenseProduct.begin()));
    assert(std::equal(
        request.scopeAnsi().begin(), request.scopeAnsi().end(),
        kServerLicenseScope.begin()));
    assert(request.licenseInfo().size() == kMaximumRdpClientCalBytes);
    assert(std::all_of(
        request.licenseInfo().begin(), request.licenseInfo().end(),
        [](std::uint8_t value) { return value == 0x42U; }));
    assert(std::equal(
        request.hardwareId().begin(), request.hardwareId().end(),
        kExistingCalPlainHardwareId.begin()));
    assert(request.verificationUnixSeconds() == verificationUnixSeconds);
    assert(request.admissionGeneration() == admissionGeneration);
    assert(request.sessionGeneration() == sessionGeneration);
    assert(request.requestCorrelation().size() ==
           kRdpExistingClientCalAuthorityRequestCorrelationBytes);
    assert(!std::all_of(
        request.requestCorrelation().begin(),
        request.requestCorrelation().end(),
        [](std::uint8_t value) { return value == 0U; }));

    // Request storage owns the exact bytes independently of peer/test buffers.
    std::fill(exactMaximumCal.begin(), exactMaximumCal.end(), 0U);
    assert(std::all_of(
        request.licenseInfo().begin(), request.licenseInfo().end(),
        [](std::uint8_t value) { return value == 0x42U; }));

    RdpExistingClientCalAuthorityRequest moved{std::move(request)};
    assert(!request.active());
    assert(moved.active());
    assert(std::equal(
        moved.hardwareId().begin(), moved.hardwareId().end(),
        kExistingCalPlainHardwareId.begin()));
    moved.retire();
    assert(!moved.active());
    assert(moved.licenseInfo().empty());
    assert(moved.hardwareId().empty());
    assert(moved.requestCorrelation().empty());
}

void testExistingCalAuthorityRequestHardwareProofGate()
{
    static_assert(
        !std::is_constructible_v<
            RdpClientLicenseInfoHardwareIdProof,
            std::span<const std::uint8_t>, bool>);
    static_assert(
        !std::is_constructible_v<
            RdpExistingClientCalAuthorityRequest,
            std::span<const std::uint8_t>, bool>);

    constexpr std::array<std::uint8_t, 3> opaqueCal{0x41U, 0x42U, 0x43U};
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    RdpExistingClientCalAuthorityRequest request;
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::
            bindProductIdentity(request, identity) ==
        RdpExistingClientCalAuthorityRequestError::None);

    RdpClientLicenseInfoHardwareIdProof missingProof;
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(missingProof), opaqueCal,
            1780315200LL, 11U, 22U) ==
        RdpExistingClientCalAuthorityRequestError::MissingHardwareProof);
    assert(!request.active());

    auto keys = existingCalProofKeys();
    auto badMac = kExistingCalHardwareIdMac;
    badMac[0] ^= 0x01U;
    const auto badMacMessage = makeClientLicenseInfoWithHardwareProof(
        kExistingCalEncryptedHardwareId, badMac, opaqueCal);
    const auto badMacProof =
        verifyAndRetainRdpClientLicenseInfoHardwareId(
            badMacMessage, keys);
    assert(!badMacProof);
    assert(badMacProof.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);

    auto alteredHardwareId = kExistingCalEncryptedHardwareId;
    alteredHardwareId[7] ^= 0x80U;
    const auto alteredMessage = makeClientLicenseInfoWithHardwareProof(
        alteredHardwareId, kExistingCalHardwareIdMac, opaqueCal);
    const auto alteredProof =
        verifyAndRetainRdpClientLicenseInfoHardwareId(
            alteredMessage, keys);
    assert(!alteredProof);
    assert(alteredProof.error ==
           RdpClientLicenseInfoHardwareIdError::MacMismatch);

    const auto unsupportedBranch =
        verifyAndRetainRdpClientLicenseInfoHardwareId(
            makeClientNewLicenseRequest(), keys);
    assert(!unsupportedBranch);
    assert(unsupportedBranch.error ==
           RdpClientLicenseInfoHardwareIdError::InvalidMessage);

    auto malformedMessage = makeClientLicenseInfoWithHardwareProof(
        kExistingCalEncryptedHardwareId,
        kExistingCalHardwareIdMac,
        opaqueCal);
    const auto parsed = parseRdpClientLicenseInfo(malformedMessage);
    assert(parsed);
    const auto licenseOffset = static_cast<std::size_t>(
        parsed.value.licenseInfo.data() - malformedMessage.data());
    assert(licenseOffset >= 2U);
    malformedMessage[licenseOffset - 2U] = 0U;
    malformedMessage[licenseOffset - 1U] = 0U;
    const auto malformedProof =
        verifyAndRetainRdpClientLicenseInfoHardwareId(
            malformedMessage, keys);
    assert(!malformedProof);
    assert(malformedProof.error ==
           RdpClientLicenseInfoHardwareIdError::InvalidMessage);
    cleanseRdpLicensingKeyMaterial(keys);

    auto emptyCalProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(emptyCalProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(emptyCalProof.proof), {},
            1780315200LL, 11U, 22U) ==
        RdpExistingClientCalAuthorityRequestError::InvalidLicense);
    assert(!request.active());

    std::vector<std::uint8_t> oversizedCal(
        kMaximumRdpClientCalBytes + 1U, 0x33U);
    auto oversizedProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(oversizedProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(oversizedProof.proof), oversizedCal,
            1780315200LL, 11U, 22U) ==
        RdpExistingClientCalAuthorityRequestError::OversizedLicense);
    assert(!request.active());

    auto validProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(validProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(validProof.proof), opaqueCal,
            1780315200LL, 11U, 22U) ==
        RdpExistingClientCalAuthorityRequestError::None);
    assert(request.active());
    assert(std::equal(
        request.hardwareId().begin(), request.hardwareId().end(),
        kExistingCalPlainHardwareId.begin()));
}

void testExistingCalAuthorityRequestProductAndCorrelationDenials()
{
    constexpr std::array<std::uint8_t, 3> opaqueCal{0x41U, 0x42U, 0x43U};
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));

    auto differentProduct = kServerLicenseProduct;
    differentProduct[0] = 0x42U;
    RdpServerLicenseIdentity wrongProduct;
    assert(wrongProduct.configure(
        0x00060001U, kServerLicenseCompany, differentProduct,
        kServerLicenseCertificate, kServerLicenseScope));

    auto differentScope = kServerLicenseScope;
    differentScope[0] = 0x78U;
    RdpServerLicenseIdentity wrongScope;
    assert(wrongScope.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        kServerLicenseCertificate, differentScope));

    RdpExistingClientCalAuthorityRequest request;
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::
            bindProductIdentity(request, identity) ==
        RdpExistingClientCalAuthorityRequestError::None);
    assert(request.matchesProductIdentity(identity));
    assert(!request.matchesProductIdentity(wrongProduct));
    assert(!request.matchesProductIdentity(wrongScope));
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::
            bindProductIdentity(request, identity) ==
        RdpExistingClientCalAuthorityRequestError::AlreadyBound);

    auto invalidTimeProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(invalidTimeProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(invalidTimeProof.proof), opaqueCal,
            0, 31U, 41U) ==
        RdpExistingClientCalAuthorityRequestError::InvalidVerificationTime);
    assert(!request.active());

    auto zeroGenerationProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(zeroGenerationProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(zeroGenerationProof.proof), opaqueCal,
            1780315200LL, 0U, 41U) ==
        RdpExistingClientCalAuthorityRequestError::InvalidAdmissionGeneration);
    assert(!request.active());

    constexpr std::uint64_t admissionGeneration = 31U;
    constexpr std::uint64_t sessionGeneration = 41U;
    auto validProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(validProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(validProof.proof), opaqueCal,
            1780315200LL, admissionGeneration, sessionGeneration) ==
        RdpExistingClientCalAuthorityRequestError::None);

    std::array<std::uint8_t,
        kRdpExistingClientCalAuthorityRequestCorrelationBytes>
        correlation{};
    std::copy(
        request.requestCorrelation().begin(),
        request.requestCorrelation().end(),
        correlation.begin());
    assert(request.matchesRequest(
        correlation, admissionGeneration, sessionGeneration));

    auto wrongCorrelation = correlation;
    wrongCorrelation[0] ^= 0x80U;
    assert(!request.matchesRequest(
        wrongCorrelation, admissionGeneration, sessionGeneration));
    assert(!request.matchesRequest(
        correlation, admissionGeneration + 1U, sessionGeneration));
    assert(!request.matchesRequest(
        correlation, admissionGeneration, sessionGeneration + 1U));
    assert(!request.retireRequest(
        wrongCorrelation, admissionGeneration, sessionGeneration));
    assert(request.active());

    auto duplicateProof = makeExistingCalHardwareIdProof(opaqueCal);
    assert(duplicateProof);
    assert(
        RdpExistingClientCalAuthorityRequestTestAccess::complete(
            request, std::move(duplicateProof.proof), opaqueCal,
            1780315201LL, admissionGeneration, sessionGeneration) ==
        RdpExistingClientCalAuthorityRequestError::AlreadyCompleted);
    assert(request.matchesRequest(
        correlation, admissionGeneration, sessionGeneration));
}


void testMcsExistingCalSynchronousReadOnlyLifetime()
{
    constexpr std::uint64_t admissionGeneration = 111U;
    constexpr std::uint64_t sessionGeneration = 222U;
    std::vector<std::uint8_t> cal(kMaximumRdpClientCalBytes, 0x42U);
    const auto message = makeClientLicenseInfoWithHardwareProof(
        kExistingCalEncryptedHardwareId, kExistingCalHardwareIdMac, cal);
    auto proof = makeExistingCalHardwareIdProof(cal);
    assert(proof);
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));

    McsSessionLifecycle session;
    std::size_t visits = 0;
    const auto inspect = +[](
        const RdpExistingClientCalAuthorityRequest &request,
        void *opaque) noexcept
    {
        auto &count = *static_cast<std::size_t *>(opaque);
        ++count;
        assert(request.active());
        assert(request.licenseInfo().size() == kMaximumRdpClientCalBytes);
        assert(std::all_of(request.licenseInfo().begin(),
                           request.licenseInfo().end(),
                           [](std::uint8_t byte) { return byte == 0x42U; }));
        assert(std::equal(request.hardwareId().begin(),
                          request.hardwareId().end(),
                          kExistingCalPlainHardwareId.begin()));
        assert(request.verificationUnixSeconds() == 1780315200LL);
        assert(request.productVersion() == 0x00060001U);
        assert(std::equal(request.companyNameUtf16().begin(),
                          request.companyNameUtf16().end(),
                          kServerLicenseCompany.begin()));
        assert(std::equal(request.productIdUtf16().begin(),
                          request.productIdUtf16().end(),
                          kServerLicenseProduct.begin()));
        assert(std::equal(request.scopeAnsi().begin(),
                          request.scopeAnsi().end(),
                          kServerLicenseScope.begin()));
        assert(request.requestCorrelation().size() ==
               kRdpExistingClientCalAuthorityRequestCorrelationBytes);
        assert(request.admissionGeneration() == admissionGeneration);
        assert(request.sessionGeneration() == sessionGeneration);
    };
    assert(!session.visitExistingClientCalAuthorityRequest(inspect, &visits));
    assert(McsSessionLifecycleTestAccess::stage(
        session, identity, std::move(proof.proof), cal, message,
        admissionGeneration, sessionGeneration));
    std::fill(cal.begin(), cal.end(), 0U);
    assert(!session.visitExistingClientCalAuthorityRequest(nullptr, &visits));
    assert(session.visitExistingClientCalAuthorityRequest(inspect, &visits));
    assert(visits == 1U);
    assert(session.licensingPhase() == RdpLicensingPhase::AwaitServerDecision);
    McsSessionLifecycleTestAccess::phaseMismatch(session);
    assert(!session.visitExistingClientCalAuthorityRequest(inspect, &visits));
    McsSessionLifecycleTestAccess::restorePhase(session);
    assert(session.visitExistingClientCalAuthorityRequest(inspect, &visits));
    McsSessionLifecycleTestAccess::consumed(session);
    assert(!session.visitExistingClientCalAuthorityRequest(inspect, &visits));
    assert(visits == 2U);
    session.close();
    assert(!session.visitExistingClientCalAuthorityRequest(inspect, &visits));

    auto secondProof = makeExistingCalHardwareIdProof(
        std::array<std::uint8_t, 3>{0x41U, 0x42U, 0x43U});
    assert(secondProof);
    constexpr std::array<std::uint8_t, 3> smallCal{0x41U, 0x42U, 0x43U};
    const auto secondMessage = makeClientLicenseInfoWithHardwareProof(
        kExistingCalEncryptedHardwareId, kExistingCalHardwareIdMac, smallCal);
    McsSessionLifecycle replacement;
    assert(McsSessionLifecycleTestAccess::stage(
        replacement, identity, std::move(secondProof.proof),
        smallCal, secondMessage, admissionGeneration, sessionGeneration));
    McsSessionLifecycleTestAccess::stale(replacement);
    assert(!replacement.visitExistingClientCalAuthorityRequest(inspect, &visits));
    replacement.cancelExistingClientCalAuthorityRequest({});
    assert(!replacement.visitExistingClientCalAuthorityRequest(inspect, &visits));
    assert(visits == 2U);
}

void testExistingCalAuthorityRequestRevocationReplay()
{
    constexpr std::array<std::uint8_t, 3> opaqueCal{0x41U, 0x42U, 0x43U};
    constexpr std::uint64_t admissionGeneration = 51U;
    constexpr std::uint64_t sessionGeneration = 61U;

    const auto makeRequest =
        [&]() -> RdpExistingClientCalAuthorityRequest
        {
            RdpServerLicenseIdentity identity;
            assert(configureServerLicenseIdentity(identity));
            RdpExistingClientCalAuthorityRequest request;
            assert(
                RdpExistingClientCalAuthorityRequestTestAccess::
                    bindProductIdentity(request, identity) ==
                RdpExistingClientCalAuthorityRequestError::None);
            auto proof = makeExistingCalHardwareIdProof(opaqueCal);
            assert(proof);
            assert(
                RdpExistingClientCalAuthorityRequestTestAccess::complete(
                    request, std::move(proof.proof), opaqueCal,
                    1780315200LL,
                    admissionGeneration, sessionGeneration) ==
                RdpExistingClientCalAuthorityRequestError::None);
            return request;
        };

    auto generationRequest = makeRequest();
    std::array<std::uint8_t,
        kRdpExistingClientCalAuthorityRequestCorrelationBytes>
        generationCorrelation{};
    std::copy(
        generationRequest.requestCorrelation().begin(),
        generationRequest.requestCorrelation().end(),
        generationCorrelation.begin());
    generationRequest.revokeUnlessAdmissionBindingMatches(
        admissionGeneration, sessionGeneration);
    assert(generationRequest.active());
    generationRequest.revokeUnlessAdmissionBindingMatches(
        admissionGeneration + 1U, sessionGeneration);
    assert(!generationRequest.active());
    assert(generationRequest.licenseInfo().empty());
    assert(generationRequest.hardwareId().empty());
    assert(generationRequest.requestCorrelation().empty());
    assert(!generationRequest.matchesRequest(
        generationCorrelation, admissionGeneration, sessionGeneration));

    auto cancelledRequest = makeRequest();
    std::array<std::uint8_t,
        kRdpExistingClientCalAuthorityRequestCorrelationBytes>
        cancellationCorrelation{};
    std::copy(
        cancelledRequest.requestCorrelation().begin(),
        cancelledRequest.requestCorrelation().end(),
        cancellationCorrelation.begin());
    assert(cancelledRequest.retireRequest(
        cancellationCorrelation, admissionGeneration, sessionGeneration));
    assert(!cancelledRequest.active());
    // A late provider response or duplicate cancellation cannot revive the
    // retired request even if it repeats the exact old correlation/generations.
    assert(!cancelledRequest.matchesRequest(
        cancellationCorrelation, admissionGeneration, sessionGeneration));
    assert(!cancelledRequest.retireRequest(
        cancellationCorrelation, admissionGeneration, sessionGeneration));
}

using LicensingKeyPointer =
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using LicensingCertificatePointer =
    std::unique_ptr<X509, decltype(&X509_free)>;
using LicensingBioPointer =
    std::unique_ptr<BIO, decltype(&BIO_free)>;
using LicensingPkeyContextPointer =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using LicensingX509NamePointer =
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using LicensingPkcs7Pointer =
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)>;
using LicensingAsn1ObjectPointer =
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
using LicensingAsn1OctetStringPointer =
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>;
using LicensingExtensionPointer =
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;

[[nodiscard]] LicensingCertificatePointer makeLicensingFixtureCertificate(
    EVP_PKEY *subjectKey,
    const X509 *issuerCertificate,
    EVP_PKEY *issuerKey,
    long serial,
    std::string_view commonName,
    const EVP_MD *signatureDigest = EVP_sha256())
{
    LicensingCertificatePointer certificate{X509_new(), X509_free};
    assert(certificate);
    assert(X509_set_version(certificate.get(), 2) == 1);
    assert(ASN1_INTEGER_set(
               X509_get_serialNumber(certificate.get()), serial) == 1);
    assert(X509_gmtime_adj(
        X509_getm_notBefore(certificate.get()), -60));
    assert(X509_gmtime_adj(
        X509_getm_notAfter(certificate.get()), 3600));
    assert(X509_set_pubkey(certificate.get(), subjectKey) == 1);

    LicensingX509NamePointer subject{X509_NAME_new(), X509_NAME_free};
    assert(subject);
    assert(commonName.size() <=
           static_cast<std::size_t>(std::numeric_limits<int>::max()));
    assert(X509_NAME_add_entry_by_txt(
               subject.get(), "CN", MBSTRING_ASC,
               reinterpret_cast<const unsigned char *>(commonName.data()),
               static_cast<int>(commonName.size()), -1, 0) == 1);
    assert(X509_set_subject_name(certificate.get(), subject.get()) == 1);

    const X509_NAME *issuerName = issuerCertificate != nullptr
        ? X509_get_subject_name(issuerCertificate)
        : subject.get();
    assert(issuerName != nullptr);
    assert(X509_set_issuer_name(certificate.get(), issuerName) == 1);
    assert(signatureDigest != nullptr);
    assert(X509_sign(certificate.get(), issuerKey, signatureDigest) > 0);
    return certificate;
}

void setLicensingFixtureCertificateValidity(
    X509 *certificate,
    const char *notBefore,
    const char *notAfter)
{
    assert(certificate != nullptr);
    assert(notBefore != nullptr && notAfter != nullptr);
    assert(ASN1_TIME_set_string_X509(
               X509_getm_notBefore(certificate), notBefore) == 1);
    assert(ASN1_TIME_set_string_X509(
               X509_getm_notAfter(certificate), notAfter) == 1);
}

[[nodiscard]] std::vector<std::uint8_t> licensingFixtureCertificateDer(
    X509 *certificate)
{
    const int encodedBytes = i2d_X509(certificate, nullptr);
    assert(encodedBytes > 0);
    std::vector<std::uint8_t> encoded(
        static_cast<std::size_t>(encodedBytes));
    unsigned char *cursor = encoded.data();
    assert(i2d_X509(certificate, &cursor) == encodedBytes);
    assert(cursor == encoded.data() + encoded.size());
    return encoded;
}

[[nodiscard]] std::vector<std::uint8_t> licensingFixturePrivateKeyPem(
    EVP_PKEY *key)
{
    LicensingBioPointer bio{BIO_new(BIO_s_mem()), BIO_free};
    assert(bio);
    assert(PEM_write_bio_PrivateKey(
               bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1);

    const std::size_t bytes = BIO_ctrl_pending(bio.get());
    assert(bytes > 0U &&
           bytes <= kMaximumRdpLicensingPrivateKeyPemBytes);
    std::vector<std::uint8_t> pem(bytes);
    std::size_t bytesRead = 0U;
    assert(BIO_read_ex(
               bio.get(), pem.data(), pem.size(), &bytesRead) == 1);
    assert(bytesRead == pem.size());
    return pem;
}

void appendLicensingFixtureLe32(
    std::vector<std::uint8_t> &output,
    std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
}

constexpr std::array<const char *, 5> kClientCalRequiredExtensionOids{
    "1.3.6.1.4.1.311.18.4",
    "1.3.6.1.4.1.311.18.2",
    "1.3.6.1.4.1.311.18.5",
    "1.3.6.1.4.1.311.18.6",
    "1.3.6.1.4.1.311.18.7"};

void addClientCalFixtureExtension(
    X509 *certificate,
    const char *oid,
    std::span<const std::uint8_t> payload,
    bool critical = false)
{
    assert(certificate != nullptr && oid != nullptr);
    assert(payload.size() <=
           static_cast<std::size_t>((std::numeric_limits<int>::max)()));

    LicensingAsn1ObjectPointer object{OBJ_txt2obj(oid, 1), ASN1_OBJECT_free};
    LicensingAsn1OctetStringPointer value{
        ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free};
    assert(object && value);
    assert(ASN1_OCTET_STRING_set(
               value.get(), payload.data(),
               static_cast<int>(payload.size())) == 1);

    LicensingExtensionPointer extension{
        X509_EXTENSION_create_by_OBJ(
            nullptr, object.get(), critical ? 1 : 0, value.get()),
        X509_EXTENSION_free};
    assert(extension);
    assert(X509_add_ext(certificate, extension.get(), -1) == 1);
}

void addLicensingFixtureStandardExtension(
    X509 *certificate, int nid, std::string_view value)
{
    assert(certificate != nullptr);
    std::string mutableValue{value};
    LicensingExtensionPointer extension{
        X509V3_EXT_conf_nid(
            nullptr, nullptr, nid, mutableValue.data()),
        X509_EXTENSION_free};
    assert(extension);
    assert(X509_add_ext(certificate, extension.get(), -1) == 1);
}

void addLicensingFixtureIssuerConstraints(
    X509 *certificate,
    bool certificateAuthority = true,
    bool criticalBasicConstraints = true,
    bool includeKeyUsage = true,
    bool allowCertificateSigning = true)
{
    const std::string_view basicConstraints =
        certificateAuthority
        ? (criticalBasicConstraints
               ? "critical,CA:TRUE"
               : "CA:TRUE")
        : (criticalBasicConstraints
               ? "critical,CA:FALSE"
               : "CA:FALSE");
    addLicensingFixtureStandardExtension(
        certificate, NID_basic_constraints, basicConstraints);

    if (!includeKeyUsage)
        return;

    addLicensingFixtureStandardExtension(
        certificate, NID_key_usage,
        allowCertificateSigning
            ? "critical,keyCertSign"
            : "critical,digitalSignature");
}

void addRequiredClientCalFixtureExtensions(X509 *certificate)
{
    for (std::size_t index = 0U;
         index < kClientCalRequiredExtensionOids.size(); ++index)
    {
        const std::array<std::uint8_t, 3> payload{
            static_cast<std::uint8_t>(0x20U + index),
            static_cast<std::uint8_t>(0x40U + index),
            static_cast<std::uint8_t>(0x60U + index)};
        addClientCalFixtureExtension(
            certificate, kClientCalRequiredExtensionOids[index], payload);
    }
}

enum class ClientCalSignedContentKind : std::uint8_t
{
    Absent,
    Empty,
    NonEmpty,
};

[[nodiscard]] std::vector<std::uint8_t> encodeClientCalFixture(
    std::span<X509 *const> certificates,
    ClientCalSignedContentKind signedContentKind =
        ClientCalSignedContentKind::Empty)
{
    LicensingPkcs7Pointer container{PKCS7_new(), PKCS7_free};
    assert(container);
    assert(PKCS7_set_type(container.get(), NID_pkcs7_signed) == 1);
    assert(PKCS7_content_new(container.get(), NID_pkcs7_data) == 1);
    assert(container->d.sign != nullptr);
    assert(container->d.sign->contents != nullptr);
    ASN1_OCTET_STRING *signedContent =
        container->d.sign->contents->d.data;
    assert(signedContent != nullptr);
    if (signedContentKind == ClientCalSignedContentKind::Absent)
    {
        ASN1_OCTET_STRING_free(signedContent);
        container->d.sign->contents->d.data = nullptr;
    }
    else if (signedContentKind == ClientCalSignedContentKind::NonEmpty)
    {
        constexpr std::array<unsigned char, 1> payload{0x5aU};
        assert(ASN1_OCTET_STRING_set(
                   signedContent, payload.data(),
                   static_cast<int>(payload.size())) == 1);
    }
    // Empty uses PKCS7_content_new()'s allocated zero-length OCTET STRING.
    for (X509 *certificate : certificates)
    {
        assert(certificate != nullptr);
        assert(PKCS7_add_certificate(container.get(), certificate) == 1);
    }

    const int encodedBytes = i2d_PKCS7(container.get(), nullptr);
    assert(encodedBytes > 0);
    std::vector<std::uint8_t> encoded(
        static_cast<std::size_t>(encodedBytes));
    unsigned char *cursor = encoded.data();
    assert(i2d_PKCS7(container.get(), &cursor) == encodedBytes);
    assert(cursor == encoded.data() + encoded.size());
    return encoded;
}

[[nodiscard]] std::vector<std::uint8_t>
encodeUnsupportedClientCalFixture()
{
    LicensingPkcs7Pointer container{PKCS7_new(), PKCS7_free};
    assert(container);
    assert(PKCS7_set_type(container.get(), NID_pkcs7_data) == 1);
    constexpr std::array<unsigned char, 1> payload{0x01U};
    assert(container->d.data != nullptr);
    assert(ASN1_OCTET_STRING_set(
               container->d.data, payload.data(),
               static_cast<int>(payload.size())) == 1);

    const int encodedBytes = i2d_PKCS7(container.get(), nullptr);
    assert(encodedBytes > 0);
    std::vector<std::uint8_t> encoded(
        static_cast<std::size_t>(encodedBytes));
    unsigned char *cursor = encoded.data();
    assert(i2d_PKCS7(container.get(), &cursor) == encodedBytes);
    assert(cursor == encoded.data() + encoded.size());
    return encoded;
}

struct ClientCalFixture final
{
    LicensingKeyPointer rootKey{nullptr, EVP_PKEY_free};
    LicensingKeyPointer issuerKey{nullptr, EVP_PKEY_free};
    LicensingKeyPointer leafKey{nullptr, EVP_PKEY_free};
    LicensingKeyPointer alternateRootKey{nullptr, EVP_PKEY_free};
    LicensingCertificatePointer rootCertificate{nullptr, X509_free};
    LicensingCertificatePointer issuerCertificate{nullptr, X509_free};
    LicensingCertificatePointer leafCertificate{nullptr, X509_free};
    LicensingCertificatePointer alternateRootCertificate{nullptr, X509_free};
    std::vector<std::uint8_t> rootDer;
    std::vector<std::uint8_t> alternateRootDer;
    std::vector<std::uint8_t> cal;

    explicit ClientCalFixture(bool addRequiredExtensions = true)
    {
        // Synthetic hierarchy only. It proves verifier mechanics against an
        // explicit test anchor and is never a production CAL authority.
        rootKey.reset(EVP_RSA_gen(2048));
        issuerKey.reset(EVP_RSA_gen(2048));
        leafKey.reset(EVP_RSA_gen(2048));
        alternateRootKey.reset(EVP_RSA_gen(2048));
        assert(rootKey && issuerKey && leafKey && alternateRootKey);

        rootCertificate = makeLicensingFixtureCertificate(
            rootKey.get(), nullptr, rootKey.get(), 101L,
            "rdp-cal-test-root", EVP_sha1());
        issuerCertificate = makeLicensingFixtureCertificate(
            issuerKey.get(), rootCertificate.get(), rootKey.get(), 102L,
            "rdp-cal-test-issuer", EVP_sha1());
        addLicensingFixtureIssuerConstraints(issuerCertificate.get());
        assert(X509_sign(
                   issuerCertificate.get(), rootKey.get(),
                   EVP_sha1()) > 0);
        leafCertificate = makeLicensingFixtureCertificate(
            leafKey.get(), issuerCertificate.get(), issuerKey.get(), 103L,
            "rdp-cal-test-leaf", EVP_sha1());
        alternateRootCertificate = makeLicensingFixtureCertificate(
            alternateRootKey.get(), nullptr, alternateRootKey.get(), 201L,
            "rdp-cal-test-alternate-root", EVP_sha1());

        if (addRequiredExtensions)
        {
            addRequiredClientCalFixtureExtensions(leafCertificate.get());
            assert(X509_sign(
                       leafCertificate.get(), issuerKey.get(),
                       EVP_sha1()) > 0);
        }

        rootDer = licensingFixtureCertificateDer(rootCertificate.get());
        alternateRootDer =
            licensingFixtureCertificateDer(alternateRootCertificate.get());
        rebuild();
    }

    void rebuild()
    {
        // CertificateSet is a DER SET; insertion order is intentionally not
        // treated as issuer authority by production CAL inspection.
        const std::array<X509 *, 3> certificates{
            leafCertificate.get(),
            rootCertificate.get(),
            issuerCertificate.get()};
        cal = encodeClientCalFixture(certificates);
        assert(cal.size() <= kMaximumRdpClientCalBytes);
    }
};

[[nodiscard]] std::vector<std::uint8_t> corruptClientCalLeafSignature(
    const ClientCalFixture &fixture)
{
    auto corrupted = fixture.cal;
    const auto leafDer =
        licensingFixtureCertificateDer(fixture.leafCertificate.get());
    const auto leafBegin = std::search(
        corrupted.begin(), corrupted.end(), leafDer.begin(), leafDer.end());
    assert(leafBegin != corrupted.end());

    const ASN1_BIT_STRING *signature = nullptr;
    const X509_ALGOR *algorithm = nullptr;
    X509_get0_signature(
        &signature, &algorithm, fixture.leafCertificate.get());
    assert(signature != nullptr && algorithm != nullptr);
    const int signatureLength = ASN1_STRING_length(signature);
    const unsigned char *signatureData =
        ASN1_STRING_get0_data(signature);
    assert(signatureData != nullptr && signatureLength > 0);

    const std::span<const std::uint8_t> signatureBytes{
        signatureData, static_cast<std::size_t>(signatureLength)};
    const auto signatureBegin = std::search(
        leafDer.begin(), leafDer.end(),
        signatureBytes.begin(), signatureBytes.end());
    assert(signatureBegin != leafDer.end());

    const std::size_t leafOffset = static_cast<std::size_t>(
        leafBegin - corrupted.begin());
    const std::size_t signatureOffset = static_cast<std::size_t>(
        signatureBegin - leafDer.begin());
    assert(leafOffset + signatureOffset < corrupted.size());
    corrupted[leafOffset + signatureOffset] ^= 0x01U;
    return corrupted;
}

struct LicensingCryptoFixture final
{
    LicensingKeyPointer rootKey{nullptr, EVP_PKEY_free};
    LicensingKeyPointer terminalKey{nullptr, EVP_PKEY_free};
    LicensingCertificatePointer rootCertificate{nullptr, X509_free};
    LicensingCertificatePointer terminalCertificate{nullptr, X509_free};
    std::vector<std::uint8_t> serverCertificate;
    std::vector<std::uint8_t> privateKeyPem;
    std::vector<std::uint8_t> mismatchedPrivateKeyPem;
    std::vector<std::uint8_t> encryptedPreMasterSecret;
    std::array<std::uint8_t, kRdpLicensingPreMasterSecretBytes> preMaster{};

    LicensingCryptoFixture()
    {
        // Ephemeral offline crypto fixture only. It is never service
        // provisioning, never trusted as a license authority, and never
        // enters the R2/R3 admission path.
        rootKey.reset(EVP_RSA_gen(2048));
        terminalKey.reset(EVP_RSA_gen(2048));
        assert(rootKey && terminalKey);

        rootCertificate = makeLicensingFixtureCertificate(
            rootKey.get(), nullptr, rootKey.get(), 1L,
            "rdp-licensing-test-root");
        terminalCertificate = makeLicensingFixtureCertificate(
            terminalKey.get(), rootCertificate.get(), rootKey.get(), 2L,
            "rdp-licensing-test-terminal");

        const auto rootDer =
            licensingFixtureCertificateDer(rootCertificate.get());
        const auto terminalDer =
            licensingFixtureCertificateDer(terminalCertificate.get());
        privateKeyPem =
            licensingFixturePrivateKeyPem(terminalKey.get());
        mismatchedPrivateKeyPem =
            licensingFixturePrivateKeyPem(rootKey.get());

        // SERVER_CERTIFICATE::dwVersion = CERT_CHAIN_VERSION_2 followed by
        // X509_CERTIFICATE_CHAIN with root-first order and terminal leaf last.
        appendLicensingFixtureLe32(serverCertificate, 0x00000002U);
        appendLicensingFixtureLe32(serverCertificate, 2U);
        appendLicensingFixtureLe32(
            serverCertificate,
            static_cast<std::uint32_t>(rootDer.size()));
        serverCertificate.insert(
            serverCertificate.end(), rootDer.begin(), rootDer.end());
        appendLicensingFixtureLe32(
            serverCertificate,
            static_cast<std::uint32_t>(terminalDer.size()));
        serverCertificate.insert(
            serverCertificate.end(), terminalDer.begin(), terminalDer.end());
        serverCertificate.resize(
            serverCertificate.size() + 16U, 0U); // 8 + 4*NumCertBlobs
        assert(serverCertificate.size() <=
               kMaximumRdpServerLicenseCertificateBytes);

        for (std::size_t index = 0U; index < preMaster.size(); ++index)
            preMaster[index] =
                static_cast<std::uint8_t>(0x31U + index);

        const int keyBytesSigned = EVP_PKEY_get_size(terminalKey.get());
        assert(keyBytesSigned > 0);
        const std::size_t keyBytes =
            static_cast<std::size_t>(keyBytesSigned);
        assert(keyBytes <= kMaximumRdpLicensingRsaModulusBytes);

        std::array<std::uint8_t, kMaximumRdpLicensingRsaModulusBytes>
            plaintextLittleEndian{};
        std::array<std::uint8_t, kMaximumRdpLicensingRsaModulusBytes>
            plaintextBigEndian{};
        std::array<std::uint8_t, kMaximumRdpLicensingRsaModulusBytes>
            ciphertextBigEndian{};
        std::copy(
            preMaster.begin(), preMaster.end(),
            plaintextLittleEndian.begin());
        std::reverse_copy(
            plaintextLittleEndian.begin(),
            plaintextLittleEndian.begin() +
                static_cast<std::ptrdiff_t>(keyBytes),
            plaintextBigEndian.begin());

        LicensingPkeyContextPointer context{
            EVP_PKEY_CTX_new(terminalKey.get(), nullptr),
            EVP_PKEY_CTX_free};
        assert(context);
        assert(EVP_PKEY_encrypt_init(context.get()) == 1);
        assert(EVP_PKEY_CTX_set_rsa_padding(
                   context.get(), RSA_NO_PADDING) == 1);
        std::size_t encryptedBytes = keyBytes;
        assert(EVP_PKEY_encrypt(
                   context.get(), ciphertextBigEndian.data(),
                   &encryptedBytes, plaintextBigEndian.data(),
                   keyBytes) == 1);
        assert(encryptedBytes == keyBytes);

        encryptedPreMasterSecret.resize(keyBytes + 8U, 0U);
        std::reverse_copy(
            ciphertextBigEndian.begin(),
            ciphertextBigEndian.begin() +
                static_cast<std::ptrdiff_t>(keyBytes),
            encryptedPreMasterSecret.begin());
    }
};

void testRdpClientCalChainStructure()
{
    ClientCalFixture fixture;
    const auto accepted =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(accepted.error == RdpClientCalChainError::None);
    assert(accepted.facts.certificateCount == 3U);
    assert(accepted.facts.signaturesVerified);
    assert(accepted.facts.trustedIssuerMatched);
    assert(accepted.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);

    auto minimumLeaf = makeLicensingFixtureCertificate(
        fixture.leafKey.get(), fixture.rootCertificate.get(),
        fixture.rootKey.get(), 104L, "rdp-cal-minimum-leaf", EVP_sha1());
    addRequiredClientCalFixtureExtensions(minimumLeaf.get());
    assert(X509_sign(
               minimumLeaf.get(), fixture.rootKey.get(), EVP_sha1()) > 0);
    const std::array<X509 *, 2> minimumCertificates{
        minimumLeaf.get(), fixture.rootCertificate.get()};
    const auto minimumCal = encodeClientCalFixture(minimumCertificates);
    const auto minimumAccepted =
        inspectRdpClientCalCertificateChain(minimumCal, fixture.rootDer);
    assert(minimumAccepted.error == RdpClientCalChainError::None);
    assert(minimumAccepted.facts.certificateCount == 2U);

    const std::array<X509 *, 1> oneCertificate{
        fixture.rootCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(oneCertificate), fixture.rootDer).error ==
           RdpClientCalChainError::CertificateCountOutOfRange);

    auto truncated = fixture.cal;
    truncated.pop_back();
    assert(inspectRdpClientCalCertificateChain(
               truncated, fixture.rootDer).error ==
           RdpClientCalChainError::MalformedContainer);

    LicensingCertificatePointer oversizedLeaf{
        X509_dup(fixture.leafCertificate.get()), X509_free};
    assert(oversizedLeaf);
    const std::vector<std::uint8_t> largePayload(9000U, 0x5aU);
    addClientCalFixtureExtension(
        oversizedLeaf.get(), "1.3.6.1.4.1.55555.9", largePayload);
    assert(X509_sign(
               oversizedLeaf.get(), fixture.issuerKey.get(),
               EVP_sha1()) > 0);
    const std::array<X509 *, 3> oversizedCertificates{
        oversizedLeaf.get(), fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    const auto oversizedCertificateCal =
        encodeClientCalFixture(oversizedCertificates);
    assert(oversizedCertificateCal.size() <= kMaximumRdpClientCalBytes);
    assert(inspectRdpClientCalCertificateChain(
               oversizedCertificateCal, fixture.rootDer).error ==
           RdpClientCalChainError::OversizedCertificate);

    std::vector<std::uint8_t> oversizedCal(
        kMaximumRdpClientCalBytes + 1U, 0x30U);
    assert(inspectRdpClientCalCertificateChain(
               oversizedCal, fixture.rootDer).error ==
           RdpClientCalChainError::Oversized);

    const std::array<X509 *, 2> missingIssuerCertificates{
        fixture.rootCertificate.get(), fixture.leafCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(missingIssuerCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::MissingIssuer);

    auto trailing = fixture.cal;
    trailing.push_back(0U);
    assert(inspectRdpClientCalCertificateChain(
               trailing, fixture.rootDer).error ==
           RdpClientCalChainError::MalformedContainer);

    const std::array<X509 *, 4> duplicateCertificates{
        fixture.leafCertificate.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get(),
        fixture.issuerCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(duplicateCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::DuplicateCertificate);

    auto secondLeaf = makeLicensingFixtureCertificate(
        fixture.leafKey.get(), fixture.issuerCertificate.get(),
        fixture.issuerKey.get(), 105L, "rdp-cal-second-leaf", EVP_sha1());
    addRequiredClientCalFixtureExtensions(secondLeaf.get());
    assert(X509_sign(
               secondLeaf.get(), fixture.issuerKey.get(),
               EVP_sha1()) > 0);
    const std::array<X509 *, 4> ambiguousCertificates{
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get(),
        fixture.leafCertificate.get(),
        secondLeaf.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(ambiguousCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::AmbiguousChain);

    const auto leafDer =
        licensingFixtureCertificateDer(fixture.leafCertificate.get());
    auto badInnerLength = fixture.cal;
    const auto leafBegin = std::search(
        badInnerLength.begin(), badInnerLength.end(),
        leafDer.begin(), leafDer.end());
    assert(leafBegin != badInnerLength.end());
    const std::size_t leafOffset = static_cast<std::size_t>(
        leafBegin - badInnerLength.begin());
    assert(leafDer.size() > 4U && leafDer[0] == 0x30U);
    badInnerLength[leafOffset + 3U] ^= 0x01U;
    assert(inspectRdpClientCalCertificateChain(
               badInnerLength, fixture.rootDer).error ==
           RdpClientCalChainError::MalformedContainer);

    const auto unsupportedContainer = encodeUnsupportedClientCalFixture();
    assert(inspectRdpClientCalCertificateChain(
               unsupportedContainer, fixture.rootDer).error ==
           RdpClientCalChainError::UnsupportedContainer);

    LicensingCryptoFixture serverCertificateFixture;
    assert(inspectRdpClientCalCertificateChain(
               serverCertificateFixture.serverCertificate,
               fixture.rootDer).error ==
           RdpClientCalChainError::MalformedContainer);
}

void testRdpClientCalSignedContentEmptyOnly()
{
    ClientCalFixture fixture;
    const std::array<X509 *, 3> certificates{
        fixture.leafCertificate.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};

    // A missing optional content OCTET STRING and an explicitly present,
    // zero-length one are both valid. A single payload octet must be denied
    // as UnsupportedContainer before any CAL chain is trusted.
    const auto absent = encodeClientCalFixture(
        certificates, ClientCalSignedContentKind::Absent);
    const auto empty = encodeClientCalFixture(
        certificates, ClientCalSignedContentKind::Empty);
    const auto nonempty = encodeClientCalFixture(
        certificates, ClientCalSignedContentKind::NonEmpty);
    assert(absent != empty && empty != nonempty && absent != nonempty);
    assert(inspectRdpClientCalCertificateChain(
               absent, fixture.rootDer).error ==
           RdpClientCalChainError::None);
    assert(inspectRdpClientCalCertificateChain(
               empty, fixture.rootDer).error ==
           RdpClientCalChainError::None);
    assert(inspectRdpClientCalCertificateChain(
               nonempty, fixture.rootDer).error ==
           RdpClientCalChainError::UnsupportedContainer);
}

void testRdpClientCalIssuerSignatureDenials()
{
    ClientCalFixture fixture;
    const auto verified =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(verified.error == RdpClientCalChainError::None);
    assert(verified.facts.signaturesVerified);
    assert(verified.facts.trustedIssuerMatched);

    assert(inspectRdpClientCalCertificateChain(
               corruptClientCalLeafSignature(fixture),
               fixture.rootDer).error ==
           RdpClientCalChainError::SignatureVerificationFailure);

    // Mutate already-signed DER and parse a fresh X509 object. Setter calls on
    // X509_dup() can retain provider-specific cached TBSCertificate bytes, so
    // they are not a reliable way to build a changed-signed-content fixture.
    auto changedSignedLeaf = makeLicensingFixtureCertificate(
        fixture.leafKey.get(), fixture.issuerCertificate.get(),
        fixture.issuerKey.get(), 108L, "rdp-cal-changed-signed-content",
        EVP_sha1());
    addRequiredClientCalFixtureExtensions(changedSignedLeaf.get());
    constexpr std::array<std::uint8_t, 16> signedContentMarker{
        0x91U, 0x26U, 0xe4U, 0x73U, 0x5bU, 0x0cU, 0xa8U, 0x3dU,
        0xf1U, 0x44U, 0x62U, 0x9eU, 0x17U, 0xb5U, 0x38U, 0xc0U};
    addClientCalFixtureExtension(
        changedSignedLeaf.get(), "1.3.6.1.4.1.55555.88",
        signedContentMarker);
    assert(X509_sign(
               changedSignedLeaf.get(), fixture.issuerKey.get(),
               EVP_sha1()) > 0);

    auto changedLeafDer =
        licensingFixtureCertificateDer(changedSignedLeaf.get());
    const auto markerBegin = std::search(
        changedLeafDer.begin(), changedLeafDer.end(),
        signedContentMarker.begin(), signedContentMarker.end());
    assert(markerBegin != changedLeafDer.end());
    const auto afterMarker = std::next(
        markerBegin,
        static_cast<std::ptrdiff_t>(signedContentMarker.size()));
    assert(std::search(
               afterMarker, changedLeafDer.end(),
               signedContentMarker.begin(),
               signedContentMarker.end()) == changedLeafDer.end());
    *markerBegin ^= 0x01U;

    const unsigned char *changedCursor = changedLeafDer.data();
    const unsigned char *const changedEnd =
        changedLeafDer.data() + changedLeafDer.size();
    LicensingCertificatePointer changedLeaf{
        d2i_X509(
            nullptr, &changedCursor,
            static_cast<long>(changedLeafDer.size())),
        X509_free};
    assert(changedLeaf && changedCursor == changedEnd);
    assert(X509_verify(
               changedLeaf.get(), fixture.issuerKey.get()) != 1);

    const std::array<X509 *, 3> changedCertificates{
        changedLeaf.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(changedCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::SignatureVerificationFailure);

    auto wrongIssuerLeaf = makeLicensingFixtureCertificate(
        fixture.leafKey.get(), fixture.issuerCertificate.get(),
        fixture.alternateRootKey.get(), 106L, "rdp-cal-wrong-key",
        EVP_sha1());
    addRequiredClientCalFixtureExtensions(wrongIssuerLeaf.get());
    assert(X509_sign(
               wrongIssuerLeaf.get(), fixture.alternateRootKey.get(),
               EVP_sha1()) > 0);
    const std::array<X509 *, 3> wrongIssuerCertificates{
        wrongIssuerLeaf.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(wrongIssuerCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::SignatureVerificationFailure);

    assert(inspectRdpClientCalCertificateChain(
               fixture.cal, fixture.alternateRootDer).error ==
           RdpClientCalChainError::UntrustedTrustAnchor);

    const auto peerRootOnly =
        inspectRdpClientCalCertificateChain(fixture.cal, {});
    assert(peerRootOnly.error == RdpClientCalChainError::MissingTrustAnchor);
    assert(peerRootOnly.facts.signaturesVerified);
    assert(!peerRootOnly.facts.trustedIssuerMatched);

    auto malformedAnchor = fixture.rootDer;
    malformedAnchor.push_back(0U);
    assert(inspectRdpClientCalCertificateChain(
               fixture.cal, malformedAnchor).error ==
           RdpClientCalChainError::MalformedTrustAnchor);

    LicensingCryptoFixture serverCertificateFixture;
    const auto terminalDer = licensingFixtureCertificateDer(
        serverCertificateFixture.terminalCertificate.get());
    assert(inspectRdpClientCalCertificateChain(
               fixture.cal, terminalDer).error ==
           RdpClientCalChainError::UntrustedTrustAnchor);

    LicensingCertificatePointer sha256Leaf{
        X509_dup(fixture.leafCertificate.get()), X509_free};
    assert(sha256Leaf);
    assert(X509_sign(
               sha256Leaf.get(), fixture.issuerKey.get(),
               EVP_sha256()) > 0);
    const std::array<X509 *, 3> sha256Certificates{
        sha256Leaf.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(sha256Certificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::UnsupportedSignatureAlgorithm);

    LicensingKeyPointer ecKey{
        EVP_EC_gen("prime256v1"), EVP_PKEY_free};
    assert(ecKey);
    auto ecLeaf = makeLicensingFixtureCertificate(
        ecKey.get(), fixture.issuerCertificate.get(),
        fixture.issuerKey.get(), 107L, "rdp-cal-ec-leaf", EVP_sha1());
    addRequiredClientCalFixtureExtensions(ecLeaf.get());
    assert(X509_sign(
               ecLeaf.get(), fixture.issuerKey.get(), EVP_sha1()) > 0);
    const std::array<X509 *, 3> ecCertificates{
        ecLeaf.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(ecCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::UnsupportedKeyType);

    const std::array<X509 *, 2> missingIssuerCertificates{
        fixture.rootCertificate.get(), fixture.leafCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(missingIssuerCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::MissingIssuer);
}

void testRdpClientCalIssuerConstraints()
{
    ClientCalFixture fixture;
    const auto accepted =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(accepted.error == RdpClientCalChainError::None);
    assert(accepted.facts.signaturesVerified);
    assert(accepted.facts.trustedIssuerMatched);
    assert(accepted.facts.issuerConstraintsVerified);

    const auto inspectWithIssuer =
        [&fixture](X509 *issuer)
        {
            const std::array<X509 *, 3> certificates{
                fixture.leafCertificate.get(),
                fixture.rootCertificate.get(),
                issuer};
            return inspectRdpClientCalCertificateChain(
                encodeClientCalFixture(certificates), fixture.rootDer);
        };

    auto missingBasicConstraints = makeLicensingFixtureCertificate(
        fixture.issuerKey.get(), fixture.rootCertificate.get(),
        fixture.rootKey.get(), 301L, "rdp-cal-test-issuer", EVP_sha1());
    const auto missing = inspectWithIssuer(
        missingBasicConstraints.get());
    assert(missing.error ==
           RdpClientCalChainError::InvalidIssuerConstraints);
    assert(missing.facts.signaturesVerified);
    assert(missing.facts.trustedIssuerMatched);
    assert(!missing.facts.issuerConstraintsVerified);

    auto nonCaIssuer = makeLicensingFixtureCertificate(
        fixture.issuerKey.get(), fixture.rootCertificate.get(),
        fixture.rootKey.get(), 302L, "rdp-cal-test-issuer", EVP_sha1());
    addLicensingFixtureIssuerConstraints(
        nonCaIssuer.get(), false, true, false, false);
    assert(X509_sign(
               nonCaIssuer.get(), fixture.rootKey.get(), EVP_sha1()) > 0);
    assert(inspectWithIssuer(nonCaIssuer.get()).error ==
           RdpClientCalChainError::InvalidIssuerConstraints);

    auto nonCriticalCa = makeLicensingFixtureCertificate(
        fixture.issuerKey.get(), fixture.rootCertificate.get(),
        fixture.rootKey.get(), 303L, "rdp-cal-test-issuer", EVP_sha1());
    addLicensingFixtureIssuerConstraints(
        nonCriticalCa.get(), true, false, false, false);
    assert(X509_sign(
               nonCriticalCa.get(), fixture.rootKey.get(), EVP_sha1()) > 0);
    assert(inspectWithIssuer(nonCriticalCa.get()).error ==
           RdpClientCalChainError::InvalidIssuerConstraints);

    auto deniedKeyUsage = makeLicensingFixtureCertificate(
        fixture.issuerKey.get(), fixture.rootCertificate.get(),
        fixture.rootKey.get(), 304L, "rdp-cal-test-issuer", EVP_sha1());
    addLicensingFixtureIssuerConstraints(
        deniedKeyUsage.get(), true, true, true, false);
    assert(X509_sign(
               deniedKeyUsage.get(), fixture.rootKey.get(),
               EVP_sha1()) > 0);
    assert(inspectWithIssuer(deniedKeyUsage.get()).error ==
           RdpClientCalChainError::InvalidIssuerConstraints);

    auto absentKeyUsage = makeLicensingFixtureCertificate(
        fixture.issuerKey.get(), fixture.rootCertificate.get(),
        fixture.rootKey.get(), 305L, "rdp-cal-test-issuer", EVP_sha1());
    addLicensingFixtureIssuerConstraints(
        absentKeyUsage.get(), true, true, false, false);
    assert(X509_sign(
               absentKeyUsage.get(), fixture.rootKey.get(),
               EVP_sha1()) > 0);
    const auto withoutKeyUsage = inspectWithIssuer(absentKeyUsage.get());
    assert(withoutKeyUsage.error == RdpClientCalChainError::None);
    assert(withoutKeyUsage.facts.issuerConstraintsVerified);
    assert(withoutKeyUsage.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);
}

void testRdpClientCalProductExtensionDenials()
{
    ClientCalFixture fixture;
    const auto presentButUnparsed =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(presentButUnparsed.error == RdpClientCalChainError::None);
    assert(presentButUnparsed.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);

    ClientCalFixture missingExtensions{false};
    const auto missing = inspectRdpClientCalCertificateChain(
        missingExtensions.cal, missingExtensions.rootDer);
    assert(missing.error == RdpClientCalChainError::None);
    assert(missing.facts.policyStatus ==
           RdpClientCalPolicyStatus::MissingRequiredExtension);

    LicensingCertificatePointer duplicateLeaf{
        X509_dup(fixture.leafCertificate.get()), X509_free};
    assert(duplicateLeaf);
    constexpr std::array<std::uint8_t, 1> duplicatePayload{0x55U};
    addClientCalFixtureExtension(
        duplicateLeaf.get(), kClientCalRequiredExtensionOids[2],
        duplicatePayload);
    assert(X509_sign(
               duplicateLeaf.get(), fixture.issuerKey.get(),
               EVP_sha1()) > 0);
    const std::array<X509 *, 3> duplicateCertificates{
        duplicateLeaf.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    const auto duplicate = inspectRdpClientCalCertificateChain(
        encodeClientCalFixture(duplicateCertificates), fixture.rootDer);
    assert(duplicate.error == RdpClientCalChainError::None);
    assert(duplicate.facts.policyStatus ==
           RdpClientCalPolicyStatus::DuplicateRequiredExtension);

    LicensingCertificatePointer criticalLeaf{
        X509_dup(fixture.leafCertificate.get()), X509_free};
    assert(criticalLeaf);
    constexpr std::array<std::uint8_t, 2> criticalPayload{0xdeU, 0xadU};
    addClientCalFixtureExtension(
        criticalLeaf.get(), "1.3.6.1.4.1.55555.77",
        criticalPayload, true);
    assert(X509_sign(
               criticalLeaf.get(), fixture.issuerKey.get(),
               EVP_sha1()) > 0);
    const std::array<X509 *, 3> criticalCertificates{
        criticalLeaf.get(),
        fixture.rootCertificate.get(),
        fixture.issuerCertificate.get()};
    const auto critical = inspectRdpClientCalCertificateChain(
        encodeClientCalFixture(criticalCertificates), fixture.rootDer);
    assert(critical.error == RdpClientCalChainError::None);
    assert(critical.facts.policyStatus ==
           RdpClientCalPolicyStatus::UnsupportedCriticalExtension);

    LicensingCertificatePointer oldVersionRoot{
        X509_dup(fixture.rootCertificate.get()), X509_free};
    assert(oldVersionRoot);
    assert(X509_set_version(oldVersionRoot.get(), 1) == 1);
    assert(X509_sign(
               oldVersionRoot.get(), fixture.rootKey.get(),
               EVP_sha1()) > 0);
    const std::array<X509 *, 3> oldVersionCertificates{
        fixture.leafCertificate.get(),
        oldVersionRoot.get(),
        fixture.issuerCertificate.get()};
    assert(inspectRdpClientCalCertificateChain(
               encodeClientCalFixture(oldVersionCertificates),
               fixture.rootDer).error ==
           RdpClientCalChainError::UnsupportedCertificateVersion);

    // Arbitrary payloads under all five OIDs never become product/version
    // authority. Their encodings are intentionally unparsed in this increment.
    ClientCalFixture arbitraryPolicy{false};
    for (std::size_t index = 0U;
         index < kClientCalRequiredExtensionOids.size(); ++index)
    {
        const std::array<std::uint8_t, 4> arbitraryPayload{
            0xffU, 0x00U,
            static_cast<std::uint8_t>(index),
            static_cast<std::uint8_t>(0xa0U + index)};
        addClientCalFixtureExtension(
            arbitraryPolicy.leafCertificate.get(),
            kClientCalRequiredExtensionOids[index], arbitraryPayload);
    }
    assert(X509_sign(
               arbitraryPolicy.leafCertificate.get(),
               arbitraryPolicy.issuerKey.get(), EVP_sha1()) > 0);
    arbitraryPolicy.rebuild();
    const auto arbitrary = inspectRdpClientCalCertificateChain(
        arbitraryPolicy.cal, arbitraryPolicy.rootDer);
    assert(arbitrary.error == RdpClientCalChainError::None);
    assert(arbitrary.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);
}

void testRdpClientCalCertificateValidity()
{
    constexpr std::int64_t beforeNotBefore = 1767225599LL;
    constexpr std::int64_t exactNotBefore = 1767225600LL;
    constexpr std::int64_t insideWindow = 1780315200LL;
    constexpr std::int64_t exactNotAfter = 1798761599LL;
    constexpr std::int64_t afterNotAfter = 1798761600LL;

    ClientCalFixture fixture{false};
    setLicensingFixtureCertificateValidity(
        fixture.leafCertificate.get(),
        "260101000000Z", "261231235959Z");
    addRequiredClientCalFixtureExtensions(fixture.leafCertificate.get());
    assert(X509_sign(
               fixture.leafCertificate.get(), fixture.issuerKey.get(),
               EVP_sha1()) > 0);
    fixture.rebuild();

    const auto withoutTime =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(withoutTime.error == RdpClientCalChainError::None);
    assert(withoutTime.facts.leafCertificateValidity ==
           RdpClientCalLeafCertificateValidityStatus::NotEvaluated);

    const auto inspectAt =
        [&fixture](std::int64_t verificationUnixSeconds)
        {
            const auto result = inspectRdpClientCalCertificateChainAtTime(
                fixture.cal, fixture.rootDer, verificationUnixSeconds);
            assert(result.error == RdpClientCalChainError::None);
            assert(result.facts.signaturesVerified);
            assert(result.facts.trustedIssuerMatched);
            assert(result.facts.policyStatus ==
                   RdpClientCalPolicyStatus::
                       RequiredExtensionsPresentButUnparsed);
            return result.facts.leafCertificateValidity;
        };

    assert(inspectAt(beforeNotBefore) ==
           RdpClientCalLeafCertificateValidityStatus::NotYetValid);
    assert(inspectAt(exactNotBefore) ==
           RdpClientCalLeafCertificateValidityStatus::Valid);
    assert(inspectAt(insideWindow) ==
           RdpClientCalLeafCertificateValidityStatus::Valid);
    assert(inspectAt(exactNotAfter) ==
           RdpClientCalLeafCertificateValidityStatus::Valid);
    assert(inspectAt(afterNotAfter) ==
           RdpClientCalLeafCertificateValidityStatus::Expired);

    ClientCalFixture invertedWindow{false};
    setLicensingFixtureCertificateValidity(
        invertedWindow.leafCertificate.get(),
        "270101000000Z", "260101000000Z");
    addRequiredClientCalFixtureExtensions(
        invertedWindow.leafCertificate.get());
    assert(X509_sign(
               invertedWindow.leafCertificate.get(),
               invertedWindow.issuerKey.get(), EVP_sha1()) > 0);
    invertedWindow.rebuild();
    const auto inverted = inspectRdpClientCalCertificateChainAtTime(
        invertedWindow.cal, invertedWindow.rootDer, insideWindow);
    assert(inverted.error == RdpClientCalChainError::None);
    assert(inverted.facts.leafCertificateValidity ==
           RdpClientCalLeafCertificateValidityStatus::MalformedWindow);

    ClientCalFixture malformedWindow{false};
    setLicensingFixtureCertificateValidity(
        malformedWindow.leafCertificate.get(),
        "260101000000Z", "261231235959Z");
    constexpr std::string_view malformedNotAfter{"261301000000Z"};
    assert(ASN1_STRING_set(
               X509_getm_notAfter(malformedWindow.leafCertificate.get()),
               malformedNotAfter.data(),
               static_cast<int>(malformedNotAfter.size())) == 1);
    addRequiredClientCalFixtureExtensions(
        malformedWindow.leafCertificate.get());
    assert(X509_sign(
               malformedWindow.leafCertificate.get(),
               malformedWindow.issuerKey.get(), EVP_sha1()) > 0);
    malformedWindow.rebuild();
    const auto malformed = inspectRdpClientCalCertificateChainAtTime(
        malformedWindow.cal, malformedWindow.rootDer, insideWindow);
    assert(malformed.error == RdpClientCalChainError::None);
    assert(malformed.facts.leafCertificateValidity ==
           RdpClientCalLeafCertificateValidityStatus::MalformedWindow);

    // X.509 validity is necessary evidence, not CAL expiration/classification
    // policy. The proprietary licensing extensions remain deliberately
    // unparsed and cannot authorize STATUS_VALID_CLIENT.
    assert(inspectAt(insideWindow) ==
           RdpClientCalLeafCertificateValidityStatus::Valid);
}

void testRdpClientCalExpiryHwidDenials()
{
    ClientCalFixture fixture;
    const auto chain =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(chain.error == RdpClientCalChainError::None);
    assert(chain.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);

    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> mac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    RdpLicensingKeyMaterial material{};
    material.macSaltKey = key;
    material.encryptionKey = key;
    const auto message = makeClientLicenseInfoWithHardwareProof(
        cipher, mac, fixture.cal);
    const auto parsed = parseRdpClientLicenseInfo(message);
    assert(parsed);
    assert(parsed.value.licenseInfo.size() == fixture.cal.size());
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));

    auto badMac = mac;
    badMac[0] ^= 0x01U;
    assert(!verifyRdpClientLicenseInfoHardwareId(
        makeClientLicenseInfoWithHardwareProof(
            cipher, badMac, fixture.cal),
        material));

    auto wrongKey = material;
    wrongKey.encryptionKey[0] ^= 0x01U;
    assert(!verifyRdpClientLicenseInfoHardwareId(message, wrongKey));
    cleanseRdpLicensingKeyMaterial(wrongKey);

    const auto noAnchor =
        inspectRdpClientCalCertificateChain(fixture.cal, {});
    assert(noAnchor.error == RdpClientCalChainError::MissingTrustAnchor);

    // CAL expiry/renewal/classification and CAL-to-HWID binding are not
    // guessed from X.509 notAfter or a valid protected-message HWID MAC.
    assert(chain.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);
    cleanseRdpLicensingKeyMaterial(material);
}

void testRdpClientCalNoPrematureCompletion()
{
    ClientCalFixture fixture;
    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> mac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    RdpLicensingKeyMaterial material{};
    material.macSaltKey = key;
    material.encryptionKey = key;
    const auto message = makeClientLicenseInfoWithHardwareProof(
        cipher, mac, fixture.cal);

    RdpLicensingLifecycle lifecycle;
    assert(deliverServerLicenseRequest(lifecycle));
    assert(lifecycle.onClientMessage(message) ==
           RdpLicensingIntake::ClientLicenseInfoAccepted);
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::ClientLicenseInfoValidation);

    const auto chain =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(chain.error == RdpClientCalChainError::None);
    assert(chain.facts.signaturesVerified);
    assert(chain.facts.trustedIssuerMatched);
    assert(chain.facts.policyStatus ==
           RdpClientCalPolicyStatus::RequiredExtensionsPresentButUnparsed);
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));

    // Offline facts cannot mutate the live lifecycle or queue a license grant.
    assert(lifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);
    assert(lifecycle.decisionBranch() ==
           RdpLicensingDecisionBranch::ClientLicenseInfoValidation);
    RdpServerLicenseGrantWriteGate grantWriter{lifecycle};
    assert(!grantWriter.pendingWrite());

    // A separate MCS owner still requires genuine R2 admission; no CAL result
    // can fabricate an admission lease or begin Share activation.
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);

    lifecycle.close();
    lifecycle.close();
    assert(lifecycle.phase() == RdpLicensingPhase::Closed);

    RdpLicensingLifecycle fresh;
    assert(fresh.phase() == RdpLicensingPhase::NotStarted);
    assert(fresh.decisionBranch() == RdpLicensingDecisionBranch::None);
    cleanseRdpLicensingKeyMaterial(material);
}

void testRdpClientCalTerminalRetirement()
{
    ClientCalFixture fixture;
    const std::size_t mutationLimit =
        fixture.cal.size() < 64U ? fixture.cal.size() : 64U;
    for (std::size_t size = 0U; size < mutationLimit; ++size)
    {
        const auto malformed = inspectRdpClientCalCertificateChain(
            std::span(fixture.cal).first(size), fixture.rootDer);
        assert(malformed.error != RdpClientCalChainError::None);
        assert(!malformed.facts.trustedIssuerMatched);
    }

    // A malformed provider parse leaves no retained X.509/candidate state.
    const auto freshVerification =
        inspectRdpClientCalCertificateChain(fixture.cal, fixture.rootDer);
    assert(freshVerification.error == RdpClientCalChainError::None);
    assert(freshVerification.facts.signaturesVerified);
    assert(freshVerification.facts.trustedIssuerMatched);

    constexpr std::array<std::uint8_t, kRdpLicensingKeyBytes> key{
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    constexpr std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> cipher{
        0xe9,0x9d,0x42,0xfa,0x43,0xe7,0x1f,0xcb,0x0e,0xd2,
        0x9d,0xcd,0x02,0xd0,0x24,0x40,0xc3,0x60,0x93,0x4c};
    constexpr std::array<std::uint8_t, kRdpLicensingMacBytes> mac{
        0x65,0xdd,0xb1,0x4d,0xda,0x05,0x0d,0x5d,
        0x2c,0x53,0xbe,0xfe,0x9d,0x5c,0x3e,0x5d};

    RdpLicensingKeyMaterial material{};
    material.macSaltKey = key;
    material.encryptionKey = key;
    auto message = makeClientLicenseInfoWithHardwareProof(
        cipher, mac, fixture.cal);
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));
    const auto parsed = parseRdpClientLicenseInfo(message);
    assert(parsed);
    const std::size_t macOffset = static_cast<std::size_t>(
        parsed.value.macData.data() - message.data());
    message[macOffset] ^= 0x01U;
    assert(!verifyRdpClientLicenseInfoHardwareId(message, material));
    message[macOffset] ^= 0x01U;
    assert(verifyRdpClientLicenseInfoHardwareId(message, material));

    RdpLicensingLifecycle retired;
    assert(deliverServerLicenseRequest(retired));
    assert(retired.onClientMessage(message) ==
           RdpLicensingIntake::ClientLicenseInfoAccepted);
    retired.close();
    retired.close();
    assert(retired.phase() == RdpLicensingPhase::Closed);
    assert(retired.onClientMessage(message) == RdpLicensingIntake::Closed);

    RdpLicensingLifecycle replacement;
    assert(replacement.phase() == RdpLicensingPhase::NotStarted);
    assert(replacement.decisionBranch() == RdpLicensingDecisionBranch::None);
    cleanseRdpLicensingKeyMaterial(material);
}

void writeRuntimeLicensingFixtureFile(
    const char *path, std::span<const std::uint8_t> bytes)
{
    assert(path != nullptr && *path != '\0' && !bytes.empty());
    std::ofstream output{
        path, std::ios::binary | std::ios::out | std::ios::trunc};
    assert(output.good());
    output.write(
        reinterpret_cast<const char *>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    assert(output.good());
}

[[nodiscard]] std::vector<std::uint8_t>
readRuntimeLicensingFixtureFile(const char *path)
{
    assert(path != nullptr && *path != '\0');
    std::ifstream input{path, std::ios::binary};
    assert(input.good());
    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    assert(end > 0);
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    input.read(
        reinterpret_cast<char *>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    assert(input.good());
    return bytes;
}

void emitRuntimeLicensingCredentialFixture(
    const char *serverCertificatePath,
    const char *privateKeyPath,
    const char *encryptedPreMasterPath)
{
    const LicensingCryptoFixture fixture;
    writeRuntimeLicensingFixtureFile(
        serverCertificatePath, fixture.serverCertificate);
    writeRuntimeLicensingFixtureFile(
        privateKeyPath, fixture.privateKeyPem);
    writeRuntimeLicensingFixtureFile(
        encryptedPreMasterPath, fixture.encryptedPreMasterSecret);
}

void testRuntimeLicensingContextSecureFiles(
    const char *serverCertificatePath,
    const char *privateKeyPath,
    const char *encryptedPreMasterPath)
{
    RuntimeLicensingContext context;
    assert(context.configureFromCredentialFiles(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        serverCertificatePath, kServerLicenseScope, privateKeyPath));

    const auto *identity = context.identity();
    const auto *credential = context.credential();
    assert(identity != nullptr && credential != nullptr);
    assert(credential->matches(*identity));

    const std::vector<std::uint8_t> retainedCertificate{
        identity->serverCertificate().begin(),
        identity->serverCertificate().end()};
    const auto encryptedPreMaster =
        readRuntimeLicensingFixtureFile(encryptedPreMasterPath);

    constexpr std::array<std::uint8_t, 8> replacement{
        'R', 'E', 'P', 'L', 'A', 'C', 'E', 'D'};
    writeRuntimeLicensingFixtureFile(serverCertificatePath, replacement);
    writeRuntimeLicensingFixtureFile(privateKeyPath, replacement);

    assert(std::equal(
        identity->serverCertificate().begin(),
        identity->serverCertificate().end(),
        retainedCertificate.begin(), retainedCertificate.end()));
    assert(credential->matches(*identity));

    std::array<std::uint8_t, kRdpLicensingPreMasterSecretBytes>
        expectedPreMaster{};
    for (std::size_t index = 0U; index < expectedPreMaster.size(); ++index)
        expectedPreMaster[index] =
            static_cast<std::uint8_t>(0x31U + index);

    const auto decrypted =
        credential->decryptPreMasterSecret(encryptedPreMaster);
    assert(decrypted);
    assert(decrypted.value == expectedPreMaster);

    assert(!context.configureFromCredentialFiles(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        serverCertificatePath, kServerLicenseScope, privateKeyPath));
}

void testRuntimeLicensingContextSecureFileDenial(
    const char *serverCertificatePath,
    const char *privateKeyPath)
{
    RuntimeLicensingContext context;
    assert(!context.configureFromCredentialFiles(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        serverCertificatePath, kServerLicenseScope, privateKeyPath));
    assert(!context.configured());
    assert(context.identity() == nullptr);
    assert(context.credential() == nullptr);
    assert(!context.configureFromCredentialFiles(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        serverCertificatePath, kServerLicenseScope, privateKeyPath));
    assert(!context.configured());
    assert(context.identity() == nullptr);
    assert(context.credential() == nullptr);
}

void testRuntimeLicensingContextReplacementFreshness(
    const char *serverCertificatePath,
    const char *privateKeyPath,
    const char *encryptedPreMasterPath)
{
    // The existing secure-file case intentionally leaves both credential
    // pathnames replaced with garbage after proving the first context retained
    // its owned snapshots. A distinct context must reopen the CURRENT files;
    // no process/global cache may replay the earlier successful snapshot.
    testRuntimeLicensingContextSecureFiles(
        serverCertificatePath, privateKeyPath, encryptedPreMasterPath);

    RuntimeLicensingContext freshContext;
    assert(!freshContext.configureFromCredentialFiles(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        serverCertificatePath, kServerLicenseScope, privateKeyPath));
    assert(!freshContext.configured());
    assert(freshContext.identity() == nullptr);
    assert(freshContext.credential() == nullptr);

    // Failed provisioning is one-shot as well; repeating the stale pathname
    // pair cannot revive or partially publish credential state.
    assert(!freshContext.configureFromCredentialFiles(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        serverCertificatePath, kServerLicenseScope, privateKeyPath));
    assert(!freshContext.configured());
    assert(freshContext.identity() == nullptr);
    assert(freshContext.credential() == nullptr);
}

void testRuntimeLicensingContextOwnership()
{
    LicensingCryptoFixture fixture;
    auto callerCertificate = fixture.serverCertificate;
    auto callerPrivateKey = fixture.privateKeyPem;

    RuntimeLicensingContext context;
    assert(!context.configured());
    assert(context.identity() == nullptr);
    assert(context.credential() == nullptr);

    assert(context.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        callerCertificate, kServerLicenseScope, callerPrivateKey));
    assert(context.configured());
    const auto *identity = context.identity();
    const auto *credential = context.credential();
    assert(identity != nullptr && credential != nullptr);
    assert(identity->configured());
    assert(credential->configured());
    assert(credential->matches(*identity));
    assert(identity->serverCertificate().size() ==
           fixture.serverCertificate.size());
    assert(std::equal(
        identity->serverCertificate().begin(),
        identity->serverCertificate().end(),
        fixture.serverCertificate.begin()));
    assert(credential->certificateFingerprint().size() == 32U);

    // R10 must own the successful snapshots. Caller storage can change
    // immediately without altering the advertised identity or private key.
    std::fill(callerCertificate.begin(), callerCertificate.end(), 0U);
    std::fill(callerPrivateKey.begin(), callerPrivateKey.end(), 0U);
    assert(std::equal(
        identity->serverCertificate().begin(),
        identity->serverCertificate().end(),
        fixture.serverCertificate.begin()));
    const auto decrypted = credential->decryptPreMasterSecret(
        fixture.encryptedPreMasterSecret);
    assert(decrypted);
    assert(decrypted.value == fixture.preMaster);

    // Service configuration is immutable once published.
    assert(!context.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope,
        fixture.privateKeyPem));
}

void testRuntimeLicensingContextDenials()
{
    LicensingCryptoFixture fixture;

    // A cryptographically mismatched key fails the complete context and the
    // failed one-shot object cannot later be repaired under active consumers.
    RuntimeLicensingContext mismatch;
    assert(!mismatch.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope,
        fixture.mismatchedPrivateKeyPem));
    assert(!mismatch.configured());
    assert(mismatch.identity() == nullptr);
    assert(mismatch.credential() == nullptr);
    assert(!mismatch.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope,
        fixture.privateKeyPem));

    // Identity failure is equally terminal; no partially configured R3 object
    // becomes externally observable through R10.
    RuntimeLicensingContext invalidIdentity;
    assert(!invalidIdentity.configure(
        0x00060001U, {}, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope,
        fixture.privateKeyPem));
    assert(!invalidIdentity.configured());
    assert(invalidIdentity.identity() == nullptr);
    assert(invalidIdentity.credential() == nullptr);
    assert(!invalidIdentity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope,
        fixture.privateKeyPem));
}

void testRdpLicensingPreMasterDecrypt()
{
    const LicensingCryptoFixture fixture;
    RdpServerLicenseIdentity identity;
    assert(identity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope));

    RdpLicensingServiceCredential credential;
    assert(credential.configure(identity, fixture.privateKeyPem));
    assert(credential.configured());
    assert(credential.matches(identity));

    const auto decrypted = credential.decryptPreMasterSecret(
        fixture.encryptedPreMasterSecret);
    assert(decrypted);
    assert(decrypted.value == fixture.preMaster);

    // The decrypted premaster is suitable only as input to the already
    // independent key-derivation primitive; neither operation mutates R3.
    std::array<std::uint8_t, kRdpLicensingRandomBytes> clientRandom{};
    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom{};
    for (std::size_t index = 0U; index < clientRandom.size(); ++index)
    {
        clientRandom[index] = static_cast<std::uint8_t>(index + 1U);
        serverRandom[index] = static_cast<std::uint8_t>(0x80U + index);
    }
    assert(deriveRdpLicensingKeys(
        decrypted.value, clientRandom, serverRandom));

    // Credential binding covers the exact advertised certificate bytes,
    // including chain padding, rather than only a matching leaf key.
    auto differentCertificate = fixture.serverCertificate;
    assert(!differentCertificate.empty());
    differentCertificate.back() ^= 0x01U;
    RdpServerLicenseIdentity differentIdentity;
    assert(differentIdentity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        differentCertificate, kServerLicenseScope));
    assert(!credential.matches(differentIdentity));
}

void testRdpInitialLicensingCryptoPreparation()
{
    const LicensingCryptoFixture fixture;
    RdpServerLicenseIdentity identity;
    assert(identity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope));
    RdpLicensingServiceCredential credential;
    assert(credential.configure(identity, fixture.privateKeyPem));

    std::array<std::uint8_t, kRdpLicensingRandomBytes> clientRandom{};
    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom{};
    for (std::size_t index = 0U; index < clientRandom.size(); ++index)
    {
        clientRandom[index] = static_cast<std::uint8_t>(0x40U + index);
        serverRandom[index] = static_cast<std::uint8_t>(0x90U + index);
    }
    const auto message = makeClientNewLicenseRequestWithKeyExchange(
        clientRandom, fixture.encryptedPreMasterSecret);
    const auto exchange = parseRdpClientLicensingKeyExchange(message);
    assert(exchange);
    assert(std::equal(
        exchange.value.clientRandom.begin(),
        exchange.value.clientRandom.end(), clientRandom.begin()));

    auto prepared = prepareInitialRdpLicensingCrypto(
        credential, message, serverRandom);
    assert(prepared);
    auto expected = deriveRdpLicensingKeys(
        fixture.preMaster, clientRandom, serverRandom);
    assert(expected);
    assert(prepared.value.macSaltKey == expected.value.macSaltKey);
    assert(prepared.value.encryptionKey == expected.value.encryptionKey);

    cleanseRdpLicensingKeyMaterial(prepared.value);
    cleanseRdpLicensingKeyMaterial(expected.value);
    assert(std::all_of(
        prepared.value.macSaltKey.begin(),
        prepared.value.macSaltKey.end(),
        [](std::uint8_t value) { return value == 0U; }));
    assert(std::all_of(
        prepared.value.encryptionKey.begin(),
        prepared.value.encryptionKey.end(),
        [](std::uint8_t value) { return value == 0U; }));
}

void testRdpInitialLicensingCryptoDenials()
{
    const LicensingCryptoFixture fixture;
    RdpServerLicenseIdentity identity;
    assert(identity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope));
    RdpLicensingServiceCredential credential;
    assert(credential.configure(identity, fixture.privateKeyPem));

    std::array<std::uint8_t, kRdpLicensingRandomBytes> clientRandom{};
    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom{};
    for (std::size_t index = 0U; index < clientRandom.size(); ++index)
    {
        clientRandom[index] = static_cast<std::uint8_t>(index + 1U);
        serverRandom[index] = static_cast<std::uint8_t>(0xa0U + index);
    }
    const auto valid = makeClientNewLicenseRequestWithKeyExchange(
        clientRandom, fixture.encryptedPreMasterSecret);

    const auto shortRandom = prepareInitialRdpLicensingCrypto(
        credential, valid,
        std::span(serverRandom).first(serverRandom.size() - 1U));
    assert(!shortRandom);
    assert(shortRandom.error ==
           RdpInitialLicensingCryptoError::InvalidServerRandom);

    const auto truncated = prepareInitialRdpLicensingCrypto(
        credential, std::span(valid).first(valid.size() - 1U),
        serverRandom);
    assert(!truncated);
    assert(truncated.error ==
           RdpInitialLicensingCryptoError::InvalidClientMessage);

    RdpLicensingServiceCredential unconfiguredCredential;
    const auto noCredential = prepareInitialRdpLicensingCrypto(
        unconfiguredCredential, valid, serverRandom);
    assert(!noCredential);
    assert(noCredential.error ==
           RdpInitialLicensingCryptoError::PreMasterDecryptFailure);

    auto badCiphertext = fixture.encryptedPreMasterSecret;
    badCiphertext.back() = 0x01U;
    const auto badCipherMessage = makeClientNewLicenseRequestWithKeyExchange(
        clientRandom, badCiphertext);
    const auto badCipher = prepareInitialRdpLicensingCrypto(
        credential, badCipherMessage, serverRandom);
    assert(!badCipher);
    assert(badCipher.error ==
           RdpInitialLicensingCryptoError::PreMasterDecryptFailure);
    assert(std::all_of(
        badCipher.value.macSaltKey.begin(),
        badCipher.value.macSaltKey.end(),
        [](std::uint8_t value) { return value == 0U; }));
    assert(std::all_of(
        badCipher.value.encryptionKey.begin(),
        badCipher.value.encryptionKey.end(),
        [](std::uint8_t value) { return value == 0U; }));

    constexpr std::array<std::uint8_t, 4> challenge{
        0x15, 0x03, 0x04, 0x00};
    const auto unexpected = prepareInitialRdpLicensingCrypto(
        credential, challenge, serverRandom);
    assert(!unexpected);
    assert(unexpected.error ==
           RdpInitialLicensingCryptoError::InvalidClientMessage);
}

void testRdpLicensingPreMasterDecryptDenials()
{
    const LicensingCryptoFixture fixture;

    RdpServerLicenseIdentity identity;
    assert(identity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        fixture.serverCertificate, kServerLicenseScope));
    RdpLicensingServiceCredential credential;
    assert(credential.configure(identity, fixture.privateKeyPem));

    // A different RSA key cannot configure a service credential for the
    // terminal leaf that was advertised to the client.
    RdpLicensingServiceCredential mismatchedCredential;
    assert(!mismatchedCredential.configure(
        identity, fixture.mismatchedPrivateKeyPem));
    assert(!mismatchedCredential.configured());
    const auto unconfigured =
        mismatchedCredential.decryptPreMasterSecret(
            fixture.encryptedPreMasterSecret);
    assert(!unconfigured);
    assert(unconfigured.error ==
           RdpLicensingPreMasterDecryptError::NotConfigured);

    auto unsupportedCertificate = fixture.serverCertificate;
    unsupportedCertificate[0] = 0x01U;
    RdpServerLicenseIdentity unsupportedIdentity;
    assert(unsupportedIdentity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        unsupportedCertificate, kServerLicenseScope));
    RdpLicensingServiceCredential unsupportedCredential;
    assert(!unsupportedCredential.configure(
        unsupportedIdentity, fixture.privateKeyPem));

    auto malformedCertificate = fixture.serverCertificate;
    malformedCertificate[4] = 0x01U; // NumCertBlobs below minimum 2.
    RdpServerLicenseIdentity malformedIdentity;
    assert(malformedIdentity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        malformedCertificate, kServerLicenseScope));
    RdpLicensingServiceCredential malformedCredential;
    assert(!malformedCredential.configure(
        malformedIdentity, fixture.privateKeyPem));

    // Preserve valid DER framing but corrupt the terminal certificate's
    // signature. Internal root->leaf signature coherence must be checked.
    auto badSignatureCertificate = fixture.serverCertificate;
    assert(badSignatureCertificate.size() > 16U);
    badSignatureCertificate[badSignatureCertificate.size() - 17U] ^= 0x01U;
    RdpServerLicenseIdentity badSignatureIdentity;
    assert(badSignatureIdentity.configure(
        0x00060001U, kServerLicenseCompany, kServerLicenseProduct,
        badSignatureCertificate, kServerLicenseScope));
    RdpLicensingServiceCredential badSignatureCredential;
    assert(!badSignatureCredential.configure(
        badSignatureIdentity, fixture.privateKeyPem));

    auto badPadding = fixture.encryptedPreMasterSecret;
    badPadding.back() = 0x01U;
    const auto paddingDenied =
        credential.decryptPreMasterSecret(badPadding);
    assert(!paddingDenied);
    assert(paddingDenied.error ==
           RdpLicensingPreMasterDecryptError::
               InvalidEncryptedPreMasterSecret);

    const auto truncated = credential.decryptPreMasterSecret(
        std::span(fixture.encryptedPreMasterSecret).first(
            fixture.encryptedPreMasterSecret.size() - 1U));
    assert(!truncated);
    assert(truncated.error ==
           RdpLicensingPreMasterDecryptError::
               InvalidEncryptedPreMasterSecret);

    auto trailingGarbageKey = fixture.privateKeyPem;
    trailingGarbageKey.push_back(0x41U);
    RdpLicensingServiceCredential invalidKeyCredential;
    assert(!invalidKeyCredential.configure(identity, trailingGarbageKey));

    const LicensingKeyPointer ecKey{
        EVP_EC_gen("prime256v1"), EVP_PKEY_free};
    assert(ecKey);
    const auto ecPrivateKeyPem =
        licensingFixturePrivateKeyPem(ecKey.get());
    RdpLicensingServiceCredential nonRsaCredential;
    assert(!nonRsaCredential.configure(identity, ecPrivateKeyPem));

    std::vector<std::uint8_t> oversizedKey(
        kMaximumRdpLicensingPrivateKeyPemBytes + 1U, 0x41U);
    RdpLicensingServiceCredential oversizedKeyCredential;
    assert(!oversizedKeyCredential.configure(identity, oversizedKey));

    // Entropy provenance cannot be inferred from the decoded value. Raw RSA
    // ciphertext zero therefore round-trips to an all-zero 48-byte premaster;
    // later protocol/authentication checks, not this primitive, decide use.
    std::vector<std::uint8_t> zeroCiphertext(
        fixture.encryptedPreMasterSecret.size(), 0U);
    const auto zeroDecoded =
        credential.decryptPreMasterSecret(zeroCiphertext);
    assert(zeroDecoded);
    assert((zeroDecoded.value ==
            std::array<std::uint8_t,
                       kRdpLicensingPreMasterSecretBytes>{}));

    // Configuration is one-shot even after failure; callers cannot replace
    // rejected credential material under an already-checked service object.
    assert(!mismatchedCredential.configure(
        identity, fixture.privateKeyPem));
}

void testRdpLicensingKeyMaterialTerminalReplay()
{
    RdpServerLicenseIdentity identity;
    assert(configureServerLicenseIdentity(identity));
    const auto clientResponse = makeClientNewLicenseRequest();

    // A queued/partially written request owns a private random, but that
    // material is not decision-visible until every request byte is accepted.
    RdpLicensingLifecycle cancelledLifecycle;
    RdpServerLicenseRequestWriteGate cancelledWriter{cancelledLifecycle};
    assert(cancelledLifecycle.serverRandom().empty());
    assert(cancelledWriter.queue(identity));
    assert(cancelledLifecycle.serverRandom().empty());

    const auto initial = cancelledWriter.pendingWrite();
    assert(initial);
    constexpr std::size_t acceptedBytes = 11U;
    assert(initial.bytes.size() > acceptedBytes);
    assert(cancelledWriter.onBytesWritten(
               initial.replySequence, initial.writeSliceSequence,
               acceptedBytes) == RdpServerLicenseRequestWriteOutcome::Pending);
    const auto remainder = cancelledWriter.pendingWrite();
    assert(remainder);
    assert(cancelledLifecycle.serverRandom().empty());

    const auto cancelledReplySequence = remainder.replySequence;
    const auto cancelledSliceSequence = remainder.writeSliceSequence;
    const auto cancelledRemainingBytes = remainder.bytes.size();
    cancelledWriter.close();
    assert(cancelledLifecycle.phase() == RdpLicensingPhase::Closed);
    assert(cancelledLifecycle.serverRandom().empty());
    assert(cancelledWriter.onBytesWritten(
               cancelledReplySequence, cancelledSliceSequence,
               cancelledRemainingBytes) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(cancelledLifecycle.serverRandom().empty());
    assert(cancelledLifecycle.onClientMessage(clientResponse) ==
           RdpLicensingIntake::Closed);

    // Full delivery publishes exactly the wire random. Replaying the completed
    // receipt is terminal and must erase that retained key-derivation input.
    RdpLicensingLifecycle deliveredLifecycle;
    RdpServerLicenseRequestWriteGate deliveredWriter{deliveredLifecycle};
    assert(deliveredWriter.queue(identity));
    const auto deliveredPending = deliveredWriter.pendingWrite();
    assert(deliveredPending);
    std::array<std::uint8_t, kRdpLicensingRandomBytes> deliveredRandom{};
    std::copy_n(
        deliveredPending.bytes.begin() + 4U, deliveredRandom.size(),
        deliveredRandom.begin());
    const auto deliveredReplySequence = deliveredPending.replySequence;
    const auto deliveredSliceSequence = deliveredPending.writeSliceSequence;
    const auto deliveredBytes = deliveredPending.bytes.size();
    assert(deliveredLifecycle.serverRandom().empty());
    assert(deliveredWriter.onBytesWritten(
               deliveredReplySequence, deliveredSliceSequence,
               deliveredBytes) == RdpServerLicenseRequestWriteOutcome::Delivered);
    assert(deliveredLifecycle.phase() ==
           RdpLicensingPhase::AwaitClientLicenseResponse);
    assert(std::equal(
        deliveredLifecycle.serverRandom().begin(),
        deliveredLifecycle.serverRandom().end(),
        deliveredRandom.begin()));
    assert(deliveredWriter.onBytesWritten(
               deliveredReplySequence, deliveredSliceSequence, 0U) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(deliveredLifecycle.phase() == RdpLicensingPhase::Closed);
    assert(deliveredLifecycle.serverRandom().empty());

    // Malformed client intake after a completed request is terminal and clears
    // the retained random before any later valid replay can be considered.
    RdpLicensingLifecycle malformedLifecycle;
    RdpServerLicenseRequestWriteGate malformedWriter{malformedLifecycle};
    assert(malformedWriter.queue(identity));
    const auto malformedPending = malformedWriter.pendingWrite();
    assert(malformedPending);
    assert(malformedWriter.onBytesWritten(
               malformedPending.replySequence,
               malformedPending.writeSliceSequence,
               malformedPending.bytes.size()) ==
           RdpServerLicenseRequestWriteOutcome::Delivered);
    assert(!malformedLifecycle.serverRandom().empty());
    assert(malformedLifecycle.onClientMessage(
               std::span(clientResponse).first(clientResponse.size() - 1U)) ==
           RdpLicensingIntake::MalformedMessage);
    assert(malformedLifecycle.phase() == RdpLicensingPhase::Failed);
    assert(malformedLifecycle.serverRandom().empty());
    assert(malformedLifecycle.onClientMessage(clientResponse) ==
           RdpLicensingIntake::Failed);
    assert(malformedLifecycle.serverRandom().empty());

    // A legitimate first client response may retain the random for the future
    // server decision, but a duplicate response is terminal and erases it.
    RdpLicensingLifecycle replayLifecycle;
    RdpServerLicenseRequestWriteGate replayWriter{replayLifecycle};
    assert(replayWriter.queue(identity));
    const auto replayPending = replayWriter.pendingWrite();
    assert(replayPending);
    assert(replayWriter.onBytesWritten(
               replayPending.replySequence, replayPending.writeSliceSequence,
               replayPending.bytes.size()) ==
           RdpServerLicenseRequestWriteOutcome::Delivered);
    assert(replayLifecycle.onClientMessage(clientResponse) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    assert(replayLifecycle.phase() == RdpLicensingPhase::AwaitServerDecision);
    assert(!replayLifecycle.serverRandom().empty());
    assert(replayLifecycle.onClientMessage(clientResponse) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(replayLifecycle.phase() == RdpLicensingPhase::Failed);
    assert(replayLifecycle.serverRandom().empty());

    // Replacement ownership starts with no inherited key material.
    RdpLicensingLifecycle replacementLifecycle;
    RdpServerLicenseRequestWriteGate replacementWriter{replacementLifecycle};
    assert(replacementLifecycle.phase() == RdpLicensingPhase::NotStarted);
    assert(replacementLifecycle.serverRandom().empty());
    assert(replacementWriter.queue(identity));
    assert(replacementLifecycle.serverRandom().empty());
    replacementWriter.close();
    assert(replacementLifecycle.phase() == RdpLicensingPhase::Closed);
    assert(replacementLifecycle.serverRandom().empty());
}

void testRdpLicensingPreambleAndState()
{
    const auto newRequest = makeClientNewLicenseRequest();
    const auto parsed = parseRdpLicensingMessage(newRequest);
    assert(parsed);
    assert(parsed.value.type ==
           RdpLicensingMessageType::ClientNewLicenseRequest);
    assert(parsed.value.protocolVersion == 3U);
    assert(parsed.value.extendedErrorSupported);
    assert(parsed.value.body.data() == newRequest.data() + 4U);
    assert(parsed.value.body.size() == newRequest.size() - 4U);

    RdpLicensingLifecycle newLicense;
    assert(newLicense.phase() == RdpLicensingPhase::NotStarted);
    assert(deliverServerLicenseRequest(newLicense));
    assert(newLicense.phase() ==
           RdpLicensingPhase::AwaitClientLicenseResponse);
    assert(newLicense.onClientMessage(newRequest) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    assert(newLicense.phase() == RdpLicensingPhase::AwaitServerDecision);

    const auto licenseInfo = makeClientLicenseInfo();
    const auto existingParsed = parseRdpLicensingMessage(licenseInfo);
    assert(existingParsed);
    assert(existingParsed.value.type ==
           RdpLicensingMessageType::ClientLicenseInfo);
    assert(existingParsed.value.protocolVersion == 3U);
    assert(!existingParsed.value.extendedErrorSupported);

    RdpLicensingLifecycle existingLicense;
    assert(deliverServerLicenseRequest(existingLicense));
    assert(existingLicense.onClientMessage(licenseInfo) ==
           RdpLicensingIntake::ClientLicenseInfoAccepted);
    assert(existingLicense.phase() ==
           RdpLicensingPhase::AwaitServerDecision);
}

void testRdpLicensingLengthBounds()
{
    const auto valid = makeClientNewLicenseRequest();
    for (std::size_t size = 0; size < valid.size(); ++size)
    {
        RdpLicensingLifecycle lifecycle;
        assert(deliverServerLicenseRequest(lifecycle));
        assert(lifecycle.onClientMessage(
                   std::span(valid).first(size)) ==
               RdpLicensingIntake::MalformedMessage);
        assert(lifecycle.phase() == RdpLicensingPhase::Failed);
    }

    auto badLength = valid;
    --badLength[2];
    assert(parseRdpLicensingMessage(badLength).error ==
           RdpLicensingParseError::LengthMismatch);

    auto invalidType = valid;
    invalidType[0] = 0x14U;
    assert(parseRdpLicensingMessage(invalidType).error ==
           RdpLicensingParseError::InvalidType);

    auto invalidFlags = valid;
    invalidFlags[1] = 0x73U;
    assert(parseRdpLicensingMessage(invalidFlags).error ==
           RdpLicensingParseError::InvalidFlags);

    auto nestedOverflow = valid;
    nestedOverflow[46] = 0xffU;
    nestedOverflow[47] = 0xffU;
    RdpLicensingLifecycle overflowLifecycle;
    assert(deliverServerLicenseRequest(overflowLifecycle));
    assert(overflowLifecycle.onClientMessage(nestedOverflow) ==
           RdpLicensingIntake::MalformedMessage);

    auto zeroBlob = valid;
    zeroBlob[46] = 0x00U;
    zeroBlob[47] = 0x00U;
    RdpLicensingLifecycle zeroLifecycle;
    assert(deliverServerLicenseRequest(zeroLifecycle));
    assert(zeroLifecycle.onClientMessage(zeroBlob) ==
           RdpLicensingIntake::MalformedMessage);

    auto surplus = valid;
    surplus.push_back(0x00U);
    assert(parseRdpLicensingMessage(surplus).error ==
           RdpLicensingParseError::LengthMismatch);
    finishLicensingMessageSize(surplus);
    RdpLicensingLifecycle surplusLifecycle;
    assert(deliverServerLicenseRequest(surplusLifecycle));
    assert(surplusLifecycle.onClientMessage(surplus) ==
           RdpLicensingIntake::MalformedMessage);

    std::vector<std::uint8_t> oversized(
        kMaximumRdpLicensingPduBytes + 1U, 0U);
    oversized[0] = 0x13U;
    oversized[1] = 0x03U;
    assert(parseRdpLicensingMessage(oversized).error ==
           RdpLicensingParseError::Oversized);
}

void testRdpLicensingOrderingDenials()
{
    const auto request = makeClientNewLicenseRequest();

    RdpLicensingLifecycle beforeRequest;
    assert(beforeRequest.onClientMessage(request) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(beforeRequest.phase() == RdpLicensingPhase::Failed);
    assert(beforeRequest.onClientMessage(request) ==
           RdpLicensingIntake::Failed);

    RdpLicensingLifecycle duplicateMessage;
    assert(deliverServerLicenseRequest(duplicateMessage));
    assert(duplicateMessage.onClientMessage(request) ==
           RdpLicensingIntake::ClientNewLicenseRequestAccepted);
    assert(duplicateMessage.onClientMessage(request) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(duplicateMessage.phase() == RdpLicensingPhase::Failed);

    constexpr std::array<std::uint8_t, 4> challengeResponse{
        0x15, 0x03, 0x04, 0x00};
    assert(parseRdpLicensingMessage(challengeResponse));
    RdpLicensingLifecycle wrongInitialType;
    assert(deliverServerLicenseRequest(wrongInitialType));
    assert(wrongInitialType.onClientMessage(challengeResponse) ==
           RdpLicensingIntake::UnexpectedMessage);
    assert(wrongInitialType.phase() == RdpLicensingPhase::Failed);

    RdpLicensingLifecycle closed;
    closed.close();
    assert(closed.phase() == RdpLicensingPhase::Closed);
    assert(closed.onClientMessage(request) == RdpLicensingIntake::Closed);

    McsSessionLifecycle owner;
    assert(owner.licensingPhase() == RdpLicensingPhase::NotStarted);
    owner.close();
    assert(owner.licensingPhase() == RdpLicensingPhase::Closed);

    McsSessionLifecycle denied;
    assert(denied.onConnectInitial(publishedFixture()) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(denied.licensingPhase() == RdpLicensingPhase::Closed);

    McsSessionLifecycle fresh;
    assert(fresh.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(fresh.licensingPhase() == RdpLicensingPhase::NotStarted);
}


} // namespace

struct McsTestCase
{
    std::string_view name;
    void (*run)();
};

// No new executable or fixture owner; expose independent behaviors in
// the canonical CTest registry. Unknown case names must not pass.
constexpr std::array<McsTestCase, 170> kMcsTestCases{{
    {"mcs-envelope-microsoft", &testRealMicrosoftConnectionEnvelope},
    {"mcs-envelope-tpkt-errors", &testInvalidOuterTransport},
    {"mcs-envelope-ber-errors", &testBerLengthsAndType},
    {"mcs-envelope-mutations", &testInputMutationsRemainBounded},
    {"mcs-domain-merge", &testMicrosoftDomainNegotiation},
    {"mcs-domain-rejections", &testMcsDomainNegotiationRejections},
    {"mcs-response-wire", &testMcsResponseWire},
    {"mcs-gcc-first-exchange-conformance", &testMcsGccFirstExchangeConformance},
    {"mcs-response-security-replay", &testMcsResponseSecurityReplay},
    {"mcs-response-session-allocation-plan", &testMcsResponseSessionAllocationPlan},
    {"mcs-static-channel-role-binding", &testMcsStaticChannelRoleBinding},
    {"mcs-static-channel-role-denials", &testMcsStaticChannelRoleDenials},
    {"mcs-client-info-protected-route", &testMcsClientInfoProtectedRoute},
    {"mcs-client-info-protected-route-denials", &testMcsClientInfoProtectedRouteDenials},
    {"mcs-client-info-packet-structure", &testRdpClientInfoPacketStructure},
    {"mcs-client-info-packet-denials", &testRdpClientInfoPacketDenials},
    {"mcs-response-write-receipts", &testMcsResponseWriteReceipts},
    {"mcs-response-write-denials", &testMcsResponseWriteDenials},
    {"mcs-response-rejections", &testMcsResponseRejectInvalidInputs},
    {"mcs-erect-request", &testMcsErectDomainRequest},
    {"mcs-attach-request", &testMcsAttachUserRequest},
    {"mcs-channel-join-request", &testMcsChannelJoinRequest},
    {"mcs-rdp-user-id-range-conformance", &testMcsRdpUserIdRangeConformance},
    {"mcs-attach-confirm-wire", &testMcsAttachConfirmWire},
    {"mcs-session-attach-confirm-write-receipts", &testMcsSessionAttachConfirmWriteReceipts},
    {"mcs-session-attach-confirm-denials", &testMcsSessionAttachConfirmDenials},
    {"mcs-channel-join-confirm", &testMcsChannelJoinConfirmWireAndRejections},
    {"mcs-session-join-confirm-receipts", &testMcsSessionJoinConfirmReceipts},
    {"mcs-session-join-confirm-denials", &testMcsSessionJoinConfirmDenials},
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
    {"mcs-session-unadmitted-domain-size-bounds", &testMcsSessionUnadmittedDomainSizeBounds},
    {"mcs-session-first-failure-boundaries", &testMcsSessionFirstFailureBoundaries},
    {"mcs-session-domain-failure-boundaries", &testMcsSessionDomainFailureBoundaries},
    {"licensing-personal-no-cal-valid-client-completion", &testPersonalDesktopNoCalValidClientCompletion},
    {"licensing-personal-presented-cal-valid-client-completion", &testPersonalDesktopPresentedCalValidClientCompletion},
    {"licensing-personal-mode-and-malformed-denials", &testPersonalDesktopModeAndMalformedDenials},
    {"licensing-personal-valid-client-duplicate-and-partial-revocation", &testPersonalDesktopDuplicateAndPartialRevocation},
    {"licensing-server-request-wire", &testRdpServerLicenseRequestWire},
    {"licensing-server-identity-configuration", &testRdpServerLicenseIdentityConfiguration},
    {"licensing-server-request-certificate-required", &testRdpServerLicenseRequestCertificateRequired},
    {"licensing-server-request-generated-random", &testRdpServerLicenseRequestGeneratedRandom},
    {"licensing-server-request-write-receipts", &testRdpServerLicenseRequestWriteReceipts},
    {"licensing-server-request-write-denials", &testRdpServerLicenseRequestWriteDenials},
    {"licensing-client-response-before-request-delivery", &testRdpClientResponseBeforeRequestDelivery},
    {"licensing-generated-request-cancellation-replay", &testRdpGeneratedRequestCancellationReplay},
    {"licensing-client-response-single-consumption", &testRdpClientResponseSingleConsumption},
    {"licensing-client-envelope-wire", &testRdpClientLicensingEnvelopeWire},
    {"licensing-client-envelope-denials", &testRdpClientLicensingEnvelopeDenials},
    {"licensing-key-exchange-wire", &testRdpClientLicensingKeyExchangeViews},
    {"licensing-key-exchange-denials", &testRdpClientLicensingKeyExchangeDenials},
    {"licensing-key-derivation", &testRdpLicensingKeyDerivation},
    {"licensing-rc4-wire", &testRdpLicensingRc4Wire},
    {"licensing-mac-wire", &testRdpLicensingMacWire},
    {"licensing-client-license-info-hwid-proof", &testRdpClientLicenseInfoHardwareIdProof},
    {"licensing-client-license-info-hwid-denials", &testRdpClientLicenseInfoHardwareIdDenials},
    {"licensing-client-license-info-hwid-fresh-verification", &testRdpClientLicenseInfoHardwareIdFreshVerification},
    {"licensing-existing-cal-authority-request-ownership", &testExistingCalAuthorityRequestOwnership},
    {"licensing-existing-cal-live-visit-lifetime", &testMcsExistingCalSynchronousReadOnlyLifetime},
    {"licensing-existing-cal-authority-request-hwid-proof-gate", &testExistingCalAuthorityRequestHardwareProofGate},
    {"licensing-existing-cal-authority-request-product-and-correlation-denials", &testExistingCalAuthorityRequestProductAndCorrelationDenials},
    {"licensing-existing-cal-authority-request-revocation-replay", &testExistingCalAuthorityRequestRevocationReplay},
    {"licensing-client-cal-chain-structure", &testRdpClientCalChainStructure},
    {"licensing-client-cal-signed-content-empty-only", &testRdpClientCalSignedContentEmptyOnly},
    {"licensing-client-cal-issuer-signature-denials", &testRdpClientCalIssuerSignatureDenials},
    {"licensing-client-cal-issuer-constraints", &testRdpClientCalIssuerConstraints},
    {"licensing-client-cal-product-extension-denials", &testRdpClientCalProductExtensionDenials},
    {"licensing-client-cal-certificate-validity", &testRdpClientCalCertificateValidity},
    {"licensing-client-cal-expiry-hwid-denials", &testRdpClientCalExpiryHwidDenials},
    {"licensing-client-cal-no-premature-completion", &testRdpClientCalNoPrematureCompletion},
    {"licensing-client-cal-terminal-retirement", &testRdpClientCalTerminalRetirement},
    {"licensing-server-platform-challenge-wire", &testRdpServerPlatformChallengeWire},
    {"licensing-server-platform-challenge-write-receipts", &testRdpServerPlatformChallengeWriteReceipts},
    {"licensing-server-platform-challenge-write-denials", &testRdpServerPlatformChallengeWriteDenials},
    {"licensing-client-platform-challenge-response-proof", &testRdpClientPlatformChallengeResponseProof},
    {"licensing-client-platform-challenge-response-denials", &testRdpClientPlatformChallengeResponseDenials},
    {"licensing-authority-grant-boundary", &testRdpLicensingAuthorityGrantBoundary},
    {"licensing-server-license-grant-write-receipts", &testRdpServerLicenseGrantWriteReceipts},
    {"licensing-server-license-grant-write-denials", &testRdpServerLicenseGrantWriteDenials},
    {"licensing-new-license-info-wire", &testRdpNewLicenseInformationWire},
    {"licensing-new-license-info-denials", &testRdpNewLicenseInformationDenials},
    {"licensing-server-new-license-wire", &testRdpServerNewLicenseWire},
    {"licensing-server-upgrade-license-wire", &testRdpServerUpgradeLicenseWire},
    {"licensing-server-license-grant-encode-denials", &testRdpServerLicenseGrantEncodeDenials},
    {"licensing-server-license-grant-transactional-output", &testRdpServerLicenseGrantTransactionalOutput},
    {"licensing-server-grant-no-live-publication", &testRdpServerGrantNoLivePublication},
    {"licensing-premaster-rsa-decrypt", &testRdpLicensingPreMasterDecrypt},
    {"licensing-premaster-rsa-denials", &testRdpLicensingPreMasterDecryptDenials},
    {"licensing-runtime-context-ownership", &testRuntimeLicensingContextOwnership},
    {"licensing-runtime-context-denials", &testRuntimeLicensingContextDenials},
    {"licensing-initial-crypto-preparation", &testRdpInitialLicensingCryptoPreparation},
    {"licensing-initial-crypto-denials", &testRdpInitialLicensingCryptoDenials},
    {"licensing-key-material-terminal-replay", &testRdpLicensingKeyMaterialTerminalReplay},
    {"licensing-preamble-and-state", &testRdpLicensingPreambleAndState},
    {"licensing-length-bounds", &testRdpLicensingLengthBounds},
    {"licensing-ordering-denials", &testRdpLicensingOrderingDenials},
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
    {"share-input-slow-path-wire", &testRdpSlowPathInputWire},
    {"share-input-slow-path-rejections", &testRdpSlowPathInputRejections},
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
    {"share-personal-activation-ordering", &testPersonalDesktopShareActivationOrdering},
    {"share-confirm-active-client-capability-store", &testPersonalDesktopConfirmActiveCapabilityStore},
    {"share-finalization-early-input-ignore", &testPersonalDesktopShareEarlyInputIgnored},
    {"share-personal-activation-denials", &testPersonalDesktopShareActivationDenials},
    {"rdpgfx-client-core-capability-gate", &testRdpGraphicsClientCoreCapabilityGate},
    {"dvc-graphics-create-success", &testGraphicsDynamicVirtualChannelCreateSuccess},
    {"dvc-graphics-caps-selection", &testGraphicsDynamicVirtualChannelCapabilitiesSelection},
    {"dvc-graphics-caps-unsupported-denial", &testGraphicsDynamicVirtualChannelCapabilitiesUnsupportedDenial},
    {"dvc-graphics-presentation-wire", &testGraphicsPresentationInitializationWire},
    {"dvc-graphics-frame-ack-handoff-wire", &testGraphicsFrameAcknowledgeHandoffWire},
    {"dvc-graphics-frame-ack-handoff-malformed", &testGraphicsFrameAcknowledgeHandoffMalformed},
    {"dvc-graphics-frame-ack-handoff-stale", &testGraphicsFrameAcknowledgeHandoffStale},
    {"dvc-graphics-frame-credit-preflight", &testGraphicsFrameCreditPreflight},
    {"dvc-graphics-surface-remap", &testGraphicsSurfaceRemap},
    {"dvc-graphics-first-client-acceptance-observability",
     &testFirstClientAcceptanceObservability},
    {"dvc-graphics-frame-acceptance-status-projection",
     &testFirstClientAcceptanceObservability},
    {"dvc-graphics-create-response-denials", &testGraphicsDynamicVirtualChannelResponseDenials},
    {"dvc-graphics-generation-cancellation", &testGraphicsDynamicVirtualChannelGenerationCancellation},
    {"dvc-graphics-pre-share-denial", &testGraphicsDynamicVirtualChannelPreShareDenial},
    {"post-share-classifier-joined-routes", &testPostShareClassifierJoinedRoutes},
    {"post-share-classifier-malformed-and-wrong-role", &testPostShareClassifierMalformedAndWrongJoinedRole},
    {"post-share-classifier-graphics-dynamic-id-phase", &testPostShareClassifierGraphicsDynamicIdAndPhase},
    {"post-share-classifier-generations-share-disconnect", &testPostShareClassifierGenerationShareAndDisconnect},
    {"cliprdr-pre-share-denial", &testClipboardPreShareDenial},
    {"dvc-graphics-frame-zero-publication", &testGraphicsFrameZeroPublication},
    {"dvc-graphics-frame-multifragment-delivery", &testGraphicsFrameMultiFragmentDelivery},
    {"dvc-graphics-frame-header-partial-abort", &testGraphicsFrameHeaderPartialAbort},
    {"dvc-graphics-frame-payload-partial-abort", &testGraphicsFramePayloadPartialAbort},
    {"dvc-graphics-frame-stale-receipt", &testGraphicsFrameStaleReceiptAbort},
    {"dvc-graphics-frame-share-loss-abort", &testGraphicsFrameShareLossAbort},
    {"dvc-graphics-data-malformed-first", &testGraphicsDataFirstMalformed},
    {"dvc-graphics-data-wrong-channel", &testGraphicsDataWrongChannel},
    {"dvc-graphics-data-fragment-ordering", &testGraphicsDataFragmentOrdering},
    {"share-active-exchange-correlation", &testRdpActiveExchangeCorrelation},
    {"share-active-exchange-denials", &testRdpActiveExchangeDenials},
    {"share-finalization-exchange-correlation", &testRdpFinalizationExchangeCorrelation},
    {"share-finalization-exchange-denials", &testRdpFinalizationExchangeDenials},
}};

int main(int argc, char **argv)
{
    if (argc == 5 && argv[1] != nullptr && argv[2] != nullptr &&
        argv[3] != nullptr && argv[4] != nullptr)
    {
        const std::string_view mode{argv[1]};
        if (mode == "emit-runtime-licensing-fixture")
        {
            emitRuntimeLicensingCredentialFixture(
                argv[2], argv[3], argv[4]);
            return 0;
        }
        if (mode == "licensing-runtime-context-secure-files")
        {
            testRuntimeLicensingContextSecureFiles(
                argv[2], argv[3], argv[4]);
            return 0;
        }
        if (mode == "licensing-runtime-context-replacement-freshness")
        {
            testRuntimeLicensingContextReplacementFreshness(
                argv[2], argv[3], argv[4]);
            return 0;
        }
        if (mode == "licensing-runtime-context-secure-file-denial")
        {
            testRuntimeLicensingContextSecureFileDenial(argv[2], argv[3]);
            return 0;
        }
        return 2;
    }

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
