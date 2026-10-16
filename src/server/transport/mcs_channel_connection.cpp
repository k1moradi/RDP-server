// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_channel_connection.h"
#include "mcs_connect_initial.h"
#include "gcc_conference_create.h"

#include <array>
#include <cstddef>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{
namespace
{
// T.125 aligned BASIC-PER nonnegative unconstrained INTEGER for
// ErectDomainRequest subHeight/subInterval. One short length octet
// followed by exactly 1..4 significant bytes. No fragmented PER
// length determinant and no nonminimal leading-zero encodings.
[[nodiscard]] bool readPerInteger(std::span<const std::uint8_t> payload,
                                  std::size_t &offset,
                                  std::uint32_t &output) noexcept
{
    if (offset == payload.size())
        return false;
    const std::size_t size = payload[offset++];
    if (size == 0 || size > sizeof(std::uint32_t) ||
        size > payload.size() - offset ||
        (size > 1 && payload[offset] == 0))
        return false;

    std::uint32_t value = 0;
    for (std::size_t i = 0; i < size; ++i)
        value = (value << 8U) | payload[offset++];
    output = value;
    return true;
}
[[nodiscard]] std::uint16_t readLe16At(
    std::span<const std::uint8_t> bytes,
    std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(bytes[offset + 1]) << 8U));
}

// Shared by the Demand/Confirm Active decoder and the Demand Active
// writer. All caller lengths are checked BEFORE taking a subspan.
[[nodiscard]] bool validCapabilitySetEnvelopes(
    std::span<const std::uint8_t> capabilities,
    std::uint16_t count) noexcept
{
    if (count > capabilities.size() / 4U)
        return false;
    std::size_t position = 0;
    for (std::size_t index = 0; index < count; ++index)
    {
        const std::size_t remaining = capabilities.size() - position;
        if (remaining < 4U)
            return false;
        const std::size_t length = readLe16At(capabilities, position + 2U);
        if (length < 4U || length > remaining)
            return false;
        position += length;
    }
    return position == capabilities.size();
}

// std::less provides a strict total ordering across pointers (unlike
// relational operators on unrelated arrays). Empty views do not
// overlap and are checked without pointer arithmetic on nullptr.
[[nodiscard]] bool spansOverlap(
    std::span<const std::uint8_t> source,
    std::span<std::uint8_t> destination) noexcept
{
    if (source.empty() || destination.empty())
        return false;
    const std::less<const std::uint8_t *> less{};
    return less(source.data(), destination.data() + destination.size()) &&
           less(destination.data(), source.data() + source.size());
}
} // namespace

McsChannelParseResult parseMcsChannelRequest(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    // Reuse the existing owned RFC1006/X.224 validation, including
    // rejection of truncated and coalesced trailing TPKT bytes.
    std::span<const std::uint8_t> payload;
    if (!parseDataTpdu(completeTpkt, payload))
        return {};
    if (payload.empty())
        return {{}, McsChannelParseError::InvalidDomainPdu};

    if (payload[0] == 0x04)
    {
        McsChannelRequest request{};
        std::size_t pos = 1;
        if (!readPerInteger(payload, pos, request.subHeight) ||
            !readPerInteger(payload, pos, request.subInterval) ||
            pos != payload.size())
            return {{}, McsChannelParseError::InvalidPerValue};
        request.kind = McsChannelRequestKind::ErectDomain;
        return {request, McsChannelParseError::None};
    }

    if (payload[0] == 0x28)
    {
        if (payload.size() != 1)
            return {{}, McsChannelParseError::InvalidDomainPdu};
        McsChannelRequest request{};
        request.kind = McsChannelRequestKind::AttachUser;
        return {request, McsChannelParseError::None};
    }

    if (payload[0] == 0x38)
    {
        // T.125 ChannelJoinRequest ::= initiator UserId,
        // channelId ChannelId. The PER initiator is offset by 1001;
        // no user identity or channel allocation is implied.
        if (payload.size() != 5)
            return {{}, McsChannelParseError::InvalidDomainPdu};
        const auto encodedInitiator =
            (static_cast<std::uint32_t>(payload[1]) << 8U) | payload[2];
        constexpr std::uint32_t kFirstUserId = 1001;
        constexpr std::uint32_t kMaxUserId = 65536;
        if (encodedInitiator > kMaxUserId - kFirstUserId)
            return {{}, McsChannelParseError::InvalidPerValue};
        McsChannelRequest request{};
        request.kind = McsChannelRequestKind::ChannelJoin;
        request.initiator = encodedInitiator + kFirstUserId;
        request.channelId = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(payload[3]) << 8U) | payload[4]);
        return {request, McsChannelParseError::None};
    }

    if (payload[0] == 0x64U)
    {
        // T.125 DomainMCSPDU choice 25: client SendDataRequest.
        // Layout after choice: initiator[2], channelId[2],
        // dataPriority[2 bits] | segmentation[2 bits] | pad[4 bits],
        // aligned PER OCTET STRING length[1..2], then userData.
        // No channel state or OS identity is inferred from syntax.
        constexpr std::size_t fixedHeaderBytes = 6;
        constexpr std::uint32_t firstUserId = 1001;
        constexpr std::uint32_t lastUserId = 65536;
        if (payload.size() <= fixedHeaderBytes ||
            (payload[5] & 0x0fU) != 0)
            return {{}, McsChannelParseError::InvalidDomainPdu};

        const auto encodedInitiator =
            (static_cast<std::uint32_t>(payload[1]) << 8U) | payload[2];
        if (encodedInitiator > lastUserId - firstUserId)
            return {{}, McsChannelParseError::InvalidPerValue};

        // RFC 1006 bounds the entire TPKT; T.125 aligned PER
        // supports short (7-bit) and long (14-bit) determinants here.
        // An 0x80..0xbf long determinant is accepted even for a
        // short value: actual Microsoft/FreeRDP clients emit it.
        // 0xc0..0xff would require segmented PER fragments, not
        // supported by this single-envelope syntax parser.
        const std::uint8_t firstLength = payload[fixedHeaderBytes];
        if ((firstLength & 0xc0U) == 0xc0U)
            return {{}, McsChannelParseError::InvalidPerValue};
        std::size_t dataOffset = fixedHeaderBytes + 1U;
        std::size_t dataLength = firstLength;
        if ((firstLength & 0x80U) != 0)
        {
            if (payload.size() == dataOffset)
                return {{}, McsChannelParseError::InvalidPerValue};
            dataLength =
                (static_cast<std::size_t>(firstLength & 0x3fU) << 8U) |
                payload[dataOffset++];
        }
        if (payload.size() - dataOffset != dataLength)
            return {{}, McsChannelParseError::InvalidPerValue};

        McsChannelRequest request{};
        request.kind = McsChannelRequestKind::SendDataRequest;
        request.initiator = encodedInitiator + firstUserId;
        request.channelId = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(payload[3]) << 8U) | payload[4]);
        request.dataPriority = static_cast<std::uint8_t>(
            (payload[5] >> 6U) & 0x03U);
        request.segmentation = static_cast<std::uint8_t>(
            (payload[5] >> 4U) & 0x03U);
        request.userData = payload.subspan(dataOffset, dataLength);
        return {request, McsChannelParseError::None};
    }

    if ((payload[0] & 0xfeU) == 0x20U)
    {
        // MS-RDPBCGR 2.2.2.3: choice 8, plus two-bit reason
        // straddling the two final octets. Reject nonzero padding.
        // MS-RDPBCGR 3.1.5.1.2: receiving servers MUST ignore
        // the reason, including reserved values.
        if (payload.size() != 2 || (payload[1] & 0x7fU) != 0)
            return {{}, McsChannelParseError::InvalidDomainPdu};
        McsChannelRequest request{};
        request.kind = McsChannelRequestKind::DisconnectProviderUltimatum;
        return {request, McsChannelParseError::None};
    }

    // Unknown DomainMCSPDU types, T.125 extension bits/flags, and
    // response/opposite-direction types must not be accepted as requests.
    return {{}, McsChannelParseError::InvalidDomainPdu};
}

namespace
{
constexpr std::uint32_t kFirstMcsUserId = 1001;
constexpr std::uint32_t kLastMcsUserId = 65536;

[[nodiscard]] bool validMcsUser(std::uint32_t value) noexcept
{
    return value >= kFirstMcsUserId && value <= kLastMcsUserId;
}

[[nodiscard]] std::uint8_t highByte(std::uint32_t value) noexcept
{
    return static_cast<std::uint8_t>(value >> 8U);
}
[[nodiscard]] std::uint8_t lowByte(std::uint32_t value) noexcept
{
    return static_cast<std::uint8_t>(value);
}
}

// MS-RDPBCGR 4.1.7: 03 00 00 0b 02 f0 80 2e 00 00 06 for user 1007.
// 0x2e is attachUserConfirm with the optional initiator present.
// 0x00 represents rt-successful. All writes are bounded fixed-size.
McsChannelConfirm encodeMcsAttachUserConfirm(
    std::uint32_t assignedUserId) noexcept
{
    if (!validMcsUser(assignedUserId))
        return {};
    const auto offset = assignedUserId - kFirstMcsUserId;
    McsChannelConfirm result{};
    result.packet = {0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80,
                     0x2e, 0x00, highByte(offset), lowByte(offset)};
    result.length = 11;
    return result;
}

// MS-RDPBCGR 4.1.8.2.2: 03 00 00 0f 02 f0 80 3e 00 00 06
// 03 eb 03 eb for joined I/O channel 1003 and user 1007.
McsChannelConfirm encodeMcsChannelJoinConfirm(
    const McsChannelRequest &joinRequest,
    std::uint32_t assignedUserId,
    std::span<const std::uint16_t> assignedChannelIds) noexcept
{
    if (joinRequest.kind != McsChannelRequestKind::ChannelJoin ||
        !validMcsUser(assignedUserId) ||
        joinRequest.initiator != assignedUserId ||
        joinRequest.subHeight != 0 || joinRequest.subInterval != 0 ||
        joinRequest.channelId == 0 ||
        assignedChannelIds.empty() ||
        assignedChannelIds.size() > kMaximumStaticChannelCount + 2U)
        return {};

    // The authenticated owner, NOT this encoder, is responsible
    // for proving assignedChannelIds are real allocations. Require
    // exactly one matching entry; fail closed on any duplicates.
    std::size_t matches = 0;
    for (std::size_t i = 0; i < assignedChannelIds.size(); ++i)
    {
        const auto channel = assignedChannelIds[i];
        if (channel == 0)
            return {};
        if (channel == joinRequest.channelId)
            ++matches;
        for (std::size_t j = 0; j < i; ++j)
        {
            if (assignedChannelIds[j] == channel)
                return {};
        }
    }
    if (matches != 1)
        return {};

    const auto userOffset = assignedUserId - kFirstMcsUserId;
    const auto channel = joinRequest.channelId;
    McsChannelConfirm result{};
    result.packet = {0x03, 0x00, 0x00, 0x0f, 0x02, 0xf0, 0x80,
                     0x3e, 0x00, highByte(userOffset),
                     lowByte(userOffset), highByte(channel),
                     lowByte(channel), highByte(channel),
                     lowByte(channel)};
    result.length = 15;
    return result;
}

namespace
{
struct McsSessionConnectValidation
{
    McsDomainParameters domain{};
    GccClientSettings settings{};
    McsConnectResponseAllocation allocation{};
    std::optional<McsSessionIntake> failure{};
};
[[nodiscard]] McsSessionConnectValidation validateMcsSessionConnectInitial(
    std::span<const std::uint8_t> tpkt) noexcept
{
    if(tpkt.size()>kMaximumInitialMcsTpktBytes)
        return {{},{},{},McsSessionIntake::OversizedEnvelope};
    if(tpkt.size()<8U) return {{},{},{},McsSessionIntake::InvalidEnvelope};
    const auto p=parseMcsConnectInitial(tpkt);
    if(!p) return {{},{},{},McsSessionIntake::InvalidEnvelope};
    const auto d=mergeMcsDomainParameters(p.value);
    if(!d) return {{},{},{},McsSessionIntake::InvalidDomainParameters};
    const auto g=parseGccConferenceCreate(p.value.gccUserData);
    if(!g) return {{},{},{},McsSessionIntake::InvalidGccUserData};
    const auto a=planMcsConnectResponseAllocation(d.value,g.settings);
    if(!a) return {{},{},{},McsSessionIntake::InvalidResourceAllocation};
    return {d.value,g.settings,*a,std::nullopt};
}
} // namespace

McsSessionIntake McsSessionLifecycle::onConnectInitial(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == McsSessionPhase::Closed)
        return McsSessionIntake::Closed;
    if (phase_ != McsSessionPhase::AwaitVerifiedR2Admission)
    {
        close();
        return McsSessionIntake::InvalidOrdering;
    }

    const auto validation = validateMcsSessionConnectInitial(completeTpkt);
    close();
    return validation.failure.has_value()
               ? *validation.failure
               : McsSessionIntake::ValidButNotAdmitted;
}

McsSessionIntake McsSessionLifecycle::onVerifiedR2ConnectInitial(
    std::uint64_t admissionGeneration,
    std::uint64_t sessionGeneration,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == McsSessionPhase::Closed)
        return McsSessionIntake::Closed;
    if (phase_ != McsSessionPhase::AwaitVerifiedR2Admission)
    {
        close();
        return McsSessionIntake::InvalidOrdering;
    }
    if (admissionGeneration == 0 || sessionGeneration == 0)
    {
        close();
        return McsSessionIntake::AdmissionDenied;
    }

    const auto validation = validateMcsSessionConnectInitial(completeTpkt);
    if (validation.failure.has_value())
    {
        close();
        return *validation.failure;
    }

    connectResponseDomain_ = validation.domain;
    connectResponseClientSettings_ = validation.settings;
    connectResponseAllocation_ = validation.allocation;
    admissionGeneration_ = admissionGeneration;
    sessionGeneration_ = sessionGeneration;
    phase_ = McsSessionPhase::AwaitConnectResponse;
    return McsSessionIntake::AdmittedConnectInitial;
}

void McsSessionLifecycle::revokeUnlessAdmissionBindingMatches(
    std::uint64_t admissionGeneration,
    std::uint64_t sessionGeneration) noexcept
{
    // Public scalar inputs are revocation-only. Keep only an already-admitted
    // phase with the exact stored generations; this fence also applies after
    // Connect Response delivery.
    if (phase_ == McsSessionPhase::AwaitVerifiedR2Admission ||
        phase_ == McsSessionPhase::Closed ||
        admissionGeneration == 0 || sessionGeneration == 0 ||
        admissionGeneration_ != admissionGeneration ||
        sessionGeneration_ != sessionGeneration)
    {
        close();
    }
}


std::optional<McsConnectResponseWriteView>
McsSessionLifecycle::prepareConnectResponseWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if(phase_!=McsSessionPhase::AwaitConnectResponse ||
       !connectResponseAllocation_ ||
       !matchesMcsSecurityNegotiationReplay(
           connectResponseClientSettings_,provenance)){
        close(); return std::nullopt;
    }
    if(connectResponseProvenanceBound_){
        if(connectResponseBoundProvenance_!=provenance){
            close(); return std::nullopt;
        }
    }else{
        const auto response=encodeMcsConnectResponseFromNegotiatedState(
            connectResponseDomain_,connectResponseClientSettings_.channelCount,
            connectResponseAllocation_.staticChannels(),
            connectResponseAllocation_.gccNodeId,
            provenance.clientRequestedProtocols);
        if(!response||!connectResponseWrite_.queue(response)){
            close(); return std::nullopt;
        }
        connectResponseBoundProvenance_=provenance;
        connectResponseProvenanceBound_=true;
    }
    const auto pending=connectResponseWrite_.pendingWrite();
    if(!pending){close();return std::nullopt;}
    return pending;
}

McsConnectResponseWriteOutcome McsSessionLifecycle::completeConnectResponseWrite(
    std::uint64_t reply,std::uint64_t slice,std::size_t accepted) noexcept
{
    if(phase_!=McsSessionPhase::AwaitConnectResponse){
        close(); return McsConnectResponseWriteOutcome::Rejected;
    }
    const auto out=connectResponseWrite_.onBytesWritten(reply,slice,accepted);
    if(out==McsConnectResponseWriteOutcome::Rejected) close();
    else if(out==McsConnectResponseWriteOutcome::Delivered)
        phase_=McsSessionPhase::AwaitErectDomain;
    return out;
}

McsSessionIntake McsSessionLifecycle::onDomainPdu(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == McsSessionPhase::Closed)
        return McsSessionIntake::Closed;

    const McsSessionPhase phaseAtIntake = phase_;
    // Until Connect Response completes, keep the same conservative intake
    // budget. A valid peer Disconnect remains legal teardown in either open
    // phase; every other DomainMCSPDU is classified then rejected by order.
    if (completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return McsSessionIntake::OversizedEnvelope;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    close();
    if (!parsed)
    {
        switch (parsed.error)
        {
        case McsChannelParseError::InvalidTransport:
            return McsSessionIntake::InvalidDomainTransport;
        case McsChannelParseError::InvalidDomainPdu:
            return McsSessionIntake::InvalidDomainPdu;
        case McsChannelParseError::InvalidPerValue:
            return McsSessionIntake::InvalidDomainPerValue;
        case McsChannelParseError::None:
            break;
        }
        return McsSessionIntake::InvalidEnvelope;
    }
    if (parsed.request.kind ==
        McsChannelRequestKind::DisconnectProviderUltimatum)
        return McsSessionIntake::PeerDisconnected;
    return phaseAtIntake == McsSessionPhase::AwaitVerifiedR2Admission
               ? McsSessionIntake::ValidButNotAdmitted
               : McsSessionIntake::InvalidOrdering;
}

std::optional<std::array<std::uint8_t, 9>>
encodeMcsDisconnectProviderUltimatum(McsDisconnectReason reason) noexcept
{
    // Per MS-RDPBCGR 3.1.5.1.1 only provider-initiated (1)
    // and user-requested (3) are legal for server transmission.
    if (reason != McsDisconnectReason::ProviderInitiated &&
        reason != McsDisconnectReason::UserRequested)
        return std::nullopt;

    // Nine exact TPKT/X.224/PER octets, no intermediate buffer.
    // Provider (01) = 20 80; user (11) = 21 80.
    return std::array<std::uint8_t, 9>{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80,
        reason == McsDisconnectReason::UserRequested
            ? static_cast<std::uint8_t>(0x21)
            : static_cast<std::uint8_t>(0x20),
        0x80};
}

std::optional<std::size_t> encodeMcsSendDataIndication(
    std::uint32_t assignedUserId,
    std::uint16_t channelId,
    std::uint8_t dataPriority,
    std::uint8_t segmentation,
    std::span<const std::uint8_t> userData,
    std::span<std::uint8_t> output) noexcept
{
    // T.125 11.33 / MS-RDPBCGR 2.2.6.1: server Send Data Indication
    // is choice 26 (0x68), NOT the client Send Data Request (0x64).
    // The caller owns both buffer and authenticated channel state.
    constexpr std::size_t kShortHeaderBytes = 14;
    constexpr std::size_t kLongHeaderBytes = 15;
    constexpr std::size_t kLargestUnfragmentedPer = 16383;
    if (!validMcsUser(assignedUserId) || channelId == 0 ||
        dataPriority > 3 || segmentation > 3 ||
        userData.size() > kLargestUnfragmentedPer)
        return std::nullopt;

    const bool longLength = userData.size() >= 128;
    const std::size_t headerBytes =
        longLength ? kLongHeaderBytes : kShortHeaderBytes;
    const std::size_t packetBytes = headerBytes + userData.size();
    if (output.size() < packetBytes)
        return std::nullopt;

    // Overlap-safe, allocation-free; copying the payload first is
    // essential when the source aliases the destination header.
    if (!userData.empty())
        std::memmove(output.data() + headerBytes, userData.data(),
                     userData.size());

    const auto offset = assignedUserId - kFirstMcsUserId;
    output[0] = 0x03;
    output[1] = 0x00;
    output[2] = highByte(static_cast<std::uint32_t>(packetBytes));
    output[3] = lowByte(static_cast<std::uint32_t>(packetBytes));
    output[4] = 0x02;
    output[5] = 0xf0;
    output[6] = 0x80;
    output[7] = 0x68;
    output[8] = highByte(offset);
    output[9] = lowByte(offset);
    output[10] = highByte(channelId);
    output[11] = lowByte(channelId);
    output[12] = static_cast<std::uint8_t>(
        (dataPriority << 6U) | (segmentation << 4U));
    if (longLength)
    {
        output[13] = static_cast<std::uint8_t>(
            0x80U | (userData.size() >> 8U));
        output[14] = static_cast<std::uint8_t>(userData.size());
    }
    else
    {
        output[13] = static_cast<std::uint8_t>(userData.size());
    }
    return packetBytes;
}

RdpShareControlParseResult parseRdpShareControlHeader(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    // MS-RDPBCGR 2.2.8.1.1.1.1: six-byte little-endian
    // TS_SHARECONTROLHEADER with exact totalLength.
    constexpr std::size_t headerBytes = 6;
    if (completeSharePdu.size() < headerBytes)
        return {};

    const std::size_t totalLength =
        static_cast<std::size_t>(completeSharePdu[0]) |
        (static_cast<std::size_t>(completeSharePdu[1]) << 8U);
    if (totalLength == 0x8000U)
    {
        // T.128 FlowPDU must be IGNORED rather than dispatched as
        // ordinary share traffic. Do not expose its untrusted body.
        return {{}, RdpShareControlError::FlowPduIgnored};
    }
    if (totalLength != completeSharePdu.size())
        return {};

    const std::uint16_t typeAndVersion =
        static_cast<std::uint16_t>(completeSharePdu[2]) |
        (static_cast<std::uint16_t>(completeSharePdu[3]) << 8U);
    // 12-bit PDUVersion must be 1 (TS_PROTOCOL_VERSION = 0x10).
    // Only the low four bits encode the normative PDU type.
    if ((typeAndVersion & 0xfff0U) != 0x0010U)
        return {{}, RdpShareControlError::InvalidType};

    const auto kind =
        static_cast<RdpShareControlKind>(typeAndVersion & 0x0fU);
    switch (kind)
    {
    case RdpShareControlKind::DemandActive:
    case RdpShareControlKind::ConfirmActive:
    case RdpShareControlKind::DeactivateAll:
    case RdpShareControlKind::Data:
    case RdpShareControlKind::ServerRedirection:
        break;
    default:
        return {{}, RdpShareControlError::InvalidType};
    }

    RdpShareControlHeader header{};
    header.kind = kind;
    header.pduSource =
        static_cast<std::uint16_t>(completeSharePdu[4]) |
        (static_cast<std::uint16_t>(completeSharePdu[5]) << 8U);
    header.body = completeSharePdu.subspan(headerBytes);
    return {header, RdpShareControlError::None};
}

RdpShareDataParseResult parseRdpShareDataHeader(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    // Reuse the one authoritative Share Control length/version/type
    // check rather than accepting arbitrary MCS userData as a Data PDU.
    const auto control = parseRdpShareControlHeader(completeSharePdu);
    if (control.error == RdpShareControlError::FlowPduIgnored)
        return {{}, RdpShareDataError::FlowPduIgnored};
    if (!control)
        return {};
    if (control.value.kind != RdpShareControlKind::Data)
        return {{}, RdpShareDataError::NotDataPdu};

    constexpr std::size_t headerBytes = 12;
    const auto bytes = control.value.body;
    if (bytes.size() < headerBytes)
        return {{}, RdpShareDataError::IncompleteHeader};

    const std::uint8_t pduType2 = bytes[8];
    // MS-RDPBCGR 2.2.8.1.1.1.2 defines these Data PDU types.
    // Unknown types must not reach an application dispatcher.
    switch (pduType2)
    {
    case 0x02: // UPDATE
    case 0x14: // CONTROL
    case 0x1b: // POINTER
    case 0x1c: // INPUT
    case 0x1f: // SYNCHRONIZE
    case 0x21: // REFRESH_RECT
    case 0x22: // PLAY_SOUND
    case 0x23: // SUPPRESS_OUTPUT
    case 0x24: // SHUTDOWN_REQUEST
    case 0x25: // SHUTDOWN_DENIED
    case 0x26: // SAVE_SESSION_INFO
    case 0x27: // FONTLIST
    case 0x28: // FONTMAP
    case 0x29: // SET_KEYBOARD_INDICATORS
    case 0x2b: // BITMAPCACHE_PERSISTENT_LIST
    case 0x2c: // BITMAPCACHE_ERROR_PDU
    case 0x2d: // SET_KEYBOARD_IME_STATUS
    case 0x2e: // OFFSCRCACHE_ERROR_PDU
    case 0x2f: // SET_ERROR_INFO_PDU
    case 0x30: // DRAWNINEGRID_ERROR_PDU
    case 0x31: // DRAWGDIPLUS_ERROR_PDU
    case 0x32: // ARC_STATUS_PDU
    case 0x36: // STATUS_INFO_PDU
    case 0x37: // MONITOR_LAYOUT_PDU
        break;
    default:
        return {{}, RdpShareDataError::InvalidDataPduType};
    }

    const std::uint8_t stream = bytes[5];
    // STREAM_UNDEFINED is reserved except for the Windows
    // Server Synchronize PDU compatibility exception.
    if (stream != 1 && stream != 2 && stream != 4 &&
        !(stream == 0 && pduType2 == 0x1f))
        return {{}, RdpShareDataError::InvalidStream};

    // A nonzero compressedType can require MPPC/RDP6 history state;
    // never reinterpret such bytes as uncompressed application data.
    if (bytes[9] != 0)
        return {{}, RdpShareDataError::UnsupportedCompression};

    RdpShareDataHeader header{};
    header.pduSource = control.value.pduSource;
    header.shareId = static_cast<std::uint32_t>(bytes[0]) |
                     (static_cast<std::uint32_t>(bytes[1]) << 8U) |
                     (static_cast<std::uint32_t>(bytes[2]) << 16U) |
                     (static_cast<std::uint32_t>(bytes[3]) << 24U);
    // bytes[4] pad1 MUST be ignored, including nonzero values.
    header.streamId = stream;
    header.reportedUncompressedLength =
        static_cast<std::uint16_t>(bytes[6]) |
        (static_cast<std::uint16_t>(bytes[7]) << 8U);
    header.pduType2 = pduType2;
    header.compressedType = bytes[9];
    header.compressedLength = static_cast<std::uint16_t>(bytes[10]) |
                              (static_cast<std::uint16_t>(bytes[11]) << 8U);
    // A historical client may send uninitialized uncompressedLength
    // (e.g. Font List). Preserve it as metadata, NOT an allocation
    // count or proof of valid length. The enclosing control's
    // totalLength is the validated boundary.
    header.body = bytes.subspan(headerBytes);
    return {header, RdpShareDataError::None};
}

RdpSynchronizeParseResult parseRdpSynchronizePdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    // Reuse both authoritative framing validators. A byte sequence
    // from MCS is not inherently a decrypted Share Control PDU.
    const auto data = parseRdpShareDataHeader(completeSharePdu);
    if (!data)
        return {};
    if (data.value.pduType2 != 0x1fU)
        return {{}, RdpFinalizationError::WrongDataPduType};
    const auto body = data.value.body;
    if (body.size() != 4U)
        return {{}, RdpFinalizationError::InvalidBodyLength};
    // MS-RDPBCGR 2.2.1.14.1: SYNCMSGTYPE_SYNC = 1, LE16.
    if (body[0] != 1U || body[1] != 0U)
        return {{}, RdpFinalizationError::InvalidValue};

    RdpSynchronizePdu value{};
    value.pduSource = data.value.pduSource;
    value.shareId = data.value.shareId;
    value.targetUser = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(body[2]) |
        (static_cast<std::uint16_t>(body[3]) << 8U));
    // targetUser is not checked against any actual assigned channel;
    // only the separately authenticated session owner can do so.
    return {value, RdpFinalizationError::None};
}

RdpControlParseResult parseRdpControlPdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    const auto data = parseRdpShareDataHeader(completeSharePdu);
    if (!data)
        return {};
    if (data.value.pduType2 != 0x14U)
        return {{}, RdpFinalizationError::WrongDataPduType};
    const auto body = data.value.body;
    if (body.size() != 8U)
        return {{}, RdpFinalizationError::InvalidBodyLength};

    const std::uint16_t action = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(body[0]) |
        (static_cast<std::uint16_t>(body[1]) << 8U));
    if (action < 1U || action > 4U)
        return {{}, RdpFinalizationError::InvalidValue};

    RdpControlPdu value{};
    value.pduSource = data.value.pduSource;
    value.shareId = data.value.shareId;
    value.action = static_cast<RdpControlAction>(action);
    value.grantId = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(body[2]) |
        (static_cast<std::uint16_t>(body[3]) << 8U));
    value.controlId = static_cast<std::uint32_t>(body[4]) |
                      (static_cast<std::uint32_t>(body[5]) << 8U) |
                      (static_cast<std::uint32_t>(body[6]) << 16U) |
                      (static_cast<std::uint32_t>(body[7]) << 24U);
    // A valid enum and raw IDs do not prove grant, session owner,
    // direction, MCS membership or active share negotiation.
    return {value, RdpFinalizationError::None};
}

RdpActivePduParseResult parseRdpActivePdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    // Reuse the authoritative complete, exact-length Share Control
    // header check. This does not prove TLS/session/channel provenance.
    const auto control = parseRdpShareControlHeader(completeSharePdu);
    if (!control)
        return {};
    const bool demand = control.value.kind ==
                        RdpShareControlKind::DemandActive;
    if (!demand && control.value.kind != RdpShareControlKind::ConfirmActive)
        return {{}, RdpActivePduError::WrongPduType};

    const auto bytes = control.value.body;
    // Demand: shareID[4], sourceLen[2], combinedLen[2].
    // Confirm: shareID[4], originatorID[2], sourceLen[2],
    // combinedLen[2]. Both contain descriptor, count+pad,
    // capability sets; Demand additionally has sessionID[4].
    const std::size_t prefix = demand ? 8U : 10U;
    const std::size_t sessionBytes = demand ? 4U : 0U;
    if (bytes.size() < prefix + 4U + sessionBytes)
        return {{}, RdpActivePduError::InvalidLayout};

    const auto le16 = [](std::span<const std::uint8_t> data,
                         std::size_t offset) noexcept -> std::uint16_t
    {
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(data[offset]) |
            (static_cast<std::uint16_t>(data[offset + 1]) << 8U));
    };
    const auto le32 = [&le16](std::span<const std::uint8_t> data,
                              std::size_t offset) noexcept -> std::uint32_t
    {
        return static_cast<std::uint32_t>(le16(data, offset)) |
               (static_cast<std::uint32_t>(
                    le16(data, offset + 2)) << 16U);
    };
    const std::uint16_t originator =
        demand ? 0U : le16(bytes, 4U);
    // In Confirm Active the originatorID MUST be server channel 1002,
    // not a client UserId. Still no authorization is implied.
    if (!demand && originator != 1002U)
        return {{}, RdpActivePduError::InvalidOriginator};

    const std::size_t sourceBytes = le16(bytes, prefix - 4U);
    const std::size_t combinedBytes = le16(bytes, prefix - 2U);
    if (combinedBytes < 4U || sourceBytes > bytes.size() - prefix)
        return {{}, RdpActivePduError::InvalidLayout};
    const std::size_t capabilityStart = prefix + sourceBytes;
    const std::size_t available = bytes.size() - capabilityStart;
    if (combinedBytes > available ||
        available - combinedBytes != sessionBytes)
        return {{}, RdpActivePduError::InvalidLayout};

    const auto capabilities =
        bytes.subspan(capabilityStart + 4U, combinedBytes - 4U);
    const std::size_t count = le16(bytes, capabilityStart);
    // Validate exactly count envelopes. Shared with the server writer
    // to avoid any parser/wire-generation acceptance divergence.
    if (!validCapabilitySetEnvelopes(
            capabilities, static_cast<std::uint16_t>(count)))
        return {{}, RdpActivePduError::InvalidCapabilitySet};

    RdpActivePdu value{};
    value.kind = control.value.kind;
    value.pduSource = control.value.pduSource;
    value.shareId = le32(bytes, 0U);
    value.originatorId = originator;
    value.sessionId = demand ? le32(bytes, bytes.size() - 4U) : 0U;
    value.capabilityCount = static_cast<std::uint16_t>(count);
    value.sourceDescriptor = bytes.subspan(prefix, sourceBytes);
    value.capabilitySets = capabilities;
    return {value, RdpActivePduError::None};
}

RdpGeneralCapabilityParseResult parseRdpGeneralCapabilityFromActive(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    // The existing parser verifies one entire Share Control PDU, the
    // capability count and EVERY nested envelope before any byte access.
    const auto active = parseRdpActivePdu(completeSharePdu);
    if (!active)
        return {{}, RdpGeneralCapabilityError::InvalidActivePdu};

    constexpr std::uint16_t kGeneralType = 1U;
    constexpr std::size_t kGeneralBytes = 24U;
    constexpr std::uint16_t kProtocolVersion = 0x0200U;
    const auto capabilities = active.value.capabilitySets;
    std::size_t position = 0;
    std::span<const std::uint8_t> generalBytes;
    for (std::size_t index = 0; index < active.value.capabilityCount; ++index)
    {
        // Exact, bounded envelopes are established by parseRdpActivePdu.
        const std::size_t length = readLe16At(capabilities, position + 2U);
        if (readLe16At(capabilities, position) == kGeneralType)
        {
            if (!generalBytes.empty())
                return {{}, RdpGeneralCapabilityError::Duplicate};
            if (length != kGeneralBytes)
                return {{}, RdpGeneralCapabilityError::InvalidLayout};
            generalBytes = capabilities.subspan(position, length);
        }
        position += length;
    }
    if (generalBytes.empty())
        return {{}, RdpGeneralCapabilityError::Missing};
    if (readLe16At(generalBytes, 8U) != kProtocolVersion)
        return {{}, RdpGeneralCapabilityError::InvalidProtocolVersion};
    if (generalBytes[22U] > 1U || generalBytes[23U] > 1U)
        return {{}, RdpGeneralCapabilityError::InvalidBoolean};

    RdpGeneralCapability value{};
    value.osMajorType = readLe16At(generalBytes, 4U);
    value.osMinorType = readLe16At(generalBytes, 6U);
    // pad2OctetsA at 10..11 MUST be ignored, not required to be zero.
    value.generalCompressionTypes = readLe16At(generalBytes, 12U);
    value.extraFlags = readLe16At(generalBytes, 14U);
    value.updateCapabilityFlag = readLe16At(generalBytes, 16U);
    value.remoteUnshareFlag = readLe16At(generalBytes, 18U);
    value.generalCompressionLevel = readLe16At(generalBytes, 20U);
    value.refreshRectSupported = generalBytes[22U] == 1U;
    value.suppressOutputSupported = generalBytes[23U] == 1U;
    // A valid announcement does not select graphics or admit any session.
    return {value, RdpGeneralCapabilityError::None};
}

RdpBitmapCapabilityParseResult parseRdpBitmapCapabilityFromActive(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    // Exact complete PDU and every nested capability-set envelope
    // have already been validated by the one authoritative parser.
    const auto active = parseRdpActivePdu(completeSharePdu);
    if (!active)
        return {{}, RdpBitmapCapabilityError::InvalidActivePdu};

    constexpr std::uint16_t kBitmapType = 2U;
    constexpr std::size_t kBitmapBytes = 28U;
    const auto capabilities = active.value.capabilitySets;
    std::span<const std::uint8_t> bitmap;
    std::size_t position = 0;
    for (std::size_t index = 0; index < active.value.capabilityCount; ++index)
    {
        const std::size_t length = readLe16At(capabilities, position + 2U);
        if (readLe16At(capabilities, position) == kBitmapType)
        {
            if (!bitmap.empty())
                return {{}, RdpBitmapCapabilityError::Duplicate};
            if (length != kBitmapBytes)
                return {{}, RdpBitmapCapabilityError::InvalidLayout};
            bitmap = capabilities.subspan(position, length);
        }
        position += length;
    }
    if (bitmap.empty())
        return {{}, RdpBitmapCapabilityError::Missing};

    const auto width = readLe16At(bitmap, 12U);
    const auto height = readLe16At(bitmap, 14U);
    if (width == 0U || height == 0U)
        return {{}, RdpBitmapCapabilityError::InvalidDesktopSize};
    const auto resize = readLe16At(bitmap, 18U);
    if (resize > 1U)
        return {{}, RdpBitmapCapabilityError::InvalidResizeFlag};

    // MS-RDPBCGR requires BOTH flags to be TRUE for a connection.
    // Ignored 1/4/8 bpp receive flags, padding and highColorFlags
    // must not be mistaken for mandatory feature negotiations.
    if (readLe16At(bitmap, 20U) != 1U ||
        readLe16At(bitmap, 24U) != 1U)
        return {{}, RdpBitmapCapabilityError::MissingRequiredSupport};

    RdpBitmapCapability value{};
    value.preferredBitsPerPixel = readLe16At(bitmap, 4U);
    value.desktopWidth = width;
    value.desktopHeight = height;
    value.desktopResizeSupported = resize == 1U;
    value.drawingFlags = bitmap[23U];
    return {value, RdpBitmapCapabilityError::None};
}

std::optional<std::size_t> encodeRdpDemandActivePdu(
    std::uint32_t shareId,
    std::uint32_t sessionId,
    std::span<const std::uint8_t> sourceDescriptor,
    std::uint16_t capabilityCount,
    std::span<const std::uint8_t> capabilitySets,
    std::span<std::uint8_t> output) noexcept
{
    // MS-RDPBCGR 2.2.1.13.1.1 Demand Active fixed portions:
    // Share Control 6, shareID/source/combined lengths 8,
    // numberCapabilities/pad 4, sessionID 4.
    constexpr std::size_t kFixedBytes = 22U;
    constexpr std::size_t kMaxField =
        std::numeric_limits<std::uint16_t>::max();
    constexpr std::size_t kFlowPduLength = 0x8000U;
    if (sourceDescriptor.size() > kMaxField ||
        capabilitySets.size() > kMaxField - 4U ||
        !validCapabilitySetEnvelopes(capabilitySets, capabilityCount))
        return std::nullopt;

    // A full Share Control totalLength MUST fit LE16 and MUST NOT be
    // the reserved T.128 FlowPDU marker. Arithmetic is bounded by
    // the individual 16-bit lengths above before any addition.
    const std::size_t size =
        kFixedBytes + sourceDescriptor.size() + capabilitySets.size();
    if (size > kMaxField || size == kFlowPduLength ||
        output.size() < size)
        return std::nullopt;
    const auto written = output.first(size);
    if (spansOverlap(sourceDescriptor, written) ||
        spansOverlap(capabilitySets, written))
        return std::nullopt;

    // All validation is complete. The two source spans remain live
    // and disjoint from the touched output. No copies or allocations
    // on the failure path; exactly one copy per input slice on success.
    const auto write16 = [&written](std::size_t pos,
                                   std::uint16_t value) noexcept
    {
        written[pos] = static_cast<std::uint8_t>(value);
        written[pos + 1U] = static_cast<std::uint8_t>(value >> 8U);
    };
    const auto write32 = [&write16](std::size_t pos,
                                   std::uint32_t value) noexcept
    {
        write16(pos, static_cast<std::uint16_t>(value));
        write16(pos + 2U, static_cast<std::uint16_t>(value >> 16U));
    };

    write16(0U, static_cast<std::uint16_t>(size));
    write16(2U, 0x0011U); // TS_PROTOCOL_VERSION | DEMANDACTIVE
    write16(4U, 1002U);   // MCS server channel (0x03ea)
    write32(6U, shareId);
    write16(10U, static_cast<std::uint16_t>(sourceDescriptor.size()));
    write16(12U, static_cast<std::uint16_t>(capabilitySets.size() + 4U));
    if (!sourceDescriptor.empty())
        std::memcpy(written.data() + 14U,
                    sourceDescriptor.data(), sourceDescriptor.size());
    const std::size_t countOffset = 14U + sourceDescriptor.size();
    write16(countOffset, capabilityCount);
    write16(countOffset + 2U, 0U); // pad2Octets, ignored on read.
    if (!capabilitySets.empty())
        std::memcpy(written.data() + countOffset + 4U,
                    capabilitySets.data(), capabilitySets.size());
    write32(size - 4U, sessionId);
    return size;
}

namespace
{
void writeLe16(std::span<std::uint8_t> bytes,
               std::size_t offset,
               std::uint16_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void writeLe32(std::span<std::uint8_t> bytes,
               std::size_t offset,
               std::uint32_t value) noexcept
{
    writeLe16(bytes, offset, static_cast<std::uint16_t>(value));
    writeLe16(bytes, offset + 2U,
              static_cast<std::uint16_t>(value >> 16U));
}

// Called ONLY after the public writer checks the entire capacity
// and any semantic parameter restrictions. Does not allocate.
void writeServerShareDataHeader(std::span<std::uint8_t> bytes,
                                std::uint16_t packetSize,
                                std::uint32_t shareId,
                                std::uint8_t pduType2,
                                std::uint8_t streamId) noexcept
{
    writeLe16(bytes, 0U, packetSize);
    writeLe16(bytes, 2U, 0x0017U); // T.128 version 1, Data PDU.
    writeLe16(bytes, 4U, 1002U);   // Server MCS channel.
    writeLe32(bytes, 6U, shareId);
    bytes[10] = 0;                 // pad1, receiver ignores.
    bytes[11] = streamId;
    writeLe16(bytes, 12U, packetSize); // Uncompressed length.
    bytes[14] = pduType2;
    bytes[15] = 0;                 // No MPPC compression.
    writeLe16(bytes, 16U, 0U);     // No compressed bytes.
}
} // namespace

std::optional<std::size_t> encodeRdpServerSynchronizePdu(
    std::uint32_t shareId,
    std::uint16_t targetUser,
    std::span<std::uint8_t> output) noexcept
{
    // MS-RDPBCGR 2.2.1.14.1 and 2.2.1.19: 18-byte
    // Share Control/Data header + 4-byte Synchronize body.
    constexpr std::size_t size = 22U;
    if (output.size() < size)
        return std::nullopt;
    const auto bytes = output.first(size);
    // Microsoft's Server Synchronize can use STREAM_UNDEFINED=0;
    // the existing Share Data parser explicitly recognizes this.
    writeServerShareDataHeader(bytes, 22U, shareId, 0x1fU, 0U);
    writeLe16(bytes, 18U, 1U); // SYNCMSGTYPE_SYNC
    writeLe16(bytes, 20U, targetUser);
    return size;
}

std::optional<std::size_t> encodeRdpServerControlPdu(
    std::uint32_t shareId,
    RdpControlAction action,
    std::uint32_t assignedClientUserId,
    std::span<std::uint8_t> output) noexcept
{
    // MS-RDPBCGR 2.2.1.15.1, 2.2.1.20, 2.2.1.21:
    // server only sends Cooperate/Granted during finalization.
    // Neither action is a valid authorization signal by itself.
    const bool cooperate = action == RdpControlAction::Cooperate;
    const bool granted = action == RdpControlAction::GrantedControl;
    if ((!cooperate && !granted) ||
        (cooperate && assignedClientUserId != 0U) ||
        (granted &&
         (assignedClientUserId < 1001U ||
          assignedClientUserId > 65535U)))
        return std::nullopt;

    constexpr std::size_t size = 26U;
    if (output.size() < size)
        return std::nullopt;
    const auto bytes = output.first(size);
    writeServerShareDataHeader(bytes, 26U, shareId, 0x14U, 2U);
    writeLe16(bytes, 18U, static_cast<std::uint16_t>(action));
    writeLe16(bytes, 20U,
              cooperate ? 0U
                        : static_cast<std::uint16_t>(assignedClientUserId));
    writeLe32(bytes, 22U, cooperate ? 0U : 1002U);
    return size;
}

RdpActiveExchangeCorrelation correlateRdpActiveExchange(
    std::span<const std::uint8_t> serverDemandSharePdu,
    std::span<const std::uint8_t> clientConfirmSharePdu,
    std::uint32_t expectedClientUserId) noexcept
{
    // A 16-bit Share Control pduSource cannot represent 65536,
    // even though the T.125 initiator domain can. Refuse an
    // unrepresentable or unassigned user channel before parsing.
    if (expectedClientUserId < 1001U ||
        expectedClientUserId > 65535U)
        return RdpActiveExchangeCorrelation::Rejected;

    const auto demand = parseRdpActivePdu(serverDemandSharePdu);
    if (!demand ||
        demand.value.kind != RdpShareControlKind::DemandActive ||
        demand.value.pduSource != 1002U)
        return RdpActiveExchangeCorrelation::Rejected;

    const auto confirm = parseRdpActivePdu(clientConfirmSharePdu);
    if (!confirm ||
        confirm.value.kind != RdpShareControlKind::ConfirmActive ||
        confirm.value.pduSource != expectedClientUserId ||
        confirm.value.originatorId != 1002U ||
        confirm.value.shareId != demand.value.shareId)
        return RdpActiveExchangeCorrelation::Rejected;

    // Even a matching exchange says nothing about the meaning of
    // either opaque capability list, client session identity,
    // licenses, share lifecycle or actual sender provenance.
    return RdpActiveExchangeCorrelation::ConsistentSyntaxOnly;
}


RdpFinalizationCorrelation correlateRdpFinalizationExchange(
    const RdpFinalizationTranscript &transcript,
    std::uint32_t expectedShareId,
    std::uint32_t expectedClientUserId) noexcept
{
    // Both Share Control source and Control grant identifiers are LE16.
    // This check is only representability, not authenticated allocation.
    constexpr auto rejected = RdpFinalizationCorrelation::Rejected;
    if (expectedClientUserId < 1001U ||
        expectedClientUserId > 65535U)
        return rejected;

    const auto clientSync =
        parseRdpSynchronizePdu(transcript.clientSynchronize);
    const auto clientCooperate =
        parseRdpControlPdu(transcript.clientCooperate);
    const auto clientRequest =
        parseRdpControlPdu(transcript.clientRequestControl);
    const auto serverSync =
        parseRdpSynchronizePdu(transcript.serverSynchronize);
    const auto serverCooperate =
        parseRdpControlPdu(transcript.serverCooperate);
    const auto serverGranted =
        parseRdpControlPdu(transcript.serverGrantedControl);
    if (!clientSync || !clientCooperate || !clientRequest ||
        !serverSync || !serverCooperate || !serverGranted)
        return rejected;

    if (clientSync.value.pduSource != expectedClientUserId ||
        clientSync.value.shareId != expectedShareId ||
        clientSync.value.targetUser != 1002U ||
        clientCooperate.value.pduSource != expectedClientUserId ||
        clientCooperate.value.shareId != expectedShareId ||
        clientCooperate.value.action != RdpControlAction::Cooperate ||
        clientCooperate.value.grantId != 0U ||
        clientCooperate.value.controlId != 0U ||
        clientRequest.value.pduSource != expectedClientUserId ||
        clientRequest.value.shareId != expectedShareId ||
        clientRequest.value.action != RdpControlAction::RequestControl ||
        clientRequest.value.grantId != 0U ||
        clientRequest.value.controlId != 0U)
        return rejected;

    // Microsoft's server Synchronize example has an uninitialized
    // targetUser; its raw value is NOT a channel membership proof.
    if (serverSync.value.pduSource != 1002U ||
        serverSync.value.shareId != expectedShareId ||
        serverCooperate.value.pduSource != 1002U ||
        serverCooperate.value.shareId != expectedShareId ||
        serverCooperate.value.action != RdpControlAction::Cooperate ||
        serverCooperate.value.grantId != 0U ||
        serverCooperate.value.controlId != 0U ||
        serverGranted.value.pduSource != 1002U ||
        serverGranted.value.shareId != expectedShareId ||
        serverGranted.value.action != RdpControlAction::GrantedControl ||
        serverGranted.value.grantId != expectedClientUserId ||
        serverGranted.value.controlId != 1002U)
        return rejected;

    // A borrowed packet comparison does not prove transport delivery
    // order, TLS/NLA identity, OS permission, license or share activation.
    return RdpFinalizationCorrelation::ConsistentSyntaxOnly;
}

} // namespace rdp_server::server::transport
