// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_channel_connection.h"
#include "mcs_connect_initial.h"
#include "gcc_conference_create.h"

#include <array>
#include <cstddef>
#include <cstring>
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
    // capSetType[2], lengthCapability[2] and opaque capData. Each
    // length includes the four-byte envelope; unknown IDs remain
    // opaque (a later negotiated capability owner handles semantics).
    if (count > capabilities.size() / 4U)
        return {{}, RdpActivePduError::InvalidCapabilitySet};
    std::size_t position = 0;
    for (std::size_t index = 0; index < count; ++index)
    {
        const std::size_t remaining = capabilities.size() - position;
        if (remaining < 4U)
            return {{}, RdpActivePduError::InvalidCapabilitySet};
        const std::size_t length = le16(capabilities, position + 2U);
        if (length < 4U || length > remaining)
            return {{}, RdpActivePduError::InvalidCapabilitySet};
        position += length;
    }
    if (position != capabilities.size())
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

} // namespace rdp_server::server::transport
