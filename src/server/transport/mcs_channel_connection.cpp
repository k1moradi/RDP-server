// SPDX-License-Identifier: GPL-3.0-or-later
#include "mcs_channel_connection.h"
#include "mcs_connect_initial.h"
#include "gcc_conference_create.h"
#include "rdp/gfx_avc420_capabilities.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <cstdint>
#include <span>
#include <utility>

namespace rdp_server::server::transport
{
namespace
{
// The sole R3 process-wide clipboard route-generation allocator. Native
// session replacements must never reuse an old static channel tuple, even
// if its MCS channel ID is assigned again by a later connection.
std::atomic<std::uint64_t> nextClipboardRouteGeneration{1U};

// Process-local reconnect correlation only. This value is never accepted as
// R2 authority, a native-session generation or a protocol generation.
std::atomic<std::uint64_t>
    nextFirstClientAcceptanceReconnectGeneration{1U};

[[nodiscard]] std::optional<std::uint64_t>
allocateClipboardRouteGeneration() noexcept
{
    auto generation =
        nextClipboardRouteGeneration.load(std::memory_order_relaxed);
    while (generation != 0U &&
           generation != std::numeric_limits<std::uint64_t>::max())
    {
        if (nextClipboardRouteGeneration.compare_exchange_weak(
                generation, generation + 1U,
                std::memory_order_relaxed, std::memory_order_relaxed))
            return generation;
    }
    return std::nullopt;
}

[[nodiscard]] std::uint64_t
allocateFirstClientAcceptanceReconnectGeneration() noexcept
{
    auto generation =
        nextFirstClientAcceptanceReconnectGeneration.load(
            std::memory_order_relaxed);
    while (generation != 0U)
    {
        const auto next =
            generation == std::numeric_limits<std::uint64_t>::max()
                ? 0U
                : generation + 1U;
        if (nextFirstClientAcceptanceReconnectGeneration.compare_exchange_weak(
                generation, next,
                std::memory_order_relaxed, std::memory_order_relaxed))
            return generation;
    }
    return 0U;
}

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

[[nodiscard]] std::uint32_t readLe32At(
    std::span<const std::uint8_t> bytes,
    std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

void writeLe32At(
    std::span<std::uint8_t> bytes,
    std::size_t offset,
    std::uint32_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
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

struct VirtualChannelCapabilityInfo
{
    bool valid{true};
    bool chunkFieldPresent{};
    std::size_t serverToClientChunkBytes{
        kRdpStaticVirtualChannelDefaultChunkBytes};
};

[[nodiscard]] VirtualChannelCapabilityInfo virtualChannelCapabilityInfo(
    std::span<const std::uint8_t> capabilities,
    std::uint16_t count) noexcept
{
    constexpr std::uint16_t kVirtualChannelCapabilityType = 0x0014U;
    VirtualChannelCapabilityInfo result{};
    bool seen = false;
    std::size_t position = 0U;
    for (std::size_t index = 0U; index < count; ++index)
    {
        if (position > capabilities.size() ||
            capabilities.size() - position < 4U)
            return {false, false, kRdpStaticVirtualChannelDefaultChunkBytes};
        const std::size_t length =
            readLe16At(capabilities, position + 2U);
        if (length < 4U ||
            length > capabilities.size() - position)
            return {false, false, kRdpStaticVirtualChannelDefaultChunkBytes};

        if (readLe16At(capabilities, position) ==
            kVirtualChannelCapabilityType)
        {
            if (seen || (length != 8U && length != 12U))
                return {false, false, kRdpStaticVirtualChannelDefaultChunkBytes};
            seen = true;
            if (length == 12U)
            {
                const std::size_t chunkBytes =
                    readLe32At(capabilities, position + 8U);
                if (chunkBytes <
                        kRdpStaticVirtualChannelDefaultChunkBytes ||
                    chunkBytes >
                        kRdpStaticVirtualChannelMaximumChunkBytes)
                    return {false, false, kRdpStaticVirtualChannelDefaultChunkBytes};
                result.chunkFieldPresent = true;
                result.serverToClientChunkBytes = chunkBytes;
            }
        }
        position += length;
    }
    if (position != capabilities.size())
        return {false, false, kRdpStaticVirtualChannelDefaultChunkBytes};
    return result;
}

inline constexpr std::uint16_t kRdpInputFlagScancodes = 0x0001U;
inline constexpr std::uint16_t kRdpInputFlagMouseX = 0x0004U;
inline constexpr std::uint16_t kRdpInputFlagUnicode = 0x0010U;
inline constexpr std::uint16_t kRdpInputFlagMouseRelative = 0x0080U;
inline constexpr std::uint16_t kRdpInputFlagMouseHorizontalWheel = 0x0100U;
inline constexpr std::uint16_t kRdpPointerFlagHorizontalWheel = 0x0400U;

struct InputCapabilityInfo
{
    bool valid{true};
    bool present{};
    std::uint16_t flags{};
};

[[nodiscard]] InputCapabilityInfo inputCapabilityInfo(
    std::span<const std::uint8_t> capabilities,
    std::uint16_t count) noexcept
{
    constexpr std::uint16_t kInputCapabilityType = 0x000dU;
    InputCapabilityInfo result{};
    std::size_t position = 0U;
    for (std::size_t index = 0U; index < count; ++index)
    {
        if (position > capabilities.size() ||
            capabilities.size() - position < 4U)
            return {false, false, 0U};
        const std::size_t length =
            readLe16At(capabilities, position + 2U);
        if (length < 4U || length > capabilities.size() - position)
            return {false, false, 0U};

        if (readLe16At(capabilities, position) == kInputCapabilityType)
        {
            if (result.present || length != 88U)
                return {false, false, 0U};
            result.present = true;
            result.flags = readLe16At(capabilities, position + 4U);
            // MS-RDPBCGR 2.2.7.1.6 requires SCANCODES at minimum.
            if ((result.flags & kRdpInputFlagScancodes) == 0U)
                return {false, false, 0U};
        }
        position += length;
    }
    if (position != capabilities.size())
        return {false, false, 0U};
    return result;
}

[[nodiscard]] bool slowPathInputAllowed(
    const RdpSlowPathInputPdu &input,
    std::uint16_t negotiatedFlags) noexcept
{
    if ((negotiatedFlags & kRdpInputFlagScancodes) == 0U)
        return false;

    RdpSlowPathInputEvent event{};
    for (std::size_t index = 0U; index < input.eventCount; ++index)
    {
        if (!input.eventAt(index, event))
            return false;
        switch (event.kind)
        {
        case RdpSlowPathInputEventKind::Synchronize:
        case RdpSlowPathInputEventKind::Unused:
            break;
        case RdpSlowPathInputEventKind::ScancodeKeyboard:
            if ((negotiatedFlags & kRdpInputFlagScancodes) == 0U)
                return false;
            break;
        case RdpSlowPathInputEventKind::UnicodeKeyboard:
            if ((negotiatedFlags & kRdpInputFlagUnicode) == 0U)
                return false;
            break;
        case RdpSlowPathInputEventKind::Mouse:
            if ((event.pointerFlags & kRdpPointerFlagHorizontalWheel) != 0U &&
                (negotiatedFlags & kRdpInputFlagMouseHorizontalWheel) == 0U)
                return false;
            break;
        case RdpSlowPathInputEventKind::ExtendedMouse:
            if ((negotiatedFlags & kRdpInputFlagMouseX) == 0U)
                return false;
            break;
        case RdpSlowPathInputEventKind::RelativeMouse:
            if ((negotiatedFlags & kRdpInputFlagMouseRelative) == 0U)
                return false;
            break;
        }
    }
    return true;
}

[[nodiscard]] std::size_t dynamicChannelIdBytes(
    std::uint32_t channelId) noexcept
{
    return channelId > 0xffffU ? 4U :
           (channelId > 0xffU ? 2U : 1U);
}

[[nodiscard]] std::uint8_t dynamicChannelIdCode(
    std::size_t channelIdBytes) noexcept
{
    return channelIdBytes == 4U ? 2U :
           (channelIdBytes == 2U ? 1U : 0U);
}

[[nodiscard]] std::size_t dynamicLengthBytes(
    std::size_t length) noexcept
{
    return length > 0xffffU ? 4U :
           (length > 0xffU ? 2U : 1U);
}

[[nodiscard]] std::uint8_t dynamicLengthCode(
    std::size_t lengthBytes) noexcept
{
    return lengthBytes == 4U ? 2U :
           (lengthBytes == 2U ? 1U : 0U);
}

void writeDynamicLittleEndian(
    std::span<std::uint8_t> output,
    std::size_t offset,
    std::uint32_t value,
    std::size_t bytes) noexcept
{
    for (std::size_t index = 0U; index < bytes; ++index)
        output[offset + index] = static_cast<std::uint8_t>(
            value >> (index * 8U));
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
std::optional<std::uint16_t> resolveMcsStaticChannelRole(
    const GccClientSettings &settings,
    const McsConnectResponseAllocation &allocation,
    McsStaticChannelRole role) noexcept
{
    // NUL-padded CHANNEL_DEF names must match all eight bytes. Never
    // grant CLIPRDR from a prefix, malformed string or copied channel ID.
    std::array<char, 8> expected{};
    switch (role)
    {
    case McsStaticChannelRole::Clipboard:
        expected = {'c', 'l', 'i', 'p', 'r', 'd', 'r', 0};
        break;
    case McsStaticChannelRole::DeviceRedirection:
        expected = {'r', 'd', 'p', 'd', 'r', 0, 0, 0};
        break;
    case McsStaticChannelRole::Sound:
        expected = {'r', 'd', 'p', 's', 'n', 'd', 0, 0};
        break;
    case McsStaticChannelRole::DynamicVirtualChannels:
        expected = {'d', 'r', 'd', 'y', 'n', 'v', 'c', 0};
        break;
    default:
        return std::nullopt;
    }

    if (!settings.hasNetworkData || !allocation ||
        settings.channelCount > settings.channels.size() ||
        allocation.staticChannelCount != settings.channelCount ||
        allocation.gccNodeId < 1001U || allocation.gccNodeId > 65536U ||
        allocation.ioChannelId == 0U ||
        allocation.ioChannelId == allocation.gccNodeId)
        return std::nullopt;

    std::optional<std::uint16_t> found;
    const auto ids = allocation.staticChannels();
    for (std::size_t index = 0; index < ids.size(); ++index)
    {
        if (ids[index] == 0U || ids[index] == allocation.ioChannelId ||
            ids[index] == allocation.gccNodeId)
            return std::nullopt;
        for (std::size_t earlier = 0; earlier < index; ++earlier)
        {
            if (ids[index] == ids[earlier])
                return std::nullopt;
        }
        if (settings.channels[index].name == expected)
        {
            // A duplicated negotiated role is ambiguous, not a first-win.
            if (found)
                return std::nullopt;
            found = ids[index];
        }
    }
    return found;
}

RdpClientInfoEnvelopeParseResult parseEnhancedSecurityClientInfoEnvelope(
    std::span<const std::uint8_t> mcsUserData) noexcept
{
    constexpr std::size_t kBasicSecurityHeaderBytes = 4U;
    constexpr std::size_t kInfoPacketFixedBytes = 18U;
    constexpr std::uint16_t kSecInfoPkt = 0x0040U;
    constexpr std::uint16_t kSecResetSeqNo = 0x0010U;
    constexpr std::uint16_t kSecIgnoreSeqNo = 0x0020U;
    constexpr std::uint16_t kSecFlagsHiValid = 0x8000U;
    constexpr std::uint16_t kAllowed =
        kSecInfoPkt | kSecResetSeqNo | kSecIgnoreSeqNo | kSecFlagsHiValid;

    if (mcsUserData.size() < kBasicSecurityHeaderBytes)
        return {{}, RdpClientInfoEnvelopeError::TruncatedSecurityHeader};

    const std::uint16_t flags =
        static_cast<std::uint16_t>(mcsUserData[0]) |
        (static_cast<std::uint16_t>(mcsUserData[1]) << 8U);
    const std::uint16_t flagsHi =
        static_cast<std::uint16_t>(mcsUserData[2]) |
        (static_cast<std::uint16_t>(mcsUserData[3]) << 8U);

    // PROTOCOL_HYBRID already protects the outer RDP PDU through R1 TLS.
    // Client Info must still identify itself using SEC_INFO_PKT, while
    // Standard-Security encryption and every competing packet-kind flag
    // are rejected here rather than ambiguously reinterpreting the payload.
    if ((flags & kSecInfoPkt) == 0U ||
        (flags & static_cast<std::uint16_t>(~kAllowed)) != 0U)
        return {{}, RdpClientInfoEnvelopeError::InvalidSecurityFlags};

    const auto info = mcsUserData.subspan(kBasicSecurityHeaderBytes);
    if (info.size() < kInfoPacketFixedBytes)
        return {{}, RdpClientInfoEnvelopeError::TruncatedInfoPacket};

    return {{flags, flagsHi, info}, RdpClientInfoEnvelopeError::None};
}

RdpLicensingEnvelopeParseResult parseEnhancedSecurityLicensingEnvelope(
    std::span<const std::uint8_t> mcsUserData) noexcept
{
    constexpr std::size_t kBasicSecurityHeaderBytes = 4U;
    constexpr std::size_t kLicensePreambleBytes = 4U;
    constexpr std::uint16_t kSecLicensePkt = 0x0080U;
    constexpr std::uint16_t kSecResetSeqNo = 0x0010U;
    constexpr std::uint16_t kSecIgnoreSeqNo = 0x0020U;
    constexpr std::uint16_t kSecFlagsHiValid = 0x8000U;
    constexpr std::uint16_t kAllowed =
        kSecLicensePkt | kSecResetSeqNo | kSecIgnoreSeqNo | kSecFlagsHiValid;

    if (mcsUserData.size() < kBasicSecurityHeaderBytes)
        return {{}, RdpLicensingEnvelopeError::TruncatedSecurityHeader};

    const std::uint16_t flags =
        static_cast<std::uint16_t>(mcsUserData[0]) |
        (static_cast<std::uint16_t>(mcsUserData[1]) << 8U);
    const std::uint16_t flagsHi =
        static_cast<std::uint16_t>(mcsUserData[2]) |
        (static_cast<std::uint16_t>(mcsUserData[3]) << 8U);

    // PROTOCOL_HYBRID already provides encryption/authentication through R1
    // TLS. SEC_ENCRYPT/SEC_EXCHANGE_PKT/SEC_INFO_PKT and every other packet
    // kind would describe a different security/connection-sequence path.
    if ((flags & kSecLicensePkt) == 0U ||
        (flags & static_cast<std::uint16_t>(~kAllowed)) != 0U)
        return {{}, RdpLicensingEnvelopeError::InvalidSecurityFlags};

    const auto licensingMessage =
        mcsUserData.subspan(kBasicSecurityHeaderBytes);
    if (licensingMessage.size() < kLicensePreambleBytes)
        return {{}, RdpLicensingEnvelopeError::TruncatedLicensingMessage};

    return {{flags, flagsHi, licensingMessage},
            RdpLicensingEnvelopeError::None};
}

RdpClientInfoPacketParseResult parseRdpClientInfoPacket(
    std::span<const std::uint8_t> infoPacket) noexcept
{
    constexpr std::size_t kFixedBytes = 18U;
    constexpr std::uint32_t kInfoUnicode = 0x00000010U;
    constexpr std::size_t kMaxStringBytes = 512U;
    constexpr std::size_t kTimeZoneBytes = 172U;
    constexpr std::size_t kMaxAddressBytes = 80U;
    constexpr std::size_t kMaxDynamicTimeZoneKeyBytes = 254U;

    const auto read16 = [](std::span<const std::uint8_t> bytes,
                           std::size_t offset) noexcept -> std::uint16_t
    {
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[offset]) |
            (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
    };
    const auto read32 = [&read16](std::span<const std::uint8_t> bytes,
                                  std::size_t offset) noexcept -> std::uint32_t
    {
        return static_cast<std::uint32_t>(read16(bytes, offset)) |
               (static_cast<std::uint32_t>(read16(bytes, offset + 2U)) << 16U);
    };

    if (infoPacket.size() < kFixedBytes)
        return {{}, RdpClientInfoPacketError::TruncatedFixedFields};

    RdpClientInfoPacketSummary summary{};
    summary.codePage = read32(infoPacket, 0U);
    summary.flags = read32(infoPacket, 4U);
    summary.unicode = (summary.flags & kInfoUnicode) != 0U;
    summary.domainBytes = read16(infoPacket, 8U);
    summary.userNameBytes = read16(infoPacket, 10U);
    summary.passwordBytes = read16(infoPacket, 12U);
    summary.alternateShellBytes = read16(infoPacket, 14U);
    summary.workingDirBytes = read16(infoPacket, 16U);

    const std::size_t terminator = summary.unicode ? 2U : 1U;
    const std::array<std::uint16_t, 5> lengths{
        summary.domainBytes,
        summary.userNameBytes,
        summary.passwordBytes,
        summary.alternateShellBytes,
        summary.workingDirBytes};

    std::size_t offset = kFixedBytes;
    for (const std::uint16_t rawLength : lengths)
    {
        const std::size_t length = rawLength;
        if ((summary.unicode && (length & 1U) != 0U) ||
            length > kMaxStringBytes - terminator)
            return {{}, RdpClientInfoPacketError::InvalidStringLength};
        if (offset > infoPacket.size() ||
            length + terminator > infoPacket.size() - offset)
            return {{}, RdpClientInfoPacketError::InvalidStringLength};

        const std::size_t nullOffset = offset + length;
        if (infoPacket[nullOffset] != 0U ||
            (summary.unicode && infoPacket[nullOffset + 1U] != 0U))
            return {{}, RdpClientInfoPacketError::MissingStringTerminator};
        offset = nullOffset + terminator;
    }

    if (offset == infoPacket.size())
        return {summary, RdpClientInfoPacketError::None};

    summary.hasExtendedInfo = true;
    auto remaining = [&]() noexcept -> std::size_t
    {
        return offset <= infoPacket.size() ? infoPacket.size() - offset : 0U;
    };
    auto consumeTerminated = [&](std::size_t length,
                                 std::size_t maximum) noexcept -> bool
    {
        if (length < terminator || length > maximum ||
            (summary.unicode && (length & 1U) != 0U) ||
            length > remaining())
            return false;
        const std::size_t nullOffset = offset + length - terminator;
        if (infoPacket[nullOffset] != 0U ||
            (summary.unicode && infoPacket[nullOffset + 1U] != 0U))
            return false;
        offset += length;
        return true;
    };

    // TS_EXTENDED_INFO_PACKET mandatory prefix.
    if (remaining() < 4U)
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};
    const std::uint16_t addressFamily = read16(infoPacket, offset);
    offset += 2U;
    const std::size_t addressBytes = read16(infoPacket, offset);
    offset += 2U;
    if (addressFamily != 0x0002U && addressFamily != 0x0017U)
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};
    if (!consumeTerminated(addressBytes, kMaxAddressBytes))
        return {{}, RdpClientInfoPacketError::InvalidExtendedTerminator};

    if (remaining() < 2U)
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};
    const std::size_t clientDirBytes = read16(infoPacket, offset);
    offset += 2U;
    if (!consumeTerminated(clientDirBytes, kMaxStringBytes))
        return {{}, RdpClientInfoPacketError::InvalidExtendedTerminator};

    // Optional fields form a strict suffix chain. An exact stop after any
    // complete optional group is valid; a partial field or a later field
    // without its predecessor is not.
    if (remaining() == 0U)
        return {summary, RdpClientInfoPacketError::None};
    if (remaining() < kTimeZoneBytes)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    offset += kTimeZoneBytes;

    if (remaining() == 0U)
        return {summary, RdpClientInfoPacketError::None};
    if (remaining() < 4U)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    offset += 4U; // clientSessionId

    if (remaining() == 0U)
        return {summary, RdpClientInfoPacketError::None};
    if (remaining() < 4U)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    offset += 4U; // performanceFlags

    if (remaining() == 0U)
        return {summary, RdpClientInfoPacketError::None};
    if (remaining() < 2U)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    const std::size_t autoReconnectBytes = read16(infoPacket, offset);
    offset += 2U;
    if (autoReconnectBytes != 0U && autoReconnectBytes != 28U)
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};
    if (autoReconnectBytes > remaining())
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    offset += autoReconnectBytes;

    if (remaining() == 0U)
        return {summary, RdpClientInfoPacketError::None};
    if (remaining() < 4U)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    offset += 2U; // reserved1 is ignored.
    if (read16(infoPacket, offset) != 0U)
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};
    offset += 2U; // reserved2 MUST be zero.

    if (remaining() == 0U)
        return {summary, RdpClientInfoPacketError::None};
    if (remaining() < 2U)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    const std::size_t dynamicKeyBytes = read16(infoPacket, offset);
    offset += 2U;
    if (dynamicKeyBytes > kMaxDynamicTimeZoneKeyBytes ||
        (dynamicKeyBytes & 1U) != 0U ||
        dynamicKeyBytes > remaining())
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};
    offset += dynamicKeyBytes;
    if (remaining() < 2U)
        return {{}, RdpClientInfoPacketError::InvalidOptionalOrdering};
    const std::uint16_t dynamicDisabled = read16(infoPacket, offset);
    offset += 2U;
    if (dynamicDisabled > 1U || remaining() != 0U)
        return {{}, RdpClientInfoPacketError::InvalidExtendedInfo};

    return {summary, RdpClientInfoPacketError::None};
}

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

bool McsAttachUserConfirmWriteGate::queue(std::uint32_t assignedUserId) noexcept
{
    if (closed_ || delivered_ || pending_ ||
        replySequence_ == std::numeric_limits<std::uint64_t>::max() ||
        writeSliceSequence_ == std::numeric_limits<std::uint64_t>::max())
    {
        close();
        return false;
    }
    const auto confirmation = encodeMcsAttachUserConfirm(assignedUserId);
    if (!confirmation || confirmation.length != 11U)
    {
        close();
        return false;
    }
    pending_ = confirmation;
    ++replySequence_;
    ++writeSliceSequence_;
    bytesWritten_ = 0;
    return true;
}

McsConnectResponseWriteView
McsAttachUserConfirmWriteGate::pendingWrite() const noexcept
{
    if (closed_ || delivered_ || !pending_)
        return {};
    const auto remaining = pending_.bytes().subspan(bytesWritten_);
    return remaining.empty() ? McsConnectResponseWriteView{} :
        McsConnectResponseWriteView{
            remaining, replySequence_, writeSliceSequence_};
}

McsConnectResponseWriteOutcome
McsAttachUserConfirmWriteGate::onBytesWritten(
    std::uint64_t replySequence, std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome = McsConnectResponseWriteOutcome;
    if (closed_ || delivered_ || !pending_ ||
        replySequence == 0U || replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pending_.length - bytesWritten_)
    {
        close();
        return Outcome::Rejected;
    }
    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pending_.length)
    {
        if (acceptedBytes != 0U)
        {
            if (writeSliceSequence_ ==
                std::numeric_limits<std::uint64_t>::max())
            {
                close();
                return Outcome::Rejected;
            }
            ++writeSliceSequence_;
        }
        return Outcome::Pending;
    }
    pending_ = {};
    bytesWritten_ = 0;
    delivered_ = true;
    return Outcome::Delivered;
}

void McsAttachUserConfirmWriteGate::close() noexcept
{
    pending_ = {};
    bytesWritten_ = 0;
    delivered_ = false;
    closed_ = true;
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

McsSessionIntake McsSessionLifecycle::onVerifiedR2ErectDomain(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == McsSessionPhase::Closed)
        return McsSessionIntake::Closed;
    if (phase_ != McsSessionPhase::AwaitErectDomain)
    {
        close();
        return McsSessionIntake::InvalidOrdering;
    }
    if (completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return McsSessionIntake::OversizedEnvelope;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed)
    {
        close();
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
    {
        close();
        return McsSessionIntake::PeerDisconnected;
    }
    if (parsed.request.kind != McsChannelRequestKind::ErectDomain)
    {
        close();
        return McsSessionIntake::InvalidOrdering;
    }

    // Both PER INTEGER fields are already known present and bounded. Microsoft
    // recommends zero client values, but server processing requires presence,
    // not a zero-value rejection.
    phase_ = McsSessionPhase::AwaitAttachUser;
    return McsSessionIntake::ErectDomainAccepted;
}

std::optional<std::uint32_t>
McsSessionLifecycle::allocateAttachUserId() const noexcept
{
    // Connect Response fixes GCC node 1001, leaves 1002 for the sole user,
    // and assigns I/O 1003 plus static channels starting at 1004. Check the
    // negotiated shared namespace and domain capacities before reserving it.
    constexpr std::uint32_t kAssignedUserId = 1002U;
    if (!connectResponseAllocation_ || allocatedUserId_ != 0U ||
        connectResponseDomain_.values[0] <
            connectResponseAllocation_.staticChannels().size() + 3U ||
        connectResponseDomain_.values[1] < 2U ||
        connectResponseAllocation_.gccNodeId == kAssignedUserId ||
        connectResponseAllocation_.ioChannelId == kAssignedUserId ||
        connectResponseAllocation_.ioChannelId ==
            connectResponseAllocation_.gccNodeId ||
        connectResponseAllocation_.gccNodeId < 1001U ||
        connectResponseAllocation_.gccNodeId > 65536U ||
        connectResponseAllocation_.ioChannelId == 0U)
        return std::nullopt;

    const auto channels = connectResponseAllocation_.staticChannels();
    for (std::size_t index = 0; index < channels.size(); ++index)
    {
        if (channels[index] == 0U ||
            channels[index] == connectResponseAllocation_.gccNodeId ||
            channels[index] == kAssignedUserId ||
            channels[index] == connectResponseAllocation_.ioChannelId)
            return std::nullopt;
        for (std::size_t previous = 0; previous < index; ++previous)
        {
            if (channels[index] == channels[previous])
                return std::nullopt;
        }
    }
    return kAssignedUserId;
}

McsSessionIntake McsSessionLifecycle::onVerifiedR2AttachUser(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == McsSessionPhase::Closed)
        return McsSessionIntake::Closed;
    if (phase_ != McsSessionPhase::AwaitAttachUser)
    {
        close();
        return McsSessionIntake::InvalidOrdering;
    }
    if (!connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return McsSessionIntake::AdmissionDenied;
    }
    if (completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return McsSessionIntake::OversizedEnvelope;
    }
    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed)
    {
        close();
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
    {
        close();
        return McsSessionIntake::PeerDisconnected;
    }
    if (parsed.request.kind != McsChannelRequestKind::AttachUser)
    {
        close();
        return McsSessionIntake::InvalidOrdering;
    }

    const auto assignedUserId = allocateAttachUserId();
    if (!assignedUserId || !attachConfirmWrite_.queue(*assignedUserId))
    {
        close();
        return McsSessionIntake::InvalidResourceAllocation;
    }
    allocatedUserId_ = *assignedUserId;
    phase_ = McsSessionPhase::AwaitAttachConfirm;
    return McsSessionIntake::AttachUserAccepted;
}

std::optional<McsConnectResponseWriteView>
McsSessionLifecycle::prepareAttachUserConfirmWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (phase_ != McsSessionPhase::AwaitAttachConfirm ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return std::nullopt;
    }
    const auto pending = attachConfirmWrite_.pendingWrite();
    if (!pending)
        close();
    return pending ? std::optional{pending} : std::nullopt;
}

McsConnectResponseWriteOutcome
McsSessionLifecycle::completeAttachUserConfirmWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence, std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome = McsConnectResponseWriteOutcome;
    if (phase_ != McsSessionPhase::AwaitAttachConfirm ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return Outcome::Rejected;
    }
    const auto result = attachConfirmWrite_.onBytesWritten(
        replySequence, writeSliceSequence, acceptedBytes);
    if (result == Outcome::Rejected)
    {
        close();
        return result;
    }
    if (result == Outcome::Delivered)
    {
        // Only a completely accepted confirmation makes these channel IDs
        // available for later protected joins. No join PDU is admitted here.
        std::array<std::uint16_t, kMaximumStaticChannelCount + 2U> channels{};
        constexpr std::size_t kFixedChannelCount = 2U;
        channels[0] = static_cast<std::uint16_t>(allocatedUserId_);
        channels[1] = connectResponseAllocation_.ioChannelId;
        const auto staticChannels = connectResponseAllocation_.staticChannels();
        std::copy(staticChannels.begin(), staticChannels.end(),
                  channels.begin() + kFixedChannelCount);
        if (!joins_.configure(
                allocatedUserId_,
                std::span(channels).first(
                    kFixedChannelCount + staticChannels.size())))
        {
            close();
            return Outcome::Rejected;
        }
        phase_ = McsSessionPhase::AwaitChannelJoin;
    }
    return result;
}

McsJoinStartOutcome McsSessionLifecycle::onVerifiedR2ChannelJoin(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ != McsSessionPhase::AwaitChannelJoin ||
        allocatedUserId_ == 0U ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return McsJoinStartOutcome::Rejected;
    }

    // Each request is one already-decrypted, exact TPKT from R1. The gate
    // copies only the allocated channel index; no borrowed packet survives.
    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed || parsed.request.kind != McsChannelRequestKind::ChannelJoin)
    {
        // A peer Disconnect is terminal, never a successful Join.
        close();
        return McsJoinStartOutcome::Rejected;
    }

    const auto outcome = joins_.beginJoin(parsed.request);
    if (outcome == McsJoinStartOutcome::Rejected)
        close();
    // AlreadyJoined/AlreadyPending are idempotent according to T.125.
    // Buffered permits a bounded batch, not an outbound scheduling owner.
    return outcome;
}

std::optional<McsConnectResponseWriteView>
McsSessionLifecycle::prepareChannelJoinConfirmWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (phase_ != McsSessionPhase::AwaitChannelJoin ||
        allocatedUserId_ == 0U ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return std::nullopt;
    }
    const auto suffix = joins_.pendingBytes();
    const auto replySequence = joins_.pendingReplySequence();
    const auto writeSliceSequence = joins_.pendingWriteSliceSequence();
    if (suffix.empty() || replySequence == 0U || writeSliceSequence == 0U)
    {
        close();
        return std::nullopt;
    }
    return McsConnectResponseWriteView{
        suffix, replySequence, writeSliceSequence};
}

McsJoinWriteOutcome McsSessionLifecycle::completeChannelJoinConfirmWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ != McsSessionPhase::AwaitChannelJoin ||
        allocatedUserId_ == 0U ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return McsJoinWriteOutcome::Rejected;
    }
    const auto outcome = joins_.onReplyBytesWritten(
        replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == McsJoinWriteOutcome::Rejected)
        close();
    else if (joins_.allConfiguredChannelsJoined())
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::McsEstablished);
    // Even an accepted full Join Confirm grants no licensing, Share Control
    // or application-channel dispatch without later protected transitions.
    return outcome;
}

std::optional<std::uint16_t>
McsSessionLifecycle::resolveVerifiedR2JoinedClipboardChannel(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if ((phase_ != McsSessionPhase::AwaitChannelJoin &&
         phase_ != McsSessionPhase::AwaitServerLicenseRequest) ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return std::nullopt;
    }

    const auto id = resolveMcsStaticChannelRole(
        connectResponseClientSettings_, connectResponseAllocation_,
        McsStaticChannelRole::Clipboard);
    // Both foundational joins and this static role's own confirmation
    // must have been fully accepted. No licensing/Share progression here.
    if (!id ||
        !joins_.channelJoinConfirmed(
            static_cast<std::uint16_t>(allocatedUserId_)) ||
        !joins_.channelJoinConfirmed(connectResponseAllocation_.ioChannelId) ||
        !joins_.channelJoinConfirmed(*id))
        return std::nullopt;
    return id;
}

std::optional<RdpClientInfoEnvelopeView>
McsSessionLifecycle::routeVerifiedR2ClientInfoEnvelope(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ != McsSessionPhase::AwaitChannelJoin ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return std::nullopt;
    }

    // Under Enhanced RDP Security the Client Info PDU follows completion
    // of all requested MCS joins when no Standard-Security Exchange PDU is
    // used. Do not route early I/O or static-channel data around that order.
    if (!joins_.allConfiguredChannelsJoined())
    {
        close();
        return std::nullopt;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        !joins_.matchesJoinedInboundSendData(parsed.request) ||
        parsed.request.channelId != connectResponseAllocation_.ioChannelId ||
        parsed.request.segmentation != 3U)
    {
        close();
        return std::nullopt;
    }

    const auto envelope =
        parseEnhancedSecurityClientInfoEnvelope(parsed.request.userData);
    if (!envelope)
    {
        close();
        return std::nullopt;
    }

    // Syntax-only route: no sequence state changes here.
    return envelope.value;
}

McsSessionLifecycle::McsSessionLifecycle() noexcept
    : firstClientAcceptanceReconnectGeneration_(
          allocateFirstClientAcceptanceReconnectGeneration())
{
}

void McsSessionLifecycle::recordFirstClientAcceptanceEvent(
    RdpFirstClientAcceptanceEventKind kind) noexcept
{
    using Kind = RdpFirstClientAcceptanceEventKind;
    switch (kind)
    {
    case Kind::McsEstablished:
        if (firstClientAcceptanceMcsEstablished_)
            return;
        firstClientAcceptanceMcsEstablished_ = true;
        break;
    case Kind::ShareActivated:
        if (firstClientAcceptanceShareActivated_)
            return;
        firstClientAcceptanceShareActivated_ = true;
        break;
    case Kind::GraphicsDynamicVirtualChannelActivated:
        if (firstClientAcceptanceGraphicsDynamicVirtualChannelActivated_)
            return;
        firstClientAcceptanceGraphicsDynamicVirtualChannelActivated_ = true;
        break;
    case Kind::GraphicsControlReady:
        if (firstClientAcceptanceGraphicsControlReady_)
            return;
        firstClientAcceptanceGraphicsControlReady_ = true;
        break;
    case Kind::SurfaceCreated:
        firstClientAcceptanceSurfaceCreated_ = true;
        break;
    case Kind::SurfaceMapped:
        firstClientAcceptanceSurfaceMapped_ = true;
        break;
    case Kind::FirstFramePublicationAccepted:
        if (firstClientAcceptanceFramePublicationAccepted_)
            return;
        firstClientAcceptanceFramePublicationAccepted_ = true;
        break;
    case Kind::FirstFrameAcknowledge:
        if (firstClientAcceptanceFrameAcknowledge_)
            return;
        firstClientAcceptanceFrameAcknowledge_ = true;
        break;
    case Kind::ResizeRemapStarted:
    case Kind::ResizeRemapCompleted:
    case Kind::ResizeRemapRejected:
        break;
    case Kind::None:
        return;
    }

    if (firstClientAcceptanceEventSequence_ ==
        std::numeric_limits<std::uint64_t>::max())
    {
        if (firstClientAcceptanceDroppedEventCount_ !=
            std::numeric_limits<std::uint64_t>::max())
            ++firstClientAcceptanceDroppedEventCount_;
        return;
    }

    const RdpFirstClientAcceptanceEvent event{
        kind, ++firstClientAcceptanceEventSequence_};
    if (firstClientAcceptanceEventCount_ <
        kMaximumRdpFirstClientAcceptanceEvents)
    {
        const std::size_t index =
            (firstClientAcceptanceEventStart_ +
             firstClientAcceptanceEventCount_) %
            kMaximumRdpFirstClientAcceptanceEvents;
        firstClientAcceptanceEvents_[index] = event;
        ++firstClientAcceptanceEventCount_;
        return;
    }

    firstClientAcceptanceEvents_[firstClientAcceptanceEventStart_] = event;
    firstClientAcceptanceEventStart_ =
        (firstClientAcceptanceEventStart_ + 1U) %
        kMaximumRdpFirstClientAcceptanceEvents;
    if (firstClientAcceptanceDroppedEventCount_ !=
        std::numeric_limits<std::uint64_t>::max())
        ++firstClientAcceptanceDroppedEventCount_;
}

RdpFirstClientAcceptanceObservability
McsSessionLifecycle::firstClientAcceptanceObservability() const noexcept
{
    RdpFirstClientAcceptanceObservability result{};
    result.reconnectGeneration = firstClientAcceptanceReconnectGeneration_;
    result.latestEventSequence = firstClientAcceptanceEventSequence_;
    result.droppedEventCount = firstClientAcceptanceDroppedEventCount_;
    result.eventCount = firstClientAcceptanceEventCount_;
    result.mcsEstablished = firstClientAcceptanceMcsEstablished_;
    result.shareActivated = firstClientAcceptanceShareActivated_;
    result.graphicsDynamicVirtualChannelActivated =
        firstClientAcceptanceGraphicsDynamicVirtualChannelActivated_;
    result.graphicsControlReady = firstClientAcceptanceGraphicsControlReady_;
    result.surfaceCreated = firstClientAcceptanceSurfaceCreated_;
    result.surfaceMapped = firstClientAcceptanceSurfaceMapped_;

    const auto r4Status =
        graphicsDynamicVirtualChannel_.presentationLifecycle_.
            acceptanceStatus();
    // The event latches remain only for bounded event-ring de-duplication.
    // Public frame-delivery/ACK truth comes from the one R4 lifecycle owner.
    result.firstFramePublicationAccepted =
        r4Status.firstExactFrameWriteCommitted;
    result.firstFrameAcknowledge =
        r4Status.firstGenuineFrameAcknowledge;
    result.firstClearCodecFramePrepared =
        r4Status.firstClearCodecFramePrepared;
    result.firstExactFrameWriteCommitted =
        r4Status.firstExactFrameWriteCommitted;
    result.outstandingFrameAcknowledgements =
        r4Status.outstandingFrameAcknowledgements;
    result.firstGenuineFrameAcknowledge =
        r4Status.firstGenuineFrameAcknowledge;
    result.resizeRemapInProgress =
        graphicsDynamicVirtualChannel_.replacementSurfaceId_ != 0U;

    for (std::size_t index = 0U;
         index < firstClientAcceptanceEventCount_; ++index)
    {
        result.events[index] =
            firstClientAcceptanceEvents_[
                (firstClientAcceptanceEventStart_ + index) %
                kMaximumRdpFirstClientAcceptanceEvents];
    }
    return result;
}

McsSessionLifecycle::~McsSessionLifecycle()
{
    cleanseRdpLicensingKeyMaterial(licensingKeyMaterial_);
    licensingKeyMaterialReady_ = false;
}

std::optional<RdpClientInfoPacketSummary>
McsSessionLifecycle::acceptVerifiedR2ClientInfoPacket(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    const auto envelope =
        routeVerifiedR2ClientInfoEnvelope(provenance, completeTpkt);
    if (!envelope)
        return std::nullopt;

    const auto info = parseRdpClientInfoPacket(envelope->infoPacket);
    if (!info)
    {
        close();
        return std::nullopt;
    }

    // Consuming Client Info is the first state change after Join. The next
    // legal positive action is an R3-owned Server License Request writer;
    // the existing licensing lifecycle remains NotStarted until that future
    // writer reports complete accepted-byte progress.
    phase_ = McsSessionPhase::AwaitServerLicenseRequest;
    return info.value;
}

bool McsSessionLifecycle::selectVerifiedR2PersonalDesktopLicensingMode() noexcept
{
    if (phase_ != McsSessionPhase::AwaitServerLicenseRequest ||
        admissionGeneration_ == 0U || sessionGeneration_ == 0U ||
        personalDesktopPolicySelected_ ||
        licensing_.phase() != RdpLicensingPhase::NotStarted ||
        !licensing_.selectPersonalDesktopProtocolMode())
    {
        close();
        return false;
    }
    personalDesktopPolicySelected_ = true;
    return true;
}

std::optional<RdpServerLicenseRequestWriteView>
McsSessionLifecycle::prepareServerLicenseRequestWrite(
    const SecurityNegotiationProvenance &provenance,
    const RdpServerLicenseIdentity &identity,
    const RdpLicensingServiceCredential &credential) noexcept
{
    const auto credentialFingerprint = credential.certificateFingerprint();
    if (phase_ != McsSessionPhase::AwaitServerLicenseRequest ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        licensing_.phase() != RdpLicensingPhase::NotStarted ||
        !credential.matches(identity) ||
        credentialFingerprint.size() !=
            licensingCredentialFingerprint_.size())
    {
        close();
        return std::nullopt;
    }

    if (existingCalAuthorityRequest_.productIdentityBound())
    {
        if (!existingCalAuthorityRequest_.matchesProductIdentity(identity))
        {
            close();
            return std::nullopt;
        }
    }
    else if (existingCalAuthorityRequest_.bindProductIdentity(identity) !=
             RdpExistingClientCalAuthorityRequestError::None)
    {
        close();
        return std::nullopt;
    }

    if (licensingCredentialBound_)
    {
        if (!std::equal(
                credentialFingerprint.begin(),
                credentialFingerprint.end(),
                licensingCredentialFingerprint_.begin()))
        {
            close();
            return std::nullopt;
        }
    }
    else
    {
        std::copy(
            credentialFingerprint.begin(), credentialFingerprint.end(),
            licensingCredentialFingerprint_.begin());
        licensingCredentialBound_ = true;
    }

    auto pending = serverLicenseRequestWrite_.pendingWrite();
    if (!pending)
    {
        if (!serverLicenseRequestWrite_.queue(identity))
        {
            close();
            return std::nullopt;
        }
        pending = serverLicenseRequestWrite_.pendingWrite();
    }
    if (!pending)
    {
        close();
        return std::nullopt;
    }
    return pending;
}

RdpServerLicenseRequestWriteOutcome
McsSessionLifecycle::completeServerLicenseRequestWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ != McsSessionPhase::AwaitServerLicenseRequest ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_)
    {
        close();
        return RdpServerLicenseRequestWriteOutcome::Rejected;
    }

    const auto outcome = serverLicenseRequestWrite_.onBytesWritten(
        replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == RdpServerLicenseRequestWriteOutcome::Rejected)
    {
        close();
        return outcome;
    }
    if (outcome == RdpServerLicenseRequestWriteOutcome::Delivered)
    {
        if (licensing_.phase() != RdpLicensingPhase::AwaitClientLicenseResponse)
        {
            close();
            return RdpServerLicenseRequestWriteOutcome::Rejected;
        }
        phase_ = McsSessionPhase::AwaitClientLicenseResponse;
    }
    return outcome;
}

std::optional<RdpLicensingIntake>
McsSessionLifecycle::acceptVerifiedR2ClientLicensingMessage(
    const SecurityNegotiationProvenance &provenance,
    const RdpLicensingServiceCredential &credential,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    const auto credentialFingerprint = credential.certificateFingerprint();
    if (phase_ != McsSessionPhase::AwaitClientLicenseResponse ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() != RdpLicensingPhase::AwaitClientLicenseResponse ||
        !licensingCredentialBound_ ||
        !existingCalAuthorityRequest_.productIdentityBound() ||
        credentialFingerprint.size() !=
            licensingCredentialFingerprint_.size() ||
        !std::equal(
            credentialFingerprint.begin(), credentialFingerprint.end(),
            licensingCredentialFingerprint_.begin()) ||
        completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return std::nullopt;
    }

    if (!joins_.allConfiguredChannelsJoined())
    {
        close();
        return std::nullopt;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        !joins_.matchesJoinedInboundSendData(parsed.request) ||
        parsed.request.channelId != connectResponseAllocation_.ioChannelId ||
        parsed.request.segmentation != 3U)
    {
        close();
        return std::nullopt;
    }

    const auto envelope =
        parseEnhancedSecurityLicensingEnvelope(parsed.request.userData);
    if (!envelope)
    {
        close();
        return std::nullopt;
    }

    if (personalDesktopPolicySelected_)
    {
        if (licensing_.protocolMode() !=
                RdpLicensingProtocolMode::PersonalDesktop ||
            licensingKeyMaterialReady_)
        {
            close();
            return std::nullopt;
        }

        // Personal-terminal-server semantics intentionally stop after
        // structural validation. A presented CAL is not signature/HWID
        // validated and no CAL owner/provider request is created.
        const auto intake =
            licensing_.onClientMessage(envelope.value.licensingMessage);
        if ((intake != RdpLicensingIntake::ClientLicenseInfoAccepted &&
             intake != RdpLicensingIntake::ClientNewLicenseRequestAccepted) ||
            licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
            licensing_.decisionBranch() !=
                RdpLicensingDecisionBranch::
                    PersonalDesktopCompletionRequired)
        {
            close();
            return std::nullopt;
        }

        acceptedInitialLicensingIntake_ = intake;
        phase_ = McsSessionPhase::AwaitPersonalDesktopValidClientWrite;
        return intake;
    }

    if (licensing_.protocolMode() !=
            RdpLicensingProtocolMode::AppServerAuthority ||
        licensingKeyMaterialReady_)
    {
        close();
        return std::nullopt;
    }

    auto prepared = prepareInitialRdpLicensingCrypto(
        credential, envelope.value.licensingMessage,
        licensing_.serverRandom());
    if (!prepared)
    {
        close();
        return std::nullopt;
    }

    std::optional<RdpClientLicenseInfoHardwareIdProof> hardwareIdProof;
    std::span<const std::uint8_t> existingCal;
    if (prepared.messageType == RdpLicensingMessageType::ClientLicenseInfo)
    {
        const auto info =
            parseRdpClientLicenseInfo(envelope.value.licensingMessage);
        if (!info || info.value.licenseInfo.empty() ||
            info.value.licenseInfo.size() > kMaximumRdpClientCalBytes)
        {
            cleanseRdpLicensingKeyMaterial(prepared.value);
            close();
            return std::nullopt;
        }

        auto verifiedHardwareId =
            verifyAndRetainRdpClientLicenseInfoHardwareId(
                envelope.value.licensingMessage, prepared.value);
        if (!verifiedHardwareId)
        {
            cleanseRdpLicensingKeyMaterial(prepared.value);
            close();
            return std::nullopt;
        }
        hardwareIdProof.emplace(std::move(verifiedHardwareId.proof));
        existingCal = info.value.licenseInfo;
    }

    licensingKeyMaterial_ = prepared.value;
    cleanseRdpLicensingKeyMaterial(prepared.value);
    licensingKeyMaterialReady_ = true;

    const auto intake =
        licensing_.onClientMessage(envelope.value.licensingMessage);
    if (intake != RdpLicensingIntake::ClientLicenseInfoAccepted &&
        intake != RdpLicensingIntake::ClientNewLicenseRequestAccepted)
    {
        close();
        return std::nullopt;
    }
    if (licensing_.phase() != RdpLicensingPhase::AwaitServerDecision)
    {
        close();
        return std::nullopt;
    }

    if (intake == RdpLicensingIntake::ClientLicenseInfoAccepted)
    {
        if (!hardwareIdProof || existingCal.empty())
        {
            close();
            return std::nullopt;
        }

        const auto verificationUnixSeconds =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        if (verificationUnixSeconds <= 0 ||
            existingCalAuthorityRequest_.complete(
                std::move(*hardwareIdProof),
                existingCal,
                static_cast<std::int64_t>(verificationUnixSeconds),
                admissionGeneration_,
                sessionGeneration_) !=
                RdpExistingClientCalAuthorityRequestError::None)
        {
            close();
            return std::nullopt;
        }
    }

    acceptedInitialLicensingIntake_ = intake;
    phase_ = McsSessionPhase::AwaitServerLicenseDecision;
    return intake;
}

std::optional<RdpPersonalDesktopValidClientWriteView>
McsSessionLifecycle::preparePersonalDesktopValidClientWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (phase_ != McsSessionPhase::AwaitPersonalDesktopValidClientWrite ||
        !personalDesktopPolicySelected_ ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.protocolMode() !=
            RdpLicensingProtocolMode::PersonalDesktop ||
        licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_.decisionBranch() !=
            RdpLicensingDecisionBranch::
                PersonalDesktopCompletionRequired ||
        !acceptedInitialLicensingIntake_.has_value() ||
        !joins_.allConfiguredChannelsJoined())
    {
        close();
        return std::nullopt;
    }

    auto pending = personalDesktopValidClientWrite_.pendingWrite();
    if (!pending)
    {
        if (!personalDesktopValidClientWrite_.queue(
                connectResponseAllocation_.ioChannelId))
        {
            close();
            return std::nullopt;
        }
        pending = personalDesktopValidClientWrite_.pendingWrite();
    }
    if (!pending)
    {
        close();
        return std::nullopt;
    }
    return pending;
}

RdpPersonalDesktopValidClientWriteOutcome
McsSessionLifecycle::completePersonalDesktopValidClientWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ != McsSessionPhase::AwaitPersonalDesktopValidClientWrite ||
        !personalDesktopPolicySelected_ ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.protocolMode() !=
            RdpLicensingProtocolMode::PersonalDesktop ||
        licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_.decisionBranch() !=
            RdpLicensingDecisionBranch::
                PersonalDesktopCompletionRequired ||
        !joins_.allConfiguredChannelsJoined())
    {
        close();
        return RdpPersonalDesktopValidClientWriteOutcome::Rejected;
    }

    const auto outcome = personalDesktopValidClientWrite_.onBytesWritten(
        replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == RdpPersonalDesktopValidClientWriteOutcome::Rejected)
    {
        close();
        return outcome;
    }
    if (outcome == RdpPersonalDesktopValidClientWriteOutcome::Delivered)
    {
        if (licensing_.phase() != RdpLicensingPhase::Licensed)
        {
            close();
            return RdpPersonalDesktopValidClientWriteOutcome::Rejected;
        }
        existingCalAuthorityRequest_.retire();
        acceptedInitialLicensingIntake_.reset();
        cleanseRdpLicensingKeyMaterial(licensingKeyMaterial_);
        licensingKeyMaterialReady_ = false;
        phase_ = McsSessionPhase::AwaitDemandActive;
    }
    return outcome;
}

std::optional<RdpServerPlatformChallengeWriteView>
McsSessionLifecycle::prepareServerPlatformChallengeWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (phase_ != McsSessionPhase::AwaitServerLicenseDecision ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_.decisionBranch() !=
            RdpLicensingDecisionBranch::PlatformChallengeRequired ||
        !licensingKeyMaterialReady_ ||
        acceptedInitialLicensingIntake_ !=
            RdpLicensingIntake::ClientNewLicenseRequestAccepted)
    {
        close();
        return std::nullopt;
    }

    auto pending = serverPlatformChallengeWrite_.pendingWrite();
    if (!pending)
    {
        if (!serverPlatformChallengeWrite_.queue(licensingKeyMaterial_))
        {
            close();
            return std::nullopt;
        }
        pending = serverPlatformChallengeWrite_.pendingWrite();
    }
    if (!pending)
    {
        close();
        return std::nullopt;
    }
    return pending;
}

RdpServerPlatformChallengeWriteOutcome
McsSessionLifecycle::completeServerPlatformChallengeWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ != McsSessionPhase::AwaitServerLicenseDecision ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_.decisionBranch() !=
            RdpLicensingDecisionBranch::PlatformChallengeRequired ||
        !licensingKeyMaterialReady_ ||
        acceptedInitialLicensingIntake_ !=
            RdpLicensingIntake::ClientNewLicenseRequestAccepted)
    {
        close();
        return RdpServerPlatformChallengeWriteOutcome::Rejected;
    }

    const auto outcome = serverPlatformChallengeWrite_.onBytesWritten(
        replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == RdpServerPlatformChallengeWriteOutcome::Rejected)
    {
        close();
        return outcome;
    }
    if (outcome == RdpServerPlatformChallengeWriteOutcome::Delivered)
    {
        if (licensing_.phase() !=
                RdpLicensingPhase::AwaitClientPlatformChallengeResponse ||
            licensing_.decisionBranch() !=
                RdpLicensingDecisionBranch::AwaitPlatformChallengeResponse ||
            licensing_.platformChallenge().size() !=
                kRdpPlatformChallengePlaintextBytes)
        {
            close();
            return RdpServerPlatformChallengeWriteOutcome::Rejected;
        }
        phase_ = McsSessionPhase::AwaitClientPlatformChallengeResponse;
    }
    return outcome;
}

std::optional<RdpLicensingIntake>
McsSessionLifecycle::acceptVerifiedR2ClientPlatformChallengeResponse(
    const SecurityNegotiationProvenance &provenance,
    const RdpLicensingServiceCredential &credential,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    const auto credentialFingerprint = credential.certificateFingerprint();
    if (phase_ != McsSessionPhase::AwaitClientPlatformChallengeResponse ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() !=
            RdpLicensingPhase::AwaitClientPlatformChallengeResponse ||
        licensing_.decisionBranch() !=
            RdpLicensingDecisionBranch::AwaitPlatformChallengeResponse ||
        !licensingKeyMaterialReady_ ||
        !licensingCredentialBound_ ||
        credentialFingerprint.size() !=
            licensingCredentialFingerprint_.size() ||
        !std::equal(
            credentialFingerprint.begin(), credentialFingerprint.end(),
            licensingCredentialFingerprint_.begin()) ||
        completeTpkt.size() > kMaximumInitialMcsTpktBytes)
    {
        close();
        return std::nullopt;
    }

    if (!joins_.allConfiguredChannelsJoined())
    {
        close();
        return std::nullopt;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        !joins_.matchesJoinedInboundSendData(parsed.request) ||
        parsed.request.channelId != connectResponseAllocation_.ioChannelId ||
        parsed.request.segmentation != 3U)
    {
        close();
        return std::nullopt;
    }

    const auto envelope =
        parseEnhancedSecurityLicensingEnvelope(parsed.request.userData);
    if (!envelope)
    {
        close();
        return std::nullopt;
    }

    const auto intake = licensing_.onClientPlatformChallengeResponse(
        envelope.value.licensingMessage, licensingKeyMaterial_);
    if (intake !=
            RdpLicensingIntake::ClientPlatformChallengeResponseAccepted ||
        licensing_.phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_.decisionBranch() !=
            RdpLicensingDecisionBranch::NewLicenseIssuanceRequired)
    {
        close();
        return std::nullopt;
    }

    phase_ = McsSessionPhase::AwaitServerLicenseDecision;
    return intake;
}

std::optional<RdpDemandActiveProfileView>
McsSessionLifecycle::prepareVerifiedR2DemandActiveProfile(
    const SecurityNegotiationProvenance &provenance,
    RdpDemandActiveFeature features) noexcept
{
    if (phase_ != McsSessionPhase::AwaitDemandActive ||
        admissionGeneration_ == 0U || sessionGeneration_ == 0U ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        !personalDesktopPolicySelected_ ||
        licensing_.protocolMode() != RdpLicensingProtocolMode::PersonalDesktop ||
        licensing_.phase() != RdpLicensingPhase::Licensed ||
        !joins_.allConfiguredChannelsJoined())
    {
        close();
        return std::nullopt;
    }

    if (hasRdpDemandActiveFeature(
            features, RdpDemandActiveFeature::DynamicVirtualChannels))
    {
        const auto dynamicVirtualChannel = resolveMcsStaticChannelRole(
            connectResponseClientSettings_, connectResponseAllocation_,
            McsStaticChannelRole::DynamicVirtualChannels);
        if (!dynamicVirtualChannel ||
            !joins_.channelJoinConfirmed(*dynamicVirtualChannel))
        {
            close();
            return std::nullopt;
        }
    }

    const RdpDemandActiveProfilePolicy profilePolicy{
        connectResponseClientSettings_.requestedWidth,
        connectResponseClientSettings_.requestedHeight,
        RdpDemandActivePlatform::LinuxX11,
        features};
    const auto profile =
        demandActiveProfileProvider_.prepare(sessionGeneration_, profilePolicy);
    if (!profile)
    {
        close();
        return std::nullopt;
    }
    return profile;
}

std::optional<RdpShareActivationWriteView>
McsSessionLifecycle::beginVerifiedR2ShareActivation(
    const SecurityNegotiationProvenance &provenance,
    const RdpDemandActiveProfileView &profile) noexcept
{
    if (phase_ != McsSessionPhase::AwaitDemandActive ||
        admissionGeneration_ == 0U || sessionGeneration_ == 0U ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        !personalDesktopPolicySelected_ ||
        licensing_.protocolMode() != RdpLicensingProtocolMode::PersonalDesktop ||
        licensing_.phase() != RdpLicensingPhase::Licensed ||
        !joins_.allConfiguredChannelsJoined() ||
        profile.sessionGeneration() != sessionGeneration_ ||
        !demandActiveProfileProvider_.owns(profile) ||
        !shareActivation_.begin(
            allocatedUserId_, connectResponseAllocation_.ioChannelId,
            profile.shareId(), profile.sessionId(), profile.sourceDescriptor(),
            profile.capabilityCount(), profile.capabilitySets()))
    {
        close();
        return std::nullopt;
    }

    phase_ = McsSessionPhase::ShareActivation;
    const auto pending = shareActivation_.pendingServerWrite();
    if (!pending)
    {
        close();
        return std::nullopt;
    }
    return pending;
}

std::optional<RdpShareActivationWriteView>
McsSessionLifecycle::pendingVerifiedR2ShareActivationWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (phase_ != McsSessionPhase::ShareActivation ||
        admissionGeneration_ == 0U || sessionGeneration_ == 0U ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() != RdpLicensingPhase::Licensed ||
        !joins_.allConfiguredChannelsJoined())
    {
        close();
        return std::nullopt;
    }
    const auto pending = shareActivation_.pendingServerWrite();
    return pending ? std::optional<RdpShareActivationWriteView>{pending}
                   : std::nullopt;
}

RdpShareActivationWriteOutcome
McsSessionLifecycle::completeVerifiedR2ShareActivationWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ != McsSessionPhase::ShareActivation ||
        admissionGeneration_ == 0U || sessionGeneration_ == 0U ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() != RdpLicensingPhase::Licensed ||
        !joins_.allConfiguredChannelsJoined())
    {
        close();
        return RdpShareActivationWriteOutcome::Rejected;
    }

    const auto outcome = shareActivation_.onServerBytesWritten(
        replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == RdpShareActivationWriteOutcome::Rejected)
    {
        close();
        return outcome;
    }
    if (outcome == RdpShareActivationWriteOutcome::Activated)
    {
        phase_ = McsSessionPhase::ShareActivated;
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::ShareActivated);
    }
    return outcome;
}

RdpShareActivationClientIntake
McsSessionLifecycle::acceptVerifiedR2ShareActivationPdu(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ != McsSessionPhase::ShareActivation ||
        admissionGeneration_ == 0U || sessionGeneration_ == 0U ||
        !connectResponseProvenanceBound_ ||
        provenance != connectResponseBoundProvenance_ ||
        provenance.serverSelectedProtocol != kRdpProtocolHybrid ||
        licensing_.phase() != RdpLicensingPhase::Licensed ||
        !joins_.allConfiguredChannelsJoined())
    {
        close();
        return RdpShareActivationClientIntake::Rejected;
    }

    const auto intake = shareActivation_.onClientTpkt(completeTpkt);
    if (intake == RdpShareActivationClientIntake::Rejected ||
        intake == RdpShareActivationClientIntake::Closed)
        close();
    return intake;
}

bool McsSessionLifecycle::verifiedR2ApplicationTrafficReady(
    const SecurityNegotiationProvenance &provenance) const noexcept
{
    return phase_ == McsSessionPhase::ShareActivated &&
           admissionGeneration_ != 0U && sessionGeneration_ != 0U &&
           connectResponseProvenanceBound_ &&
           provenance == connectResponseBoundProvenance_ &&
           provenance.serverSelectedProtocol == kRdpProtocolHybrid &&
           licensing_.phase() == RdpLicensingPhase::Licensed &&
           shareActivation_.activated() &&
           joins_.allConfiguredChannelsJoined();
}


RdpPostShareTpktRoute McsSessionLifecycle::classifyVerifiedR2PostShareTpkt(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) const noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        allocatedUserId_ == 0U || !connectResponseAllocation_ ||
        !joins_.channelJoinConfirmed(
            static_cast<std::uint16_t>(allocatedUserId_)) ||
        !joins_.channelJoinConfirmed(connectResponseAllocation_.ioChannelId))
        return {};

    // One complete-TPKT/X.224/T.125 PER parse. The session's negotiated
    // and fully confirmed MCS identities are the only route authority.
    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        parsed.request.kind != McsChannelRequestKind::SendDataRequest ||
        parsed.request.initiator != allocatedUserId_ ||
        parsed.request.segmentation != 3U)
        return {};

    const auto userData = parsed.request.userData;
    if (parsed.request.channelId == connectResponseAllocation_.ioChannelId)
    {
        const auto input = parseRdpSlowPathInputPdu(userData);
        if (!input ||
            input.value.pduSource !=
                static_cast<std::uint16_t>(allocatedUserId_) ||
            !shareActivation_.matchesActivatedClientShare(
                input.value.shareId, input.value.pduSource) ||
            !slowPathInputAllowed(
                input.value, shareActivation_.negotiatedSlowPathInputFlags()))
            return {};
        return {RdpPostShareTpktRouteKind::SlowPathInput, completeTpkt};
    }

    const auto graphicsChannel = resolveMcsStaticChannelRole(
        connectResponseClientSettings_, connectResponseAllocation_,
        McsStaticChannelRole::DynamicVirtualChannels);
    if (graphicsChannel && parsed.request.channelId == *graphicsChannel &&
        joins_.channelJoinConfirmed(*graphicsChannel))
    {
        using Phase = RdpGraphicsDvcPhase;
        const auto phase = graphicsDynamicVirtualChannel_.phase();
        if (graphicsDynamicVirtualChannel_.channelGeneration() == 0U ||
            graphicsDynamicVirtualChannel_.dynamicChannelId() == 0U ||
            (phase != Phase::AwaitCapabilitiesResponse &&
             phase != Phase::AwaitCreateResponse &&
             phase != Phase::Created && phase != Phase::Ready) ||
            userData.size() < 9U ||
            readLe32At(userData, 0U) != userData.size() - 8U ||
            (readLe32At(userData, 4U) & 0x00000003U) != 0x00000003U ||
            (readLe32At(userData, 4U) & ~0x000000f3U) != 0U ||
            userData.size() - 8U >
                kRdpStaticVirtualChannelDefaultChunkBytes)
            return {};
        // DRDYNVC is shared by multiple dynamic channels. A joined static
        // channel alone cannot identify Graphics; only the current R3
        // Graphics phase and allocated DVC ID may select this route.
        const auto dvc = userData.subspan(8U);
        if (phase == Phase::AwaitCapabilitiesResponse)
        {
            if (dvc.size() != 4U || dvc[0] != 0x50U ||
                dvc[1] != 0U || readLe16At(dvc, 2U) == 0U ||
                readLe16At(dvc, 2U) > 3U)
                return {};
        }
        else
        {
            const std::uint8_t command =
                static_cast<std::uint8_t>(dvc[0] & 0xf0U);
            const std::uint8_t idCode =
                static_cast<std::uint8_t>(dvc[0] & 0x03U);
            if (idCode == 3U)
                return {};
            const std::size_t idBytes =
                idCode == 0U ? 1U : (idCode == 1U ? 2U : 4U);
            if (phase == Phase::AwaitCreateResponse)
            {
                if (command != 0x10U || (dvc[0] & 0x0cU) != 0U ||
                    dvc.size() != 1U + idBytes + 4U)
                    return {};
            }
            else
            {
                if ((command != 0x20U && command != 0x30U) ||
                    dvc.size() <= 1U + idBytes)
                    return {};
                if (command == 0x30U && (dvc[0] & 0x0cU) != 0U)
                    return {};
                if (command == 0x20U)
                {
                    const auto lengthCode =
                        static_cast<std::uint8_t>((dvc[0] >> 2U) & 3U);
                    if (lengthCode == 3U)
                        return {};
                    const std::size_t lengthBytes =
                        lengthCode == 0U ? 1U :
                        (lengthCode == 1U ? 2U : 4U);
                    if (dvc.size() <= 1U + idBytes + lengthBytes)
                        return {};
                }
            }
            std::uint32_t channelId = 0U;
            for (std::size_t index = 0U; index < idBytes; ++index)
                channelId |= static_cast<std::uint32_t>(
                    dvc[1U + index]) << (8U * index);
            if (channelId !=
                graphicsDynamicVirtualChannel_.dynamicChannelId())
                return {};
        }
        // The mutating consumer still owns full message validation,
        // reassembly, CAPS/CREATE state and FRAME_ACK.
        return {RdpPostShareTpktRouteKind::GraphicsDynamicVirtualChannel,
                completeTpkt};
    }

    const auto clipboardChannel = resolveMcsStaticChannelRole(
        connectResponseClientSettings_, connectResponseAllocation_,
        McsStaticChannelRole::Clipboard);
    const auto clipboard = clipboardStaticChannel_.view();
    if (clipboardChannel &&
        parsed.request.channelId == *clipboardChannel &&
        joins_.channelJoinConfirmed(*clipboardChannel) && clipboard &&
        clipboard.channelId == *clipboardChannel &&
        clipboard.generation != 0U &&
        userData.size() > 8U &&
        userData.size() - 8U <=
            kRdpStaticVirtualChannelDefaultChunkBytes)
    {
        constexpr std::uint32_t permittedFlags = 0x000000f3U;
        const auto flags = readLe32At(userData, 4U);
        const auto totalLength = readLe32At(userData, 0U);
        if ((flags & ~permittedFlags) == 0U &&
            totalLength >= 8U &&
            totalLength <= clipboard::kMaximumPduBytes)
            return {RdpPostShareTpktRouteKind::ClipboardStaticChannel,
                    completeTpkt};
    }
    return {};
}

std::optional<RdpClipboardStaticChannelView>
McsSessionLifecycle::resolveVerifiedR2ActivatedClipboardChannel(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        allocatedUserId_ == 0U || !connectResponseAllocation_)
    {
        close();
        return std::nullopt;
    }

    const auto channel = resolveMcsStaticChannelRole(
        connectResponseClientSettings_, connectResponseAllocation_,
        McsStaticChannelRole::Clipboard);
    if (!channel ||
        !joins_.channelJoinConfirmed(
            static_cast<std::uint16_t>(allocatedUserId_)) ||
        !joins_.channelJoinConfirmed(connectResponseAllocation_.ioChannelId) ||
        !joins_.channelJoinConfirmed(*channel))
    {
        close();
        return std::nullopt;
    }

    const auto current = clipboardStaticChannel_.view();
    if (current)
    {
        if (current.channelId != *channel)
        {
            close();
            return std::nullopt;
        }
        return current;
    }

    const auto newGeneration = allocateClipboardRouteGeneration();
    if (!newGeneration || !clipboardStaticChannel_.start(
            allocatedUserId_, *channel, *newGeneration,
            shareActivation_.serverToClientVirtualChannelChunkBytes()))
    {
        close();
        return std::nullopt;
    }
    return clipboardStaticChannel_.view();
}

RdpClipboardChunkIntake
McsSessionLifecycle::acceptVerifiedR2ClipboardTpkt(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt,
    std::span<const std::uint8_t> &completePdu) noexcept
{
    completePdu = {};
    const auto channel = resolveVerifiedR2ActivatedClipboardChannel(provenance);
    if (!channel)
        return RdpClipboardChunkIntake::Rejected;
    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        parsed.request.kind != McsChannelRequestKind::SendDataRequest ||
        parsed.request.initiator != allocatedUserId_ ||
        parsed.request.channelId != channel->channelId ||
        parsed.request.segmentation != 3U)
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }
    const auto outcome = clipboardStaticChannel_.receive(
        parsed.request.channelId, channel->generation,
        parsed.request.userData, completePdu);
    if (outcome == RdpClipboardChunkIntake::Rejected)
        close();
    return outcome;
}

std::optional<RdpClipboardStaticChannelWriteView>
McsSessionLifecycle::queueVerifiedR2ClipboardPdu(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completePdu) noexcept
{
    if (!resolveVerifiedR2ActivatedClipboardChannel(provenance) ||
        !clipboardStaticChannel_.queue(completePdu))
    {
        close();
        return std::nullopt;
    }
    return clipboardStaticChannel_.pending();
}

std::optional<RdpClipboardStaticChannelWriteView>
McsSessionLifecycle::pendingVerifiedR2ClipboardWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!resolveVerifiedR2ActivatedClipboardChannel(provenance))
        return std::nullopt;
    const auto pending = clipboardStaticChannel_.pending();
    return pending ? std::optional{pending} : std::nullopt;
}

RdpClipboardWriteOutcome
McsSessionLifecycle::completeVerifiedR2ClipboardWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t generation, std::uint64_t replySequence,
    std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept
{
    const auto channel = resolveVerifiedR2ActivatedClipboardChannel(provenance);
    if (!channel || channel->generation != generation)
    {
        close();
        return RdpClipboardWriteOutcome::Rejected;
    }
    const auto outcome = clipboardStaticChannel_.onAcceptedBytes(
        generation, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == RdpClipboardWriteOutcome::Rejected)
        close();
    return outcome;
}

std::optional<RdpSlowPathInputPdu>
McsSessionLifecycle::routeVerifiedR2SlowPathInputPdu(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        allocatedUserId_ == 0U || !connectResponseAllocation_)
    {
        close();
        return std::nullopt;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        parsed.request.kind != McsChannelRequestKind::SendDataRequest ||
        parsed.request.initiator != allocatedUserId_ ||
        parsed.request.channelId != connectResponseAllocation_.ioChannelId ||
        parsed.request.segmentation != 3U)
    {
        close();
        return std::nullopt;
    }

    const auto input = parseRdpSlowPathInputPdu(parsed.request.userData);
    if (!input ||
        input.value.pduSource !=
            static_cast<std::uint16_t>(allocatedUserId_) ||
        !shareActivation_.matchesActivatedClientShare(
            input.value.shareId, input.value.pduSource) ||
        !slowPathInputAllowed(
            input.value, shareActivation_.negotiatedSlowPathInputFlags()))
    {
        close();
        return std::nullopt;
    }
    return input.value;
}

std::optional<std::uint16_t>
McsSessionLifecycle::resolveVerifiedR2ActivatedDynamicVirtualChannel(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance))
    {
        close();
        return std::nullopt;
    }
    const auto id = resolveMcsStaticChannelRole(
        connectResponseClientSettings_, connectResponseAllocation_,
        McsStaticChannelRole::DynamicVirtualChannels);
    if (!id || !joins_.channelJoinConfirmed(*id))
        return std::nullopt;
    return id;
}

std::optional<RdpGraphicsDvcWriteView>
McsSessionLifecycle::beginVerifiedR2GraphicsDynamicVirtualChannel(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance))
    {
        close();
        return std::nullopt;
    }

    // The current PersonalDesktop product publishes through RDPGFX only.
    // Refuse Graphics DVC allocation when Client Core omitted the protocol
    // capability rather than inventing support or weakening admission gates.
    if (!gccClientSupportsDynamicVirtualChannelGraphics(
            connectResponseClientSettings_))
    {
        return std::nullopt;
    }

    const auto staticChannelId =
        resolveVerifiedR2ActivatedDynamicVirtualChannel(provenance);
    if (!staticChannelId)
        return std::nullopt;

    const auto allocation = dynamicVirtualChannels_.allocate();
    const ::PixelSize desktopGeometry{
        connectResponseClientSettings_.requestedWidth,
        connectResponseClientSettings_.requestedHeight};
    if (!allocation ||
        !graphicsDynamicVirtualChannel_.begin(
            allocatedUserId_, *staticChannelId, *allocation,
            desktopGeometry))
    {
        close();
        return std::nullopt;
    }

    const auto pending =
        graphicsDynamicVirtualChannel_.pendingServerWrite();
    return pending ? std::optional<RdpGraphicsDvcWriteView>{pending}
                   : std::nullopt;
}

std::optional<RdpGraphicsDvcWriteView>
McsSessionLifecycle::pendingVerifiedR2GraphicsDynamicVirtualChannelWrite(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance))
    {
        close();
        return std::nullopt;
    }
    const auto pending =
        graphicsDynamicVirtualChannel_.pendingServerWrite();
    return pending ? std::optional<RdpGraphicsDvcWriteView>{pending}
                   : std::nullopt;
}

RdpGraphicsDvcWriteOutcome
McsSessionLifecycle::completeVerifiedR2GraphicsDynamicVirtualChannelWrite(
    const SecurityNegotiationProvenance &provenance,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        graphicsDynamicVirtualChannel_.channelGeneration() == 0U)
    {
        close();
        return RdpGraphicsDvcWriteOutcome::Rejected;
    }

    const auto pendingBefore =
        graphicsDynamicVirtualChannel_.pendingServerWrite();
    const auto pendingKind = pendingBefore.kind;
    const bool completedCurrentSlice =
        pendingBefore &&
        acceptedBytes == pendingBefore.bytes.size();
    const bool resizeRemapWasInProgress =
        graphicsDynamicVirtualChannel_.replacementSurfaceId_ != 0U;
    const auto acceptanceBefore =
        graphicsDynamicVirtualChannel_.presentationLifecycle_.
            acceptanceStatus();

    const auto outcome =
        graphicsDynamicVirtualChannel_.onServerBytesWritten(
            graphicsDynamicVirtualChannel_.channelGeneration(),
            replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == RdpGraphicsDvcWriteOutcome::Rejected)
    {
        if (resizeRemapWasInProgress)
            recordFirstClientAcceptanceEvent(
                RdpFirstClientAcceptanceEventKind::ResizeRemapRejected);
        close();
        return outcome;
    }

    const auto acceptanceAfter =
        graphicsDynamicVirtualChannel_.presentationLifecycle_.
            acceptanceStatus();
    if (!acceptanceBefore.firstExactFrameWriteCommitted &&
        acceptanceAfter.firstExactFrameWriteCommitted)
    {
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::
                FirstFramePublicationAccepted);
    }

    if (completedCurrentSlice)
    {
        switch (pendingKind)
        {
        case RdpGraphicsDvcWriteKind::GraphicsCapabilitiesConfirm:
            if (graphicsDynamicVirtualChannel_.graphicsCapabilitiesConfirmed())
            {
                recordFirstClientAcceptanceEvent(
                    RdpFirstClientAcceptanceEventKind::GraphicsControlReady);
            }
            break;
        case RdpGraphicsDvcWriteKind::GraphicsCreateSurface:
            recordFirstClientAcceptanceEvent(
                RdpFirstClientAcceptanceEventKind::SurfaceCreated);
            break;
        case RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput:
            if (graphicsDynamicVirtualChannel_.presentationMapped())
            {
                recordFirstClientAcceptanceEvent(
                    RdpFirstClientAcceptanceEventKind::SurfaceMapped);
                if (resizeRemapWasInProgress)
                    recordFirstClientAcceptanceEvent(
                        RdpFirstClientAcceptanceEventKind::
                            ResizeRemapCompleted);
            }
            break;
        case RdpGraphicsDvcWriteKind::None:
        case RdpGraphicsDvcWriteKind::CapabilitiesRequest:
        case RdpGraphicsDvcWriteKind::CreateRequest:
        case RdpGraphicsDvcWriteKind::GraphicsDeleteSurface:
        case RdpGraphicsDvcWriteKind::GraphicsFrameData:
            break;
        }
    }
    return outcome;
}

RdpGraphicsDvcClientIntake
McsSessionLifecycle::acceptVerifiedR2GraphicsDynamicVirtualChannelPdu(
    const SecurityNegotiationProvenance &provenance,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        graphicsDynamicVirtualChannel_.channelGeneration() == 0U)
    {
        close();
        return RdpGraphicsDvcClientIntake::Rejected;
    }

    const auto intake = graphicsDynamicVirtualChannel_.onClientTpkt(
        graphicsDynamicVirtualChannel_.channelGeneration(), completeTpkt);
    if (intake == RdpGraphicsDvcClientIntake::Rejected ||
        intake == RdpGraphicsDvcClientIntake::Closed)
        close();
    else if (intake == RdpGraphicsDvcClientIntake::CreateAccepted)
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::
                GraphicsDynamicVirtualChannelActivated);
    return intake;
}



RdpGraphicsFrameAcknowledgeIntake
McsSessionLifecycle::consumeVerifiedR2GraphicsFrameAcknowledge(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    using Intake = RdpGraphicsFrameAcknowledgeIntake;
    const auto channel = resolveMcsStaticChannelRole(
        connectResponseClientSettings_, connectResponseAllocation_,
        McsStaticChannelRole::DynamicVirtualChannels);
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        !connectResponseAllocation_ || !channel ||
        !joins_.channelJoinConfirmed(*channel) ||
        graphicsDynamicVirtualChannel_.channelGeneration() == 0U)
    {
        close();
        return Intake::Rejected;
    }

    const auto acceptanceBefore =
        graphicsDynamicVirtualChannel_.presentationLifecycle_.
            acceptanceStatus();
    const auto intake =
        graphicsDynamicVirtualChannel_.consumePendingClientFrameAcknowledge(
            graphicsDynamicVirtualChannel_.channelGeneration());
    const auto acceptanceAfter =
        graphicsDynamicVirtualChannel_.presentationLifecycle_.
            acceptanceStatus();
    if (intake == Intake::Rejected)
        close();
    else if (!acceptanceBefore.firstGenuineFrameAcknowledge &&
             acceptanceAfter.firstGenuineFrameAcknowledge)
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::FirstFrameAcknowledge);
    return intake;
}

RdpGraphicsFramePublicationReadiness
McsSessionLifecycle::preflightVerifiedR2GraphicsFramePublication(
    const SecurityNegotiationProvenance &provenance,
    std::uint32_t frameId) const noexcept
{
    using Readiness = RdpGraphicsFramePublicationReadiness;
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        !graphicsDynamicVirtualChannel_.presentationMapped())
        return Readiness::Rejected;

    return graphicsDynamicVirtualChannel_.preflightFramePublication(frameId);
}

RdpGraphicsSurfaceReconfiguration
McsSessionLifecycle::beginVerifiedR2GraphicsSurfaceReconfiguration(
    const SecurityNegotiationProvenance &provenance,
    ::PixelSize desktopGeometry) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        !graphicsDynamicVirtualChannel_.graphicsCapabilitiesConfirmed() ||
        graphicsDynamicVirtualChannel_.channelGeneration() == 0U)
    {
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::ResizeRemapRejected);
        close();
        return RdpGraphicsSurfaceReconfiguration::Rejected;
    }

    const auto decision =
        graphicsDynamicVirtualChannel_.beginSurfaceReconfiguration(
            graphicsDynamicVirtualChannel_.channelGeneration(),
            desktopGeometry);
    if (decision == RdpGraphicsSurfaceReconfiguration::Started)
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::ResizeRemapStarted);
    else if (decision == RdpGraphicsSurfaceReconfiguration::Rejected)
        recordFirstClientAcceptanceEvent(
            RdpFirstClientAcceptanceEventKind::ResizeRemapRejected);
    return decision;
}

std::optional<RdpGraphicsDvcWriteView>
McsSessionLifecycle::beginVerifiedR2GraphicsClearCodecFramePublication(
    const SecurityNegotiationProvenance &provenance,
    std::uint32_t frameId,
    ::FramebufferView framebuffer) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        !graphicsDynamicVirtualChannel_.presentationMapped())
    {
        close();
        return std::nullopt;
    }

    rdp_server::rdp::GfxAvc420SegmentedFrame frame;
    const std::size_t staticChannelChunkBytes =
        shareActivation_.serverToClientVirtualChannelChunkBytes();
    if (staticChannelChunkBytes == 0U ||
        !graphicsDynamicVirtualChannel_.prepareClearCodecFrame(
            frameId, framebuffer, frame) ||
        !graphicsDynamicVirtualChannel_.beginFramePublication(
            std::move(frame), RdpGraphicsFrameCodec::ClearCodec,
            staticChannelChunkBytes))
        return std::nullopt;

    const auto pending =
        graphicsDynamicVirtualChannel_.pendingServerWrite();
    return pending &&
                   pending.kind ==
                       RdpGraphicsDvcWriteKind::GraphicsFrameData
               ? std::optional<RdpGraphicsDvcWriteView>{pending}
               : std::nullopt;
}

bool McsSessionLifecycle::cancelVerifiedR2UnwrittenGraphicsFrame(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        graphicsDynamicVirtualChannel_.channelGeneration() == 0U)
    {
        close();
        return false;
    }
    return graphicsDynamicVirtualChannel_.
        cancelUnwrittenFramePublication(
            graphicsDynamicVirtualChannel_.channelGeneration());
}

bool McsSessionLifecycle::abortVerifiedR2GraphicsFrame(
    const SecurityNegotiationProvenance &provenance) noexcept
{
    if (!verifiedR2ApplicationTrafficReady(provenance) ||
        graphicsDynamicVirtualChannel_.channelGeneration() == 0U)
    {
        close();
        return false;
    }
    const bool aborted =
        graphicsDynamicVirtualChannel_.abortFramePublication(
            graphicsDynamicVirtualChannel_.channelGeneration());
    close();
    return aborted;
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

std::optional<RdpDynamicVirtualChannelAllocation>
RdpDynamicVirtualChannelAllocator::allocate() noexcept
{
    if (closed_ || nextChannelId_ == 0U || nextGeneration_ == 0U)
        return std::nullopt;

    const RdpDynamicVirtualChannelAllocation allocation{
        nextChannelId_, nextGeneration_};

    if (nextChannelId_ == std::numeric_limits<std::uint32_t>::max())
        nextChannelId_ = 0U;
    else
        ++nextChannelId_;

    if (nextGeneration_ == std::numeric_limits<std::uint64_t>::max())
        nextGeneration_ = 0U;
    else
        ++nextGeneration_;

    return allocation;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
advanceReplySequence() noexcept
{
    if (replySequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++replySequence_;
    return replySequence_ != 0U;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
advanceWriteSliceSequence() noexcept
{
    if (writeSliceSequence_ ==
        std::numeric_limits<std::uint64_t>::max())
        return false;
    ++writeSliceSequence_;
    return writeSliceSequence_ != 0U;
}

void RdpGraphicsDynamicVirtualChannelLifecycle::fail() noexcept
{
    abortActiveFramePublication();
    presentationLifecycle_.disconnect();
    clearClientDvcReassembly();
    pending_.fill(0U);
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    negotiatedVersion_ = 0U;
    selectedGraphicsCapabilityVersion_ = 0U;
    selectedGraphicsCapabilityFlags_ = 0U;
    selectedGraphicsAvc420Enabled_ = false;
    graphicsCapabilitiesConfirmed_ = false;
    presentationGeometry_ = {};
    replacementSurfaceId_ = 0U;
    highestPublishedFrameId_ = 0U;
    retiredSurfaceFrameIdBoundary_ = 0U;
    hasPublishedFrame_ = false;
    hasRetiredSurfaceFrameIdBoundary_ = false;
    remappedSurface_ = false;
    surfaceReconfigurationAckDrainDeferrals_ = 0U;
    presentationReceipt_ = {};
    pendingKind_ = RdpGraphicsDvcWriteKind::None;
    phase_ = RdpGraphicsDvcPhase::Failed;
}

void RdpGraphicsDynamicVirtualChannelLifecycle::close() noexcept
{
    abortActiveFramePublication();
    presentationLifecycle_.disconnect();
    clearClientDvcReassembly();
    pending_.fill(0U);
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    clientUserId_ = 0U;
    staticChannelId_ = 0U;
    allocation_ = {};
    replySequence_ = 0U;
    writeSliceSequence_ = 0U;
    negotiatedVersion_ = 0U;
    selectedGraphicsCapabilityVersion_ = 0U;
    selectedGraphicsCapabilityFlags_ = 0U;
    selectedGraphicsAvc420Enabled_ = false;
    graphicsCapabilitiesConfirmed_ = false;
    presentationGeometry_ = {};
    replacementSurfaceId_ = 0U;
    highestPublishedFrameId_ = 0U;
    retiredSurfaceFrameIdBoundary_ = 0U;
    hasPublishedFrame_ = false;
    hasRetiredSurfaceFrameIdBoundary_ = false;
    remappedSurface_ = false;
    surfaceReconfigurationAckDrainDeferrals_ = 0U;
    presentationReceipt_ = {};
    pendingKind_ = RdpGraphicsDvcWriteKind::None;
    phase_ = RdpGraphicsDvcPhase::Closed;
}

void RdpGraphicsDynamicVirtualChannelLifecycle::
revokeUnlessChannelGenerationMatches(
    std::uint64_t channelGeneration) noexcept
{
    if (phase_ == RdpGraphicsDvcPhase::Closed)
        return;
    if (channelGeneration == 0U ||
        allocation_.generation == 0U ||
        channelGeneration != allocation_.generation)
        close();
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::queueControlPdu(
    RdpGraphicsDvcWriteKind kind,
    std::span<const std::uint8_t> dvcPdu) noexcept
{
    constexpr std::size_t kStaticChannelHeaderBytes = 8U;
    constexpr std::size_t kMaximumControlPduBytes = 48U;
    if (kind == RdpGraphicsDvcWriteKind::None ||
        dvcPdu.empty() ||
        dvcPdu.size() > kMaximumControlPduBytes ||
        staticChannelId_ == 0U ||
        pendingLength_ != 0U ||
        phase_ == RdpGraphicsDvcPhase::Failed ||
        phase_ == RdpGraphicsDvcPhase::Closed)
        return false;

    std::array<std::uint8_t,
               kStaticChannelHeaderBytes + kMaximumControlPduBytes>
        staticUserData{};
    writeLe32At(staticUserData, 0U,
                static_cast<std::uint32_t>(dvcPdu.size()));
    writeLe32At(staticUserData, 4U, 0x00000003U);
    std::copy(dvcPdu.begin(), dvcPdu.end(),
              staticUserData.begin() +
                  static_cast<std::ptrdiff_t>(
                      kStaticChannelHeaderBytes));

    const std::size_t staticBytes =
        kStaticChannelHeaderBytes + dvcPdu.size();
    const auto packetBytes = encodeMcsSendDataIndication(
        1002U, staticChannelId_, 1U, 3U,
        std::span<const std::uint8_t>{staticUserData}.first(staticBytes),
        pending_);
    if (!packetBytes ||
        *packetBytes > pending_.size() ||
        !advanceReplySequence() ||
        !advanceWriteSliceSequence())
        return false;

    pendingLength_ = *packetBytes;
    bytesWritten_ = 0U;
    pendingKind_ = kind;
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
queueCapabilitiesRequest() noexcept
{
    constexpr std::array<std::uint8_t, 4> request{
        0x50U, 0x00U, 0x01U, 0x00U};
    if (!queueControlPdu(
            RdpGraphicsDvcWriteKind::CapabilitiesRequest, request))
        return false;
    phase_ = RdpGraphicsDvcPhase::CapabilitiesRequestPending;
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::queueCreateRequest() noexcept
{
    constexpr std::size_t kMaximumChannelIdBytes = 4U;
    constexpr std::size_t kMaximumPduBytes =
        1U + kMaximumChannelIdBytes +
        kRdpGraphicsDynamicVirtualChannelName.size() + 1U;
    std::array<std::uint8_t, kMaximumPduBytes> request{};

    const std::uint32_t channelId = allocation_.channelId;
    std::size_t channelIdBytes = 1U;
    std::uint8_t cbId = 0U;
    if (channelId > 0xffffU)
    {
        channelIdBytes = 4U;
        cbId = 2U;
    }
    else if (channelId > 0xffU)
    {
        channelIdBytes = 2U;
        cbId = 1U;
    }

    request[0] = static_cast<std::uint8_t>(0x10U | cbId);
    for (std::size_t index = 0U; index < channelIdBytes; ++index)
        request[1U + index] = static_cast<std::uint8_t>(
            channelId >> (index * 8U));

    std::size_t offset = 1U + channelIdBytes;
    for (const char value : kRdpGraphicsDynamicVirtualChannelName)
        request[offset++] = static_cast<std::uint8_t>(value);
    request[offset++] = 0U;

    if (!queueControlPdu(
            RdpGraphicsDvcWriteKind::CreateRequest,
            std::span<const std::uint8_t>{request}.first(offset)))
        return false;
    phase_ = RdpGraphicsDvcPhase::CreateRequestPending;
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
queueGraphicsApplicationPdu(
    RdpGraphicsDvcWriteKind kind,
    std::span<const std::byte> graphicsPdu) noexcept
{
    constexpr std::size_t kMaximumChannelIdBytes = 4U;
    constexpr std::size_t kMaximumGraphicsCommandBytes = 24U;
    if ((kind != RdpGraphicsDvcWriteKind::GraphicsCapabilitiesConfirm &&
         kind != RdpGraphicsDvcWriteKind::GraphicsCreateSurface &&
         kind != RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput &&
         kind != RdpGraphicsDvcWriteKind::GraphicsDeleteSurface) ||
        graphicsPdu.empty() ||
        graphicsPdu.size() > kMaximumGraphicsCommandBytes)
        return false;

    std::array<std::uint8_t,
               1U + kMaximumChannelIdBytes + kMaximumGraphicsCommandBytes>
        data{};
    const std::uint32_t channelId = allocation_.channelId;
    const std::size_t channelIdBytes = dynamicChannelIdBytes(channelId);
    const std::uint8_t cbId =
        channelIdBytes == 1U ? 0U : (channelIdBytes == 2U ? 1U : 2U);

    data[0] = static_cast<std::uint8_t>(0x30U | cbId);
    writeDynamicLittleEndian(
        data, 1U, channelId, channelIdBytes);

    std::size_t offset = 1U + channelIdBytes;
    for (const std::byte value : graphicsPdu)
        data[offset++] = std::to_integer<std::uint8_t>(value);

    return queueControlPdu(
        kind, std::span<const std::uint8_t>{data}.first(offset));
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
queuePresentationCommand(
    rdp_server::rdp::GfxPresentationCommand expectedCommand,
    RdpGraphicsDvcWriteKind kind) noexcept
{
    std::array<std::byte, 24U> graphicsPdu{};
    rdp_server::rdp::GfxPresentationReceipt receipt{};
    if (!presentationLifecycle_.prepareCommand(
            allocation_.generation, graphicsPdu, receipt) ||
        receipt.command != expectedCommand ||
        receipt.bytes == 0U ||
        receipt.bytes > graphicsPdu.size() ||
        !queueGraphicsApplicationPdu(
            kind,
            std::span<const std::byte>{graphicsPdu}.first(receipt.bytes)))
    {
        presentationLifecycle_.disconnect();
        presentationReceipt_ = {};
        return false;
    }

    presentationReceipt_ = receipt;
    switch (kind)
    {
    case RdpGraphicsDvcWriteKind::GraphicsCapabilitiesConfirm:
        phase_ = RdpGraphicsDvcPhase::GraphicsCapabilitiesConfirmPending;
        break;
    case RdpGraphicsDvcWriteKind::GraphicsDeleteSurface:
        phase_ = RdpGraphicsDvcPhase::GraphicsDeleteSurfacePending;
        break;
    case RdpGraphicsDvcWriteKind::GraphicsCreateSurface:
        phase_ = RdpGraphicsDvcPhase::GraphicsCreateSurfacePending;
        break;
    case RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput:
        phase_ = RdpGraphicsDvcPhase::GraphicsMapSurfacePending;
        break;
    default:
        presentationLifecycle_.disconnect();
        presentationReceipt_ = {};
        return false;
    }
    return true;
}


void RdpGraphicsDynamicVirtualChannelLifecycle::
clearFramePublication() noexcept
{
    frame_.reset();
    frameRecordMap_.clear();
    frameRecordIndex_ = 0U;
    framePayloadAcceptedBytes_ = 0U;
    frameOuterAcceptedBytes_ = 0U;
}

void RdpGraphicsDynamicVirtualChannelLifecycle::
abortActiveFramePublication() noexcept
{
    if (frame_ && frame_->valid())
    {
        (void)rdp_server::rdp::
            abortGfxAvc420SegmentedFrameDelivery(
                presentationLifecycle_, *frame_);
    }
    clearFramePublication();
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
buildFrameRecordMap(
    std::span<const std::byte> frameBytes,
    std::size_t staticChannelChunkBytes) noexcept
{
    if (frameBytes.empty() ||
        frameBytes.size() >
            std::numeric_limits<std::uint32_t>::max() ||
        staticChannelChunkBytes <
            kRdpStaticVirtualChannelDefaultChunkBytes ||
        staticChannelChunkBytes >
            kRdpStaticVirtualChannelMaximumChunkBytes ||
        allocation_.channelId == 0U)
        return false;

    const std::size_t channelIdBytes =
        dynamicChannelIdBytes(allocation_.channelId);
    const bool fragmented =
        frameBytes.size() >
        kMaximumRdpDynamicVirtualChannelDataPayloadBytes;
    const std::size_t firstLengthBytes =
        fragmented ? dynamicLengthBytes(frameBytes.size()) : 0U;

    try
    {
        std::vector<RdpGraphicsDvcOuterRecordMapEntry> records;
        const std::size_t recordCount =
            frameBytes.size() /
                kMaximumRdpDynamicVirtualChannelDataPayloadBytes +
            (frameBytes.size() %
                     kMaximumRdpDynamicVirtualChannelDataPayloadBytes != 0U
                 ? 1U
                 : 0U);
        records.reserve(recordCount);

        std::size_t frameOffset = 0U;
        while (frameOffset < frameBytes.size())
        {
            const bool dataFirst =
                fragmented && frameOffset == 0U;
            const std::size_t dvcHeaderBytes =
                1U + channelIdBytes +
                (dataFirst ? firstLengthBytes : 0U);
            const std::size_t frameChunkBytes = (std::min)(
                kMaximumRdpDynamicVirtualChannelDataPayloadBytes,
                frameBytes.size() - frameOffset);
            const std::size_t dvcBytes =
                dvcHeaderBytes + frameChunkBytes;
            if (dvcBytes > staticChannelChunkBytes ||
                dvcBytes >
                    kRdpStaticVirtualChannelDefaultChunkBytes)
                return false;

            constexpr std::size_t kStaticChannelHeaderBytes = 8U;
            const std::size_t mcsUserDataBytes =
                kStaticChannelHeaderBytes + dvcBytes;
            const std::size_t mcsHeaderBytes =
                mcsUserDataBytes >= 128U ? 8U : 7U;
            constexpr std::size_t kTpktHeaderBytes = 4U;
            constexpr std::size_t kX224HeaderBytes = 3U;
            const std::size_t outerPlaintextBytes =
                kTpktHeaderBytes + kX224HeaderBytes +
                mcsHeaderBytes + kStaticChannelHeaderBytes +
                dvcHeaderBytes + frameChunkBytes;
            if (outerPlaintextBytes >
                kMaximumRdpDynamicVirtualChannelPacketBytes)
                return false;

            records.push_back({
                frameOffset,
                frameChunkBytes,
                kTpktHeaderBytes,
                kX224HeaderBytes,
                mcsHeaderBytes,
                kStaticChannelHeaderBytes,
                dvcHeaderBytes,
                outerPlaintextBytes,
                dataFirst});
            frameOffset += frameChunkBytes;
        }

        if (records.empty() ||
            records.front().frameOffset != 0U ||
            records.back().frameOffset +
                    records.back().frameBytes !=
                frameBytes.size())
            return false;
        for (std::size_t index = 1U;
             index < records.size(); ++index)
        {
            if (records[index - 1U].frameOffset +
                    records[index - 1U].frameBytes !=
                records[index].frameOffset)
                return false;
        }

        frameRecordMap_ = std::move(records);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
queueFrameRecord() noexcept
{
    if (!frame_ || !frame_->valid() ||
        frameRecordIndex_ >= frameRecordMap_.size() ||
        staticChannelId_ == 0U ||
        pendingLength_ != 0U)
        return false;

    const auto frameBytes = frame_->wireBytes();
    const auto &record = frameRecordMap_[frameRecordIndex_];
    if (record.frameOffset > frameBytes.size() ||
        record.frameBytes >
            frameBytes.size() - record.frameOffset)
        return false;

    constexpr std::size_t kMaximumMcsOuterHeaderBytes = 15U;
    constexpr std::size_t kStaticChannelHeaderBytes = 8U;
    auto staging = std::span<std::uint8_t>{pending_}.subspan(
        kMaximumMcsOuterHeaderBytes);
    const std::size_t dvcBytes =
        record.dvcHeaderBytes + record.frameBytes;
    const std::size_t staticBytes =
        kStaticChannelHeaderBytes + dvcBytes;
    if (staging.size() < staticBytes)
        return false;

    writeLe32At(staging, 0U,
                static_cast<std::uint32_t>(dvcBytes));
    writeLe32At(staging, 4U, 0x00000003U);

    const std::size_t channelIdBytes =
        dynamicChannelIdBytes(allocation_.channelId);
    std::size_t offset = kStaticChannelHeaderBytes;
    if (record.dataFirst)
    {
        const std::size_t lengthBytes =
            dynamicLengthBytes(frameBytes.size());
        staging[offset++] = static_cast<std::uint8_t>(
            0x20U |
            (dynamicLengthCode(lengthBytes) << 2U) |
            dynamicChannelIdCode(channelIdBytes));
        writeDynamicLittleEndian(
            staging, offset, allocation_.channelId,
            channelIdBytes);
        offset += channelIdBytes;
        writeDynamicLittleEndian(
            staging, offset,
            static_cast<std::uint32_t>(frameBytes.size()),
            lengthBytes);
        offset += lengthBytes;
    }
    else
    {
        staging[offset++] = static_cast<std::uint8_t>(
            0x30U | dynamicChannelIdCode(channelIdBytes));
        writeDynamicLittleEndian(
            staging, offset, allocation_.channelId,
            channelIdBytes);
        offset += channelIdBytes;
    }

    if (offset !=
        kStaticChannelHeaderBytes + record.dvcHeaderBytes)
        return false;

    for (std::size_t index = 0U;
         index < record.frameBytes; ++index)
    {
        staging[offset + index] = std::to_integer<std::uint8_t>(
            frameBytes[record.frameOffset + index]);
    }

    const auto packetBytes = encodeMcsSendDataIndication(
        1002U, staticChannelId_, 1U, 3U,
        staging.first(staticBytes), pending_);
    if (!packetBytes ||
        *packetBytes != record.outerPlaintextBytes)
        return false;

    pendingLength_ = *packetBytes;
    bytesWritten_ = 0U;
    pendingKind_ = RdpGraphicsDvcWriteKind::GraphicsFrameData;
    return true;
}

RdpGraphicsFramePublicationReadiness
RdpGraphicsDynamicVirtualChannelLifecycle::preflightFramePublication(
    std::uint32_t frameId) const noexcept
{
    using Readiness = RdpGraphicsFramePublicationReadiness;
    if (phase_ != RdpGraphicsDvcPhase::Ready ||
        !presentationMapped() ||
        allocation_.generation == 0U ||
        pendingLength_ != 0U || bytesWritten_ != 0U ||
        pendingKind_ != RdpGraphicsDvcWriteKind::None ||
        frame_ || !frameRecordMap_.empty())
    {
        return Readiness::Rejected;
    }

    // FRAME_ACK has no surface ID; block reuse of old frame IDs after remap.
    if (remappedSurface_ && hasPublishedFrame_ &&
        frameId <= highestPublishedFrameId_)
        return Readiness::Rejected;

    // R4 alone owns the authoritative pending-ID set and capacity decision.
    // R3 retains only its retired-surface frame-ID fence above.
    switch (presentationLifecycle_.framePublicationReadiness(
        allocation_.generation, frameId))
    {
    case rdp_server::rdp::GfxFramePublicationReadiness::Ready:
        return Readiness::Ready;
    case rdp_server::rdp::GfxFramePublicationReadiness::
        DeferredForFrameAcknowledge:
        return Readiness::DeferredForFrameAcknowledge;
    case rdp_server::rdp::GfxFramePublicationReadiness::Rejected:
        return Readiness::Rejected;
    }
    return Readiness::Rejected;
}

RdpGraphicsSurfaceReconfiguration
RdpGraphicsDynamicVirtualChannelLifecycle::beginSurfaceReconfiguration(
    std::uint64_t channelGeneration, ::PixelSize desktopGeometry) noexcept
{
    using Decision = RdpGraphicsSurfaceReconfiguration;
    if (phase_ == RdpGraphicsDvcPhase::Closed ||
        phase_ == RdpGraphicsDvcPhase::Failed ||
        channelGeneration == 0U ||
        channelGeneration != allocation_.generation ||
        !graphicsCapabilitiesConfirmed_ ||
        desktopGeometry.widthPixels == 0U ||
        desktopGeometry.heightPixels == 0U ||
        desktopGeometry.widthPixels >
            std::numeric_limits<std::uint16_t>::max() ||
        desktopGeometry.heightPixels >
            std::numeric_limits<std::uint16_t>::max())
        return Decision::Rejected;

    // No additional owner of R1 TLS writes or R4 ACK credit is introduced.
    // R10 first retires pending writes (or cancels an all-zero-byte frame).
    if (phase_ != RdpGraphicsDvcPhase::Ready ||
        !presentationMapped() || pendingLength_ != 0U ||
        bytesWritten_ != 0U ||
        pendingKind_ != RdpGraphicsDvcWriteKind::None ||
        frame_ || !frameRecordMap_.empty() ||
        clientGraphicsDataReady_ || clientDvcFragmented_ ||
        !clientDvcMessage_.empty())
        return Decision::Deferred;

    if (desktopGeometry == presentationGeometry_)
    {
        // Native geometry reverted; no remap drain obligation remains.
        surfaceReconfigurationAckDrainDeferrals_ = 0U;
        return Decision::Unchanged;
    }

    // An actual geometry remap, unlike ordinary frame publication, receives
    // a bounded R3 attempt budget while R4 still owns real ACK membership.
    if (presentationLifecycle_.outstandingFrames() != 0U)
    {
        if (++surfaceReconfigurationAckDrainDeferrals_ >=
            kMaximumSurfaceReconfigurationAckDrainDeferrals)
        {
            // Fail closed for reconnect; never invent ACKs or reuse surfaces.
            fail();
            return Decision::Rejected;
        }
        return Decision::Deferred;
    }
    surfaceReconfigurationAckDrainDeferrals_ = 0U;

    const auto previousSurfaceId = presentationLifecycle_.surfaceId();
    if (previousSurfaceId ==
        std::numeric_limits<std::uint16_t>::max())
        return Decision::Rejected; // Reconnect instead of recycling an ID.

    if (!presentationLifecycle_.requestSurfaceDelete(channelGeneration))
    {
        fail();
        return Decision::Rejected;
    }
    replacementSurfaceId_ =
        static_cast<std::uint16_t>(previousSurfaceId + 1U);
    presentationGeometry_ = desktopGeometry;
    if (!queuePresentationCommand(
            rdp_server::rdp::GfxPresentationCommand::Delete,
            RdpGraphicsDvcWriteKind::GraphicsDeleteSurface))
    {
        fail();
        return Decision::Rejected;
    }
    return Decision::Started;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
prepareClearCodecFrame(
    std::uint32_t frameId,
    ::FramebufferView framebuffer,
    rdp_server::rdp::GfxAvc420SegmentedFrame &output) noexcept
{
    if (!presentationMapped() || output.valid() ||
        (remappedSurface_ && hasPublishedFrame_ &&
         frameId <= highestPublishedFrameId_))
        return false;

    const rdp_server::rdp::GfxClearCodecFrameRequest request{
        presentationLifecycle_.surfaceId(), frameId, framebuffer};
    return rdp_server::rdp::prepareGfxClearCodecSegmentedFrame(
        presentationLifecycle_, allocation_.generation, request, output);
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
beginFramePublication(
    rdp_server::rdp::GfxAvc420SegmentedFrame &&frame,
    RdpGraphicsFrameCodec codec,
    std::size_t staticChannelChunkBytes) noexcept
{
    if (phase_ != RdpGraphicsDvcPhase::Ready ||
        !presentationMapped() ||
        pendingLength_ != 0U || frame_ || !frame.valid() ||
        (remappedSurface_ && hasPublishedFrame_ &&
         frame.frameId() <= highestPublishedFrameId_) ||
        frame.generation() != allocation_.generation ||
        !graphicsClearCodecEnabled() ||
        // R4 must bind a new x264 producer to the new surface and prove IDR
        // before AVC420 can ever resume after this same-DVC remap. Until
        // that cross-owner reset contract exists, retain ClearCodec only.
        (codec == RdpGraphicsFrameCodec::Avc420 &&
         (!graphicsAvc420Enabled() || remappedSurface_)) ||
        staticChannelChunkBytes <
            kRdpStaticVirtualChannelDefaultChunkBytes ||
        staticChannelChunkBytes >
            kRdpStaticVirtualChannelMaximumChunkBytes)
        return false;

    if (!buildFrameRecordMap(frame.wireBytes(), staticChannelChunkBytes))
        return false;
    if (!advanceReplySequence() || !advanceWriteSliceSequence())
    {
        frameRecordMap_.clear();
        fail();
        return false;
    }

    try
    {
        frame_.emplace(std::move(frame));
    }
    catch (...)
    {
        frameRecordMap_.clear();
        fail();
        return false;
    }

    if (!queueFrameRecord())
    {
        if (!rdp_server::rdp::
                cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
                    presentationLifecycle_, *frame_))
        {
            (void)rdp_server::rdp::
                abortGfxAvc420SegmentedFrameDelivery(
                    presentationLifecycle_, *frame_);
        }
        clearFramePublication();
        fail();
        return false;
    }
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
cancelUnwrittenFramePublication(
    std::uint64_t channelGeneration) noexcept
{
    if (phase_ != RdpGraphicsDvcPhase::Ready ||
        channelGeneration == 0U ||
        channelGeneration != allocation_.generation ||
        !frame_ || !frame_->valid() ||
        frameOuterAcceptedBytes_ != 0U)
        return false;

    if (!rdp_server::rdp::
            cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
                presentationLifecycle_, *frame_))
    {
        fail();
        return false;
    }

    pending_.fill(0U);
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    pendingKind_ = RdpGraphicsDvcWriteKind::None;
    clearFramePublication();
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
abortFramePublication(
    std::uint64_t channelGeneration) noexcept
{
    if (channelGeneration == 0U ||
        channelGeneration != allocation_.generation ||
        !frame_ || !frame_->valid())
    {
        fail();
        return false;
    }
    fail();
    return true;
}

void RdpGraphicsDynamicVirtualChannelLifecycle::
clearClientDvcReassembly() noexcept
{
    std::vector<std::uint8_t> empty;
    clientDvcMessage_.swap(empty);
    clientDvcExpectedBytes_ = 0U;
    clientDvcFragmented_ = false;
    clientGraphicsDataReady_ = false;
}


RdpGraphicsFrameAcknowledgeIntake
RdpGraphicsDynamicVirtualChannelLifecycle::
consumePendingClientFrameAcknowledge(
    std::uint64_t channelGeneration) noexcept
{
    using Intake = RdpGraphicsFrameAcknowledgeIntake;
    using AckResult = rdp_server::rdp::GfxFrameAckWindowResult;
    if (phase_ != RdpGraphicsDvcPhase::Ready ||
        channelGeneration == 0U ||
        allocation_.generation != channelGeneration ||
        !clientGraphicsDataReady_)
    {
        fail();
        return Intake::Rejected;
    }

    // A late ACK has no surface ID on the wire. A prior-surface ACK must
    // not suspend or update R4's fresh ACK window even when well formed.
    if (hasRetiredSurfaceFrameIdBoundary_)
    {
        rdp_server::rdp::GfxFrameAcknowledgement acknowledgement{};
        if (rdp_server::rdp::parseGfxFrameAcknowledge(
                std::as_bytes(pendingClientGraphicsData()),
                acknowledgement) &&
            acknowledgement.frameId <= retiredSurfaceFrameIdBoundary_)
        {
            // This ACK unambiguously targets a retired surface. Since the
            // wire ACK has no surface identity, accepting it as nonterminal
            // could disguise a replay after remap. Close this DVC rather
            // than touching the live R4 window or inventing ACK credit.
            fail();
            return Intake::Rejected;
        }
    }

    // No second R4 window or ACK counter: the existing mapped presentation
    // validates the exact RDPGFX FRAME_ACKNOWLEDGE and records decode progress.
    AckResult result = AckResult::InvalidPdu;
    if (!presentationLifecycle_.onFrameAcknowledge(
            channelGeneration,
            std::as_bytes(pendingClientGraphicsData()), result))
    {
        fail();
        return Intake::Rejected;
    }
    // The DVC reassembly buffer is retained through R4's synchronous parse
    // and cleared exactly once afterwards. No borrowed view survives.
    clearClientDvcReassembly();
    switch (result)
    {
    case AckResult::Acknowledged: return Intake::Acknowledged;
    case AckResult::Unmatched: return Intake::Unmatched;
    case AckResult::Suspended: return Intake::Suspended;
    case AckResult::InvalidPdu:
    case AckResult::StaleGeneration:
        break;
    }
    fail();
    return Intake::Rejected;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
consumeClientGraphicsData(
    std::uint64_t channelGeneration) noexcept
{
    if (phase_ != RdpGraphicsDvcPhase::Ready ||
        channelGeneration == 0U ||
        channelGeneration != allocation_.generation ||
        !clientGraphicsDataReady_)
        return false;
    clearClientDvcReassembly();
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::
acceptClientDvcData(
    std::span<const std::uint8_t> dvcPdu,
    std::span<const std::uint8_t> &completeMessage) noexcept
{
    completeMessage = {};
    if (dvcPdu.empty() ||
        dvcPdu.size() >
            kRdpStaticVirtualChannelDefaultChunkBytes ||
        clientGraphicsDataReady_)
        return false;

    const std::uint8_t command =
        static_cast<std::uint8_t>(dvcPdu[0] & 0xf0U);
    const std::uint8_t channelIdCode =
        static_cast<std::uint8_t>(dvcPdu[0] & 0x03U);
    if (channelIdCode == 3U ||
        (command != 0x20U && command != 0x30U))
        return false;

    const std::size_t channelIdBytes =
        channelIdCode == 0U ? 1U :
        (channelIdCode == 1U ? 2U : 4U);
    if (dvcPdu.size() <= 1U + channelIdBytes)
        return false;

    std::uint32_t channelId = 0U;
    for (std::size_t index = 0U;
         index < channelIdBytes; ++index)
    {
        channelId |= static_cast<std::uint32_t>(
            dvcPdu[1U + index]) << (index * 8U);
    }
    if (channelId != allocation_.channelId)
        return false;

    if (command == 0x20U)
    {
        if (clientDvcFragmented_)
            return false;
        const std::uint8_t lengthCode =
            static_cast<std::uint8_t>(
                (dvcPdu[0] >> 2U) & 0x03U);
        if (lengthCode == 3U)
            return false;
        const std::size_t lengthBytes =
            lengthCode == 0U ? 1U :
            (lengthCode == 1U ? 2U : 4U);
        const std::size_t headerBytes =
            1U + channelIdBytes + lengthBytes;
        if (dvcPdu.size() <= headerBytes)
            return false;

        std::uint32_t expectedBytes = 0U;
        for (std::size_t index = 0U;
             index < lengthBytes; ++index)
        {
            expectedBytes |= static_cast<std::uint32_t>(
                dvcPdu[1U + channelIdBytes + index])
                << (index * 8U);
        }

        const auto fragment = dvcPdu.subspan(headerBytes);
        if (expectedBytes <=
                kMaximumRdpDynamicVirtualChannelDataPayloadBytes ||
            expectedBytes >
                kMaximumRdpGraphicsDvcClientMessageBytes ||
            fragment.empty() ||
            fragment.size() >
                kMaximumRdpDynamicVirtualChannelDataPayloadBytes ||
            fragment.size() >= expectedBytes)
            return false;

        try
        {
            clientDvcMessage_.assign(
                fragment.begin(), fragment.end());
        }
        catch (...)
        {
            return false;
        }
        clientDvcExpectedBytes_ = expectedBytes;
        clientDvcFragmented_ = true;
        return true;
    }

    if ((dvcPdu[0] & 0x0cU) != 0U)
        return false;
    const auto fragment =
        dvcPdu.subspan(1U + channelIdBytes);
    if (fragment.empty() ||
        fragment.size() >
            kMaximumRdpDynamicVirtualChannelDataPayloadBytes)
        return false;

    if (!clientDvcFragmented_)
    {
        try
        {
            clientDvcMessage_.assign(
                fragment.begin(), fragment.end());
        }
        catch (...)
        {
            return false;
        }
        clientGraphicsDataReady_ = true;
        completeMessage = clientDvcMessage_;
        return true;
    }

    if (clientDvcMessage_.size() >
            clientDvcExpectedBytes_ ||
        fragment.size() >
            clientDvcExpectedBytes_ -
                clientDvcMessage_.size())
        return false;
    try
    {
        clientDvcMessage_.insert(
            clientDvcMessage_.end(),
            fragment.begin(), fragment.end());
    }
    catch (...)
    {
        return false;
    }

    if (clientDvcMessage_.size() <
        clientDvcExpectedBytes_)
        return true;
    if (clientDvcMessage_.size() !=
        clientDvcExpectedBytes_)
        return false;

    clientDvcFragmented_ = false;
    clientDvcExpectedBytes_ = 0U;
    clientGraphicsDataReady_ = true;
    completeMessage = clientDvcMessage_;
    return true;
}

bool RdpGraphicsDynamicVirtualChannelLifecycle::begin(
    std::uint32_t clientUserId,
    std::uint16_t staticChannelId,
    RdpDynamicVirtualChannelAllocation allocation,
    ::PixelSize desktopGeometry) noexcept
{
    if (phase_ != RdpGraphicsDvcPhase::NotStarted ||
        clientUserId < 1001U || clientUserId > 65536U ||
        staticChannelId == 0U || !allocation ||
        desktopGeometry.widthPixels == 0U ||
        desktopGeometry.heightPixels == 0U ||
        desktopGeometry.widthPixels >
            std::numeric_limits<std::uint16_t>::max() ||
        desktopGeometry.heightPixels >
            std::numeric_limits<std::uint16_t>::max())
    {
        fail();
        return false;
    }

    clientUserId_ = clientUserId;
    staticChannelId_ = staticChannelId;
    allocation_ = allocation;
    presentationGeometry_ = desktopGeometry;
    if (!presentationLifecycle_.open(allocation_.generation) ||
        !queueCapabilitiesRequest())
    {
        fail();
        return false;
    }
    return true;
}

RdpGraphicsDvcWriteView
RdpGraphicsDynamicVirtualChannelLifecycle::pendingServerWrite() const noexcept
{
    if (pendingLength_ == 0U || bytesWritten_ >= pendingLength_ ||
        pendingKind_ == RdpGraphicsDvcWriteKind::None ||
        phase_ == RdpGraphicsDvcPhase::Failed ||
        phase_ == RdpGraphicsDvcPhase::Closed)
        return {};

    return {
        std::span<const std::uint8_t>{pending_}
            .first(pendingLength_).subspan(bytesWritten_),
        pendingKind_,
        allocation_.generation,
        allocation_.channelId,
        replySequence_,
        writeSliceSequence_};
}

RdpGraphicsDvcWriteOutcome
RdpGraphicsDynamicVirtualChannelLifecycle::onServerBytesWritten(
    std::uint64_t channelGeneration,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ == RdpGraphicsDvcPhase::Closed)
        return RdpGraphicsDvcWriteOutcome::Rejected;
    if (phase_ == RdpGraphicsDvcPhase::Failed ||
        channelGeneration == 0U ||
        channelGeneration != allocation_.generation ||
        pendingLength_ == 0U ||
        replySequence == 0U ||
        replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pendingLength_ - bytesWritten_)
    {
        fail();
        return RdpGraphicsDvcWriteOutcome::Rejected;
    }

    if (acceptedBytes == 0U)
        return RdpGraphicsDvcWriteOutcome::Pending;

    if (pendingKind_ ==
        RdpGraphicsDvcWriteKind::GraphicsFrameData)
    {
        if (!frame_ || !frame_->valid() ||
                frameRecordIndex_ >= frameRecordMap_.size() ||
            pendingLength_ !=
                frameRecordMap_[frameRecordIndex_].
                    outerPlaintextBytes)
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }

        const auto &record =
            frameRecordMap_[frameRecordIndex_];
        const std::size_t previousOuterBytes =
            bytesWritten_;
        const std::size_t acceptedEnd =
            previousOuterBytes + acceptedBytes;
        const std::size_t payloadStart =
            record.outerPlaintextBytes -
            record.frameBytes;
        const std::size_t mappedStart =
            (std::max)(previousOuterBytes, payloadStart);
        const std::size_t mappedEnd =
            (std::min)(acceptedEnd,
                       record.outerPlaintextBytes);
        const std::size_t newlyAcceptedPayload =
            mappedEnd > mappedStart
                ? mappedEnd - mappedStart
                : 0U;

        if (framePayloadAcceptedBytes_ >
                std::numeric_limits<std::size_t>::max() -
                    newlyAcceptedPayload ||
            frameOuterAcceptedBytes_ >
                std::numeric_limits<std::size_t>::max() -
                    acceptedBytes)
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }

        framePayloadAcceptedBytes_ +=
            newlyAcceptedPayload;
        frameOuterAcceptedBytes_ += acceptedBytes;
        bytesWritten_ = acceptedEnd;

        if (bytesWritten_ != pendingLength_)
        {
            if (!advanceWriteSliceSequence())
            {
                fail();
                return RdpGraphicsDvcWriteOutcome::Rejected;
            }
            return RdpGraphicsDvcWriteOutcome::Pending;
        }

        const std::size_t expectedMappedBytes =
            record.frameOffset + record.frameBytes;
        if (framePayloadAcceptedBytes_ !=
            expectedMappedBytes)
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }

        pending_.fill(0U);
        pendingLength_ = 0U;
        bytesWritten_ = 0U;
        pendingKind_ = RdpGraphicsDvcWriteKind::None;

        if (frameRecordIndex_ + 1U <
            frameRecordMap_.size())
        {
            ++frameRecordIndex_;
            if (!advanceReplySequence() ||
                !advanceWriteSliceSequence() ||
                !queueFrameRecord())
            {
                fail();
                return RdpGraphicsDvcWriteOutcome::Rejected;
            }
            return RdpGraphicsDvcWriteOutcome::Pending;
        }

        const std::size_t deliveredWireBytes =
            frame_->wireBytes().size();
        const std::uint32_t deliveredFrameId = frame_->frameId();
        if (framePayloadAcceptedBytes_ !=
                deliveredWireBytes ||
            !rdp_server::rdp::
                completeGfxAvc420SegmentedFrameDelivery(
                    presentationLifecycle_, *frame_,
                    deliveredWireBytes))
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        if (!hasPublishedFrame_ ||
            deliveredFrameId > highestPublishedFrameId_)
            highestPublishedFrameId_ = deliveredFrameId;
        hasPublishedFrame_ = true;
        clearFramePublication();
        return RdpGraphicsDvcWriteOutcome::Delivered;
    }

    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pendingLength_)
    {
        if (!advanceWriteSliceSequence())
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        return RdpGraphicsDvcWriteOutcome::Pending;
    }

    const auto completedKind = pendingKind_;
    pending_.fill(0U);
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    pendingKind_ = RdpGraphicsDvcWriteKind::None;

    switch (completedKind)
    {
    case RdpGraphicsDvcWriteKind::CapabilitiesRequest:
        phase_ = RdpGraphicsDvcPhase::AwaitCapabilitiesResponse;
        break;
    case RdpGraphicsDvcWriteKind::CreateRequest:
        phase_ = RdpGraphicsDvcPhase::AwaitCreateResponse;
        break;
    case RdpGraphicsDvcWriteKind::GraphicsCapabilitiesConfirm:
        if (!presentationLifecycle_.completeCommand(
                presentationReceipt_, presentationReceipt_.bytes))
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        presentationReceipt_ = {};
        graphicsCapabilitiesConfirmed_ = true;
        if (!presentationLifecycle_.configureSurface(
                allocation_.generation, 0U, presentationGeometry_) ||
            !queuePresentationCommand(
                rdp_server::rdp::GfxPresentationCommand::Create,
                RdpGraphicsDvcWriteKind::GraphicsCreateSurface))
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        return RdpGraphicsDvcWriteOutcome::Pending;
    case RdpGraphicsDvcWriteKind::GraphicsDeleteSurface:
        if (!presentationLifecycle_.completeCommand(
                presentationReceipt_, presentationReceipt_.bytes) ||
            presentationLifecycle_.stage() !=
                rdp_server::rdp::GfxPresentationStage::SurfaceUnconfigured ||
            replacementSurfaceId_ == 0U)
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        presentationReceipt_ = {};
        if (!presentationLifecycle_.configureSurface(
                allocation_.generation, replacementSurfaceId_,
                presentationGeometry_) ||
            !queuePresentationCommand(
                rdp_server::rdp::GfxPresentationCommand::Create,
                RdpGraphicsDvcWriteKind::GraphicsCreateSurface))
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        return RdpGraphicsDvcWriteOutcome::Pending;
    case RdpGraphicsDvcWriteKind::GraphicsCreateSurface:
        if (!presentationLifecycle_.completeCommand(
                presentationReceipt_, presentationReceipt_.bytes))
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        presentationReceipt_ = {};
        if (!queuePresentationCommand(
                rdp_server::rdp::GfxPresentationCommand::Map,
                RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput))
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        return RdpGraphicsDvcWriteOutcome::Pending;
    case RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput:
        if (!presentationLifecycle_.completeCommand(
                presentationReceipt_, presentationReceipt_.bytes) ||
            presentationLifecycle_.stage() !=
                rdp_server::rdp::GfxPresentationStage::Mapped)
        {
            fail();
            return RdpGraphicsDvcWriteOutcome::Rejected;
        }
        presentationReceipt_ = {};
        if (replacementSurfaceId_ != 0U)
        {
            // Delayed ACKs from a retired surface must not change the new
            // mapping's queue depth or ACK-suspension state.
            retiredSurfaceFrameIdBoundary_ = highestPublishedFrameId_;
            hasRetiredSurfaceFrameIdBoundary_ = hasPublishedFrame_;
            remappedSurface_ = true;
            replacementSurfaceId_ = 0U;
        }
        phase_ = RdpGraphicsDvcPhase::Ready;
        break;
    case RdpGraphicsDvcWriteKind::GraphicsFrameData:
        fail();
        return RdpGraphicsDvcWriteOutcome::Rejected;
    case RdpGraphicsDvcWriteKind::None:
        fail();
        return RdpGraphicsDvcWriteOutcome::Rejected;
    }
    return RdpGraphicsDvcWriteOutcome::Delivered;
}

RdpGraphicsDvcClientIntake
RdpGraphicsDynamicVirtualChannelLifecycle::onClientTpkt(
    std::uint64_t channelGeneration,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == RdpGraphicsDvcPhase::Closed)
        return RdpGraphicsDvcClientIntake::Closed;
    if (phase_ == RdpGraphicsDvcPhase::Failed ||
        channelGeneration == 0U ||
        channelGeneration != allocation_.generation ||
        (phase_ != RdpGraphicsDvcPhase::AwaitCapabilitiesResponse &&
         phase_ != RdpGraphicsDvcPhase::AwaitCreateResponse &&
         phase_ != RdpGraphicsDvcPhase::Created &&
         phase_ != RdpGraphicsDvcPhase::Ready))
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        parsed.request.kind != McsChannelRequestKind::SendDataRequest ||
        parsed.request.initiator != clientUserId_ ||
        parsed.request.channelId != staticChannelId_ ||
        parsed.request.segmentation != 3U)
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }

    constexpr std::size_t kStaticChannelHeaderBytes = 8U;
    constexpr std::uint32_t kFirstLast = 0x00000003U;
    constexpr std::uint32_t kIgnoredClientFlags = 0x000000f0U;
    const auto wire = parsed.request.userData;
    if (wire.size() < kStaticChannelHeaderBytes + 1U ||
        readLe32At(wire, 0U) !=
            wire.size() - kStaticChannelHeaderBytes ||
        (readLe32At(wire, 4U) & kFirstLast) != kFirstLast ||
        (readLe32At(wire, 4U) &
         ~(kFirstLast | kIgnoredClientFlags)) != 0U)
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }

    const auto dvcPdu = wire.subspan(kStaticChannelHeaderBytes);
    if (phase_ == RdpGraphicsDvcPhase::AwaitCapabilitiesResponse)
    {
        if (dvcPdu.size() != 4U ||
            dvcPdu[0] != 0x50U ||
            dvcPdu[1] != 0x00U)
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }

        const std::uint16_t clientVersion =
            readLe16At(dvcPdu, 2U);
        if (clientVersion < 1U || clientVersion > 3U)
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }

        // The client reports its own highest supported level, not an echo
        // of the server request. This owner implements v1, so all valid
        // v1/v2/v3 responses negotiate down to the common v1 feature set.
        negotiatedVersion_ = 1U;
        if (!queueCreateRequest())
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }
        return RdpGraphicsDvcClientIntake::CapabilitiesAccepted;
    }

    if (phase_ == RdpGraphicsDvcPhase::AwaitCreateResponse)
    {
        if (dvcPdu.empty() ||
            (dvcPdu[0] & 0xf0U) != 0x10U ||
            (dvcPdu[0] & 0x0cU) != 0U)
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }

        const std::uint8_t cbId =
            static_cast<std::uint8_t>(dvcPdu[0] & 0x03U);
        if (cbId == 3U)
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }
        const std::size_t channelIdBytes =
            cbId == 0U ? 1U : (cbId == 1U ? 2U : 4U);
        if (dvcPdu.size() != 1U + channelIdBytes + 4U)
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }

        std::uint32_t channelId = 0U;
        for (std::size_t index = 0U; index < channelIdBytes; ++index)
            channelId |= static_cast<std::uint32_t>(
                dvcPdu[1U + index]) << (index * 8U);
        if (channelId != allocation_.channelId)
        {
            fail();
            return RdpGraphicsDvcClientIntake::Rejected;
        }

        const std::uint32_t creationStatus =
            readLe32At(dvcPdu, 1U + channelIdBytes);
        if ((creationStatus & 0x80000000U) != 0U)
        {
            fail();
            return RdpGraphicsDvcClientIntake::CreateRejected;
        }

        phase_ = RdpGraphicsDvcPhase::Created;
        return RdpGraphicsDvcClientIntake::CreateAccepted;
    }

    std::span<const std::uint8_t> graphicsPdu;
    if (!acceptClientDvcData(dvcPdu, graphicsPdu))
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }
    if (graphicsPdu.empty())
        return RdpGraphicsDvcClientIntake::
            GraphicsDataFragmentAccepted;

    if (phase_ == RdpGraphicsDvcPhase::Ready)
        return RdpGraphicsDvcClientIntake::GraphicsDataAccepted;

    // Capability negotiation is the first application payload after CREATE,
    // but it may itself arrive as DATA_FIRST followed by one or more DATA
    // blocks. Only the exact complete reassembled message reaches R4.
    const auto negotiation =
        rdp_server::rdp::negotiateGfxCapabilities(
            std::as_bytes(graphicsPdu));
    if (!negotiation.accepted() ||
        negotiation.confirmationBytes == 0U ||
        negotiation.confirmationBytes >
            negotiation.confirmation.size())
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }

    if (!presentationLifecycle_.acceptCapabilities(
            allocation_.generation, std::as_bytes(graphicsPdu)) ||
        presentationLifecycle_.avc420Enabled() !=
            negotiation.avc420Enabled)
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }

    selectedGraphicsCapabilityVersion_ =
        negotiation.selectedVersion;
    selectedGraphicsCapabilityFlags_ =
        negotiation.selectedFlags;
    selectedGraphicsAvc420Enabled_ =
        negotiation.avc420Enabled;
    clearClientDvcReassembly();
    if (!queuePresentationCommand(
            rdp_server::rdp::GfxPresentationCommand::Confirm,
            RdpGraphicsDvcWriteKind::GraphicsCapabilitiesConfirm))
    {
        fail();
        return RdpGraphicsDvcClientIntake::Rejected;
    }
    return RdpGraphicsDvcClientIntake::
        GraphicsCapabilitiesAccepted;
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

bool RdpPersonalDesktopValidClientWriteGate::advanceReplySequence() noexcept
{
    if (replySequence_ == UINT64_MAX)
        return false;
    ++replySequence_;
    return replySequence_ != 0U;
}

bool RdpPersonalDesktopValidClientWriteGate::
advanceWriteSliceSequence() noexcept
{
    if (writeSliceSequence_ == UINT64_MAX)
        return false;
    ++writeSliceSequence_;
    return writeSliceSequence_ != 0U;
}

bool RdpPersonalDesktopValidClientWriteGate::queue(
    std::uint16_t ioChannelId) noexcept
{
    if (closed_ || queued_ || delivered_ || ioChannelId == 0U ||
        licensing_ == nullptr ||
        licensing_->protocolMode() !=
            RdpLicensingProtocolMode::PersonalDesktop ||
        licensing_->phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_->decisionBranch() !=
            RdpLicensingDecisionBranch::
                PersonalDesktopCompletionRequired)
    {
        close();
        return false;
    }

    std::array<std::uint8_t, 4U + kRdpValidClientLicensingMessageBytes>
        userData{};
    userData[0] = 0x80U; // SEC_LICENSE_PKT, Basic Security Header.
    const auto licensingMessage = encodeRdpValidClientLicensingMessage();
    std::copy(
        licensingMessage.begin(), licensingMessage.end(),
        userData.begin() + 4U);

    const auto packetBytes = encodeMcsSendDataIndication(
        1002U, ioChannelId, 1U, 3U, userData, pending_);
    if (!packetBytes ||
        *packetBytes != kRdpPersonalDesktopValidClientPacketBytes ||
        !advanceReplySequence() || !advanceWriteSliceSequence())
    {
        close();
        return false;
    }

    bytesWritten_ = 0U;
    queued_ = true;
    return true;
}

RdpPersonalDesktopValidClientWriteView
RdpPersonalDesktopValidClientWriteGate::pendingWrite() const noexcept
{
    if (closed_ || delivered_ || !queued_ ||
        bytesWritten_ >= pending_.size())
        return {};
    return {
        std::span<const std::uint8_t>{pending_}.subspan(bytesWritten_),
        replySequence_, writeSliceSequence_};
}

RdpPersonalDesktopValidClientWriteOutcome
RdpPersonalDesktopValidClientWriteGate::onBytesWritten(
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (closed_ || delivered_ || !queued_ || licensing_ == nullptr ||
        licensing_->protocolMode() !=
            RdpLicensingProtocolMode::PersonalDesktop ||
        licensing_->phase() != RdpLicensingPhase::AwaitServerDecision ||
        licensing_->decisionBranch() !=
            RdpLicensingDecisionBranch::
                PersonalDesktopCompletionRequired ||
        replySequence == 0U || replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pending_.size() - bytesWritten_)
    {
        close();
        return RdpPersonalDesktopValidClientWriteOutcome::Rejected;
    }

    if (acceptedBytes == 0U)
        return RdpPersonalDesktopValidClientWriteOutcome::Pending;

    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pending_.size())
    {
        if (!advanceWriteSliceSequence())
        {
            close();
            return RdpPersonalDesktopValidClientWriteOutcome::Rejected;
        }
        return RdpPersonalDesktopValidClientWriteOutcome::Pending;
    }

    if (!licensing_->onPersonalDesktopValidClientWritten())
    {
        close();
        return RdpPersonalDesktopValidClientWriteOutcome::Rejected;
    }

    pending_.fill(0U);
    bytesWritten_ = 0U;
    queued_ = false;
    delivered_ = true;
    return RdpPersonalDesktopValidClientWriteOutcome::Delivered;
}

void RdpPersonalDesktopValidClientWriteGate::close() noexcept
{
    pending_.fill(0U);
    bytesWritten_ = 0U;
    queued_ = false;
    delivered_ = false;
    closed_ = true;
    if (licensing_ != nullptr)
        licensing_->close();
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

bool RdpSlowPathInputPdu::eventAt(
    std::size_t index, RdpSlowPathInputEvent &event) const noexcept
{
    if (index >= eventCount ||
        eventBytes.size() !=
            static_cast<std::size_t>(eventCount) *
                kRdpSlowPathInputEventBytes)
        return false;

    const auto bytes = eventBytes.subspan(
        index * kRdpSlowPathInputEventBytes,
        kRdpSlowPathInputEventBytes);
    const std::uint16_t messageType = readLe16At(bytes, 4U);
    event = {};
    event.eventTime = readLe32At(bytes, 0U);

    switch (messageType)
    {
    case 0x0000U: // INPUT_EVENT_SYNC
        event.kind = RdpSlowPathInputEventKind::Synchronize;
        event.toggleFlags = readLe32At(bytes, 8U);
        return true;
    case 0x0002U: // INPUT_EVENT_UNUSED
        event.kind = RdpSlowPathInputEventKind::Unused;
        return true;
    case 0x0004U: // INPUT_EVENT_SCANCODE
        event.kind = RdpSlowPathInputEventKind::ScancodeKeyboard;
        event.keyboardFlags = readLe16At(bytes, 6U);
        event.keyCode = readLe16At(bytes, 8U);
        // The wire field is 16 bits, but RDP scancodes are 8-bit values.
        return event.keyCode <= 0xffU;
    case 0x0005U: // INPUT_EVENT_UNICODE
        event.kind = RdpSlowPathInputEventKind::UnicodeKeyboard;
        event.keyboardFlags = readLe16At(bytes, 6U);
        event.unicodeCode = readLe16At(bytes, 8U);
        return true;
    case 0x8001U: // INPUT_EVENT_MOUSE
        event.kind = RdpSlowPathInputEventKind::Mouse;
        event.pointerFlags = readLe16At(bytes, 6U);
        event.xPos = readLe16At(bytes, 8U);
        event.yPos = readLe16At(bytes, 10U);
        return true;
    case 0x8002U: // INPUT_EVENT_MOUSEX
        event.kind = RdpSlowPathInputEventKind::ExtendedMouse;
        event.pointerFlags = readLe16At(bytes, 6U);
        event.xPos = readLe16At(bytes, 8U);
        event.yPos = readLe16At(bytes, 10U);
        return true;
    case 0x8004U: // INPUT_EVENT_MOUSEREL
    {
        event.kind = RdpSlowPathInputEventKind::RelativeMouse;
        event.pointerFlags = readLe16At(bytes, 6U);
        const auto x = readLe16At(bytes, 8U);
        const auto y = readLe16At(bytes, 10U);
        event.xDelta = (x & 0x8000U) != 0U
                           ? static_cast<std::int32_t>(x) - 0x10000
                           : static_cast<std::int32_t>(x);
        event.yDelta = (y & 0x8000U) != 0U
                           ? static_cast<std::int32_t>(y) - 0x10000
                           : static_cast<std::int32_t>(y);
        return true;
    }
    default:
        return false;
    }
}

RdpSlowPathInputParseResult parseRdpSlowPathInputPdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    if (completeSharePdu.size() > kMaximumRdpSlowPathInputPduBytes)
        return {{}, RdpSlowPathInputError::TooManyEvents};

    const auto data = parseRdpShareDataHeader(completeSharePdu);
    if (!data)
        return {{}, RdpSlowPathInputError::InvalidShareData};
    if (data.value.pduType2 != 0x1cU)
        return {{}, RdpSlowPathInputError::WrongDataPduType};

    constexpr std::size_t prefixBytes = 4U;
    const auto body = data.value.body;
    if (body.size() < prefixBytes)
        return {{}, RdpSlowPathInputError::InvalidBodyLength};

    const std::uint16_t count = readLe16At(body, 0U);
    if (count > kMaximumRdpSlowPathInputEvents)
        return {{}, RdpSlowPathInputError::TooManyEvents};

    const std::size_t expectedBytes =
        prefixBytes +
        static_cast<std::size_t>(count) * kRdpSlowPathInputEventBytes;
    if (body.size() != expectedBytes)
        return {{}, RdpSlowPathInputError::InvalidBodyLength};

    RdpSlowPathInputPdu value{};
    value.pduSource = data.value.pduSource;
    value.shareId = data.value.shareId;
    value.eventCount = count;
    value.eventBytes = body.subspan(prefixBytes);

    RdpSlowPathInputEvent event{};
    for (std::size_t index = 0; index < count; ++index)
    {
        if (!value.eventAt(index, event))
            return {{}, RdpSlowPathInputError::UnknownEventType};
    }
    return {value, RdpSlowPathInputError::None};
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

RdpFontListParseResult parseRdpClientFontListPdu(
    std::span<const std::uint8_t> completeSharePdu) noexcept
{
    const auto data = parseRdpShareDataHeader(completeSharePdu);
    if (!data)
        return {};
    if (data.value.pduType2 != 0x27U)
        return {{}, RdpFontListError::WrongDataPduType};
    if (data.value.body.size() != 8U)
        return {{}, RdpFontListError::InvalidBodyLength};

    const auto readLe16 = [](std::span<const std::uint8_t> bytes,
                             std::size_t offset) noexcept
    {
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[offset]) |
            (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
    };
    RdpFontListPdu value{};
    value.pduSource = data.value.pduSource;
    value.shareId = data.value.shareId;
    value.numberFonts = readLe16(data.value.body, 0U);
    value.totalNumFonts = readLe16(data.value.body, 2U);
    value.listFlags = readLe16(data.value.body, 4U);
    value.entrySize = readLe16(data.value.body, 6U);
    return {value, RdpFontListError::None};
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

std::optional<std::size_t> encodeRdpServerFontMapPdu(
    std::uint32_t shareId,
    std::span<std::uint8_t> output) noexcept
{
    constexpr std::size_t size = 26U;
    if (shareId == 0U || output.size() < size)
        return std::nullopt;
    const auto bytes = output.first(size);
    writeServerShareDataHeader(bytes, 26U, shareId, 0x28U, 2U);
    writeLe16(bytes, 18U, 0U);
    writeLe16(bytes, 20U, 0U);
    writeLe16(bytes, 22U, 0x0003U);
    writeLe16(bytes, 24U, 0x0004U);
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

bool RdpShareActivationLifecycle::advanceReplySequence() noexcept
{
    if (replySequence_ == UINT64_MAX)
        return false;
    ++replySequence_;
    return replySequence_ != 0U;
}

bool RdpShareActivationLifecycle::advanceWriteSliceSequence() noexcept
{
    if (writeSliceSequence_ == UINT64_MAX)
        return false;
    ++writeSliceSequence_;
    return writeSliceSequence_ != 0U;
}

void RdpShareActivationLifecycle::fail() noexcept
{
    pending_.fill(0U);
    demandSharePdu_.fill(0U);
    clientCapabilitySets_.fill(0U);
    demandShareLength_ = 0U;
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    clientCapabilityBytes_ = 0U;
    clientCapabilityCount_ = 0U;
    serverSlowPathInputFlags_ = 0U;
    clientSlowPathInputFlags_ = 0U;
    negotiatedSlowPathInputFlags_ = 0U;
    clientCapabilitiesConfirmed_ = false;
    pendingKind_ = RdpShareServerWriteKind::None;
    serverVirtualChannelChunkBytes_ =
        kRdpStaticVirtualChannelDefaultChunkBytes;
    negotiatedVirtualChannelChunkBytes_ =
        kRdpStaticVirtualChannelDefaultChunkBytes;
    serverVirtualChannelChunkFieldPresent_ = false;
    phase_ = RdpShareActivationPhase::Failed;
}

void RdpShareActivationLifecycle::close() noexcept
{
    pending_.fill(0U);
    demandSharePdu_.fill(0U);
    clientCapabilitySets_.fill(0U);
    demandShareLength_ = 0U;
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    clientCapabilityBytes_ = 0U;
    clientCapabilityCount_ = 0U;
    serverSlowPathInputFlags_ = 0U;
    clientSlowPathInputFlags_ = 0U;
    negotiatedSlowPathInputFlags_ = 0U;
    clientCapabilitiesConfirmed_ = false;
    clientUserId_ = 0U;
    ioChannelId_ = 0U;
    shareId_ = 0U;
    pendingKind_ = RdpShareServerWriteKind::None;
    clientStage_ = ClientStage::ConfirmActive;
    demandDelivered_ = false;
    serverSynchronizeDelivered_ = false;
    serverCooperateDelivered_ = false;
    clientRequestControlSeen_ = false;
    serverGrantedControlDelivered_ = false;
    clientFontListSeen_ = false;
    serverVirtualChannelChunkBytes_ =
        kRdpStaticVirtualChannelDefaultChunkBytes;
    negotiatedVirtualChannelChunkBytes_ =
        kRdpStaticVirtualChannelDefaultChunkBytes;
    serverVirtualChannelChunkFieldPresent_ = false;
    phase_ = RdpShareActivationPhase::Closed;
}

bool RdpShareActivationLifecycle::queueSharePdu(
    RdpShareServerWriteKind kind,
    std::span<const std::uint8_t> sharePdu) noexcept
{
    if (kind == RdpShareServerWriteKind::None || sharePdu.empty() ||
        pendingLength_ != 0U || ioChannelId_ == 0U)
        return false;
    const auto packetBytes = encodeMcsSendDataIndication(
        1002U, ioChannelId_, 1U, 3U, sharePdu, pending_);
    if (!packetBytes || !advanceReplySequence() ||
        !advanceWriteSliceSequence())
        return false;
    pendingLength_ = *packetBytes;
    bytesWritten_ = 0U;
    pendingKind_ = kind;
    return true;
}

bool RdpShareActivationLifecycle::queueSynchronize() noexcept
{
    std::array<std::uint8_t, 22> pdu{};
    const auto bytes = encodeRdpServerSynchronizePdu(
        shareId_, static_cast<std::uint16_t>(clientUserId_), pdu);
    return bytes && queueSharePdu(
        RdpShareServerWriteKind::Synchronize,
        std::span<const std::uint8_t>{pdu}.first(*bytes));
}

bool RdpShareActivationLifecycle::queueCooperate() noexcept
{
    std::array<std::uint8_t, 26> pdu{};
    const auto bytes = encodeRdpServerControlPdu(
        shareId_, RdpControlAction::Cooperate, 0U, pdu);
    return bytes && queueSharePdu(
        RdpShareServerWriteKind::Cooperate,
        std::span<const std::uint8_t>{pdu}.first(*bytes));
}

bool RdpShareActivationLifecycle::queueGrantedControl() noexcept
{
    std::array<std::uint8_t, 26> pdu{};
    const auto bytes = encodeRdpServerControlPdu(
        shareId_, RdpControlAction::GrantedControl, clientUserId_, pdu);
    return bytes && queueSharePdu(
        RdpShareServerWriteKind::GrantedControl,
        std::span<const std::uint8_t>{pdu}.first(*bytes));
}

bool RdpShareActivationLifecycle::queueFontMap() noexcept
{
    std::array<std::uint8_t, 26> pdu{};
    const auto bytes = encodeRdpServerFontMapPdu(shareId_, pdu);
    return bytes && queueSharePdu(
        RdpShareServerWriteKind::FontMap,
        std::span<const std::uint8_t>{pdu}.first(*bytes));
}

bool RdpShareActivationLifecycle::begin(
    std::uint32_t clientUserId,
    std::uint16_t ioChannelId,
    std::uint32_t shareId,
    std::uint32_t sessionId,
    std::span<const std::uint8_t> sourceDescriptor,
    std::uint16_t capabilityCount,
    std::span<const std::uint8_t> capabilitySets) noexcept
{
    if (phase_ != RdpShareActivationPhase::NotStarted ||
        clientUserId < 1001U || clientUserId > 65535U ||
        ioChannelId == 0U || shareId == 0U)
    {
        fail();
        return false;
    }
    const auto virtualChannel =
        virtualChannelCapabilityInfo(
            capabilitySets, capabilityCount);
    const auto inputCapability =
        inputCapabilityInfo(capabilitySets, capabilityCount);
    if (!virtualChannel.valid || !inputCapability.valid)
    {
        fail();
        return false;
    }

    const auto demandBytes = encodeRdpDemandActivePdu(
        shareId, sessionId, sourceDescriptor, capabilityCount,
        capabilitySets, demandSharePdu_);
    if (!demandBytes)
    {
        fail();
        return false;
    }
    clientUserId_ = clientUserId;
    ioChannelId_ = ioChannelId;
    shareId_ = shareId;
    demandShareLength_ = *demandBytes;
    serverVirtualChannelChunkBytes_ =
        virtualChannel.serverToClientChunkBytes;
    serverVirtualChannelChunkFieldPresent_ =
        virtualChannel.chunkFieldPresent;
    negotiatedVirtualChannelChunkBytes_ =
        kRdpStaticVirtualChannelDefaultChunkBytes;
    serverSlowPathInputFlags_ =
        inputCapability.present ? inputCapability.flags : 0U;
    clientStage_ = ClientStage::ConfirmActive;
    if (!queueSharePdu(
            RdpShareServerWriteKind::DemandActive,
            std::span<const std::uint8_t>{demandSharePdu_}.first(
                demandShareLength_)))
    {
        fail();
        return false;
    }
    phase_ = RdpShareActivationPhase::DemandActivePending;
    return true;
}

RdpShareActivationWriteView
RdpShareActivationLifecycle::pendingServerWrite() const noexcept
{
    if (phase_ == RdpShareActivationPhase::Failed ||
        phase_ == RdpShareActivationPhase::Closed ||
        pendingLength_ == 0U || bytesWritten_ >= pendingLength_ ||
        pendingKind_ == RdpShareServerWriteKind::None)
        return {};
    return {
        std::span<const std::uint8_t>{pending_}
            .first(pendingLength_).subspan(bytesWritten_),
        pendingKind_, replySequence_, writeSliceSequence_};
}

RdpShareActivationWriteOutcome
RdpShareActivationLifecycle::onServerBytesWritten(
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (phase_ == RdpShareActivationPhase::Failed ||
        phase_ == RdpShareActivationPhase::Closed ||
        pendingLength_ == 0U ||
        replySequence == 0U || replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pendingLength_ - bytesWritten_)
    {
        fail();
        return RdpShareActivationWriteOutcome::Rejected;
    }
    if (acceptedBytes == 0U)
        return RdpShareActivationWriteOutcome::Pending;
    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pendingLength_)
    {
        if (!advanceWriteSliceSequence())
        {
            fail();
            return RdpShareActivationWriteOutcome::Rejected;
        }
        return RdpShareActivationWriteOutcome::Pending;
    }

    const auto completedKind = pendingKind_;
    pending_.fill(0U);
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    pendingKind_ = RdpShareServerWriteKind::None;

    switch (completedKind)
    {
    case RdpShareServerWriteKind::DemandActive:
        demandDelivered_ = true;
        phase_ = RdpShareActivationPhase::AwaitConfirmActive;
        break;
    case RdpShareServerWriteKind::Synchronize:
        serverSynchronizeDelivered_ = true;
        phase_ = RdpShareActivationPhase::Finalizing;
        if (!queueCooperate())
        {
            fail();
            return RdpShareActivationWriteOutcome::Rejected;
        }
        break;
    case RdpShareServerWriteKind::Cooperate:
        serverCooperateDelivered_ = true;
        if (clientRequestControlSeen_ && !queueGrantedControl())
        {
            fail();
            return RdpShareActivationWriteOutcome::Rejected;
        }
        break;
    case RdpShareServerWriteKind::GrantedControl:
        serverGrantedControlDelivered_ = true;
        if (clientFontListSeen_ && !queueFontMap())
        {
            fail();
            return RdpShareActivationWriteOutcome::Rejected;
        }
        break;
    case RdpShareServerWriteKind::FontMap:
        if (!clientFontListSeen_ ||
            clientStage_ != ClientStage::Complete)
        {
            fail();
            return RdpShareActivationWriteOutcome::Rejected;
        }
        phase_ = RdpShareActivationPhase::Activated;
        return RdpShareActivationWriteOutcome::Activated;
    case RdpShareServerWriteKind::None:
        fail();
        return RdpShareActivationWriteOutcome::Rejected;
    }
    return RdpShareActivationWriteOutcome::Delivered;
}

RdpShareActivationClientIntake
RdpShareActivationLifecycle::onClientTpkt(
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (phase_ == RdpShareActivationPhase::Closed)
        return RdpShareActivationClientIntake::Closed;
    if (phase_ == RdpShareActivationPhase::Failed ||
        !demandDelivered_ ||
        (phase_ != RdpShareActivationPhase::AwaitConfirmActive &&
         phase_ != RdpShareActivationPhase::Finalizing))
    {
        fail();
        return RdpShareActivationClientIntake::Rejected;
    }

    const auto parsed = parseMcsChannelRequest(completeTpkt);
    if (!parsed ||
        parsed.request.kind != McsChannelRequestKind::SendDataRequest ||
        parsed.request.initiator != clientUserId_ ||
        parsed.request.channelId != ioChannelId_ ||
        parsed.request.segmentation != 3U)
    {
        fail();
        return RdpShareActivationClientIntake::Rejected;
    }

    const auto sharePdu = parsed.request.userData;
    if (clientStage_ != ClientStage::ConfirmActive)
    {
        const auto input = parseRdpSlowPathInputPdu(sharePdu);
        if (input)
        {
            if (input.value.pduSource != clientUserId_ ||
                input.value.shareId != shareId_ ||
                !slowPathInputAllowed(
                    input.value, negotiatedSlowPathInputFlags_))
            {
                fail();
                return RdpShareActivationClientIntake::Rejected;
            }
            // Protocol-valid early input is consumed but never dispatched
            // until Share activation and the native authorization path exist.
            return RdpShareActivationClientIntake::
                InputIgnoredUntilActivated;
        }
    }

    switch (clientStage_)
    {
    case ClientStage::ConfirmActive:
    {
        if (correlateRdpActiveExchange(
                std::span<const std::uint8_t>{demandSharePdu_}.first(
                    demandShareLength_),
                sharePdu, clientUserId_) !=
            RdpActiveExchangeCorrelation::ConsistentSyntaxOnly)
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        const auto clientActive = parseRdpActivePdu(sharePdu);
        if (!clientActive)
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        const auto clientVirtualChannel =
            virtualChannelCapabilityInfo(
                clientActive.value.capabilitySets,
                clientActive.value.capabilityCount);
        const auto clientInputCapability =
            inputCapabilityInfo(
                clientActive.value.capabilitySets,
                clientActive.value.capabilityCount);
        if (!clientVirtualChannel.valid || !clientInputCapability.valid ||
            clientActive.value.capabilitySets.size() >
                clientCapabilitySets_.size())
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        negotiatedVirtualChannelChunkBytes_ =
            serverVirtualChannelChunkFieldPresent_ &&
                    clientVirtualChannel.chunkFieldPresent
                ? serverVirtualChannelChunkBytes_
                : kRdpStaticVirtualChannelDefaultChunkBytes;

        clientCapabilitySets_.fill(0U);
        std::copy(
            clientActive.value.capabilitySets.begin(),
            clientActive.value.capabilitySets.end(),
            clientCapabilitySets_.begin());
        clientCapabilityBytes_ =
            clientActive.value.capabilitySets.size();
        clientCapabilityCount_ = clientActive.value.capabilityCount;
        clientSlowPathInputFlags_ =
            clientInputCapability.present ? clientInputCapability.flags : 0U;
        negotiatedSlowPathInputFlags_ =
            static_cast<std::uint16_t>(
                serverSlowPathInputFlags_ & clientSlowPathInputFlags_);
        clientCapabilitiesConfirmed_ = true;

        clientStage_ = ClientStage::Synchronize;
        phase_ = RdpShareActivationPhase::Finalizing;
        if (!queueSynchronize())
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        return RdpShareActivationClientIntake::ConfirmActiveAccepted;
    }

    case ClientStage::Synchronize:
    {
        const auto sync = parseRdpSynchronizePdu(sharePdu);
        if (!sync || sync.value.pduSource != clientUserId_ ||
            sync.value.shareId != shareId_ ||
            sync.value.targetUser != 1002U)
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        clientStage_ = ClientStage::Cooperate;
        return RdpShareActivationClientIntake::SynchronizeAccepted;
    }
    case ClientStage::Cooperate:
    {
        const auto control = parseRdpControlPdu(sharePdu);
        if (!control || control.value.pduSource != clientUserId_ ||
            control.value.shareId != shareId_ ||
            control.value.action != RdpControlAction::Cooperate ||
            control.value.grantId != 0U ||
            control.value.controlId != 0U)
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        clientStage_ = ClientStage::RequestControl;
        return RdpShareActivationClientIntake::CooperateAccepted;
    }
    case ClientStage::RequestControl:
    {
        const auto control = parseRdpControlPdu(sharePdu);
        if (!control || control.value.pduSource != clientUserId_ ||
            control.value.shareId != shareId_ ||
            control.value.action != RdpControlAction::RequestControl ||
            control.value.grantId != 0U ||
            control.value.controlId != 0U)
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        clientRequestControlSeen_ = true;
        clientStage_ = ClientStage::FontList;
        if (serverCooperateDelivered_ && pendingLength_ == 0U &&
            !queueGrantedControl())
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        return RdpShareActivationClientIntake::RequestControlAccepted;
    }
    case ClientStage::FontList:
    {
        const auto fontList = parseRdpClientFontListPdu(sharePdu);
        if (!fontList ||
            fontList.value.pduSource != clientUserId_ ||
            fontList.value.shareId != shareId_)
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        clientFontListSeen_ = true;
        clientStage_ = ClientStage::Complete;
        if (serverGrantedControlDelivered_ && pendingLength_ == 0U &&
            !queueFontMap())
        {
            fail();
            return RdpShareActivationClientIntake::Rejected;
        }
        return RdpShareActivationClientIntake::FontListAccepted;
    }
    case ClientStage::Complete:
        fail();
        return RdpShareActivationClientIntake::Rejected;
    }
    fail();
    return RdpShareActivationClientIntake::Rejected;
}

} // namespace rdp_server::server::transport
