// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_ntlmssp.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{
namespace
{

using ByteSpan = std::span<const std::uint8_t>;

constexpr std::array<std::uint8_t, 8> kNtlmSignature{
    'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
constexpr std::size_t kNegotiateHeaderBytes = 40U;
constexpr std::size_t kChallengeHeaderBytes = 56U;
constexpr std::size_t kAuthenticateHeaderBytes = 72U;
constexpr std::size_t kNtlmMicBytes = 16U;
constexpr std::size_t kSecurityBufferBytes = 8U;
constexpr std::size_t kNtlmV2ProofBytes = 16U;
constexpr std::size_t kNtlmV2BlobPrefixBytes = 28U;
constexpr std::size_t kNtlmV2FinalReservedBytes = 4U;
constexpr std::uint16_t kMsvAvEol = 0U;
constexpr std::uint16_t kMsvAvNbComputerName = 1U;
constexpr std::uint16_t kMsvAvNbDomainName = 2U;
constexpr std::uint16_t kMsvAvFlags = 6U;
constexpr std::uint16_t kMsvAvTimestamp = 7U;
constexpr std::uint32_t kMsvAvMicPresent = 0x00000002U;

struct SecurityBuffer final
{
    ByteSpan bytes{};
    std::size_t offset{};
};

[[nodiscard]] constexpr std::uint16_t loadLe16(
    const std::uint8_t *bytes) noexcept
{
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[0]) |
        (static_cast<std::uint16_t>(bytes[1]) << 8U));
}

[[nodiscard]] constexpr std::uint32_t loadLe32(
    const std::uint8_t *bytes) noexcept
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

constexpr void storeLe16(
    std::uint8_t *output, std::uint16_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
}

constexpr void storeLe32(
    std::uint8_t *output, std::uint32_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
    output[2] = static_cast<std::uint8_t>(value >> 16U);
    output[3] = static_cast<std::uint8_t>(value >> 24U);
}

constexpr void storeLe64(
    std::uint8_t *output, std::uint64_t value) noexcept
{
    for (std::size_t index = 0; index < 8U; ++index)
        output[index] =
            static_cast<std::uint8_t>(value >> (index * 8U));
}

[[nodiscard]] bool allZero(ByteSpan bytes) noexcept
{
    std::uint8_t combined = 0;
    for (const std::uint8_t byte : bytes)
        combined |= byte;
    return combined == 0U;
}

[[nodiscard]] bool readSecurityBuffer(
    ByteSpan message,
    std::size_t fieldOffset,
    std::size_t payloadFloor,
    SecurityBuffer &output) noexcept
{
    output = {};
    if (fieldOffset > message.size() ||
        message.size() - fieldOffset < kSecurityBufferBytes)
    {
        return false;
    }

    const std::size_t length = loadLe16(message.data() + fieldOffset);
    const std::size_t offset =
        loadLe32(message.data() + fieldOffset + 4U);
    if (length == 0U)
        return true;
    if (offset < payloadFloor || offset > message.size() ||
        length > message.size() - offset)
    {
        return false;
    }

    output.bytes = message.subspan(offset, length);
    output.offset = offset;
    return true;
}

[[nodiscard]] bool rangesOverlap(
    const SecurityBuffer &left,
    const SecurityBuffer &right) noexcept
{
    if (left.bytes.empty() || right.bytes.empty())
        return false;
    const std::size_t leftEnd = left.offset + left.bytes.size();
    const std::size_t rightEnd = right.offset + right.bytes.size();
    return left.offset < rightEnd && right.offset < leftEnd;
}

template <std::size_t Count>
[[nodiscard]] bool buffersDoNotOverlap(
    const std::array<SecurityBuffer, Count> &buffers) noexcept
{
    for (std::size_t left = 0; left < buffers.size(); ++left)
    {
        for (std::size_t right = left + 1U;
             right < buffers.size(); ++right)
        {
            if (rangesOverlap(buffers[left], buffers[right]))
                return false;
        }
    }
    return true;
}

[[nodiscard]] bool validUtf16(
    std::u16string_view value, bool allowEmpty) noexcept
{
    if (!allowEmpty && value.empty())
        return false;

    for (std::size_t index = 0; index < value.size(); ++index)
    {
        const std::uint16_t code =
            static_cast<std::uint16_t>(value[index]);
        if (code == 0U)
            return false;
        if (code >= 0xd800U && code <= 0xdbffU)
        {
            if (++index >= value.size())
                return false;
            const std::uint16_t low =
                static_cast<std::uint16_t>(value[index]);
            if (low < 0xdc00U || low > 0xdfffU)
                return false;
        }
        else if (code >= 0xdc00U && code <= 0xdfffU)
        {
            return false;
        }
    }
    return true;
}

template <std::size_t Capacity>
[[nodiscard]] bool decodeUtf16LittleEndian(
    ByteSpan bytes,
    std::array<char16_t, Capacity> &output,
    std::size_t &outputLength,
    bool allowEmpty) noexcept
{
    output.fill(u'\0');
    outputLength = 0;
    if ((bytes.size() & 1U) != 0U)
        return false;

    const std::size_t codeUnits = bytes.size() / 2U;
    if (codeUnits >= Capacity)
        return false;

    for (std::size_t index = 0; index < codeUnits; ++index)
    {
        output[index] = static_cast<char16_t>(
            loadLe16(bytes.data() + index * 2U));
    }

    const std::u16string_view decoded{output.data(), codeUnits};
    if (!validUtf16(decoded, allowEmpty))
    {
        output.fill(u'\0');
        return false;
    }
    outputLength = codeUnits;
    return true;
}

void writeUtf16LittleEndian(
    std::u16string_view value, std::uint8_t *output) noexcept
{
    for (std::size_t index = 0; index < value.size(); ++index)
    {
        storeLe16(
            output + index * 2U,
            static_cast<std::uint16_t>(value[index]));
    }
}

[[nodiscard]] bool readMicRequirement(
    ByteSpan ntChallengeResponse,
    bool &micPresent) noexcept
{
    micPresent = false;
    constexpr std::size_t minimumBlobBytes =
        kNtlmV2BlobPrefixBytes + 4U + kNtlmV2FinalReservedBytes;
    if (ntChallengeResponse.size() <
            kNtlmV2ProofBytes + minimumBlobBytes ||
        ntChallengeResponse.size() >
            kMaximumNtlmV2ChallengeResponseBytes)
    {
        return false;
    }

    const ByteSpan blob =
        ntChallengeResponse.subspan(kNtlmV2ProofBytes);
    if (blob[0] != 1U || blob[1] != 1U ||
        !allZero(blob.subspan(2U, 6U)) ||
        !allZero(blob.subspan(24U, 4U)) ||
        !allZero(blob.last(kNtlmV2FinalReservedBytes)))
    {
        return false;
    }

    const std::size_t avEnd =
        blob.size() - kNtlmV2FinalReservedBytes;
    std::size_t offset = kNtlmV2BlobPrefixBytes;
    bool sawFlags = false;
    while (offset + 4U <= avEnd)
    {
        const std::uint16_t avId = loadLe16(blob.data() + offset);
        const std::uint16_t avLength =
            loadLe16(blob.data() + offset + 2U);
        offset += 4U;

        if (avId == kMsvAvEol)
            return avLength == 0U && offset == avEnd;
        if (avLength > avEnd - offset)
            return false;

        if (avId == kMsvAvFlags)
        {
            if (sawFlags || avLength != 4U)
                return false;
            sawFlags = true;
            micPresent =
                (loadLe32(blob.data() + offset) &
                 kMsvAvMicPresent) != 0U;
        }
        offset += avLength;
    }
    return false;
}

[[nodiscard]] bool validChallengeName(
    std::u16string_view value,
    std::size_t maximumCodeUnits) noexcept
{
    return !value.empty() &&
           value.size() <= maximumCodeUnits &&
           validUtf16(value, false);
}

} // namespace

NtlmMessageParseResult parseNtlmNegotiateMessage(
    std::span<const std::uint8_t> message,
    NtlmNegotiateMessage &output) noexcept
{
    output = {};
    if (message.size() < kNegotiateHeaderBytes ||
        message.size() > kMaximumStandaloneNtlmMessageBytes)
    {
        return NtlmMessageParseResult::InvalidInput;
    }
    if (!std::equal(
            kNtlmSignature.begin(), kNtlmSignature.end(),
            message.begin()))
    {
        return NtlmMessageParseResult::InvalidSignature;
    }
    if (loadLe32(message.data() + 8U) != 1U)
        return NtlmMessageParseResult::WrongMessageType;

    const std::uint32_t flags = loadLe32(message.data() + 12U);
    const std::size_t headerBytes = kNegotiateHeaderBytes;
    if ((flags & kNtlmNegotiateVersion) == 0U &&
        !allZero(message.subspan(32U, 8U)))
    {
        return NtlmMessageParseResult::InvalidInput;
    }

    SecurityBuffer domain;
    SecurityBuffer workstation;
    if ((flags & kNtlmNegotiateOemDomainSupplied) != 0U &&
        !readSecurityBuffer(message, 16U, headerBytes, domain))
    {
        return NtlmMessageParseResult::InvalidSecurityBuffer;
    }
    if ((flags & kNtlmNegotiateOemWorkstationSupplied) != 0U &&
        !readSecurityBuffer(message, 24U, headerBytes, workstation))
    {
        return NtlmMessageParseResult::InvalidSecurityBuffer;
    }
    if (rangesOverlap(domain, workstation))
        return NtlmMessageParseResult::InvalidSecurityBuffer;

    output.negotiateFlags = flags;
    return NtlmMessageParseResult::Parsed;
}

NtlmChallengeEncodeResult encodeNtlmChallengeMessage(
    const NtlmChallengeMessageParameters &parameters,
    std::span<std::uint8_t> output) noexcept
{
    NtlmChallengeEncodeResult result{};
    if (!validChallengeName(
            parameters.netbiosDomainName,
            kMaximumStandaloneNtlmDomainCodeUnits) ||
        !validChallengeName(
            parameters.netbiosComputerName,
            kMaximumStandaloneNtlmUserCodeUnits) ||
        parameters.timestampFileTime == 0U ||
        allZero(ByteSpan{
            parameters.serverChallenge.data(),
            parameters.serverChallenge.size()}))
    {
        result.status = NtlmChallengeEncodeStatus::InvalidInput;
        return result;
    }

    constexpr std::uint32_t requiredClientFlags =
        kNtlmNegotiateUnicode | kNtlmNegotiateNtlm |
        kRequiredStandaloneCredSspNtlmFlags;
    if ((parameters.clientNegotiateFlags & requiredClientFlags) !=
        requiredClientFlags)
    {
        result.status = NtlmChallengeEncodeStatus::UnsupportedFlags;
        return result;
    }

    const std::size_t domainBytes =
        parameters.netbiosDomainName.size() * 2U;
    const std::size_t computerBytes =
        parameters.netbiosComputerName.size() * 2U;
    const std::size_t targetInfoBytes =
        4U + domainBytes +
        4U + computerBytes +
        4U + 8U +
        4U;
    const std::size_t totalBytes =
        kChallengeHeaderBytes + targetInfoBytes;
    if (domainBytes > 0xffffU || computerBytes > 0xffffU ||
        targetInfoBytes > 0xffffU ||
        totalBytes > kMaximumStandaloneNtlmMessageBytes)
    {
        result.status = NtlmChallengeEncodeStatus::InvalidInput;
        return result;
    }
    if (output.size() < totalBytes)
    {
        result.status = NtlmChallengeEncodeStatus::OutputTooSmall;
        return result;
    }

    std::uint32_t selectedFlags =
        requiredClientFlags |
        kNtlmTargetTypeServer |
        kNtlmNegotiateTargetInfo;
    constexpr std::uint32_t optionalClientFlags =
        kNtlmNegotiateOem |
        kNtlmNegotiateAlwaysSign |
        kNtlmNegotiateKeyExchange |
        kNtlmNegotiate56;
    selectedFlags |=
        parameters.clientNegotiateFlags & optionalClientFlags;
    selectedFlags &= ~(kNtlmNegotiateVersion | kNtlmRequestTarget);

    std::fill_n(output.begin(), totalBytes, std::uint8_t{0});
    std::copy(
        kNtlmSignature.begin(), kNtlmSignature.end(),
        output.begin());
    storeLe32(output.data() + 8U, 2U);
    storeLe32(
        output.data() + 16U,
        static_cast<std::uint32_t>(kChallengeHeaderBytes));
    storeLe32(output.data() + 20U, selectedFlags);
    std::copy(
        parameters.serverChallenge.begin(),
        parameters.serverChallenge.end(),
        output.begin() + 24);

    storeLe16(
        output.data() + 40U,
        static_cast<std::uint16_t>(targetInfoBytes));
    storeLe16(
        output.data() + 42U,
        static_cast<std::uint16_t>(targetInfoBytes));
    storeLe32(
        output.data() + 44U,
        static_cast<std::uint32_t>(kChallengeHeaderBytes));

    std::size_t offset = kChallengeHeaderBytes;
    storeLe16(output.data() + offset, kMsvAvNbDomainName);
    storeLe16(
        output.data() + offset + 2U,
        static_cast<std::uint16_t>(domainBytes));
    offset += 4U;
    writeUtf16LittleEndian(
        parameters.netbiosDomainName, output.data() + offset);
    offset += domainBytes;

    storeLe16(output.data() + offset, kMsvAvNbComputerName);
    storeLe16(
        output.data() + offset + 2U,
        static_cast<std::uint16_t>(computerBytes));
    offset += 4U;
    writeUtf16LittleEndian(
        parameters.netbiosComputerName, output.data() + offset);
    offset += computerBytes;

    storeLe16(output.data() + offset, kMsvAvTimestamp);
    storeLe16(output.data() + offset + 2U, 8U);
    storeLe64(
        output.data() + offset + 4U,
        parameters.timestampFileTime);
    offset += 12U;

    storeLe16(output.data() + offset, kMsvAvEol);
    storeLe16(output.data() + offset + 2U, 0U);
    offset += 4U;

    if (offset != totalBytes)
    {
        std::fill_n(output.begin(), totalBytes, std::uint8_t{0});
        result.status = NtlmChallengeEncodeStatus::InvalidInput;
        return result;
    }

    result.status = NtlmChallengeEncodeStatus::Encoded;
    result.bytesWritten = totalBytes;
    result.negotiateFlags = selectedFlags;
    return result;
}

NtlmMessageParseResult parseNtlmAuthenticateMessage(
    std::span<const std::uint8_t> message,
    NtlmAuthenticateMessage &output) noexcept
{
    output = {};
    if (message.size() < kAuthenticateHeaderBytes ||
        message.size() > kMaximumStandaloneNtlmMessageBytes)
    {
        return NtlmMessageParseResult::InvalidInput;
    }
    if (!std::equal(
            kNtlmSignature.begin(), kNtlmSignature.end(),
            message.begin()))
    {
        return NtlmMessageParseResult::InvalidSignature;
    }
    if (loadLe32(message.data() + 8U) != 3U)
        return NtlmMessageParseResult::WrongMessageType;

    const std::uint32_t flags = loadLe32(message.data() + 60U);
    if ((flags & kNtlmNegotiateUnicode) == 0U ||
        (flags & kNtlmNegotiateNtlm) == 0U)
    {
        return NtlmMessageParseResult::UnsupportedFlags;
    }

    const std::size_t baseHeaderBytes = kAuthenticateHeaderBytes;
    if ((flags & kNtlmNegotiateVersion) == 0U &&
        !allZero(message.subspan(64U, 8U)))
    {
        return NtlmMessageParseResult::InvalidInput;
    }

    SecurityBuffer preliminaryNtResponse;
    if (!readSecurityBuffer(
            message, 20U, baseHeaderBytes,
            preliminaryNtResponse))
    {
        return NtlmMessageParseResult::InvalidSecurityBuffer;
    }

    bool micPresent = false;
    if (!readMicRequirement(
            preliminaryNtResponse.bytes, micPresent))
    {
        return NtlmMessageParseResult::InvalidNtlmV2Response;
    }

    const std::size_t payloadFloor =
        baseHeaderBytes + (micPresent ? kNtlmMicBytes : 0U);
    if (message.size() < payloadFloor)
        return NtlmMessageParseResult::InvalidInput;

    std::array<SecurityBuffer, 6> buffers{};
    if (!readSecurityBuffer(message, 12U, payloadFloor, buffers[0]) ||
        !readSecurityBuffer(message, 20U, payloadFloor, buffers[1]) ||
        !readSecurityBuffer(message, 28U, payloadFloor, buffers[2]) ||
        !readSecurityBuffer(message, 36U, payloadFloor, buffers[3]) ||
        !readSecurityBuffer(message, 44U, payloadFloor, buffers[4]) ||
        !readSecurityBuffer(message, 52U, payloadFloor, buffers[5]) ||
        !buffersDoNotOverlap(buffers))
    {
        return NtlmMessageParseResult::InvalidSecurityBuffer;
    }

    const auto &lmResponse = buffers[0];
    const auto &ntResponse = buffers[1];
    const auto &domain = buffers[2];
    const auto &username = buffers[3];
    const auto &workstation = buffers[4];
    const auto &encryptedSessionKey = buffers[5];

    if ((!lmResponse.bytes.empty() &&
         lmResponse.bytes.size() != 24U) ||
        ntResponse.bytes.size() <
            kNtlmV2ProofBytes + 36U ||
        ntResponse.bytes.size() >
            kMaximumNtlmV2ChallengeResponseBytes)
    {
        return NtlmMessageParseResult::InvalidNtlmV2Response;
    }

    if ((!domain.bytes.empty() && (domain.offset & 1U) != 0U) ||
        (!username.bytes.empty() && (username.offset & 1U) != 0U) ||
        (!workstation.bytes.empty() &&
         (workstation.offset & 1U) != 0U))
    {
        return NtlmMessageParseResult::InvalidEncoding;
    }

    std::array<char16_t, kMaximumStandaloneNtlmUserCodeUnits + 1U>
        workstationStorage{};
    std::size_t workstationLength = 0;
    if (!decodeUtf16LittleEndian(
            domain.bytes,
            output.domainStorage,
            output.domainLength,
            true) ||
        !decodeUtf16LittleEndian(
            username.bytes,
            output.usernameStorage,
            output.usernameLength,
            false) ||
        !decodeUtf16LittleEndian(
            workstation.bytes,
            workstationStorage,
            workstationLength,
            true))
    {
        return NtlmMessageParseResult::InvalidEncoding;
    }
    (void)workstationLength;

    const bool keyExchange =
        (flags & kNtlmNegotiateKeyExchange) != 0U;
    if ((keyExchange &&
         encryptedSessionKey.bytes.size() != kNtlmV2KeyBytes) ||
        (!keyExchange && !encryptedSessionKey.bytes.empty()))
    {
        return NtlmMessageParseResult::InvalidSecurityBuffer;
    }

    output.ntChallengeResponse = ntResponse.bytes;
    output.encryptedRandomSessionKey = encryptedSessionKey.bytes;
    output.messageIntegrityCode = micPresent
        ? message.subspan(baseHeaderBytes, kNtlmMicBytes)
        : ByteSpan{};
    output.negotiateFlags = flags;
    return NtlmMessageParseResult::Parsed;
}

} // namespace rdp_server::server::security
