// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::tests::ntlm_type2_conformance
{

using ByteSpan = std::span<const std::uint8_t>;

inline constexpr std::uint32_t kNegotiateUnicode = 0x00000001U;
inline constexpr std::uint32_t kNegotiateOem = 0x00000002U;
inline constexpr std::uint32_t kRequestTarget = 0x00000004U;
inline constexpr std::uint32_t kNegotiateSign = 0x00000010U;
inline constexpr std::uint32_t kNegotiateSeal = 0x00000020U;
inline constexpr std::uint32_t kNegotiateNtlm = 0x00000200U;
inline constexpr std::uint32_t kNegotiateAlwaysSign = 0x00008000U;
inline constexpr std::uint32_t kTargetTypeDomain = 0x00010000U;
inline constexpr std::uint32_t kTargetTypeServer = 0x00020000U;
inline constexpr std::uint32_t kExtendedSessionSecurity = 0x00080000U;
inline constexpr std::uint32_t kNegotiateTargetInfo = 0x00800000U;
inline constexpr std::uint32_t kNegotiateVersion = 0x02000000U;
inline constexpr std::uint32_t kNegotiate128 = 0x20000000U;
inline constexpr std::uint32_t kNegotiateKeyExchange = 0x40000000U;
inline constexpr std::uint32_t kNegotiate56 = 0x80000000U;

inline constexpr std::uint16_t kMsvAvEol = 0U;
inline constexpr std::uint16_t kMsvAvNbComputerName = 1U;
inline constexpr std::uint16_t kMsvAvNbDomainName = 2U;
inline constexpr std::uint16_t kMsvAvTimestamp = 7U;

struct ParsedChallenge final
{
    std::array<std::uint8_t, 8> challenge{};
    std::uint32_t flags{};
    ByteSpan targetName{};
    ByteSpan targetInfo{};
    std::size_t targetNameOffset{};
    std::size_t targetInfoOffset{};
};

[[nodiscard]] constexpr std::uint16_t loadLe16(
    const std::uint8_t* bytes) noexcept
{
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[0]) |
        (static_cast<std::uint16_t>(bytes[1]) << 8U));
}

[[nodiscard]] constexpr std::uint32_t loadLe32(
    const std::uint8_t* bytes) noexcept
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

struct SecurityBuffer final
{
    ByteSpan bytes{};
    std::size_t offset{};
};

[[nodiscard]] inline bool readSecurityBuffer(
    ByteSpan message,
    std::size_t descriptorOffset,
    std::size_t payloadFloor,
    SecurityBuffer& output) noexcept
{
    output = {};
    if (descriptorOffset > message.size() ||
        message.size() - descriptorOffset < 8U)
    {
        return false;
    }

    const std::size_t length = loadLe16(message.data() + descriptorOffset);
    const std::size_t maximum =
        loadLe16(message.data() + descriptorOffset + 2U);
    const std::size_t offset =
        loadLe32(message.data() + descriptorOffset + 4U);
    if (length != maximum || length == 0U ||
        offset < payloadFloor || offset > message.size() ||
        length > message.size() - offset)
    {
        return false;
    }

    output.bytes = message.subspan(offset, length);
    output.offset = offset;
    return true;
}

[[nodiscard]] inline bool rangesOverlap(
    const SecurityBuffer& left,
    const SecurityBuffer& right) noexcept
{
    const std::size_t leftEnd = left.offset + left.bytes.size();
    const std::size_t rightEnd = right.offset + right.bytes.size();
    return left.offset < rightEnd && right.offset < leftEnd;
}

[[nodiscard]] inline bool validUtf16LittleEndian(ByteSpan bytes) noexcept
{
    if (bytes.empty() || (bytes.size() & 1U) != 0U)
        return false;

    for (std::size_t offset = 0U; offset < bytes.size(); offset += 2U)
    {
        const std::uint16_t code = loadLe16(bytes.data() + offset);
        if (code == 0U)
            return false;

        if (code >= 0xd800U && code <= 0xdbffU)
        {
            offset += 2U;
            if (offset >= bytes.size())
                return false;
            const std::uint16_t low = loadLe16(bytes.data() + offset);
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

[[nodiscard]] inline bool parseTargetInfo(
    ByteSpan targetInfo,
    ByteSpan targetName) noexcept
{
    ByteSpan computerName{};
    ByteSpan domainName{};
    bool sawTimestamp = false;
    bool sawEol = false;
    std::size_t offset = 0U;

    while (offset <= targetInfo.size())
    {
        if (targetInfo.size() - offset < 4U)
            return false;

        const std::uint16_t id = loadLe16(targetInfo.data() + offset);
        const std::size_t length =
            loadLe16(targetInfo.data() + offset + 2U);
        offset += 4U;
        if (length > targetInfo.size() - offset)
            return false;

        const ByteSpan value = targetInfo.subspan(offset, length);
        offset += length;

        if (id == kMsvAvEol)
        {
            if (length != 0U || offset != targetInfo.size())
                return false;
            sawEol = true;
            break;
        }

        if (id == kMsvAvNbComputerName)
        {
            if (!computerName.empty() || !validUtf16LittleEndian(value))
                return false;
            computerName = value;
        }
        else if (id == kMsvAvNbDomainName)
        {
            if (!domainName.empty() || !validUtf16LittleEndian(value))
                return false;
            domainName = value;
        }
        else if (id == kMsvAvTimestamp)
        {
            if (sawTimestamp || length != 8U ||
                std::ranges::all_of(
                    value, [](std::uint8_t byte) { return byte == 0U; }))
            {
                return false;
            }
            sawTimestamp = true;
        }
    }

    return sawEol && sawTimestamp &&
           !computerName.empty() && !domainName.empty() &&
           computerName.size() == targetName.size() &&
           std::equal(
               computerName.begin(), computerName.end(), targetName.begin());
}

[[nodiscard]] inline bool parseConformantChallenge(
    ByteSpan message,
    ParsedChallenge& output) noexcept
{
    output = {};
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    if (message.size() < 56U ||
        !std::equal(signature.begin(), signature.end(), message.begin()) ||
        loadLe32(message.data() + 8U) != 2U)
    {
        return false;
    }

    const std::uint32_t flags = loadLe32(message.data() + 20U);
    constexpr std::uint32_t requiredFlags =
        kNegotiateUnicode |
        kRequestTarget |
        kNegotiateSign |
        kNegotiateSeal |
        kNegotiateNtlm |
        kTargetTypeServer |
        kExtendedSessionSecurity |
        kNegotiateTargetInfo |
        kNegotiate128;
    constexpr std::uint32_t allowedFlags =
        requiredFlags |
        kNegotiateOem |
        kNegotiateAlwaysSign |
        kTargetTypeDomain |
        kNegotiateVersion |
        kNegotiateKeyExchange |
        kNegotiate56;
    if ((flags & requiredFlags) != requiredFlags ||
        (flags & ~allowedFlags) != 0U ||
        (flags & kTargetTypeDomain) != 0U)
    {
        return false;
    }

    const ByteSpan version = message.subspan(48U, 8U);
    if ((flags & kNegotiateVersion) != 0U)
    {
        // VERSION is debugging-only protocol metadata. A negotiated profile
        // still has to use the fixed reserved bytes and NTLMSSP revision.
        if (version[4U] != 0U || version[5U] != 0U ||
            version[6U] != 0U || version[7U] != 0x0fU)
        {
            return false;
        }
    }
    else if (!std::ranges::all_of(
                 version,
                 [](std::uint8_t byte) { return byte == 0U; }))
    {
        return false;
    }

    SecurityBuffer targetName;
    SecurityBuffer targetInfo;
    constexpr std::size_t payloadFloor = 56U;
    if (!readSecurityBuffer(
            message, 12U, payloadFloor, targetName) ||
        !readSecurityBuffer(
            message, 40U, payloadFloor, targetInfo) ||
        rangesOverlap(targetName, targetInfo) ||
        !validUtf16LittleEndian(targetName.bytes))
    {
        return false;
    }

    const std::size_t targetNameEnd =
        targetName.offset + targetName.bytes.size();
    const std::size_t targetInfoEnd =
        targetInfo.offset + targetInfo.bytes.size();
    if ((std::max)(targetNameEnd, targetInfoEnd) != message.size() ||
        !parseTargetInfo(targetInfo.bytes, targetName.bytes))
    {
        return false;
    }

    std::copy_n(
        message.begin() + 24,
        output.challenge.size(),
        output.challenge.begin());
    if (std::ranges::all_of(
            output.challenge,
            [](std::uint8_t byte) { return byte == 0U; }))
    {
        output = {};
        return false;
    }

    output.flags = flags;
    output.targetName = targetName.bytes;
    output.targetInfo = targetInfo.bytes;
    output.targetNameOffset = targetName.offset;
    output.targetInfoOffset = targetInfo.offset;
    return true;
}

[[nodiscard]] inline bool utf16LittleEndianEquals(
    ByteSpan bytes,
    std::u16string_view expected) noexcept
{
    if (bytes.size() != expected.size() * 2U)
        return false;
    for (std::size_t index = 0U; index < expected.size(); ++index)
    {
        if (loadLe16(bytes.data() + index * 2U) !=
            static_cast<std::uint16_t>(expected[index]))
        {
            return false;
        }
    }
    return true;
}

} // namespace rdp_server::tests::ntlm_type2_conformance
