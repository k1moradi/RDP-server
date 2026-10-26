// SPDX-License-Identifier: GPL-3.0-or-later
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sspi.h>

#include "server/security/standalone_ntlmssp.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>

using namespace rdp_server::server::security;

namespace
{

enum class TargetProfile : std::uint8_t
{
    PortableServerName,
    PhysicalIpv4,
};

enum class TypeTwoIdentityProfile : std::uint8_t
{
    ProductionPortable,
    EndpointTargetName,
    EndpointServiceSpn,
};

[[nodiscard]] constexpr const char *typeTwoIdentityProfileName(
    TypeTwoIdentityProfile profile) noexcept
{
    switch (profile)
    {
    case TypeTwoIdentityProfile::ProductionPortable:
        return "production-portable";
    case TypeTwoIdentityProfile::EndpointTargetName:
        return "endpoint-target-name";
    case TypeTwoIdentityProfile::EndpointServiceSpn:
        return "endpoint-service-spn";
    }
    return "unknown";
}

constexpr std::u16string_view kPhysicalIpTargetName{u"192.168.1.5"};
constexpr std::u16string_view kPhysicalIpServiceSpn{
    u"TERMSRV/192.168.1.5"};

[[nodiscard]] constexpr const char *targetProfileName(
    TargetProfile profile) noexcept
{
    switch (profile)
    {
    case TargetProfile::PortableServerName:
        return "TERMSRV/RDP-SERVER";
    case TargetProfile::PhysicalIpv4:
        return "TERMSRV/192.168.1.5";
    }
    return "unknown";
}

[[nodiscard]] bool copyTargetName(
    TargetProfile profile,
    std::array<wchar_t, 64> &target) noexcept
{
    target.fill(L'\0');
    const std::wstring_view source =
        profile == TargetProfile::PortableServerName
            ? std::wstring_view{L"TERMSRV/RDP-SERVER"}
            : std::wstring_view{L"TERMSRV/192.168.1.5"};
    if (source.size() + 1U > target.size())
        return false;
    std::copy(source.begin(), source.end(), target.begin());
    return true;
}

constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr ULONG kContextRequirements =
    ISC_REQ_CONNECTION |
    ISC_REQ_CONFIDENTIALITY |
    ISC_REQ_INTEGRITY |
    ISC_REQ_REPLAY_DETECT |
    ISC_REQ_SEQUENCE_DETECT;
constexpr ULONG kRequiredContextAttributes =
    ISC_RET_CONFIDENTIALITY |
    ISC_RET_INTEGRITY |
    ISC_RET_REPLAY_DETECT |
    ISC_RET_SEQUENCE_DETECT;

struct TokenBuffer final
{
    std::array<std::uint8_t, kMaximumStandaloneNtlmMessageBytes> bytes{};
    std::size_t size{};

    [[nodiscard]] std::span<const std::uint8_t> view() const noexcept
    {
        return {bytes.data(), size};
    }
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

[[nodiscard]] bool replaceTypeTwoTargetName(
    std::span<std::uint8_t> storage,
    std::size_t &messageSize,
    std::u16string_view targetName) noexcept
{
    constexpr std::size_t challengeHeaderBytes = 56U;
    if (messageSize < challengeHeaderBytes || messageSize > storage.size() ||
        targetName.empty() ||
        targetName.size() > kMaximumStandaloneNtlmServerNameCodeUnits)
    {
        return false;
    }

    const std::size_t oldTargetNameBytes = loadLe16(storage.data() + 12U);
    const std::size_t oldTargetNameOffset = loadLe32(storage.data() + 16U);
    const std::size_t targetInfoBytes = loadLe16(storage.data() + 40U);
    const std::size_t oldTargetInfoOffset = loadLe32(storage.data() + 44U);
    const std::size_t newTargetNameBytes = targetName.size() * 2U;
    if (oldTargetNameOffset != challengeHeaderBytes ||
        oldTargetInfoOffset != oldTargetNameOffset + oldTargetNameBytes ||
        oldTargetInfoOffset > messageSize ||
        targetInfoBytes > messageSize - oldTargetInfoOffset ||
        oldTargetInfoOffset + targetInfoBytes != messageSize ||
        newTargetNameBytes > 0xffffU)
    {
        return false;
    }

    const std::size_t newTargetInfoOffset =
        oldTargetNameOffset + newTargetNameBytes;
    const std::size_t newMessageSize =
        newTargetInfoOffset + targetInfoBytes;
    if (newMessageSize > storage.size())
        return false;

    std::memmove(
        storage.data() + newTargetInfoOffset,
        storage.data() + oldTargetInfoOffset,
        targetInfoBytes);
    for (std::size_t index = 0; index < targetName.size(); ++index)
    {
        storeLe16(
            storage.data() + oldTargetNameOffset + index * 2U,
            static_cast<std::uint16_t>(targetName[index]));
    }

    storeLe16(
        storage.data() + 12U,
        static_cast<std::uint16_t>(newTargetNameBytes));
    storeLe16(
        storage.data() + 14U,
        static_cast<std::uint16_t>(newTargetNameBytes));
    storeLe32(
        storage.data() + 44U,
        static_cast<std::uint32_t>(newTargetInfoOffset));
    if (newMessageSize < messageSize)
    {
        std::fill(
            storage.begin() + static_cast<std::ptrdiff_t>(newMessageSize),
            storage.begin() + static_cast<std::ptrdiff_t>(messageSize),
            std::uint8_t{0});
    }
    messageSize = newMessageSize;
    return true;
}

[[nodiscard]] bool appendTargetInfoServiceTarget(
    std::span<std::uint8_t> storage,
    std::size_t &messageSize,
    std::u16string_view serviceTarget) noexcept
{
    constexpr std::uint16_t msvAvEol = 0U;
    constexpr std::uint16_t msvAvTargetName = 9U;
    if (messageSize < 56U || messageSize > storage.size() ||
        serviceTarget.empty())
    {
        return false;
    }

    const std::size_t targetInfoBytes = loadLe16(storage.data() + 40U);
    const std::size_t targetInfoOffset = loadLe32(storage.data() + 44U);
    if (targetInfoOffset > messageSize ||
        targetInfoBytes > messageSize - targetInfoOffset ||
        targetInfoOffset + targetInfoBytes != messageSize)
    {
        return false;
    }

    const std::size_t targetInfoEnd = targetInfoOffset + targetInfoBytes;
    std::size_t eolOffset = targetInfoOffset;
    while (eolOffset + 4U <= targetInfoEnd)
    {
        const std::uint16_t avId = loadLe16(storage.data() + eolOffset);
        const std::size_t avBytes = loadLe16(storage.data() + eolOffset + 2U);
        if (avId == msvAvEol)
        {
            if (avBytes != 0U || eolOffset + 4U != targetInfoEnd)
                return false;
            break;
        }
        if (avId == msvAvTargetName ||
            avBytes > targetInfoEnd - (eolOffset + 4U))
        {
            return false;
        }
        eolOffset += 4U + avBytes;
    }
    if (eolOffset + 4U != targetInfoEnd)
        return false;

    const std::size_t serviceTargetBytes = serviceTarget.size() * 2U;
    const std::size_t insertedBytes = 4U + serviceTargetBytes;
    const std::size_t newTargetInfoBytes = targetInfoBytes + insertedBytes;
    const std::size_t newMessageSize = messageSize + insertedBytes;
    if (serviceTargetBytes > 0xffffU ||
        newTargetInfoBytes > 0xffffU ||
        newMessageSize > storage.size())
    {
        return false;
    }

    std::memmove(
        storage.data() + eolOffset + insertedBytes,
        storage.data() + eolOffset,
        messageSize - eolOffset);
    storeLe16(storage.data() + eolOffset, msvAvTargetName);
    storeLe16(
        storage.data() + eolOffset + 2U,
        static_cast<std::uint16_t>(serviceTargetBytes));
    for (std::size_t index = 0; index < serviceTarget.size(); ++index)
    {
        storeLe16(
            storage.data() + eolOffset + 4U + index * 2U,
            static_cast<std::uint16_t>(serviceTarget[index]));
    }
    storeLe16(
        storage.data() + 40U,
        static_cast<std::uint16_t>(newTargetInfoBytes));
    storeLe16(
        storage.data() + 42U,
        static_cast<std::uint16_t>(newTargetInfoBytes));
    messageSize = newMessageSize;
    return true;
}

[[nodiscard]] bool applyTypeTwoIdentityProfile(
    TypeTwoIdentityProfile profile,
    std::span<std::uint8_t> storage,
    std::size_t &messageSize) noexcept
{
    switch (profile)
    {
    case TypeTwoIdentityProfile::ProductionPortable:
        return true;
    case TypeTwoIdentityProfile::EndpointTargetName:
        return replaceTypeTwoTargetName(
            storage, messageSize, kPhysicalIpTargetName);
    case TypeTwoIdentityProfile::EndpointServiceSpn:
        return replaceTypeTwoTargetName(
                   storage, messageSize, kPhysicalIpTargetName) &&
               appendTargetInfoServiceTarget(
                   storage, messageSize, kPhysicalIpServiceSpn);
    }
    return false;
}


[[nodiscard]] bool securityStatusSucceeded(SECURITY_STATUS status) noexcept
{
    return status >= 0;
}

[[nodiscard]] SECURITY_STATUS completeOutputTokenIfNeeded(
    SECURITY_STATUS status,
    CtxtHandle &context,
    SecBufferDesc &outputDescriptor) noexcept
{
    if (status != SEC_I_COMPLETE_NEEDED &&
        status != SEC_I_COMPLETE_AND_CONTINUE)
    {
        return status;
    }

    const SECURITY_STATUS completeStatus =
        CompleteAuthToken(&context, &outputDescriptor);
    if (!securityStatusSucceeded(completeStatus))
        return completeStatus;

    return status == SEC_I_COMPLETE_AND_CONTINUE
        ? SEC_I_CONTINUE_NEEDED
        : SEC_E_OK;
}

class SspiNtlmClient final
{
public:
    SspiNtlmClient() noexcept
    {
        identity_.User = username_.data();
        identity_.UserLength =
            static_cast<unsigned long>(username_.size());
        identity_.Domain = domain_.data();
        identity_.DomainLength =
            static_cast<unsigned long>(domain_.size());
        identity_.Password = password_.data();
        identity_.PasswordLength =
            static_cast<unsigned long>(password_.size());
        identity_.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    ~SspiNtlmClient()
    {
        if (contextValid_)
            DeleteSecurityContext(&context_);
        if (credentialValid_)
            FreeCredentialsHandle(&credential_);
        SecureZeroMemory(
            password_.data(), password_.size() * sizeof(password_[0]));
    }

    SspiNtlmClient(const SspiNtlmClient &) = delete;
    SspiNtlmClient &operator=(const SspiNtlmClient &) = delete;
    SspiNtlmClient(SspiNtlmClient &&) = delete;
    SspiNtlmClient &operator=(SspiNtlmClient &&) = delete;

    [[nodiscard]] SECURITY_STATUS acquire() noexcept
    {
        wchar_t packageName[] = L"NTLM";
        TimeStamp expiry{};
        const SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr,
            packageName,
            SECPKG_CRED_OUTBOUND,
            nullptr,
            &identity_,
            nullptr,
            nullptr,
            &credential_,
            &expiry);
        credentialValid_ = securityStatusSucceeded(status);
        return status;
    }

    [[nodiscard]] SECURITY_STATUS begin(
        TargetProfile targetProfile,
        TokenBuffer &output,
        ULONG &contextAttributes) noexcept
    {
        output = {};
        contextAttributes = 0;
        if (!credentialValid_)
            return SEC_E_INVALID_HANDLE;

        SecBuffer outputBuffer{};
        outputBuffer.cbBuffer =
            static_cast<unsigned long>(output.bytes.size());
        outputBuffer.BufferType = SECBUFFER_TOKEN;
        outputBuffer.pvBuffer = output.bytes.data();
        SecBufferDesc outputDescriptor{
            SECBUFFER_VERSION, 1U, &outputBuffer};

        std::array<wchar_t, 64> targetName{};
        if (!copyTargetName(targetProfile, targetName))
            return SEC_E_TARGET_UNKNOWN;
        TimeStamp expiry{};
        SECURITY_STATUS status = InitializeSecurityContextW(
            &credential_,
            nullptr,
            targetName.data(),
            kContextRequirements,
            0U,
            SECURITY_NATIVE_DREP,
            nullptr,
            0U,
            &context_,
            &outputDescriptor,
            &contextAttributes,
            &expiry);
        if (securityStatusSucceeded(status))
            contextValid_ = true;
        status = completeOutputTokenIfNeeded(
            status, context_, outputDescriptor);
        if (!securityStatusSucceeded(status) ||
            outputBuffer.cbBuffer > output.bytes.size())
        {
            output.size = 0;
            return !securityStatusSucceeded(status)
                ? status
                : SEC_E_BUFFER_TOO_SMALL;
        }

        output.size = outputBuffer.cbBuffer;
        return status;
    }

    [[nodiscard]] SECURITY_STATUS continueWithChallenge(
        TargetProfile targetProfile,
        std::span<std::uint8_t> challenge,
        TokenBuffer &output,
        ULONG &contextAttributes) noexcept
    {
        output = {};
        contextAttributes = 0;
        if (!credentialValid_ || !contextValid_ || challenge.empty())
            return SEC_E_INVALID_HANDLE;

        SecBuffer inputBuffer{};
        inputBuffer.cbBuffer =
            static_cast<unsigned long>(challenge.size());
        inputBuffer.BufferType = SECBUFFER_TOKEN;
        inputBuffer.pvBuffer = challenge.data();
        SecBufferDesc inputDescriptor{
            SECBUFFER_VERSION, 1U, &inputBuffer};

        SecBuffer outputBuffer{};
        outputBuffer.cbBuffer =
            static_cast<unsigned long>(output.bytes.size());
        outputBuffer.BufferType = SECBUFFER_TOKEN;
        outputBuffer.pvBuffer = output.bytes.data();
        SecBufferDesc outputDescriptor{
            SECBUFFER_VERSION, 1U, &outputBuffer};

        std::array<wchar_t, 64> targetName{};
        if (!copyTargetName(targetProfile, targetName))
            return SEC_E_TARGET_UNKNOWN;
        TimeStamp expiry{};
        SECURITY_STATUS status = InitializeSecurityContextW(
            &credential_,
            &context_,
            targetName.data(),
            kContextRequirements,
            0U,
            SECURITY_NATIVE_DREP,
            &inputDescriptor,
            0U,
            &context_,
            &outputDescriptor,
            &contextAttributes,
            &expiry);
        status = completeOutputTokenIfNeeded(
            status, context_, outputDescriptor);
        if (!securityStatusSucceeded(status) ||
            outputBuffer.cbBuffer > output.bytes.size())
        {
            output.size = 0;
            return !securityStatusSucceeded(status)
                ? status
                : SEC_E_BUFFER_TOO_SMALL;
        }

        output.size = outputBuffer.cbBuffer;
        return status;
    }

private:
    std::array<unsigned short, 4> username_{
        static_cast<unsigned short>('U'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('e'),
        static_cast<unsigned short>('r')};
    std::array<unsigned short, 3> domain_{
        static_cast<unsigned short>('R'),
        static_cast<unsigned short>('D'),
        static_cast<unsigned short>('P')};
    std::array<unsigned short, 8> password_{
        static_cast<unsigned short>('P'),
        static_cast<unsigned short>('a'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('w'),
        static_cast<unsigned short>('o'),
        static_cast<unsigned short>('r'),
        static_cast<unsigned short>('d')};
    SEC_WINNT_AUTH_IDENTITY_W identity_{};
    CredHandle credential_{};
    CtxtHandle context_{};
    bool credentialValid_{};
    bool contextValid_{};
};

[[nodiscard]] bool readTypeOneFlags(
    std::span<const std::uint8_t> token,
    std::uint32_t &flags) noexcept
{
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    flags = 0;
    if (token.size() < 16U ||
        !std::equal(signature.begin(), signature.end(), token.begin()) ||
        loadLe32(token.data() + 8U) != 1U)
    {
        return false;
    }
    flags = loadLe32(token.data() + 12U);
    return true;
}

[[nodiscard]] bool isTypeThree(
    std::span<const std::uint8_t> token) noexcept
{
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    return token.size() >= 12U &&
           std::equal(signature.begin(), signature.end(), token.begin()) &&
           loadLe32(token.data() + 8U) == 3U;
}

[[nodiscard]] std::uint64_t currentWindowsFileTime() noexcept
{
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32U) |
           static_cast<std::uint64_t>(fileTime.dwLowDateTime);
}

enum class ChallengeVariant : std::uint8_t
{
    Production,
    WithVersion,
    WithoutTimestamp,
    DifferentTargetName,
    WithoutOem,
    WithoutAlwaysSign,
    WithoutKeyExchange,
    Without56,
};

[[nodiscard]] const char *variantName(ChallengeVariant variant) noexcept
{
    switch (variant)
    {
    case ChallengeVariant::Production:
        return "production";
    case ChallengeVariant::WithVersion:
        return "with-version";
    case ChallengeVariant::WithoutTimestamp:
        return "target-info-without-timestamp";
    case ChallengeVariant::DifferentTargetName:
        return "target-name-text-only";
    case ChallengeVariant::WithoutOem:
        return "without-oem";
    case ChallengeVariant::WithoutAlwaysSign:
        return "without-always-sign";
    case ChallengeVariant::WithoutKeyExchange:
        return "without-key-exchange";
    case ChallengeVariant::Without56:
        return "without-56";
    }
    return "unknown";
}

[[nodiscard]] bool clearChallengeFlag(
    std::span<std::uint8_t> message,
    std::uint32_t flag) noexcept
{
    if (message.size() < 24U)
        return false;
    const std::uint32_t flags = loadLe32(message.data() + 20U);
    if ((flags & flag) == 0U)
        return false;
    storeLe32(message.data() + 20U, flags & ~flag);
    return true;
}

[[nodiscard]] bool addVersion(
    std::span<std::uint8_t> message,
    std::uint32_t clientFlags) noexcept
{
    if (message.size() < 56U ||
        (clientFlags & kNtlmNegotiateVersion) == 0U)
    {
        return false;
    }

    const std::uint32_t flags = loadLe32(message.data() + 20U);
    storeLe32(message.data() + 20U, flags | kNtlmNegotiateVersion);
    // Test-only portable VERSION: product/build 0, NTLM revision 0x0f.
    // This isolates VERSION without pretending to be a Windows release.
    std::fill(
        message.begin() + 48,
        message.begin() + 55,
        std::uint8_t{0});
    message[55] = 0x0fU;
    return true;
}

[[nodiscard]] bool removeTimestampFromTargetInfo(
    std::span<std::uint8_t> storage,
    std::size_t &messageSize) noexcept
{
    if (messageSize < 48U || messageSize > storage.size())
        return false;

    const std::size_t targetInfoLength = loadLe16(storage.data() + 40U);
    const std::size_t targetInfoOffset = loadLe32(storage.data() + 44U);
    if (targetInfoLength < 4U ||
        targetInfoOffset > messageSize ||
        targetInfoLength > messageSize - targetInfoOffset ||
        targetInfoOffset + targetInfoLength != messageSize)
    {
        return false;
    }

    const std::size_t targetInfoEnd = targetInfoOffset + targetInfoLength;
    std::size_t cursor = targetInfoOffset;
    while (cursor + 4U <= targetInfoEnd)
    {
        const std::uint16_t avId = loadLe16(storage.data() + cursor);
        const std::size_t avLength = loadLe16(storage.data() + cursor + 2U);
        if (cursor + 4U + avLength > targetInfoEnd)
            return false;
        if (avId == 0U)
            return false;
        if (avId == 7U)
        {
            if (avLength != 8U)
                return false;
            constexpr std::size_t removedBytes = 12U;
            const std::size_t sourceOffset = cursor + removedBytes;
            const std::size_t bytesToMove = messageSize - sourceOffset;
            std::memmove(
                storage.data() + cursor,
                storage.data() + sourceOffset,
                bytesToMove);
            const std::size_t oldSize = messageSize;
            messageSize -= removedBytes;
            std::fill(
                storage.begin() + static_cast<std::ptrdiff_t>(messageSize),
                storage.begin() + static_cast<std::ptrdiff_t>(oldSize),
                std::uint8_t{0});
            const auto newTargetInfoLength = static_cast<std::uint16_t>(
                targetInfoLength - removedBytes);
            storeLe16(storage.data() + 40U, newTargetInfoLength);
            storeLe16(storage.data() + 42U, newTargetInfoLength);
            return true;
        }
        cursor += 4U + avLength;
    }
    return false;
}

[[nodiscard]] bool replaceServerIdentityText(
    std::span<std::uint8_t> message) noexcept
{
    // TargetName and MsvAvNbComputerName are two encodings of one semantic
    // server identity. Keep them equal so this remains one legal experiment.
    constexpr std::u16string_view alternateName{u"SSPI-SRV01"};
    if (message.size() < 48U)
        return false;

    const std::size_t targetNameLength = loadLe16(message.data() + 12U);
    const std::size_t targetNameOffset = loadLe32(message.data() + 16U);
    const std::size_t targetInfoLength = loadLe16(message.data() + 40U);
    const std::size_t targetInfoOffset = loadLe32(message.data() + 44U);
    if (targetNameLength != alternateName.size() * 2U ||
        targetNameOffset > message.size() ||
        targetNameLength > message.size() - targetNameOffset ||
        targetInfoOffset > message.size() ||
        targetInfoLength > message.size() - targetInfoOffset)
    {
        return false;
    }

    for (std::size_t index = 0; index < alternateName.size(); ++index)
    {
        storeLe16(
            message.data() + targetNameOffset + index * 2U,
            static_cast<std::uint16_t>(alternateName[index]));
    }

    const std::size_t targetInfoEnd = targetInfoOffset + targetInfoLength;
    std::size_t cursor = targetInfoOffset;
    while (cursor + 4U <= targetInfoEnd)
    {
        const std::uint16_t avId = loadLe16(message.data() + cursor);
        const std::size_t avLength = loadLe16(message.data() + cursor + 2U);
        cursor += 4U;
        if (avLength > targetInfoEnd - cursor)
            return false;
        if (avId == 0U)
            return false;
        if (avId == 1U)
        {
            if (avLength != alternateName.size() * 2U)
                return false;
            for (std::size_t index = 0; index < alternateName.size(); ++index)
            {
                storeLe16(
                    message.data() + cursor + index * 2U,
                    static_cast<std::uint16_t>(alternateName[index]));
            }
            return true;
        }
        cursor += avLength;
    }
    return false;
}

[[nodiscard]] bool applyVariant(
    ChallengeVariant variant,
    std::span<std::uint8_t> storage,
    std::size_t &messageSize,
    std::uint32_t clientFlags) noexcept
{
    auto message = storage.first(messageSize);
    switch (variant)
    {
    case ChallengeVariant::Production:
        return true;
    case ChallengeVariant::WithVersion:
        return addVersion(message, clientFlags);
    case ChallengeVariant::WithoutTimestamp:
        return removeTimestampFromTargetInfo(storage, messageSize);
    case ChallengeVariant::DifferentTargetName:
        return replaceServerIdentityText(message);
    case ChallengeVariant::WithoutOem:
        return clearChallengeFlag(message, kNtlmNegotiateOem);
    case ChallengeVariant::WithoutAlwaysSign:
        return clearChallengeFlag(message, kNtlmNegotiateAlwaysSign);
    case ChallengeVariant::WithoutKeyExchange:
        return clearChallengeFlag(message, kNtlmNegotiateKeyExchange);
    case ChallengeVariant::Without56:
        return clearChallengeFlag(message, kNtlmNegotiate56);
    }
    return false;
}

[[nodiscard]] bool verifyTypeThree(
    std::span<const std::uint8_t> typeThree) noexcept
{
    NtlmAuthenticateMessage authenticate;
    if (parseNtlmAuthenticateMessage(typeThree, authenticate) !=
        NtlmMessageParseResult::Parsed)
    {
        return false;
    }

    EphemeralNtlmV2Credential credential;
    std::array<char16_t, 8> password{
        u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
    if (!credential.configure(u"User", password))
        return false;

    NtlmV2SecurityContext securityContext;
    return credential.verifyAndDeriveSecurityContext(
               authenticate.verificationRequest(kServerChallenge),
               securityContext) == NtlmV2VerifyResult::Verified &&
           securityContext.active();
}

struct AttemptResult final
{
    const char *failureStage{"not-started"};
    SECURITY_STATUS acquireStatus{SEC_E_INTERNAL_ERROR};
    SECURITY_STATUS firstStatus{SEC_E_INTERNAL_ERROR};
    SECURITY_STATUS secondStatus{SEC_E_INTERNAL_ERROR};
    std::uint32_t typeOneFlags{};
    std::uint32_t typeTwoFlags{};
    ULONG contextAttributes{};
    bool variantApplied{};
    bool identityProfileApplied{};
    bool microsoftProducedTypeThree{};
    bool contextComplete{};
    bool securityAttributesSatisfied{};
    bool localVerificationPassed{};
};

[[nodiscard]] AttemptResult runAttempt(
    TargetProfile targetProfile,
    TypeTwoIdentityProfile identityProfile,
    ChallengeVariant variant,
    std::uint64_t timestampFileTime) noexcept
{
    AttemptResult result{};
    SspiNtlmClient client;
    result.failureStage = "acquire-credentials";
    result.acquireStatus = client.acquire();
    if (!securityStatusSucceeded(result.acquireStatus))
        return result;

    TokenBuffer typeOne;
    ULONG ignoredFirstAttributes = 0;
    result.failureStage = "initialize-type1";
    result.firstStatus = client.begin(
        targetProfile, typeOne, ignoredFirstAttributes);
    if (result.firstStatus != SEC_I_CONTINUE_NEEDED)
        return result;

    result.failureStage = "parse-type1-flags";
    if (!readTypeOneFlags(typeOne.view(), result.typeOneFlags))
        return result;

    std::array<std::uint8_t, kMaximumStandaloneNtlmMessageBytes> typeTwo{};
    const NtlmChallengeMessageParameters parameters{
        kServerChallenge,
        kStandaloneNtlmPortableDomainName,
        kStandaloneNtlmPortableServerName,
        timestampFileTime,
        result.typeOneFlags};
    result.failureStage = "encode-production-type2";
    const NtlmChallengeEncodeResult encoded =
        encodeNtlmChallengeMessage(parameters, typeTwo);
    if (!encoded)
        return result;

    NtlmChallengeMessageObservation observation;
    if (validateNtlmChallengeMessage(
            std::span<const std::uint8_t>{typeTwo}.first(
                encoded.bytesWritten),
            result.typeOneFlags,
            observation) != NtlmMessageParseResult::Parsed)
    {
        result.failureStage = "validate-production-type2";
        return result;
    }

    std::size_t typeTwoSize = encoded.bytesWritten;
    result.failureStage = "apply-single-delta";
    result.variantApplied = applyVariant(
        variant, typeTwo, typeTwoSize, result.typeOneFlags);
    if (!result.variantApplied)
        return result;

    result.failureStage = "apply-target-identity-profile";
    result.identityProfileApplied = applyTypeTwoIdentityProfile(
        identityProfile, typeTwo, typeTwoSize);
    if (!result.identityProfileApplied)
        return result;

    result.typeTwoFlags = loadLe32(typeTwo.data() + 20U);
    result.failureStage = "validate-single-delta";
    NtlmChallengeMessageObservation variantObservation;
    if (validateNtlmChallengeMessage(
            std::span<const std::uint8_t>{typeTwo}.first(typeTwoSize),
            result.typeOneFlags,
            variantObservation) != NtlmMessageParseResult::Parsed)
    {
        return result;
    }

    TokenBuffer typeThree;
    result.failureStage = "initialize-type3";
    result.secondStatus = client.continueWithChallenge(
        targetProfile,
        std::span<std::uint8_t>{typeTwo}.first(typeTwoSize),
        typeThree,
        result.contextAttributes);
    result.contextComplete = result.secondStatus == SEC_E_OK;
    result.microsoftProducedTypeThree =
        securityStatusSucceeded(result.secondStatus) &&
        isTypeThree(typeThree.view());
    if (!result.microsoftProducedTypeThree)
        return result;

    result.securityAttributesSatisfied =
        (result.contextAttributes & kRequiredContextAttributes) ==
        kRequiredContextAttributes;
    result.failureStage = "verify-microsoft-type3";
    result.localVerificationPassed = verifyTypeThree(typeThree.view());
    if (result.contextComplete &&
        result.securityAttributesSatisfied &&
        result.localVerificationPassed)
    {
        result.failureStage = "none";
    }
    return result;
}

void printStatus(
    const char *label,
    SECURITY_STATUS status) noexcept
{
    std::fprintf(
        stderr,
        "%s=0x%08lx\n",
        label,
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(status)));
}

void printAttemptFailure(
    TargetProfile targetProfile,
    TypeTwoIdentityProfile identityProfile,
    ChallengeVariant variant,
    const AttemptResult &result) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-sspi-ntlm target=%s type2-identity=%s variant=%s stage=%s "
        "type1-flags=0x%08lx type2-flags=0x%08lx "
        "type3=%s complete=%s attributes=%s local-verify=%s\n",
        targetProfileName(targetProfile),
        typeTwoIdentityProfileName(identityProfile),
        variantName(variant),
        result.failureStage,
        static_cast<unsigned long>(result.typeOneFlags),
        static_cast<unsigned long>(result.typeTwoFlags),
        result.microsoftProducedTypeThree ? "yes" : "no",
        result.contextComplete ? "yes" : "no",
        result.securityAttributesSatisfied ? "yes" : "no",
        result.localVerificationPassed ? "yes" : "no");
    printStatus("microsoft-sspi-acquire-status", result.acquireStatus);
    printStatus("microsoft-sspi-type1-status", result.firstStatus);
    printStatus("microsoft-sspi-type2-status", result.secondStatus);
}

[[nodiscard]] bool isExploratoryTargetRejection(
    SECURITY_STATUS status) noexcept
{
    if (securityStatusSucceeded(status))
        return false;
    switch (status)
    {
    case SEC_E_BUFFER_TOO_SMALL:
    case SEC_E_INSUFFICIENT_MEMORY:
    case SEC_E_INVALID_HANDLE:
    case SEC_E_INTERNAL_ERROR:
        return false;
    default:
        return true;
    }
}

} // namespace

int main(int argc, char **argv)
{
    TargetProfile targetProfile = TargetProfile::PortableServerName;
    TypeTwoIdentityProfile identityProfile =
        TypeTwoIdentityProfile::ProductionPortable;
    bool exploratoryIdentityProfile = false;
    if (argc == 2 && argv[1] != nullptr)
    {
        const std::string_view mode{argv[1]};
        if (mode == "control-target")
        {
            targetProfile = TargetProfile::PortableServerName;
        }
        else if (mode == "physical-ip-target")
        {
            targetProfile = TargetProfile::PhysicalIpv4;
        }
        else if (mode == "physical-ip-endpoint-target-name")
        {
            targetProfile = TargetProfile::PhysicalIpv4;
            identityProfile = TypeTwoIdentityProfile::EndpointTargetName;
            exploratoryIdentityProfile = true;
        }
        else if (mode == "physical-ip-endpoint-service-spn")
        {
            targetProfile = TargetProfile::PhysicalIpv4;
            identityProfile = TypeTwoIdentityProfile::EndpointServiceSpn;
            exploratoryIdentityProfile = true;
        }
        else
        {
            return 2;
        }
    }
    else if (argc != 1)
    {
        return 2;
    }

    const std::uint64_t timestampFileTime = currentWindowsFileTime();
    if (timestampFileTime == 0U)
    {
        std::fprintf(stderr, "microsoft-sspi-filetime=unavailable\n");
        return 1;
    }

    const AttemptResult production = runAttempt(
        targetProfile, identityProfile,
        ChallengeVariant::Production, timestampFileTime);
    if (production.microsoftProducedTypeThree)
    {
        if (production.contextComplete &&
            production.securityAttributesSatisfied &&
            production.localVerificationPassed)
        {
            return 0;
        }

        std::fprintf(
            stderr,
            "microsoft-sspi-production-type2=accepted-but-local-chain-failed\n");
        printAttemptFailure(
            targetProfile, identityProfile,
            ChallengeVariant::Production, production);
        return 1;
    }

    std::fprintf(
        stderr,
        "microsoft-sspi-production-type2=rejected target=%s\n",
        targetProfileName(targetProfile));
    printAttemptFailure(
        targetProfile, identityProfile,
        ChallengeVariant::Production, production);

    if (exploratoryIdentityProfile)
    {
        return production.identityProfileApplied &&
               isExploratoryTargetRejection(production.secondStatus)
            ? 77
            : 1;
    }

    // The endpoint-target differential is evidence about the target principal,
    // not authorization to mutate a Microsoft-accepted production challenge.
    if (targetProfile == TargetProfile::PhysicalIpv4)
        return 1;

    constexpr std::array diagnosticVariants{
        ChallengeVariant::WithVersion,
        ChallengeVariant::WithoutTimestamp,
        ChallengeVariant::DifferentTargetName,
        ChallengeVariant::WithoutOem,
        ChallengeVariant::WithoutAlwaysSign,
        ChallengeVariant::WithoutKeyExchange,
        ChallengeVariant::Without56};

    const char *firstAcceptedDelta = nullptr;
    for (const ChallengeVariant variant : diagnosticVariants)
    {
        const AttemptResult diagnostic = runAttempt(
            targetProfile, TypeTwoIdentityProfile::ProductionPortable,
            variant, timestampFileTime);
        if (!diagnostic.variantApplied)
        {
            std::fprintf(
                stderr,
                "microsoft-sspi-single-delta=%s skipped=not-applicable\n",
                variantName(variant));
            continue;
        }
        if (diagnostic.microsoftProducedTypeThree)
        {
            if (firstAcceptedDelta == nullptr)
                firstAcceptedDelta = variantName(variant);
            std::fprintf(
                stderr,
                "microsoft-sspi-single-delta=%s accepted-type3=yes "
                "complete=%s attributes=%s local-verify=%s\n",
                variantName(variant),
                diagnostic.contextComplete ? "yes" : "no",
                diagnostic.securityAttributesSatisfied ? "yes" : "no",
                diagnostic.localVerificationPassed ? "yes" : "no");
        }
        else
        {
            std::fprintf(
                stderr,
                "microsoft-sspi-single-delta=%s accepted-type3=no\n",
                variantName(variant));
            printStatus(
                "microsoft-sspi-single-delta-status",
                diagnostic.secondStatus);
        }
    }

    if (firstAcceptedDelta != nullptr)
    {
        std::fprintf(
            stderr,
            "microsoft-sspi-first-accepted-single-delta=%s\n",
            firstAcceptedDelta);
    }
    else
    {
        std::fprintf(
            stderr,
            "microsoft-sspi-first-accepted-single-delta=none\n");
    }
    return 1;
}
