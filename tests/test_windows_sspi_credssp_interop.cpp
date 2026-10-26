// SPDX-License-Identifier: GPL-3.0-or-later
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <credssp.h>
#include <schannel.h>
#include <sspi.h>

#include "server/runtime/runtime_tls_context.h"
#include "server/security/credssp_tsrequest.h"
#include "server/security/standalone_credssp.h"
#include "server/security/standalone_ntlmssp.h"
#include "server/security/standalone_ntlmv2.h"
#include "server/security/standalone_spnego.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace rdp_server::server::runtime;
using namespace rdp_server::server::security;

namespace
{

enum class TargetProfile : std::uint8_t
{
    PortableServerName,
    PhysicalIpv4,
    BarePhysicalIpv4,
};

enum class ChallengeExperiment : std::uint8_t
{
    Production,
    EndpointTypeTwoTargetName,
    EndpointMsvAvTargetName,
    EndpointTypeTwoAndMsvAvTargetName,
};

[[nodiscard]] constexpr const char *experimentName(
    ChallengeExperiment experiment) noexcept
{
    switch (experiment)
    {
    case ChallengeExperiment::Production:
        return "production";
    case ChallengeExperiment::EndpointTypeTwoTargetName:
        return "endpoint-type2-target-name";
    case ChallengeExperiment::EndpointMsvAvTargetName:
        return "endpoint-msv-av-target-name";
    case ChallengeExperiment::EndpointTypeTwoAndMsvAvTargetName:
        return "endpoint-type2-and-msv-av-target-name";
    }
    return "unknown";
}

[[nodiscard]] constexpr std::wstring_view targetName(
    TargetProfile profile) noexcept
{
    switch (profile)
    {
    case TargetProfile::PortableServerName:
        return L"TERMSRV/RDP-SERVER";
    case TargetProfile::PhysicalIpv4:
        return L"TERMSRV/192.168.1.5";
    case TargetProfile::BarePhysicalIpv4:
        return L"192.168.1.5";
    }
    return {};
}

[[nodiscard]] constexpr const char *targetLabel(
    TargetProfile profile) noexcept
{
    switch (profile)
    {
    case TargetProfile::PortableServerName:
        return "TERMSRV/RDP-SERVER";
    case TargetProfile::PhysicalIpv4:
        return "TERMSRV/192.168.1.5";
    case TargetProfile::BarePhysicalIpv4:
        return "192.168.1.5";
    }
    return "unknown";
}

constexpr std::string_view kPhysicalEndpoint{"192.168.1.5"};
constexpr std::u16string_view kPhysicalEndpointUtf16{u"192.168.1.5"};
constexpr std::u16string_view kPhysicalEndpointSpnUtf16{
    u"TERMSRV/192.168.1.5"};
constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr ULONG kCredSspContextRequirements =
    ISC_REQ_ALLOCATE_MEMORY |
    ISC_REQ_CONNECTION |
    ISC_REQ_MANUAL_CRED_VALIDATION;
constexpr std::size_t kMaximumExchangeRounds = 128U;
constexpr std::size_t kMaximumRawTokenBytes = 256U * 1024U;

[[nodiscard]] bool securityStatusSucceeded(
    SECURITY_STATUS status) noexcept
{
    return status >= 0;
}

[[nodiscard]] std::uint64_t currentWindowsFileTime() noexcept
{
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32U) |
           static_cast<std::uint64_t>(fileTime.dwLowDateTime);
}


[[nodiscard]] const char *securityStatusName(
    SECURITY_STATUS status) noexcept
{
    const auto code = static_cast<std::uint32_t>(status);
    switch (code)
    {
    case 0x00000000U: return "SEC_E_OK";
    case 0x00090312U: return "SEC_I_CONTINUE_NEEDED";
    case 0x00090313U: return "SEC_I_COMPLETE_NEEDED";
    case 0x00090314U: return "SEC_I_COMPLETE_AND_CONTINUE";
    case 0x00090320U: return "SEC_I_INCOMPLETE_CREDENTIALS";
    case 0x80090303U: return "SEC_E_TARGET_UNKNOWN";
    case 0x80090308U: return "SEC_E_INVALID_TOKEN";
    case 0x80090318U: return "SEC_E_INCOMPLETE_MESSAGE";
    case 0x80090322U: return "SEC_E_WRONG_PRINCIPAL";
    case 0x8009035eU: return "SEC_E_DELEGATION_POLICY";
    case 0x8009035fU: return "SEC_E_POLICY_NLTM_ONLY";
    case 0x80090363U: return "SEC_E_MUTUAL_AUTH_FAILED";
    default: return "OTHER";
    }
}

void printClientStatus(
    TargetProfile profile,
    const char *phase,
    SECURITY_STATUS status) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-credssp-status target=%s phase=%s status=%s "
        "code=0x%08lx\n",
        targetLabel(profile),
        phase,
        securityStatusName(status),
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(status)));
}

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
    std::uint8_t *output,
    std::uint16_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
}

constexpr void storeLe32(
    std::uint8_t *output,
    std::uint32_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
    output[2] = static_cast<std::uint8_t>(value >> 16U);
    output[3] = static_cast<std::uint8_t>(value >> 24U);
}

[[nodiscard]] bool isNtlmMessageAt(
    std::span<const std::uint8_t> token,
    std::size_t offset,
    std::uint32_t messageType) noexcept
{
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    return offset <= token.size() &&
           token.size() - offset >= 12U &&
           std::equal(
               signature.begin(),
               signature.end(),
               token.begin() +
                   static_cast<std::ptrdiff_t>(offset)) &&
           loadLe32(token.data() + offset + 8U) == messageType;
}

[[nodiscard]] bool hasNtlmMessageType(
    std::span<const std::uint8_t> token,
    std::uint32_t messageType) noexcept
{
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    for (std::size_t offset = 0U;
         offset + 12U <= token.size();
         ++offset)
    {
        if (std::equal(
                signature.begin(),
                signature.end(),
                token.begin() +
                    static_cast<std::ptrdiff_t>(offset)) &&
            loadLe32(token.data() + offset + 8U) == messageType)
        {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::vector<std::uint8_t> utf16LittleEndian(
    std::u16string_view text)
{
    std::vector<std::uint8_t> bytes(text.size() * 2U);
    for (std::size_t index = 0U; index < text.size(); ++index)
    {
        storeLe16(
            bytes.data() + index * 2U,
            static_cast<std::uint16_t>(text[index]));
    }
    return bytes;
}

[[nodiscard]] std::size_t typeTwoBytesAt(
    std::span<const std::uint8_t> bytes,
    std::size_t offset) noexcept
{
    if (offset > bytes.size() || bytes.size() - offset < 56U ||
        !isNtlmMessageAt(bytes, offset, 2U))
    {
        return 0U;
    }

    const auto message = bytes.subspan(offset);
    std::size_t required = 56U;
    for (const std::size_t fieldOffset : {12U, 40U})
    {
        const std::size_t length =
            loadLe16(message.data() + fieldOffset);
        const std::size_t dataOffset =
            loadLe32(message.data() + fieldOffset + 4U);
        if (dataOffset > message.size() ||
            length > message.size() - dataOffset)
        {
            return 0U;
        }
        required = std::max(required, dataOffset + length);
    }
    return required;
}

struct TypeTwoLocation final
{
    std::size_t offset{};
    std::size_t bytes{};
};

[[nodiscard]] TypeTwoLocation findTypeTwo(
    std::span<const std::uint8_t> bytes) noexcept
{
    for (std::size_t offset = 0U;
         offset + 56U <= bytes.size();
         ++offset)
    {
        const std::size_t messageBytes =
            typeTwoBytesAt(bytes, offset);
        if (messageBytes != 0U)
            return {offset, messageBytes};
    }
    return {};
}

[[nodiscard]] bool readTypeOneFlags(
    std::span<const std::uint8_t> bytes,
    std::uint32_t &flags) noexcept
{
    flags = 0U;
    for (std::size_t offset = 0U;
         offset + 16U <= bytes.size();
         ++offset)
    {
        if (isNtlmMessageAt(bytes, offset, 1U))
        {
            flags = loadLe32(bytes.data() + offset + 12U);
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool appendTargetNameAvPair(
    std::vector<std::uint8_t> &targetInfo)
{
    if (targetInfo.size() < 4U ||
        loadLe16(targetInfo.data() + targetInfo.size() - 4U) != 0U ||
        loadLe16(targetInfo.data() + targetInfo.size() - 2U) != 0U)
    {
        return false;
    }

    const auto value = utf16LittleEndian(kPhysicalEndpointSpnUtf16);
    if (value.empty() ||
        value.size() >
            static_cast<std::size_t>(
                (std::numeric_limits<std::uint16_t>::max)()))
    {
        return false;
    }

    targetInfo.resize(targetInfo.size() - 4U);
    const std::size_t avOffset = targetInfo.size();
    targetInfo.resize(avOffset + 4U);
    storeLe16(targetInfo.data() + avOffset, 9U);
    storeLe16(
        targetInfo.data() + avOffset + 2U,
        static_cast<std::uint16_t>(value.size()));
    targetInfo.insert(targetInfo.end(), value.begin(), value.end());
    targetInfo.insert(targetInfo.end(), {0U,0U,0U,0U});
    return true;
}

[[nodiscard]] std::vector<std::uint8_t> makeTypeTwoExperiment(
    std::span<const std::uint8_t> production,
    std::uint32_t clientFlags,
    ChallengeExperiment experiment)
{
    if (experiment == ChallengeExperiment::Production ||
        production.size() < 56U)
    {
        return {};
    }

    const std::size_t targetNameLength =
        loadLe16(production.data() + 12U);
    const std::size_t targetNameOffset =
        loadLe32(production.data() + 16U);
    const std::size_t targetInfoLength =
        loadLe16(production.data() + 40U);
    const std::size_t targetInfoOffset =
        loadLe32(production.data() + 44U);
    if (targetNameOffset > production.size() ||
        targetNameLength > production.size() - targetNameOffset ||
        targetInfoOffset > production.size() ||
        targetInfoLength > production.size() - targetInfoOffset)
    {
        return {};
    }

    std::vector<std::uint8_t> targetName(
        production.begin() +
            static_cast<std::ptrdiff_t>(targetNameOffset),
        production.begin() +
            static_cast<std::ptrdiff_t>(
                targetNameOffset + targetNameLength));
    std::vector<std::uint8_t> targetInfo(
        production.begin() +
            static_cast<std::ptrdiff_t>(targetInfoOffset),
        production.begin() +
            static_cast<std::ptrdiff_t>(
                targetInfoOffset + targetInfoLength));

    if (experiment == ChallengeExperiment::EndpointTypeTwoTargetName ||
        experiment ==
            ChallengeExperiment::EndpointTypeTwoAndMsvAvTargetName)
    {
        targetName = utf16LittleEndian(kPhysicalEndpointUtf16);
    }
    if (experiment == ChallengeExperiment::EndpointMsvAvTargetName ||
        experiment ==
            ChallengeExperiment::EndpointTypeTwoAndMsvAvTargetName)
    {
        if (!appendTargetNameAvPair(targetInfo))
            return {};
    }

    if (targetName.empty() || targetInfo.empty() ||
        targetName.size() >
            static_cast<std::size_t>(
                (std::numeric_limits<std::uint16_t>::max)()) ||
        targetInfo.size() >
            static_cast<std::size_t>(
                (std::numeric_limits<std::uint16_t>::max)()))
    {
        return {};
    }

    std::vector<std::uint8_t> output(56U);
    std::copy_n(production.begin(), 56U, output.begin());
    storeLe16(
        output.data() + 12U,
        static_cast<std::uint16_t>(targetName.size()));
    storeLe16(
        output.data() + 14U,
        static_cast<std::uint16_t>(targetName.size()));
    storeLe32(output.data() + 16U, 56U);
    storeLe16(
        output.data() + 40U,
        static_cast<std::uint16_t>(targetInfo.size()));
    storeLe16(
        output.data() + 42U,
        static_cast<std::uint16_t>(targetInfo.size()));
    storeLe32(
        output.data() + 44U,
        static_cast<std::uint32_t>(56U + targetName.size()));
    output.insert(output.end(), targetName.begin(), targetName.end());
    output.insert(output.end(), targetInfo.begin(), targetInfo.end());

    NtlmChallengeMessageObservation observation;
    if (validateNtlmChallengeMessage(
            output, clientFlags, observation) !=
        NtlmMessageParseResult::Parsed)
    {
        return {};
    }
    return output;
}

[[nodiscard]] bool readDerObject(
    std::span<const std::uint8_t> input,
    std::uint8_t &tag,
    std::size_t &headerBytes,
    std::size_t &payloadBytes) noexcept
{
    tag = 0U;
    headerBytes = 0U;
    payloadBytes = 0U;
    if (input.size() < 2U)
        return false;

    tag = input[0];
    const std::uint8_t firstLength = input[1];
    if (firstLength < 0x80U)
    {
        headerBytes = 2U;
        payloadBytes = firstLength;
    }
    else
    {
        const std::size_t lengthOctets = firstLength & 0x7fU;
        if (lengthOctets == 0U || lengthOctets > 2U ||
            input.size() < 2U + lengthOctets ||
            input[2] == 0U)
        {
            return false;
        }
        headerBytes = 2U + lengthOctets;
        for (std::size_t index = 0U;
             index < lengthOctets;
             ++index)
        {
            payloadBytes =
                (payloadBytes << 8U) | input[2U + index];
        }
        if (payloadBytes < 128U)
            return false;
    }
    return payloadBytes <= input.size() - headerBytes;
}

void appendDerHeader(
    std::vector<std::uint8_t> &output,
    std::uint8_t tag,
    std::size_t payloadBytes)
{
    output.push_back(tag);
    if (payloadBytes < 128U)
    {
        output.push_back(
            static_cast<std::uint8_t>(payloadBytes));
    }
    else if (payloadBytes <= 0xffU)
    {
        output.push_back(0x81U);
        output.push_back(
            static_cast<std::uint8_t>(payloadBytes));
    }
    else
    {
        output.push_back(0x82U);
        output.push_back(
            static_cast<std::uint8_t>(payloadBytes >> 8U));
        output.push_back(
            static_cast<std::uint8_t>(payloadBytes));
    }
}

[[nodiscard]] bool rewriteDerTypeTwo(
    std::span<const std::uint8_t> input,
    std::span<const std::uint8_t> replacement,
    std::vector<std::uint8_t> &output,
    bool &replaced,
    std::size_t depth = 0U)
{
    if (depth > 16U)
        return false;

    std::uint8_t tag = 0U;
    std::size_t headerBytes = 0U;
    std::size_t payloadBytes = 0U;
    if (!readDerObject(
            input, tag, headerBytes, payloadBytes) ||
        headerBytes + payloadBytes != input.size())
    {
        return false;
    }

    const auto payload =
        input.subspan(headerBytes, payloadBytes);
    if (tag == 0x04U &&
        typeTwoBytesAt(payload, 0U) == payload.size())
    {
        if (replaced)
            return false;
        appendDerHeader(output, tag, replacement.size());
        output.insert(
            output.end(),
            replacement.begin(),
            replacement.end());
        replaced = true;
        return true;
    }

    if ((tag & 0x20U) == 0U)
    {
        output.insert(output.end(), input.begin(), input.end());
        return true;
    }

    std::vector<std::uint8_t> rewrittenPayload;
    std::size_t offset = 0U;
    while (offset < payload.size())
    {
        [[maybe_unused]] std::uint8_t childTag = 0U;
        std::size_t childHeaderBytes = 0U;
        std::size_t childPayloadBytes = 0U;
        const auto remaining = payload.subspan(offset);
        if (!readDerObject(
                remaining,
                childTag,
                childHeaderBytes,
                childPayloadBytes))
        {
            return false;
        }
        const std::size_t childBytes =
            childHeaderBytes + childPayloadBytes;
        if (!rewriteDerTypeTwo(
                remaining.first(childBytes),
                replacement,
                rewrittenPayload,
                replaced,
                depth + 1U))
        {
            return false;
        }
        offset += childBytes;
    }

    appendDerHeader(output, tag, rewrittenPayload.size());
    output.insert(
        output.end(),
        rewrittenPayload.begin(),
        rewrittenPayload.end());
    return true;
}

[[nodiscard]] std::vector<std::uint8_t>
buildDiagnosticProviderReply(
    std::span<const std::uint8_t> clientToken,
    std::span<const std::uint8_t> providerReply,
    ChallengeExperiment experiment)
{
    std::uint32_t clientFlags = 0U;
    if (!readTypeOneFlags(clientToken, clientFlags))
        return {};

    const TypeTwoLocation location =
        findTypeTwo(providerReply);
    if (location.bytes == 0U)
        return {};

    const auto productionTypeTwo =
        providerReply.subspan(location.offset, location.bytes);
    const auto experimentalTypeTwo =
        makeTypeTwoExperiment(
            productionTypeTwo, clientFlags, experiment);
    if (experimentalTypeTwo.empty())
        return {};

    if (location.offset == 0U &&
        location.bytes == providerReply.size())
    {
        return experimentalTypeTwo;
    }

    std::vector<std::uint8_t> rewritten;
    bool replaced = false;
    if (!rewriteDerTypeTwo(
            providerReply,
            experimentalTypeTwo,
            rewritten,
            replaced) ||
        !replaced)
    {
        return {};
    }
    return rewritten;
}

class AllocatedSspiToken final
{
public:
    AllocatedSspiToken() noexcept = default;
    ~AllocatedSspiToken() { reset(); }

    AllocatedSspiToken(const AllocatedSspiToken &) = delete;
    AllocatedSspiToken &operator=(const AllocatedSspiToken &) = delete;

    AllocatedSspiToken(AllocatedSspiToken &&other) noexcept
        : data_(std::exchange(other.data_, nullptr)),
          size_(std::exchange(other.size_, 0U))
    {
    }

    AllocatedSspiToken &operator=(AllocatedSspiToken &&other) noexcept
    {
        if (this == &other)
            return *this;
        reset();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0U);
        return *this;
    }

    void adopt(void *data, unsigned long size) noexcept
    {
        reset();
        data_ = data;
        size_ = static_cast<std::size_t>(size);
    }

    [[nodiscard]] std::span<const std::uint8_t> view() const noexcept
    {
        if (data_ == nullptr)
            return {};
        return {
            static_cast<const std::uint8_t *>(data_),
            size_};
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return data_ == nullptr || size_ == 0U;
    }

private:
    void reset() noexcept
    {
        if (data_ != nullptr)
            FreeContextBuffer(data_);
        data_ = nullptr;
        size_ = 0U;
    }

    void *data_{};
    std::size_t size_{};
};

struct CredSspClientStep final
{
    SECURITY_STATUS status{SEC_E_INTERNAL_ERROR};
    ULONG contextAttributes{};
    AllocatedSspiToken output{};
    std::size_t retainedServerInputBytes{};
    bool stateChanged{};
};

[[nodiscard]] bool credSspClientStatusCanContinue(
    SECURITY_STATUS status) noexcept
{
    return status == SEC_E_OK ||
           status == SEC_I_CONTINUE_NEEDED ||
           status == SEC_E_INCOMPLETE_MESSAGE;
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

class WindowsCredSspClient final
{
public:
    WindowsCredSspClient() noexcept
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

        schannel_.dwVersion = SCHANNEL_CRED_VERSION;
        schannel_.dwFlags =
            SCH_CRED_MANUAL_CRED_VALIDATION |
            SCH_CRED_NO_DEFAULT_CREDS |
            SCH_USE_STRONG_CRYPTO;

        credSsp_.Type = CredsspSubmitBufferBoth;
        credSsp_.pSchannelCred = &schannel_;
        credSsp_.pSpnegoCred = &identity_;
    }

    ~WindowsCredSspClient()
    {
        if (contextValid_)
            DeleteSecurityContext(&context_);
        if (credentialValid_)
            FreeCredentialsHandle(&credential_);
        SecureZeroMemory(
            password_.data(), password_.size() * sizeof(password_[0]));
    }

    WindowsCredSspClient(const WindowsCredSspClient &) = delete;
    WindowsCredSspClient &operator=(const WindowsCredSspClient &) = delete;

    [[nodiscard]] SECURITY_STATUS acquire() noexcept
    {
        wchar_t packageName[] = L"CREDSSP";
        TimeStamp expiry{};
        const SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr,
            packageName,
            SECPKG_CRED_OUTBOUND,
            nullptr,
            &credSsp_,
            nullptr,
            nullptr,
            &credential_,
            &expiry);
        credentialValid_ = securityStatusSucceeded(status);
        return status;
    }

    [[nodiscard]] bool hasContext() const noexcept
    {
        return contextValid_;
    }

    [[nodiscard]] bool canContinueWithoutNewServerBytes() const noexcept
    {
        return contextValid_ && !needsMoreServerBytes_ &&
               (!pendingServerInput_.empty() ||
                continuationWithoutWireAllowed_);
    }

    [[nodiscard]] std::size_t pendingServerInputBytes() const noexcept
    {
        return pendingServerInput_.size();
    }

    [[nodiscard]] CredSspClientStep step(
        TargetProfile profile,
        std::span<const std::uint8_t> serverToken) noexcept
    {
        CredSspClientStep result{};
        if (!credentialValid_)
        {
            result.status = SEC_E_INVALID_HANDLE;
            return result;
        }

        std::array<wchar_t, 64> mutableTarget{};
        const auto sourceTarget = targetName(profile);
        if (sourceTarget.empty() ||
            sourceTarget.size() + 1U > mutableTarget.size())
        {
            result.status = SEC_E_TARGET_UNKNOWN;
            return result;
        }
        std::copy(
            sourceTarget.begin(), sourceTarget.end(), mutableTarget.begin());

        if (!serverToken.empty())
        {
            if (serverToken.size() >
                    kMaximumRawTokenBytes - pendingServerInput_.size())
            {
                result.status = SEC_E_INSUFFICIENT_MEMORY;
                return result;
            }
            try
            {
                pendingServerInput_.insert(
                    pendingServerInput_.end(),
                    serverToken.begin(),
                    serverToken.end());
            }
            catch (...)
            {
                result.status = SEC_E_INSUFFICIENT_MEMORY;
                return result;
            }
        }

        const bool contextWasValid = contextValid_;
        const SECURITY_STATUS previousStatus = lastStatus_;
        const ULONG previousContextAttributes = lastContextAttributes_;
        const bool previouslyNeededMoreServerBytes = needsMoreServerBytes_;
        const bool previouslyAllowedContinuation =
            continuationWithoutWireAllowed_;
        const std::size_t providerInputBytes =
            pendingServerInput_.size();

        std::array<SecBuffer, 2> inputBuffers{};
        SecBufferDesc inputDescriptor{};
        SecBufferDesc *input = nullptr;
        if (contextValid_)
        {
            if (pendingServerInput_.size() >
                    static_cast<std::size_t>(
                        (std::numeric_limits<unsigned long>::max)()))
            {
                result.status = SEC_E_INSUFFICIENT_MEMORY;
                return result;
            }
            if (pendingServerInput_.empty() && needsMoreServerBytes_)
            {
                result.status = SEC_E_INCOMPLETE_MESSAGE;
                result.retainedServerInputBytes = 0U;
                return result;
            }

            inputBuffers[0].BufferType = SECBUFFER_TOKEN;
            inputBuffers[0].cbBuffer =
                static_cast<unsigned long>(
                    pendingServerInput_.size());
            inputBuffers[0].pvBuffer =
                pendingServerInput_.empty()
                    ? nullptr
                    : pendingServerInput_.data();
            inputBuffers[1].BufferType = SECBUFFER_EMPTY;
            inputDescriptor.ulVersion = SECBUFFER_VERSION;
            inputDescriptor.cBuffers =
                static_cast<unsigned long>(inputBuffers.size());
            inputDescriptor.pBuffers = inputBuffers.data();
            input = &inputDescriptor;
        }

        SecBuffer outputBuffer{};
        outputBuffer.BufferType = SECBUFFER_TOKEN;
        SecBufferDesc outputDescriptor{
            SECBUFFER_VERSION, 1U, &outputBuffer};

        TimeStamp expiry{};
        CtxtHandle newContext{};
        CtxtHandle *const existingContext =
            contextValid_ ? &context_ : nullptr;
        CtxtHandle *const outputContext =
            contextValid_ ? &context_ : &newContext;

        result.status = InitializeSecurityContextW(
            &credential_,
            existingContext,
            mutableTarget.data(),
            kCredSspContextRequirements,
            0U,
            SECURITY_NATIVE_DREP,
            input,
            0U,
            outputContext,
            &outputDescriptor,
            &result.contextAttributes,
            &expiry);

        if (!contextValid_ && securityStatusSucceeded(result.status))
        {
            context_ = newContext;
            contextValid_ = true;
        }

        if (contextValid_)
        {
            result.status = completeOutputTokenIfNeeded(
                result.status, context_, outputDescriptor);
        }

        if (input != nullptr &&
            result.status != SEC_E_INCOMPLETE_MESSAGE)
        {
            if (inputBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                const std::size_t extraBytes =
                    inputBuffers[1].cbBuffer;
                if (extraBytes > pendingServerInput_.size())
                {
                    result.status = SEC_E_INVALID_TOKEN;
                    pendingServerInput_.clear();
                }
                else
                {
                    const std::size_t extraOffset =
                        pendingServerInput_.size() - extraBytes;
                    if (extraBytes != 0U)
                    {
                        std::memmove(
                            pendingServerInput_.data(),
                            pendingServerInput_.data() + extraOffset,
                            extraBytes);
                    }
                    pendingServerInput_.resize(extraBytes);
                }
            }
            else
            {
                pendingServerInput_.clear();
            }
        }

        if (outputBuffer.pvBuffer != nullptr)
        {
            result.output.adopt(
                outputBuffer.pvBuffer, outputBuffer.cbBuffer);
            outputBuffer.pvBuffer = nullptr;
            outputBuffer.cbBuffer = 0U;
        }

        needsMoreServerBytes_ =
            result.status == SEC_E_INCOMPLETE_MESSAGE;
        continuationWithoutWireAllowed_ =
            result.status == SEC_I_CONTINUE_NEEDED &&
            result.output.empty() &&
            !needsMoreServerBytes_;
        result.retainedServerInputBytes =
            pendingServerInput_.size();
        result.stateChanged =
            contextWasValid != contextValid_ ||
            providerInputBytes != pendingServerInput_.size() ||
            previousStatus != result.status ||
            previousContextAttributes != result.contextAttributes ||
            previouslyNeededMoreServerBytes != needsMoreServerBytes_ ||
            previouslyAllowedContinuation !=
                continuationWithoutWireAllowed_ ||
            !result.output.empty();
        lastStatus_ = result.status;
        lastContextAttributes_ = result.contextAttributes;
        return result;
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
    SCHANNEL_CRED schannel_{};
    CREDSSP_CRED credSsp_{};
    CredHandle credential_{};
    CtxtHandle context_{};
    std::vector<std::uint8_t> pendingServerInput_{};
    SECURITY_STATUS lastStatus_{SEC_E_INTERNAL_ERROR};
    ULONG lastContextAttributes_{};
    bool credentialValid_{};
    bool contextValid_{};
    bool needsMoreServerBytes_{};
    bool continuationWithoutWireAllowed_{};
};

enum class TlsAdvance : std::uint8_t
{
    NeedRead,
    NeedWrite,
    Ready,
    Failed,
};

enum class FrameAdvance : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Complete,
    Failed,
};

enum class ReplyAdvance : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    Complete,
    Failed,
};

class ProductionCredSspServer final
{
public:
    explicit ProductionCredSspServer(
        ChallengeExperiment experiment =
            ChallengeExperiment::Production) noexcept
        : experiment_(experiment),
          tls_(nullptr, &SSL_free)
    {
        tlsContext_ =
            RuntimeServerTlsContext::fromGeneratedIpAddress(
                kPhysicalEndpoint);
        if (!tlsContext_ ||
            tlsContext_.validateEndpointIdentity(kPhysicalEndpoint) !=
                RuntimeTlsEndpointIdentityStatus::Match)
        {
            return;
        }

        tls_ = tlsContext_.createServerTls();
        if (!tls_)
            return;

        BIO *inputBio = BIO_new(BIO_s_mem());
        BIO *outputBio = BIO_new(BIO_s_mem());
        if (inputBio == nullptr || outputBio == nullptr)
        {
            BIO_free(inputBio);
            BIO_free(outputBio);
            return;
        }
        BIO_set_mem_eof_return(inputBio, -1);
        BIO_set_mem_eof_return(outputBio, -1);
        SSL_set_bio(tls_.get(), inputBio, outputBio);
        inputBio_ = SSL_get_rbio(tls_.get());
        outputBio_ = SSL_get_wbio(tls_.get());

        std::array<char16_t, 8> password{
            u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
        const bool credentialReady =
            credential_.configure(u"User", password);
        SecureZeroMemory(
            password.data(), password.size() * sizeof(password[0]));
        if (!credentialReady)
            return;

        const std::uint64_t timestamp = currentWindowsFileTime();
        if (timestamp == 0U)
            return;
        const StandaloneSpnegoChallengeConfiguration challenge{
            kServerChallenge,
            kStandaloneNtlmPortableDomainName,
            kStandaloneNtlmPortableServerName,
            timestamp};
        const bool mechanismReady =
            experiment_ == ChallengeExperiment::Production
            ? acceptor_.configureChallenge(challenge)
            : diagnosticMechanism_.configureChallenge(challenge);
        if (!mechanismReady)
            return;

        valid_ = inputBio_ != nullptr && outputBio_ != nullptr;
    }

    [[nodiscard]] bool valid() const noexcept { return valid_; }

    [[nodiscard]] bool feedRaw(
        std::span<const std::uint8_t> bytes) noexcept
    {
        if (!valid_ || bytes.empty() ||
            bytes.size() > kMaximumRawTokenBytes)
        {
            return false;
        }

        std::size_t offset = 0U;
        while (offset < bytes.size())
        {
            std::size_t written = 0U;
            if (BIO_write_ex(
                    inputBio_,
                    bytes.data() + offset,
                    bytes.size() - offset,
                    &written) != 1 ||
                written == 0U)
            {
                return false;
            }
            offset += written;
        }
        return true;
    }

    [[nodiscard]] std::vector<std::uint8_t> drainRaw()
    {
        std::vector<std::uint8_t> output;
        if (!valid_)
            return output;

        std::array<std::uint8_t, 16U * 1024U> buffer{};
        for (;;)
        {
            const std::size_t pending =
                static_cast<std::size_t>(BIO_ctrl_pending(outputBio_));
            if (pending == 0U)
                break;
            if (output.size() + pending > kMaximumRawTokenBytes)
            {
                output.clear();
                valid_ = false;
                break;
            }

            std::size_t read = 0U;
            const std::size_t requested =
                std::min(buffer.size(), pending);
            if (BIO_read_ex(
                    outputBio_, buffer.data(), requested, &read) != 1 ||
                read == 0U)
            {
                output.clear();
                valid_ = false;
                break;
            }
            output.insert(
                output.end(),
                buffer.begin(),
                buffer.begin() + static_cast<std::ptrdiff_t>(read));
        }
        return output;
    }

    [[nodiscard]] bool tlsReady() const noexcept
    {
        return valid_ && SSL_is_init_finished(tls_.get()) == 1;
    }

    [[nodiscard]] int tlsStateValue() const noexcept
    {
        return tls_
            ? static_cast<int>(SSL_get_state(tls_.get()))
            : -1;
    }

    [[nodiscard]] int negotiatedTlsVersion() const noexcept
    {
        return tlsReady() ? SSL_version(tls_.get()) : 0;
    }

    [[nodiscard]] int minimumTlsVersion() const noexcept
    {
        return tls_ ? SSL_get_min_proto_version(tls_.get()) : 0;
    }

    [[nodiscard]] int maximumTlsVersion() const noexcept
    {
        return tls_ ? SSL_get_max_proto_version(tls_.get()) : 0;
    }

    [[nodiscard]] std::size_t inputBioPendingBytes() const noexcept
    {
        return inputBio_ != nullptr
            ? static_cast<std::size_t>(BIO_ctrl_pending(inputBio_))
            : 0U;
    }

    [[nodiscard]] std::size_t outputBioPendingBytes() const noexcept
    {
        return outputBio_ != nullptr
            ? static_cast<std::size_t>(BIO_ctrl_pending(outputBio_))
            : 0U;
    }

    [[nodiscard]] std::size_t applicationPendingBytes() const noexcept
    {
        if (!tls_)
            return 0U;
        const int pending = SSL_pending(tls_.get());
        return pending > 0
            ? static_cast<std::size_t>(pending)
            : 0U;
    }

    [[nodiscard]] int replyStateValue() const noexcept
    {
        return static_cast<int>(writer_.status());
    }

    [[nodiscard]] TlsAdvance advanceHandshake() noexcept
    {
        if (!valid_)
            return TlsAdvance::Failed;
        if (SSL_is_init_finished(tls_.get()) == 1)
            return TlsAdvance::Ready;

        ERR_clear_error();
        const int handshakeResult = SSL_do_handshake(tls_.get());
        if (handshakeResult == 1)
            return TlsAdvance::Ready;
        const int error = SSL_get_error(tls_.get(), handshakeResult);
        if (error == SSL_ERROR_WANT_READ)
            return TlsAdvance::NeedRead;
        if (error == SSL_ERROR_WANT_WRITE)
            return TlsAdvance::NeedWrite;
        return TlsAdvance::Failed;
    }

    [[nodiscard]] FrameAdvance advanceFrame() noexcept
    {
        if (!valid_ || SSL_is_init_finished(tls_.get()) != 1)
            return FrameAdvance::Failed;

        const auto result = reader_.readOneTlsStep(tls_.get());
        switch (result.status)
        {
        case TsRequestTlsReadStatus::Progress:
            return FrameAdvance::Progress;
        case TsRequestTlsReadStatus::NeedRead:
            return FrameAdvance::NeedRead;
        case TsRequestTlsReadStatus::NeedWrite:
            return FrameAdvance::NeedWrite;
        case TsRequestTlsReadStatus::Complete:
            return FrameAdvance::Complete;
        case TsRequestTlsReadStatus::Invalid:
        case TsRequestTlsReadStatus::Closed:
            return FrameAdvance::Failed;
        }
        return FrameAdvance::Failed;
    }

    [[nodiscard]] bool processInitialFrame() noexcept
    {
        if (reader_.status() != TsRequestFrameStatus::Complete)
            return false;
        const auto request = parseCredSspTsRequest(reader_.completeDer());
        if (!request || request.value.version != 6U ||
            request.value.tokenCount != 1U ||
            !request.value.initialNegoTokenOnly())
        {
            return false;
        }

        if (experiment_ != ChallengeExperiment::Production)
        {
            std::array<
                std::uint8_t,
                kMaximumStandaloneSpnegoTokenBytes> providerStorage{};
            const StandaloneSpnegoStep mechanismStep =
                diagnosticMechanism_.acceptInitialToken(
                    request.value.tokens[0],
                    providerStorage);
            if (!mechanismStep ||
                mechanismStep.bytesWritten == 0U ||
                mechanismStep.bytesWritten > providerStorage.size())
            {
                return false;
            }

            const auto providerReply =
                std::span<const std::uint8_t>{providerStorage}.first(
                    mechanismStep.bytesWritten);
            const auto selectedProviderReply =
                buildDiagnosticProviderReply(
                    request.value.tokens[0],
                    providerReply,
                    experiment_);
            if (selectedProviderReply.empty() ||
                !reader_.releaseFrame())
            {
                return false;
            }
            return writer_.queueReply(
                tls_.get(),
                request.value.version,
                CredSspServerReplyField::NegoToken,
                selectedProviderReply);
        }

        const auto status = acceptor_.processCompleteFrame(
            reader_, writer_, credential_);
        return status == StandaloneCredSspFrameStatus::NegoReplyQueued &&
               acceptor_.lastNtlmMessageType() == 1U &&
               acceptor_.stage() == StandaloneCredSspStage::NegoContinue;
    }

    [[nodiscard]] ReplyAdvance advanceProductionReply() noexcept
    {
        if (!valid_ || SSL_is_init_finished(tls_.get()) != 1)
            return ReplyAdvance::Failed;

        const auto result = writer_.writeOneTlsStep(tls_.get());
        switch (result.status)
        {
        case TsRequestTlsWriteStatus::Progress:
            return ReplyAdvance::Progress;
        case TsRequestTlsWriteStatus::NeedRead:
            return ReplyAdvance::NeedRead;
        case TsRequestTlsWriteStatus::NeedWrite:
            return ReplyAdvance::NeedWrite;
        case TsRequestTlsWriteStatus::Complete:
            return ReplyAdvance::Complete;
        case TsRequestTlsWriteStatus::Idle:
        case TsRequestTlsWriteStatus::Invalid:
        case TsRequestTlsWriteStatus::Closed:
            return ReplyAdvance::Failed;
        }
        return ReplyAdvance::Failed;
    }

    [[nodiscard]] bool releaseProductionReply() noexcept
    {
        return writer_.status() == TsRequestTlsWriteStatus::Complete &&
               writer_.releaseReply();
    }

    [[nodiscard]] bool processNextClientFrame(
        std::uint8_t &tokenCount,
        bool &hasPubKeyAuth,
        bool &typeThreeObserved,
        bool &typeThreeVerified) noexcept
    {
        tokenCount = 0U;
        hasPubKeyAuth = false;
        typeThreeObserved = false;
        typeThreeVerified = false;
        if (reader_.status() != TsRequestFrameStatus::Complete)
            return false;

        const auto request = parseCredSspTsRequest(reader_.completeDer());
        if (!request)
            return false;
        tokenCount = request.value.tokenCount;
        hasPubKeyAuth = request.value.hasPubKeyAuth;
        for (std::uint8_t index = 0U;
             index < request.value.tokenCount;
             ++index)
        {
            if (hasNtlmMessageType(
                    request.value.tokens[index], 3U))
            {
                typeThreeObserved = true;
                break;
            }
        }

        // The P0 oracle stops at the next client message. A Type 3 signature
        // is useful evidence but does not require advancing pubKeyAuth or
        // credential delegation in this test.
        typeThreeVerified = false;
        return reader_.releaseFrame();
    }

    [[nodiscard]] NtlmChallengeMessageObservation
    challengeObservation() const noexcept
    {
        return experiment_ == ChallengeExperiment::Production
            ? acceptor_.challengeObservation()
            : diagnosticMechanism_.challengeObservation();
    }

private:
    ChallengeExperiment experiment_{ChallengeExperiment::Production};
    RuntimeServerTlsContext tlsContext_{};
    RuntimeServerTlsContext::ServerTls tls_;
    BIO *inputBio_{};
    BIO *outputBio_{};
    TsRequestFrameReader reader_{};
    TsRequestTlsReplyWriter writer_{};
    StandaloneCredSspNtlmAcceptor acceptor_{};
    StandaloneSpnegoNtlmAcceptor diagnosticMechanism_{};
    EphemeralNtlmV2Credential credential_{};
    bool valid_{};
};

enum class CredSspPumpBoundary : std::uint8_t
{
    InitialClientTsRequest,
    NextClientTsRequest,
};

enum class CredSspPumpStopReason : std::uint8_t
{
    BoundaryComplete,
    TypedFailure,
    NoProgress,
    RoundLimit,
};

struct CredSspPumpIteration final
{
    std::size_t clientToServerBytes{};
    std::size_t serverToClientBytes{};
    std::size_t serverInputBioPendingBytes{};
    std::size_t serverOutputBioPendingBytes{};
    std::size_t serverApplicationPendingBytes{};
    std::size_t microsoftRetainedServerInputBytes{};
    SECURITY_STATUS microsoftStatus{SEC_E_INTERNAL_ERROR};
    bool serverTlsStateChanged{};
    bool serverApplicationFrameCompleted{};
    bool microsoftSspiCalled{};
    bool microsoftSspiStateChanged{};
    bool serverApplicationStateChanged{};
    bool serverBufferedStateChanged{};

    [[nodiscard]] bool anyProgress() const noexcept
    {
        return clientToServerBytes != 0U ||
               serverToClientBytes != 0U ||
               serverTlsStateChanged ||
               serverApplicationFrameCompleted ||
               microsoftSspiStateChanged ||
               serverApplicationStateChanged ||
               serverBufferedStateChanged;
    }
};

struct CredSspPumpResult final
{
    std::array<CredSspPumpIteration, kMaximumExchangeRounds> iterations{};
    std::size_t iterationCount{};
    SECURITY_STATUS lastClientStatus{SEC_E_INTERNAL_ERROR};
    const char *failureStage{"memory-bio-round-limit"};
    CredSspPumpStopReason stopReason{CredSspPumpStopReason::RoundLimit};
    int negotiatedTlsVersion{};
    bool tlsEstablished{};
    bool productionReplyCommitted{};
    bool microsoftOutputGenerated{};
};

[[nodiscard]] CredSspPumpResult pumpCredSspMemoryBio(
    TargetProfile profile,
    WindowsCredSspClient &client,
    ProductionCredSspServer &server,
    CredSspPumpBoundary boundary,
    bool sendQueuedProductionReply)
{
    CredSspPumpResult result{};
    CredSspClientStep pendingClientStep{};
    bool havePendingClientStep = false;
    bool productionReplyCommitted = !sendQueuedProductionReply;

    for (std::size_t round = 0U;
         round < kMaximumExchangeRounds;
         ++round)
    {
        CredSspPumpIteration iteration{};
        iteration.microsoftStatus = result.lastClientStatus;

        if (havePendingClientStep &&
            !pendingClientStep.output.empty())
        {
            const auto output = pendingClientStep.output.view();
            iteration.clientToServerBytes = output.size();
            if (!server.feedRaw(output))
            {
                result.failureStage = "memory-bio-client-to-server";
                result.stopReason = CredSspPumpStopReason::TypedFailure;
                result.iterations[result.iterationCount++] = iteration;
                return result;
            }
        }
        pendingClientStep = {};
        havePendingClientStep = false;

        const int tlsStateBefore = server.tlsStateValue();
        const std::size_t inputPendingBefore =
            server.inputBioPendingBytes();
        const std::size_t applicationPendingBefore =
            server.applicationPendingBytes();

        bool serverProviderOperationPerformed = false;
        if (!server.tlsReady())
        {
            const TlsAdvance tlsAdvance = server.advanceHandshake();
            serverProviderOperationPerformed = true;
            if (tlsAdvance == TlsAdvance::Failed)
            {
                result.failureStage = "memory-bio-server-tls";
                result.stopReason = CredSspPumpStopReason::TypedFailure;
                result.iterations[result.iterationCount++] = iteration;
                return result;
            }
        }

        if (server.tlsReady() && !serverProviderOperationPerformed)
        {
            result.tlsEstablished = true;
            result.negotiatedTlsVersion =
                server.negotiatedTlsVersion();

            if (!productionReplyCommitted)
            {
                const int replyStateBefore =
                    server.replyStateValue();
                const ReplyAdvance reply =
                    server.advanceProductionReply();
                iteration.serverApplicationStateChanged =
                    reply == ReplyAdvance::Progress ||
                    reply == ReplyAdvance::Complete ||
                    server.replyStateValue() != replyStateBefore;
                if (reply == ReplyAdvance::Failed)
                {
                    result.failureStage =
                        "memory-bio-production-type2-write";
                    result.stopReason =
                        CredSspPumpStopReason::TypedFailure;
                    result.iterations[result.iterationCount++] =
                        iteration;
                    return result;
                }
                if (reply == ReplyAdvance::Complete)
                {
                    if (!server.releaseProductionReply())
                    {
                        result.failureStage =
                            "memory-bio-production-type2-release";
                        result.stopReason =
                            CredSspPumpStopReason::TypedFailure;
                        result.iterations[result.iterationCount++] =
                            iteration;
                        return result;
                    }
                    productionReplyCommitted = true;
                    result.productionReplyCommitted = true;
                }
            }
            else
            {
                const FrameAdvance frame = server.advanceFrame();
                iteration.serverApplicationStateChanged =
                    frame == FrameAdvance::Progress;
                if (frame == FrameAdvance::Failed)
                {
                    result.failureStage =
                        boundary ==
                            CredSspPumpBoundary::InitialClientTsRequest
                        ? "memory-bio-server-initial-tsrequest"
                        : "memory-bio-server-next-tsrequest";
                    result.stopReason =
                        CredSspPumpStopReason::TypedFailure;
                    result.iterations[result.iterationCount++] =
                        iteration;
                    return result;
                }
                iteration.serverApplicationFrameCompleted =
                    frame == FrameAdvance::Complete;
            }
        }

        iteration.serverTlsStateChanged =
            server.tlsStateValue() != tlsStateBefore;
        const std::size_t inputPendingAfter =
            server.inputBioPendingBytes();
        const std::size_t applicationPendingAfter =
            server.applicationPendingBytes();
        iteration.serverBufferedStateChanged =
            inputPendingAfter != inputPendingBefore ||
            applicationPendingAfter != applicationPendingBefore;

        if (iteration.serverApplicationFrameCompleted)
        {
            iteration.serverInputBioPendingBytes =
                inputPendingAfter;
            iteration.serverOutputBioPendingBytes =
                server.outputBioPendingBytes();
            iteration.serverApplicationPendingBytes =
                applicationPendingAfter;
            iteration.microsoftRetainedServerInputBytes =
                client.pendingServerInputBytes();
            result.iterations[result.iterationCount++] =
                iteration;
            result.stopReason =
                CredSspPumpStopReason::BoundaryComplete;
            result.failureStage = "none";
            return result;
        }

        const auto serverToken = server.drainRaw();
        if (!server.valid())
        {
            result.failureStage = "memory-bio-server-to-client";
            result.stopReason = CredSspPumpStopReason::TypedFailure;
            result.iterations[result.iterationCount++] = iteration;
            return result;
        }
        iteration.serverToClientBytes = serverToken.size();

        const bool shouldAdvanceMicrosoft =
            !serverToken.empty() ||
            !client.hasContext() ||
            client.canContinueWithoutNewServerBytes();
        if (shouldAdvanceMicrosoft)
        {
            const char *const phase =
                !client.hasContext()
                ? "initial-context"
                : boundary ==
                      CredSspPumpBoundary::InitialClientTsRequest
                    ? "tls-or-credssp-continue"
                    : "after-production-type2";
            pendingClientStep =
                client.step(profile, serverToken);
            havePendingClientStep = true;
            iteration.microsoftSspiCalled = true;
            iteration.microsoftSspiStateChanged =
                pendingClientStep.stateChanged;
            iteration.microsoftStatus =
                pendingClientStep.status;
            iteration.microsoftRetainedServerInputBytes =
                pendingClientStep.retainedServerInputBytes;
            result.lastClientStatus =
                pendingClientStep.status;
            printClientStatus(
                profile, phase, pendingClientStep.status);

            if (!credSspClientStatusCanContinue(
                    pendingClientStep.status))
            {
                result.failureStage = "memory-bio-microsoft-credssp";
                result.stopReason =
                    CredSspPumpStopReason::TypedFailure;
                result.iterations[result.iterationCount++] =
                    iteration;
                return result;
            }

            if (sendQueuedProductionReply &&
                productionReplyCommitted &&
                !pendingClientStep.output.empty())
            {
                result.microsoftOutputGenerated = true;
            }
        }
        else
        {
            iteration.microsoftRetainedServerInputBytes =
                client.pendingServerInputBytes();
        }

        iteration.serverInputBioPendingBytes =
            server.inputBioPendingBytes();
        iteration.serverOutputBioPendingBytes =
            server.outputBioPendingBytes();
        iteration.serverApplicationPendingBytes =
            server.applicationPendingBytes();
        result.iterations[result.iterationCount++] = iteration;

        if (!iteration.anyProgress())
        {
            result.failureStage = "memory-bio-no-progress";
            result.stopReason = CredSspPumpStopReason::NoProgress;
            return result;
        }
    }

    return result;
}

struct FullCredSspAttempt final
{
    const char *stage{"not-started"};
    SECURITY_STATUS acquireStatus{SEC_E_INTERNAL_ERROR};
    SECURITY_STATUS lastClientStatus{SEC_E_INTERNAL_ERROR};
    CredSspPumpResult initialPump{};
    CredSspPumpResult nextPump{};
    std::uint32_t typeTwoFlags{};
    std::size_t typeTwoTargetNameCodeUnits{};
    int minimumTlsVersion{};
    int maximumTlsVersion{};
    int negotiatedTlsVersion{};
    bool tlsEstablished{};
    bool initialClientTsRequestReceived{};
    bool productionTypeTwoQueued{};
    bool productionTypeTwoTlsCommitted{};
    bool microsoftNextTokenGenerated{};
    bool nextClientTsRequestReceived{};
    bool productionObservedTypeThree{};
    bool productionVerifiedTypeThree{};
    bool nextClientHasPubKeyAuth{};
};

[[nodiscard]] FullCredSspAttempt runFullCredSspAttempt(
    TargetProfile profile,
    ChallengeExperiment experiment =
        ChallengeExperiment::Production)
{
    FullCredSspAttempt result{};
    WindowsCredSspClient client;
    ProductionCredSspServer server{experiment};
    if (!server.valid())
    {
        result.stage = "production-server-setup";
        return result;
    }
    result.minimumTlsVersion = server.minimumTlsVersion();
    result.maximumTlsVersion = server.maximumTlsVersion();

    result.stage = "acquire-credssp";
    result.acquireStatus = client.acquire();
    printClientStatus(
        profile, "acquire-credentials", result.acquireStatus);
    if (!securityStatusSucceeded(result.acquireStatus))
        return result;

    result.stage = "memory-bio-initial-tsrequest";
    result.initialPump = pumpCredSspMemoryBio(
        profile, client, server,
        CredSspPumpBoundary::InitialClientTsRequest, false);
    result.lastClientStatus = result.initialPump.lastClientStatus;
    result.tlsEstablished = result.initialPump.tlsEstablished;
    result.negotiatedTlsVersion =
        result.initialPump.negotiatedTlsVersion;
    if (result.initialPump.stopReason !=
        CredSspPumpStopReason::BoundaryComplete)
    {
        result.stage = result.initialPump.failureStage;
        return result;
    }
    result.initialClientTsRequestReceived = true;

    result.stage = "production-type2";
    if (!server.processInitialFrame())
        return result;
    result.productionTypeTwoQueued = true;
    const auto challenge = server.challengeObservation();
    result.typeTwoFlags = challenge.negotiateFlags;
    result.typeTwoTargetNameCodeUnits = challenge.targetNameCodeUnits;

    result.stage = "memory-bio-after-production-type2";
    result.nextPump = pumpCredSspMemoryBio(
        profile, client, server,
        CredSspPumpBoundary::NextClientTsRequest, true);
    result.lastClientStatus = result.nextPump.lastClientStatus;
    result.productionTypeTwoTlsCommitted =
        result.nextPump.productionReplyCommitted;
    result.microsoftNextTokenGenerated =
        result.nextPump.microsoftOutputGenerated;
    if (result.nextPump.negotiatedTlsVersion != 0)
        result.negotiatedTlsVersion = result.nextPump.negotiatedTlsVersion;
    if (result.nextPump.stopReason !=
        CredSspPumpStopReason::BoundaryComplete)
    {
        result.stage = result.nextPump.failureStage;
        return result;
    }
    result.nextClientTsRequestReceived = true;

    [[maybe_unused]] std::uint8_t tokenCount = 0U;
    result.stage = "production-consume-next-client-token";
    if (!server.processNextClientFrame(
            tokenCount,
            result.nextClientHasPubKeyAuth,
            result.productionObservedTypeThree,
            result.productionVerifiedTypeThree))
    {
        return result;
    }
    result.stage = "none";
    return result;
}

[[nodiscard]] const char *tlsVersionName(int version) noexcept
{
    switch (version)
    {
    case 0:
        return "default";
    case TLS1_2_VERSION:
        return "TLS1.2";
#if defined(TLS1_3_VERSION)
    case TLS1_3_VERSION:
        return "TLS1.3";
#endif
    default:
        return "other";
    }
}

[[nodiscard]] const char *pumpStopReasonName(
    CredSspPumpStopReason reason) noexcept
{
    switch (reason)
    {
    case CredSspPumpStopReason::BoundaryComplete:
        return "boundary-complete";
    case CredSspPumpStopReason::TypedFailure:
        return "typed-failure";
    case CredSspPumpStopReason::NoProgress:
        return "no-progress";
    case CredSspPumpStopReason::RoundLimit:
        return "round-limit";
    }
    return "unknown";
}

void printPumpTrace(
    const char *phase,
    const CredSspPumpResult &pump) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-credssp-pump-summary phase=%s stop=%s "
        "rounds=%zu failure-stage=%s\n",
        phase, pumpStopReasonName(pump.stopReason),
        pump.iterationCount, pump.failureStage);
    for (std::size_t index = 0U; index < pump.iterationCount; ++index)
    {
        const auto &iteration = pump.iterations[index];
        std::fprintf(
            stderr,
            "microsoft-credssp-pump phase=%s round=%zu "
            "client-to-server=%zu server-to-client=%zu "
            "tls-state-changed=%s app-frame-completed=%s "
            "sspi-called=%s sspi-state-changed=%s "
            "app-state-changed=%s buffered-state-changed=%s "
            "rbio-pending=%zu wbio-pending=%zu ssl-pending=%zu "
            "sspi-retained=%zu sspi-status=%s code=0x%08lx\n",
            phase, index,
            iteration.clientToServerBytes,
            iteration.serverToClientBytes,
            iteration.serverTlsStateChanged ? "yes" : "no",
            iteration.serverApplicationFrameCompleted ? "yes" : "no",
            iteration.microsoftSspiCalled ? "yes" : "no",
            iteration.microsoftSspiStateChanged ? "yes" : "no",
            iteration.serverApplicationStateChanged ? "yes" : "no",
            iteration.serverBufferedStateChanged ? "yes" : "no",
            iteration.serverInputBioPendingBytes,
            iteration.serverOutputBioPendingBytes,
            iteration.serverApplicationPendingBytes,
            iteration.microsoftRetainedServerInputBytes,
            securityStatusName(iteration.microsoftStatus),
            static_cast<unsigned long>(
                static_cast<std::uint32_t>(iteration.microsoftStatus)));
    }
}

void printStatus(const char *label, SECURITY_STATUS status) noexcept
{
    std::fprintf(
        stderr,
        "%s=0x%08lx\n",
        label,
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(status)));
}

void printFailure(
    TargetProfile profile,
    const FullCredSspAttempt &result) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-credssp target=%s stage=%s tls=%s "
        "tls-version=%s tls-min=%s tls-max=%s "
        "initial-tsrequest=%s type2-queued=%s type2-tls-committed=%s "
        "type2-flags=0x%08lx type2-target-code-units=%zu "
        "next-token=%s next-tsrequest=%s type3=%s "
        "type3-verified=%s pubkeyauth=%s\n",
        targetLabel(profile),
        result.stage,
        result.tlsEstablished ? "established" : "not-established",
        tlsVersionName(result.negotiatedTlsVersion),
        tlsVersionName(result.minimumTlsVersion),
        tlsVersionName(result.maximumTlsVersion),
        result.initialClientTsRequestReceived ? "yes" : "no",
        result.productionTypeTwoQueued ? "yes" : "no",
        result.productionTypeTwoTlsCommitted ? "yes" : "no",
        static_cast<unsigned long>(result.typeTwoFlags),
        result.typeTwoTargetNameCodeUnits,
        result.microsoftNextTokenGenerated ? "yes" : "no",
        result.nextClientTsRequestReceived ? "yes" : "no",
        result.productionObservedTypeThree ? "yes" : "no",
        result.productionVerifiedTypeThree ? "yes" : "no",
        result.nextClientHasPubKeyAuth ? "yes" : "no");
    printStatus("microsoft-credssp-acquire-status", result.acquireStatus);
    printStatus(
        "microsoft-credssp-last-client-status",
        result.lastClientStatus);
    if (result.initialPump.iterationCount != 0U &&
        result.initialPump.stopReason != CredSspPumpStopReason::BoundaryComplete)
        printPumpTrace("initial-tsrequest", result.initialPump);
    if (result.nextPump.iterationCount != 0U &&
        result.nextPump.stopReason != CredSspPumpStopReason::BoundaryComplete)
        printPumpTrace("after-production-type2", result.nextPump);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;

    const std::string_view mode{argv[1]};
    TargetProfile profile{};
    if (mode == "control-target")
        profile = TargetProfile::PortableServerName;
    else if (mode == "physical-ip-target")
        profile = TargetProfile::PhysicalIpv4;
    else if (mode == "bare-ip-target")
        profile = TargetProfile::BarePhysicalIpv4;
    else
        return 2;

    const auto acceptedNextClientMessage =
        [](const FullCredSspAttempt &attempt) noexcept
    {
        return std::string_view{attempt.stage} == "none" &&
               attempt.tlsEstablished &&
               attempt.initialClientTsRequestReceived &&
               attempt.productionTypeTwoQueued &&
               attempt.productionTypeTwoTlsCommitted &&
               attempt.microsoftNextTokenGenerated &&
               attempt.nextClientTsRequestReceived;
    };

    const FullCredSspAttempt result =
        runFullCredSspAttempt(
            profile, ChallengeExperiment::Production);
    if (acceptedNextClientMessage(result))
    {
        std::fprintf(
            stderr,
            "microsoft-credssp target=%s production-type2=accepted "
            "tls=%s next-client-token=yes type3=%s type3-verified=%s "
            "pubkeyauth=%s\n",
            targetLabel(profile),
            tlsVersionName(result.negotiatedTlsVersion),
            result.productionObservedTypeThree ? "yes" : "no",
            result.productionVerifiedTypeThree ? "yes" : "no",
            result.nextClientHasPubKeyAuth ? "yes" : "no");
        return 0;
    }

    printFailure(profile, result);

    if (profile != TargetProfile::PhysicalIpv4)
        return 1;

    const FullCredSspAttempt control =
        runFullCredSspAttempt(
            TargetProfile::PortableServerName,
            ChallengeExperiment::Production);
    if (!acceptedNextClientMessage(control))
    {
        std::fprintf(
            stderr,
            "microsoft-credssp-identity-experiments="
            "skipped-control-not-accepted\n");
        return 1;
    }

    constexpr std::array experiments{
        ChallengeExperiment::EndpointTypeTwoTargetName,
        ChallengeExperiment::EndpointMsvAvTargetName,
        ChallengeExperiment::EndpointTypeTwoAndMsvAvTargetName};

    const char *firstAcceptedExperiment = nullptr;
    for (const ChallengeExperiment experiment : experiments)
    {
        const FullCredSspAttempt diagnostic =
            runFullCredSspAttempt(
                TargetProfile::PhysicalIpv4, experiment);
        std::fprintf(
            stderr,
            "microsoft-credssp-diagnostic target=%s experiment=%s "
            "next-client-token=%s type3=%s pubkeyauth=%s stage=%s\n",
            targetLabel(TargetProfile::PhysicalIpv4),
            experimentName(experiment),
            diagnostic.microsoftNextTokenGenerated ? "yes" : "no",
            diagnostic.productionObservedTypeThree ? "yes" : "no",
            diagnostic.nextClientHasPubKeyAuth ? "yes" : "no",
            diagnostic.stage);
        if (firstAcceptedExperiment == nullptr &&
            acceptedNextClientMessage(diagnostic))
        {
            firstAcceptedExperiment = experimentName(experiment);
        }
    }

    std::fprintf(
        stderr,
        "microsoft-credssp-first-accepted-single-delta=%s\n",
        firstAcceptedExperiment != nullptr
            ? firstAcceptedExperiment
            : "none");

    // Test-only diagnostic variants never make the production gate green.
    return 1;
}
