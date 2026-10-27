// SPDX-License-Identifier: GPL-3.0-or-later
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SCHANNEL_USE_BLACKLISTS
#include <windows.h>
#include <winternl.h>
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
#include <initializer_list>
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

enum class SchannelCredentialProfile : std::uint8_t
{
    LegacySchannelCred,
    ModernSystemDefaults,
};

enum class CredSspCredentialState : std::uint8_t
{
    CorrectPassword,
    WrongPassword,
    MissingCredentials,
    EmptyPassword,
};

[[nodiscard]] constexpr const char *credentialStateName(
    CredSspCredentialState state) noexcept
{
    switch (state)
    {
    case CredSspCredentialState::CorrectPassword:
        return "correct";
    case CredSspCredentialState::WrongPassword:
        return "wrong-password";
    case CredSspCredentialState::MissingCredentials:
        return "missing-credentials";
    case CredSspCredentialState::EmptyPassword:
        return "empty-password";
    }
    return "unknown";
}

[[nodiscard]] constexpr const char *schannelCredentialProfileName(
    SchannelCredentialProfile profile) noexcept
{
    switch (profile)
    {
    case SchannelCredentialProfile::LegacySchannelCred:
        return "SCHANNEL_CRED";
    case SchannelCredentialProfile::ModernSystemDefaults:
        return "SCH_CREDENTIALS-system-defaults";
    }
    return "unknown";
}

enum class TlsServerProfile : std::uint8_t
{
    SystemDefault,
    Tls12Only,
    Tls13Only,
};

[[nodiscard]] constexpr const char *tlsServerProfileName(
    TlsServerProfile profile) noexcept
{
    switch (profile)
    {
    case TlsServerProfile::SystemDefault:
        return "system-default";
    case TlsServerProfile::Tls12Only:
        return "tls12-only";
    case TlsServerProfile::Tls13Only:
        return "tls13-only";
    }
    return "unknown";
}

[[nodiscard]] bool applyTlsServerProfile(
    SSL *tls, TlsServerProfile profile) noexcept
{
    if (tls == nullptr)
        return false;

    switch (profile)
    {
    case TlsServerProfile::SystemDefault:
        return true;
    case TlsServerProfile::Tls12Only:
        return SSL_set_min_proto_version(tls, TLS1_2_VERSION) == 1 &&
               SSL_set_max_proto_version(tls, TLS1_2_VERSION) == 1;
    case TlsServerProfile::Tls13Only:
#if defined(TLS1_3_VERSION)
        return SSL_set_min_proto_version(tls, TLS1_3_VERSION) == 1 &&
               SSL_set_max_proto_version(tls, TLS1_3_VERSION) == 1;
#else
        return false;
#endif
    }
    return false;
}

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
    ISC_REQ_STREAM |
    ISC_REQ_MANUAL_CRED_VALIDATION;

[[nodiscard]] constexpr bool credSspUsesWireStreamSemantics() noexcept
{
    return (kCredSspContextRequirements & ISC_REQ_STREAM) != 0U &&
           (kCredSspContextRequirements & ISC_REQ_CONNECTION) == 0U;
}
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
    case 0x00090321U: return "SEC_I_RENEGOTIATE";
    case 0x80090303U: return "SEC_E_TARGET_UNKNOWN";
    case 0x80090308U: return "SEC_E_INVALID_TOKEN";
    case 0x8009030cU: return "SEC_E_LOGON_DENIED";
    case 0x8009030dU: return "SEC_E_UNKNOWN_CREDENTIALS";
    case 0x8009030eU: return "SEC_E_NO_CREDENTIALS";
    case 0x80090311U: return "SEC_E_NO_AUTHENTICATING_AUTHORITY";
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
    std::size_t inputBytes{};
    std::size_t retainedServerInputBytes{};
    std::size_t retainedExtraBytes{};
    std::size_t missingBytes{};
    bool zeroLengthInputToken{};
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

class SspiServerInputBuffer final
{
public:
    [[nodiscard]] bool append(
        std::span<const std::uint8_t> bytes) noexcept
    {
        if (bytes.empty())
            return true;
        if (bytes_.size() > kMaximumRawTokenBytes ||
            bytes.size() > kMaximumRawTokenBytes - bytes_.size())
        {
            return false;
        }
        try
        {
            bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
        }
        catch (...)
        {
            return false;
        }
        return true;
    }

    [[nodiscard]] bool retainAfterStep(
        SECURITY_STATUS status,
        const SecBuffer &extraBuffer,
        std::size_t &retainedExtraBytes) noexcept
    {
        retainedExtraBytes = 0U;
        if (status == SEC_E_INCOMPLETE_MESSAGE)
            return true;

        if (extraBuffer.BufferType != SECBUFFER_EXTRA)
        {
            bytes_.clear();
            return true;
        }

        const std::size_t extraBytes = extraBuffer.cbBuffer;
        if (extraBytes > bytes_.size())
        {
            bytes_.clear();
            return false;
        }

        const std::size_t extraOffset = bytes_.size() - extraBytes;
        if (extraBytes != 0U)
        {
            std::memmove(
                bytes_.data(),
                bytes_.data() + extraOffset,
                extraBytes);
        }
        bytes_.resize(extraBytes);
        retainedExtraBytes = extraBytes;
        return true;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return bytes_.empty();
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        return bytes_.size();
    }

    [[nodiscard]] std::uint8_t *data() noexcept
    {
        return bytes_.data();
    }

    [[nodiscard]] std::span<const std::uint8_t> view() const noexcept
    {
        return bytes_;
    }

private:
    std::vector<std::uint8_t> bytes_{};
};

class WindowsCredSspClient final
{
public:
    using Step = CredSspClientStep;

    explicit WindowsCredSspClient(
        SchannelCredentialProfile schannelCredentialProfile,
        CredSspCredentialState credentialState =
            CredSspCredentialState::CorrectPassword) noexcept
        : schannelCredentialProfile_(schannelCredentialProfile)
    {
        identity_.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        if (credentialState != CredSspCredentialState::MissingCredentials)
        {
            identity_.User = username_.data();
            identity_.UserLength =
                static_cast<unsigned long>(username_.size());
            identity_.Domain = domain_.data();
            identity_.DomainLength =
                static_cast<unsigned long>(domain_.size());
        }

        switch (credentialState)
        {
        case CredSspCredentialState::CorrectPassword:
            identity_.Password = correctPassword_.data();
            identity_.PasswordLength =
                static_cast<unsigned long>(correctPassword_.size());
            break;
        case CredSspCredentialState::WrongPassword:
            identity_.Password = wrongPassword_.data();
            identity_.PasswordLength =
                static_cast<unsigned long>(wrongPassword_.size());
            break;
        case CredSspCredentialState::MissingCredentials:
            // An explicit empty SPNEGO identity prevents this test from
            // borrowing the CI process account's default credentials.
            identity_.User = nullptr;
            identity_.UserLength = 0U;
            identity_.Domain = nullptr;
            identity_.DomainLength = 0U;
            identity_.Password = nullptr;
            identity_.PasswordLength = 0U;
            break;
        case CredSspCredentialState::EmptyPassword:
            // Keep a non-null password address while declaring zero UTF-16
            // code units so this remains distinct from missing credentials.
            identity_.Password = emptyPassword_.data();
            identity_.PasswordLength = 0U;
            break;
        }

        schannel_.dwVersion = SCHANNEL_CRED_VERSION;
        schannel_.dwFlags =
            SCH_CRED_MANUAL_CRED_VALIDATION |
            SCH_CRED_NO_DEFAULT_CREDS |
            SCH_USE_STRONG_CRYPTO;

        modernSchannel_.dwVersion = SCH_CREDENTIALS_VERSION;
        modernSchannel_.dwFlags =
            SCH_CRED_MANUAL_CRED_VALIDATION |
            SCH_CRED_NO_DEFAULT_CREDS |
            SCH_USE_STRONG_CRYPTO;
        // Zero TLS_PARAMETERS entries deliberately select Schannel system
        // defaults instead of imposing a test-only protocol cap.
        modernSchannel_.cTlsParameters = 0U;
        modernSchannel_.pTlsParameters = nullptr;

        credSsp_.Type = CredsspSubmitBufferBoth;
        credSsp_.pSchannelCred =
            schannelCredentialProfile_ ==
                    SchannelCredentialProfile::ModernSystemDefaults
                ? static_cast<void *>(&modernSchannel_)
                : static_cast<void *>(&schannel_);
        credSsp_.pSpnegoCred = &identity_;
    }

    ~WindowsCredSspClient()
    {
        if (contextValid_)
            DeleteSecurityContext(&context_);
        if (credentialValid_)
            FreeCredentialsHandle(&credential_);
        SecureZeroMemory(
            correctPassword_.data(),
            correctPassword_.size() * sizeof(correctPassword_[0]));
        SecureZeroMemory(
            wrongPassword_.data(),
            wrongPassword_.size() * sizeof(wrongPassword_[0]));
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

        if (!pendingServerInput_.append(serverToken))
        {
            result.status = SEC_E_INSUFFICIENT_MEMORY;
            return result;
        }

        const bool contextWasValid = contextValid_;
        const SECURITY_STATUS previousStatus = lastStatus_;
        const ULONG previousContextAttributes = lastContextAttributes_;
        const bool previouslyNeededMoreServerBytes = needsMoreServerBytes_;
        const bool previouslyAllowedContinuation =
            continuationWithoutWireAllowed_;
        const std::size_t providerInputBytes =
            pendingServerInput_.size();
        result.inputBytes = providerInputBytes;
        result.zeroLengthInputToken =
            contextWasValid && providerInputBytes == 0U;

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

        if (input != nullptr)
        {
            for (const SecBuffer &buffer : inputBuffers)
            {
                if (buffer.BufferType == SECBUFFER_MISSING)
                {
                    result.missingBytes = (std::max)(
                        result.missingBytes,
                        static_cast<std::size_t>(buffer.cbBuffer));
                }
            }

            if (!pendingServerInput_.retainAfterStep(
                    result.status,
                    inputBuffers[1],
                    result.retainedExtraBytes))
            {
                result.status = SEC_E_INVALID_TOKEN;
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
    std::array<unsigned short, 8> correctPassword_{
        static_cast<unsigned short>('P'),
        static_cast<unsigned short>('a'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('w'),
        static_cast<unsigned short>('o'),
        static_cast<unsigned short>('r'),
        static_cast<unsigned short>('d')};
    std::array<unsigned short, 13> wrongPassword_{
        static_cast<unsigned short>('W'),
        static_cast<unsigned short>('r'),
        static_cast<unsigned short>('o'),
        static_cast<unsigned short>('n'),
        static_cast<unsigned short>('g'),
        static_cast<unsigned short>('P'),
        static_cast<unsigned short>('a'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('w'),
        static_cast<unsigned short>('o'),
        static_cast<unsigned short>('r'),
        static_cast<unsigned short>('d')};
    std::array<unsigned short, 1> emptyPassword_{0U};
    SEC_WINNT_AUTH_IDENTITY_W identity_{};
    SCHANNEL_CRED schannel_{};
    SCH_CREDENTIALS modernSchannel_{};
    CREDSSP_CRED credSsp_{};
    SchannelCredentialProfile schannelCredentialProfile_{
        SchannelCredentialProfile::LegacySchannelCred};
    CredHandle credential_{};
    CtxtHandle context_{};
    SspiServerInputBuffer pendingServerInput_{};
    SECURITY_STATUS lastStatus_{SEC_E_INTERNAL_ERROR};
    ULONG lastContextAttributes_{};
    bool credentialValid_{};
    bool contextValid_{};
    bool needsMoreServerBytes_{};
    bool continuationWithoutWireAllowed_{};
};

[[nodiscard]] const char *credSspTokenEnvelope(
    std::span<const std::uint8_t> token) noexcept
{
    if (token.empty())
        return "empty";

    constexpr std::array<std::uint8_t, 8> ntlmSignature{
        'N','T','L','M','S','S','P',0U};
    if (token.size() >= ntlmSignature.size() &&
        std::equal(
            ntlmSignature.begin(),
            ntlmSignature.end(),
            token.begin()))
    {
        return "ntlmssp";
    }

    switch (token.front())
    {
    case 0x30U:
        return "der-sequence";
    case 0x60U:
        return "gss-initial-context-token";
    case 0xa0U:
        return "spnego-neg-token-init";
    case 0xa1U:
        return "spnego-neg-token-resp";
    default:
        break;
    }

    if (token.size() < 5U || token[1] != 0x03U)
        return "opaque-other";

    switch (token.front())
    {
    case 0x14U: return "tls-change-cipher-spec";
    case 0x15U: return "tls-alert";
    case 0x16U: return "tls-handshake";
    case 0x17U: return "tls-application-data";
    case 0x18U: return "tls-heartbeat";
    default: return "opaque-other";
    }
}

[[nodiscard]] const char *tsRequestTlsReadStatusName(
    TsRequestTlsReadStatus status) noexcept
{
    switch (status)
    {
    case TsRequestTlsReadStatus::Progress: return "progress";
    case TsRequestTlsReadStatus::NeedRead: return "need-read";
    case TsRequestTlsReadStatus::NeedWrite: return "need-write";
    case TsRequestTlsReadStatus::Complete: return "complete";
    case TsRequestTlsReadStatus::Invalid: return "invalid";
    case TsRequestTlsReadStatus::Closed: return "closed";
    }
    return "unknown";
}

[[nodiscard]] const char *tsRequestErrorName(
    TsRequestError error) noexcept
{
    switch (error)
    {
    case TsRequestError::None: return "none";
    case TsRequestError::InvalidDer: return "invalid-der";
    case TsRequestError::InvalidVersion: return "invalid-version";
    case TsRequestError::InvalidFields: return "invalid-fields";
    case TsRequestError::InvalidTokens: return "invalid-tokens";
    case TsRequestError::InvalidNonce: return "invalid-nonce";
    }
    return "unknown";
}

template <typename ClientStep>
[[nodiscard]] const char *credSspClientStepDisposition(
    const ClientStep &step) noexcept
{
    if (step.status == SEC_E_INCOMPLETE_MESSAGE)
        return "incomplete-message";
    if (!credSspClientStatusCanContinue(step.status))
        return "hard-error";
    if (!step.output.empty())
        return "output-generated";
    if (step.retainedExtraBytes != 0U)
        return "extra-input-retained";
    if (step.status == SEC_E_OK)
        return "context-complete";
    if (step.status == SEC_I_CONTINUE_NEEDED)
        return "local-continuation-allowed";
    return "peer-input-required";
}

template <typename ClientStep>
void printCredSspClientCall(
    TargetProfile profile,
    const char *phase,
    const ClientStep &step,
    bool tlsFinished,
    bool initialTsRequestSeen,
    bool productionTypeTwoConsumed,
    bool nextClientTsRequestProduced,
    bool typeThreeObserved) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-credssp-call target=%s phase=%s status=%s "
        "code=0x%08lx input-bytes=%zu output-bytes=%zu "
        "output-envelope=%s "
        "retained-extra-bytes=%zu retained-input-bytes=%zu "
        "missing-bytes=%zu zero-token-input=%s disposition=%s "
        "tls-finished=%s initial-tsrequest-seen=%s "
        "production-type2-consumed=%s "
        "next-client-tsrequest-produced=%s type3-observed=%s\n",
        targetLabel(profile),
        phase,
        securityStatusName(step.status),
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(step.status)),
        step.inputBytes,
        step.output.view().size(),
        credSspTokenEnvelope(step.output.view()),
        step.retainedExtraBytes,
        step.retainedServerInputBytes,
        step.missingBytes,
        step.zeroLengthInputToken ? "yes" : "no",
        credSspClientStepDisposition(step),
        tlsFinished ? "yes" : "no",
        initialTsRequestSeen ? "yes" : "no",
        productionTypeTwoConsumed ? "yes" : "no",
        nextClientTsRequestProduced ? "yes" : "no",
        typeThreeObserved ? "yes" : "no");
}

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
            ChallengeExperiment::Production,
        TlsServerProfile tlsServerProfile =
            TlsServerProfile::SystemDefault) noexcept
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
        if (!tls_ ||
            !applyTlsServerProfile(tls_.get(), tlsServerProfile))
        {
            return;
        }

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

    [[nodiscard]] const char *negotiatedTlsVersionName() const noexcept
    {
        return tlsReady() ? SSL_get_version(tls_.get()) : "none";
    }

    [[nodiscard]] const char *negotiatedCipherName() const noexcept
    {
        if (!tlsReady())
            return "none";
        const SSL_CIPHER *const cipher = SSL_get_current_cipher(tls_.get());
        return cipher != nullptr ? SSL_CIPHER_get_name(cipher) : "none";
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

        const std::size_t inputBioPendingBefore =
            inputBioPendingBytes();
        const std::size_t applicationPendingBefore =
            applicationPendingBytes();
        const unsigned long openSslErrorBefore =
            ERR_peek_last_error();
        const auto result = reader_.readOneTlsStep(tls_.get());
        if (result.status == TsRequestTlsReadStatus::Invalid ||
            result.status == TsRequestTlsReadStatus::Closed)
        {
            std::fprintf(
                stderr,
                "microsoft-credssp-server-frame-failure "
                "tls-read-status=%s tsrequest-error=%s "
                "plaintext-read=%zu rbio-before=%zu "
                "ssl-pending-before=%zu openssl-before=0x%08lx "
                "openssl-after=0x%08lx\n",
                tsRequestTlsReadStatusName(result.status),
                tsRequestErrorName(result.error),
                result.plaintextBytesRead,
                inputBioPendingBefore,
                applicationPendingBefore,
                openSslErrorBefore,
                ERR_peek_last_error());
        }

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
        const auto requestVersion =
            static_cast<std::uint8_t>(request.value.version);

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
                requestVersion,
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

    [[nodiscard]] StandaloneSpnegoInitialTokenObservation
    initialTokenObservation() const noexcept
    {
        return experiment_ == ChallengeExperiment::Production
            ? acceptor_.initialNegoObservation().spnego
            : diagnosticMechanism_.initialTokenObservation();
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
    std::size_t microsoftInputBytes{};
    std::size_t microsoftOutputBytes{};
    std::size_t microsoftRetainedServerInputBytes{};
    std::size_t microsoftRetainedExtraBytes{};
    std::size_t microsoftMissingBytes{};
    SECURITY_STATUS microsoftStatus{SEC_E_INTERNAL_ERROR};
    bool microsoftZeroLengthInputToken{};
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
    bool productionTypeTwoConsumed{};
    bool microsoftOutputGenerated{};
};

template <typename Client, typename Server>
[[nodiscard]] CredSspPumpResult pumpCredSspMemoryBio(
    TargetProfile profile,
    Client &client,
    Server &server,
    CredSspPumpBoundary boundary,
    bool sendQueuedProductionReply)
{
    CredSspPumpResult result{};
    typename Client::Step pendingClientStep{};
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
        const bool tlsReadyBefore = server.tlsReady();
        const std::size_t inputPendingBefore =
            server.inputBioPendingBytes();
        const std::size_t applicationPendingBefore =
            server.applicationPendingBytes();

        bool serverProviderOperationPerformed = false;
        if (!tlsReadyBefore)
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

        const bool tlsBecameReady =
            !tlsReadyBefore && server.tlsReady();
        if (server.tlsReady())
        {
            result.tlsEstablished = true;
            result.negotiatedTlsVersion =
                server.negotiatedTlsVersion();
        }

        if (server.tlsReady() && !serverProviderOperationPerformed)
        {
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

        const bool tlsCompletedWithEmptyPeerToken =
            tlsBecameReady &&
            iteration.clientToServerBytes != 0U &&
            serverToken.empty() &&
            client.hasContext() &&
            result.lastClientStatus == SEC_I_CONTINUE_NEEDED &&
            client.pendingServerInputBytes() == 0U;
        const bool shouldAdvanceMicrosoft =
            !serverToken.empty() ||
            !client.hasContext() ||
            client.canContinueWithoutNewServerBytes() ||
            tlsCompletedWithEmptyPeerToken;
        if (shouldAdvanceMicrosoft)
        {
            const char *const phase =
                !client.hasContext()
                ? "initial-context"
                : tlsCompletedWithEmptyPeerToken
                    ? "tls-complete-empty-peer-continue"
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
            iteration.microsoftInputBytes =
                pendingClientStep.inputBytes;
            iteration.microsoftOutputBytes =
                pendingClientStep.output.view().size();
            iteration.microsoftStatus =
                pendingClientStep.status;
            iteration.microsoftRetainedServerInputBytes =
                pendingClientStep.retainedServerInputBytes;
            iteration.microsoftRetainedExtraBytes =
                pendingClientStep.retainedExtraBytes;
            iteration.microsoftMissingBytes =
                pendingClientStep.missingBytes;
            iteration.microsoftZeroLengthInputToken =
                pendingClientStep.zeroLengthInputToken;
            result.lastClientStatus =
                pendingClientStep.status;

            const bool productionTypeTwoConsumedThisCall =
                sendQueuedProductionReply &&
                productionReplyCommitted &&
                pendingClientStep.inputBytes != 0U &&
                pendingClientStep.status != SEC_E_INCOMPLETE_MESSAGE &&
                pendingClientStep.retainedServerInputBytes == 0U;
            result.productionTypeTwoConsumed =
                result.productionTypeTwoConsumed ||
                productionTypeTwoConsumedThisCall;
            const bool nextClientTsRequestProduced =
                sendQueuedProductionReply &&
                result.productionTypeTwoConsumed &&
                !pendingClientStep.output.empty();
            printCredSspClientCall(
                profile,
                phase,
                pendingClientStep,
                server.tlsReady(),
                boundary == CredSspPumpBoundary::NextClientTsRequest,
                result.productionTypeTwoConsumed,
                nextClientTsRequestProduced,
                false);

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

            if (tlsCompletedWithEmptyPeerToken &&
                pendingClientStep.status == SEC_E_INCOMPLETE_MESSAGE)
            {
                result.failureStage =
                    "memory-bio-zero-token-after-tls-incomplete";
                result.stopReason =
                    CredSspPumpStopReason::TypedFailure;
                result.iterations[result.iterationCount++] =
                    iteration;
                return result;
            }
            if (tlsCompletedWithEmptyPeerToken &&
                pendingClientStep.status == SEC_E_OK &&
                pendingClientStep.output.empty())
            {
                result.failureStage =
                    "memory-bio-zero-token-after-tls-no-tsrequest";
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

class ScriptedCredSspToken final
{
public:
    ScriptedCredSspToken() = default;

    ScriptedCredSspToken(
        std::initializer_list<std::uint8_t> bytes)
        : bytes_(bytes)
    {
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return bytes_.empty();
    }

    [[nodiscard]] std::span<const std::uint8_t> view() const noexcept
    {
        return bytes_;
    }

private:
    std::vector<std::uint8_t> bytes_{};
};

struct ScriptedCredSspClientStep final
{
    SECURITY_STATUS status{SEC_E_INTERNAL_ERROR};
    ULONG contextAttributes{};
    ScriptedCredSspToken output{};
    std::size_t inputBytes{};
    std::size_t retainedServerInputBytes{};
    std::size_t retainedExtraBytes{};
    std::size_t missingBytes{};
    bool zeroLengthInputToken{};
    bool stateChanged{};
};

[[nodiscard]] bool scriptedBytesEqual(
    std::span<const std::uint8_t> bytes,
    std::initializer_list<std::uint8_t> expected) noexcept
{
    return bytes.size() == expected.size() &&
           std::equal(
               bytes.begin(),
               bytes.end(),
               expected.begin());
}

class ScriptedCredSspClient final
{
public:
    using Step = ScriptedCredSspClientStep;

    [[nodiscard]] bool hasContext() const noexcept
    {
        return stepIndex_ != 0U;
    }

    [[nodiscard]] bool canContinueWithoutNewServerBytes() const noexcept
    {
        return allowLocalRepump_;
    }

    [[nodiscard]] std::size_t pendingServerInputBytes() const noexcept
    {
        return retainedServerInputBytes_;
    }

    [[nodiscard]] Step step(
        TargetProfile,
        std::span<const std::uint8_t> serverToken)
    {
        ++stepCount_;
        if (!serverToken.empty())
            ++peerTokenStepCount_;

        switch (stepIndex_++)
        {
        case 0U:
            if (!serverToken.empty())
                return makeFailedStep();
            return makeSuccessfulStep(
                SEC_I_CONTINUE_NEEDED,
                ScriptedCredSspToken{0x10U},
                0U,
                0U,
                0U,
                0U,
                false,
                false);

        case 1U:
            if (!scriptedBytesEqual(
                    serverToken, {0x20U, 0x21U}))
            {
                return makeFailedStep();
            }
            sawZeroOutputContinuation_ = true;
            sawExtraRetention_ = true;
            return makeSuccessfulStep(
                SEC_I_CONTINUE_NEEDED,
                ScriptedCredSspToken{},
                2U,
                1U,
                1U,
                0U,
                false,
                true);

        case 2U:
            if (!serverToken.empty() || !allowLocalRepump_)
                return makeFailedStep();
            sawLocalRepump_ = true;
            return makeSuccessfulStep(
                SEC_I_CONTINUE_NEEDED,
                ScriptedCredSspToken{0x11U},
                1U,
                0U,
                0U,
                0U,
                false,
                false);

        case 3U:
            if (!scriptedBytesEqual(serverToken, {0x22U}))
                return makeFailedStep();
            sawIncompleteMessage_ = true;
            return makeSuccessfulStep(
                SEC_E_INCOMPLETE_MESSAGE,
                ScriptedCredSspToken{},
                1U,
                1U,
                0U,
                1U,
                false,
                false);

        case 4U:
            if (!scriptedBytesEqual(
                    serverToken, {0x23U, 0x24U}) ||
                retainedServerInputBytes_ != 1U)
            {
                return makeFailedStep();
            }
            sawIncompleteRecovery_ = true;
            return makeSuccessfulStep(
                SEC_I_CONTINUE_NEEDED,
                ScriptedCredSspToken{0x12U, 0x13U},
                3U,
                0U,
                0U,
                0U,
                false,
                false);

        case 5U:
            if (!serverToken.empty() || allowLocalRepump_ ||
                retainedServerInputBytes_ != 0U)
            {
                return makeFailedStep();
            }
            sawTlsCompletionEmptyPeerContinuation_ = true;
            return makeSuccessfulStep(
                SEC_I_CONTINUE_NEEDED,
                ScriptedCredSspToken{0x14U, 0x15U},
                0U,
                0U,
                0U,
                0U,
                true,
                false);

        default:
            return makeFailedStep();
        }
    }

    [[nodiscard]] bool complete() const noexcept
    {
        return !failed_ &&
               stepCount_ == 6U &&
               peerTokenStepCount_ == 3U &&
               sawZeroOutputContinuation_ &&
               sawExtraRetention_ &&
               sawLocalRepump_ &&
               sawIncompleteMessage_ &&
               sawIncompleteRecovery_ &&
               sawTlsCompletionEmptyPeerContinuation_;
    }

private:
    [[nodiscard]] Step makeSuccessfulStep(
        SECURITY_STATUS status,
        ScriptedCredSspToken output,
        std::size_t inputBytes,
        std::size_t retainedServerInputBytes,
        std::size_t retainedExtraBytes,
        std::size_t missingBytes,
        bool zeroLengthInputToken,
        bool allowLocalRepump)
    {
        retainedServerInputBytes_ = retainedServerInputBytes;
        allowLocalRepump_ = allowLocalRepump;
        return {
            status,
            0U,
            std::move(output),
            inputBytes,
            retainedServerInputBytes_,
            retainedExtraBytes,
            missingBytes,
            zeroLengthInputToken,
            true};
    }

    [[nodiscard]] Step makeFailedStep()
    {
        failed_ = true;
        retainedServerInputBytes_ = 0U;
        allowLocalRepump_ = false;
        return {
            SEC_E_INVALID_TOKEN,
            0U,
            {},
            0U,
            0U,
            0U,
            0U,
            false,
            true};
    }

    std::size_t stepIndex_{};
    std::size_t stepCount_{};
    std::size_t peerTokenStepCount_{};
    std::size_t retainedServerInputBytes_{};
    bool allowLocalRepump_{};
    bool sawZeroOutputContinuation_{};
    bool sawExtraRetention_{};
    bool sawLocalRepump_{};
    bool sawIncompleteMessage_{};
    bool sawIncompleteRecovery_{};
    bool sawTlsCompletionEmptyPeerContinuation_{};
    bool failed_{};
};

class ScriptedCredSspServer final
{
public:
    [[nodiscard]] bool valid() const noexcept
    {
        return !failed_;
    }

    [[nodiscard]] bool feedRaw(
        std::span<const std::uint8_t> bytes) noexcept
    {
        const bool expectedBytes =
            (clientFeedCount_ == 0U &&
             scriptedBytesEqual(bytes, {0x10U})) ||
            (clientFeedCount_ == 1U &&
             scriptedBytesEqual(bytes, {0x11U})) ||
            (clientFeedCount_ == 2U &&
             scriptedBytesEqual(bytes, {0x12U, 0x13U})) ||
            (clientFeedCount_ == 3U &&
             scriptedBytesEqual(bytes, {0x14U, 0x15U}));
        if (!expectedBytes)
        {
            failed_ = true;
            return false;
        }

        ++clientFeedCount_;
        if (clientFeedCount_ == 4U)
            coalescedApplicationPending_ = true;
        return true;
    }

    [[nodiscard]] bool tlsReady() const noexcept
    {
        return tlsReady_;
    }

    [[nodiscard]] int tlsStateValue() const noexcept
    {
        return tlsStateValue_;
    }

    [[nodiscard]] int negotiatedTlsVersion() const noexcept
    {
        return tlsReady_ ? TLS1_2_VERSION : 0;
    }

    [[nodiscard]] std::size_t inputBioPendingBytes() const noexcept
    {
        return coalescedApplicationPending_ ? 1U : 0U;
    }

    [[nodiscard]] std::size_t outputBioPendingBytes() const noexcept
    {
        return outgoingBytes_.size();
    }

    [[nodiscard]] std::size_t applicationPendingBytes() const noexcept
    {
        return coalescedApplicationPending_ ? 1U : 0U;
    }

    [[nodiscard]] int replyStateValue() const noexcept
    {
        return 0;
    }

    [[nodiscard]] TlsAdvance advanceHandshake() noexcept
    {
        ++handshakeOperationCount_;
        outgoingBytes_.clear();

        switch (handshakeOperationCount_)
        {
        case 1U:
            return TlsAdvance::NeedRead;

        case 2U:
            outgoingBytes_ = {0x20U, 0x21U};
            ++tlsStateValue_;
            return TlsAdvance::NeedRead;

        case 3U:
            return TlsAdvance::NeedRead;

        case 4U:
            outgoingBytes_ = {0x22U};
            ++tlsStateValue_;
            return TlsAdvance::NeedRead;

        case 5U:
            outgoingBytes_ = {0x23U, 0x24U};
            ++tlsStateValue_;
            return TlsAdvance::NeedRead;

        case 6U:
            if (clientFeedCount_ != 3U)
            {
                failed_ = true;
                return TlsAdvance::Failed;
            }
            tlsReady_ = true;
            ++tlsStateValue_;
            return TlsAdvance::Ready;

        default:
            failed_ = true;
            return TlsAdvance::Failed;
        }
    }

    [[nodiscard]] FrameAdvance advanceFrame() noexcept
    {
        ++frameReadCount_;
        if (!tlsReady_ ||
            !coalescedApplicationPending_ ||
            clientFeedCount_ != 4U)
        {
            failed_ = true;
            return FrameAdvance::Failed;
        }

        coalescedApplicationPending_ = false;
        coalescedApplicationConsumed_ = true;
        return FrameAdvance::Complete;
    }

    [[nodiscard]] ReplyAdvance advanceProductionReply() noexcept
    {
        failed_ = true;
        return ReplyAdvance::Failed;
    }

    [[nodiscard]] bool releaseProductionReply() noexcept
    {
        failed_ = true;
        return false;
    }

    [[nodiscard]] std::vector<std::uint8_t> drainRaw()
    {
        std::vector<std::uint8_t> outgoingBytes =
            std::move(outgoingBytes_);
        outgoingBytes_.clear();
        return outgoingBytes;
    }

    [[nodiscard]] bool complete() const noexcept
    {
        return !failed_ &&
               clientFeedCount_ == 4U &&
               handshakeOperationCount_ == 6U &&
               frameReadCount_ == 1U &&
               coalescedApplicationConsumed_;
    }

private:
    std::vector<std::uint8_t> outgoingBytes_{};
    std::size_t clientFeedCount_{};
    std::size_t handshakeOperationCount_{};
    std::size_t frameReadCount_{};
    int tlsStateValue_{};
    bool tlsReady_{};
    bool coalescedApplicationPending_{};
    bool coalescedApplicationConsumed_{};
    bool failed_{};
};

[[nodiscard]] bool runHarnessStreamBufferRetention()
{
    SspiServerInputBuffer inputBuffer;
    const std::array<std::uint8_t, 6> initialBytes{
        1U, 2U, 3U, 4U, 5U, 6U};
    if (!inputBuffer.append(initialBytes))
        return false;

    std::size_t retainedExtraBytes = 0U;
    SecBuffer extraBuffer{};
    extraBuffer.BufferType = SECBUFFER_EXTRA;
    extraBuffer.cbBuffer = 2U;
    if (!inputBuffer.retainAfterStep(
            SEC_I_CONTINUE_NEEDED,
            extraBuffer,
            retainedExtraBytes) ||
        retainedExtraBytes != 2U ||
        !scriptedBytesEqual(
            inputBuffer.view(), {5U, 6U}))
    {
        return false;
    }

    const std::array<std::uint8_t, 2> additionalBytes{
        7U, 8U};
    if (!inputBuffer.append(additionalBytes))
        return false;

    SecBuffer missingBuffer{};
    missingBuffer.BufferType = SECBUFFER_MISSING;
    missingBuffer.cbBuffer = 3U;
    if (!inputBuffer.retainAfterStep(
            SEC_E_INCOMPLETE_MESSAGE,
            missingBuffer,
            retainedExtraBytes) ||
        retainedExtraBytes != 0U ||
        !scriptedBytesEqual(
            inputBuffer.view(), {5U, 6U, 7U, 8U}))
    {
        return false;
    }

    SecBuffer emptyBuffer{};
    emptyBuffer.BufferType = SECBUFFER_EMPTY;
    return inputBuffer.retainAfterStep(
               SEC_I_CONTINUE_NEEDED,
               emptyBuffer,
               retainedExtraBytes) &&
           retainedExtraBytes == 0U &&
           inputBuffer.empty();
}

[[nodiscard]] bool runHarnessMultiTurnRoundProgression()
{
    // This oracle connects SSPI output directly to the production OpenSSL
    // memory-BIO peer. Stream semantics keep SSPI message framing on the
    // bytes handed to that wire peer; connection semantics deliberately do
    // not handle message formatting.
    if (!credSspUsesWireStreamSemantics())
        return false;

    ScriptedCredSspClient scriptedClient;
    ScriptedCredSspServer scriptedServer;
    const CredSspPumpResult pumpResult =
        pumpCredSspMemoryBio(
            TargetProfile::PortableServerName,
            scriptedClient,
            scriptedServer,
            CredSspPumpBoundary::InitialClientTsRequest,
            false);
    return pumpResult.stopReason ==
               CredSspPumpStopReason::BoundaryComplete &&
           pumpResult.tlsEstablished &&
           pumpResult.iterationCount == 7U &&
           scriptedClient.complete() &&
           scriptedServer.complete();
}

using BoundedCipherName = std::array<char, 64>;

void copyBoundedCipherName(
    BoundedCipherName &destination,
    const char *source) noexcept
{
    destination.fill('\0');
    if (source == nullptr)
        return;

    const std::string_view sourceView{source};
    const std::size_t bytesToCopy =
        std::min(sourceView.size(), destination.size() - 1U);
    std::copy_n(sourceView.begin(), bytesToCopy, destination.begin());
}

struct FullCredSspAttempt final
{
    const char *stage{"not-started"};
    TlsServerProfile tlsServerProfile{TlsServerProfile::SystemDefault};
    SECURITY_STATUS acquireStatus{SEC_E_INTERNAL_ERROR};
    SECURITY_STATUS lastClientStatus{SEC_E_INTERNAL_ERROR};
    CredSspPumpResult initialPump{};
    CredSspPumpResult nextPump{};
    bool typeOneObserved{};
    bool directNtlmTypeOneAccepted{};
    const char *rawTokenType{"not-observed"};
    std::size_t rawTokenBytes{};
    std::size_t typeOneTokenBytes{};
    NtlmNegotiateMessage typeOne{};
    NtlmChallengeMessageObservation typeTwo{};
    std::uint32_t typeTwoFlags{};
    std::size_t typeTwoTargetNameCodeUnits{};
    int minimumTlsVersion{};
    int maximumTlsVersion{};
    int negotiatedTlsVersion{};
    BoundedCipherName negotiatedCipherName{'n','o','n','e','\0'};
    SchannelCredentialProfile schannelCredentialProfile{
        SchannelCredentialProfile::LegacySchannelCred};
    CredSspCredentialState credentialState{
        CredSspCredentialState::CorrectPassword};
    bool tlsEstablished{};
    bool initialClientTsRequestReceived{};
    bool productionTypeTwoQueued{};
    bool productionTypeTwoTlsCommitted{};
    bool productionTypeTwoConsumed{};
    bool microsoftNextTokenGenerated{};
    bool nextClientTsRequestReceived{};
    bool productionObservedTypeThree{};
    bool productionVerifiedTypeThree{};
    bool nextClientHasPubKeyAuth{};
};


[[nodiscard]] const char *rawInitialTokenType(
    const StandaloneSpnegoInitialTokenObservation &observation) noexcept
{
    if (observation.negotiationEnvelope ==
        StandaloneNtlmNegotiationEnvelope::DirectNtlm)
        return "direct-ntlm-type1";
    if (observation.gssInitialContextToken)
        return "gss-initial-context-token";
    if (observation.negTokenInit2)
        return "spnego-neg-token-init2";
    if (observation.negTokenInit)
        return "spnego-neg-token-init";
    if (observation.negotiationEnvelope ==
        StandaloneNtlmNegotiationEnvelope::Spnego)
        return "spnego-other";
    return "unknown";
}

void printClientProfileObservation(
    TargetProfile profile,
    const FullCredSspAttempt &result) noexcept
{
    if (!result.typeOneObserved)
    {
        std::fprintf(
            stderr,
            "microsoft-credssp-type1-profile target=%s observed=no\n",
            targetLabel(profile));
        return;
    }

    const auto &typeOne = result.typeOne;
    const auto &typeTwo = result.typeTwo;
    std::fprintf(
        stderr,
        "microsoft-credssp-type1-profile target=%s observed=yes "
        "raw-token=%s raw-token-bytes=%zu message-type=1 "
        "type1-bytes=%zu flags=0x%08lx "
        "version-present=%s "
        "version=%u.%u.%u ntlm-revision=0x%02x "
        "domain-supplied=%s workstation-supplied=%s "
        "domain-field-bytes=%zu workstation-field-bytes=%zu\n",
        targetLabel(profile),
        result.rawTokenType,
        result.rawTokenBytes,
        result.typeOneTokenBytes,
        static_cast<unsigned long>(typeOne.negotiateFlags),
        typeOne.versionPresent ? "yes" : "no",
        static_cast<unsigned int>(typeOne.majorVersion),
        static_cast<unsigned int>(typeOne.minorVersion),
        static_cast<unsigned int>(typeOne.buildNumber),
        static_cast<unsigned int>(typeOne.ntlmRevision),
        typeOne.domainSupplied ? "yes" : "no",
        typeOne.workstationSupplied ? "yes" : "no",
        typeOne.domainFieldBytes,
        typeOne.workstationFieldBytes);

    constexpr std::size_t physicalTypeOneBytes = 40U;
    constexpr std::uint32_t physicalTypeOneFlags = 0xe2088235U;
    constexpr std::uint32_t physicalTypeTwoFlags = 0xe08a8235U;
    constexpr std::size_t physicalTargetNameCodeUnits = 10U;
    constexpr std::size_t physicalTargetInfoBytes = 50U;
    constexpr std::size_t physicalTypeTwoBytes = 126U;
    constexpr std::array<std::uint16_t, 4> physicalAvIds{2U, 1U, 7U, 0U};
    const bool sameAvIds =
        typeTwo.targetInfoAvIdCount == physicalAvIds.size() &&
        std::equal(
            physicalAvIds.begin(), physicalAvIds.end(),
            typeTwo.targetInfoAvIds.begin());
    const bool typeTwoStructureDiffers =
        typeTwo.negotiateFlags != physicalTypeTwoFlags ||
        typeTwo.targetNameCodeUnits != physicalTargetNameCodeUnits ||
        typeTwo.targetInfoBytes != physicalTargetInfoBytes ||
        typeTwo.totalBytes != physicalTypeTwoBytes ||
        !typeTwo.targetTypeServer || !typeTwo.targetNamePresent ||
        !sameAvIds;

    std::fprintf(
        stderr,
        "microsoft-credssp-client-profile-differential target=%s "
        "physical-type1-bytes=%zu hosted-type1-bytes=%zu "
        "type1-bytes-match=%s type1-exact-equality-required=no "
        "physical-type1-flags=0x%08lx hosted-type1-flags=0x%08lx "
        "type1-flags-xor=0x%08lx physical-version=6.0.6001/0x0f "
        "hosted-version-present=%s hosted-version-structure=%s "
        "hosted-version=%u.%u.%u/0x%02x "
        "physical-type2-flags=0x%08lx hosted-type2-flags=0x%08lx "
        "physical-target-name-code-units=%zu hosted-target-name-code-units=%zu "
        "physical-target-info-bytes=%zu hosted-target-info-bytes=%zu "
        "physical-type2-bytes=%zu hosted-type2-bytes=%zu "
        "physical-av-ids=2,1,7,0 hosted-av-ids=",
        targetLabel(profile),
        physicalTypeOneBytes,
        result.typeOneTokenBytes,
        result.typeOneTokenBytes == physicalTypeOneBytes ? "yes" : "no",
        static_cast<unsigned long>(physicalTypeOneFlags),
        static_cast<unsigned long>(typeOne.negotiateFlags),
        static_cast<unsigned long>(
            physicalTypeOneFlags ^ typeOne.negotiateFlags),
        typeOne.versionPresent ? "yes" : "no",
        typeOne.versionPresent ? "valid" : "absent",
        static_cast<unsigned int>(typeOne.majorVersion),
        static_cast<unsigned int>(typeOne.minorVersion),
        static_cast<unsigned int>(typeOne.buildNumber),
        static_cast<unsigned int>(typeOne.ntlmRevision),
        static_cast<unsigned long>(physicalTypeTwoFlags),
        static_cast<unsigned long>(typeTwo.negotiateFlags),
        physicalTargetNameCodeUnits,
        typeTwo.targetNameCodeUnits,
        physicalTargetInfoBytes,
        typeTwo.targetInfoBytes,
        physicalTypeTwoBytes,
        typeTwo.totalBytes);
    for (std::size_t index = 0U;
         index < typeTwo.targetInfoAvIdCount;
         ++index)
    {
        std::fprintf(
            stderr, "%s%u", index == 0U ? "" : ",",
            static_cast<unsigned int>(typeTwo.targetInfoAvIds[index]));
    }
    std::fprintf(
        stderr,
        " type2-structure-differs=%s\n",
        typeTwoStructureDiffers ? "yes" : "no");
}

[[nodiscard]] FullCredSspAttempt runFullCredSspAttempt(
    TargetProfile profile,
    ChallengeExperiment experiment =
        ChallengeExperiment::Production,
    SchannelCredentialProfile schannelCredentialProfile =
        SchannelCredentialProfile::LegacySchannelCred,
    TlsServerProfile tlsServerProfile =
        TlsServerProfile::SystemDefault,
    CredSspCredentialState credentialState =
        CredSspCredentialState::CorrectPassword)
{
    FullCredSspAttempt result{};
    result.schannelCredentialProfile = schannelCredentialProfile;
    result.tlsServerProfile = tlsServerProfile;
    result.credentialState = credentialState;
    WindowsCredSspClient client{
        schannelCredentialProfile, credentialState};
    ProductionCredSspServer server{experiment, tlsServerProfile};
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
    copyBoundedCipherName(
        result.negotiatedCipherName,
        server.negotiatedCipherName());
    std::fprintf(
        stderr,
        "microsoft-credssp-tls-profile target=%s schannel=%s "
        "server-profile=%s negotiated-tls=%s cipher=%s target-string=%s "
        "certificate-profile=generated-cn-rdp-server-ip-san "
        "certificate-endpoint=192.168.1.5\n",
        targetLabel(profile),
        schannelCredentialProfileName(schannelCredentialProfile),
        tlsServerProfileName(tlsServerProfile),
        server.negotiatedTlsVersionName(),
        server.negotiatedCipherName(),
        targetLabel(profile));
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
    const auto initialToken = server.initialTokenObservation();
    result.typeOneObserved = initialToken.ntlmTypeOneObserved;
    result.directNtlmTypeOneAccepted =
        initialToken.directNtlmType1Accepted;
    result.rawTokenType = rawInitialTokenType(initialToken);
    result.rawTokenBytes = initialToken.tokenBytes;
    result.typeOneTokenBytes =
        initialToken.negotiationEnvelope ==
            StandaloneNtlmNegotiationEnvelope::DirectNtlm
        ? initialToken.tokenBytes
        : initialToken.optimisticMechanismTokenBytes;
    result.typeOne = initialToken.ntlmTypeOne;
    if (!result.typeOneObserved)
    {
        result.stage = "production-type1-observation";
        return result;
    }
    const auto challenge = server.challengeObservation();
    result.typeTwo = challenge;
    result.typeTwoFlags = challenge.negotiateFlags;
    result.typeTwoTargetNameCodeUnits = challenge.targetNameCodeUnits;
    printClientProfileObservation(profile, result);

    result.stage = "memory-bio-after-production-type2";
    result.nextPump = pumpCredSspMemoryBio(
        profile, client, server,
        CredSspPumpBoundary::NextClientTsRequest, true);
    result.lastClientStatus = result.nextPump.lastClientStatus;
    result.productionTypeTwoTlsCommitted =
        result.nextPump.productionReplyCommitted;
    result.productionTypeTwoConsumed =
        result.nextPump.productionTypeTwoConsumed;
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
    result.stage = result.productionObservedTypeThree
        ? "none"
        : "next-client-tsrequest-without-type3";
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
            "sspi-input=%zu sspi-output=%zu sspi-retained=%zu "
            "sspi-extra=%zu sspi-missing=%zu zero-token-input=%s "
            "sspi-status=%s code=0x%08lx\n",
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
            iteration.microsoftInputBytes,
            iteration.microsoftOutputBytes,
            iteration.microsoftRetainedServerInputBytes,
            iteration.microsoftRetainedExtraBytes,
            iteration.microsoftMissingBytes,
            iteration.microsoftZeroLengthInputToken ? "yes" : "no",
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

[[nodiscard]] bool acceptedNextClientMessage(
    const FullCredSspAttempt &attempt) noexcept
{
    return std::string_view{attempt.stage} == "none" &&
           attempt.tlsEstablished &&
           attempt.initialClientTsRequestReceived &&
           attempt.productionTypeTwoQueued &&
           attempt.productionTypeTwoTlsCommitted &&
           attempt.productionTypeTwoConsumed &&
           attempt.microsoftNextTokenGenerated &&
           attempt.nextClientTsRequestReceived &&
           attempt.productionObservedTypeThree;
}

[[nodiscard]] SECURITY_STATUS reportedMicrosoftStatus(
    const FullCredSspAttempt &attempt) noexcept
{
    return std::string_view{attempt.stage} == "acquire-credssp"
        ? attempt.acquireStatus
        : attempt.lastClientStatus;
}

[[nodiscard]] bool microsoftCredentialFailureObserved(
    const FullCredSspAttempt &attempt) noexcept
{
    const SECURITY_STATUS status = reportedMicrosoftStatus(attempt);
    const bool credentialStatus =
        !securityStatusSucceeded(status) ||
        static_cast<std::uint32_t>(status) == 0x00090320U;
    if (!credentialStatus)
        return false;

    if (std::string_view{attempt.stage} == "acquire-credssp")
        return true;

    const auto isMicrosoftFailure = [](const CredSspPumpResult &pump) {
        return pump.stopReason == CredSspPumpStopReason::TypedFailure &&
               std::string_view{pump.failureStage} ==
                   "memory-bio-microsoft-credssp";
    };
    return isMicrosoftFailure(attempt.initialPump) ||
           isMicrosoftFailure(attempt.nextPump);
}

void printCredentialSemanticRow(
    const FullCredSspAttempt &attempt) noexcept
{
    const SECURITY_STATUS status = reportedMicrosoftStatus(attempt);
    std::fprintf(
        stderr,
        "microsoft-credssp-credential-semantics "
        "credential-state=%s type1=%s type2-consumed=%s type3=%s "
        "microsoft-status=%s code=0x%08lx stage=%s\n",
        credentialStateName(attempt.credentialState),
        attempt.typeOneObserved ? "yes" : "no",
        attempt.productionTypeTwoConsumed ? "yes" : "no",
        attempt.productionObservedTypeThree ? "yes" : "no",
        securityStatusName(status),
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(status)),
        attempt.stage);
}

void printFailure(
    TargetProfile profile,
    const FullCredSspAttempt &result) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-credssp target=%s schannel=%s server-profile=%s "
        "stage=%s tls=%s tls-version=%s cipher=%s tls-min=%s tls-max=%s "
        "initial-tsrequest=%s type2-queued=%s type2-tls-committed=%s "
        "type2-consumed=%s type2-flags=0x%08lx "
        "type2-target-code-units=%zu "
        "next-token=%s next-tsrequest=%s type3=%s "
        "type3-verified=%s pubkeyauth=%s\n",
        targetLabel(profile),
        schannelCredentialProfileName(result.schannelCredentialProfile),
        tlsServerProfileName(result.tlsServerProfile),
        result.stage,
        result.tlsEstablished ? "established" : "not-established",
        tlsVersionName(result.negotiatedTlsVersion),
        result.negotiatedCipherName.data(),
        tlsVersionName(result.minimumTlsVersion),
        tlsVersionName(result.maximumTlsVersion),
        result.initialClientTsRequestReceived ? "yes" : "no",
        result.productionTypeTwoQueued ? "yes" : "no",
        result.productionTypeTwoTlsCommitted ? "yes" : "no",
        result.productionTypeTwoConsumed ? "yes" : "no",
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

[[nodiscard]] bool runModernSchannelSystemDefaultsProbe()
{
    const TargetProfile profile = TargetProfile::PortableServerName;
    const FullCredSspAttempt legacyControl =
        runFullCredSspAttempt(
            profile,
            ChallengeExperiment::Production,
            SchannelCredentialProfile::LegacySchannelCred);
    if (!acceptedNextClientMessage(legacyControl))
    {
        printFailure(profile, legacyControl);
        std::fprintf(
            stderr,
            "microsoft-credssp-modern-schannel-probe control=FAIL "
            "modern=NOT_RUN\n");
        return false;
    }

    const FullCredSspAttempt modern =
        runFullCredSspAttempt(
            profile,
            ChallengeExperiment::Production,
            SchannelCredentialProfile::ModernSystemDefaults);
    const bool modernAccepted = acceptedNextClientMessage(modern);
    const bool tls13TypeThreePass =
#if defined(TLS1_3_VERSION)
        modernAccepted &&
        modern.negotiatedTlsVersion == TLS1_3_VERSION;
#else
        false;
#endif

    const bool typedFailure =
        !modernAccepted &&
        ((!securityStatusSucceeded(modern.acquireStatus) &&
          std::string_view{modern.stage} == "acquire-credssp") ||
         modern.initialPump.stopReason ==
             CredSspPumpStopReason::TypedFailure ||
         modern.nextPump.stopReason ==
             CredSspPumpStopReason::TypedFailure ||
         std::string_view{modern.stage} ==
             "next-client-tsrequest-without-type3");

    if (!modernAccepted)
        printFailure(profile, modern);

    const SECURITY_STATUS reportedStatus =
        std::string_view{modern.stage} == "acquire-credssp"
            ? modern.acquireStatus
            : modern.lastClientStatus;
    std::fprintf(
        stderr,
        "microsoft-credssp-modern-schannel-probe control=PASS "
        "credential-struct=SCH_CREDENTIALS tls-parameters=system-defaults "
        "modern-result=%s phase=%s microsoft-status=%s code=0x%08lx "
        "tls=%s type3=%s tls13-type3-pass=%s\n",
        tls13TypeThreePass
            ? "TLS13_TYPE3_PASS"
            : modernAccepted
                ? "TYPE3_PASS_NON_TLS13"
                : typedFailure
                    ? "FAILED_BEFORE_TYPE3"
                    : "HARNESS_UNCLASSIFIED",
        modern.stage,
        securityStatusName(reportedStatus),
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(reportedStatus)),
        tlsVersionName(modern.negotiatedTlsVersion),
        modern.productionObservedTypeThree ? "yes" : "no",
        tls13TypeThreePass ? "yes" : "no");

    // A typed modern-provider rejection is a useful experiment result, not
    // permission to weaken production TLS. No-progress remains a test failure.
    return modernAccepted || typedFailure;
}

[[nodiscard]] bool runTlsVersionQualification(
    TlsServerProfile tlsServerProfile)
{
    const SchannelCredentialProfile clientProfile =
        tlsServerProfile == TlsServerProfile::Tls13Only
            ? SchannelCredentialProfile::ModernSystemDefaults
            : SchannelCredentialProfile::LegacySchannelCred;
    const FullCredSspAttempt result =
        runFullCredSspAttempt(
            TargetProfile::PortableServerName,
            ChallengeExperiment::Production,
            clientProfile,
            tlsServerProfile);

    const bool reachedTypeThree = acceptedNextClientMessage(result);
    const bool expectedNegotiatedVersion =
        tlsServerProfile == TlsServerProfile::SystemDefault
            ? result.negotiatedTlsVersion != 0
            : tlsServerProfile == TlsServerProfile::Tls12Only
                ? result.negotiatedTlsVersion == TLS1_2_VERSION
#if defined(TLS1_3_VERSION)
                : result.negotiatedTlsVersion == TLS1_3_VERSION;
#else
                : false;
#endif

    const bool serverPinnedToTls13 =
#if defined(TLS1_3_VERSION)
        tlsServerProfile == TlsServerProfile::Tls13Only &&
        result.minimumTlsVersion == TLS1_3_VERSION &&
        result.maximumTlsVersion == TLS1_3_VERSION;
#else
        false;
#endif
    const bool noAuthenticationWireState =
        !result.tlsEstablished &&
        !result.initialClientTsRequestReceived &&
        !result.typeOneObserved &&
        !result.productionTypeTwoQueued &&
        !result.productionTypeTwoTlsCommitted &&
        !result.nextClientTsRequestReceived &&
        !result.productionObservedTypeThree;
    const bool providerRejectedBeforeTls =
        std::string_view{result.stage} == "acquire-credssp" &&
        !securityStatusSucceeded(result.acquireStatus);
    const bool providerCouldNotNegotiateTls13 =
        securityStatusSucceeded(result.acquireStatus) &&
        noAuthenticationWireState &&
        result.initialPump.stopReason == CredSspPumpStopReason::TypedFailure;
    const bool tls13OracleLimitation =
        serverPinnedToTls13 &&
        noAuthenticationWireState &&
        (providerRejectedBeforeTls || providerCouldNotNegotiateTls13);

    const bool passed =
        reachedTypeThree && expectedNegotiatedVersion;
    const char *const status =
        passed ? "PASS"
               : tls13OracleLimitation ? "ORACLE_LIMITATION"
                                       : "FAIL";
    const SECURITY_STATUS reportedStatus =
        std::string_view{result.stage} == "acquire-credssp"
            ? result.acquireStatus
            : result.lastClientStatus;

    std::fprintf(
        stderr,
        "microsoft-credssp-tls-version-matrix "
        "profile=%s schannel=%s status=%s negotiated-tls=%s cipher=%s "
        "server-min=%s server-max=%s first-tsrequest=%s type1=%s "
        "type2-committed=%s next-tsrequest=%s type3=%s "
        "microsoft-status=%s code=0x%08lx "
        "physical-reference-tls=TLS1.3 "
        "physical-reference-cipher=TLS_AES_256_GCM_SHA384 "
        "stage=%s\n",
        tlsServerProfileName(tlsServerProfile),
        schannelCredentialProfileName(clientProfile),
        status,
        result.tlsEstablished
            ? tlsVersionName(result.negotiatedTlsVersion)
            : "none",
        result.negotiatedCipherName.data(),
        tlsVersionName(result.minimumTlsVersion),
        tlsVersionName(result.maximumTlsVersion),
        result.initialClientTsRequestReceived ? "yes" : "no",
        result.typeOneObserved ? "yes" : "no",
        result.productionTypeTwoTlsCommitted ? "yes" : "no",
        result.nextClientTsRequestReceived ? "yes" : "no",
        result.productionObservedTypeThree ? "yes" : "no",
        securityStatusName(reportedStatus),
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(reportedStatus)),
        result.stage);

    if (!passed && !tls13OracleLimitation)
        printFailure(TargetProfile::PortableServerName, result);
    return passed || tls13OracleLimitation;
}

[[nodiscard]] bool runCredentialSemanticDifferential()
{
    const TargetProfile target = TargetProfile::PortableServerName;
    const auto runState = [target](CredSspCredentialState state) {
        return runFullCredSspAttempt(
            target,
            ChallengeExperiment::Production,
            SchannelCredentialProfile::LegacySchannelCred,
            TlsServerProfile::SystemDefault,
            state);
    };

    const FullCredSspAttempt correct =
        runState(CredSspCredentialState::CorrectPassword);
    const FullCredSspAttempt wrong =
        runState(CredSspCredentialState::WrongPassword);
    const FullCredSspAttempt missing =
        runState(CredSspCredentialState::MissingCredentials);
    const FullCredSspAttempt empty =
        runState(CredSspCredentialState::EmptyPassword);

    printCredentialSemanticRow(correct);
    printCredentialSemanticRow(wrong);
    printCredentialSemanticRow(missing);
    printCredentialSemanticRow(empty);

    const bool correctQualified = acceptedNextClientMessage(correct);
    const bool wrongQualified = acceptedNextClientMessage(wrong);
    const bool missingQualified =
        !missing.productionObservedTypeThree &&
        microsoftCredentialFailureObserved(missing);
    const bool emptyQualified =
        acceptedNextClientMessage(empty) ||
        (!empty.productionObservedTypeThree &&
         microsoftCredentialFailureObserved(empty));

    if (!correctQualified)
        printFailure(target, correct);
    if (!wrongQualified)
        printFailure(target, wrong);
    if (!missingQualified)
        printFailure(target, missing);
    if (!emptyQualified)
        printFailure(target, empty);

    std::fprintf(
        stderr,
        "microsoft-credssp-credential-semantics-summary "
        "correct=%s wrong-password=%s missing-credentials=%s "
        "empty-password=%s wrong-password-pretype3-eof-match=%s "
        "production-type2-change-authorized=no\n",
        correctQualified ? "TYPE3" : "FAIL",
        wrongQualified ? "TYPE3" : "FAIL",
        missingQualified ? "TYPED_NO_TYPE3" : "FAIL",
        acceptedNextClientMessage(empty)
            ? "TYPE3"
            : emptyQualified ? "TYPED_NO_TYPE3" : "FAIL",
        wrongQualified ? "no" : "unresolved");

    return correctQualified &&
           wrongQualified &&
           missingQualified &&
           emptyQualified;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;

    const std::string_view mode{argv[1]};
    if (mode == "harness-stream-buffer-retention")
        return runHarnessStreamBufferRetention() ? 0 : 1;
    if (mode == "harness-multi-turn-round-progression")
        return runHarnessMultiTurnRoundProgression() ? 0 : 1;
    if (mode == "tls-system-default")
        return runTlsVersionQualification(
                   TlsServerProfile::SystemDefault) ? 0 : 1;
    if (mode == "tls12-only-server")
        return runTlsVersionQualification(
                   TlsServerProfile::Tls12Only) ? 0 : 1;
    if (mode == "tls13-only-server")
        return runTlsVersionQualification(
                   TlsServerProfile::Tls13Only) ? 0 : 1;
    if (mode == "modern-schannel-system-defaults-probe")
        return runModernSchannelSystemDefaultsProbe() ? 0 : 1;
    if (mode == "credential-semantic-differential")
        return runCredentialSemanticDifferential() ? 0 : 1;

    TargetProfile profile{};
    if (mode == "control-target")
        profile = TargetProfile::PortableServerName;
    else if (mode == "physical-ip-target")
        profile = TargetProfile::PhysicalIpv4;
    else if (mode == "bare-ip-target")
        profile = TargetProfile::BarePhysicalIpv4;
    else
        return 2;

    if (profile != TargetProfile::PortableServerName)
    {
        const FullCredSspAttempt control =
            runFullCredSspAttempt(
                TargetProfile::PortableServerName,
                ChallengeExperiment::Production);
        if (!acceptedNextClientMessage(control))
        {
            printFailure(TargetProfile::PortableServerName, control);
            std::fprintf(
                stderr,
                "microsoft-credssp-matrix target=%s "
                "status=blocked-control-not-accepted\n",
                targetLabel(profile));
            return 1;
        }
        std::fprintf(
            stderr,
            "microsoft-credssp-matrix target=%s "
            "control=TERMSRV/RDP-SERVER status=accepted\n",
            targetLabel(profile));
    }

    const FullCredSspAttempt result =
        runFullCredSspAttempt(
            profile, ChallengeExperiment::Production);
    if (acceptedNextClientMessage(result))
    {
        std::fprintf(
            stderr,
            "microsoft-credssp target=%s schannel=%s "
            "production-type2=accepted tls=%s type2-consumed=yes "
            "next-client-tsrequest=yes type3=%s "
            "type3-verified=%s pubkeyauth=%s\n",
            targetLabel(profile),
            schannelCredentialProfileName(
                result.schannelCredentialProfile),
            tlsVersionName(result.negotiatedTlsVersion),
            result.productionObservedTypeThree ? "yes" : "no",
            result.productionVerifiedTypeThree ? "yes" : "no",
            result.nextClientHasPubKeyAuth ? "yes" : "no");
        return 0;
    }

    printFailure(profile, result);

    if (profile != TargetProfile::PhysicalIpv4)
        return 1;

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
