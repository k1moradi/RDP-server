// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_spnego.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{
namespace
{

using ByteSpan = std::span<const std::uint8_t>;

constexpr std::array<std::uint8_t, 6> kSpnegoOid{
    0x2b,0x06,0x01,0x05,0x05,0x02};
constexpr std::array<std::uint8_t, 10> kNtlmOid{
    0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};

constexpr std::uint8_t kAcceptCompleted = 0U;
constexpr std::uint8_t kAcceptIncomplete = 1U;
constexpr std::uint8_t kRequestMic = 3U;

struct DerElement final
{
    std::uint8_t tag{};
    ByteSpan content{};
};

[[nodiscard]] bool readDerElement(
    ByteSpan input,
    std::size_t &offset,
    DerElement &element) noexcept
{
    element = {};
    if (offset >= input.size())
        return false;

    element.tag = input[offset++];
    if (offset >= input.size())
        return false;

    const std::uint8_t firstLength = input[offset++];
    std::size_t contentLength = 0;
    if ((firstLength & 0x80U) == 0U)
    {
        contentLength = firstLength;
    }
    else
    {
        const std::size_t lengthOctets = firstLength & 0x7fU;
        if (lengthOctets == 0U || lengthOctets > 2U ||
            lengthOctets > input.size() - offset ||
            input[offset] == 0U)
        {
            return false;
        }

        for (std::size_t index = 0; index < lengthOctets; ++index)
            contentLength =
                (contentLength << 8U) | input[offset++];

        if ((lengthOctets == 1U && contentLength < 128U) ||
            (lengthOctets == 2U && contentLength < 256U))
        {
            return false;
        }
    }

    if (contentLength > input.size() - offset)
        return false;

    element.content = input.subspan(offset, contentLength);
    offset += contentLength;
    return true;
}

[[nodiscard]] bool unwrapSingle(
    ByteSpan encoded,
    std::uint8_t expectedTag,
    ByteSpan &content) noexcept
{
    std::size_t offset = 0;
    DerElement element;
    if (!readDerElement(encoded, offset, element) ||
        element.tag != expectedTag ||
        offset != encoded.size())
    {
        return false;
    }
    content = element.content;
    return true;
}

[[nodiscard]] bool oidEquals(
    ByteSpan oid,
    ByteSpan expected) noexcept
{
    return oid.size() == expected.size() &&
           std::equal(oid.begin(), oid.end(), expected.begin());
}

[[nodiscard]] std::size_t derLengthOctets(
    std::size_t contentLength) noexcept
{
    if (contentLength < 128U)
        return 1U;
    if (contentLength < 256U)
        return 2U;
    return 3U;
}

[[nodiscard]] std::size_t derElementBytes(
    std::size_t contentLength) noexcept
{
    return 1U + derLengthOctets(contentLength) + contentLength;
}

[[nodiscard]] bool writeDerHeader(
    std::span<std::uint8_t> output,
    std::size_t &offset,
    std::uint8_t tag,
    std::size_t contentLength) noexcept
{
    const std::size_t lengthOctets = derLengthOctets(contentLength);
    const std::size_t required = 1U + lengthOctets;
    if (offset > output.size() || required > output.size() - offset)
        return false;

    output[offset++] = tag;
    if (contentLength < 128U)
    {
        output[offset++] = static_cast<std::uint8_t>(contentLength);
    }
    else if (contentLength < 256U)
    {
        output[offset++] = 0x81U;
        output[offset++] = static_cast<std::uint8_t>(contentLength);
    }
    else
    {
        if (contentLength > 0xffffU)
            return false;
        output[offset++] = 0x82U;
        output[offset++] =
            static_cast<std::uint8_t>(contentLength >> 8U);
        output[offset++] =
            static_cast<std::uint8_t>(contentLength);
    }
    return true;
}

[[nodiscard]] bool appendBytes(
    std::span<std::uint8_t> output,
    std::size_t &offset,
    ByteSpan bytes) noexcept
{
    if (offset > output.size() || bytes.size() > output.size() - offset)
        return false;
    std::copy(bytes.begin(), bytes.end(), output.begin() +
              static_cast<std::ptrdiff_t>(offset));
    offset += bytes.size();
    return true;
}

struct ParsedInitialToken final
{
    ByteSpan mechanismToken{};
    ByteSpan mechanismListEncoded{};
    ByteSpan mechListMic{};
    bool ntlmOffered{};
    bool ntlmFirst{};
};

[[nodiscard]] bool rejectInitialToken(
    StandaloneSpnegoInitialTokenObservation &observation,
    StandaloneSpnegoRejectionReason reason) noexcept
{
    observation.rejectionReason = reason;
    return false;
}

[[nodiscard]] bool parseMechanismList(
    ByteSpan encoded,
    ParsedInitialToken &result,
    StandaloneSpnegoInitialTokenObservation &observation) noexcept
{
    ByteSpan sequence;
    if (!unwrapSingle(encoded, 0x30U, sequence))
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::MalformedMechList);

    std::size_t offset = 0U;
    std::size_t mechanismIndex = 0U;
    bool sawNtlm = false;
    while (offset < sequence.size())
    {
        if (mechanismIndex >= kMaximumStandaloneSpnegoMechanisms)
            return rejectInitialToken(
                observation, StandaloneSpnegoRejectionReason::MalformedMechList);

        DerElement oid;
        if (!readDerElement(sequence, offset, oid) ||
            oid.tag != 0x06U || oid.content.empty())
        {
            return rejectInitialToken(
                observation, StandaloneSpnegoRejectionReason::MalformedMechList);
        }

        auto &mechanism = observation.mechanisms[mechanismIndex];
        const std::size_t capturedOidBytes = std::min(
            oid.content.size(), kMaximumStandaloneSpnegoMechanismOidBytes);
        std::copy_n(
            oid.content.begin(), capturedOidBytes, mechanism.oid.begin());
        mechanism.oidBytes = capturedOidBytes;
        mechanism.oidTruncated = capturedOidBytes != oid.content.size();

        // Publish each structurally valid offered OID as soon as it is parsed
        // so a later duplicate/malformed field cannot erase useful bounded
        // first-token diagnostics.
        observation.mechanismCount = mechanismIndex + 1U;

        if (oidEquals(oid.content, kNtlmOid))
        {
            if (sawNtlm)
                return rejectInitialToken(
                    observation, StandaloneSpnegoRejectionReason::DuplicateNtlm);
            sawNtlm = true;
            result.ntlmOffered = true;
            result.ntlmFirst = mechanismIndex == 0U;
            observation.ntlmOffered = true;
            observation.ntlmMechanismIndex =
                static_cast<std::uint8_t>(mechanismIndex);
        }
        ++mechanismIndex;
    }

    if (mechanismIndex == 0U)
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::MalformedMechList);
    if (!sawNtlm)
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::NtlmNotOffered);

    result.mechanismListEncoded = encoded;
    return true;
}

[[nodiscard]] bool validNegHints(ByteSpan encoded) noexcept
{
    ByteSpan sequence;
    if (!unwrapSingle(encoded, 0x30U, sequence))
        return false;

    std::size_t offset = 0U;
    std::uint8_t previousTag = 0x9fU;
    while (offset < sequence.size())
    {
        DerElement field;
        if (!readDerElement(sequence, offset, field) ||
            field.tag < 0xa0U || field.tag > 0xa1U ||
            field.tag <= previousTag)
            return false;
        previousTag = field.tag;

        ByteSpan nested;
        if (field.tag == 0xa0U)
        {
            if (!unwrapSingle(field.content, 0x1bU, nested) ||
                nested.empty() || nested.size() > 256U)
                return false;
        }
        else if (!unwrapSingle(field.content, 0x04U, nested) ||
                 nested.size() > 256U)
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool validContextFlags(ByteSpan encoded) noexcept
{
    ByteSpan bits;
    if (!unwrapSingle(encoded, 0x03U, bits) ||
        bits.empty() || bits[0] > 7U)
        return false;

    const std::uint8_t unusedBits = bits[0];
    if (unusedBits != 0U && bits.size() > 1U)
    {
        const std::uint8_t mask =
            static_cast<std::uint8_t>((1U << unusedBits) - 1U);
        if ((bits.back() & mask) != 0U)
            return false;
    }
    return true;
}

[[nodiscard]] bool parseInitialToken(
    ByteSpan token,
    ParsedInitialToken &result,
    StandaloneSpnegoInitialTokenObservation &observation) noexcept
{
    result = {};
    observation = {};
    observation.observed = true;
    observation.tokenBytes = token.size();
    if (!token.empty())
        observation.topLevelTag = token.front();

    if (token.size() > kMaximumStandaloneSpnegoTokenBytes)
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::TokenTooLarge);
    if (token.empty())
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::InvalidGssWrapper);

    ByteSpan initialContext;
    if (!unwrapSingle(token, 0x60U, initialContext))
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::InvalidGssWrapper);
    observation.gssInitialContextToken = true;

    std::size_t outerOffset = 0U;
    DerElement mechanismOid;
    if (!readDerElement(initialContext, outerOffset, mechanismOid) ||
        mechanismOid.tag != 0x06U)
    {
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::InvalidGssWrapper);
    }
    if (!oidEquals(mechanismOid.content, kSpnegoOid))
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::UnexpectedMechanismOid);

    DerElement negotiationToken;
    if (!readDerElement(initialContext, outerOffset, negotiationToken) ||
        negotiationToken.tag != 0xa0U ||
        outerOffset != initialContext.size())
    {
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::InvalidNegTokenChoice);
    }
    observation.negTokenInit = true;

    ByteSpan sequence;
    if (!unwrapSingle(negotiationToken.content, 0x30U, sequence))
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::InvalidNegTokenChoice);

    std::size_t offset = 0U;
    std::uint8_t previousTag = 0x9fU;
    bool sawMechanisms = false;
    while (offset < sequence.size())
    {
        DerElement field;
        if (!readDerElement(sequence, offset, field) ||
            field.tag < 0xa0U || field.tag > 0xa4U)
        {
            return rejectInitialToken(
                observation, StandaloneSpnegoRejectionReason::InvalidNegTokenChoice);
        }
        if (field.tag <= previousTag)
            return rejectInitialToken(
                observation, StandaloneSpnegoRejectionReason::UnsupportedFieldOrder);
        previousTag = field.tag;

        ByteSpan nested;
        switch (field.tag)
        {
        case 0xa0U:
            if (sawMechanisms)
                return rejectInitialToken(
                    observation, StandaloneSpnegoRejectionReason::UnsupportedFieldOrder);
            if (!parseMechanismList(field.content, result, observation))
                return false;
            sawMechanisms = true;
            break;
        case 0xa1U:
            observation.reqFlagsPresent = true;
            if (!validContextFlags(field.content))
                return rejectInitialToken(
                    observation, StandaloneSpnegoRejectionReason::MalformedContextFlags);
            break;
        case 0xa2U:
            observation.optimisticMechanismTokenPresent = true;
            if (!unwrapSingle(field.content, 0x04U, nested) || nested.empty())
                return rejectInitialToken(
                    observation, StandaloneSpnegoRejectionReason::OptimisticTokenShape);
            observation.optimisticMechanismTokenBytes = nested.size();
            if (nested.size() > kMaximumStandaloneNtlmMessageBytes)
                return rejectInitialToken(
                    observation, StandaloneSpnegoRejectionReason::TokenTooLarge);
            result.mechanismToken = nested;
            break;
        case 0xa3U:
            if (!field.content.empty() && field.content.front() == 0x04U)
            {
                observation.mechListMicPresent = true;
                if (!unwrapSingle(field.content, 0x04U, nested) ||
                    !result.mechListMic.empty())
                {
                    return rejectInitialToken(
                        observation, StandaloneSpnegoRejectionReason::UnsupportedIntegrityShape);
                }
                result.mechListMic = nested;
            }
            else
            {
                observation.negHintsPresent = true;
                observation.negTokenInit2 = true;
                if (!validNegHints(field.content))
                    return rejectInitialToken(
                        observation, StandaloneSpnegoRejectionReason::MalformedNegHints);
            }
            break;
        case 0xa4U:
            observation.negTokenInit2 = true;
            observation.mechListMicPresent = true;
            if (!unwrapSingle(field.content, 0x04U, nested) ||
                !result.mechListMic.empty())
            {
                return rejectInitialToken(
                    observation, StandaloneSpnegoRejectionReason::UnsupportedIntegrityShape);
            }
            result.mechListMic = nested;
            break;
        default:
            return rejectInitialToken(
                observation, StandaloneSpnegoRejectionReason::InvalidNegTokenChoice);
        }
    }

    if (!sawMechanisms || result.mechanismListEncoded.empty())
        return rejectInitialToken(
            observation, StandaloneSpnegoRejectionReason::MalformedMechList);
    observation.rejectionReason = StandaloneSpnegoRejectionReason::None;
    return true;
}

struct ParsedResponseToken final
{
    ByteSpan mechanismToken{};
    ByteSpan mechListMic{};
    bool hasNegState{};
    std::uint8_t negState{};
};

[[nodiscard]] bool parseResponseToken(
    ByteSpan token,
    ParsedResponseToken &result) noexcept
{
    result = {};
    if (token.empty() ||
        token.size() > kMaximumStandaloneSpnegoTokenBytes)
    {
        return false;
    }

    ByteSpan responseChoice;
    if (!unwrapSingle(token, 0xa1U, responseChoice))
        return false;

    ByteSpan sequence;
    if (!unwrapSingle(responseChoice, 0x30U, sequence))
        return false;

    std::size_t offset = 0;
    std::uint8_t previousTag = 0x9fU;
    while (offset < sequence.size())
    {
        DerElement field;
        if (!readDerElement(sequence, offset, field) ||
            field.tag < 0xa0U || field.tag > 0xa3U ||
            field.tag <= previousTag)
        {
            return false;
        }
        previousTag = field.tag;

        ByteSpan nested;
        switch (field.tag)
        {
        case 0xa0U:
            if (!unwrapSingle(field.content, 0x0aU, nested) ||
                nested.size() != 1U || nested[0] > 3U)
            {
                return false;
            }
            result.hasNegState = true;
            result.negState = nested[0];
            break;
        case 0xa1U:
            if (!unwrapSingle(field.content, 0x06U, nested) ||
                !oidEquals(nested, kNtlmOid))
            {
                return false;
            }
            break;
        case 0xa2U:
            if (!unwrapSingle(field.content, 0x04U, nested) ||
                nested.empty() ||
                nested.size() > kMaximumStandaloneNtlmMessageBytes)
            {
                return false;
            }
            result.mechanismToken = nested;
            break;
        case 0xa3U:
            if (!unwrapSingle(field.content, 0x04U, nested))
                return false;
            result.mechListMic = nested;
            break;
        default:
            return false;
        }
    }

    if (result.hasNegState &&
        result.negState != kAcceptIncomplete)
    {
        return false;
    }
    return !result.mechanismToken.empty();
}

[[nodiscard]] bool encodeServerResponse(
    std::uint8_t negState,
    bool includeSupportedMechanism,
    ByteSpan responseToken,
    ByteSpan mechListMic,
    std::span<std::uint8_t> output,
    std::size_t &bytesWritten) noexcept
{
    bytesWritten = 0;
    if (negState > kRequestMic || negState == 2U ||
        responseToken.size() > kMaximumStandaloneNtlmMessageBytes ||
        mechListMic.size() > kNtlmMessageSignatureBytes)
    {
        return false;
    }

    constexpr std::size_t enumeratedBytes = 3U;
    const std::size_t stateFieldBytes =
        derElementBytes(enumeratedBytes);

    constexpr std::size_t oidBytes =
        1U + 1U + kNtlmOid.size();
    const std::size_t mechanismFieldBytes =
        includeSupportedMechanism ? derElementBytes(oidBytes) : 0U;

    const std::size_t octetStringBytes = responseToken.empty()
        ? 0U : derElementBytes(responseToken.size());
    const std::size_t responseFieldBytes = responseToken.empty()
        ? 0U : derElementBytes(octetStringBytes);
    const std::size_t micOctetStringBytes = mechListMic.empty()
        ? 0U : derElementBytes(mechListMic.size());
    const std::size_t micFieldBytes = mechListMic.empty()
        ? 0U : derElementBytes(micOctetStringBytes);

    const std::size_t sequenceContentBytes =
        stateFieldBytes + mechanismFieldBytes +
        responseFieldBytes + micFieldBytes;
    const std::size_t sequenceBytes =
        derElementBytes(sequenceContentBytes);
    const std::size_t totalBytes =
        derElementBytes(sequenceBytes);

    if (totalBytes > kMaximumStandaloneSpnegoTokenBytes ||
        output.size() < totalBytes)
    {
        return false;
    }

    std::size_t offset = 0;
    if (!writeDerHeader(output, offset, 0xa1U, sequenceBytes) ||
        !writeDerHeader(
            output, offset, 0x30U, sequenceContentBytes) ||
        !writeDerHeader(output, offset, 0xa0U, enumeratedBytes) ||
        !writeDerHeader(output, offset, 0x0aU, 1U) ||
        offset >= output.size())
    {
        return false;
    }
    output[offset++] = negState;

    if (includeSupportedMechanism)
    {
        if (!writeDerHeader(output, offset, 0xa1U, oidBytes) ||
            !writeDerHeader(
                output, offset, 0x06U, kNtlmOid.size()) ||
            !appendBytes(output, offset, kNtlmOid))
        {
            return false;
        }
    }

    if (!responseToken.empty())
    {
        if (!writeDerHeader(
                output, offset, 0xa2U, octetStringBytes) ||
            !writeDerHeader(
                output, offset, 0x04U, responseToken.size()) ||
            !appendBytes(output, offset, responseToken))
        {
            return false;
        }
    }

    if (!mechListMic.empty())
    {
        if (!writeDerHeader(
                output, offset, 0xa3U, micOctetStringBytes) ||
            !writeDerHeader(
                output, offset, 0x04U, mechListMic.size()) ||
            !appendBytes(output, offset, mechListMic))
        {
            return false;
        }
    }

    if (offset != totalBytes)
        return false;
    bytesWritten = totalBytes;
    return true;
}


} // namespace

StandaloneSpnegoNtlmAcceptor::~StandaloneSpnegoNtlmAcceptor()
{
    reset();
}

void StandaloneSpnegoNtlmAcceptor::clearMechanismState() noexcept
{
    securityContext_.clear();
    OPENSSL_cleanse(
        negotiateMessage_.data(), negotiateMessage_.size());
    OPENSSL_cleanse(
        challengeMessage_.data(), challengeMessage_.size());
    OPENSSL_cleanse(
        mechanismList_.data(), mechanismList_.size());
    negotiateMessageLength_ = 0;
    challengeMessageLength_ = 0;
    mechanismListLength_ = 0;
    ntlmWasFirstMechanism_ = false;
}

void StandaloneSpnegoNtlmAcceptor::reset() noexcept
{
    clearMechanismState();
    OPENSSL_cleanse(
        domainName_.data(),
        domainName_.size() * sizeof(domainName_[0]));
    OPENSSL_cleanse(
        computerName_.data(),
        computerName_.size() * sizeof(computerName_[0]));
    OPENSSL_cleanse(
        serverChallenge_.data(), serverChallenge_.size());
    domainNameLength_ = 0;
    computerNameLength_ = 0;
    timestampFileTime_ = 0;
    stage_ = StandaloneSpnegoStage::Unconfigured;
    failureStage_ = StandaloneSpnegoFailureStage::None;
    rejectionReason_ = StandaloneSpnegoRejectionReason::None;
    initialTokenObservation_ = {};
}

StandaloneSpnegoStep StandaloneSpnegoNtlmAcceptor::fail(
    StandaloneSpnegoStatus status) noexcept
{
    if (rejectionReason_ == StandaloneSpnegoRejectionReason::None)
    {
        switch (status)
        {
        case StandaloneSpnegoStatus::InvalidState:
            rejectionReason_ = StandaloneSpnegoRejectionReason::InvalidState;
            break;
        case StandaloneSpnegoStatus::OutputTooSmall:
            rejectionReason_ = StandaloneSpnegoRejectionReason::OutputExhausted;
            break;
        case StandaloneSpnegoStatus::CredentialRejected:
            rejectionReason_ = StandaloneSpnegoRejectionReason::CredentialRejected;
            break;
        case StandaloneSpnegoStatus::InvalidToken:
        case StandaloneSpnegoStatus::UnsupportedMechanismIntegrity:
        case StandaloneSpnegoStatus::Continue:
        case StandaloneSpnegoStatus::MechanismVerified:
            rejectionReason_ = StandaloneSpnegoRejectionReason::ContinuationEnvelope;
            break;
        }
    }
    if (failureStage_ == StandaloneSpnegoFailureStage::None)
    {
        switch (status)
        {
        case StandaloneSpnegoStatus::UnsupportedMechanismIntegrity:
            failureStage_ = StandaloneSpnegoFailureStage::Mic;
            break;
        case StandaloneSpnegoStatus::CredentialRejected:
            failureStage_ = StandaloneSpnegoFailureStage::NtlmNegotiation;
            break;
        case StandaloneSpnegoStatus::Continue:
        case StandaloneSpnegoStatus::MechanismVerified:
        case StandaloneSpnegoStatus::InvalidState:
        case StandaloneSpnegoStatus::InvalidToken:
        case StandaloneSpnegoStatus::OutputTooSmall:
            failureStage_ = StandaloneSpnegoFailureStage::Spnego;
            break;
        }
    }
    const auto failureStage = failureStage_;
    clearMechanismState();
    stage_ = StandaloneSpnegoStage::Failed;
    failureStage_ = failureStage;
    return {status, 0U};
}

bool StandaloneSpnegoNtlmAcceptor::configureChallenge(
    const StandaloneSpnegoChallengeConfiguration &configuration) noexcept
{
    if (stage_ != StandaloneSpnegoStage::Unconfigured)
    {
        (void)fail(StandaloneSpnegoStatus::InvalidState);
        return false;
    }

    std::array<std::uint8_t, kMaximumStandaloneNtlmMessageBytes>
        validation{};
    constexpr std::uint32_t validationFlags =
        kNtlmNegotiateUnicode |
        kNtlmNegotiateNtlm |
        kRequiredStandaloneCredSspNtlmFlags;
    const auto validated = encodeNtlmChallengeMessage(
        {configuration.serverChallenge,
         configuration.netbiosDomainName,
         configuration.netbiosComputerName,
         configuration.timestampFileTime,
         validationFlags},
        validation);
    OPENSSL_cleanse(validation.data(), validation.size());
    if (!validated ||
        configuration.netbiosDomainName.size() >= domainName_.size() ||
        configuration.netbiosComputerName.size() >= computerName_.size())
    {
        failureStage_ = StandaloneSpnegoFailureStage::NtlmNegotiation;
        stage_ = StandaloneSpnegoStage::Failed;
        return false;
    }

    serverChallenge_ = configuration.serverChallenge;
    timestampFileTime_ = configuration.timestampFileTime;
    std::copy(
        configuration.netbiosDomainName.begin(),
        configuration.netbiosDomainName.end(),
        domainName_.begin());
    domainNameLength_ = configuration.netbiosDomainName.size();
    std::copy(
        configuration.netbiosComputerName.begin(),
        configuration.netbiosComputerName.end(),
        computerName_.begin());
    computerNameLength_ = configuration.netbiosComputerName.size();
    stage_ = StandaloneSpnegoStage::AwaitInitialToken;
    return true;
}

StandaloneSpnegoStep StandaloneSpnegoNtlmAcceptor::issueChallenge(
    std::span<const std::uint8_t> negotiateMessage,
    bool includeSupportedMechanism,
    std::span<std::uint8_t> output) noexcept
{
    failureStage_ = StandaloneSpnegoFailureStage::NtlmNegotiation;
    rejectionReason_ = StandaloneSpnegoRejectionReason::NtlmNegotiate;
    if (negotiateMessage.empty() ||
        negotiateMessage.size() > negotiateMessage_.size())
    {
        return fail(StandaloneSpnegoStatus::InvalidToken);
    }

    NtlmNegotiateMessage parsed;
    if (parseNtlmNegotiateMessage(
            negotiateMessage, parsed) !=
        NtlmMessageParseResult::Parsed)
    {
        return fail(StandaloneSpnegoStatus::InvalidToken);
    }

    const auto challenge = encodeNtlmChallengeMessage(
        {serverChallenge_,
         {domainName_.data(), domainNameLength_},
         {computerName_.data(), computerNameLength_},
         timestampFileTime_,
         parsed.negotiateFlags},
        challengeMessage_);
    if (!challenge)
        return fail(StandaloneSpnegoStatus::InvalidToken);

    std::copy(
        negotiateMessage.begin(),
        negotiateMessage.end(),
        negotiateMessage_.begin());
    negotiateMessageLength_ = negotiateMessage.size();
    challengeMessageLength_ = challenge.bytesWritten;
    failureStage_ = StandaloneSpnegoFailureStage::None;
    rejectionReason_ = StandaloneSpnegoRejectionReason::None;

    std::size_t bytesWritten = 0;
    if (!encodeServerResponse(
            kAcceptIncomplete,
            includeSupportedMechanism,
            std::span<const std::uint8_t>{challengeMessage_}.first(
                challengeMessageLength_),
            {},
            output,
            bytesWritten))
    {
        return fail(StandaloneSpnegoStatus::OutputTooSmall);
    }

    stage_ = StandaloneSpnegoStage::AwaitNtlmAuthenticate;
    return {StandaloneSpnegoStatus::Continue, bytesWritten};
}

StandaloneSpnegoStep StandaloneSpnegoNtlmAcceptor::acceptInitialToken(
    std::span<const std::uint8_t> token,
    std::span<std::uint8_t> output) noexcept
{
    if (stage_ != StandaloneSpnegoStage::AwaitInitialToken)
        return fail(StandaloneSpnegoStatus::InvalidState);

    ParsedInitialToken parsed;
    if (!parseInitialToken(token, parsed, initialTokenObservation_))
    {
        rejectionReason_ = initialTokenObservation_.rejectionReason;
        return fail(StandaloneSpnegoStatus::InvalidToken);
    }
    rejectionReason_ = StandaloneSpnegoRejectionReason::None;
    if (!parsed.mechListMic.empty() ||
        parsed.mechanismListEncoded.size() > mechanismList_.size())
    {
        rejectionReason_ =
            StandaloneSpnegoRejectionReason::UnsupportedIntegrityShape;
        initialTokenObservation_.rejectionReason = rejectionReason_;
        return fail(
            StandaloneSpnegoStatus::UnsupportedMechanismIntegrity);
    }

    std::copy(
        parsed.mechanismListEncoded.begin(),
        parsed.mechanismListEncoded.end(),
        mechanismList_.begin());
    mechanismListLength_ = parsed.mechanismListEncoded.size();

    ntlmWasFirstMechanism_ = parsed.ntlmFirst;
    if (parsed.ntlmFirst && !parsed.mechanismToken.empty())
        return issueChallenge(parsed.mechanismToken, true, output);

    std::size_t bytesWritten = 0;
    if (!encodeServerResponse(
            kRequestMic, true, {}, {}, output, bytesWritten))
    {
        return fail(StandaloneSpnegoStatus::OutputTooSmall);
    }

    stage_ = StandaloneSpnegoStage::AwaitNtlmNegotiate;
    rejectionReason_ = StandaloneSpnegoRejectionReason::None;
    return {StandaloneSpnegoStatus::Continue, bytesWritten};
}

StandaloneSpnegoStep
StandaloneSpnegoNtlmAcceptor::acceptContinuationToken(
    std::span<const std::uint8_t> token,
    const EphemeralNtlmV2Credential &credential,
    std::span<std::uint8_t> output) noexcept
{
    if (stage_ != StandaloneSpnegoStage::AwaitNtlmNegotiate &&
        stage_ != StandaloneSpnegoStage::AwaitNtlmAuthenticate)
    {
        return fail(StandaloneSpnegoStatus::InvalidState);
    }

    ParsedResponseToken parsed;
    if (!parseResponseToken(token, parsed))
        return fail(StandaloneSpnegoStatus::InvalidToken);

    if (stage_ == StandaloneSpnegoStage::AwaitNtlmNegotiate)
    {
        if (!parsed.mechListMic.empty())
        {
            return fail(
                StandaloneSpnegoStatus::UnsupportedMechanismIntegrity);
        }
        return issueChallenge(
            parsed.mechanismToken, false, output);
    }

    NtlmAuthenticateMessage authenticate;
    failureStage_ = StandaloneSpnegoFailureStage::NtlmNegotiation;
    if (parseNtlmAuthenticateMessage(
            parsed.mechanismToken, authenticate) !=
        NtlmMessageParseResult::Parsed)
    {
        return fail(StandaloneSpnegoStatus::InvalidToken);
    }
    failureStage_ = StandaloneSpnegoFailureStage::None;

    if (credential.verifyAndDeriveSecurityContext(
            authenticate.verificationRequest(serverChallenge_),
            securityContext_) != NtlmV2VerifyResult::Verified)
    {
        return fail(StandaloneSpnegoStatus::CredentialRejected);
    }

    if (!authenticate.messageIntegrityCode.empty())
    {
        failureStage_ = StandaloneSpnegoFailureStage::Mic;
        const std::uint8_t *const messageStart =
            parsed.mechanismToken.data();
        const std::uint8_t *const micStart =
            authenticate.messageIntegrityCode.data();
        if (micStart < messageStart ||
            micStart >
                messageStart + parsed.mechanismToken.size() ||
            static_cast<std::size_t>(micStart - messageStart) >
                parsed.mechanismToken.size() -
                    authenticate.messageIntegrityCode.size())
        {
            return fail(StandaloneSpnegoStatus::InvalidToken);
        }

        const std::size_t micOffset =
            static_cast<std::size_t>(micStart - messageStart);
        if (!securityContext_.verifyAuthenticateMessageMic(
                std::span<const std::uint8_t>{negotiateMessage_}.first(
                    negotiateMessageLength_),
                std::span<const std::uint8_t>{challengeMessage_}.first(
                    challengeMessageLength_),
                parsed.mechanismToken,
                micOffset))
        {
            return fail(StandaloneSpnegoStatus::CredentialRejected);
        }
        failureStage_ = StandaloneSpnegoFailureStage::None;
    }

    std::array<std::uint8_t, kNtlmMessageSignatureBytes>
        serverMechListMic{};
    ByteSpan serverMechListMicView{};
    if (!parsed.mechListMic.empty())
    {
        failureStage_ = StandaloneSpnegoFailureStage::Mic;
        if (parsed.mechListMic.size() != kNtlmMessageSignatureBytes ||
            mechanismListLength_ == 0U)
        {
            return fail(StandaloneSpnegoStatus::InvalidToken);
        }

        const auto clientMic =
            std::span<const std::uint8_t, kNtlmMessageSignatureBytes>{
                parsed.mechListMic.data(),
                parsed.mechListMic.size()};
        const auto mechanismList =
            std::span<const std::uint8_t>{mechanismList_}.first(
                mechanismListLength_);
        if (securityContext_.verifyClientMessageSignature(
                mechanismList, clientMic) !=
            NtlmMessageSecurityResult::Processed ||
            securityContext_.signServerMessage(
                mechanismList, serverMechListMic) !=
            NtlmMessageSecurityResult::Processed)
        {
            return fail(StandaloneSpnegoStatus::CredentialRejected);
        }
        serverMechListMicView = serverMechListMic;
        failureStage_ = StandaloneSpnegoFailureStage::None;
    }
    else if (!ntlmWasFirstMechanism_)
    {
        return fail(
            StandaloneSpnegoStatus::UnsupportedMechanismIntegrity);
    }

    std::size_t bytesWritten = 0;
    if (!encodeServerResponse(
            kAcceptCompleted, false, {},
            serverMechListMicView, output, bytesWritten))
    {
        OPENSSL_cleanse(
            serverMechListMic.data(), serverMechListMic.size());
        return fail(StandaloneSpnegoStatus::OutputTooSmall);
    }
    OPENSSL_cleanse(
        serverMechListMic.data(), serverMechListMic.size());

    failureStage_ = StandaloneSpnegoFailureStage::None;
    stage_ = StandaloneSpnegoStage::MechanismVerified;
    return {StandaloneSpnegoStatus::MechanismVerified, bytesWritten};
}

NtlmMessageSecurityResult
StandaloneSpnegoNtlmAcceptor::unwrapClientMessage(
    std::span<const std::uint8_t> sealedMessage,
    std::span<const std::uint8_t, kNtlmMessageSignatureBytes> signature,
    std::span<std::uint8_t> plaintext) noexcept
{
    if (stage_ != StandaloneSpnegoStage::MechanismVerified)
        return NtlmMessageSecurityResult::Inactive;

    const auto result = securityContext_.unwrapClientMessage(
        sealedMessage, signature, plaintext);
    if (!securityContext_.active())
        stage_ = StandaloneSpnegoStage::Failed;
    return result;
}

NtlmMessageSecurityResult
StandaloneSpnegoNtlmAcceptor::wrapServerMessage(
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> sealedMessage,
    std::span<std::uint8_t, kNtlmMessageSignatureBytes> signature) noexcept
{
    if (stage_ != StandaloneSpnegoStage::MechanismVerified)
        return NtlmMessageSecurityResult::Inactive;

    const auto result = securityContext_.wrapServerMessage(
        plaintext, sealedMessage, signature);
    if (!securityContext_.active())
        stage_ = StandaloneSpnegoStage::Failed;
    return result;
}

} // namespace rdp_server::server::security
