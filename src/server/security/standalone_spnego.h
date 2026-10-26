// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "standalone_ntlmssp.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

inline constexpr std::size_t kMaximumStandaloneSpnegoTokenBytes = 8192U;
inline constexpr std::size_t kMaximumStandaloneSpnegoMechanisms = 16U;
inline constexpr std::size_t kMaximumStandaloneSpnegoMechanismOidBytes = 32U;
inline constexpr std::uint8_t kStandaloneSpnegoNoMechanismIndex = 0xffU;

enum class StandaloneNtlmNegotiationEnvelope : std::uint8_t
{
    Undetermined,
    Spnego,
    DirectNtlm,
};

[[nodiscard]] constexpr const char *standaloneNtlmNegotiationEnvelopeName(
    StandaloneNtlmNegotiationEnvelope envelope) noexcept
{
    switch (envelope)
    {
    case StandaloneNtlmNegotiationEnvelope::Undetermined:
        return "undetermined";
    case StandaloneNtlmNegotiationEnvelope::Spnego:
        return "spnego";
    case StandaloneNtlmNegotiationEnvelope::DirectNtlm:
        return "direct-ntlm";
    }
    return "undetermined";
}

enum class StandaloneSpnegoStage : std::uint8_t
{
    Unconfigured,
    AwaitInitialToken,
    AwaitNtlmNegotiate,
    AwaitNtlmAuthenticate,
    MechanismVerified,
    Failed,
};

enum class StandaloneSpnegoStatus : std::uint8_t
{
    Continue,
    MechanismVerified,
    InvalidState,
    InvalidToken,
    UnsupportedMechanismIntegrity,
    CredentialRejected,
    OutputTooSmall,
};

// Redacted failure boundary for real Microsoft-client acceptance. This carries
// no token, response, session key, username or password material.
enum class StandaloneSpnegoFailureStage : std::uint8_t
{
    None,
    Spnego,
    NtlmNegotiation,
    Mic,
};

// Non-secret, bounded structural rejection reason for owner diagnostics.
// This is intentionally finer than the public protocol status.
enum class StandaloneSpnegoRejectionReason : std::uint8_t
{
    None,
    InvalidGssWrapper,
    UnexpectedMechanismOid,
    InvalidNegTokenChoice,
    MalformedMechList,
    NtlmNotOffered,
    DuplicateNtlm,
    UnsupportedFieldOrder,
    MalformedNegHints,
    MalformedContextFlags,
    OptimisticTokenShape,
    TokenTooLarge,
    UnsupportedIntegrityShape,
    NtlmNegotiate,
    ContinuationEnvelope,
    InvalidState,
    OutputExhausted,
    CredentialRejected,
};

[[nodiscard]] constexpr const char *standaloneSpnegoRejectionReasonName(
    StandaloneSpnegoRejectionReason reason) noexcept
{
    switch (reason)
    {
    case StandaloneSpnegoRejectionReason::None: return "none";
    case StandaloneSpnegoRejectionReason::InvalidGssWrapper:
        return "invalid-gss-wrapper";
    case StandaloneSpnegoRejectionReason::UnexpectedMechanismOid:
        return "unexpected-mechanism-oid";
    case StandaloneSpnegoRejectionReason::InvalidNegTokenChoice:
        return "invalid-neg-token-choice";
    case StandaloneSpnegoRejectionReason::MalformedMechList:
        return "malformed-mech-list";
    case StandaloneSpnegoRejectionReason::NtlmNotOffered:
        return "ntlm-not-offered";
    case StandaloneSpnegoRejectionReason::DuplicateNtlm:
        return "duplicate-ntlm";
    case StandaloneSpnegoRejectionReason::UnsupportedFieldOrder:
        return "unsupported-field-order";
    case StandaloneSpnegoRejectionReason::MalformedNegHints:
        return "malformed-neg-hints";
    case StandaloneSpnegoRejectionReason::MalformedContextFlags:
        return "malformed-context-flags";
    case StandaloneSpnegoRejectionReason::OptimisticTokenShape:
        return "optimistic-token-shape";
    case StandaloneSpnegoRejectionReason::TokenTooLarge:
        return "token-too-large";
    case StandaloneSpnegoRejectionReason::UnsupportedIntegrityShape:
        return "unsupported-integrity-shape";
    case StandaloneSpnegoRejectionReason::NtlmNegotiate:
        return "ntlm-negotiate";
    case StandaloneSpnegoRejectionReason::ContinuationEnvelope:
        return "invalid-continuation-envelope";
    case StandaloneSpnegoRejectionReason::InvalidState:
        return "invalid-mechanism-state";
    case StandaloneSpnegoRejectionReason::OutputExhausted:
        return "bounded-output-exhausted";
    case StandaloneSpnegoRejectionReason::CredentialRejected:
        return "ntlm-credential-rejected";
    }
    return "invalid-neg-token-choice";
}

struct StandaloneSpnegoMechanismOidObservation final
{
    std::array<std::uint8_t, kMaximumStandaloneSpnegoMechanismOidBytes> oid{};
    std::size_t oidBytes{};
    bool oidTruncated{};
};

struct StandaloneSpnegoInitialTokenObservation final
{
    bool observed{};
    StandaloneNtlmNegotiationEnvelope negotiationEnvelope{
        StandaloneNtlmNegotiationEnvelope::Undetermined};
    bool directNtlmType1Accepted{};
    // Same production Type-1 parser result used to select the challenge.
    // Payload identities are absent; only safe structural metadata survives.
    bool ntlmTypeOneObserved{};
    NtlmNegotiateMessage ntlmTypeOne{};
    std::size_t tokenBytes{};
    std::uint8_t topLevelTag{};
    bool gssInitialContextToken{};
    bool negTokenInit{};
    bool negTokenInit2{};
    bool reqFlagsPresent{};
    bool negHintsPresent{};
    bool mechListMicPresent{};
    std::size_t mechanismCount{};
    bool ntlmOffered{};
    std::uint8_t ntlmMechanismIndex{kStandaloneSpnegoNoMechanismIndex};
    bool optimisticMechanismTokenPresent{};
    std::size_t optimisticMechanismTokenBytes{};
    std::array<
        StandaloneSpnegoMechanismOidObservation,
        kMaximumStandaloneSpnegoMechanisms> mechanisms{};
    StandaloneSpnegoRejectionReason rejectionReason{
        StandaloneSpnegoRejectionReason::None};
};

struct StandaloneSpnegoStep final
{
    StandaloneSpnegoStatus status{StandaloneSpnegoStatus::InvalidToken};
    std::size_t bytesWritten{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return status == StandaloneSpnegoStatus::Continue ||
               status == StandaloneSpnegoStatus::MechanismVerified;
    }
};

struct StandaloneSpnegoChallengeConfiguration final
{
    NtlmServerChallenge serverChallenge{};
    std::u16string_view netbiosDomainName{};
    std::u16string_view netbiosComputerName{};
    std::uint64_t timestampFileTime{};
};

// One noncopyable connection-oriented negotiation/NTLM owner for the
// standalone application-password track.
//
// The first valid token immutably selects either SPNEGO or direct NTLM for this
// accepted connection. SPNEGO keeps the existing Microsoft NTLM mechanism-OID
// selection and RFC 4178 mechListMIC rules. Direct NTLM accepts only raw
// NTLMSSP Type 1 -> Type 2 -> Type 3 messages. Both envelopes share the exact
// same NTLM transcript, password verification and directional message-security
// state; there is no second NTLM implementation.
//
// No method here grants R2 desktop admission or performs TLS/TSRequest I/O.
class StandaloneSpnegoNtlmAcceptor final
{
public:
    StandaloneSpnegoNtlmAcceptor() noexcept = default;
    ~StandaloneSpnegoNtlmAcceptor();

    StandaloneSpnegoNtlmAcceptor(
        const StandaloneSpnegoNtlmAcceptor &) = delete;
    StandaloneSpnegoNtlmAcceptor &operator=(
        const StandaloneSpnegoNtlmAcceptor &) = delete;
    StandaloneSpnegoNtlmAcceptor(
        StandaloneSpnegoNtlmAcceptor &&) = delete;
    StandaloneSpnegoNtlmAcceptor &operator=(
        StandaloneSpnegoNtlmAcceptor &&) = delete;

    [[nodiscard]] bool configureChallenge(
        const StandaloneSpnegoChallengeConfiguration &configuration) noexcept;

    [[nodiscard]] StandaloneSpnegoStep acceptInitialToken(
        std::span<const std::uint8_t> token,
        std::span<std::uint8_t> output) noexcept;

    [[nodiscard]] StandaloneSpnegoStep acceptContinuationToken(
        std::span<const std::uint8_t> token,
        const EphemeralNtlmV2Credential &credential,
        std::span<std::uint8_t> output) noexcept;

    [[nodiscard]] NtlmMessageSecurityResult unwrapClientMessage(
        std::span<const std::uint8_t> sealedMessage,
        std::span<const std::uint8_t, kNtlmMessageSignatureBytes> signature,
        std::span<std::uint8_t> plaintext) noexcept;

    [[nodiscard]] NtlmMessageSecurityResult wrapServerMessage(
        std::span<const std::uint8_t> plaintext,
        std::span<std::uint8_t> sealedMessage,
        std::span<std::uint8_t, kNtlmMessageSignatureBytes> signature) noexcept;

    [[nodiscard]] StandaloneSpnegoStage stage() const noexcept
    {
        return stage_;
    }

    [[nodiscard]] StandaloneSpnegoFailureStage failureStage() const noexcept
    {
        return failureStage_;
    }

    [[nodiscard]] StandaloneNtlmNegotiationEnvelope negotiationEnvelope()
        const noexcept
    {
        return negotiationEnvelope_;
    }

    // Redacted message kind from the last successfully parsed NTLM Type 1/3.
    // It carries no token material and is reset with the connection owner.
    [[nodiscard]] std::uint32_t lastNtlmMessageType() const noexcept
    {
        return lastNtlmMessageType_;
    }

    [[nodiscard]] StandaloneSpnegoRejectionReason rejectionReason() const noexcept
    {
        return rejectionReason_;
    }

    [[nodiscard]] StandaloneSpnegoInitialTokenObservation
    initialTokenObservation() const noexcept
    {
        return initialTokenObservation_;
    }

    [[nodiscard]] NtlmChallengeMessageObservation
    challengeObservation() const noexcept
    {
        return challengeObservation_;
    }

    void reset() noexcept;

private:
    [[nodiscard]] StandaloneSpnegoStep issueChallenge(
        std::span<const std::uint8_t> negotiateMessage,
        bool includeSupportedMechanism,
        std::span<std::uint8_t> output) noexcept;
    [[nodiscard]] StandaloneSpnegoStep fail(
        StandaloneSpnegoStatus status) noexcept;
    void clearMechanismState() noexcept;

    std::array<char16_t, kMaximumStandaloneNtlmDomainCodeUnits + 1U>
        domainName_{};
    std::size_t domainNameLength_{};
    std::array<char16_t, kMaximumStandaloneNtlmServerNameCodeUnits + 1U>
        computerName_{};
    std::size_t computerNameLength_{};
    NtlmServerChallenge serverChallenge_{};
    std::uint64_t timestampFileTime_{};

    std::array<std::uint8_t, kMaximumStandaloneNtlmMessageBytes>
        negotiateMessage_{};
    std::size_t negotiateMessageLength_{};
    std::array<std::uint8_t, kMaximumStandaloneNtlmMessageBytes>
        challengeMessage_{};
    std::size_t challengeMessageLength_{};
    std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes>
        mechanismList_{};
    std::size_t mechanismListLength_{};

    bool ntlmWasFirstMechanism_{};
    StandaloneNtlmNegotiationEnvelope negotiationEnvelope_{
        StandaloneNtlmNegotiationEnvelope::Undetermined};
    std::uint32_t lastNtlmMessageType_{};
    NtlmV2SecurityContext securityContext_{};
    StandaloneSpnegoStage stage_{StandaloneSpnegoStage::Unconfigured};
    StandaloneSpnegoFailureStage failureStage_{
        StandaloneSpnegoFailureStage::None};
    StandaloneSpnegoRejectionReason rejectionReason_{
        StandaloneSpnegoRejectionReason::None};
    StandaloneSpnegoInitialTokenObservation initialTokenObservation_{};
    NtlmChallengeMessageObservation challengeObservation_{};
};

} // namespace rdp_server::server::security
