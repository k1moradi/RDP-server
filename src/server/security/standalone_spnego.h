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
    InitialEnvelope,
    MechanismList,
    InitialNegotiationField,
    UnsupportedInitialMic,
    NtlmNegotiate,
    ContinuationEnvelope,
    InvalidState,
    OutputExhausted,
    CredentialRejected,
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

// One noncopyable connection-oriented SPNEGO/NTLM owner for the standalone
// application-password track.
//
// The object accepts only SPNEGO with the Microsoft NTLM mechanism OID. It can
// select NTLM when it was not the initiator's first mechanism and requires the
// RFC 4178 mechListMIC exchange before that fallback can complete. The
// NTLM-first path retains the exact Type 1
// and server-emitted Type 2 bytes, verifies the Type 3 password proof and MIC,
// and then owns the established directional NTLM message-security state.
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

    [[nodiscard]] StandaloneSpnegoRejectionReason rejectionReason() const noexcept
    {
        return rejectionReason_;
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
    std::array<char16_t, kMaximumStandaloneNtlmUserCodeUnits + 1U>
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
    NtlmV2SecurityContext securityContext_{};
    StandaloneSpnegoStage stage_{StandaloneSpnegoStage::Unconfigured};
    StandaloneSpnegoFailureStage failureStage_{
        StandaloneSpnegoFailureStage::None};
    StandaloneSpnegoRejectionReason rejectionReason_{
        StandaloneSpnegoRejectionReason::None};
};

} // namespace rdp_server::server::security
