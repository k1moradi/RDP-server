// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

inline constexpr std::size_t kNtlmV2KeyBytes = 16U;
inline constexpr std::size_t kNtlmServerChallengeBytes = 8U;
inline constexpr std::size_t kMaximumStandaloneNtlmUserCodeUnits = 128U;
inline constexpr std::size_t kMaximumStandaloneNtlmDomainCodeUnits = 128U;
inline constexpr std::size_t kMaximumStandalonePasswordCodeUnits = 256U;
inline constexpr std::size_t kMaximumNtlmV2ChallengeResponseBytes = 4096U;

using NtlmV2Key = std::array<std::uint8_t, kNtlmV2KeyBytes>;
using NtlmServerChallenge =
    std::array<std::uint8_t, kNtlmServerChallengeBytes>;

// MS-NLMP negotiate flags needed by the standalone CredSSP profile. The
// prototype refuses weaker non-ESS/non-sealed/non-128-bit session security.
inline constexpr std::uint32_t kNtlmNegotiateSign = 0x00000010U;
inline constexpr std::uint32_t kNtlmNegotiateSeal = 0x00000020U;
inline constexpr std::uint32_t kNtlmNegotiateExtendedSessionSecurity =
    0x00080000U;
inline constexpr std::uint32_t kNtlmNegotiate128 = 0x20000000U;
inline constexpr std::uint32_t kNtlmNegotiateKeyExchange = 0x40000000U;
inline constexpr std::uint32_t kRequiredStandaloneCredSspNtlmFlags =
    kNtlmNegotiateSign | kNtlmNegotiateSeal |
    kNtlmNegotiateExtendedSessionSecurity | kNtlmNegotiate128;

enum class NtlmV2VerifyResult : std::uint8_t
{
    Verified,
    NotConfigured,
    InvalidInput,
    UnsupportedFlags,
    InvalidResponse,
    ProofMismatch,
    CryptoFailure,
};

struct NtlmV2AuthenticateRequest final
{
    NtlmServerChallenge serverChallenge{};
    std::u16string_view domain{};
    std::span<const std::uint8_t> ntChallengeResponse{};
    std::uint32_t negotiateFlags{};
    std::span<const std::uint8_t> encryptedRandomSessionKey{};
};

struct StandaloneNtlmV2TestAccess;

// Secret key material derived after a valid NTLMv2 challenge response.
// This is not itself R2 admission. A future SPNEGO/NTLM state machine must
// bind it to the exact TLS/CredSSP transcript before pubKeyAuth/authInfo use.
//
// Noncopyable/nonmovable: one connection state owns these keys. clear() is the
// Stop/revoke barrier and the destructor is a final non-elidable cleanse.
class NtlmV2SecurityContext final
{
public:
    NtlmV2SecurityContext() noexcept = default;
    ~NtlmV2SecurityContext();

    NtlmV2SecurityContext(const NtlmV2SecurityContext &) = delete;
    NtlmV2SecurityContext &operator=(const NtlmV2SecurityContext &) = delete;
    NtlmV2SecurityContext(NtlmV2SecurityContext &&) = delete;
    NtlmV2SecurityContext &operator=(NtlmV2SecurityContext &&) = delete;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] std::span<const std::uint8_t, kNtlmV2KeyBytes>
    sessionBaseKey() const noexcept { return sessionBaseKey_; }
    [[nodiscard]] std::span<const std::uint8_t, kNtlmV2KeyBytes>
    exportedSessionKey() const noexcept { return exportedSessionKey_; }
    [[nodiscard]] std::span<const std::uint8_t, kNtlmV2KeyBytes>
    clientSigningKey() const noexcept { return clientSigningKey_; }
    [[nodiscard]] std::span<const std::uint8_t, kNtlmV2KeyBytes>
    serverSigningKey() const noexcept { return serverSigningKey_; }
    [[nodiscard]] std::span<const std::uint8_t, kNtlmV2KeyBytes>
    clientSealingKey() const noexcept { return clientSealingKey_; }
    [[nodiscard]] std::span<const std::uint8_t, kNtlmV2KeyBytes>
    serverSealingKey() const noexcept { return serverSealingKey_; }

    void clear() noexcept;

private:
    friend class EphemeralNtlmV2Credential;
    friend struct StandaloneNtlmV2TestAccess;

    void activate(
        const NtlmV2Key &sessionBaseKey,
        const NtlmV2Key &exportedSessionKey,
        const NtlmV2Key &clientSigningKey,
        const NtlmV2Key &serverSigningKey,
        const NtlmV2Key &clientSealingKey,
        const NtlmV2Key &serverSealingKey) noexcept;

    NtlmV2Key sessionBaseKey_{};
    NtlmV2Key exportedSessionKey_{};
    NtlmV2Key clientSigningKey_{};
    NtlmV2Key serverSigningKey_{};
    NtlmV2Key clientSealingKey_{};
    NtlmV2Key serverSealingKey_{};
    bool active_{};
};

// Memory-only first-party standalone NTLMv2 credential prototype.
//
// configure() consumes mutable UTF-16 password storage and scrubs that caller
// buffer before returning on every path. Only the NT hash and bounded username
// remain in this object; revoke()/destruction cleanse both. No plaintext,
// registry/file/keychain persistence, domain account or cloud dependency.
//
// This first increment deliberately supports ASCII usernames only so the
// MS-NLMP Uppercase(User) operation is locale-independent and exact. It accepts
// an empty domain. Full Unicode username case mapping is deferred rather than
// guessed.
//
// It verifies the canonical NTLMv2 response and derives the 128-bit CredSSP
// session/sign/seal keys. It does NOT parse NTLM Type 1/2/3 messages, implement
// SPNEGO, wrap/unwrap pubKeyAuth/authInfo, grant R2 admission or claim mstsc /
// Windows App interoperability.
class EphemeralNtlmV2Credential final
{
public:
    EphemeralNtlmV2Credential() noexcept = default;
    ~EphemeralNtlmV2Credential();

    EphemeralNtlmV2Credential(
        const EphemeralNtlmV2Credential &) = delete;
    EphemeralNtlmV2Credential &operator=(
        const EphemeralNtlmV2Credential &) = delete;
    EphemeralNtlmV2Credential(EphemeralNtlmV2Credential &&) = delete;
    EphemeralNtlmV2Credential &operator=(
        EphemeralNtlmV2Credential &&) = delete;

    [[nodiscard]] bool configure(
        std::u16string_view username,
        std::span<char16_t> password) noexcept;
    void revoke() noexcept;
    [[nodiscard]] bool configured() const noexcept { return configured_; }

    // ResponseKeyNT is password-equivalent derived material; callers must
    // cleanse it after immediate use.
    [[nodiscard]] bool deriveResponseKeyNt(
        std::u16string_view domain,
        NtlmV2Key &output) const noexcept;

    [[nodiscard]] NtlmV2VerifyResult verifyAndDeriveSecurityContext(
        const NtlmV2AuthenticateRequest &request,
        NtlmV2SecurityContext &output) const noexcept;

private:
    friend struct StandaloneNtlmV2TestAccess;

    std::array<char16_t, kMaximumStandaloneNtlmUserCodeUnits + 1U>
        username_{};
    std::size_t usernameLength_{};
    NtlmV2Key ntHash_{};
    bool configured_{};
};

} // namespace rdp_server::server::security
