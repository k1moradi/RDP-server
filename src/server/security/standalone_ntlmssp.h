// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "standalone_ntlmv2.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

inline constexpr std::size_t kMaximumStandaloneNtlmMessageBytes = 8192U;
inline constexpr std::size_t kMaximumStandaloneNtlmServerNameCodeUnits = 128U;

// Stable standalone NTLM naming is portable protocol state, not host identity.
// Normal hosting never derives these values from the host name, filesystem,
// locale, local account, or the remote application username. A host may
// deliberately replace them only through the same bounded UTF-16 challenge
// configuration used by every platform.
inline constexpr std::u16string_view kStandaloneNtlmPortableDomainName{u"RDP"};
inline constexpr std::u16string_view kStandaloneNtlmPortableServerName{
    u"RDP-SERVER"};
static_assert(
    kStandaloneNtlmPortableServerName.size() <=
    kMaximumStandaloneNtlmServerNameCodeUnits);

inline constexpr std::uint32_t kNtlmNegotiateUnicode = 0x00000001U;
inline constexpr std::uint32_t kNtlmNegotiateOem = 0x00000002U;
inline constexpr std::uint32_t kNtlmRequestTarget = 0x00000004U;
inline constexpr std::uint32_t kNtlmNegotiateNtlm = 0x00000200U;
inline constexpr std::uint32_t kNtlmNegotiateOemDomainSupplied = 0x00001000U;
inline constexpr std::uint32_t kNtlmNegotiateOemWorkstationSupplied =
    0x00002000U;
inline constexpr std::uint32_t kNtlmNegotiateAlwaysSign = 0x00008000U;
inline constexpr std::uint32_t kNtlmTargetTypeDomain = 0x00010000U;
inline constexpr std::uint32_t kNtlmTargetTypeServer = 0x00020000U;
inline constexpr std::uint32_t kNtlmNegotiateTargetInfo = 0x00800000U;
inline constexpr std::uint32_t kNtlmNegotiateVersion = 0x02000000U;
inline constexpr std::uint32_t kNtlmNegotiate56 = 0x80000000U;

enum class NtlmMessageParseResult : std::uint8_t
{
    Parsed,
    InvalidInput,
    InvalidSignature,
    WrongMessageType,
    InvalidSecurityBuffer,
    UnsupportedFlags,
    InvalidEncoding,
    InvalidNtlmV2Response,
};

// Redacted structural view of one MS-NLMP NEGOTIATE_MESSAGE. Domain and
// workstation payload bytes are deliberately excluded; only their supplied
// bits and byte counts are retained for interoperability diagnostics.
struct NtlmNegotiateMessage final
{
    std::uint32_t negotiateFlags{};
    bool versionPresent{};
    std::uint8_t majorVersion{};
    std::uint8_t minorVersion{};
    std::uint16_t buildNumber{};
    std::uint8_t ntlmRevision{};
    bool domainSupplied{};
    bool workstationSupplied{};
    std::size_t domainFieldBytes{};
    std::size_t workstationFieldBytes{};
};

// Parsed Type 3 fields borrow only opaque response/key/MIC bytes from the
// caller-owned wire message. Unicode identity fields are copied into bounded
// aligned storage so no unaligned reinterpret_cast is needed. This object is
// syntax/provenance only and does not authenticate a user by itself.
struct NtlmAuthenticateMessage final
{
    std::array<char16_t, kMaximumStandaloneNtlmDomainCodeUnits + 1U>
        domainStorage{};
    std::size_t domainLength{};
    std::array<char16_t, kMaximumStandaloneNtlmUserCodeUnits + 1U>
        usernameStorage{};
    std::size_t usernameLength{};
    std::span<const std::uint8_t> ntChallengeResponse{};
    std::span<const std::uint8_t> encryptedRandomSessionKey{};
    std::span<const std::uint8_t> messageIntegrityCode{};
    std::uint32_t negotiateFlags{};

    [[nodiscard]] std::u16string_view domain() const noexcept
    {
        return {domainStorage.data(), domainLength};
    }

    [[nodiscard]] std::u16string_view username() const noexcept
    {
        return {usernameStorage.data(), usernameLength};
    }

    [[nodiscard]] NtlmV2AuthenticateRequest verificationRequest(
        const NtlmServerChallenge &serverChallenge) const noexcept
    {
        return {
            serverChallenge,
            username(),
            domain(),
            ntChallengeResponse,
            negotiateFlags,
            encryptedRandomSessionKey};
    }
};

inline constexpr std::size_t kMaximumStandaloneNtlmChallengeAvPairs = 16U;

// Bounded structural view of one MS-NLMP CHALLENGE_MESSAGE. Challenge bytes,
// NTLM responses, session keys and credentials are deliberately excluded so
// this object is safe to retain for fail-only interoperability diagnostics.
struct NtlmChallengeMessageObservation final
{
    bool valid{};
    std::uint32_t clientNegotiateFlags{};
    std::uint32_t negotiateFlags{};
    std::size_t targetNameCodeUnits{};
    std::size_t targetInfoBytes{};
    std::size_t totalBytes{};
    std::array<std::uint16_t, kMaximumStandaloneNtlmChallengeAvPairs>
        targetInfoAvIds{};
    std::size_t targetInfoAvIdCount{};
    bool targetTypeServer{};
    bool targetNamePresent{};
};

struct NtlmChallengeMessageParameters final
{
    NtlmServerChallenge serverChallenge{};
    std::u16string_view netbiosDomainName{};
    std::u16string_view netbiosComputerName{};
    std::uint64_t timestampFileTime{};
    std::uint32_t clientNegotiateFlags{};
};

enum class NtlmChallengeEncodeStatus : std::uint8_t
{
    Encoded,
    InvalidInput,
    UnsupportedFlags,
    OutputTooSmall,
};

struct NtlmChallengeEncodeResult final
{
    NtlmChallengeEncodeStatus status{NtlmChallengeEncodeStatus::InvalidInput};
    std::size_t bytesWritten{};
    std::uint32_t negotiateFlags{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return status == NtlmChallengeEncodeStatus::Encoded;
    }
};

// MS-NLMP 2.2.1.1 syntax parser. OEM Domain/Workstation payloads are never
// interpreted as credentials; when their supplied flags are set they are only
// range-checked. Policy selection happens when constructing the Type 2 reply.
[[nodiscard]] NtlmMessageParseResult parseNtlmNegotiateMessage(
    std::span<const std::uint8_t> message,
    NtlmNegotiateMessage &output) noexcept;

// Validate one complete Type 2 against MS-NLMP structural invariants and the
// exact Type-1 capability flags that preceded it. Security-buffer MaxLen is
// advisory on receipt; the writer still emits MaxLen == Len.
[[nodiscard]] NtlmMessageParseResult validateNtlmChallengeMessage(
    std::span<const std::uint8_t> message,
    std::uint32_t clientNegotiateFlags,
    NtlmChallengeMessageObservation &output) noexcept;

// Encode one connection-oriented NTLM Type 2 challenge for the standalone
// CredSSP profile. The caller owns cryptographically random ServerChallenge and
// current FILETIME generation. The bounded NetBIOS computer name is also the
// MS-NLMP server TargetName and is emitted explicitly as UTF-16LE together with
// REQUEST_TARGET/TARGET_TYPE_SERVER. TargetInfo carries the same computer name,
// the bounded domain name and timestamp. No locale/host-name lookup occurs here.
// The encoder clears the debugging-only VERSION option and never allocates or
// persists secret material.
[[nodiscard]] NtlmChallengeEncodeResult encodeNtlmChallengeMessage(
    const NtlmChallengeMessageParameters &parameters,
    std::span<std::uint8_t> output) noexcept;

// MS-NLMP 2.2.1.3 bounded Type 3 parser for the standalone NTLMv2 profile.
// It validates every used security-buffer extent, negotiated Unicode string
// encoding, optional MIC placement signaled by MsvAvFlags, LMv2/key lengths,
// and canonical NTLMv2 AV-list framing. It still does not verify proof or MIC;
// feed verificationRequest() to EphemeralNtlmV2Credential and a future
// transcript owner must verify MIC before authenticated CredSSP wrapping.
[[nodiscard]] NtlmMessageParseResult parseNtlmAuthenticateMessage(
    std::span<const std::uint8_t> message,
    NtlmAuthenticateMessage &output) noexcept;

} // namespace rdp_server::server::security
