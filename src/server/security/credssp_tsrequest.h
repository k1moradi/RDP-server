// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{

// Strict DER framing only (MS-CSSP 2.2.1). This is NOT a CredSSP
// implementation: no SPNEGO, Kerberos, NTLM, TLS binding, user credentials,
// encryption/decryption or authentication is performed by this parser.
inline constexpr std::size_t kMaximumCredSspRequestBytes = 16 * 1024;
inline constexpr std::size_t kMaximumCredSspTokenBytes = 8192;
inline constexpr std::size_t kMaximumCredSspTokens = 4;

enum class TsRequestError : std::uint8_t
{
    None,
    InvalidDer,
    InvalidVersion,
    InvalidFields,
    InvalidTokens,
    InvalidNonce,
};

struct TsRequestInfo
{
    std::uint32_t version{};
    // Views belong ONLY to the caller's incoming TLS-decrypted byte buffer.
    // Never cache these spans beyond a synchronous parse/SSPI handoff.
    std::array<std::span<const std::uint8_t>, kMaximumCredSspTokens> tokens{};
    std::uint8_t tokenCount{};
    bool hasAuthInfo{};
    bool hasPubKeyAuth{};
    bool hasErrorCode{};
    bool hasClientNonce{};
    // Borrowed opaque DER OCTET STRING contents; valid only as long as
    // the original TLS-decrypted TSRequest byte buffer stays alive.
    // In particular, pubKeyAuth is encrypted GSS data, NOT a plaintext hash.
    std::span<const std::uint8_t> encryptedAuthInfo{};
    std::span<const std::uint8_t> encryptedPubKeyAuth{};
    std::span<const std::uint8_t> clientNonce{};

    // Eligible for a FUTURE SPNEGO implementation to inspect, not proof of
    // identity and never permission to issue an MCS Connect-Response.
    [[nodiscard]] bool initialNegoTokenOnly() const noexcept
    {
        return tokenCount != 0 && !hasAuthInfo && !hasPubKeyAuth &&
               !hasErrorCode && !hasClientNonce;
    }
};

struct TsRequestResult
{
    TsRequestInfo value{};
    TsRequestError error{TsRequestError::None};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == TsRequestError::None;
    }
};

// Exactly one minimal, definite-length ASN.1 DER TSRequest.
// Reject unknown/duplicate/out-of-order fields and nonminimal encodings.
// On failure returns no token views or client-controlled metadata.
[[nodiscard]] TsRequestResult parseCredSspTsRequest(
    std::span<const std::uint8_t> der) noexcept;

} // namespace rdp_server::server::security
