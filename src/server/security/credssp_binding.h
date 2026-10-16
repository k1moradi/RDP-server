// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{

// MS-CSSP 3.1.5, versions 5 and 6. Each direction MUST use a different
// label (including its terminating NUL), followed by the 32-byte client
// nonce and TLS server certificate SubjectPublicKey BIT STRING contents.
// This computes expected *plaintext* hashes for a FUTURE authenticated
// SPNEGO/GSS_Unwrap result. Never compare raw TSRequest.pubKeyAuth here.
//
// Hash calculation is NOT SPNEGO, TLS authentication, authorization, or a
// credential-verification service, and cannot grant access to MCS.
enum class CredSspBindingDirection : std::uint8_t
{
    ClientToServer,
    ServerToClient,
};

inline constexpr std::size_t kCredSspNonceBytes = 32;
inline constexpr std::size_t kCredSspBindingHashBytes = 32;
inline constexpr std::size_t kMaximumCredSspPublicKeyBytes = 4096;
using CredSspHash = std::array<std::uint8_t, kCredSspBindingHashBytes>;

// Returns false for absent/oversized certificate key bits, incorrect nonce
// length, or OpenSSL failure, always zeroing the output on failure.
[[nodiscard]] bool computeCredSspBindingHash(
    CredSspBindingDirection direction,
    std::span<const std::uint8_t> clientNonce,
    std::span<const std::uint8_t> tlsSubjectPublicKey,
    CredSspHash &output) noexcept;

// Constant-time check of the *already unwrapped and integrity-verified*
// client's Client-To-Server hash against the expected active-TLS key hash.
// The external SPNEGO provider MUST perform authenticated unwrapping BEFORE
// calling this function. A true result is NOT user authentication.
[[nodiscard]] bool verifyCredSspClientBindingHash(
    std::span<const std::uint8_t> clientNonce,
    std::span<const std::uint8_t> tlsSubjectPublicKey,
    std::span<const std::uint8_t> alreadyUnwrappedClientHash) noexcept;

} // namespace rdp_server::server::security
