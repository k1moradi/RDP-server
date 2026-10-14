// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "credssp_binding.h"

#include <openssl/ssl.h>

#include <cstdint>
#include <span>

namespace rdp_server::server::security
{

// Computes the CredSSP v5/6 binding against the *selected local certificate*
// of an already established SERVER-side TLS session, not a caller-supplied
// certificate or a peer certificate. No user identity is inferred.
//
// No ownership of SSL or its certificate is transferred. This function
// refuses clients, pre-handshake connections, missing certificates and
// oversized/malformed SubjectPublicKey BIT STRINGs. No heap allocation.
[[nodiscard]] bool computeCredSspBindingForActiveServerTls(
    const SSL *serverTls,
    CredSspBindingDirection direction,
    std::span<const std::uint8_t> clientNonce,
    CredSspHash &output) noexcept;

// The hash MUST have been authenticated and unwrapped by a separate
// GSSAPI/SSPI provider. Raw TLS or raw TSRequest.pubKeyAuth input MUST NOT
// be passed here. Matching hashes do not authorize an RDP session.
[[nodiscard]] bool verifyCredSspClientBindingForActiveServerTls(
    const SSL *serverTls,
    std::span<const std::uint8_t> clientNonce,
    std::span<const std::uint8_t> authenticatedUnwrappedHash) noexcept;

} // namespace rdp_server::server::security
