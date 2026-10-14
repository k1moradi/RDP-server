// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_tls_certificate.h"

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>

namespace rdp_server::server::security
{
namespace
{

// A borrowed view of SubjectPublicKey BIT STRING contents. It does NOT
// include AlgorithmIdentifier, DER wrapper, the "unused bits" octet, or PEM.
// The selected certificate is owned by the live SSL connection.
[[nodiscard]] bool selectedServerPublicKey(
    const SSL *connection,
    std::span<const std::uint8_t> &key) noexcept
{
    key = {};
    // SSL_get_certificate() returns the last configured certificate BEFORE
    // selection; do not allow this to accidentally bind to an unselected
    // certificate during ClientHello/SNI negotiation.
    if (connection == nullptr ||
        SSL_is_server(connection) != 1 ||
        SSL_is_init_finished(connection) != 1)
    {
        return false;
    }
    X509 *certificate = SSL_get_certificate(connection);
    if (certificate == nullptr)
    {
        return false;
    }
    const ASN1_BIT_STRING *bits = X509_get0_pubkey_bitstr(certificate);
    if (bits == nullptr)
    {
        return false;
    }
    const int length = ASN1_STRING_length(bits);
    const unsigned char *data = ASN1_STRING_get0_data(bits);
    if (length <= 0 || length > static_cast<int>(kMaximumCredSspPublicKeyBytes) ||
        data == nullptr)
    {
        return false;
    }
    key = {data, static_cast<std::size_t>(length)};
    return true;
}

} // namespace

bool computeCredSspBindingForActiveServerTls(
    const SSL *serverTls,
    CredSspBindingDirection direction,
    std::span<const std::uint8_t> clientNonce,
    CredSspHash &output) noexcept
{
    output.fill(0);
    std::span<const std::uint8_t> publicKey;
    if (!selectedServerPublicKey(serverTls, publicKey))
    {
        return false;
    }
    return computeCredSspBindingHash(direction, clientNonce, publicKey,
                                     output);
}

bool verifyCredSspClientBindingForActiveServerTls(
    const SSL *serverTls,
    std::span<const std::uint8_t> clientNonce,
    std::span<const std::uint8_t> authenticatedUnwrappedHash) noexcept
{
    if (authenticatedUnwrappedHash.size() != kCredSspBindingHashBytes)
    {
        return false;
    }
    CredSspHash expected{};
    if (!computeCredSspBindingForActiveServerTls(
            serverTls, CredSspBindingDirection::ClientToServer,
            clientNonce, expected))
    {
        return false;
    }
    const bool matches = CRYPTO_memcmp(
        expected.data(), authenticatedUnwrappedHash.data(),
        expected.size()) == 0;
    OPENSSL_cleanse(expected.data(), expected.size());
    return matches;
}

} // namespace rdp_server::server::security
