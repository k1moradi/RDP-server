// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_tls_certificate.h"

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] X509 *selectedServerCertificate(
    const SSL *connection) noexcept
{
    // Never fingerprint a merely configured, not-yet-negotiated key.
    // Do not accept legacy SSL/TLS or a connection with no active cipher.
    if (connection == nullptr ||
        SSL_is_server(connection) != 1 ||
        SSL_is_init_finished(connection) != 1 ||
        SSL_version(connection) < TLS1_2_VERSION ||
        SSL_get_current_cipher(connection) == nullptr)
    {
        return nullptr;
    }
    return SSL_get_certificate(connection);
}

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
    X509 *certificate = selectedServerCertificate(connection);
    if (certificate == nullptr)
    {
        return false;
    }
    const ASN1_BIT_STRING *bits = X509_get0_pubkey_bitstr(certificate);
    if (bits == nullptr)
    {
        return false;
    }
#if !defined(LIBRESSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x40100000L
    const std::size_t length = ASN1_STRING_get_length(bits);
    const unsigned char *data = ASN1_STRING_get0_data(bits);
    if (length == 0U || length > kMaximumCredSspPublicKeyBytes ||
        data == nullptr)
    {
        return false;
    }
    key = {data, length};
#else
    const int length = ASN1_STRING_length(bits);
    const unsigned char *data = ASN1_STRING_get0_data(bits);
    if (length <= 0 ||
        length > static_cast<int>(kMaximumCredSspPublicKeyBytes) ||
        data == nullptr)
    {
        return false;
    }
    key = {data, static_cast<std::size_t>(length)};
#endif
    return true;
}

} // namespace

bool fingerprintActiveCredSspServerTlsCertificate(
    const SSL *serverTls,
    CredSspTlsCertificateFingerprint &output) noexcept
{
    output.fill(0);
    X509 *certificate = selectedServerCertificate(serverTls);
    if (certificate == nullptr)
        return false;

    unsigned int actualBytes = 0;
    // X509_digest fingerprints the actual selected DER certificate, not
    // the mutable SSL_CTX default or a caller-provided client certificate.
    if (X509_digest(certificate, EVP_sha256(), output.data(),
                    &actualBytes) != 1 ||
        actualBytes != output.size())
    {
        OPENSSL_cleanse(output.data(), output.size());
        return false;
    }
    return true;
}

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
