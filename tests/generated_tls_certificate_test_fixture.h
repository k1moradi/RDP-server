// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_tls_context.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace rdp_server::tests
{
namespace detail
{
struct PrivateKeyDeleter final
{
    void operator()(EVP_PKEY *value) const noexcept
    {
        EVP_PKEY_free(value);
    }
};

struct CertificateDeleter final
{
    void operator()(X509 *value) const noexcept
    {
        X509_free(value);
    }
};

struct X509NameDeleter final
{
    void operator()(X509_NAME *value) const noexcept
    {
        X509_NAME_free(value);
    }
};

struct ExtensionDeleter final
{
    void operator()(X509_EXTENSION *value) const noexcept
    {
        X509_EXTENSION_free(value);
    }
};

using OwnedPrivateKey = std::unique_ptr<EVP_PKEY, PrivateKeyDeleter>;
using OwnedCertificate = std::unique_ptr<X509, CertificateDeleter>;
using OwnedX509Name = std::unique_ptr<X509_NAME, X509NameDeleter>;
using OwnedExtension = std::unique_ptr<X509_EXTENSION, ExtensionDeleter>;

[[nodiscard]] inline bool addStaticExtension(
    X509 *certificate,
    int extensionNid,
    const char *value) noexcept
{
    if (certificate == nullptr || value == nullptr)
        return false;

    X509V3_CTX extensionContext{};
    X509V3_set_ctx(
        &extensionContext, certificate, certificate, nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&extensionContext);
    OwnedExtension extension{
        X509V3_EXT_conf_nid(
            nullptr,
            &extensionContext,
            extensionNid,
            const_cast<char *>(value))};
    return extension != nullptr &&
           X509_add_ext(certificate, extension.get(), -1) == 1;
}

[[nodiscard]] inline std::vector<unsigned char> certificateDer(
    const X509 *certificate)
{
    if (certificate == nullptr)
        return {};

    const int encodedBytes = i2d_X509(certificate, nullptr);
    if (encodedBytes <= 0)
        return {};

    std::vector<unsigned char> result(
        static_cast<std::size_t>(encodedBytes));
    unsigned char *output = result.data();
    if (i2d_X509(certificate, &output) != encodedBytes ||
        output != result.data() + result.size())
    {
        return {};
    }
    return result;
}
} // namespace detail

// Returns the exact production-generated leaf profile for the selected endpoint.
// The test borrows only the public certificate; the production TLS owner keeps
// the generated private key and destroys it with the temporary context.
[[nodiscard]] inline std::vector<unsigned char>
productionGeneratedCertificateDer(std::string_view endpoint)
{
    auto tlsContext =
        server::runtime::RuntimeServerTlsContext::fromGeneratedIpAddress(
            endpoint);
    if (!tlsContext)
        return {};
    return detail::certificateDer(tlsContext.certificate());
}

// Test-only comparison profile: identical RSA/signature/validity/EKU/key-usage
// intent and IP SAN, but the Common Name is the endpoint text. This helper is
// never linked into production and is not a production certificate selector.
[[nodiscard]] inline std::vector<unsigned char>
endpointCommonNameCertificateDer(std::string_view endpoint)
{
    if (endpoint.empty() ||
        endpoint.size() >
            static_cast<std::size_t>((std::numeric_limits<int>::max)()))
    {
        return {};
    }

    detail::OwnedPrivateKey privateKey{
        EVP_PKEY_Q_keygen(
            nullptr, nullptr, "RSA", static_cast<std::size_t>(2048U))};
    detail::OwnedCertificate certificate{X509_new()};
    if (!privateKey || !certificate ||
        X509_set_version(certificate.get(), 2L) != 1)
    {
        return {};
    }

    std::uint64_t serial = 0U;
    if (RAND_bytes(
            reinterpret_cast<unsigned char *>(&serial),
            static_cast<int>(sizeof(serial))) != 1)
    {
        return {};
    }
    serial &= (std::numeric_limits<std::uint64_t>::max)() >> 1U;
    if (serial == 0U)
        serial = 1U;

    constexpr long kClockSkewSeconds = 5L * 60L;
    constexpr long kLifetimeSeconds = 365L * 24L * 60L * 60L;
    if (ASN1_INTEGER_set_uint64(
            X509_get_serialNumber(certificate.get()), serial) != 1 ||
        X509_gmtime_adj(
            X509_getm_notBefore(certificate.get()),
            -kClockSkewSeconds) == nullptr ||
        X509_gmtime_adj(
            X509_getm_notAfter(certificate.get()),
            kLifetimeSeconds) == nullptr ||
        X509_set_pubkey(certificate.get(), privateKey.get()) != 1)
    {
        return {};
    }

    detail::OwnedX509Name subject{X509_NAME_new()};
    if (!subject ||
        X509_NAME_add_entry_by_NID(
            subject.get(),
            NID_commonName,
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(endpoint.data()),
            static_cast<int>(endpoint.size()),
            -1,
            0) != 1 ||
        X509_set_subject_name(certificate.get(), subject.get()) != 1 ||
        X509_set_issuer_name(certificate.get(), subject.get()) != 1)
    {
        return {};
    }

    std::string subjectAlternativeName{"IP:"};
    subjectAlternativeName.append(endpoint);
    if (!detail::addStaticExtension(
            certificate.get(),
            NID_basic_constraints,
            "critical,CA:FALSE") ||
        !detail::addStaticExtension(
            certificate.get(),
            NID_key_usage,
            "critical,digitalSignature,keyEncipherment") ||
        !detail::addStaticExtension(
            certificate.get(),
            NID_ext_key_usage,
            "serverAuth") ||
        !detail::addStaticExtension(
            certificate.get(),
            NID_subject_alt_name,
            subjectAlternativeName.c_str()) ||
        X509_sign(
            certificate.get(), privateKey.get(), EVP_sha256()) <= 0 ||
        X509_verify(certificate.get(), privateKey.get()) != 1)
    {
        return {};
    }

    return detail::certificateDer(certificate.get());
}

} // namespace rdp_server::tests
