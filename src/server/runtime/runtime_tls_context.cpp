// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_tls_context.h"
#include "runtime_credential_file_internal.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <new>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace rdp_server::server::runtime
{
namespace
{

constexpr std::size_t kMaximumCertificateBytes = 1024U * 1024U;
constexpr std::size_t kMaximumPrivateKeyBytes = 256U * 1024U;
constexpr std::string_view kCertificateBeginMarker =
    "-----BEGIN CERTIFICATE-----";

struct BioCloser
{
    void operator()(BIO *bio) const noexcept { ::BIO_free(bio); }
};
struct X509Closer
{
    void operator()(X509 *certificate) const noexcept { ::X509_free(certificate); }
};
struct PkeyCloser
{
    void operator()(EVP_PKEY *key) const noexcept { ::EVP_PKEY_free(key); }
};

using OwnedBio = std::unique_ptr<BIO, BioCloser>;
using OwnedCertificate = std::unique_ptr<X509, X509Closer>;
using OwnedPrivateKey = std::unique_ptr<EVP_PKEY, PkeyCloser>;

struct ValidatedTlsCredentials
{
    OwnedCertificate certificate{};
    OwnedPrivateKey privateKey{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return certificate != nullptr && privateKey != nullptr;
    }
};

int rejectPrivateKeyPassword(char *, int, int, void *) noexcept
{
    return 0;
}

[[nodiscard]] bool isPemWhitespace(unsigned char value) noexcept
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

[[nodiscard]] bool beginsWithExpectedPemObject(
    const unsigned char *data, std::size_t bytes,
    std::string_view expectedMarker) noexcept
{
    if (data == nullptr || bytes < expectedMarker.size()) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < bytes && isPemWhitespace(data[offset])) {
        ++offset;
    }
    if (bytes - offset < expectedMarker.size()) {
        return false;
    }
    return std::equal(expectedMarker.begin(), expectedMarker.end(),
                      reinterpret_cast<const char *>(data + offset));
}

[[nodiscard]] bool bioRemainderIsWhitespace(BIO *bio) noexcept
{
    if (bio == nullptr) {
        return false;
    }
    std::array<unsigned char, 256> buffer{};
    while (true) {
        std::size_t bytesRead = 0;
        const int result =
            ::BIO_read_ex(bio, buffer.data(), buffer.size(), &bytesRead);
        for (std::size_t index = 0; index < bytesRead; ++index) {
            if (!isPemWhitespace(buffer[index])) {
                return false;
            }
        }
        if (result != 1) {
            return bytesRead == 0 && !::BIO_should_retry(bio);
        }
        if (bytesRead == 0) {
            return true;
        }
    }
}

[[nodiscard]] bool hasCurrentCertificateValidity(
    const X509 *certificate) noexcept
{
    if (certificate == nullptr) {
        return false;
    }
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    return ::X509_check_certificate_times(nullptr, certificate, nullptr) == 1;
#else
    const int notBeforeComparison =
        ::X509_cmp_current_time(::X509_get0_notBefore(certificate));
    const int notAfterComparison =
        ::X509_cmp_current_time(::X509_get0_notAfter(certificate));
    return notBeforeComparison == -1 && notAfterComparison == 1;
#endif
}

[[nodiscard]] ValidatedTlsCredentials loadValidatedTlsCredentials(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    auto snapshot = detail::loadSecureRuntimeCredentialFilePair(
        certificatePath, privateKeyPath,
        kMaximumCertificateBytes, kMaximumPrivateKeyBytes);
    if (!snapshot)
        return {};

    const auto certificateData = snapshot.publicBytes();
    const auto privateKeyData = snapshot.privateKeyBytes();
    if (!beginsWithExpectedPemObject(
            certificateData.data(), certificateData.size(),
            kCertificateBeginMarker) ||
        !beginsWithExpectedPemObject(
            privateKeyData.data(), privateKeyData.size(), "-----BEGIN "))
        return {};

    OwnedBio certificateBio{::BIO_new_mem_buf(
        certificateData.data(), static_cast<int>(certificateData.size()))};
    OwnedBio privateKeyBio{::BIO_new_mem_buf(
        privateKeyData.data(), static_cast<int>(privateKeyData.size()))};
    if (!certificateBio || !privateKeyBio) {
        return {};
    }

    OwnedCertificate certificate{
        ::PEM_read_bio_X509(certificateBio.get(), nullptr, nullptr, nullptr)};
    OwnedPrivateKey privateKey{::PEM_read_bio_PrivateKey(
        privateKeyBio.get(), nullptr, rejectPrivateKeyPassword, nullptr)};
    if (!certificate || !privateKey ||
        !bioRemainderIsWhitespace(certificateBio.get()) ||
        !bioRemainderIsWhitespace(privateKeyBio.get()) ||
        !hasCurrentCertificateValidity(certificate.get()) ||
        ::X509_check_private_key(certificate.get(), privateKey.get()) != 1 ||
        ::X509_check_purpose(
            certificate.get(), X509_PURPOSE_SSL_SERVER, 0) != 1) {
        return {};
    }

    return {std::move(certificate), std::move(privateKey)};
}

} // namespace

bool validateTlsFileReferences(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    return detail::validateSecureRuntimeCredentialFilePairReferences(
        certificatePath, privateKeyPath,
        kMaximumCertificateBytes, kMaximumPrivateKeyBytes);
}

bool validateTlsCredentialContents(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    return static_cast<bool>(
        loadValidatedTlsCredentials(certificatePath, privateKeyPath));
}

RuntimeServerTlsContext RuntimeServerTlsContext::fromCredentialFiles(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    ValidatedTlsCredentials credentials =
        loadValidatedTlsCredentials(certificatePath, privateKeyPath);
    if (!credentials) {
        return {};
    }

    OwnedContext context{::SSL_CTX_new(::TLS_server_method()), &::SSL_CTX_free};
    if (!context ||
        ::SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) != 1) {
        return {};
    }

    std::uint64_t requiredOptions = SSL_OP_NO_COMPRESSION;
#if defined(SSL_OP_NO_RENEGOTIATION)
    requiredOptions |= SSL_OP_NO_RENEGOTIATION;
#endif
    const std::uint64_t configuredOptions =
        ::SSL_CTX_set_options(context.get(), requiredOptions);
    if ((configuredOptions & requiredOptions) != requiredOptions ||
        ::SSL_CTX_use_certificate(
            context.get(), credentials.certificate.get()) != 1 ||
        ::SSL_CTX_use_PrivateKey(
            context.get(), credentials.privateKey.get()) != 1 ||
        ::SSL_CTX_check_private_key(context.get()) != 1) {
        return {};
    }

    return RuntimeServerTlsContext{std::move(context)};
}

RuntimeServerTlsContext::ServerTls
RuntimeServerTlsContext::createServerTls() const noexcept
{
    ServerTls serverTls{context_ ? ::SSL_new(context_.get()) : nullptr,
                        &::SSL_free};
    if (serverTls) {
        ::SSL_set_accept_state(serverTls.get());
    }
    return serverTls;
}

int RuntimeServerTlsContext::minimumProtocolVersion() const noexcept
{
    return context_ ? ::SSL_CTX_get_min_proto_version(context_.get()) : 0;
}

std::uint64_t RuntimeServerTlsContext::options() const noexcept
{
    return context_ ? ::SSL_CTX_get_options(context_.get()) : 0U;
}

const X509 *RuntimeServerTlsContext::certificate() const noexcept
{
    return context_ ? ::SSL_CTX_get0_certificate(context_.get()) : nullptr;
}

} // namespace rdp_server::server::runtime
