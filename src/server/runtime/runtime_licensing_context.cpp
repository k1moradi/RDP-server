// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_licensing_context.h"
#include "runtime_credential_file_internal.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>

namespace rdp_server::server::runtime
{
namespace
{
using namespace rdp_server::server::transport;

struct BioCloser
{
    void operator()(BIO* value) const noexcept { ::BIO_free(value); }
};
struct CertificateCloser
{
    void operator()(X509* value) const noexcept { ::X509_free(value); }
};
struct NameCloser
{
    void operator()(X509_NAME* value) const noexcept { ::X509_NAME_free(value); }
};
struct KeyCloser
{
    void operator()(EVP_PKEY* value) const noexcept { ::EVP_PKEY_free(value); }
};
struct ExtensionCloser
{
    void operator()(X509_EXTENSION* value) const noexcept
    {
        ::X509_EXTENSION_free(value);
    }
};

using OwnedBio = std::unique_ptr<BIO, BioCloser>;
using OwnedCertificate = std::unique_ptr<X509, CertificateCloser>;
using OwnedName = std::unique_ptr<X509_NAME, NameCloser>;
using OwnedKey = std::unique_ptr<EVP_PKEY, KeyCloser>;
using OwnedExtension = std::unique_ptr<X509_EXTENSION, ExtensionCloser>;

template <std::size_t N>
consteval std::array<std::uint8_t, N * 2U>
utf16Le(const char (&text)[N]) noexcept
{
    std::array<std::uint8_t, N * 2U> result{};
    for (std::size_t index = 0U; index < N; ++index)
        result[index * 2U] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    return result;
}

template <std::size_t N>
consteval std::array<std::uint8_t, N>
ansi(const char (&text)[N]) noexcept
{
    std::array<std::uint8_t, N> result{};
    for (std::size_t index = 0U; index < N; ++index)
        result[index] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    return result;
}

// ProductInfo is stable application identity. The certificate/key material is
// deliberately fresh per process; changing cryptographic identity must not
// silently change the product/scope presented by MS-RDPELE.
inline constexpr std::uint32_t kApplicationLicensingProductVersion = 0x00010000U;
inline constexpr auto kApplicationLicensingCompany = utf16Le("RDP-server");
inline constexpr auto kApplicationLicensingProduct =
    utf16Le("RDP-server Personal Desktop");
inline constexpr auto kApplicationLicensingScope = ansi("RDP-server");

struct GeneratedLicensingMaterial final
{
    std::array<std::uint8_t, kMaximumRdpServerLicenseCertificateBytes>
        serverCertificate{};
    std::size_t serverCertificateBytes{};
    std::array<std::uint8_t, kMaximumRdpLicensingPrivateKeyPemBytes>
        privateKeyPem{};
    std::size_t privateKeyPemBytes{};

    ~GeneratedLicensingMaterial()
    {
        ::OPENSSL_cleanse(privateKeyPem.data(), privateKeyPem.size());
        privateKeyPemBytes = 0U;
    }
};

[[nodiscard]] bool setRandomSerial(X509* certificate) noexcept
{
    if (certificate == nullptr)
        return false;

    std::uint64_t serial = 0U;
    if (::RAND_bytes(
            reinterpret_cast<unsigned char*>(&serial),
            static_cast<int>(sizeof(serial))) != 1)
        return false;
    serial &= (std::numeric_limits<std::uint64_t>::max)() >> 1U;
    if (serial == 0U)
        serial = 1U;

    ASN1_INTEGER* value = ::ASN1_INTEGER_new();
    if (value == nullptr)
        return false;
    const bool configured =
        ::ASN1_INTEGER_set_uint64(value, serial) == 1 &&
        ::X509_set_serialNumber(certificate, value) == 1;
    ::ASN1_INTEGER_free(value);
    return configured;
}

[[nodiscard]] bool setValidity(X509* certificate) noexcept
{
    if (certificate == nullptr)
        return false;

    constexpr long kClockSkewSeconds = 5L * 60L;
    constexpr long kLifetimeSeconds = 365L * 24L * 60L * 60L;
    ASN1_TIME* notBefore = ::X509_gmtime_adj(nullptr, -kClockSkewSeconds);
    ASN1_TIME* notAfter = ::X509_gmtime_adj(nullptr, kLifetimeSeconds);
    if (notBefore == nullptr || notAfter == nullptr)
    {
        ::ASN1_TIME_free(notBefore);
        ::ASN1_TIME_free(notAfter);
        return false;
    }
    const bool configured =
        ::X509_set1_notBefore(certificate, notBefore) == 1 &&
        ::X509_set1_notAfter(certificate, notAfter) == 1;
    ::ASN1_TIME_free(notBefore);
    ::ASN1_TIME_free(notAfter);
    return configured;
}

[[nodiscard]] OwnedName makeName(const unsigned char* commonName) noexcept
{
    OwnedName name{::X509_NAME_new()};
    if (!name || commonName == nullptr ||
        ::X509_NAME_add_entry_by_NID(
            name.get(), NID_commonName, MBSTRING_ASC,
            commonName, -1, -1, 0) != 1)
        return {};
    return name;
}

[[nodiscard]] bool addExtension(
    X509* certificate, X509* issuer, int nid, const char* value) noexcept
{
    if (certificate == nullptr || issuer == nullptr || value == nullptr)
        return false;

    X509V3_CTX context{};
    ::X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&context);
    OwnedExtension extension{
        ::X509V3_EXT_conf_nid(
            nullptr, &context, nid, const_cast<char*>(value))};
    return extension != nullptr &&
           ::X509_add_ext(certificate, extension.get(), -1) == 1;
}

[[nodiscard]] OwnedCertificate makeRootCertificate(EVP_PKEY* key) noexcept
{
    if (key == nullptr)
        return {};
    OwnedCertificate certificate{::X509_new()};
    constexpr unsigned char kRootName[] = "RDP-server Licensing Root";
    OwnedName name = makeName(kRootName);
    if (!certificate || !name ||
        ::X509_set_version(certificate.get(), 2L) != 1 ||
        !setRandomSerial(certificate.get()) ||
        !setValidity(certificate.get()) ||
        ::X509_set_pubkey(certificate.get(), key) != 1 ||
        ::X509_set_subject_name(certificate.get(), name.get()) != 1 ||
        ::X509_set_issuer_name(certificate.get(), name.get()) != 1 ||
        !addExtension(
            certificate.get(), certificate.get(), NID_basic_constraints,
            "critical,CA:TRUE,pathlen:0") ||
        !addExtension(
            certificate.get(), certificate.get(), NID_key_usage,
            "critical,keyCertSign,cRLSign") ||
        ::X509_sign(certificate.get(), key, ::EVP_sha256()) <= 0 ||
        ::X509_verify(certificate.get(), key) != 1)
        return {};
    return certificate;
}

[[nodiscard]] OwnedCertificate makeLeafCertificate(
    EVP_PKEY* key, X509* root, EVP_PKEY* rootKey) noexcept
{
    if (key == nullptr || root == nullptr || rootKey == nullptr)
        return {};
    OwnedCertificate certificate{::X509_new()};
    constexpr unsigned char kLeafName[] = "RDP-server Licensing";
    OwnedName name = makeName(kLeafName);
    const X509_NAME* issuer = ::X509_get0_subject_name(root);
    if (!certificate || !name || issuer == nullptr ||
        ::X509_set_version(certificate.get(), 2L) != 1 ||
        !setRandomSerial(certificate.get()) ||
        !setValidity(certificate.get()) ||
        ::X509_set_pubkey(certificate.get(), key) != 1 ||
        ::X509_set_subject_name(certificate.get(), name.get()) != 1 ||
        ::X509_set_issuer_name(certificate.get(), issuer) != 1 ||
        !addExtension(
            certificate.get(), root, NID_basic_constraints,
            "critical,CA:FALSE") ||
        !addExtension(
            certificate.get(), root, NID_key_usage,
            "critical,digitalSignature,keyEncipherment") ||
        ::X509_sign(certificate.get(), rootKey, ::EVP_sha256()) <= 0 ||
        ::X509_verify(certificate.get(), rootKey) != 1)
        return {};
    return certificate;
}

void writeLe32(
    std::span<std::uint8_t> output, std::size_t offset,
    std::uint32_t value) noexcept
{
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

[[nodiscard]] bool appendDerCertificate(
    X509* certificate, GeneratedLicensingMaterial& output,
    std::size_t& offset) noexcept
{
    const int encodedBytes =
        certificate == nullptr ? -1 : ::i2d_X509(certificate, nullptr);
    if (encodedBytes <= 0 ||
        static_cast<std::size_t>(encodedBytes) >
            (std::numeric_limits<std::uint32_t>::max)() ||
        offset > output.serverCertificate.size() ||
        output.serverCertificate.size() - offset <
            4U + static_cast<std::size_t>(encodedBytes))
        return false;

    writeLe32(
        output.serverCertificate, offset,
        static_cast<std::uint32_t>(encodedBytes));
    offset += 4U;
    unsigned char* cursor = output.serverCertificate.data() + offset;
    if (::i2d_X509(certificate, &cursor) != encodedBytes)
        return false;
    offset += static_cast<std::size_t>(encodedBytes);
    return true;
}

[[nodiscard]] bool serializeLicensingChain(
    X509* root, X509* leaf, GeneratedLicensingMaterial& output) noexcept
{
    // MS-RDPBCGR SERVER_CERTIFICATE / CERT_CHAIN_VERSION_2: root-first X.509
    // chain, followed by 8 + 4*NumCertBlobs zero padding bytes.
    constexpr std::uint32_t kX509ChainVersion = 0x00000002U;
    constexpr std::uint32_t kCertificateCount = 2U;
    constexpr std::size_t kPaddingBytes =
        8U + 4U * static_cast<std::size_t>(kCertificateCount);

    std::size_t offset = 0U;
    if (output.serverCertificate.size() < 8U)
        return false;
    writeLe32(output.serverCertificate, offset, kX509ChainVersion);
    offset += 4U;
    writeLe32(output.serverCertificate, offset, kCertificateCount);
    offset += 4U;
    if (!appendDerCertificate(root, output, offset) ||
        !appendDerCertificate(leaf, output, offset) ||
        offset > output.serverCertificate.size() ||
        output.serverCertificate.size() - offset < kPaddingBytes)
        return false;
    std::fill_n(
        output.serverCertificate.begin() +
            static_cast<std::ptrdiff_t>(offset),
        kPaddingBytes, std::uint8_t{0});
    offset += kPaddingBytes;
    output.serverCertificateBytes = offset;
    return true;
}

[[nodiscard]] bool serializeLeafPrivateKey(
    EVP_PKEY* key, GeneratedLicensingMaterial& output) noexcept
{
    OwnedBio bio{::BIO_new(::BIO_s_mem())};
    if (!bio || key == nullptr ||
        ::PEM_write_bio_PrivateKey(
            bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        return false;

    BUF_MEM* buffer = nullptr;
    ::BIO_get_mem_ptr(bio.get(), &buffer);
    if (buffer == nullptr || buffer->data == nullptr || buffer->length == 0U ||
        buffer->length > output.privateKeyPem.size())
        return false;

    std::copy_n(
        reinterpret_cast<const std::uint8_t*>(buffer->data),
        buffer->length, output.privateKeyPem.begin());
    output.privateKeyPemBytes = buffer->length;
    ::OPENSSL_cleanse(buffer->data, buffer->length);
    return true;
}

[[nodiscard]] bool generateLicensingMaterial(
    GeneratedLicensingMaterial& output) noexcept
{
    // Licensing is a distinct cryptographic role from R1 endpoint TLS.
    // Provider-backed RSA generation keeps both private keys process-local.
    OwnedKey rootKey{::EVP_PKEY_Q_keygen(
        nullptr, nullptr, "RSA", static_cast<std::size_t>(2048U))};
    OwnedKey leafKey{::EVP_PKEY_Q_keygen(
        nullptr, nullptr, "RSA", static_cast<std::size_t>(2048U))};
    if (!rootKey || !leafKey)
        return false;

    OwnedCertificate root = makeRootCertificate(rootKey.get());
    OwnedCertificate leaf =
        makeLeafCertificate(leafKey.get(), root.get(), rootKey.get());
    if (!root || !leaf ||
        !serializeLicensingChain(root.get(), leaf.get(), output) ||
        !serializeLeafPrivateKey(leafKey.get(), output))
        return false;
    return true;
}
} // namespace

bool RuntimeLicensingContext::configureGeneratedApplicationIdentity() noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;

    GeneratedLicensingMaterial generated{};
    if (!generateLicensingMaterial(generated))
        return false;

    return configureSnapshot(
        kApplicationLicensingProductVersion,
        kApplicationLicensingCompany,
        kApplicationLicensingProduct,
        std::span(generated.serverCertificate)
            .first(generated.serverCertificateBytes),
        kApplicationLicensingScope,
        std::span(generated.privateKeyPem).first(generated.privateKeyPemBytes));
}

bool RuntimeLicensingContext::configure(
    std::uint32_t productVersion,
    std::span<const std::uint8_t> companyNameUtf16,
    std::span<const std::uint8_t> productIdUtf16,
    std::span<const std::uint8_t> serverCertificate,
    std::span<const std::uint8_t> scopeAnsi,
    std::span<const std::uint8_t> privateKeyPem) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;
    return configureSnapshot(
        productVersion, companyNameUtf16, productIdUtf16,
        serverCertificate, scopeAnsi, privateKeyPem);
}

bool RuntimeLicensingContext::configureFromCredentialFiles(
    std::uint32_t productVersion,
    std::span<const std::uint8_t> companyNameUtf16,
    std::span<const std::uint8_t> productIdUtf16,
    std::string_view serverCertificatePath,
    std::span<const std::uint8_t> scopeAnsi,
    std::string_view privateKeyPath) noexcept
{
    using namespace rdp_server::server::transport;

    if (attempted_)
        return false;
    attempted_ = true;

    auto snapshot = detail::loadSecureRuntimeCredentialFilePair(
        serverCertificatePath, privateKeyPath,
        kMaximumRdpServerLicenseCertificateBytes,
        kMaximumRdpLicensingPrivateKeyPemBytes);
    if (!snapshot)
        return false;

    return configureSnapshot(
        productVersion, companyNameUtf16, productIdUtf16,
        snapshot.publicBytes(), scopeAnsi, snapshot.privateKeyBytes());
}

bool RuntimeLicensingContext::configureSnapshot(
    std::uint32_t productVersion,
    std::span<const std::uint8_t> companyNameUtf16,
    std::span<const std::uint8_t> productIdUtf16,
    std::span<const std::uint8_t> serverCertificate,
    std::span<const std::uint8_t> scopeAnsi,
    std::span<const std::uint8_t> privateKeyPem) noexcept
{
    if (!identity_.configure(
            productVersion, companyNameUtf16, productIdUtf16,
            serverCertificate, scopeAnsi))
        return false;

    if (!credential_.configure(identity_, privateKeyPem))
        return false;

    configured_ = true;
    return true;
}

} // namespace rdp_server::server::runtime
