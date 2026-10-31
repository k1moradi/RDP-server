// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_tls_context.h"
#include "server/transport/lan_listener.h"
#include "runtime_credential_file_internal.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

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
struct X509NameCloser
{
    void operator()(X509_NAME *name) const noexcept { ::X509_NAME_free(name); }
};
struct PkeyCloser
{
    void operator()(EVP_PKEY *key) const noexcept { ::EVP_PKEY_free(key); }
};
struct X509ExtensionCloser
{
    void operator()(X509_EXTENSION *extension) const noexcept
    {
        ::X509_EXTENSION_free(extension);
    }
};
struct GeneralNamesCloser
{
    void operator()(GENERAL_NAMES *names) const noexcept
    {
        ::GENERAL_NAMES_free(names);
    }
};

using OwnedBio = std::unique_ptr<BIO, BioCloser>;
using OwnedCertificate = std::unique_ptr<X509, X509Closer>;
using OwnedX509Name = std::unique_ptr<X509_NAME, X509NameCloser>;
using OwnedPrivateKey = std::unique_ptr<EVP_PKEY, PkeyCloser>;
using OwnedX509Extension = std::unique_ptr<X509_EXTENSION, X509ExtensionCloser>;
using OwnedGeneralNames = std::unique_ptr<GENERAL_NAMES, GeneralNamesCloser>;
using OwnedSslContext = std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)>;

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

[[nodiscard]] bool validateTlsCredentialPair(
    const X509 *certificate, const EVP_PKEY *privateKey) noexcept
{
    return certificate != nullptr && privateKey != nullptr &&
           hasCurrentCertificateValidity(certificate) &&
           ::X509_check_private_key(certificate, privateKey) == 1 &&
           ::X509_check_purpose(
               const_cast<X509 *>(certificate),
               X509_PURPOSE_SSL_SERVER, 0) == 1;
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
        !validateTlsCredentialPair(certificate.get(), privateKey.get())) {
        return {};
    }

    return {std::move(certificate), std::move(privateKey)};
}

struct ParsedNumericIpAddress
{
    std::array<unsigned char, 16> bytes{};
    std::size_t size{};
};

[[nodiscard]] std::optional<ParsedNumericIpAddress> parseNumericIpAddress(
    std::string_view numericIpAddress) noexcept
{
    if (numericIpAddress.empty() ||
        numericIpAddress.size() >= INET6_ADDRSTRLEN ||
        numericIpAddress.find('\0') != std::string_view::npos)
        return std::nullopt;

    std::array<char, INET6_ADDRSTRLEN> text{};
    std::memcpy(text.data(), numericIpAddress.data(), numericIpAddress.size());

    ParsedNumericIpAddress parsed;
    if (::inet_pton(AF_INET, text.data(), parsed.bytes.data()) == 1)
    {
        parsed.size = 4U;
        return parsed;
    }
    if (::inet_pton(AF_INET6, text.data(), parsed.bytes.data()) == 1)
    {
        parsed.size = 16U;
        return parsed;
    }
    return std::nullopt;
}

#if OPENSSL_VERSION_NUMBER >= 0x40100000L && !defined(LIBRESSL_VERSION_NUMBER)
// OpenSSL 4.1 deprecates X509_check_ip_asc/X509_check_host in favor of
// X509_verify_cert. This check is deliberately SAN coverage only: running
// certificate-chain verification here would change its security contract.
[[nodiscard]] char lowercaseAscii(char character) noexcept
{
    return character >= 'A' && character <= 'Z'
        ? static_cast<char>(character + ('a' - 'A'))
        : character;
}

[[nodiscard]] bool equalAsciiIgnoreCase(
    std::string_view left, std::string_view right) noexcept
{
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin(),
                      [](char first, char second) noexcept {
                          return lowercaseAscii(first) == lowercaseAscii(second);
                      });
}

[[nodiscard]] bool dnsSanMatchesEndpoint(
    std::string_view subjectAlternativeName,
    std::string_view endpoint) noexcept
{
    // An embedded NUL in a certificate name must never shorten a match.
    if (subjectAlternativeName.find('\0') != std::string_view::npos)
        return false;
    if (equalAsciiIgnoreCase(subjectAlternativeName, endpoint))
        return true;

    // Match the existing NO_PARTIAL_WILDCARDS policy: only a complete
    // leftmost '*' label, exactly one endpoint label, no multi-label match.
    if (subjectAlternativeName.size() < 3U ||
        subjectAlternativeName.substr(0U, 2U) != "*." ||
        subjectAlternativeName.find('*', 1U) != std::string_view::npos)
        return false;
    const std::size_t firstDot = endpoint.find('.');
    return firstDot != std::string_view::npos && firstDot > 0U &&
           equalAsciiIgnoreCase(endpoint.substr(firstDot + 1U),
                                subjectAlternativeName.substr(2U));
}

[[nodiscard]] RuntimeTlsEndpointIdentityStatus matchCertificateSubjectAltName(
    const X509 *certificate, std::string_view endpoint) noexcept
{
    // inet_pton distinguishes genuine numeric literals from DNS references;
    // malformed IP-looking strings still follow the former DNS-mismatch path.
    const auto numericAddress = parseNumericIpAddress(endpoint);
    OwnedGeneralNames names{static_cast<GENERAL_NAMES *>(
        ::X509_get_ext_d2i(const_cast<X509 *>(certificate),
                           NID_subject_alt_name, nullptr, nullptr))};
    if (!names)
        return RuntimeTlsEndpointIdentityStatus::Mismatch;

    const int nameCount = sk_GENERAL_NAME_num(names.get());
    for (int index = 0; index < nameCount; ++index)
    {
        const GENERAL_NAME *const name =
            sk_GENERAL_NAME_value(names.get(), index);
        if (name == nullptr)
            continue;

        if (numericAddress)
        {
            if (name->type != GEN_IPADD || name->d.iPAddress == nullptr)
                continue;
            const ASN1_OCTET_STRING *const ipAddress = name->d.iPAddress;
            const std::size_t nameBytes = ::ASN1_STRING_get_length(ipAddress);
            const unsigned char *const nameData =
                ::ASN1_STRING_get0_data(ipAddress);
            if (nameData == nullptr || nameBytes != numericAddress->size)
                continue;
            const std::span<const unsigned char> certificateIp{nameData, nameBytes};
            if (std::equal(certificateIp.begin(), certificateIp.end(),
                           numericAddress->bytes.begin()))
                return RuntimeTlsEndpointIdentityStatus::Match;
        }
        else
        {
            if (name->type != GEN_DNS || name->d.dNSName == nullptr)
                continue;
            const ASN1_IA5STRING *const dnsName = name->d.dNSName;
            const std::size_t nameBytes = ::ASN1_STRING_get_length(dnsName);
            const unsigned char *const nameData =
                ::ASN1_STRING_get0_data(dnsName);
            if (nameData == nullptr || nameBytes == 0U || nameBytes > 253U)
                continue;
            const std::string_view certificateDnsName{
                reinterpret_cast<const char *>(nameData), nameBytes};
            if (dnsSanMatchesEndpoint(certificateDnsName, endpoint))
                return RuntimeTlsEndpointIdentityStatus::Match;
        }
    }
    return RuntimeTlsEndpointIdentityStatus::Mismatch;
}
#endif

[[nodiscard]] bool addStaticCertificateExtension(
    X509 *certificate, int extensionNid, const char *value) noexcept
{
    if (certificate == nullptr || value == nullptr)
        return false;

    X509V3_CTX extensionContext{};
    ::X509V3_set_ctx(
        &extensionContext, certificate, certificate, nullptr, nullptr, 0);
    X509V3_set_ctx_nodb(&extensionContext);
    OwnedX509Extension extension{
        ::X509V3_EXT_conf_nid(
            nullptr, &extensionContext, extensionNid,
            const_cast<char *>(value))};
    return extension != nullptr &&
           ::X509_add_ext(certificate, extension.get(), -1) == 1;
}

[[nodiscard]] bool addIpSubjectAlternativeName(
    X509 *certificate, const ParsedNumericIpAddress& address) noexcept
{
    if (certificate == nullptr ||
        (address.size != 4U && address.size != 16U))
        return false;

    OwnedGeneralNames names{::GENERAL_NAMES_new()};
    if (!names)
        return false;

    GENERAL_NAME *const name = ::GENERAL_NAME_new();
    ASN1_OCTET_STRING *const ipAddress = ::ASN1_OCTET_STRING_new();
    if (name == nullptr || ipAddress == nullptr)
    {
        ::GENERAL_NAME_free(name);
        ::ASN1_OCTET_STRING_free(ipAddress);
        return false;
    }
    if (::ASN1_OCTET_STRING_set(
            ipAddress, address.bytes.data(),
            static_cast<int>(address.size)) != 1)
    {
        ::GENERAL_NAME_free(name);
        ::ASN1_OCTET_STRING_free(ipAddress);
        return false;
    }

    // GENERAL_NAME owns ipAddress after set0; GENERAL_NAMES owns name after
    // the successful push. The exact numeric endpoint is the only SAN.
    ::GENERAL_NAME_set0_value(name, GEN_IPADD, ipAddress);
    if (sk_GENERAL_NAME_push(names.get(), name) == 0)
    {
        ::GENERAL_NAME_free(name);
        return false;
    }
    return ::X509_add1_ext_i2d(
               certificate, NID_subject_alt_name, names.get(), 0,
               X509V3_ADD_DEFAULT) == 1;
}

[[nodiscard]] ValidatedTlsCredentials generateTlsCredentials(
    const ParsedNumericIpAddress& address) noexcept
{
    // RSA-2048 remains broadly interoperable with Microsoft RDP TLS clients.
    // EVP_PKEY_Q_keygen uses OpenSSL's provider-backed CSPRNG; no key bytes
    // cross an application string, file, environment variable or log.
    OwnedPrivateKey privateKey{
        ::EVP_PKEY_Q_keygen(
            nullptr, nullptr, "RSA", static_cast<std::size_t>(2048U))};
    OwnedCertificate certificate{::X509_new()};
    if (!privateKey || !certificate)
        return {};

    if (::X509_set_version(certificate.get(), 2L) != 1)
        return {};

    std::uint64_t serial = 0U;
    if (::RAND_bytes(
            reinterpret_cast<unsigned char *>(&serial),
            static_cast<int>(sizeof(serial))) != 1)
        return {};
    serial &= (std::numeric_limits<std::uint64_t>::max)() >> 1U;
    if (serial == 0U)
        serial = 1U;
    if (::ASN1_INTEGER_set_uint64(
            ::X509_get_serialNumber(certificate.get()), serial) != 1)
        return {};

    constexpr long kClockSkewSeconds = 5L * 60L;
    constexpr long kLifetimeSeconds = 365L * 24L * 60L * 60L;
    if (::X509_gmtime_adj(
            ::X509_getm_notBefore(certificate.get()),
            -kClockSkewSeconds) == nullptr ||
        ::X509_gmtime_adj(
            ::X509_getm_notAfter(certificate.get()),
            kLifetimeSeconds) == nullptr ||
        ::X509_set_pubkey(certificate.get(), privateKey.get()) != 1)
        return {};

    // Build the mutable subject independently. OpenSSL 4 exposes certificate
    // subject accessors as const; generated-certificate construction must not
    // depend on mutating an X509-owned name through a legacy accessor.
    OwnedX509Name subject{::X509_NAME_new()};
    constexpr unsigned char kCommonName[] = "RDP Server";
    if (!subject ||
        ::X509_NAME_add_entry_by_NID(
            subject.get(), NID_commonName, MBSTRING_ASC,
            kCommonName, -1, -1, 0) != 1 ||
        ::X509_set_subject_name(certificate.get(), subject.get()) != 1 ||
        ::X509_set_issuer_name(certificate.get(), subject.get()) != 1)
        return {};

    if (!addStaticCertificateExtension(
            certificate.get(), NID_basic_constraints,
            "critical,CA:FALSE") ||
        !addStaticCertificateExtension(
            certificate.get(), NID_key_usage,
            "critical,digitalSignature,keyEncipherment") ||
        !addStaticCertificateExtension(
            certificate.get(), NID_ext_key_usage, "serverAuth") ||
        !addIpSubjectAlternativeName(certificate.get(), address))
        return {};

    if (::X509_sign(
            certificate.get(), privateKey.get(), ::EVP_sha256()) <= 0 ||
        ::X509_verify(certificate.get(), privateKey.get()) != 1 ||
        !validateTlsCredentialPair(certificate.get(), privateKey.get()))
        return {};

    return {std::move(certificate), std::move(privateKey)};
}

[[nodiscard]] OwnedSslContext createConfiguredServerTlsContext(
    const ValidatedTlsCredentials& credentials) noexcept
{
    OwnedSslContext context{
        ::SSL_CTX_new(::TLS_server_method()), &::SSL_CTX_free};
    if (!context ||
        ::SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) != 1)
        return {nullptr, &::SSL_CTX_free};

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
        ::SSL_CTX_check_private_key(context.get()) != 1)
        return {nullptr, &::SSL_CTX_free};

    return context;
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
    if (!credentials)
        return {};

    OwnedSslContext context = createConfiguredServerTlsContext(credentials);
    if (!context)
        return {};
    return RuntimeServerTlsContext{std::move(context)};
}

RuntimeServerTlsContext RuntimeServerTlsContext::fromGeneratedIpAddress(
    std::string_view numericIpAddress) noexcept
{
    const auto parsedAddress = parseNumericIpAddress(numericIpAddress);
    if (!parsedAddress)
        return {};

    ValidatedTlsCredentials credentials =
        generateTlsCredentials(*parsedAddress);
    if (!credentials)
        return {};

    OwnedSslContext context = createConfiguredServerTlsContext(credentials);
    if (!context)
        return {};

    RuntimeServerTlsContext result{std::move(context)};
    if (result.validateEndpointIdentity(numericIpAddress) !=
        RuntimeTlsEndpointIdentityStatus::Match)
        return {};
    return result;
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

RuntimeTlsEndpointIdentityStatus
RuntimeServerTlsContext::validateEndpointIdentity(
    std::string_view endpoint) const noexcept
{
    const X509 *const selectedCertificate = certificate();
    if (selectedCertificate == nullptr)
        return RuntimeTlsEndpointIdentityStatus::CertificateUnavailable;

    // RFC DNS names are bounded to 253 visible octets. This also leaves room
    // for every textual IPv6 literal and one terminating NUL on the stack.
    if (endpoint.empty() || endpoint.size() > 253U ||
        endpoint.find('\0') != std::string_view::npos)
        return RuntimeTlsEndpointIdentityStatus::InvalidEndpoint;

#if OPENSSL_VERSION_NUMBER >= 0x40100000L && !defined(LIBRESSL_VERSION_NUMBER)
    return matchCertificateSubjectAltName(selectedCertificate, endpoint);
#else
    std::array<char, 254> endpointText{};
    std::memcpy(endpointText.data(), endpoint.data(), endpoint.size());

    // OpenSSL returns -2 when the text is not a syntactically valid IP
    // literal. A syntactically valid IP MUST match an iPAddress SAN and must
    // never fall back to DNS/CN matching.
    const int ipMatch =
        ::X509_check_ip_asc(const_cast<X509 *>(selectedCertificate), endpointText.data(), 0U);
    if (ipMatch == 1)
        return RuntimeTlsEndpointIdentityStatus::Match;
    if (ipMatch == 0)
        return RuntimeTlsEndpointIdentityStatus::Mismatch;
    if (ipMatch != -2)
        return RuntimeTlsEndpointIdentityStatus::InvalidEndpoint;

    constexpr unsigned int hostFlags =
        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS |
        X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;
    const int hostMatch = ::X509_check_host(
        const_cast<X509 *>(selectedCertificate), endpoint.data(), endpoint.size(),
        hostFlags, nullptr);
    if (hostMatch == 1)
        return RuntimeTlsEndpointIdentityStatus::Match;
    if (hostMatch == 0)
        return RuntimeTlsEndpointIdentityStatus::Mismatch;
    return RuntimeTlsEndpointIdentityStatus::InvalidEndpoint;
#endif
}

bool RuntimeServerTlsContext::certificateSha256Fingerprint(
    RuntimeTlsCertificateFingerprint &output) const noexcept
{
    output.fill(0U);
    const X509 *const selectedCertificate = certificate();
    if (selectedCertificate == nullptr)
        return false;

    unsigned int actualBytes = 0U;
    if (::X509_digest(selectedCertificate, ::EVP_sha256(), output.data(),
                      &actualBytes) != 1 ||
        actualBytes != output.size())
    {
        OPENSSL_cleanse(output.data(), output.size());
        return false;
    }
    return true;
}

RuntimeTlsIdentityStatus RuntimeServerTlsContext::identityStatus() const noexcept
{
    RuntimeTlsIdentityStatus snapshot{};
    if (!certificateSha256Fingerprint(snapshot.certificateSha256))
        return snapshot;
    snapshot.fingerprintAvailable = true;
    snapshot.state = RuntimeTlsIdentityState::ConfiguredUnbound;
    return snapshot;
}

RuntimeTlsIdentityStatus RuntimeServerTlsContext::boundIdentityStatus(
    const rdp_server::server::transport::OwnedLanListener &listener)
    const noexcept
{
    RuntimeTlsIdentityStatus snapshot = identityStatus();
    if (!snapshot.fingerprintAvailable || !listener.valid())
        return snapshot;

    snapshot.endpointGeneration = listener.generation();
    if (snapshot.endpointGeneration == 0U)
    {
        snapshot.state = RuntimeTlsIdentityState::InvalidEndpoint;
        return snapshot;
    }
    if (!listener.interfaceStillMatches())
    {
        snapshot.state = RuntimeTlsIdentityState::InterfaceUnavailable;
        return snapshot;
    }

    // This endpoint was constructed only after R1 verified getsockname()
    // against its selected native interface, numeric address, and port.
    const auto endpoint = listener.boundEndpoint();
    if (endpoint.port == 0U || !endpoint.valid())
    {
        snapshot.state = RuntimeTlsIdentityState::InvalidEndpoint;
        return snapshot;
    }

    int addressFamily = 0;
    switch (endpoint.family)
    {
    case rdp_server::server::transport::TcpPeerAddressFamily::Ipv4:
        addressFamily = AF_INET;
        break;
    case rdp_server::server::transport::TcpPeerAddressFamily::Ipv6:
        addressFamily = AF_INET6;
        break;
    case rdp_server::server::transport::TcpPeerAddressFamily::Unspecified:
        snapshot.state = RuntimeTlsIdentityState::InvalidEndpoint;
        return snapshot;
    }

    std::array<char, INET6_ADDRSTRLEN> boundAddress{};
    if (::inet_ntop(addressFamily, endpoint.address.data(),
                    boundAddress.data(), boundAddress.size()) == nullptr)
    {
        snapshot.state = RuntimeTlsIdentityState::InvalidEndpoint;
        return snapshot;
    }
    switch (validateEndpointIdentity(boundAddress.data()))
    {
    case RuntimeTlsEndpointIdentityStatus::Match:
        snapshot.state = RuntimeTlsIdentityState::BoundAndMatched;
        break;
    case RuntimeTlsEndpointIdentityStatus::Mismatch:
        snapshot.state = RuntimeTlsIdentityState::CertificateMismatch;
        break;
    case RuntimeTlsEndpointIdentityStatus::InvalidEndpoint:
        snapshot.state = RuntimeTlsIdentityState::InvalidEndpoint;
        break;
    case RuntimeTlsEndpointIdentityStatus::CertificateUnavailable:
        snapshot.state = RuntimeTlsIdentityState::Unavailable;
        snapshot.fingerprintAvailable = false;
        snapshot.certificateSha256.fill(0U);
        break;
    }
    return snapshot;
}

} // namespace rdp_server::server::runtime
