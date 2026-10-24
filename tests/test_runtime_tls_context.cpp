// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_tls_context.h"
#include "server/transport/lan_listener.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <algorithm>
#include <array>
#include <concepts>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace
{
static_assert(std::same_as<
    rdp_server::server::runtime::RuntimeServerTlsContext::ServerTls,
    rdp_server::server::transport::OwnedPreauthTcpConnection::ServerTls>);

struct FileCloser
{
    void operator()(std::FILE *file) const noexcept
    {
        (void)std::fclose(file);
    }
};
struct BioCloser
{
    void operator()(BIO *bio) const noexcept { ::BIO_free(bio); }
};
struct X509Closer
{
    void operator()(X509 *certificate) const noexcept { ::X509_free(certificate); }
};

using OwnedFile = std::unique_ptr<std::FILE, FileCloser>;
using OwnedBio = std::unique_ptr<BIO, BioCloser>;
using OwnedCertificate = std::unique_ptr<X509, X509Closer>;

constexpr std::uintmax_t kMaximumFixtureCertificateBytes = 1024U * 1024U;

[[nodiscard]] bool fail(const char *message) noexcept
{
    std::fprintf(stderr, "runtime TLS context test failed: %s\n", message);
    return false;
}

[[nodiscard]] OwnedCertificate readCertificate(const char *path) noexcept
{
    if (path == nullptr) {
        return {};
    }

    std::error_code fileSizeError;
    const std::uintmax_t fileBytes =
        std::filesystem::file_size(path, fileSizeError);
    if (fileSizeError || fileBytes == 0 ||
        fileBytes > kMaximumFixtureCertificateBytes) {
        return {};
    }

    OwnedFile file{std::fopen(path, "rb")};
    if (!file) {
        return {};
    }

    const std::size_t bytes = static_cast<std::size_t>(fileBytes);
    auto data = std::make_unique_for_overwrite<unsigned char[]>(bytes);
    if (std::fread(data.get(), 1, bytes, file.get()) != bytes ||
        std::ferror(file.get()) != 0 || std::fgetc(file.get()) != EOF) {
        return {};
    }

    // Never pass an application-CRT FILE* into OpenSSL on Windows. The
    // production R10 loader uses the same memory-BIO boundary so this oracle
    // independently parses the fixture without requiring OPENSSL_Applink.
    OwnedBio bio{::BIO_new_mem_buf(data.get(), static_cast<int>(bytes))};
    if (!bio) {
        return {};
    }
    return OwnedCertificate{
        ::PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
}

[[nodiscard]] bool validateContext(const char *certificatePath,
                                   const char *privateKeyPath) noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    const OwnedCertificate expected = readCertificate(certificatePath);
    if (!expected) {
        return fail("cannot parse expected fixture certificate");
    }
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    if (!context) {
        return fail("production context construction failed");
    }
    if (context.minimumProtocolVersion() != TLS1_2_VERSION) {
        return fail("TLS minimum is not 1.2");
    }
    if ((context.options() & SSL_OP_NO_COMPRESSION) == 0) {
        return fail("compression was not disabled");
    }
#if defined(SSL_OP_NO_RENEGOTIATION)
    if ((context.options() & SSL_OP_NO_RENEGOTIATION) == 0) {
        return fail("legacy renegotiation was not disabled");
    }
#endif
    if (context.certificate() == nullptr ||
        ::X509_cmp(expected.get(), context.certificate()) != 0) {
        return fail("context does not retain the validated certificate");
    }
    RuntimeServerTlsContext::ServerTls serverTls = context.createServerTls();
    if (!serverTls || ::SSL_is_server(serverTls.get()) != 1) {
        return fail("per-connection SSL is missing or not server role");
    }
    X509 *selected = ::SSL_get_certificate(serverTls.get());
    if (selected == nullptr || ::X509_cmp(expected.get(), selected) != 0) {
        return fail("SSL does not expose the validated certificate");
    }
    return true;
}

[[nodiscard]] bool validateReplacementSurvival(
    const char *certificatePath, const char *privateKeyPath,
    const char *replacementCertificatePath,
    const char *replacementPrivateKeyPath) noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    const OwnedCertificate expected = readCertificate(certificatePath);
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    if (!expected || !context) {
        return fail("pre-replacement construction failed");
    }

    std::error_code error;
    std::filesystem::remove(certificatePath, error);
    if (error) {
        return fail("cannot remove original certificate path");
    }
    std::filesystem::rename(replacementCertificatePath, certificatePath, error);
    if (error) {
        return fail("cannot replace certificate path");
    }
    std::filesystem::remove(privateKeyPath, error);
    if (error) {
        return fail("cannot remove original key path");
    }
    std::filesystem::rename(replacementPrivateKeyPath, privateKeyPath, error);
    if (error) {
        return fail("cannot replace key path");
    }

    RuntimeServerTlsContext::ServerTls serverTls = context.createServerTls();
    if (!serverTls || ::SSL_is_server(serverTls.get()) != 1) {
        return fail("SSL creation after path replacement failed");
    }
    X509 *selected = ::SSL_get_certificate(serverTls.get());
    if (selected == nullptr || ::X509_cmp(expected.get(), selected) != 0) {
        return fail("path replacement changed retained server identity");
    }
    return true;
}
[[nodiscard]] bool validateLanEndpointIdentity(
    const char *certificatePath, const char *privateKeyPath) noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    using rdp_server::server::runtime::RuntimeTlsCertificateFingerprint;
    using rdp_server::server::runtime::RuntimeTlsEndpointIdentityStatus;
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    if (!context)
        return fail("LAN identity context construction failed");

    constexpr auto match = RuntimeTlsEndpointIdentityStatus::Match;
    constexpr auto mismatch = RuntimeTlsEndpointIdentityStatus::Mismatch;
    constexpr auto invalid = RuntimeTlsEndpointIdentityStatus::InvalidEndpoint;
    if (context.validateEndpointIdentity("rdp-lan.test") != match ||
        context.validateEndpointIdentity("RDP-LAN.TEST") != match ||
        context.validateEndpointIdentity("host.local") != match ||
        context.validateEndpointIdentity("192.168.50.10") != match ||
        context.validateEndpointIdentity("fd00::1234") != match)
        return fail("expected SAN identity did not match");

    if (context.validateEndpointIdentity("wrong.local") != mismatch ||
        context.validateEndpointIdentity("192.168.50.11") != mismatch ||
        context.validateEndpointIdentity("fd00::1235") != mismatch ||
        context.validateEndpointIdentity("") != invalid)
        return fail("mismatched/invalid endpoint was accepted");

    const std::array<char, 15> embeddedNul{
        'h','o','s','t','.','l','o','c','a','l','\0','e','v','i','l'};
    if (context.validateEndpointIdentity(
            std::string_view{embeddedNul.data(), embeddedNul.size()}) != invalid)
        return fail("embedded-NUL endpoint was accepted");

    RuntimeTlsCertificateFingerprint fingerprint{};
    if (!context.certificateSha256Fingerprint(fingerprint))
        return fail("certificate fingerprint unavailable");

    RuntimeTlsCertificateFingerprint expected{};
    unsigned int expectedBytes = 0U;
    if (::X509_digest(context.certificate(), ::EVP_sha256(), expected.data(),
                      &expectedBytes) != 1 ||
        expectedBytes != expected.size() ||
        fingerprint != expected)
        return fail("certificate fingerprint mismatch");

    bool allZero = true;
    for (std::uint8_t byte : fingerprint)
        allZero = allZero && byte == 0U;
    if (allZero)
        return fail("certificate fingerprint unexpectedly zero");
    return true;
}


[[nodiscard]] bool validateOfflineTlsIdentityLifecycle(
    const char *certificatePath, const char *privateKeyPath,
    const char *replacementCertificatePath,
    const char *replacementPrivateKeyPath) noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    using rdp_server::server::runtime::RuntimeTlsClientTrust;
    using rdp_server::server::runtime::RuntimeTlsEndpointIdentityStatus;
    using rdp_server::server::runtime::RuntimeTlsIdentityState;

    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    if (!context)
        return fail("cannot create lifecycle TLS context");

    const auto configured = context.identityStatus();
    if (configured.state != RuntimeTlsIdentityState::ConfiguredUnbound ||
        configured.clientTrust != RuntimeTlsClientTrust::Unknown ||
        !configured.fingerprintAvailable ||
        configured.endpointGeneration != 0U ||
        configured.boundIdentityMatches())
        return fail("configured TLS context invented bound/client authority");

    // The first fixture has no IP SAN, so a numeric LAN identity must fail
    // closed instead of falling back to its Common Name.
    if (context.validateEndpointIdentity("192.168.50.10") !=
        RuntimeTlsEndpointIdentityStatus::Mismatch)
        return fail("certificate without IP SAN matched a numeric endpoint");

    RuntimeServerTlsContext::ServerTls failedTls = context.createServerTls();
    if (!failedTls)
        return fail("cannot create server TLS for failed-handshake lifecycle");

    constexpr std::string_view malformedClientHello{
        "GET / HTTP/1.0\r\n\r\n"};
    BIO *input = ::BIO_new_mem_buf(
        malformedClientHello.data(),
        static_cast<int>(malformedClientHello.size()));
    BIO *output = ::BIO_new(::BIO_s_mem());
    if (input == nullptr || output == nullptr)
    {
        ::BIO_free(input);
        ::BIO_free(output);
        return fail("cannot create failed-handshake memory BIOs");
    }
    ::SSL_set_bio(failedTls.get(), input, output);
    const int handshakeResult = ::SSL_do_handshake(failedTls.get());
    const int handshakeError =
        handshakeResult == 1 ? SSL_ERROR_NONE
                             : ::SSL_get_error(failedTls.get(), handshakeResult);
    if (handshakeResult == 1 ||
        ::SSL_is_init_finished(failedTls.get()) == 1 ||
        handshakeError == SSL_ERROR_WANT_READ ||
        handshakeError == SSL_ERROR_WANT_WRITE)
        return fail("malformed client bytes did not terminate TLS handshake");

    const auto afterFailedHandshake = context.identityStatus();
    if (afterFailedHandshake.state != RuntimeTlsIdentityState::ConfiguredUnbound ||
        afterFailedHandshake.clientTrust != RuntimeTlsClientTrust::Unknown ||
        !afterFailedHandshake.fingerprintAvailable ||
        afterFailedHandshake.certificateSha256 != configured.certificateSha256 ||
        afterFailedHandshake.endpointGeneration != 0U ||
        afterFailedHandshake.boundIdentityMatches())
        return fail("failed TLS handshake promoted or changed identity status");

    RuntimeServerTlsContext rotatedContext =
        RuntimeServerTlsContext::fromCredentialFiles(
            replacementCertificatePath, replacementPrivateKeyPath);
    if (!rotatedContext)
        return fail("cannot create rotated TLS context");
    const auto rotated = rotatedContext.identityStatus();
    if (rotated.state != RuntimeTlsIdentityState::ConfiguredUnbound ||
        rotated.clientTrust != RuntimeTlsClientTrust::Unknown ||
        !rotated.fingerprintAvailable || rotated.endpointGeneration != 0U ||
        rotated.boundIdentityMatches() ||
        rotated.certificateSha256 == configured.certificateSha256)
        return fail("certificate rotation retained stale identity evidence");

    if (rotatedContext.validateEndpointIdentity("192.168.50.10") !=
            RuntimeTlsEndpointIdentityStatus::Match ||
        rotatedContext.validateEndpointIdentity("192.168.50.11") !=
            RuntimeTlsEndpointIdentityStatus::Mismatch)
        return fail("rotated certificate IP SAN identity mismatch");

    // Endpoint generations are descriptive anti-stale metadata. Simulate an
    // R10 cached value only to prove that replacement generation cannot reuse
    // a prior positive observation; this does not construct listener authority.
    auto boundObservation = rotated;
    boundObservation.state = RuntimeTlsIdentityState::BoundAndMatched;
    boundObservation.endpointGeneration = 41U;
    if (!boundObservation.boundIdentityMatches() ||
        !boundObservation.boundIdentityMatchesGeneration(41U) ||
        boundObservation.boundIdentityMatchesGeneration(42U) ||
        boundObservation.endpointGenerationIsCurrent(42U))
        return fail("stale endpoint generation was accepted");
    boundObservation.endpointGeneration = 0U;
    if (boundObservation.boundIdentityMatches() ||
        boundObservation.boundIdentityMatchesGeneration(0U))
        return fail("zero endpoint generation became bound identity");

    return true;
}

[[nodiscard]] bool validateReadOnlyUnboundIdentityStatus(
    const char *certificatePath, const char *privateKeyPath) noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    using rdp_server::server::runtime::RuntimeTlsIdentityState;
    using rdp_server::server::runtime::RuntimeTlsClientTrust;
    using rdp_server::server::transport::OwnedLanListener;

    const OwnedLanListener unopenedListener;
    RuntimeServerTlsContext context;
    const auto absent = context.identityStatus();
    if (absent.state != RuntimeTlsIdentityState::Unavailable ||
        absent.clientTrust != RuntimeTlsClientTrust::Unknown ||
        absent.fingerprintAvailable || absent.boundIdentityMatches() ||
        context.boundIdentityStatus(unopenedListener).fingerprintAvailable)
        return fail("unconfigured TLS context published identity");

    context = RuntimeServerTlsContext::fromCredentialFiles(
        certificatePath, privateKeyPath);
    if (!context)
        return fail("cannot create configured TLS context");
    rdp_server::server::runtime::RuntimeTlsCertificateFingerprint actual{};
    if (!context.certificateSha256Fingerprint(actual))
        return fail("configured certificate fingerprint unavailable");
    const auto configured = context.identityStatus();
    const auto unbound = context.boundIdentityStatus(unopenedListener);
    if (configured.state != RuntimeTlsIdentityState::ConfiguredUnbound ||
        !configured.fingerprintAvailable ||
        configured.certificateSha256 != actual ||
        configured.clientTrust != RuntimeTlsClientTrust::Unknown ||
        configured.boundIdentityMatches() ||
        unbound.state != RuntimeTlsIdentityState::ConfiguredUnbound ||
        unbound.certificateSha256 != actual ||
        unbound.clientTrust != RuntimeTlsClientTrust::Unknown ||
        unbound.boundIdentityMatches())
        return fail("unbound TLS status invented listener/client trust");

    // Re-observation after context replacement must not reuse old identity.
    context = RuntimeServerTlsContext{};
    const auto retired = context.boundIdentityStatus(unopenedListener);
    if (retired.state != RuntimeTlsIdentityState::Unavailable ||
        retired.fingerprintAvailable || retired.boundIdentityMatches() ||
        retired.clientTrust != RuntimeTlsClientTrust::Unknown)
        return fail("retired TLS context published stale identity");
    for (std::uint8_t byte : retired.certificateSha256)
        if (byte != 0U)
            return fail("retired identity retained an old fingerprint");
    return true;
}

[[nodiscard]] bool validateGeneratedIdentity(
    std::string_view endpoint, std::string_view wrongEndpoint) noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    using rdp_server::server::runtime::RuntimeTlsEndpointIdentityStatus;

    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromGeneratedIpAddress(endpoint);
    if (!context)
        return fail("generated TLS context construction failed");
    if (context.minimumProtocolVersion() != TLS1_2_VERSION ||
        (context.options() & SSL_OP_NO_COMPRESSION) == 0U)
        return fail("generated TLS context lost hardening");
#if defined(SSL_OP_NO_RENEGOTIATION)
    if ((context.options() & SSL_OP_NO_RENEGOTIATION) == 0U)
        return fail("generated TLS context permits renegotiation");
#endif
    if (context.certificate() == nullptr ||
        ::X509_check_purpose(
            const_cast<X509 *>(context.certificate()),
            X509_PURPOSE_SSL_SERVER, 0) != 1)
        return fail("generated certificate lacks server purpose");

    if (context.validateEndpointIdentity(endpoint) !=
            RuntimeTlsEndpointIdentityStatus::Match ||
        context.validateEndpointIdentity(wrongEndpoint) !=
            RuntimeTlsEndpointIdentityStatus::Mismatch)
        return fail("generated certificate IP SAN coverage is incorrect");

    RuntimeServerTlsContext::ServerTls serverTls = context.createServerTls();
    if (!serverTls || ::SSL_is_server(serverTls.get()) != 1)
        return fail("generated server SSL unavailable");
    if (::SSL_get_fd(serverTls.get()) != -1)
        return fail("identity generation unexpectedly attached a socket");

    EVP_PKEY *const privateKey = ::SSL_get_privatekey(serverTls.get());
    if (privateKey == nullptr ||
        ::X509_check_private_key(context.certificate(), privateKey) != 1)
        return fail("generated certificate/private key do not match");
    return true;
}

[[nodiscard]] bool validateGeneratedGenericSubject() noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    using rdp_server::server::runtime::RuntimeTlsEndpointIdentityStatus;

    constexpr std::string_view endpoint{"192.0.2.60"};
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromGeneratedIpAddress(endpoint);
    if (!context || context.certificate() == nullptr)
        return fail("generated subject context unavailable");

    const X509_NAME *const subject =
        ::X509_get_subject_name(context.certificate());
    const int commonNameIndex = subject == nullptr
        ? -1
        : ::X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    const X509_NAME_ENTRY *const commonNameEntry =
        commonNameIndex < 0 ? nullptr
                            : ::X509_NAME_get_entry(subject, commonNameIndex);
    const ASN1_STRING *const commonNameValue =
        commonNameEntry == nullptr
        ? nullptr
        : ::X509_NAME_ENTRY_get_data(commonNameEntry);

    unsigned char *commonNameUtf8 = nullptr;
    const int commonNameBytes = commonNameValue == nullptr
        ? -1
        : ::ASN1_STRING_to_UTF8(&commonNameUtf8, commonNameValue);
    const bool commonNameMatches =
        commonNameBytes == 10 && commonNameUtf8 != nullptr &&
        std::string_view{
            reinterpret_cast<const char *>(commonNameUtf8),
            static_cast<std::size_t>(commonNameBytes)} == "RDP Server";
    ::OPENSSL_free(commonNameUtf8);

    if (!commonNameMatches ||
        ::X509_NAME_get_index_by_NID(
            subject, NID_commonName, commonNameIndex) != -1)
        return fail("generated certificate subject is not generic");

    if (context.validateEndpointIdentity(endpoint) !=
            RuntimeTlsEndpointIdentityStatus::Match ||
        context.validateEndpointIdentity("192.0.2.61") !=
            RuntimeTlsEndpointIdentityStatus::Mismatch)
        return fail("IP SAN did not remain the endpoint identity authority");
    return true;
}

[[nodiscard]] bool validateGeneratedOwnerIpv4SanDer() noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    using rdp_server::server::runtime::RuntimeTlsEndpointIdentityStatus;
    constexpr std::array<unsigned char, 4> kOwnerIpv4{
        0xc0U, 0xa8U, 0x01U, 0x05U};

    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromGeneratedIpAddress("192.168.1.5");
    if (!context || context.certificate() == nullptr)
        return fail("owner IPv4 generated certificate unavailable");

    GENERAL_NAMES *rawNames = static_cast<GENERAL_NAMES *>(
        ::X509_get_ext_d2i(
            const_cast<X509 *>(context.certificate()),
            NID_subject_alt_name, nullptr, nullptr));
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>
        names{rawNames, GENERAL_NAMES_free};
    if (!names || sk_GENERAL_NAME_num(names.get()) != 1)
        return fail("owner IPv4 SAN count mismatch");

    const GENERAL_NAME *const name =
        sk_GENERAL_NAME_value(names.get(), 0);
    if (name == nullptr || name->type != GEN_IPADD ||
        name->d.iPAddress == nullptr ||
        ::ASN1_STRING_length(name->d.iPAddress) !=
            static_cast<int>(kOwnerIpv4.size()))
        return fail("owner IPv4 SAN is not one GEN_IPADD");

    const unsigned char *const bytes =
        ::ASN1_STRING_get0_data(name->d.iPAddress);
    if (bytes == nullptr ||
        !std::equal(kOwnerIpv4.begin(), kOwnerIpv4.end(), bytes))
        return fail("owner IPv4 SAN bytes are not C0 A8 01 05");

    if (context.validateEndpointIdentity("192.168.1.5") !=
            RuntimeTlsEndpointIdentityStatus::Match)
        return fail("owner IPv4 self-check failed");
    return true;
}

[[nodiscard]] bool validateGeneratedRetirement() noexcept
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromGeneratedIpAddress("192.0.2.40");
    if (!context)
        return fail("generated retirement context unavailable");

    RuntimeServerTlsContext::ServerTls serverTls = context.createServerTls();
    if (!serverTls || ::SSL_get_fd(serverTls.get()) != -1)
        return fail("generated retirement SSL unexpectedly owns a socket");
    serverTls.reset();

    context = RuntimeServerTlsContext{};
    const auto retired = context.identityStatus();
    if (context || retired.fingerprintAvailable || retired.boundIdentityMatches())
        return fail("retired generated identity retained runtime ownership");
    for (const std::uint8_t byte : retired.certificateSha256)
        if (byte != 0U)
            return fail("retired generated identity retained fingerprint bytes");
    return true;
}

} // namespace

int main(int argumentCount, char **argumentValues)
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    if (argumentCount < 2 || argumentValues[1] == nullptr)
        return fail("invalid arguments") ? 0 : 1;

    const std::string_view testCase{argumentValues[1]};
    if (testCase == "generated-tls-identity-ipv4-san")
        return validateGeneratedIdentity(
            "192.0.2.40", "192.0.2.41") ? 0 : 1;
    if (testCase == "generated-tls-identity-ipv6-san")
        return validateGeneratedIdentity(
            "2001:db8::40", "2001:db8::41") ? 0 : 1;
    if (testCase == "generated-tls-identity-generic-subject-ip-san-authority")
        return validateGeneratedGenericSubject() ? 0 : 1;
    if (testCase == "generated-tls-identity-owner-ipv4-san-der")
        return validateGeneratedOwnerIpv4SanDer() ? 0 : 1;
    if (testCase == "generated-tls-identity-wrong-endpoint-denial")
    {
        RuntimeServerTlsContext context =
            RuntimeServerTlsContext::fromGeneratedIpAddress("198.51.100.20");
        if (!context ||
            context.validateEndpointIdentity("198.51.100.21") !=
                rdp_server::server::runtime::
                    RuntimeTlsEndpointIdentityStatus::Mismatch ||
            RuntimeServerTlsContext::fromGeneratedIpAddress("rdp.local") ||
            RuntimeServerTlsContext::fromGeneratedIpAddress(
                "198.51.100.20:3389"))
            return 1;
        return 0;
    }
    if (testCase == "generated-tls-identity-stop-retirement")
        return validateGeneratedRetirement() ? 0 : 1;
    if (testCase == "generated-tls-identity-no-listener-side-effect")
    {
        RuntimeServerTlsContext context =
            RuntimeServerTlsContext::fromGeneratedIpAddress("203.0.113.15");
        auto serverTls = context.createServerTls();
        return context && serverTls && ::SSL_get_fd(serverTls.get()) == -1
            ? 0 : 1;
    }

    if (argumentCount < 4 || argumentValues[2] == nullptr ||
        argumentValues[3] == nullptr)
        return fail("credential fixture arguments missing") ? 0 : 1;
    if (testCase == "validates-live-tls-context-construction") {
        return validateContext(argumentValues[2], argumentValues[3]) ? 0 : 1;
    }
    if (testCase == "validates-lan-endpoint-certificate-identity") {
        return validateLanEndpointIdentity(
            argumentValues[2], argumentValues[3]) ? 0 : 1;
    }
    if (testCase == "tls-context-read-only-unbound-identity-status") {
        return validateReadOnlyUnboundIdentityStatus(
            argumentValues[2], argumentValues[3]) ? 0 : 1;
    }
    if (testCase == "tls-identity-offline-lifecycle-denials") {
        if (argumentCount != 6 || argumentValues[4] == nullptr ||
            argumentValues[5] == nullptr) {
            return fail("lifecycle replacement fixture arguments missing") ? 0 : 1;
        }
        return validateOfflineTlsIdentityLifecycle(
            argumentValues[2], argumentValues[3],
            argumentValues[4], argumentValues[5]) ? 0 : 1;
    }
    if (testCase == "tls-context-survives-credential-path-replacement") {
        if (argumentCount != 6 || argumentValues[4] == nullptr ||
            argumentValues[5] == nullptr) {
            return fail("replacement fixture arguments missing") ? 0 : 1;
        }
        return validateReplacementSurvival(
            argumentValues[2], argumentValues[3],
            argumentValues[4], argumentValues[5]) ? 0 : 1;
    }
    if (testCase == "rejects-live-tls-context-invalid-material" ||
        testCase == "rejects-live-tls-context-extra-certificate-material" ||
        testCase == "rejects-live-tls-context-private-key-mismatch") {
        RuntimeServerTlsContext context =
            RuntimeServerTlsContext::fromCredentialFiles(
                argumentValues[2], argumentValues[3]);
        return context ? 1 : 0;
    }
    return fail("unknown test case") ? 0 : 1;
}
