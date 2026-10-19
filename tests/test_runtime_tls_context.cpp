// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_tls_context.h"
#include "server/transport/lan_listener.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <array>
#include <concepts>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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

} // namespace

int main(int argumentCount, char **argumentValues)
{
    using rdp_server::server::runtime::RuntimeServerTlsContext;
    if (argumentCount < 4 || argumentValues[1] == nullptr ||
        argumentValues[2] == nullptr || argumentValues[3] == nullptr) {
        return fail("invalid arguments") ? 0 : 1;
    }
    const std::string_view testCase{argumentValues[1]};
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
        testCase == "rejects-live-tls-context-extra-certificate-material") {
        RuntimeServerTlsContext context =
            RuntimeServerTlsContext::fromCredentialFiles(
                argumentValues[2], argumentValues[3]);
        return context ? 1 : 0;
    }
    return fail("unknown test case") ? 0 : 1;
}
