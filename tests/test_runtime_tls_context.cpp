// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_tls_context.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <concepts>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string_view>

#include <openssl/pem.h>
#include <openssl/x509.h>

namespace
{
static_assert(std::same_as<
    rdp_server::server::runtime::RuntimeServerTlsContext::ServerTls,
    rdp_server::server::transport::OwnedPreauthTcpConnection::ServerTls>);

struct X509Closer
{
    void operator()(X509 *certificate) const noexcept { ::X509_free(certificate); }
};
using OwnedCertificate = std::unique_ptr<X509, X509Closer>;

[[nodiscard]] bool fail(const char *message) noexcept
{
    std::fprintf(stderr, "runtime TLS context test failed: %s\n", message);
    return false;
}

[[nodiscard]] OwnedCertificate readCertificate(const char *path) noexcept
{
    std::FILE *file = std::fopen(path, "rb");
    if (file == nullptr) {
        return {};
    }
    OwnedCertificate certificate{::PEM_read_X509(file, nullptr, nullptr, nullptr)};
    (void)std::fclose(file);
    return certificate;
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
