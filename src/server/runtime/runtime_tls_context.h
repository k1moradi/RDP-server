// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "runtime_tls_identity_status.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>

#include <openssl/ssl.h>

namespace rdp_server::server::transport
{
class OwnedLanListener;
}

namespace rdp_server::server::runtime
{

enum class RuntimeTlsEndpointIdentityStatus : std::uint8_t
{
    Match,
    Mismatch,
    InvalidEndpoint,
    CertificateUnavailable,
};


// R1 runtime TLS server identity owner. A valid instance owns exactly one
// configured SSL_CTX. The runtime must keep this owner alive while connection
// SSL objects created from it remain active; R1 owns each returned SSL.
class RuntimeServerTlsContext final
{
public:
    using ServerTls = std::unique_ptr<SSL, decltype(&::SSL_free)>;

    RuntimeServerTlsContext() noexcept = default;
    RuntimeServerTlsContext(const RuntimeServerTlsContext &) = delete;
    RuntimeServerTlsContext &operator=(const RuntimeServerTlsContext &) = delete;
    RuntimeServerTlsContext(RuntimeServerTlsContext &&) noexcept = default;
    RuntimeServerTlsContext &operator=(RuntimeServerTlsContext &&) noexcept = default;
    ~RuntimeServerTlsContext() = default;

    [[nodiscard]] static RuntimeServerTlsContext fromCredentialFiles(
        std::string_view certificatePath,
        std::string_view privateKeyPath) noexcept;

    // Generates one process-owned self-signed server identity entirely in
    // memory for the exact numeric LAN address. The private key is never
    // exposed, serialized or written to a temporary file. No socket is opened.
    [[nodiscard]] static RuntimeServerTlsContext fromGeneratedIpAddress(
        std::string_view numericIpAddress) noexcept;

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context_ != nullptr;
    }

    [[nodiscard]] ServerTls createServerTls() const noexcept;
    [[nodiscard]] int minimumProtocolVersion() const noexcept;
    [[nodiscard]] std::uint64_t options() const noexcept;
    [[nodiscard]] const X509 *certificate() const noexcept;

    // Identity coverage only; this does NOT establish certificate-chain trust,
    // install a CA, suppress client warnings, or authorize an RDP session.
    // Numeric IP literals require an iPAddress SAN. Hostnames require a DNS
    // SAN; legacy Common Name fallback is deliberately disabled.
    [[nodiscard]] RuntimeTlsEndpointIdentityStatus validateEndpointIdentity(
        std::string_view endpoint) const noexcept;

    // SHA-256 of the exact configured leaf certificate for R10/R7 display.
    // A fingerprint is descriptive/pinning metadata, never R2 admission.
    [[nodiscard]] bool certificateSha256Fingerprint(
        RuntimeTlsCertificateFingerprint &output) const noexcept;

    // Derived from the actual loaded SSL_CTX certificate; no pathname or
    // user-entered GUI identity participates. No socket or admission action.
    [[nodiscard]] RuntimeTlsIdentityStatus identityStatus() const noexcept;

    // Only R1's checked, live getsockname listener can establish a bound
    // address for certificate SAN validation. R10 must re-observe on
    // replacement/rotation, Stop, interface loss and every new connection.
    [[nodiscard]] RuntimeTlsIdentityStatus boundIdentityStatus(
        const rdp_server::server::transport::OwnedLanListener &listener)
        const noexcept;

private:
    using OwnedContext = std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)>;

    explicit RuntimeServerTlsContext(OwnedContext context) noexcept
        : context_(std::move(context)) {}

    OwnedContext context_{nullptr, &::SSL_CTX_free};
};

// Offline metadata and cryptographic checks share the exact secure native
// credential-open and snapshot loader used by RuntimeServerTlsContext.
[[nodiscard]] bool validateTlsFileReferences(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept;
[[nodiscard]] bool validateTlsCredentialContents(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept;

} // namespace rdp_server::server::runtime
