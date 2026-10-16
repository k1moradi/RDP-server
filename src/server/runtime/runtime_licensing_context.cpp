// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_licensing_context.h"
#include "runtime_credential_file_internal.h"

namespace rdp_server::server::runtime
{

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
