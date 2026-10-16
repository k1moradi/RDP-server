// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_licensing_context.h"

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
