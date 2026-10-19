// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>

namespace rdp_server::server::runtime
{
// Server identity evidence never authorizes R2 admission or GUI Start.
// Server-side evidence cannot reveal the client's certificate-trust choice.
enum class RuntimeTlsClientTrust : std::uint8_t { Unknown };

enum class RuntimeTlsIdentityState : std::uint8_t
{
    Unavailable,
    ConfiguredUnbound,
    BoundAndMatched,
    CertificateMismatch,
    InterfaceUnavailable,
    InvalidEndpoint,
};

using RuntimeTlsCertificateFingerprint = std::array<std::uint8_t, 32>;

struct RuntimeTlsIdentityStatus
{
    RuntimeTlsIdentityState state{RuntimeTlsIdentityState::Unavailable};
    RuntimeTlsClientTrust clientTrust{RuntimeTlsClientTrust::Unknown};
    RuntimeTlsCertificateFingerprint certificateSha256{};
    bool fingerprintAvailable{};

    // Descriptive endpoint/certificate evidence; never an admission lease.
    [[nodiscard]] constexpr bool boundIdentityMatches() const noexcept
    {
        return fingerprintAvailable &&
               state == RuntimeTlsIdentityState::BoundAndMatched;
    }
};
} // namespace rdp_server::server::runtime
