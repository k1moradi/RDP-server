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
    // Nonzero only for evidence derived from one live R1 listener bind.
    // Process-local and descriptive; never an admission or trust capability.
    std::uint64_t endpointGeneration{};

    [[nodiscard]] constexpr bool endpointGenerationIsCurrent(
        std::uint64_t currentEndpointGeneration) const noexcept
    {
        switch (state)
        {
        case RuntimeTlsIdentityState::Unavailable:
        case RuntimeTlsIdentityState::ConfiguredUnbound:
            return endpointGeneration == 0U;
        case RuntimeTlsIdentityState::BoundAndMatched:
        case RuntimeTlsIdentityState::CertificateMismatch:
        case RuntimeTlsIdentityState::InterfaceUnavailable:
        case RuntimeTlsIdentityState::InvalidEndpoint:
            return endpointGeneration != 0U &&
                   endpointGeneration == currentEndpointGeneration;
        }
        return false;
    }

    // Descriptive endpoint/certificate evidence; never an admission lease.
    [[nodiscard]] constexpr bool boundIdentityMatches() const noexcept
    {
        return fingerprintAvailable && endpointGeneration != 0U &&
               state == RuntimeTlsIdentityState::BoundAndMatched;
    }

    [[nodiscard]] constexpr bool boundIdentityMatchesGeneration(
        std::uint64_t currentEndpointGeneration) const noexcept
    {
        return boundIdentityMatches() &&
               endpointGenerationIsCurrent(currentEndpointGeneration);
    }
};
} // namespace rdp_server::server::runtime
