// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace rdp_server::server::security
{

// R2-owned GUI-facing feasibility decision, NOT a login result or capability.
// No status here authorizes listening, TLS, MCS, Share, desktop or input.
// The OS-backed path remains subject to genuine CredSSP authentication and
// freshly verified, host-owner-authorized native admission by the R2 broker.
// Safe to call from any thread: pure, immutable, no secrets or allocations.
enum class LanCredentialChoice : std::uint8_t
{
    Unconfigured,
    ExistingOsAccount,
    IndependentApplicationPassword,
};

enum class LanCredentialDecision : std::uint8_t
{
    CredentialNotConfigured,
    RequiresGenuineOsAuthenticationAndHostConsent,
    RequiresStandalonePasswordAndHostConsent,
    // Retained for source compatibility with older callers. Current Linux
    // StandalonePassword no longer returns this decision.
    UnsupportedIndependentPasswordCredSsp,
};

[[nodiscard]] constexpr LanCredentialDecision assessLanCredentialChoice(
    LanCredentialChoice choice) noexcept
{
    switch (choice)
    {
    case LanCredentialChoice::ExistingOsAccount:
        return LanCredentialDecision::
            RequiresGenuineOsAuthenticationAndHostConsent;
    case LanCredentialChoice::IndependentApplicationPassword:
        return LanCredentialDecision::
            RequiresStandalonePasswordAndHostConsent;
    case LanCredentialChoice::Unconfigured:
        return LanCredentialDecision::CredentialNotConfigured;
    }
    // Also deny unknown values received from a future GUI/config version.
    return LanCredentialDecision::CredentialNotConfigured;
}

// This separate, intentionally deny-only predicate prevents callers from
// treating the OS-account *configuration* choice as completed admission.
// Only the existing non-constructible R2 lease and broker authorize() path
// can issue capabilities, after actual transport/credentials/OS checks.
[[nodiscard]] constexpr bool mayStartSharingFromCredentialChoice(
    LanCredentialChoice /* choice */) noexcept
{
    return false;
}

} // namespace rdp_server::server::security
