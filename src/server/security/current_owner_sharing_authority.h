// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_identity_policy.h"

#include <atomic>
#include <cstdint>
#include <limits>

namespace rdp_server::server::security
{

// A GUI request is untrusted intent, not affirmative current-owner consent.
// A future trusted native owner interaction must choose the actual lifetime.
struct OwnerSharingIntent final
{
    std::uint32_t requestedPermissions{};
    std::uint64_t requestedLifetimeMilliseconds{};
};

enum class OwnerConsentRequestResult : std::uint8_t
{
    InvalidIntent,
    TrustedOwnerProofUnavailable,
};

enum class OwnerConsentRevocationReason : std::uint8_t
{
    Stop, LockOrUnknown, Logout, UserSwitch, SessionReplacement,
    CredentialChange, NativeAuthorizationLost,
};

inline constexpr std::uint64_t
    kMaximumOwnerSharingLifetimeMilliseconds = 86'400'000U;

// R2-owned per-host lifetime. No public, injected or test-only grant issuer.
// At present Linux X11/logind cannot independently prove human consent AND
// authoritative unlock, so even valid intent never authorizes admission.
// R10 must serialize request/validation with its lifecycle. revoke() and
// revocationGeneration() are atomic for native change notifications.
// The host-side R2 owner must outlive every borrowing admission broker.
class CurrentOwnerSharingAuthority final
{
public:
    CurrentOwnerSharingAuthority() noexcept = default;
    CurrentOwnerSharingAuthority(const CurrentOwnerSharingAuthority&) = delete;
    CurrentOwnerSharingAuthority& operator=(
        const CurrentOwnerSharingAuthority&) = delete;

    [[nodiscard]] OwnerConsentRequestResult requestConsent(
        const OwnerSharingIntent& intent) const noexcept
    {
        if ((intent.requestedPermissions & kConsoleViewPermission) == 0U ||
            (intent.requestedPermissions & ~kConsoleAllowedPermissions) != 0U ||
            intent.requestedLifetimeMilliseconds == 0U ||
            intent.requestedLifetimeMilliseconds >
                kMaximumOwnerSharingLifetimeMilliseconds)
        {
            return OwnerConsentRequestResult::InvalidIntent;
        }
        // No status, GUI Boolean, client response, session ID, synthetic
        // lease or cached permission can stand in for trusted owner proof.
        return OwnerConsentRequestResult::TrustedOwnerProofUnavailable;
    }

    [[nodiscard]] bool authorizes(
        std::uint32_t /*requiredPermissions*/) const noexcept
    {
        // Future grant: privately bind actual UID, seat0 session, native
        // generation, permission scope, owner-chosen deadline, trusted local
        // affirmative response and authoritative unlocked state; recheck
        // all evidence at every protected R10/R2 operation boundary.
        return false;
    }

    void revoke(OwnerConsentRevocationReason /*reason*/) noexcept
    {
        auto observed = revocationGeneration_.load(std::memory_order_relaxed);
        while (observed != std::numeric_limits<std::uint64_t>::max() &&
               !revocationGeneration_.compare_exchange_weak(
                   observed, observed + 1U, std::memory_order_acq_rel,
                   std::memory_order_relaxed))
        {
        }
    }

    [[nodiscard]] std::uint64_t revocationGeneration() const noexcept
    {
        return revocationGeneration_.load(std::memory_order_acquire);
    }

private:
    std::atomic<std::uint64_t> revocationGeneration_{1U};
};

} // namespace rdp_server::server::security
