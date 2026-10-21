// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>

namespace rdp_server::server::security
{

// Intent reaches this object only from R10's local GUI command path. It is not
// itself permission; requestConsent() samples native owner/session/lock facts.
struct OwnerSharingIntent final
{
    std::uint32_t requestedPermissions{};
    std::uint64_t requestedLifetimeMilliseconds{};
};

enum class OwnerConsentRequestResult : std::uint8_t
{
    Granted,
    InvalidIntent,
    TrustedOwnerProofUnavailable,
    NativeSessionUnavailable,
    LockStateNotUnlocked,
    GenerationExhausted,
};

enum class OwnerConsentRevocationReason : std::uint8_t
{
    Stop,
    LockOrUnknown,
    Logout,
    UserSwitch,
    SessionReplacement,
    CredentialChange,
    AuthorityExpired,
    NativeAuthorizationLost,
};

// Read-only presentation state for R10/R7. This observation is never an
// authorization capability: only authorizes() may validate the current native
// session and permission scope for a protected operation.
enum class OwnerSharingGrantExpiryState : std::uint8_t
{
    Unavailable,
    Active,
    Expired,
};

struct OwnerSharingGrantObservation final
{
    OwnerSharingGrantExpiryState expiryState{
        OwnerSharingGrantExpiryState::Unavailable};
    std::uint32_t effectivePermissionMask{};
    std::uint64_t remainingMilliseconds{};
};

// Exact scalar fence used only while composing an already-authorized native
// capability. Neither generation is authorization by itself. A replacement
// consent grant changes grantGeneration even when no explicit revocation was
// published, preventing an old native binding from following a new grant.
struct OwnerSharingAuthorizationEpoch final
{
    std::uint64_t grantGeneration{};
    std::uint64_t revocationGeneration{};

    [[nodiscard]] friend constexpr bool operator==(
        const OwnerSharingAuthorizationEpoch &,
        const OwnerSharingAuthorizationEpoch &) noexcept = default;
};

// M1 deliberately limits one explicit local consent grant to at most one hour.
// The GUI may request a shorter owner-selected interval.
inline constexpr std::uint64_t
    kMaximumOwnerSharingLifetimeMilliseconds = 3'600'000U;

// R10's single noncopyable positive owner-consent/lease interface.
//
// M1 threat boundary: the locally running GUI and the currently logged-in
// desktop-user session are trusted. This does NOT claim resistance to a
// malicious process already running as the same UID or another X11 client
// capable of synthetic input. Those cases are outside the M1 threat model.
//
// requestConsent() is non-const and is reachable only from R10's local owner
// command path. LinuxRuntimeConnection receives only a const pointer, so a
// network peer can consume fresh authorization checks but cannot mint consent.
// requestConsent()/authorizes() are serialized on R10's owner thread.
class CurrentOwnerSharingAuthority final
{
public:
    CurrentOwnerSharingAuthority() noexcept = default;
    explicit CurrentOwnerSharingAuthority(
        ConsoleOsEvidenceSource &evidenceSource) noexcept
        : evidenceSource_(&evidenceSource)
    {
    }

    CurrentOwnerSharingAuthority(const CurrentOwnerSharingAuthority &) = delete;
    CurrentOwnerSharingAuthority &operator=(
        const CurrentOwnerSharingAuthority &) = delete;
    CurrentOwnerSharingAuthority(CurrentOwnerSharingAuthority &&) = delete;
    CurrentOwnerSharingAuthority &operator=(
        CurrentOwnerSharingAuthority &&) = delete;

    [[nodiscard]] OwnerConsentRequestResult requestConsent(
        const OwnerSharingIntent &intent) noexcept
    {
        if (!validIntent(intent))
            return OwnerConsentRequestResult::InvalidIntent;
        if (evidenceSource_ == nullptr)
            return OwnerConsentRequestResult::TrustedOwnerProofUnavailable;

        const ConsoleSessionObservation session =
            evidenceSource_->readActiveConsole();
        const std::optional<std::uint64_t> now =
            evidenceSource_->readMonotonicMilliseconds();
        const OwnerConsentRequestResult observation =
            validateObservation(session, now);
        if (observation != OwnerConsentRequestResult::Granted)
            return observation;

        const std::uint64_t currentRevocation = revocationGeneration();
        if (currentRevocation ==
                (std::numeric_limits<std::uint64_t>::max)() ||
            nextLeaseGeneration_ ==
                (std::numeric_limits<std::uint64_t>::max)() ||
            *now > (std::numeric_limits<std::uint64_t>::max)() -
                       intent.requestedLifetimeMilliseconds)
        {
            return OwnerConsentRequestResult::GenerationExhausted;
        }

        GrantState next{};
        std::copy(session.sessionId.begin(), session.sessionId.end(),
                  next.sessionId.begin());
        next.sessionIdLength = session.sessionId.size();
        std::copy(session.display.begin(), session.display.end(),
                  next.display.begin());
        next.displayLength = session.display.size();
        next.localUid = session.localProcessUid;
        next.sessionGeneration = session.sessionGeneration;
        next.permissions = intent.requestedPermissions;
        next.deadlineMonotonicMilliseconds =
            *now + intent.requestedLifetimeMilliseconds;
        next.leaseGeneration = ++nextLeaseGeneration_;
        next.revocationGeneration = currentRevocation;
        grant_ = next;
        return OwnerConsentRequestResult::Granted;
    }

    // Fresh native evidence is mandatory before every protected operation.
    // Any expiry, lock uncertainty or native owner/session mismatch revokes the
    // current epoch before returning false. No cached GUI Boolean authorizes.
    [[nodiscard]] bool authorizes(
        std::uint32_t requiredPermissions) const noexcept
    {
        if (evidenceSource_ == nullptr ||
            grant_.leaseGeneration == 0 ||
            grant_.revocationGeneration != revocationGeneration() ||
            requiredPermissions == 0 ||
            (requiredPermissions & ~kConsoleAllowedPermissions) != 0 ||
            (grant_.permissions & requiredPermissions) != requiredPermissions)
        {
            return false;
        }

        // Sample the session first, then the clock: an observation timestamp
        // emitted by the source cannot accidentally appear newer than now.
        const ConsoleSessionObservation session =
            evidenceSource_->readActiveConsole();
        const std::optional<std::uint64_t> now =
            evidenceSource_->readMonotonicMilliseconds();
        if (!now.has_value() ||
            *now >= grant_.deadlineMonotonicMilliseconds)
        {
            publishRevocation();
            return false;
        }

        if (!observationMatchesGrant(session, *now))
        {
            publishRevocation();
            return false;
        }
        return grant_.revocationGeneration == revocationGeneration();
    }

    // Non-secret, non-authorizing grant projection. It deliberately samples
    // only the monotonic clock and the current revocation epoch; it does not
    // refresh native session evidence, revoke state, or substitute for
    // authorizes(). Expired/revoked grants expose no effective permissions.
    [[nodiscard]] OwnerSharingGrantObservation grantObservation() const noexcept
    {
        OwnerSharingGrantObservation observation{};
        if (evidenceSource_ == nullptr ||
            grant_.leaseGeneration == 0 ||
            grant_.revocationGeneration != revocationGeneration())
        {
            return observation;
        }

        const std::optional<std::uint64_t> now =
            evidenceSource_->readMonotonicMilliseconds();
        if (!now.has_value())
            return observation;

        if (*now >= grant_.deadlineMonotonicMilliseconds)
        {
            observation.expiryState = OwnerSharingGrantExpiryState::Expired;
            return observation;
        }

        observation.expiryState = OwnerSharingGrantExpiryState::Active;
        observation.effectivePermissionMask = grant_.permissions;
        observation.remainingMilliseconds =
            grant_.deadlineMonotonicMilliseconds - *now;
        return observation;
    }

    // R2-only scalar fence for platform-native capability composition. The
    // returned epoch is useful only after this method has freshly authorized
    // the requested permission scope. Callers must still use authorizesAtEpoch()
    // immediately around every protected synchronous native visit.
    [[nodiscard]] std::optional<OwnerSharingAuthorizationEpoch>
    authorizationEpoch(std::uint32_t requiredPermissions) const noexcept
    {
        if (!authorizes(requiredPermissions))
            return std::nullopt;

        const std::uint64_t currentRevocation = revocationGeneration();
        if (grant_.leaseGeneration == 0 ||
            grant_.revocationGeneration != currentRevocation)
        {
            return std::nullopt;
        }
        return OwnerSharingAuthorizationEpoch{
            grant_.leaseGeneration, currentRevocation};
    }

    [[nodiscard]] bool authorizesAtEpoch(
        std::uint32_t requiredPermissions,
        const OwnerSharingAuthorizationEpoch &expectedEpoch) const noexcept
    {
        if (expectedEpoch.grantGeneration == 0 ||
            expectedEpoch.revocationGeneration == 0 ||
            grant_.leaseGeneration != expectedEpoch.grantGeneration ||
            grant_.revocationGeneration != expectedEpoch.revocationGeneration ||
            revocationGeneration() != expectedEpoch.revocationGeneration)
        {
            return false;
        }
        if (!authorizes(requiredPermissions))
            return false;

        return grant_.leaseGeneration == expectedEpoch.grantGeneration &&
               grant_.revocationGeneration ==
                   expectedEpoch.revocationGeneration &&
               revocationGeneration() == expectedEpoch.revocationGeneration;
    }

    void revoke(OwnerConsentRevocationReason /* reason */) noexcept
    {
        publishRevocation();
    }

    [[nodiscard]] std::uint64_t revocationGeneration() const noexcept
    {
        return revocationGeneration_.load(std::memory_order_acquire);
    }

private:
    struct GrantState final
    {
        std::array<char, 65> sessionId{};
        std::size_t sessionIdLength{};
        std::array<char, 9> display{};
        std::size_t displayLength{};
        std::uint32_t localUid{};
        std::uint64_t sessionGeneration{};
        std::uint32_t permissions{};
        std::uint64_t deadlineMonotonicMilliseconds{};
        std::uint64_t leaseGeneration{};
        std::uint64_t revocationGeneration{};
    };

    [[nodiscard]] static bool validIntent(
        const OwnerSharingIntent &intent) noexcept
    {
        return intent.requestedPermissions != 0 &&
               (intent.requestedPermissions & kConsoleViewPermission) != 0 &&
               (intent.requestedPermissions & ~kConsoleAllowedPermissions) == 0 &&
               intent.requestedLifetimeMilliseconds != 0 &&
               intent.requestedLifetimeMilliseconds <=
                   kMaximumOwnerSharingLifetimeMilliseconds;
    }

    [[nodiscard]] static bool validSessionId(
        std::string_view sessionId) noexcept
    {
        if (sessionId.empty() || sessionId.size() > 64)
            return false;
        for (const char character : sessionId)
        {
            if ((character < 'a' || character > 'z') &&
                (character < 'A' || character > 'Z') &&
                (character < '0' || character > '9') &&
                character != '_' && character != '-')
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] static bool observationFresh(
        const ConsoleSessionObservation &session,
        std::uint64_t now) noexcept
    {
        return session.observedAtMonotonicMilliseconds != 0 &&
               now >= session.observedAtMonotonicMilliseconds &&
               now - session.observedAtMonotonicMilliseconds <=
                   kMaximumConsoleObservationAgeMilliseconds;
    }

    [[nodiscard]] static OwnerConsentRequestResult validateObservation(
        const ConsoleSessionObservation &session,
        const std::optional<std::uint64_t> &now) noexcept
    {
        if (session.status != ConsoleEvidenceReadStatus::Observed ||
            !session.active || !session.physical || session.remote ||
            session.seat != "seat0" || !validSessionId(session.sessionId) ||
            session.display.empty() || session.display.size() > 8 ||
            session.ownerUid == 0 ||
            session.ownerUid ==
                (std::numeric_limits<std::uint32_t>::max)() ||
            session.localProcessUid == 0 ||
            session.localProcessUid != session.ownerUid ||
            session.sessionGeneration == 0 || !now.has_value() ||
            !observationFresh(session, *now))
        {
            return OwnerConsentRequestResult::NativeSessionUnavailable;
        }
        if (session.lockState != ConsoleDesktopLockState::Unlocked)
            return OwnerConsentRequestResult::LockStateNotUnlocked;
        return OwnerConsentRequestResult::Granted;
    }

    [[nodiscard]] bool observationMatchesGrant(
        const ConsoleSessionObservation &session,
        std::uint64_t now) const noexcept
    {
        return session.status == ConsoleEvidenceReadStatus::Observed &&
               session.active && session.physical && !session.remote &&
               session.lockState == ConsoleDesktopLockState::Unlocked &&
               session.seat == "seat0" &&
               session.localProcessUid != 0 &&
               session.localProcessUid == session.ownerUid &&
               session.ownerUid == grant_.localUid &&
               session.sessionGeneration != 0 &&
               session.sessionGeneration == grant_.sessionGeneration &&
               session.sessionId.size() == grant_.sessionIdLength &&
               session.sessionId == std::string_view(
                   grant_.sessionId.data(), grant_.sessionIdLength) &&
               session.display.size() == grant_.displayLength &&
               session.display == std::string_view(
                   grant_.display.data(), grant_.displayLength) &&
               observationFresh(session, now);
    }

    void publishRevocation() const noexcept
    {
        std::uint64_t observed =
            revocationGeneration_.load(std::memory_order_relaxed);
        while (observed != (std::numeric_limits<std::uint64_t>::max)())
        {
            if (revocationGeneration_.compare_exchange_weak(
                    observed, observed + 1U,
                    std::memory_order_release, std::memory_order_relaxed))
            {
                return;
            }
        }
    }

    ConsoleOsEvidenceSource *evidenceSource_{};
    GrantState grant_{};
    std::uint64_t nextLeaseGeneration_{};
    mutable std::atomic<std::uint64_t> revocationGeneration_{1U};
};

} // namespace rdp_server::server::security
