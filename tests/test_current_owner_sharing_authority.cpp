// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/current_owner_sharing_authority.h"
#include "server/security/standalone_credential_consent.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <string_view>
#include <type_traits>

using namespace rdp_server::server::security;

namespace
{
class FakeOwnerEvidence final : public ConsoleOsEvidenceSource
{
public:
    ConsoleSessionObservation session{
        ConsoleEvidenceReadStatus::Observed, "session-1", "seat0", ":0",
        1000U, 41U, 1000U, true, true, 1000U,
        ConsoleDesktopLockState::Unlocked, false};
    std::optional<std::uint64_t> now{1000U};

    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view) noexcept override { return {}; }
    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override
    {
        session.observedAtMonotonicMilliseconds = now.value_or(0U);
        return session;
    }
    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override { return now; }
};

void grant(CurrentOwnerSharingAuthority &authority,
           std::uint64_t lifetimeMilliseconds = 500U,
           std::uint32_t permissions =
               kConsoleViewPermission | kConsoleInputPermission)
{
    assert(authority.requestConsent({permissions, lifetimeMilliseconds}) ==
           OwnerConsentRequestResult::Granted);
}

template <typename Mutator>
void expectRevocation(Mutator mutate)
{
    FakeOwnerEvidence evidence;
    CurrentOwnerSharingAuthority authority(evidence);
    grant(authority);
    const std::uint64_t before = authority.revocationGeneration();
    mutate(evidence, authority);
    assert(!authority.authorizes(kConsoleViewPermission));
    assert(authority.revocationGeneration() != before);
}
} // namespace

static_assert(!std::is_copy_constructible_v<CurrentOwnerSharingAuthority>);
static_assert(!std::is_copy_assignable_v<CurrentOwnerSharingAuthority>);
static_assert(!std::is_move_constructible_v<CurrentOwnerSharingAuthority>);
static_assert(!std::is_move_assignable_v<CurrentOwnerSharingAuthority>);

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr) return 2;
    const std::string_view testCase{argv[1]};

    if (testCase == "standalone-credential-portable-stop-revoke-matrix")
    {
        assert(!shouldRetireStandaloneApplicationCredential(
            OwnerConsentRevocationReason::Stop));
        constexpr std::array terminalReasons{
            OwnerConsentRevocationReason::LockOrUnknown,
            OwnerConsentRevocationReason::Logout,
            OwnerConsentRevocationReason::UserSwitch,
            OwnerConsentRevocationReason::SessionReplacement,
            OwnerConsentRevocationReason::CredentialChange,
            OwnerConsentRevocationReason::AuthorityExpired,
            OwnerConsentRevocationReason::NativeAuthorizationLost};
        for (const auto reason : terminalReasons)
            assert(shouldRetireStandaloneApplicationCredential(reason));
        return 0;
    }
    if (testCase == "owner-consent-positive-seat0-unlocked-grant")
    {
        FakeOwnerEvidence evidence;
        CurrentOwnerSharingAuthority authority(evidence);
        grant(authority);
        assert(authority.authorizes(kConsoleViewPermission));
        assert(authority.authorizes(kConsoleInputPermission));
        assert(!authority.authorizes(kConsoleClipboardPermission));
        grant(authority, 250U,
              kConsoleViewPermission | kConsoleClipboardPermission);
        assert(authority.authorizes(kConsoleViewPermission));
        assert(authority.authorizes(kConsoleClipboardPermission));
        assert(!authority.authorizes(kConsoleInputPermission));
        return 0;
    }
    if (testCase == "owner-consent-expiry-revokes")
    {
        FakeOwnerEvidence evidence;
        CurrentOwnerSharingAuthority authority(evidence);
        grant(authority, 100U);
        const auto before = authority.revocationGeneration();
        evidence.now = 1100U;
        assert(!authority.authorizes(kConsoleViewPermission));
        assert(authority.revocationGeneration() != before);
        return 0;
    }
    if (testCase == "owner-consent-read-only-grant-observation")
    {
        FakeOwnerEvidence evidence;
        CurrentOwnerSharingAuthority authority(evidence);
        const auto unavailable = authority.grantObservation();
        assert(unavailable.expiryState ==
               OwnerSharingGrantExpiryState::Unavailable);
        assert(unavailable.effectivePermissionMask == 0U);
        assert(unavailable.remainingMilliseconds == 0U);

        constexpr std::uint32_t permissions =
            kConsoleViewPermission | kConsoleClipboardPermission;
        grant(authority, 500U, permissions);
        evidence.now = 1100U;
        const auto active = authority.grantObservation();
        assert(active.expiryState == OwnerSharingGrantExpiryState::Active);
        assert(active.effectivePermissionMask == permissions);
        assert(active.remainingMilliseconds == 400U);

        const auto revocationBeforeExpiry = authority.revocationGeneration();
        evidence.now = 1500U;
        const auto expired = authority.grantObservation();
        assert(expired.expiryState == OwnerSharingGrantExpiryState::Expired);
        assert(expired.effectivePermissionMask == 0U);
        assert(expired.remainingMilliseconds == 0U);
        // Observation must stay read-only. Protected-operation authorization
        // remains the owner that turns expiry into revocation.
        assert(authority.revocationGeneration() == revocationBeforeExpiry);

        authority.revoke(OwnerConsentRevocationReason::AuthorityExpired);
        const auto revoked = authority.grantObservation();
        assert(revoked.expiryState ==
               OwnerSharingGrantExpiryState::Unavailable);
        assert(revoked.effectivePermissionMask == 0U);
        assert(revoked.remainingMilliseconds == 0U);
        return 0;
    }
    if (testCase == "owner-consent-read-only-product-facts")
    {
        FakeOwnerEvidence evidence;
        CurrentOwnerSharingAuthority authority(evidence);

        auto observation = authority.permissionObservation();
        assert(observation.canRequest);
        assert(!observation.activeGrant);
        assert(observation.denial ==
               OwnerSharingReadOnlyDenial::PermissionRequired);

        constexpr std::uint32_t permissions =
            kConsoleViewPermission | kConsoleInputPermission |
            kConsoleClipboardPermission;
        grant(authority, 15U * 60U * 1000U, permissions);
        evidence.now = 61'000U;
        observation = authority.permissionObservation();
        assert(observation.canRequest);
        assert(observation.activeGrant);
        assert(observation.effectivePermissionMask == permissions);
        assert(observation.remainingMilliseconds ==
               14U * 60U * 1000U);
        assert(observation.denial == OwnerSharingReadOnlyDenial::None);

        const std::uint64_t beforeReadOnlyDenials =
            authority.revocationGeneration();
        evidence.session.lockState = ConsoleDesktopLockState::Locked;
        observation = authority.permissionObservation();
        assert(!observation.canRequest);
        assert(!observation.activeGrant);
        assert(observation.denial ==
               OwnerSharingReadOnlyDenial::ComputerLocked);
        assert(authority.revocationGeneration() == beforeReadOnlyDenials);

        evidence.session.lockState = ConsoleDesktopLockState::Unlocked;
        evidence.session.sessionId = "session-2";
        ++evidence.session.sessionGeneration;
        observation = authority.permissionObservation();
        assert(observation.canRequest);
        assert(!observation.activeGrant);
        assert(observation.denial ==
               OwnerSharingReadOnlyDenial::LoggedInDesktopChanged);
        assert(authority.revocationGeneration() == beforeReadOnlyDenials);

        evidence.session.sessionId = "session-1";
        --evidence.session.sessionGeneration;
        evidence.now = 901'000U;
        observation = authority.permissionObservation();
        assert(observation.canRequest);
        assert(!observation.activeGrant);
        assert(observation.denial ==
               OwnerSharingReadOnlyDenial::PermissionExpired);
        assert(authority.revocationGeneration() == beforeReadOnlyDenials);

        evidence.now = 61'000U;
        grant(authority, 15U * 60U * 1000U, permissions);
        authority.revoke(OwnerConsentRevocationReason::Stop);
        observation = authority.permissionObservation();
        assert(observation.canRequest);
        assert(!observation.activeGrant);
        assert(observation.denial ==
               OwnerSharingReadOnlyDenial::PermissionRevoked);
        assert(observation.effectivePermissionMask == 0U);
        assert(observation.remainingMilliseconds == 0U);
        return 0;
    }
    if (testCase == "owner-consent-invalid-native-evidence-denials")
    {
        CurrentOwnerSharingAuthority unavailable;
        assert(unavailable.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::TrustedOwnerProofUnavailable);
        FakeOwnerEvidence evidence;
        CurrentOwnerSharingAuthority authority(evidence);

        // Offline owner-consent tests must not inherit the machine's native
        // console state. Unavailable evidence is non-requestable, cannot mint
        // a grant and projects only the redacted evidence-unavailable denial.
        evidence.session.status = ConsoleEvidenceReadStatus::Unavailable;
        auto unavailableObservation = authority.permissionObservation();
        assert(!unavailableObservation.canRequest);
        assert(!unavailableObservation.activeGrant);
        assert(unavailableObservation.effectivePermissionMask == 0U);
        assert(unavailableObservation.remainingMilliseconds == 0U);
        assert(unavailableObservation.denial ==
               OwnerSharingReadOnlyDenial::EvidenceUnavailable);
        assert(authority.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::NativeSessionUnavailable);
        assert(authority.grantObservation().expiryState ==
               OwnerSharingGrantExpiryState::Unavailable);
        evidence.session.status = ConsoleEvidenceReadStatus::Observed;

        constexpr std::array invalidIntents{
            OwnerSharingIntent{0U, 100U},
            OwnerSharingIntent{kConsoleInputPermission, 100U},
            OwnerSharingIntent{kConsoleViewPermission | 0x80U, 100U},
            OwnerSharingIntent{kConsoleViewPermission, 0U},
            OwnerSharingIntent{kConsoleViewPermission,
                kMaximumOwnerSharingLifetimeMilliseconds + 1U}};
        for (const auto &intent : invalidIntents)
            assert(authority.requestConsent(intent) ==
                   OwnerConsentRequestResult::InvalidIntent);
        evidence.session.lockState = ConsoleDesktopLockState::Unknown;
        assert(authority.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::LockStateNotUnlocked);
        evidence.session.lockState = ConsoleDesktopLockState::Locked;
        assert(authority.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::LockStateNotUnlocked);
        evidence.session.lockState = ConsoleDesktopLockState::Unlocked;
        evidence.session.remote = true;
        assert(authority.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::NativeSessionUnavailable);
        evidence.session.remote = false;
        evidence.session.seat = "seat1";
        assert(authority.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::NativeSessionUnavailable);
        evidence.session.seat = "seat0";
        evidence.session.localProcessUid = 1001U;
        assert(authority.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::NativeSessionUnavailable);
        return 0;
    }
    if (testCase ==
        "owner-consent-stop-lock-logout-switch-replacement-revocations")
    {
        expectRevocation([](FakeOwnerEvidence &,
                            CurrentOwnerSharingAuthority &authority) {
            authority.revoke(OwnerConsentRevocationReason::Stop);
        });
        expectRevocation([](FakeOwnerEvidence &evidence,
                            CurrentOwnerSharingAuthority &) {
            evidence.session.lockState = ConsoleDesktopLockState::Locked;
        });
        expectRevocation([](FakeOwnerEvidence &evidence,
                            CurrentOwnerSharingAuthority &) {
            evidence.session.lockState = ConsoleDesktopLockState::Unknown;
        });
        expectRevocation([](FakeOwnerEvidence &evidence,
                            CurrentOwnerSharingAuthority &) {
            evidence.session.active = false;
        });
        expectRevocation([](FakeOwnerEvidence &evidence,
                            CurrentOwnerSharingAuthority &) {
            evidence.session.ownerUid = 1001U;
            evidence.session.localProcessUid = 1001U;
        });
        expectRevocation([](FakeOwnerEvidence &evidence,
                            CurrentOwnerSharingAuthority &) {
            evidence.session.sessionId = "session-2";
            ++evidence.session.sessionGeneration;
        });
        return 0;
    }
    if (testCase == "owner-consent-start-admission-evidence-mismatch-diagnostics")
    {
        {
            FakeOwnerEvidence evidence;
            CurrentOwnerSharingAuthority authority(evidence);
            grant(authority);
            assert(authority.authorizes(kConsoleViewPermission));
            assert(authority.lastAuthorizationMismatch() ==
                   OwnerSharingAuthorizationMismatch::None);
            ++evidence.session.sessionGeneration;
            assert(!authority.authorizes(kConsoleViewPermission));
            assert(authority.lastAuthorizationMismatch() ==
                   OwnerSharingAuthorizationMismatch::SessionGeneration);
        }
        {
            FakeOwnerEvidence evidence;
            CurrentOwnerSharingAuthority authority(evidence);
            grant(authority);
            evidence.session.display = ":1";
            assert(!authority.authorizes(kConsoleViewPermission));
            assert(authority.lastAuthorizationMismatch() ==
                   OwnerSharingAuthorizationMismatch::Display);
        }
        {
            FakeOwnerEvidence evidence;
            CurrentOwnerSharingAuthority authority(evidence);
            grant(authority);
            evidence.session.remote = true;
            assert(!authority.authorizes(kConsoleViewPermission));
            assert(authority.lastAuthorizationMismatch() ==
                   OwnerSharingAuthorizationMismatch::Remote);
        }
        return 0;
    }
    if (testCase ==
        "owner-consent-credential-expiry-native-loss-revocations")
    {
        expectRevocation([](FakeOwnerEvidence &,
                            CurrentOwnerSharingAuthority &authority) {
            authority.revoke(OwnerConsentRevocationReason::CredentialChange);
        });
        expectRevocation([](FakeOwnerEvidence &,
                            CurrentOwnerSharingAuthority &authority) {
            authority.revoke(OwnerConsentRevocationReason::AuthorityExpired);
        });
        expectRevocation([](FakeOwnerEvidence &,
                            CurrentOwnerSharingAuthority &authority) {
            authority.revoke(
                OwnerConsentRevocationReason::NativeAuthorizationLost);
        });
        expectRevocation([](FakeOwnerEvidence &evidence,
                            CurrentOwnerSharingAuthority &) {
            evidence.session.status = ConsoleEvidenceReadStatus::Unavailable;
        });
        return 0;
    }
    return 2;
}
