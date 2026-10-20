// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/current_owner_sharing_authority.h"

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
    if (testCase == "owner-consent-invalid-native-evidence-denials")
    {
        CurrentOwnerSharingAuthority unavailable;
        assert(unavailable.requestConsent({kConsoleViewPermission, 100U}) ==
               OwnerConsentRequestResult::TrustedOwnerProofUnavailable);
        FakeOwnerEvidence evidence;
        CurrentOwnerSharingAuthority authority(evidence);
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
