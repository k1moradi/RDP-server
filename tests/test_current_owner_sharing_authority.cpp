// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/current_owner_sharing_authority.h"

#include <array>
#include <cassert>
#include <string_view>
#include <type_traits>

using namespace rdp_server::server::security;

int main(int argumentCount, char** argumentValues)
{
    if (argumentCount != 2 || argumentValues[1] == nullptr)
        return 2;
    const std::string_view testCase{argumentValues[1]};
    CurrentOwnerSharingAuthority authority;
    static_assert(!std::is_copy_constructible_v<CurrentOwnerSharingAuthority>);

    if (testCase == "owner-consent-gui-intent-never-authorizes")
    {
        assert(authority.requestConsent({kConsoleViewPermission, 60'000U}) ==
               OwnerConsentRequestResult::TrustedOwnerProofUnavailable);
        assert(authority.requestConsent({kConsoleAllowedPermissions,
                                         kMaximumOwnerSharingLifetimeMilliseconds}) ==
               OwnerConsentRequestResult::TrustedOwnerProofUnavailable);
        assert(!authority.authorizes(kConsoleViewPermission));
        assert(!authority.authorizes(kConsoleInputPermission));
        assert(!authority.authorizes(kConsoleClipboardPermission));
        assert(!authority.authorizes(kConsoleAllowedPermissions));
        return 0;
    }
    if (testCase == "owner-consent-invalid-scope-and-lifetime-denials")
    {
        constexpr std::array invalidRequests{
            OwnerSharingIntent{0U, 60'000U},
            OwnerSharingIntent{kConsoleInputPermission, 60'000U},
            OwnerSharingIntent{kConsoleViewPermission | 0x80U, 60'000U},
            OwnerSharingIntent{kConsoleViewPermission, 0U},
            OwnerSharingIntent{kConsoleViewPermission,
                kMaximumOwnerSharingLifetimeMilliseconds + 1U},
        };
        for (const auto& request : invalidRequests)
            assert(authority.requestConsent(request) ==
                   OwnerConsentRequestResult::InvalidIntent);
        assert(!authority.authorizes(kConsoleViewPermission));
        return 0;
    }
    if (testCase == "owner-consent-stop-lock-session-credential-revocations")
    {
        constexpr std::array reasons{
            OwnerConsentRevocationReason::Stop,
            OwnerConsentRevocationReason::LockOrUnknown,
            OwnerConsentRevocationReason::Logout,
            OwnerConsentRevocationReason::UserSwitch,
            OwnerConsentRevocationReason::SessionReplacement,
            OwnerConsentRevocationReason::CredentialChange,
            OwnerConsentRevocationReason::NativeAuthorizationLost,
        };
        auto generation = authority.revocationGeneration();
        for (const auto reason : reasons)
        {
            authority.revoke(reason);
            ++generation;
            assert(authority.revocationGeneration() == generation);
            assert(!authority.authorizes(kConsoleAllowedPermissions));
            assert(authority.requestConsent({kConsoleViewPermission, 1U}) ==
                   OwnerConsentRequestResult::TrustedOwnerProofUnavailable);
        }
        return 0;
    }
    return 2;
}
