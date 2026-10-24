// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "current_owner_sharing_authority.h"
#include "standalone_ntlmv2.h"

#include <span>
#include <string_view>

namespace rdp_server::server::security
{

// One R2 credential-replacement transaction shared by platform HostControls.
// Replacement intent invalidates any prior owner-consent generation before the
// production credential owner consumes and scrubs the mutable password. The
// returned observation is descriptive only; native admission, owner permission
// and listener Start remain independent later gates.
[[nodiscard]] inline StandalonePasswordCredentialObservation
replaceStandaloneApplicationCredential(
    StandalonePasswordCredentialOwner& credentialOwner,
    CurrentOwnerSharingAuthority& ownerAuthority,
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    ownerAuthority.revoke(OwnerConsentRevocationReason::CredentialChange);

    if (!credentialOwner.configure(username, password))
        return credentialOwner.observation();

    const auto observation = credentialOwner.observation();
    if (observation.configured && observation.generation != 0U)
        return observation;

    credentialOwner.revoke();
    return credentialOwner.observation();
}

} // namespace rdp_server::server::security
