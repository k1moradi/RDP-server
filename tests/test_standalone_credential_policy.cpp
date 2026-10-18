// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/standalone_credential_policy.h"

#include <cassert>
#include <cstdint>
#include <string_view>

using namespace rdp_server::server::security;

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr ||
        std::string_view(argv[1]) != "lan-credential-mode-denials")
    {
        return 2;
    }

    static_assert(assessLanCredentialChoice(LanCredentialChoice::Unconfigured) ==
                  LanCredentialDecision::CredentialNotConfigured);
    static_assert(assessLanCredentialChoice(LanCredentialChoice::ExistingOsAccount) ==
                  LanCredentialDecision::RequiresGenuineOsAuthenticationAndHostConsent);
    static_assert(assessLanCredentialChoice(
                      LanCredentialChoice::IndependentApplicationPassword) ==
                  LanCredentialDecision::UnsupportedIndependentPasswordCredSsp);
    static_assert(assessLanCredentialChoice(static_cast<LanCredentialChoice>(255)) ==
                  LanCredentialDecision::CredentialNotConfigured);

    static_assert(!mayStartSharingFromCredentialChoice(LanCredentialChoice::Unconfigured));
    static_assert(!mayStartSharingFromCredentialChoice(LanCredentialChoice::ExistingOsAccount));
    static_assert(!mayStartSharingFromCredentialChoice(
        LanCredentialChoice::IndependentApplicationPassword));
    static_assert(!mayStartSharingFromCredentialChoice(
        static_cast<LanCredentialChoice>(255)));
    assert(!mayStartSharingFromCredentialChoice(LanCredentialChoice::ExistingOsAccount));
    return 0;
}
