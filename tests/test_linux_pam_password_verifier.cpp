// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/linux_pam_password_verifier.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::server::security;

namespace
{

[[nodiscard]] std::vector<std::uint8_t> utf16Le(
    std::u16string_view text)
{
    std::vector<std::uint8_t> result;
    result.reserve(text.size() * 2U);
    for (const char16_t character : text)
    {
        const auto codeUnit = static_cast<std::uint16_t>(character);
        result.push_back(static_cast<std::uint8_t>(codeUnit));
        result.push_back(static_cast<std::uint8_t>(codeUnit >> 8U));
    }
    return result;
}

void testConfigurationAndInputDenials()
{
    LinuxPamPasswordVerifier missingConfiguration;
    assert(!missingConfiguration.configured());
    assert(missingConfiguration.serviceName().empty());
    const auto password = utf16Le(u"not-a-real-password");
    assert(missingConfiguration.verify("_rdp_no_such_user", password) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);

    LinuxPamPasswordVerifier invalidService;
    assert(!invalidService.configure("../login"));
    assert(!invalidService.configured());
    assert(!invalidService.configure("rdp-server"));

    LinuxPamPasswordVerifier configured;
    assert(configured.configure("rdp-server-r2-ci"));
    assert(configured.configured());
    assert(configured.serviceName() == "rdp-server-r2-ci");
    assert(!configured.configure("login"));

    assert(configured.verify("", password) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
    assert(configured.verify("root", password) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
    assert(configured.verify("BadUser", password) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);

    assert(configured.verify("_rdp_no_such_user", {}) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
    auto oddPassword = password;
    oddPassword.pop_back();
    assert(configured.verify("_rdp_no_such_user", oddPassword) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
    const std::array<std::uint8_t, 4> embeddedNul{
        0x41, 0x00, 0x00, 0x00};
    assert(configured.verify("_rdp_no_such_user", embeddedNul) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
    const std::array<std::uint8_t, 2> loneHighSurrogate{0x00, 0xd8};
    assert(configured.verify(
               "_rdp_no_such_user", loneHighSurrogate) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
    const std::array<std::uint8_t, 2> loneLowSurrogate{0x00, 0xdc};
    assert(configured.verify(
               "_rdp_no_such_user", loneLowSurrogate) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);

    std::vector<std::uint8_t> oversized(4098U, 0x41);
    assert(configured.verify("_rdp_no_such_user", oversized) ==
           LinuxPamPasswordVerificationStatus::InvalidInput);
}

void testRealProviderCannotAuthorizeSyntheticAccount()
{
    LinuxPamPasswordVerifier verifier;
    assert(verifier.configure("rdp-server-r2-ci"));

    const auto password = utf16Le(u"definitely-not-a-host-credential");
    const auto result = verifier.verify("_rdp_no_such_user", password);

    // This calls the real host PAM API. Ordinary CI supplies no account,
    // password or PAM fixture and therefore may report Denied or a provider
    // failure depending on the host's "other" stack. Neither is authority.
    assert(result == LinuxPamPasswordVerificationStatus::Denied ||
           result == LinuxPamPasswordVerificationStatus::ProviderFailure);
}

} // namespace

int main()
{
    testConfigurationAndInputDenials();
    testRealProviderCannotAuthorizeSyntheticAccount();
    return 0;
}
