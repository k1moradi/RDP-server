// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/credssp_credentials_internal.h"
#include "server/security/gssapi_spnego_acceptor.h"
#include "server/security/linux_pam_password_verifier.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::server::security;

namespace
{

using Bytes = std::vector<std::uint8_t>;

[[nodiscard]] Bytes derLength(std::size_t length)
{
    if (length < 128)
    {
        return {static_cast<std::uint8_t>(length)};
    }
    if (length <= 255)
    {
        return {0x81, static_cast<std::uint8_t>(length)};
    }
    assert(length <= 65535);
    return {0x82, static_cast<std::uint8_t>(length >> 8U),
            static_cast<std::uint8_t>(length)};
}

[[nodiscard]] Bytes wrap(
    std::uint8_t tag, std::span<const std::uint8_t> value)
{
    Bytes result{tag};
    const auto length = derLength(value.size());
    result.insert(result.end(), length.begin(), length.end());
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

[[nodiscard]] Bytes append(Bytes first, const Bytes &second)
{
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

[[nodiscard]] Bytes utf16Le(std::u16string_view text)
{
    Bytes result;
    result.reserve(text.size() * 2U);
    for (const char16_t character : text)
    {
        const auto codeUnit = static_cast<std::uint16_t>(character);
        result.push_back(static_cast<std::uint8_t>(codeUnit));
        result.push_back(static_cast<std::uint8_t>(codeUnit >> 8U));
    }
    return result;
}

[[nodiscard]] Bytes octetContext(
    std::uint8_t tag, const Bytes &value)
{
    return wrap(tag, wrap(0x04, value));
}

[[nodiscard]] Bytes passwordCredentials(
    const Bytes &domain, const Bytes &user, const Bytes &password)
{
    Bytes fields = octetContext(0xa0, domain);
    fields = append(fields, octetContext(0xa1, user));
    fields = append(fields, octetContext(0xa2, password));
    const Bytes passwordSequence = wrap(0x30, fields);
    const Bytes credentialType =
        wrap(0x02, std::array<std::uint8_t, 1>{1});
    return wrap(0x30, append(
        wrap(0xa0, credentialType),
        octetContext(0xa1, passwordSequence)));
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

struct PamPasswordFieldContext final
{
    const LinuxPamPasswordVerifier *verifier{};
    LinuxPamPasswordVerificationStatus status{
        LinuxPamPasswordVerificationStatus::InvalidInput};
    bool invoked{};
};

void verifyVisitedPasswordField(
    std::string_view unixAccount,
    std::span<const std::uint8_t> passwordUtf16Le,
    void *opaqueContext) noexcept
{
    auto &context = *static_cast<PamPasswordFieldContext *>(opaqueContext);
    assert(context.verifier != nullptr);
    assert(!context.invoked);
    context.status =
        context.verifier->verify(unixAccount, passwordUtf16Le);
    context.invoked = true;
}

void testCredSspPamPasswordFieldDenial()
{
    LinuxPamPasswordVerifier verifier;
    assert(verifier.configure("rdp-server-r2-ci"));

    Bytes plaintext = passwordCredentials(
        {}, utf16Le(u"_rdp_no_such_user"),
        utf16Le(u"definitely-not-a-host-credential"));
    PamPasswordFieldContext context{&verifier};
    {
        SensitiveBytesGuard cleanse{plaintext};
        assert(visitCredSspPasswordCredential(
                   plaintext, &verifyVisitedPasswordField, &context) ==
               CredSspPasswordFieldVisitStatus::Visited);
        assert(context.invoked);
        assert(context.status == LinuxPamPasswordVerificationStatus::Denied ||
               context.status ==
                   LinuxPamPasswordVerificationStatus::ProviderFailure);
    }
    for (const auto byte : plaintext)
    {
        assert(byte == 0);
    }
}

void testGssapiPamVerifierBindingDenials()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add(
               {"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                1001U, kConsoleViewPermission}) == ConsoleRuleError::None);

    LinuxPamPasswordVerifier unconfigured;
    GssapiSpnegoAcceptor missingVerifierConfiguration;
    assert(missingVerifierConfiguration.bindConsoleIdentityPolicy(policy));
    assert(!missingVerifierConfiguration.bindLinuxPamPasswordVerifier(
        unconfigured));
    assert(missingVerifierConfiguration.stage() == SpnegoStage::Failed);

    LinuxPamPasswordVerifier verifier;
    assert(verifier.configure("rdp-server-r2-ci"));

    GssapiSpnegoAcceptor missingPolicy;
    assert(!missingPolicy.bindLinuxPamPasswordVerifier(verifier));
    assert(missingPolicy.stage() == SpnegoStage::Failed);

    GssapiSpnegoAcceptor bound;
    assert(bound.bindConsoleIdentityPolicy(policy));
    assert(bound.bindLinuxPamPasswordVerifier(verifier));
    assert(bound.stage() == SpnegoStage::Unconfigured);

    // The verifier binding is one-shot and cannot be replaced after the
    // service owner has established the credential policy.
    assert(!bound.bindLinuxPamPasswordVerifier(verifier));
    assert(bound.stage() == SpnegoStage::Failed);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        testConfigurationAndInputDenials();
        testRealProviderCannotAuthorizeSyntheticAccount();
        return 0;
    }
    if (argc != 2 || argv[1] == nullptr)
    {
        return 2;
    }

    const std::string_view selected{argv[1]};
    if (selected == "credssp-pam-password-field-verifier-denials")
    {
        testCredSspPamPasswordFieldDenial();
        return 0;
    }
    if (selected == "gssapi-pam-verifier-binding-denials")
    {
        testGssapiPamVerifierBindingDenials();
        return 0;
    }
    return 2;
}
