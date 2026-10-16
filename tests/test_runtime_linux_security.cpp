// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_security.h"
#include "server/security/linux_console_admission.h"

#include <krb5.h>

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/stat.h>

namespace
{
using rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration;
using rdp_server::server::security::ConsoleIdentityRuleInput;
using rdp_server::server::security::GssapiSpnegoAcceptor;
using rdp_server::server::security::LinuxConsoleAdmissionBroker;
using rdp_server::server::security::LinuxConsoleAdmissionState;
using rdp_server::server::security::SpnegoStage;
using rdp_server::server::security::kConsoleClipboardPermission;
using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;

constexpr std::string_view kServicePrincipal{
    "TERMSRV/rdp.example.test@EXAMPLE.TEST"};

[[nodiscard]] ConsoleIdentityRuleInput validRule() noexcept
{
    return {
        "alice@EXAMPLE.TEST",
        "alice",
        "seat0",
        ":0",
        1001U,
        kConsoleViewPermission |
            kConsoleInputPermission |
            kConsoleClipboardPermission};
}

[[nodiscard]] bool writeSyntheticKeytab(
    const std::filesystem::path &path,
    std::string_view servicePrincipal)
{
    std::error_code filesystemError;
    std::filesystem::remove(path, filesystemError);

    krb5_context context = nullptr;
    krb5_keytab keytab = nullptr;
    krb5_principal principal = nullptr;
    krb5_keytab_entry entry{};
    bool keyInitialized = false;

    if (::krb5_init_context(&context) != 0 || context == nullptr)
    {
        return false;
    }

    const std::string writableKeytab =
        "WRFILE:" + path.string();
    const std::string principalText{servicePrincipal};

    bool success =
        ::krb5_kt_resolve(
            context, writableKeytab.c_str(), &keytab) == 0 &&
        keytab != nullptr &&
        ::krb5_parse_name(
            context, principalText.c_str(), &principal) == 0 &&
        principal != nullptr;
    if (success)
    {
        entry.principal = principal;
        entry.vno = 1;
        entry.timestamp = 0;
        success =
            ::krb5_c_make_random_key(
                context, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                &entry.key) == 0;
        keyInitialized = success;
    }
    if (success)
    {
        success = ::krb5_kt_add_entry(context, keytab, &entry) == 0;
    }

    if (keyInitialized)
    {
        ::krb5_free_keyblock_contents(context, &entry.key);
    }
    if (keytab != nullptr)
    {
        (void)::krb5_kt_close(context, keytab);
    }
    if (principal != nullptr)
    {
        ::krb5_free_principal(context, principal);
    }
    ::krb5_free_context(context);

    if (!success || ::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0)
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool writePrivateGarbage(
    const std::filesystem::path &path)
{
    std::FILE *file = std::fopen(path.c_str(), "wb");
    if (file == nullptr)
    {
        return false;
    }
    constexpr char garbage[] = "not-a-keytab";
    const bool written =
        std::fwrite(garbage, 1, sizeof(garbage) - 1U, file) ==
        sizeof(garbage) - 1U;
    const bool closed = std::fclose(file) == 0;
    return written && closed &&
        ::chmod(path.c_str(), S_IRUSR | S_IWUSR) == 0;
}

void testExplicitKeytabContinuity(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab = fixtureDirectory / "runtime-security.keytab";
    const auto retained =
        fixtureDirectory / "runtime-security.original.keytab";
    std::error_code error;
    std::filesystem::remove(retained, error);

    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    const std::string keytabUri = "FILE:" + keytab.string();
    assert(configuration.configure(
        kServicePrincipal, keytabUri, validRule()));
    assert(configuration.configured());
    assert(configuration.servicePrincipal() == kServicePrincipal);
    assert(configuration.policy() != nullptr);
    assert(configuration.policy()->size() == 1U);

    // Replace the original configured pathname after R10 retained its native
    // descriptor. Later R2 acquisition must still consume the original keytab
    // through /proc/self/fd, never the now-invalid replacement pathname.
    std::filesystem::rename(keytab, retained, error);
    assert(!error);
    assert(writePrivateGarbage(keytab));

    GssapiSpnegoAcceptor connectionAcceptor;
    assert(configuration.configureAcceptor(connectionAcceptor));
    assert(connectionAcceptor.stage() == SpnegoStage::AwaitInitialToken);

    LinuxConsoleAdmissionBroker broker(*configuration.policy());
    assert(broker.state() == LinuxConsoleAdmissionState::Ready);
    assert(broker.nativeChangeFd() == -1);

    // Runtime security configuration is immutable after first attempt.
    assert(!configuration.configure(
        kServicePrincipal, keytabUri, validRule()));
    assert(configuration.configured());
}

void testKeytabAndPolicyDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto privateKeytab = fixtureDirectory / "private.keytab";
    assert(writeSyntheticKeytab(privateKeytab, kServicePrincipal));
    const std::string privateUri = "FILE:" + privateKeytab.string();

    {
        assert(::chmod(
            privateKeytab.c_str(),
            S_IRUSR | S_IWUSR | S_IRGRP) == 0);
        LinuxRuntimeSecurityConfiguration configuration;
        assert(!configuration.configure(
            kServicePrincipal, privateUri, validRule()));
        assert(!configuration.configured());
        assert(configuration.policy() == nullptr);
    }
    assert(::chmod(privateKeytab.c_str(), S_IRUSR | S_IWUSR) == 0);

    {
        const auto linkPath = fixtureDirectory / "keytab-link";
        std::error_code error;
        std::filesystem::remove(linkPath, error);
        std::filesystem::create_symlink(privateKeytab, linkPath, error);
        assert(!error);
        LinuxRuntimeSecurityConfiguration configuration;
        assert(!configuration.configure(
            kServicePrincipal,
            "FILE:" + linkPath.string(),
            validRule()));
    }

    {
        LinuxRuntimeSecurityConfiguration configuration;
        assert(!configuration.configure(
            "HOST/rdp.example.test@EXAMPLE.TEST",
            privateUri,
            validRule()));
    }

    {
        ConsoleIdentityRuleInput invalidRule = validRule();
        invalidRule.unixAccount = "root";
        LinuxRuntimeSecurityConfiguration configuration;
        assert(!configuration.configure(
            kServicePrincipal, privateUri, invalidRule));
    }

    {
        LinuxRuntimeSecurityConfiguration configuration;
        assert(!configuration.configure(
            kServicePrincipal, "FILE:relative.keytab", validRule()));
    }

    {
        const auto missingKeytab = fixtureDirectory / "missing.keytab";
        std::error_code error;
        std::filesystem::remove(missingKeytab, error);
        LinuxRuntimeSecurityConfiguration configuration;
        assert(!configuration.configure(
            kServicePrincipal,
            "FILE:" + missingKeytab.string(),
            validRule()));
    }
}

} // namespace

int main(int argumentCount, char **argumentValues)
{
    if (argumentCount != 3 ||
        argumentValues[1] == nullptr ||
        argumentValues[2] == nullptr)
    {
        return 2;
    }

    const std::string_view testCase{argumentValues[1]};
    std::error_code error;
    if (testCase == "write-synthetic-keytab")
    {
        const std::filesystem::path keytabPath{argumentValues[2]};
        const auto parentPath = keytabPath.parent_path();
        if (parentPath.empty())
        {
            return 2;
        }
        std::filesystem::create_directories(parentPath, error);
        if (error || !writeSyntheticKeytab(keytabPath, kServicePrincipal))
        {
            return 1;
        }
        return 0;
    }

    const std::filesystem::path fixtureDirectory{argumentValues[2]};
    std::filesystem::create_directories(fixtureDirectory, error);
    if (error)
    {
        return 2;
    }
    if (testCase == "linux-security-explicit-keytab-continuity")
    {
        testExplicitKeytabContinuity(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-security-keytab-policy-denials")
    {
        testKeytabAndPolicyDenials(fixtureDirectory);
        return 0;
    }
    return 2;
}
