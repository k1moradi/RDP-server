// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_connection.h"
#include "server/runtime/linux_runtime_security.h"
#include "server/security/linux_console_admission.h"

#include <krb5.h>

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
using rdp_server::server::runtime::LinuxRuntimeConnection;
using rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration;
using rdp_server::server::security::ConsoleEvidenceRequest;
using rdp_server::server::security::ConsoleIdentityRuleInput;
using rdp_server::server::security::GssapiSpnegoAcceptor;
using rdp_server::server::security::LinuxConsoleAdmissionBroker;
using rdp_server::server::security::LinuxConsoleAdmissionState;
using rdp_server::server::security::SpnegoStage;
using rdp_server::server::security::kConsoleClipboardPermission;
using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::OwnedNativeTcpSocket;
using rdp_server::server::transport::TcpAcceptOutcome;
using rdp_server::server::transport::acceptNonblockingTcpConnection;

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

[[nodiscard]] OwnedNativeTcpSocket acceptLoopbackConnection(
    int &clientDescriptor)
{
    const int listenerDescriptor =
        ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(listenerDescriptor >= 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(::bind(
        listenerDescriptor, reinterpret_cast<const sockaddr *>(&address),
        sizeof(address)) == 0);
    assert(::listen(listenerDescriptor, 1) == 0);

    const int flags = ::fcntl(listenerDescriptor, F_GETFL, 0);
    assert(flags >= 0);
    assert(::fcntl(
        listenerDescriptor, F_SETFL, flags | O_NONBLOCK) == 0);

    socklen_t addressLength = sizeof(address);
    assert(::getsockname(
        listenerDescriptor, reinterpret_cast<sockaddr *>(&address),
        &addressLength) == 0);

    clientDescriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(clientDescriptor >= 0);
    assert(::connect(
        clientDescriptor, reinterpret_cast<const sockaddr *>(&address),
        sizeof(address)) == 0);

    auto accepted = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(listenerDescriptor));
    assert(::close(listenerDescriptor) == 0);
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    assert(accepted.connection.valid());
    return std::move(accepted.connection);
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

void testSealedKeytabSnapshotSurvivesSourceMutation(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-security-mutable-source.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    const std::string keytabUri = "FILE:" + keytab.string();
    assert(configuration.configure(
        kServicePrincipal, keytabUri, validRule()));

    // Mutate the exact source inode in place after configuration. Retaining
    // only that source descriptor would expose these new bytes to the next
    // GSS credential acquisition. R10 must instead use its sealed snapshot.
    assert(writePrivateGarbage(keytab));

    GssapiSpnegoAcceptor connectionAcceptor;
    assert(configuration.configureAcceptor(connectionAcceptor));
    assert(connectionAcceptor.stage() == SpnegoStage::AwaitInitialToken);
}

void testConnectionAggregateOrderedRevocation(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-connection-aggregate.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    {
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        assert(connection.ready());
        assert(!accepted.valid());
        assert(connection.gssStage() == SpnegoStage::AwaitInitialToken);
        assert(connection.admissionState() ==
               LinuxConsoleAdmissionState::Ready);
        assert(connection.mcsPhase() ==
               McsSessionPhase::AwaitVerifiedR2Admission);
        assert(!connection.hasAdmissionLease());

        connection.revoke();
        assert(!connection.ready());
        assert(connection.gssStage() == SpnegoStage::Failed);
        assert(connection.admissionState() ==
               LinuxConsoleAdmissionState::Revoked);
        assert(connection.mcsPhase() == McsSessionPhase::Closed);
        assert(!connection.hasAdmissionLease());

        // Ordered teardown is idempotent and never revives R1/R2/R3 state.
        connection.revoke();
        assert(!connection.ready());
        assert(connection.mcsPhase() == McsSessionPhase::Closed);
    }
    assert(::close(clientDescriptor) == 0);
}

void testConnectionCredSspAuthorizationDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-connection-credssp-denials.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    assert(connection.ready());
    assert(!connection.hasAdmissionLease());

    // No TLS or R1-selected HYBRID provenance: deny before GSS/DER.
    const auto result = connection.onCredSspIoReady();
    assert(result.status ==
           rdp_server::server::security::TsRequestTlsReadStatus::Invalid);
    assert(!connection.ready());
    assert(connection.gssStage() == SpnegoStage::Failed);
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(!connection.hasAdmissionLease());

    // Late callbacks and repeated teardown never resume the R1 owner.
    assert(connection.onCredSspIoReady().status ==
           rdp_server::server::security::TsRequestTlsReadStatus::Closed);
    connection.revoke();
    assert(connection.onCredSspIoReady().status ==
           rdp_server::server::security::TsRequestTlsReadStatus::Closed);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionAggregatePrematureAdmissionDenial(
    const std::filesystem::path &fixtureDirectory)
{
    // An accepted socket cannot survive construction without completed R10
    // service provisioning. This exercises the constructor's fail-closed path
    // before any protocol callback is possible.
    {
        LinuxRuntimeSecurityConfiguration unconfigured;
        int unconfiguredClientDescriptor = -1;
        auto unconfiguredAccepted =
            acceptLoopbackConnection(unconfiguredClientDescriptor);
        LinuxRuntimeConnection denied{
            unconfigured, std::move(unconfiguredAccepted)};
        assert(!denied.ready());
        assert(!unconfiguredAccepted.valid());
        assert(denied.gssStage() == SpnegoStage::Failed);
        assert(denied.admissionState() ==
               LinuxConsoleAdmissionState::Revoked);
        assert(denied.mcsPhase() == McsSessionPhase::Closed);
        assert(::close(unconfiguredClientDescriptor) == 0);
    }

    const auto keytab =
        fixtureDirectory / "runtime-connection-premature-admission.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{
        configuration, std::move(accepted)};
    assert(connection.ready());

    // An explicit policy-shaped request is not sufficient. No CredSSP/GSS
    // principal or R1 HYBRID provenance exists yet, so the aggregate must
    // terminate all R3/R2/R1 ownership rather than sampling OS admission.
    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};
    assert(!connection.issueAdmission(request));
    assert(!connection.ready());
    assert(connection.gssStage() == SpnegoStage::Failed);
    assert(connection.admissionState() ==
           LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(!connection.hasAdmissionLease());

    assert(::close(clientDescriptor) == 0);
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
    if (testCase == "linux-security-keytab-snapshot-mutation-continuity")
    {
        testSealedKeytabSnapshotSurvivesSourceMutation(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-security-keytab-policy-denials")
    {
        testKeytabAndPolicyDenials(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-credssp-authorization-denials")
    {
        testConnectionCredSspAuthorizationDenials(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-aggregate-ordered-revocation")
    {
        testConnectionAggregateOrderedRevocation(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-aggregate-premature-admission-denial")
    {
        testConnectionAggregatePrematureAdmissionDenial(fixtureDirectory);
        return 0;
    }
    return 2;
}
