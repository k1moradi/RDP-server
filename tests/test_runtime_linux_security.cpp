// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_connection.h"
#include "server/runtime/linux_runtime_security.h"
#include "server/security/linux_console_admission.h"

#include <krb5.h>

#include <algorithm>
#include <cassert>
#include <array>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace rdp_server::server::transport
{
// This fixture stages only R3 protocol bookkeeping to prove the private
// personal-mode selector is one-shot and the production generation fence is
// terminal. It never constructs or substitutes an R2 admission lease.
class McsSessionLifecycleTestAccess final
{
public:
    static void stagePersonalDesktopSelection(
        McsSessionLifecycle &session,
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept
    {
        session.admissionGeneration_ = admissionGeneration;
        session.sessionGeneration_ = sessionGeneration;
        session.phase_ = McsSessionPhase::AwaitServerLicenseRequest;
    }

    static void stageShareActivated(
        McsSessionLifecycle &session,
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept
    {
        session.admissionGeneration_ = admissionGeneration;
        session.sessionGeneration_ = sessionGeneration;
        session.phase_ = McsSessionPhase::ShareActivated;
    }

    [[nodiscard]] static bool selectPersonalDesktop(
        McsSessionLifecycle &session) noexcept
    {
        return session.selectVerifiedR2PersonalDesktopLicensingMode();
    }
};
} // namespace rdp_server::server::transport

namespace rdp_server::server::security
{
// Test access binds only the non-authorizing PersonalDesktop policy identity.
// It cannot create a lease, GSS principal, TLS owner or native-session proof.
struct LinuxConsoleAdmissionBrokerTestAccess final
{
    static void bindPersonalDesktopPolicy(
        LinuxConsoleAdmissionBroker &broker,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept
    {
        broker.personalDesktopPolicy_ = &deploymentPolicy;
    }

    [[nodiscard]] static bool personalDesktopPolicyMatches(
        const LinuxConsoleAdmissionBroker &broker,
        const rdp_server::server::runtime::RuntimeDeploymentPolicy
            &deploymentPolicy) noexcept
    {
        return broker.personalDesktopPolicyMatches(deploymentPolicy);
    }
};
} // namespace rdp_server::server::security

namespace
{
using rdp_server::server::runtime::LinuxCredSspStepStatus;
using rdp_server::server::runtime::LinuxPreAdmissionStepStatus;
using rdp_server::server::runtime::LinuxPostAdmissionMcsStepStatus;
using rdp_server::server::runtime::
    LinuxPersonalDesktopLicenseWriteStepStatus;
using rdp_server::server::runtime::
    LinuxPersonalDesktopClientLicensingStepStatus;
using rdp_server::server::runtime::
    LinuxPersonalDesktopValidClientWriteStepStatus;
using rdp_server::server::runtime::
    LinuxPersonalDesktopShareActivationStepStatus;
using rdp_server::server::runtime::LinuxRuntimeConnection;
using rdp_server::server::runtime::LinuxRuntimeMcsTpktFrameReader;
using rdp_server::server::runtime::LinuxRuntimeMcsTpktFrameStatus;
using rdp_server::server::runtime::LinuxRuntimeNativeChangeRegistration;
using rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration;
using rdp_server::server::runtime::RuntimeLicensingAuthority;
using rdp_server::server::runtime::RuntimeLicensingContext;
using rdp_server::server::runtime::RuntimeLicensingExistingCalOperation;
using rdp_server::server::runtime::RuntimeDeploymentPolicy;
using rdp_server::server::runtime::RuntimeServerTlsContext;
using rdp_server::server::security::ConsoleEvidenceRequest;
using rdp_server::server::security::ConsoleIdentityRuleInput;
using rdp_server::server::security::CredSspServerReplyField;
using rdp_server::server::security::GssapiSpnegoAcceptor;
using rdp_server::server::security::encodeCredSspServerTsRequest;
using rdp_server::server::security::LinuxConsoleAdmissionBroker;
using rdp_server::server::security::LinuxConsoleAdmissionBrokerTestAccess;
using rdp_server::server::security::LinuxConsoleAdmissionState;
using rdp_server::server::security::SpnegoStage;
using rdp_server::server::security::kConsoleClipboardPermission;
using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;
using rdp_server::server::transport::McsSessionLifecycle;
using rdp_server::server::transport::McsSessionLifecycleTestAccess;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::
    RdpPersonalDesktopValidClientWriteOutcome;
using rdp_server::server::transport::RdpShareActivationClientIntake;
using rdp_server::server::transport::RdpShareActivationWriteOutcome;
using rdp_server::server::transport::RdpGraphicsDvcWriteOutcome;
using rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome;
using rdp_server::server::transport::OwnedNativeTcpSocket;
using rdp_server::server::transport::TcpAcceptOutcome;
using rdp_server::server::transport::TcpConnectionIoInterest;
using rdp_server::server::transport::TcpPreauthEvent;
using rdp_server::server::transport::TlsHandshakeStatus;
using rdp_server::server::transport::kRdpProtocolHybrid;
using rdp_server::server::transport::kRdpProtocolSsl;
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

using TestSslContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using TestSsl = std::unique_ptr<SSL, decltype(&SSL_free)>;
using TestKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using TestCertificate = std::unique_ptr<X509, decltype(&X509_free)>;
using TestX509Name = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using TestBio = std::unique_ptr<BIO, decltype(&BIO_free)>;

inline constexpr std::array<std::uint8_t, 19> kHybridNlaRequest{
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x08, 0x00,
    static_cast<std::uint8_t>(kRdpProtocolSsl | kRdpProtocolHybrid),
    0x00, 0x00, 0x00};

inline constexpr std::array<std::uint8_t, 11> kRejectedInitialSpnego{
    0x60, 0x09, 0x06, 0x06, 0x2b, 0x06,
    0x01, 0x05, 0x05, 0x02, 0xa0};

inline constexpr std::array<std::uint8_t, 15> kV6LogonFailure{
    0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
    0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x6d};

[[nodiscard]] bool setNonblocking(int descriptor) noexcept
{
    const int flags = ::fcntl(descriptor, F_GETFL, 0);
    return flags >= 0 &&
           ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

[[nodiscard]] bool sendSocketAll(
    int descriptor, std::span<const std::uint8_t> bytes) noexcept
{
    std::size_t offset = 0;
    for (std::size_t attempt = 0;
         offset < bytes.size() && attempt < 16384; ++attempt)
    {
        const auto remaining = bytes.subspan(offset);
        const ssize_t sent = ::send(
            descriptor, remaining.data(), remaining.size(), MSG_NOSIGNAL);
        if (sent > 0)
        {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        {
            std::this_thread::yield();
            continue;
        }
        return false;
    }
    return offset == bytes.size();
}

[[nodiscard]] bool receiveSocketAll(
    int descriptor, std::span<std::uint8_t> bytes) noexcept
{
    std::size_t offset = 0;
    for (std::size_t attempt = 0;
         offset < bytes.size() && attempt < 16384; ++attempt)
    {
        const auto remaining = bytes.subspan(offset);
        const ssize_t received =
            ::recv(descriptor, remaining.data(), remaining.size(), 0);
        if (received > 0)
        {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        {
            std::this_thread::yield();
            continue;
        }
        return false;
    }
    return offset == bytes.size();
}

[[nodiscard]] bool writeTlsCredentials(
    const std::filesystem::path &certificatePath,
    const std::filesystem::path &privateKeyPath)
{
    std::error_code error;
    std::filesystem::remove(certificatePath, error);
    error.clear();
    std::filesystem::remove(privateKeyPath, error);

    const TestKey key{EVP_EC_gen("prime256v1"), EVP_PKEY_free};
    const TestCertificate certificate{X509_new(), X509_free};
    const TestX509Name name{X509_NAME_new(), X509_NAME_free};
    if (!key || !certificate || !name ||
        X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) == nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) == nullptr ||
        X509_set_pubkey(certificate.get(), key.get()) != 1 ||
        X509_NAME_add_entry_by_txt(
            name.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>(
                "rdp-runtime-credssp-test"),
            -1, -1, 0) != 1 ||
        X509_set_subject_name(certificate.get(), name.get()) != 1 ||
        X509_set_issuer_name(certificate.get(), name.get()) != 1 ||
        X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0)
    {
        return false;
    }

    const std::string certificateName = certificatePath.string();
    const std::string privateKeyName = privateKeyPath.string();
    const TestBio certificateBio{
        BIO_new_file(certificateName.c_str(), "wb"), BIO_free};
    const TestBio privateKeyBio{
        BIO_new_file(privateKeyName.c_str(), "wb"), BIO_free};
    if (!certificateBio || !privateKeyBio ||
        PEM_write_bio_X509(certificateBio.get(), certificate.get()) != 1 ||
        PEM_write_bio_PrivateKey(
            privateKeyBio.get(), key.get(), nullptr, nullptr, 0, nullptr,
            nullptr) != 1)
    {
        return false;
    }
    return ::chmod(certificatePath.c_str(), S_IRUSR | S_IWUSR) == 0 &&
           ::chmod(privateKeyPath.c_str(), S_IRUSR | S_IWUSR) == 0;
}

[[nodiscard]] TestSsl establishHybridTls(
    LinuxRuntimeConnection &connection, int clientDescriptor,
    const RuntimeServerTlsContext &tlsContext)
{
    assert(setNonblocking(clientDescriptor));
    assert(sendSocketAll(clientDescriptor, kHybridNlaRequest));

    TcpPreauthEvent preauth = TcpPreauthEvent::NeedRead;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        preauth = connection.onReadable();
        if (preauth != TcpPreauthEvent::NeedRead)
        {
            break;
        }
        std::this_thread::yield();
    }
    assert(preauth == TcpPreauthEvent::NeedWrite);

    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        preauth = connection.onWritable();
        if (preauth != TcpPreauthEvent::NeedWrite)
        {
            break;
        }
        std::this_thread::yield();
    }
    assert(preauth == TcpPreauthEvent::ReadyForTls);

    std::array<std::uint8_t, 19> confirm{};
    assert(receiveSocketAll(clientDescriptor, confirm));
    assert(confirm[11] == 0x02);
    assert(confirm[15] == kRdpProtocolHybrid);
    assert(connection.attachServerTls(tlsContext));

    const TestSslContext clientContext{
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
    assert(clientContext);
    assert(SSL_CTX_set_min_proto_version(
               clientContext.get(), TLS1_2_VERSION) == 1);
    SSL_CTX_set_verify(clientContext.get(), SSL_VERIFY_NONE, nullptr);

    TestSsl clientTls{SSL_new(clientContext.get()), SSL_free};
    assert(clientTls);
    SSL_set_connect_state(clientTls.get());
    assert(SSL_set_fd(clientTls.get(), clientDescriptor) == 1);

    bool clientEstablished = false;
    bool serverEstablished = false;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        if (!clientEstablished)
        {
            const int result = SSL_do_handshake(clientTls.get());
            if (result == 1)
            {
                clientEstablished = true;
            }
            else
            {
                const int sslError = SSL_get_error(clientTls.get(), result);
                assert(sslError == SSL_ERROR_WANT_READ ||
                       sslError == SSL_ERROR_WANT_WRITE);
            }
        }
        if (!serverEstablished)
        {
            const auto result = connection.onTlsIoReady();
            assert(result != TlsHandshakeStatus::Invalid);
            assert(result != TlsHandshakeStatus::Closed);
            serverEstablished = result == TlsHandshakeStatus::Established;
        }
        if (clientEstablished && serverEstablished)
        {
            break;
        }
        std::this_thread::yield();
    }
    assert(clientEstablished && serverEstablished);
    return clientTls;
}

[[nodiscard]] bool writeTlsClientAll(
    SSL *clientTls, std::span<const std::uint8_t> bytes) noexcept
{
    std::size_t offset = 0;
    for (std::size_t attempt = 0;
         offset < bytes.size() && attempt < 16384; ++attempt)
    {
        std::size_t written = 0;
        const auto remaining = bytes.subspan(offset);
        const int result = SSL_write_ex(
            clientTls, remaining.data(), remaining.size(), &written);
        if (result == 1)
        {
            if (written == 0 || written > remaining.size())
            {
                return false;
            }
            offset += written;
            continue;
        }
        const int sslError = SSL_get_error(clientTls, result);
        if (sslError != SSL_ERROR_WANT_READ &&
            sslError != SSL_ERROR_WANT_WRITE)
        {
            return false;
        }
        std::this_thread::yield();
    }
    return offset == bytes.size();
}

[[nodiscard]] bool readTlsClientAll(
    SSL *clientTls, std::span<std::uint8_t> bytes) noexcept
{
    std::size_t offset = 0;
    for (std::size_t attempt = 0;
         offset < bytes.size() && attempt < 16384; ++attempt)
    {
        std::size_t received = 0;
        const auto remaining = bytes.subspan(offset);
        const int result = SSL_read_ex(
            clientTls, remaining.data(), remaining.size(), &received);
        if (result == 1)
        {
            if (received == 0 || received > remaining.size())
            {
                return false;
            }
            offset += received;
            continue;
        }
        const int sslError = SSL_get_error(clientTls, result);
        if (sslError != SSL_ERROR_WANT_READ &&
            sslError != SSL_ERROR_WANT_WRITE)
        {
            return false;
        }
        std::this_thread::yield();
    }
    return offset == bytes.size();
}

[[nodiscard]] RuntimeServerTlsContext makeRuntimeTlsContext(
    const std::filesystem::path &fixtureDirectory,
    std::string_view fixtureName)
{
    std::error_code error;
    const auto absoluteFixtureDirectory =
        std::filesystem::absolute(fixtureDirectory, error);
    assert(!error);
    const std::string prefix = "runtime-credssp-" + std::string(fixtureName);
    const auto certificate =
        absoluteFixtureDirectory / (prefix + "-certificate.pem");
    const auto privateKey =
        absoluteFixtureDirectory / (prefix + "-private-key.pem");
    assert(writeTlsCredentials(certificate, privateKey));
    const std::string certificatePath = certificate.string();
    const std::string privateKeyPath = privateKey.string();
    auto context = RuntimeServerTlsContext::fromCredentialFiles(
        certificatePath, privateKeyPath);
    assert(context);
    return context;
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

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
void testPamVerifierProvisioning(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab = fixtureDirectory / "runtime-security-pam.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    const std::string keytabUri = "FILE:" + keytab.string();

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, keytabUri, validRule(), "rdp-server-r2-ci"));
    assert(configuration.configured());
    assert(configuration.pamServiceName() == "rdp-server-r2-ci");

    GssapiSpnegoAcceptor connectionAcceptor;
    assert(configuration.configureAcceptor(connectionAcceptor));
    assert(connectionAcceptor.stage() == SpnegoStage::AwaitInitialToken);

    // Runtime provisioning does not turn a configured verifier into a user
    // authentication result, final CredSSP completion or native admission.
    LinuxConsoleAdmissionBroker broker(*configuration.policy());
    assert(broker.state() == LinuxConsoleAdmissionState::Ready);
    assert(broker.nativeChangeFd() == -1);

    LinuxRuntimeSecurityConfiguration invalidPamService;
    assert(!invalidPamService.configure(
        kServicePrincipal, keytabUri, validRule(), "../login"));
    assert(!invalidPamService.configured());
    assert(invalidPamService.pamServiceName().empty());
    assert(invalidPamService.policy() == nullptr);
    assert(!invalidPamService.configure(
        kServicePrincipal, keytabUri, validRule(), "rdp-server-r2-ci"));
}
#endif

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

void testConnectionCredSspOwnerFraming(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-connection-credssp-framing.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));
    auto tlsContext = makeRuntimeTlsContext(fixtureDirectory, "framing");

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    assert(connection.ready());
    TestSsl clientTls =
        establishHybridTls(connection, clientDescriptor, tlsContext);

    const auto request = encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::NegoToken, kRejectedInitialSpnego);
    assert(request.size() > 8);
    assert(writeTlsClientAll(clientTls.get(), std::span(request).first(8)));

    std::size_t totalRead = 0;
    bool retainedPartialFrame = false;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        const auto step = connection.onCredSspIoReady();
        totalRead += step.plaintextBytesRead;
        assert(step.plaintextBytesWritten == 0);
        assert(step.status != LinuxCredSspStepStatus::Invalid);
        assert(step.status != LinuxCredSspStepStatus::Closed);
        if (totalRead == 8 &&
            (step.status == LinuxCredSspStepStatus::NeedRead ||
             step.status == LinuxCredSspStepStatus::NeedWrite))
        {
            retainedPartialFrame = true;
            break;
        }
        assert(totalRead <= 8);
        std::this_thread::yield();
    }
    assert(retainedPartialFrame);
    assert(!connection.hasAdmissionLease());

    assert(writeTlsClientAll(clientTls.get(), std::span(request).subspan(8)));
    std::size_t totalWritten = 0;
    bool providerFailureObserved = false;
    bool terminalReplyFlushed = false;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        const auto step = connection.onCredSspIoReady();

        // R2 may transition from a completed frame to an already-pending
        // provider reply between callbacks. Scheduling must not affect the
        // oracle: one bounded R1 step may read OR write, never both.
        assert(step.plaintextBytesRead == 0 ||
               step.plaintextBytesWritten == 0);
        totalRead += step.plaintextBytesRead;
        totalWritten += step.plaintextBytesWritten;
        assert(totalRead <= request.size());
        assert(totalWritten <= kV6LogonFailure.size());

        // No provider output may enter R1 until the complete DER request has
        // been consumed. A queued failure is not native/R3 admission.
        if (step.plaintextBytesWritten != 0)
        {
            assert(totalRead == request.size());
            assert(connection.gssStage() == SpnegoStage::Failed);
        }
        if (connection.gssStage() == SpnegoStage::Failed)
        {
            providerFailureObserved = true;
            assert(totalRead == request.size());
            assert(!connection.hasAdmissionLease());
        }

        if (step.status == LinuxCredSspStepStatus::Invalid)
        {
            terminalReplyFlushed = true;
            break;
        }
        assert(step.status == LinuxCredSspStepStatus::Progress ||
               step.status == LinuxCredSspStepStatus::NeedRead ||
               step.status == LinuxCredSspStepStatus::NeedWrite);
        std::this_thread::yield();
    }
    assert(providerFailureObserved);
    assert(terminalReplyFlushed);
    assert(totalWritten == kV6LogonFailure.size());

    std::array<std::uint8_t, kV6LogonFailure.size()> received{};
    assert(readTlsClientAll(clientTls.get(), received));
    assert(received == kV6LogonFailure);
    assert(!connection.ready());
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(connection.onCredSspIoReady().status ==
           LinuxCredSspStepStatus::Closed);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionCredSspProgressAccounting(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-connection-credssp-progress.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));
    auto tlsContext = makeRuntimeTlsContext(fixtureDirectory, "progress");

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    TestSsl clientTls =
        establishHybridTls(connection, clientDescriptor, tlsContext);

    const auto request = encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::NegoToken, kRejectedInitialSpnego);
    assert(writeTlsClientAll(clientTls.get(), request));

    std::size_t totalRead = 0;
    bool finalReadReportedOnNeedWrite = false;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        const auto step = connection.onCredSspIoReady();
        assert(step.plaintextBytesRead == 0 ||
               step.plaintextBytesWritten == 0);
        assert(step.plaintextBytesWritten == 0);
        totalRead += step.plaintextBytesRead;
        assert(totalRead <= request.size());

        if (step.status == LinuxCredSspStepStatus::NeedWrite &&
            connection.gssStage() == SpnegoStage::Failed)
        {
            // The final request bytes and provider failure can share one R2
            // step; R10 must not discard accepted R1 read progress merely
            // because the next required readiness direction is write.
            assert(step.plaintextBytesRead != 0);
            assert(totalRead == request.size());
            finalReadReportedOnNeedWrite = true;
            break;
        }

        assert(step.status == LinuxCredSspStepStatus::Progress ||
               step.status == LinuxCredSspStepStatus::NeedRead ||
               step.status == LinuxCredSspStepStatus::NeedWrite);
        std::this_thread::yield();
    }

    assert(finalReadReportedOnNeedWrite);
    assert(connection.gssStage() == SpnegoStage::Failed);
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Ready);
    assert(connection.mcsPhase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);
    assert(!connection.hasAdmissionLease());

    connection.revoke();
    assert(!connection.ready());
    assert(connection.onCredSspIoReady().status ==
           LinuxCredSspStepStatus::Closed);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionPostAdmissionMcsFramingDenials(
    const std::filesystem::path &fixtureDirectory)
{
    using FrameStatus = LinuxRuntimeMcsTpktFrameStatus;
    using Step = LinuxPostAdmissionMcsStepStatus;

    constexpr std::array<std::uint8_t, 8U> minimalTpkt{
        0x03U, 0x00U, 0x00U, 0x08U,
        0x02U, 0xf0U, 0x80U, 0x00U};

    {
        LinuxRuntimeMcsTpktFrameReader reader;
        assert(reader.bytesNeeded() == 4U);
        auto framed = reader.consume(std::span{minimalTpkt}.first(2U));
        assert(framed.bytesConsumed == 2U);
        assert(framed.status == FrameStatus::NeedMore);
        assert(reader.bytesNeeded() == 2U);

        framed = reader.consume(std::span{minimalTpkt}.subspan(2U, 2U));
        assert(framed.bytesConsumed == 2U);
        assert(framed.status == FrameStatus::NeedMore);
        assert(reader.bytesNeeded() == 4U);

        std::array<std::uint8_t, 5U> finalAndFollowing{
            minimalTpkt[4], minimalTpkt[5], minimalTpkt[6], minimalTpkt[7],
            0xaaU};
        framed = reader.consume(finalAndFollowing);
        assert(framed.bytesConsumed == 4U);
        assert(framed.status == FrameStatus::Complete);
        assert(reader.bytesNeeded() == 0U);
        const auto complete = reader.completeTpkt();
        assert(complete.size() == minimalTpkt.size());
        assert(std::equal(
            complete.begin(), complete.end(), minimalTpkt.begin()));
        reader.close();
        assert(reader.status() == FrameStatus::Closed);
        assert(reader.completeTpkt().empty());
    }

    for (const std::array<std::uint8_t, 4U> invalidHeader : {
             std::array<std::uint8_t, 4U>{0x02U, 0x00U, 0x00U, 0x08U},
             std::array<std::uint8_t, 4U>{0x03U, 0x01U, 0x00U, 0x08U},
             std::array<std::uint8_t, 4U>{0x03U, 0x00U, 0x00U, 0x07U},
             std::array<std::uint8_t, 4U>{0x03U, 0x00U, 0x20U, 0x01U}})
    {
        LinuxRuntimeMcsTpktFrameReader reader;
        const auto framed = reader.consume(invalidHeader);
        assert(framed.bytesConsumed == invalidHeader.size());
        assert(framed.status == FrameStatus::Invalid);
        assert(reader.bytesNeeded() == 0U);
        assert(reader.completeTpkt().empty());
    }

    {
        LinuxRuntimeMcsTpktFrameReader truncated;
        auto framed = truncated.consume(std::span{minimalTpkt}.first(6U));
        assert(framed.bytesConsumed == 6U);
        assert(framed.status == FrameStatus::NeedMore);
        assert(truncated.bytesNeeded() == 2U);
        truncated.close();
        assert(truncated.status() == FrameStatus::Closed);
        assert(truncated.completeTpkt().empty());
    }

    const auto keytab =
        fixtureDirectory / "runtime-connection-post-admission-mcs.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    assert(connection.ready());
    assert(!connection.hasAdmissionLease());

    const auto denied =
        connection.advancePostAdmissionMcsConnectInitial(true, true);
    assert(denied.status == Step::AdmissionDenied);
    assert(denied.plaintextBytesRead == 0U);
    assert(!connection.ready());
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(!connection.hasAdmissionLease());

    const auto replay =
        connection.advancePostAdmissionMcsConnectInitial(true, true);
    assert(replay.status == Step::Closed);
    assert(replay.plaintextBytesRead == 0U);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionPreAdmissionDispatch(
    const std::filesystem::path &fixtureDirectory)
{
    using Step = LinuxPreAdmissionStepStatus;

    const auto keytab =
        fixtureDirectory / "runtime-connection-pre-admission-dispatch.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));
    auto tlsContext =
        makeRuntimeTlsContext(fixtureDirectory, "pre-admission-dispatch");

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    assert(setNonblocking(clientDescriptor));
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    assert(connection.ready());
    assert(connection.ioInterest() == TcpConnectionIoInterest::Read);

    // Wrong-direction readiness is a bounded no-op. In particular, it must
    // not call the legacy plaintext adapter and must not mutate R1/R2/R3.
    auto step = connection.advancePreAdmission(false, true, tlsContext);
    assert(step.status == Step::NeedRead);
    assert(step.plaintextBytesRead == 0);
    assert(step.plaintextBytesWritten == 0);
    assert(connection.ready());
    assert(connection.ioInterest() == TcpConnectionIoInterest::Read);

    assert(sendSocketAll(clientDescriptor, kHybridNlaRequest));
    step = connection.advancePreAdmission(true, false, tlsContext);
    assert(step.status == Step::NeedWrite);
    assert(step.plaintextBytesRead == 0);
    assert(step.plaintextBytesWritten == 0);
    assert(connection.ioInterest() == TcpConnectionIoInterest::Write);

    // A readable callback while the X.224 Confirm is pending cannot consume
    // ClientHello/CredSSP bytes or repeatedly redispatch the pre-TLS reader.
    step = connection.advancePreAdmission(true, false, tlsContext);
    assert(step.status == Step::NeedWrite);
    assert(step.plaintextBytesRead == 0);
    assert(step.plaintextBytesWritten == 0);

    step = connection.advancePreAdmission(false, true, tlsContext);
    assert(step.status == Step::Progress);
    std::array<std::uint8_t, 19> confirm{};
    assert(receiveSocketAll(clientDescriptor, confirm));
    assert(confirm[11] == 0x02);
    assert(confirm[15] == kRdpProtocolHybrid);

    const TestSslContext clientContext{
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
    assert(clientContext);
    assert(SSL_CTX_set_min_proto_version(
               clientContext.get(), TLS1_2_VERSION) == 1);
    SSL_CTX_set_verify(clientContext.get(), SSL_VERIFY_NONE, nullptr);
    TestSsl clientTls{SSL_new(clientContext.get()), SSL_free};
    assert(clientTls);
    SSL_set_connect_state(clientTls.get());
    assert(SSL_set_fd(clientTls.get(), clientDescriptor) == 1);

    bool clientEstablished = false;
    bool serverEstablished = false;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        if (!clientEstablished)
        {
            const int result = SSL_do_handshake(clientTls.get());
            if (result == 1)
            {
                clientEstablished = true;
            }
            else
            {
                const int sslError = SSL_get_error(clientTls.get(), result);
                assert(sslError == SSL_ERROR_WANT_READ ||
                       sslError == SSL_ERROR_WANT_WRITE);
            }
        }

        if (!serverEstablished)
        {
            step = connection.advancePreAdmission(true, true, tlsContext);
            assert(step.status == Step::NeedRead ||
                   step.status == Step::NeedWrite ||
                   step.status == Step::TlsEstablished);
            if (step.status == Step::TlsEstablished)
            {
                serverEstablished = true;
            }
        }

        if (clientEstablished && serverEstablished)
        {
            break;
        }
        std::this_thread::yield();
    }
    assert(clientEstablished && serverEstablished);
    assert(connection.ready());
    assert(connection.ioInterest() == TcpConnectionIoInterest::Read);
    assert(connection.gssStage() == SpnegoStage::AwaitInitialToken);
    assert(connection.mcsPhase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);

    // This is the key HYBRID scheduler fence: R1 advertises readable
    // application readiness, but only R2's owner-driven CredSSP step may
    // consume it. Wrong-direction readiness remains zero-progress.
    step = connection.advancePreAdmission(false, true, tlsContext);
    assert(step.status == Step::NeedRead);
    assert(step.plaintextBytesRead == 0);
    assert(step.plaintextBytesWritten == 0);
    assert(connection.gssStage() == SpnegoStage::AwaitInitialToken);

    const auto request = encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::NegoToken, kRejectedInitialSpnego);
    assert(writeTlsClientAll(clientTls.get(), request));

    // The first bounded CredSSP read asks only for the DER header. OpenSSL
    // may decrypt the rest of that TLS record at the same time. The next
    // serialized scheduler step must therefore progress from R1-owned
    // buffered plaintext even with no fresh native readable callback.
    step = connection.advancePreAdmission(true, false, tlsContext);
    assert(step.status == Step::Progress);
    assert(step.plaintextBytesRead > 0);
    assert(step.plaintextBytesWritten == 0);
    std::size_t totalRead = step.plaintextBytesRead;
    std::size_t totalWritten = 0;

    const auto bufferedStep =
        connection.advancePreAdmission(false, false, tlsContext);
    assert(bufferedStep.plaintextBytesRead > 0);
    assert(bufferedStep.plaintextBytesWritten == 0);
    assert(bufferedStep.status == Step::Progress ||
           bufferedStep.status == Step::NeedWrite ||
           bufferedStep.status == Step::NeedRead);
    totalRead += bufferedStep.plaintextBytesRead;

    bool providerFailureObserved =
        connection.gssStage() == SpnegoStage::Failed;
    bool wrongWriteDirectionObserved = false;
    bool terminal = false;
    for (std::size_t attempt = 0; attempt < 16384; ++attempt)
    {
        const auto interest = connection.ioInterest();
        assert(interest == TcpConnectionIoInterest::Read ||
               interest == TcpConnectionIoInterest::Write);

        if (!wrongWriteDirectionObserved &&
            interest == TcpConnectionIoInterest::Write)
        {
            const auto wrong =
                connection.advancePreAdmission(true, false, tlsContext);
            assert(wrong.status == Step::NeedWrite);
            assert(wrong.plaintextBytesRead == 0);
            assert(wrong.plaintextBytesWritten == 0);
            assert(connection.ioInterest() == TcpConnectionIoInterest::Write);
            wrongWriteDirectionObserved = true;
            continue;
        }

        step = connection.advancePreAdmission(
            interest == TcpConnectionIoInterest::Read,
            interest == TcpConnectionIoInterest::Write,
            tlsContext);
        assert(step.plaintextBytesRead == 0 ||
               step.plaintextBytesWritten == 0);
        totalRead += step.plaintextBytesRead;
        totalWritten += step.plaintextBytesWritten;
        assert(totalRead <= request.size());
        assert(totalWritten <= kV6LogonFailure.size());

        if (connection.gssStage() == SpnegoStage::Failed)
        {
            providerFailureObserved = true;
            assert(totalRead == request.size());
            assert(!connection.hasAdmissionLease());
        }

        if (step.status == Step::Invalid)
        {
            terminal = true;
            break;
        }
        assert(step.status == Step::Progress ||
               step.status == Step::NeedRead ||
               step.status == Step::NeedWrite);
        std::this_thread::yield();
    }

    assert(providerFailureObserved);
    assert(wrongWriteDirectionObserved);
    assert(terminal);
    assert(totalRead == request.size());
    assert(totalWritten == kV6LogonFailure.size());

    std::array<std::uint8_t, kV6LogonFailure.size()> received{};
    assert(readTlsClientAll(clientTls.get(), received));
    assert(received == kV6LogonFailure);
    assert(!connection.ready());
    assert(connection.admissionState() ==
           LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(!connection.hasAdmissionLease());

    const auto stale =
        connection.advancePreAdmission(true, true, tlsContext);
    assert(stale.status == Step::Closed);
    assert(stale.plaintextBytesRead == 0);
    assert(stale.plaintextBytesWritten == 0);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionCredSspRevocationOrder(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-connection-credssp-revoke.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));
    auto tlsContext = makeRuntimeTlsContext(fixtureDirectory, "revoke");

    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{configuration, std::move(accepted)};
        TestSsl clientTls =
            establishHybridTls(connection, clientDescriptor, tlsContext);
        const auto request = encodeCredSspServerTsRequest(
            6, CredSspServerReplyField::NegoToken, kRejectedInitialSpnego);
        assert(request.size() > 8);
        assert(writeTlsClientAll(
            clientTls.get(), std::span(request).first(8)));

        std::size_t totalRead = 0;
        bool partialFrameRetained = false;
        for (std::size_t attempt = 0; attempt < 16384; ++attempt)
        {
            const auto step = connection.onCredSspIoReady();
            totalRead += step.plaintextBytesRead;
            if (totalRead == 8 &&
                (step.status == LinuxCredSspStepStatus::NeedRead ||
                 step.status == LinuxCredSspStepStatus::NeedWrite))
            {
                partialFrameRetained = true;
                break;
            }
            assert(step.status == LinuxCredSspStepStatus::Progress ||
                   step.status == LinuxCredSspStepStatus::NeedRead ||
                   step.status == LinuxCredSspStepStatus::NeedWrite);
            assert(totalRead <= 8);
            std::this_thread::yield();
        }
        assert(partialFrameRetained);

        connection.revoke();
        assert(!connection.ready());
        assert(connection.gssStage() == SpnegoStage::Failed);
        assert(connection.admissionState() ==
               LinuxConsoleAdmissionState::Revoked);
        assert(connection.mcsPhase() == McsSessionPhase::Closed);
        assert(!connection.hasAdmissionLease());
        assert(connection.onCredSspIoReady().status ==
               LinuxCredSspStepStatus::Closed);
        connection.revoke();
        assert(connection.onCredSspIoReady().status ==
               LinuxCredSspStepStatus::Closed);
        assert(::close(clientDescriptor) == 0);
    }

    // A provider-generated terminal reply is still R2 framing state. Explicit
    // cancellation must retire it before R1 releases the exact SSL/socket.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{configuration, std::move(accepted)};
        TestSsl clientTls =
            establishHybridTls(connection, clientDescriptor, tlsContext);
        const auto request = encodeCredSspServerTsRequest(
            6, CredSspServerReplyField::NegoToken, kRejectedInitialSpnego);
        assert(writeTlsClientAll(clientTls.get(), request));

        bool failureReplyQueued = false;
        for (std::size_t attempt = 0; attempt < 16384; ++attempt)
        {
            const auto step = connection.onCredSspIoReady();
            if (step.status == LinuxCredSspStepStatus::NeedWrite)
            {
                failureReplyQueued = true;
                break;
            }
            assert(step.status == LinuxCredSspStepStatus::Progress ||
                   step.status == LinuxCredSspStepStatus::NeedRead ||
                   step.status == LinuxCredSspStepStatus::NeedWrite);
            std::this_thread::yield();
        }
        assert(failureReplyQueued);
        assert(connection.gssStage() == SpnegoStage::Failed);
        assert(connection.admissionState() ==
               LinuxConsoleAdmissionState::Ready);
        assert(connection.mcsPhase() ==
               McsSessionPhase::AwaitVerifiedR2Admission);
        assert(!connection.hasAdmissionLease());

        connection.revoke();
        assert(!connection.ready());
        assert(connection.onCredSspIoReady().status ==
               LinuxCredSspStepStatus::Closed);
        connection.revoke();
        assert(::close(clientDescriptor) == 0);
    }
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
           LinuxCredSspStepStatus::Invalid);
    assert(!connection.ready());
    assert(connection.gssStage() == SpnegoStage::Failed);
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(!connection.hasAdmissionLease());

    // Late callbacks and repeated teardown never resume the R1 owner.
    assert(connection.onCredSspIoReady().status ==
           LinuxCredSspStepStatus::Closed);
    connection.revoke();
    assert(connection.onCredSspIoReady().status ==
           LinuxCredSspStepStatus::Closed);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionFinalCredentialNativeAdmissionDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-connection-final-credential-denials.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    const std::string keytabUri = "FILE:" + keytab.string();

    LinuxRuntimeSecurityConfiguration configuration;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    assert(configuration.configure(
        kServicePrincipal, keytabUri, validRule(), "rdp-server-r2-ci"));
#else
    assert(configuration.configure(
        kServicePrincipal, keytabUri, validRule()));
#endif
    auto tlsContext =
        makeRuntimeTlsContext(fixtureDirectory, "final-credential-denials");

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    TestSsl clientTls =
        establishHybridTls(connection, clientDescriptor, tlsContext);

    assert(connection.ready());
    assert(connection.gssStage() == SpnegoStage::AwaitInitialToken);
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Ready);
    assert(connection.mcsPhase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);
    assert(!connection.hasAdmissionLease());

    // Exact HYBRID/TLS provenance and explicit PAM provisioning still cannot
    // reach NSS/logind or advance R1 to MCS. Only the private result of a real
    // GSS-bound final authInfo + PAM Authorized path can satisfy this gate.
    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};
    assert(!connection.issueAdmission(request));
    assert(!connection.ready());
    assert(connection.gssStage() == SpnegoStage::Failed);
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(!connection.hasAdmissionLease());

    clientTls.reset();
    assert(::close(clientDescriptor) == 0);
}

void testConnectionNativeMonitorBorrowDenials(
    const std::filesystem::path &fixtureDirectory)
{
    LinuxRuntimeSecurityConfiguration unconfigured;
    int rejectedClientDescriptor = -1;
    auto rejectedSocket = acceptLoopbackConnection(rejectedClientDescriptor);
    LinuxRuntimeConnection rejected{unconfigured, std::move(rejectedSocket)};
    assert(rejected.nativeChangeFd() == -1);
    assert(rejected.nativeChangeEvents() == -1);
    assert(!rejected.onNativeSessionChangeReady());
    rejected.revoke();
    assert(rejected.nativeChangeFd() == -1);
    assert(rejected.nativeChangeEvents() == -1);
    assert(::close(rejectedClientDescriptor) == 0);

    const auto keytab = fixtureDirectory / "runtime-native-borrow-denials.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));
    int clientDescriptor = -1;
    auto acceptedSocket = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(acceptedSocket)};
    assert(connection.ready());
    assert(!connection.hasAdmissionLease());
    assert(connection.nativeChangeFd() == -1);
    assert(connection.nativeChangeEvents() == -1);

    // Premature readiness cannot promote a policy-shaped connection into
    // logind admission; it terminates the R3/R2/R1 owner instead.
    assert(!connection.onNativeSessionChangeReady());
    assert(!connection.ready());
    assert(connection.nativeChangeFd() == -1);
    assert(connection.nativeChangeEvents() == -1);
    assert(connection.admissionState() == LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    connection.revoke();
    connection.revoke();
    assert(connection.nativeChangeFd() == -1);
    assert(connection.nativeChangeEvents() == -1);
    assert(!connection.onNativeSessionChangeReady());
    assert(connection.nativeChangeFd() == -1);
    assert(connection.nativeChangeEvents() == -1);
    assert(!connection.hasAdmissionLease());
    assert(::close(clientDescriptor) == 0);
}

void testConnectionNativeMonitorRegistrationDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-native-registration-denials.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto acceptedSocket = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{
        configuration, std::move(acceptedSocket)};
    assert(connection.ready());
    assert(!connection.hasAdmissionLease());
    assert(!connection.registerNativeChange());

    const LinuxRuntimeNativeChangeRegistration invented{
        41, 1, 0x1001U, 0x2001U};
    assert(!connection.unregisterNativeChange(invented));
    assert(!connection.dispatchNativeChangeReady(invented));
    assert(connection.ready());

    connection.revoke();
    assert(!connection.registerNativeChange());
    assert(!connection.unregisterNativeChange(invented));
    assert(!connection.dispatchNativeChangeReady(invented));
    assert(::close(clientDescriptor) == 0);
}

void testConnectionExistingCalUnadmittedDenial(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-existing-cal-unadmitted.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));
    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto acceptedSocket = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{
        configuration, std::move(acceptedSocket)};
    assert(connection.ready());
    assert(!connection.hasAdmissionLease());

    RuntimeLicensingContext licensingContext;
    RuntimeLicensingAuthority authority;
    assert(connection.beginExistingCalValidation(
               licensingContext, authority) ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(!connection.ready());
    assert(connection.mcsPhase() == McsSessionPhase::Closed);
    assert(connection.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(connection.cancelExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(!connection.authorizeExistingCalValidationDecision());
    assert(!connection.retireExistingCalValidationDecision());
    assert(::close(clientDescriptor) == 0);
}

void testConnectionNativeDesktopSelectionDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-native-desktop-selection-denials.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    LinuxRuntimeConnection connection{configuration, std::move(accepted)};
    assert(connection.ready());
    assert(!connection.hasAdmissionLease());

    bool visitorInvoked = false;
    const auto visitor =
        [](const rdp_server::server::security::
               LinuxNativeDesktopSelectionView &,
           void *context) noexcept {
            *static_cast<bool *>(context) = true;
            return true;
        };

    // Policy-shaped configuration and an accepted socket cannot expose a
    // DISPLAY/session selector. Only a genuine final CredSSP + PAM + NSS/
    // logind lease can enter the synchronous selection visitor.
    assert(!connection.visitNativeDesktopSelection(
        visitor, &visitorInvoked));
    assert(!visitorInvoked);
    assert(!connection.ready());
    assert(!connection.hasAdmissionLease());
    assert(connection.admissionState() ==
           LinuxConsoleAdmissionState::Revoked);
    assert(connection.mcsPhase() == McsSessionPhase::Closed);

    // Late/replayed consumer attempts stay terminal and never invoke R10.
    assert(!connection.visitNativeDesktopSelection(
        visitor, &visitorInvoked));
    assert(!visitorInvoked);
    connection.revoke();
    connection.revoke();
    assert(!connection.visitNativeDesktopSelection(
        visitor, &visitorInvoked));
    assert(!visitorInvoked);
    assert(::close(clientDescriptor) == 0);
}

void testConnectionPersonalDesktopLicenseRequestR1WriteDenials(
    const std::filesystem::path &fixtureDirectory)
{
    using Step = LinuxPersonalDesktopLicenseWriteStepStatus;

    const auto keytab =
        fixtureDirectory / "runtime-personal-license-r1-write.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy personalPolicy;
    assert(personalPolicy.configurePersonalDesktop(false, 0U));
    RuntimeDeploymentPolicy appServerPolicy;
    assert(appServerPolicy.configureAppServerIssuerBacked());
    RuntimeLicensingContext licensingContext;

    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        const auto denied =
            connection.advancePersonalDesktopServerLicenseRequestWrite(
                personalPolicy, licensingContext, false, true);
        assert(denied.status == Step::AdmissionDenied);
        assert(denied.plaintextBytesWritten == 0U);
        assert(!connection.ready());

        const auto replay =
            connection.advancePersonalDesktopServerLicenseRequestWrite(
                personalPolicy, licensingContext, true, true);
        assert(replay.status == Step::Closed);
        assert(replay.plaintextBytesWritten == 0U);
        assert(::close(clientDescriptor) == 0);
    }

    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        const auto denied =
            connection.advancePersonalDesktopServerLicenseRequestWrite(
                appServerPolicy, licensingContext, true, true);
        assert(denied.status == Step::AdmissionDenied);
        assert(denied.plaintextBytesWritten == 0U);
        assert(!connection.ready());
        assert(::close(clientDescriptor) == 0);
    }
}

void testConnectionPersonalDesktopPolicyReceiptDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-personal-policy-receipt.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy selectedPolicy;
    RuntimeDeploymentPolicy replacementPolicy;
    RuntimeDeploymentPolicy appServerPolicy;
    assert(selectedPolicy.configurePersonalDesktop(false, 0U));
    assert(replacementPolicy.configurePersonalDesktop(false, 0U));
    assert(appServerPolicy.configureAppServerIssuerBacked());

    LinuxConsoleAdmissionBroker broker(*configuration.policy());
    LinuxConsoleAdmissionBrokerTestAccess::bindPersonalDesktopPolicy(
        broker, selectedPolicy);

    // Policy equality is object identity, not equivalent configuration text.
    // This fixture manipulates only the non-authorizing pointer bookkeeping;
    // it never creates a positive R2 admission capability.
    assert(LinuxConsoleAdmissionBrokerTestAccess::personalDesktopPolicyMatches(
        broker, selectedPolicy));
    assert(!LinuxConsoleAdmissionBrokerTestAccess::personalDesktopPolicyMatches(
        broker, replacementPolicy));
    assert(!LinuxConsoleAdmissionBrokerTestAccess::personalDesktopPolicyMatches(
        broker, appServerPolicy));

    GssapiSpnegoAcceptor acceptor;
    assert(configuration.configureAcceptor(acceptor));

    McsSessionLifecycle session;
    McsSessionLifecycleTestAccess::stagePersonalDesktopSelection(
        session, 47U, 83U);
    assert(McsSessionLifecycleTestAccess::selectPersonalDesktop(session));
    assert(session.phase() == McsSessionPhase::AwaitServerLicenseRequest);

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    rdp_server::server::transport::OwnedPreauthTcpConnection r1Connection{
        std::move(accepted)};

    // A transport may already have accepted plaintext before logout or
    // disconnect. Without the live lease the R2 receipt boundary closes R3
    // before the byte count can become durable licensing progress.
    assert(broker.completeR3PersonalDesktopServerLicenseRequestWrite(
               nullptr, acceptor, r1Connection, session, selectedPolicy,
               1U, 1U, 7U) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(!LinuxConsoleAdmissionBrokerTestAccess::personalDesktopPolicyMatches(
        broker, selectedPolicy));
    assert(::close(clientDescriptor) == 0);
}

void testConnectionPersonalDesktopClientLicensingR1IntakeDenials(
    const std::filesystem::path &fixtureDirectory)
{
    using Step = LinuxPersonalDesktopClientLicensingStepStatus;

    // The production fixed-capacity TPKT owner must retain an incomplete
    // licensing-candidate frame without treating truncation as completion.
    {
        LinuxRuntimeMcsTpktFrameReader reader;
        constexpr std::array<std::uint8_t, 12> licensingCandidate{
            3U, 0U, 0U, 12U, 0x02U, 0xf0U, 0x80U, 0x64U,
            0U, 0U, 0U, 0U};
        const auto partial = reader.consume(
            std::span<const std::uint8_t>{licensingCandidate}.first(7U));
        assert(partial.bytesConsumed == 7U);
        assert(partial.status == LinuxRuntimeMcsTpktFrameStatus::NeedMore);
        assert(reader.bytesNeeded() == 5U);
        assert(reader.completeTpkt().empty());
        reader.close();
        assert(reader.status() == LinuxRuntimeMcsTpktFrameStatus::Closed);
    }

    // A TPKT length below the minimum X.224 envelope is terminal before R3.
    {
        LinuxRuntimeMcsTpktFrameReader reader;
        constexpr std::array<std::uint8_t, 4> malformed{
            3U, 0U, 0U, 7U};
        const auto rejected = reader.consume(
            std::span<const std::uint8_t>{malformed});
        assert(rejected.bytesConsumed == malformed.size());
        assert(rejected.status == LinuxRuntimeMcsTpktFrameStatus::Invalid);
        assert(reader.completeTpkt().empty());
    }

    const auto keytab =
        fixtureDirectory / "runtime-personal-client-licensing-intake.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy personalPolicy;
    assert(personalPolicy.configurePersonalDesktop(false, 0U));
    RuntimeDeploymentPolicy appServerPolicy;
    assert(appServerPolicy.configureAppServerIssuerBacked());
    RuntimeLicensingContext licensingContext;

    // A correctly shaped product policy is powerless without a genuine R2
    // lease and prior policy selection. No TLS read is attempted and replay is
    // terminal after the aggregate revokes.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        const auto denied =
            connection.advancePersonalDesktopClientLicensingIntake(
                personalPolicy, licensingContext, true, true);
        assert(denied.status == Step::AdmissionDenied);
        assert(denied.plaintextBytesRead == 0U);
        assert(!connection.ready());

        const auto replay =
            connection.advancePersonalDesktopClientLicensingIntake(
                personalPolicy, licensingContext, true, true);
        assert(replay.status == Step::Closed);
        assert(replay.plaintextBytesRead == 0U);
        assert(::close(clientDescriptor) == 0);
    }

    // AppServerIssuerBacked cannot enter the PersonalDesktop R1/R2/R3 route.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        const auto denied =
            connection.advancePersonalDesktopClientLicensingIntake(
                appServerPolicy, licensingContext, true, true);
        assert(denied.status == Step::AdmissionDenied);
        assert(denied.plaintextBytesRead == 0U);
        assert(!connection.ready());
        assert(::close(clientDescriptor) == 0);
    }
}

void testConnectionPersonalDesktopValidClientR1WriteDenials(
    const std::filesystem::path &fixtureDirectory)
{
    using Step = LinuxPersonalDesktopValidClientWriteStepStatus;

    const auto keytab =
        fixtureDirectory / "runtime-personal-valid-client-r1-write.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy personalPolicy;
    assert(personalPolicy.configurePersonalDesktop(false, 0U));
    RuntimeDeploymentPolicy appServerPolicy;
    assert(appServerPolicy.configureAppServerIssuerBacked());

    // STATUS_VALID_CLIENT cannot reach R1 before genuine R2 admission and the
    // preceding receipt-bound licensing intake. Replay remains terminal.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};

        const auto denied =
            connection.advancePersonalDesktopValidClientWrite(
                personalPolicy, false, true);
        assert(denied.status == Step::AdmissionDenied);
        assert(denied.plaintextBytesWritten == 0U);
        assert(!connection.ready());

        const auto replay =
            connection.advancePersonalDesktopValidClientWrite(
                personalPolicy, true, true);
        assert(replay.status == Step::Closed);
        assert(replay.plaintextBytesWritten == 0U);
        assert(::close(clientDescriptor) == 0);
    }

    // The issuer-backed mode cannot enter the personal Valid Client writer.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};

        const auto denied =
            connection.advancePersonalDesktopValidClientWrite(
                appServerPolicy, true, true);
        assert(denied.status == Step::AdmissionDenied);
        assert(denied.plaintextBytesWritten == 0U);
        assert(!connection.ready());
        assert(::close(clientDescriptor) == 0);
    }
}

void testConnectionPersonalDesktopShareR1IoDenials(
    const std::filesystem::path &fixtureDirectory)
{
    using Step = LinuxPersonalDesktopShareActivationStepStatus;

    // Share needs several client TPKTs, so the production fixed-capacity
    // framer must be reusable only after a completed packet is consumed.
    {
        LinuxRuntimeMcsTpktFrameReader reader;
        constexpr std::array<std::uint8_t, 8> packet{
            3U, 0U, 0U, 8U, 0x02U, 0xf0U, 0x80U, 0U};
        const auto first = reader.consume(packet);
        assert(first.bytesConsumed == packet.size());
        assert(first.status == LinuxRuntimeMcsTpktFrameStatus::Complete);
        assert(reader.completeTpkt().size() == packet.size());
        assert(reader.reset());
        assert(reader.status() == LinuxRuntimeMcsTpktFrameStatus::NeedMore);
        assert(reader.bytesNeeded() == 4U);

        const auto second = reader.consume(packet);
        assert(second.bytesConsumed == packet.size());
        assert(second.status == LinuxRuntimeMcsTpktFrameStatus::Complete);
        reader.close();
        assert(!reader.reset());
    }

    const auto keytab =
        fixtureDirectory / "runtime-personal-share-r1-io.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy personalPolicy;
    assert(personalPolicy.configurePersonalDesktop(false, 0U));
    RuntimeDeploymentPolicy appServerPolicy;
    assert(appServerPolicy.configureAppServerIssuerBacked());
    constexpr std::array<std::uint8_t, 4> sourceDescriptor{
        'r', 'd', 'p', 0};

    // Share cannot begin from configuration or a socket alone. Failure
    // revokes the aggregate and a later scheduler call stays closed.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};

        assert(!connection.startPersonalDesktopShareActivation(
            personalPolicy, 0x10001U, 1U, sourceDescriptor, 0U, {}));
        assert(!connection.ready());

        const auto replay =
            connection.advancePersonalDesktopShareActivation(
                personalPolicy, true, true);
        assert(replay.status == Step::Closed);
        assert(replay.plaintextBytesRead == 0U);
        assert(replay.plaintextBytesWritten == 0U);
        assert(::close(clientDescriptor) == 0);
    }

    // Wrong product mode is terminal before Demand Active can reach R1.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};

        assert(!connection.startPersonalDesktopShareActivation(
            appServerPolicy, 0x10001U, 1U, sourceDescriptor, 0U, {}));
        assert(!connection.ready());
        assert(::close(clientDescriptor) == 0);
    }
}

void testConnectionPersonalDesktopGraphicsDvcAuthorityDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-personal-graphics-dvc-authority.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy personalPolicy;
    assert(personalPolicy.configurePersonalDesktop(false, 0U));

    LinuxConsoleAdmissionBroker broker(*configuration.policy());
    LinuxConsoleAdmissionBrokerTestAccess::bindPersonalDesktopPolicy(
        broker, personalPolicy);

    GssapiSpnegoAcceptor acceptor;
    assert(configuration.configureAcceptor(acceptor));

    McsSessionLifecycle session;
    McsSessionLifecycleTestAccess::stageShareActivated(
        session, 91U, 123U);
    assert(session.phase() == McsSessionPhase::ShareActivated);

    int clientDescriptor = -1;
    auto accepted = acceptLoopbackConnection(clientDescriptor);
    rdp_server::server::transport::OwnedPreauthTcpConnection r1Connection{
        std::move(accepted)};

    // R1 may already have accepted a positive plaintext slice when logout,
    // disconnect or policy/native authority loss becomes visible. A missing
    // live lease must close R3 before that late receipt can advance the DVC.
    // This fixture stages only R3 phase bookkeeping; it does not create a DVC
    // allocation or fabricate an R2 admission capability.
    assert(broker.completeR3PersonalDesktopGraphicsDynamicVirtualChannelWrite(
               nullptr, acceptor, r1Connection, session, personalPolicy,
               1U, 1U, 13U) == RdpGraphicsDvcWriteOutcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(!LinuxConsoleAdmissionBrokerTestAccess::personalDesktopPolicyMatches(
        broker, personalPolicy));
    assert(::close(clientDescriptor) == 0);
}

void testConnectionPersonalDesktopR3AuthorityDenials(
    const std::filesystem::path &fixtureDirectory)
{
    const auto keytab =
        fixtureDirectory / "runtime-personal-desktop-r3-authority.keytab";
    assert(writeSyntheticKeytab(keytab, kServicePrincipal));

    LinuxRuntimeSecurityConfiguration configuration;
    assert(configuration.configure(
        kServicePrincipal, "FILE:" + keytab.string(), validRule()));

    RuntimeDeploymentPolicy personalPolicy;
    assert(personalPolicy.configurePersonalDesktop(false, 0U));
    RuntimeDeploymentPolicy wrongModePolicy;
    assert(wrongModePolicy.configureAppServerIssuerBacked());

    // Mode mismatch is terminal even though this fixture has no admission
    // lease. Configuration policy alone can never select the R3 branch.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        assert(connection.ready());
        assert(!connection.hasAdmissionLease());
        assert(!connection.selectPersonalDesktopLicensingMode(
            wrongModePolicy));
        assert(!connection.ready());
        assert(connection.mcsPhase() == McsSessionPhase::Closed);
        assert(::close(clientDescriptor) == 0);
    }

    // A correct immutable policy is still powerless before genuine final
    // CredSSP/PAM/NSS/logind admission. Repeated selection cannot create a
    // capability and late callbacks remain terminal.
    {
        int clientDescriptor = -1;
        auto accepted = acceptLoopbackConnection(clientDescriptor);
        LinuxRuntimeConnection connection{
            configuration, std::move(accepted)};
        assert(connection.ready());
        assert(!connection.hasAdmissionLease());
        assert(!connection.selectPersonalDesktopLicensingMode(personalPolicy));
        assert(!connection.selectPersonalDesktopLicensingMode(personalPolicy));
        assert(!connection.authorizePersonalDesktopValidClientWrite(
            personalPolicy));
        assert(connection.completePersonalDesktopValidClientWrite(
                   personalPolicy, 1U, 1U, 1U) ==
               RdpPersonalDesktopValidClientWriteOutcome::Rejected);

        constexpr std::array<std::uint8_t, 4> sourceDescriptor{
            'r', 'd', 'p', 0};
        assert(!connection.beginPersonalDesktopShareActivation(
            personalPolicy, 0x10001U, 1U, sourceDescriptor, 0U, {}));
        assert(!connection.authorizePersonalDesktopShareActivationWrite(
            personalPolicy));
        assert(connection.completePersonalDesktopShareActivationWrite(
                   personalPolicy, 1U, 1U, 1U) ==
               RdpShareActivationWriteOutcome::Rejected);
        assert(connection.acceptPersonalDesktopShareActivationPdu(
                   personalPolicy, {}) ==
               RdpShareActivationClientIntake::Rejected);
        assert(!connection.authorizePersonalDesktopApplicationTraffic(
            personalPolicy));

        // Explicit cancellation and repeated teardown cannot make a late
        // accepted-byte receipt or intake durable.
        connection.revoke();
        connection.revoke();
        assert(connection.completePersonalDesktopValidClientWrite(
                   personalPolicy, 1U, 1U, 1U) ==
               RdpPersonalDesktopValidClientWriteOutcome::Rejected);
        assert(connection.completePersonalDesktopShareActivationWrite(
                   personalPolicy, 1U, 1U, 1U) ==
               RdpShareActivationWriteOutcome::Rejected);
        assert(connection.acceptPersonalDesktopShareActivationPdu(
                   personalPolicy, {}) ==
               RdpShareActivationClientIntake::Rejected);
        assert(!connection.authorizePersonalDesktopApplicationTraffic(
            personalPolicy));
        assert(::close(clientDescriptor) == 0);
    }

    // R3's existing private selector/fence are exercised without fabricating
    // R2 authority: test-only protocol bookkeeping proves duplicate selection
    // and stale generation replacement are terminal before any wire owner can
    // be reused. Positive broker admission remains owner-host-only.
    {
        McsSessionLifecycle duplicate;
        McsSessionLifecycleTestAccess::stagePersonalDesktopSelection(
            duplicate, 41U, 73U);
        assert(McsSessionLifecycleTestAccess::selectPersonalDesktop(
            duplicate));
        assert(!McsSessionLifecycleTestAccess::selectPersonalDesktop(
            duplicate));
        assert(duplicate.phase() == McsSessionPhase::Closed);

        McsSessionLifecycle stale;
        McsSessionLifecycleTestAccess::stagePersonalDesktopSelection(
            stale, 43U, 79U);
        stale.revokeUnlessAdmissionBindingMatches(43U, 79U);
        assert(stale.phase() == McsSessionPhase::AwaitServerLicenseRequest);
        stale.revokeUnlessAdmissionBindingMatches(43U, 80U);
        assert(stale.phase() == McsSessionPhase::Closed);
    }
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
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    if (testCase == "linux-security-pam-verifier-provisioning")
    {
        testPamVerifierProvisioning(fixtureDirectory);
        return 0;
    }
#endif
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
    if (testCase == "linux-connection-credssp-owner-framing")
    {
        testConnectionCredSspOwnerFraming(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-credssp-progress-accounting")
    {
        testConnectionCredSspProgressAccounting(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-pre-admission-dispatch")
    {
        testConnectionPreAdmissionDispatch(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-post-admission-mcs-framing-denials")
    {
        testConnectionPostAdmissionMcsFramingDenials(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-credssp-revocation-order")
    {
        testConnectionCredSspRevocationOrder(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-credssp-authorization-denials")
    {
        testConnectionCredSspAuthorizationDenials(fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-final-credential-native-admission-denials")
    {
        testConnectionFinalCredentialNativeAdmissionDenials(
            fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-aggregate-ordered-revocation")
    {
        testConnectionAggregateOrderedRevocation(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-native-monitor-borrow-denials")
    {
        testConnectionNativeMonitorBorrowDenials(fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-native-monitor-registration-denials")
    {
        testConnectionNativeMonitorRegistrationDenials(fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-native-desktop-selection-denials")
    {
        testConnectionNativeDesktopSelectionDenials(fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-license-request-r1-write-denials")
    {
        testConnectionPersonalDesktopLicenseRequestR1WriteDenials(
            fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-desktop-policy-receipt-denials")
    {
        testConnectionPersonalDesktopPolicyReceiptDenials(fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-client-licensing-r1-intake-denials")
    {
        testConnectionPersonalDesktopClientLicensingR1IntakeDenials(
            fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-share-r1-io-denials")
    {
        testConnectionPersonalDesktopShareR1IoDenials(fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-desktop-graphics-dvc-authority-denials")
    {
        testConnectionPersonalDesktopGraphicsDvcAuthorityDenials(
            fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-valid-client-r1-write-denials")
    {
        testConnectionPersonalDesktopValidClientR1WriteDenials(
            fixtureDirectory);
        return 0;
    }
    if (testCase ==
        "linux-connection-personal-desktop-r3-authority-denials")
    {
        testConnectionPersonalDesktopR3AuthorityDenials(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-existing-cal-unadmitted-denial")
    {
        testConnectionExistingCalUnadmittedDenial(fixtureDirectory);
        return 0;
    }
    if (testCase == "linux-connection-aggregate-premature-admission-denial")
    {
        testConnectionAggregatePrematureAdmissionDenial(fixtureDirectory);
        return 0;
    }
    return 2;
}
