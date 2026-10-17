// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_connection.h"
#include "server/runtime/linux_runtime_security.h"
#include "server/security/linux_console_admission.h"

#include <krb5.h>

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

namespace
{
using rdp_server::server::runtime::LinuxCredSspStepStatus;
using rdp_server::server::runtime::LinuxPreAdmissionStepStatus;
using rdp_server::server::runtime::LinuxRuntimeConnection;
using rdp_server::server::runtime::LinuxRuntimeNativeChangeRegistration;
using rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration;
using rdp_server::server::runtime::RuntimeLicensingAuthority;
using rdp_server::server::runtime::RuntimeLicensingContext;
using rdp_server::server::runtime::RuntimeLicensingExistingCalOperation;
using rdp_server::server::runtime::RuntimeServerTlsContext;
using rdp_server::server::security::ConsoleEvidenceRequest;
using rdp_server::server::security::ConsoleIdentityRuleInput;
using rdp_server::server::security::CredSspServerReplyField;
using rdp_server::server::security::GssapiSpnegoAcceptor;
using rdp_server::server::security::encodeCredSspServerTsRequest;
using rdp_server::server::security::LinuxConsoleAdmissionBroker;
using rdp_server::server::security::LinuxConsoleAdmissionState;
using rdp_server::server::security::SpnegoStage;
using rdp_server::server::security::kConsoleClipboardPermission;
using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;
using rdp_server::server::transport::McsSessionPhase;
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
