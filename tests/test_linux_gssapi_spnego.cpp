// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/gssapi_spnego_acceptor.h"
#include "security/gssapi_console_gate.h"
#include "security/linux_console_admission.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

using namespace rdp_server::server::security;
using rdp_server::server::transport::McsSessionIntake;
using rdp_server::server::transport::McsSessionLifecycle;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::NativeTcpIo;
using rdp_server::server::transport::OwnedNativeTcpSocket;
using rdp_server::server::transport::OwnedPreauthTcpConnection;
using rdp_server::server::transport::RdpLicensingIntake;
using rdp_server::server::transport::RdpLicensingLifecycle;
using rdp_server::server::transport::RdpLicensingPhase;
using rdp_server::server::transport::RdpLicensingServiceCredential;
using rdp_server::server::transport::RdpServerLicenseIdentity;
using rdp_server::server::transport::RdpServerLicenseRequestFields;
using rdp_server::server::transport::RdpServerLicenseRequestWriteGate;
using rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome;
using rdp_server::server::transport::RdpServerLicenseRequestWriteView;
using rdp_server::server::transport::RdpServerPlatformChallengeWriteOutcome;
using rdp_server::server::transport::RdpServerPlatformChallengeWriteView;
using rdp_server::server::transport::SecurityNegotiationProvenance;
using rdp_server::server::transport::TcpAcceptOutcome;
using rdp_server::server::transport::TcpIoOutcome;
using rdp_server::server::transport::TcpPreauthEvent;
using rdp_server::server::transport::TlsHandshakeStatus;
using rdp_server::server::transport::acceptNonblockingTcpConnection;
using rdp_server::server::transport::attachNonblockingTcpBio;
using rdp_server::server::transport::kRdpProtocolHybrid;
using rdp_server::server::transport::kRdpProtocolSsl;

namespace
{

constexpr std::array<std::uint8_t, 21> kInitialTsRequest{
    0x30, 0x13, 0xa0, 0x03, 0x02, 0x01, 0x06,
    0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08,
    0xa0, 0x06, 0x04, 0x04, 0x60, 0x82, 0x01, 0x00};

constexpr std::array<std::uint8_t, 19> kDiagnosticSslRequest{
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00};

[[nodiscard]] constexpr std::array<std::uint8_t, 19>
diagnosticSslAndHybridRequest() noexcept
{
    auto request = kDiagnosticSslRequest;
    request[15] = static_cast<std::uint8_t>(
        kRdpProtocolSsl | kRdpProtocolHybrid);
    return request;
}

inline constexpr auto kDiagnosticSslAndHybridRequest =
    diagnosticSslAndHybridRequest();

class LocalSocket final
{
public:
    LocalSocket() noexcept = default;
    LocalSocket(const LocalSocket &) = delete;
    LocalSocket &operator=(const LocalSocket &) = delete;
    ~LocalSocket()
    {
        if (value_ >= 0)
        {
            (void)::close(value_);
        }
    }

    [[nodiscard]] int value() const noexcept { return value_; }

    void reset(int value) noexcept
    {
        if (value_ >= 0)
        {
            (void)::close(value_);
        }
        value_ = value;
    }

private:
    int value_{-1};
};

void setNonblocking(int socket)
{
    const int flags = ::fcntl(socket, F_GETFL, 0);
    assert(flags >= 0);
    assert(::fcntl(socket, F_SETFL, flags | O_NONBLOCK) == 0);
}

void sendAll(NativeTcpIo &io, std::span<const std::uint8_t> bytes)
{
    std::size_t offset = 0;
    for (std::size_t attempt = 0;
         attempt < 16384 && offset < bytes.size(); ++attempt)
    {
        const auto result = io.send(bytes.subspan(offset));
        if (result.outcome == TcpIoOutcome::Progress)
        {
            assert(result.bytes > 0 &&
                   result.bytes <= bytes.size() - offset);
            offset += result.bytes;
            continue;
        }
        assert(result.outcome == TcpIoOutcome::WouldBlock);
        assert(result.bytes == 0);
        std::this_thread::yield();
    }
    assert(offset == bytes.size());
}

void receiveAll(NativeTcpIo &io, std::span<std::uint8_t> bytes)
{
    std::size_t offset = 0;
    for (std::size_t attempt = 0;
         attempt < 16384 && offset < bytes.size(); ++attempt)
    {
        const auto result = io.receive(bytes.subspan(offset));
        if (result.outcome == TcpIoOutcome::Progress)
        {
            assert(result.bytes > 0 &&
                   result.bytes <= bytes.size() - offset);
            offset += result.bytes;
            continue;
        }
        assert(result.outcome == TcpIoOutcome::WouldBlock);
        assert(result.bytes == 0);
        std::this_thread::yield();
    }
    assert(offset == bytes.size());
}

using ContextPointer = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPointer = std::unique_ptr<SSL, decltype(&SSL_free)>;
using KeyPointer = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CertificatePointer = std::unique_ptr<X509, decltype(&X509_free)>;
using X509NamePointer = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;

class R1DiagnosticTlsFixture final
{
public:
    explicit R1DiagnosticTlsFixture(
        std::span<const std::uint8_t> request,
        bool completeTlsHandshake)
    {
        listener_.reset(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        assert(listener_.value() >= 0);

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        assert(::bind(
                   listener_.value(),
                   reinterpret_cast<const sockaddr *>(&address),
                   sizeof(address)) == 0);
        assert(::listen(listener_.value(), 1) == 0);
        setNonblocking(listener_.value());

        socklen_t addressLength = sizeof(address);
        assert(::getsockname(
                   listener_.value(),
                   reinterpret_cast<sockaddr *>(&address),
                   &addressLength) == 0);

        client_.reset(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        assert(client_.value() >= 0);
        assert(::connect(
                   client_.value(),
                   reinterpret_cast<const sockaddr *>(&address),
                   sizeof(address)) == 0);
        setNonblocking(client_.value());

        rdp_server::server::transport::TcpAcceptResult accepted{};
        for (std::size_t attempt = 0; attempt < 16384; ++attempt)
        {
            accepted = acceptNonblockingTcpConnection(
                static_cast<std::uintptr_t>(listener_.value()));
            if (accepted.outcome == TcpAcceptOutcome::Accepted)
            {
                break;
            }
            assert(accepted.outcome == TcpAcceptOutcome::WouldBlock);
            std::this_thread::yield();
        }
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        assert(accepted.connection.valid());

        connection_ = std::make_unique<OwnedPreauthTcpConnection>(
            std::move(accepted.connection));
        clientIo_ = std::make_unique<NativeTcpIo>(
            static_cast<std::uintptr_t>(client_.value()));
        assert(connection_->active());
        sendAll(*clientIo_, request);

        TcpPreauthEvent preauth = TcpPreauthEvent::NeedRead;
        for (std::size_t attempt = 0; attempt < 16384; ++attempt)
        {
            preauth = connection_->onReadable();
            if (preauth != TcpPreauthEvent::NeedRead)
            {
                break;
            }
            std::this_thread::yield();
        }
        assert(preauth == TcpPreauthEvent::NeedWrite);

        for (std::size_t attempt = 0; attempt < 16384; ++attempt)
        {
            preauth = connection_->onWritable();
            if (preauth != TcpPreauthEvent::NeedWrite)
            {
                break;
            }
            std::this_thread::yield();
        }
        assert(preauth == TcpPreauthEvent::ReadyForTls);

        std::array<std::uint8_t, 19> response{};
        receiveAll(*clientIo_, response);
        assert(response[11] == 0x02);
        assert(response[15] ==
               static_cast<std::uint8_t>(kRdpProtocolSsl));
        assert(response[16] == 0 && response[17] == 0 && response[18] == 0);

        createTlsObjects();
        OwnedPreauthTcpConnection::ServerTls server{
            serverTls_.release(), SSL_free};
        assert(connection_->attachServerTls(std::move(server)));
        assert(attachNonblockingTcpBio(clientTls_.get(), *clientIo_));

        if (completeTlsHandshake)
        {
            completeHandshake();
        }
    }

    [[nodiscard]] OwnedPreauthTcpConnection &connection() noexcept
    {
        return *connection_;
    }

private:
    void createTlsObjects()
    {
        serverContext_.reset(SSL_CTX_new(TLS_server_method()));
        clientContext_.reset(SSL_CTX_new(TLS_client_method()));
        assert(serverContext_ && clientContext_);
        assert(SSL_CTX_set_min_proto_version(
                   serverContext_.get(), TLS1_2_VERSION) == 1);
        assert(SSL_CTX_set_min_proto_version(
                   clientContext_.get(), TLS1_2_VERSION) == 1);

        const KeyPointer key{EVP_EC_gen("prime256v1"), EVP_PKEY_free};
        const CertificatePointer certificate{X509_new(), X509_free};
        assert(key && certificate);
        assert(X509_set_version(certificate.get(), 2) == 1);
        assert(ASN1_INTEGER_set(
                   X509_get_serialNumber(certificate.get()), 1) == 1);
        assert(X509_gmtime_adj(
            X509_getm_notBefore(certificate.get()), -60));
        assert(X509_gmtime_adj(
            X509_getm_notAfter(certificate.get()), 3600));
        assert(X509_set_pubkey(certificate.get(), key.get()) == 1);

        const X509NamePointer name{X509_NAME_new(), X509_NAME_free};
        assert(name);
        assert(X509_NAME_add_entry_by_txt(
                   name.get(), "CN", MBSTRING_ASC,
                   reinterpret_cast<const unsigned char *>(
                       "rdp-r2-provenance-test"),
                   -1, -1, 0) == 1);
        assert(X509_set_subject_name(certificate.get(), name.get()) == 1);
        assert(X509_set_issuer_name(certificate.get(), name.get()) == 1);
        assert(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);
        assert(SSL_CTX_use_certificate(
                   serverContext_.get(), certificate.get()) == 1);
        assert(SSL_CTX_use_PrivateKey(
                   serverContext_.get(), key.get()) == 1);
        assert(SSL_CTX_check_private_key(serverContext_.get()) == 1);

        serverTls_.reset(SSL_new(serverContext_.get()));
        clientTls_.reset(SSL_new(clientContext_.get()));
        assert(serverTls_ && clientTls_);
        SSL_set_accept_state(serverTls_.get());
        SSL_set_connect_state(clientTls_.get());
    }

    void completeHandshake()
    {
        bool clientEstablished = false;
        bool serverEstablished = false;
        for (std::size_t attempt = 0; attempt < 16384; ++attempt)
        {
            if (!clientEstablished)
            {
                const int result = SSL_do_handshake(clientTls_.get());
                if (result == 1)
                {
                    clientEstablished = true;
                }
                else
                {
                    const int error =
                        SSL_get_error(clientTls_.get(), result);
                    assert(error == SSL_ERROR_WANT_READ ||
                           error == SSL_ERROR_WANT_WRITE);
                }
            }

            if (!serverEstablished)
            {
                const auto result = connection_->onTlsIoReady();
                assert(result == TlsHandshakeStatus::NeedRead ||
                       result == TlsHandshakeStatus::NeedWrite ||
                       result == TlsHandshakeStatus::Established);
                serverEstablished =
                    result == TlsHandshakeStatus::Established;
            }

            if (clientEstablished && serverEstablished)
            {
                break;
            }
            std::this_thread::yield();
        }
        assert(clientEstablished && serverEstablished);
        assert(connection_->establishedTls() != nullptr);
    }

    LocalSocket listener_{};
    LocalSocket client_{};
    ContextPointer serverContext_{nullptr, SSL_CTX_free};
    ContextPointer clientContext_{nullptr, SSL_CTX_free};
    // The client BIO borrows clientIo_, so destroy client SSL first.
    std::unique_ptr<NativeTcpIo> clientIo_{};
    SslPointer serverTls_{nullptr, SSL_free};
    SslPointer clientTls_{nullptr, SSL_free};
    std::unique_ptr<OwnedPreauthTcpConnection> connection_{};
};


void testConfigurationRejections()
{
    GssapiSpnegoAcceptor missingKeytab;
    assert(missingKeytab.stage() == SpnegoStage::Unconfigured);
    // No environment/default keytab is allowed; this path is deliberately
    // nonexistent. Exercise the real MIT GSS acquire-cred-from provider.
    assert(!missingKeytab.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));
    assert(missingKeytab.stage() == SpnegoStage::Failed);
    assert(missingKeytab.verifiedPrincipal().empty());
    const auto diagnostics = missingKeytab.configurationDiagnostics();
    assert(diagnostics.stage == GssConfigurationFailure::ImportService ||
           diagnostics.stage == GssConfigurationFailure::AcquireCredentials);
    // A failed provider instance cannot be reconfigured or resurrected.
    assert(!missingKeytab.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));

    GssapiSpnegoAcceptor noService;
    assert(!noService.configure(
        "host/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));
    assert(noService.stage() == SpnegoStage::Failed);
    assert(noService.configurationDiagnostics().stage ==
           GssConfigurationFailure::InvalidOptions);

    GssapiSpnegoAcceptor relativeKeytab;
    assert(!relativeKeytab.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:relative.keytab"));
    assert(relativeKeytab.stage() == SpnegoStage::Failed);

    // Initial SPNEGO tag and OID validation is syntax only; the provider
    // still must authenticate an actual GSS token after configuration.
    constexpr std::array<std::uint8_t, 11> spnegoToken{
        0x60, 0x09, 0x06, 0x06, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x02, 0xa0};
    assert(isInitialSpnegoToken(spnegoToken));
    auto wrongOid = spnegoToken;
    wrongOid[7] ^= 0x01U;
    assert(!isInitialSpnegoToken(wrongOid));
    assert(!isInitialSpnegoToken({}));

    // The protected binding request recognizer is NOT a trust check and
    // cannot grant user or console authorization.
    std::array<std::uint8_t, 48> protectedBinding{
        0x30, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa3, 0x03, 0x04, 0x01, 0x55,
        0xa5, 0x22, 0x04, 0x20};
    for (std::size_t offset = 16; offset < protectedBinding.size(); ++offset)
    {
        protectedBinding[offset] = 0x42;
    }
    assert(isCredSspPublicKeyAuthRequest(protectedBinding));
    protectedBinding[6] = 4; // v4 cannot use v5/v6 public-key nonce binding.
    assert(!isCredSspPublicKeyAuthRequest(protectedBinding));
    protectedBinding[6] = 6;
    protectedBinding[15] = 31; // malformed nonce size.
    assert(!isCredSspPublicKeyAuthRequest(protectedBinding));
}

void testFramedGssHandoffFailClosed()
{
    // No configured credentials and no GSS security context. Even a valid
    // DER TSRequest cannot authenticate a user or trigger a reply.
    GssapiSpnegoAcceptor unconfigured;
    TsRequestFrameReader reader;
    const auto framed = reader.consume(kInitialTsRequest);
    assert(framed.status == TsRequestFrameStatus::Complete);
    assert(framed.bytesConsumed == kInitialTsRequest.size());
    const auto result = unconfigured.acceptFramedNegoRequest(reader);
    assert(result.status == SpnegoStatus::Rejected);
    assert(result.outputToken.empty());
    assert(unconfigured.stage() == SpnegoStage::Failed);
    assert(unconfigured.verifiedPrincipal().empty());
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(reader.completeDer().empty());
    assert(reader.bytesNeeded() == 0);

    GssapiSpnegoAcceptor premature;
    TsRequestFrameReader incomplete;
    assert(incomplete.consume(
        std::span(kInitialTsRequest).first(4)).status ==
        TsRequestFrameStatus::NeedMore);
    assert(premature.acceptFramedNegoRequest(incomplete).status ==
           SpnegoStatus::Rejected);
    assert(incomplete.status() == TsRequestFrameStatus::Closed);
    assert(premature.stage() == SpnegoStage::Failed);

    GssapiSpnegoAcceptor unsupportedVersion;
    TsRequestFrameReader oldVersion;
    auto downgraded = kInitialTsRequest;
    downgraded[6] = 4;
    assert(oldVersion.consume(downgraded).status ==
           TsRequestFrameStatus::Complete);
    assert(unsupportedVersion.acceptFramedNegoRequest(oldVersion).status ==
           SpnegoStatus::Rejected);
    assert(unsupportedVersion.stage() == SpnegoStage::Failed);
    assert(oldVersion.completeDer().empty());
    assert(oldVersion.status() == TsRequestFrameStatus::Closed);

    GssapiSpnegoAcceptor malformed;
    TsRequestFrameReader rejectedFrame;
    const std::array<std::uint8_t, 2> wrongTag{0x31, 0x00};
    assert(rejectedFrame.consume(wrongTag).status ==
           TsRequestFrameStatus::Invalid);
    assert(malformed.acceptFramedNegoRequest(rejectedFrame).status ==
           SpnegoStatus::Rejected);
    assert(malformed.stage() == SpnegoStage::Failed);
}

// This intentionally controllable source can produce a policy-matching
// candidate from synthetic inputs. It CANNOT authenticate Kerberos or the
// OS. The GSS-to-OS gate must refuse even reading this source when no
// independently TLS-bound provider name exists.
class CountingConsoleEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    int accountReads{};
    int sessionReads{};
    int clockReads{};

    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override
    {
        ++accountReads;
        return {ConsoleEvidenceReadStatus::Observed, account, 1001};
    }

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override
    {
        ++sessionReads;
        return {ConsoleEvidenceReadStatus::Observed,
                "c2", "seat0", ":0", 1001, 4, 1000, true, true};
    }

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override
    {
        ++clockReads;
        return 1001;
    }

    void reset() noexcept
    {
        accountReads = 0;
        sessionReads = 0;
        clockReads = 0;
    }

    [[nodiscard]] bool untouched() const noexcept
    {
        return accountReads == 0 && sessionReads == 0 && clockReads == 0;
    }
};

using PositiveNativeAdmissionIssue =
    std::optional<LinuxConsoleAdmissionLease> (
        LinuxConsoleAdmissionBroker::*)(
            GssapiSpnegoAcceptor &,
            const OwnedPreauthTcpConnection &,
            const ConsoleEvidenceRequest &) noexcept;
using LegacyNativeAdmissionIssue =
    std::optional<LinuxConsoleAdmissionLease> (
        LinuxConsoleAdmissionBroker::*)(
            GssapiSpnegoAcceptor &,
            const SSL *,
            const ConsoleEvidenceRequest &) noexcept;
using R3McsAdmission =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3McsConnectInitial);
using R3NativeChange =
    decltype(&LinuxConsoleAdmissionBroker::onNativeSessionChangeReady);
using R3ProtectedTransition =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition);
using R3ConnectResponseWrite =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3ConnectResponseWrite);
using R3ConnectResponseCompletion =
    decltype(&LinuxConsoleAdmissionBroker::completeR3ConnectResponseWrite);
using R3ErectDomain =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3ErectDomain);

static_assert(!std::is_default_constructible_v<LinuxConsoleAdmissionLease>);
static_assert(!std::is_copy_constructible_v<LinuxConsoleAdmissionLease>);
static_assert(!std::is_copy_assignable_v<LinuxConsoleAdmissionLease>);
static_assert(std::is_move_constructible_v<LinuxConsoleAdmissionLease>);
static_assert(std::is_invocable_v<
              PositiveNativeAdmissionIssue,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              const ConsoleEvidenceRequest &>);
static_assert(std::is_invocable_v<
              LegacyNativeAdmissionIssue,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              const ConsoleEvidenceRequest &>);
static_assert(!std::is_invocable_v<
              PositiveNativeAdmissionIssue,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              const ConsoleEvidenceRequest &>);
static_assert(std::is_invocable_r_v<
              McsSessionIntake,
              R3McsAdmission,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              std::span<const std::uint8_t>>);
static_assert(!std::is_invocable_v<
              R3McsAdmission,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              std::span<const std::uint8_t>>);
static_assert(std::is_invocable_r_v<
              bool,
              R3NativeChange,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              McsSessionLifecycle &>);
static_assert(std::is_invocable_r_v<
              bool,
              R3ProtectedTransition,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              std::uint32_t>);
static_assert(!std::is_invocable_v<
              R3ProtectedTransition,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              std::uint32_t>);
static_assert(std::is_invocable_v<
              R3ConnectResponseWrite,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &>);
static_assert(std::is_invocable_r_v<
              rdp_server::server::transport::McsConnectResponseWriteOutcome,
              R3ConnectResponseCompletion,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease *,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              std::uint64_t, std::uint64_t, std::size_t>);
static_assert(std::is_invocable_r_v<
              McsSessionIntake,
              R3ErectDomain,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const OwnedPreauthTcpConnection &,
              McsSessionLifecycle &,
              std::span<const std::uint8_t>>);


void testNativeAdmissionR1NlaProvenanceDenials()
{
    const std::optional<SecurityNegotiationProvenance> missing{};
    assert(!hasHybridNlaNegotiationProvenance(missing));
    assert(!hasHybridNlaNegotiationProvenance(
        SecurityNegotiationProvenance{kRdpProtocolSsl, kRdpProtocolSsl}));
    assert(!hasHybridNlaNegotiationProvenance(
        SecurityNegotiationProvenance{
            kRdpProtocolSsl | kRdpProtocolHybrid, kRdpProtocolSsl}));
    assert(!hasHybridNlaNegotiationProvenance(
        SecurityNegotiationProvenance{
            kRdpProtocolSsl, kRdpProtocolHybrid}));
    // This predicate is deliberately not a capability. No caller-supplied
    // provenance reaches issue(); only the exact live R1 owner can do so.
    assert(hasHybridNlaNegotiationProvenance(
        SecurityNegotiationProvenance{
            kRdpProtocolSsl | kRdpProtocolHybrid, kRdpProtocolHybrid}));

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};

    // Null/inactive ownership is rejected before a native session-change
    // monitor or any NSS/logind evidence can become part of a capability.
    OwnedPreauthTcpConnection inactive{OwnedNativeTcpSocket{}};
    GssapiSpnegoAcceptor inactiveAcceptor;
    LinuxConsoleAdmissionBroker inactiveBroker(policy);
    assert(!inactiveBroker.issue(inactiveAcceptor, inactive, request));
    assert(inactiveBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(inactiveBroker.nativeChangeFd() == -1);
    assert(inactiveBroker.nativeChangeEvents() == -1);
    assert(inactiveAcceptor.stage() == SpnegoStage::Failed);
    assert(!inactiveBroker.issue(inactiveAcceptor, inactive, request));

    // A real accepted R1 connection with its server SSL attached but with
    // TLS unfinished has neither establishedTls() nor immutable provenance.
    R1DiagnosticTlsFixture incomplete{
        kDiagnosticSslAndHybridRequest, false};
    assert(incomplete.connection().active());
    assert(incomplete.connection().establishedTls() == nullptr);
    assert(!incomplete.connection().securityNegotiationProvenance());
    GssapiSpnegoAcceptor incompleteAcceptor;
    LinuxConsoleAdmissionBroker incompleteBroker(policy);
    assert(!incompleteBroker.issue(
        incompleteAcceptor, incomplete.connection(), request));
    assert(incompleteBroker.nativeChangeFd() == -1);
    assert(incompleteBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(incompleteAcceptor.stage() == SpnegoStage::Failed);

    // A genuine established TLS owner is still denial-only when R1 selected
    // diagnostic PROTOCOL_SSL. TLS success is not NLA admission evidence.
    R1DiagnosticTlsFixture sslOnly{kDiagnosticSslRequest, true};
    const auto sslOnlyProvenance =
        sslOnly.connection().securityNegotiationProvenance();
    assert(sslOnly.connection().establishedTls() != nullptr);
    assert(sslOnlyProvenance);
    assert(sslOnlyProvenance->clientRequestedProtocols == kRdpProtocolSsl);
    assert(sslOnlyProvenance->serverSelectedProtocol == kRdpProtocolSsl);
    assert(!hasHybridNlaNegotiationProvenance(sslOnlyProvenance));
    GssapiSpnegoAcceptor sslAcceptor;
    LinuxConsoleAdmissionBroker sslBroker(policy);
    assert(!sslBroker.issue(sslAcceptor, sslOnly.connection(), request));
    assert(sslBroker.nativeChangeFd() == -1);
    assert(sslBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(sslAcceptor.stage() == SpnegoStage::Failed);

    // A client HYBRID offer is also insufficient: current R1 genuinely
    // replies with PROTOCOL_SSL, and the exact stored pair must deny R2.
    R1DiagnosticTlsFixture hybridOffered{
        kDiagnosticSslAndHybridRequest, true};
    const auto offeredProvenance =
        hybridOffered.connection().securityNegotiationProvenance();
    assert(hybridOffered.connection().establishedTls() != nullptr);
    assert(offeredProvenance);
    assert((offeredProvenance->clientRequestedProtocols &
            kRdpProtocolHybrid) != 0);
    assert(offeredProvenance->serverSelectedProtocol == kRdpProtocolSsl);
    assert(!hasHybridNlaNegotiationProvenance(offeredProvenance));
    GssapiSpnegoAcceptor offeredAcceptor;
    LinuxConsoleAdmissionBroker offeredBroker(policy);
    assert(!offeredBroker.issue(
        offeredAcceptor, hybridOffered.connection(), request));
    assert(offeredBroker.nativeChangeFd() == -1);
    assert(offeredBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(offeredAcceptor.stage() == SpnegoStage::Failed);
    assert(!offeredBroker.issue(
        offeredAcceptor, hybridOffered.connection(), request));

    // The legacy raw-SSL route is terminal deny-only even with the exact
    // established SSL object owned by a genuine R1 connection.
    GssapiSpnegoAcceptor legacyAcceptor;
    LinuxConsoleAdmissionBroker legacyBroker(policy);
    assert(!legacyBroker.issue(
        legacyAcceptor, hybridOffered.connection().establishedTls(), request));
    assert(legacyBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(legacyAcceptor.stage() == SpnegoStage::Failed);

    // Cancellation revokes TLS and provenance together; neither stale R1
    // state nor a fresh broker can replay the old connection into admission.
    hybridOffered.connection().cancel();
    assert(!hybridOffered.connection().active());
    assert(hybridOffered.connection().establishedTls() == nullptr);
    assert(!hybridOffered.connection().securityNegotiationProvenance());
    GssapiSpnegoAcceptor cancelledAcceptor;
    LinuxConsoleAdmissionBroker cancelledBroker(policy);
    assert(!cancelledBroker.issue(
        cancelledAcceptor, hybridOffered.connection(), request));
    assert(cancelledBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(cancelledAcceptor.stage() == SpnegoStage::Failed);
}

void testR3InitialNlaOwnerFence()
{
    // The static assertions above prove the initial and generic protected R3
    // authorization APIs require OwnedPreauthTcpConnection and cannot be
    // invoked using an independently supplied SSL pointer.
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;

    // Ordinary CI has no genuine HYBRID+Kerberos+logind lease, so exercise
    // the real terminal ordering barrier rather than constructing one.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(session.pendingJoinConfirmation().empty());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Late/replayed transition attempts cannot advance toward Connect
    // Response or Erect Domain after the sole R3 owner has been retired.
    session.revokeUnlessAdmissionBindingMatches(UINT64_MAX, UINT64_MAX);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.allocatedGccNodeId() == 0U);
    assert(session.allocatedIoChannelId() == 0U);
    assert(session.allocatedStaticChannelIds().empty());
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
}

void testNativeAdmissionCapabilityDenials()
{
    ConsoleIdentityPolicy policy;
    assert(policy.generation() == 0);
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.generation() == 1);

    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};

    // No provider-derived GSS/TLS identity: fail before any positive native
    // admission can exist, then remain terminal on replay.
    GssapiSpnegoAcceptor unverified;
    LinuxConsoleAdmissionBroker broker(policy);
    assert(broker.state() == LinuxConsoleAdmissionState::Ready);
    const auto denied = broker.issue(unverified, nullptr, request);
    assert(!denied.has_value());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(broker.nativeChangeFd() == -1);
    assert(broker.nativeChangeEvents() == -1);
    assert(unverified.stage() == SpnegoStage::Failed);

    const auto replay = broker.issue(unverified, nullptr, request);
    assert(!replay.has_value());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);

    // Only successful policy mutation advances the lease-revocation epoch.
    const std::uint64_t generation = policy.generation();
    assert(policy.add({"alice@EXAMPLE.TEST", "other", "seat0", ":0",
                       1002, kConsoleViewPermission}) ==
           ConsoleRuleError::Duplicate);
    assert(policy.generation() == generation);
    assert(policy.add({"bob@EXAMPLE.TEST", "bob", "seat0", ":0",
                       1002, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.generation() == generation + 1);
}

void testR3McsAdmissionContract()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);

    // No fake positive lease is constructed by this test. Exercise the
    // production cancellation barrier that R1 must use on disconnect:
    // R3 protocol state closes before R2/GSS is revoked.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Repeated readiness/disconnect callbacks cannot revive either owner.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

void testR3ProtectedTransitionGenerationFence()
{
    // Public scalar generation values are revocation-only. Before a genuine
    // private R2 handoff no pair, including nonzero guesses, can make the sole
    // R3 owner retain state or advance toward Connect Response.
    McsSessionLifecycle guessed;
    assert(guessed.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    guessed.revokeUnlessAdmissionBindingMatches(1, 1);
    assert(guessed.phase() == McsSessionPhase::Closed);
    assert(guessed.licensingPhase() == RdpLicensingPhase::Closed);
    assert(guessed.pendingJoinConfirmation().empty());

    McsSessionLifecycle zero;
    zero.revokeUnlessAdmissionBindingMatches(0, 0);
    assert(zero.phase() == McsSessionPhase::Closed);
    assert(zero.licensingPhase() == RdpLicensingPhase::Closed);

    // Repeated or changed scalar input cannot revive a terminal owner.
    zero.revokeUnlessAdmissionBindingMatches(UINT64_MAX, UINT64_MAX);
    assert(zero.phase() == McsSessionPhase::Closed);
    assert(zero.pendingJoinConfirmation().empty());
    assert(!zero.channelJoinConfirmed(1003U));
}


void testR3ConnectResponseWriteContract()
{
    // The positive preparation API still requires a nonforgeable lease and
    // exact R1 owner. Completion is covered separately because it now has the
    // same authority requirement rather than accepting receipt scalars alone.
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST","alice","seat0",":0",
                       1001,kConsoleViewPermission})==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    broker.revokeR3Session(acceptor,session);
    assert(session.phase()==McsSessionPhase::Closed);
    assert(session.licensingPhase()==RdpLicensingPhase::Closed);
    assert(broker.state()==LinuxConsoleAdmissionState::Revoked);
}

void testR3ConnectResponseCompletionReauthorization()
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    using rdp_server::server::transport::OwnedNativeTcpSocket;
    using rdp_server::server::transport::OwnedPreauthTcpConnection;

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST","alice","seat0",":0",
                       1001,kConsoleViewPermission})==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    // Ordinary CI must not fabricate a positive lease. Exercise the real
    // denial path instead: no null lease, guessed receipt or late replay may
    // publish writer progress or preserve R3/GSS authority.
    assert(broker.completeR3ConnectResponseWrite(
        nullptr,acceptor,connection,session,1U,1U,0U)==Outcome::Rejected);
    assert(session.phase()==McsSessionPhase::Closed);
    assert(session.licensingPhase()==RdpLicensingPhase::Closed);
    assert(broker.state()==LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage()==SpnegoStage::Failed);
    assert(broker.completeR3ConnectResponseWrite(
        nullptr,acceptor,connection,session,UINT64_MAX,UINT64_MAX,1U)==
           Outcome::Rejected);
    assert(session.phase()==McsSessionPhase::Closed);
    assert(broker.state()==LinuxConsoleAdmissionState::Revoked);
}


void testR3ProtectedTransitionTerminalReplayFence()
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    using rdp_server::server::transport::OwnedNativeTcpSocket;
    using rdp_server::server::transport::OwnedPreauthTcpConnection;

    constexpr std::array<std::uint8_t, 12> erect{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x04, 0x01, 0x00, 0x01, 0x00};
    constexpr std::uint64_t guessedReply = 17U;
    constexpr std::uint64_t guessedSlice = 29U;

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    // No positive lease or established R1 transport exists. A guessed
    // completion must retire R3 and revoke R2/GSS before receipt state moves.
    assert(broker.completeR3ConnectResponseWrite(
               nullptr, acceptor, connection, session,
               guessedReply, guessedSlice, 0U) == Outcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Late Erect work, changed receipts and public generation guesses cannot
    // revive the same terminal owner.
    assert(session.onDomainPdu(erect) == McsSessionIntake::Closed);
    session.revokeUnlessAdmissionBindingMatches(UINT64_MAX, UINT64_MAX);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.completeR3ConnectResponseWrite(
               nullptr, acceptor, connection, session,
               guessedReply, guessedSlice, 1U) == Outcome::Rejected);
    assert(broker.completeR3ConnectResponseWrite(
               nullptr, acceptor, connection, session,
               0U, 0U, 0U) == Outcome::Rejected);

    // Replacing only R3 cannot cross an already revoked R2/GSS boundary.
    McsSessionLifecycle replacement;
    assert(replacement.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(broker.completeR3ConnectResponseWrite(
               nullptr, acceptor, connection, replacement,
               guessedReply, guessedSlice, 0U) == Outcome::Rejected);
    assert(replacement.phase() == McsSessionPhase::Closed);
    assert(replacement.onDomainPdu(erect) == McsSessionIntake::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // A full reconnect has fresh owners, but receipt values alone are still
    // not authority and cannot manufacture the missing lease/R1 state.
    GssapiSpnegoAcceptor freshAcceptor;
    LinuxConsoleAdmissionBroker freshBroker(policy);
    McsSessionLifecycle freshSession;
    OwnedPreauthTcpConnection freshConnection{OwnedNativeTcpSocket{}};
    assert(freshBroker.state() == LinuxConsoleAdmissionState::Ready);
    assert(freshSession.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(freshBroker.completeR3ConnectResponseWrite(
               nullptr, freshAcceptor, freshConnection, freshSession,
               guessedReply, guessedSlice, 0U) == Outcome::Rejected);
    assert(freshSession.phase() == McsSessionPhase::Closed);
    assert(freshSession.onDomainPdu(erect) == McsSessionIntake::Closed);
    assert(freshSession.licensingPhase() == RdpLicensingPhase::Closed);
    assert(freshBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(freshAcceptor.stage() == SpnegoStage::Failed);
}

void testR3ErectDomainContract()
{
    constexpr std::array<std::uint8_t, 12> erect{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x04, 0x01, 0x00, 0x01, 0x00};

    McsSessionLifecycle unadmitted;
    assert(unadmitted.onDomainPdu(erect) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(unadmitted.phase() == McsSessionPhase::Closed);
    assert(unadmitted.licensingPhase() == RdpLicensingPhase::Closed);

    McsSessionLifecycle fresh;
    assert(fresh.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    fresh.revokeUnlessAdmissionBindingMatches(1U, 1U);
    assert(fresh.phase() == McsSessionPhase::Closed);
}

void testR3AttachUserContract()
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    using IntakeMethod =
        decltype(&LinuxConsoleAdmissionBroker::authorizeR3AttachUser);
    using PrepareMethod =
        decltype(&LinuxConsoleAdmissionBroker::authorizeR3AttachUserConfirmWrite);
    using CompletionMethod =
        decltype(&LinuxConsoleAdmissionBroker::completeR3AttachUserConfirmWrite);
    using Packet = std::span<const std::uint8_t>;
    using Connection = const OwnedPreauthTcpConnection &;
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Session = McsSessionLifecycle &;
    static_assert(std::is_invocable_r_v<
        McsSessionIntake,IntakeMethod,Broker,const LinuxConsoleAdmissionLease &,
        Acceptor,Connection,Session,Packet>);
    static_assert(!std::is_invocable_v<
        IntakeMethod,Broker,bool,Acceptor,Connection,Session,Packet>);
    static_assert(!std::is_invocable_v<
        IntakeMethod,Broker,const SSL *,Acceptor,Connection,Session,Packet>);
    static_assert(!std::is_invocable_v<
        IntakeMethod,Broker,std::uint64_t,Acceptor,Connection,Session,Packet>);
    static_assert(std::is_invocable_v<
        PrepareMethod,Broker,const LinuxConsoleAdmissionLease &,
        Acceptor,Connection,Session>);
    static_assert(!std::is_invocable_v<
        PrepareMethod,Broker,bool,Acceptor,Connection,Session>);
    static_assert(std::is_invocable_r_v<
        Outcome,CompletionMethod,Broker,const LinuxConsoleAdmissionLease *,
        Acceptor,Connection,Session,std::uint64_t,std::uint64_t,std::size_t>);
    static_assert(!std::is_invocable_v<
        CompletionMethod,Broker,bool,Acceptor,Connection,Session,
        std::uint64_t,std::uint64_t,std::size_t>);

    constexpr std::array<std::uint8_t,8> attach{
        0x03,0x00,0x00,0x08,0x02,0xf0,0x80,0x28};
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST","alice","seat0",":0",
                       1001,kConsoleViewPermission}) == ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};
    // Offline CI cannot fabricate a positive lease, native session or TLS.
    assert(broker.completeR3AttachUserConfirmWrite(
        nullptr,acceptor,connection,session,1U,1U,11U) == Outcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.allocatedUserId() == 0U);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(session.pendingJoinConfirmation().empty());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(broker.completeR3AttachUserConfirmWrite(
        nullptr,acceptor,connection,session,UINT64_MAX,UINT64_MAX,0U) ==
        Outcome::Rejected);
    assert(session.onDomainPdu(attach) == McsSessionIntake::Closed);
    McsSessionLifecycle early;
    assert(early.onDomainPdu(attach) == McsSessionIntake::ValidButNotAdmitted);
    assert(early.phase() == McsSessionPhase::Closed);
    assert(early.allocatedUserId() == 0U);
    assert(early.onDomainPdu(attach) == McsSessionIntake::Closed);
}


void testR3AttachUserTerminalReplayFence()
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;

    constexpr std::array<std::uint8_t, 8> attach{
        0x03, 0x00, 0x00, 0x08, 0x02, 0xf0, 0x80, 0x28};
    constexpr std::array<std::uint8_t, 12> erect{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x04, 0x01, 0x00, 0x01, 0x00};

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    // No positive lease/TLS/native session exists. Guessed confirmation
    // receipts must retire the exact R3/R2/GSS owners before any later Attach
    // or Erect work can be consumed.
    assert(broker.completeR3AttachUserConfirmWrite(
               nullptr, acceptor, connection, session,
               41U, 43U, 11U) == Outcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.allocatedUserId() == 0U);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(session.pendingJoinConfirmation().empty());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    assert(session.onDomainPdu(attach) == McsSessionIntake::Closed);
    assert(session.onDomainPdu(erect) == McsSessionIntake::Closed);
    assert(broker.completeR3AttachUserConfirmWrite(
               nullptr, acceptor, connection, session,
               UINT64_MAX, UINT64_MAX, 0U) == Outcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);

    // Replacing only R3 does not cross already revoked R2/GSS authority.
    McsSessionLifecycle replacement;
    assert(broker.completeR3AttachUserConfirmWrite(
               nullptr, acceptor, connection, replacement,
               41U, 43U, 0U) == Outcome::Rejected);
    assert(replacement.phase() == McsSessionPhase::Closed);
    assert(replacement.onDomainPdu(attach) == McsSessionIntake::Closed);

    // A complete reconnect gets fresh owners, but scalar receipts still do
    // not manufacture the missing nonforgeable lease or established R1 TLS.
    GssapiSpnegoAcceptor freshAcceptor;
    LinuxConsoleAdmissionBroker freshBroker(policy);
    McsSessionLifecycle freshSession;
    OwnedPreauthTcpConnection freshConnection{OwnedNativeTcpSocket{}};
    assert(freshBroker.state() == LinuxConsoleAdmissionState::Ready);
    assert(freshBroker.completeR3AttachUserConfirmWrite(
               nullptr, freshAcceptor, freshConnection, freshSession,
               41U, 43U, 11U) == Outcome::Rejected);
    assert(freshSession.phase() == McsSessionPhase::Closed);
    assert(freshSession.allocatedUserId() == 0U);
    assert(freshSession.onDomainPdu(attach) == McsSessionIntake::Closed);
    assert(freshBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(freshAcceptor.stage() == SpnegoStage::Failed);
}

void testR3ProtectedChannelJoinContract()
{
    using StartMethod =
        decltype(&LinuxConsoleAdmissionBroker::authorizeR3ChannelJoin);
    using PrepareMethod =
        decltype(&LinuxConsoleAdmissionBroker::authorizeR3ChannelJoinConfirmWrite);
    using CompletionMethod =
        decltype(&LinuxConsoleAdmissionBroker::completeR3ChannelJoinConfirmWrite);
    using Start = rdp_server::server::transport::McsJoinStartOutcome;
    using Outcome = rdp_server::server::transport::McsJoinWriteOutcome;
    using Packet = std::span<const std::uint8_t>;
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;

    static_assert(std::is_invocable_r_v<
        Start, StartMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Packet>);
    static_assert(!std::is_invocable_v<
        StartMethod, Broker, bool, Acceptor, Connection, Session, Packet>);
    static_assert(!std::is_invocable_v<
        StartMethod, Broker, const SSL *, Acceptor, Connection, Session, Packet>);
    static_assert(!std::is_invocable_v<
        StartMethod, Broker, std::uint64_t, Acceptor, Connection, Session, Packet>);
    static_assert(std::is_invocable_r_v<
        std::optional<rdp_server::server::transport::McsConnectResponseWriteView>,
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, bool, Acceptor, Connection, Session>);
    static_assert(std::is_invocable_r_v<
        Outcome, CompletionMethod, Broker, const LinuxConsoleAdmissionLease *,
        Acceptor, Connection, Session, std::uint64_t, std::uint64_t,
        std::size_t>);
    static_assert(!std::is_invocable_v<
        CompletionMethod, Broker, bool, Acceptor, Connection, Session,
        std::uint64_t, std::uint64_t, std::size_t>);

    constexpr std::array<std::uint8_t, 12> validJoin{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x01, 0x03, 0xeb};
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST","alice","seat0",":0",
                       1001,kConsoleViewPermission}) == ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};
    assert(broker.completeR3ChannelJoinConfirmWrite(
        nullptr, acceptor, connection, session, 1U, 1U, 15U) ==
        Outcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(session.allocatedUserId() == 0U);
    assert(session.pendingJoinConfirmation().empty());
    assert(!session.channelJoinConfirmed(1003U));
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(broker.completeR3ChannelJoinConfirmWrite(
        nullptr, acceptor, connection, session, UINT64_MAX, UINT64_MAX,
        0U) == Outcome::Rejected);
    assert(session.onDomainPdu(validJoin) == McsSessionIntake::Closed);

    // Fresh R3 cannot accept the packet by syntax alone.
    McsSessionLifecycle unadmitted;
    assert(unadmitted.onDomainPdu(validJoin) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(unadmitted.phase() == McsSessionPhase::Closed);
    assert(!unadmitted.channelJoinConfirmed(1003U));
}

void testR3ChannelJoinTerminalReplayFence()
{
    using Gate = rdp_server::server::transport::McsChannelJoinWriteGate;
    using StartOutcome = rdp_server::server::transport::McsJoinStartOutcome;
    using WriteOutcome = rdp_server::server::transport::McsJoinWriteOutcome;
    using rdp_server::server::transport::parseMcsChannelRequest;

    constexpr std::array<std::uint8_t, 12> validJoin{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x01, 0x03, 0xeb};
    auto changedIdentityJoin = validJoin;
    changedIdentityJoin[9] = 0x02;
    auto unassignedJoin = validJoin;
    unassignedJoin[10] = 0x03;
    unassignedJoin[11] = 0xee;
    const auto truncatedJoin = std::span(validJoin).first(6);

    const auto parsedJoin = parseMcsChannelRequest(validJoin);
    const auto parsedChangedIdentity =
        parseMcsChannelRequest(changedIdentityJoin);
    const auto parsedUnassigned = parseMcsChannelRequest(unassignedJoin);
    assert(parsedJoin);
    assert(parsedChangedIdentity);
    assert(parsedUnassigned);
    assert(parsedChangedIdentity.request.initiator !=
           parsedJoin.request.initiator);
    assert(parsedUnassigned.request.channelId != parsedJoin.request.channelId);
    assert(!parseMcsChannelRequest(truncatedJoin));

    // The standalone production write gate is bookkeeping, not authority.
    // Retire one real pending reply so its copied receipt values can be
    // replayed against R2/R3 without fabricating an admission lease.
    constexpr std::array<std::uint16_t, 3> assignedChannels{
        1002U, 1003U, 1004U};
    Gate retiredGate;
    assert(retiredGate.configure(1002U, assignedChannels));
    assert(retiredGate.beginJoin(parsedJoin.request) ==
           StartOutcome::ReplyPending);
    const auto retiredReplySequence = retiredGate.pendingReplySequence();
    const auto retiredSliceSequence = retiredGate.pendingWriteSliceSequence();
    const auto retiredResponse = retiredGate.pendingBytes();
    assert(retiredReplySequence != 0U);
    assert(retiredSliceSequence != 0U);
    assert(retiredResponse.size() == 15U);
    assert(!retiredGate.channelJoinConfirmed(1002U));
    assert(!retiredGate.channelJoinConfirmed(1003U));
    assert(!retiredGate.channelJoinConfirmed(1004U));
    retiredGate.close();
    assert(retiredGate.pendingBytes().empty());
    assert(!retiredGate.channelJoinConfirmed(1002U));
    assert(!retiredGate.channelJoinConfirmed(1003U));
    assert(!retiredGate.channelJoinConfirmed(1004U));

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    const auto expectProtectedCompletionDenial =
        [&](std::uint64_t replySequence,
            std::uint64_t writeSliceSequence,
            std::size_t acceptedBytes)
    {
        GssapiSpnegoAcceptor acceptor;
        LinuxConsoleAdmissionBroker broker(policy);
        McsSessionLifecycle session;
        OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

        assert(broker.completeR3ChannelJoinConfirmWrite(
                   nullptr, acceptor, connection, session,
                   replySequence, writeSliceSequence, acceptedBytes) ==
               WriteOutcome::Rejected);
        assert(session.phase() == McsSessionPhase::Closed);
        assert(session.licensingPhase() == RdpLicensingPhase::Closed);
        assert(session.allocatedUserId() == 0U);
        assert(session.allocatedIoChannelId() == 0U);
        assert(session.allocatedStaticChannelIds().empty());
        assert(session.pendingJoinConfirmation().empty());
        assert(!session.channelJoinConfirmed(1002U));
        assert(!session.channelJoinConfirmed(1003U));
        assert(!session.channelJoinConfirmed(1004U));
        assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
        assert(acceptor.stage() == SpnegoStage::Failed);
    };

    // Guessed, zero, stale, mismatched and impossible completion reports all
    // fail at the protected completion boundary before integers can become
    // authority.
    expectProtectedCompletionDenial(0U, 0U, 0U);
    expectProtectedCompletionDenial(
        retiredReplySequence, retiredSliceSequence, 1U);
    expectProtectedCompletionDenial(
        retiredReplySequence + 1U, retiredSliceSequence, 1U);
    expectProtectedCompletionDenial(
        retiredReplySequence, retiredSliceSequence + 1U, 1U);
    expectProtectedCompletionDenial(
        retiredReplySequence, retiredSliceSequence, 16U);

    // One owner stays terminal after the first denial. Neither repeated write
    // completion nor late valid/malformed/changed Join input can revive it.
    GssapiSpnegoAcceptor terminalAcceptor;
    LinuxConsoleAdmissionBroker terminalBroker(policy);
    McsSessionLifecycle terminalSession;
    OwnedPreauthTcpConnection terminalConnection{OwnedNativeTcpSocket{}};
    assert(terminalBroker.completeR3ChannelJoinConfirmWrite(
               nullptr, terminalAcceptor, terminalConnection, terminalSession,
               retiredReplySequence, retiredSliceSequence, 1U) ==
           WriteOutcome::Rejected);
    assert(terminalBroker.completeR3ChannelJoinConfirmWrite(
               nullptr, terminalAcceptor, terminalConnection, terminalSession,
               UINT64_MAX, UINT64_MAX, 15U) ==
           WriteOutcome::Rejected);
    for (const auto packet : {
             std::span<const std::uint8_t>{validJoin},
             std::span<const std::uint8_t>{validJoin},
             truncatedJoin,
             std::span<const std::uint8_t>{unassignedJoin},
             std::span<const std::uint8_t>{changedIdentityJoin}})
    {
        assert(terminalSession.onDomainPdu(packet) ==
               McsSessionIntake::Closed);
    }
    assert(terminalSession.pendingJoinConfirmation().empty());
    assert(!terminalSession.channelJoinConfirmed(1003U));
    assert(terminalSession.licensingPhase() == RdpLicensingPhase::Closed);
    assert(terminalBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(terminalAcceptor.stage() == SpnegoStage::Failed);

    // Explicit disconnect before a late callback is the same terminal fence.
    GssapiSpnegoAcceptor disconnectedAcceptor;
    LinuxConsoleAdmissionBroker disconnectedBroker(policy);
    McsSessionLifecycle disconnectedSession;
    OwnedPreauthTcpConnection disconnectedConnection{OwnedNativeTcpSocket{}};
    disconnectedBroker.revokeR3Session(
        disconnectedAcceptor, disconnectedSession);
    assert(disconnectedBroker.completeR3ChannelJoinConfirmWrite(
               nullptr, disconnectedAcceptor, disconnectedConnection,
               disconnectedSession, retiredReplySequence,
               retiredSliceSequence, 15U) == WriteOutcome::Rejected);
    assert(disconnectedSession.onDomainPdu(validJoin) ==
           McsSessionIntake::Closed);
    assert(disconnectedSession.pendingJoinConfirmation().empty());
    assert(disconnectedSession.licensingPhase() ==
           RdpLicensingPhase::Closed);

    // Replacing only R3 cannot inherit authority from the already revoked R2
    // broker/GSS owner, even when an old receipt is replayed.
    McsSessionLifecycle replacementSession;
    assert(terminalBroker.completeR3ChannelJoinConfirmWrite(
               nullptr, terminalAcceptor, terminalConnection,
               replacementSession, retiredReplySequence,
               retiredSliceSequence, 15U) == WriteOutcome::Rejected);
    assert(replacementSession.phase() == McsSessionPhase::Closed);
    assert(replacementSession.pendingJoinConfirmation().empty());
    assert(!replacementSession.channelJoinConfirmed(1003U));

    // A completely fresh owner set also rejects receipt integers copied from
    // an independent production gate. Matching syntax and plausible receipt
    // values are insufficient without genuine R1/R2 authorization.
    Gate independentGate;
    assert(independentGate.configure(1002U, assignedChannels));
    assert(independentGate.beginJoin(parsedJoin.request) ==
           StartOutcome::ReplyPending);
    const auto independentReplySequence =
        independentGate.pendingReplySequence();
    const auto independentSliceSequence =
        independentGate.pendingWriteSliceSequence();
    const auto independentBytes = independentGate.pendingBytes().size();
    GssapiSpnegoAcceptor freshAcceptor;
    LinuxConsoleAdmissionBroker freshBroker(policy);
    McsSessionLifecycle freshSession;
    OwnedPreauthTcpConnection freshConnection{OwnedNativeTcpSocket{}};
    assert(freshBroker.completeR3ChannelJoinConfirmWrite(
               nullptr, freshAcceptor, freshConnection, freshSession,
               independentReplySequence, independentSliceSequence,
               independentBytes) == WriteOutcome::Rejected);
    assert(freshSession.phase() == McsSessionPhase::Closed);
    assert(freshSession.pendingJoinConfirmation().empty());
    assert(!freshSession.channelJoinConfirmed(1003U));
    assert(freshBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(freshAcceptor.stage() == SpnegoStage::Failed);
    independentGate.close();

    // Caller-supplied generation guesses remain revocation-only in another
    // fresh R3 object and cannot bootstrap a later copied completion.
    GssapiSpnegoAcceptor guessedAcceptor;
    LinuxConsoleAdmissionBroker guessedBroker(policy);
    McsSessionLifecycle guessedSession;
    OwnedPreauthTcpConnection guessedConnection{OwnedNativeTcpSocket{}};
    guessedSession.revokeUnlessAdmissionBindingMatches(41U, 43U);
    assert(guessedSession.phase() == McsSessionPhase::Closed);
    assert(guessedBroker.completeR3ChannelJoinConfirmWrite(
               nullptr, guessedAcceptor, guessedConnection, guessedSession,
               retiredReplySequence, retiredSliceSequence, 0U) ==
           WriteOutcome::Rejected);
    assert(guessedSession.pendingJoinConfirmation().empty());
    assert(guessedSession.licensingPhase() == RdpLicensingPhase::Closed);
    assert(guessedBroker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(guessedAcceptor.stage() == SpnegoStage::Failed);
}

void testR3JoinedClipboardRoleContract()
{
    // The only positive role observation takes a concrete R2 lease, original
    // R1 TLS connection, GSS acceptor and sole R3 owner. No bool/string,
    // guessed UserId or borrowed SSL pointer can substitute for the lease.
    using Method =
        decltype(&LinuxConsoleAdmissionBroker::authorizeR3JoinedClipboardChannel);
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;
    static_assert(std::is_invocable_r_v<std::optional<std::uint16_t>,
        Method, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session>);
    static_assert(!std::is_invocable_v<
        Method, Broker, bool, Acceptor, Connection, Session>);
    static_assert(!std::is_invocable_v<
        Method, Broker, const SSL *, Acceptor, Connection, Session>);
    static_assert(!std::is_invocable_v<
        Method, Broker, std::uint64_t, Acceptor, Connection, Session>);

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission |
                                 kConsoleClipboardPermission}) ==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle owner;
    // No positive test lease or selected-TLS/GSS proof is forged.
    assert(owner.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(owner.allocatedStaticChannelIds().empty());
    assert(!owner.channelJoinConfirmed(1005U));
    broker.revokeR3Session(acceptor, owner);
    assert(owner.phase() == McsSessionPhase::Closed);
    assert(owner.allocatedUserId() == 0U);
    assert(owner.allocatedStaticChannelIds().empty());
    assert(!owner.channelJoinConfirmed(1005U));
    assert(owner.pendingJoinConfirmation().empty());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);
    broker.revokeR3Session(acceptor, owner);
    assert(owner.phase() == McsSessionPhase::Closed);
}

void testR3ClientInfoRouteContract()
{
    using Method =
        decltype(&LinuxConsoleAdmissionBroker::authorizeR3ClientInfoPacket);
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;
    using Packet = std::span<const std::uint8_t>;
    using Summary =
        rdp_server::server::transport::RdpClientInfoPacketSummary;

    static_assert(std::is_invocable_r_v<
        std::optional<Summary>, Method, Broker,
        const LinuxConsoleAdmissionLease &, Acceptor,
        Connection, Session, Packet>);
    static_assert(!std::is_invocable_v<
        Method, Broker, bool, Acceptor, Connection, Session, Packet>);
    static_assert(!std::is_invocable_v<
        Method, Broker, const SSL *, Acceptor, Connection, Session, Packet>);
    static_assert(!std::is_invocable_v<
        Method, Broker, std::uint16_t, Acceptor, Connection, Session, Packet>);

    constexpr std::array<std::uint8_t, 36> clientInfo{
        0x03,0x00,0x00,0x24,0x02,0xf0,0x80,
        0x64,0x00,0x01,0x03,0xeb,0x70,0x16,
        0x40,0x00,0x00,0x00,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    const auto parsed =
        rdp_server::server::transport::parseMcsChannelRequest(clientInfo);
    assert(parsed);
    assert(parsed.request.kind ==
           rdp_server::server::transport::McsChannelRequestKind::
               SendDataRequest);
    assert(parsed.request.initiator == 1002U);
    assert(parsed.request.channelId == 1003U);
    assert(parsed.request.segmentation == 3U);

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    // Ordinary CI must not mint an R2 lease merely to obtain positive
    // Client Info acceptance. The public R3 domain entry remains terminal
    // denial and cannot advance to AwaitServerLicenseRequest.
    assert(session.onDomainPdu(clientInfo) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(session.allocatedUserId() == 0U);
    assert(session.pendingJoinConfirmation().empty());

    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);
    (void)connection;
}

void testR3ServerLicenseRequestWriteContract()
{
    using PrepareMethod =
        decltype(&LinuxConsoleAdmissionBroker::
                     authorizeR3ServerLicenseRequestWrite);
    using CompletionMethod =
        decltype(&LinuxConsoleAdmissionBroker::
                     completeR3ServerLicenseRequestWrite);
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;
    using Identity = const RdpServerLicenseIdentity &;
    using Credential = const RdpLicensingServiceCredential &;
    using Fields = const RdpServerLicenseRequestFields &;

    static_assert(std::is_invocable_r_v<
        std::optional<RdpServerLicenseRequestWriteView>,
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Identity, Credential>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Identity>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, bool, Acceptor, Connection, Session,
        Identity, Credential>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, Credential, Acceptor, Connection, Session,
        Identity, Credential>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Fields, Credential>);
    static_assert(std::is_invocable_r_v<
        RdpServerLicenseRequestWriteOutcome,
        CompletionMethod, Broker, const LinuxConsoleAdmissionLease *,
        Acceptor, Connection, Session, std::uint64_t, std::uint64_t,
        std::size_t>);
    static_assert(!std::is_invocable_v<
        CompletionMethod, Broker, bool, Acceptor, Connection, Session,
        std::uint64_t, std::uint64_t, std::size_t>);

    constexpr std::array<std::uint8_t, 8> company{
        0x52,0x00,0x44,0x00,0x50,0x00,0x00,0x00};
    constexpr std::array<std::uint8_t, 8> product{
        0x41,0x00,0x30,0x00,0x32,0x00,0x00,0x00};
    constexpr std::array<std::uint8_t, 4> certificate{
        0xde,0xad,0xbe,0xef};
    constexpr std::array<std::uint8_t, 6> scope{
        0x73,0x63,0x6f,0x70,0x65,0x00};
    RdpServerLicenseIdentity identity;
    assert(identity.configure(
        0x00060001U, company, product, certificate, scope));

    // A real production licensing writer obtains its own CSPRNG random and can
    // produce valid receipt integers. Those integers remain non-transferable.
    RdpLicensingLifecycle detachedLifecycle;
    RdpServerLicenseRequestWriteGate detachedWriter{detachedLifecycle};
    assert(detachedWriter.queue(identity));
    const auto first = detachedWriter.pendingWrite();
    assert(first && first.bytes.size() > 11U);
    assert(detachedWriter.onBytesWritten(
               first.replySequence, first.writeSliceSequence, 11U) ==
           RdpServerLicenseRequestWriteOutcome::Pending);
    const auto remainder = detachedWriter.pendingWrite();
    assert(remainder);
    assert(remainder.replySequence == first.replySequence);
    assert(remainder.writeSliceSequence != first.writeSliceSequence);
    const auto copiedReplySequence = remainder.replySequence;
    const auto copiedWriteSliceSequence = remainder.writeSliceSequence;
    const auto copiedAcceptedBytes = remainder.bytes.size();
    assert(detachedWriter.onBytesWritten(
               copiedReplySequence, copiedWriteSliceSequence,
               copiedAcceptedBytes) ==
           RdpServerLicenseRequestWriteOutcome::Delivered);
    assert(detachedLifecycle.phase() ==
           RdpLicensingPhase::AwaitClientLicenseResponse);

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);

    // A copied real writer receipt plus plausible accepted-byte count cannot
    // substitute for the unforgeable lease or original HYBRID/TLS/GSS owner.
    assert(broker.completeR3ServerLicenseRequestWrite(
               nullptr, acceptor, connection, session,
               copiedReplySequence, copiedWriteSliceSequence,
               copiedAcceptedBytes) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Terminal replay is still denial even with the exact same real receipt.
    assert(broker.completeR3ServerLicenseRequestWrite(
               nullptr, acceptor, connection, session,
               copiedReplySequence, copiedWriteSliceSequence,
               copiedAcceptedBytes) ==
           RdpServerLicenseRequestWriteOutcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
}

void testR3ServerPlatformChallengeWriteContract()
{
    using PrepareMethod =
        decltype(&LinuxConsoleAdmissionBroker::
                     authorizeR3ServerPlatformChallengeWrite);
    using CompletionMethod =
        decltype(&LinuxConsoleAdmissionBroker::
                     completeR3ServerPlatformChallengeWrite);
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;
    using KeyMaterial =
        const rdp_server::server::transport::RdpLicensingKeyMaterial &;

    static_assert(std::is_invocable_r_v<
        std::optional<RdpServerPlatformChallengeWriteView>,
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, bool, Acceptor, Connection, Session>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, const SSL *, Session>);
    static_assert(!std::is_invocable_v<
        PrepareMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, KeyMaterial>);

    static_assert(std::is_invocable_r_v<
        RdpServerPlatformChallengeWriteOutcome,
        CompletionMethod, Broker, const LinuxConsoleAdmissionLease *,
        Acceptor, Connection, Session, std::uint64_t, std::uint64_t,
        std::size_t>);
    static_assert(!std::is_invocable_v<
        CompletionMethod, Broker, bool, Acceptor, Connection, Session,
        std::uint64_t, std::uint64_t, std::size_t>);

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    // A guessed challenge receipt cannot substitute for the move-only native
    // lease or the exact established HYBRID/TLS/GSS owner.
    assert(broker.completeR3ServerPlatformChallengeWrite(
               nullptr, acceptor, connection, session,
               1U, 1U, 1U) ==
           RdpServerPlatformChallengeWriteOutcome::Rejected);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);
}

void testR3ClientLicensingRouteContract()
{
    using RouteMethod =
        decltype(&LinuxConsoleAdmissionBroker::
                     authorizeR3ClientLicensingMessage);
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;
    using Bytes = std::span<const std::uint8_t>;
    using KeyExchange =
        rdp_server::server::transport::RdpClientLicensingKeyExchangeView;
    using KeyMaterial =
        rdp_server::server::transport::RdpLicensingKeyMaterial;
    using ClientLicenseInfo =
        rdp_server::server::transport::RdpClientLicenseInfoView;
    using HardwareIdProof =
        rdp_server::server::transport::
            RdpClientLicenseInfoHardwareIdResult;
    using Credential = const RdpLicensingServiceCredential &;

    static_assert(std::is_invocable_r_v<
        std::optional<RdpLicensingIntake>,
        RouteMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, bool, Acceptor, Connection, Session,
        Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, Credential, Acceptor, Connection, Session,
        Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, const SSL *, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const LinuxConsoleAdmissionLease *,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, std::uint64_t,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, std::string_view,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const KeyExchange &,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const KeyMaterial &,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const ClientLicenseInfo &,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const HardwareIdProof &,
        Acceptor, Connection, Session, Credential, Bytes>);

    // The HWID verifier result is intentionally a small status value. Even a
    // success-shaped value remains protocol evidence, not native admission.
    const HardwareIdProof successShapedHardwareIdProof{
        rdp_server::server::transport::
            RdpClientLicenseInfoHardwareIdError::None};
    assert(successShapedHardwareIdProof);

    // Build one structurally complete CLIENT_NEW_LICENSE_REQUEST. R3's public
    // parsers may classify protocol bytes and derive keys from already-decoded
    // material, but none of those values is an R2 admission capability.
    std::vector<std::uint8_t> licensingMessage{0x13, 0x83, 0x00, 0x00};
    const auto appendLe32 =
        [&](std::uint32_t value)
        {
            for (unsigned shift = 0U; shift < 32U; shift += 8U)
                licensingMessage.push_back(
                    static_cast<std::uint8_t>(value >> shift));
        };
    const auto appendBlob =
        [&](std::uint16_t type, std::span<const std::uint8_t> payload)
        {
            assert(payload.size() <= UINT16_MAX);
            const auto length = static_cast<std::uint16_t>(payload.size());
            licensingMessage.push_back(static_cast<std::uint8_t>(type));
            licensingMessage.push_back(static_cast<std::uint8_t>(type >> 8U));
            licensingMessage.push_back(static_cast<std::uint8_t>(length));
            licensingMessage.push_back(
                static_cast<std::uint8_t>(length >> 8U));
            licensingMessage.insert(
                licensingMessage.end(), payload.begin(), payload.end());
        };

    appendLe32(1U);          // KEY_EXCHANGE_ALG_RSA
    appendLe32(0x04010000U); // Microsoft WinNT platform
    for (std::uint8_t value = 0U; value < 32U; ++value)
        licensingMessage.push_back(value);

    constexpr std::array<std::uint8_t, 3> encryptedPreMaster{
        0x11, 0x22, 0x33};
    constexpr std::array<std::uint8_t, 5> user{
        0x75, 0x73, 0x65, 0x72, 0x00};
    constexpr std::array<std::uint8_t, 5> host{
        0x68, 0x6f, 0x73, 0x74, 0x00};
    appendBlob(0x0002U, encryptedPreMaster);
    appendBlob(0x000fU, user);
    appendBlob(0x0010U, host);
    assert(licensingMessage.size() <= UINT16_MAX);
    const auto licensingLength =
        static_cast<std::uint16_t>(licensingMessage.size());
    licensingMessage[2] =
        static_cast<std::uint8_t>(licensingLength);
    licensingMessage[3] =
        static_cast<std::uint8_t>(licensingLength >> 8U);

    std::vector<std::uint8_t> licensingEnvelope{
        0x80, 0x00, 0x00, 0x00}; // SEC_LICENSE_PKT
    licensingEnvelope.insert(
        licensingEnvelope.end(),
        licensingMessage.begin(), licensingMessage.end());
    assert(licensingEnvelope.size() < 128U);

    // Complete TPKT/X.224/MCS SendDataRequest for UserId 1002, global I/O
    // channel 1003, begin|end segmentation. The one-byte PER length is valid
    // because the complete Enhanced-Security licensing envelope is <128 B.
    std::vector<std::uint8_t> licensingPacket{
        0x03,0x00,0x00,0x00,0x02,0xf0,0x80,
        0x64,0x00,0x01,0x03,0xeb,0x70,
        static_cast<std::uint8_t>(licensingEnvelope.size())};
    licensingPacket.insert(
        licensingPacket.end(),
        licensingEnvelope.begin(), licensingEnvelope.end());
    assert(licensingPacket.size() <= UINT16_MAX);
    const auto packetLength =
        static_cast<std::uint16_t>(licensingPacket.size());
    licensingPacket[2] = static_cast<std::uint8_t>(packetLength >> 8U);
    licensingPacket[3] = static_cast<std::uint8_t>(packetLength);

    const auto parsed =
        rdp_server::server::transport::parseMcsChannelRequest(
            licensingPacket);
    assert(parsed);
    assert(parsed.request.kind ==
           rdp_server::server::transport::McsChannelRequestKind::
               SendDataRequest);
    assert(parsed.request.initiator == 1002U);
    assert(parsed.request.channelId == 1003U);
    assert(parsed.request.segmentation == 3U);

    const auto envelope =
        rdp_server::server::transport::parseEnhancedSecurityLicensingEnvelope(
            parsed.request.userData);
    assert(envelope);
    const auto licensing =
        rdp_server::server::transport::parseRdpLicensingMessage(
            envelope.value.licensingMessage);
    assert(licensing);
    assert(licensing.value.type ==
           rdp_server::server::transport::RdpLicensingMessageType::
               ClientNewLicenseRequest);

    const auto keyExchange =
        rdp_server::server::transport::parseRdpClientLicensingKeyExchange(
            envelope.value.licensingMessage);
    assert(keyExchange);
    assert(keyExchange.value.clientRandom.size() == 32U);
    assert(keyExchange.value.encryptedPreMasterSecret.size() ==
           encryptedPreMaster.size());
    assert(std::equal(
        keyExchange.value.encryptedPreMasterSecret.begin(),
        keyExchange.value.encryptedPreMasterSecret.end(),
        encryptedPreMaster.begin()));

    std::array<std::uint8_t,
               rdp_server::server::transport::
                   kRdpLicensingPreMasterSecretBytes> preMaster{};
    std::array<std::uint8_t,
               rdp_server::server::transport::
                   kRdpLicensingRandomBytes> serverRandom{};
    for (std::size_t index = 0U; index < preMaster.size(); ++index)
        preMaster[index] = static_cast<std::uint8_t>(index);
    for (std::size_t index = 0U; index < serverRandom.size(); ++index)
        serverRandom[index] = static_cast<std::uint8_t>(0x80U + index);
    auto derived =
        rdp_server::server::transport::deriveRdpLicensingKeys(
            preMaster, keyExchange.value.clientRandom, serverRandom);
    assert(derived);

    // Ordinary hosted CI has no positive native lease. Even valid licensing
    // syntax plus extracted key-exchange fields and derived symmetric keys
    // cannot skip Client Info/request delivery or cross the private
    // R2-authorized licensing intake.
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);
    assert(session.onDomainPdu(licensingPacket) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);

    derived.value = {};
    preMaster.fill(0U);
    serverRandom.fill(0U);
}

void testR3ClientPlatformChallengeResponseRouteContract()
{
    using RouteMethod =
        decltype(&LinuxConsoleAdmissionBroker::
                     authorizeR3ClientPlatformChallengeResponse);
    using Broker = LinuxConsoleAdmissionBroker &;
    using Acceptor = GssapiSpnegoAcceptor &;
    using Connection = const OwnedPreauthTcpConnection &;
    using Session = McsSessionLifecycle &;
    using Credential = const RdpLicensingServiceCredential &;
    using Bytes = std::span<const std::uint8_t>;

    static_assert(std::is_invocable_r_v<
        std::optional<RdpLicensingIntake>,
        RouteMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, bool, Acceptor, Connection, Session,
        Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const LinuxConsoleAdmissionLease *,
        Acceptor, Connection, Session, Credential, Bytes>);
    static_assert(!std::is_invocable_v<
        RouteMethod, Broker, const LinuxConsoleAdmissionLease &,
        Acceptor, const SSL *, Session, Credential, Bytes>);

    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    OwnedPreauthTcpConnection connection{OwnedNativeTcpSocket{}};

    // Public/unadmitted state is terminal even for challenge-response-shaped
    // traffic; only the concrete move-only lease can reach the private route.
    constexpr std::array<std::uint8_t, 22> shaped{
        0x03,0x00,0x00,0x16,0x02,0xf0,0x80,
        0x64,0x00,0x01,0x03,0xeb,0x70,0x08,
        0x80,0x00,0x00,0x00,0x15,0x03,0x04,0x00};
    assert(session.onDomainPdu(shaped) ==
           McsSessionIntake::ValidButNotAdmitted);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
}

void testR3NativeChangeRevocation()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;

    // A readiness callback without a successfully issued concrete native
    // lease/watch is never ignored or promoted into authorization.
    assert(!broker.onNativeSessionChangeReady(acceptor, session));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(broker.nativeChangeFd() == -1);
    assert(broker.nativeChangeEvents() == -1);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Late/repeated event-loop delivery cannot revive any owner.
    assert(!broker.onNativeSessionChangeReady(acceptor, session));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}


void testR3McsDisconnectRevocationFence()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    constexpr std::array<std::uint8_t, 12> lateJoin{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 9> lateDisconnect{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};

    const auto parsedJoin =
        rdp_server::server::transport::parseMcsChannelRequest(lateJoin);
    assert(parsedJoin);
    assert(parsedJoin.request.kind ==
           rdp_server::server::transport::McsChannelRequestKind::ChannelJoin);
    const auto parsedDisconnect =
        rdp_server::server::transport::parseMcsChannelRequest(lateDisconnect);
    assert(parsedDisconnect);
    assert(parsedDisconnect.request.kind ==
           rdp_server::server::transport::McsChannelRequestKind::
               DisconnectProviderUltimatum);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);

    // Model R1 disconnect using the real R2->R3 cancellation barrier. Once
    // R3 closes, syntactically valid queued/late MCS work cannot revive it or
    // produce a join confirmation, even if a readiness callback arrives late.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(broker.nativeChangeFd() == -1);
    assert(broker.nativeChangeEvents() == -1);
    assert(acceptor.stage() == SpnegoStage::Failed);

    assert(session.onDomainPdu(lateJoin) == McsSessionIntake::Closed);
    assert(session.onDomainPdu(lateDisconnect) == McsSessionIntake::Closed);
    assert(session.pendingJoinConfirmation().empty());
    assert(!session.channelJoinConfirmed(1003U));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);

    // Duplicate teardown after late work remains terminal and idempotent.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

void testConsoleGssProvenanceBeforeOsRead()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};
    CountingConsoleEvidenceSource fakeSource;
    // A fake source can report policy-consistent values, proving why
    // CandidateOnly must NEVER be treated as admission authority.
    assert(ConsoleOsEvidenceInspector{}.inspect(
        policy, request, fakeSource) == ConsoleEvidenceMatch::CandidateOnly);
    assert(fakeSource.accountReads == 1 &&
           fakeSource.sessionReads == 1 && fakeSource.clockReads == 1);
    fakeSource.reset();

    // A plausible caller identity with no GSS/TLS proof cannot even
    // trigger a read-only OS sample, let alone grant access.
    GssapiSpnegoAcceptor noKerberos;
    ConsoleAdmissionGate gate(policy);
    assert(gate.state() == ConsoleAdmissionState::NotRequested);
    assert(noKerberos.verifiedPrincipal().empty());
    gate.requestWithOsEvidence(noKerberos, request, fakeSource);
    assert(gate.state() == ConsoleAdmissionState::Denied);
    assert(noKerberos.stage() == SpnegoStage::Failed);
    assert(noKerberos.verifiedPrincipal().empty());
    assert(fakeSource.untouched());

    // The terminal gate and rejected provider may not be replayed, even
    // with different caller identity and a source that would match.
    const ConsoleEvidenceRequest forged{
        "bob@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};
    gate.requestWithOsEvidence(noKerberos, forged, fakeSource);
    assert(gate.state() == ConsoleAdmissionState::Denied);
    assert(fakeSource.untouched());

    // Even a genuinely attempted but failed explicit-keytab provider
    // must never sample OS data or return a candidate.
    GssapiSpnegoAcceptor missingProvider;
    assert(!missingProvider.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));
    ConsoleAdmissionGate failedGate(policy);
    failedGate.requestWithOsEvidence(missingProvider, request, fakeSource);
    assert(failedGate.state() == ConsoleAdmissionState::Denied);
    assert(missingProvider.stage() == SpnegoStage::Failed);
    assert(fakeSource.untouched());

    // The historical caller-constructed policy snapshot is permanently
    // deny-only, even when its rule fields are otherwise consistent.
    GssapiSpnegoAcceptor snapshotProvider;
    ConsoleAdmissionGate snapshotGate(policy);
    snapshotGate.request(
        snapshotProvider, {"alice@EXAMPLE.TEST", "alice", "seat0",
                           ":0", 1001, 1001, kConsoleViewPermission});
    assert(snapshotGate.state() == ConsoleAdmissionState::Denied);
    assert(snapshotProvider.stage() == SpnegoStage::Failed);
    assert(fakeSource.untouched());
}

} // namespace

int main(int argc, char **argv)
{
    const auto invoke = [](std::string_view name) -> int
    {
        if (name == "gssapi-configuration-rejections")
        {
            testConfigurationRejections();
            return 0;
        }
        if (name == "gssapi-framed-handoff")
        {
            testFramedGssHandoffFailClosed();
            return 0;
        }
        if (name == "gssapi-console-provenance-before-os-read")
        {
            testConsoleGssProvenanceBeforeOsRead();
            return 0;
        }
        if (name == "gssapi-native-os-admission-capability-denials")
        {
            testNativeAdmissionCapabilityDenials();
            return 0;
        }
        if (name == "gssapi-native-admission-r1-nla-provenance-denials")
        {
            testNativeAdmissionR1NlaProvenanceDenials();
            return 0;
        }
        if (name == "gssapi-r3-initial-nla-owner-fence")
        {
            testR3InitialNlaOwnerFence();
            return 0;
        }
        if (name == "gssapi-r3-mcs-admission-contract")
        {
            testR3McsAdmissionContract();
            return 0;
        }
        if (name == "gssapi-r3-protected-transition-generation-fence")
        {
            testR3ProtectedTransitionGenerationFence();
            return 0;
        }
        if (name == "gssapi-r3-connect-response-write-contract")
        {
            testR3ConnectResponseWriteContract();
            return 0;
        }
        if (name == "gssapi-r3-connect-response-completion-reauthorization")
        {
            testR3ConnectResponseCompletionReauthorization();
            return 0;
        }
        if (name == "gssapi-r3-erect-domain-contract")
        {
            testR3ErectDomainContract();
            return 0;
        }
        if (name == "gssapi-r3-protected-transition-terminal-replay-fence")
        {
            testR3ProtectedTransitionTerminalReplayFence();
            return 0;
        }
        if (name == "gssapi-r3-attach-user-contract")
        {
            testR3AttachUserContract();
            return 0;
        }
        if (name == "gssapi-r3-attach-user-terminal-replay-fence")
        {
            testR3AttachUserTerminalReplayFence();
            return 0;
        }
        if (name == "gssapi-r3-channel-join-contract")
        {
            testR3ProtectedChannelJoinContract();
            return 0;
        }
        if (name == "gssapi-r3-channel-join-terminal-replay-fence")
        {
            testR3ChannelJoinTerminalReplayFence();
            return 0;
        }
        if (name == "gssapi-r3-joined-clipboard-role-contract")
        {
            testR3JoinedClipboardRoleContract();
            return 0;
        }
        if (name == "gssapi-r3-client-info-route-contract")
        {
            testR3ClientInfoRouteContract();
            return 0;
        }
        if (name == "gssapi-r3-server-license-request-write-contract")
        {
            testR3ServerLicenseRequestWriteContract();
            return 0;
        }
        if (name == "gssapi-r3-client-licensing-route-contract")
        {
            testR3ClientLicensingRouteContract();
            return 0;
        }
        if (name == "gssapi-r3-server-platform-challenge-write-contract")
        {
            testR3ServerPlatformChallengeWriteContract();
            return 0;
        }
        if (name == "gssapi-r3-client-platform-challenge-response-route-contract")
        {
            testR3ClientPlatformChallengeResponseRouteContract();
            return 0;
        }
        if (name == "gssapi-r3-native-change-revocation")
        {
            testR3NativeChangeRevocation();
            return 0;
        }
        if (name == "gssapi-r3-mcs-disconnect-revocation-fence")
        {
            testR3McsDisconnectRevocationFence();
            return 0;
        }
        return 2;
    };
    if (argc == 2)
    {
        return invoke(argv[1]);
    }
    if (argc != 1)
    {
        return 2;
    }
    testConfigurationRejections();
    testFramedGssHandoffFailClosed();
    testConsoleGssProvenanceBeforeOsRead();
    testNativeAdmissionCapabilityDenials();
    testNativeAdmissionR1NlaProvenanceDenials();
    testR3InitialNlaOwnerFence();
    testR3McsAdmissionContract();
    testR3ProtectedTransitionGenerationFence();
    testR3ConnectResponseWriteContract();
    testR3ConnectResponseCompletionReauthorization();
    testR3ErectDomainContract();
    testR3ProtectedTransitionTerminalReplayFence();
    testR3AttachUserContract();
    testR3AttachUserTerminalReplayFence();
    testR3ProtectedChannelJoinContract();
    testR3ChannelJoinTerminalReplayFence();
    testR3JoinedClipboardRoleContract();
    testR3ClientInfoRouteContract();
    testR3ServerLicenseRequestWriteContract();
    testR3ClientLicensingRouteContract();
    testR3ServerPlatformChallengeWriteContract();
    testR3ClientPlatformChallengeResponseRouteContract();
    testR3NativeChangeRevocation();
    testR3McsDisconnectRevocationFence();
    return 0;
}
