// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_tls_context.h"
#include "transport/preauth_session.h"
#include "transport/nonblocking_tcp_adapter.h"
#include "transport/mcs_connect_response.h"
#include "transport/tpkt_x224.h"
#include "security/credssp_tsrequest.h"
#include "security/credssp_tls_certificate.h"
#ifdef RDP_TEST_LINUX_GSSAPI
#include "server/runtime/linux_runtime_connection.h"
#include "security/gssapi_spnego_acceptor.h"
#include "security/linux_console_admission.h"
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <cstdlib>
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <fstream>
#include <filesystem>
#include <memory>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
#include <thread>
#include <chrono>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef OWNED_MCS_FIXTURE_PATH
#error OWNED_MCS_FIXTURE_PATH must point to the checked-in Microsoft fixture
#endif

using namespace rdp_server::server::transport;
using namespace rdp_server::server::security;
using rdp_server::server::runtime::RuntimeServerTlsContext;
#ifdef RDP_TEST_LINUX_GSSAPI
using rdp_server::server::runtime::LinuxCredSspStepStatus;
using rdp_server::server::runtime::LinuxRuntimeConnection;
using rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration;
#endif

namespace
{

[[nodiscard]] std::vector<std::uint8_t> validMcsPacket()
{
    std::ifstream file{OWNED_MCS_FIXTURE_PATH};
    assert(file.good());
    std::vector<std::uint8_t> bytes;
    std::string line;
    while (std::getline(file, line))
    {
        if (line.empty() || line.front() == '#')
        {
            continue;
        }
        std::istringstream input{line};
        unsigned int octet = 0;
        while (input >> std::hex >> octet)
        {
            assert(octet <= 255);
            bytes.push_back(static_cast<std::uint8_t>(octet));
        }
        assert(input.eof());
    }
    assert(bytes.size() == 416);
    return bytes;
}


using ContextPointer = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPointer = std::unique_ptr<SSL, decltype(&SSL_free)>;
using KeyPointer = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CertificatePointer = std::unique_ptr<X509, decltype(&X509_free)>;
using X509NamePointer = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;

struct TlsHandshakeFixture final
{
    ContextPointer serverContext{SSL_CTX_new(TLS_server_method()), SSL_CTX_free};
    ContextPointer clientContext{SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
    SslPointer server{nullptr, SSL_free};
    SslPointer client{nullptr, SSL_free};

    explicit TlsHandshakeFixture(bool completeImmediately = true,
                                 bool useMemoryBio = true,
                                 std::size_t serverBioCapacity = 0)
    {
        assert(serverContext && clientContext);
        assert(SSL_CTX_set_min_proto_version(serverContext.get(),
                                             TLS1_2_VERSION) == 1);
        assert(SSL_CTX_set_min_proto_version(clientContext.get(),
                                             TLS1_2_VERSION) == 1);
        // A fresh key/certificate exists ONLY in memory during this test.
        // Client verification is disabled only for this self-signed test.
        const KeyPointer key{EVP_EC_gen("prime256v1"), EVP_PKEY_free};
        const CertificatePointer cert{X509_new(), X509_free};
        assert(key && cert);
        assert(X509_set_version(cert.get(), 2) == 1);
        assert(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1);
        assert(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60));
        assert(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600));
        assert(X509_set_pubkey(cert.get(), key.get()) == 1);
        // OpenSSL 4 returns const X509_NAME* from X509_get_subject_name.
        // Build an independent mutable X.509 name before installing it
        // in the certificate; this works with OpenSSL 3 and OpenSSL 4.
        const X509NamePointer name{X509_NAME_new(), X509_NAME_free};
        assert(name);
        assert(X509_NAME_add_entry_by_txt(
            name.get(), "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char *>("rdp-test-only"),
            -1, -1, 0) == 1);
        assert(X509_set_subject_name(cert.get(), name.get()) == 1);
        assert(X509_set_issuer_name(cert.get(), name.get()) == 1);
        assert(X509_sign(cert.get(), key.get(), EVP_sha256()) > 0);
        assert(SSL_CTX_use_certificate(serverContext.get(), cert.get()) == 1);
        assert(SSL_CTX_use_PrivateKey(serverContext.get(), key.get()) == 1);
        assert(SSL_CTX_check_private_key(serverContext.get()) == 1);

        server.reset(SSL_new(serverContext.get()));
        client.reset(SSL_new(clientContext.get()));
        assert(server && client);
        if (useMemoryBio)
        {
            BIO *serverBio = nullptr;
            BIO *clientBio = nullptr;
            assert(BIO_new_bio_pair(&serverBio, serverBioCapacity,
                                    &clientBio, 0) == 1);
            // OpenSSL assumes ownership of both ends for memory-only
            // regressions. Native socket tests attach their own BIOs.
            SSL_set_bio(server.get(), serverBio, serverBio);
            SSL_set_bio(client.get(), clientBio, clientBio);
        }
        SSL_set_accept_state(server.get());
        SSL_set_connect_state(client.get());

        if (completeImmediately)
        {
            assert(useMemoryBio);
            completeHandshake();
        }
    }

    void completeHandshake()
    {
        // Nonblocking in-memory BIO transport. Tests of production
        // advanceTlsHandshake call it separately on each readiness event.
        for (int pass = 0; pass < 64; ++pass)
        {
            const int clientResult = SSL_do_handshake(client.get());
            if (clientResult != 1)
            {
                const int error = SSL_get_error(client.get(), clientResult);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
            const int serverResult = SSL_do_handshake(server.get());
            if (serverResult != 1)
            {
                const int error = SSL_get_error(server.get(), serverResult);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
            if (SSL_is_init_finished(client.get()) == 1 &&
                SSL_is_init_finished(server.get()) == 1)
            {
                break;
            }
        }
        assert(SSL_is_init_finished(client.get()) == 1);
        assert(SSL_is_init_finished(server.get()) == 1);
        assert(SSL_version(server.get()) >= TLS1_2_VERSION);
    }
};

struct RuntimeTlsClientFixture final
{
    ContextPointer context{SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
    SslPointer connection{nullptr, SSL_free};

    RuntimeTlsClientFixture()
    {
        assert(context);
        assert(SSL_CTX_set_min_proto_version(context.get(),
                                             TLS1_2_VERSION) == 1);
        // This loopback client verifies the server identity explicitly with
        // X509_cmp after the handshake; no CA store or external trust exists.
        SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
        connection.reset(SSL_new(context.get()));
        assert(connection);
        SSL_set_connect_state(connection.get());
    }
};

[[nodiscard]] const TlsHandshakeFixture &completedTls()
{
    // Reuse one real, completed OpenSSL handshake across deterministic
    // preauth framing regressions; it does NOT authorize user identity.
    static const TlsHandshakeFixture fixture{};
    return fixture;
}

[[nodiscard]] constexpr std::array<std::uint8_t, 19>
validRequestWire() noexcept
{
    return {
        3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0,
        1, 0, 8, 0, 1, 0, 0, 0,
    };
}

[[nodiscard]] ConnectionParseResult validRequest()
{
    return parseConnectionRequest(validRequestWire());
}

[[nodiscard]] constexpr std::array<std::uint8_t, 19>
tlsAndHybridRequestWire() noexcept
{
    auto request = validRequestWire();
    request[15] = static_cast<std::uint8_t>(
        kRdpProtocolSsl | kRdpProtocolHybrid);
    return request;
}

[[nodiscard]] bool acknowledgeCompleteReply(
    PreauthConnectionStream &connection)
{
    const auto remaining = connection.pendingConnectionReply();
    return remaining.size() == 19 &&
           connection.onConnectionReplyBytesWritten(remaining.size()) ==
               ConnectionReplyWriteStatus::ReplySentStartTls;
}

void advanceToMcs(PreauthConnectionStream &connection)
{
    const auto request = connection.consumeConnectionRequest(
        validRequestWire());
    assert(request.bytesConsumed == validRequestWire().size());
    assert(request.status == ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(connection));
    assert(connection.onTlsHandshake(completedTls().server.get()));
    assert(connection.stage() == PreauthStage::AwaitMcsConnectInitial);
}


void testFragmentedConnectionRequestIntake()
{
    const auto request = validRequestWire();
    for (std::size_t split = 0; split < request.size(); ++split)
    {
        PreauthConnectionStream connection;
        const auto first = connection.consumeConnectionRequest(
            std::span(request).first(split));
        assert(first.bytesConsumed == split);
        assert(first.status == ConnectionIntakeStatus::NeedMore);
        assert(connection.stage() == PreauthStage::AwaitConnectionRequest);

        const auto second = connection.consumeConnectionRequest(
            std::span(request).subspan(split));
        assert(second.bytesConsumed == request.size() - split);
        assert(second.status == ConnectionIntakeStatus::ReplyThenTls);
        assert(second.reply.decision == SecurityDecision::Tls);
        assert(second.reply.packet[11] == 0x02);
        assert(connection.stage() == PreauthStage::AwaitTls);

        // A valid request is never accepted twice.
        assert(connection.consumeConnectionRequest(request).status ==
               ConnectionIntakeStatus::Closed);
        assert(connection.onTlsHandshake(nullptr) == false);
        assert(connection.stage() == PreauthStage::Closed);
    }

    PreauthConnectionStream bytewise;
    for (std::size_t index = 0; index < request.size(); ++index)
    {
        const auto result = bytewise.consumeConnectionRequest(
            std::span(request).subspan(index, 1));
        assert(result.bytesConsumed == 1);
        assert(result.status ==
               (index + 1 == request.size()
                    ? ConnectionIntakeStatus::ReplyThenTls
                    : ConnectionIntakeStatus::NeedMore));
    }
    assert(bytewise.stage() == PreauthStage::AwaitTls);
}

void testConnectionRequestByteBoundaryAndFailure()
{
    const auto request = validRequestWire();
    // A receive can already contain TLS data. Never consume beyond the
    // first complete X.224 request before the Security Reply is sent.
    std::vector<std::uint8_t> coalesced(request.begin(), request.end());
    coalesced.insert(coalesced.end(), {0x16, 0x03, 0x03, 0x00, 0x05});
    PreauthConnectionStream withTrailingTls;
    const auto result = withTrailingTls.consumeConnectionRequest(coalesced);
    assert(result.status == ConnectionIntakeStatus::ReplyThenTls);
    assert(result.bytesConsumed == request.size());
    assert(withTrailingTls.consumeConnectionRequest(
               std::span(coalesced).subspan(request.size())).bytesConsumed == 0);
    assert(withTrailingTls.stage() == PreauthStage::AwaitTls);
    assert(acknowledgeCompleteReply(withTrailingTls));
    assert(withTrailingTls.onTlsHandshake(completedTls().server.get()));
    assert(withTrailingTls.stage() == PreauthStage::AwaitMcsConnectInitial);
    withTrailingTls.close();

    auto unsupported = request;
    unsupported[15] = 0; // Client did not offer TLS.
    PreauthConnectionStream noTls;
    const auto rejection = noTls.consumeConnectionRequest(unsupported);
    assert(rejection.status == ConnectionIntakeStatus::ReplyThenClose);
    assert(rejection.bytesConsumed == unsupported.size());
    assert(rejection.reply.decision == SecurityDecision::Reject);
    assert(rejection.reply.packet[11] == 0x03);
    assert(noTls.stage() == PreauthStage::Closed);

    auto invalid = request;
    invalid[5] = 0xf0; // Not an X.224 Connection Request TPDU.
    PreauthConnectionStream malformed;
    const auto bad = malformed.consumeConnectionRequest(invalid);
    assert(bad.status == ConnectionIntakeStatus::Invalid);
    assert(bad.bytesConsumed == invalid.size());
    assert(malformed.stage() == PreauthStage::Closed);
    assert(malformed.consumeConnectionRequest(request).bytesConsumed == 0);
}


void testRealTlsTransportGate()
{
    const auto request = validRequestWire();
    const auto &tls = completedTls();
    assert(SSL_is_server(tls.server.get()) == 1);
    assert(SSL_is_init_finished(tls.server.get()) == 1);

    // Even a cryptographically complete handshake cannot be installed
    // before the X.224 Confirm write has completed.
    PreauthConnectionStream early;
    assert(early.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(!early.onTlsHandshake(tls.server.get()));
    assert(early.stage() == PreauthStage::Closed);

    // A TLS CLIENT SSL handle is not valid evidence for the server.
    PreauthConnectionStream wrongRole;
    assert(wrongRole.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(wrongRole));
    assert(!wrongRole.onTlsHandshake(tls.client.get()));
    assert(wrongRole.stage() == PreauthStage::Closed);

    // SSL_new only allocates an SSL handle: neither a configured
    // certificate nor SSL_set_accept_state establishes a TLS session.
    const SslPointer unfinished{SSL_new(tls.serverContext.get()), SSL_free};
    assert(unfinished);
    SSL_set_accept_state(unfinished.get());
    PreauthConnectionStream incomplete;
    assert(incomplete.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(incomplete));
    assert(!incomplete.onTlsHandshake(unfinished.get()));
    assert(incomplete.stage() == PreauthStage::Closed);

    PreauthConnectionStream nullTls;
    assert(nullTls.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(nullTls));
    assert(!nullTls.onTlsHandshake(nullptr));
    assert(nullTls.stage() == PreauthStage::Closed);

    PreauthConnectionStream real;
    assert(real.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(real));
    assert(real.onTlsHandshake(tls.server.get()));
    assert(real.stage() == PreauthStage::AwaitMcsConnectInitial);
    // The same completed TLS object cannot be replayed to advance again.
    assert(!real.onTlsHandshake(tls.server.get()));
    assert(real.stage() == PreauthStage::Closed);
}

void testConnectionReplyMustBeSentBeforeTls()
{
    const auto request = validRequestWire();

    PreauthConnectionStream prematureTls;
    assert(prematureTls.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(!prematureTls.onTlsHandshake(completedTls().server.get()));
    assert(prematureTls.stage() == PreauthStage::Closed);

    PreauthConnectionStream failedSend;
    assert(failedSend.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    // A hard socket I/O error aborts any pending reply.
    failedSend.close();
    assert(failedSend.stage() == PreauthStage::Closed);

    PreauthConnectionStream repeatedSend;
    assert(repeatedSend.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(repeatedSend));
    assert(repeatedSend.onConnectionReplyBytesWritten(1) ==
           ConnectionReplyWriteStatus::Invalid);
    assert(repeatedSend.stage() == PreauthStage::Closed);

    PreauthConnectionStream prematureReport;
    assert(prematureReport.onConnectionReplyBytesWritten(19) ==
           ConnectionReplyWriteStatus::Invalid);
    assert(prematureReport.stage() == PreauthStage::Closed);

    PreauthConnectionStream successfulTls;
    assert(successfulTls.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(successfulTls));
    assert(successfulTls.onTlsHandshake(completedTls().server.get()));
    assert(successfulTls.stage() == PreauthStage::AwaitMcsConnectInitial);
    // The same TLS transition is not reusable.
    assert(!successfulTls.onTlsHandshake(completedTls().server.get()));
    assert(successfulTls.stage() == PreauthStage::Closed);
}


void testPartialConnectionReplyWrites()
{
    constexpr std::size_t kReplyBytes = 19;
    const auto request = validRequestWire();
    const auto expected =
        negotiateDiagnosticTls(parseConnectionRequest(request)).packet;

    for (std::size_t split = 0; split <= kReplyBytes; ++split)
    {
        PreauthConnectionStream connection;
        assert(connection.pendingConnectionReply().empty());
        const auto response = connection.consumeConnectionRequest(request);
        assert(response.status == ConnectionIntakeStatus::ReplyThenTls);
        assert(response.reply.packet == expected);
        assert(connection.pendingConnectionReply().size() == kReplyBytes);
        assert(connection.onConnectionReplyBytesWritten(0) ==
               ConnectionReplyWriteStatus::NeedMore);
        if (split != 0)
        {
            assert(connection.onConnectionReplyBytesWritten(split) ==
                   (split == kReplyBytes
                        ? ConnectionReplyWriteStatus::ReplySentStartTls
                        : ConnectionReplyWriteStatus::NeedMore));
        }
        if (split < kReplyBytes)
        {
            const auto suffix = connection.pendingConnectionReply();
            assert(suffix.size() == kReplyBytes - split);
            assert(std::equal(suffix.begin(), suffix.end(),
                              expected.begin() + split));
            assert(connection.stage() == PreauthStage::AwaitTls);
            assert(connection.onConnectionReplyBytesWritten(suffix.size()) ==
                   ConnectionReplyWriteStatus::ReplySentStartTls);
        }
        assert(connection.pendingConnectionReply().empty());
        assert(connection.onTlsHandshake(completedTls().server.get()));
        connection.close();
    }

    PreauthConnectionStream bytewise;
    assert(bytewise.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    for (std::size_t i = 0; i < kReplyBytes; ++i)
    {
        const auto pending = bytewise.pendingConnectionReply();
        assert(pending.size() == kReplyBytes - i);
        assert(pending.front() == expected[i]);
        assert(bytewise.onConnectionReplyBytesWritten(1) ==
               (i + 1 == kReplyBytes
                    ? ConnectionReplyWriteStatus::ReplySentStartTls
                    : ConnectionReplyWriteStatus::NeedMore));
    }
    bytewise.close();

    PreauthConnectionStream overrun;
    assert(overrun.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(overrun.onConnectionReplyBytesWritten(kReplyBytes + 1) ==
           ConnectionReplyWriteStatus::Invalid);
    assert(overrun.stage() == PreauthStage::Closed);
    assert(overrun.pendingConnectionReply().empty());

    PreauthConnectionStream premature;
    assert(premature.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(premature.onConnectionReplyBytesWritten(kReplyBytes - 1) ==
           ConnectionReplyWriteStatus::NeedMore);
    assert(!premature.onTlsHandshake(completedTls().server.get()));
    assert(premature.stage() == PreauthStage::Closed);

    auto unsupported = request;
    unsupported[15] = 0;
    PreauthConnectionStream rejected;
    const auto failure = rejected.consumeConnectionRequest(unsupported);
    assert(failure.status == ConnectionIntakeStatus::ReplyThenClose);
    assert(rejected.stage() == PreauthStage::Closed);
    assert(failure.reply.packet[11] == 3);
    const auto pending = rejected.pendingConnectionReply();
    assert(pending.size() == kReplyBytes);
    assert(std::equal(pending.begin(), pending.end(),
                      failure.reply.packet.begin()));
    assert(rejected.onConnectionReplyBytesWritten(9) ==
           ConnectionReplyWriteStatus::NeedMore);
    assert(rejected.pendingConnectionReply().size() == 10);
    assert(rejected.onConnectionReplyBytesWritten(10) ==
           ConnectionReplyWriteStatus::ReplySentClose);
    assert(rejected.pendingConnectionReply().empty());
    assert(rejected.onConnectionReplyBytesWritten(1) ==
           ConnectionReplyWriteStatus::Closed);

    PreauthConnectionStream cancelled;
    assert(cancelled.consumeConnectionRequest(request).status ==
           ConnectionIntakeStatus::ReplyThenTls);
    assert(cancelled.onConnectionReplyBytesWritten(5) ==
           ConnectionReplyWriteStatus::NeedMore);
    cancelled.close();
    assert(cancelled.pendingConnectionReply().empty());
    assert(cancelled.onConnectionReplyBytesWritten(14) ==
           ConnectionReplyWriteStatus::Closed);
}

void testIncrementalDecryptedMcsIntake()
{
    const auto frame = validMcsPacket();

    // Every split, including zero-length first input, must reassemble
    // exactly one BER MCS Connect Initial / GCC Conference Create PDU.
    for (std::size_t split = 0; split < frame.size(); ++split)
    {
        PreauthConnectionStream connection;
        advanceToMcs(connection);
        const auto first = connection.consumeDecryptedMcsConnectInitial(
            std::span(frame).first(split));
        assert(first.bytesConsumed == split);
        assert(first.status == McsIntakeStatus::NeedMore);
        assert(connection.stage() == PreauthStage::AwaitMcsConnectInitial);

        const auto last = connection.consumeDecryptedMcsConnectInitial(
            std::span(frame).subspan(split));
        assert(last.bytesConsumed == frame.size() - split);
        assert(last.status == McsIntakeStatus::EnvelopeValidated);
        assert(connection.stage() == PreauthStage::Closed);
        const auto replay = connection.consumeDecryptedMcsConnectInitial(frame);
        assert(replay.bytesConsumed == 0);
        assert(replay.status == McsIntakeStatus::Closed);
    }

    PreauthConnectionStream bytewise;
    advanceToMcs(bytewise);
    for (std::size_t index = 0; index < frame.size(); ++index)
    {
        const auto consumed = bytewise.consumeDecryptedMcsConnectInitial(
            std::span(frame).subspan(index, 1));
        assert(consumed.bytesConsumed == 1);
        assert(consumed.status ==
               (index + 1 == frame.size()
                    ? McsIntakeStatus::EnvelopeValidated
                    : McsIntakeStatus::NeedMore));
    }

    // One TLS read may contain a later TPKT: return only the bytes
    // belonging to the first, validated envelope, never admit the rest.
    auto combined = frame;
    combined.insert(combined.end(), {3, 0, 0, 8, 2, 0xf0, 0x80, 0});
    PreauthConnectionStream coalesced;
    advanceToMcs(coalesced);
    const auto result = coalesced.consumeDecryptedMcsConnectInitial(combined);
    assert(result.status == McsIntakeStatus::EnvelopeValidated);
    assert(result.bytesConsumed == frame.size());
    assert(coalesced.stage() == PreauthStage::Closed);
}

void testRejectedDecryptedMcsBoundaries()
{
    const auto reference = validMcsPacket();

    // No decrypted data can be fed before a completed X.224 reply and
    // a synthetic successful TLS transition. No credentials are accepted.
    PreauthConnectionStream premature;
    const auto early = premature.consumeDecryptedMcsConnectInitial(reference);
    assert(early.bytesConsumed == 0);
    assert(early.status == McsIntakeStatus::Invalid);
    assert(premature.stage() == PreauthStage::Closed);

    for (const auto invalidHeader : {
             std::array<std::uint8_t, 4>{4, 0, 1, 0xa0},
             std::array<std::uint8_t, 4>{3, 1, 1, 0xa0},
             std::array<std::uint8_t, 4>{3, 0, 0, 7},
             std::array<std::uint8_t, 4>{3, 0, 0x20, 1},
             std::array<std::uint8_t, 4>{3, 0, 0xff, 0xff},
         })
    {
        PreauthConnectionStream connection;
        advanceToMcs(connection);
        auto hostile = reference;
        std::copy(invalidHeader.begin(), invalidHeader.end(), hostile.begin());
        const auto result = connection.consumeDecryptedMcsConnectInitial(hostile);
        assert(result.bytesConsumed == 4); // Reject before payload buffering.
        assert(result.status == McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
    }

    for (std::size_t index = 4; index < 7; ++index)
    {
        PreauthConnectionStream connection;
        advanceToMcs(connection);
        auto hostile = reference;
        hostile[index] ^= 0x01;
        const auto result = connection.consumeDecryptedMcsConnectInitial(hostile);
        assert(result.bytesConsumed == 7); // Reject before BER buffering.
        assert(result.status == McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
    }

    // A BER-valid client domain proposal which cannot negotiate
    // RDP's protocolVersion 2 must fail closed after the full TPKT.
    auto unsupportedDomain = reference;
    unsupportedDomain[47] = 3;
    unsupportedDomain[74] = 3;
    unsupportedDomain[104] = 3;
    assert(parseMcsConnectInitial(unsupportedDomain));
    PreauthConnectionStream invalidDomain;
    advanceToMcs(invalidDomain);
    const auto invalidMerge =
        invalidDomain.consumeDecryptedMcsConnectInitial(unsupportedDomain);
    assert(invalidMerge.bytesConsumed == reference.size());
    assert(invalidMerge.status == McsIntakeStatus::Invalid);
    assert(invalidDomain.stage() == PreauthStage::Closed);

    auto hostileBer = reference;
    hostileBer[7] = 0; // Not BER APPLICATION 101 (0x7F 0x65).
    PreauthConnectionStream badBer;
    advanceToMcs(badBer);
    const auto malformed = badBer.consumeDecryptedMcsConnectInitial(hostileBer);
    assert(malformed.bytesConsumed == reference.size());
    assert(malformed.status == McsIntakeStatus::Invalid);
    assert(badBer.stage() == PreauthStage::Closed);

    // A decrypted frame truncated at any position cannot validate until
    // its advertised TPKT length has arrived. Disconnect discards it.
    for (std::size_t cut = 0; cut < reference.size(); ++cut)
    {
        PreauthConnectionStream truncated;
        advanceToMcs(truncated);
        const auto partial = truncated.consumeDecryptedMcsConnectInitial(
            std::span(reference).first(cut));
        assert(partial.bytesConsumed == cut);
        assert(partial.status == McsIntakeStatus::NeedMore);
        truncated.close();
        assert(truncated.stage() == PreauthStage::Closed);
        assert(truncated.consumeDecryptedMcsConnectInitial(reference).status ==
               McsIntakeStatus::Closed);
    }
}


void writeTlsClientApplicationData(SSL *client,
                                   std::span<const std::uint8_t> data)
{
    std::size_t offset = 0;
    while (offset < data.size())
    {
        std::size_t sent = 0;
        const int ok = SSL_write_ex(client, data.data() + offset,
                                    data.size() - offset, &sent);
        assert(ok == 1);
        assert(sent > 0 && sent <= data.size() - offset);
        offset += sent;
    }
}

void advanceToTlsMcs(PreauthConnectionStream &connection, SSL *server)
{
    const auto response = connection.consumeConnectionRequest(validRequestWire());
    assert(response.status == ConnectionIntakeStatus::ReplyThenTls);
    assert(acknowledgeCompleteReply(connection));
    assert(connection.onTlsHandshake(server));
    assert(connection.stage() == PreauthStage::AwaitMcsConnectInitial);
}

void testActualTlsApplicationDataIntake()
{
    const auto packet = validMcsPacket();
    // Each split uses a separate completed OpenSSL TLS session; fragments
    // are actual TLS encrypted records, not direct parser input.
    for (std::size_t split = 0; split < packet.size(); ++split)
    {
        TlsHandshakeFixture tls;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());
        assert(connection.consumeMcsConnectInitialFromTls(tls.server.get())
                   .status == McsIntakeStatus::NeedMore);
        if (split != 0)
        {
            writeTlsClientApplicationData(
                tls.client.get(), std::span(packet).first(split));
            const auto first =
                connection.consumeMcsConnectInitialFromTls(tls.server.get());
            assert(first.bytesConsumed == split);
            assert(first.status == McsIntakeStatus::NeedMore);
        }
        writeTlsClientApplicationData(
            tls.client.get(), std::span(packet).subspan(split));
        const auto last =
            connection.consumeMcsConnectInitialFromTls(tls.server.get());
        assert(last.bytesConsumed == packet.size() - split);
        assert(last.status == McsIntakeStatus::EnvelopeValidated);
        assert(connection.stage() == PreauthStage::Closed);
        assert(connection.consumeMcsConnectInitialFromTls(tls.server.get())
                   .status == McsIntakeStatus::Closed);
    }

    // One TLS application record containing more than one RDP TPKT must
    // not cause the second packet to be consumed or admitted.
    TlsHandshakeFixture tls;
    PreauthConnectionStream connection;
    advanceToTlsMcs(connection, tls.server.get());
    auto coalesced = packet;
    constexpr std::array<std::uint8_t, 8> next{
        3, 0, 0, 8, 2, 0xf0, 0x80, 0};
    coalesced.insert(coalesced.end(), next.begin(), next.end());
    writeTlsClientApplicationData(tls.client.get(), coalesced);
    const auto first = connection.consumeMcsConnectInitialFromTls(tls.server.get());
    assert(first.bytesConsumed == packet.size());
    assert(first.status == McsIntakeStatus::EnvelopeValidated);
    std::array<std::uint8_t, 8> remaining{};
    std::size_t read = 0;
    assert(SSL_read_ex(tls.server.get(), remaining.data(),
                       remaining.size(), &read) == 1);
    assert(read == next.size());
    assert(remaining == next);
}

void testTlsRecordFailClosedBoundaries()
{
    const auto packet = validMcsPacket();
    {
        TlsHandshakeFixture tls;
        PreauthConnectionStream premature;
        assert(premature.consumeMcsConnectInitialFromTls(tls.server.get())
                   .status == McsIntakeStatus::Invalid);
        assert(premature.stage() == PreauthStage::Closed);
    }
    {
        TlsHandshakeFixture tls;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());
        assert(connection.consumeMcsConnectInitialFromTls(nullptr).status ==
               McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
    }
    {
        TlsHandshakeFixture tls;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());
        assert(connection.consumeMcsConnectInitialFromTls(tls.client.get())
                   .status == McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
    }
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture alternate;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());
        assert(connection.consumeMcsConnectInitialFromTls(
                   alternate.server.get()).status == McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
    }
    // Reject malformed first four decrypted TPKT bytes without reading
    // the appended MCS/BER data out of this TLS session.
    {
        TlsHandshakeFixture tls;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());
        auto damaged = packet;
        damaged[0] = 4;
        writeTlsClientApplicationData(tls.client.get(), damaged);
        const auto result =
            connection.consumeMcsConnectInitialFromTls(tls.server.get());
        assert(result.status == McsIntakeStatus::Invalid);
        assert(result.bytesConsumed == 4);
        assert(connection.stage() == PreauthStage::Closed);
        std::array<std::uint8_t, 4> unread{};
        std::size_t read = 0;
        assert(SSL_read_ex(tls.server.get(), unread.data(),
                           unread.size(), &read) == 1);
        assert(read == unread.size());
        assert(unread[0] == packet[4]);
    }
    // TLS orderly EOF before the complete initial packet is fatal for
    // this diagnostic; the stream must never return a valid envelope.
    {
        TlsHandshakeFixture tls;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());
        writeTlsClientApplicationData(
            tls.client.get(), std::span(packet).first(17));
        const auto partial =
            connection.consumeMcsConnectInitialFromTls(tls.server.get());
        assert(partial.status == McsIntakeStatus::NeedMore);
        assert(partial.bytesConsumed == 17);
        assert(SSL_shutdown(tls.client.get()) >= 0);
        const auto closed =
            connection.consumeMcsConnectInitialFromTls(tls.server.get());
        assert(closed.status == McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
    }
}

void testConnectionRequestLengthRejectionAndClose()
{
    const std::array<std::array<std::uint8_t, 4>, 4> invalidHeaders{{
        {4, 0, 0, 19},   // TPKT version
        {3, 1, 0, 19},   // Reserved byte
        {3, 0, 0, 10},   // Shorter than an X.224 CR
        {3, 0, 1, 5},    // Larger than X.224's maximum CR
    }};
    for (const auto &header : invalidHeaders)
    {
        PreauthConnectionStream connection;
        const auto result = connection.consumeConnectionRequest(header);
        assert(result.bytesConsumed == header.size());
        assert(result.status == ConnectionIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
        assert(connection.consumeConnectionRequest(header).status ==
               ConnectionIntakeStatus::Closed);
    }

    PreauthConnectionStream interrupted;
    const std::array<std::uint8_t, 3> fragment{3, 0, 0};
    assert(interrupted.consumeConnectionRequest(fragment).status ==
           ConnectionIntakeStatus::NeedMore);
    interrupted.close();
    assert(interrupted.stage() == PreauthStage::Closed);
    assert(interrupted.consumeConnectionRequest(fragment).bytesConsumed == 0);

    // The diagnostic does not grant authorization even when given a
    // complete handshake and a valid fixture later in the sequence.
    PreauthConnectionStream prematureTls;
    assert(!prematureTls.onTlsHandshake(completedTls().server.get()));
    assert(prematureTls.stage() == PreauthStage::Closed);
}

} // namespace


class ScriptedTcp final : public TcpNonblockingIo
{
public:
    std::vector<std::uint8_t> inbound{};
    std::vector<std::uint8_t> outbound{};
    std::size_t readOffset{};
    std::size_t readLimit{260};
    std::size_t writeLimit{19};
    std::size_t largestRead{};
    bool blockRead{};
    bool blockWrite{};
    bool eofRead{};
    bool failRead{};
    bool failWrite{};
    bool overreportRead{};
    bool overreportWrite{};
    bool zeroProgressRead{};
    bool zeroProgressWrite{};

    [[nodiscard]] TcpIoResult receive(
        std::span<std::uint8_t> destination) noexcept override
    {
        largestRead = (std::max)(largestRead, destination.size());
        if (overreportRead)
            return {TcpIoOutcome::Progress, destination.size() + 1};
        if (failRead) return {TcpIoOutcome::Failure, 0};
        if (eofRead) return {TcpIoOutcome::EndOfStream, 0};
        if (zeroProgressRead) return {TcpIoOutcome::Progress, 0};
        if (blockRead) return {TcpIoOutcome::WouldBlock, 0};
        const std::size_t available = inbound.size() - readOffset;
        const auto count = (std::min)(
            (std::min)(destination.size(), readLimit), available);
        if (!count) return {TcpIoOutcome::WouldBlock, 0};
        std::copy_n(inbound.begin() + readOffset, count, destination.begin());
        readOffset += count;
        return {TcpIoOutcome::Progress, count};
    }

    [[nodiscard]] TcpIoResult send(
        std::span<const std::uint8_t> source) noexcept override
    {
        if (overreportWrite)
            return {TcpIoOutcome::Progress, source.size() + 1};
        if (failWrite) return {TcpIoOutcome::Failure, 0};
        if (zeroProgressWrite) return {TcpIoOutcome::Progress, 0};
        if (blockWrite) return {TcpIoOutcome::WouldBlock, 0};
        const auto count = (std::min)(source.size(), writeLimit);
        if (!count) return {TcpIoOutcome::WouldBlock, 0};
        outbound.insert(outbound.end(), source.begin(), source.begin() + count);
        return {TcpIoOutcome::Progress, count};
    }
};


void testBorrowedTcpBioChunkBounds()
{
    // The TLS BIO callback must never pass an unchecked OpenSSL buffer
    // size to TCP I/O. One callback performs at most one bounded read
    // or write without accumulating data or retry-looping internally.
    TlsHandshakeFixture tls{false, false};
    ScriptedTcp tcp;
    assert(attachNonblockingTcpBio(tls.server.get(), tcp));
    BIO *bio = SSL_get_rbio(tls.server.get());
    assert(bio != nullptr && bio == SSL_get_wbio(tls.server.get()));

    constexpr std::size_t maxChunk = kMaximumTcpIoChunkBytes;
    std::vector<std::uint8_t> payload(maxChunk * 2U + 19U);
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<std::uint8_t>(i & 0xffU);
    std::vector<std::uint8_t> output(payload.size(), 0xffU);

    std::size_t actual = 777U;
    assert(BIO_read_ex(bio, output.data(), output.size(), &actual) == 0);
    assert(actual == 0 && BIO_should_read(bio));
    assert(tcp.largestRead == maxChunk);

    tcp.inbound = payload;
    tcp.readLimit = payload.size();
    std::size_t offset = 0;
    for (const auto expected : {maxChunk, maxChunk, std::size_t{19}})
    {
        actual = 777U;
        assert(BIO_read_ex(
            bio, output.data() + offset, output.size() - offset,
            &actual) == 1);
        assert(actual == expected && !BIO_should_retry(bio));
        offset += actual;
    }
    assert(offset == payload.size());
    assert(output == payload);
    assert(tcp.largestRead == maxChunk);
    tcp.overreportRead = true;
    actual = 777U;
    assert(BIO_read_ex(bio, output.data(), output.size(), &actual) == 0);
    assert(actual == 0 && !BIO_should_retry(bio));
    tcp.overreportRead = false;

    tcp.writeLimit = payload.size();
    offset = 0;
    for (const auto expected : {maxChunk, maxChunk, std::size_t{19}})
    {
        actual = 777U;
        assert(BIO_write_ex(
            bio, payload.data() + offset, payload.size() - offset,
            &actual) == 1);
        assert(actual == expected && !BIO_should_retry(bio));
        offset += actual;
    }
    assert(offset == payload.size() && tcp.outbound == payload);
    tcp.blockWrite = true;
    actual = 777U;
    assert(BIO_write_ex(bio, payload.data(), payload.size(), &actual) == 0);
    assert(actual == 0 && BIO_should_write(bio));
    tcp.blockWrite = false;
    tcp.overreportWrite = true;
    actual = 777U;
    assert(BIO_write_ex(bio, payload.data(), payload.size(), &actual) == 0);
    assert(actual == 0 && !BIO_should_retry(bio));
}

void testTcpAdapterFragmentedIo()
{
    const auto req = validRequestWire();
    for (std::size_t split = 0; split <= req.size(); ++split)
    {
        ScriptedTcp tcp;
        tcp.inbound.assign(req.begin(), req.begin() + split);
        tcp.readLimit = 1;
        tcp.writeLimit = 1;
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onWritable() == TcpPreauthEvent::NeedRead);
        assert(adapter.onReadable() ==
               (split == req.size() ? TcpPreauthEvent::NeedWrite
                                    : TcpPreauthEvent::NeedRead));
        assert(tcp.readOffset == split);
        tcp.inbound.insert(tcp.inbound.end(),
                           req.begin() + split, req.end());
        // Simulate a TCP segment that also contains the first TLS
        // ClientHello bytes. Neither native recv nor the parser may
        // consume them as an X.224 Connection Request.
        constexpr std::array<std::uint8_t, 5> tlsPrefix{
            0x16, 0x03, 0x03, 0, 0x05};
        tcp.inbound.insert(tcp.inbound.end(), tlsPrefix.begin(),
                           tlsPrefix.end());
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(tcp.readOffset == req.size());
        assert(tcp.largestRead <= 15);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(tcp.readOffset == req.size());

        tcp.blockWrite = true;
        assert(adapter.onWritable() == TcpPreauthEvent::NeedWrite);
        assert(tcp.outbound.empty());
        tcp.blockWrite = false;
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onReadable() == TcpPreauthEvent::ReadyForTls);
        assert(tcp.outbound.size() == 19);
        const auto expected = negotiateDiagnosticTls(validRequest()).packet;
        assert(std::equal(tcp.outbound.begin(), tcp.outbound.end(),
                          expected.begin()));
        assert(tcp.inbound.size() - tcp.readOffset == tlsPrefix.size());
        assert(std::equal(tcp.inbound.begin() + tcp.readOffset,
                          tcp.inbound.end(), tlsPrefix.begin()));
        assert(adapter.connection().onTlsHandshake(
            completedTls().server.get()));
        adapter.close();
        assert(adapter.onReadable() == TcpPreauthEvent::Closed);
    }
}

void testTcpAdapterFailureAndBackpressure()
{
    const auto request = validRequestWire();

    // The exact same native output path carries NEG_FAILURE to completion,
    // with no possibility of starting TLS on rejected security.
    {
        auto unsupported = request;
        unsupported[15] = 0;
        ScriptedTcp tcp;
        tcp.inbound.assign(unsupported.begin(), unsupported.end());
        tcp.readLimit = 2;
        tcp.writeLimit = 2;
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(adapter.onWritable() == TcpPreauthEvent::Closed);
        const auto expected = negotiateDiagnosticTls(
            parseConnectionRequest(unsupported)).packet;
        assert(tcp.outbound.size() == 19);
        assert(std::equal(tcp.outbound.begin(), tcp.outbound.end(),
                          expected.begin()));
        assert(adapter.onWritable() == TcpPreauthEvent::Closed);
    }

    // Incomplete I/O, EOF and poisoned callback results fail closed.
    for (int fault = 0; fault < 4; ++fault)
    {
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        if (fault == 0) tcp.eofRead = true;
        if (fault == 1) tcp.failRead = true;
        if (fault == 2) tcp.overreportRead = true;
        if (fault == 3) tcp.zeroProgressRead = true;
        assert(adapter.onReadable() == TcpPreauthEvent::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(tcp.outbound.empty());
    }
    for (int fault = 0; fault < 3; ++fault)
    {
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        if (fault == 0) tcp.failWrite = true;
        if (fault == 1) tcp.overreportWrite = true;
        if (fault == 2) tcp.zeroProgressWrite = true;
        assert(adapter.onWritable() == TcpPreauthEvent::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(adapter.connection().pendingConnectionReply().empty());
    }
    {
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        tcp.blockRead = true;
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedRead);
        assert(tcp.readOffset == 0);
        tcp.blockRead = false;
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        tcp.writeLimit = 3;
        tcp.blockWrite = true;
        assert(adapter.onWritable() == TcpPreauthEvent::NeedWrite);
        assert(tcp.outbound.empty());
        tcp.blockWrite = false;
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(tcp.outbound.size() == 19);
    }
    {
        ScriptedTcp tcp;
        auto malformed = request;
        malformed[0] = 4;
        tcp.inbound.assign(malformed.begin(), malformed.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::Invalid);
        assert(tcp.readOffset == 4);
        assert(tcp.outbound.empty());
    }
}


void testAttachedTcpTlsOwnershipDenials()
{
    const auto request = validRequestWire();

    // A completed X.224 response by itself never permits the connected
    // TLS callback without an explicitly attached server-role BIO.
    {
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onAttachedTlsIoReady() ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }

    // Explicitly attaching TLS before the X.224 Confirm is drained
    // must terminate the owner without consuming a TLS ClientHello.
    {
        TlsHandshakeFixture tls{false, false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(!adapter.attachTlsTransport(tls.server.get()));
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }

    // The exact same connected SSL/BIO identity is pinned for all
    // readiness callbacks. A second attach must never replace it.
    {
        TlsHandshakeFixture tls{false, false};
        TlsHandshakeFixture alternate{false, false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.attachTlsTransport(tls.server.get()));
        assert(SSL_get_rbio(tls.server.get()) != nullptr);
        assert(adapter.onTlsIoReady(alternate.server.get()) ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
    {
        TlsHandshakeFixture tls{false, false};
        TlsHandshakeFixture alternate{false, false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.attachTlsTransport(tls.server.get()));
        assert(!adapter.attachTlsTransport(alternate.server.get()));
        assert(SSL_get_rbio(alternate.server.get()) == nullptr);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }

    // Retargeting a borrowed BIO's data pointer on the same SSL
    // must fail BEFORE any new encrypted socket read/write.
    {
        TlsHandshakeFixture tls{false, false};
        ScriptedTcp tcp;
        ScriptedTcp unrelatedTcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.attachTlsTransport(tls.server.get()));
        BIO_set_data(SSL_get_rbio(tls.server.get()), &unrelatedTcp);
        assert(adapter.onAttachedTlsIoReady() ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(tcp.readOffset == request.size());
        assert(unrelatedTcp.readOffset == 0);
        assert(unrelatedTcp.outbound.empty());
    }
}

void testAttachedTcpMcsOrderingDenials()
{
    const auto request = validRequestWire();

    // The attached MCS intake may never run without a TLS transport or
    // before that transport finishes its server-side handshake.
    {
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onAttachedMcsIoReady().status ==
               McsIntakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(adapter.onAttachedMcsIoReady().status ==
               McsIntakeStatus::Closed);
    }
    {
        TlsHandshakeFixture tls{false, false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.attachTlsTransport(tls.server.get()));
        assert(adapter.onAttachedMcsIoReady().status ==
               McsIntakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }

    // An in-place BIO replacement cannot silently substitute a new
    // socket, even if the caller supplies the same SSL pointer.
    {
        TlsHandshakeFixture tls{false, false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter{tcp};
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.attachTlsTransport(tls.server.get()));
        BIO *replacement = BIO_new(BIO_s_mem());
        assert(replacement != nullptr);
        SSL_set_bio(tls.server.get(), replacement, replacement);
        assert(adapter.onAttachedTlsIoReady() ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
}

void testNonblockingTlsHandshakeProgress()
{
    TlsHandshakeFixture tls{false};
    ScriptedTcp tcp;
    const auto request = validRequestWire();
    tcp.inbound.assign(request.begin(), request.end());
    PreauthTcpAdapter adapter(tcp);
    assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
    assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
    assert(adapter.connection().stage() == PreauthStage::AwaitTls);
    assert(SSL_is_init_finished(tls.server.get()) == 0);

    // The initial server step has no ClientHello yet and must ask for
    // readiness without modifying the X.224/TLS session stage.
    assert(adapter.onTlsIoReady(tls.server.get()) ==
           TlsHandshakeStatus::NeedRead);
    assert(adapter.connection().stage() == PreauthStage::AwaitTls);
    assert(SSL_is_init_finished(tls.server.get()) == 0);

    bool established = false;
    for (int attempt = 0; attempt < 64; ++attempt)
    {
        const int clientResult = SSL_do_handshake(tls.client.get());
        if (clientResult != 1)
        {
            const int error = SSL_get_error(tls.client.get(), clientResult);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
        }
        const auto state = adapter.onTlsIoReady(tls.server.get());
        assert(state == TlsHandshakeStatus::NeedRead ||
               state == TlsHandshakeStatus::NeedWrite ||
               state == TlsHandshakeStatus::Established);
        if (state == TlsHandshakeStatus::Established)
        {
            established = true;
            break;
        }
        assert(adapter.connection().stage() == PreauthStage::AwaitTls);
    }
    assert(established);
    assert(SSL_is_init_finished(tls.server.get()) == 1);
    assert(adapter.connection().stage() == PreauthStage::AwaitMcsConnectInitial);

    // The same handshaken provider must decrypt the first MCS/GCC PDU.
    const auto frame = validMcsPacket();
    writeTlsClientApplicationData(tls.client.get(), frame);
    const auto intake =
        adapter.connection().consumeMcsConnectInitialFromTls(tls.server.get());
    assert(intake.status == McsIntakeStatus::EnvelopeValidated);
    assert(intake.bytesConsumed == frame.size());
    assert(adapter.connection().stage() == PreauthStage::Closed);
    assert(adapter.onTlsIoReady(tls.server.get()) ==
           TlsHandshakeStatus::Closed);
}

void testNonblockingTlsHandshakeFailures()
{
    const auto request = validRequestWire();
    // TLS may never start while X.224 Confirm output remains unsent.
    {
        TlsHandshakeFixture tls{false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onTlsIoReady(tls.server.get()) ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(adapter.connection().pendingConnectionReply().empty());
    }
    // Wrong TLS role and null provider fail closed even after Confirm.
    for (int choice = 0; choice < 2; ++choice)
    {
        TlsHandshakeFixture tls{false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onTlsIoReady(choice == 0 ? nullptr : tls.client.get())
               == TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
    // The first WANT_READ binds the EXACT SSL pointer. A different
    // server-role SSL is not permitted to replace the initial provider.
    {
        TlsHandshakeFixture tls{false};
        TlsHandshakeFixture other{false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onTlsIoReady(tls.server.get()) ==
               TlsHandshakeStatus::NeedRead);
        assert(adapter.onTlsIoReady(other.server.get()) ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
    // An unfinished handshake is not evidence of user or MCS admission;
    // explicit transport cancellation must be terminal and replay-safe.
    {
        TlsHandshakeFixture tls{false};
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onTlsIoReady(tls.server.get()) ==
               TlsHandshakeStatus::NeedRead);
        adapter.close();
        assert(adapter.onTlsIoReady(tls.server.get()) ==
               TlsHandshakeStatus::Closed);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
    // Configured accept-side SSL without BIO/socket cannot handshake.
    {
        const ContextPointer context{SSL_CTX_new(TLS_server_method()),
                                     SSL_CTX_free};
        assert(context);
        const SslPointer disconnected{SSL_new(context.get()), SSL_free};
        assert(disconnected);
        SSL_set_accept_state(disconnected.get());
        ScriptedTcp tcp;
        tcp.inbound.assign(request.begin(), request.end());
        PreauthTcpAdapter adapter(tcp);
        assert(adapter.onReadable() == TcpPreauthEvent::NeedWrite);
        assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
        assert(adapter.onTlsIoReady(disconnected.get()) ==
               TlsHandshakeStatus::Invalid);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
}


#ifdef _WIN32
using LocalSocketId = SOCKET;
constexpr LocalSocketId kInvalidLocalSocket = INVALID_SOCKET;
#else
using LocalSocketId = int;
constexpr LocalSocketId kInvalidLocalSocket = -1;
#endif

class LocalSocket final
{
public:
    LocalSocketId value{kInvalidLocalSocket};
    LocalSocket() = default;
    LocalSocket(const LocalSocket &) = delete;
    LocalSocket &operator=(const LocalSocket &) = delete;
    ~LocalSocket() { close(); }

    void close() noexcept
    {
        if (value == kInvalidLocalSocket) return;
#ifdef _WIN32
        ::closesocket(value);
#else
        ::close(value);
#endif
        value = kInvalidLocalSocket;
    }
};

class LoopbackSocketPair final
{
public:
    LocalSocket listener{};
    LocalSocket client{};
    LocalSocket server{};

    explicit LoopbackSocketPair(bool acceptInFixture = true)
    {
#ifdef _WIN32
        assert(WSAStartup(MAKEWORD(2, 2), &wsa_) == 0);
#endif
        listener.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(listener.value != kInvalidLocalSocket);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0; // OS-assigned ephemeral port, loopback only.
        assert(::bind(listener.value,
                      reinterpret_cast<const sockaddr *>(&address),
                      sizeof(address)) == 0);
        assert(::listen(listener.value, 1) == 0);
#ifdef _WIN32
        int addressLength = sizeof(address);
#else
        socklen_t addressLength = sizeof(address);
#endif
        assert(::getsockname(listener.value,
                             reinterpret_cast<sockaddr *>(&address),
                             &addressLength) == 0);
        assert(address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        client.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(client.value != kInvalidLocalSocket);
        // Connect and accept synchronously before switching both ends to
        // nonblocking mode. No RDP service or externally reachable port.
        assert(::connect(client.value,
                         reinterpret_cast<const sockaddr *>(&address),
                         sizeof(address)) == 0);
        if (acceptInFixture)
        {
            server.value = ::accept(listener.value, nullptr, nullptr);
            assert(server.value != kInvalidLocalSocket);
            listener.close(); // No open listener while exercising TLS.
            makeNonblocking(server.value);
        }
        else
        {
            // Let the production acceptor acquire and own this socket.
            makeNonblocking(listener.value);
        }
        makeNonblocking(client.value);
    }

    LoopbackSocketPair(const LoopbackSocketPair &) = delete;
    LoopbackSocketPair &operator=(const LoopbackSocketPair &) = delete;

    ~LoopbackSocketPair()
    {
        // Members are destroyed AFTER this body, so close sockets before
        // the Windows socket subsystem is deinitialized.
        server.close();
        client.close();
        listener.close();
#ifdef _WIN32
        assert(WSACleanup() == 0);
#endif
    }

private:
#ifdef _WIN32
    WSADATA wsa_{};
#endif
    static void makeNonblocking(LocalSocketId s)
    {
#ifdef _WIN32
        u_long mode = 1;
        assert(::ioctlsocket(s, FIONBIO, &mode) == 0);
#else
        const int flags = ::fcntl(s, F_GETFL, 0);
        assert(flags >= 0);
        assert(::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0);
#ifdef SO_NOSIGPIPE
        const int enabled = 1;
        assert(::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE,
                            &enabled, sizeof(enabled)) == 0);
#endif
#endif
    }
};

void nativeSendAll(TcpNonblockingIo &io,
                   std::span<const std::uint8_t> payload)
{
    std::size_t total = 0;
    for (int tries = 0; tries < 16384 && total < payload.size(); ++tries)
    {
        const auto sent = io.send(payload.subspan(total));
        if (sent.outcome == TcpIoOutcome::WouldBlock)
        {
            assert(sent.bytes == 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        assert(sent.outcome == TcpIoOutcome::Progress);
        assert(sent.bytes > 0 && sent.bytes <= payload.size() - total);
        total += sent.bytes;
    }
    assert(total == payload.size());
}

void nativeReadAll(TcpNonblockingIo &io, std::span<std::uint8_t> output)
{
    std::size_t total = 0;
    for (int tries = 0; tries < 16384 && total < output.size(); ++tries)
    {
        const auto received = io.receive(output.subspan(total));
        if (received.outcome == TcpIoOutcome::WouldBlock)
        {
            assert(received.bytes == 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        assert(received.outcome == TcpIoOutcome::Progress);
        assert(received.bytes > 0 &&
               received.bytes <= output.size() - total);
        total += received.bytes;
    }
    assert(total == output.size());
}

[[nodiscard]] TcpAcceptResult waitForAcceptedLoopbackConnection(
    std::uintptr_t listener)
{
    // connect() completion does not guarantee a nonblocking listener can
    // immediately observe the queued peer on every hosted kernel. Retry only
    // this TEST fixture boundary; production accept remains exactly one-step.
    for (int attempt = 0; attempt < 2048; ++attempt)
    {
        auto accepted = acceptNonblockingTcpConnection(listener);
        if (accepted.outcome == TcpAcceptOutcome::Accepted)
            return accepted;
        assert(accepted.outcome == TcpAcceptOutcome::WouldBlock);
        assert(!accepted.connection.valid());
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    assert(false && "loopback peer was never observable by native accept");
    return {};
}

void waitForNativeRequest(PreauthTcpAdapter &adapter)
{
    // A connected NONBLOCKING peer may legitimately have no readable
    // bytes yet. Poll only inside this bounded test fixture, not
    // inside the production event-loop callback.
    bool complete = false;
    for (int attempt = 0; attempt < 2048; ++attempt)
    {
        const auto event = adapter.onReadable();
        if (event == TcpPreauthEvent::NeedWrite)
        {
            complete = true;
            break;
        }
        assert(event == TcpPreauthEvent::NeedRead);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(complete);
}

void testNativeTcpAcceptOwnershipAndCancellation()
{
    // Real ephemeral loopback only; no persistent service and no OS
    // admission. Only the newly accepted connection is transferred.
    LoopbackSocketPair pair{false};
    assert(pair.listener.value != kInvalidLocalSocket);
    assert(pair.server.value == kInvalidLocalSocket);

    const auto invalid = acceptNonblockingTcpConnection(
        OwnedNativeTcpSocket::kInvalidSocket);
    assert(invalid.outcome == TcpAcceptOutcome::Failure);
    assert(!invalid.connection.valid());
    const auto notListener = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.client.value));
    assert(notListener.outcome == TcpAcceptOutcome::Failure);
    assert(!notListener.connection.valid());
#ifndef _WIN32
    if constexpr (sizeof(std::uintptr_t) > sizeof(int))
    {
        const auto tooLarge = acceptNonblockingTcpConnection(
            static_cast<std::uintptr_t>(
                (std::numeric_limits<int>::max)()) + 1U);
        assert(tooLarge.outcome == TcpAcceptOutcome::Failure);
        assert(!tooLarge.connection.valid());
    }
#endif

    auto accepted = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    assert(accepted.connection.valid());
    const auto acceptedHandle = accepted.connection.nativeSocket();
    assert(acceptedHandle != OwnedNativeTcpSocket::kInvalidSocket);

#ifdef _WIN32
    DWORD handleFlags = HANDLE_FLAG_INHERIT;
    assert(::GetHandleInformation(reinterpret_cast<HANDLE>(acceptedHandle),
                                  &handleFlags) != 0);
    assert((handleFlags & HANDLE_FLAG_INHERIT) == 0);
#else
    const int acceptedDescriptor = static_cast<int>(acceptedHandle);
    const int socketFlags = ::fcntl(acceptedDescriptor, F_GETFL);
    const int descriptorFlags = ::fcntl(acceptedDescriptor, F_GETFD);
    assert(socketFlags >= 0 && (socketFlags & O_NONBLOCK) != 0);
    assert(descriptorFlags >= 0 && (descriptorFlags & FD_CLOEXEC) != 0);
#endif

    const auto noSecondConnection = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(noSecondConnection.outcome == TcpAcceptOutcome::WouldBlock);
    assert(!noSecondConnection.connection.valid());

    NativeTcpIo acceptedIo{acceptedHandle};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    std::array<std::uint8_t, 19> response{};
    assert(acceptedIo.receive(response).outcome == TcpIoOutcome::WouldBlock);

    // Drive the PRODUCTION preauth owner with a real client CR, not just
    // raw TCP bytes. It must produce the complete exact X.224 Confirm.
    PreauthTcpAdapter connection{acceptedIo};
    const auto request = validRequestWire();
    nativeSendAll(clientIo, request);
    waitForNativeRequest(connection);
    assert(connection.onWritable() == TcpPreauthEvent::ReadyForTls);
    nativeReadAll(clientIo, response);
    assert(response == negotiateDiagnosticTls(validRequest()).packet);
    connection.close();
    assert(connection.connection().stage() == PreauthStage::Closed);

    // Moving the owner cannot duplicate the descriptor or invalidate the
    // borrowed native I/O. Closing it is terminal and idempotent.
    OwnedNativeTcpSocket moved{};
    moved = std::move(accepted.connection);
    assert(!accepted.connection.valid());
    assert(moved.valid() && moved.nativeSocket() == acceptedHandle);
    moved.close();
    assert(!moved.valid());
    moved.close();
    assert(!moved.valid());
}


void testNativeTcpAcceptedPeerEndpointIdentity()
{
    LoopbackSocketPair pair{false};

    sockaddr_in clientAddress{};
#ifdef _WIN32
    int clientAddressLength = sizeof(clientAddress);
#else
    socklen_t clientAddressLength = sizeof(clientAddress);
#endif
    assert(::getsockname(
        pair.client.value, reinterpret_cast<sockaddr *>(&clientAddress),
        &clientAddressLength) == 0);
    assert(static_cast<std::size_t>(clientAddressLength) ==
           sizeof(clientAddress));
    assert(clientAddress.sin_family == AF_INET);
    assert(clientAddress.sin_port != 0);

    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    const auto endpoint = accepted.connection.peerEndpoint();
    assert(endpoint.valid());
    assert(endpoint.family == TcpPeerAddressFamily::Ipv4);
    assert(endpoint.port == ntohs(clientAddress.sin_port));
    assert(endpoint.ipv6ScopeId == 0);

    const std::uint32_t address = ntohl(clientAddress.sin_addr.s_addr);
    const std::array<std::uint8_t, 4> expectedAddress{
        static_cast<std::uint8_t>((address >> 24U) & 0xffU),
        static_cast<std::uint8_t>((address >> 16U) & 0xffU),
        static_cast<std::uint8_t>((address >> 8U) & 0xffU),
        static_cast<std::uint8_t>(address & 0xffU)};
    assert(std::equal(expectedAddress.begin(), expectedAddress.end(),
                      endpoint.address.begin()));
    assert(std::all_of(endpoint.address.begin() + expectedAddress.size(),
                       endpoint.address.end(),
                       [](std::uint8_t octet) { return octet == 0; }));
    assert(endpoint.address[0] == 127);

    // The immutable metadata moves with the ONLY accepted-socket owner.
    OwnedNativeTcpSocket moved{std::move(accepted.connection)};
    assert(!accepted.connection.valid());
    assert(!accepted.connection.peerEndpoint().valid());
    assert(moved.peerEndpoint() == endpoint);

    OwnedPreauthTcpConnection owner{std::move(moved)};
    assert(!moved.valid());
    assert(!moved.peerEndpoint().valid());
    assert(owner.active());
    assert(owner.peerEndpoint() == endpoint);

    // Closing the transport revokes both raw socket access and peer
    // metadata so a stale endpoint cannot masquerade as an active peer.
    owner.cancel();
    assert(!owner.active());
    assert(!owner.peerEndpoint().valid());
    assert(pair.listener.value != kInvalidLocalSocket);
}

void testNativeTcpAcceptMoveReplacement()
{
    static_assert(!std::is_copy_constructible_v<OwnedNativeTcpSocket>);
    static_assert(!std::is_copy_assignable_v<OwnedNativeTcpSocket>);
    static_assert(std::is_nothrow_move_constructible_v<OwnedNativeTcpSocket>);
    static_assert(std::is_nothrow_move_assignable_v<OwnedNativeTcpSocket>);

    // Both fixtures retain their caller-owned listener; replacement must
    // close precisely the old accepted connection, not either listener.
    LoopbackSocketPair first{false};
    LoopbackSocketPair second{false};
    auto firstAccepted = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(first.listener.value));
    auto secondAccepted = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(second.listener.value));
    assert(firstAccepted.outcome == TcpAcceptOutcome::Accepted);
    assert(secondAccepted.outcome == TcpAcceptOutcome::Accepted);
    assert(firstAccepted.connection.valid());
    assert(secondAccepted.connection.valid());
    const auto replacedHandle = firstAccepted.connection.nativeSocket();
    const auto incomingHandle = secondAccepted.connection.nativeSocket();
    assert(replacedHandle != incomingHandle);

    OwnedNativeTcpSocket owner{std::move(firstAccepted.connection)};
    OwnedNativeTcpSocket incoming{std::move(secondAccepted.connection)};
    assert(!firstAccepted.connection.valid());
    assert(!secondAccepted.connection.valid());

    // An aliased self-move must leave the descriptor valid and owned.
    auto &alias = owner;
    owner = std::move(alias);
    assert(owner.valid() && owner.nativeSocket() == replacedHandle);

    // Move assignment must close the existing descriptor before adopting
    // the incoming one, and must not touch either borrowed listener.
    owner = std::move(incoming);
    assert(owner.valid() && owner.nativeSocket() == incomingHandle);
    assert(!incoming.valid());
#ifdef _WIN32
    int closedError = 0;
    int errorLength = sizeof(closedError);
    assert(::getsockopt(static_cast<SOCKET>(replacedHandle), SOL_SOCKET,
                        SO_ERROR, reinterpret_cast<char *>(&closedError),
                        &errorLength) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAENOTSOCK);
#else
    errno = 0;
    assert(::fcntl(static_cast<int>(replacedHandle), F_GETFD) == -1);
    assert(errno == EBADF);
#endif
    assert(first.listener.value != kInvalidLocalSocket);
    assert(second.listener.value != kInvalidLocalSocket);
    assert(acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(first.listener.value)).outcome ==
        TcpAcceptOutcome::WouldBlock);
    assert(acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(second.listener.value)).outcome ==
        TcpAcceptOutcome::WouldBlock);

    NativeTcpIo ownedIo{owner.nativeSocket()};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(second.client.value)};
    constexpr std::array<std::uint8_t, 8> payload{
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    std::array<std::uint8_t, payload.size()> received{};
    nativeSendAll(clientIo, payload);
    nativeReadAll(ownedIo, received);
    assert(received == payload);
    owner.close();
    owner.close();
    assert(!owner.valid());
}

void testNativeTcpAcceptOrderlyPeerDisconnect()
{
    // A TCP FIN is not a TLS/authentication success. The native transport
    // must deliver all already-queued bytes, then an explicit EOF, and the
    // owner must be safe to cancel without affecting its borrowed listener.
    LoopbackSocketPair pair{false};
    auto accepted = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    assert(accepted.connection.valid());
    const auto acceptedHandle = accepted.connection.nativeSocket();
    NativeTcpIo serverIo{acceptedHandle};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};

    constexpr std::array<std::uint8_t, 7> payload{
        0x03, 0x00, 0x00, 0x07, 0x06, 0xe0, 0x00};
    nativeSendAll(clientIo, payload);
#ifdef _WIN32
    assert(::shutdown(pair.client.value, SD_SEND) == 0);
#else
    assert(::shutdown(pair.client.value, SHUT_WR) == 0);
#endif
    std::array<std::uint8_t, payload.size()> delivered{};
    nativeReadAll(serverIo, delivered);
    assert(delivered == payload);

    std::array<std::uint8_t, 1> eofByte{};
    bool observedEof = false;
    for (int attempt = 0; attempt < 2048; ++attempt)
    {
        const auto read = serverIo.receive(eofByte);
        if (read.outcome == TcpIoOutcome::EndOfStream)
        {
            assert(read.bytes == 0);
            observedEof = true;
            break;
        }
        assert(read.outcome == TcpIoOutcome::WouldBlock);
        assert(read.bytes == 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(observedEof);

    // Cancellation closes only the owned accepted descriptor. No callback
    // is invoked on its borrowed I/O after the owner has been destroyed.
    accepted.connection.close();
    accepted.connection.close();
    assert(!accepted.connection.valid());
#ifdef _WIN32
    int unused = 0;
    int length = sizeof(unused);
    assert(::getsockopt(static_cast<SOCKET>(acceptedHandle), SOL_SOCKET,
                        SO_ERROR, reinterpret_cast<char *>(&unused),
                        &length) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAENOTSOCK);
#else
    errno = 0;
    assert(::fcntl(static_cast<int>(acceptedHandle), F_GETFD) == -1);
    assert(errno == EBADF);
#endif
    assert(pair.listener.value != kInvalidLocalSocket);
    const auto next = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(next.outcome == TcpAcceptOutcome::WouldBlock);
    assert(!next.connection.valid());
}


[[nodiscard]] TcpAcceptResult waitForAcceptedLoopbackConnection(
    std::uintptr_t listener);

void testOwnedTcpConnectionTlsLifecycle()
{
    static_assert(!std::is_move_constructible_v<OwnedPreauthTcpConnection>);
    static_assert(!std::is_copy_constructible_v<OwnedPreauthTcpConnection>);

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
    assert(owner.active());
    assert(!accepted.connection.valid());
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    const auto request = validRequestWire();
    nativeSendAll(clientIo, request);
    TcpPreauthEvent status = TcpPreauthEvent::NeedRead;
    for (int step = 0; step < 2048; ++step)
    {
        status = owner.onReadable();
        if (status != TcpPreauthEvent::NeedRead) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(status == TcpPreauthEvent::NeedWrite);
    assert(owner.onWritable() == TcpPreauthEvent::ReadyForTls);
    assert(owner.stage() == PreauthStage::AwaitTls);
    std::array<std::uint8_t, 19> confirm{};
    nativeReadAll(clientIo, confirm);
    assert(confirm == negotiateDiagnosticTls(validRequest()).packet);

    TlsHandshakeFixture tls{false, false};
    OwnedPreauthTcpConnection::ServerTls server{
        tls.server.release(), SSL_free};
    assert(owner.attachServerTls(std::move(server)));
    assert(!server);
    assert(attachNonblockingTcpBio(tls.client.get(), clientIo));
    bool clientEstablished = false;
    bool serverEstablished = false;
    for (int pass = 0; pass < 16384; ++pass)
    {
        if (!clientEstablished)
        {
            const int success = SSL_do_handshake(tls.client.get());
            if (success == 1)
                clientEstablished = true;
            else
            {
                const int error = SSL_get_error(tls.client.get(), success);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
        }
        if (!serverEstablished)
        {
            const auto outcome = owner.onTlsIoReady();
            assert(outcome == TlsHandshakeStatus::NeedRead ||
                   outcome == TlsHandshakeStatus::NeedWrite ||
                   outcome == TlsHandshakeStatus::Established);
            serverEstablished = outcome == TlsHandshakeStatus::Established;
        }
        if (clientEstablished && serverEstablished) break;
        std::this_thread::yield();
    }
    assert(clientEstablished && serverEstablished);
    assert(owner.active());
    assert(owner.stage() == PreauthStage::AwaitMcsConnectInitial);

    const auto frame = validMcsPacket();
    std::size_t written = 0;
    for (int pass = 0; pass < 16384 && written < frame.size(); ++pass)
    {
        std::size_t count = 0;
        const int success = SSL_write_ex(tls.client.get(),
            frame.data() + written, frame.size() - written, &count);
        if (success == 1)
        {
            assert(count > 0 && count <= frame.size() - written);
            written += count;
        }
        else
        {
            const int error = SSL_get_error(tls.client.get(), success);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
            std::this_thread::yield();
        }
    }
    assert(written == frame.size());

    McsIntakeResult response{};
    std::size_t total = 0;
    for (int pass = 0; pass < 16384; ++pass)
    {
        response = owner.onMcsIoReady();
        total += response.bytesConsumed;
        if (response.status != McsIntakeStatus::NeedMore) break;
        std::this_thread::yield();
    }
    assert(response.status == McsIntakeStatus::EnvelopeValidated);
    assert(total == frame.size());
    assert(!owner.active());
    assert(owner.stage() == PreauthStage::Closed);
    assert(owner.onTlsIoReady() == TlsHandshakeStatus::Closed);
    assert(owner.onMcsIoReady().status == McsIntakeStatus::Closed);
    assert(pair.listener.value != kInvalidLocalSocket);
    assert(acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value)).outcome ==
        TcpAcceptOutcome::WouldBlock);
    // Diagnostic validation is NOT R2 identity or R3 session admission.
}

void testOwnedTcpConnectionCancellation()
{
    OwnedPreauthTcpConnection empty{OwnedNativeTcpSocket{}};
    assert(!empty.active());
    assert(empty.onReadable() == TcpPreauthEvent::Closed);
    assert(empty.onWritable() == TcpPreauthEvent::Closed);
    assert(empty.onTlsIoReady() == TlsHandshakeStatus::Closed);
    assert(empty.onMcsIoReady().status == McsIntakeStatus::Closed);
    empty.cancel();
    empty.cancel();

    // Cancel during an incomplete plaintext X.224 Connection Request.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        const auto native = accepted.connection.nativeSocket();
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = validRequestWire();
        nativeSendAll(clientIo, std::span(request).first(3));
        assert(owner.onReadable() == TcpPreauthEvent::NeedRead);
        assert(owner.stage() == PreauthStage::AwaitConnectionRequest);
        owner.cancel();
        owner.cancel();
        assert(!owner.active());
        assert(owner.stage() == PreauthStage::Closed);
        assert(owner.onReadable() == TcpPreauthEvent::Closed);
        assert(owner.onWritable() == TcpPreauthEvent::Closed);
#ifdef _WIN32
        int error = 0;
        int length = sizeof(error);
        assert(::getsockopt(static_cast<SOCKET>(native), SOL_SOCKET,
                            SO_ERROR, reinterpret_cast<char *>(&error),
                            &length) == SOCKET_ERROR);
        assert(WSAGetLastError() == WSAENOTSOCK);
#else
        errno = 0;
        assert(::fcntl(static_cast<int>(native), F_GETFD) == -1);
        assert(errno == EBADF);
#endif
        assert(pair.listener.value != kInvalidLocalSocket);
    }

    // Cancel after attaching SSL but before a ClientHello arrives.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = validRequestWire();
        nativeSendAll(clientIo, request);
        TcpPreauthEvent status = TcpPreauthEvent::NeedRead;
        for (int step = 0; step < 2048; ++step)
        {
            status = owner.onReadable();
            if (status != TcpPreauthEvent::NeedRead) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(status == TcpPreauthEvent::NeedWrite);
        assert(owner.onWritable() == TcpPreauthEvent::ReadyForTls);
        TlsHandshakeFixture tls{false, false};
        OwnedPreauthTcpConnection::ServerTls server{
            tls.server.release(), SSL_free};
        assert(owner.attachServerTls(std::move(server)));
        assert(owner.onTlsIoReady() == TlsHandshakeStatus::NeedRead);
        owner.cancel();
        assert(!owner.active());
        assert(owner.stage() == PreauthStage::Closed);
        assert(owner.onTlsIoReady() == TlsHandshakeStatus::Closed);
        assert(owner.onMcsIoReady().status == McsIntakeStatus::Closed);
        assert(pair.listener.value != kInvalidLocalSocket);
    }
}



[[nodiscard]] TcpConnectionIoInterest waitForOwnedTcpReply(
    OwnedPreauthTcpConnection &owner)
{
    // A single nonblocking recv may contain only a fragment even after
    // nativeSendAll returned. Retry only the READ direction under a
    // bounded fixture deadline; the production owner remains one-step.
    for (int attempt = 0; attempt < 2048; ++attempt)
    {
        const auto interest = owner.onSocketReady(true, false);
        if (interest != TcpConnectionIoInterest::Read)
            return interest;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(false && "X.224 input did not reach the expected reply boundary");
    return owner.ioInterest();
}



void testOwnedSecurityNegotiationProvenance()
{
    using Interest = TcpConnectionIoInterest;

    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        assert(!owner.securityNegotiationProvenance().has_value());

        auto request = tlsAndHybridRequestWire();
        const auto parsed = parseConnectionRequest(request);
        assert(parsed);
        const auto expectedReply = negotiateDiagnosticTls(parsed);
        assert(expectedReply.decision == SecurityDecision::Tls);
        assert(expectedReply.selectedProtocol == kRdpProtocolSsl);

        nativeSendAll(clientIo, request);
        assert(waitForOwnedTcpReply(owner) == Interest::Write);
        assert(!owner.securityNegotiationProvenance().has_value());
        assert(owner.onSocketReady(false, true) == Interest::ConfigureTls);
        assert(!owner.securityNegotiationProvenance().has_value());

        std::array<std::uint8_t, 19> confirm{};
        nativeReadAll(clientIo, confirm);
        assert(confirm == expectedReply.packet);

        // The later provenance snapshot must not borrow this caller copy.
        request[15] = 0;

        TlsHandshakeFixture tls{false, false};
        OwnedPreauthTcpConnection::ServerTls server{
            tls.server.release(), SSL_free};
        assert(owner.attachServerTls(std::move(server)));
        assert(!server);
        assert(attachNonblockingTcpBio(tls.client.get(), clientIo));
        assert(owner.onTlsIoReady() == TlsHandshakeStatus::NeedRead);
        assert(!owner.securityNegotiationProvenance().has_value());

        bool clientEstablished = false;
        bool serverEstablished = false;
        for (int pass = 0; pass < 16384; ++pass)
        {
            if (!clientEstablished)
            {
                const int result = SSL_do_handshake(tls.client.get());
                if (result == 1)
                    clientEstablished = true;
                else
                {
                    const int error =
                        SSL_get_error(tls.client.get(), result);
                    assert(error == SSL_ERROR_WANT_READ ||
                           error == SSL_ERROR_WANT_WRITE);
                }
            }
            if (!serverEstablished)
            {
                const auto result = owner.onTlsIoReady();
                assert(result == TlsHandshakeStatus::NeedRead ||
                       result == TlsHandshakeStatus::NeedWrite ||
                       result == TlsHandshakeStatus::Established);
                serverEstablished =
                    result == TlsHandshakeStatus::Established;
            }
            if (clientEstablished && serverEstablished) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(clientEstablished && serverEstablished);
        assert(owner.establishedTls() != nullptr);

        const auto provenance = owner.securityNegotiationProvenance();
        assert(provenance.has_value());
        assert(provenance->clientRequestedProtocols ==
               (kRdpProtocolSsl | kRdpProtocolHybrid));
        assert(provenance->serverSelectedProtocol == kRdpProtocolSsl);

        auto callerCopy = *provenance;
        callerCopy.clientRequestedProtocols = 0;
        callerCopy.serverSelectedProtocol = 0;
        const auto reread = owner.securityNegotiationProvenance();
        assert(reread.has_value());
        assert(reread->clientRequestedProtocols ==
               (kRdpProtocolSsl | kRdpProtocolHybrid));
        assert(reread->serverSelectedProtocol == kRdpProtocolSsl);

        owner.cancel();
        assert(!owner.active());
        assert(!owner.securityNegotiationProvenance().has_value());
    }

    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        auto rejectedRequest = validRequestWire();
        rejectedRequest[15] = 0;
        const auto parsed = parseConnectionRequest(rejectedRequest);
        assert(parsed);
        const auto expectedFailure = negotiateDiagnosticTls(parsed);
        assert(expectedFailure.decision == SecurityDecision::Reject);
        assert(expectedFailure.selectedProtocol == 0U);

        nativeSendAll(clientIo, rejectedRequest);
        assert(waitForOwnedTcpReply(owner) == Interest::Write);
        assert(!owner.securityNegotiationProvenance().has_value());
        assert(owner.onSocketReady(false, true) == Interest::Closed);
        std::array<std::uint8_t, 19> failure{};
        nativeReadAll(clientIo, failure);
        assert(failure == expectedFailure.packet);
        assert(!owner.active());
        assert(!owner.securityNegotiationProvenance().has_value());
    }
}


using RuntimeTlsServer = RuntimeServerTlsContext::ServerTls;
using RuntimeClock = std::chrono::steady_clock;

[[nodiscard]] RuntimeClock::time_point runtimeTlsFixtureDeadline()
{
    return RuntimeClock::now() + std::chrono::seconds{5};
}

void nativeSendAllBefore(TcpNonblockingIo &io,
                         std::span<const std::uint8_t> payload,
                         RuntimeClock::time_point deadline)
{
    std::size_t total = 0;
    while (total < payload.size() && RuntimeClock::now() < deadline)
    {
        const auto sent = io.send(payload.subspan(total));
        if (sent.outcome == TcpIoOutcome::WouldBlock)
        {
            assert(sent.bytes == 0);
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        assert(sent.outcome == TcpIoOutcome::Progress);
        assert(sent.bytes > 0 && sent.bytes <= payload.size() - total);
        total += sent.bytes;
    }
    assert(total == payload.size());
}

void nativeReadAllBefore(TcpNonblockingIo &io,
                         std::span<std::uint8_t> output,
                         RuntimeClock::time_point deadline)
{
    std::size_t total = 0;
    while (total < output.size() && RuntimeClock::now() < deadline)
    {
        const auto received = io.receive(output.subspan(total));
        if (received.outcome == TcpIoOutcome::WouldBlock)
        {
            assert(received.bytes == 0);
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
            continue;
        }
        assert(received.outcome == TcpIoOutcome::Progress);
        assert(received.bytes > 0 &&
               received.bytes <= output.size() - total);
        total += received.bytes;
    }
    assert(total == output.size());
}

[[nodiscard]] OwnedNativeTcpSocket acceptRuntimeLoopbackWithDeadline(
    LoopbackSocketPair &pair)
{
    struct Capture final
    {
        OwnedNativeTcpSocket socket{};
    } capture{};

    const auto onAccepted = +[](OwnedNativeTcpSocket accepted,
                                void *context) noexcept -> bool
    {
        auto &state = *static_cast<Capture *>(context);
        assert(accepted.valid());
        assert(!state.socket.valid());
        state.socket = std::move(accepted);
        return false;
    };

    const auto deadline = runtimeTlsFixtureDeadline();
    while (!capture.socket.valid() && RuntimeClock::now() < deadline)
    {
        const auto polled = pollNonblockingTcpAcceptBatch(
            static_cast<std::uintptr_t>(pair.listener.value),
            1, onAccepted, &capture, deadline, kMaximumTcpPollWait);
        if (polled.outcome == TcpListenerPollOutcome::BatchCompleted)
        {
            assert(polled.batch.outcome ==
                   TcpAcceptBatchOutcome::CallbackStopped);
            assert(polled.batch.accepted == 1);
            break;
        }
        assert(polled.outcome == TcpListenerPollOutcome::NoEvent);
        assert(polled.batch.accepted == 0);
    }

    assert(capture.socket.valid());
    assert(pair.listener.value != kInvalidLocalSocket);
    return std::move(capture.socket);
}

void completeOwnedRuntimeX224(OwnedPreauthTcpConnection &owner,
                              NativeTcpIo &clientIo)
{
    using Interest = TcpConnectionIoInterest;
    const auto request = tlsAndHybridRequestWire();
    const auto parsed = parseConnectionRequest(request);
    assert(parsed);
    const auto expectedReply = negotiateDiagnosticTls(parsed);
    assert(expectedReply.decision == SecurityDecision::Tls);
    assert(expectedReply.selectedProtocol == kRdpProtocolSsl);

    const auto deadline = runtimeTlsFixtureDeadline();
    nativeSendAllBefore(clientIo, request, deadline);
    while (owner.ioInterest() != Interest::ConfigureTls &&
           RuntimeClock::now() < deadline)
    {
        const auto polled =
            owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
        assert(polled.outcome == TcpConnectionPollOutcome::Dispatched ||
               polled.outcome == TcpConnectionPollOutcome::NoEvent);
        assert(polled.nextInterest == Interest::Read ||
               polled.nextInterest == Interest::Write ||
               polled.nextInterest == Interest::ConfigureTls);
    }

    assert(owner.ioInterest() == Interest::ConfigureTls);
    assert(owner.stage() == PreauthStage::AwaitTls);
    assert(owner.establishedTls() == nullptr);
    assert(!owner.securityNegotiationProvenance().has_value());

    // The client must receive the complete Confirm before any SSL is attached.
    std::array<std::uint8_t, 19> confirm{};
    nativeReadAllBefore(clientIo, confirm, deadline);
    assert(confirm == expectedReply.packet);
}

void establishOwnedRuntimeTls(
    OwnedPreauthTcpConnection &owner,
    NativeTcpIo &clientIo,
    RuntimeTlsClientFixture &clientTls,
    RuntimeTlsServer serverTls,
    const X509 *expectedCertificate,
    bool forceShortServerWrites = false)
{
    using Interest = TcpConnectionIoInterest;
    assert(serverTls);
    assert(expectedCertificate != nullptr);
    assert(SSL_is_server(serverTls.get()) == 1);
    assert(SSL_get_certificate(serverTls.get()) != nullptr);
    assert(X509_cmp(SSL_get_certificate(serverTls.get()),
                    expectedCertificate) == 0);

    if (forceShortServerWrites)
        assert(SSL_set_max_send_fragment(serverTls.get(), 1024) == 1);

    assert(owner.attachServerTls(std::move(serverTls)));
    assert(!serverTls);
    assert(attachNonblockingTcpBio(clientTls.connection.get(), clientIo));
    assert(owner.establishedTls() == nullptr);
    assert(!owner.securityNegotiationProvenance().has_value());

    // One server step without a ClientHello must expose provider backpressure;
    // R1 must not spin internally or publish an established TLS snapshot.
    const auto initialServerStep = owner.onTlsIoReady();
    assert(initialServerStep == TlsHandshakeStatus::NeedRead ||
           initialServerStep == TlsHandshakeStatus::NeedWrite);
    assert(owner.establishedTls() == nullptr);

    bool clientEstablished = false;
    const auto deadline = runtimeTlsFixtureDeadline();
    while (RuntimeClock::now() < deadline)
    {
        if (!clientEstablished)
        {
            const int result = SSL_do_handshake(clientTls.connection.get());
            if (result == 1)
            {
                clientEstablished = true;
            }
            else
            {
                const int error =
                    SSL_get_error(clientTls.connection.get(), result);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
        }

        if (owner.establishedTls() == nullptr)
        {
            const auto polled =
                owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
            assert(polled.outcome == TcpConnectionPollOutcome::Dispatched ||
                   polled.outcome == TcpConnectionPollOutcome::NoEvent);
            assert(polled.nextInterest == Interest::Read ||
                   polled.nextInterest == Interest::Write);
        }

        if (clientEstablished && owner.establishedTls() != nullptr)
            break;
    }

    assert(clientEstablished);
    assert(SSL_is_init_finished(clientTls.connection.get()) == 1);
    assert(owner.establishedTls() != nullptr);
    assert(owner.stage() == PreauthStage::AwaitMcsConnectInitial);
    assert(owner.ioInterest() == Interest::Read);

    const CertificatePointer observedCertificate{
        SSL_get1_peer_certificate(clientTls.connection.get()), X509_free};
    assert(observedCertificate);
    assert(X509_cmp(observedCertificate.get(), expectedCertificate) == 0);

    const auto provenance = owner.securityNegotiationProvenance();
    assert(provenance.has_value());
    assert(provenance->clientRequestedProtocols ==
           (kRdpProtocolSsl | kRdpProtocolHybrid));
    assert(provenance->serverSelectedProtocol == kRdpProtocolSsl);
}

void writeRuntimeTlsClientAll(SSL *client,
                              std::span<const std::uint8_t> payload)
{
    assert(client != nullptr);
    const auto deadline = runtimeTlsFixtureDeadline();
    std::size_t total = 0;
    while (total < payload.size() && RuntimeClock::now() < deadline)
    {
        std::size_t bytes = 0;
        const int result = SSL_write_ex(
            client, payload.data() + total, payload.size() - total, &bytes);
        if (result == 1)
        {
            assert(bytes > 0 && bytes <= payload.size() - total);
            total += bytes;
            continue;
        }
        assert(bytes == 0);
        const int error = SSL_get_error(client, result);
        assert(error == SSL_ERROR_WANT_READ ||
               error == SSL_ERROR_WANT_WRITE);
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    assert(total == payload.size());
}

void readRuntimeTlsClientAll(SSL *client, std::span<std::uint8_t> output)
{
    assert(client != nullptr);
    const auto deadline = runtimeTlsFixtureDeadline();
    std::size_t total = 0;
    while (total < output.size() && RuntimeClock::now() < deadline)
    {
        std::size_t bytes = 0;
        const int result = SSL_read_ex(
            client, output.data() + total, output.size() - total, &bytes);
        if (result == 1)
        {
            assert(bytes > 0 && bytes <= output.size() - total);
            total += bytes;
            continue;
        }
        assert(bytes == 0);
        const int error = SSL_get_error(client, result);
        assert(error == SSL_ERROR_WANT_READ ||
               error == SSL_ERROR_WANT_WRITE);
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    assert(total == output.size());
}

void readOwnedRuntimeTlsAll(OwnedPreauthTcpConnection &owner,
                            std::span<std::uint8_t> output)
{
    using Outcome = TlsApplicationIoOutcome;
    const auto deadline = runtimeTlsFixtureDeadline();
    std::size_t total = 0;
    while (total < output.size() && RuntimeClock::now() < deadline)
    {
        const auto remaining = output.subspan(total);
        const auto result = owner.readTlsApplicationData(remaining);
        if (result.outcome == Outcome::Progress)
        {
            assert(result.bytes > 0 && result.bytes <= remaining.size());
            total += result.bytes;
            continue;
        }

        assert(result.bytes == 0);
        assert(result.outcome == Outcome::NeedRead ||
               result.outcome == Outcome::NeedWrite);
        const auto polled =
            owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
        assert(polled.outcome == TcpConnectionPollOutcome::Dispatched ||
               polled.outcome == TcpConnectionPollOutcome::NoEvent);
    }
    assert(total == output.size());
}

void writeOwnedRuntimeTlsAll(OwnedPreauthTcpConnection &owner,
                             std::span<const std::uint8_t> payload,
                             bool &observedShortProgress)
{
    using Outcome = TlsApplicationIoOutcome;
    const auto deadline = runtimeTlsFixtureDeadline();
    std::size_t total = 0;
    while (total < payload.size() && RuntimeClock::now() < deadline)
    {
        const auto remaining = payload.subspan(total);
        const auto result = owner.writeTlsApplicationData(remaining);
        if (result.outcome == Outcome::Progress)
        {
            assert(result.bytes > 0 && result.bytes <= remaining.size());
            if (result.bytes < remaining.size())
                observedShortProgress = true;
            total += result.bytes;
            continue;
        }

        assert(result.bytes == 0);
        assert(result.outcome == Outcome::NeedRead ||
               result.outcome == Outcome::NeedWrite);
        const auto polled =
            owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
        assert(polled.outcome == TcpConnectionPollOutcome::Dispatched ||
               polled.outcome == TcpConnectionPollOutcome::NoEvent);
    }
    assert(total == payload.size());
}

void assertRuntimeTransportRevoked(OwnedPreauthTcpConnection &owner,
                                   LoopbackSocketPair &pair)
{
    using Outcome = TlsApplicationIoOutcome;
    using Interest = TcpConnectionIoInterest;
    assert(!owner.active());
    assert(owner.stage() == PreauthStage::Closed);
    assert(owner.establishedTls() == nullptr);
    assert(!owner.securityNegotiationProvenance().has_value());
    assert(!owner.peerEndpoint().valid());
    assert(owner.ioInterest() == Interest::Closed);
    assert(owner.onTlsIoReady() == TlsHandshakeStatus::Closed);
    assert(owner.onSocketReady(true, true) == Interest::Closed);

    std::array<std::uint8_t, 1> byte{};
    assert(owner.readTlsApplicationData(byte).outcome ==
           Outcome::TransportClosed);
    assert(owner.writeTlsApplicationData(byte).outcome ==
           Outcome::TransportClosed);

    assert(pair.listener.value != kInvalidLocalSocket);
    const auto idle = acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(idle.outcome == TcpAcceptOutcome::WouldBlock);
    assert(!idle.connection.valid());
}

void replaceRuntimeTlsCredentialPath(const char *configuredPath,
                                     const char *replacementPath)
{
    std::error_code error;
    const bool removed = std::filesystem::remove(configuredPath, error);
    assert(removed && !error);
    std::filesystem::rename(replacementPath, configuredPath, error);
    assert(!error);
}

void testOwnedRuntimeTlsHandshake(const char *certificatePath,
                                  const char *privateKeyPath)
{
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    assert(context);
    assert(context.certificate() != nullptr);

    // A missing R10 context cannot manufacture a per-connection TLS owner.
    {
        RuntimeServerTlsContext missingContext{};
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        completeOwnedRuntimeX224(owner, clientIo);
        assert(!missingContext.createServerTls());
        assert(!owner.attachServerTls(missingContext.createServerTls()));
        assertRuntimeTransportRevoked(owner, pair);
    }

    // Attaching a genuine R10 SSL while Confirm bytes are still pending is
    // terminal. The caller-owned listener remains independent of R1 teardown.
    {
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = tlsAndHybridRequestWire();
        const auto deadline = runtimeTlsFixtureDeadline();
        nativeSendAllBefore(clientIo, request, deadline);
        while (owner.ioInterest() == TcpConnectionIoInterest::Read &&
               RuntimeClock::now() < deadline)
        {
            const auto polled =
                owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
            assert(polled.outcome ==
                       TcpConnectionPollOutcome::Dispatched ||
                   polled.outcome == TcpConnectionPollOutcome::NoEvent);
        }
        assert(owner.ioInterest() == TcpConnectionIoInterest::Write);
        assert(!owner.attachServerTls(context.createServerTls()));
        assertRuntimeTransportRevoked(owner, pair);
    }

    // An attached SSL that has not received a ClientHello exposes one WANT
    // step, never establishedTls/provenance, and remains safely cancellable.
    {
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        completeOwnedRuntimeX224(owner, clientIo);
        assert(owner.attachServerTls(context.createServerTls()));
        const auto status = owner.onTlsIoReady();
        assert(status == TlsHandshakeStatus::NeedRead ||
               status == TlsHandshakeStatus::NeedWrite);
        assert(owner.establishedTls() == nullptr);
        assert(!owner.securityNegotiationProvenance().has_value());
        owner.cancel();
        assertRuntimeTransportRevoked(owner, pair);
    }

    // Complete R10 -> R1 ownership, encrypted I/O and explicit cancellation.
    {
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        const auto peer = accepted.peerEndpoint();
        assert(peer.valid());
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        assert(owner.peerEndpoint() == peer);
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        completeOwnedRuntimeX224(owner, clientIo);

        RuntimeTlsClientFixture clientTls{};
        establishOwnedRuntimeTls(
            owner, clientIo, clientTls, context.createServerTls(),
            context.certificate(), true);
        assert(owner.peerEndpoint() == peer);

        std::array<std::uint8_t, 257> inbound{};
        for (std::size_t index = 0; index < inbound.size(); ++index)
            inbound[index] =
                static_cast<std::uint8_t>((index * 13U + 7U) & 0xffU);
        std::array<std::uint8_t, 257> received{};
        const auto blocked = owner.readTlsApplicationData(received);
        assert(blocked.outcome == TlsApplicationIoOutcome::NeedRead);
        assert(blocked.bytes == 0);
        writeRuntimeTlsClientAll(clientTls.connection.get(), inbound);
        readOwnedRuntimeTlsAll(owner, received);
        assert(received == inbound);

        std::array<std::uint8_t, 4096> outbound{};
        for (std::size_t index = 0; index < outbound.size(); ++index)
            outbound[index] =
                static_cast<std::uint8_t>((index * 29U + 3U) & 0xffU);
        bool observedShortProgress = false;
        writeOwnedRuntimeTlsAll(owner, outbound, observedShortProgress);
        assert(observedShortProgress);
        std::array<std::uint8_t, 4096> delivered{};
        readRuntimeTlsClientAll(clientTls.connection.get(), delivered);
        assert(delivered == outbound);

        assert(owner.establishedTls() != nullptr);
        assert(owner.securityNegotiationProvenance().has_value());
        owner.cancel();
        // Do not dereference the previously borrowed SSL after cancellation.
        assertRuntimeTransportRevoked(owner, pair);
    }

    // Recognize a genuine peer close_notify through the same R10-backed SSL.
    {
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        completeOwnedRuntimeX224(owner, clientIo);
        RuntimeTlsClientFixture clientTls{};
        establishOwnedRuntimeTls(
            owner, clientIo, clientTls, context.createServerTls(),
            context.certificate());

        const auto deadline = runtimeTlsFixtureDeadline();
        bool closeNotifySent = false;
        while (!closeNotifySent && RuntimeClock::now() < deadline)
        {
            const int result = SSL_shutdown(clientTls.connection.get());
            if (result >= 0)
            {
                closeNotifySent = true;
                break;
            }
            const int error =
                SSL_get_error(clientTls.connection.get(), result);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
        }
        assert(closeNotifySent);

        std::array<std::uint8_t, 16> buffer{};
        TlsApplicationIoResult result{};
        while (owner.active() && RuntimeClock::now() < deadline)
        {
            result = owner.readTlsApplicationData(buffer);
            if (result.outcome == TlsApplicationIoOutcome::TlsClosed)
                break;
            assert(result.bytes == 0);
            assert(result.outcome == TlsApplicationIoOutcome::NeedRead ||
                   result.outcome == TlsApplicationIoOutcome::NeedWrite);
            const auto polled =
                owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
            assert(polled.outcome ==
                       TcpConnectionPollOutcome::Dispatched ||
                   polled.outcome == TcpConnectionPollOutcome::NoEvent);
        }
        assert(result.outcome == TlsApplicationIoOutcome::TlsClosed);
        assertRuntimeTransportRevoked(owner, pair);
    }

    // Abrupt peer loss is transport closure, never successful TLS/session state.
    {
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        completeOwnedRuntimeX224(owner, clientIo);
        RuntimeTlsClientFixture clientTls{};
        establishOwnedRuntimeTls(
            owner, clientIo, clientTls, context.createServerTls(),
            context.certificate());
        pair.client.close();

        const auto deadline = runtimeTlsFixtureDeadline();
        std::array<std::uint8_t, 16> buffer{};
        TlsApplicationIoResult result{};
        while (owner.active() && RuntimeClock::now() < deadline)
        {
            result = owner.readTlsApplicationData(buffer);
            if (result.outcome ==
                TlsApplicationIoOutcome::TransportClosed)
                break;
            assert(result.bytes == 0);
            assert(result.outcome == TlsApplicationIoOutcome::NeedRead ||
                   result.outcome == TlsApplicationIoOutcome::NeedWrite);
            const auto polled =
                owner.pollSocketOnce(deadline, kMaximumTcpPollWait);
            assert(polled.outcome ==
                       TcpConnectionPollOutcome::Dispatched ||
                   polled.outcome == TcpConnectionPollOutcome::NoEvent);
        }
        assert(result.outcome == TlsApplicationIoOutcome::TransportClosed);
        assertRuntimeTransportRevoked(owner, pair);
    }
}

void testOwnedRuntimeTlsIdentityContinuity(
    const char *certificatePath,
    const char *privateKeyPath,
    const char *replacementCertificatePath,
    const char *replacementPrivateKeyPath)
{
    RuntimeServerTlsContext context =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    assert(context);
    const CertificatePointer expectedCertificate{
        X509_dup(context.certificate()), X509_free};
    assert(expectedCertificate);

    // R10 has already validated and retained its identity. Replace both
    // configured pathnames with invalid material before creating this SSL.
    replaceRuntimeTlsCredentialPath(
        certificatePath, replacementCertificatePath);
    replaceRuntimeTlsCredentialPath(
        privateKeyPath, replacementPrivateKeyPath);

    RuntimeTlsServer serverTls = context.createServerTls();
    assert(serverTls);
    assert(SSL_get_certificate(serverTls.get()) != nullptr);
    assert(X509_cmp(SSL_get_certificate(serverTls.get()),
                    expectedCertificate.get()) == 0);

    McsSessionLifecycle r3Session{};
    assert(r3Session.phase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);

    LoopbackSocketPair pair{false};
    OwnedNativeTcpSocket accepted =
        acceptRuntimeLoopbackWithDeadline(pair);
    const auto peer = accepted.peerEndpoint();
    assert(peer.valid());
    OwnedPreauthTcpConnection owner{std::move(accepted)};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    completeOwnedRuntimeX224(owner, clientIo);
    RuntimeTlsClientFixture clientTls{};
    establishOwnedRuntimeTls(
        owner, clientIo, clientTls, std::move(serverTls),
        expectedCertificate.get());

    const CertificatePointer observedCertificate{
        SSL_get1_peer_certificate(clientTls.connection.get()), X509_free};
    assert(observedCertificate);
    assert(X509_cmp(observedCertificate.get(),
                    expectedCertificate.get()) == 0);
    assert(owner.peerEndpoint() == peer);

    // TLS establishment and X.224 provenance are transport facts only.
    // Without an R2 lease, the independent R3 owner cannot advance.
    assert(r3Session.phase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);

    owner.cancel();
    assertRuntimeTransportRevoked(owner, pair);
}


void testOwnedHybridNlaNegotiation()
{
    using Interest = TcpConnectionIoInterest;

    // HybridNla is explicit per connection. SSL-only cannot be accepted or
    // downgraded when R2 requires NLA provenance.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};

        const auto request = validRequestWire();
        const auto parsed = parseConnectionRequest(request);
        assert(parsed);
        const auto expected = negotiateSecurity(
            parsed, SecurityNegotiationPolicy::HybridNla);
        assert(expected.decision == SecurityDecision::Reject);
        assert(expected.selectedProtocol == 0U);
        assert(expected.packet[15] == 5U);

        nativeSendAll(clientIo, request);
        assert(waitForOwnedTcpReply(owner) == Interest::Write);
        assert(owner.onSocketReady(false, true) == Interest::Closed);
        std::array<std::uint8_t, 19> failure{};
        nativeReadAll(clientIo, failure);
        assert(failure == expected.packet);
        assert(!owner.active());
        assert(owner.establishedTls() == nullptr);
        assert(!owner.securityNegotiationProvenance().has_value());
        assert(pair.listener.value != kInvalidLocalSocket);
    }

    // A combined SSL+HYBRID offer selects HYBRID on wire, then binds that
    // exact immutable selection to the same completed R1-owned TLS object.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};

        auto request = tlsAndHybridRequestWire();
        const auto parsed = parseConnectionRequest(request);
        assert(parsed);
        const auto expected = negotiateSecurity(
            parsed, SecurityNegotiationPolicy::HybridNla);
        assert(expected.decision == SecurityDecision::Tls);
        assert(expected.selectedProtocol == kRdpProtocolHybrid);

        nativeSendAll(clientIo, request);
        assert(waitForOwnedTcpReply(owner) == Interest::Write);
        assert(!owner.securityNegotiationProvenance().has_value());
        assert(owner.onSocketReady(false, true) == Interest::ConfigureTls);
        std::array<std::uint8_t, 19> confirm{};
        nativeReadAll(clientIo, confirm);
        assert(confirm == expected.packet);
        assert(confirm[15] == kRdpProtocolHybrid);

        request[15] = 0; // Caller storage cannot rewrite R1 provenance.

        TlsHandshakeFixture tls{false, false};
        OwnedPreauthTcpConnection::ServerTls server{
            tls.server.release(), SSL_free};
        assert(owner.attachServerTls(std::move(server)));
        assert(!server);
        assert(attachNonblockingTcpBio(tls.client.get(), clientIo));

        bool clientEstablished = false;
        bool serverEstablished = false;
        for (int pass = 0; pass < 16384; ++pass)
        {
            if (!clientEstablished)
            {
                const int result = SSL_do_handshake(tls.client.get());
                if (result == 1)
                    clientEstablished = true;
                else
                {
                    const int error =
                        SSL_get_error(tls.client.get(), result);
                    assert(error == SSL_ERROR_WANT_READ ||
                           error == SSL_ERROR_WANT_WRITE);
                }
            }
            if (!serverEstablished)
            {
                const auto result = owner.onTlsIoReady();
                assert(result == TlsHandshakeStatus::NeedRead ||
                       result == TlsHandshakeStatus::NeedWrite ||
                       result == TlsHandshakeStatus::Established);
                serverEstablished =
                    result == TlsHandshakeStatus::Established;
            }
            if (clientEstablished && serverEstablished) break;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        assert(clientEstablished && serverEstablished);
        assert(owner.establishedTls() != nullptr);

        const auto provenance = owner.securityNegotiationProvenance();
        assert(provenance.has_value());
        assert(provenance->clientRequestedProtocols ==
               (kRdpProtocolSsl | kRdpProtocolHybrid));
        assert(provenance->serverSelectedProtocol == kRdpProtocolHybrid);

        owner.cancel();
        assert(!owner.active());
        assert(owner.establishedTls() == nullptr);
        assert(!owner.securityNegotiationProvenance().has_value());
        assert(pair.listener.value != kInvalidLocalSocket);
    }
}

void establishOwnedApplicationTlsForRequest(
    OwnedPreauthTcpConnection &owner,
    NativeTcpIo &clientIo,
    TlsHandshakeFixture &tls,
    std::span<const std::uint8_t> request,
    SecurityNegotiationPolicy policy)
{
    using Interest = TcpConnectionIoInterest;
    const auto parsed = parseConnectionRequest(request);
    assert(parsed);
    nativeSendAll(clientIo, request);
    assert(waitForOwnedTcpReply(owner) == Interest::Write);
    assert(owner.onSocketReady(false, true) == Interest::ConfigureTls);
    std::array<std::uint8_t, 19> confirm{};
    nativeReadAll(clientIo, confirm);
    assert(confirm == negotiateSecurity(parsed, policy).packet);

    OwnedPreauthTcpConnection::ServerTls server{
        tls.server.release(), SSL_free};
    assert(owner.attachServerTls(std::move(server)));
    assert(!server);
    assert(attachNonblockingTcpBio(tls.client.get(), clientIo));

    bool clientEstablished = false;
    bool serverEstablished = false;
    for (int pass = 0; pass < 16384; ++pass)
    {
        if (!clientEstablished)
        {
            const int result = SSL_do_handshake(tls.client.get());
            if (result == 1)
                clientEstablished = true;
            else
            {
                const int error = SSL_get_error(tls.client.get(), result);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
        }
        if (!serverEstablished)
        {
            const auto result = owner.onTlsIoReady();
            assert(result == TlsHandshakeStatus::NeedRead ||
                   result == TlsHandshakeStatus::NeedWrite ||
                   result == TlsHandshakeStatus::Established);
            serverEstablished =
                result == TlsHandshakeStatus::Established;
        }
        if (clientEstablished && serverEstablished) break;
        std::this_thread::yield();
    }
    assert(clientEstablished && serverEstablished);
    assert(owner.establishedTls() != nullptr);
    assert(owner.ioInterest() == Interest::Read);
}

void establishOwnedApplicationTls(
    OwnedPreauthTcpConnection &owner,
    NativeTcpIo &clientIo,
    TlsHandshakeFixture &tls)
{
    const auto request = validRequestWire();
    establishOwnedApplicationTlsForRequest(
        owner, clientIo, tls, request,
        SecurityNegotiationPolicy::DiagnosticTlsOnly);
}

void writeNativeTlsClientAll(
    SSL *client, std::span<const std::uint8_t> payload)
{
    assert(client != nullptr);
    std::size_t total = 0;
    for (int attempt = 0; attempt < 16384 && total < payload.size();
         ++attempt)
    {
        std::size_t bytes = 0;
        const int result = SSL_write_ex(
            client, payload.data() + total, payload.size() - total, &bytes);
        if (result == 1)
        {
            assert(bytes > 0 && bytes <= payload.size() - total);
            total += bytes;
            continue;
        }
        assert(bytes == 0);
        const int error = SSL_get_error(client, result);
        assert(error == SSL_ERROR_WANT_READ ||
               error == SSL_ERROR_WANT_WRITE);
        // Real loopback delivery is asynchronous even after the peer's
        // preceding SSL_write_ex accepted plaintext. Keep retry delay in
        // this bounded fixture; production application I/O never sleeps.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(total == payload.size());
}

void readNativeTlsClientAll(
    SSL *client, std::span<std::uint8_t> output)
{
    assert(client != nullptr);
    std::size_t total = 0;
    for (int attempt = 0; attempt < 16384 && total < output.size();
         ++attempt)
    {
        std::size_t bytes = 0;
        const int result = SSL_read_ex(
            client, output.data() + total, output.size() - total, &bytes);
        if (result == 1)
        {
            assert(bytes > 0 && bytes <= output.size() - total);
            total += bytes;
            continue;
        }
        assert(bytes == 0);
        const int error = SSL_get_error(client, result);
        assert(error == SSL_ERROR_WANT_READ ||
               error == SSL_ERROR_WANT_WRITE);
        // A successful server SSL_write_ex does not make all TCP segments
        // synchronously readable on every hosted kernel.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(total == output.size());
}

void testOwnedTlsApplicationIo()
{
    using Outcome = TlsApplicationIoOutcome;
    using Interest = TcpConnectionIoInterest;
    using Clock = std::chrono::steady_clock;

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};

    std::array<std::uint8_t, 1> premature{};
    assert(owner.readTlsApplicationData(premature).outcome ==
           Outcome::Invalid);
    assert(owner.writeTlsApplicationData(premature).outcome ==
           Outcome::Invalid);
    assert(owner.active());
    assert(owner.stage() == PreauthStage::AwaitConnectionRequest);

    TlsHandshakeFixture tls{false, false};
    establishOwnedApplicationTls(owner, clientIo, tls);
    const SSL *const established = owner.establishedTls();
    assert(established != nullptr);

    std::array<std::uint8_t, kMaximumTlsApplicationIoBytes + 1U>
        oversized{};
    assert(owner.readTlsApplicationData({}).outcome == Outcome::Invalid);
    assert(owner.writeTlsApplicationData({}).outcome == Outcome::Invalid);
    assert(owner.readTlsApplicationData(oversized).outcome ==
           Outcome::Invalid);
    assert(owner.writeTlsApplicationData(oversized).outcome ==
           Outcome::Invalid);
    assert(owner.establishedTls() == established);

    std::array<std::uint8_t, 257> inbound{};
    for (std::size_t index = 0; index < inbound.size(); ++index)
        inbound[index] =
            static_cast<std::uint8_t>((index * 13U + 7U) & 0xffU);
    std::array<std::uint8_t, 257> received{};
    const auto blocked = owner.readTlsApplicationData(received);
    assert(blocked.outcome == Outcome::NeedRead && blocked.bytes == 0);
    assert(owner.ioInterest() == Interest::Read);
    assert(owner.onSocketReady(false, true) == Interest::Read);

    writeNativeTlsClientAll(tls.client.get(), inbound);
    const auto polled = owner.pollSocketOnce(
        Clock::now() + std::chrono::seconds{1}, kMaximumTcpPollWait);
    assert(polled.outcome == TcpConnectionPollOutcome::Dispatched);
    assert(polled.nextInterest == Interest::Read);
    assert(std::all_of(received.begin(), received.end(),
                       [](std::uint8_t byte) { return byte == 0; }));

    const auto read = owner.readTlsApplicationData(received);
    assert(read.outcome == Outcome::Progress);
    assert(read.bytes == inbound.size());
    assert(received == inbound);
    assert(owner.ioInterest() == Interest::Read);

    std::array<std::uint8_t, 511> outbound{};
    for (std::size_t index = 0; index < outbound.size(); ++index)
        outbound[index] =
            static_cast<std::uint8_t>((index * 29U + 3U) & 0xffU);
    std::size_t written = 0;
    for (int attempt = 0; attempt < 128 && written < outbound.size();
         ++attempt)
    {
        const auto result = owner.writeTlsApplicationData(
            std::span(outbound).subspan(written));
        if (result.outcome == Outcome::Progress)
        {
            assert(result.bytes > 0 &&
                   result.bytes <= outbound.size() - written);
            written += result.bytes;
            continue;
        }
        assert(result.bytes == 0);
        const auto expected = result.outcome == Outcome::NeedRead
            ? Interest::Read
            : Interest::Write;
        assert(result.outcome == Outcome::NeedRead ||
               result.outcome == Outcome::NeedWrite);
        assert(owner.ioInterest() == expected);
        assert(owner.onSocketReady(true, true) == expected);
    }
    assert(written == outbound.size());

    std::array<std::uint8_t, 511> delivered{};
    readNativeTlsClientAll(tls.client.get(), delivered);
    assert(delivered == outbound);
    assert(owner.establishedTls() == established);
    assert(owner.onMcsIoReady().status == McsIntakeStatus::Invalid);
    assert(!owner.active());
    assert(owner.establishedTls() == nullptr);
}

void testOwnedTlsApplicationPartialWrite()
{
    using Outcome = TlsApplicationIoOutcome;
    using Interest = TcpConnectionIoInterest;
    static_assert(kMaximumTlsApplicationIoBytes ==
                  kMaximumTcpIoChunkBytes);

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    TlsHandshakeFixture tls{false, false};
    assert(SSL_set_max_send_fragment(tls.server.get(), 1024) == 1);
    establishOwnedApplicationTls(owner, clientIo, tls);
    // Do not cast away the public const SSL inspection boundary merely to
    // introspect modes. The forced 1 KiB record size below proves partial
    // write behavior through the public R1 application-I/O contract.

    std::array<std::uint8_t, kMaximumTlsApplicationIoBytes> payload{};
    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] =
            static_cast<std::uint8_t>((index * 17U + 11U) & 0xffU);

    std::size_t written = 0;
    bool observedShortProgress = false;
    for (int attempt = 0; attempt < 256 && written < payload.size();
         ++attempt)
    {
        const auto remaining = std::span(payload).subspan(written);
        const auto result = owner.writeTlsApplicationData(remaining);
        if (result.outcome == Outcome::Progress)
        {
            assert(result.bytes > 0 && result.bytes <= remaining.size());
            if (written == 0)
            {
                assert(result.bytes <= 1024);
                assert(result.bytes < remaining.size());
                observedShortProgress = true;
            }
            written += result.bytes;
            continue;
        }
        assert(result.bytes == 0);
        assert(result.outcome == Outcome::NeedRead ||
               result.outcome == Outcome::NeedWrite);
        const auto expected = result.outcome == Outcome::NeedRead
            ? Interest::Read
            : Interest::Write;
        assert(owner.ioInterest() == expected);
        assert(owner.onSocketReady(true, true) == expected);
    }
    assert(observedShortProgress);
    assert(written == payload.size());

    std::array<std::uint8_t, kMaximumTlsApplicationIoBytes> delivered{};
    readNativeTlsClientAll(tls.client.get(), delivered);
    assert(delivered == payload);

    std::array<std::uint8_t, 7> pendingRead{};
    const auto blocked = owner.readTlsApplicationData(pendingRead);
    assert(blocked.outcome == Outcome::NeedRead && blocked.bytes == 0);
    std::array<std::uint8_t, 7> wrongDirection{};
    assert(owner.writeTlsApplicationData(wrongDirection).outcome ==
           Outcome::Invalid);
    assert(owner.readTlsApplicationData(
               std::span(pendingRead).first(6)).outcome ==
           Outcome::Invalid);
    assert(owner.ioInterest() == Interest::Read);

    constexpr std::array<std::uint8_t, 7> retryPayload{
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    writeNativeTlsClientAll(tls.client.get(), retryPayload);
    TlsApplicationIoResult completed{};
    for (int attempt = 0; attempt < 2048; ++attempt)
    {
        completed = owner.readTlsApplicationData(pendingRead);
        if (completed.outcome == Outcome::Progress) break;
        assert(completed.bytes == 0);
        assert(completed.outcome == Outcome::NeedRead ||
               completed.outcome == Outcome::NeedWrite);
        const auto expected = completed.outcome == Outcome::NeedRead
            ? Interest::Read
            : Interest::Write;
        assert(owner.ioInterest() == expected);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(completed.outcome == Outcome::Progress);
    assert(completed.bytes == retryPayload.size());
    assert(pendingRead == retryPayload);
    owner.cancel();
}

void testR3ConnectResponseSliceThroughOwnedTls()
{
    using Outcome = TlsApplicationIoOutcome;
    using Interest = TcpConnectionIoInterest;
    using WriteOutcome = McsConnectResponseWriteOutcome;

    static_assert(kMaximumMcsResponseBytes <=
                  kMaximumTlsApplicationIoBytes);

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};

    TlsHandshakeFixture tls{false, false};
    assert(SSL_set_max_send_fragment(tls.server.get(), 1024) == 1);
    establishOwnedApplicationTls(owner, clientIo, tls);

    // Byte/receipt compatibility only. This synthetic response is never an
    // R2 authorization or permission to publish an R3 Connect Response.
    McsConnectResponse response{};
    response.length = response.packet.size();
    for (std::size_t index = 0; index < response.length; ++index)
        response.packet[index] =
            static_cast<std::uint8_t>((index * 37U + 19U) & 0xffU);

    McsConnectResponseWriteGate gate;
    assert(gate.queue(response));
    auto view = gate.pendingWrite();
    assert(view);
    assert(view.bytes.size() == kMaximumMcsResponseBytes);
    assert(view.bytes.size() <= kMaximumTlsApplicationIoBytes);

    bool observedShortProgress = false;
    WriteOutcome completion = WriteOutcome::Pending;
    for (int attempt = 0;
         attempt < 2048 && completion == WriteOutcome::Pending;
         ++attempt)
    {
        const auto replySequence = view.replySequence;
        const auto sliceSequence = view.writeSliceSequence;
        const auto offered = view.bytes;
        const auto write = owner.writeTlsApplicationData(offered);

        if (write.outcome == Outcome::Progress)
        {
            assert(write.bytes > 0 && write.bytes <= offered.size());
            if (offered.size() == kMaximumMcsResponseBytes)
            {
                assert(write.bytes <= 1024U);
                assert(write.bytes < offered.size());
                observedShortProgress = true;
            }

            completion = gate.onBytesWritten(
                replySequence, sliceSequence, write.bytes);
            if (completion == WriteOutcome::Pending)
            {
                const auto next = gate.pendingWrite();
                assert(next);
                assert(next.replySequence == replySequence);
                assert(next.writeSliceSequence != sliceSequence);
                assert(next.bytes.size() ==
                       offered.size() - write.bytes);
                view = next;
            }
            continue;
        }

        assert(write.bytes == 0);
        assert(write.outcome == Outcome::NeedRead ||
               write.outcome == Outcome::NeedWrite);
        const auto expected = write.outcome == Outcome::NeedRead
            ? Interest::Read
            : Interest::Write;
        assert(owner.ioInterest() == expected);
        assert(gate.onBytesWritten(
                   replySequence, sliceSequence, 0U) ==
               WriteOutcome::Pending);
        const auto retry = gate.pendingWrite();
        assert(retry.replySequence == replySequence);
        assert(retry.writeSliceSequence == sliceSequence);
        assert(retry.bytes.data() == offered.data());
        assert(retry.bytes.size() == offered.size());
        assert(owner.onSocketReady(true, true) == expected);
        view = retry;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    assert(observedShortProgress);
    assert(completion == WriteOutcome::Delivered);
    assert(!gate.pendingWrite());

    std::array<std::uint8_t, kMaximumMcsResponseBytes> delivered{};
    readNativeTlsClientAll(tls.client.get(), delivered);
    assert(std::equal(delivered.begin(), delivered.end(),
                      response.packet.begin(), response.packet.end()));
    owner.cancel();
}

void testOwnedTlsApplicationCancellation()
{
    using Outcome = TlsApplicationIoOutcome;
    using Interest = TcpConnectionIoInterest;
    using Clock = std::chrono::steady_clock;

    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTls(owner, clientIo, tls);
        std::array<std::uint8_t, 8> buffer{};
        assert(owner.readTlsApplicationData(buffer).outcome ==
               Outcome::NeedRead);
        const auto deadline = Clock::now();
        assert(owner.cancelIfExpired(deadline, deadline));
        assert(!owner.active());
        assert(owner.ioInterest() == Interest::Closed);
        assert(owner.readTlsApplicationData(buffer).outcome ==
               Outcome::TransportClosed);
        assert(owner.writeTlsApplicationData(buffer).outcome ==
               Outcome::TransportClosed);
        assert(owner.onSocketReady(true, true) == Interest::Closed);
        owner.cancel();
        owner.cancel();
    }

    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTls(owner, clientIo, tls);

        bool closeNotifySent = false;
        for (int attempt = 0; attempt < 128; ++attempt)
        {
            const int result = SSL_shutdown(tls.client.get());
            if (result >= 0)
            {
                closeNotifySent = true;
                break;
            }
            const int error = SSL_get_error(tls.client.get(), result);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
            std::this_thread::yield();
        }
        assert(closeNotifySent);

        std::array<std::uint8_t, 16> buffer{};
        TlsApplicationIoResult result{};
        for (int attempt = 0; attempt < 128; ++attempt)
        {
            result = owner.readTlsApplicationData(buffer);
            if (result.outcome != Outcome::NeedRead &&
                result.outcome != Outcome::NeedWrite)
                break;
            assert(result.bytes == 0);
            std::this_thread::yield();
        }
        assert(result.outcome == Outcome::TlsClosed);
        assert(result.bytes == 0);
        assert(!owner.active());
    }

    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTls(owner, clientIo, tls);
        pair.client.close();

        std::array<std::uint8_t, 16> buffer{};
        TlsApplicationIoResult result{};
        for (int attempt = 0; attempt < 128; ++attempt)
        {
            result = owner.readTlsApplicationData(buffer);
            if (result.outcome != Outcome::NeedRead &&
                result.outcome != Outcome::NeedWrite)
                break;
            assert(result.bytes == 0);
            std::this_thread::yield();
        }
        assert(result.outcome == Outcome::TransportClosed);
        assert(result.bytes == 0);
        assert(!owner.active());
    }

    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTls(owner, clientIo, tls);
        constexpr std::array<std::uint8_t, 6> invalidTlsRecord{
            0x17, 0x03, 0x03, 0x00, 0x01, 0x00};
        nativeSendAll(clientIo, invalidTlsRecord);

        std::array<std::uint8_t, 16> buffer{};
        TlsApplicationIoResult result{};
        for (int attempt = 0; attempt < 128; ++attempt)
        {
            result = owner.readTlsApplicationData(buffer);
            if (result.outcome != Outcome::NeedRead &&
                result.outcome != Outcome::NeedWrite)
                break;
            assert(result.bytes == 0);
            std::this_thread::yield();
        }
        assert(result.outcome == Outcome::FatalTlsFailure);
        assert(result.bytes == 0);
        assert(!owner.active());
        owner.cancel();
    }
}


void testOwnedTcpReadinessDispatch()
{
    // Real ephemeral TCP listener; no OS session admission or service.
    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
    using Interest = TcpConnectionIoInterest;
    assert(owner.ioInterest() == Interest::Read);
    assert(owner.establishedTls() == nullptr);

    // A writable-only notification cannot steal a plaintext read. No
    // readiness means no socket callback or protocol transition.
    assert(owner.onSocketReady(false, true) == Interest::Read);
    assert(owner.onSocketReady(false, false) == Interest::Read);
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    const auto request = validRequestWire();
    nativeSendAll(clientIo, std::span(request).first(3));
    assert(owner.onSocketReady(true, false) == Interest::Read);
    nativeSendAll(clientIo, std::span(request).subspan(3));
    assert(waitForOwnedTcpReply(owner) == Interest::Write);

    // The Confirm cannot be emitted on a readable-only callback.
    assert(owner.onSocketReady(true, false) == Interest::Write);
    std::array<std::uint8_t, 19> confirm{};
    assert(clientIo.receive(confirm).outcome == TcpIoOutcome::WouldBlock);
    assert(owner.onSocketReady(false, true) == Interest::ConfigureTls);
    assert(owner.onSocketReady(true, true) == Interest::ConfigureTls);
    assert(owner.establishedTls() == nullptr);
    nativeReadAll(clientIo, confirm);
    assert(confirm == negotiateDiagnosticTls(validRequest()).packet);

    TlsHandshakeFixture tls{false, false};
    const SSL *const selectedServer = tls.server.get();
    OwnedPreauthTcpConnection::ServerTls server{
        tls.server.release(), SSL_free};
    assert(owner.attachServerTls(std::move(server)));
    assert(!server);
    assert(owner.ioInterest() == Interest::Read);
    // Until a ClientHello can be consumed, writable-only readiness is
    // not a license to start a different TLS/connection identity.
    assert(owner.onSocketReady(false, true) == Interest::Read);
    assert(attachNonblockingTcpBio(tls.client.get(), clientIo));

    bool clientEstablished = false;
    bool serverEstablished = false;
    for (int pass = 0; pass < 16384; ++pass)
    {
        if (!clientEstablished)
        {
            const int outcome = SSL_do_handshake(tls.client.get());
            if (outcome == 1)
                clientEstablished = true;
            else
            {
                const int err = SSL_get_error(tls.client.get(), outcome);
                assert(err == SSL_ERROR_WANT_READ ||
                       err == SSL_ERROR_WANT_WRITE);
            }
        }
        const auto interest = owner.onSocketReady(true, true);
        assert(interest == Interest::Read ||
               interest == Interest::Write ||
               interest == Interest::Closed);
        assert(interest != Interest::Closed);
        serverEstablished = owner.establishedTls() != nullptr;
        if (clientEstablished && serverEstablished) break;
        std::this_thread::yield();
    }
    assert(clientEstablished && serverEstablished);
    assert(owner.establishedTls() == selectedServer);
    assert(owner.ioInterest() == Interest::Read);

    const auto frame = validMcsPacket();
    std::size_t sent = 0;
    for (int pass = 0; pass < 16384 && sent < frame.size(); ++pass)
    {
        std::size_t amount = 0;
        const int result = SSL_write_ex(tls.client.get(),
            frame.data() + sent, frame.size() - sent, &amount);
        if (result == 1)
        {
            assert(amount > 0 && amount <= frame.size() - sent);
            sent += amount;
        }
        else
        {
            const int err = SSL_get_error(tls.client.get(), result);
            assert(err == SSL_ERROR_WANT_READ ||
                   err == SSL_ERROR_WANT_WRITE);
            std::this_thread::yield();
        }
    }
    assert(sent == frame.size());
    for (int pass = 0; pass < 16384 && owner.active(); ++pass)
    {
        const auto interest = owner.onSocketReady(true, true);
        assert(interest == Interest::Read ||
               interest == Interest::Write ||
               interest == Interest::Closed);
        if (owner.active()) std::this_thread::yield();
    }
    assert(!owner.active()); // diagnostic MCS envelope closes on success
    assert(owner.stage() == PreauthStage::Closed);
    assert(owner.establishedTls() == nullptr);
    assert(owner.onSocketReady(true, true) == Interest::Closed);
    assert(pair.listener.value != kInvalidLocalSocket);
    assert(acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value)).outcome ==
        TcpAcceptOutcome::WouldBlock);

    // A denied CR must first flush its X.224 NEG_FAILURE response, not
    // start TLS or close prematurely on the first readable event.
    LoopbackSocketPair rejectedPair{false};
    auto rejectedSocket = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(rejectedPair.listener.value));
    assert(rejectedSocket.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection rejected{
        std::move(rejectedSocket.connection)};
    NativeTcpIo rejectedClient{
        static_cast<std::uintptr_t>(rejectedPair.client.value)};
    auto malformed = validRequestWire();
    malformed[15] = 0;
    nativeSendAll(rejectedClient, malformed);
    assert(waitForOwnedTcpReply(rejected) == Interest::Write);
    assert(rejected.onSocketReady(true, false) == Interest::Write);
    assert(rejected.onSocketReady(false, true) == Interest::Closed);
    std::array<std::uint8_t, 19> failureReply{};
    nativeReadAll(rejectedClient, failureReply);
    assert(failureReply == negotiateDiagnosticTls(
        parseConnectionRequest(malformed)).packet);
    assert(rejected.establishedTls() == nullptr);
    assert(rejected.onSocketReady(true, true) == Interest::Closed);
}


void testOwnedTcpPendingReplyInterestPriority()
{
    // Parsing a complete request advances the diagnostic stage BEFORE
    // its X.224 response is sent. Polling must still request Write,
    // for both a successful Confirm and a fail-closed NEG_FAILURE.
    using Interest = TcpConnectionIoInterest;
    for (const bool valid : {true, false})
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo client{static_cast<std::uintptr_t>(pair.client.value)};
        auto request = validRequestWire();
        if (!valid) request[15] = 0;
        nativeSendAll(client, request);

        assert(owner.ioInterest() == Interest::Read);
        assert(waitForOwnedTcpReply(owner) == Interest::Write);
        assert(owner.ioInterest() == Interest::Write);
        assert(owner.establishedTls() == nullptr);
        assert(owner.onSocketReady(true, false) == Interest::Write);
        const auto expected = negotiateDiagnosticTls(
            parseConnectionRequest(request)).packet;
        assert(owner.onSocketReady(false, true) ==
               (valid ? Interest::ConfigureTls : Interest::Closed));
        std::array<std::uint8_t, 19> response{};
        nativeReadAll(client, response);
        assert(response == expected);
        assert(owner.onSocketReady(true, true) ==
               (valid ? Interest::ConfigureTls : Interest::Closed));
        assert(owner.establishedTls() == nullptr);
        assert(pair.listener.value != kInvalidLocalSocket);
        owner.cancel();
        assert(!owner.active());
    }
}

void testOwnedTcpDeadlineCancellation()
{
    using Interest = TcpConnectionIoInterest;
    using Clock = std::chrono::steady_clock;
    const auto created = Clock::time_point{std::chrono::seconds{20}};
    const auto deadline = created + std::chrono::milliseconds{100};

    OwnedPreauthTcpConnection empty{OwnedNativeTcpSocket{}};
    assert(empty.ioInterest() == Interest::Closed);
    assert(!empty.cancelIfExpired(deadline, deadline));

    // The caller supplies its monotonic clock and can cancel a partial
    // incoming request without sleeps, allocation or a timer thread.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo client{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = validRequestWire();
        nativeSendAll(client, std::span(request).first(3));
        assert(owner.onSocketReady(true, false) == Interest::Read);
        assert(!owner.cancelIfExpired(deadline -
                std::chrono::nanoseconds{1}, deadline));
        assert(owner.active());
        assert(owner.cancelIfExpired(deadline, deadline));
        assert(!owner.active());
        assert(owner.stage() == PreauthStage::Closed);
        assert(owner.ioInterest() == Interest::Closed);
        assert(owner.onSocketReady(true, true) == Interest::Closed);
        assert(owner.establishedTls() == nullptr);
        assert(!owner.cancelIfExpired(deadline +
                std::chrono::seconds{1}, deadline));
        assert(pair.listener.value != kInvalidLocalSocket);
    }

    // A timed out connection with an attached SSL/BIO must free that
    // exact TLS before releasing its borrowed nonblocking native socket.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo client{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = validRequestWire();
        nativeSendAll(client, request);
        assert(waitForOwnedTcpReply(owner) == Interest::Write);
        assert(owner.onSocketReady(false, true) == Interest::ConfigureTls);
        std::array<std::uint8_t, 19> confirm{};
        nativeReadAll(client, confirm);
        TlsHandshakeFixture tls{false, false};
        OwnedPreauthTcpConnection::ServerTls server{
            tls.server.release(), SSL_free};
        assert(owner.attachServerTls(std::move(server)));
        assert(owner.ioInterest() == Interest::Read);
        assert(owner.onSocketReady(true, false) == Interest::Read);
        assert(owner.establishedTls() == nullptr);
        assert(owner.cancelIfExpired(deadline, deadline));
        assert(owner.ioInterest() == Interest::Closed);
        assert(owner.onSocketReady(true, true) == Interest::Closed);
        assert(owner.establishedTls() == nullptr);
        owner.cancel();
        assert(pair.listener.value != kInvalidLocalSocket);
    }
}


[[nodiscard]] TcpConnectionPollResult pollUntilTcpInterest(
    OwnedPreauthTcpConnection &owner,
    TcpConnectionIoInterest expected,
    std::chrono::steady_clock::time_point deadline)
{
    TcpConnectionPollResult last{};
    for (int attempt = 0; attempt < 4096; ++attempt)
    {
        last = owner.pollSocketOnce(deadline, std::chrono::milliseconds{2});
        if (last.nextInterest == expected) return last;
        assert(last.outcome == TcpConnectionPollOutcome::Dispatched ||
               last.outcome == TcpConnectionPollOutcome::NoEvent);
        assert(owner.active());
    }
    assert(false && "bounded TCP poll did not reach expected interest");
    return last;
}

void testOwnedTcpBoundedPollLoopbackTls()
{
    using Interest = TcpConnectionIoInterest;
    using Outcome = TcpConnectionPollOutcome;
    using Clock = std::chrono::steady_clock;

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
    assert(owner.active());
    assert(!accepted.connection.valid());
    const auto deadline = Clock::now() + std::chrono::seconds{10};

    // Empty socket: one zero-budget poll must not invoke a callback.
    const auto idle = owner.pollSocketOnce(deadline,
                                          std::chrono::milliseconds{0});
    assert(idle.outcome == Outcome::NoEvent);
    assert(idle.nextInterest == Interest::Read);

    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    const auto request = validRequestWire();
    nativeSendAll(clientIo, std::span(request).first(3));
    auto partial = pollUntilTcpInterest(owner, Interest::Read, deadline);
    assert(partial.nextInterest == Interest::Read);
    assert(owner.stage() == PreauthStage::AwaitConnectionRequest);
    nativeSendAll(clientIo, std::span(request).subspan(3));

    // Native poll detects read, then writable interest for queued Confirm.
    const auto read = pollUntilTcpInterest(owner, Interest::Write, deadline);
    assert(read.outcome == Outcome::Dispatched);
    const auto reply = owner.pollSocketOnce(deadline,
                                           std::chrono::milliseconds{2});
    assert(reply.outcome == Outcome::Dispatched);
    assert(reply.nextInterest == Interest::ConfigureTls);
    assert(owner.pollSocketOnce(deadline).outcome == Outcome::NeedsTls);
    std::array<std::uint8_t, 19> confirm{};
    nativeReadAll(clientIo, confirm);
    assert(confirm == negotiateDiagnosticTls(validRequest()).packet);

    TlsHandshakeFixture tls{false, false};
    const SSL *serverIdentity = tls.server.get();
    OwnedPreauthTcpConnection::ServerTls server{
        tls.server.release(), SSL_free};
    assert(owner.attachServerTls(std::move(server)));
    assert(attachNonblockingTcpBio(tls.client.get(), clientIo));
    bool clientEstablished = false;
    bool serverEstablished = false;
    for (int attempt = 0; attempt < 16384; ++attempt)
    {
        if (!clientEstablished)
        {
            const int success = SSL_do_handshake(tls.client.get());
            if (success == 1)
                clientEstablished = true;
            else
            {
                const int err = SSL_get_error(tls.client.get(), success);
                assert(err == SSL_ERROR_WANT_READ ||
                       err == SSL_ERROR_WANT_WRITE);
            }
        }
        const auto step = owner.pollSocketOnce(
            deadline, std::chrono::milliseconds{2});
        assert(step.outcome == Outcome::Dispatched ||
               step.outcome == Outcome::NoEvent);
        serverEstablished = owner.establishedTls() != nullptr;
        if (clientEstablished && serverEstablished) break;
    }
    assert(clientEstablished && serverEstablished);
    assert(owner.establishedTls() == serverIdentity);
    assert(owner.stage() == PreauthStage::AwaitMcsConnectInitial);

    const auto frame = validMcsPacket();
    std::size_t written = 0;
    for (int attempt = 0; attempt < 16384 && written < frame.size();
         ++attempt)
    {
        std::size_t count = 0;
        const int success = SSL_write_ex(tls.client.get(),
            frame.data() + written, frame.size() - written, &count);
        if (success == 1)
        {
            assert(count > 0 && count <= frame.size() - written);
            written += count;
        }
        else
        {
            const int err = SSL_get_error(tls.client.get(), success);
            assert(err == SSL_ERROR_WANT_READ ||
                   err == SSL_ERROR_WANT_WRITE);
            std::this_thread::yield();
        }
    }
    assert(written == frame.size());
    for (int attempt = 0; attempt < 16384 && owner.active(); ++attempt)
    {
        const auto step = owner.pollSocketOnce(
            deadline, std::chrono::milliseconds{2});
        assert(step.outcome == Outcome::Dispatched ||
               step.outcome == Outcome::NoEvent);
    }
    assert(!owner.active());
    assert(owner.stage() == PreauthStage::Closed);
    assert(owner.establishedTls() == nullptr);
    assert(owner.pollSocketOnce(deadline).outcome == Outcome::Closed);
    assert(pair.listener.value != kInvalidLocalSocket);
    assert(acceptNonblockingTcpConnection(
        static_cast<std::uintptr_t>(pair.listener.value)).outcome ==
        TcpAcceptOutcome::WouldBlock);
}

void testOwnedTcpBoundedPollTimeoutAndDisconnect()
{
    using Interest = TcpConnectionIoInterest;
    using Outcome = TcpConnectionPollOutcome;
    using Clock = std::chrono::steady_clock;

    OwnedPreauthTcpConnection empty{OwnedNativeTcpSocket{}};
    assert(empty.pollSocketOnce(Clock::now()).outcome == Outcome::Closed);
    assert(!empty.active());

    // Even a huge caller wait is clamped to a 25ms maximum OS wait;
    // expiration is checked at both ends of the one-step poll.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        const auto start = Clock::now();
        const auto hugeWait = owner.pollSocketOnce(
            start + std::chrono::seconds{4}, std::chrono::hours{1});
        const auto duration = Clock::now() - start;
        assert(hugeWait.outcome == Outcome::NoEvent);
        assert(hugeWait.nextInterest == Interest::Read);
        assert(duration < std::chrono::seconds{3});

        const auto expired = owner.pollSocketOnce(
            Clock::now() - std::chrono::nanoseconds{1},
            std::chrono::milliseconds{0});
        assert(expired.outcome == Outcome::Expired);
        assert(!owner.active());
        assert(owner.pollSocketOnce(Clock::now()).outcome ==
               Outcome::Closed);
        owner.cancel();
        assert(pair.listener.value != kInvalidLocalSocket);
    }

    // Closing the client in the middle of X.224 must report native
    // readable/HUP then fail closed, while preserving the listener.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo client{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = validRequestWire();
        nativeSendAll(client, std::span(request).first(3));
        pair.client.close();
        const auto deadline = Clock::now() + std::chrono::seconds{10};
        for (int i = 0; i < 4096 && owner.active(); ++i)
        {
            const auto result = owner.pollSocketOnce(
                deadline, std::chrono::milliseconds{2});
            assert(result.outcome == Outcome::Dispatched ||
                   result.outcome == Outcome::NoEvent);
        }
        assert(!owner.active());
        assert(owner.stage() == PreauthStage::Closed);
        assert(owner.pollSocketOnce(deadline).outcome == Outcome::Closed);
        assert(pair.listener.value != kInvalidLocalSocket);
    }
}

void connectAdditionalLoopbackClient(LocalSocket &additional,
                                     LocalSocketId listener)
{
    sockaddr_in address{};
#ifdef _WIN32
    int addressLength = sizeof(address);
#else
    socklen_t addressLength = sizeof(address);
#endif
    assert(::getsockname(listener,
                         reinterpret_cast<sockaddr *>(&address),
                         &addressLength) == 0);
    assert(address.sin_family == AF_INET);
    assert(address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    additional.value = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(additional.value != kInvalidLocalSocket);
    assert(::connect(additional.value,
                     reinterpret_cast<const sockaddr *>(&address),
                     sizeof(address)) == 0);
}

void testNativeTcpAcceptBatchBudgetAndHandoff()
{
    using Outcome = TcpAcceptBatchOutcome;
    using Interest = TcpConnectionIoInterest;
    LoopbackSocketPair pair{false};
    // Exactly three clients, but never require more than one queued at
    // once: Windows may preserve its original listen backlog limit.
    // The second arrives after the first handoff; the callback for
    // that second accepted socket connects the third before returning.
    LocalSocket secondClient{};
    LocalSocket thirdClient{};

    NativeTcpIo originalClient{
        static_cast<std::uintptr_t>(pair.client.value)};
    nativeSendAll(originalClient, validRequestWire());

    struct HandoffState
    {
        NativeTcpIo &firstClient;
        LocalSocket &thirdClient;
        LocalSocketId listener;
        std::size_t transferred{};
    } state{originalClient, thirdClient, pair.listener.value};
    const auto handoff = +[](OwnedNativeTcpSocket accepted,
                             void *context) noexcept -> bool
    {
        auto &state = *static_cast<HandoffState *>(context);
        assert(accepted.valid());
        // A single sole preauth owner adopts the callback's move-only
        // socket. It cannot move while SSL/BIO might borrow its IO.
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        assert(!accepted.valid());
        assert(owner.active());
        assert(owner.ioInterest() == Interest::Read);
        if (state.transferred == 0)
        {
            assert(waitForOwnedTcpReply(owner) == Interest::Write);
            assert(owner.onSocketReady(false, true) ==
                   Interest::ConfigureTls);
            std::array<std::uint8_t, 19> confirm{};
            nativeReadAll(state.firstClient, confirm);
            assert(confirm == negotiateDiagnosticTls(validRequest()).packet);
            assert(owner.establishedTls() == nullptr);
        }
        if (state.transferred == 1)
        {
            // The second accepted socket is already removed from the
            // backlog. Queue the third now, so a batch of two still
            // proves multiple accepts without assuming backlog >= 2.
            connectAdditionalLoopbackClient(
                state.thirdClient, state.listener);
        }
        ++state.transferred;
        owner.cancel();
        assert(!owner.active());
        return true;
    };

    const auto first = acceptNonblockingTcpBatch(
        static_cast<std::uintptr_t>(pair.listener.value),
        1, handoff, &state);
    assert(first.outcome == Outcome::BudgetReached);
    assert(first.accepted == 1 && state.transferred == 1);
    assert(pair.listener.value != kInvalidLocalSocket);
    connectAdditionalLoopbackClient(secondClient, pair.listener.value);

    const auto next = acceptNonblockingTcpBatch(
        static_cast<std::uintptr_t>(pair.listener.value),
        2, handoff, &state);
    assert(next.outcome == Outcome::BudgetReached);
    assert(next.accepted == 2 && state.transferred == 3);
    // BudgetReached deliberately makes no false claim that the native
    // backlog has been fully drained. The next call observes WouldBlock.
    const auto idle = acceptNonblockingTcpBatch(
        static_cast<std::uintptr_t>(pair.listener.value),
        kMaximumTcpAcceptBatch, handoff, &state);
    assert(idle.outcome == Outcome::WouldBlock);
    assert(idle.accepted == 0 && state.transferred == 3);
    assert(pair.listener.value != kInvalidLocalSocket);
}

void testNativeTcpAcceptBatchStopsAndDenials()
{
    using Outcome = TcpAcceptBatchOutcome;
    LoopbackSocketPair pair{false};
    struct StopState
    {
        std::size_t calls{};
        std::uintptr_t closedHandle{OwnedNativeTcpSocket::kInvalidSocket};
    } state{};
    const auto stop = +[](OwnedNativeTcpSocket accepted,
                          void *context) noexcept -> bool
    {
        auto &state = *static_cast<StopState *>(context);
        assert(accepted.valid());
        state.closedHandle = accepted.nativeSocket();
        ++state.calls;
        // No adoption: accepted RAII handle closes on return.
        return false;
    };

    // Invalid budgets and absent callback must NEVER steal the one
    // queued connection, and an unrelated socket is not a listener.
    const auto listener = static_cast<std::uintptr_t>(pair.listener.value);
    assert(acceptNonblockingTcpBatch(
        listener, 0, stop, &state).outcome == Outcome::InvalidInput);
    assert(acceptNonblockingTcpBatch(
        listener, kMaximumTcpAcceptBatch + 1, stop, &state).outcome ==
        Outcome::InvalidInput);
    assert(acceptNonblockingTcpBatch(
        listener, 1, nullptr, &state).outcome == Outcome::InvalidInput);
    assert(acceptNonblockingTcpBatch(
        OwnedNativeTcpSocket::kInvalidSocket, 1, stop, &state).outcome ==
        Outcome::InvalidInput);
    assert(state.calls == 0);
    const auto nonListener = acceptNonblockingTcpBatch(
        static_cast<std::uintptr_t>(pair.client.value), 1,
        stop, &state);
    assert(nonListener.outcome == Outcome::Failure);
    assert(nonListener.accepted == 0 && state.calls == 0);

    const auto stopped = acceptNonblockingTcpBatch(listener, 8,
                                                    stop, &state);
    assert(stopped.outcome == Outcome::CallbackStopped);
    assert(stopped.accepted == 1 && state.calls == 1);
#ifdef _WIN32
    int errorCode = 0;
    int errorSize = sizeof(errorCode);
    assert(::getsockopt(static_cast<SOCKET>(state.closedHandle),
                        SOL_SOCKET, SO_ERROR,
                        reinterpret_cast<char *>(&errorCode),
                        &errorSize) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAENOTSOCK);
#else
    errno = 0;
    assert(::fcntl(static_cast<int>(state.closedHandle), F_GETFD) == -1);
    assert(errno == EBADF);
#endif
    const auto idle = acceptNonblockingTcpBatch(listener, 8, stop, &state);
    assert(idle.outcome == Outcome::WouldBlock);
    assert(idle.accepted == 0 && state.calls == 1);
    assert(pair.listener.value != kInvalidLocalSocket);

    // A full handoff followed by a would-block is distinguishable from
    // budget exhaustion, and does not close the borrowed listener.
    LoopbackSocketPair drainedPair{false};
    std::size_t seen = 0;
    const auto keep = +[](OwnedNativeTcpSocket owned, void *context)
                          noexcept -> bool
    {
        assert(owned.valid());
        ++*static_cast<std::size_t *>(context);
        return true; // RAII auto-close (no session adopted).
    };
    // TCP connect returning does NOT guarantee the listener's pending
    // accept is immediately observable on every POSIX scheduler. Wait
    // boundedly using the production listener-readiness gate, without
    // adding a new socket owner or changing batch/drain semantics.
    TcpListenerPollResult drained{};
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{5};
    for (int attempt = 0; attempt < 128; ++attempt)
    {
        drained = pollNonblockingTcpAcceptBatch(
            static_cast<std::uintptr_t>(drainedPair.listener.value),
            2, keep, &seen, deadline, kMaximumTcpPollWait);
        if (drained.outcome != TcpListenerPollOutcome::NoEvent) break;
    }
    assert(drained.outcome == TcpListenerPollOutcome::BatchCompleted);
    assert(drained.batch.outcome == Outcome::Drained);
    assert(drained.batch.accepted == 1 && seen == 1);
    assert(drainedPair.listener.value != kInvalidLocalSocket);
}


void testNativeTcpListenerPollBudgetAndOwnerHandoff()
{
    using Outcome = TcpListenerPollOutcome;
    using BatchOutcome = TcpAcceptBatchOutcome;
    using Interest = TcpConnectionIoInterest;
    using Clock = std::chrono::steady_clock;

    LoopbackSocketPair pair{false};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    nativeSendAll(clientIo, validRequestWire());

    struct Handoff
    {
        NativeTcpIo &client;
        std::size_t received{};
    } state{clientIo};
    const auto callback = +[](OwnedNativeTcpSocket accepted,
                              void *context) noexcept -> bool
    {
        auto &state = *static_cast<Handoff *>(context);
        assert(accepted.valid());
        OwnedPreauthTcpConnection owner{std::move(accepted)};
        assert(!accepted.valid());
        assert(owner.active());
        assert(owner.ioInterest() == Interest::Read);
        if (state.received == 0)
        {
            assert(waitForOwnedTcpReply(owner) == Interest::Write);
            assert(owner.onSocketReady(false, true) ==
                   Interest::ConfigureTls);
            std::array<std::uint8_t, 19> confirm{};
            nativeReadAll(state.client, confirm);
            assert(confirm == negotiateDiagnosticTls(validRequest()).packet);
            assert(owner.establishedTls() == nullptr);
        }
        ++state.received;
        owner.cancel();
        assert(!owner.active());
        return true;
    };

    const auto deadline = Clock::now() + std::chrono::seconds{10};
    const auto listener = static_cast<std::uintptr_t>(pair.listener.value);
    const auto first = pollNonblockingTcpAcceptBatch(
        listener, 1, callback, &state, deadline,
        std::chrono::milliseconds{0});
    assert(first.outcome == Outcome::BatchCompleted);
    assert(first.batch.outcome == BatchOutcome::BudgetReached);
    assert(first.batch.accepted == 1 && state.received == 1);

    // The poll gate does not invoke the callback on an idle listener.
    const auto idle = pollNonblockingTcpAcceptBatch(
        listener, 2, callback, &state, deadline,
        std::chrono::milliseconds{0});
    assert(idle.outcome == Outcome::NoEvent);
    assert(idle.batch.accepted == 0 && state.received == 1);

    // No more than one pending client at a time: portable across
    // Windows and POSIX without depending on a backlog of two.
    LocalSocket secondClient{};
    connectAdditionalLoopbackClient(secondClient, pair.listener.value);
    const auto second = pollNonblockingTcpAcceptBatch(
        listener, 2, callback, &state, deadline,
        kMaximumTcpPollWait);
    assert(second.outcome == Outcome::BatchCompleted);
    assert(second.batch.outcome == BatchOutcome::Drained);
    assert(second.batch.accepted == 1 && state.received == 2);
    assert(pair.listener.value != kInvalidLocalSocket);
    assert(acceptNonblockingTcpConnection(listener).outcome ==
           TcpAcceptOutcome::WouldBlock);
}

void testNativeTcpListenerPollDeadlineAndDenials()
{
    using Outcome = TcpListenerPollOutcome;
    using BatchOutcome = TcpAcceptBatchOutcome;
    using Clock = std::chrono::steady_clock;

    LoopbackSocketPair pair{false};
    const auto listener = static_cast<std::uintptr_t>(pair.listener.value);
    struct StopState
    {
        std::size_t called{};
        std::uintptr_t acceptedSocket{OwnedNativeTcpSocket::kInvalidSocket};
    } state{};
    const auto stop = +[](OwnedNativeTcpSocket accepted,
                          void *context) noexcept -> bool
    {
        auto &state = *static_cast<StopState *>(context);
        assert(accepted.valid());
        state.acceptedSocket = accepted.nativeSocket();
        ++state.called;
        return false; // RAII auto-closes the incoming handle.
    };
    const auto future = Clock::now() + std::chrono::seconds{10};
    assert(pollNonblockingTcpAcceptBatch(
        listener, 0, stop, &state, future).outcome ==
        Outcome::InvalidInput);
    assert(pollNonblockingTcpAcceptBatch(
        listener, kMaximumTcpAcceptBatch + 1, stop, &state,
        future).outcome == Outcome::InvalidInput);
    assert(pollNonblockingTcpAcceptBatch(
        listener, 1, nullptr, &state, future).outcome ==
        Outcome::InvalidInput);
    assert(pollNonblockingTcpAcceptBatch(
        OwnedNativeTcpSocket::kInvalidSocket, 1, stop, &state,
        future).outcome == Outcome::InvalidInput);
#ifndef _WIN32
    if constexpr (sizeof(std::uintptr_t) > sizeof(int))
    {
        assert(pollNonblockingTcpAcceptBatch(
            static_cast<std::uintptr_t>(
                (std::numeric_limits<int>::max)()) + 1U,
            1, stop, &state, future).outcome ==
            Outcome::InvalidInput);
    }
#endif
    assert(state.called == 0);

    // Expiration is checked BEFORE touching an actually queued peer.
    const auto expired = pollNonblockingTcpAcceptBatch(
        listener, 1, stop, &state,
        Clock::now() - std::chrono::nanoseconds{1});
    assert(expired.outcome == Outcome::Expired);
    assert(state.called == 0);
    assert(pair.listener.value != kInvalidLocalSocket);

    const auto once = pollNonblockingTcpAcceptBatch(
        listener, kMaximumTcpAcceptBatch, stop, &state, future,
        std::chrono::milliseconds{0});
    assert(once.outcome == Outcome::BatchCompleted);
    assert(once.batch.outcome == BatchOutcome::CallbackStopped);
    assert(once.batch.accepted == 1 && state.called == 1);
#ifdef _WIN32
    int error = 0;
    int length = sizeof(error);
    assert(::getsockopt(static_cast<SOCKET>(state.acceptedSocket),
                        SOL_SOCKET, SO_ERROR,
                        reinterpret_cast<char *>(&error),
                        &length) == SOCKET_ERROR);
    assert(WSAGetLastError() == WSAENOTSOCK);
#else
    errno = 0;
    assert(::fcntl(static_cast<int>(state.acceptedSocket), F_GETFD) == -1);
    assert(errno == EBADF);
#endif

    // An excessive caller wait is clamped to 25ms even without a
    // connection; callback count remains unchanged.
    const auto before = Clock::now();
    const auto idle = pollNonblockingTcpAcceptBatch(
        listener, 1, stop, &state,
        before + std::chrono::seconds{5}, std::chrono::hours{1});
    const auto elapsed = Clock::now() - before;
    assert(idle.outcome == Outcome::NoEvent);
    assert(idle.batch.accepted == 0 && state.called == 1);
    assert(elapsed < std::chrono::seconds{2});

    // A closed native listening descriptor reports a hard error and
    // cannot be closed again by this borrowed-listener API.
    const auto native = pair.listener.value;
    pair.listener.close();
    const auto failed = pollNonblockingTcpAcceptBatch(
        static_cast<std::uintptr_t>(native), 1, stop, &state,
        future, std::chrono::milliseconds{0});
    assert(failed.outcome == Outcome::Failure);
    assert(failed.batch.accepted == 0 && state.called == 1);
}


void testNativeTcpListenerRoleAndModeDenials()
{
    using Batch = TcpAcceptBatchOutcome;
    using Poll = TcpListenerPollOutcome;
    using Clock = std::chrono::steady_clock;

    LoopbackSocketPair pair{false};
    const auto listener = static_cast<std::uintptr_t>(pair.listener.value);
    const auto client = static_cast<std::uintptr_t>(pair.client.value);
    std::size_t calls = 0;
    const auto callback = +[](OwnedNativeTcpSocket socket,
                              void *context) noexcept -> bool
    {
        assert(socket.valid());
        ++*static_cast<std::size_t *>(context);
        OwnedPreauthTcpConnection owner{std::move(socket)};
        assert(owner.active());
        assert(!socket.valid());
        owner.cancel();
        assert(!owner.active());
        return true;
    };
    const auto deadline = Clock::now() + std::chrono::seconds{10};

    // A connected stream socket is not a listening socket. It cannot
    // be promoted into a preauth owner by a one-shot/batch/poll call.
    const auto directRejected = acceptNonblockingTcpConnection(client);
    assert(directRejected.outcome == TcpAcceptOutcome::Failure);
    assert(!directRejected.connection.valid());
    const auto batchRejected = acceptNonblockingTcpBatch(
        client, 1, callback, &calls);
    assert(batchRejected.outcome == Batch::Failure);
    assert(batchRejected.accepted == 0 && calls == 0);
    const auto pollRejected = pollNonblockingTcpAcceptBatch(
        client, 1, callback, &calls, deadline,
        std::chrono::milliseconds{0});
    assert(pollRejected.outcome == Poll::Failure);
    assert(pollRejected.batch.accepted == 0 && calls == 0);

#ifndef _WIN32
    // The legitimate listener has a client queued. A temporarily
    // blocking descriptor must fail closed without consuming it
    // and without silently changing borrowed descriptor flags.
    const int fd = static_cast<int>(listener);
    const int flags = ::fcntl(fd, F_GETFL, 0);
    assert(flags >= 0 && (flags & O_NONBLOCK) != 0);
    assert(::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0);
    const auto blockedDirect = acceptNonblockingTcpConnection(listener);
    assert(blockedDirect.outcome == TcpAcceptOutcome::Failure);
    assert(!blockedDirect.connection.valid());
    const auto blockedBatch = acceptNonblockingTcpBatch(
        listener, kMaximumTcpAcceptBatch, callback, &calls);
    assert(blockedBatch.outcome == Batch::Failure);
    assert(blockedBatch.accepted == 0 && calls == 0);
    const auto blockedPoll = pollNonblockingTcpAcceptBatch(
        listener, 1, callback, &calls, deadline,
        std::chrono::milliseconds{0});
    assert(blockedPoll.outcome == Poll::Failure);
    assert(blockedPoll.batch.accepted == 0 && calls == 0);
    assert((::fcntl(fd, F_GETFL, 0) & O_NONBLOCK) == 0);
    // Only the caller may restore its listening descriptor mode.
    assert(::fcntl(fd, F_SETFL, flags) == 0);
    assert((::fcntl(fd, F_GETFL, 0) & O_NONBLOCK) != 0);
#endif

    // The original queued client is STILL available and transferred
    // once into the same existing nonmoving preauth connection owner.
    const auto accepted = acceptNonblockingTcpBatch(
        listener, 1, callback, &calls);
    assert(accepted.outcome == Batch::BudgetReached);
    assert(accepted.accepted == 1 && calls == 1);
    assert(pair.listener.value != kInvalidLocalSocket);
    const auto idle = acceptNonblockingTcpBatch(
        listener, 1, callback, &calls);
    assert(idle.outcome == Batch::WouldBlock);
    assert(idle.accepted == 0 && calls == 1);
}


void testNativeTcpWrongSocketTypeDenials()
{
    using Batch = TcpAcceptBatchOutcome;
    using Poll = TcpListenerPollOutcome;
    using Clock = std::chrono::steady_clock;
    LoopbackSocketPair pair{false};
    LocalSocket datagram{};
    datagram.value = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(datagram.value != kInvalidLocalSocket);
#ifdef _WIN32
    u_long nonblocking = 1;
    assert(::ioctlsocket(datagram.value, FIONBIO, &nonblocking) == 0);
#else
    const int flags = ::fcntl(datagram.value, F_GETFL, 0);
    assert(flags >= 0);
    assert(::fcntl(datagram.value, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
    std::size_t called = 0;
    const auto cb = +[](OwnedNativeTcpSocket socket,
                        void *context) noexcept -> bool
    {
        assert(socket.valid());
        ++*static_cast<std::size_t *>(context);
        socket.close();
        return true;
    };
    const auto invalid = static_cast<std::uintptr_t>(datagram.value);
    assert(acceptNonblockingTcpConnection(invalid).outcome ==
           TcpAcceptOutcome::Failure);
    const auto batch = acceptNonblockingTcpBatch(invalid, 2, cb, &called);
    assert(batch.outcome == Batch::Failure);
    assert(batch.accepted == 0 && called == 0);
    const auto deadline = Clock::now() + std::chrono::seconds{10};
    const auto polling = pollNonblockingTcpAcceptBatch(
        invalid, 1, cb, &called, deadline, std::chrono::milliseconds{0});
    assert(polling.outcome == Poll::Failure);
    assert(polling.batch.accepted == 0 && called == 0);

    // A valid borrowed nonblocking TCP listener has not lost its
    // already queued peer. Wait boundedly for OS-level readability.
    bool transferred = false;
    for (int i = 0; i < 128; ++i)
    {
        const auto ready = pollNonblockingTcpAcceptBatch(
            static_cast<std::uintptr_t>(pair.listener.value),
            1, cb, &called, deadline, kMaximumTcpPollWait);
        if (ready.outcome == Poll::NoEvent) continue;
        assert(ready.outcome == Poll::BatchCompleted);
        assert(ready.batch.outcome == Batch::BudgetReached);
        assert(ready.batch.accepted == 1 && called == 1);
        transferred = true;
        break;
    }
    assert(transferred);
    assert(pair.listener.value != kInvalidLocalSocket);
}

void testNativeTcpChunkBounds()
{
    // Real OS sockets, loopback only. The caller provides buffers much
    // larger than an int-safe bounded syscall; verify every nonblocking
    // native send/recv uses <= the shared per-callback limit and every
    // byte is eventually delivered in the correct order.
    LoopbackSocketPair pair;
    NativeTcpIo sender{static_cast<std::uintptr_t>(pair.client.value)};
    NativeTcpIo receiver{static_cast<std::uintptr_t>(pair.server.value)};
    const std::size_t maxChunk = kMaximumTcpIoChunkBytes;
    std::vector<std::uint8_t> payload(maxChunk * 2U + 37U);
    std::vector<std::uint8_t> delivered(payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<std::uint8_t>((i * 7U) & 0xffU);

    assert(sender.send({}).outcome == TcpIoOutcome::Failure);
    assert(receiver.receive({}).outcome == TcpIoOutcome::Failure);
    std::size_t total = 0;
    for (int iteration = 0; iteration < 16384 && total < payload.size();
         ++iteration)
    {
        const auto sent = sender.send(std::span(payload).subspan(total));
        if (sent.outcome == TcpIoOutcome::WouldBlock)
        {
            assert(sent.bytes == 0);
            std::this_thread::yield();
            continue;
        }
        assert(sent.outcome == TcpIoOutcome::Progress);
        assert(sent.bytes > 0 && sent.bytes <= maxChunk);
        std::size_t receivedForChunk = 0;
        for (int readAttempt = 0;
             readAttempt < 16384 && receivedForChunk < sent.bytes;
             ++readAttempt)
        {
            const auto read = receiver.receive(
                std::span(delivered).subspan(total + receivedForChunk));
            if (read.outcome == TcpIoOutcome::WouldBlock)
            {
                assert(read.bytes == 0);
                std::this_thread::yield();
                continue;
            }
            assert(read.outcome == TcpIoOutcome::Progress);
            assert(read.bytes > 0 && read.bytes <= maxChunk);
            assert(read.bytes <= sent.bytes - receivedForChunk);
            receivedForChunk += read.bytes;
        }
        assert(receivedForChunk == sent.bytes);
        total += sent.bytes;
    }
    assert(total == payload.size());
    assert(delivered == payload);
}

void testNativeLoopbackTlsAndMcs()
{
    LoopbackSocketPair pair;
    NativeTcpIo serverIo{static_cast<std::uintptr_t>(pair.server.value)};
    NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
    PreauthTcpAdapter adapter{serverIo};
    const auto request = validRequestWire();
    nativeSendAll(clientIo, request);
    waitForNativeRequest(adapter);
    assert(adapter.onWritable() == TcpPreauthEvent::ReadyForTls);
    std::array<std::uint8_t, 19> confirm{};
    nativeReadAll(clientIo, confirm);
    assert(confirm == negotiateDiagnosticTls(validRequest()).packet);

    // Both SSLs use real native nonblocking TCP I/O. No SSL_set_fd int
    // narrowing on Windows; BIO callbacks borrow the platform adapter.
    TlsHandshakeFixture tls{false, false};
    assert(adapter.attachTlsTransport(tls.server.get()));
    assert(attachNonblockingTcpBio(tls.client.get(), clientIo));
    assert(SSL_get_rbio(tls.server.get()) != nullptr);
    assert(SSL_get_wbio(tls.client.get()) != nullptr);
    assert(SSL_get_rbio(tls.server.get()) ==
           SSL_get_wbio(tls.server.get()));

    bool clientEstablished = false;
    bool serverEstablished = false;
    for (int pass = 0; pass < 16384; ++pass)
    {
        if (!clientEstablished)
        {
            const int clientResult = SSL_do_handshake(tls.client.get());
            if (clientResult == 1)
                clientEstablished = true;
            else
            {
                const int error = SSL_get_error(tls.client.get(),
                                                clientResult);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
        }
        if (!serverEstablished)
        {
            const auto status = adapter.onAttachedTlsIoReady();
            assert(status == TlsHandshakeStatus::NeedRead ||
                   status == TlsHandshakeStatus::NeedWrite ||
                   status == TlsHandshakeStatus::Established);
            serverEstablished = status == TlsHandshakeStatus::Established;
        }
        if (clientEstablished && serverEstablished) break;
        std::this_thread::yield();
    }
    assert(clientEstablished);
    assert(serverEstablished);
    assert(adapter.connection().stage() ==
           PreauthStage::AwaitMcsConnectInitial);

    const auto frame = validMcsPacket();
    std::size_t written = 0;
    for (int pass = 0; pass < 16384 && written != frame.size(); ++pass)
    {
        std::size_t output = 0;
        const int success = SSL_write_ex(
            tls.client.get(), frame.data() + written,
            frame.size() - written, &output);
        if (success == 1)
        {
            assert(output > 0 && output <= frame.size() - written);
            written += output;
        }
        else
        {
            const int error = SSL_get_error(tls.client.get(), success);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
            std::this_thread::yield();
        }
    }
    assert(written == frame.size());

    McsIntakeResult result{};
    std::size_t totalDecrypted = 0;
    for (int pass = 0; pass < 16384; ++pass)
    {
        result = adapter.onAttachedMcsIoReady();
        totalDecrypted += result.bytesConsumed;
        if (result.status != McsIntakeStatus::NeedMore) break;
        std::this_thread::yield();
    }
    assert(result.status == McsIntakeStatus::EnvelopeValidated);
    assert(totalDecrypted == frame.size());
    assert(adapter.connection().stage() == PreauthStage::Closed);
    // Only offline protocol validation occurred; no OS identity was
    // authenticated and the diagnostic never sends MCS Connect-Response.
}

void testNativeLoopbackCloseAndFailure()
{
    // A real socket FIN in the middle of the plaintext X.224 CR
    // terminates preauthentication; there is no TLS downgrade.
    {
        LoopbackSocketPair pair;
        NativeTcpIo serverIo{static_cast<std::uintptr_t>(pair.server.value)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        const auto request = validRequestWire();
        nativeSendAll(clientIo, std::span(request).first(3));
        PreauthTcpAdapter adapter{serverIo};
        bool partialReceived = false;
        for (int attempt = 0; attempt < 2048; ++attempt)
        {
            assert(adapter.onReadable() == TcpPreauthEvent::NeedRead);
            if (adapter.connection().connectionRequestBytesNeeded() == 1)
            {
                partialReceived = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(partialReceived);
        pair.client.close();
        bool sawEof = false;
        for (int attempt = 0; attempt < 2048; ++attempt)
        {
            const auto event = adapter.onReadable();
            if (event == TcpPreauthEvent::Invalid)
            {
                sawEof = true;
                break;
            }
            assert(event == TcpPreauthEvent::NeedRead);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        assert(sawEof);
        assert(adapter.connection().stage() == PreauthStage::Closed);
    }
    // The protocol-rejected request delivers a real X.224 NEG_FAILURE
    // on the connected socket and must not attach a TLS session.
    {
        LoopbackSocketPair pair;
        NativeTcpIo serverIo{static_cast<std::uintptr_t>(pair.server.value)};
        NativeTcpIo clientIo{static_cast<std::uintptr_t>(pair.client.value)};
        auto request = validRequestWire();
        request[15] = 0;
        nativeSendAll(clientIo, request);
        PreauthTcpAdapter adapter{serverIo};
        waitForNativeRequest(adapter);
        assert(adapter.onWritable() == TcpPreauthEvent::Closed);
        std::array<std::uint8_t, 19> response{};
        nativeReadAll(clientIo, response);
        assert(response == negotiateDiagnosticTls(
            parseConnectionRequest(request)).packet);
        assert(response[11] == 3);
        assert(adapter.connection().stage() == PreauthStage::Closed);
        assert(adapter.onWritable() == TcpPreauthEvent::Closed);
    }
}

// An independent complete MS-CSSP DER envelope. The contained token is
// intentionally NOT a valid GSS authenticator: only TLS + DER are tested.
constexpr std::array<std::uint8_t, 21> kTestCredSspDer{
    0x30, 0x13, 0xa0, 0x03, 0x02, 0x01, 0x06,
    0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08,
    0xa0, 0x06, 0x04, 0x04, 0x60, 0x82, 0x01, 0x00};

// Syntactically valid final authInfo shape with intentionally opaque,
// non-GSS ciphertext. It is used only to prove premature owner dispatch denial.
constexpr std::array<std::uint8_t, 14> kTestCredSspAuthInfoDer{
    0x30, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x06,
    0xa2, 0x05, 0x04, 0x03, 0x11, 0x22, 0x33};


[[nodiscard]] std::vector<std::uint8_t> makeFinalCredSspDer(
    std::uint8_t version)
{
    // One syntactically correct but NOT GSS-authenticated final TSRequest.
    // A negative fixture must never be accepted as Kerberos identity.
    std::vector<std::uint8_t> bytes(kTestCredSspDer.begin(),
                                    kTestCredSspDer.end());
    bytes.insert(bytes.end(), {0xa3, 0x03, 0x04, 0x01, 0x55,
                                0xa5, 0x22, 0x04, 0x20});
    bytes.insert(bytes.end(), 32, 0x42);
    assert(bytes.size() == 62);
    bytes[1] = static_cast<std::uint8_t>(bytes.size() - 2);
    bytes[6] = version;
    return bytes;
}

// Read as many already-available TLS plaintext segments as required for
// exactly one DER envelope; 1 SSL_read_ex per production method invocation.
std::size_t drainCredSspFromTls(
    TsRequestFrameReader &reader, SSL *serverTls,
    TsRequestTlsReadStatus finalStatus)
{
    std::size_t total = 0;
    for (std::size_t step = 0; step < kTestCredSspDer.size() + 8; ++step)
    {
        const auto result = reader.readOneTlsStep(serverTls);
        total += result.plaintextBytesRead;
        assert(result.error == TsRequestError::None);
        if (result.status == finalStatus)
        {
            assert(finalStatus != TsRequestTlsReadStatus::NeedRead ||
                   result.plaintextBytesRead == 0);
            return total;
        }
        assert(result.status == TsRequestTlsReadStatus::Progress);
        assert(result.plaintextBytesRead > 0);
    }
    assert(false && "TLS frame intake did not reach its expected boundary");
    return total;
}

std::size_t drainCredSspFromOwnedTls(
    TsRequestFrameReader &reader,
    OwnedPreauthTcpConnection &owner,
    TsRequestTlsReadStatus finalStatus,
    std::size_t minimumPlaintextBeforeNeedRead = 0)
{
    using PollOutcome = TcpConnectionPollOutcome;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{5};
    std::size_t total = 0;
    for (std::size_t step = 0; step < kTestCredSspDer.size() + 16; ++step)
    {
        const auto result = reader.readOneTlsStep(owner);
        total += result.plaintextBytesRead;
        assert(result.error == TsRequestError::None);
        if (result.status == finalStatus &&
            (finalStatus != TsRequestTlsReadStatus::NeedRead ||
             total >= minimumPlaintextBeforeNeedRead))
            return total;
        if (result.status == TsRequestTlsReadStatus::Progress)
        {
            assert(result.plaintextBytesRead > 0);
            continue;
        }
        assert(result.status == TsRequestTlsReadStatus::NeedRead ||
               result.status == TsRequestTlsReadStatus::NeedWrite);
        const auto polled = owner.pollSocketOnce(
            deadline, kMaximumTcpPollWait);
        assert(polled.outcome == PollOutcome::Dispatched ||
               polled.outcome == PollOutcome::NoEvent);
    }
    assert(false && "R1-owned CredSSP frame intake did not complete");
    return total;
}

std::size_t drainCredSspReplyThroughOwnedTls(
    TsRequestTlsReplyWriter &writer,
    OwnedPreauthTcpConnection &owner,
    bool &observedShortProgress)
{
    using PollOutcome = TcpConnectionPollOutcome;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{5};
    std::size_t total = 0;
    for (std::size_t step = 0; step < kMaximumCredSspRequestBytes + 16;
         ++step)
    {
        const auto before = writer.bytesRemaining();
        const auto result = writer.writeOneTlsStep(owner);
        total += result.plaintextBytesWritten;
        if (result.status == TsRequestTlsWriteStatus::Complete)
            return total;
        if (result.status == TsRequestTlsWriteStatus::Progress)
        {
            assert(result.plaintextBytesWritten > 0);
            assert(result.plaintextBytesWritten <= before);
            if (result.plaintextBytesWritten < before)
                observedShortProgress = true;
            continue;
        }
        assert(result.status == TsRequestTlsWriteStatus::NeedRead ||
               result.status == TsRequestTlsWriteStatus::NeedWrite);
        assert(result.plaintextBytesWritten == 0);
        const auto polled = owner.pollSocketOnce(
            deadline, kMaximumTcpPollWait);
        assert(polled.outcome == PollOutcome::Dispatched ||
               polled.outcome == PollOutcome::NoEvent);
    }
    assert(false && "R1-owned CredSSP reply did not complete");
    return total;
}



// Test-only certificate substitution helper is defined below the new
// HYBRID cases; declare it here so all compilers see the helper first.
void substituteCredSspReplyCertificate(SSL *destination, const SSL *source);

void testOwnedHybridCredSspFirstRecord()
{
    using Interest = TcpConnectionIoInterest;

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{
        std::move(accepted.connection),
        SecurityNegotiationPolicy::HybridNla};
    NativeTcpIo clientIo{
        static_cast<std::uintptr_t>(pair.client.value)};
    TlsHandshakeFixture tls{false, false};
    SSL *const selectedServer = tls.server.get();
    auto request = tlsAndHybridRequestWire();

    establishOwnedApplicationTlsForRequest(
        owner, clientIo, tls, request,
        SecurityNegotiationPolicy::HybridNla);
    assert(owner.stage() == PreauthStage::AwaitCredSsp);
    assert(owner.ioInterest() == Interest::Read);
    assert(owner.establishedTls() == selectedServer);

    request[15] = 0; // Caller storage cannot rewrite immutable provenance.
    const auto provenance = owner.securityNegotiationProvenance();
    assert(provenance.has_value());
    assert(provenance->clientRequestedProtocols ==
           (kRdpProtocolSsl | kRdpProtocolHybrid));
    assert(provenance->serverSelectedProtocol == kRdpProtocolHybrid);

    TsRequestFrameReader reader;
    const auto initial = reader.readOneTlsStep(owner);
    assert(initial.status == TsRequestTlsReadStatus::NeedRead);
    assert(initial.plaintextBytesRead == 0);
    assert(reader.completedFrameServerTls() == nullptr);

    writeNativeTlsClientAll(tls.client.get(), kTestCredSspDer);
    assert(drainCredSspFromOwnedTls(
               reader, owner, TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size());
    assert(owner.stage() == PreauthStage::AwaitCredSsp);
    assert(reader.completedFrameServerTls() == selectedServer);
    assert(std::equal(reader.completeDer().begin(),
                      reader.completeDer().end(),
                      kTestCredSspDer.begin(), kTestCredSspDer.end()));
    assert(reader.releaseFrame());
    assert(owner.stage() == PreauthStage::AwaitCredSsp);

    // DER framing is syntax only: TLS completion and one valid TSRequest do
    // not create R2 authentication or advance this transport into R3 MCS.
    owner.cancel();
    assert(owner.stage() == PreauthStage::Closed);
    assert(!owner.securityNegotiationProvenance().has_value());
}

void testOwnedHybridNoPrematureMcs()
{
    using Interest = TcpConnectionIoInterest;
    using PollOutcome = TcpConnectionPollOutcome;
    using Clock = std::chrono::steady_clock;

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{
        std::move(accepted.connection),
        SecurityNegotiationPolicy::HybridNla};
    NativeTcpIo clientIo{
        static_cast<std::uintptr_t>(pair.client.value)};
    TlsHandshakeFixture tls{false, false};
    const auto request = tlsAndHybridRequestWire();
    establishOwnedApplicationTlsForRequest(
        owner, clientIo, tls, request,
        SecurityNegotiationPolicy::HybridNla);
    assert(owner.stage() == PreauthStage::AwaitCredSsp);

    // Make a syntactically valid MCS envelope readable as the first post-TLS
    // application record. Readiness dispatch must not consume it as MCS.
    const auto earlyMcs = validMcsPacket();
    writeNativeTlsClientAll(tls.client.get(), earlyMcs);
    const auto deadline = Clock::now() + std::chrono::seconds{5};
    bool readinessSurfaced = false;
    for (std::size_t step = 0; step < 256; ++step)
    {
        const auto polled = owner.pollSocketOnce(
            deadline, kMaximumTcpPollWait);
        assert(polled.outcome == PollOutcome::Dispatched ||
               polled.outcome == PollOutcome::NoEvent);
        if (polled.outcome == PollOutcome::Dispatched)
        {
            assert(polled.nextInterest == Interest::Read);
            readinessSurfaced = true;
            break;
        }
    }
    assert(readinessSurfaced);
    assert(owner.active());
    assert(owner.stage() == PreauthStage::AwaitCredSsp);
    assert(owner.securityNegotiationProvenance().has_value());

    // The diagnostic MCS API is not an authentication bypass for HYBRID.
    // It fails closed before any SSL_read_ex and revokes all R1 provenance.
    const auto denied = owner.onMcsIoReady();
    assert(denied.status == McsIntakeStatus::Invalid);
    assert(denied.bytesConsumed == 0);
    assert(!owner.active());
    assert(owner.stage() == PreauthStage::Closed);
    assert(owner.establishedTls() == nullptr);
    assert(!owner.securityNegotiationProvenance().has_value());
}

void testOwnedHybridProvenanceRevocation()
{
    // Stable HYBRID provenance remains available through a valid CredSSP
    // readiness wait, then cancellation makes every borrowed identity inert.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        auto request = tlsAndHybridRequestWire();
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, request,
            SecurityNegotiationPolicy::HybridNla);
        request[15] = 0;

        const auto provenance = owner.securityNegotiationProvenance();
        assert(provenance.has_value());
        assert(provenance->clientRequestedProtocols ==
               (kRdpProtocolSsl | kRdpProtocolHybrid));
        assert(provenance->serverSelectedProtocol == kRdpProtocolHybrid);

        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(owner).status ==
               TsRequestTlsReadStatus::NeedRead);
        assert(owner.securityNegotiationProvenance() == provenance);

        owner.cancel();
        owner.cancel();
        assert(owner.stage() == PreauthStage::Closed);
        assert(owner.establishedTls() == nullptr);
        assert(!owner.securityNegotiationProvenance().has_value());
        assert(reader.readOneTlsStep(owner).status ==
               TsRequestTlsReadStatus::Closed);
        assert(owner.onTlsIoReady() == TlsHandshakeStatus::Closed);
        assert(!owner.securityNegotiationProvenance().has_value());
    }

    // Replacing the selected certificate in-place on the same established
    // SSL revokes negotiation provenance even though the raw SSL pointer is
    // unchanged. No mutable SSL capability is exposed by the production API.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        SSL *const selectedServer = tls.server.get();
        const auto request = tlsAndHybridRequestWire();
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, request,
            SecurityNegotiationPolicy::HybridNla);
        assert(owner.securityNegotiationProvenance().has_value());

        TlsHandshakeFixture replacementCertificate;
        substituteCredSspReplyCertificate(
            selectedServer, replacementCertificate.server.get());
        assert(owner.establishedTls() == selectedServer);
        assert(!owner.securityNegotiationProvenance().has_value());
        owner.cancel();
    }

    // A caller cannot replace the R1-owned SSL object after establishment.
    // The attempted second owner is consumed by RAII and terminally revokes
    // the original connection rather than creating another TLS controller.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        const auto request = tlsAndHybridRequestWire();
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, request,
            SecurityNegotiationPolicy::HybridNla);
        assert(owner.securityNegotiationProvenance().has_value());

        TlsHandshakeFixture replacement{false, false};
        OwnedPreauthTcpConnection::ServerTls replacementServer{
            replacement.server.release(), SSL_free};
        assert(!owner.attachServerTls(std::move(replacementServer)));
        assert(!owner.active());
        assert(owner.stage() == PreauthStage::Closed);
        assert(owner.establishedTls() == nullptr);
        assert(!owner.securityNegotiationProvenance().has_value());
    }
}

void testLiveTlsCertificateBindingPositive()
{
    // The OpenSSL TLS fixture performs a real handshake and chooses an
    // ephemeral X.509 certificate. This proves the selected certificate
    // hash computation, NOT a GSS unwrapped/authenticated token.
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        assert(SSL_is_init_finished(tls.server.get()) == 1);
        assert(SSL_is_server(tls.server.get()) == 1);
        const X509 *selected = SSL_get_certificate(tls.server.get());
        assert(selected);
        const ASN1_BIT_STRING *bits = X509_get0_pubkey_bitstr(selected);
        assert(bits);
        const int keyLength = ASN1_STRING_length(bits);
        assert(keyLength > 0);
        const auto *keyBytes = ASN1_STRING_get0_data(bits);
        assert(keyBytes);
        const auto keyView = std::span{
            static_cast<const std::uint8_t *>(keyBytes),
            static_cast<std::size_t>(keyLength)};

        CredSspTlsCertificateFingerprint fingerprint{};
        assert(fingerprintActiveCredSspServerTlsCertificate(
            tls.server.get(), fingerprint));
        assert(std::any_of(fingerprint.begin(), fingerprint.end(),
                           [](std::uint8_t octet) { return octet != 0; }));
        for (const auto seed : {std::uint8_t{0}, std::uint8_t{0x73}})
        {
            std::array<std::uint8_t, 32> nonce{};
            for (std::size_t i = 0; i < nonce.size(); ++i)
                nonce[i] = static_cast<std::uint8_t>(seed + i + version);
            for (auto direction : {
                     CredSspBindingDirection::ClientToServer,
                     CredSspBindingDirection::ServerToClient})
            {
                CredSspHash independent{};
                CredSspHash selectedTls{};
                assert(computeCredSspBindingHash(
                    direction, nonce, keyView, independent));
                assert(computeCredSspBindingForActiveServerTls(
                    tls.server.get(), direction, nonce, selectedTls));
                assert(selectedTls == independent);
                assert(verifyCredSspClientBindingForActiveServerTls(
                    tls.server.get(), nonce,
                    direction == CredSspBindingDirection::ClientToServer
                        ? independent : CredSspHash{}) ==
                    (direction == CredSspBindingDirection::ClientToServer));
            }
        }
    }
}

void testLiveTlsCertificateBindingRejections()
{
    TlsHandshakeFixture left;
    TlsHandshakeFixture right;
    const std::array<std::uint8_t, 32> nonce{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    CredSspTlsCertificateFingerprint lhs{};
    CredSspTlsCertificateFingerprint rhs{};
    assert(fingerprintActiveCredSspServerTlsCertificate(
        left.server.get(), lhs));
    assert(fingerprintActiveCredSspServerTlsCertificate(
        right.server.get(), rhs));
    assert(lhs != rhs);
    CredSspHash clientHash{};
    CredSspHash serverHash{};
    assert(computeCredSspBindingForActiveServerTls(
        left.server.get(), CredSspBindingDirection::ClientToServer,
        nonce, clientHash));
    assert(computeCredSspBindingForActiveServerTls(
        left.server.get(), CredSspBindingDirection::ServerToClient,
        nonce, serverHash));
    assert(clientHash != serverHash);
    assert(verifyCredSspClientBindingForActiveServerTls(
        left.server.get(), nonce, clientHash));
    assert(!verifyCredSspClientBindingForActiveServerTls(
        right.server.get(), nonce, clientHash));
    assert(!verifyCredSspClientBindingForActiveServerTls(
        left.server.get(), nonce, serverHash));
    for (std::size_t i = 0; i < nonce.size(); ++i)
    {
        auto changed = nonce;
        changed[i] ^= 0x01U;
        assert(!verifyCredSspClientBindingForActiveServerTls(
            left.server.get(), changed, clientHash));
    }
    for (std::size_t i = 0; i < clientHash.size(); ++i)
    {
        auto changed = clientHash;
        changed[i] ^= 0x80U;
        assert(!verifyCredSspClientBindingForActiveServerTls(
            left.server.get(), nonce, changed));
    }
    assert(!verifyCredSspClientBindingForActiveServerTls(
        left.server.get(), nonce, std::span(clientHash).first(31)));
    assert(!verifyCredSspClientBindingForActiveServerTls(
        left.server.get(), nonce, std::span(clientHash).first(0)));

    for (auto *tls : {static_cast<SSL *>(nullptr),
                      left.client.get()})
    {
        CredSspTlsCertificateFingerprint fingerprint{};
        fingerprint.fill(0xff);
        assert(!fingerprintActiveCredSspServerTlsCertificate(
            tls, fingerprint));
        assert(std::all_of(fingerprint.begin(), fingerprint.end(),
                           [](std::uint8_t v) { return v == 0; }));
        CredSspHash invalid{};
        invalid.fill(0xee);
        assert(!computeCredSspBindingForActiveServerTls(
            tls, CredSspBindingDirection::ClientToServer, nonce, invalid));
        assert(std::all_of(invalid.begin(), invalid.end(),
                           [](std::uint8_t v) { return v == 0; }));
        assert(!verifyCredSspClientBindingForActiveServerTls(
            tls, nonce, clientHash));
    }
    TlsHandshakeFixture unfinished{false};
    CredSspTlsCertificateFingerprint noHandshake{};
    assert(!fingerprintActiveCredSspServerTlsCertificate(
        unfinished.server.get(), noHandshake));
    assert(!verifyCredSspClientBindingForActiveServerTls(
        unfinished.server.get(), nonce, clientHash));
    for (const auto length : {std::size_t{0}, std::size_t{31},
                              std::size_t{33}})
    {
        const std::vector<std::uint8_t> invalidNonce(length, 0xaa);
        CredSspHash output{};
        output.fill(0xcc);
        assert(!computeCredSspBindingForActiveServerTls(
            left.server.get(), CredSspBindingDirection::ClientToServer,
            invalidNonce, output));
        assert(std::all_of(output.begin(), output.end(),
                           [](std::uint8_t v) { return v == 0; }));
        assert(!verifyCredSspClientBindingForActiveServerTls(
            left.server.get(), invalidNonce, clientHash));
    }
}

void testTlsCredSspCertificatePinning()
{
    // The SSL* stays the same, but changing its configured selected cert
    // after a complete TLS handshake must invalidate the original pinned
    // certificate identity across both completion and the next DER frame.
    TlsHandshakeFixture tls;
    TlsHandshakeFixture other;
    TsRequestFrameReader reader;
    writeTlsClientApplicationData(tls.client.get(), kTestCredSspDer);
    assert(drainCredSspFromTls(reader, tls.server.get(),
                              TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size());
    assert(reader.completedFrameServerTls() == tls.server.get());
    // OpenSSL 4 returns const X509*; SSL_use_certificate requires
    // mutable certificate ownership. Duplicate the test-only X509
    // without casting away const or weakening the selected-cert check.
    const CertificatePointer replacement{
        X509_dup(SSL_get_certificate(other.server.get())), X509_free};
    assert(replacement);
    assert(SSL_use_certificate(tls.server.get(), replacement.get()) == 1);
    CredSspTlsCertificateFingerprint newFingerprint{};
    CredSspTlsCertificateFingerprint expectedFingerprint{};
    assert(fingerprintActiveCredSspServerTlsCertificate(
        tls.server.get(), newFingerprint));
    assert(fingerprintActiveCredSspServerTlsCertificate(
        other.server.get(), expectedFingerprint));
    assert(newFingerprint == expectedFingerprint);
    assert(reader.completedFrameServerTls() == nullptr);
    const auto refused = reader.readOneTlsStep(tls.server.get());
    assert(refused.status == TsRequestTlsReadStatus::Invalid);
    assert(refused.plaintextBytesRead == 0);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(reader.completeDer().empty());
    assert(reader.completedFrameServerTls() == nullptr);

    // A partial frame also pins the certificate from its first live
    // read. A swap before the following chunk must be terminal.
    TlsHandshakeFixture partialTls;
    TlsHandshakeFixture otherCert;
    TsRequestFrameReader partial;
    writeTlsClientApplicationData(partialTls.client.get(),
                                  std::span(kTestCredSspDer).first(2));
    const auto first = partial.readOneTlsStep(partialTls.server.get());
    assert(first.status == TsRequestTlsReadStatus::Progress);
    assert(first.plaintextBytesRead == 2);
    assert(partial.completedFrameServerTls() == nullptr);
    const CertificatePointer alternate{
        X509_dup(SSL_get_certificate(otherCert.server.get())), X509_free};
    assert(alternate);
    assert(SSL_use_certificate(
        partialTls.server.get(), alternate.get()) == 1);
    writeTlsClientApplicationData(
        partialTls.client.get(), std::span(kTestCredSspDer).subspan(2));
    const auto second = partial.readOneTlsStep(partialTls.server.get());
    assert(second.status == TsRequestTlsReadStatus::Invalid);
    assert(second.plaintextBytesRead == 0);
    assert(partial.status() == TsRequestFrameStatus::Closed);

    // Without a certificate change, release must keep exactly the same
    // selected TLS identity for all subsequent TSRequest frames.
    TlsHandshakeFixture stable;
    TsRequestFrameReader reused;
    for (int iteration = 0; iteration < 3; ++iteration)
    {
        writeTlsClientApplicationData(stable.client.get(), kTestCredSspDer);
        assert(drainCredSspFromTls(
            reused, stable.server.get(), TsRequestTlsReadStatus::Complete) ==
               kTestCredSspDer.size());
        assert(reused.completedFrameServerTls() == stable.server.get());
        assert(reused.releaseFrame());
        assert(reused.completedFrameServerTls() == nullptr);
    }
    reused.close();
    assert(reused.status() == TsRequestFrameStatus::Closed);
}

void testTlsCredSspReplyWire()
{
    // Bytes come from the existing offline encoder; this test validates
    // their real TLS transport, not GSS authentication or OS admission.
    for (const std::size_t length : {std::size_t{1}, std::size_t{127},
                                     std::size_t{128}, std::size_t{256},
                                     std::size_t{8192}})
    {
        TlsHandshakeFixture tls;
        TsRequestTlsReplyWriter writer;
        for (const auto field : {CredSspServerReplyField::NegoToken,
                                 CredSspServerReplyField::EncryptedServerBinding})
        {
            std::vector<std::uint8_t> output(length, 0x5a);
            const auto expected = encodeCredSspServerTsRequest(6, field, output);
            assert(!expected.empty());
            assert(writer.queueReply(tls.server.get(), 6, field, output));
            assert(writer.status() == TsRequestTlsWriteStatus::NeedWrite);
            assert(writer.bytesRemaining() == expected.size());
            // Snapshot provider output: no caller ownership after enqueue.
            output[0] = 0xff;
            assert(!writer.releaseReply());
            const auto sent = writer.writeOneTlsStep(tls.server.get());
            assert(sent.status == TsRequestTlsWriteStatus::Complete);
            assert(sent.plaintextBytesWritten == expected.size());
            assert(writer.bytesRemaining() == 0);
            const auto again = writer.writeOneTlsStep(tls.server.get());
            assert(again.status == TsRequestTlsWriteStatus::Complete);
            assert(again.plaintextBytesWritten == 0);

            std::vector<std::uint8_t> actual;
            for (int step = 0; step < 128 && actual.size() < expected.size(); ++step)
            {
                std::array<std::uint8_t, 512> readBuffer{};
                std::size_t received = 0;
                assert(SSL_read_ex(tls.client.get(), readBuffer.data(),
                                   readBuffer.size(), &received) == 1);
                assert(received > 0 && received <= readBuffer.size());
                actual.insert(actual.end(), readBuffer.begin(),
                              readBuffer.begin() + static_cast<std::ptrdiff_t>(received));
            }
            assert(actual == expected);
            const auto decoded = parseCredSspTsRequest(actual);
            assert(decoded && decoded.value.version == 6);
            assert(decoded.value.tokenCount ==
                   (field == CredSspServerReplyField::NegoToken ? 1 : 0));
            assert(decoded.value.hasPubKeyAuth ==
                   (field == CredSspServerReplyField::EncryptedServerBinding));
            assert(writer.releaseReply());
            assert(writer.status() == TsRequestTlsWriteStatus::Idle);
            assert(!writer.releaseReply());
        }
        writer.close();
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    }
}

void testTlsCredSspReplyBackpressure()
{
    // Establish the BIO pair with bounded capacity BEFORE pairing; OpenSSL
    // forbids resizing an already-paired BIO (even after the handshake).
    // 2048 bytes is enough for this test handshake flight but smaller
    // than the protected long DER record, forcing real WANT_WRITE.
    TlsHandshakeFixture tls{true, true, 2048};
    TsRequestTlsReplyWriter writer;
    const std::vector<std::uint8_t> token(8192, 0x3a);
    const auto expected = encodeCredSspServerTsRequest(
        5, CredSspServerReplyField::NegoToken, token);
    assert(writer.queueReply(tls.server.get(), 5,
                             CredSspServerReplyField::NegoToken, token));
    bool blocked = false;
    std::size_t written = 0;
    std::vector<std::uint8_t> received;
    for (int step = 0; step < 2048 &&
                       (writer.status() != TsRequestTlsWriteStatus::Complete ||
                        received.size() != expected.size()); ++step)
    {
        if (writer.status() != TsRequestTlsWriteStatus::Complete)
        {
            const auto result = writer.writeOneTlsStep(tls.server.get());
            written += result.plaintextBytesWritten;
            if (result.status == TsRequestTlsWriteStatus::NeedWrite)
            {
                assert(result.plaintextBytesWritten == 0);
                blocked = true;
                assert(writer.bytesRemaining() == expected.size() - written);
            }
            else
                assert(result.status == TsRequestTlsWriteStatus::Progress ||
                       result.status == TsRequestTlsWriteStatus::Complete);
        }
        std::array<std::uint8_t, 512> bytes{};
        std::size_t count = 0;
        const int ok = SSL_read_ex(tls.client.get(), bytes.data(),
                                   bytes.size(), &count);
        if (ok == 1)
        {
            assert(count != 0 && received.size() + count <= expected.size());
            received.insert(received.end(), bytes.begin(),
                            bytes.begin() + static_cast<std::ptrdiff_t>(count));
        }
        else
        {
            const int error = SSL_get_error(tls.client.get(), ok);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
        }
    }
    assert(blocked);
    assert(writer.status() == TsRequestTlsWriteStatus::Complete);
    assert(written == expected.size());
    assert(received == expected);
    assert(writer.releaseReply());
}

// Replace the configured selected server X.509 on the SAME completed SSL
// connection. This deliberately simulates a certificate mutation without
// inventing a GSS identity or opening a live RDP service.
void substituteCredSspReplyCertificate(
    SSL *destination, const SSL *source)
{
    assert(destination && source);
    const CertificatePointer replacement{
        X509_dup(SSL_get_certificate(source)), X509_free};
    assert(replacement);
    assert(SSL_use_certificate(destination, replacement.get()) == 1);
    CredSspTlsCertificateFingerprint actual{};
    CredSspTlsCertificateFingerprint expected{};
    assert(fingerprintActiveCredSspServerTlsCertificate(
        destination, actual));
    assert(fingerprintActiveCredSspServerTlsCertificate(
        source, expected));
    assert(actual == expected);
}

void testTlsCredSspReleaseCertificateContinuity()
{
    // Stable TLS provenance remains reusable across released frames.
    TlsHandshakeFixture stable;
    TsRequestFrameReader reusable;
    for (int iteration = 0; iteration < 2; ++iteration)
    {
        writeTlsClientApplicationData(stable.client.get(), kTestCredSspDer);
        assert(drainCredSspFromTls(
            reusable, stable.server.get(), TsRequestTlsReadStatus::Complete) ==
               kTestCredSspDer.size());
        assert(reusable.completedFrameServerTls() == stable.server.get());
        assert(reusable.releaseFrame());
        assert(reusable.status() == TsRequestFrameStatus::NeedMore);
        assert(reusable.completeDer().empty());
        assert(reusable.completedFrameServerTls() == nullptr);
    }

    // A selected-certificate substitution on the SAME SSL* must fail at
    // release itself, wipe the retained DER and make the reader inert.
    TlsHandshakeFixture changed;
    TlsHandshakeFixture replacementSource;
    TsRequestFrameReader denied;
    SSL *const pinnedServer = changed.server.get();
    writeTlsClientApplicationData(changed.client.get(), kTestCredSspDer);
    assert(drainCredSspFromTls(
        denied, pinnedServer, TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size());
    assert(denied.completedFrameServerTls() == pinnedServer);
    assert(denied.completeDer().size() == kTestCredSspDer.size());

    substituteCredSspReplyCertificate(
        changed.server.get(), replacementSource.server.get());
    assert(changed.server.get() == pinnedServer);
    assert(denied.completedFrameServerTls() == nullptr);
    assert(!denied.releaseFrame());
    assert(denied.status() == TsRequestFrameStatus::Closed);
    assert(denied.completeDer().empty());
    assert(denied.bytesNeeded() == 0);
    assert(denied.completedFrameServerTls() == nullptr);
    assert(!denied.releaseFrame());

    writeTlsClientApplicationData(changed.client.get(), kTestCredSspDer);
    const auto replay = denied.readOneTlsStep(pinnedServer);
    assert(replay.status == TsRequestTlsReadStatus::Closed);
    assert(replay.plaintextBytesRead == 0);
    assert(replay.error == TsRequestError::None);
    const auto injectedReplay = denied.consume(kTestCredSspDer);
    assert(injectedReplay.status == TsRequestFrameStatus::Closed);
    assert(injectedReplay.bytesConsumed == 0);

    // Offline/manual framing has no TLS certificate provenance and keeps its
    // established release semantics. Explicit close remains terminal.
    TsRequestFrameReader offline;
    const auto firstOffline = offline.consume(kTestCredSspDer);
    assert(firstOffline.status == TsRequestFrameStatus::Complete);
    assert(firstOffline.bytesConsumed == kTestCredSspDer.size());
    assert(offline.completedFrameServerTls() == nullptr);
    assert(offline.releaseFrame());
    assert(offline.status() == TsRequestFrameStatus::NeedMore);

    const auto secondOffline = offline.consume(kTestCredSspDer);
    assert(secondOffline.status == TsRequestFrameStatus::Complete);
    offline.close();
    assert(offline.status() == TsRequestFrameStatus::Closed);
    assert(offline.completeDer().empty());
    assert(offline.bytesNeeded() == 0);
    assert(!offline.releaseFrame());
}

void testMcsTlsSelectedCertificateContinuity()
{
    // The selected server certificate must remain pinned across a
    // nonblocking WANT_READ, partial encrypted MCS frame, and completion.
    TlsHandshakeFixture tls;
    PreauthConnectionStream connection;
    advanceToTlsMcs(connection, tls.server.get());
    const auto idle = connection.consumeMcsConnectInitialFromTls(
        tls.server.get());
    assert(idle.bytesConsumed == 0);
    assert(idle.status == McsIntakeStatus::NeedMore);

    const auto packet = validMcsPacket();
    constexpr std::size_t firstFragmentBytes = 17;
    writeTlsClientApplicationData(
        tls.client.get(), std::span(packet).first(firstFragmentBytes));
    const auto partial = connection.consumeMcsConnectInitialFromTls(
        tls.server.get());
    assert(partial.bytesConsumed == firstFragmentBytes);
    assert(partial.status == McsIntakeStatus::NeedMore);
    assert(connection.stage() == PreauthStage::AwaitMcsConnectInitial);
    writeTlsClientApplicationData(
        tls.client.get(), std::span(packet).subspan(firstFragmentBytes));
    const auto complete = connection.consumeMcsConnectInitialFromTls(
        tls.server.get());
    assert(complete.bytesConsumed == packet.size() - firstFragmentBytes);
    assert(complete.status == McsIntakeStatus::EnvelopeValidated);
    assert(connection.stage() == PreauthStage::Closed);
}

void testMcsTlsSelectedCertificateSubstitution()
{
    // Swap the selected X.509 in place on the SAME completed SSL*.
    // One case changes it before the first MCS read, the other after
    // a real decrypted partial TPKT (and subsequent readiness event).
    const auto packet = validMcsPacket();
    for (const bool afterPartialRead : {false, true})
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture otherCertificate;
        PreauthConnectionStream connection;
        advanceToTlsMcs(connection, tls.server.get());

        CredSspTlsCertificateFingerprint previousFingerprint{};
        CredSspTlsCertificateFingerprint replacementFingerprint{};
        assert(fingerprintActiveCredSspServerTlsCertificate(
            tls.server.get(), previousFingerprint));
        assert(fingerprintActiveCredSspServerTlsCertificate(
            otherCertificate.server.get(), replacementFingerprint));
        assert(previousFingerprint != replacementFingerprint);

        constexpr std::size_t fragmentBytes = 17;
        writeTlsClientApplicationData(
            tls.client.get(), std::span(packet).first(fragmentBytes));
        if (afterPartialRead)
        {
            const auto partial = connection.consumeMcsConnectInitialFromTls(
                tls.server.get());
            assert(partial.bytesConsumed == fragmentBytes);
            assert(partial.status == McsIntakeStatus::NeedMore);
        }
        substituteCredSspReplyCertificate(
            tls.server.get(), otherCertificate.server.get());
        const auto refused = connection.consumeMcsConnectInitialFromTls(
            tls.server.get());
        assert(refused.bytesConsumed == 0);
        assert(refused.status == McsIntakeStatus::Invalid);
        assert(connection.stage() == PreauthStage::Closed);
        assert(connection.consumeMcsConnectInitialFromTls(tls.server.get())
                   .status == McsIntakeStatus::Closed);

        if (!afterPartialRead)
        {
            // No bytes from a substituted-certificate TLS source were
            // consumed before rejecting the MCS frame.
            std::array<std::uint8_t, 4> unread{};
            std::size_t obtained = 0;
            assert(SSL_read_ex(tls.server.get(), unread.data(),
                               unread.size(), &obtained) == 1);
            assert(obtained == unread.size());
            assert(std::equal(unread.begin(), unread.end(), packet.begin()));
        }
    }
}

void testTlsCredSspReplyCertPending()
{
    // Outgoing provider bytes are owned but must never be written after
    // the same SSL object's selected certificate changes before writing.
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        for (const auto field : {CredSspServerReplyField::NegoToken,
                                 CredSspServerReplyField::EncryptedServerBinding})
        {
            TlsHandshakeFixture tls;
            TlsHandshakeFixture substituted;
            TsRequestTlsReplyWriter writer;
            const std::array<std::uint8_t, 3> payload{0x12, 0x34, 0x56};
            assert(writer.queueReply(tls.server.get(), version, field, payload));
            assert(writer.bytesRemaining() > payload.size());
            substituteCredSspReplyCertificate(
                tls.server.get(), substituted.server.get());
            const auto rejected = writer.writeOneTlsStep(tls.server.get());
            assert(rejected.status == TsRequestTlsWriteStatus::Invalid);
            assert(rejected.plaintextBytesWritten == 0);
            assert(writer.status() == TsRequestTlsWriteStatus::Closed);
            assert(writer.bytesRemaining() == 0);
            assert(!writer.releaseReply());
            assert(writer.writeOneTlsStep(tls.server.get()).status ==
                   TsRequestTlsWriteStatus::Closed);
            assert(!writer.queueReply(tls.server.get(), version, field, payload));
            // No TLS write happened: this client must receive no reply.
            std::array<std::uint8_t, 64> bytes{};
            std::size_t count = 0;
            const int received = SSL_read_ex(
                tls.client.get(), bytes.data(), bytes.size(), &count);
            assert(received != 1);
            assert(SSL_get_error(tls.client.get(), received) ==
                   SSL_ERROR_WANT_READ);
            assert(count == 0);
        }
    }
}

void testTlsCredSspReplyCertCompletionAndReuse()
{
    const std::array<std::uint8_t, 2> token{0x41, 0x42};
    // A reply that WAS correctly encrypted and submitted is not
    // retractable; only future writer operations are forbidden after
    // a certificate change. Test both Complete and released Idle states.
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture substituted;
        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(tls.server.get(), 6,
                                 CredSspServerReplyField::NegoToken, token));
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Complete);
        substituteCredSspReplyCertificate(
            tls.server.get(), substituted.server.get());
        assert(!writer.releaseReply());
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
    }
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture substituted;
        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(tls.server.get(), 5,
                                 CredSspServerReplyField::NegoToken, token));
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Complete);
        substituteCredSspReplyCertificate(
            tls.server.get(), substituted.server.get());
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Invalid);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture substituted;
        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(tls.server.get(), 6,
                                 CredSspServerReplyField::NegoToken, token));
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Complete);
        assert(writer.releaseReply());
        assert(writer.status() == TsRequestTlsWriteStatus::Idle);
        substituteCredSspReplyCertificate(
            tls.server.get(), substituted.server.get());
        assert(!writer.queueReply(
            tls.server.get(), 6,
            CredSspServerReplyField::EncryptedServerBinding, token));
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
    }
    // The existing positive multi-reply behavior is preserved for an
    // unchanged certificate on the same TLS identity.
    {
        TlsHandshakeFixture tls;
        TsRequestTlsReplyWriter writer;
        for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
        {
            assert(writer.queueReply(tls.server.get(), version,
                                     CredSspServerReplyField::NegoToken, token));
            assert(writer.writeOneTlsStep(tls.server.get()).status ==
                   TsRequestTlsWriteStatus::Complete);
            assert(writer.writeOneTlsStep(tls.server.get()).status ==
                   TsRequestTlsWriteStatus::Complete);
            assert(writer.releaseReply());
            assert(writer.status() == TsRequestTlsWriteStatus::Idle);
        }
    }
}

void testTlsCredSspReplyCertBackpressure()
{
    // Constrained BIO forces an ACTUAL OpenSSL WANT_WRITE. The pending
    // retry buffer must be wiped, never resubmitted after the original
    // server's selected certificate is changed on the same SSL pointer.
    TlsHandshakeFixture tls{true, true, 2048};
    TlsHandshakeFixture substituted;
    TsRequestTlsReplyWriter writer;
    const std::vector<std::uint8_t> token(8192, 0x4a);
    assert(writer.queueReply(
        tls.server.get(), 6, CredSspServerReplyField::NegoToken, token));
    const auto blocked = writer.writeOneTlsStep(tls.server.get());
    assert(blocked.status == TsRequestTlsWriteStatus::NeedWrite);
    assert(blocked.plaintextBytesWritten == 0);
    const std::size_t remaining = writer.bytesRemaining();
    assert(remaining > 8192);
    substituteCredSspReplyCertificate(
        tls.server.get(), substituted.server.get());
    const auto rejected = writer.writeOneTlsStep(tls.server.get());
    assert(rejected.status == TsRequestTlsWriteStatus::Invalid);
    assert(rejected.plaintextBytesWritten == 0);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    assert(writer.bytesRemaining() == 0);
    assert(!writer.releaseReply());
    // Already-buffered SSL transport bytes cannot be recalled, and are
    // intentionally not counted as a new successful TLS write here.
}

void testTlsCredSspFailureReplyWire()
{
    // MS-CSSP 2.2.1: version 6 errorCode is a negative signed NTSTATUS.
    // Real completed TLS, canonical DER, no fabricated provider identity.
    for (auto failure : {CredSspServerFailure::LogonFailure,
                         CredSspServerFailure::NotSupported})
    {
        TlsHandshakeFixture tls;
        TsRequestTlsReplyWriter writer;
        const auto expected = encodeCredSspServerFailureTsRequest(6, failure);
        assert(expected.size() == 15);
        assert(writer.queueFailureReply(tls.server.get(), 6, failure));
        assert(writer.status() == TsRequestTlsWriteStatus::NeedWrite);
        assert(writer.bytesRemaining() == expected.size());
        assert(!writer.releaseReply());
        const auto wrote = writer.writeOneTlsStep(tls.server.get());
        assert(wrote.status == TsRequestTlsWriteStatus::Complete);
        assert(wrote.plaintextBytesWritten == expected.size());
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Complete);
        std::array<std::uint8_t, 64> plaintext{};
        std::size_t length = 0;
        assert(SSL_read_ex(tls.client.get(), plaintext.data(),
                           plaintext.size(), &length) == 1);
        assert(length == expected.size());
        assert(std::equal(expected.begin(), expected.end(),
                          plaintext.begin()));
        const auto parsed = parseCredSspTsRequest(
            std::span(plaintext).first(length));
        assert(parsed && parsed.value.version == 6);
        assert(parsed.value.hasErrorCode);
        assert(!parsed.value.hasAuthInfo && !parsed.value.hasPubKeyAuth &&
               !parsed.value.hasClientNonce && parsed.value.tokenCount == 0);
        assert(!parsed.value.initialNegoTokenOnly());
        assert(!parsed.value.finalNegoAndBindingOnly());
        // Once the error is transmitted and released the writer MUST
        // terminate; client and server never continue after errorCode.
        assert(writer.releaseReply());
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
        constexpr std::array<std::uint8_t, 1> token{0x42};
        assert(!writer.queueReply(
            tls.server.get(), 6, CredSspServerReplyField::NegoToken,
            token));
        assert(!writer.queueFailureReply(tls.server.get(), 6, failure));
    }

    // A regular negotiation response can be completed/released first,
    // then a failure queued on the SAME TLS fingerprint, but not after.
    TlsHandshakeFixture tls;
    TsRequestTlsReplyWriter writer;
    constexpr std::array<std::uint8_t, 2> negotiation{0x10, 0x20};
    assert(writer.queueReply(
        tls.server.get(), 6, CredSspServerReplyField::NegoToken,
        negotiation));
    assert(writer.writeOneTlsStep(tls.server.get()).status ==
           TsRequestTlsWriteStatus::Complete);
    std::array<std::uint8_t, 64> discard{};
    std::size_t read = 0;
    assert(SSL_read_ex(tls.client.get(), discard.data(),
                       discard.size(), &read) == 1);
    assert(read != 0);
    assert(writer.releaseReply());
    assert(writer.queueFailureReply(
        tls.server.get(), 6, CredSspServerFailure::LogonFailure));
    assert(writer.writeOneTlsStep(tls.server.get()).status ==
           TsRequestTlsWriteStatus::Complete);
    assert(writer.releaseReply());
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
}

void testTlsCredSspFailureReplyRejections()
{
    constexpr auto failure = CredSspServerFailure::LogonFailure;
    constexpr std::array<std::uint8_t, 1> token{0x7a};
    {
        TsRequestTlsReplyWriter nullWriter;
        assert(!nullWriter.queueFailureReply(nullptr, 6, failure));
        assert(nullWriter.status() == TsRequestTlsWriteStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        for (auto version : {std::uint8_t{0}, std::uint8_t{4},
                             std::uint8_t{5}, std::uint8_t{7}})
        {
            TsRequestTlsReplyWriter writer;
            assert(!writer.queueFailureReply(
                tls.server.get(), version, failure));
            assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        }
        TsRequestTlsReplyWriter invalid;
        assert(!invalid.queueFailureReply(
            tls.server.get(), 6,
            static_cast<CredSspServerFailure>(255)));
        assert(invalid.status() == TsRequestTlsWriteStatus::Closed);
        TsRequestTlsReplyWriter clientRole;
        assert(!clientRole.queueFailureReply(
            tls.client.get(), 6, failure));
        assert(clientRole.status() == TsRequestTlsWriteStatus::Closed);
    }
    {
        TlsHandshakeFixture unfinished{false};
        TsRequestTlsReplyWriter writer;
        assert(!writer.queueFailureReply(
            unfinished.server.get(), 6, failure));
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        TsRequestTlsReplyWriter pending;
        assert(pending.queueReply(
            tls.server.get(), 6,
            CredSspServerReplyField::NegoToken, token));
        assert(!pending.queueFailureReply(
            tls.server.get(), 6, failure));
        assert(pending.status() == TsRequestTlsWriteStatus::Closed);
        assert(pending.bytesRemaining() == 0);
    }
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture replacement;
        TsRequestTlsReplyWriter writer;
        assert(writer.queueFailureReply(
            tls.server.get(), 6, failure));
        substituteCredSspReplyCertificate(
            tls.server.get(), replacement.server.get());
        const auto rejected = writer.writeOneTlsStep(tls.server.get());
        assert(rejected.status == TsRequestTlsWriteStatus::Invalid);
        assert(rejected.plaintextBytesWritten == 0);
        assert(writer.bytesRemaining() == 0);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        std::array<std::uint8_t, 64> plaintext{};
        std::size_t length = 0;
        const int got = SSL_read_ex(
            tls.client.get(), plaintext.data(), plaintext.size(), &length);
        assert(got != 1);
        assert(SSL_get_error(tls.client.get(), got) ==
               SSL_ERROR_WANT_READ);
        assert(length == 0);
    }
}

void testTlsCredSspReplyRejections()
{
    {
        TsRequestTlsReplyWriter writer;
        assert(writer.writeOneTlsStep(nullptr).status ==
               TsRequestTlsWriteStatus::Idle);
        assert(!writer.releaseReply());
        const std::array<std::uint8_t, 1> token{0x7a};
        assert(!writer.queueReply(nullptr, 6,
            CredSspServerReplyField::NegoToken, token));
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.writeOneTlsStep(nullptr).status ==
               TsRequestTlsWriteStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        const std::array<std::uint8_t, 1> token{0x1a};
        TsRequestTlsReplyWriter clientRole;
        assert(!clientRole.queueReply(tls.client.get(), 6,
               CredSspServerReplyField::NegoToken, token));
        assert(clientRole.status() == TsRequestTlsWriteStatus::Closed);
        for (auto version : {std::uint8_t{4}, std::uint8_t{7}})
        {
            TsRequestTlsReplyWriter invalidVersion;
            assert(!invalidVersion.queueReply(tls.server.get(), version,
                   CredSspServerReplyField::NegoToken, token));
            assert(invalidVersion.status() == TsRequestTlsWriteStatus::Closed);
        }
        TsRequestTlsReplyWriter empty;
        assert(!empty.queueReply(tls.server.get(), 6,
               CredSspServerReplyField::NegoToken, {}));
        TsRequestTlsReplyWriter oversized;
        const std::vector<std::uint8_t> huge(8193, 0x1a);
        assert(!oversized.queueReply(tls.server.get(), 6,
               CredSspServerReplyField::NegoToken, huge));
    }
    {
        TlsHandshakeFixture unhandshaken{false};
        TsRequestTlsReplyWriter writer;
        const std::array<std::uint8_t, 1> token{0x7a};
        assert(!writer.queueReply(unhandshaken.server.get(), 6,
               CredSspServerReplyField::NegoToken, token));
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture substitute;
        TsRequestTlsReplyWriter writer;
        const std::array<std::uint8_t, 2> token{0x4a, 0x4b};
        assert(writer.queueReply(tls.server.get(), 6,
               CredSspServerReplyField::NegoToken, token));
        assert(writer.writeOneTlsStep(substitute.server.get()).status ==
               TsRequestTlsWriteStatus::Invalid);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
        assert(!writer.queueReply(tls.server.get(), 6,
               CredSspServerReplyField::NegoToken, token));
    }
    {
        TlsHandshakeFixture tls;
        TsRequestTlsReplyWriter writer;
        const std::array<std::uint8_t, 2> token{0x4a, 0x4b};
        assert(writer.queueReply(tls.server.get(), 5,
               CredSspServerReplyField::NegoToken, token));
        assert(!writer.queueReply(tls.server.get(), 5,
               CredSspServerReplyField::NegoToken, token));
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Closed);
    }
}

void testTlsCredSspFragmentation()
{
    for (std::size_t split = 1; split < kTestCredSspDer.size(); ++split)
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        // An empty read on a completed server SSL is nonfatal.
        assert(reader.readOneTlsStep(tls.server.get()).status ==
               TsRequestTlsReadStatus::NeedRead);
        writeTlsClientApplicationData(
            tls.client.get(), std::span(kTestCredSspDer).first(split));
        assert(drainCredSspFromTls(
            reader, tls.server.get(), TsRequestTlsReadStatus::NeedRead) ==
            split);
        assert(reader.status() == TsRequestFrameStatus::NeedMore);
        assert(reader.completeDer().empty());

        writeTlsClientApplicationData(
            tls.client.get(), std::span(kTestCredSspDer).subspan(split));
        assert(drainCredSspFromTls(
            reader, tls.server.get(), TsRequestTlsReadStatus::Complete) ==
            kTestCredSspDer.size() - split);
        assert(std::equal(reader.completeDer().begin(),
                          reader.completeDer().end(),
                          kTestCredSspDer.begin(), kTestCredSspDer.end()));
        const auto parsed = parseCredSspTsRequest(reader.completeDer());
        assert(parsed && parsed.value.version == 6);
        assert(parsed.value.tokenCount == 1 && !parsed.value.hasAuthInfo);
        assert(reader.releaseFrame());
        assert(reader.completeDer().empty());
        assert(reader.status() == TsRequestFrameStatus::NeedMore);
    }
}

void testTlsCredSspCoalescingAndIdentity()
{
    TlsHandshakeFixture tls;
    TsRequestFrameReader reader;
    std::array<std::uint8_t, kTestCredSspDer.size() * 2> combined{};
    std::copy(kTestCredSspDer.begin(), kTestCredSspDer.end(),
              combined.begin());
    std::copy(kTestCredSspDer.begin(), kTestCredSspDer.end(),
              combined.begin() + kTestCredSspDer.size());
    writeTlsClientApplicationData(tls.client.get(), combined);
    assert(drainCredSspFromTls(
        reader, tls.server.get(), TsRequestTlsReadStatus::Complete) ==
        kTestCredSspDer.size());
    const auto first = reader.completeDer();
    assert(std::equal(first.begin(), first.end(),
                      kTestCredSspDer.begin(), kTestCredSspDer.end()));
    // No socket read after Complete, including when the next frame was
    // coalesced into the same TLS record.
    const auto stillComplete = reader.readOneTlsStep(tls.server.get());
    assert(stillComplete.status == TsRequestTlsReadStatus::Complete &&
           stillComplete.plaintextBytesRead == 0);
    assert(reader.releaseFrame());
    assert(drainCredSspFromTls(
        reader, tls.server.get(), TsRequestTlsReadStatus::Complete) ==
        kTestCredSspDer.size());
    assert(reader.releaseFrame());
    assert(reader.completeDer().empty());

    // Mixing caller-crafted plaintext into this TLS-owned stream would
    // bypass the server TLS identity requirement: reject it terminally.
    assert(reader.consume(kTestCredSspDer).status ==
           TsRequestFrameStatus::Invalid);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(reader.readOneTlsStep(tls.server.get()).status ==
           TsRequestTlsReadStatus::Closed);
}

void testTlsCredSspRejections()
{
    {
        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(nullptr).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.completeDer().empty());
        assert(reader.readOneTlsStep(nullptr).status ==
               TsRequestTlsReadStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(tls.client.get()).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.status() == TsRequestFrameStatus::Closed);
    }
    {
        TlsHandshakeFixture tls{false};
        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(tls.server.get()).status ==
               TsRequestTlsReadStatus::Invalid);
    }
    {
        TlsHandshakeFixture tls;
        TlsHandshakeFixture substitute;
        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(tls.server.get()).status ==
               TsRequestTlsReadStatus::NeedRead);
        assert(reader.readOneTlsStep(substitute.server.get()).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
    }
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        // Opposite direction of mixed-source rejection: a manually
        // buffered DER header cannot later be blessed by real TLS.
        assert(reader.consume(std::span(kTestCredSspDer).first(1)).status ==
               TsRequestFrameStatus::NeedMore);
        assert(reader.readOneTlsStep(tls.server.get()).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.status() == TsRequestFrameStatus::Closed);
    }
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        constexpr std::array<std::uint8_t, 4> invalidDer{
            0x31, 0x02, 0xa0, 0x00};
        writeTlsClientApplicationData(tls.client.get(), invalidDer);
        const auto invalid = reader.readOneTlsStep(tls.server.get());
        assert(invalid.status == TsRequestTlsReadStatus::Invalid);
        assert(invalid.plaintextBytesRead == 2);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
    }
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        writeTlsClientApplicationData(
            tls.client.get(), std::span(kTestCredSspDer).first(5));
        assert(drainCredSspFromTls(
            reader, tls.server.get(), TsRequestTlsReadStatus::NeedRead) ==
            5);
        assert(SSL_shutdown(tls.client.get()) >= 0);
        assert(reader.readOneTlsStep(tls.server.get()).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
    }
}


void testTlsCredSspProvenance()
{
    // Syntactically complete bytes fed without OpenSSL are not
    // authenticated TLS evidence and must never be accepted by GSS.
    TsRequestFrameReader manual;
    assert(manual.consume(kTestCredSspDer).status ==
           TsRequestFrameStatus::Complete);
    assert(manual.completedFrameServerTls() == nullptr);
    assert(manual.releaseFrame());
    assert(manual.completedFrameServerTls() == nullptr);

    TlsHandshakeFixture tls;
    TsRequestFrameReader reader;
    assert(reader.completedFrameServerTls() == nullptr);
    assert(reader.readOneTlsStep(tls.server.get()).status ==
           TsRequestTlsReadStatus::NeedRead);
    assert(reader.completedFrameServerTls() == nullptr);
    writeTlsClientApplicationData(
        tls.client.get(), std::span(kTestCredSspDer).first(8));
    assert(drainCredSspFromTls(reader, tls.server.get(),
                              TsRequestTlsReadStatus::NeedRead) == 8);
    assert(reader.completedFrameServerTls() == nullptr);
    writeTlsClientApplicationData(
        tls.client.get(), std::span(kTestCredSspDer).subspan(8));
    assert(drainCredSspFromTls(reader, tls.server.get(),
                              TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size() - 8);
    assert(reader.completedFrameServerTls() == tls.server.get());
    assert(reader.completedFrameServerTls() != tls.client.get());
    assert(reader.releaseFrame());
    assert(reader.completedFrameServerTls() == nullptr);

    // A second DER frame on the same SSL yields the same borrowed
    // transport identity. No second auth/session owner is created.
    writeTlsClientApplicationData(tls.client.get(), kTestCredSspDer);
    assert(drainCredSspFromTls(reader, tls.server.get(),
                              TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size());
    assert(reader.completedFrameServerTls() == tls.server.get());
    reader.close();
    assert(reader.completedFrameServerTls() == nullptr);
    assert(reader.completeDer().empty());
}


void testOwnedTlsCredSspFraming()
{
    // Positive framing over the exact R1-owned SSL/BIO/socket.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        SSL *const selectedServer = tls.server.get();
        establishOwnedApplicationTls(owner, clientIo, tls);

        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(owner).status ==
               TsRequestTlsReadStatus::NeedRead);
        assert(reader.completedFrameServerTls() == nullptr);

        writeNativeTlsClientAll(
            tls.client.get(), std::span(kTestCredSspDer).first(8));
        assert(drainCredSspFromOwnedTls(
            reader, owner, TsRequestTlsReadStatus::NeedRead, 8) == 8);
        assert(reader.completedFrameServerTls() == nullptr);

        writeNativeTlsClientAll(
            tls.client.get(), std::span(kTestCredSspDer).subspan(8));
        assert(drainCredSspFromOwnedTls(
            reader, owner, TsRequestTlsReadStatus::Complete) ==
               kTestCredSspDer.size() - 8);
        assert(reader.completedFrameServerTls() == selectedServer);
        assert(reader.completedFrameServerTls() == owner.establishedTls());
        assert(std::equal(reader.completeDer().begin(),
                          reader.completeDer().end(),
                          kTestCredSspDer.begin(), kTestCredSspDer.end()));
        assert(reader.releaseFrame());
        assert(reader.completedFrameServerTls() == nullptr);

        // Once production framing is owner-bound, raw SSL I/O cannot take
        // over even if the caller retained the same pointer.
        assert(reader.readOneTlsStep(owner).status ==
               TsRequestTlsReadStatus::NeedRead);
        assert(reader.readOneTlsStep(selectedServer).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(owner.active());
        owner.cancel();
    }

    // A different established R1 owner cannot satisfy an in-progress frame.
    {
        LoopbackSocketPair leftPair{false};
        LoopbackSocketPair rightPair{false};
        auto leftAccepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(leftPair.listener.value));
        auto rightAccepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(rightPair.listener.value));
        assert(leftAccepted.outcome == TcpAcceptOutcome::Accepted);
        assert(rightAccepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection left{std::move(leftAccepted.connection)};
        OwnedPreauthTcpConnection right{std::move(rightAccepted.connection)};
        NativeTcpIo leftClient{
            static_cast<std::uintptr_t>(leftPair.client.value)};
        NativeTcpIo rightClient{
            static_cast<std::uintptr_t>(rightPair.client.value)};
        TlsHandshakeFixture leftTls{false, false};
        TlsHandshakeFixture rightTls{false, false};
        establishOwnedApplicationTls(left, leftClient, leftTls);
        establishOwnedApplicationTls(right, rightClient, rightTls);

        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(left).status ==
               TsRequestTlsReadStatus::NeedRead);
        assert(reader.readOneTlsStep(right).status ==
               TsRequestTlsReadStatus::Invalid);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(left.active());
        assert(right.active());
        left.cancel();
        right.cancel();
    }

    // R1 cancellation invalidates the borrowed provenance before the reader
    // touches the freed SSL/certificate.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTls(owner, clientIo, tls);

        TsRequestFrameReader reader;
        assert(reader.readOneTlsStep(owner).status ==
               TsRequestTlsReadStatus::NeedRead);
        owner.cancel();
        assert(reader.completedFrameServerTls() == nullptr);
        assert(reader.readOneTlsStep(owner).status ==
               TsRequestTlsReadStatus::Closed);
        assert(reader.status() == TsRequestFrameStatus::Closed);
    }
}

void testOwnedTlsCredSspReplyTransport()
{
    // Production reply bytes advance only through R1. Force OpenSSL's
    // partial-write mode to expose bounded short progress.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        assert(SSL_set_max_send_fragment(tls.server.get(), 1024) == 1);
        SSL *const selectedServer = tls.server.get();
        establishOwnedApplicationTls(owner, clientIo, tls);

        std::vector<std::uint8_t> token(8192, 0x3a);
        const auto expected = encodeCredSspServerTsRequest(
            6, CredSspServerReplyField::NegoToken, token);
        assert(!expected.empty());

        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(
            owner, 6, CredSspServerReplyField::NegoToken, token));
        token[0] ^= 0xffU;
        assert(writer.status() == TsRequestTlsWriteStatus::NeedWrite);

        const auto first = writer.writeOneTlsStep(owner);
        assert(first.status == TsRequestTlsWriteStatus::Progress);
        assert(first.plaintextBytesWritten > 0);
        assert(first.plaintextBytesWritten <= 1024U);
        bool observedShortProgress =
            first.plaintextBytesWritten < expected.size();
        const auto remainder = drainCredSspReplyThroughOwnedTls(
            writer, owner, observedShortProgress);
        assert(first.plaintextBytesWritten + remainder == expected.size());
        assert(observedShortProgress);

        std::vector<std::uint8_t> received(expected.size());
        readNativeTlsClientAll(
            tls.client.get(), std::span<std::uint8_t>{received});
        assert(received == expected);
        assert(writer.releaseReply());
        assert(writer.status() == TsRequestTlsWriteStatus::Idle);

        // Existing GSS queueing performs no I/O. On a fresh writer, a
        // raw-queued reply can therefore be adopted by the exact R1 owner
        // on its FIRST write without allowing any direct SSL_write_ex.
        constexpr std::array<std::uint8_t, 4> smallToken{
            0x60, 0x82, 0x01, 0x00};
        const auto secondExpected = encodeCredSspServerTsRequest(
            6, CredSspServerReplyField::NegoToken, smallToken);
        TsRequestTlsReplyWriter adoptedWriter;
        assert(adoptedWriter.queueReply(
            selectedServer, 6, CredSspServerReplyField::NegoToken,
            smallToken));
        bool secondShort = false;
        assert(drainCredSspReplyThroughOwnedTls(
                   adoptedWriter, owner, secondShort) ==
               secondExpected.size());
        std::vector<std::uint8_t> secondReceived(secondExpected.size());
        readNativeTlsClientAll(
            tls.client.get(), std::span<std::uint8_t>{secondReceived});
        assert(secondReceived == secondExpected);

        // Cancellation between complete write and release must fail safely
        // without dereferencing the SSL that R1 just destroyed.
        owner.cancel();
        assert(!adoptedWriter.releaseReply());
        assert(adoptedWriter.status() == TsRequestTlsWriteStatus::Closed);
    }

    // An owner-bound writer cannot be downgraded to direct SSL_write_ex.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        SSL *const selectedServer = tls.server.get();
        establishOwnedApplicationTls(owner, clientIo, tls);
        constexpr std::array<std::uint8_t, 4> token{
            0x60, 0x82, 0x01, 0x00};

        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(
            owner, 6, CredSspServerReplyField::NegoToken, token));
        assert(writer.writeOneTlsStep(selectedServer).status ==
               TsRequestTlsWriteStatus::Invalid);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(owner.active());
        owner.cancel();
    }

    // A queued reply is tied to one exact R1 owner even when two valid TLS
    // connections happen to be simultaneously established.
    {
        LoopbackSocketPair leftPair{false};
        LoopbackSocketPair rightPair{false};
        auto leftAccepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(leftPair.listener.value));
        auto rightAccepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(rightPair.listener.value));
        assert(leftAccepted.outcome == TcpAcceptOutcome::Accepted);
        assert(rightAccepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection left{std::move(leftAccepted.connection)};
        OwnedPreauthTcpConnection right{std::move(rightAccepted.connection)};
        NativeTcpIo leftClient{
            static_cast<std::uintptr_t>(leftPair.client.value)};
        NativeTcpIo rightClient{
            static_cast<std::uintptr_t>(rightPair.client.value)};
        TlsHandshakeFixture leftTls{false, false};
        TlsHandshakeFixture rightTls{false, false};
        establishOwnedApplicationTls(left, leftClient, leftTls);
        establishOwnedApplicationTls(right, rightClient, rightTls);
        constexpr std::array<std::uint8_t, 4> token{
            0x60, 0x82, 0x01, 0x00};

        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(
            left, 6, CredSspServerReplyField::NegoToken, token));
        assert(writer.writeOneTlsStep(right).status ==
               TsRequestTlsWriteStatus::Invalid);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(left.active());
        assert(right.active());
        left.cancel();
        right.cancel();
    }
}

#ifdef RDP_TEST_LINUX_GSSAPI

// The explicitly OPT-IN Kerberos probe uses only an externally provisioned
// FILE: client cache and a separately supplied service keytab. Never query
// host login, a default cache, or an automatically selected service name.
struct TestKerberosInitiator final
{
    gss_name_t target{GSS_C_NO_NAME};
    gss_cred_id_t credential{GSS_C_NO_CREDENTIAL};
    gss_ctx_id_t context{GSS_C_NO_CONTEXT};

    TestKerberosInitiator(std::string_view service, std::string_view cache)
    {
        assert(service.starts_with("TERMSRV/") && service.find('@') !=
               service.npos);
        assert(cache.starts_with("FILE:/"));
        OM_uint32 minor = 0;
        gss_buffer_desc name{service.size(),
                             const_cast<char *>(service.data())};
        assert(gss_import_name(&minor, &name, GSS_KRB5_NT_PRINCIPAL_NAME,
                               &target) == GSS_S_COMPLETE);
        const std::string explicitCache{cache};
        gss_key_value_element_desc element{
            "ccache", explicitCache.c_str()};
        gss_key_value_set_desc store{1, &element};
        assert(gss_acquire_cred_from(
            &minor, GSS_C_NO_NAME, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
            GSS_C_INITIATE, &store, &credential, nullptr, nullptr) ==
            GSS_S_COMPLETE);
        assert(credential != GSS_C_NO_CREDENTIAL);
    }
    TestKerberosInitiator(const TestKerberosInitiator &) = delete;
    TestKerberosInitiator &operator=(const TestKerberosInitiator &) = delete;
    ~TestKerberosInitiator()
    {
        OM_uint32 minor = 0;
        if (context != GSS_C_NO_CONTEXT)
            (void)gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
        if (credential != GSS_C_NO_CREDENTIAL)
            (void)gss_release_cred(&minor, &credential);
        if (target != GSS_C_NO_NAME)
            (void)gss_release_name(&minor, &target);
    }
    [[nodiscard]] OM_uint32 next(
        std::span<const std::uint8_t> serverToken,
        std::vector<std::uint8_t> &clientToken)
    {
        static std::array<std::uint8_t, 6> oidData{
            0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
        static gss_OID_desc spnego{oidData.size(), oidData.data()};
        gss_buffer_desc incoming{serverToken.size(),
                                 const_cast<std::uint8_t *>(serverToken.data())};
        gss_buffer_desc outgoing = GSS_C_EMPTY_BUFFER;
        OM_uint32 minor = 0;
        OM_uint32 flags = 0;
        constexpr OM_uint32 requested = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG |
            GSS_C_CONF_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
        const auto major = gss_init_sec_context(
            &minor, credential, &context, target, &spnego,
            requested, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
            serverToken.empty() ? GSS_C_NO_BUFFER : &incoming,
            nullptr, &outgoing, &flags, nullptr);
        assert(major == GSS_S_CONTINUE_NEEDED || major == GSS_S_COMPLETE);
        assert(outgoing.length <= kMaximumSpnegoInputBytes);
        clientToken.clear();
        if (outgoing.length != 0)
        {
            assert(outgoing.value);
            const auto *bytes =
                static_cast<const std::uint8_t *>(outgoing.value);
            clientToken.assign(bytes, bytes + outgoing.length);
        }
        (void)gss_release_buffer(&minor, &outgoing);
        if (major == GSS_S_COMPLETE)
            assert((flags & requested) == requested);
        return major;
    }

    [[nodiscard]] std::vector<std::uint8_t> seal(
        std::span<const std::uint8_t> cleartext) const
    {
        assert(context != GSS_C_NO_CONTEXT);
        gss_buffer_desc input{
            cleartext.size(), const_cast<std::uint8_t *>(cleartext.data())};
        gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
        OM_uint32 minor = 0;
        int confidential = 0;
        assert(gss_wrap(&minor, context, 1, GSS_C_QOP_DEFAULT, &input,
                        &confidential, &output) == GSS_S_COMPLETE);
        assert(confidential != 0 && output.value != nullptr);
        assert(output.length > 0 && output.length <= kMaximumSpnegoInputBytes);
        const auto *bytes =
            static_cast<const std::uint8_t *>(output.value);
        std::vector<std::uint8_t> ciphertext(bytes, bytes + output.length);
        (void)gss_release_buffer(&minor, &output);
        return ciphertext;
    }

    void verifyProtectedServerProof(
        std::span<const std::uint8_t> ciphertext,
        std::span<const std::uint8_t> expected) const
    {
        gss_buffer_desc input{
            ciphertext.size(), const_cast<std::uint8_t *>(ciphertext.data())};
        gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
        OM_uint32 minor = 0;
        int confidential = 0;
        assert(gss_unwrap(&minor, context, &input, &output,
                          &confidential, nullptr) == GSS_S_COMPLETE);
        assert(confidential != 0 && output.value != nullptr);
        assert(output.length == expected.size());
        assert(CRYPTO_memcmp(output.value, expected.data(),
                             expected.size()) == 0);
        OPENSSL_cleanse(output.value, output.length);
        (void)gss_release_buffer(&minor, &output);
    }
};

// Binding-only DER shape; intentionally NOT a real GSS-protected hash.
constexpr std::array<std::uint8_t, 48> kTestBindingOnlyDer{{
    0x30, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x06,
    0xa3, 0x03, 0x04, 0x01, 0x55,
    0xa5, 0x22, 0x04, 0x20,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}};

void receiveOneCredSspTlsFrame(
    TsRequestFrameReader &reader, SSL *server, std::size_t expected)
{
    std::size_t total = 0;
    for (std::size_t index = 0; index < expected + 8; ++index)
    {
        const auto step = reader.readOneTlsStep(server);
        total += step.plaintextBytesRead;
        assert(step.error == TsRequestError::None);
        if (step.status == TsRequestTlsReadStatus::Complete)
        {
            assert(total == expected);
            assert(reader.completedFrameServerTls() == server);
            return;
        }
        assert(step.status == TsRequestTlsReadStatus::Progress);
        assert(step.plaintextBytesRead > 0);
    }
    assert(false && "no complete real TLS CredSSP frame");
}

void assertNoGssReplyDelivered(SSL *client)
{
    // A rejected GSS provider must not produce even one TLS application
    // record, independent of whether the DER token was syntactically valid.
    std::array<std::uint8_t, 32> received{};
    std::size_t count = 0;
    const int result = SSL_read_ex(client, received.data(), received.size(),
                                   &count);
    assert(result != 1);
    assert(SSL_get_error(client, result) == SSL_ERROR_WANT_READ);
    assert(count == 0);
}


using OwnedCredSspAdvance =
    OwnedCredSspHandshakeResult (GssapiSpnegoAcceptor::*)(
        OwnedPreauthTcpConnection &,
        TsRequestFrameReader &,
        TsRequestTlsReplyWriter &) noexcept;

static_assert(std::is_invocable_r_v<
              OwnedCredSspHandshakeResult,
              OwnedCredSspAdvance,
              GssapiSpnegoAcceptor &,
              OwnedPreauthTcpConnection &,
              TsRequestFrameReader &,
              TsRequestTlsReplyWriter &>);
static_assert(!std::is_invocable_v<
              OwnedCredSspAdvance,
              GssapiSpnegoAcceptor &,
              SSL *,
              TsRequestFrameReader &,
              TsRequestTlsReplyWriter &>);

void testGssapiOwnedCredSspProvenanceFence()
{
    // Diagnostic TLS-only selection rejects before consuming peer plaintext.
    const auto rejectBeforeRead =
        [](std::span<const std::uint8_t> connectionRequest)
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{std::move(accepted.connection)};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, connectionRequest,
            SecurityNegotiationPolicy::DiagnosticTlsOnly);

        const auto provenance = owner.securityNegotiationProvenance();
        assert(provenance.has_value());
        assert(provenance->serverSelectedProtocol == kRdpProtocolSsl);

        writeNativeTlsClientAll(tls.client.get(), kTestCredSspDer);
        GssapiSpnegoAcceptor acceptor;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        const auto denied = acceptor.advanceOwnedCredSspHandshake(
            owner, reader, writer);
        assert(denied.status == OwnedCredSspHandshakeStatus::Rejected);
        assert(denied.plaintextBytesRead == 0);
        assert(denied.plaintextBytesWritten == 0);
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(owner.active());

        std::array<std::uint8_t, kTestCredSspDer.size()> preserved{};
        readOwnedRuntimeTlsAll(owner, preserved);
        assert(preserved == kTestCredSspDer);
        owner.cancel();
    };

    const auto sslOnly = validRequestWire();
    rejectBeforeRead(sslOnly);
    const auto hybridOfferedButDowngraded = tlsAndHybridRequestWire();
    rejectBeforeRead(hybridOfferedButDowngraded);

    // Genuine R1 HYBRID selection passes the provenance fence and drives the
    // frame through owner-backed TLS I/O. With no configured service keytab,
    // the existing GSS semantic gate then rejects silently after exact intake.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        const auto request = tlsAndHybridRequestWire();
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, request,
            SecurityNegotiationPolicy::HybridNla);

        const auto provenance = owner.securityNegotiationProvenance();
        assert(provenance.has_value());
        assert(provenance->serverSelectedProtocol == kRdpProtocolHybrid);

        writeNativeTlsClientAll(tls.client.get(), kTestCredSspDer);
        GssapiSpnegoAcceptor acceptor;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        std::size_t bytesRead = 0;
        OwnedCredSspHandshakeStatus finalStatus{
            OwnedCredSspHandshakeStatus::NeedRead};
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{5};
        while (std::chrono::steady_clock::now() < deadline)
        {
            const auto step = acceptor.advanceOwnedCredSspHandshake(
                owner, reader, writer);
            bytesRead += step.plaintextBytesRead;
            assert(step.plaintextBytesWritten == 0);
            finalStatus = step.status;
            if (finalStatus == OwnedCredSspHandshakeStatus::Rejected)
                break;
            assert(finalStatus == OwnedCredSspHandshakeStatus::Progress ||
                   finalStatus == OwnedCredSspHandshakeStatus::NeedRead ||
                   finalStatus == OwnedCredSspHandshakeStatus::NeedWrite);
            if (finalStatus == OwnedCredSspHandshakeStatus::NeedRead ||
                finalStatus == OwnedCredSspHandshakeStatus::NeedWrite)
            {
                const auto polled = owner.pollSocketOnce(
                    deadline, kMaximumTcpPollWait);
                assert(polled.outcome ==
                           TcpConnectionPollOutcome::Dispatched ||
                       polled.outcome == TcpConnectionPollOutcome::NoEvent);
            }
        }
        assert(finalStatus == OwnedCredSspHandshakeStatus::Rejected);
        assert(bytesRead == kTestCredSspDer.size());
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());
        assert(owner.active());
        owner.cancel();
    }

    // Valid HYBRID provenance still cannot authorize caller-prequeued output.
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        const auto request = tlsAndHybridRequestWire();
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, request,
            SecurityNegotiationPolicy::HybridNla);

        constexpr std::array<std::uint8_t, 2> syntheticReply{0x41, 0x42};
        GssapiSpnegoAcceptor acceptor;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        assert(writer.queueReply(
            owner, 6, CredSspServerReplyField::NegoToken, syntheticReply));
        const auto denied = acceptor.advanceOwnedCredSspHandshake(
            owner, reader, writer);
        assert(denied.status == OwnedCredSspHandshakeStatus::Rejected);
        assert(denied.plaintextBytesRead == 0);
        assert(denied.plaintextBytesWritten == 0);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());
        assert(owner.active());
        owner.cancel();
    }
}

void testGssapiOwnedCredSspAuthInfoTerminalDenials()
{
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, tlsAndHybridRequestWire(),
            SecurityNegotiationPolicy::HybridNla);

        auto authInfo = kTestCredSspAuthInfoDer;
        authInfo[6] = version;
        const auto parsedAuthInfo = parseCredSspTsRequest(authInfo);
        assert(parsedAuthInfo && parsedAuthInfo.value.finalAuthInfoOnly());
        writeNativeTlsClientAll(tls.client.get(), authInfo);

        GssapiSpnegoAcceptor acceptor;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        std::size_t bytesRead = 0;
        OwnedCredSspHandshakeStatus finalStatus{
            OwnedCredSspHandshakeStatus::NeedRead};
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{5};

        for (std::size_t stepIndex = 0;
             stepIndex < kMaximumCredSspRequestBytes + 16;
             ++stepIndex)
        {
            const auto step = acceptor.advanceOwnedCredSspHandshake(
                owner, reader, writer);
            bytesRead += step.plaintextBytesRead;
            assert(step.plaintextBytesWritten == 0);
            finalStatus = step.status;
            if (finalStatus == OwnedCredSspHandshakeStatus::Rejected)
                break;
            assert(finalStatus == OwnedCredSspHandshakeStatus::Progress ||
                   finalStatus == OwnedCredSspHandshakeStatus::NeedRead ||
                   finalStatus == OwnedCredSspHandshakeStatus::NeedWrite);
            if (finalStatus == OwnedCredSspHandshakeStatus::NeedRead ||
                finalStatus == OwnedCredSspHandshakeStatus::NeedWrite)
            {
                const auto polled = owner.pollSocketOnce(
                    deadline, kMaximumTcpPollWait);
                assert(polled.outcome ==
                           TcpConnectionPollOutcome::Dispatched ||
                       polled.outcome ==
                           TcpConnectionPollOutcome::NoEvent);
            }
        }

        assert(finalStatus == OwnedCredSspHandshakeStatus::Rejected);
        assert(bytesRead == authInfo.size());
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());
        owner.cancel();
    }
}

void testGssapiOwnedCredSspBindingDeliveryFence()
{
    using Method = decltype(
        &GssapiSpnegoAcceptor::verifiedPrincipalForOwnedConnection);
    static_assert(std::is_invocable_r_v<
        std::string_view, Method, const GssapiSpnegoAcceptor &,
        const OwnedPreauthTcpConnection &>);
    static_assert(!std::is_invocable_v<
        Method, const GssapiSpnegoAcceptor &, const SSL *>);

    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{
        std::move(accepted.connection), SecurityNegotiationPolicy::HybridNla};
    NativeTcpIo clientIo{
        static_cast<std::uintptr_t>(pair.client.value)};
    TlsHandshakeFixture tls{false, false};
    establishOwnedApplicationTlsForRequest(
        owner, clientIo, tls, tlsAndHybridRequestWire(),
        SecurityNegotiationPolicy::HybridNla);

    GssapiSpnegoAcceptor acceptor;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    assert(acceptor.verifiedPrincipalForOwnedConnection(owner).empty());
    writeNativeTlsClientAll(tls.client.get(), kTestCredSspDer);

    OwnedCredSspHandshakeStatus finalStatus{
        OwnedCredSspHandshakeStatus::NeedRead};
    std::size_t totalRead = 0;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline)
    {
        const auto step = acceptor.advanceOwnedCredSspHandshake(
            owner, reader, writer);
        totalRead += step.plaintextBytesRead;
        assert(step.status != OwnedCredSspHandshakeStatus::BindingVerified);
        assert(acceptor.verifiedPrincipalForOwnedConnection(owner).empty());
        finalStatus = step.status;
        if (finalStatus == OwnedCredSspHandshakeStatus::Rejected)
            break;
        assert(finalStatus == OwnedCredSspHandshakeStatus::Progress ||
               finalStatus == OwnedCredSspHandshakeStatus::NeedRead ||
               finalStatus == OwnedCredSspHandshakeStatus::NeedWrite);
        if (finalStatus == OwnedCredSspHandshakeStatus::NeedRead ||
            finalStatus == OwnedCredSspHandshakeStatus::NeedWrite)
        {
            const auto polled = owner.pollSocketOnce(
                deadline, kMaximumTcpPollWait);
            assert(polled.outcome ==
                       TcpConnectionPollOutcome::Dispatched ||
                   polled.outcome == TcpConnectionPollOutcome::NoEvent);
        }
    }
    assert(finalStatus == OwnedCredSspHandshakeStatus::Rejected);
    assert(totalRead == kTestCredSspDer.size());
    assert(acceptor.verifiedPrincipalForOwnedConnection(owner).empty());

    owner.cancel();
    assert(acceptor.verifiedPrincipalForOwnedConnection(owner).empty());
}

void testGssapiOwnedCredSspCancellationFence()
{
    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{
        std::move(accepted.connection),
        SecurityNegotiationPolicy::HybridNla};
    NativeTcpIo clientIo{
        static_cast<std::uintptr_t>(pair.client.value)};
    TlsHandshakeFixture tls{false, false};
    const auto request = tlsAndHybridRequestWire();
    establishOwnedApplicationTlsForRequest(
        owner, clientIo, tls, request,
        SecurityNegotiationPolicy::HybridNla);

    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    constexpr std::array<std::uint8_t, 2> syntheticReply{0x51, 0x52};
    assert(writer.queueReply(
        owner, 6, CredSspServerReplyField::NegoToken, syntheticReply));

    GssapiSpnegoAcceptor acceptor;
    owner.cancel();
    assert(!owner.active());
    assert(owner.establishedTls() == nullptr);
    assert(!owner.securityNegotiationProvenance());

    const auto first = acceptor.advanceOwnedCredSspHandshake(
        owner, reader, writer);
    assert(first.status == OwnedCredSspHandshakeStatus::TransportClosed);
    assert(first.plaintextBytesRead == 0);
    assert(first.plaintextBytesWritten == 0);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);

    const auto replay = acceptor.advanceOwnedCredSspHandshake(
        owner, reader, writer);
    assert(replay.status == OwnedCredSspHandshakeStatus::TransportClosed);
    assert(replay.plaintextBytesRead == 0);
    assert(replay.plaintextBytesWritten == 0);
}

void testGssapiOwnedCompletedFrameCancellationFence()
{
    LoopbackSocketPair pair{false};
    auto accepted = waitForAcceptedLoopbackConnection(
        static_cast<std::uintptr_t>(pair.listener.value));
    assert(accepted.outcome == TcpAcceptOutcome::Accepted);
    OwnedPreauthTcpConnection owner{
        std::move(accepted.connection),
        SecurityNegotiationPolicy::HybridNla};
    NativeTcpIo clientIo{
        static_cast<std::uintptr_t>(pair.client.value)};
    TlsHandshakeFixture tls{false, false};
    establishOwnedApplicationTlsForRequest(
        owner, clientIo, tls, tlsAndHybridRequestWire(),
        SecurityNegotiationPolicy::HybridNla);

    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    writeNativeTlsClientAll(tls.client.get(), kTestCredSspDer);
    assert(drainCredSspFromOwnedTls(
               reader, owner, TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size());
    assert(reader.status() == TsRequestFrameStatus::Complete);
    const SSL *const retiredServerTls = reader.completedFrameServerTls();
    assert(retiredServerTls != nullptr);
    assert(retiredServerTls == owner.establishedTls());
    assert(owner.securityNegotiationProvenance().has_value());

    // R1 cancellation destroys the live SSL owner after the reader has
    // completed a frame. The reader may retain only an internal borrowed
    // address; its public provenance accessor must reject that retired
    // identity before dereferencing it.
    GssapiSpnegoAcceptor acceptor;
    owner.cancel();
    assert(!owner.active());
    assert(owner.establishedTls() == nullptr);
    assert(!owner.securityNegotiationProvenance().has_value());
    assert(reader.status() == TsRequestFrameStatus::Complete);
    assert(reader.completedFrameServerTls() == nullptr);

    // R2 checks the exact R1 owner before parsing the retained frame. The
    // terminal result closes and wipes every child object, and replay cannot
    // revive the completed DER or its former TLS identity.
    const auto denied = acceptor.advanceOwnedCredSspHandshake(
        owner, reader, writer);
    assert(denied.status == OwnedCredSspHandshakeStatus::TransportClosed);
    assert(denied.plaintextBytesRead == 0);
    assert(denied.plaintextBytesWritten == 0);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(reader.completeDer().empty());
    assert(reader.bytesNeeded() == 0);
    assert(reader.completedFrameServerTls() == nullptr);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    assert(!reader.releaseFrame());

    const auto replay = acceptor.advanceOwnedCredSspHandshake(
        owner, reader, writer);
    assert(replay.status == OwnedCredSspHandshakeStatus::TransportClosed);
    assert(replay.plaintextBytesRead == 0);
    assert(replay.plaintextBytesWritten == 0);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
}

void testGssapiFailureReplyWithoutCredentialsDenied()
{
    // A real completed in-memory TLS exchange is NOT enough to
    // authenticate GSS. An unconfigured acceptor must not convert a
    // plausible v6 SPNEGO token into an errorCode or an identity.
    constexpr std::array<std::uint8_t, 11> fakeInitialSpnego{
        0x60, 0x09, 0x06, 0x06, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x02, 0xa0};
    assert(isInitialSpnegoToken(fakeInitialSpnego));
    for (const std::uint8_t version :
         {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        const auto framed = encodeCredSspServerTsRequest(
            version, CredSspServerReplyField::NegoToken,
            fakeInitialSpnego);
        assert(!framed.empty());
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        writeTlsClientApplicationData(tls.client.get(), framed);
        receiveOneCredSspTlsFrame(
            reader, tls.server.get(), framed.size());
        GssapiSpnegoAcceptor provider;
        assert(provider.acceptFramedNegoAndQueueReply(reader, writer) ==
               SpnegoStatus::Rejected);
        assert(provider.stage() == SpnegoStage::Failed);
        assert(provider.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());
        // Fail-only status must NOT become a reconfiguration/retry path.
        assert(provider.acceptFramedNegoAndQueueReply(reader, writer) ==
               SpnegoStatus::Rejected);
    }

    // Manual DER is never TLS-derived, even when handed a valid-looking
    // v6 token. A release/closed frame similarly cannot inject a failure.
    constexpr std::array<std::uint8_t, 11> fake{
        0x60, 0x09, 0x06, 0x06, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x02, 0xa0};
    auto version6 = encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::NegoToken, fake);
    TsRequestFrameReader manual;
    assert(manual.consume(version6).status == TsRequestFrameStatus::Complete);
    TsRequestTlsReplyWriter writer;
    GssapiSpnegoAcceptor provider;
    assert(provider.acceptFramedNegoAndQueueReply(manual, writer) ==
           SpnegoStatus::Rejected);
    assert(provider.stage() == SpnegoStage::Failed);
    assert(manual.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
}

void testGssapiNegotiationReplyHandoffDenied()
{
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        auto request = kTestCredSspDer;
        request[6] = version;
        writeTlsClientApplicationData(tls.client.get(), request);
        receiveOneCredSspTlsFrame(reader, tls.server.get(), request.size());
        GssapiSpnegoAcceptor acceptor;
        // Only a real accepted GSS_C_CONTINUE_NEEDED output may be queued.
        // These bytes came through real TLS but are NOT a valid Kerberos
        // exchange and no keytab was explicitly configured.
        assert(acceptor.acceptFramedNegoAndQueueReply(reader, writer) ==
               SpnegoStatus::Rejected);
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(acceptor.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());

        TsRequestFrameReader replay;
        TsRequestTlsReplyWriter replayWriter;
        writeTlsClientApplicationData(tls.client.get(), request);
        receiveOneCredSspTlsFrame(replay, tls.server.get(), request.size());
        assert(acceptor.acceptFramedNegoAndQueueReply(
                   replay, replayWriter) == SpnegoStatus::Rejected);
        assert(replay.status() == TsRequestFrameStatus::Closed);
        assert(replayWriter.status() == TsRequestTlsWriteStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());
    }

    // Caller-supplied DER lacks a completed TLS source, even if it parses.
    TsRequestFrameReader synthetic;
    assert(synthetic.consume(kTestCredSspDer).status ==
           TsRequestFrameStatus::Complete);
    GssapiSpnegoAcceptor acceptor;
    TsRequestTlsReplyWriter writer;
    assert(acceptor.acceptFramedNegoAndQueueReply(synthetic, writer) ==
           SpnegoStatus::Rejected);
    assert(synthetic.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    assert(acceptor.stage() == SpnegoStage::Failed);
}

void testGssapiBindingReplyHandoffDenied()
{
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        const auto finalRequest = makeFinalCredSspDer(version);
        writeTlsClientApplicationData(tls.client.get(), finalRequest);
        receiveOneCredSspTlsFrame(
            reader, tls.server.get(), finalRequest.size());
        const auto parsed = parseCredSspTsRequest(reader.completeDer());
        assert(parsed && parsed.value.finalNegoAndBindingOnly());

        GssapiSpnegoAcceptor acceptor;
        // Ciphertext bytes or the existence of a clientNonce cannot
        // manufacture a GSS security context or TLS public-key proof.
        assert(!acceptor.processFinalFramedNegoAndQueueBindingReply(
            reader, writer));
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(acceptor.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
        assertNoGssReplyDelivered(tls.client.get());
    }

    // An incomplete or plaintext-injected final message must not be
    // "upgraded" to a protected GSS reply on any future SSL handle.
    GssapiSpnegoAcceptor manualProvider;
    TsRequestFrameReader manual;
    TsRequestTlsReplyWriter manualWriter;
    const auto finalRequest = makeFinalCredSspDer(6);
    assert(manual.consume(finalRequest).status ==
           TsRequestFrameStatus::Complete);
    assert(!manualProvider.processFinalFramedNegoAndQueueBindingReply(
        manual, manualWriter));
    assert(manual.status() == TsRequestFrameStatus::Closed);
    assert(manualWriter.status() == TsRequestTlsWriteStatus::Closed);

    GssapiSpnegoAcceptor partialProvider;
    TsRequestFrameReader partial;
    TsRequestTlsReplyWriter partialWriter;
    assert(partial.consume(std::span(finalRequest).first(6)).status ==
           TsRequestFrameStatus::NeedMore);
    assert(!partialProvider.processFinalFramedNegoAndQueueBindingReply(
        partial, partialWriter));
    assert(partial.status() == TsRequestFrameStatus::Closed);
    assert(partialWriter.status() == TsRequestTlsWriteStatus::Closed);
}

void testGssapiReplyOrderAndPendingDenials()
{
    // The provider must refuse to accept another client token while
    // a previous server reply remains queued and unwritten. Even a
    // caller-generated offline DER reply must never sneak onto the wire.
    for (const bool finalBinding : {false, true})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        constexpr std::array<std::uint8_t, 2> opaque{0x41, 0x42};
        assert(writer.queueReply(tls.server.get(), 6,
                                  CredSspServerReplyField::NegoToken,
                                  opaque));
        assert(writer.status() == TsRequestTlsWriteStatus::NeedWrite);
        const auto finalRequest = makeFinalCredSspDer(6);
        if (finalBinding)
        {
            writeTlsClientApplicationData(tls.client.get(), finalRequest);
            receiveOneCredSspTlsFrame(
                reader, tls.server.get(), finalRequest.size());
        }
        else
        {
            writeTlsClientApplicationData(tls.client.get(), kTestCredSspDer);
            receiveOneCredSspTlsFrame(
                reader, tls.server.get(), kTestCredSspDer.size());
        }
        GssapiSpnegoAcceptor provider;
        if (finalBinding)
            assert(!provider.processFinalFramedNegoAndQueueBindingReply(
                reader, writer));
        else
            assert(provider.acceptFramedNegoAndQueueReply(
                       reader, writer) == SpnegoStatus::Rejected);
        assert(provider.stage() == SpnegoStage::Failed);
        assert(provider.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
        assertNoGssReplyDelivered(tls.client.get());
    }
}

void testGssapiCombinedFinalBindingDenied()
{
    // A valid final MS-CSSP envelope received over real TLS must remain
    // rejected without a positive, previously continuing Kerberos context.
    // No ciphertext may be interpreted as plaintext TLS hash or authority.
    for (std::uint8_t version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        const auto finalDer = makeFinalCredSspDer(version);
        writeTlsClientApplicationData(tls.client.get(), finalDer);
        std::size_t read = 0;
        for (std::size_t step = 0; step < 8; ++step)
        {
            const auto response = reader.readOneTlsStep(tls.server.get());
            read += response.plaintextBytesRead;
            assert(response.status == TsRequestTlsReadStatus::Progress ||
                   response.status == TsRequestTlsReadStatus::Complete);
            if (response.status == TsRequestTlsReadStatus::Complete)
                break;
        }
        assert(read == finalDer.size());
        assert(reader.completedFrameServerTls() == tls.server.get());
        const auto parsed = parseCredSspTsRequest(reader.completeDer());
        assert(parsed && parsed.value.finalNegoAndBindingOnly());
        GssapiSpnegoAcceptor acceptor;
        const auto denied = acceptor.processFinalFramedNegoAndBinding(reader);
        assert(!denied.ready);
        assert(denied.encryptedServerBinding.empty());
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(acceptor.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
        assert(reader.completedFrameServerTls() == nullptr);
        // No retry, even if the attacker reconnects with a correct TLS
        // handle and a syntactically valid final GSS/binding envelope.
        TsRequestFrameReader again;
        writeTlsClientApplicationData(tls.client.get(), finalDer);
        for (std::size_t step = 0; step < 8; ++step)
        {
            const auto r = again.readOneTlsStep(tls.server.get());
            assert(r.status == TsRequestTlsReadStatus::Progress ||
                   r.status == TsRequestTlsReadStatus::Complete);
            if (r.status == TsRequestTlsReadStatus::Complete) break;
        }
        assert(again.status() == TsRequestFrameStatus::Complete);
        assert(!acceptor.processFinalFramedNegoAndBinding(again).ready);
        assert(again.status() == TsRequestFrameStatus::Closed);
    }

    GssapiSpnegoAcceptor synthetic;
    TsRequestFrameReader manual;
    const auto der = makeFinalCredSspDer(6);
    assert(manual.consume(der).status == TsRequestFrameStatus::Complete);
    assert(manual.completedFrameServerTls() == nullptr);
    assert(!synthetic.processFinalFramedNegoAndBinding(manual).ready);
    assert(synthetic.stage() == SpnegoStage::Failed);
    assert(manual.status() == TsRequestFrameStatus::Closed);

    GssapiSpnegoAcceptor premature;
    TsRequestFrameReader partial;
    assert(partial.consume(std::span(der).first(13)).status ==
           TsRequestFrameStatus::NeedMore);
    assert(!premature.processFinalFramedNegoAndBinding(partial).ready);
    assert(partial.status() == TsRequestFrameStatus::Closed);
    assert(premature.stage() == SpnegoStage::Failed);
}

// Test-only DER framing of the externally authenticated GSS wrap result.
// The production TSRequest parser checks the resulting exact field shape.
std::vector<std::uint8_t> wrapKerberosTestDer(
    std::uint8_t tag, std::span<const std::uint8_t> body)
{
    assert(body.size() <= kMaximumCredSspRequestBytes);
    std::vector<std::uint8_t> output;
    output.reserve(body.size() + 4);
    output.push_back(tag);
    if (body.size() < 128)
        output.push_back(static_cast<std::uint8_t>(body.size()));
    else if (body.size() <= 255)
    {
        output.push_back(0x81);
        output.push_back(static_cast<std::uint8_t>(body.size()));
    }
    else
    {
        output.push_back(0x82);
        output.push_back(static_cast<std::uint8_t>(body.size() >> 8));
        output.push_back(static_cast<std::uint8_t>(body.size()));
    }
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

std::vector<std::uint8_t> realKerberosBindingOnlyDer(
    std::uint8_t version,
    std::span<const std::uint8_t> encrypted,
    std::span<const std::uint8_t> nonce)
{
    assert((version == 5 || version == 6) && nonce.size() == 32);
    const std::array<std::uint8_t, 3> versionDer{0x02, 0x01, version};
    std::vector<std::uint8_t> body =
        wrapKerberosTestDer(0xa0, versionDer);
    const auto pubKey = wrapKerberosTestDer(
        0xa3, wrapKerberosTestDer(0x04, encrypted));
    body.insert(body.end(), pubKey.begin(), pubKey.end());
    const auto nonceField = wrapKerberosTestDer(
        0xa5, wrapKerberosTestDer(0x04, nonce));
    body.insert(body.end(), nonceField.begin(), nonceField.end());
    const auto frame = wrapKerberosTestDer(0x30, body);
    const auto parsed = parseCredSspTsRequest(frame);
    assert(parsed && parsed.value.version == version);
    assert(parsed.value.hasPubKeyAuth && parsed.value.hasClientNonce &&
           parsed.value.tokenCount == 0 && !parsed.value.hasAuthInfo);
    return frame;
}

std::vector<std::uint8_t> realKerberosFinalNegoAndBindingDer(
    std::uint8_t version,
    std::span<const std::uint8_t> finalNegoToken,
    std::span<const std::uint8_t> encrypted,
    std::span<const std::uint8_t> nonce)
{
    assert((version == 5 || version == 6) &&
           !finalNegoToken.empty() &&
           finalNegoToken.size() <= kMaximumSpnegoInputBytes &&
           nonce.size() == 32);

    const std::array<std::uint8_t, 3> versionDer{0x02, 0x01, version};
    std::vector<std::uint8_t> body =
        wrapKerberosTestDer(0xa0, versionDer);

    const auto tokenOctets = wrapKerberosTestDer(0x04, finalNegoToken);
    const auto tokenChoice = wrapKerberosTestDer(0xa0, tokenOctets);
    const auto negoItem = wrapKerberosTestDer(0x30, tokenChoice);
    const auto negoSequence = wrapKerberosTestDer(0x30, negoItem);
    const auto negoTokens = wrapKerberosTestDer(0xa1, negoSequence);
    body.insert(body.end(), negoTokens.begin(), negoTokens.end());

    const auto pubKey = wrapKerberosTestDer(
        0xa3, wrapKerberosTestDer(0x04, encrypted));
    body.insert(body.end(), pubKey.begin(), pubKey.end());
    const auto nonceField = wrapKerberosTestDer(
        0xa5, wrapKerberosTestDer(0x04, nonce));
    body.insert(body.end(), nonceField.begin(), nonceField.end());

    const auto frame = wrapKerberosTestDer(0x30, body);
    const auto parsed = parseCredSspTsRequest(frame);
    assert(parsed && parsed.value.version == version);
    assert(parsed.value.finalNegoAndBindingOnly());
    assert(parsed.value.tokenCount == 1 &&
           parsed.value.tokens[0].size() == finalNegoToken.size() &&
           std::equal(parsed.value.tokens[0].begin(),
                      parsed.value.tokens[0].end(),
                      finalNegoToken.begin()));
    return frame;
}

std::vector<std::uint8_t> realKerberosAuthInfoDer(
    std::uint8_t version,
    std::span<const std::uint8_t> encryptedAuthInfo)
{
    assert((version == 5 || version == 6) && !encryptedAuthInfo.empty() &&
           encryptedAuthInfo.size() <= kMaximumDecryptedCredentialsBytes);
    const std::array<std::uint8_t, 3> versionDer{0x02, 0x01, version};
    std::vector<std::uint8_t> body =
        wrapKerberosTestDer(0xa0, versionDer);
    const auto authInfo = wrapKerberosTestDer(
        0xa2, wrapKerberosTestDer(0x04, encryptedAuthInfo));
    body.insert(body.end(), authInfo.begin(), authInfo.end());
    const auto frame = wrapKerberosTestDer(0x30, body);
    const auto parsed = parseCredSspTsRequest(frame);
    assert(parsed && parsed.value.version == version);
    assert(parsed.value.finalAuthInfoOnly());
    return frame;
}

void establishRuntimeAggregateHybridTls(
    LinuxRuntimeConnection &connection,
    NativeTcpIo &clientIo,
    RuntimeTlsClientFixture &clientTls,
    const RuntimeServerTlsContext &tlsContext)
{
    const auto request = tlsAndHybridRequestWire();
    const auto parsed = parseConnectionRequest(request);
    assert(parsed);
    const auto expected = negotiateSecurity(
        parsed, SecurityNegotiationPolicy::HybridNla);
    assert(expected.decision == SecurityDecision::Tls);
    assert(expected.selectedProtocol == kRdpProtocolHybrid);

    const auto deadline = runtimeTlsFixtureDeadline();
    nativeSendAllBefore(clientIo, request, deadline);

    TcpPreauthEvent preauth = TcpPreauthEvent::NeedRead;
    while (preauth == TcpPreauthEvent::NeedRead &&
           RuntimeClock::now() < deadline)
    {
        preauth = connection.onReadable();
        if (preauth == TcpPreauthEvent::NeedRead)
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    assert(preauth == TcpPreauthEvent::NeedWrite);

    while (preauth == TcpPreauthEvent::NeedWrite &&
           RuntimeClock::now() < deadline)
    {
        preauth = connection.onWritable();
        if (preauth == TcpPreauthEvent::NeedWrite)
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    assert(preauth == TcpPreauthEvent::ReadyForTls);

    std::array<std::uint8_t, 19> confirm{};
    nativeReadAllBefore(clientIo, confirm, deadline);
    assert(confirm == expected.packet);
    assert(confirm[15] == kRdpProtocolHybrid);

    assert(connection.attachServerTls(tlsContext));
    assert(attachNonblockingTcpBio(clientTls.connection.get(), clientIo));

    bool clientEstablished = false;
    bool serverEstablished = false;
    while ((!clientEstablished || !serverEstablished) &&
           RuntimeClock::now() < deadline)
    {
        if (!clientEstablished)
        {
            const int result = SSL_do_handshake(clientTls.connection.get());
            if (result == 1)
            {
                clientEstablished = true;
            }
            else
            {
                const int error =
                    SSL_get_error(clientTls.connection.get(), result);
                assert(error == SSL_ERROR_WANT_READ ||
                       error == SSL_ERROR_WANT_WRITE);
            }
        }

        if (!serverEstablished)
        {
            const auto status = connection.onTlsIoReady();
            assert(status != TlsHandshakeStatus::Invalid);
            assert(status != TlsHandshakeStatus::Closed);
            serverEstablished = status == TlsHandshakeStatus::Established;
        }

        if (!clientEstablished || !serverEstablished)
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    assert(clientEstablished && serverEstablished);

    const CertificatePointer observed{
        SSL_get1_peer_certificate(clientTls.connection.get()), X509_free};
    assert(observed);
    assert(tlsContext.certificate() != nullptr);
    assert(X509_cmp(observed.get(), tlsContext.certificate()) == 0);
}

[[nodiscard]] std::size_t driveRuntimeAggregateCredSspReply(
    LinuxRuntimeConnection &connection,
    std::size_t expectedRequestBytes,
    bool expectBindingVerified)
{
    std::size_t totalRead = 0;
    std::size_t totalWritten = 0;
    const auto deadline = runtimeTlsFixtureDeadline();

    for (std::size_t stepIndex = 0;
         stepIndex < kMaximumCredSspRequestBytes + 64 &&
         RuntimeClock::now() < deadline;
         ++stepIndex)
    {
        const auto step = connection.onCredSspIoReady();

        // One aggregate callback delegates at most one R1 TLS application
        // read OR write. GSS/DER bookkeeping may occur in the same call.
        assert(step.plaintextBytesRead == 0 ||
               step.plaintextBytesWritten == 0);
        totalRead += step.plaintextBytesRead;
        totalWritten += step.plaintextBytesWritten;
        assert(totalRead <= expectedRequestBytes);
        assert(totalWritten <= kMaximumCredSspRequestBytes);

        assert(step.status != LinuxCredSspStepStatus::Invalid);
        assert(step.status != LinuxCredSspStepStatus::Closed);
        assert(step.status !=
               LinuxCredSspStepStatus::UnsupportedFinalCredentials);

        if (expectBindingVerified &&
            step.status == LinuxCredSspStepStatus::BindingVerified)
        {
            assert(totalRead == expectedRequestBytes);
            assert(totalWritten > 0);
            return totalWritten;
        }

        // A completed continuation reply returns Progress after R2 releases
        // its writer. Read interest proves no queued response remains.
        if (!expectBindingVerified &&
            step.status == LinuxCredSspStepStatus::Progress &&
            totalRead == expectedRequestBytes &&
            totalWritten > 0 &&
            connection.ioInterest() == TcpConnectionIoInterest::Read)
        {
            return totalWritten;
        }

        assert(step.status == LinuxCredSspStepStatus::Progress ||
               step.status == LinuxCredSspStepStatus::NeedRead ||
               step.status == LinuxCredSspStepStatus::NeedWrite);
        if (step.status != LinuxCredSspStepStatus::Progress)
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }

    assert(false && "R10 aggregate CredSSP reply did not complete");
    return 0;
}

// Opt-in real-provider proof for the complete non-listening R10 aggregate.
// The externally supplied ticket/keytab are used only by MIT GSS. The test
// stops at R2 BindingVerified and never creates native admission or R3 state.
void runRuntimeRealKerberosAggregateScenario(
    const char *certificatePath,
    const char *privateKeyPath,
    bool finalAuthInfoDenial)
{
    const char *serviceName = std::getenv("RDP_TEST_KRB5_SERVICE");
    const char *serviceKeytab = std::getenv("RDP_TEST_KRB5_KEYTAB");
    const char *clientCache = std::getenv("RDP_TEST_KRB5_CCACHE");
    assert(serviceName && serviceKeytab && clientCache);

    const std::string_view service{serviceName};
    const std::string_view keytab{serviceKeytab};
    const std::string_view cache{clientCache};
    assert(service.starts_with("TERMSRV/") &&
           service.find('@') != service.npos);
    assert(keytab.starts_with("FILE:/") && cache.starts_with("FILE:/"));

    LinuxRuntimeSecurityConfiguration securityConfiguration;
    const ConsoleIdentityRuleInput unusedNativeRule{
        "runtime.probe@EXAMPLE.TEST", "rdptest", "seat0", ":0",
        1001U, kConsoleViewPermission};
    assert(securityConfiguration.configure(
        service, keytab, unusedNativeRule));

    RuntimeServerTlsContext tlsContext =
        RuntimeServerTlsContext::fromCredentialFiles(
            certificatePath, privateKeyPath);
    assert(tlsContext);
    assert(tlsContext.certificate() != nullptr);

    const ASN1_BIT_STRING *publicKeyBits =
        X509_get0_pubkey_bitstr(tlsContext.certificate());
    assert(publicKeyBits);
    const int publicKeyLength = ASN1_STRING_length(publicKeyBits);
    assert(publicKeyLength > 0);
    const auto *publicKeyBytes = ASN1_STRING_get0_data(publicKeyBits);
    assert(publicKeyBytes);
    const auto publicKey = std::span{
        static_cast<const std::uint8_t *>(publicKeyBytes),
        static_cast<std::size_t>(publicKeyLength)};

    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        LoopbackSocketPair pair{false};
        OwnedNativeTcpSocket accepted =
            acceptRuntimeLoopbackWithDeadline(pair);
        LinuxRuntimeConnection connection{
            securityConfiguration, std::move(accepted)};
        assert(connection.ready());
        assert(connection.gssStage() == SpnegoStage::AwaitInitialToken);
        assert(!connection.hasAdmissionLease());

        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        RuntimeTlsClientFixture clientTls{};
        establishRuntimeAggregateHybridTls(
            connection, clientIo, clientTls, tlsContext);

        TestKerberosInitiator client{service, cache};
        std::vector<std::uint8_t> nextClientToken;
        OM_uint32 clientStatus = client.next({}, nextClientToken);
        assert(clientStatus == GSS_S_CONTINUE_NEEDED);
        assert(!nextClientToken.empty());
        assert(isInitialSpnegoToken(nextClientToken));

        bool haveFinalClientToken = false;
        for (std::size_t round = 0;
             round < kMaximumSpnegoRoundTrips;
             ++round)
        {
            const auto request = encodeCredSspServerTsRequest(
                version, CredSspServerReplyField::NegoToken,
                nextClientToken);
            assert(!request.empty());
            OPENSSL_cleanse(
                nextClientToken.data(), nextClientToken.size());
            nextClientToken.clear();

            writeRuntimeTlsClientAll(
                clientTls.connection.get(), request);
            const std::size_t replyBytes =
                driveRuntimeAggregateCredSspReply(
                    connection, request.size(), false);
            std::vector<std::uint8_t> reply(replyBytes);
            readRuntimeTlsClientAll(clientTls.connection.get(), reply);

            const auto parsedReply = parseCredSspTsRequest(reply);
            assert(parsedReply &&
                   parsedReply.value.version == version &&
                   parsedReply.value.initialNegoTokenOnly() &&
                   parsedReply.value.tokenCount == 1);

            clientStatus = client.next(
                parsedReply.value.tokens[0], nextClientToken);
            OPENSSL_cleanse(reply.data(), reply.size());

            assert(connection.gssStage() == SpnegoStage::ContinueNeeded);
            assert(!connection.hasAdmissionLease());
            assert(connection.mcsPhase() ==
                   McsSessionPhase::AwaitVerifiedR2Admission);

            if (clientStatus == GSS_S_COMPLETE)
            {
                haveFinalClientToken = true;
                break;
            }
            assert(clientStatus == GSS_S_CONTINUE_NEEDED);
            assert(!nextClientToken.empty());
        }
        assert(haveFinalClientToken);
        assert(clientStatus == GSS_S_COMPLETE);
        assert(!nextClientToken.empty());

        std::array<std::uint8_t, kCredSspNonceBytes> nonce{};
        for (std::size_t index = 0; index < nonce.size(); ++index)
            nonce[index] =
                static_cast<std::uint8_t>(0x60U + version + index);

        CredSspHash clientHash{};
        CredSspHash serverHash{};
        assert(computeCredSspBindingHash(
            CredSspBindingDirection::ClientToServer,
            nonce, publicKey, clientHash));
        assert(computeCredSspBindingHash(
            CredSspBindingDirection::ServerToClient,
            nonce, publicKey, serverHash));

        auto encryptedBinding = client.seal(clientHash);
        OPENSSL_cleanse(clientHash.data(), clientHash.size());
        const auto finalRequest = realKerberosFinalNegoAndBindingDer(
            version, nextClientToken, encryptedBinding, nonce);
        OPENSSL_cleanse(
            nextClientToken.data(), nextClientToken.size());
        nextClientToken.clear();
        OPENSSL_cleanse(
            encryptedBinding.data(), encryptedBinding.size());
        encryptedBinding.clear();

        writeRuntimeTlsClientAll(
            clientTls.connection.get(), finalRequest);
        const std::size_t bindingReplyBytes =
            driveRuntimeAggregateCredSspReply(
                connection, finalRequest.size(), true);

        assert(connection.gssStage() ==
               SpnegoStage::ServerBindingPrepared);
        assert(connection.admissionState() ==
               LinuxConsoleAdmissionState::Ready);
        assert(connection.mcsPhase() ==
               McsSessionPhase::AwaitVerifiedR2Admission);
        assert(!connection.hasAdmissionLease());

        std::vector<std::uint8_t> bindingReply(bindingReplyBytes);
        readRuntimeTlsClientAll(
            clientTls.connection.get(), bindingReply);
        const auto parsedBindingReply =
            parseCredSspTsRequest(bindingReply);
        assert(parsedBindingReply &&
               parsedBindingReply.value.version == version &&
               parsedBindingReply.value.hasPubKeyAuth &&
               parsedBindingReply.value.tokenCount == 0);
        client.verifyProtectedServerProof(
            parsedBindingReply.value.encryptedPubKeyAuth,
            serverHash);
        OPENSSL_cleanse(serverHash.data(), serverHash.size());
        OPENSSL_cleanse(
            bindingReply.data(), bindingReply.size());

        // Binding proof is deliberately not desktop authority.
        assert(!connection.hasAdmissionLease());
        assert(connection.mcsPhase() ==
               McsSessionPhase::AwaitVerifiedR2Admission);

        if (finalAuthInfoDenial)
        {
            std::array<std::uint8_t, 29> credentials{
                0x30, 0x1b,
                0xa0, 0x03, 0x02, 0x01, 0x01,
                0xa1, 0x14, 0x04, 0x12,
                0x30, 0x10,
                0xa0, 0x02, 0x04, 0x00,
                0xa1, 0x04, 0x04, 0x02, 0x75, 0x00,
                0xa2, 0x04, 0x04, 0x02, 0x70, 0x00};
            assert(inspectCredSspCredentials(credentials));

            auto encryptedAuthInfo = client.seal(credentials);
            OPENSSL_cleanse(credentials.data(), credentials.size());
            auto authInfoRequest = realKerberosAuthInfoDer(
                version, encryptedAuthInfo);
            OPENSSL_cleanse(
                encryptedAuthInfo.data(), encryptedAuthInfo.size());
            encryptedAuthInfo.clear();

            const std::size_t expectedAuthInfoBytes =
                authInfoRequest.size();
            writeRuntimeTlsClientAll(
                clientTls.connection.get(), authInfoRequest);
            OPENSSL_cleanse(
                authInfoRequest.data(), authInfoRequest.size());
            authInfoRequest.clear();

            std::size_t authInfoBytesRead = 0;
            LinuxCredSspStepStatus terminalStatus{
                LinuxCredSspStepStatus::NeedRead};
            const auto authInfoDeadline = runtimeTlsFixtureDeadline();
            for (std::size_t stepIndex = 0;
                 stepIndex < kMaximumCredSspRequestBytes + 16 &&
                 RuntimeClock::now() < authInfoDeadline;
                 ++stepIndex)
            {
                const auto step = connection.onCredSspIoReady();
                authInfoBytesRead += step.plaintextBytesRead;
                assert(step.plaintextBytesWritten == 0);
                assert(authInfoBytesRead <= expectedAuthInfoBytes);
                terminalStatus = step.status;

                if (terminalStatus ==
                    LinuxCredSspStepStatus::UnsupportedFinalCredentials)
                {
                    break;
                }
                assert(terminalStatus ==
                           LinuxCredSspStepStatus::Progress ||
                       terminalStatus ==
                           LinuxCredSspStepStatus::NeedRead ||
                       terminalStatus ==
                           LinuxCredSspStepStatus::NeedWrite);
                if (terminalStatus != LinuxCredSspStepStatus::Progress)
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds{1});
            }

            assert(terminalStatus ==
                   LinuxCredSspStepStatus::UnsupportedFinalCredentials);
            assert(authInfoBytesRead == expectedAuthInfoBytes);
            assert(!connection.ready());
            assert(connection.gssStage() == SpnegoStage::Failed);
            assert(connection.admissionState() ==
                   LinuxConsoleAdmissionState::Revoked);
            assert(connection.mcsPhase() == McsSessionPhase::Closed);
            assert(!connection.hasAdmissionLease());
            assert(connection.onCredSspIoReady().status ==
                   LinuxCredSspStepStatus::Closed);
            continue;
        }

        connection.revoke();
        assert(!connection.ready());
        assert(connection.gssStage() == SpnegoStage::Failed);
        assert(connection.admissionState() ==
               LinuxConsoleAdmissionState::Revoked);
        assert(connection.mcsPhase() == McsSessionPhase::Closed);
        assert(!connection.hasAdmissionLease());
        assert(connection.onCredSspIoReady().status ==
               LinuxCredSspStepStatus::Closed);
    }
}

void testRuntimeRealKerberosOwnedBinding(
    const char *certificatePath,
    const char *privateKeyPath)
{
    runRuntimeRealKerberosAggregateScenario(
        certificatePath, privateKeyPath, false);
}

void testRuntimeRealKerberosAuthInfoDenial(
    const char *certificatePath,
    const char *privateKeyPath)
{
    runRuntimeRealKerberosAggregateScenario(
        certificatePath, privateKeyPath, true);
}

enum class RealKerberosOwnedCredSspScenario : std::uint8_t
{
    BindingReceipt,
    PublicKeyNotNativeAdmission,
    FinalAuthInfoDenied,
};

// Opt-in positive proof for the production R1-owner/R2 CredSSP path.
// This requires caller-provisioned Kerberos credentials and never creates
// native OS admission, an R3 capability, delegated credentials or a desktop.
void runRealKerberosOwnedCredSspScenario(
    RealKerberosOwnedCredSspScenario scenario)
{
    const char *serviceName = std::getenv("RDP_TEST_KRB5_SERVICE");
    const char *serviceKeytab = std::getenv("RDP_TEST_KRB5_KEYTAB");
    const char *clientCache = std::getenv("RDP_TEST_KRB5_CCACHE");
    assert(serviceName && serviceKeytab && clientCache);
    const std::string_view service{serviceName};
    const std::string_view keytab{serviceKeytab};
    const std::string_view cache{clientCache};
    assert(service.starts_with("TERMSRV/") &&
           service.find('@') != service.npos);
    assert(keytab.starts_with("FILE:/") && cache.starts_with("FILE:/"));

    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        LoopbackSocketPair pair{false};
        auto accepted = waitForAcceptedLoopbackConnection(
            static_cast<std::uintptr_t>(pair.listener.value));
        assert(accepted.outcome == TcpAcceptOutcome::Accepted);
        OwnedPreauthTcpConnection owner{
            std::move(accepted.connection),
            SecurityNegotiationPolicy::HybridNla};
        NativeTcpIo clientIo{
            static_cast<std::uintptr_t>(pair.client.value)};
        TlsHandshakeFixture tls{false, false};
        establishOwnedApplicationTlsForRequest(
            owner, clientIo, tls, tlsAndHybridRequestWire(),
            SecurityNegotiationPolicy::HybridNla);

        const auto provenance = owner.securityNegotiationProvenance();
        assert(provenance.has_value());
        assert((provenance->clientRequestedProtocols &
                kRdpProtocolHybrid) != 0);
        assert(provenance->serverSelectedProtocol ==
               kRdpProtocolHybrid);
        assert(owner.establishedTls() != nullptr);

        GssapiSpnegoAcceptor server;
        assert(server.configure(service, keytab));
        TestKerberosInitiator client{service, cache};
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;

        const auto driveServerReply =
            [&](bool expectBindingVerified) -> std::size_t
        {
            using Status = OwnedCredSspHandshakeStatus;
            const auto deadline =
                std::chrono::steady_clock::now() +
                std::chrono::seconds{5};
            std::size_t replyBytes = 0;

            for (std::size_t stepIndex = 0;
                 stepIndex < kMaximumCredSspRequestBytes + 64;
                 ++stepIndex)
            {
                const auto step = server.advanceOwnedCredSspHandshake(
                    owner, reader, writer);

                if (step.status == Status::Rejected ||
                    step.status == Status::TransportClosed)
                {
                    assert(false &&
                           "real owner-driven CredSSP unexpectedly rejected");
                }

                if (writer.status() == TsRequestTlsWriteStatus::NeedWrite &&
                    replyBytes == 0)
                {
                    replyBytes = writer.bytesRemaining();
                    assert(replyBytes > 0);
                    // The queue operation itself performs no R1 TLS write.
                    continue;
                }

                if (expectBindingVerified &&
                    step.status == Status::BindingVerified)
                {
                    assert(replyBytes > 0);
                    assert(writer.status() == TsRequestTlsWriteStatus::Idle);
                    return replyBytes;
                }

                if (!expectBindingVerified &&
                    replyBytes > 0 &&
                    writer.status() == TsRequestTlsWriteStatus::Idle &&
                    step.status == Status::Progress)
                {
                    return replyBytes;
                }

                if (step.status == Status::NeedRead ||
                    step.status == Status::NeedWrite)
                {
                    const auto polled = owner.pollSocketOnce(
                        deadline, kMaximumTcpPollWait);
                    assert(polled.outcome ==
                               TcpConnectionPollOutcome::Dispatched ||
                           polled.outcome ==
                               TcpConnectionPollOutcome::NoEvent);
                    continue;
                }

                assert(step.status == Status::Progress);
            }
            assert(false && "owner-driven CredSSP reply did not complete");
            return 0;
        };

        std::vector<std::uint8_t> nextClientToken;
        OM_uint32 clientStatus = client.next({}, nextClientToken);
        assert(clientStatus == GSS_S_CONTINUE_NEEDED);
        assert(!nextClientToken.empty());
        assert(isInitialSpnegoToken(nextClientToken));

        bool haveFinalClientToken = false;
        for (std::size_t round = 0;
             round < kMaximumSpnegoRoundTrips;
             ++round)
        {
            const auto request = encodeCredSspServerTsRequest(
                version, CredSspServerReplyField::NegoToken,
                nextClientToken);
            assert(!request.empty());
            OPENSSL_cleanse(
                nextClientToken.data(), nextClientToken.size());
            nextClientToken.clear();

            writeNativeTlsClientAll(tls.client.get(), request);
            const std::size_t replyBytes = driveServerReply(false);
            std::vector<std::uint8_t> reply(replyBytes);
            readNativeTlsClientAll(tls.client.get(), reply);

            const auto parsed = parseCredSspTsRequest(reply);
            assert(parsed && parsed.value.version == version);
            assert(parsed.value.initialNegoTokenOnly());
            assert(parsed.value.tokenCount == 1);

            clientStatus = client.next(
                parsed.value.tokens[0], nextClientToken);
            OPENSSL_cleanse(reply.data(), reply.size());

            assert(server.stage() == SpnegoStage::ContinueNeeded);
            assert(server.verifiedPrincipal().empty());
            assert(server.verifiedPrincipalForOwnedConnection(owner).empty());
            assert(!nextClientToken.empty());

            if (clientStatus == GSS_S_COMPLETE)
            {
                haveFinalClientToken = true;
                break;
            }
            assert(clientStatus == GSS_S_CONTINUE_NEEDED);
        }
        assert(haveFinalClientToken);
        assert(clientStatus == GSS_S_COMPLETE);

        std::array<std::uint8_t, 32> nonce{};
        for (std::size_t index = 0; index < nonce.size(); ++index)
        {
            nonce[index] =
                static_cast<std::uint8_t>(0x40U + version + index);
        }

        CredSspHash clientHash{};
        CredSspHash serverHash{};
        assert(computeCredSspBindingForActiveServerTls(
            owner.establishedTls(),
            CredSspBindingDirection::ClientToServer,
            nonce, clientHash));
        assert(computeCredSspBindingForActiveServerTls(
            owner.establishedTls(),
            CredSspBindingDirection::ServerToClient,
            nonce, serverHash));
        auto encryptedBinding = client.seal(clientHash);
        OPENSSL_cleanse(clientHash.data(), clientHash.size());

        const auto finalRequest = realKerberosFinalNegoAndBindingDer(
            version, nextClientToken, encryptedBinding, nonce);
        OPENSSL_cleanse(
            nextClientToken.data(), nextClientToken.size());
        nextClientToken.clear();
        OPENSSL_cleanse(
            encryptedBinding.data(), encryptedBinding.size());
        encryptedBinding.clear();

        writeNativeTlsClientAll(tls.client.get(), finalRequest);

        std::size_t bindingReplyBytes = 0;
        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds{5};
        for (std::size_t stepIndex = 0;
             stepIndex < kMaximumCredSspRequestBytes + 64;
             ++stepIndex)
        {
            const auto step = server.advanceOwnedCredSspHandshake(
                owner, reader, writer);
            assert(step.status != OwnedCredSspHandshakeStatus::Rejected);
            assert(step.status !=
                   OwnedCredSspHandshakeStatus::TransportClosed);

            if (writer.status() == TsRequestTlsWriteStatus::NeedWrite &&
                bindingReplyBytes == 0)
            {
                bindingReplyBytes = writer.bytesRemaining();
                assert(bindingReplyBytes > 0);
                assert(server.stage() ==
                       SpnegoStage::ServerBindingPrepared);
                assert(!server.verifiedPrincipal().empty());
                // Semantic proof is deliberately still non-authorizing until
                // the exact R1 owner completes the server binding reply.
                assert(server.verifiedPrincipalForOwnedConnection(
                           owner).empty());
                continue;
            }

            if (step.status ==
                OwnedCredSspHandshakeStatus::BindingVerified)
            {
                assert(bindingReplyBytes > 0);
                assert(writer.status() ==
                       TsRequestTlsWriteStatus::Idle);
                break;
            }

            if (step.status == OwnedCredSspHandshakeStatus::NeedRead ||
                step.status == OwnedCredSspHandshakeStatus::NeedWrite)
            {
                const auto polled = owner.pollSocketOnce(
                    deadline, kMaximumTcpPollWait);
                assert(polled.outcome ==
                           TcpConnectionPollOutcome::Dispatched ||
                       polled.outcome ==
                           TcpConnectionPollOutcome::NoEvent);
            }
            else
            {
                assert(step.status ==
                       OwnedCredSspHandshakeStatus::Progress);
            }
        }

        assert(bindingReplyBytes > 0);
        assert(server.stage() == SpnegoStage::ServerBindingPrepared);
        const std::string_view ownerPrincipal =
            server.verifiedPrincipalForOwnedConnection(owner);
        assert(!ownerPrincipal.empty());
        assert(ownerPrincipal == server.verifiedPrincipal());

        std::vector<std::uint8_t> bindingReply(bindingReplyBytes);
        readNativeTlsClientAll(tls.client.get(), bindingReply);
        const auto parsedBindingReply =
            parseCredSspTsRequest(bindingReply);
        assert(parsedBindingReply &&
               parsedBindingReply.value.version == version);
        assert(parsedBindingReply.value.hasPubKeyAuth);
        assert(parsedBindingReply.value.tokenCount == 0);
        client.verifyProtectedServerProof(
            parsedBindingReply.value.encryptedPubKeyAuth,
            serverHash);
        OPENSSL_cleanse(serverHash.data(), serverHash.size());
        OPENSSL_cleanse(
            bindingReply.data(), bindingReply.size());

        if (scenario ==
            RealKerberosOwnedCredSspScenario::PublicKeyNotNativeAdmission)
        {
            const std::string principal{ownerPrincipal};
            ConsoleIdentityPolicy policy;
            assert(policy.add(
                       {std::string_view{principal}, "rdptest", "seat0", ":0",
                        1001U, kConsoleViewPermission}) ==
                   ConsoleRuleError::None);
            LinuxConsoleAdmissionBroker broker{policy};
            const ConsoleEvidenceRequest request{
                std::string_view{principal}, "rdptest", "seat0", ":0",
                kConsoleViewPermission};

            // The exact live HYBRID owner, real Kerberos principal and fully
            // delivered server binding are still insufficient. The private R2
            // final-credential completion proof is absent, so denial occurs
            // before native NSS/logind monitoring or evidence sampling.
            assert(!broker.issue(server, owner, request));
            assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
            assert(broker.nativeChangeFd() == -1);
            assert(broker.nativeChangeEvents() == -1);
            assert(server.stage() == SpnegoStage::Failed);
        }
        else if (scenario ==
                 RealKerberosOwnedCredSspScenario::FinalAuthInfoDenied)
        {
            std::array<std::uint8_t, 29> credentials{
                0x30, 0x1b,
                0xa0, 0x03, 0x02, 0x01, 0x01,
                0xa1, 0x14, 0x04, 0x12,
                0x30, 0x10,
                0xa0, 0x02, 0x04, 0x00,
                0xa1, 0x04, 0x04, 0x02, 0x75, 0x00,
                0xa2, 0x04, 0x04, 0x02, 0x70, 0x00};
            assert(inspectCredSspCredentials(credentials));
            auto encryptedAuthInfo = client.seal(credentials);
            OPENSSL_cleanse(credentials.data(), credentials.size());
            auto authInfoRequest = realKerberosAuthInfoDer(
                version, encryptedAuthInfo);
            OPENSSL_cleanse(
                encryptedAuthInfo.data(), encryptedAuthInfo.size());
            encryptedAuthInfo.clear();

            const std::size_t authInfoRequestSize = authInfoRequest.size();
            writeNativeTlsClientAll(tls.client.get(), authInfoRequest);
            OPENSSL_cleanse(
                authInfoRequest.data(), authInfoRequest.size());
            authInfoRequest.clear();

            std::size_t authInfoBytesRead = 0;
            OwnedCredSspHandshakeStatus terminalStatus{
                OwnedCredSspHandshakeStatus::NeedRead};
            const auto authInfoDeadline =
                std::chrono::steady_clock::now() +
                std::chrono::seconds{5};
            for (std::size_t stepIndex = 0;
                 stepIndex < kMaximumCredSspRequestBytes + 16;
                 ++stepIndex)
            {
                const auto step = server.advanceOwnedCredSspHandshake(
                    owner, reader, writer);
                authInfoBytesRead += step.plaintextBytesRead;
                assert(step.plaintextBytesWritten == 0);
                terminalStatus = step.status;
                if (terminalStatus ==
                    OwnedCredSspHandshakeStatus::
                        UnsupportedFinalCredentials)
                {
                    break;
                }
                assert(terminalStatus ==
                           OwnedCredSspHandshakeStatus::Progress ||
                       terminalStatus ==
                           OwnedCredSspHandshakeStatus::NeedRead ||
                       terminalStatus ==
                           OwnedCredSspHandshakeStatus::NeedWrite);
                if (terminalStatus ==
                        OwnedCredSspHandshakeStatus::NeedRead ||
                    terminalStatus ==
                        OwnedCredSspHandshakeStatus::NeedWrite)
                {
                    const auto polled = owner.pollSocketOnce(
                        authInfoDeadline, kMaximumTcpPollWait);
                    assert(polled.outcome ==
                               TcpConnectionPollOutcome::Dispatched ||
                           polled.outcome ==
                               TcpConnectionPollOutcome::NoEvent);
                }
            }

            assert(terminalStatus ==
                   OwnedCredSspHandshakeStatus::
                       UnsupportedFinalCredentials);
            assert(authInfoBytesRead == authInfoRequestSize);
            assert(server.stage() == SpnegoStage::Failed);
            assert(server.verifiedPrincipal().empty());
            assert(reader.status() == TsRequestFrameStatus::Closed);
            assert(reader.completeDer().empty());
            assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        }
        else
        {
            // R2/GSS proof remains diagnostic and is explicitly retired.
            server.reject();
            assert(server.verifiedPrincipalForOwnedConnection(owner).empty());
        }

        owner.cancel();
        assert(!owner.active());
    }
}

void testRealKerberosOwnedCredSspBindingVerified()
{
    runRealKerberosOwnedCredSspScenario(
        RealKerberosOwnedCredSspScenario::BindingReceipt);
}

void testRealKerberosPublicKeyNotNativeAdmission()
{
    runRealKerberosOwnedCredSspScenario(
        RealKerberosOwnedCredSspScenario::PublicKeyNotNativeAdmission);
}

void testRealKerberosOwnedAuthInfoDenial()
{
    runRealKerberosOwnedCredSspScenario(
        RealKerberosOwnedCredSspScenario::FinalAuthInfoDenied);
}

// Opt-in ONLY. Every GSS token below comes from MIT's actual initiator
// using a caller-designated FILE: cache and explicit service keytab. The
// provider and peer each use a real in-memory TLS application-data stream.
// A clean SPNEGO mechanism is not OS session authorization or MS-CSSP
// client acceptance; no user credentials, MCS, or desktop are enabled.
void testRealKerberosSpnegoOverTls()
{
    const char *serviceName = std::getenv("RDP_TEST_KRB5_SERVICE");
    const char *serviceKeytab = std::getenv("RDP_TEST_KRB5_KEYTAB");
    const char *clientCache = std::getenv("RDP_TEST_KRB5_CCACHE");
    assert(serviceName && serviceKeytab && clientCache);
    const std::string_view service{serviceName};
    const std::string_view keytab{serviceKeytab};
    const std::string_view cache{clientCache};
    assert(service.starts_with("TERMSRV/") && service.find('@') !=
           service.npos);
    assert(keytab.starts_with("FILE:/") && cache.starts_with("FILE:/"));
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
      for (const bool substituteSelectedCert : {false, true})
      {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        GssapiSpnegoAcceptor server;
        assert(server.configure(service, keytab));
        TestKerberosInitiator client{service, cache};

        std::vector<std::uint8_t> nextClientToken;
        OM_uint32 clientStatus = client.next({}, nextClientToken);
        assert(!nextClientToken.empty());
        assert(isInitialSpnegoToken(nextClientToken));
        bool verified = false;
        for (std::size_t round = 0; round < kMaximumSpnegoRoundTrips;
             ++round)
        {
            const auto clientDer = encodeCredSspServerTsRequest(
                version, CredSspServerReplyField::NegoToken,
                nextClientToken);
            assert(!clientDer.empty());
            writeTlsClientApplicationData(tls.client.get(), clientDer);
            receiveOneCredSspTlsFrame(
                reader, tls.server.get(), clientDer.size());
            auto accepted = server.acceptFramedNegoRequest(reader);
            assert(accepted.status != SpnegoStatus::Rejected);
            assert(reader.status() == TsRequestFrameStatus::NeedMore);
            if (!accepted.outputToken.empty())
            {
                // Only opaque REAL provider GSS output crosses this TLS.
                assert(writer.queueReply(
                    tls.server.get(), version,
                    CredSspServerReplyField::NegoToken,
                    accepted.outputToken));
                assert(writer.writeOneTlsStep(tls.server.get()).status ==
                       TsRequestTlsWriteStatus::Complete);
                std::array<std::uint8_t, kMaximumCredSspRequestBytes> bytes{};
                std::size_t count = 0;
                assert(SSL_read_ex(tls.client.get(), bytes.data(),
                                   bytes.size(), &count) == 1);
                const auto decoded = parseCredSspTsRequest(
                    std::span(bytes).first(count));
                assert(decoded && decoded.value.initialNegoTokenOnly());
                assert(decoded.value.version == version);
                clientStatus = client.next(
                    decoded.value.tokens[0], nextClientToken);
                assert(writer.releaseReply());
                OPENSSL_cleanse(bytes.data(), count);
            }
            else
            {
                nextClientToken.clear();
            }
            if (!accepted.outputToken.empty())
            {
                OPENSSL_cleanse(accepted.outputToken.data(),
                                accepted.outputToken.size());
            }
            if (accepted.status == SpnegoStatus::MechanismVerified)
            {
                assert(clientStatus == GSS_S_COMPLETE);
                assert(nextClientToken.empty());
                assert(server.stage() == SpnegoStage::MechanismVerified);
                // GSS identity alone is not a TLS-bound console identity.
                assert(server.verifiedPrincipal().empty());
                verified = true;
                break;
            }
            assert(accepted.status == SpnegoStatus::Continue);
            assert(!nextClientToken.empty());
        }
        assert(verified);
        // This is the binding-only GSS provider diagnostic, not the
        // complete MS-CSSP combined-last-token Windows client flow.
        std::array<std::uint8_t, 32> nonce{};
        for (std::size_t i = 0; i < nonce.size(); ++i)
            nonce[i] = static_cast<std::uint8_t>(version + i);
        CredSspHash clientHash{};
        CredSspHash serverHash{};
        assert(computeCredSspBindingForActiveServerTls(
            tls.server.get(), CredSspBindingDirection::ClientToServer,
            nonce, clientHash));
        assert(computeCredSspBindingForActiveServerTls(
            tls.server.get(), CredSspBindingDirection::ServerToClient,
            nonce, serverHash));
        auto ciphertext = client.seal(clientHash);
        OPENSSL_cleanse(clientHash.data(), clientHash.size());
        const auto binding = realKerberosBindingOnlyDer(
            version, ciphertext, nonce);
        OPENSSL_cleanse(ciphertext.data(), ciphertext.size());

        // Deliberately create a SECOND reader: it has no knowledge of the
        // certificate pinned when the genuine Kerberos tokens arrived.
        // The GSS acceptor itself must reject a same-SSL certificate swap.
        TsRequestFrameReader nextReader;
        if (substituteSelectedCert)
        {
            TlsHandshakeFixture other;
            const CertificatePointer replacement{
                X509_dup(SSL_get_certificate(other.server.get())), X509_free};
            assert(replacement);
            assert(SSL_use_certificate(
                tls.server.get(), replacement.get()) == 1);
        }
        writeTlsClientApplicationData(tls.client.get(), binding);
        receiveOneCredSspTlsFrame(
            nextReader, tls.server.get(), binding.size());
        if (substituteSelectedCert)
        {
            const auto denied = server.processFramedProtectedBinding(
                nextReader);
            assert(!denied.ready && denied.encryptedServerBinding.empty());
            assert(nextReader.status() == TsRequestFrameStatus::Closed);
            assert(server.stage() == SpnegoStage::Failed);
        }
        else
        {
            assert(server.processFramedProtectedBindingAndQueueReply(
                nextReader, writer));
            assert(server.stage() == SpnegoStage::ServerBindingPrepared);
            assert(!server.verifiedPrincipal().empty());
            assert(writer.writeOneTlsStep(tls.server.get()).status ==
                   TsRequestTlsWriteStatus::Complete);
            std::array<std::uint8_t, kMaximumCredSspRequestBytes> bytes{};
            std::size_t count = 0;
            assert(SSL_read_ex(tls.client.get(), bytes.data(),
                               bytes.size(), &count) == 1);
            const auto result = parseCredSspTsRequest(
                std::span(bytes).first(count));
            assert(result && result.value.version == version);
            assert(result.value.hasPubKeyAuth &&
                   result.value.tokenCount == 0);
            client.verifyProtectedServerProof(
                result.value.encryptedPubKeyAuth, serverHash);
            OPENSSL_cleanse(bytes.data(), count);
            assert(writer.releaseReply());
            // The GSS proof stays valid internally, but a swapped
            // selected X.509 invalidates its OS-facing principal borrow.
            TlsHandshakeFixture replacement;
            substituteCredSspReplyCertificate(
                tls.server.get(), replacement.server.get());
            assert(server.stage() == SpnegoStage::ServerBindingPrepared);
            assert(server.verifiedPrincipal().empty());
        }
        OPENSSL_cleanse(serverHash.data(), serverHash.size());
        // Even genuine MIT Kerberos with an intact TLS-binding proof
        // never authorizes a desktop, credentials or MCS in this SDK.
        reader.close();
        nextReader.close();
        writer.close();
        server.reject();
        assert(server.stage() == SpnegoStage::Failed);
        assert(server.verifiedPrincipal().empty());
      }
    }
}

// Opt-in ONLY: requires an explicit externally provisioned Kerberos
// service keytab. The SYNTACTICALLY valid but defective SPNEGO token
// below must reach the real MIT GSS provider and fail; no default
// host keytab, implicit KDC, authentication success or OS admission.
void testRealKerberosProviderFailureReplyOverTls()
{
    const char *serviceName = std::getenv("RDP_TEST_KRB5_SERVICE");
    const char *serviceKeytab = std::getenv("RDP_TEST_KRB5_KEYTAB");
    const char *clientCache = std::getenv("RDP_TEST_KRB5_CCACHE");
    assert(serviceName && serviceKeytab && clientCache);
    const std::string_view service{serviceName};
    const std::string_view keytab{serviceKeytab};
    const std::string_view cache{clientCache};
    assert(service.starts_with("TERMSRV/") &&
           service.find('@') != service.npos);
    assert(keytab.starts_with("FILE:/") && cache.starts_with("FILE:/"));
    constexpr std::array<std::uint8_t, 11> malformedGssToken{
        0x60, 0x09, 0x06, 0x06, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x02, 0xa0};
    assert(isInitialSpnegoToken(malformedGssToken));
    constexpr std::array<std::uint8_t, 15> v6LogonFailure{
        0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x6d};

    for (const std::uint8_t version :
         {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        GssapiSpnegoAcceptor server;
        assert(server.configure(service, keytab));
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        const auto framed = encodeCredSspServerTsRequest(
            version, CredSspServerReplyField::NegoToken, malformedGssToken);
        assert(!framed.empty());
        writeTlsClientApplicationData(tls.client.get(), framed);
        receiveOneCredSspTlsFrame(reader, tls.server.get(), framed.size());
        const auto outcome =
            server.acceptFramedNegoAndQueueReply(reader, writer);
        assert(server.stage() == SpnegoStage::Failed);
        assert(server.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        if (version == 5)
        {
            assert(outcome == SpnegoStatus::Rejected);
            assert(writer.status() == TsRequestTlsWriteStatus::Closed);
            assertNoGssReplyDelivered(tls.client.get());
            continue;
        }
        assert(outcome == SpnegoStatus::FailureQueued);
        assert(writer.status() == TsRequestTlsWriteStatus::NeedWrite);
        assert(writer.bytesRemaining() == v6LogonFailure.size());
        assert(writer.writeOneTlsStep(tls.server.get()).status ==
               TsRequestTlsWriteStatus::Complete);
        std::array<std::uint8_t, 32> received{};
        std::size_t count = 0;
        assert(SSL_read_ex(tls.client.get(), received.data(),
                           received.size(), &count) == 1);
        assert(count == v6LogonFailure.size());
        assert(std::equal(received.begin(), received.begin() + count,
                          v6LogonFailure.begin()));
        OPENSSL_cleanse(received.data(), received.size());
        assert(writer.releaseReply());
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(server.stage() == SpnegoStage::Failed);
        assertNoGssReplyDelivered(tls.client.get());
    }
}

void testGssapiFramedBindingOnlyDenials()
{
    for (const std::uint8_t version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        auto der = kTestBindingOnlyDer;
        der[6] = version;
        assert(isCredSspPublicKeyAuthRequest(der));
        TsRequestFrameReader reader;
        writeTlsClientApplicationData(tls.client.get(), der);
        receiveOneCredSspTlsFrame(reader, tls.server.get(), der.size());
        const auto parsed = parseCredSspTsRequest(reader.completeDer());
        assert(parsed && parsed.value.version == version &&
               parsed.value.hasPubKeyAuth && parsed.value.hasClientNonce &&
               parsed.value.tokenCount == 0);
        GssapiSpnegoAcceptor acceptor;
        const auto result = acceptor.processFramedProtectedBinding(reader);
        assert(!result.ready && result.encryptedServerBinding.empty());
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(acceptor.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
        assert(reader.completedFrameServerTls() == nullptr);
        TsRequestFrameReader replay;
        writeTlsClientApplicationData(tls.client.get(), der);
        receiveOneCredSspTlsFrame(replay, tls.server.get(), der.size());
        assert(!acceptor.processFramedProtectedBinding(replay).ready);
        assert(replay.status() == TsRequestFrameStatus::Closed);
    }
    // The historical caller-injected API is terminal even if handed an
    // otherwise valid finished server SSL handle.
    TlsHandshakeFixture tls;
    GssapiSpnegoAcceptor raw;
    assert(!raw.processProtectedBinding(tls.server.get(),
                                        kTestBindingOnlyDer).ready);
    assert(raw.stage() == SpnegoStage::Failed);
    GssapiSpnegoAcceptor synthetic;
    TsRequestFrameReader manual;
    assert(manual.consume(kTestBindingOnlyDer).status ==
           TsRequestFrameStatus::Complete);
    assert(manual.completedFrameServerTls() == nullptr);
    assert(!synthetic.processFramedProtectedBinding(manual).ready);
    assert(manual.status() == TsRequestFrameStatus::Closed);
    GssapiSpnegoAcceptor incompleteProvider;
    TsRequestFrameReader incomplete;
    assert(incomplete.consume(
        std::span(kTestBindingOnlyDer).first(10)).status ==
        TsRequestFrameStatus::NeedMore);
    assert(!incompleteProvider.processFramedProtectedBinding(incomplete).ready);
    assert(incomplete.status() == TsRequestFrameStatus::Closed);
}

void testGssapiFramedBindingReplyOrder()
{
    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        auto der = kTestBindingOnlyDer;
        der[6] = version;
        writeTlsClientApplicationData(tls.client.get(), der);
        receiveOneCredSspTlsFrame(reader, tls.server.get(), der.size());
        GssapiSpnegoAcceptor acceptor;
        assert(!acceptor.processFramedProtectedBindingAndQueueReply(
            reader, writer));
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
        assert(writer.bytesRemaining() == 0);
        assertNoGssReplyDelivered(tls.client.get());
    }
    // Even a pending offline-canonical server reply is dropped on a
    // binding-order error. Neither old bytes nor fake proof are sent.
    TlsHandshakeFixture tls;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    constexpr std::array<std::uint8_t, 1> opaque{0x5a};
    assert(writer.queueReply(
        tls.server.get(), 6, CredSspServerReplyField::NegoToken, opaque));
    writeTlsClientApplicationData(tls.client.get(), kTestBindingOnlyDer);
    receiveOneCredSspTlsFrame(
        reader, tls.server.get(), kTestBindingOnlyDer.size());
    GssapiSpnegoAcceptor provider;
    assert(!provider.processFramedProtectedBindingAndQueueReply(
        reader, writer));
    assert(provider.stage() == SpnegoStage::Failed);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    assert(writer.bytesRemaining() == 0);
    assertNoGssReplyDelivered(tls.client.get());

    TsRequestFrameReader synthetic;
    assert(synthetic.consume(kTestBindingOnlyDer).status ==
           TsRequestFrameStatus::Complete);
    TsRequestTlsReplyWriter syntheticWriter;
    GssapiSpnegoAcceptor syntheticProvider;
    assert(!syntheticProvider.processFramedProtectedBindingAndQueueReply(
        synthetic, syntheticWriter));
    assert(synthetic.status() == TsRequestFrameStatus::Closed);
    assert(syntheticWriter.status() == TsRequestTlsWriteStatus::Closed);
    assert(syntheticProvider.stage() == SpnegoStage::Failed);
}

void testGssapiTlsBoundHandoffDenials()
{
    // An authentic TLS record does not make a fabricated SPNEGO token
    // or a missing explicit service keytab into a Kerberos identity.
    for (const std::uint8_t version : {std::uint8_t{5},
                                       std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        auto request = kTestCredSspDer;
        request[6] = version;
        writeTlsClientApplicationData(tls.client.get(), request);
        assert(drainCredSspFromTls(reader, tls.server.get(),
                                  TsRequestTlsReadStatus::Complete) ==
               request.size());
        assert(reader.completedFrameServerTls() == tls.server.get());
        GssapiSpnegoAcceptor provider;
        const auto result = provider.acceptFramedNegoRequest(reader);
        assert(result.status == SpnegoStatus::Rejected);
        assert(result.outputToken.empty());
        assert(provider.stage() == SpnegoStage::Failed);
        assert(provider.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completedFrameServerTls() == nullptr);
    }
    // Manual DER has no TLS provenance, even when syntactically valid
    // and the caller can supply an independently completed SSL object.
    TlsHandshakeFixture unrelated;
    TsRequestFrameReader synthetic;
    assert(synthetic.consume(kTestCredSspDer).status ==
           TsRequestFrameStatus::Complete);
    assert(synthetic.completedFrameServerTls() == nullptr);
    GssapiSpnegoAcceptor provider;
    const auto result = provider.acceptFramedNegoRequest(synthetic);
    assert(result.status == SpnegoStatus::Rejected);
    assert(provider.stage() == SpnegoStage::Failed);
    assert(synthetic.status() == TsRequestFrameStatus::Closed);
    assert(synthetic.completedFrameServerTls() == nullptr);

    // The public-key binding API must never treat a matched-looking
    // opaque DER blob as an authenticated TLS-bound GSS context.
    const auto &binding = kTestBindingOnlyDer;
    GssapiSpnegoAcceptor unbound;
    const auto wrapped = unbound.processProtectedBinding(
        unrelated.server.get(), binding);
    assert(!wrapped.ready && wrapped.encryptedServerBinding.empty());
    assert(unbound.stage() == SpnegoStage::Failed);
    assert(unbound.verifiedPrincipal().empty());
}

void testGssapiPrincipalTlsProofGate()
{
    // The real TLS framing path cannot fabricate a provider-authenticated
    // principal when no explicit GSS keytab/context was supplied.
    for (const std::uint8_t version : {std::uint8_t{5},
                                       std::uint8_t{6}})
    {
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        GssapiSpnegoAcceptor acceptor;
        auto request = kTestCredSspDer;
        request[6] = version;
        assert(acceptor.verifiedPrincipal().empty());
        writeTlsClientApplicationData(tls.client.get(), request);
        assert(drainCredSspFromTls(
            reader, tls.server.get(), TsRequestTlsReadStatus::Complete) ==
               request.size());
        assert(reader.completedFrameServerTls() == tls.server.get());
        assert(acceptor.verifiedPrincipal().empty());
        assert(acceptor.acceptFramedNegoRequest(reader).status ==
               SpnegoStatus::Rejected);
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(acceptor.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
    }
    // A fresh X.509 substituted on the same SSL* also fails before GSS.
    TlsHandshakeFixture tls;
    TlsHandshakeFixture differentCertificate;
    TsRequestFrameReader reader;
    GssapiSpnegoAcceptor acceptor;
    writeTlsClientApplicationData(tls.client.get(), kTestCredSspDer);
    assert(drainCredSspFromTls(
        reader, tls.server.get(), TsRequestTlsReadStatus::Complete) ==
           kTestCredSspDer.size());
    substituteCredSspReplyCertificate(
        tls.server.get(), differentCertificate.server.get());
    assert(reader.completedFrameServerTls() == nullptr);
    assert(acceptor.verifiedPrincipal().empty());
    assert(acceptor.acceptFramedNegoRequest(reader).status ==
           SpnegoStatus::Rejected);
    assert(acceptor.stage() == SpnegoStage::Failed);
    assert(acceptor.verifiedPrincipal().empty());
    assert(reader.status() == TsRequestFrameStatus::Closed);
}

void testGssapiTlsFramedCredentialDenials()
{
    // Real TLS carries syntactically valid authInfo-only v5/v6 DER.
    // The opaque bytes intentionally are NOT a GSS-wrapped credential.
    // No implicit keytab, credential cache or OS login is ever touched.
    constexpr std::array<std::uint8_t, 14> authInfo{
        0x30, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa2, 0x05, 0x04, 0x03, 0x11, 0x22, 0x33};

    for (const auto version : {std::uint8_t{5}, std::uint8_t{6}})
    {
        auto der = authInfo;
        der[6] = version;
        const auto parsed = parseCredSspTsRequest(der);
        assert(parsed && parsed.value.version == version);
        assert(parsed.value.hasAuthInfo && !parsed.value.hasPubKeyAuth);
        assert(parsed.value.tokenCount == 0);
        assert(parsed.value.encryptedAuthInfo.size() == 3);

        // A complete AUTHENTIC TLS frame is necessary but insufficient:
        // without real GSS and pubKeyAuth proof, deny and wipe.
        TlsHandshakeFixture tls;
        TsRequestFrameReader reader;
        GssapiSpnegoAcceptor acceptor;
        writeTlsClientApplicationData(tls.client.get(), der);
        receiveOneCredSspTlsFrame(reader, tls.server.get(), der.size());
        assert(reader.completedFrameServerTls() == tls.server.get());
        acceptor.consumeFramedAndDenyDelegatedCredentials(reader);
        assert(acceptor.stage() == SpnegoStage::Failed);
        assert(acceptor.verifiedPrincipal().empty());
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(reader.completeDer().empty());
        assert(reader.completedFrameServerTls() == nullptr);
        assert(reader.bytesNeeded() == 0);
        assert(reader.consume(der).status == TsRequestFrameStatus::Closed);
        assertNoGssReplyDelivered(tls.client.get());

        // Caller-provided DER and partial frames never gain TLS origin.
        TsRequestFrameReader manual;
        GssapiSpnegoAcceptor manualAcceptor;
        assert(manual.consume(der).status == TsRequestFrameStatus::Complete);
        assert(manual.completedFrameServerTls() == nullptr);
        manualAcceptor.consumeFramedAndDenyDelegatedCredentials(manual);
        assert(manualAcceptor.stage() == SpnegoStage::Failed);
        assert(manual.status() == TsRequestFrameStatus::Closed);
        assert(manual.completeDer().empty());
        TsRequestFrameReader partial;
        GssapiSpnegoAcceptor partialAcceptor;
        assert(partial.consume(std::span(der).first(5)).status ==
               TsRequestFrameStatus::NeedMore);
        partialAcceptor.consumeFramedAndDenyDelegatedCredentials(partial);
        assert(partialAcceptor.stage() == SpnegoStage::Failed);
        assert(partial.status() == TsRequestFrameStatus::Closed);

        // A new selected X.509 on the SAME SSL* must deny a completed
        // TLS credential frame, even before the GSS admission check.
        TlsHandshakeFixture certTls;
        TlsHandshakeFixture other;
        TsRequestFrameReader changed;
        GssapiSpnegoAcceptor certAcceptor;
        writeTlsClientApplicationData(certTls.client.get(), der);
        receiveOneCredSspTlsFrame(changed, certTls.server.get(), der.size());
        substituteCredSspReplyCertificate(
            certTls.server.get(), other.server.get());
        assert(changed.completedFrameServerTls() == nullptr);
        certAcceptor.consumeFramedAndDenyDelegatedCredentials(changed);
        assert(certAcceptor.stage() == SpnegoStage::Failed);
        assert(changed.status() == TsRequestFrameStatus::Closed);
        assert(changed.completeDer().empty());

        // The historical raw-DER path is permanently deny-only and
        // cannot perform a GSS unwrap of caller-provided ciphertext.
        GssapiSpnegoAcceptor oldApi;
        oldApi.consumeAndDenyDelegatedCredentials(der);
        assert(oldApi.stage() == SpnegoStage::Failed);
        assert(oldApi.verifiedPrincipal().empty());
    }
}
#endif

void testMcsPreauthTerminalRevocation()
{
    // R1 may validate X.224 and TLS without ever receiving the independently
    // OS-authorized R2 capability required to progress the one R3 owner.
    const auto request = validRequest();
    assert(request);
    const auto frame = validMcsPacket();

    PreauthSession denied;
    assert(denied.mcsLifecyclePhase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);
    assert(denied.onConnectionRequest({}).decision ==
           SecurityDecision::Reject);
    assert(denied.stage() == PreauthStage::Closed);
    assert(denied.mcsLifecyclePhase() == McsSessionPhase::Closed);
    assert(!denied.onTlsHandshake(true));
    assert(!denied.onEncryptedMcsConnectInitial(frame));
    assert(denied.mcsLifecyclePhase() == McsSessionPhase::Closed);

    PreauthSession duplicate;
    assert(duplicate.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(duplicate.mcsLifecyclePhase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);
    assert(duplicate.onConnectionRequest(request).decision ==
           SecurityDecision::Reject);
    assert(duplicate.stage() == PreauthStage::Closed);
    assert(duplicate.mcsLifecyclePhase() == McsSessionPhase::Closed);
    assert(!duplicate.onEncryptedMcsConnectInitial(frame));

    PreauthSession tlsRejected;
    assert(tlsRejected.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(!tlsRejected.onTlsHandshake(false));
    assert(tlsRejected.stage() == PreauthStage::Closed);
    assert(tlsRejected.mcsLifecyclePhase() == McsSessionPhase::Closed);
    assert(!tlsRejected.onTlsHandshake(true));
    assert(!tlsRejected.onEncryptedMcsConnectInitial(frame));

    PreauthSession prematureTls;
    assert(!prematureTls.onTlsHandshake(true));
    assert(prematureTls.mcsLifecyclePhase() == McsSessionPhase::Closed);

    PreauthSession cancelled;
    assert(cancelled.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    cancelled.close();
    cancelled.close();
    assert(cancelled.stage() == PreauthStage::Closed);
    assert(cancelled.mcsLifecyclePhase() == McsSessionPhase::Closed);
    assert(!cancelled.onEncryptedMcsConnectInitial(frame));

    // Normal synthetic diagnostic progress remains syntax-only and
    // cannot claim R2 authority. A valid MCS envelope closes R3 too.
    PreauthSession diagnostic;
    assert(diagnostic.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(diagnostic.onTlsHandshake(true));
    assert(diagnostic.stage() == PreauthStage::AwaitMcsConnectInitial);
    assert(diagnostic.mcsLifecyclePhase() ==
           McsSessionPhase::AwaitVerifiedR2Admission);
    assert(diagnostic.onEncryptedMcsConnectInitial(frame));
    assert(diagnostic.stage() == PreauthStage::Closed);
    assert(diagnostic.mcsLifecyclePhase() == McsSessionPhase::Closed);
    assert(!diagnostic.onEncryptedMcsConnectInitial(frame));
}

void testMcsPreauthFirstEnvelopeSizeBound()
{
    // R1's public syntax-only callback must use the SAME R3 envelope
    // ceiling as the incremental TLS intake. No Boolean can grant OS
    // admission or revive the closed session on a later valid packet.
    const auto request = validRequest();
    assert(request);
    const auto valid = validMcsPacket();

    for (const std::size_t size : {
             std::size_t{0}, std::size_t{7},
             kMaximumInitialMcsTpktBytes,
             kMaximumInitialMcsTpktBytes + 1U})
    {
        std::vector<std::uint8_t> frame(size, 0);
        PreauthSession session;
        assert(session.onConnectionRequest(request).decision ==
               SecurityDecision::Tls);
        assert(session.onTlsHandshake(true));
        assert(!session.onEncryptedMcsConnectInitial(frame));
        assert(session.stage() == PreauthStage::Closed);
        assert(session.mcsLifecyclePhase() == McsSessionPhase::Closed);
        assert(!session.onEncryptedMcsConnectInitial(valid));
        session.close();
    }

    PreauthSession normalDiagnostic;
    assert(normalDiagnostic.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(normalDiagnostic.onTlsHandshake(true));
    assert(normalDiagnostic.onEncryptedMcsConnectInitial(valid));
    assert(normalDiagnostic.stage() == PreauthStage::Closed);
    assert(normalDiagnostic.mcsLifecyclePhase() == McsSessionPhase::Closed);
}

void testPreauthSessionLifecycle()
{
    const auto frame = validMcsPacket();
    const auto request = validRequest();
    assert(request);

    PreauthSession normal;
    assert(normal.stage() == PreauthStage::AwaitConnectionRequest);
    assert(normal.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(normal.stage() == PreauthStage::AwaitTls);
    assert(normal.onTlsHandshake(true));
    assert(normal.stage() == PreauthStage::AwaitMcsConnectInitial);
    assert(normal.onEncryptedMcsConnectInitial(frame));
    assert(normal.stage() == PreauthStage::Closed);
    assert(!normal.onEncryptedMcsConnectInitial(frame));
    assert(!normal.onTlsHandshake(true));

    PreauthSession noNegotiation;
    assert(!noNegotiation.onTlsHandshake(true));
    assert(noNegotiation.stage() == PreauthStage::Closed);
    assert(noNegotiation.onConnectionRequest(request).decision ==
           SecurityDecision::Reject);

    PreauthSession tlsFailure;
    assert(tlsFailure.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(!tlsFailure.onTlsHandshake(false));
    assert(tlsFailure.stage() == PreauthStage::Closed);

    PreauthSession invalidFrame;
    assert(invalidFrame.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(invalidFrame.onTlsHandshake(true));
    auto malformed = frame;
    malformed[5] = 0xe0; // invalid X.224 Data TPDU
    assert(!invalidFrame.onEncryptedMcsConnectInitial(malformed));
    assert(invalidFrame.stage() == PreauthStage::Closed);

    PreauthSession oversized;
    assert(oversized.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    assert(oversized.onTlsHandshake(true));
    const std::vector<std::uint8_t> huge(
        kMaximumInitialMcsTpktBytes + 1, 0);
    assert(!oversized.onEncryptedMcsConnectInitial(huge));
    assert(oversized.stage() == PreauthStage::Closed);

    PreauthSession prematureMcs;
    assert(!prematureMcs.onEncryptedMcsConnectInitial(frame));
    assert(prematureMcs.stage() == PreauthStage::Closed);

    PreauthSession explicitClose;
    assert(explicitClose.onConnectionRequest(request).decision ==
           SecurityDecision::Tls);
    explicitClose.close();
    assert(!explicitClose.onTlsHandshake(true));

}

struct PreauthTestCase
{
    std::string_view name;
    void (*run)();
};

// Keep one executable/fixture implementation but expose independent
// behavior-named CTest cases to make regressions visible in CTest output.
// Running without an argument still executes the complete native suite.
constexpr auto kPreauthTestCases = std::to_array<PreauthTestCase>({
    {"preauth-session-lifecycle", &testPreauthSessionLifecycle},
    {"mcs-preauth-terminal-revocation", &testMcsPreauthTerminalRevocation},
    {"mcs-preauth-first-envelope-size-bound", &testMcsPreauthFirstEnvelopeSizeBound},
    {"x224-request-fragments", &testFragmentedConnectionRequestIntake},
    {"x224-request-outcomes", &testConnectionRequestByteBoundaryAndFailure},
    {"x224-confirm-write-order", &testConnectionReplyMustBeSentBeforeTls},
    {"x224-confirm-partial-writes", &testPartialConnectionReplyWrites},
    {"tcp-adapter-fragments", &testTcpAdapterFragmentedIo},
    {"tcp-adapter-backpressure", &testTcpAdapterFailureAndBackpressure},
    {"tcp-bio-chunk-bounds", &testBorrowedTcpBioChunkBounds},
    {"tcp-native-chunk-bounds", &testNativeTcpChunkBounds},
    {"tcp-native-accept-ownership", &testNativeTcpAcceptOwnershipAndCancellation},
    {"tcp-native-accepted-peer-endpoint", &testNativeTcpAcceptedPeerEndpointIdentity},
    {"tcp-native-accept-move-replacement", &testNativeTcpAcceptMoveReplacement},
    {"tcp-native-accept-orderly-eof", &testNativeTcpAcceptOrderlyPeerDisconnect},
    {"tcp-native-accept-batch-budget-handoff", &testNativeTcpAcceptBatchBudgetAndHandoff},
    {"tcp-native-accept-batch-stops-denials", &testNativeTcpAcceptBatchStopsAndDenials},
    {"tcp-native-listener-role-and-mode-denials", &testNativeTcpListenerRoleAndModeDenials},
    {"tcp-native-wrong-socket-type-denials", &testNativeTcpWrongSocketTypeDenials},
    {"tcp-listener-poll-budget-handoff", &testNativeTcpListenerPollBudgetAndOwnerHandoff},
    {"tcp-listener-poll-deadline-denials", &testNativeTcpListenerPollDeadlineAndDenials},
    {"tcp-owned-connection-tls-lifecycle", &testOwnedTcpConnectionTlsLifecycle},
    {"tcp-owned-connection-cancellation", &testOwnedTcpConnectionCancellation},
    {"tcp-owned-readiness-dispatch", &testOwnedTcpReadinessDispatch},
    {"tcp-owned-reply-interest-priority", &testOwnedTcpPendingReplyInterestPriority},
    {"tcp-owned-deadline-cancellation", &testOwnedTcpDeadlineCancellation},
    {"tcp-owned-bounded-poll-loopback-tls", &testOwnedTcpBoundedPollLoopbackTls},
    {"tcp-owned-bounded-poll-timeout-eof", &testOwnedTcpBoundedPollTimeoutAndDisconnect},
    {"tcp-owned-security-negotiation-provenance", &testOwnedSecurityNegotiationProvenance},
    {"tcp-owned-hybrid-nla-negotiation", &testOwnedHybridNlaNegotiation},
    {"tcp-owned-hybrid-credssp-first-record", &testOwnedHybridCredSspFirstRecord},
    {"tcp-owned-hybrid-no-premature-mcs", &testOwnedHybridNoPrematureMcs},
    {"tcp-owned-hybrid-provenance-revocation", &testOwnedHybridProvenanceRevocation},
    {"tcp-owned-tls-application-io", &testOwnedTlsApplicationIo},
    {"tcp-owned-tls-application-partial-write", &testOwnedTlsApplicationPartialWrite},
    {"tcp-owned-r3-connect-response-slice", &testR3ConnectResponseSliceThroughOwnedTls},
    {"tcp-owned-tls-application-cancellation", &testOwnedTlsApplicationCancellation},
    {"tls-nonblocking-handshake", &testNonblockingTlsHandshakeProgress},
    {"tls-nonblocking-failures", &testNonblockingTlsHandshakeFailures},
    {"tcp-native-loopback-tls", &testNativeLoopbackTlsAndMcs},
    {"tcp-native-loopback-close", &testNativeLoopbackCloseAndFailure},
    {"tcp-attached-tls-ownership-denials", &testAttachedTcpTlsOwnershipDenials},
    {"tcp-attached-mcs-order-denials", &testAttachedTcpMcsOrderingDenials},
    {"tls-handshake-gate", &testRealTlsTransportGate},
    {"x224-length-and-close", &testConnectionRequestLengthRejectionAndClose},
    {"mcs-decrypted-fragments", &testIncrementalDecryptedMcsIntake},
    {"mcs-decrypted-rejections", &testRejectedDecryptedMcsBoundaries},
    {"mcs-tls-record-fragments", &testActualTlsApplicationDataIntake},
    {"mcs-tls-record-rejections", &testTlsRecordFailClosedBoundaries},
    {"mcs-tls-selected-certificate-continuity", &testMcsTlsSelectedCertificateContinuity},
    {"mcs-tls-selected-certificate-substitution", &testMcsTlsSelectedCertificateSubstitution},
    {"credssp-tls-fragments", &testTlsCredSspFragmentation},
    {"credssp-tls-coalesced", &testTlsCredSspCoalescingAndIdentity},
    {"credssp-tls-rejections", &testTlsCredSspRejections},
    {"credssp-tls-provenance", &testTlsCredSspProvenance},
    {"credssp-r1-owned-framing", &testOwnedTlsCredSspFraming},
    {"credssp-r1-owned-reply", &testOwnedTlsCredSspReplyTransport},
    {"credssp-tls-certificate-pinning", &testTlsCredSspCertificatePinning},
    {"credssp-tls-release-certificate-denial", &testTlsCredSspReleaseCertificateContinuity},
    {"credssp-active-tls-binding-positive", &testLiveTlsCertificateBindingPositive},
    {"credssp-active-tls-binding-rejections", &testLiveTlsCertificateBindingRejections},
    {"credssp-tls-reply-wire", &testTlsCredSspReplyWire},
    {"credssp-tls-reply-backpressure", &testTlsCredSspReplyBackpressure},
    {"credssp-tls-reply-rejections", &testTlsCredSspReplyRejections},
    {"credssp-tls-reply-cert-pending", &testTlsCredSspReplyCertPending},
    {"credssp-tls-reply-cert-completion", &testTlsCredSspReplyCertCompletionAndReuse},
    {"credssp-tls-reply-cert-backpressure", &testTlsCredSspReplyCertBackpressure},
    {"credssp-tls-failure-reply-wire", &testTlsCredSspFailureReplyWire},
    {"credssp-tls-failure-reply-rejections", &testTlsCredSspFailureReplyRejections},
#ifdef RDP_TEST_LINUX_GSSAPI
    {"gssapi-r1-owned-credssp-provenance-fence",
     &testGssapiOwnedCredSspProvenanceFence},
    {"gssapi-r1-owned-binding-delivery-fence",
     &testGssapiOwnedCredSspBindingDeliveryFence},
    {"gssapi-credssp-authinfo-terminal-denials",
     &testGssapiOwnedCredSspAuthInfoTerminalDenials},
    {"gssapi-r1-owned-credssp-cancellation-fence",
     &testGssapiOwnedCredSspCancellationFence},
    {"gssapi-r1-owned-completed-frame-cancellation-fence",
     &testGssapiOwnedCompletedFrameCancellationFence},
    {"gssapi-tls-ownership", &testGssapiTlsBoundHandoffDenials},
    {"gssapi-principal-tls-proof-gate", &testGssapiPrincipalTlsProofGate},
    {"gssapi-tls-framed-credential-denials", &testGssapiTlsFramedCredentialDenials},
    {"gssapi-final-combined-denials", &testGssapiCombinedFinalBindingDenied},
    {"gssapi-negotiation-reply-gates", &testGssapiNegotiationReplyHandoffDenied},
    {"gssapi-failure-reply-denials", &testGssapiFailureReplyWithoutCredentialsDenied},
    {"gssapi-binding-reply-gates", &testGssapiBindingReplyHandoffDenied},
    {"gssapi-reply-order-denials", &testGssapiReplyOrderAndPendingDenials},
    {"gssapi-framed-binding-only-denials", &testGssapiFramedBindingOnlyDenials},
    {"gssapi-framed-binding-reply-order", &testGssapiFramedBindingReplyOrder},
#ifdef RDP_TEST_REAL_KERBEROS
    {"gssapi-real-kerberos-owned-binding",
     &testRealKerberosOwnedCredSspBindingVerified},
    {"gssapi-credssp-public-key-not-native-admission",
     &testRealKerberosPublicKeyNotNativeAdmission},
    {"gssapi-real-kerberos-owned-authinfo-denial",
     &testRealKerberosOwnedAuthInfoDenial},
    {"gssapi-real-kerberos-tls-mechanism", &testRealKerberosSpnegoOverTls},
    {"gssapi-real-kerberos-tls-failure", &testRealKerberosProviderFailureReplyOverTls},
#endif
#endif
});

int main(int argc, char **argv)
{
    if (argc >= 2 && argv[1] != nullptr)
    {
        const std::string_view fixtureCase{argv[1]};
        if (fixtureCase == "tcp-owned-runtime-tls-handshake")
        {
            if (argc != 4 || argv[2] == nullptr || argv[3] == nullptr)
                return 2;
            testOwnedRuntimeTlsHandshake(argv[2], argv[3]);
            return 0;
        }
#ifdef RDP_TEST_REAL_KERBEROS
        if (fixtureCase == "linux-connection-real-kerberos-binding" ||
            fixtureCase == "linux-connection-real-kerberos-authinfo-denial")
        {
            if (argc != 4 || argv[2] == nullptr || argv[3] == nullptr)
                return 2;
            if (fixtureCase == "linux-connection-real-kerberos-binding")
                testRuntimeRealKerberosOwnedBinding(argv[2], argv[3]);
            else
                testRuntimeRealKerberosAuthInfoDenial(argv[2], argv[3]);
            return 0;
        }
#endif
        if (fixtureCase == "tcp-owned-runtime-tls-identity-continuity")
        {
            if (argc != 6 || argv[2] == nullptr || argv[3] == nullptr ||
                argv[4] == nullptr || argv[5] == nullptr)
                return 2;
            testOwnedRuntimeTlsIdentityContinuity(
                argv[2], argv[3], argv[4], argv[5]);
            return 0;
        }
    }

    if (argc == 1)
    {
        for (const auto &test : kPreauthTestCases)
        {
            test.run();
        }
        return 0;
    }
    if (argc != 2)
    {
        return 2;
    }
    const std::string_view selected{argv[1]};
    for (const auto &test : kPreauthTestCases)
    {
        if (selected == test.name)
        {
            test.run();
            return 0;
        }
    }
    // Unknown/mistyped case names MUST fail, not report false-green CI.
    return 2;
}
