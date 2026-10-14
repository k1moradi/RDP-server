// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport/preauth_session.h"
#include "transport/nonblocking_tcp_adapter.h"
#include "transport/tpkt_x224.h"
#include "security/credssp_tsrequest.h"
#include "security/credssp_tls_certificate.h"
#ifdef RDP_TEST_LINUX_GSSAPI
#include "security/gssapi_spnego_acceptor.h"
#endif

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <memory>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <chrono>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
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

    LoopbackSocketPair()
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
        server.value = ::accept(listener.value, nullptr, nullptr);
        assert(server.value != kInvalidLocalSocket);
        listener.close(); // No open listener while exercising TLS.
        makeNonblocking(server.value);
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
            const auto status = adapter.onTlsIoReady(tls.server.get());
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
        result = adapter.connection().consumeMcsConnectInitialFromTls(
            tls.server.get());
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

#ifdef RDP_TEST_LINUX_GSSAPI


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
    constexpr std::array<std::uint8_t, 48> binding{{
        0x30, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa3, 0x03, 0x04, 0x01, 0x55,
        0xa5, 0x22, 0x04, 0x20,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}};
    GssapiSpnegoAcceptor unbound;
    const auto wrapped = unbound.processProtectedBinding(
        unrelated.server.get(), binding);
    assert(!wrapped.ready && wrapped.encryptedServerBinding.empty());
    assert(unbound.stage() == SpnegoStage::Failed);
    assert(unbound.verifiedPrincipal().empty());
}
#endif

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
    {"x224-request-fragments", &testFragmentedConnectionRequestIntake},
    {"x224-request-outcomes", &testConnectionRequestByteBoundaryAndFailure},
    {"x224-confirm-write-order", &testConnectionReplyMustBeSentBeforeTls},
    {"x224-confirm-partial-writes", &testPartialConnectionReplyWrites},
    {"tcp-adapter-fragments", &testTcpAdapterFragmentedIo},
    {"tcp-adapter-backpressure", &testTcpAdapterFailureAndBackpressure},
    {"tls-nonblocking-handshake", &testNonblockingTlsHandshakeProgress},
    {"tls-nonblocking-failures", &testNonblockingTlsHandshakeFailures},
    {"tcp-native-loopback-tls", &testNativeLoopbackTlsAndMcs},
    {"tcp-native-loopback-close", &testNativeLoopbackCloseAndFailure},
    {"tls-handshake-gate", &testRealTlsTransportGate},
    {"x224-length-and-close", &testConnectionRequestLengthRejectionAndClose},
    {"mcs-decrypted-fragments", &testIncrementalDecryptedMcsIntake},
    {"mcs-decrypted-rejections", &testRejectedDecryptedMcsBoundaries},
    {"mcs-tls-record-fragments", &testActualTlsApplicationDataIntake},
    {"mcs-tls-record-rejections", &testTlsRecordFailClosedBoundaries},
    {"credssp-tls-fragments", &testTlsCredSspFragmentation},
    {"credssp-tls-coalesced", &testTlsCredSspCoalescingAndIdentity},
    {"credssp-tls-rejections", &testTlsCredSspRejections},
    {"credssp-tls-provenance", &testTlsCredSspProvenance},
    {"credssp-tls-certificate-pinning", &testTlsCredSspCertificatePinning},
    {"credssp-active-tls-binding-positive", &testLiveTlsCertificateBindingPositive},
    {"credssp-active-tls-binding-rejections", &testLiveTlsCertificateBindingRejections},
    {"credssp-tls-reply-wire", &testTlsCredSspReplyWire},
    {"credssp-tls-reply-backpressure", &testTlsCredSspReplyBackpressure},
    {"credssp-tls-reply-rejections", &testTlsCredSspReplyRejections},
#ifdef RDP_TEST_LINUX_GSSAPI
    {"gssapi-tls-ownership", &testGssapiTlsBoundHandoffDenials},
    {"gssapi-final-combined-denials", &testGssapiCombinedFinalBindingDenied},
    {"gssapi-negotiation-reply-gates", &testGssapiNegotiationReplyHandoffDenied},
    {"gssapi-binding-reply-gates", &testGssapiBindingReplyHandoffDenied},
    {"gssapi-reply-order-denials", &testGssapiReplyOrderAndPendingDenials},
#endif
});

int main(int argc, char **argv)
{
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
