// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport/preauth_session.h"
#include "transport/nonblocking_tcp_adapter.h"
#include "transport/tpkt_x224.h"

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

#ifndef OWNED_MCS_FIXTURE_PATH
#error OWNED_MCS_FIXTURE_PATH must point to the checked-in Microsoft fixture
#endif

using namespace rdp_server::server::transport;

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

    TlsHandshakeFixture()
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
        BIO *serverBio = nullptr;
        BIO *clientBio = nullptr;
        assert(BIO_new_bio_pair(&serverBio, 0, &clientBio, 0) == 1);
        // SSL_set_bio takes ownership of both ends. The shared pointer
        // for each SSL's read/write sides is freed only once by SSL_free.
        SSL_set_bio(server.get(), serverBio, serverBio);
        SSL_set_bio(client.get(), clientBio, clientBio);
        SSL_set_accept_state(server.get());
        SSL_set_connect_state(client.get());

        // Non-blocking in-memory transport: OpenSSL owns all TLS records.
        // No sockets, listeners, file credentials or external services.
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
constexpr std::array<PreauthTestCase, 13> kPreauthTestCases{{
    {"preauth-session-lifecycle", &testPreauthSessionLifecycle},
    {"x224-request-fragments", &testFragmentedConnectionRequestIntake},
    {"x224-request-outcomes", &testConnectionRequestByteBoundaryAndFailure},
    {"x224-confirm-write-order", &testConnectionReplyMustBeSentBeforeTls},
    {"x224-confirm-partial-writes", &testPartialConnectionReplyWrites},
    {"tcp-adapter-fragments", &testTcpAdapterFragmentedIo},
    {"tcp-adapter-backpressure", &testTcpAdapterFailureAndBackpressure},
    {"tls-handshake-gate", &testRealTlsTransportGate},
    {"x224-length-and-close", &testConnectionRequestLengthRejectionAndClose},
    {"mcs-decrypted-fragments", &testIncrementalDecryptedMcsIntake},
    {"mcs-decrypted-rejections", &testRejectedDecryptedMcsBoundaries},
    {"mcs-tls-record-fragments", &testActualTlsApplicationDataIntake},
    {"mcs-tls-record-rejections", &testTlsRecordFailClosedBoundaries},
}};

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
