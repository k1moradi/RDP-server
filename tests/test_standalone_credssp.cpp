// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/standalone_credssp.h"
#include "server/security/credssp_tls_certificate.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace rdp_server::server::security;

static_assert(std::is_base_of_v<
              NativeDesktopAuthenticatedSessionProof,
              StandalonePasswordAuthenticatedPrincipalProof>);
static_assert(!std::is_copy_constructible_v<
              StandalonePasswordAuthenticatedPrincipalProof>);

namespace rdp_server::server::security
{
struct StandaloneNtlmV2TestAccess
{
    static void activateClientMirror(
        const NtlmV2SecurityContext &serverPerspective,
        NtlmV2SecurityContext &clientPerspective) noexcept
    {
        clientPerspective.activate(
            serverPerspective.sessionBaseKey_,
            serverPerspective.exportedSessionKey_,
            serverPerspective.serverSigningKey_,
            serverPerspective.clientSigningKey_,
            serverPerspective.serverSealingKey_,
            serverPerspective.clientSealingKey_,
            serverPerspective.negotiateFlags_);
    }
};
} // namespace rdp_server::server::security

namespace
{

using Bytes = std::vector<std::uint8_t>;
using ContextPointer =
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPointer =
    std::unique_ptr<SSL, decltype(&SSL_free)>;
using KeyPointer =
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CertificatePointer =
    std::unique_ptr<X509, decltype(&X509_free)>;
using X509NamePointer =
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;

constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr std::uint64_t kTimestamp = 0x0102030405060708ULL;
constexpr NtlmV2Key kEncryptedRandomSessionKey{
    0xc5,0xda,0xd2,0x54,0x4f,0xc9,0x79,0x90,
    0x94,0xce,0x1c,0xe9,0x0b,0xc9,0xd0,0x3e};
constexpr std::uint32_t kMicrosoftAuthenticateFlags = 0xe2888235U;
constexpr std::array<std::uint8_t, 10> kNtlmOid{
    0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};
constexpr std::array<std::uint8_t, 6> kSpnegoOid{
    0x2b,0x06,0x01,0x05,0x05,0x02};

constexpr std::array<std::uint8_t, 84> kNtlmV2Response{
    0x68,0xcd,0x0a,0xb8,0x51,0xe5,0x1c,0x96,
    0xaa,0xbc,0x92,0x7b,0xeb,0xef,0x6a,0x1c,
    0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0x00,0x00,0x00,0x00,
    0x02,0x00,0x0c,0x00,
    0x44,0x00,0x6f,0x00,0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
    0x01,0x00,0x0c,0x00,
    0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00};

constexpr std::array<std::uint8_t, 232> kMicrosoftAuthenticateMessage{
    0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
    0x03,0x00,0x00,0x00,0x18,0x00,0x18,0x00,
    0x6c,0x00,0x00,0x00,0x54,0x00,0x54,0x00,
    0x84,0x00,0x00,0x00,0x0c,0x00,0x0c,0x00,
    0x48,0x00,0x00,0x00,0x08,0x00,0x08,0x00,
    0x54,0x00,0x00,0x00,0x10,0x00,0x10,0x00,
    0x5c,0x00,0x00,0x00,0x10,0x00,0x10,0x00,
    0xd8,0x00,0x00,0x00,0x35,0x82,0x88,0xe2,
    0x05,0x01,0x28,0x0a,0x00,0x00,0x00,0x0f,
    0x44,0x00,0x6f,0x00,0x6d,0x00,0x61,0x00,
    0x69,0x00,0x6e,0x00,0x55,0x00,0x73,0x00,
    0x65,0x00,0x72,0x00,0x43,0x00,0x4f,0x00,
    0x4d,0x00,0x50,0x00,0x55,0x00,0x54,0x00,
    0x45,0x00,0x52,0x00,0x86,0xc3,0x50,0x97,
    0xac,0x9c,0xec,0x10,0x25,0x54,0x76,0x4a,
    0x57,0xcc,0xcc,0x19,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0x68,0xcd,0x0a,0xb8,
    0x51,0xe5,0x1c,0x96,0xaa,0xbc,0x92,0x7b,
    0xeb,0xef,0x6a,0x1c,0x01,0x01,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0x00,0x00,0x00,0x00,
    0x02,0x00,0x0c,0x00,0x44,0x00,0x6f,0x00,
    0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
    0x01,0x00,0x0c,0x00,0x53,0x00,0x65,0x00,
    0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xc5,0xda,0xd2,0x54,0x4f,0xc9,0x79,0x90,
    0x94,0xce,0x1c,0xe9,0x0b,0xc9,0xd0,0x3e};

[[nodiscard]] Bytes derLength(std::size_t length)
{
    if (length < 128U)
        return {static_cast<std::uint8_t>(length)};
    if (length < 256U)
        return {0x81U, static_cast<std::uint8_t>(length)};
    assert(length <= 65535U);
    return {
        0x82U,
        static_cast<std::uint8_t>(length >> 8U),
        static_cast<std::uint8_t>(length)};
}

[[nodiscard]] Bytes wrap(
    std::uint8_t tag,
    std::span<const std::uint8_t> value)
{
    Bytes output{tag};
    const auto encodedLength = derLength(value.size());
    output.insert(
        output.end(), encodedLength.begin(), encodedLength.end());
    output.insert(output.end(), value.begin(), value.end());
    return output;
}

[[nodiscard]] Bytes append(Bytes first, const Bytes &second)
{
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

[[nodiscard]] Bytes oid(std::span<const std::uint8_t> value)
{
    return wrap(0x06U, value);
}

[[nodiscard]] Bytes initialSpnego(
    std::span<const std::uint8_t> mechanismToken)
{
    const auto mechanism = oid(kNtlmOid);
    const auto mechanismList = wrap(0x30U, mechanism);
    Bytes fields = wrap(0xa0U, mechanismList);
    const auto tokenField =
        wrap(0xa2U, wrap(0x04U, mechanismToken));
    fields.insert(
        fields.end(), tokenField.begin(), tokenField.end());

    const auto init = wrap(0xa0U, wrap(0x30U, fields));
    Bytes body = oid(kSpnegoOid);
    body.insert(body.end(), init.begin(), init.end());
    return wrap(0x60U, body);
}

[[nodiscard]] Bytes continuationSpnego(
    std::span<const std::uint8_t> mechanismToken)
{
    const auto token =
        wrap(0xa2U, wrap(0x04U, mechanismToken));
    return wrap(0xa1U, wrap(0x30U, token));
}

[[nodiscard]] Bytes version(std::uint8_t value)
{
    return wrap(
        0xa0U,
        wrap(0x02U, std::array<std::uint8_t, 1>{value}));
}

[[nodiscard]] Bytes tokens(const Bytes &token)
{
    const auto item =
        wrap(0x30U, wrap(0xa0U, wrap(0x04U, token)));
    return wrap(0xa1U, wrap(0x30U, item));
}

[[nodiscard]] Bytes octetContext(
    std::uint8_t tag,
    std::span<const std::uint8_t> value)
{
    return wrap(tag, wrap(0x04U, value));
}

[[nodiscard]] Bytes combinedFinalRequest(
    const Bytes &token,
    std::span<const std::uint8_t> protectedBinding,
    std::span<const std::uint8_t> nonce)
{
    Bytes fields = append(version(6U), tokens(token));
    fields = append(
        fields, octetContext(0xa3U, protectedBinding));
    fields = append(
        fields, octetContext(0xa5U, nonce));
    return wrap(0x30U, fields);
}

[[nodiscard]] Bytes utf16Le(std::u16string_view text)
{
    Bytes bytes;
    bytes.reserve(text.size() * 2U);
    for (const char16_t character : text)
    {
        const auto code = static_cast<std::uint16_t>(character);
        bytes.push_back(static_cast<std::uint8_t>(code));
        bytes.push_back(static_cast<std::uint8_t>(code >> 8U));
    }
    return bytes;
}

[[nodiscard]] Bytes passwordCredentials(
    std::u16string_view domain,
    std::u16string_view user,
    std::u16string_view delegatedPassword)
{
    Bytes fields = octetContext(0xa0U, utf16Le(domain));
    fields = append(
        fields, octetContext(0xa1U, utf16Le(user)));
    fields = append(
        fields, octetContext(0xa2U, utf16Le(delegatedPassword)));
    const auto passwordCreds = wrap(0x30U, fields);

    const auto type = wrap(
        0xa0U,
        wrap(0x02U, std::array<std::uint8_t, 1>{1U}));
    const auto credentials =
        octetContext(0xa1U, passwordCreds);
    return wrap(0x30U, append(type, credentials));
}

[[nodiscard]] Bytes authInfoRequest(
    std::span<const std::uint8_t> protectedAuthInfo)
{
    return wrap(
        0x30U,
        append(
            version(6U),
            octetContext(0xa2U, protectedAuthInfo)));
}

[[nodiscard]] std::array<std::uint8_t, 40> negotiateMessage()
{
    std::array<std::uint8_t, 40> message{};
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    std::copy(
        signature.begin(), signature.end(), message.begin());
    message[8] = 1U;
    constexpr std::uint32_t flags =
        kNtlmNegotiateUnicode |
        kNtlmNegotiateNtlm |
        kNtlmNegotiateAlwaysSign |
        kRequiredStandaloneCredSspNtlmFlags |
        kNtlmNegotiateKeyExchange |
        kNtlmNegotiate56;
    message[12] = static_cast<std::uint8_t>(flags);
    message[13] = static_cast<std::uint8_t>(flags >> 8U);
    message[14] = static_cast<std::uint8_t>(flags >> 16U);
    message[15] = static_cast<std::uint8_t>(flags >> 24U);
    return message;
}

[[nodiscard]] std::array<char16_t, 8> password()
{
    return {
        u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
}

[[nodiscard]] NtlmV2AuthenticateRequest microsoftRequest()
{
    return {
        kServerChallenge,
        u"User",
        u"Domain",
        kNtlmV2Response,
        kMicrosoftAuthenticateFlags,
        kEncryptedRandomSessionKey};
}

class MemoryTlsPair final
{
public:
    MemoryTlsPair()
        : serverContext_(SSL_CTX_new(TLS_server_method()), SSL_CTX_free),
          clientContext_(SSL_CTX_new(TLS_client_method()), SSL_CTX_free)
    {
        assert(serverContext_ && clientContext_);
        assert(SSL_CTX_set_min_proto_version(
                   serverContext_.get(), TLS1_2_VERSION) == 1);
        assert(SSL_CTX_set_max_proto_version(
                   serverContext_.get(), TLS1_2_VERSION) == 1);
        assert(SSL_CTX_set_min_proto_version(
                   clientContext_.get(), TLS1_2_VERSION) == 1);
        assert(SSL_CTX_set_max_proto_version(
                   clientContext_.get(), TLS1_2_VERSION) == 1);
        SSL_CTX_set_verify(
            clientContext_.get(), SSL_VERIFY_NONE, nullptr);

        const KeyPointer key{
            EVP_EC_gen("prime256v1"), EVP_PKEY_free};
        const CertificatePointer certificate{
            X509_new(), X509_free};
        assert(key && certificate);
        assert(X509_set_version(certificate.get(), 2) == 1);
        assert(ASN1_INTEGER_set(
                   X509_get_serialNumber(certificate.get()), 7) == 1);
        assert(X509_gmtime_adj(
            X509_getm_notBefore(certificate.get()), -60));
        assert(X509_gmtime_adj(
            X509_getm_notAfter(certificate.get()), 3600));
        assert(X509_set_pubkey(
                   certificate.get(), key.get()) == 1);

        const X509NamePointer name{
            X509_NAME_new(), X509_NAME_free};
        assert(name);
        assert(X509_NAME_add_entry_by_txt(
                   name.get(), "CN", MBSTRING_ASC,
                   reinterpret_cast<const unsigned char *>(
                       "standalone-credssp.test"),
                   -1, -1, 0) == 1);
        assert(X509_set_subject_name(
                   certificate.get(), name.get()) == 1);
        assert(X509_set_issuer_name(
                   certificate.get(), name.get()) == 1);
        assert(X509_sign(
                   certificate.get(), key.get(),
                   EVP_sha256()) > 0);
        assert(SSL_CTX_use_certificate(
                   serverContext_.get(),
                   certificate.get()) == 1);
        assert(SSL_CTX_use_PrivateKey(
                   serverContext_.get(), key.get()) == 1);
        assert(SSL_CTX_check_private_key(
                   serverContext_.get()) == 1);

        server_.reset(SSL_new(serverContext_.get()));
        client_.reset(SSL_new(clientContext_.get()));
        assert(server_ && client_);
        SSL_set_accept_state(server_.get());
        SSL_set_connect_state(client_.get());

        BIO *serverBio = nullptr;
        BIO *clientBio = nullptr;
        assert(BIO_new_bio_pair(
                   &serverBio, 0, &clientBio, 0) == 1);
        assert(serverBio != nullptr && clientBio != nullptr);
        SSL_set_bio(server_.get(), serverBio, serverBio);
        SSL_set_bio(client_.get(), clientBio, clientBio);

        bool serverReady = false;
        bool clientReady = false;
        for (std::size_t attempt = 0;
             attempt < 4096U &&
             (!serverReady || !clientReady);
             ++attempt)
        {
            if (!clientReady)
            {
                const int result =
                    SSL_do_handshake(client_.get());
                if (result == 1)
                    clientReady = true;
                else
                {
                    const int error =
                        SSL_get_error(client_.get(), result);
                    assert(error == SSL_ERROR_WANT_READ ||
                           error == SSL_ERROR_WANT_WRITE);
                }
            }
            if (!serverReady)
            {
                const int result =
                    SSL_do_handshake(server_.get());
                if (result == 1)
                    serverReady = true;
                else
                {
                    const int error =
                        SSL_get_error(server_.get(), result);
                    assert(error == SSL_ERROR_WANT_READ ||
                           error == SSL_ERROR_WANT_WRITE);
                }
            }
        }
        assert(serverReady && clientReady);
        assert(SSL_is_init_finished(server_.get()) == 1);
        assert(SSL_is_server(server_.get()) == 1);
    }

    [[nodiscard]] SSL *server() noexcept
    {
        return server_.get();
    }

    void sendClient(std::span<const std::uint8_t> bytes)
    {
        std::size_t offset = 0;
        for (std::size_t attempt = 0;
             attempt < 4096U && offset < bytes.size();
             ++attempt)
        {
            std::size_t written = 0;
            const int result = SSL_write_ex(
                client_.get(),
                bytes.data() + offset,
                bytes.size() - offset,
                &written);
            if (result == 1)
            {
                assert(written != 0);
                offset += written;
                continue;
            }
            const int error =
                SSL_get_error(client_.get(), result);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
        }
        assert(offset == bytes.size());
    }

    void readServerFrame(TsRequestFrameReader &reader)
    {
        for (std::size_t attempt = 0;
             attempt < 4096U;
             ++attempt)
        {
            const auto result =
                reader.readOneTlsStep(server_.get());
            if (result.status ==
                TsRequestTlsReadStatus::Complete)
            {
                return;
            }
            assert(result.status ==
                       TsRequestTlsReadStatus::Progress ||
                   result.status ==
                       TsRequestTlsReadStatus::NeedRead ||
                   result.status ==
                       TsRequestTlsReadStatus::NeedWrite);
        }
        assert(false && "TLS frame did not complete");
    }

    [[nodiscard]] Bytes flushServerReply(
        TsRequestTlsReplyWriter &writer)
    {
        for (std::size_t attempt = 0;
             attempt < 4096U;
             ++attempt)
        {
            const auto result =
                writer.writeOneTlsStep(server_.get());
            if (result.status ==
                TsRequestTlsWriteStatus::Complete)
            {
                break;
            }
            assert(result.status ==
                       TsRequestTlsWriteStatus::Progress ||
                   result.status ==
                       TsRequestTlsWriteStatus::NeedRead ||
                   result.status ==
                       TsRequestTlsWriteStatus::NeedWrite);
        }
        assert(writer.status() ==
               TsRequestTlsWriteStatus::Complete);

        Bytes plaintext;
        std::array<std::uint8_t,
                   kMaximumCredSspRequestBytes> buffer{};
        for (std::size_t attempt = 0;
             attempt < 4096U;
             ++attempt)
        {
            std::size_t read = 0;
            const int result = SSL_read_ex(
                client_.get(), buffer.data(),
                buffer.size(), &read);
            if (result == 1)
            {
                assert(read != 0);
                plaintext.insert(
                    plaintext.end(),
                    buffer.begin(),
                    buffer.begin() +
                        static_cast<std::ptrdiff_t>(read));
                const auto parsed =
                    parseCredSspTsRequest(plaintext);
                if (parsed && SSL_pending(client_.get()) == 0)
                    break;
                continue;
            }

            const int error =
                SSL_get_error(client_.get(), result);
            assert(error == SSL_ERROR_WANT_READ ||
                   error == SSL_ERROR_WANT_WRITE);
            assert(parseCredSspTsRequest(plaintext));
            break;
        }
        assert(parseCredSspTsRequest(plaintext));
        assert(writer.releaseReply());
        return plaintext;
    }

private:
    ContextPointer serverContext_{nullptr, SSL_CTX_free};
    ContextPointer clientContext_{nullptr, SSL_CTX_free};
    SslPointer server_{nullptr, SSL_free};
    SslPointer client_{nullptr, SSL_free};
};

void configureServerCredential(
    EphemeralNtlmV2Credential &credential)
{
    auto mutablePassword = password();
    assert(credential.configure(
        u"User", mutablePassword));
}

void prepareInitialNegotiation(
    StandaloneCredSspNtlmAcceptor &acceptor,
    EphemeralNtlmV2Credential &credential,
    MemoryTlsPair &tls,
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    std::uint8_t requestVersion = 6U)
{
    assert(acceptor.configureChallenge(
        {kServerChallenge, u"Domain", u"Server",
         kTimestamp}));
    const auto negotiate = negotiateMessage();
    const auto spnego = initialSpnego(negotiate);
    const auto request =
        wrap(0x30U, append(version(requestVersion), tokens(spnego)));

    tls.sendClient(request);
    tls.readServerFrame(reader);
    assert(acceptor.processCompleteFrame(
               reader, writer, credential) ==
           StandaloneCredSspFrameStatus::NegoReplyQueued);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::NegoContinue);

    const auto initialObservation = acceptor.initialNegoObservation();
    assert(initialObservation.observed);
    assert(initialObservation.tsRequestVersion == requestVersion);
    assert(initialObservation.tokenCount == 1U);
    assert(initialObservation.spnego.observed);
    assert(initialObservation.spnego.tokenBytes == spnego.size());
    assert(initialObservation.spnego.topLevelTag == 0x60U);
    assert(initialObservation.spnego.gssInitialContextToken);
    assert(initialObservation.spnego.negTokenInit);
    assert(initialObservation.spnego.mechanismCount == 1U);
    assert(initialObservation.spnego.ntlmOffered);
    assert(initialObservation.spnego.ntlmMechanismIndex == 0U);
    assert(initialObservation.spnego.optimisticMechanismTokenPresent);
    assert(initialObservation.spnego.optimisticMechanismTokenBytes ==
           negotiate.size());
    assert(initialObservation.spnego.rejectionReason ==
           StandaloneSpnegoRejectionReason::None);

    const auto reply = tls.flushServerReply(writer);
    const auto parsed = parseCredSspTsRequest(reply);
    assert(parsed && parsed.value.tokenCount == 1);
    assert(!parsed.value.tokens[0].empty());
    // Preserve a real NTLM Type 2 challenge in the SPNEGO reply, rather
    // than accepting an empty/selection-only negotiation response.
    constexpr std::array<std::uint8_t, 12> typeTwoSignature{
        'N','T','L','M','S','S','P',0,2,0,0,0};
    const auto replyToken = parsed.value.tokens[0];
    assert(std::search(replyToken.begin(), replyToken.end(),
                       typeTwoSignature.begin(), typeTwoSignature.end()) !=
           replyToken.end());
}

void configureClientMirror(
    NtlmV2SecurityContext &clientPerspective)
{
    EphemeralNtlmV2Credential credential;
    configureServerCredential(credential);
    NtlmV2SecurityContext serverPerspective;
    assert(credential.verifyAndDeriveSecurityContext(
               microsoftRequest(), serverPerspective) ==
           NtlmV2VerifyResult::Verified);
    StandaloneNtlmV2TestAccess::activateClientMirror(
        serverPerspective, clientPerspective);
}

[[nodiscard]] Bytes protectClientBinding(
    MemoryTlsPair &tls,
    NtlmV2SecurityContext &clientPerspective,
    std::span<const std::uint8_t> nonce)
{
    CredSspHash hash{};
    assert(computeCredSspBindingForActiveServerTls(
        tls.server(),
        CredSspBindingDirection::ClientToServer,
        nonce, hash));

    std::array<std::uint8_t, kCredSspBindingHashBytes>
        ciphertext{};
    std::array<std::uint8_t, kNtlmMessageSignatureBytes>
        signature{};
    assert(clientPerspective.wrapServerMessage(
               hash, ciphertext, signature) ==
           NtlmMessageSecurityResult::Processed);

    Bytes protectedBytes;
    protectedBytes.reserve(
        signature.size() + ciphertext.size());
    protectedBytes.insert(
        protectedBytes.end(),
        signature.begin(), signature.end());
    protectedBytes.insert(
        protectedBytes.end(),
        ciphertext.begin(), ciphertext.end());
    return protectedBytes;
}

[[nodiscard]] Bytes protectAuthInfo(
    NtlmV2SecurityContext &clientSecurity,
    std::span<const std::uint8_t> plaintext)
{
    Bytes ciphertext(plaintext.size());
    std::array<std::uint8_t, kNtlmMessageSignatureBytes> signature{};
    assert(clientSecurity.wrapServerMessage(
               plaintext, ciphertext, signature) ==
           NtlmMessageSecurityResult::Processed);

    Bytes protectedBytes;
    protectedBytes.reserve(signature.size() + ciphertext.size());
    protectedBytes.insert(
        protectedBytes.end(), signature.begin(), signature.end());
    protectedBytes.insert(
        protectedBytes.end(), ciphertext.begin(), ciphertext.end());
    return protectedBytes;
}

[[nodiscard]] std::array<std::uint8_t, 32> nonce()
{
    std::array<std::uint8_t, 32> value{};
    for (std::size_t index = 0; index < value.size(); ++index)
        value[index] = static_cast<std::uint8_t>(index);
    return value;
}

void completeBindingForAuthInfo(
    StandaloneCredSspNtlmAcceptor &acceptor,
    EphemeralNtlmV2Credential &serverCredential,
    NtlmV2SecurityContext &clientSecurity,
    MemoryTlsPair &tls,
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer)
{
    prepareInitialNegotiation(
        acceptor, serverCredential, tls, reader, writer);
    configureClientMirror(clientSecurity);
    const auto clientNonce = nonce();
    const auto protectedBinding =
        protectClientBinding(
            tls, clientSecurity, clientNonce);
    const auto finalRequest = combinedFinalRequest(
        continuationSpnego(kMicrosoftAuthenticateMessage),
        protectedBinding, clientNonce);

    tls.sendClient(finalRequest);
    tls.readServerFrame(reader);
    assert(acceptor.processCompleteFrame(
               reader, writer, serverCredential) ==
           StandaloneCredSspFrameStatus::BindingReplyQueued);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::ServerBindingReplyQueued);

    const auto reply = tls.flushServerReply(writer);
    const auto parsed = parseCredSspTsRequest(reply);
    assert(parsed && parsed.value.hasPubKeyAuth);
    const auto protectedServer =
        parsed.value.encryptedPubKeyAuth;
    assert(protectedServer.size() ==
           kNtlmMessageSignatureBytes +
               kCredSspBindingHashBytes);
    const auto signature =
        std::span<const std::uint8_t,
                  kNtlmMessageSignatureBytes>{
            protectedServer.data(),
            kNtlmMessageSignatureBytes};
    const auto ciphertext =
        protectedServer.subspan(
            kNtlmMessageSignatureBytes);
    CredSspHash serverHash{};
    assert(clientSecurity.unwrapClientMessage(
               ciphertext, signature, serverHash) ==
           NtlmMessageSecurityResult::Processed);
    CredSspHash expected{};
    assert(computeCredSspBindingForActiveServerTls(
        tls.server(),
        CredSspBindingDirection::ServerToClient,
        clientNonce, expected));
    assert(serverHash == expected);
}

void testTlsBoundCombinedPubKeyAuth()
{
    MemoryTlsPair tls;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    EphemeralNtlmV2Credential serverCredential;
    configureServerCredential(serverCredential);
    StandaloneCredSspNtlmAcceptor acceptor;
    prepareInitialNegotiation(
        acceptor, serverCredential, tls, reader, writer);

    NtlmV2SecurityContext clientSecurity;
    configureClientMirror(clientSecurity);
    const auto clientNonce = nonce();
    const auto protectedBinding =
        protectClientBinding(
            tls, clientSecurity, clientNonce);

    const auto finalSpnego =
        continuationSpnego(kMicrosoftAuthenticateMessage);
    const auto finalRequest = combinedFinalRequest(
        finalSpnego, protectedBinding, clientNonce);
    tls.sendClient(finalRequest);
    tls.readServerFrame(reader);
    assert(acceptor.processCompleteFrame(
               reader, writer, serverCredential) ==
           StandaloneCredSspFrameStatus::BindingReplyQueued);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::ServerBindingReplyQueued);

    const auto reply = tls.flushServerReply(writer);
    const auto parsed = parseCredSspTsRequest(reply);
    assert(parsed);
    assert(parsed.value.version == 6);
    assert(parsed.value.hasPubKeyAuth);
    assert(parsed.value.tokenCount == 0);
    assert(!parsed.value.hasAuthInfo);
    assert(!parsed.value.hasClientNonce);

    const auto protectedServer =
        parsed.value.encryptedPubKeyAuth;
    assert(protectedServer.size() ==
           kNtlmMessageSignatureBytes +
               kCredSspBindingHashBytes);
    const auto signature =
        std::span<const std::uint8_t,
                  kNtlmMessageSignatureBytes>{
            protectedServer.data(),
            kNtlmMessageSignatureBytes};
    const auto ciphertext =
        protectedServer.subspan(
            kNtlmMessageSignatureBytes);
    CredSspHash serverHash{};
    assert(clientSecurity.unwrapClientMessage(
               ciphertext, signature, serverHash) ==
           NtlmMessageSecurityResult::Processed);

    CredSspHash expected{};
    assert(computeCredSspBindingForActiveServerTls(
        tls.server(),
        CredSspBindingDirection::ServerToClient,
        clientNonce, expected));
    assert(serverHash == expected);
}

void testPubKeyAuthTamperRevokes()
{
    MemoryTlsPair tls;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    EphemeralNtlmV2Credential serverCredential;
    configureServerCredential(serverCredential);
    StandaloneCredSspNtlmAcceptor acceptor;
    prepareInitialNegotiation(
        acceptor, serverCredential, tls, reader, writer);

    NtlmV2SecurityContext clientSecurity;
    configureClientMirror(clientSecurity);
    const auto clientNonce = nonce();
    auto protectedBinding =
        protectClientBinding(
            tls, clientSecurity, clientNonce);
    protectedBinding[5] ^= 0x01U;

    const auto finalRequest = combinedFinalRequest(
        continuationSpnego(kMicrosoftAuthenticateMessage),
        protectedBinding, clientNonce);
    tls.sendClient(finalRequest);
    tls.readServerFrame(reader);
    assert(acceptor.processCompleteFrame(
               reader, writer, serverCredential) ==
           StandaloneCredSspFrameStatus::Rejected);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::Failed);
    assert(acceptor.failureStage() ==
           StandaloneAuthenticationFailureStage::SignSeal);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);

    // Preserve valid SIGN/SEAL while substituting the CredSSP nonce. The
    // protected payload decrypts, but its channel binding no longer matches.
    MemoryTlsPair bindingTls;
    TsRequestFrameReader bindingReader;
    TsRequestTlsReplyWriter bindingWriter;
    EphemeralNtlmV2Credential bindingCredential;
    configureServerCredential(bindingCredential);
    StandaloneCredSspNtlmAcceptor bindingAcceptor;
    prepareInitialNegotiation(
        bindingAcceptor, bindingCredential,
        bindingTls, bindingReader, bindingWriter);
    NtlmV2SecurityContext bindingClientSecurity;
    configureClientMirror(bindingClientSecurity);
    const auto signedNonce = nonce();
    const auto signedBinding = protectClientBinding(
        bindingTls, bindingClientSecurity, signedNonce);
    auto substitutedNonce = signedNonce;
    substitutedNonce[0] ^= 0x01U;
    const auto bindingRequest = combinedFinalRequest(
        continuationSpnego(kMicrosoftAuthenticateMessage),
        signedBinding, substitutedNonce);
    bindingTls.sendClient(bindingRequest);
    bindingTls.readServerFrame(bindingReader);
    assert(bindingAcceptor.processCompleteFrame(
               bindingReader, bindingWriter, bindingCredential) ==
           StandaloneCredSspFrameStatus::Rejected);
    assert(bindingAcceptor.failureStage() ==
           StandaloneAuthenticationFailureStage::PubKeyAuth);
}

void testAuthInfoExactCredentialMatch()
{
    MemoryTlsPair tls;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    EphemeralNtlmV2Credential serverCredential;
    configureServerCredential(serverCredential);
    StandaloneCredSspNtlmAcceptor acceptor;
    NtlmV2SecurityContext clientSecurity;
    completeBindingForAuthInfo(
        acceptor, serverCredential, clientSecurity,
        tls, reader, writer);

    const auto credentials =
        passwordCredentials({}, u"User", u"Password");
    const auto protectedAuthInfo =
        protectAuthInfo(clientSecurity, credentials);
    const auto request = authInfoRequest(protectedAuthInfo);
    tls.sendClient(request);
    tls.readServerFrame(reader);

    assert(acceptor.processCompleteFrame(
               reader, writer, serverCredential) ==
           StandaloneCredSspFrameStatus::CredentialsVerified);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::CredentialsVerified);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    assert(serverCredential.configured());
}

void testDirectTlsCannotBindAdmissionProof()
{
    MemoryTlsPair tls;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    EphemeralNtlmV2Credential serverCredential;
    configureServerCredential(serverCredential);
    StandaloneCredSspNtlmAcceptor acceptor;
    NtlmV2SecurityContext clientSecurity;
    completeBindingForAuthInfo(
        acceptor, serverCredential, clientSecurity,
        tls, reader, writer);

    const auto credentials =
        passwordCredentials({}, u"User", u"Password");
    const auto protectedAuthInfo =
        protectAuthInfo(clientSecurity, credentials);
    const auto request = authInfoRequest(protectedAuthInfo);
    tls.sendClient(request);
    tls.readServerFrame(reader);
    assert(!reader.completedFrameUsesOwnedTransport());

    assert(acceptor.processCompleteFrame(
               reader, writer, serverCredential) ==
           StandaloneCredSspFrameStatus::CredentialsVerified);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::CredentialsVerified);

    StandalonePasswordCredentialOwner credentialOwner;
    std::array<char16_t, 8> password{
        u'P', u'a', u's', u's', u'w', u'o', u'r', u'd'};
    assert(credentialOwner.configure(u"User", password));
    const auto observation = credentialOwner.observation();
    assert(observation.configured);
    assert(observation.generation != 0);

    using rdp_server::server::transport::OwnedNativeTcpSocket;
    using rdp_server::server::transport::OwnedPreauthTcpConnection;
    OwnedPreauthTcpConnection inactiveConnection{OwnedNativeTcpSocket{}};
    StandalonePasswordAuthenticatedPrincipalProof proof;
    assert(!proof.bind(
        acceptor, credentialOwner, observation.generation,
        inactiveConnection));
    assert(proof.authenticationKind() ==
           NativeDesktopAuthenticationKind::StandalonePassword);
    assert(proof.authenticationGeneration() == 0U);
    assert(!proof.revalidatesAuthenticatedSession());
    assert(acceptor.stage() == StandaloneCredSspStage::Unconfigured);
}

void testAuthInfoCredentialMismatchRevokes()
{
    const auto runMismatch = [](
        std::u16string_view domain,
        std::u16string_view user,
        std::u16string_view delegatedPassword)
    {
        MemoryTlsPair tls;
        TsRequestFrameReader reader;
        TsRequestTlsReplyWriter writer;
        EphemeralNtlmV2Credential serverCredential;
        configureServerCredential(serverCredential);
        StandaloneCredSspNtlmAcceptor acceptor;
        NtlmV2SecurityContext clientSecurity;
        completeBindingForAuthInfo(
            acceptor, serverCredential, clientSecurity,
            tls, reader, writer);

        const auto credentials =
            passwordCredentials(
                domain, user, delegatedPassword);
        const auto protectedAuthInfo =
            protectAuthInfo(clientSecurity, credentials);
        const auto request =
            authInfoRequest(protectedAuthInfo);
        tls.sendClient(request);
        tls.readServerFrame(reader);

        assert(acceptor.processCompleteFrame(
                   reader, writer, serverCredential) ==
               StandaloneCredSspFrameStatus::Rejected);
        assert(acceptor.stage() ==
               StandaloneCredSspStage::Failed);
        assert(acceptor.failureStage() ==
               StandaloneAuthenticationFailureStage::AuthInfo);
        assert(reader.status() == TsRequestFrameStatus::Closed);
        assert(writer.status() == TsRequestTlsWriteStatus::Closed);
    };

    runMismatch({}, u"Other", u"Password");
    runMismatch({}, u"User", u"Passw0rd");
    runMismatch(u"Domain", u"User", u"Password");
}

void testAuthInfoTamperRevokes()
{
    MemoryTlsPair tls;
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    EphemeralNtlmV2Credential serverCredential;
    configureServerCredential(serverCredential);
    StandaloneCredSspNtlmAcceptor acceptor;
    NtlmV2SecurityContext clientSecurity;
    completeBindingForAuthInfo(
        acceptor, serverCredential, clientSecurity,
        tls, reader, writer);

    const auto credentials =
        passwordCredentials({}, u"User", u"Password");
    auto protectedAuthInfo =
        protectAuthInfo(clientSecurity, credentials);
    assert(protectedAuthInfo.size() > kNtlmMessageSignatureBytes);
    protectedAuthInfo[kNtlmMessageSignatureBytes + 3U] ^= 0x01U;

    const auto request =
        authInfoRequest(protectedAuthInfo);
    tls.sendClient(request);
    tls.readServerFrame(reader);
    assert(acceptor.processCompleteFrame(
               reader, writer, serverCredential) ==
           StandaloneCredSspFrameStatus::Rejected);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::Failed);
    assert(acceptor.failureStage() ==
           StandaloneAuthenticationFailureStage::SignSeal);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
}

void testManualFrameProvenanceDenial()
{
    EphemeralNtlmV2Credential credential;
    configureServerCredential(credential);
    StandaloneCredSspNtlmAcceptor acceptor;
    assert(acceptor.configureChallenge(
        {kServerChallenge, u"Domain", u"Server",
         kTimestamp}));

    const auto request = wrap(
        0x30U,
        append(
            version(6U),
            tokens(initialSpnego(negotiateMessage()))));
    TsRequestFrameReader reader;
    TsRequestTlsReplyWriter writer;
    assert(reader.consume(request).status ==
           TsRequestFrameStatus::Complete);
    assert(reader.completedFrameServerTls() == nullptr);
    assert(acceptor.processCompleteFrame(
               reader, writer, credential) ==
           StandaloneCredSspFrameStatus::Rejected);
    assert(acceptor.stage() ==
           StandaloneCredSspStage::Failed);
    assert(acceptor.failureStage() ==
           StandaloneAuthenticationFailureStage::Spnego);
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(writer.status() == TsRequestTlsWriteStatus::Closed);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};

    if (testCase == "r9-standalone-credssp-tsrequest-v5-v6-ntlm-challenge")
    {
        // Both CredSSP TSRequest versions cross the actual in-memory TLS
        // record reader and R2 SPNEGO acceptor, including NTLM Type 2 output.
        // This does not substitute for the listener's owned R1 socket or a
        // captured unmodified Windows-client NegTokenInit2.
        for (const std::uint8_t requestVersion : {5U, 6U})
        {
            MemoryTlsPair tls;
            TsRequestFrameReader reader;
            TsRequestTlsReplyWriter writer;
            EphemeralNtlmV2Credential serverCredential;
            configureServerCredential(serverCredential);
            StandaloneCredSspNtlmAcceptor acceptor;
            prepareInitialNegotiation(
                acceptor, serverCredential, tls, reader, writer,
                requestVersion);
            assert(acceptor.lastSpnegoStatus() ==
                   StandaloneSpnegoStatus::Continue);
        }
        return 0;
    }
    if (testCase ==
        "standalone-credssp-tls-bound-combined-pubkeyauth")
    {
        testTlsBoundCombinedPubKeyAuth();
        return 0;
    }
    if (testCase ==
        "standalone-credssp-pubkeyauth-tamper-revokes")
    {
        testPubKeyAuthTamperRevokes();
        return 0;
    }
    if (testCase ==
        "standalone-credssp-authinfo-exact-credential-match")
    {
        testAuthInfoExactCredentialMatch();
        return 0;
    }
    if (testCase ==
        "standalone-credssp-direct-tls-cannot-bind-admission-proof")
    {
        testDirectTlsCannotBindAdmissionProof();
        return 0;
    }
    if (testCase ==
        "standalone-credssp-authinfo-credential-mismatch-revokes")
    {
        testAuthInfoCredentialMismatchRevokes();
        return 0;
    }
    if (testCase ==
        "standalone-credssp-authinfo-tamper-revokes")
    {
        testAuthInfoTamperRevokes();
        return 0;
    }
    if (testCase ==
        "standalone-credssp-manual-frame-provenance-denial")
    {
        testManualFrameProvenanceDenial();
        return 0;
    }
    return 2;
}
