// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/mac_runtime_host_control.h"
#include "server/security/credssp_binding.h"
#include "server/security/standalone_credssp.h"
#include "server/security/standalone_ntlmssp.h"
#include "ntlm_type2_conformance.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

using namespace rdp_server::server::runtime;
using rdp_server::server::security::ConsoleAccountObservation;
using rdp_server::server::security::ConsoleDesktopLockState;
using rdp_server::server::security::ConsoleEvidenceReadStatus;
using rdp_server::server::security::ConsoleOsEvidenceSource;
using rdp_server::server::security::ConsoleSessionObservation;
using rdp_server::server::security::LanCredentialChoice;

namespace rdp_server::server::security
{

// Test-only mirror of the already-derived server NTLMv2 signing/sealing state.
// It creates no production admission and never escapes this test process.
struct StandaloneNtlmV2TestAccess
{
    static void activateClientMirror(
        const NtlmV2SecurityContext& serverPerspective,
        NtlmV2SecurityContext& clientPerspective) noexcept
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

struct StandaloneVisitObservation final
{
    bool visited{};
};

[[nodiscard]] bool observeStandaloneCredential(
    const rdp_server::server::security::EphemeralNtlmV2Credential& credential,
    void* rawContext) noexcept
{
    auto* observation = static_cast<StandaloneVisitObservation*>(rawContext);
    if (observation == nullptr)
        return false;
    observation->visited = credential.configured();
    return observation->visited;
}

[[nodiscard]] std::array<char16_t, 8> standalonePassword()
{
    return {u'P', u'a', u's', u's', u'w', u'o', u'r', u'd'};
}


using Bytes = std::vector<std::uint8_t>;
using ByteSpan = std::span<const std::uint8_t>;
using EvpMacPointer = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using EvpMacContextPointer =
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;
using SslContextPointer =
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPointer = std::unique_ptr<SSL, decltype(&SSL_free)>;
using CertificatePointer = std::unique_ptr<X509, decltype(&X509_free)>;

using namespace rdp_server::server::security;

constexpr std::uint32_t kDirectTypeOneFlags =
    kNtlmNegotiateUnicode | kNtlmRequestTarget |
    kNtlmNegotiateNtlm | kNtlmNegotiateAlwaysSign |
    kRequiredStandaloneCredSspNtlmFlags | kNtlmNegotiate56;

void storeLe16(std::uint8_t* bytes, std::uint16_t value) noexcept
{
    bytes[0] = static_cast<std::uint8_t>(value);
    bytes[1] = static_cast<std::uint8_t>(value >> 8U);
}

void storeLe32(std::uint8_t* bytes, std::uint32_t value) noexcept
{
    bytes[0] = static_cast<std::uint8_t>(value);
    bytes[1] = static_cast<std::uint8_t>(value >> 8U);
    bytes[2] = static_cast<std::uint8_t>(value >> 16U);
    bytes[3] = static_cast<std::uint8_t>(value >> 24U);
}

[[nodiscard]] Bytes derLength(std::size_t length)
{
    if (length < 128U)
        return {static_cast<std::uint8_t>(length)};
    if (length < 256U)
        return {0x81U, static_cast<std::uint8_t>(length)};
    if (length > 65535U)
        return {};
    return {
        0x82U,
        static_cast<std::uint8_t>(length >> 8U),
        static_cast<std::uint8_t>(length)};
}

[[nodiscard]] Bytes wrap(std::uint8_t tag, ByteSpan value)
{
    const Bytes encodedLength = derLength(value.size());
    if (encodedLength.empty())
        return {};

    const std::size_t prefixBytes = 1U + encodedLength.size();
    if (value.size() > kMaximumCredSspRequestBytes - prefixBytes)
        return {};

    Bytes output(prefixBytes + value.size());
    output[0] = tag;
    std::copy(
        encodedLength.begin(), encodedLength.end(), output.begin() + 1);
    std::copy(
        value.begin(), value.end(),
        output.begin() + static_cast<std::ptrdiff_t>(prefixBytes));
    return output;
}

[[nodiscard]] Bytes append(Bytes first, ByteSpan second)
{
    if (first.size() > kMaximumCredSspRequestBytes ||
        second.size() > kMaximumCredSspRequestBytes - first.size())
    {
        return {};
    }
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

[[nodiscard]] Bytes version(std::uint8_t value)
{
    const std::array<std::uint8_t, 1U> encoded{value};
    return wrap(0xa0U, wrap(0x02U, encoded));
}

[[nodiscard]] Bytes tokens(ByteSpan token)
{
    return wrap(
        0xa1U,
        wrap(0x30U, wrap(0x30U, wrap(0xa0U, wrap(0x04U, token)))));
}

[[nodiscard]] Bytes octetContext(std::uint8_t tag, ByteSpan value)
{
    return wrap(tag, wrap(0x04U, value));
}

[[nodiscard]] Bytes initialTokenRequest(ByteSpan token)
{
    return wrap(0x30U, append(version(6U), tokens(token)));
}

[[nodiscard]] Bytes combinedFinalRequest(
    ByteSpan token,
    ByteSpan protectedBinding,
    ByteSpan nonce)
{
    Bytes fields = append(version(6U), tokens(token));
    fields = append(std::move(fields), octetContext(0xa3U, protectedBinding));
    fields = append(std::move(fields), octetContext(0xa5U, nonce));
    return wrap(0x30U, fields);
}

[[nodiscard]] Bytes utf16Le(std::u16string_view text)
{
    Bytes bytes;
    bytes.reserve(text.size() * 2U);
    for (const char16_t character : text)
    {
        const std::uint16_t code = static_cast<std::uint16_t>(character);
        bytes.emplace_back(static_cast<std::uint8_t>(code));
        bytes.emplace_back(static_cast<std::uint8_t>(code >> 8U));
    }
    return bytes;
}

[[nodiscard]] Bytes passwordCredentials()
{
    const Bytes emptyDomain;
    Bytes fields = octetContext(0xa0U, emptyDomain);
    const Bytes user = utf16Le(u"rdp");
    fields = append(std::move(fields), octetContext(0xa1U, user));
    const auto passwordStorage = standalonePassword();
    const std::u16string_view passwordView{
        passwordStorage.data(), passwordStorage.size()};
    const Bytes password = utf16Le(passwordView);
    fields = append(std::move(fields), octetContext(0xa2U, password));

    const Bytes passwordCreds = wrap(0x30U, fields);
    const std::array<std::uint8_t, 1U> passwordType{1U};
    const Bytes type = wrap(0xa0U, wrap(0x02U, passwordType));
    return wrap(
        0x30U,
        append(type, octetContext(0xa1U, passwordCreds)));
}

[[nodiscard]] Bytes authInfoRequest(ByteSpan protectedAuthInfo)
{
    return wrap(
        0x30U,
        append(version(6U), octetContext(0xa2U, protectedAuthInfo)));
}

[[nodiscard]] std::array<std::uint8_t, 40U> directTypeOne()
{
    std::array<std::uint8_t, 40U> message{};
    constexpr std::array<std::uint8_t, 8U> signature{
        'N','T','L','M','S','S','P',0};
    std::copy(signature.begin(), signature.end(), message.begin());
    message[8] = 1U;
    storeLe32(message.data() + 12U, kDirectTypeOneFlags);
    return message;
}

[[nodiscard]] bool hmacMd5(
    const NtlmV2Key& key,
    std::span<const ByteSpan> parts,
    NtlmV2Key& output) noexcept
{
    output.fill(0U);
    EvpMacPointer mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr), EVP_MAC_free);
    if (!mac)
        return false;
    EvpMacContextPointer context(
        EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
    if (!context)
        return false;

    char digestName[] = "MD5";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, digestName, 0U),
        OSSL_PARAM_construct_end()};
    if (EVP_MAC_init(
            context.get(), key.data(), key.size(), parameters) != 1)
    {
        return false;
    }

    for (const ByteSpan part : parts)
    {
        if (!part.empty() &&
            EVP_MAC_update(context.get(), part.data(), part.size()) != 1)
        {
            return false;
        }
    }

    std::size_t outputBytes = 0U;
    return EVP_MAC_final(
               context.get(), output.data(), &outputBytes,
               output.size()) == 1 &&
           outputBytes == output.size();
}

using ParsedTypeTwo =
    rdp_server::tests::ntlm_type2_conformance::ParsedChallenge;

[[nodiscard]] std::optional<ParsedTypeTwo> parseDirectTypeTwo(
    ByteSpan message)
{
    ParsedTypeTwo parsed;
    if (!rdp_server::tests::ntlm_type2_conformance::
            parseConformantChallenge(message, parsed))
    {
        return std::nullopt;
    }
    return parsed;
}

void writeSecurityBuffer(
    Bytes& message,
    std::size_t descriptorOffset,
    std::uint16_t bytes,
    std::uint32_t payloadOffset)
{
    assert(descriptorOffset + 8U <= message.size());
    storeLe16(message.data() + descriptorOffset, bytes);
    storeLe16(message.data() + descriptorOffset + 2U, bytes);
    storeLe32(message.data() + descriptorOffset + 4U, payloadOffset);
}

[[nodiscard]] std::optional<Bytes> makeDirectTypeThree(
    const ParsedTypeTwo& challenge,
    NtlmV2SecurityContext& clientSecurity)
{
    EphemeralNtlmV2Credential credential;
    auto password = standalonePassword();
    if (!credential.configure(u"rdp", password))
        return std::nullopt;

    NtlmV2Key responseKey{};
    if (!credential.deriveResponseKeyNt(u"", responseKey))
        return std::nullopt;

    Bytes blob(28U, 0U);
    blob[0] = 1U;
    blob[1] = 1U;
    for (std::size_t index = 0U; index < 8U; ++index)
        blob[16U + index] = static_cast<std::uint8_t>(0xa0U + index);
    blob.insert(
        blob.end(), challenge.targetInfo.begin(), challenge.targetInfo.end());
    blob.insert(blob.end(), 4U, 0U);

    NtlmV2Key proof{};
    const std::array<ByteSpan, 2U> proofParts{
        ByteSpan{challenge.challenge}, ByteSpan{blob}};
    if (!hmacMd5(responseKey, proofParts, proof))
        return std::nullopt;

    Bytes ntResponse;
    ntResponse.reserve(proof.size() + blob.size());
    ntResponse.insert(ntResponse.end(), proof.begin(), proof.end());
    ntResponse.insert(ntResponse.end(), blob.begin(), blob.end());

    const Bytes user = utf16Le(u"rdp");
    constexpr std::size_t kHeaderBytes = 72U;
    const std::size_t userOffset = kHeaderBytes;
    const std::size_t ntResponseOffset = userOffset + user.size();
    const std::size_t totalBytes = ntResponseOffset + ntResponse.size();
    if (user.size() > 0xffffU ||
        ntResponse.size() > 0xffffU ||
        totalBytes > kMaximumStandaloneNtlmMessageBytes)
    {
        return std::nullopt;
    }

    Bytes authenticate(totalBytes, 0U);
    constexpr std::array<std::uint8_t, 8U> signature{
        'N','T','L','M','S','S','P',0};
    std::copy(signature.begin(), signature.end(), authenticate.begin());
    storeLe32(authenticate.data() + 8U, 3U);
    writeSecurityBuffer(
        authenticate, 12U, 0U,
        static_cast<std::uint32_t>(kHeaderBytes));
    writeSecurityBuffer(
        authenticate, 20U,
        static_cast<std::uint16_t>(ntResponse.size()),
        static_cast<std::uint32_t>(ntResponseOffset));
    writeSecurityBuffer(
        authenticate, 28U, 0U,
        static_cast<std::uint32_t>(kHeaderBytes));
    writeSecurityBuffer(
        authenticate, 36U,
        static_cast<std::uint16_t>(user.size()),
        static_cast<std::uint32_t>(userOffset));
    writeSecurityBuffer(
        authenticate, 44U, 0U,
        static_cast<std::uint32_t>(ntResponseOffset));
    writeSecurityBuffer(
        authenticate, 52U, 0U,
        static_cast<std::uint32_t>(totalBytes));

    const std::uint32_t flags =
        challenge.flags & ~kNtlmNegotiateKeyExchange;
    storeLe32(authenticate.data() + 60U, flags);
    std::copy(
        user.begin(), user.end(),
        authenticate.begin() + static_cast<std::ptrdiff_t>(userOffset));
    std::copy(
        ntResponse.begin(), ntResponse.end(),
        authenticate.begin() +
            static_cast<std::ptrdiff_t>(ntResponseOffset));

    NtlmAuthenticateMessage parsed;
    if (parseNtlmAuthenticateMessage(authenticate, parsed) !=
        NtlmMessageParseResult::Parsed)
    {
        return std::nullopt;
    }

    NtlmV2SecurityContext serverPerspective;
    if (credential.verifyAndDeriveSecurityContext(
            parsed.verificationRequest(challenge.challenge),
            serverPerspective) != NtlmV2VerifyResult::Verified)
    {
        return std::nullopt;
    }
    rdp_server::server::security::StandaloneNtlmV2TestAccess::
        activateClientMirror(serverPerspective, clientSecurity);
    return clientSecurity.active()
        ? std::optional<Bytes>{std::move(authenticate)}
        : std::nullopt;
}

[[nodiscard]] std::array<std::uint8_t, kCredSspNonceBytes>
clientNonce(std::uint8_t seed) noexcept
{
    std::array<std::uint8_t, kCredSspNonceBytes> nonce{};
    for (std::size_t index = 0U; index < nonce.size(); ++index)
        nonce[index] = static_cast<std::uint8_t>(seed + index);
    return nonce;
}

[[nodiscard]] std::optional<CredSspHash> tlsBindingHash(
    SSL* tls,
    CredSspBindingDirection direction,
    ByteSpan nonce)
{
    CertificatePointer certificate(
        SSL_get1_peer_certificate(tls), X509_free);
    if (!certificate)
        return std::nullopt;

    const ASN1_BIT_STRING* bits =
        X509_get0_pubkey_bitstr(certificate.get());
    if (bits == nullptr)
        return std::nullopt;

#if !defined(LIBRESSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x40100000L
    const std::size_t publicKeyBytes = ASN1_STRING_get_length(bits);
    const unsigned char* publicKey = ASN1_STRING_get0_data(bits);
    if (publicKeyBytes == 0U ||
        publicKeyBytes > kMaximumCredSspPublicKeyBytes ||
        publicKey == nullptr)
    {
        return std::nullopt;
    }
#else
    const int signedPublicKeyBytes = ASN1_STRING_length(bits);
    const unsigned char* publicKey = ASN1_STRING_get0_data(bits);
    if (signedPublicKeyBytes <= 0 ||
        signedPublicKeyBytes >
            static_cast<int>(kMaximumCredSspPublicKeyBytes) ||
        publicKey == nullptr)
    {
        return std::nullopt;
    }
    const std::size_t publicKeyBytes =
        static_cast<std::size_t>(signedPublicKeyBytes);
#endif

    CredSspHash hash{};
    if (!computeCredSspBindingHash(
            direction, nonce,
            ByteSpan{publicKey, publicKeyBytes}, hash))
    {
        return std::nullopt;
    }
    return hash;
}

[[nodiscard]] std::optional<Bytes> protectClientMessage(
    NtlmV2SecurityContext& clientSecurity,
    ByteSpan plaintext)
{
    if (plaintext.empty())
        return std::nullopt;

    Bytes ciphertext(plaintext.size());
    std::array<std::uint8_t, kNtlmMessageSignatureBytes> signature{};
    if (clientSecurity.wrapServerMessage(
            plaintext, ciphertext, signature) !=
        NtlmMessageSecurityResult::Processed)
    {
        return std::nullopt;
    }

    Bytes protectedBytes;
    protectedBytes.reserve(signature.size() + ciphertext.size());
    protectedBytes.insert(
        protectedBytes.end(), signature.begin(), signature.end());
    protectedBytes.insert(
        protectedBytes.end(), ciphertext.begin(), ciphertext.end());
    return protectedBytes;
}

[[nodiscard]] bool verifyServerBindingReply(
    SSL* tls,
    NtlmV2SecurityContext& clientSecurity,
    ByteSpan nonce,
    ByteSpan reply)
{
    const auto parsed = parseCredSspTsRequest(reply);
    if (!parsed || !parsed.value.hasPubKeyAuth ||
        parsed.value.tokenCount != 0U)
    {
        return false;
    }

    const ByteSpan protectedServer = parsed.value.encryptedPubKeyAuth;
    if (protectedServer.size() !=
        kNtlmMessageSignatureBytes + kCredSspBindingHashBytes)
    {
        return false;
    }

    const std::span<const std::uint8_t, kNtlmMessageSignatureBytes> signature{
        protectedServer.data(), kNtlmMessageSignatureBytes};
    const ByteSpan ciphertext =
        protectedServer.subspan(kNtlmMessageSignatureBytes);
    CredSspHash plaintext{};
    if (clientSecurity.unwrapClientMessage(
            ciphertext, signature, plaintext) !=
        NtlmMessageSecurityResult::Processed)
    {
        return false;
    }

    const auto expected = tlsBindingHash(
        tls, CredSspBindingDirection::ServerToClient, nonce);
    return expected.has_value() &&
           std::equal(
               expected->begin(), expected->end(), plaintext.begin());
}

[[nodiscard]] std::optional<std::size_t> derFrameBytes(
    ByteSpan bytes) noexcept
{
    if (bytes.size() < 2U || bytes[0] != 0x30U)
        return std::nullopt;

    const std::uint8_t lengthByte = bytes[1];
    if ((lengthByte & 0x80U) == 0U)
        return 2U + lengthByte;

    const std::uint8_t lengthBytes =
        static_cast<std::uint8_t>(lengthByte & 0x7fU);
    if (lengthBytes == 0U || lengthBytes > 2U ||
        bytes.size() < 2U + lengthBytes)
    {
        return std::nullopt;
    }

    std::size_t contentBytes = 0U;
    for (std::size_t index = 0U; index < lengthBytes; ++index)
        contentBytes = (contentBytes << 8U) | bytes[2U + index];
    if (contentBytes < 128U)
        return std::nullopt;
    return 2U + lengthBytes + contentBytes;
}

class NetworkTlsClient final
{
public:
    NetworkTlsClient() = default;
    ~NetworkTlsClient()
    {
        tls_.reset();
        context_.reset();
        if (descriptor_ >= 0)
            (void)::close(descriptor_);
    }

    NetworkTlsClient(const NetworkTlsClient&) = delete;
    NetworkTlsClient& operator=(const NetworkTlsClient&) = delete;

    [[nodiscard]] bool connectHybrid(
        std::string_view ipAddress,
        std::uint16_t port,
        std::atomic<bool>& tcpConnected)
    {
        descriptor_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (descriptor_ < 0)
            return false;

        timeval deadline{3, 0};
        (void)::setsockopt(
            descriptor_, SOL_SOCKET, SO_RCVTIMEO,
            &deadline, sizeof(deadline));
        (void)::setsockopt(
            descriptor_, SOL_SOCKET, SO_SNDTIMEO,
            &deadline, sizeof(deadline));

        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port);
        const std::string address(ipAddress);
        if (::inet_pton(
                AF_INET, address.c_str(), &endpoint.sin_addr) != 1 ||
            ::connect(
                descriptor_,
                reinterpret_cast<sockaddr*>(&endpoint),
                sizeof(endpoint)) != 0)
        {
            return false;
        }
        tcpConnected.store(true, std::memory_order_release);

        constexpr std::array<unsigned char, 19U> hybridRequest{
            0x03,0x00,0x00,0x13,0x0e,0xe0,0,0,0,0,0,
            0x01,0x00,0x08,0x00,0x02,0,0,0};
        std::array<unsigned char, 19U> confirmation{};
        if (::send(
                descriptor_, hybridRequest.data(), hybridRequest.size(), 0) !=
                static_cast<ssize_t>(hybridRequest.size()) ||
            ::recv(
                descriptor_, confirmation.data(), confirmation.size(),
                MSG_WAITALL) !=
                static_cast<ssize_t>(confirmation.size()) ||
            confirmation[0] != 0x03U ||
            confirmation[1] != 0x00U ||
            confirmation[5] != 0xd0U ||
            confirmation[11] != 0x02U ||
            confirmation[12] != 0x00U ||
            confirmation[13] != 0x08U ||
            confirmation[14] != 0x00U ||
            confirmation[15] != 0x02U)
        {
            return false;
        }

        context_.reset(SSL_CTX_new(TLS_client_method()));
        if (!context_)
            return false;
        SSL_CTX_set_verify(context_.get(), SSL_VERIFY_NONE, nullptr);
        tls_.reset(SSL_new(context_.get()));
        if (!tls_ ||
            SSL_set_fd(tls_.get(), descriptor_) != 1 ||
            SSL_connect(tls_.get()) != 1)
        {
            return false;
        }

        CertificatePointer certificate(
            SSL_get1_peer_certificate(tls_.get()), X509_free);
        return certificate != nullptr &&
               SSL_is_init_finished(tls_.get()) == 1;
    }

    [[nodiscard]] SSL* tls() noexcept
    {
        return tls_.get();
    }

    [[nodiscard]] bool writeFrame(ByteSpan bytes) noexcept
    {
        if (!tls_ || bytes.empty())
            return false;

        std::size_t offset = 0U;
        for (std::size_t attempt = 0U;
             attempt < 4096U && offset < bytes.size();
             ++attempt)
        {
            std::size_t written = 0U;
            const int result = SSL_write_ex(
                tls_.get(), bytes.data() + offset,
                bytes.size() - offset, &written);
            if (result == 1)
            {
                if (written == 0U)
                    return false;
                offset += written;
                continue;
            }

            const int error = SSL_get_error(tls_.get(), result);
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE)
            {
                return false;
            }
        }
        return offset == bytes.size();
    }

    [[nodiscard]] std::optional<Bytes> readFrame() noexcept
    {
        if (!tls_)
            return std::nullopt;

        Bytes frame;
        frame.reserve(1024U);
        std::array<std::uint8_t, kMaximumCredSspRequestBytes> buffer{};
        std::optional<std::size_t> expected;
        for (std::size_t attempt = 0U; attempt < 4096U; ++attempt)
        {
            if (expected.has_value() && frame.size() == *expected)
            {
                if (parseCredSspTsRequest(frame))
                    return frame;
                return std::nullopt;
            }
            if (frame.size() >= kMaximumCredSspRequestBytes)
                return std::nullopt;

            std::size_t read = 0U;
            const int result = SSL_read_ex(
                tls_.get(), buffer.data(),
                buffer.size() - frame.size(), &read);
            if (result == 1)
            {
                if (read == 0U)
                    return std::nullopt;
                frame.insert(
                    frame.end(), buffer.begin(),
                    buffer.begin() +
                        static_cast<std::ptrdiff_t>(read));
                if (!expected.has_value())
                    expected = derFrameBytes(frame);
                if (expected.has_value() &&
                    (*expected > kMaximumCredSspRequestBytes ||
                     frame.size() > *expected))
                {
                    return std::nullopt;
                }
                continue;
            }

            const int error = SSL_get_error(tls_.get(), result);
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE)
            {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

private:
    int descriptor_{-1};
    SslContextPointer context_{nullptr, SSL_CTX_free};
    SslPointer tls_{nullptr, SSL_free};
};

[[nodiscard]] Bytes loadMicrosoftMcsConnectInitialFixture()
{
    std::ifstream input{RDP_R3_MICROSOFT_MCS_FIXTURE_PATH};
    assert(input.good());

    Bytes packet;
    packet.reserve(416U);
    std::string line;
    while (std::getline(input, line))
    {
        if (line.empty() || line.front() == '#')
            continue;

        std::istringstream bytes{line};
        unsigned int value = 0U;
        while (bytes >> std::hex >> value)
        {
            assert(value <= 255U);
            packet.emplace_back(static_cast<std::uint8_t>(value));
        }
        assert(bytes.eof());
    }

    assert(packet.size() == 416U);
    assert(packet[0] == 0x03U);
    assert(packet[1] == 0x00U);
    assert(packet[2] == 0x01U);
    assert(packet[3] == 0xa0U);
    return packet;
}

struct CompletedCredSspPeerGate final
{
    std::atomic<bool> tcpConnected{};
    std::atomic<bool> authInfoSent{};
    std::atomic<bool> firstMcsQueued{};
    std::atomic<bool> release{};
    std::atomic<bool> finished{};
};

struct CompletedCredSspPeerResult final
{
    bool directTypeTwoReceived{};
    bool bindingVerified{};
    bool completed{};
};

[[nodiscard]] bool waitForRelease(
    const std::atomic<bool>& release) noexcept
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{8};
    while (!release.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    return release.load(std::memory_order_acquire);
}

[[nodiscard]] CompletedCredSspPeerResult runCompletedCredSspPeer(
    std::string_view address,
    std::uint16_t port,
    std::uint8_t nonceSeed,
    CompletedCredSspPeerGate& gate) noexcept
{
    CompletedCredSspPeerResult result;
    NetworkTlsClient client;
    if (!client.connectHybrid(address, port, gate.tcpConnected))
        return result;

    const auto negotiate = directTypeOne();
    const Bytes initialRequest = initialTokenRequest(negotiate);
    if (!client.writeFrame(initialRequest))
        return result;

    const auto challengeFrame = client.readFrame();
    if (!challengeFrame)
        return result;
    const auto parsedChallengeFrame =
        parseCredSspTsRequest(*challengeFrame);
    if (!parsedChallengeFrame ||
        parsedChallengeFrame.value.tokenCount != 1U)
    {
        return result;
    }

    const auto challenge =
        parseDirectTypeTwo(parsedChallengeFrame.value.tokens[0]);
    if (!challenge)
        return result;
    result.directTypeTwoReceived = true;

    NtlmV2SecurityContext clientSecurity;
    const auto authenticate =
        makeDirectTypeThree(*challenge, clientSecurity);
    if (!authenticate)
        return result;

    const auto nonce = clientNonce(nonceSeed);
    const auto clientBinding = tlsBindingHash(
        client.tls(), CredSspBindingDirection::ClientToServer, nonce);
    if (!clientBinding)
        return result;
    const auto protectedBinding =
        protectClientMessage(clientSecurity, *clientBinding);
    if (!protectedBinding)
        return result;

    const Bytes finalRequest = combinedFinalRequest(
        *authenticate, *protectedBinding, nonce);
    if (!client.writeFrame(finalRequest))
        return result;

    const auto bindingReply = client.readFrame();
    if (!bindingReply ||
        !verifyServerBindingReply(
            client.tls(), clientSecurity, nonce, *bindingReply))
    {
        return result;
    }
    result.bindingVerified = true;

    const Bytes credentials = passwordCredentials();
    const auto protectedCredentials =
        protectClientMessage(clientSecurity, credentials);
    if (!protectedCredentials)
        return result;
    const Bytes authInfo = authInfoRequest(*protectedCredentials);
    if (!client.writeFrame(authInfo))
        return result;
    gate.authInfoSent.store(true, std::memory_order_release);

    // Queue one real published Microsoft Connect-Initial immediately after
    // final authInfo. R10 must leave it unread while no genuine R2 admission
    // exists, even though the exact CredSSP proof is now valid.
    const Bytes microsoftConnectInitial =
        loadMicrosoftMcsConnectInitialFixture();
    if (!client.writeFrame(microsoftConnectInitial))
        return result;
    gate.firstMcsQueued.store(true, std::memory_order_release);

    result.completed = waitForRelease(gate.release);
    return result;
}

enum class CompletedCredSspRetirement : std::uint8_t
{
    Stop,
    ConsentEpochReplacement,
    SessionReplacement,
    ExplicitClientDisconnect,
};

class PortableBootstrapEvidence final : public ConsoleOsEvidenceSource
{
public:
    explicit PortableBootstrapEvidence(std::uint32_t uid) noexcept : uid_(uid) {}

    ConsoleAccountObservation readUnixAccount(std::string_view) noexcept override
    {
        return {};
    }

    ConsoleSessionObservation readActiveConsole() noexcept override
    {
        return {
            ConsoleEvidenceReadStatus::Observed,
            "mac-bootstrap-session",
            "seat0",
            ":0",
            uid_,
            sessionGeneration_,
            now_,
            true,
            true,
            uid_,
            ConsoleDesktopLockState::Unlocked,
            false};
    }

    std::optional<std::uint64_t> readMonotonicMilliseconds() noexcept override
    {
        return now_;
    }

    void replaceSession() noexcept
    {
        ++sessionGeneration_;
    }

private:
    std::uint32_t uid_{501U};
    std::uint64_t now_{10'000U};
    std::uint64_t sessionGeneration_{91U};
};

void testInitialProductProjection()
{
    MacRuntimeHostControl control;
    const auto snapshot = control.status();
    assert(snapshot.stage == RuntimeHostStage::Stopped);
    assert(snapshot.product.controlAvailable);
    assert(snapshot.product.credentialEditingAllowed);
    assert(snapshot.product.automaticRuntimeProvisioned);
    assert(snapshot.product.nativeDesktopTargetAvailable);
    assert(snapshot.product.nativeDesktopTarget == "macOS ScreenCaptureKit Desktop");
    assert(snapshot.product.credentialCapabilities
               .standalonePasswordConfigurationAvailable);
    assert(!snapshot.product.credentialCapabilities.standalonePassword);
    assert(!snapshot.credentialsConfigured);
    assert(!snapshot.hostOwnerAuthorized);
    assert(!snapshot.listenerAvailable);
    assert(snapshot.product.state == RuntimeProductHostState::Stopped);
}

void testAutomaticLicensingPrestartNoListener()
{
    MacRuntimeHostControl control;

    const auto before = control.status();
    assert(before.product.automaticRuntimeProvisioned);
    assert(before.product.readinessStage ==
           RuntimeProductReadinessStage::Provisioned);
    assert(before.stage == RuntimeHostStage::Stopped);
    assert(!before.listenerAvailable);
    assert(before.boundEndpoint.empty());
    assert(before.activeClients.empty());

    const auto idleResult = control.serviceOnce();
    assert(idleResult.succeeded());

    const auto after = control.status();
    assert(after.product.automaticRuntimeProvisioned);
    assert(after.product.readinessStage ==
           RuntimeProductReadinessStage::Provisioned);
    assert(after.stage == RuntimeHostStage::Stopped);
    assert(!after.listenerAvailable);
    assert(after.boundEndpoint.empty());
    assert(after.activeClients.empty());
}

void testStandalonePasswordLifecycle()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    const auto before = control.status();
    assert(before.product.credentialCapabilities
               .standalonePasswordConfigurationAvailable);
    assert(!before.product.credentialCapabilities.standalonePassword);
    assert(!before.credentialsConfigured);
    assert(before.product.sharingPermission.canRequest);
    assert(!before.product.sharingPermission.activeGrant);
    assert(!before.listenerAvailable);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));
    for (const char16_t codeUnit : password)
    {
        assert(codeUnit == u'\0');
    }

    const auto snapshot = control.status();
    assert(snapshot.credentialsConfigured);
    assert(snapshot.stage == RuntimeHostStage::CredentialsConfigured);
    assert(snapshot.product.credentialEditingAllowed);
    assert(snapshot.product.readinessStage == RuntimeProductReadinessStage::CredentialsConfigured);
    assert(snapshot.product.sharingPermission.canRequest);
    assert(!snapshot.product.sharingPermission.activeGrant);
    assert(snapshot.product.sharingPermission.denial ==
           RuntimeSharingPermissionDenial::PermissionRequired);
    assert(!snapshot.listenerAvailable);

    StandaloneVisitObservation observed;
    assert(control.visitStandaloneApplicationPassword(
        control.standaloneApplicationPasswordObservation().generation,
        &observeStandaloneCredential, &observed));
    assert(observed.visited);
}

void testSharingPermissionLifecycle()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(result.succeeded());

    const auto snapshot = control.status();
    assert(snapshot.hostOwnerAuthorized);
    assert(snapshot.product.ownerAuthorized);
    assert(snapshot.product.sharingPermission.activeGrant);
    assert(snapshot.product.sharingPermission.viewAllowed);
    assert(snapshot.product.sharingPermission.inputAllowed);
    assert(snapshot.product.readinessStage == RuntimeProductReadinessStage::PermissionGranted);
}

void testStopRevokeRetirement()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));
    const auto configuredCredential =
        control.standaloneApplicationPasswordObservation();
    assert(configuredCredential.configured);
    assert(configuredCredential.generation != 0U);

    RuntimeHostPermissionRequest permission;
    assert(control.requestHostPermissionSetup(permission).succeeded());
    assert(control.status().hostOwnerAuthorized);

    assert(control.stopSharing().succeeded());
    const auto stoppedCredential =
        control.standaloneApplicationPasswordObservation();
    const auto stopped = control.status();
    assert(stopped.stage == RuntimeHostStage::Stopped);
    assert(stopped.product.credentialEditingAllowed);
    assert(stopped.credentialsConfigured);
    assert(stopped.product.credentialsConfigured);
    assert(!stopped.hostOwnerAuthorized);
    assert(!stopped.product.ownerAuthorized);
    assert(stoppedCredential.configured);
    assert(stoppedCredential.generation == configuredCredential.generation);

    StandaloneVisitObservation observed;
    assert(control.visitStandaloneApplicationPassword(
        configuredCredential.generation,
        &observeStandaloneCredential, &observed));
    assert(observed.visited);

    assert(control.revokeSharing().succeeded());
    const auto revokedCredential =
        control.standaloneApplicationPasswordObservation();
    assert(!control.status().hostOwnerAuthorized);
    assert(!control.status().product.ownerAuthorized);
    assert(!control.status().credentialsConfigured);
    assert(!control.status().product.credentialsConfigured);
    assert(!revokedCredential.configured);
    assert(revokedCredential.generation > configuredCredential.generation);
    assert(!control.visitStandaloneApplicationPassword(
        configuredCredential.generation,
        &observeStandaloneCredential, &observed));
}

[[nodiscard]] bool testStopStartRetainsStandaloneCredential()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"rdp", password));
    assert(std::ranges::all_of(
        password, [](char16_t value) { return value == u'\0'; }));
    const auto original =
        control.standaloneApplicationPasswordObservation();
    assert(original.configured && original.generation != 0U);

    const auto recommendation =
        control.status().product.recommendedEndpoint;
    if (!recommendation.valid())
        return false;

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;

    std::uint16_t selectedPort = 0U;
    std::uint64_t previousListenerGeneration = 0U;
    for (std::size_t cycle = 0U; cycle < 3U; ++cycle)
    {
        const auto beforePermission = control.status();
        assert(beforePermission.credentialsConfigured);
        assert(beforePermission.product.credentialsConfigured);
        assert(!beforePermission.hostOwnerAuthorized);
        assert(!beforePermission.listenerAvailable);

        if (cycle == 0U)
        {
            // The first listener needs an owner grant before we can distinguish
            // a genuinely occupied candidate port from an authorization denial.
            assert(control.requestHostPermissionSetup(permission).succeeded());
            assert(control.status().hostOwnerAuthorized);

            for (std::uint16_t port = 34300U; port < 34330U; ++port)
            {
                const RuntimeHostOptions options{
                    recommendation.interfaceId, recommendation.address,
                    port, true, false};
                assert(control.configure(options).succeeded());
                const auto prepared = control.status();
                assert(prepared.tlsIdentityReady);
                assert(prepared.tlsIdentity.state ==
                       RuntimeTlsIdentityState::ConfiguredUnbound);
                assert(prepared.tlsIdentity.endpointGeneration == 0U);
                assert(!prepared.listenerAvailable);

                const auto start = control.startSharing();
                if (start.succeeded())
                {
                    selectedPort = port;
                    break;
                }
                assert(start.error == RuntimeHostError::PortUnavailable);
            }
            assert(selectedPort != 0U);
        }
        else
        {
            // Ordinary Stop must kill the previous consent grant. Prepare fresh
            // endpoint-bound TLS state on the same port, then prove that the
            // retained credential alone cannot authorize the next listener.
            const RuntimeHostOptions options{
                recommendation.interfaceId, recommendation.address,
                selectedPort, true, false};
            assert(control.configure(options).succeeded());
            const auto preparedWithoutConsent = control.status();
            assert(preparedWithoutConsent.credentialsConfigured);
            assert(!preparedWithoutConsent.hostOwnerAuthorized);
            assert(preparedWithoutConsent.tlsIdentityReady);
            assert(preparedWithoutConsent.tlsIdentity.state ==
                   RuntimeTlsIdentityState::ConfiguredUnbound);
            assert(preparedWithoutConsent.tlsIdentity.endpointGeneration == 0U);
            assert(!preparedWithoutConsent.listenerAvailable);

            const auto deniedWithoutFreshConsent = control.startSharing();
            assert(deniedWithoutFreshConsent.error ==
                   RuntimeHostError::HostConsentRequired);
            assert(!control.status().hostOwnerAuthorized);
            assert(!control.status().listenerAvailable);
            assert(control.standaloneApplicationPasswordObservation().generation ==
                   original.generation);

            // A2/A3 is explicit and fresh for this Start. The already-prepared
            // TLS identity remains non-authorizing until this grant exists.
            assert(control.requestHostPermissionSetup(permission).succeeded());
            assert(control.status().hostOwnerAuthorized);
            assert(control.startSharing().succeeded());
        }

        const auto live = control.status();
        assert(live.stage == RuntimeHostStage::ListenerAvailable);
        assert(live.listenerAvailable);
        assert(live.listenerGeneration != 0U);
        assert(live.listenerGeneration != previousListenerGeneration);
        assert(live.boundEndpoint == live.selectedEndpoint);
        assert(live.tlsIdentityReady);
        assert(live.tlsIdentity.boundIdentityMatchesGeneration(
            live.listenerGeneration));
        assert(live.hostOwnerAuthorized);
        assert(live.activeClients.empty());
        previousListenerGeneration = live.listenerGeneration;

        assert(control.stopSharing().succeeded());
        const auto stopped = control.status();
        assert(stopped.stage == RuntimeHostStage::Stopped);
        assert(stopped.credentialsConfigured);
        assert(stopped.product.credentialsConfigured);
        assert(!stopped.hostOwnerAuthorized);
        assert(!stopped.product.ownerAuthorized);
        assert(!stopped.listenerAvailable);
        assert(stopped.listenerGeneration == 0U);
        assert(stopped.boundEndpoint.empty());
        assert(stopped.activeClients.empty());
        // MacRuntimeNativeDesktop owns the capture/input capability. A false
        // aggregate readiness observation proves neither native nor input
        // ownership survived the ordinary Stop.
        assert(!stopped.nativeDesktopReady);
        assert(!stopped.tlsIdentityReady);
        assert(!stopped.product.tlsIdentityReady);
        assert(!stopped.tlsIdentity.fingerprintAvailable);

        const auto retained =
            control.standaloneApplicationPasswordObservation();
        assert(retained.configured);
        assert(retained.generation == original.generation);
        StandaloneVisitObservation visited;
        assert(control.visitStandaloneApplicationPassword(
            original.generation, &observeStandaloneCredential, &visited));
        assert(visited.visited);
    }

    assert(control.revokeSharing().succeeded());
    const auto revoked = control.status();
    assert(revoked.stage == RuntimeHostStage::Revoked);
    assert(!revoked.credentialsConfigured);
    assert(!revoked.product.credentialsConfigured);
    assert(!revoked.hostOwnerAuthorized);
    assert(!revoked.listenerAvailable);
    assert(!control.standaloneApplicationPasswordObservation().configured);
    return true;
}


[[nodiscard]] bool assertCompletedCredSspDormantStatus(
    const RuntimeHostStatus& status)
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    return status.stage == RuntimeHostStage::ClientAuthenticating &&
           status.activeClients.size() == 1U &&
           diagnostics.available &&
           diagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::Authenticated &&
           diagnostics.credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::CredentialsVerified &&
           diagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission &&
           !diagnostics.mcsSessionAdvanced &&
           !diagnostics.shareActivated &&
           !status.graphicsReady &&
           !status.nativeDesktopReady &&
           status.clipboardState == RuntimeClipboardState::Unavailable;
}

[[nodiscard]] bool runCompletedCredSspRetirementScenario(
    CompletedCredSspRetirement retirement,
    std::uint16_t firstPort,
    std::uint8_t nonceSeed)
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);
    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"rdp", password));
    const auto credentialBefore =
        control.standaloneApplicationPasswordObservation();
    assert(credentialBefore.configured && credentialBefore.generation != 0U);

    const auto endpoint = control.status().product.recommendedEndpoint;
    if (!endpoint.valid() ||
        endpoint.address.find(':') != std::string::npos)
    {
        return false;
    }

    RuntimeHostPermissionRequest permission;
    permission.allowClipboard = false;
    permission.allowInput = false;
    assert(control.requestHostPermissionSetup(permission).succeeded());

    std::uint16_t chosenPort = 0U;
    for (std::uint16_t port = firstPort;
         port < static_cast<std::uint16_t>(firstPort + 24U);
         ++port)
    {
        const RuntimeHostOptions options{
            endpoint.interfaceId, endpoint.address, port, true, false};
        assert(control.configure(options).succeeded());
        const auto start = control.startSharing();
        if (start.succeeded())
        {
            chosenPort = port;
            break;
        }
        assert(start.error == RuntimeHostError::PortUnavailable);
    }
    if (chosenPort == 0U)
        return false;

    CompletedCredSspPeerGate gate;
    CompletedCredSspPeerResult peerResult;
    std::thread peer([&]() noexcept {
        peerResult = runCompletedCredSspPeer(
            endpoint.address, chosenPort, nonceSeed, gate);
        gate.finished.store(true, std::memory_order_release);
    });

    const auto releaseAndJoin = [&]() noexcept {
        gate.release.store(true, std::memory_order_release);
        if (peer.joinable())
            peer.join();
    };

    const auto authenticationDeadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{8};
    bool authenticated = false;
    while (std::chrono::steady_clock::now() < authenticationDeadline)
    {
        const RuntimeHostResult step = control.serviceOnce();
        if (!step.succeeded())
            break;

        const RuntimeHostStatus status = control.status();
        if (assertCompletedCredSspDormantStatus(status) &&
            gate.authInfoSent.load(std::memory_order_acquire) &&
            gate.firstMcsQueued.load(std::memory_order_acquire))
        {
            authenticated = true;
            break;
        }
        if (gate.finished.load(std::memory_order_acquire))
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }

    if (!authenticated)
    {
        const bool tcpConnected =
            gate.tcpConnected.load(std::memory_order_acquire);
        releaseAndJoin();
        (void)control.stopSharing();
        if (!tcpConnected)
            return false;
        assert(false &&
               "production macOS HostControl did not reach completed CredSSP");
        return false;
    }

    // Re-service after a genuine Microsoft Connect-Initial is already queued.
    // The authenticated proof is valid, but no R2 native admission exists:
    // R10 must not consume first MCS or synthesize R3/native state.
    for (std::size_t index = 0U; index < 8U; ++index)
    {
        assert(control.serviceOnce().succeeded());
        assert(assertCompletedCredSspDormantStatus(control.status()));
    }

    switch (retirement)
    {
    case CompletedCredSspRetirement::ExplicitClientDisconnect:
    {
        // Unlike Stop, this retires the exact accepted R1/R2 connection
        // while keeping its listener and memory-only credential available.
        const auto before = control.status();
        assert(before.activeClients.size() == 1U);
        const std::uint64_t clientId = before.activeClients.front().opaqueId;
        assert(clientId != 0U);
        assert(control.disconnectClient(clientId).succeeded());
        const auto retired = control.status();
        assert(retired.stage == RuntimeHostStage::ListenerAvailable);
        assert(retired.listenerAvailable);
        assert(retired.credentialsConfigured);
        assert(retired.activeClients.empty());
        assert(retired.acceptedClientPreauthDiagnostics.preauthStage ==
               RuntimeAcceptedClientPreauthStage::Closed);
        assert(retired.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!retired.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!retired.acceptedClientPreauthDiagnostics.shareActivated);
        assert(!retired.graphicsReady);
        assert(!retired.nativeDesktopReady);
        assert(retired.clipboardState == RuntimeClipboardState::Unavailable);
        assert(control.disconnectClient(clientId).error ==
               RuntimeHostError::ClientNotFound);
        for (std::size_t index = 0U; index < 8U; ++index)
        {
            assert(control.serviceOnce().succeeded());
            const auto after = control.status();
            assert(after.activeClients.empty());
            assert(!after.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        }
        assert(control.stopSharing().succeeded());
        break;
    }
    case CompletedCredSspRetirement::Stop:
    {
        assert(control.stopSharing().succeeded());
        const auto stopped = control.status();
        assert(stopped.stage == RuntimeHostStage::Stopped);
        assert(!stopped.listenerAvailable);
        assert(stopped.activeClients.empty());
        assert(!stopped.nativeDesktopReady);
        assert(!stopped.graphicsReady);
        assert(stopped.clipboardState == RuntimeClipboardState::Unavailable);
        assert(stopped.acceptedClientPreauthDiagnostics.preauthStage ==
               RuntimeAcceptedClientPreauthStage::Closed);
        assert(stopped.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!stopped.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!stopped.acceptedClientPreauthDiagnostics.shareActivated);

        // A live credential replacement is intentionally forbidden while the
        // listener owns a client. Stop is the required destruction barrier;
        // after it, replacement advances generation and the old proof cannot
        // be visited or revived.
        auto replacementPassword = standalonePassword();
        replacementPassword[0] = u'R';
        assert(control.configureStandaloneApplicationPassword(
            u"rdp", replacementPassword));
        const auto replacement =
            control.standaloneApplicationPasswordObservation();
        assert(replacement.configured);
        assert(replacement.generation != credentialBefore.generation);
        StandaloneVisitObservation staleVisit;
        assert(!control.visitStandaloneApplicationPassword(
            credentialBefore.generation,
            &observeStandaloneCredential, &staleVisit));
        assert(!staleVisit.visited);
        break;
    }
    case CompletedCredSspRetirement::ConsentEpochReplacement:
    {
        assert(control.requestHostPermissionSetup(permission).succeeded());
        const auto step = control.serviceOnce();
        assert(step.error == RuntimeHostError::HostSessionStale);
        const auto retired = control.status();
        assert(retired.stage == RuntimeHostStage::ListenerAvailable);
        assert(retired.listenerAvailable);
        assert(retired.activeClients.empty());
        assert(retired.acceptedClientPreauthDiagnostics.preauthStage ==
               RuntimeAcceptedClientPreauthStage::Closed);
        assert(retired.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!retired.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!retired.acceptedClientPreauthDiagnostics.shareActivated);
        assert(!retired.nativeDesktopReady);
        assert(!retired.graphicsReady);
        assert(retired.clipboardState == RuntimeClipboardState::Unavailable);
        assert(control.stopSharing().succeeded());
        break;
    }
    case CompletedCredSspRetirement::SessionReplacement:
    {
        evidence.replaceSession();
        const auto step = control.serviceOnce();
        assert(step.error == RuntimeHostError::CredentialNotConfigured);
        const auto retired = control.status();
        assert(retired.stage == RuntimeHostStage::Stopped);
        assert(!retired.listenerAvailable);
        assert(retired.activeClients.empty());
        assert(!retired.credentialsConfigured);
        assert(!retired.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!retired.acceptedClientPreauthDiagnostics.shareActivated);
        assert(retired.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!retired.nativeDesktopReady);
        assert(!retired.graphicsReady);
        assert(retired.clipboardState == RuntimeClipboardState::Unavailable);
        break;
    }
    }

    releaseAndJoin();
    assert(peerResult.directTypeTwoReceived);
    assert(peerResult.bindingVerified);
    assert(peerResult.completed);
    assert(gate.authInfoSent.load(std::memory_order_acquire));
    assert(gate.firstMcsQueued.load(std::memory_order_acquire));
    return true;
}

[[nodiscard]] bool testMacCompletedCredSspExplicitClientRetirement()
{
    return runCompletedCredSspRetirementScenario(
        CompletedCredSspRetirement::ExplicitClientDisconnect, 34500U, 0x91U);
}

[[nodiscard]] bool testMacCompletedCredSspWithoutNativeAdmissionDenials()
{
    return runCompletedCredSspRetirementScenario(
               CompletedCredSspRetirement::Stop, 34400U, 0x31U) &&
           runCompletedCredSspRetirementScenario(
               CompletedCredSspRetirement::ConsentEpochReplacement,
               34430U, 0x51U) &&
           runCompletedCredSspRetirementScenario(
               CompletedCredSspRetirement::SessionReplacement,
               34460U, 0x71U);
}

// Only a synthetic local TCP peer is used. This narrower regression stops at
// an incomplete TPKT; the distinct completed-CredSSP case above covers the
// authenticated proof plus queued first-MCS boundary.
[[nodiscard]] bool testMacAcceptedClientPreAdmissionDormancy()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);
    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"rdp", password));

    const auto endpoint = control.status().product.recommendedEndpoint;
    if (!endpoint.valid() || endpoint.address.find(':') != std::string::npos)
        return false;

    RuntimeHostPermissionRequest permission;
    permission.allowClipboard = false;
    permission.allowInput = false;
    assert(control.requestHostPermissionSetup(permission).succeeded());

    std::uint16_t chosenPort = 0U;
    for (std::uint16_t port = 34350U; port < 34380U; ++port)
    {
        const RuntimeHostOptions options{
            endpoint.interfaceId, endpoint.address, port, true, false};
        assert(control.configure(options).succeeded());
        if (control.startSharing().succeeded())
        {
            chosenPort = port;
            break;
        }
    }
    if (chosenPort == 0U)
        return false;

    struct ScopedSocket final
    {
        int descriptor{-1};
        ~ScopedSocket()
        {
            if (descriptor >= 0)
                (void)::close(descriptor);
        }
    } client{::socket(AF_INET, SOCK_STREAM, 0)};
    if (client.descriptor < 0)
        return false;

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(chosenPort);
    if (::inet_pton(AF_INET, endpoint.address.c_str(),
                    &destination.sin_addr) != 1 ||
        ::connect(client.descriptor,
                  reinterpret_cast<const sockaddr*>(&destination),
                  static_cast<socklen_t>(sizeof(destination))) != 0)
        return false;

    assert(control.serviceOnce().succeeded());
    auto accepted = control.status();
    assert(accepted.stage == RuntimeHostStage::ClientAuthenticating);
    assert(accepted.activeClients.size() == 1U);
    assert(accepted.acceptedClientPreauthDiagnostics.available);
    assert(accepted.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    assert(!accepted.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(!accepted.nativeDesktopReady);
    assert(!accepted.graphicsReady);

    // A single incomplete TPKT header cannot advance TLS, MCS or Share.
    constexpr std::array<std::uint8_t, 1U> partialTpkt{0x03U};
    assert(::send(client.descriptor, partialTpkt.data(),
                  partialTpkt.size(), 0) ==
           static_cast<ssize_t>(partialTpkt.size()));
    for (std::size_t index = 0U; index < 4U; ++index)
        assert(control.serviceOnce().succeeded());

    accepted = control.status();
    assert(accepted.stage == RuntimeHostStage::ClientAuthenticating);
    assert(accepted.acceptedClientPreauthDiagnostics.preauthStage ==
           RuntimeAcceptedClientPreauthStage::AwaitConnectionRequest);
    assert(accepted.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    assert(!accepted.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(!accepted.acceptedClientPreauthDiagnostics.shareActivated);
    assert(!accepted.nativeDesktopReady);

    // Stop must free the borrowed R2 frame/SSL in the reverse of their
    // attachment order and cannot retain a client from the old listener.
    assert(control.stopSharing().succeeded());
    const auto stopped = control.status();
    assert(stopped.stage == RuntimeHostStage::Stopped);
    assert(!stopped.listenerAvailable);
    assert(stopped.activeClients.empty());
    assert(!stopped.nativeDesktopReady);
    assert(stopped.acceptedClientPreauthDiagnostics.preauthStage ==
           RuntimeAcceptedClientPreauthStage::Closed);
    assert(!stopped.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(stopped.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    return true;
}

void testPortableGuiBootstrapReadiness()
{
    MacPortableDesktopRuntime runtime;
    auto& control = runtime.hostControl();
    assert(control.status().product.controlAvailable);

    const auto idleResult = runtime.serviceOnce();
    assert(idleResult.succeeded());
}

void testMacLanEndpointRecommendation()
{
    RuntimeHostInterface en0Interface;
    en0Interface.stableId = "en0#15";
    en0Interface.displayName = "en0";
    en0Interface.lanEligible = true;
    en0Interface.localAddresses = {"192.168.1.6"};

    RuntimeHostInterface bridgeInterface;
    bridgeInterface.stableId = "bridge100#24";
    bridgeInterface.displayName = "bridge100";
    bridgeInterface.lanEligible = true;
    bridgeInterface.localAddresses = {"192.168.43.1"};

    const std::vector<RuntimeHostInterface> interfaces{en0Interface, bridgeInterface};

    const std::vector<MacRuntimeDefaultRoutePreference> defaultRoutes{
        {"en0#15", RuntimeHostAddressFamily::Ipv4, 10U}
    };

    const auto withRoute = recommendMacPrivateLanEndpoint(interfaces, defaultRoutes, 3389U);
    assert(!withRoute.ambiguous);
    assert(withRoute.address == "192.168.1.6");
    assert(withRoute.source == RuntimeHostRecommendationSource::PreferredRoute);

    const auto withoutRoute = recommendMacPrivateLanEndpoint(interfaces, {}, 3389U);
    assert(!withoutRoute.ambiguous);
    assert(withoutRoute.address == "192.168.1.6");
}

[[nodiscard]] bool testMacNativeLanEndpointObservation()
{
    MacRuntimeHostControl hostControl;
    const auto status = hostControl.status();
    const auto& recommended = status.product.recommendedEndpoint;
    if (status.product.eligibleLanInterfaces.empty() || !recommended.valid())
        return false;

    assert(!recommended.ambiguous);
    const RuntimeHostOptions selection{
        recommended.interfaceId, recommended.address, recommended.port,
        true, false};
    assert(assessRuntimeSelectedLanEndpoint(
               selection, status.product.eligibleLanInterfaces).succeeded());
    return true;
}

void testScreenRecordingPermissionDenial()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    control.setScreenCaptureProbeForTesting([]() noexcept {
        return rdp::macos::ScreenCapturePreflightStatus::NotGranted;
    });

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(!result.succeeded());
    assert(result.error == RuntimeHostError::NativeAuthorizationDenied);

    const auto status = control.status();
    assert(!status.hostOwnerAuthorized);
    assert(!status.product.ownerAuthorized);
    assert(status.product.lastErrorMessage.find("Screen Recording permission required") != std::string::npos);
}

void testAccessibilityPermissionDenial()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    control.setScreenCaptureProbeForTesting([]() noexcept {
        return rdp::macos::ScreenCapturePreflightStatus::Granted;
    });
    control.setInputPermissionProbeForTesting([]() noexcept {
        return rdp::macos::MacInputPermissionStatus::NotTrusted;
    });

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(!result.succeeded());
    assert(result.error == RuntimeHostError::NativeAuthorizationDenied);

    const auto status = control.status();
    assert(!status.hostOwnerAuthorized);
    assert(!status.product.ownerAuthorized);
    assert(status.product.lastErrorMessage.find("Accessibility permission required") != std::string::npos);
}

void testPermissionRevocationRetiresSharing()
{
    PortableBootstrapEvidence evidence(501U);
    MacRuntimeHostControl control(evidence);

    auto password = standalonePassword();
    assert(control.configureStandaloneApplicationPassword(u"testuser", password));

    control.setScreenCaptureProbeForTesting([]() noexcept {
        return rdp::macos::ScreenCapturePreflightStatus::Granted;
    });
    control.setInputPermissionProbeForTesting([]() noexcept {
        return rdp::macos::MacInputPermissionStatus::Trusted;
    });

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 60'000U;

    const auto result = control.requestHostPermissionSetup(permission);
    assert(result.succeeded());
    assert(control.status().hostOwnerAuthorized);

    assert(control.revokeSharing().succeeded());
    assert(!control.status().hostOwnerAuthorized);
    assert(!control.status().product.ownerAuthorized);
    assert(control.status().stage == RuntimeHostStage::Revoked);
}

void testNoPromptOnAppLaunch()
{
    MacRuntimeHostControl control;
    const auto status = control.status();
    assert(status.stage == RuntimeHostStage::Stopped);
    assert(!status.listenerAvailable);
    assert(status.lastError == RuntimeHostError::None);
    assert(control.serviceOnce().succeeded());
}

} // namespace

int main(int argc, char** argv)
{
    assert(argc == 2);
    const std::string_view selected{argv[1]};
    if (selected == "macos-host-control-initial-product-projection")
    {
        testInitialProductProjection();
    }
    else if (selected == "macos-host-control-automatic-licensing-prestart-no-listener")
    {
        testAutomaticLicensingPrestartNoListener();
    }
    else if (selected == "macos-host-control-standalone-password-lifecycle")
    {
        testStandalonePasswordLifecycle();
    }
    else if (selected == "macos-host-control-sharing-permission-lifecycle")
    {
        testSharingPermissionLifecycle();
    }
    else if (selected == "macos-host-control-stop-revoke-retirement")
    {
        testStopRevokeRetirement();
    }
    else if (selected == "macos-host-control-stop-start-retains-standalone-credential")
    {
        if (!testStopStartRetainsStandaloneCredential())
            return 77;
    }
    else if (selected == "macos-host-control-accepted-pre-admission-dormancy")
    {
        if (!testMacAcceptedClientPreAdmissionDormancy())
            return 77;
    }
    else if (selected == "macos-host-control-verified-proof-explicit-client-retirement-denials")
    {
        if (!testMacCompletedCredSspExplicitClientRetirement())
            return 77;
    }
    else if (selected == "macos-host-control-completed-credssp-without-native-admission-denials")
    {
        if (!testMacCompletedCredSspWithoutNativeAdmissionDenials())
            return 77;
    }
    else if (selected == "macos-portable-gui-bootstrap-readiness")
    {
        testPortableGuiBootstrapReadiness();
    }
    else if (selected == "macos-host-control-lan-endpoint-recommendation")
    {
        testMacLanEndpointRecommendation();
    }
    else if (selected == "macos-host-control-native-lan-endpoint-observation")
    {
        if (!testMacNativeLanEndpointObservation())
            return 77;
    }
    else if (selected == "macos-host-control-screen-recording-permission-denial")
    {
        testScreenRecordingPermissionDenial();
    }
    else if (selected == "macos-host-control-accessibility-permission-denial")
    {
        testAccessibilityPermissionDenial();
    }
    else if (selected == "macos-host-control-permission-revocation-retires-sharing")
    {
        testPermissionRevocationRetiresSharing();
    }
    else if (selected == "macos-host-control-no-prompt-on-app-launch")
    {
        testNoPromptOnAppLaunch();
    }
    else
    {
        assert(false && "unknown test case");
    }
    return 0;
}
