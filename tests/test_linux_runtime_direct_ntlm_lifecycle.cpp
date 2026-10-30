// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_host_control.h"
#include "server/runtime/linux_runtime_connection.h"
#include "server/security/credssp_binding.h"
#include "server/security/standalone_credssp.h"
#include "server/security/standalone_ntlmssp.h"
#include "ntlm_type2_conformance.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <pwd.h>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rdp_server::server::runtime;
using namespace rdp_server::server::security;

namespace rdp_server::server::security
{
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

using Bytes = std::vector<std::uint8_t>;
using ByteSpan = std::span<const std::uint8_t>;
using MacPointer = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using MacContextPointer =
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;
using ContextPointer =
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPointer = std::unique_ptr<SSL, decltype(&SSL_free)>;
using CertificatePointer = std::unique_ptr<X509, decltype(&X509_free)>;

constexpr std::u16string_view kStandaloneUser{u"rdp"};
constexpr std::array<char16_t, 8> kStandalonePassword{
    u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};

consteval std::array<char16_t, 192> makeLargeStandalonePassword()
{
    constexpr std::u16string_view pattern{
        u"Rdp9!Delegation#Transport7$"};
    std::array<char16_t, 192> password{};
    for (std::size_t index = 0U; index < password.size(); ++index)
        password[index] = pattern[index % pattern.size()];
    return password;
}

constexpr std::u16string_view kLargeStandaloneUser{
    u"rdp_transport_delegation_test_01"};
constexpr auto kLargeStandalonePassword = makeLargeStandalonePassword();
static_assert(kLargeStandaloneUser.size() == 32U);
static_assert(
    kLargeStandalonePassword.size() <= kMaximumStandalonePasswordCodeUnits);

struct CredentialFixture final
{
    std::u16string_view username{};
    std::u16string_view password{};
};

constexpr CredentialFixture kDefaultCredentialFixture{
    kStandaloneUser,
    {kStandalonePassword.data(), kStandalonePassword.size()}};
constexpr std::u16string_view kMismatchedStandalonePassword{u"Different"};
constexpr CredentialFixture kMismatchedAuthInfoCredentialFixture{
    kStandaloneUser, kMismatchedStandalonePassword};
constexpr CredentialFixture kLargeCredentialFixture{
    kLargeStandaloneUser,
    {kLargeStandalonePassword.data(), kLargeStandalonePassword.size()}};

[[nodiscard]] std::span<char16_t> copyCredentialPassword(
    const CredentialFixture& credential,
    std::array<char16_t, kMaximumStandalonePasswordCodeUnits>& storage) noexcept
{
    if (credential.password.empty() ||
        credential.password.size() > storage.size())
    {
        return {};
    }
    std::copy(
        credential.password.begin(), credential.password.end(),
        storage.begin());
    return std::span(storage).first(credential.password.size());
}

constexpr std::uint32_t kDirectTypeOneFlags =
    kNtlmNegotiateUnicode | kNtlmRequestTarget |
    kNtlmNegotiateNtlm | kNtlmNegotiateAlwaysSign |
    kRequiredStandaloneCredSspNtlmFlags | kNtlmNegotiate56;
static_assert(
    kRuntimeAcceptedClientPreauthTimeout == std::chrono::seconds{30});

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
    const auto encodedLength = derLength(value.size());
    if (encodedLength.empty())
        return {};

    const std::size_t prefixBytes = 1U + encodedLength.size();
    if (value.size() >
        kMaximumCredSspRequestBytes - prefixBytes)
    {
        return {};
    }

    Bytes output(prefixBytes + value.size());
    output[0] = tag;
    for (std::size_t index = 0U; index < encodedLength.size(); ++index)
        output[1U + index] = encodedLength[index];
    for (std::size_t index = 0U; index < value.size(); ++index)
        output[prefixBytes + index] = value[index];
    return output;
}

[[nodiscard]] Bytes append(Bytes first, ByteSpan second)
{
    if (first.size() > kMaximumCredSspRequestBytes ||
        second.size() >
            kMaximumCredSspRequestBytes - first.size())
    {
        return {};
    }

    const std::size_t originalBytes = first.size();
    first.resize(originalBytes + second.size());
    for (std::size_t index = 0U; index < second.size(); ++index)
        first[originalBytes + index] = second[index];
    return first;
}

[[nodiscard]] Bytes version(std::uint8_t value)
{
    const std::array<std::uint8_t, 1> encoded{value};
    return wrap(0xa0U, wrap(0x02U, encoded));
}

[[nodiscard]] Bytes tokens(ByteSpan token)
{
    const auto octets = wrap(0x04U, token);
    const auto tokenField = wrap(0xa0U, octets);
    const auto item = wrap(0x30U, tokenField);
    const auto sequence = wrap(0x30U, item);
    return wrap(0xa1U, sequence);
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
    fields = append(fields, octetContext(0xa3U, protectedBinding));
    fields = append(fields, octetContext(0xa5U, nonce));
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
    const CredentialFixture& credential = kDefaultCredentialFixture)
{
    const Bytes emptyDomain;
    Bytes fields = octetContext(0xa0U, emptyDomain);
    const auto user = utf16Le(credential.username);
    fields = append(fields, octetContext(0xa1U, user));
    const auto password = utf16Le(credential.password);
    fields = append(fields, octetContext(0xa2U, password));
    const auto passwordCreds = wrap(0x30U, fields);

    const std::array<std::uint8_t, 1> passwordType{1U};
    const auto type = wrap(0xa0U, wrap(0x02U, passwordType));
    const auto credentials = octetContext(0xa1U, passwordCreds);
    return wrap(0x30U, append(type, credentials));
}

[[nodiscard]] Bytes authInfoRequest(ByteSpan protectedAuthInfo)
{
    return wrap(
        0x30U,
        append(version(6U), octetContext(0xa2U, protectedAuthInfo)));
}

[[nodiscard]] std::array<std::uint8_t, 40> directTypeOne()
{
    std::array<std::uint8_t, 40> message{};
    constexpr std::array<std::uint8_t, 8> signature{
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
    MacPointer mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr), EVP_MAC_free);
    if (!mac)
        return false;
    MacContextPointer context(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);
    if (!context)
        return false;

    char digestName[] = "MD5";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, digestName, 0U),
        OSSL_PARAM_construct_end()};
    if (EVP_MAC_init(
            context.get(), key.data(), key.size(), parameters) != 1)
        return false;
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

    NtlmChallengeMessageObservation observation;
    if (validateNtlmChallengeMessage(
            message, kDirectTypeOneFlags, observation) !=
            NtlmMessageParseResult::Parsed ||
        !observation.targetTypeServer ||
        !observation.targetNamePresent)
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
    NtlmV2SecurityContext& clientSecurity,
    bool rejectCredentialProof = false,
    const CredentialFixture& credentialFixture = kDefaultCredentialFixture)
{
    EphemeralNtlmV2Credential credential;
    std::array<char16_t, kMaximumStandalonePasswordCodeUnits> passwordStorage{};
    auto password = copyCredentialPassword(
        credentialFixture, passwordStorage);
    if (password.empty() ||
        !credential.configure(credentialFixture.username, password))
    {
        return std::nullopt;
    }

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
    const std::array<ByteSpan, 2> proofParts{
        ByteSpan{challenge.challenge},
        ByteSpan{blob}};
    if (!hmacMd5(responseKey, proofParts, proof))
        return std::nullopt;

    Bytes ntResponse;
    ntResponse.reserve(proof.size() + blob.size());
    ntResponse.insert(ntResponse.end(), proof.begin(), proof.end());
    ntResponse.insert(ntResponse.end(), blob.begin(), blob.end());

    const Bytes user = utf16Le(credentialFixture.username);
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
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    std::copy(signature.begin(), signature.end(), authenticate.begin());
    storeLe32(authenticate.data() + 8U, 3U);

    // Empty LM/domain/workstation/session-key buffers remain zero length. The
    // standalone profile does not require NTLM key exchange; sessionBaseKey is
    // therefore the exported session key for the shared SIGN/SEAL context.
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
    std::copy(user.begin(), user.end(),
              authenticate.begin() +
                  static_cast<std::ptrdiff_t>(userOffset));
    std::copy(ntResponse.begin(), ntResponse.end(),
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
    StandaloneNtlmV2TestAccess::activateClientMirror(
        serverPerspective, clientSecurity);
    if (!clientSecurity.active())
        return std::nullopt;

    if (rejectCredentialProof)
    {
        // Keep the Type-3 structure valid while making the NT proof fail the
        // production verifier. No credential bytes are logged or retained.
        authenticate[ntResponseOffset] ^= 0x01U;
    }
    return authenticate;
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
    const ASN1_BIT_STRING* subjectPublicKey =
        X509_get0_pubkey_bitstr(certificate.get());
    if (subjectPublicKey == nullptr)
        return std::nullopt;
    const int publicKeyBytes = ASN1_STRING_length(subjectPublicKey);
    const unsigned char* publicKey =
        ASN1_STRING_get0_data(subjectPublicKey);
    if (publicKeyBytes <= 0 || publicKey == nullptr ||
        static_cast<std::size_t>(publicKeyBytes) >
            kMaximumCredSspPublicKeyBytes)
    {
        return std::nullopt;
    }

    CredSspHash hash{};
    const ByteSpan keyBits{
        publicKey, static_cast<std::size_t>(publicKeyBytes)};
    if (!computeCredSspBindingHash(direction, nonce, keyBits, hash))
        return std::nullopt;
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

    const auto protectedServer =
        parsed.value.encryptedPubKeyAuth;
    if (protectedServer.size() !=
        kNtlmMessageSignatureBytes + kCredSspBindingHashBytes)
    {
        return false;
    }

    const auto signature =
        std::span<const std::uint8_t, kNtlmMessageSignatureBytes>{
            protectedServer.data(), kNtlmMessageSignatureBytes};
    const auto ciphertext =
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

[[nodiscard]] std::optional<std::size_t> derFrameBytes(ByteSpan bytes)
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
    if (contentBytes < 128U && lengthBytes != 0U)
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
            ::close(descriptor_);
    }

    NetworkTlsClient(const NetworkTlsClient&) = delete;
    NetworkTlsClient& operator=(const NetworkTlsClient&) = delete;

    [[nodiscard]] bool connectHybrid(
        std::string_view ipAddress,
        std::uint16_t port)
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

        constexpr std::array<unsigned char, 19> hybridRequest{
            0x03,0x00,0x00,0x13,0x0e,0xe0,0,0,0,0,0,
            0x01,0x00,0x08,0x00,0x02,0,0,0};
        std::array<unsigned char, 19> confirmation{};
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
        if (!tls_ || SSL_set_fd(tls_.get(), descriptor_) != 1 ||
            SSL_connect(tls_.get()) != 1)
        {
            return false;
        }

        CertificatePointer certificate(
            SSL_get1_peer_certificate(tls_.get()), X509_free);
        return certificate != nullptr &&
               X509_check_ip_asc(
                   certificate.get(), address.c_str(), 0) == 1 &&
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

    [[nodiscard]] bool writeRawTransportBytes(ByteSpan bytes) noexcept
    {
        if (descriptor_ < 0 || bytes.empty())
            return false;
        std::size_t offset = 0U;
        while (offset < bytes.size())
        {
            const ssize_t written = ::send(
                descriptor_, bytes.data() + offset,
                bytes.size() - offset, MSG_NOSIGNAL);
            if (written <= 0)
                return false;
            offset += static_cast<std::size_t>(written);
        }
        return true;
    }

    [[nodiscard]] bool sendCloseNotify() noexcept
    {
        if (!tls_)
            return false;
        const int result = SSL_shutdown(tls_.get());
        return result >= 0 ||
               (SSL_get_shutdown(tls_.get()) & SSL_SENT_SHUTDOWN) != 0;
    }

    [[nodiscard]] bool sendOrderlyFin() noexcept
    {
        return descriptor_ >= 0 && ::shutdown(descriptor_, SHUT_WR) == 0;
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
    ContextPointer context_{nullptr, SSL_CTX_free};
    SslPointer tls_{nullptr, SSL_free};
};

class DirectNtlmLifecycleEvidence final : public ConsoleOsEvidenceSource
{
public:
    explicit DirectNtlmLifecycleEvidence(std::uint32_t uid)
        : uid_(uid)
    {
        const passwd* account = ::getpwuid(static_cast<uid_t>(uid));
        if (account != nullptr && account->pw_name != nullptr)
            account_.assign(account->pw_name);
    }

    [[nodiscard]] bool valid() const noexcept
    {
        return uid_ != 0U && !account_.empty();
    }

    void lockDesktop() noexcept
    {
        lockState_ = ConsoleDesktopLockState::Locked;
    }

    void logoutDesktop() noexcept
    {
        sessionAvailable_ = false;
    }

    void switchDesktopSession() noexcept
    {
        switchedSession_ = true;
        ++sessionGeneration_;
    }

    void setActiveConsoleReadDelay(
        std::chrono::milliseconds delay) noexcept
    {
        activeConsoleReadDelay_ =
            (std::max)(delay, std::chrono::milliseconds{0});
    }

    [[nodiscard]] std::uint64_t activeConsoleReadCount() const noexcept
    {
        return activeConsoleReadCount_;
    }

    ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override
    {
        if (!valid() || account != account_)
            return {};
        return {ConsoleEvidenceReadStatus::Observed, account_, uid_};
    }

    ConsoleSessionObservation readActiveConsole() noexcept override
    {
        ++activeConsoleReadCount_;
        if (activeConsoleReadDelay_.count() > 0)
            std::this_thread::sleep_for(activeConsoleReadDelay_);
        if (!valid() || !sessionAvailable_)
            return {};
        const std::string_view sessionId = switchedSession_
            ? "direct-ntlm-lifecycle-switched"
            : "direct-ntlm-lifecycle";
        return {
            ConsoleEvidenceReadStatus::Observed,
            sessionId,
            "seat0",
            ":42",
            uid_,
            sessionGeneration_,
            now_,
            true,
            true,
            uid_,
            lockState_,
            false};
    }

    std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override
    {
        return now_;
    }

private:
    std::uint32_t uid_{};
    std::string account_;
    std::uint64_t sessionGeneration_{501U};
    std::uint64_t now_{10'000U};
    ConsoleDesktopLockState lockState_{ConsoleDesktopLockState::Unlocked};
    bool sessionAvailable_{true};
    bool switchedSession_{};
    std::chrono::milliseconds activeConsoleReadDelay_{};
    std::uint64_t activeConsoleReadCount_{};
};

// A test-only peer/owner handoff; R10 remains the sole socket/TLS owner.
struct PendingAuthInfoGate final
{
    std::atomic<bool> serverBindingVerified{};
    std::atomic<bool> permitFinalAuthInfo{};
    std::atomic<bool> finalAuthInfoWritten{};
};

enum class FinalAuthInfoWritePattern : std::uint8_t
{
    Complete,
    Fragmented,
    LargeDelegatedFragmentsWithCoalescedTail,
    TruncatedWithTlsClose
};

enum class FinalAuthInfoCredentialPattern : std::uint8_t
{
    Matching,
    MismatchedPassword,
};

struct PeerResult final
{
    bool passed{};
    bool directTypeTwoReceived{};
    bool authInfoSent{};
    std::size_t finalAuthInfoBytes{};
    std::size_t expectedPostTypeTwoCredSspPlaintextBytes{};
    std::size_t trailingApplicationBytes{};
    NtlmServerChallenge serverChallenge{};
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

    // Published MS-RDPBCGR 4.1.3 fixture: one complete 416-byte TPKT.
    assert(packet.size() == 416U);
    assert(packet[0] == 0x03U);
    assert(packet[1] == 0x00U);
    assert(packet[2] == 0x01U);
    assert(packet[3] == 0xa0U);
    return packet;
}

[[nodiscard]] bool waitForRelease(
    const std::atomic<bool>& release) noexcept
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (!release.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return release.load(std::memory_order_acquire);
}

[[nodiscard]] PeerResult runDirectNtlmPeer(
    std::string_view address,
    std::uint16_t port,
    bool validCredentials,
    std::uint8_t nonceSeed,
    std::atomic<bool>& release,
    bool rejectCredentialProof = false,
    FinalAuthInfoWritePattern authInfoWritePattern =
        FinalAuthInfoWritePattern::Complete,
    PendingAuthInfoGate* pendingAuthInfoGate = nullptr,
    const CredentialFixture& credentialFixture =
        kDefaultCredentialFixture,
    FinalAuthInfoCredentialPattern authInfoCredentialPattern =
        FinalAuthInfoCredentialPattern::Matching) noexcept
{
    PeerResult result;
    NetworkTlsClient client;
    if (!client.connectHybrid(address, port))
        return result;

    const auto negotiate = directTypeOne();
    const auto initialRequest = initialTokenRequest(negotiate);
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
    result.serverChallenge = challenge->challenge;

    if (!validCredentials)
    {
        if (rejectCredentialProof)
        {
            NtlmV2SecurityContext rejectedSecurity;
            const auto rejectedTypeThree =
                makeDirectTypeThree(
                    *challenge, rejectedSecurity, true, credentialFixture);
            if (!rejectedTypeThree ||
                !client.writeFrame(initialTokenRequest(*rejectedTypeThree)))
            {
                return result;
            }
        }
        else
        {
            std::array<std::uint8_t, 40> malformedTypeThree{};
            constexpr std::array<std::uint8_t, 8> signature{
                'N','T','L','M','S','S','P',0};
            std::copy(
                signature.begin(), signature.end(),
                malformedTypeThree.begin());
            malformedTypeThree[8] = 3U;
            const auto malformed =
                initialTokenRequest(malformedTypeThree);
            if (!client.writeFrame(malformed))
                return result;
        }
        result.passed = waitForRelease(release);
        return result;
    }

    NtlmV2SecurityContext clientSecurity;
    const auto authenticate =
        makeDirectTypeThree(
            *challenge, clientSecurity, false, credentialFixture);
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

    const auto finalRequest = combinedFinalRequest(
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

    if (pendingAuthInfoGate != nullptr)
    {
        pendingAuthInfoGate->serverBindingVerified.store(
            true, std::memory_order_release);
        if (!waitForRelease(pendingAuthInfoGate->permitFinalAuthInfo))
            return result;
    }

    const CredentialFixture& authInfoCredential =
        authInfoCredentialPattern ==
                FinalAuthInfoCredentialPattern::MismatchedPassword
            ? kMismatchedAuthInfoCredentialFixture
            : credentialFixture;
    const auto credentials = passwordCredentials(authInfoCredential);
    const auto protectedCredentials =
        protectClientMessage(clientSecurity, credentials);
    if (!protectedCredentials)
        return result;
    const auto authInfo = authInfoRequest(*protectedCredentials);
    const ByteSpan authInfoBytes{authInfo};
    result.finalAuthInfoBytes = authInfoBytes.size();
    if (finalRequest.size() >
        (std::numeric_limits<std::size_t>::max)() - authInfoBytes.size())
    {
        return result;
    }
    result.expectedPostTypeTwoCredSspPlaintextBytes =
        finalRequest.size() + authInfoBytes.size();
    if (authInfoWritePattern ==
        FinalAuthInfoWritePattern::TruncatedWithTlsClose)
    {
        // The DER prefix is a valid beginning, but never a complete final
        // authInfo. The real R1 reader must discard it on TLS close.
        if (authInfoBytes.size() <= 6U)
            return result;
        result.passed = client.writeFrame(authInfoBytes.first(5U)) &&
                        client.sendCloseNotify();
        return result;
    }
    if (authInfoWritePattern == FinalAuthInfoWritePattern::Fragmented)
    {
        // Separate TLS application writes exercise 1-byte, partial DER
        // length and incomplete payload delivery on the same R1 stream.
        constexpr std::array<std::size_t, 3> fragmentSizes{1U, 2U, 3U};
        std::size_t offset = 0U;
        for (const std::size_t fragmentSize : fragmentSizes)
        {
            if (offset + fragmentSize >= authInfoBytes.size() ||
                !client.writeFrame(authInfoBytes.subspan(offset, fragmentSize)))
                return result;
            offset += fragmentSize;
        }
        if (!client.writeFrame(authInfoBytes.subspan(offset)))
            return result;
    }
    else if (
        authInfoWritePattern ==
        FinalAuthInfoWritePattern::LargeDelegatedFragmentsWithCoalescedTail)
    {
        // A large nonempty delegated TSPasswordCreds fixture crosses the
        // 512-byte R2 TLS-read scratch size and uses the canonical 0x82 outer
        // DER length. Split tag/length, body and final bytes across logical
        // TLS application writes. The last write appends the complete published
        // Microsoft Connect-Initial. R2 must stop exactly at final authInfo;
        // native Admission denial must retire those buffered MCS bytes before
        // R3 can consume or semantically dispatch them.
        if (authInfoBytes.size() <= 512U ||
            authInfoBytes.size() > kMaximumCredSspRequestBytes ||
            authInfoBytes.size() < 16U ||
            authInfoBytes[0] != 0x30U || authInfoBytes[1] != 0x82U)
        {
            return result;
        }

        constexpr std::array<std::size_t, 5> fragmentSizes{
            1U, 2U, 1U, 97U, 131U};
        constexpr std::size_t finalAuthInfoBytes = 11U;
        std::size_t offset = 0U;
        for (const std::size_t fragmentSize : fragmentSizes)
        {
            if (fragmentSize > authInfoBytes.size() - offset ||
                offset + fragmentSize >=
                    authInfoBytes.size() - finalAuthInfoBytes ||
                !client.writeFrame(
                    authInfoBytes.subspan(offset, fragmentSize)))
            {
                return result;
            }
            offset += fragmentSize;
        }

        const std::size_t bodyBytes =
            authInfoBytes.size() - finalAuthInfoBytes - offset;
        if (bodyBytes == 0U ||
            !client.writeFrame(authInfoBytes.subspan(offset, bodyBytes)))
        {
            return result;
        }
        offset += bodyBytes;

        const Bytes microsoftConnectInitial =
            loadMicrosoftMcsConnectInitialFixture();
        Bytes finalWrite;
        finalWrite.reserve(
            finalAuthInfoBytes + microsoftConnectInitial.size());
        finalWrite.insert(
            finalWrite.end(),
            authInfoBytes.begin() + static_cast<std::ptrdiff_t>(offset),
            authInfoBytes.end());
        finalWrite.insert(
            finalWrite.end(),
            microsoftConnectInitial.begin(),
            microsoftConnectInitial.end());
        result.trailingApplicationBytes = microsoftConnectInitial.size();
        if (!client.writeFrame(finalWrite))
            return result;
    }
    else if (!client.writeFrame(authInfoBytes))
    {
        return result;
    }

    result.authInfoSent = true;
    if (pendingAuthInfoGate != nullptr)
        pendingAuthInfoGate->finalAuthInfoWritten.store(
            true, std::memory_order_release);
    result.passed = waitForRelease(release);
    return result;
}

[[nodiscard]] bool receiveDirectTypeTwo(
    NetworkTlsClient& client,
    std::string_view address,
    std::uint16_t port,
    PeerResult& result) noexcept
{
    if (!client.connectHybrid(address, port))
        return false;

    const auto negotiate = directTypeOne();
    const auto initialRequest = initialTokenRequest(negotiate);
    if (!client.writeFrame(initialRequest))
        return false;

    const auto challengeFrame = client.readFrame();
    if (!challengeFrame)
        return false;
    const auto parsedChallengeFrame =
        parseCredSspTsRequest(*challengeFrame);
    if (!parsedChallengeFrame ||
        parsedChallengeFrame.value.tokenCount != 1U)
    {
        return false;
    }

    const auto challenge =
        parseDirectTypeTwo(parsedChallengeFrame.value.tokens[0]);
    if (!challenge)
        return false;

    result.directTypeTwoReceived = true;
    result.serverChallenge = challenge->challenge;
    return true;
}

[[nodiscard]] PeerResult runDirectTypeTwoThenClosePeer(
    std::string_view address,
    std::uint16_t port,
    std::atomic<bool>& typeTwoReceived,
    std::atomic<bool>& closeAfterTypeTwo,
    ByteSpan postTypeTwoPlaintext = {}) noexcept
{
    PeerResult result;
    NetworkTlsClient client;
    if (!receiveDirectTypeTwo(client, address, port, result))
        return result;

    if (!postTypeTwoPlaintext.empty() &&
        !client.writeFrame(postTypeTwoPlaintext))
    {
        return result;
    }

    typeTwoReceived.store(true, std::memory_order_release);
    result.passed = waitForRelease(closeAfterTypeTwo);
    return result;
}

enum class PostTypeTwoPeerAction : std::uint8_t
{
    Silence,
    PartialTlsRecord,
    CompleteNonTypeThreeTsRequest,
    TlsCloseNotify,
    OrderlyFin,
};

[[nodiscard]] PeerResult runPostTypeTwoObservationPeer(
    std::string_view address,
    std::uint16_t port,
    PostTypeTwoPeerAction action,
    std::atomic<bool>& typeTwoReceived,
    std::atomic<bool>& performAction,
    std::atomic<bool>& actionApplied,
    std::atomic<bool>& releasePeer) noexcept
{
    PeerResult result;
    NetworkTlsClient client;
    if (!receiveDirectTypeTwo(client, address, port, result))
        return result;

    typeTwoReceived.store(true, std::memory_order_release);
    if (!waitForRelease(performAction))
        return result;

    bool applied = false;
    switch (action)
    {
    case PostTypeTwoPeerAction::Silence:
        applied = true;
        break;
    case PostTypeTwoPeerAction::PartialTlsRecord:
    {
        // Incomplete TLS application-data record: R1 observes encrypted bytes
        // while OpenSSL correctly withholds application plaintext.
        constexpr std::array<std::uint8_t, 6> partialRecord{
            0x17U, 0x03U, 0x03U, 0x00U, 0x10U, 0x00U};
        applied = client.writeRawTransportBytes(partialRecord);
        break;
    }
    case PostTypeTwoPeerAction::CompleteNonTypeThreeTsRequest:
        applied = client.writeFrame(initialTokenRequest(directTypeOne()));
        break;
    case PostTypeTwoPeerAction::TlsCloseNotify:
        applied = client.sendCloseNotify();
        break;
    case PostTypeTwoPeerAction::OrderlyFin:
        applied = client.sendOrderlyFin();
        break;
    }

    if (!applied)
        return result;
    actionApplied.store(true, std::memory_order_release);
    result.passed = waitForRelease(releasePeer);
    return result;
}

[[nodiscard]] bool pumpUntil(
    LinuxRuntimeHostControl& control,
    const std::atomic<bool>& peerFinished,
    bool (*predicate)(const RuntimeHostStatus&)) noexcept
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline)
    {
        const RuntimeHostStatus status = control.status();
        if (predicate(status))
            return true;
        if (peerFinished.load(std::memory_order_acquire))
            return false;
        (void)control.serviceOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate(control.status());
}

[[nodiscard]] bool pumpUntilPeerSignal(
    LinuxRuntimeHostControl& control,
    const std::atomic<bool>& signal,
    const std::atomic<bool>& peerFinished) noexcept
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (signal.load(std::memory_order_acquire))
            return true;
        if (peerFinished.load(std::memory_order_acquire))
            return false;
        (void)control.serviceOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return signal.load(std::memory_order_acquire);
}

[[nodiscard]] bool directClientCredentialsVerifiedThenAdmissionDenied(
    const RuntimeHostStatus& status) noexcept;

[[nodiscard]] bool pumpUntilNewAttemptAdmissionDenied(
    LinuxRuntimeHostControl& control,
    const std::atomic<bool>& peerFinished) noexcept
{
    bool acceptedCurrentAttempt = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline)
    {
        const RuntimeHostStatus status = control.status();
        acceptedCurrentAttempt =
            acceptedCurrentAttempt || !status.activeClients.empty();
        if (acceptedCurrentAttempt &&
            directClientCredentialsVerifiedThenAdmissionDenied(status))
        {
            return true;
        }
        if (peerFinished.load(std::memory_order_acquire))
            return false;
        (void)control.serviceOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return acceptedCurrentAttempt &&
           directClientCredentialsVerifiedThenAdmissionDenied(control.status());
}

[[nodiscard]] bool badClientRetired(
    const RuntimeHostStatus& status) noexcept
{
    return status.listenerAvailable &&
           status.clientDisconnected &&
           status.activeClients.empty();
}

[[nodiscard]] bool pumpUntilClientRetired(
    LinuxRuntimeHostControl& control) noexcept
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (badClientRetired(control.status()))
            return true;
        (void)control.serviceOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return badClientRetired(control.status());
}

[[nodiscard]] bool pumpUntilNewAttemptRetired(
    LinuxRuntimeHostControl& control,
    const std::atomic<bool>& peerFinished) noexcept
{
    bool acceptedCurrentAttempt = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline)
    {
        const RuntimeHostStatus status = control.status();
        acceptedCurrentAttempt =
            acceptedCurrentAttempt || !status.activeClients.empty();
        if (acceptedCurrentAttempt && badClientRetired(status))
            return true;
        if (peerFinished.load(std::memory_order_acquire))
            return false;
        (void)control.serviceOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return acceptedCurrentAttempt && badClientRetired(control.status());
}

void assertFixedConnectionTargetIdentity(
    const RuntimeHostStatus& status,
    std::string_view numericAddress,
    std::uint16_t port,
    std::uint64_t listenerGeneration)
{
    const auto& target = status.connectionTargetIdentity;
    assert(target.valid());
    assert(target.matchesStart(
        numericAddress, port, listenerGeneration));
    assert(target.targetClass == RuntimeConnectionTargetClass::Ip);
    assert(target.serviceClass == RuntimeConnectionServiceClass::Termsrv);
    assert(target.serviceIdentityProfile ==
           RuntimeServiceIdentityProfile::FixedName);
    assert(!target.endpointBound());
    const std::u16string_view protocolServerIdentity{
        target.protocolServerIdentity.data(),
        target.protocolServerIdentity.size()};
    assert(protocolServerIdentity ==
           kStandaloneNtlmPortableServerName);

    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    if (!diagnostics.available)
        return;
    assert(diagnostics.clientTargetClass ==
           RuntimeConnectionTargetClass::Ip);
    assert(diagnostics.serviceClass ==
           RuntimeConnectionServiceClass::Termsrv);
    assert(diagnostics.serviceIdentityProfile ==
           RuntimeServiceIdentityProfile::FixedName);
    assert(diagnostics.connectionTargetGeneration ==
           listenerGeneration);
}

[[nodiscard]] bool physicalClientEnvironmentDiagnosticsMatch(
    const RuntimeHostStatus& status) noexcept
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    return diagnostics.available &&
           (diagnostics.tlsConnection.protocolVersion ==
                RuntimeAcceptedClientTlsProtocolVersion::Tls12 ||
            diagnostics.tlsConnection.protocolVersion ==
                RuntimeAcceptedClientTlsProtocolVersion::Tls13) &&
           diagnostics.tlsConnection.cipherProtocolId != 0U &&
           !diagnostics.tlsConnection.cipherNameView().empty() &&
           diagnostics.tlsConnection.sniClass ==
               RuntimeAcceptedClientTlsSniClass::None &&
           diagnostics.ntlmTypeOne.observed &&
           !diagnostics.ntlmTypeOne.versionPresent &&
           diagnostics.ntlmTypeOne.majorVersion == 0U &&
           diagnostics.ntlmTypeOne.minorVersion == 0U &&
           diagnostics.ntlmTypeOne.buildNumber == 0U &&
           diagnostics.ntlmTypeOne.ntlmRevision == 0U &&
           diagnostics.tlsConnection.certificateProfile ==
               RuntimeTlsCertificateProfile::SelfSignedExactIpSan &&
           diagnostics.tlsConnection.certificateEndpointGeneration ==
               status.listenerGeneration &&
           status.tlsCertificateProfile ==
               RuntimeTlsCertificateProfile::SelfSignedExactIpSan;
}

void assertPostTypeTwoSilence(
    const RuntimeHostStatus& status) noexcept
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    assert(diagnostics.available);
    assert(diagnostics.directNtlmTypeTwoDelivered);
    assert(diagnostics.postTypeTwoClientTlsBytes == 0U);
    assert(!diagnostics.postTypeTwoFirstClientTlsByteAvailable);
    assert(diagnostics.postTypeTwoCompleteTsRequestCount == 0U);
    assert(diagnostics.postTypeTwoPlaintextBytes == 0U);
    assert(diagnostics.postTypeTwoPartialTsRequestBytes == 0U);
    assert(diagnostics.postTypeTwoTlsAlertsReceived == 0U);
    assert(!diagnostics.postTypeTwoTlsCloseNotifyReceived);
    assert(!diagnostics.postTypeTwoTcpFinReceived);
    assert(!diagnostics.postTypeTwoTcpResetReceived);
}

[[nodiscard]] bool postTypeTwoEncryptedBytesObserved(
    const RuntimeHostStatus& status) noexcept
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    return diagnostics.available &&
           diagnostics.directNtlmTypeTwoDelivered &&
           diagnostics.postTypeTwoClientTlsBytes != 0U &&
           diagnostics.postTypeTwoFirstClientTlsByteAvailable;
}

[[nodiscard]] bool directTypeTwoPeerEofRemainsPreAdmission(
    const RuntimeHostStatus& status) noexcept
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    return status.lastError ==
               RuntimeHostError::AuthenticationIncompletePeerClosed &&
           status.listenerAvailable &&
           status.clientDisconnected &&
           status.activeClients.empty() &&
           diagnostics.available &&
           diagnostics.ntlmEnvelope ==
               RuntimeAcceptedClientNtlmEnvelope::DirectNtlm &&
           diagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmChallenge &&
           diagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission &&
           !diagnostics.mcsSessionAdvanced &&
           !diagnostics.shareActivated &&
           diagnostics.credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::Closed &&
           diagnostics.standaloneFailureStage ==
               RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation &&
           diagnostics.admissionFailureReason ==
               RuntimeAcceptedClientAdmissionFailureReason::None &&
           diagnostics.termination ==
               RuntimeAcceptedClientTermination::PeerEof &&
           diagnostics.directNtlmTypeTwoQueued &&
           diagnostics.directNtlmTypeTwoDelivered &&
           diagnostics.preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::PeerEof &&
           (diagnostics.tlsConnection.protocolVersion ==
                RuntimeAcceptedClientTlsProtocolVersion::Tls12 ||
            diagnostics.tlsConnection.protocolVersion ==
                RuntimeAcceptedClientTlsProtocolVersion::Tls13) &&
           !diagnostics.tlsConnection.cipherNameView().empty() &&
           physicalClientEnvironmentDiagnosticsMatch(status) &&
           !status.nativeDesktopReady &&
           !status.nativeDesktopInitializing &&
           !status.graphicsReady;
}

[[nodiscard]] bool directTypeTwoTimeoutRemainsPreAdmission(
    const RuntimeHostStatus& status) noexcept
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    return status.listenerAvailable &&
           status.clientDisconnected &&
           status.activeClients.empty() &&
           diagnostics.available &&
           diagnostics.ntlmEnvelope ==
               RuntimeAcceptedClientNtlmEnvelope::DirectNtlm &&
           diagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmChallenge &&
           diagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission &&
           !diagnostics.mcsSessionAdvanced &&
           !diagnostics.shareActivated &&
           diagnostics.admissionFailureReason ==
               RuntimeAcceptedClientAdmissionFailureReason::None &&
           diagnostics.termination ==
               RuntimeAcceptedClientTermination::Timeout &&
           diagnostics.directNtlmTypeTwoQueued &&
           diagnostics.directNtlmTypeTwoDelivered &&
           diagnostics.preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None &&
           !status.nativeDesktopReady &&
           !status.nativeDesktopInitializing &&
           !status.graphicsReady;
}

[[nodiscard]] bool directClientCredentialsVerifiedThenAdmissionDenied(
    const RuntimeHostStatus& status) noexcept
{
    return status.lastError == RuntimeHostError::AuthenticationRejected &&
           status.listenerAvailable &&
           status.clientDisconnected &&
           status.activeClients.empty() &&
           status.acceptedClientPreauthDiagnostics.available &&
           status.acceptedClientPreauthDiagnostics.ntlmEnvelope ==
               RuntimeAcceptedClientNtlmEnvelope::DirectNtlm &&
           status.acceptedClientPreauthDiagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::Admission &&
           status.acceptedClientPreauthDiagnostics.credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::CredentialsVerified &&
           status.acceptedClientPreauthDiagnostics.standaloneFailureStage ==
               RuntimeAcceptedClientStandaloneFailureStage::Admission &&
           status.acceptedClientPreauthDiagnostics.admissionFailureReason !=
               RuntimeAcceptedClientAdmissionFailureReason::None &&
           !status.nativeDesktopReady &&
           !status.nativeDesktopInitializing &&
           !status.graphicsReady &&
           !status.firstLiveGraphicsTrace.firstFramebufferAvailable &&
           !status.firstLiveGraphicsTrace.firstExactTlsWriteCommitted &&
           status.firstLiveGraphicsTrace.outstandingFrameAcknowledgements == 0U &&
           !status.firstLiveGraphicsTrace.firstGenuineMatchingFrameAcknowledge;
}

[[nodiscard]] bool challengesDiffer(
    const NtlmServerChallenge& first,
    const NtlmServerChallenge& second) noexcept
{
    return !std::equal(
        first.begin(), first.end(), second.begin());
}

void assertClipboardDormant(const RuntimeHostStatus& status) noexcept
{
    assert(status.clipboardState == RuntimeClipboardState::Unavailable);
    assert(!status.graphicsReady);
    assert((status.ownerGrant.effectivePermissionMask &
            kConsoleClipboardPermission) == 0U);
}

void assertGraphicsDormant(const RuntimeHostStatus& status) noexcept
{
    assert(!status.graphicsReady);
    assert(!status.nativeDesktopReady);
    assert(!status.nativeDesktopInitializing);
    assert(!status.firstLiveGraphicsTrace.firstFramebufferAvailable);
    assert(!status.firstLiveGraphicsTrace.firstClearCodecFramePrepared);
    assert(!status.firstLiveGraphicsTrace.firstExactTlsWriteCommitted);
    assert(status.firstLiveGraphicsTrace.outstandingFrameAcknowledgements == 0U);
    assert(!status.firstLiveGraphicsTrace.firstGenuineMatchingFrameAcknowledge);
}

void assertPreAdmissionNativeIsolation(
    const RuntimeHostStatus& status) noexcept
{
    const auto& diagnostics = status.acceptedClientPreauthDiagnostics;
    assert(status.stage == RuntimeHostStage::ClientAuthenticating);
    assert(status.activeClients.size() == 1U);
    assert(diagnostics.available);
    assert(diagnostics.authenticationStage ==
           RuntimeAcceptedClientAuthenticationStage::NtlmChallenge);
    assert(diagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    assert(diagnostics.directNtlmTypeTwoDelivered);
    assert(!diagnostics.mcsSessionAdvanced);
    assert(!diagnostics.shareActivated);

    // Input, capture and clipboard adapters are children of the native desktop
    // aggregate, which R10 cannot construct before genuine R2 admission,
    // Share activation and GraphicsReady. Owner consent alone is not native
    // input authority.
    assertClipboardDormant(status);
    assertGraphicsDormant(status);
}

void assertPhysicalOwnerGrantActive(const RuntimeHostStatus& status) noexcept
{
    assert(status.hostOwnerAuthorized);
    assert(status.product.ownerAuthorized);
    assert(status.ownerGrant.state == RuntimeOwnerGrantState::Active);
    assert(status.ownerGrant.effectivePermissionMask ==
           (kConsoleViewPermission | kConsoleInputPermission));
    assert(status.ownerGrant.remainingMilliseconds > 0U);
}

[[nodiscard]] bool startSharingOnPort(
    LinuxRuntimeHostControl& control,
    const RuntimeHostRecommendedEndpoint& recommendation,
    std::uint16_t port) noexcept
{
    const RuntimeHostOptions options{
        recommendation.interfaceId, recommendation.address,
        port, true, false};
    return control.configure(options).succeeded() &&
           control.startSharing().succeeded();
}

[[nodiscard]] PeerResult runAdmissionDeniedPeer(
    LinuxRuntimeHostControl& control,
    std::string_view address,
    std::uint16_t port,
    std::uint8_t nonceSeed,
    std::uint64_t expectedListenerGeneration,
    std::uint64_t expectedCredentialGeneration,
    FinalAuthInfoWritePattern authInfoWritePattern =
        FinalAuthInfoWritePattern::Complete,
    const CredentialFixture& credentialFixture =
        kDefaultCredentialFixture) noexcept
{
    std::atomic<bool> release{false};
    std::atomic<bool> finished{false};
    PeerResult peerResult;
    std::thread peer([&] {
        peerResult = runDirectNtlmPeer(
            address, port, true, nonceSeed, release, false,
            authInfoWritePattern, nullptr, credentialFixture);
        finished.store(true, std::memory_order_release);
    });

    assert(pumpUntilNewAttemptAdmissionDenied(control, finished));
    const auto status = control.status();
    assert(status.listenerAvailable);
    assert(status.listenerGeneration == expectedListenerGeneration);
    assertPhysicalOwnerGrantActive(status);
    assert(status.product.state == RuntimeProductHostState::Listening);
    assert(status.product.credentialsConfigured);
    assert(status.stage == RuntimeHostStage::ListenerAvailable);
    assert(status.clientDisconnected);
    assert(status.activeClients.empty());
    assert(status.acceptedClientPreauthDiagnostics.available);
    assert(status.acceptedClientPreauthDiagnostics.ntlmEnvelope ==
           RuntimeAcceptedClientNtlmEnvelope::DirectNtlm);
    assert(status.acceptedClientPreauthDiagnostics.authenticationStage ==
           RuntimeAcceptedClientAuthenticationStage::Admission);
    assert(status.acceptedClientPreauthDiagnostics.credSspTransition ==
           RuntimeAcceptedClientCredSspTransition::CredentialsVerified);
    assert(status.acceptedClientPreauthDiagnostics.standaloneFailureStage ==
           RuntimeAcceptedClientStandaloneFailureStage::Admission);
    assert(status.acceptedClientPreauthDiagnostics.standaloneAuthInfoFailureReason ==
           RuntimeAcceptedClientAuthInfoFailureReason::None);
    assert(status.acceptedClientPreauthDiagnostics.protocolStage ==
           RuntimeAcceptedClientProtocolStage::PreAdmission);
    assert(!status.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
    assert(!status.acceptedClientPreauthDiagnostics.shareActivated);
    assert(!status.nativeDesktopReady);
    assert(!status.nativeDesktopInitializing);
    assert(!status.graphicsReady);
    assert(status.acceptedClientPreauthDiagnostics.admissionFailureReason !=
           RuntimeAcceptedClientAdmissionFailureReason::None);
    // Admission rejection is not a TLS failure. A peer EOF observed by the
    // transport owner remains its distinct terminal category.
    assert(status.acceptedClientPreauthDiagnostics.termination !=
           RuntimeAcceptedClientTermination::TlsFailure);
    assert(status.acceptedClientPreauthDiagnostics.termination !=
           RuntimeAcceptedClientTermination::LocalTlsFailure);
    assertClipboardDormant(status);
    assertGraphicsDormant(status);
    assert(status.acceptedClientPreauthDiagnostics
               .standaloneCredentialGeneration ==
           expectedCredentialGeneration);
    assert(control.standaloneApplicationPasswordObservation().generation ==
           expectedCredentialGeneration);

    release.store(true, std::memory_order_release);
    peer.join();

    // Server-side diagnostics above prove authInfo was consumed through
    // CredentialsVerified before native Admission failed. The deliberate
    // server active-close can race the peer's final SSL_write() completion,
    // so that client-side receipt is not an admission correctness condition.
    assert(peerResult.directTypeTwoReceived);
    if (peerResult.trailingApplicationBytes != 0U)
    {
        assert(peerResult.trailingApplicationBytes == 416U);
        assert(peerResult.authInfoSent);
        assert(peerResult.finalAuthInfoBytes > 512U);
        assert(peerResult.finalAuthInfoBytes <= kMaximumCredSspRequestBytes);
        assert(peerResult.expectedPostTypeTwoCredSspPlaintextBytes > 0U);
        assert(status.acceptedClientPreauthDiagnostics
                   .postTypeTwoCompleteTsRequestCount == 2U);
        assert(status.acceptedClientPreauthDiagnostics
                   .postTypeTwoPartialTsRequestBytes == 0U);
        assert(status.acceptedClientPreauthDiagnostics
                   .postTypeTwoPlaintextBytes ==
               peerResult.expectedPostTypeTwoCredSspPlaintextBytes);
        assert(!status.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!status.acceptedClientPreauthDiagnostics.shareActivated);
    }
    return peerResult;
}

// All stage observations share one connection-local monotonic clock.
// Test ordering only; do not equate a local TLS write with remote receipt.
void assertConnectionLocalStageTimeline(
    const RuntimeAcceptedClientPreauthDiagnostics& diagnostics,
    bool peerEofObserved)
{
    assert(diagnostics.acceptedToTlsEstablishedAvailable);
    assert(diagnostics.preTlsTransportAttributionAvailable);
    assert(diagnostics.tlsEstablishedToTypeOneAvailable);
    assert(diagnostics.typeOneToTypeTwoQueuedAvailable);
    assert(diagnostics.directNtlmTypeTwoCreationToDeliveryAgeAvailable);
    if (!peerEofObserved)
    {
        assert(!diagnostics.preauthElapsedAtPeerEofAvailable);
        assert(!diagnostics.directNtlmTypeTwoToPeerEofAvailable);
        return;
    }
    assert(diagnostics.preauthElapsedAtPeerEofAvailable);
    assert(diagnostics.directNtlmTypeTwoToPeerEofAvailable);
    // The fixture is time-bounded; these sums cannot overflow uint64_t.
    const std::uint64_t preTlsStageMicroseconds =
        diagnostics.acceptedToFirstClientTransportByteMicroseconds +
        diagnostics.firstClientTransportByteToX224CompleteMicroseconds +
        diagnostics.x224CompleteToFirstServerTransportByteMicroseconds +
        diagnostics.firstServerTransportByteToX224ConfirmCompleteMicroseconds +
        diagnostics.x224ConfirmCompleteToFirstTlsClientByteMicroseconds +
        diagnostics.firstTlsClientByteToFirstTlsServerByteMicroseconds +
        diagnostics.firstTlsServerByteToTlsEstablishedMicroseconds;
    assert(diagnostics.acceptedToTlsEstablishedMicroseconds >=
           preTlsStageMicroseconds);
    assert(diagnostics.tlsHandshakeActiveWorkMicroseconds <=
           diagnostics.preTlsActiveWorkMicroseconds);
    const std::uint64_t preTlsWorkMicroseconds =
        diagnostics.preTlsReadWaitMicroseconds +
        diagnostics.preTlsWriteWaitMicroseconds +
        diagnostics.preTlsActiveWorkMicroseconds +
        diagnostics.preTlsUnattributedMicroseconds;
    assert(diagnostics.acceptedToTlsEstablishedMicroseconds ==
           preTlsWorkMicroseconds);
    assert(diagnostics.preTlsSocketPollMicroseconds <=
           diagnostics.preTlsReadWaitMicroseconds +
               diagnostics.preTlsWriteWaitMicroseconds);
    assert(diagnostics.preTlsReadReadyToServiceMicroseconds <=
           diagnostics.preTlsReadWaitMicroseconds);
    assert(diagnostics.preTlsWriteReadyToServiceMicroseconds <=
           diagnostics.preTlsWriteWaitMicroseconds);

    const std::uint64_t consecutiveStageMicroseconds =
        diagnostics.acceptedToTlsEstablishedMicroseconds +
        diagnostics.tlsEstablishedToTypeOneMicroseconds +
        diagnostics.typeOneToTypeTwoQueuedMicroseconds +
        diagnostics.directNtlmTypeTwoCreationToDeliveryMicroseconds +
        diagnostics.directNtlmTypeTwoToPeerEofMicroseconds;
    assert(diagnostics.preauthElapsedAtPeerEofMicroseconds >=
           consecutiveStageMicroseconds);
}

void assertAuthInfoFailureProjectionContract()
{
    using SourceReason = rdp_server::server::security::StandaloneAuthInfoFailureReason;
    using RuntimeReason = RuntimeAcceptedClientAuthInfoFailureReason;
    LinuxRuntimeConnectionAcceptanceDiagnostics source{};
    source.standalonePasswordSelected = true;
    source.standaloneCredentialGeneration = 41U;
    source.standaloneAuthenticationFailureStage =
        rdp_server::server::security::StandaloneAuthenticationFailureStage::AuthInfo;
    const auto projectedReason = [&source](SourceReason reason) noexcept {
        source.standaloneAuthInfoFailureReason = reason;
        return projectLinuxAcceptedClientPreauthDiagnostics(source).standaloneAuthInfoFailureReason;
    };
    assert(projectedReason(SourceReason::None) == RuntimeReason::None);
    assert(projectedReason(SourceReason::InvalidFrameOrSession) == RuntimeReason::FrameOrSessionInvalid);
    assert(projectedReason(SourceReason::InvalidProtectedLength) == RuntimeReason::ProtectedCredentialOrSignSealFailure);
    assert(projectedReason(SourceReason::SignSeal) == RuntimeReason::ProtectedCredentialOrSignSealFailure);
    assert(projectedReason(SourceReason::InvalidCredential) == RuntimeReason::CredentialStructureOrTypeFailure);
    assert(projectedReason(SourceReason::InvalidCredentialEnvelope) == RuntimeReason::CredentialStructureOrTypeFailure);
    assert(projectedReason(SourceReason::InvalidPasswordFields) == RuntimeReason::CredentialStructureOrTypeFailure);
    assert(projectedReason(SourceReason::UnsupportedCredentialType) == RuntimeReason::CredentialStructureOrTypeFailure);
    assert(projectedReason(SourceReason::NonEmptyDelegatedDomain) == RuntimeReason::DelegatedDomainRejected);
    assert(projectedReason(SourceReason::CredentialUnavailable) == RuntimeReason::CredentialUnavailableOrRevoked);
    assert(projectedReason(SourceReason::CredentialMismatch) == RuntimeReason::CredentialMismatch);
    assert(projectedReason(SourceReason::FrameRelease) == RuntimeReason::FrameReleaseFailure);
    source.standaloneAuthInfoFailureReason = SourceReason::CredentialMismatch;
    source.standaloneCredentialGeneration = 0U;
    assert(projectLinuxAcceptedClientPreauthDiagnostics(source).standaloneAuthInfoFailureReason == RuntimeReason::None);
    source.standaloneCredentialGeneration = 41U;
    source.standaloneAuthenticationFailureStage =
        rdp_server::server::security::StandaloneAuthenticationFailureStage::Admission;
    assert(projectLinuxAcceptedClientPreauthDiagnostics(source).standaloneAuthInfoFailureReason == RuntimeReason::None);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};
    const bool fullLifecycle =
        testCase == "direct-ntlm-reconnect-stop-start-lifecycle";
    const bool finalAuthInfoFragmentsReconnectOnly =
        testCase == "direct-ntlm-final-authinfo-tls-fragments-reconnect";
    const bool largeFinalAuthInfoFramingReconnectOnly =
        testCase ==
            "direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect";
    const bool admissionRetryOnly =
        testCase ==
            "admission-denial-retains-listener-and-accepts-second-tls" ||
        testCase ==
            "admission-denial-exposes-bounded-reason-and-retries" ||
        finalAuthInfoFragmentsReconnectOnly ||
        largeFinalAuthInfoFramingReconnectOnly;
    const bool typeTwoPeerEofOnly =
        testCase ==
            "direct-ntlm-type2-peer-eof-pre-admission-diagnostics";
    const bool stageTimelineDiagnosticsOnly =
        testCase == "direct-ntlm-preauth-stage-timeline-lifecycle" ||
        testCase ==
            "direct-ntlm-preauth-zero-timeout-readiness-attribution";
    const bool stopQueuedAuthInfoRetirementOnly =
        testCase == "direct-ntlm-stop-queued-authinfo-retirement";
    const bool authInfoDiagnosticReplacementOnly =
        testCase == "direct-ntlm-authinfo-diagnostic-replacement-fencing";
    const bool serviceNoStarvationOnly =
        testCase == "direct-ntlm-preauth-service-no-starvation";
    const bool typeTwoTimingDiagnosticsOnly =
        testCase == "direct-ntlm-type2-peer-eof-timing-diagnostics" ||
        stageTimelineDiagnosticsOnly;
    const bool postTypeTwoTimelineDiagnosticsOnly =
        testCase ==
            "direct-ntlm-post-type2-client-data-timeline-diagnostics";
    const bool postTypeTwoSilenceOnly =
        testCase == "direct-ntlm-post-type2-silence";
    const bool postTypeTwoPartialTlsRecordOnly =
        testCase == "direct-ntlm-post-type2-partial-tls-record";
    const bool postTypeTwoNonTypeThreeTsRequestOnly =
        testCase == "direct-ntlm-post-type2-non-type3-tsrequest";
    const bool postTypeTwoCloseNotifyOnly =
        testCase == "direct-ntlm-post-type2-tls-close-notify";
    const bool postTypeTwoOrderlyFinOnly =
        testCase == "direct-ntlm-post-type2-orderly-fin";
    const bool postTypeTwoImmediateRetryOnly =
        testCase == "direct-ntlm-post-type2-immediate-retry";
    const bool postTypeTwoObservationOnly =
        postTypeTwoSilenceOnly || postTypeTwoPartialTlsRecordOnly ||
        postTypeTwoNonTypeThreeTsRequestOnly ||
        postTypeTwoCloseNotifyOnly || postTypeTwoOrderlyFinOnly ||
        postTypeTwoImmediateRetryOnly;
    const bool typeTwoTimeoutOnly =
        testCase == "direct-ntlm-type2-waits-for-preauth-timeout";
    const bool peerCloseClassificationOnly =
        testCase ==
            "type2-peer-close-distinct-from-authentication-rejection";
    const bool invalidCredentialDiagnosticOnly =
        testCase == "direct-ntlm-invalid-credentials-diagnostic";
    const bool preauthOwnerLockIsolationOnly =
        testCase == "direct-ntlm-preauth-owner-lock-isolation";
    const bool preauthOwnerLogoutIsolationOnly =
        testCase == "direct-ntlm-preauth-owner-logout-isolation";
    const bool preauthOwnerSessionSwitchIsolationOnly =
        testCase == "direct-ntlm-preauth-owner-session-switch-isolation";
    const bool preauthOwnerPermissionRevokeIsolationOnly =
        testCase == "direct-ntlm-preauth-owner-permission-revoke-isolation";
    const bool preauthOwnerIsolationOnly =
        preauthOwnerLockIsolationOnly || preauthOwnerLogoutIsolationOnly ||
        preauthOwnerSessionSwitchIsolationOnly ||
        preauthOwnerPermissionRevokeIsolationOnly;
    const bool targetIdentityRetryOnly =
        testCase ==
            "connection-target-identity-retained-across-peer-retry";
    if (!fullLifecycle && !admissionRetryOnly && !typeTwoPeerEofOnly &&
        !typeTwoTimingDiagnosticsOnly && !serviceNoStarvationOnly &&
        !stopQueuedAuthInfoRetirementOnly &&
        !authInfoDiagnosticReplacementOnly &&
        !postTypeTwoTimelineDiagnosticsOnly && !postTypeTwoObservationOnly &&
        !typeTwoTimeoutOnly && !peerCloseClassificationOnly &&
        !invalidCredentialDiagnosticOnly &&
        !preauthOwnerIsolationOnly && !targetIdentityRetryOnly)
    {
        return 2;
    }

#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    return 77;
#else
    const auto processUid = static_cast<std::uint32_t>(::getuid());
    if (processUid == 0U)
        return 77;

    DirectNtlmLifecycleEvidence evidence(processUid);
    if (!evidence.valid())
        return 77;
    constexpr std::chrono::milliseconds kFixturePreauthTimeout{6000};
    LinuxRuntimeHostControl control(
        evidence,
        typeTwoTimeoutOnly
            ? kFixturePreauthTimeout
            : kRuntimeAcceptedClientPreauthTimeout);

    const auto recommendation =
        control.status().product.recommendedEndpoint;
    if (!recommendation.valid())
        return 77;
    in_addr parsedAddress{};
    if (::inet_pton(
            AF_INET, recommendation.address.c_str(),
            &parsedAddress) != 1)
    {
        return 77;
    }

    const CredentialFixture& credentialFixture =
        largeFinalAuthInfoFramingReconnectOnly
            ? kLargeCredentialFixture
            : kDefaultCredentialFixture;
    std::array<char16_t, kMaximumStandalonePasswordCodeUnits> passwordStorage{};
    auto password = copyCredentialPassword(
        credentialFixture, passwordStorage);
    assert(!password.empty());
    assert(control.configureStandaloneApplicationPassword(
        credentialFixture.username, password));
    assert(std::ranges::all_of(
        passwordStorage, [](char16_t value) { return value == u'\0'; }));
    const auto credential =
        control.standaloneApplicationPasswordObservation();
    assert(credential.configured && credential.generation != 0U);

    RuntimeHostPermissionRequest permission;
    permission.allowInput = true;
    permission.allowClipboard = false;
    permission.requestedLifetimeMilliseconds = 15U * 60U * 1000U;
    assert(control.requestHostPermissionSetup(permission).succeeded());

    std::uint16_t selectedPort = 0U;
    for (std::uint16_t port = 34300U; port < 34330U; ++port)
    {
        const RuntimeHostOptions options{
            recommendation.interfaceId, recommendation.address,
            port, true, false};
        assert(control.configure(options).succeeded());
        const auto started = control.startSharing();
        if (started.succeeded())
        {
            selectedPort = port;
            break;
        }
        assert(started.error == RuntimeHostError::PortUnavailable);
    }
    assert(selectedPort != 0U);

    const auto firstListener = control.status();
    assert(firstListener.listenerAvailable);
    assertPhysicalOwnerGrantActive(firstListener);
    assert(firstListener.credentialsConfigured);
    assert(!firstListener.nativeDesktopReady);
    assert(!firstListener.nativeDesktopInitializing);
    assertClipboardDormant(firstListener);
    const std::uint64_t firstListenerGeneration =
        firstListener.listenerGeneration;
    assert(firstListenerGeneration != 0U);
    assertFixedConnectionTargetIdentity(
        firstListener, recommendation.address, selectedPort,
        firstListenerGeneration);


    if (authInfoDiagnosticReplacementOnly)
    {
        assertAuthInfoFailureProjectionContract();
        std::atomic<bool> releaseFailedPeer{false}, failedPeerFinished{false};
        PeerResult failedPeerResult;
        std::thread failedPeer([&] {
            failedPeerResult = runDirectNtlmPeer(
                recommendation.address, selectedPort, true, 0x51U,
                releaseFailedPeer, false, FinalAuthInfoWritePattern::Complete,
                nullptr, kDefaultCredentialFixture,
                FinalAuthInfoCredentialPattern::MismatchedPassword);
            failedPeerFinished.store(true, std::memory_order_release);
        });
        assert(pumpUntilNewAttemptRetired(control, failedPeerFinished));
        const RuntimeHostStatus failed = control.status();
        const auto& failedDiagnostics = failed.acceptedClientPreauthDiagnostics;
        const std::uint64_t failedClientId = failedDiagnostics.acceptedClientId;
        assert(failed.listenerAvailable);
        assert(failed.listenerGeneration == firstListenerGeneration);
        assert(failed.activeClients.empty());
        assert(failedDiagnostics.available && failedClientId != 0U);
        assert(failedDiagnostics.credSspTransition == RuntimeAcceptedClientCredSspTransition::Failed);
        assert(failedDiagnostics.standaloneFailureStage == RuntimeAcceptedClientStandaloneFailureStage::AuthInfo);
        assert(failedDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::CredentialMismatch);
        assert(failedDiagnostics.standaloneCredentialGeneration == credential.generation);
        assert(failedDiagnostics.protocolStage == RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!failedDiagnostics.mcsSessionAdvanced && !failedDiagnostics.shareActivated);
        assertClipboardDormant(failed);
        assertGraphicsDormant(failed);
        releaseFailedPeer.store(true, std::memory_order_release);
        failedPeer.join();
        assert(failedPeerResult.directTypeTwoReceived);

        std::atomic<bool> replacementTypeTwoReceived{false}, releaseReplacementPeer{false}, replacementPeerFinished{false};
        PeerResult replacementPeerResult;
        std::thread replacementPeer([&] {
            replacementPeerResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                replacementTypeTwoReceived, releaseReplacementPeer);
            replacementPeerFinished.store(true, std::memory_order_release);
        });
        assert(pumpUntilPeerSignal(control, replacementTypeTwoReceived, replacementPeerFinished));
        const RuntimeHostStatus replacement = control.status();
        const auto& replacementDiagnostics = replacement.acceptedClientPreauthDiagnostics;
        assert(replacement.listenerAvailable && replacement.listenerGeneration == firstListenerGeneration);
        assert(replacement.activeClients.size() == 1U);
        assert(replacementDiagnostics.acceptedClientId != 0U && replacementDiagnostics.acceptedClientId != failedClientId);
        assert(replacementDiagnostics.standaloneCredentialGeneration == credential.generation);
        assert(replacementDiagnostics.standaloneFailureStage == RuntimeAcceptedClientStandaloneFailureStage::None);
        assert(replacementDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::None);
        assert(replacementDiagnostics.protocolStage == RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!replacementDiagnostics.mcsSessionAdvanced && !replacementDiagnostics.shareActivated);
        assertClipboardDormant(replacement);
        assertGraphicsDormant(replacement);

        assert(control.stopSharing().succeeded());
        const RuntimeHostStatus stopped = control.status();
        assert(stopped.stage == RuntimeHostStage::Stopped);
        assert(!stopped.listenerAvailable && stopped.activeClients.empty());
        assert(!stopped.acceptedClientPreauthDiagnostics.available);
        assert(stopped.acceptedClientPreauthDiagnostics.acceptedClientId == 0U);
        assert(stopped.acceptedClientPreauthDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::None);
        assert(control.standaloneApplicationPasswordObservation().generation == credential.generation);
        releaseReplacementPeer.store(true, std::memory_order_release);
        replacementPeer.join();
        assert(replacementPeerResult.passed && replacementPeerResult.directTypeTwoReceived);
        assert(!replacementPeerResult.authInfoSent);

        std::array<char16_t, kMaximumStandalonePasswordCodeUnits> replacementPasswordStorage{};
        auto replacementPassword = copyCredentialPassword(kDefaultCredentialFixture, replacementPasswordStorage);
        assert(!replacementPassword.empty());
        assert(control.configureStandaloneApplicationPassword(kDefaultCredentialFixture.username, replacementPassword));
        assert(std::ranges::all_of(replacementPassword, [](char16_t value) { return value == u'\0'; }));
        const auto replacementCredential = control.standaloneApplicationPasswordObservation();
        assert(replacementCredential.configured && replacementCredential.generation != 0U);
        assert(replacementCredential.generation != credential.generation);
        const RuntimeHostStatus afterCredentialReplacement = control.status();
        assert(!afterCredentialReplacement.listenerAvailable);
        assert(!afterCredentialReplacement.acceptedClientPreauthDiagnostics.available);
        assert(afterCredentialReplacement.acceptedClientPreauthDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::None);

        assert(control.requestHostPermissionSetup(permission).succeeded());
        assert(startSharingOnPort(control, recommendation, selectedPort));
        const RuntimeHostStatus restarted = control.status();
        assert(restarted.listenerAvailable && restarted.listenerGeneration != 0U);
        assert(restarted.listenerGeneration != firstListenerGeneration);
        assert(restarted.activeClients.empty());
        assert(!restarted.acceptedClientPreauthDiagnostics.available);
        assert(restarted.acceptedClientPreauthDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::None);

        const PeerResult authenticatedButDenied = runAdmissionDeniedPeer(
            control, recommendation.address, selectedPort, 0x61U,
            restarted.listenerGeneration, replacementCredential.generation);
        assert(authenticatedButDenied.directTypeTwoReceived);
        const RuntimeHostStatus afterAdmissionDenial = control.status();
        assert(afterAdmissionDenial.acceptedClientPreauthDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::None);
        assertClipboardDormant(afterAdmissionDenial);
        assertGraphicsDormant(afterAdmissionDenial);
        assert(control.stopSharing().succeeded());
        const RuntimeHostStatus finalStopped = control.status();
        assert(!finalStopped.acceptedClientPreauthDiagnostics.available);
        assert(finalStopped.acceptedClientPreauthDiagnostics.standaloneAuthInfoFailureReason == RuntimeAcceptedClientAuthInfoFailureReason::None);
        return 0;
    }

    if (stopQueuedAuthInfoRetirementOnly)
    {
        PendingAuthInfoGate gate;
        std::atomic<bool> releaseOldPeer{false};
        std::atomic<bool> oldPeerFinished{false};
        PeerResult oldPeerResult;
        std::thread oldPeer([&] {
            oldPeerResult = runDirectNtlmPeer(
                recommendation.address, selectedPort, true, 0x41U,
                releaseOldPeer, false, FinalAuthInfoWritePattern::Complete,
                &gate);
            oldPeerFinished.store(true, std::memory_order_release);
        });

        // The real client has verified R2's server pubKeyAuth reply.
        assert(pumpUntilPeerSignal(
            control, gate.serverBindingVerified, oldPeerFinished));
        const RuntimeHostStatus beforeStop = control.status();
        const std::uint64_t oldClientId =
            beforeStop.acceptedClientPreauthDiagnostics.acceptedClientId;
        assert(oldClientId != 0U);
        assert(beforeStop.listenerAvailable);
        assert(beforeStop.activeClients.size() == 1U);
        assert(!beforeStop.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!beforeStop.acceptedClientPreauthDiagnostics.shareActivated);
        assertClipboardDormant(beforeStop);
        assertGraphicsDormant(beforeStop);

        // The protected final authInfo reaches the old socket, but the
        // single R10 service owner does not consume it before Stop.
        gate.permitFinalAuthInfo.store(true, std::memory_order_release);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{8};
        while (!gate.finalAuthInfoWritten.load(std::memory_order_acquire) &&
               !oldPeerFinished.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        assert(gate.finalAuthInfoWritten.load(std::memory_order_acquire));
        assert(control.stopSharing().succeeded());
        const RuntimeHostStatus stopped = control.status();
        assert(stopped.stage == RuntimeHostStage::Stopped);
        assert(!stopped.listenerAvailable);
        assert(!stopped.hostOwnerAuthorized);
        assert(stopped.activeClients.empty());
        assert(!stopped.connectionTargetIdentity.valid());
        assert(!stopped.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!stopped.acceptedClientPreauthDiagnostics.shareActivated);
        assertClipboardDormant(stopped);
        assertGraphicsDormant(stopped);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        releaseOldPeer.store(true, std::memory_order_release);
        oldPeer.join();
        assert(oldPeerResult.passed && oldPeerResult.authInfoSent);

        // Only the approved memory credential survives the old generation.
        assert(control.requestHostPermissionSetup(permission).succeeded());
        assert(startSharingOnPort(control, recommendation, selectedPort));
        const RuntimeHostStatus restarted = control.status();
        assert(restarted.listenerAvailable);
        assert(restarted.listenerGeneration != firstListenerGeneration);
        assert(restarted.activeClients.empty());
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);

        std::atomic<bool> nextTypeTwoReceived{false};
        std::atomic<bool> releaseNextPeer{false};
        std::atomic<bool> nextPeerFinished{false};
        PeerResult nextPeerResult;
        std::thread nextPeer([&] {
            nextPeerResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                nextTypeTwoReceived, releaseNextPeer);
            nextPeerFinished.store(true, std::memory_order_release);
        });
        assert(pumpUntilPeerSignal(
            control, nextTypeTwoReceived, nextPeerFinished));
        const RuntimeHostStatus replacement = control.status();
        assert(replacement.listenerAvailable);
        assert(replacement.activeClients.size() == 1U);
        assert(replacement.acceptedClientPreauthDiagnostics.acceptedClientId !=
               oldClientId);
        assert(control.disconnectClient(oldClientId).error ==
               RuntimeHostError::ClientNotFound);
        const RuntimeHostStatus unaffected = control.status();
        assert(unaffected.listenerAvailable);
        assert(unaffected.activeClients.size() == 1U);
        assert(unaffected.acceptedClientPreauthDiagnostics.acceptedClientId ==
               replacement.acceptedClientPreauthDiagnostics.acceptedClientId);
        assertClipboardDormant(unaffected);
        assertGraphicsDormant(unaffected);
        releaseNextPeer.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        nextPeer.join();
        assert(nextPeerResult.passed && nextPeerResult.directTypeTwoReceived);

        // A subsequent complete CredSSP exchange remains unable to mint a
        // native R2 lease from the synthetic evidence fixture.
        const PeerResult denied = runAdmissionDeniedPeer(
            control, recommendation.address, selectedPort, 0x43U,
            restarted.listenerGeneration, credential.generation);
        assert(denied.directTypeTwoReceived);
        assert(control.stopSharing().succeeded());
        assert(control.revokeSharing().succeeded());
        return 0;
    }

    if (serviceNoStarvationOnly)
    {
        std::atomic<bool> typeTwoReceived{false};
        std::atomic<bool> releasePeer{false};
        std::atomic<bool> peerFinished{false};
        PeerResult peerResult;
        std::thread peer([&] {
            peerResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                typeTwoReceived, releasePeer);
            peerFinished.store(true, std::memory_order_release);
        });

        RuntimeHostResult acceptedResult{RuntimeHostError::None, true};
        const auto acceptDeadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{8};
        while (std::chrono::steady_clock::now() < acceptDeadline)
        {
            acceptedResult = control.serviceOnce();
            if (!control.status().activeClients.empty())
                break;
            if (peerFinished.load(std::memory_order_acquire))
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        assert(acceptedResult.succeeded());
        assert(!acceptedResult.retryable);
        assert(!control.status().activeClients.empty());

        const std::uint64_t ownerReadsBeforePreauth =
            evidence.activeConsoleReadCount();
        evidence.setActiveConsoleReadDelay(std::chrono::milliseconds{250});
        (void)control.status();
        assert(evidence.activeConsoleReadCount() == ownerReadsBeforePreauth);
        std::this_thread::sleep_for(std::chrono::milliseconds{75});

        RuntimeHostStatus stageStatus = control.status();
        const auto typeOneDeadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{8};
        while (!stageStatus.acceptedClientPreauthDiagnostics
                    .tlsEstablishedToTypeOneAvailable &&
               !peerFinished.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < typeOneDeadline)
        {
            // Inspect after every bounded production service step so this
            // early-stage assertion cannot accidentally cross Type 1, deliver
            // Type 2, and then observe legitimate Await-Type-3 owner maintenance
            // inside the same GUI burst.
            const RuntimeHostResult step = control.serviceOnce();
            assert(step.succeeded());
            stageStatus = control.status();
            assert(evidence.activeConsoleReadCount() == ownerReadsBeforePreauth);
            if (step.retryable)
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        assert(stageStatus.acceptedClientPreauthDiagnostics
                   .tlsEstablishedToTypeOneAvailable);
        evidence.setActiveConsoleReadDelay(std::chrono::milliseconds{0});

        const auto typeTwoDeadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{8};
        while (!typeTwoReceived.load(std::memory_order_acquire) &&
               !peerFinished.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < typeTwoDeadline)
        {
            const auto burst = serviceLinuxRuntimeBoundedBurst(
                [&control] { return control.serviceOnce(); });
            assert(burst.serviceCalls > 0U);
            assert(burst.serviceCalls <= kLinuxRuntimeServiceBurstLimit);
            assert(burst.lastResult.succeeded());
            if (!burst.immediateReschedule)
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        assert(typeTwoReceived.load(std::memory_order_acquire));

        const auto waiting = control.status();
        assertPreAdmissionNativeIsolation(waiting);
        const auto& diagnostics = waiting.acceptedClientPreauthDiagnostics;
        assert(diagnostics.acceptedToTlsServiceTiming.available);
        assert(diagnostics.tlsEstablishedToTypeOneServiceTiming.available);
        assert(diagnostics.acceptedToTlsServiceTiming.serviceInvocations > 0U);
        assert(diagnostics.tlsEstablishedToTypeOneServiceTiming
                   .serviceInvocations > 0U);
        assert(diagnostics.acceptedToTlsServiceTiming
                   .nativeMaintenanceMicroseconds == 0U);
        assert(diagnostics.tlsEstablishedToTypeOneServiceTiming
                   .nativeMaintenanceMicroseconds == 0U);
        constexpr std::uint64_t kMinimumInjectedGapMicroseconds{50'000U};
        assert(diagnostics.acceptedToTlsServiceTiming
                   .applicationRescheduleWaitMicroseconds >=
               kMinimumInjectedGapMicroseconds);
        assert(diagnostics.acceptedToTlsServiceTiming
                   .maximumApplicationRescheduleWaitMicroseconds >=
               kMinimumInjectedGapMicroseconds);

        releasePeer.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        peer.join();
        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);

        const auto retired = control.status();
        assert(retired.listenerAvailable);
        assert(retired.activeClients.empty());
        assert(!retired.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!retired.acceptedClientPreauthDiagnostics.shareActivated);
        assertClipboardDormant(retired);
        assertGraphicsDormant(retired);
        assert(control.stopSharing().succeeded());
        assert(control.revokeSharing().succeeded());
        return 0;
    }

    if (preauthOwnerIsolationOnly)
    {
        std::atomic<bool> typeTwoReceived{false};
        std::atomic<bool> releasePeer{false};
        std::atomic<bool> peerFinished{false};
        PeerResult peerResult;
        std::thread peer([&] {
            peerResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                typeTwoReceived, releasePeer);
            peerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilPeerSignal(control, typeTwoReceived, peerFinished));
        const auto waiting = control.status();
        assertPreAdmissionNativeIsolation(waiting);

        if (preauthOwnerLockIsolationOnly)
        {
            evidence.lockDesktop();
            const auto transition = control.serviceOnce();
            assert(
                transition.error == RuntimeHostError::CredentialNotConfigured);
        }
        else if (preauthOwnerLogoutIsolationOnly)
        {
            evidence.logoutDesktop();
            const auto transition = control.serviceOnce();
            assert(
                transition.error == RuntimeHostError::CredentialNotConfigured);
        }
        else if (preauthOwnerSessionSwitchIsolationOnly)
        {
            evidence.switchDesktopSession();
            const auto transition = control.serviceOnce();
            assert(
                transition.error == RuntimeHostError::CredentialNotConfigured);
        }
        else
        {
            assert(preauthOwnerPermissionRevokeIsolationOnly);
            assert(control.revokeSharing().succeeded());
        }

        const auto retired = control.status();
        assert(retired.activeClients.empty());
        assert(!retired.listenerAvailable);
        assertClipboardDormant(retired);
        assertGraphicsDormant(retired);
        if (preauthOwnerPermissionRevokeIsolationOnly)
        {
            assert(retired.stage == RuntimeHostStage::Revoked);
            assert(retired.lastError == RuntimeHostError::AccessRevoked);
        }
        else
        {
            assert(retired.stage == RuntimeHostStage::Stopped);
            assert(
                retired.lastError == RuntimeHostError::CredentialNotConfigured);
            assert(!retired.credentialsConfigured);
        }

        releasePeer.store(true, std::memory_order_release);
        peer.join();
        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);
        return 0;
    }

    if (invalidCredentialDiagnosticOnly)
    {
        std::atomic<bool> releasePeer{false};
        std::atomic<bool> peerFinished{false};
        PeerResult peerResult;
        std::thread peer([&] {
            peerResult = runDirectNtlmPeer(
                recommendation.address, selectedPort, false, 0x11U,
                releasePeer, true);
            peerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilNewAttemptRetired(control, peerFinished));
        const auto rejected = control.status();
        const auto& diagnostics = rejected.acceptedClientPreauthDiagnostics;
        assert(rejected.lastError == RuntimeHostError::AuthenticationRejected);
        assert(rejected.listenerAvailable);
        assert(rejected.listenerGeneration == firstListenerGeneration);
        assert(rejected.activeClients.empty());
        assert(diagnostics.available);
        assert(diagnostics.acceptedClientId != 0U);
        assert(diagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmAuthenticate);
        assert(diagnostics.credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::Failed);
        assert(diagnostics.standaloneFailureStage ==
               RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation);
        assert(diagnostics.standaloneCredentialsRejected);
        assert(diagnostics.admissionFailureReason ==
               RuntimeAcceptedClientAdmissionFailureReason::None);
        assert(diagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!diagnostics.mcsSessionAdvanced);
        assert(!diagnostics.shareActivated);
        assert(!rejected.nativeDesktopReady);
        assert(!rejected.graphicsReady);

        releasePeer.store(true, std::memory_order_release);
        peer.join();
        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);
        assert(control.stopSharing().succeeded());
        assert(control.revokeSharing().succeeded());
        return 0;
    }

    if (postTypeTwoObservationOnly)
    {
        PostTypeTwoPeerAction action = PostTypeTwoPeerAction::Silence;
        if (postTypeTwoPartialTlsRecordOnly)
            action = PostTypeTwoPeerAction::PartialTlsRecord;
        else if (postTypeTwoNonTypeThreeTsRequestOnly)
            action = PostTypeTwoPeerAction::CompleteNonTypeThreeTsRequest;
        else if (postTypeTwoCloseNotifyOnly)
            action = PostTypeTwoPeerAction::TlsCloseNotify;
        else if (postTypeTwoOrderlyFinOnly || postTypeTwoImmediateRetryOnly)
            action = PostTypeTwoPeerAction::OrderlyFin;

        std::atomic<bool> typeTwoReceived{false};
        std::atomic<bool> performAction{false};
        std::atomic<bool> actionApplied{false};
        std::atomic<bool> releasePeer{false};
        std::atomic<bool> peerFinished{false};
        PeerResult peerResult;
        std::thread peer([&] {
            peerResult = runPostTypeTwoObservationPeer(
                recommendation.address, selectedPort, action,
                typeTwoReceived, performAction, actionApplied, releasePeer);
            peerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilPeerSignal(control, typeTwoReceived, peerFinished));
        auto waiting = control.status();
        assert(waiting.activeClients.size() == 1U);
        const std::uint64_t firstClientId =
            waiting.activeClients.front().opaqueId;
        assert(firstClientId != 0U);
        assertPostTypeTwoSilence(waiting);
        assertClipboardDormant(waiting);
        assertGraphicsDormant(waiting);

        performAction.store(true, std::memory_order_release);
        assert(pumpUntilPeerSignal(control, actionApplied, peerFinished));

        if (postTypeTwoSilenceOnly)
        {
            const auto holdUntil =
                std::chrono::steady_clock::now() +
                std::chrono::milliseconds{150};
            while (std::chrono::steady_clock::now() < holdUntil)
            {
                (void)control.serviceOnce();
                waiting = control.status();
                assert(waiting.activeClients.size() == 1U);
                assertPostTypeTwoSilence(waiting);
            }
        }
        else if (postTypeTwoPartialTlsRecordOnly)
        {
            assert(pumpUntil(
                control, peerFinished, &postTypeTwoEncryptedBytesObserved));
            waiting = control.status();
            const auto& live = waiting.acceptedClientPreauthDiagnostics;
            assert(live.postTypeTwoClientTlsBytes >= 6U);
            assert(live.postTypeTwoPlaintextBytes == 0U);
            assert(live.postTypeTwoCompleteTsRequestCount == 0U);
            assert(live.postTypeTwoPartialTsRequestBytes == 0U);
            assert(live.postTypeTwoTlsAlertsReceived == 0U);
        }

        if (postTypeTwoSilenceOnly || postTypeTwoPartialTlsRecordOnly)
            releasePeer.store(true, std::memory_order_release);

        assert(pumpUntilClientRetired(control));
        releasePeer.store(true, std::memory_order_release);
        peer.join();
        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);

        const auto terminal = control.status();
        const auto& diagnostics = terminal.acceptedClientPreauthDiagnostics;
        assert(terminal.listenerAvailable);
        assert(terminal.listenerGeneration == firstListenerGeneration);
        assert(terminal.activeClients.empty());
        assert(diagnostics.directNtlmTypeTwoDelivered);
        assert(!diagnostics.mcsSessionAdvanced);
        assert(!diagnostics.shareActivated);
        assertClipboardDormant(terminal);
        assertGraphicsDormant(terminal);

        if (postTypeTwoSilenceOnly || postTypeTwoOrderlyFinOnly ||
            postTypeTwoImmediateRetryOnly)
        {
            assert(diagnostics.postTypeTwoClientTlsBytes == 0U);
            assert(!diagnostics.postTypeTwoFirstClientTlsByteAvailable);
            assert(diagnostics.postTypeTwoPlaintextBytes == 0U);
            assert(diagnostics.postTypeTwoCompleteTsRequestCount == 0U);
            assert(diagnostics.postTypeTwoPartialTsRequestBytes == 0U);
            assert(diagnostics.postTypeTwoTlsAlertsReceived == 0U);
            assert(!diagnostics.postTypeTwoTlsCloseNotifyReceived);
            assert(diagnostics.postTypeTwoTcpFinReceived);
            assert(!diagnostics.postTypeTwoTcpResetReceived);
            assert(diagnostics.directNtlmTypeTwoToPeerEofAvailable);
        }
        else if (postTypeTwoPartialTlsRecordOnly)
        {
            assert(diagnostics.postTypeTwoClientTlsBytes >= 6U);
            assert(diagnostics.postTypeTwoFirstClientTlsByteAvailable);
            assert(diagnostics.postTypeTwoPlaintextBytes == 0U);
            assert(diagnostics.postTypeTwoCompleteTsRequestCount == 0U);
            assert(diagnostics.postTypeTwoPartialTsRequestBytes == 0U);
            assert(diagnostics.postTypeTwoTlsAlertsReceived == 0U);
            assert(diagnostics.postTypeTwoTcpFinReceived);
            assert(!diagnostics.postTypeTwoTcpResetReceived);
            assert(diagnostics.directNtlmTypeTwoToPeerEofAvailable);
        }
        else if (postTypeTwoNonTypeThreeTsRequestOnly)
        {
            assert(diagnostics.postTypeTwoClientTlsBytes != 0U);
            assert(diagnostics.postTypeTwoFirstClientTlsByteAvailable);
            assert(diagnostics.postTypeTwoPlaintextBytes != 0U);
            assert(diagnostics.postTypeTwoCompleteTsRequestCount == 1U);
            assert(diagnostics.postTypeTwoPartialTsRequestBytes == 0U);
        }
        else if (postTypeTwoCloseNotifyOnly)
        {
            assert(diagnostics.postTypeTwoClientTlsBytes != 0U);
            assert(diagnostics.postTypeTwoFirstClientTlsByteAvailable);
            assert(diagnostics.postTypeTwoPlaintextBytes == 0U);
            assert(diagnostics.postTypeTwoCompleteTsRequestCount == 0U);
            assert(diagnostics.postTypeTwoPartialTsRequestBytes == 0U);
            assert(diagnostics.postTypeTwoTlsAlertsReceived != 0U);
            assert(diagnostics.postTypeTwoTlsCloseNotifyReceived);
            assert(!diagnostics.postTypeTwoTcpFinReceived);
            assert(!diagnostics.postTypeTwoTcpResetReceived);
            assert(diagnostics.termination ==
                   RuntimeAcceptedClientTermination::OrderlyTlsClose);
        }

        if (postTypeTwoImmediateRetryOnly)
        {
            std::atomic<bool> retryTypeTwoReceived{false};
            std::atomic<bool> retryPerformAction{false};
            std::atomic<bool> retryActionApplied{false};
            std::atomic<bool> releaseRetry{false};
            std::atomic<bool> retryFinished{false};
            PeerResult retryResult;
            std::thread retry([&] {
                retryResult = runPostTypeTwoObservationPeer(
                    recommendation.address, selectedPort,
                    PostTypeTwoPeerAction::Silence,
                    retryTypeTwoReceived, retryPerformAction,
                    retryActionApplied, releaseRetry);
                retryFinished.store(true, std::memory_order_release);
            });

            assert(pumpUntilPeerSignal(
                control, retryTypeTwoReceived, retryFinished));
            const auto retryWaiting = control.status();
            assert(retryWaiting.listenerGeneration == firstListenerGeneration);
            assert(retryWaiting.activeClients.size() == 1U);
            assert(retryWaiting.activeClients.front().opaqueId != firstClientId);
            assertPostTypeTwoSilence(retryWaiting);
            assertPhysicalOwnerGrantActive(retryWaiting);
            assert(retryWaiting.product.credentialsConfigured);

            retryPerformAction.store(true, std::memory_order_release);
            assert(pumpUntilPeerSignal(
                control, retryActionApplied, retryFinished));
            releaseRetry.store(true, std::memory_order_release);
            assert(pumpUntilClientRetired(control));
            retry.join();
            assert(retryResult.passed);
            assert(retryResult.directTypeTwoReceived);
        }

        assert(control.stopSharing().succeeded());
        assert(control.revokeSharing().succeeded());
        return 0;
    }

    if (typeTwoTimeoutOnly)
    {
        std::atomic<bool> typeTwoReceived{false};
        std::atomic<bool> releasePeer{false};
        std::atomic<bool> peerFinished{false};
        PeerResult peerResult;
        std::thread peer([&] {
            peerResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                typeTwoReceived, releasePeer);
            peerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilPeerSignal(control, typeTwoReceived, peerFinished));
        auto waitingForTypeThree = control.status();
        assert(waitingForTypeThree.stage ==
               RuntimeHostStage::ClientAuthenticating);
        assert(waitingForTypeThree.listenerAvailable);
        assert(waitingForTypeThree.listenerGeneration ==
               firstListenerGeneration);
        assertPhysicalOwnerGrantActive(waitingForTypeThree);
        assert(waitingForTypeThree.activeClients.size() == 1U);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmChallenge);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .mcsSessionAdvanced);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .shareActivated);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .termination ==
               RuntimeAcceptedClientTermination::Open);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoQueued);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoDelivered);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None);
        assert(waitingForTypeThree.product.credentialsConfigured);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        assertClipboardDormant(waitingForTypeThree);
        assertGraphicsDormant(waitingForTypeThree);

        // Type 2 has been read and validated by the real TLS peer. Keep
        // servicing for a bounded interval shorter than the accepted-client
        // deadline and prove there is no Type-2-specific immediate teardown.
        const auto holdUntil =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{500};
        while (std::chrono::steady_clock::now() < holdUntil)
        {
            (void)control.serviceOnce();
            waitingForTypeThree = control.status();
            assert(waitingForTypeThree.stage ==
                   RuntimeHostStage::ClientAuthenticating);
            assert(waitingForTypeThree.listenerAvailable);
            assert(waitingForTypeThree.listenerGeneration ==
                   firstListenerGeneration);
            assert(waitingForTypeThree.activeClients.size() == 1U);
            assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                       .termination ==
                   RuntimeAcceptedClientTermination::Open);
            assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                       .directNtlmTypeTwoDelivered);
            assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                        .mcsSessionAdvanced);
            assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                        .shareActivated);
            assert(waitingForTypeThree.product.credentialsConfigured);
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }

        assert(pumpUntil(
            control, peerFinished, &directTypeTwoTimeoutRemainsPreAdmission));
        const auto afterTimeout = control.status();
        assert(afterTimeout.stage == RuntimeHostStage::ListenerAvailable);
        assert(afterTimeout.listenerAvailable);
        assert(afterTimeout.listenerGeneration == firstListenerGeneration);
        assertPhysicalOwnerGrantActive(afterTimeout);
        assert(afterTimeout.product.state == RuntimeProductHostState::Listening);
        assert(afterTimeout.product.credentialsConfigured);
        assert(afterTimeout.acceptedClientPreauthDiagnostics.termination ==
               RuntimeAcceptedClientTermination::Timeout);
        assert(afterTimeout.acceptedClientPreauthDiagnostics.preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None);
        assert(!afterTimeout.acceptedClientPreauthDiagnostics.mcsSessionAdvanced);
        assert(!afterTimeout.acceptedClientPreauthDiagnostics.shareActivated);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        assertClipboardDormant(afterTimeout);
        assertGraphicsDormant(afterTimeout);

        releasePeer.store(true, std::memory_order_release);
        peer.join();
        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);

        assert(control.stopSharing().succeeded());
        assert(control.revokeSharing().succeeded());
        return 0;
    }

    if (typeTwoPeerEofOnly || typeTwoTimingDiagnosticsOnly ||
        postTypeTwoTimelineDiagnosticsOnly ||
        peerCloseClassificationOnly || targetIdentityRetryOnly)
    {
        std::atomic<bool> typeTwoReceived{false};
        std::atomic<bool> closeAfterTypeTwo{false};
        std::atomic<bool> peerFinished{false};
        PeerResult peerResult;
        std::thread peer([&] {
            peerResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                typeTwoReceived, closeAfterTypeTwo);
            peerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilPeerSignal(
            control, typeTwoReceived, peerFinished));
        const auto waitingForTypeThree = control.status();
        assert(waitingForTypeThree.activeClients.size() == 1U);
        const std::uint64_t firstAcceptedClientId =
            waitingForTypeThree.activeClients.front().opaqueId;
        assert(firstAcceptedClientId != 0U);
        assertPhysicalOwnerGrantActive(waitingForTypeThree);
        if (stageTimelineDiagnosticsOnly)
            assertConnectionLocalStageTimeline(
                waitingForTypeThree.acceptedClientPreauthDiagnostics, false);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics.available);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics.ntlmEnvelope ==
               RuntimeAcceptedClientNtlmEnvelope::DirectNtlm);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmChallenge);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::AwaitingToken);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .standaloneFailureStage ==
               RuntimeAcceptedClientStandaloneFailureStage::None);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .admissionFailureReason ==
               RuntimeAcceptedClientAdmissionFailureReason::None);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .termination ==
               RuntimeAcceptedClientTermination::Open);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoQueued);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoDelivered);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoCreationToDeliveryAgeAvailable);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .preauthElapsedAtPeerEofAvailable);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .directNtlmTypeTwoToPeerEofAvailable);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .postTypeTwoFirstClientTlsByteAvailable);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .postTypeTwoCompleteTsRequestCount == 0U);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .postTypeTwoPlaintextBytes == 0U);
        assert(waitingForTypeThree.acceptedClientPreauthDiagnostics
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .mcsSessionAdvanced);
        assert(!waitingForTypeThree.acceptedClientPreauthDiagnostics
                    .shareActivated);
        assert(waitingForTypeThree.stage != RuntimeHostStage::ShareActivated);
        assert(waitingForTypeThree.activeClients.front().authenticating);
        assert(!waitingForTypeThree.activeClients.front().shareActivated);
        assert(!waitingForTypeThree.activeClients.front().desktopVisible);
        assertClipboardDormant(waitingForTypeThree);
        assertGraphicsDormant(waitingForTypeThree);
        assertFixedConnectionTargetIdentity(
            waitingForTypeThree, recommendation.address, selectedPort,
            firstListenerGeneration);
        assert(physicalClientEnvironmentDiagnosticsMatch(
            waitingForTypeThree));

        if (typeTwoPeerEofOnly)
        {
            // Hold the exact production-backed peer in Await-Type-3 across a
            // sustained bounded service window. Elapsed wall time grants no
            // authority: this accepted connection and every clipboard/native
            // path must remain unchanged until the peer actually closes.
            constexpr std::chrono::milliseconds
                kLongPreTypeThreeClipboardDormancyHold{1500};
            const auto holdUntil =
                std::chrono::steady_clock::now() +
                kLongPreTypeThreeClipboardDormancyHold;
            do
            {
                (void)control.serviceOnce();
                const RuntimeHostStatus stalled = control.status();
                assert(stalled.listenerAvailable);
                assert(stalled.listenerGeneration == firstListenerGeneration);
                assert(stalled.activeClients.size() == 1U);
                assert(stalled.activeClients.front().opaqueId ==
                       firstAcceptedClientId);
                assert(stalled.activeClients.front().authenticating);
                assert(!stalled.activeClients.front().shareActivated);
                assert(!stalled.activeClients.front().desktopVisible);
                assert(stalled.acceptedClientPreauthDiagnostics.available);
                assert(stalled.acceptedClientPreauthDiagnostics
                           .authenticationStage ==
                       RuntimeAcceptedClientAuthenticationStage::NtlmChallenge);
                assert(stalled.acceptedClientPreauthDiagnostics.protocolStage ==
                       RuntimeAcceptedClientProtocolStage::PreAdmission);
                assert(stalled.acceptedClientPreauthDiagnostics
                           .directNtlmTypeTwoDelivered);
                assert(stalled.acceptedClientPreauthDiagnostics.termination ==
                       RuntimeAcceptedClientTermination::Open);
                assert(!stalled.acceptedClientPreauthDiagnostics
                            .preauthElapsedAtPeerEofAvailable);
                assert(stalled.acceptedClientPreauthDiagnostics
                           .preType3Termination ==
                       RuntimeAcceptedClientPreType3Termination::None);
                assert(!stalled.acceptedClientPreauthDiagnostics
                            .mcsSessionAdvanced);
                assert(!stalled.acceptedClientPreauthDiagnostics
                            .shareActivated);
                assertPhysicalOwnerGrantActive(stalled);
                assert(stalled.product.credentialsConfigured);
                assert(control.standaloneApplicationPasswordObservation()
                           .generation == credential.generation);
                assertClipboardDormant(stalled);
                assertGraphicsDormant(stalled);
                assertFixedConnectionTargetIdentity(
                    stalled, recommendation.address, selectedPort,
                    firstListenerGeneration);
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            } while (std::chrono::steady_clock::now() < holdUntil);
        }

        closeAfterTypeTwo.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        peer.join();

        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);
        const auto afterTypeTwoEof = control.status();
        if (stageTimelineDiagnosticsOnly)
            assertConnectionLocalStageTimeline(
                afterTypeTwoEof.acceptedClientPreauthDiagnostics, true);
        assert(directTypeTwoPeerEofRemainsPreAdmission(afterTypeTwoEof));
        assert(afterTypeTwoEof.activeClients.empty());
        assert(afterTypeTwoEof.listenerGeneration == firstListenerGeneration);
        assertPhysicalOwnerGrantActive(afterTypeTwoEof);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoQueued);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoDelivered);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::PeerEof);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoCreationToDeliveryAgeAvailable);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preauthElapsedAtPeerEofAvailable);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preauthElapsedAtPeerEofMicroseconds >=
               afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoCreationToDeliveryMicroseconds);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoToPeerEofAvailable);
        assert(!afterTypeTwoEof.acceptedClientPreauthDiagnostics
                    .postTypeTwoFirstClientTlsByteAvailable);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .postTypeTwoCompleteTsRequestCount == 0U);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .postTypeTwoPlaintextBytes == 0U);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics.protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(!afterTypeTwoEof.acceptedClientPreauthDiagnostics
                    .mcsSessionAdvanced);
        assert(!afterTypeTwoEof.acceptedClientPreauthDiagnostics
                    .shareActivated);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .admissionFailureReason ==
               RuntimeAcceptedClientAdmissionFailureReason::None);
        assertClipboardDormant(afterTypeTwoEof);
        assertGraphicsDormant(afterTypeTwoEof);
        assert(afterTypeTwoEof.product.state ==
               RuntimeProductHostState::Listening);
        assert(afterTypeTwoEof.product.credentialsConfigured);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        assertFixedConnectionTargetIdentity(
            afterTypeTwoEof, recommendation.address, selectedPort,
            firstListenerGeneration);

        if (peerCloseClassificationOnly)
        {
            // A malformed Type 3 is a real authentication rejection, unlike
            // the preceding peer-driven interruption after a delivered Type 2.
            // Observe the new accepted lifetime before accepting its terminal
            // snapshot so stale peer-1 diagnostics cannot satisfy this gate.
            std::atomic<bool> releaseRejected{false};
            std::atomic<bool> rejectedFinished{false};
            PeerResult rejectedResult;
            std::thread rejectedPeer([&] {
                rejectedResult = runDirectNtlmPeer(
                    recommendation.address, selectedPort, false, 0x20U,
                    releaseRejected);
                rejectedFinished.store(true, std::memory_order_release);
            });
            assert(pumpUntilNewAttemptRetired(control, rejectedFinished));

            const auto afterRejectedTypeThree = control.status();
            assert(afterRejectedTypeThree.lastError ==
                   RuntimeHostError::AuthenticationRejected);
            assert(afterRejectedTypeThree.listenerAvailable);
            assert(afterRejectedTypeThree.listenerGeneration ==
                   firstListenerGeneration);
            assert(afterRejectedTypeThree.hostOwnerAuthorized);
            assert(afterRejectedTypeThree.product.ownerAuthorized);
            assert(afterRejectedTypeThree.product.credentialsConfigured);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .authenticationStage ==
                   RuntimeAcceptedClientAuthenticationStage::NtlmAuthenticate);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .protocolStage ==
                   RuntimeAcceptedClientProtocolStage::PreAdmission);
            assert(!afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                        .mcsSessionAdvanced);
            assert(!afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                        .shareActivated);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .admissionFailureReason ==
                   RuntimeAcceptedClientAdmissionFailureReason::None);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .directNtlmTypeTwoDelivered);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoFirstClientTlsByteAvailable);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoPlaintextBytes > 0U);
            assert(afterRejectedTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoCompleteTsRequestCount == 1U);
            assert(control.standaloneApplicationPasswordObservation().generation ==
                   credential.generation);

            releaseRejected.store(true, std::memory_order_release);
            rejectedPeer.join();
            assert(rejectedResult.passed);
            assert(rejectedResult.directTypeTwoReceived);
            assert(!rejectedResult.authInfoSent);

            // A later fully verified credential exchange reaches the separate
            // native Admission boundary. Its denial remains AuthenticationRejected
            // and carries a concrete admission reason.
            const PeerResult admissionDeniedResult = runAdmissionDeniedPeer(
                control, recommendation.address, selectedPort, 0x30U,
                firstListenerGeneration, credential.generation);
            assert(challengesDiffer(
                peerResult.serverChallenge,
                rejectedResult.serverChallenge));
            assert(challengesDiffer(
                rejectedResult.serverChallenge,
                admissionDeniedResult.serverChallenge));

            assert(control.stopSharing().succeeded());
            const auto retainedCredential =
                control.standaloneApplicationPasswordObservation();
            assert(retainedCredential.configured);
            assert(retainedCredential.generation == credential.generation);
            assert(control.revokeSharing().succeeded());
            assert(!control.standaloneApplicationPasswordObservation().configured);
            return 0;
        }

        // R8 stale-lifetime gate: observe the next accepted connection before
        // it can send Type 3. Native/clipboard construction is GraphicsReady-
        // only, so a PreAdmission peer must not inherit a CLIPRDR owner or
        // clipboard generation from the retired peer.
        std::atomic<bool> retryTypeTwoReceived{false};
        std::atomic<bool> closeRetryAfterTypeTwo{false};
        std::atomic<bool> retryPeerFinished{false};
        PeerResult retryTypeTwoResult;
        constexpr std::array<std::uint8_t, 1> kPartialPostTypeTwoRequest{
            0x30U};
        std::thread retryTypeTwoPeer([&] {
            retryTypeTwoResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                retryTypeTwoReceived, closeRetryAfterTypeTwo,
                postTypeTwoTimelineDiagnosticsOnly
                    ? ByteSpan{kPartialPostTypeTwoRequest}
                    : ByteSpan{});
            retryPeerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilPeerSignal(
            control, retryTypeTwoReceived, retryPeerFinished));
        if (postTypeTwoTimelineDiagnosticsOnly)
        {
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds{8};
            while (std::chrono::steady_clock::now() < deadline)
            {
                const auto status = control.status();
                if (status.acceptedClientPreauthDiagnostics
                        .postTypeTwoFirstClientTlsByteAvailable &&
                    status.acceptedClientPreauthDiagnostics
                        .postTypeTwoPlaintextBytes > 0U)
                {
                    break;
                }
                assert(!retryPeerFinished.load(std::memory_order_acquire));
                (void)control.serviceOnce();
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }
        const auto retryWaitingForTypeThree = control.status();
        if (stageTimelineDiagnosticsOnly)
            assertConnectionLocalStageTimeline(
                retryWaitingForTypeThree.acceptedClientPreauthDiagnostics,
                false);
        assert(retryWaitingForTypeThree.listenerAvailable);
        assert(retryWaitingForTypeThree.listenerGeneration ==
               firstListenerGeneration);
        assert(retryWaitingForTypeThree.activeClients.size() == 1U);
        assert(retryWaitingForTypeThree.activeClients.front().opaqueId != 0U);
        assert(retryWaitingForTypeThree.activeClients.front().opaqueId !=
               firstAcceptedClientId);
        assert(retryWaitingForTypeThree.activeClients.front().authenticating);
        assert(!retryWaitingForTypeThree.activeClients.front().shareActivated);
        assert(!retryWaitingForTypeThree.activeClients.front().desktopVisible);
        assertPhysicalOwnerGrantActive(retryWaitingForTypeThree);
        assert(retryWaitingForTypeThree.product.credentialsConfigured);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        assert(!retryWaitingForTypeThree.clientDisconnected);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics.available);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .ntlmEnvelope ==
               RuntimeAcceptedClientNtlmEnvelope::DirectNtlm);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmChallenge);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .protocolStage ==
               RuntimeAcceptedClientProtocolStage::PreAdmission);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .credSspTransition ==
               RuntimeAcceptedClientCredSspTransition::AwaitingToken);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .standaloneFailureStage ==
               RuntimeAcceptedClientStandaloneFailureStage::None);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .admissionFailureReason ==
               RuntimeAcceptedClientAdmissionFailureReason::None);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .termination ==
               RuntimeAcceptedClientTermination::Open);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoQueued);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoDelivered);
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoCreationToDeliveryAgeAvailable);
        assert(!retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                    .preauthElapsedAtPeerEofAvailable);
        assert(!retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                    .directNtlmTypeTwoToPeerEofAvailable);
        if (postTypeTwoTimelineDiagnosticsOnly)
        {
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoFirstClientTlsByteAvailable);
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoPlaintextBytes == 1U);
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoCompleteTsRequestCount == 0U);
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoPartialTsRequestBytes == 1U);
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoClientTlsBytes != 0U);
        }
        else
        {
            assert(!retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                        .postTypeTwoFirstClientTlsByteAvailable);
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoPlaintextBytes == 0U);
            assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                       .postTypeTwoCompleteTsRequestCount == 0U);
        }
        assert(retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None);
        assert(!retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                    .mcsSessionAdvanced);
        assert(!retryWaitingForTypeThree.acceptedClientPreauthDiagnostics
                    .shareActivated);
        assertClipboardDormant(retryWaitingForTypeThree);
        assertGraphicsDormant(retryWaitingForTypeThree);
        assertFixedConnectionTargetIdentity(
            retryWaitingForTypeThree, recommendation.address, selectedPort,
            firstListenerGeneration);
        assert(physicalClientEnvironmentDiagnosticsMatch(
            retryWaitingForTypeThree));
        assert(challengesDiffer(
            peerResult.serverChallenge, retryTypeTwoResult.serverChallenge));

        closeRetryAfterTypeTwo.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        retryTypeTwoPeer.join();
        assert(retryTypeTwoResult.passed);
        assert(retryTypeTwoResult.directTypeTwoReceived);
        assert(!retryTypeTwoResult.authInfoSent);

        const auto afterRetryTypeTwoEof = control.status();
        if (stageTimelineDiagnosticsOnly)
            assertConnectionLocalStageTimeline(
                afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics, true);
        assert(directTypeTwoPeerEofRemainsPreAdmission(afterRetryTypeTwoEof));
        assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoCreationToDeliveryAgeAvailable);
        assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preauthElapsedAtPeerEofAvailable);
        assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preauthElapsedAtPeerEofMicroseconds >=
               afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoCreationToDeliveryMicroseconds);
        assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoToPeerEofAvailable);
        if (postTypeTwoTimelineDiagnosticsOnly)
        {
            assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .postTypeTwoFirstClientTlsByteAvailable);
            assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .postTypeTwoFirstClientTlsByteMicroseconds <=
                   afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .directNtlmTypeTwoToPeerEofMicroseconds);
            assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .postTypeTwoPlaintextBytes == 1U);
            assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .postTypeTwoCompleteTsRequestCount == 0U);
            assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .postTypeTwoPartialTsRequestBytes == 1U);
            assert(afterRetryTypeTwoEof.acceptedClientPreauthDiagnostics
                       .postTypeTwoClientTlsBytes != 0U);
        }
        assert(afterRetryTypeTwoEof.activeClients.empty());
        assert(afterRetryTypeTwoEof.listenerGeneration ==
               firstListenerGeneration);
        assertPhysicalOwnerGrantActive(afterRetryTypeTwoEof);
        assert(afterRetryTypeTwoEof.product.state ==
               RuntimeProductHostState::Listening);
        assert(afterRetryTypeTwoEof.product.credentialsConfigured);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        assertClipboardDormant(afterRetryTypeTwoEof);
        assertGraphicsDormant(afterRetryTypeTwoEof);
        assertFixedConnectionTargetIdentity(
            afterRetryTypeTwoEof, recommendation.address, selectedPort,
            firstListenerGeneration);

        if (!typeTwoPeerEofOnly && !typeTwoTimingDiagnosticsOnly &&
            !postTypeTwoTimelineDiagnosticsOnly)
        {
            // The target-identity case keeps its existing positive synthetic
            // retry. The dedicated Type-2/EOF dormancy case ends above this
            // boundary and never manufactures downstream clipboard authority.
            const PeerResult retryResult = runAdmissionDeniedPeer(
                control, recommendation.address, selectedPort, 0x20U,
                firstListenerGeneration, credential.generation);
            assert(challengesDiffer(
                peerResult.serverChallenge, retryResult.serverChallenge));
            assert(challengesDiffer(
                retryTypeTwoResult.serverChallenge,
                retryResult.serverChallenge));
        }

        assert(control.stopSharing().succeeded());
        const auto retainedCredential =
            control.standaloneApplicationPasswordObservation();
        assert(retainedCredential.configured);
        assert(retainedCredential.generation == credential.generation);
        assert(!control.status().connectionTargetIdentity.valid());
        assert(control.revokeSharing().succeeded());
        assert(!control.standaloneApplicationPasswordObservation().configured);
        return 0;
    }

    PeerResult badResult;
    PeerResult typeTwoEofResult;
    if (fullLifecycle)
    {
        // One malformed direct-NTLM reconnect is connection-terminal only. It
        // must not turn Sharing off, revoke consent or replace the configured
        // Session Password.
        std::atomic<bool> releaseBad{false};
        std::atomic<bool> badFinished{false};
        std::thread badPeer([&] {
            badResult = runDirectNtlmPeer(
                recommendation.address, selectedPort, false, 0x10U,
                releaseBad);
            badFinished.store(true, std::memory_order_release);
        });
        assert(pumpUntil(control, badFinished, &badClientRetired));
        const auto afterBad = control.status();
        assert(afterBad.stage == RuntimeHostStage::ListenerAvailable);
        assert(afterBad.listenerAvailable);
        assert(afterBad.listenerGeneration == firstListenerGeneration);
        assertPhysicalOwnerGrantActive(afterBad);
        assert(afterBad.product.state == RuntimeProductHostState::Listening);
        assert(afterBad.product.credentialsConfigured);
        assert(afterBad.clientDisconnected);
        assertClipboardDormant(afterBad);
        assertGraphicsDormant(afterBad);
        assert(afterBad.acceptedClientPreauthDiagnostics.available);
        assert(afterBad.acceptedClientPreauthDiagnostics.ntlmEnvelope ==
               RuntimeAcceptedClientNtlmEnvelope::DirectNtlm);
        assert(afterBad.acceptedClientPreauthDiagnostics.authenticationStage ==
               RuntimeAcceptedClientAuthenticationStage::NtlmAuthenticate);
        assert(afterBad.acceptedClientPreauthDiagnostics.standaloneFailureStage ==
               RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation);
        assert(!afterBad.acceptedClientPreauthDiagnostics
                    .standaloneCredentialsRejected);
        assert(afterBad.acceptedClientPreauthDiagnostics
                   .standaloneCredentialGeneration == credential.generation);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
        releaseBad.store(true, std::memory_order_release);
        badPeer.join();
        assert(badResult.passed && badResult.directTypeTwoReceived);

        // A peer that consumes Type 2 and closes before Type 3 has no
        // credential, admission, native desktop, graphics or clipboard
        // authority. Keep it alive until the server has exposed the accepted
        // connection so the close cannot be confused with the prior peer's
        // retained terminal snapshot.
        std::atomic<bool> typeTwoReceived{false};
        std::atomic<bool> closeAfterTypeTwo{false};
        std::atomic<bool> typeTwoEofFinished{false};
        std::thread typeTwoEofPeer([&] {
            typeTwoEofResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                typeTwoReceived, closeAfterTypeTwo);
            typeTwoEofFinished.store(true, std::memory_order_release);
        });
        assert(pumpUntilPeerSignal(
            control, typeTwoReceived, typeTwoEofFinished));

        const auto beforeTypeTwoEof = control.status();
        assert(beforeTypeTwoEof.listenerAvailable);
        assert(beforeTypeTwoEof.listenerGeneration ==
               firstListenerGeneration);
        assertPhysicalOwnerGrantActive(beforeTypeTwoEof);
        assert(beforeTypeTwoEof.activeClients.size() == 1U);
        assert(beforeTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoQueued);
        assert(beforeTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoDelivered);
        assert(beforeTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None);
        assertClipboardDormant(beforeTypeTwoEof);
        assertGraphicsDormant(beforeTypeTwoEof);

        closeAfterTypeTwo.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        typeTwoEofPeer.join();
        assert(typeTwoEofResult.passed);
        assert(typeTwoEofResult.directTypeTwoReceived);

        const auto afterTypeTwoEof = control.status();
        assert(directTypeTwoPeerEofRemainsPreAdmission(afterTypeTwoEof));
        assert(afterTypeTwoEof.stage == RuntimeHostStage::ListenerAvailable);
        assert(afterTypeTwoEof.listenerAvailable);
        assert(afterTypeTwoEof.listenerGeneration ==
               firstListenerGeneration);
        assertPhysicalOwnerGrantActive(afterTypeTwoEof);
        assert(afterTypeTwoEof.product.state ==
               RuntimeProductHostState::Listening);
        assert(afterTypeTwoEof.product.credentialsConfigured);
        assert(afterTypeTwoEof.clientDisconnected);
        assert(afterTypeTwoEof.activeClients.empty());
        assertClipboardDormant(afterTypeTwoEof);
        assertGraphicsDormant(afterTypeTwoEof);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
    }

    PeerResult truncatedAuthInfoResult;
    if (finalAuthInfoFragmentsReconnectOnly ||
        largeFinalAuthInfoFramingReconnectOnly)
    {
        // First close after a deliberately incomplete final authInfo, with
        // the server binding already committed. Neither an R2 proof nor a
        // second TLS reader is permitted to survive this accepted peer.
        std::atomic<bool> release{false};
        std::thread truncatedPeer([&] {
            truncatedAuthInfoResult = runDirectNtlmPeer(
                recommendation.address, selectedPort, true, 0x10U,
                release, false,
                FinalAuthInfoWritePattern::TruncatedWithTlsClose,
                nullptr, credentialFixture);
        });
        assert(pumpUntilClientRetired(control));
        truncatedPeer.join();
        assert(truncatedAuthInfoResult.passed);
        assert(truncatedAuthInfoResult.directTypeTwoReceived);
        assert(!truncatedAuthInfoResult.authInfoSent);
        const auto afterTruncatedAuthInfo = control.status();
        assert(afterTruncatedAuthInfo.listenerAvailable);
        assert(afterTruncatedAuthInfo.listenerGeneration ==
               firstListenerGeneration);
        assert(afterTruncatedAuthInfo.activeClients.empty());
        assert(afterTruncatedAuthInfo.acceptedClientPreauthDiagnostics.available);
        assert(afterTruncatedAuthInfo.acceptedClientPreauthDiagnostics
                   .postTypeTwoPartialTsRequestBytes > 0U);
        assert(afterTruncatedAuthInfo.acceptedClientPreauthDiagnostics
                   .credSspTransition !=
               RuntimeAcceptedClientCredSspTransition::CredentialsVerified);
        assert(!afterTruncatedAuthInfo.acceptedClientPreauthDiagnostics
                    .mcsSessionAdvanced);
        assert(!afterTruncatedAuthInfo.acceptedClientPreauthDiagnostics
                    .shareActivated);
        assertPhysicalOwnerGrantActive(afterTruncatedAuthInfo);
        assertClipboardDormant(afterTruncatedAuthInfo);
        assertGraphicsDormant(afterTruncatedAuthInfo);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);
    }

    // The first valid peer crosses established TLS and complete DirectNtlm
    // CredSSP credentials, then the production broker denies native admission.
    // Only that accepted peer is retired; listener, owner grant and configured
    // Session Password remain current.
    const PeerResult goodOneResult = runAdmissionDeniedPeer(
        control, recommendation.address, selectedPort, 0x20U,
        firstListenerGeneration, credential.generation,
        largeFinalAuthInfoFramingReconnectOnly
            ? FinalAuthInfoWritePattern::
                  LargeDelegatedFragmentsWithCoalescedTail
            : finalAuthInfoFragmentsReconnectOnly
                  ? FinalAuthInfoWritePattern::Fragmented
                  : FinalAuthInfoWritePattern::Complete,
        credentialFixture);
    if (finalAuthInfoFragmentsReconnectOnly ||
        largeFinalAuthInfoFramingReconnectOnly)
    {
        assert(challengesDiffer(
            truncatedAuthInfoResult.serverChallenge,
            goodOneResult.serverChallenge));
    }
    if (fullLifecycle)
    {
        assert(challengesDiffer(
            badResult.serverChallenge, goodOneResult.serverChallenge));
        assert(challengesDiffer(
            typeTwoEofResult.serverChallenge,
            goodOneResult.serverChallenge));
    }

    // Physical-boundary regression: without Stop/Start or any Sharing restart,
    // the unchanged listener accepts a second TLS/CredSSP client with fresh
    // connection-local NTLM state after the first native Admission denial.
    const PeerResult sameListenerRetryResult = runAdmissionDeniedPeer(
        control, recommendation.address, selectedPort, 0x30U,
        firstListenerGeneration, credential.generation,
        FinalAuthInfoWritePattern::Complete, credentialFixture);
    assert(challengesDiffer(
        goodOneResult.serverChallenge,
        sameListenerRetryResult.serverChallenge));
    if (finalAuthInfoFragmentsReconnectOnly ||
        largeFinalAuthInfoFramingReconnectOnly)
    {
        assert(challengesDiffer(
            truncatedAuthInfoResult.serverChallenge,
            sameListenerRetryResult.serverChallenge));
    }
    if (fullLifecycle)
    {
        assert(challengesDiffer(
            badResult.serverChallenge,
            sameListenerRetryResult.serverChallenge));
    }

    if (admissionRetryOnly)
    {
        assert(control.stopSharing().succeeded());
        const auto retainedCredential =
            control.standaloneApplicationPasswordObservation();
        assert(retainedCredential.configured);
        assert(retainedCredential.generation == credential.generation);
        assert(control.revokeSharing().succeeded());
        assert(!control.standaloneApplicationPasswordObservation().configured);
        return 0;
    }

    // Ordinary Stop retires the accepted client/listener/native/TLS owners and
    // consent, but retains the exact memory-only Session Password generation.
    assert(control.stopSharing().succeeded());
    const auto stopped = control.status();
    assert(stopped.stage == RuntimeHostStage::Stopped);
    assert(!stopped.listenerAvailable);
    assert(!stopped.hostOwnerAuthorized);
    assert(stopped.credentialsConfigured);
    assert(stopped.activeClients.empty());
    assertGraphicsDormant(stopped);
    assertClipboardDormant(stopped);
    const auto retained =
        control.standaloneApplicationPasswordObservation();
    assert(retained.configured);
    assert(retained.generation == credential.generation);

    // A new Start requires fresh consent and fresh listener/TLS state, not
    // password re-entry. The next direct-NTLM client must authenticate with a
    // fourth connection-local challenge/security context.
    assert(control.requestHostPermissionSetup(permission).succeeded());
    assert(startSharingOnPort(
        control, recommendation, selectedPort));
    const auto restarted = control.status();
    assert(restarted.listenerAvailable);
    assert(restarted.listenerGeneration != 0U);
    assert(restarted.listenerGeneration != firstListenerGeneration);
    assert(restarted.hostOwnerAuthorized);
    assert(restarted.credentialsConfigured);
    assertFixedConnectionTargetIdentity(
        restarted, recommendation.address, selectedPort,
        restarted.listenerGeneration);
    assertGraphicsDormant(restarted);
    assertClipboardDormant(restarted);
    assert(control.standaloneApplicationPasswordObservation().generation ==
           credential.generation);

    const PeerResult goodTwoResult = runAdmissionDeniedPeer(
        control, recommendation.address, selectedPort, 0x40U,
        restarted.listenerGeneration, credential.generation);
    assert(challengesDiffer(
        goodOneResult.serverChallenge, goodTwoResult.serverChallenge));
    assert(challengesDiffer(
        sameListenerRetryResult.serverChallenge,
        goodTwoResult.serverChallenge));
    assert(challengesDiffer(
        badResult.serverChallenge, goodTwoResult.serverChallenge));

    assert(control.stopSharing().succeeded());
    const auto finalStopped = control.status();
    assert(!finalStopped.nativeDesktopReady);
    assert(!finalStopped.nativeDesktopInitializing);
    assertClipboardDormant(finalStopped);
    assert(control.standaloneApplicationPasswordObservation().generation ==
           credential.generation);
    assert(control.revokeSharing().succeeded());
    assert(!control.standaloneApplicationPasswordObservation().configured);
    return 0;
#endif
}
