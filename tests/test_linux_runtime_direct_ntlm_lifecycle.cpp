// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_host_control.h"
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
#include <memory>
#include <optional>
#include <pwd.h>
#include <span>
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

[[nodiscard]] Bytes passwordCredentials()
{
    const Bytes emptyDomain;
    Bytes fields = octetContext(0xa0U, emptyDomain);
    const auto user = utf16Le(kStandaloneUser);
    fields = append(fields, octetContext(0xa1U, user));
    const auto password = utf16Le(
        std::u16string_view{
            kStandalonePassword.data(), kStandalonePassword.size()});
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
    NtlmV2SecurityContext& clientSecurity)
{
    EphemeralNtlmV2Credential credential;
    auto password = kStandalonePassword;
    if (!credential.configure(kStandaloneUser, password))
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
    const std::array<ByteSpan, 2> proofParts{
        ByteSpan{challenge.challenge},
        ByteSpan{blob}};
    if (!hmacMd5(responseKey, proofParts, proof))
        return std::nullopt;

    Bytes ntResponse;
    ntResponse.reserve(proof.size() + blob.size());
    ntResponse.insert(ntResponse.end(), proof.begin(), proof.end());
    ntResponse.insert(ntResponse.end(), blob.begin(), blob.end());

    const Bytes user = utf16Le(kStandaloneUser);
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

    ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override
    {
        if (!valid() || account != account_)
            return {};
        return {ConsoleEvidenceReadStatus::Observed, account_, uid_};
    }

    ConsoleSessionObservation readActiveConsole() noexcept override
    {
        if (!valid())
            return {};
        return {
            ConsoleEvidenceReadStatus::Observed,
            "direct-ntlm-lifecycle",
            "seat0",
            ":42",
            uid_,
            501U,
            now_,
            true,
            true,
            uid_,
            ConsoleDesktopLockState::Unlocked,
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
    std::uint64_t now_{10'000U};
};

struct PeerResult final
{
    bool passed{};
    bool directTypeTwoReceived{};
    bool authInfoSent{};
    NtlmServerChallenge serverChallenge{};
};

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
    std::atomic<bool>& release) noexcept
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
        result.passed = waitForRelease(release);
        return result;
    }

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

    const auto credentials = passwordCredentials();
    const auto protectedCredentials =
        protectClientMessage(clientSecurity, credentials);
    if (!protectedCredentials)
        return result;
    const auto authInfo = authInfoRequest(*protectedCredentials);
    if (!client.writeFrame(authInfo))
        return result;

    result.authInfoSent = true;
    result.passed = waitForRelease(release);
    return result;
}

[[nodiscard]] PeerResult runDirectTypeTwoThenClosePeer(
    std::string_view address,
    std::uint16_t port,
    std::atomic<bool>& typeTwoReceived,
    std::atomic<bool>& closeAfterTypeTwo) noexcept
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
    typeTwoReceived.store(true, std::memory_order_release);
    result.passed = waitForRelease(closeAfterTypeTwo);
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
    std::uint64_t expectedCredentialGeneration) noexcept
{
    std::atomic<bool> release{false};
    std::atomic<bool> finished{false};
    PeerResult peerResult;
    std::thread peer([&] {
        peerResult = runDirectNtlmPeer(
            address, port, true, nonceSeed, release);
        finished.store(true, std::memory_order_release);
    });

    assert(pumpUntilNewAttemptAdmissionDenied(control, finished));
    const auto status = control.status();
    assert(status.listenerAvailable);
    assert(status.listenerGeneration == expectedListenerGeneration);
    assert(status.hostOwnerAuthorized);
    assert(status.product.ownerAuthorized);
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
    return peerResult;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};
    const bool fullLifecycle =
        testCase == "direct-ntlm-reconnect-stop-start-lifecycle";
    const bool admissionRetryOnly =
        testCase ==
            "admission-denial-retains-listener-and-accepts-second-tls" ||
        testCase ==
            "admission-denial-exposes-bounded-reason-and-retries";
    const bool typeTwoPeerEofOnly =
        testCase ==
            "direct-ntlm-type2-peer-eof-pre-admission-diagnostics";
    const bool typeTwoTimeoutOnly =
        testCase == "direct-ntlm-type2-waits-for-preauth-timeout";
    const bool peerCloseClassificationOnly =
        testCase ==
            "type2-peer-close-distinct-from-authentication-rejection";
    if (!fullLifecycle && !admissionRetryOnly && !typeTwoPeerEofOnly &&
        !typeTwoTimeoutOnly && !peerCloseClassificationOnly)
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

    auto password = kStandalonePassword;
    assert(control.configureStandaloneApplicationPassword(
        kStandaloneUser, password));
    assert(std::ranges::all_of(
        password, [](char16_t value) { return value == u'\0'; }));
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
    assert(firstListener.hostOwnerAuthorized);
    assert(firstListener.credentialsConfigured);
    assert(!firstListener.nativeDesktopReady);
    assert(!firstListener.nativeDesktopInitializing);
    assertClipboardDormant(firstListener);
    const std::uint64_t firstListenerGeneration =
        firstListener.listenerGeneration;
    assert(firstListenerGeneration != 0U);

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
        assert(afterTimeout.hostOwnerAuthorized);
        assert(afterTimeout.product.ownerAuthorized);
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

    if (typeTwoPeerEofOnly || peerCloseClassificationOnly)
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

        closeAfterTypeTwo.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        peer.join();

        assert(peerResult.passed);
        assert(peerResult.directTypeTwoReceived);
        assert(!peerResult.authInfoSent);
        const auto afterTypeTwoEof = control.status();
        assert(directTypeTwoPeerEofRemainsPreAdmission(afterTypeTwoEof));
        assert(afterTypeTwoEof.listenerGeneration == firstListenerGeneration);
        assert(afterTypeTwoEof.hostOwnerAuthorized);
        assert(afterTypeTwoEof.product.ownerAuthorized);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoQueued);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .directNtlmTypeTwoDelivered);
        assert(afterTypeTwoEof.acceptedClientPreauthDiagnostics
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::PeerEof);
        assertClipboardDormant(afterTypeTwoEof);
        assertGraphicsDormant(afterTypeTwoEof);
        assert(afterTypeTwoEof.product.state ==
               RuntimeProductHostState::Listening);
        assert(afterTypeTwoEof.product.credentialsConfigured);
        assert(control.standaloneApplicationPasswordObservation().generation ==
               credential.generation);

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
        std::thread retryTypeTwoPeer([&] {
            retryTypeTwoResult = runDirectTypeTwoThenClosePeer(
                recommendation.address, selectedPort,
                retryTypeTwoReceived, closeRetryAfterTypeTwo);
            retryPeerFinished.store(true, std::memory_order_release);
        });

        assert(pumpUntilPeerSignal(
            control, retryTypeTwoReceived, retryPeerFinished));
        const auto retryWaitingForTypeThree = control.status();
        assert(retryWaitingForTypeThree.activeClients.size() == 1U);
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
                   .preType3Termination ==
               RuntimeAcceptedClientPreType3Termination::None);
        assertClipboardDormant(retryWaitingForTypeThree);
        assertGraphicsDormant(retryWaitingForTypeThree);
        assert(challengesDiffer(
            peerResult.serverChallenge, retryTypeTwoResult.serverChallenge));

        closeRetryAfterTypeTwo.store(true, std::memory_order_release);
        assert(pumpUntilClientRetired(control));
        retryTypeTwoPeer.join();
        assert(retryTypeTwoResult.passed);
        assert(retryTypeTwoResult.directTypeTwoReceived);
        assert(!retryTypeTwoResult.authInfoSent);

        const auto afterRetryTypeTwoEof = control.status();
        assert(directTypeTwoPeerEofRemainsPreAdmission(afterRetryTypeTwoEof));
        assertClipboardDormant(afterRetryTypeTwoEof);
        assertGraphicsDormant(afterRetryTypeTwoEof);

        // Preserve the existing same-listener positive synthetic retry after
        // the R8 freshness observation. Peer 3 completes Type 3 + pubKeyAuth
        // + authInfo through CredentialsVerified before native Admission runs.
        const PeerResult retryResult = runAdmissionDeniedPeer(
            control, recommendation.address, selectedPort, 0x20U,
            firstListenerGeneration, credential.generation);
        assert(challengesDiffer(
            peerResult.serverChallenge, retryResult.serverChallenge));
        assert(challengesDiffer(
            retryTypeTwoResult.serverChallenge, retryResult.serverChallenge));

        assert(control.stopSharing().succeeded());
        const auto retainedCredential =
            control.standaloneApplicationPasswordObservation();
        assert(retainedCredential.configured);
        assert(retainedCredential.generation == credential.generation);
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
        assert(afterBad.hostOwnerAuthorized);
        assert(afterBad.product.ownerAuthorized);
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
        assert(afterTypeTwoEof.hostOwnerAuthorized);
        assert(afterTypeTwoEof.product.ownerAuthorized);
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

    // The first valid peer crosses established TLS and complete DirectNtlm
    // CredSSP credentials, then the production broker denies native admission.
    // Only that accepted peer is retired; listener, owner grant and configured
    // Session Password remain current.
    const PeerResult goodOneResult = runAdmissionDeniedPeer(
        control, recommendation.address, selectedPort, 0x20U,
        firstListenerGeneration, credential.generation);
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
        firstListenerGeneration, credential.generation);
    assert(challengesDiffer(
        goodOneResult.serverChallenge,
        sameListenerRetryResult.serverChallenge));
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
