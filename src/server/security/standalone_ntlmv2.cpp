// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_ntlmv2.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <limits>
#include <span>
#include <string_view>
#include <utility>

namespace rdp_server::server::security
{
namespace
{

using ByteSpan = std::span<const std::uint8_t>;

class PasswordCleanser final
{
public:
    explicit PasswordCleanser(std::span<char16_t> password) noexcept
        : password_(password) {}
    PasswordCleanser(const PasswordCleanser &) = delete;
    PasswordCleanser &operator=(const PasswordCleanser &) = delete;
    ~PasswordCleanser()
    {
        cleanseStandalonePasswordInput(password_);
    }

private:
    std::span<char16_t> password_;
};

template <std::size_t Size>
class ScopedSecret final
{
public:
    ScopedSecret() noexcept = default;
    ScopedSecret(const ScopedSecret &) = delete;
    ScopedSecret &operator=(const ScopedSecret &) = delete;
    ~ScopedSecret()
    {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

    std::array<std::uint8_t, Size> bytes{};
};

[[nodiscard]] constexpr std::uint32_t loadLe32(
    const std::uint8_t *bytes) noexcept
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

constexpr void storeLe32(
    std::uint8_t *output, std::uint32_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
    output[2] = static_cast<std::uint8_t>(value >> 16U);
    output[3] = static_cast<std::uint8_t>(value >> 24U);
}

constexpr void storeLe64(
    std::uint8_t *output, std::uint64_t value) noexcept
{
    for (std::size_t index = 0; index < 8U; ++index)
        output[index] =
            static_cast<std::uint8_t>(value >> (index * 8U));
}

class Md4State final
{
public:
    Md4State() noexcept = default;
    Md4State(const Md4State &) = delete;
    Md4State &operator=(const Md4State &) = delete;
    ~Md4State()
    {
        OPENSSL_cleanse(state_.data(), state_.size() * sizeof(state_[0]));
        OPENSSL_cleanse(buffer_.data(), buffer_.size());
        totalBytes_ = 0;
        bufferedBytes_ = 0;
    }

    void update(ByteSpan input) noexcept
    {
        totalBytes_ += input.size();
        std::size_t consumed = 0;
        if (bufferedBytes_ != 0)
        {
            const std::size_t copyBytes =
                (std::min)(buffer_.size() - bufferedBytes_, input.size());
            for (std::size_t index = 0; index < copyBytes; ++index)
                buffer_[bufferedBytes_ + index] = input[index];
            bufferedBytes_ += copyBytes;
            consumed += copyBytes;
            if (bufferedBytes_ == buffer_.size())
            {
                processBlock(buffer_.data());
                bufferedBytes_ = 0;
            }
        }

        while (input.size() - consumed >= buffer_.size())
        {
            processBlock(input.data() + consumed);
            consumed += buffer_.size();
        }

        const std::size_t remaining = input.size() - consumed;
        if (remaining != 0)
        {
            for (std::size_t index = 0; index < remaining; ++index)
                buffer_[index] = input[consumed + index];
            bufferedBytes_ = remaining;
        }
    }

    void finish(NtlmV2Key &output) noexcept
    {
        const std::uint64_t bitLength =
            static_cast<std::uint64_t>(totalBytes_) * 8U;
        const std::uint8_t marker = 0x80U;
        update({&marker, 1U});

        const std::uint8_t zero = 0U;
        while (bufferedBytes_ != 56U)
            update({&zero, 1U});

        std::array<std::uint8_t, 8> lengthBytes{};
        storeLe64(lengthBytes.data(), bitLength);
        update(lengthBytes);

        for (std::size_t index = 0; index < state_.size(); ++index)
            storeLe32(output.data() + index * 4U, state_[index]);
        OPENSSL_cleanse(lengthBytes.data(), lengthBytes.size());
    }

private:
    [[nodiscard]] static constexpr std::uint32_t f(
        std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return (x & y) | (~x & z);
    }
    [[nodiscard]] static constexpr std::uint32_t g(
        std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return (x & y) | (x & z) | (y & z);
    }
    [[nodiscard]] static constexpr std::uint32_t h(
        std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept
    {
        return x ^ y ^ z;
    }

    void processBlock(const std::uint8_t *block) noexcept
    {
        std::array<std::uint32_t, 16> words{};
        for (std::size_t index = 0; index < words.size(); ++index)
            words[index] = loadLe32(block + index * 4U);

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];

        auto round1 = [&words](
            std::uint32_t &aa, std::uint32_t bb,
            std::uint32_t cc, std::uint32_t dd,
            std::size_t word, int shift) noexcept {
            aa = std::rotl(
                aa + f(bb, cc, dd) + words[word], shift);
        };
        round1(a, b, c, d, 0, 3); round1(d, a, b, c, 1, 7);
        round1(c, d, a, b, 2, 11); round1(b, c, d, a, 3, 19);
        round1(a, b, c, d, 4, 3); round1(d, a, b, c, 5, 7);
        round1(c, d, a, b, 6, 11); round1(b, c, d, a, 7, 19);
        round1(a, b, c, d, 8, 3); round1(d, a, b, c, 9, 7);
        round1(c, d, a, b, 10, 11); round1(b, c, d, a, 11, 19);
        round1(a, b, c, d, 12, 3); round1(d, a, b, c, 13, 7);
        round1(c, d, a, b, 14, 11); round1(b, c, d, a, 15, 19);

        auto round2 = [&words](
            std::uint32_t &aa, std::uint32_t bb,
            std::uint32_t cc, std::uint32_t dd,
            std::size_t word, int shift) noexcept {
            aa = std::rotl(
                aa + g(bb, cc, dd) + words[word] + 0x5a827999U,
                shift);
        };
        round2(a, b, c, d, 0, 3); round2(d, a, b, c, 4, 5);
        round2(c, d, a, b, 8, 9); round2(b, c, d, a, 12, 13);
        round2(a, b, c, d, 1, 3); round2(d, a, b, c, 5, 5);
        round2(c, d, a, b, 9, 9); round2(b, c, d, a, 13, 13);
        round2(a, b, c, d, 2, 3); round2(d, a, b, c, 6, 5);
        round2(c, d, a, b, 10, 9); round2(b, c, d, a, 14, 13);
        round2(a, b, c, d, 3, 3); round2(d, a, b, c, 7, 5);
        round2(c, d, a, b, 11, 9); round2(b, c, d, a, 15, 13);

        auto round3 = [&words](
            std::uint32_t &aa, std::uint32_t bb,
            std::uint32_t cc, std::uint32_t dd,
            std::size_t word, int shift) noexcept {
            aa = std::rotl(
                aa + h(bb, cc, dd) + words[word] + 0x6ed9eba1U,
                shift);
        };
        round3(a, b, c, d, 0, 3); round3(d, a, b, c, 8, 9);
        round3(c, d, a, b, 4, 11); round3(b, c, d, a, 12, 15);
        round3(a, b, c, d, 2, 3); round3(d, a, b, c, 10, 9);
        round3(c, d, a, b, 6, 11); round3(b, c, d, a, 14, 15);
        round3(a, b, c, d, 1, 3); round3(d, a, b, c, 9, 9);
        round3(c, d, a, b, 5, 11); round3(b, c, d, a, 13, 15);
        round3(a, b, c, d, 3, 3); round3(d, a, b, c, 11, 9);
        round3(c, d, a, b, 7, 11); round3(b, c, d, a, 15, 15);

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        OPENSSL_cleanse(words.data(), words.size() * sizeof(words[0]));
    }

    std::array<std::uint32_t, 4> state_{
        0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t totalBytes_{};
    std::size_t bufferedBytes_{};
};

[[nodiscard]] bool validUtf16(
    std::u16string_view value, bool allowEmpty) noexcept
{
    if ((!allowEmpty && value.empty()) ||
        value.size() > kMaximumStandalonePasswordCodeUnits)
        return false;

    for (std::size_t index = 0; index < value.size(); ++index)
    {
        const std::uint16_t code =
            static_cast<std::uint16_t>(value[index]);
        if (code == 0U)
            return false;
        if (code >= 0xd800U && code <= 0xdbffU)
        {
            if (++index >= value.size())
                return false;
            const std::uint16_t low =
                static_cast<std::uint16_t>(value[index]);
            if (low < 0xdc00U || low > 0xdfffU)
                return false;
        }
        else if (code >= 0xdc00U && code <= 0xdfffU)
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool validAsciiUsername(
    std::u16string_view username) noexcept
{
    if (username.empty() ||
        username.size() > kMaximumStandaloneNtlmUserCodeUnits)
        return false;
    for (const char16_t character : username)
    {
        const std::uint16_t code =
            static_cast<std::uint16_t>(character);
        if (code == 0U || code > 0x7fU)
            return false;
    }
    return true;
}

void md4Utf16Le(
    std::u16string_view value, NtlmV2Key &output) noexcept
{
    Md4State md4;
    std::array<std::uint8_t, 128> encoded{};
    std::size_t encodedBytes = 0;
    for (const char16_t character : value)
    {
        const std::uint16_t code =
            static_cast<std::uint16_t>(character);
        encoded[encodedBytes++] = static_cast<std::uint8_t>(code);
        encoded[encodedBytes++] =
            static_cast<std::uint8_t>(code >> 8U);
        if (encodedBytes == encoded.size())
        {
            md4.update(encoded);
            encodedBytes = 0;
        }
    }
    if (encodedBytes != 0)
        md4.update({encoded.data(), encodedBytes});
    md4.finish(output);
    OPENSSL_cleanse(encoded.data(), encoded.size());
}

[[nodiscard]] bool hmacMd5(
    ByteSpan key,
    std::span<const ByteSpan> parts,
    NtlmV2Key &output) noexcept
{
    output.fill(0);
    if (key.empty() || key.size() > 64U)
        return false;

    ScopedSecret<64> innerPad;
    ScopedSecret<64> outerPad;
    innerPad.bytes.fill(0x36U);
    outerPad.bytes.fill(0x5cU);
    for (std::size_t index = 0; index < key.size(); ++index)
    {
        innerPad.bytes[index] ^= key[index];
        outerPad.bytes[index] ^= key[index];
    }

    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context ||
        EVP_DigestInit_ex(context.get(), EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(
            context.get(), innerPad.bytes.data(),
            innerPad.bytes.size()) != 1)
        return false;

    for (const ByteSpan part : parts)
    {
        if (!part.empty() &&
            EVP_DigestUpdate(
                context.get(), part.data(), part.size()) != 1)
            return false;
    }

    ScopedSecret<kNtlmV2KeyBytes> innerHash;
    unsigned int size = 0;
    if (EVP_DigestFinal_ex(
            context.get(), innerHash.bytes.data(), &size) != 1 ||
        size != innerHash.bytes.size() ||
        EVP_DigestInit_ex(context.get(), EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(
            context.get(), outerPad.bytes.data(),
            outerPad.bytes.size()) != 1 ||
        EVP_DigestUpdate(
            context.get(), innerHash.bytes.data(),
            innerHash.bytes.size()) != 1)
    {
        return false;
    }

    size = 0;
    return EVP_DigestFinal_ex(
               context.get(), output.data(), &size) == 1 &&
           size == output.size();
}

[[nodiscard]] bool md5KeyAndMagic(
    const NtlmV2Key &key,
    const char *magic,
    std::size_t magicBytes,
    NtlmV2Key &output) noexcept
{
    output.fill(0);
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    unsigned int size = 0;
    return context &&
           EVP_DigestInit_ex(context.get(), EVP_md5(), nullptr) == 1 &&
           EVP_DigestUpdate(
               context.get(), key.data(), key.size()) == 1 &&
           EVP_DigestUpdate(context.get(), magic, magicBytes) == 1 &&
           EVP_DigestFinal_ex(
               context.get(), output.data(), &size) == 1 &&
           size == output.size();
}

class Rc4State final
{
public:
    explicit Rc4State(ByteSpan key) noexcept
    {
        for (std::size_t index = 0; index < state_.size(); ++index)
            state_[index] = static_cast<std::uint8_t>(index);
        std::uint8_t j = 0;
        for (std::size_t index = 0; index < state_.size(); ++index)
        {
            j = static_cast<std::uint8_t>(
                j + state_[index] + key[index % key.size()]);
            std::swap(state_[index], state_[j]);
        }
    }

    Rc4State(const Rc4State &) = delete;
    Rc4State &operator=(const Rc4State &) = delete;
    ~Rc4State()
    {
        OPENSSL_cleanse(state_.data(), state_.size());
        i_ = 0;
        j_ = 0;
    }

    void crypt(ByteSpan input, std::span<std::uint8_t> output) noexcept
    {
        for (std::size_t index = 0; index < input.size(); ++index)
        {
            i_ = static_cast<std::uint8_t>(i_ + 1U);
            j_ = static_cast<std::uint8_t>(j_ + state_[i_]);
            std::swap(state_[i_], state_[j_]);
            const std::uint8_t keyByte =
                state_[static_cast<std::uint8_t>(
                    state_[i_] + state_[j_])];
            output[index] = input[index] ^ keyByte;
        }
    }

private:
    std::array<std::uint8_t, 256> state_{};
    std::uint8_t i_{};
    std::uint8_t j_{};
};

[[nodiscard]] constexpr std::uint16_t loadLe16(
    const std::uint8_t *bytes) noexcept
{
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[0]) |
        (static_cast<std::uint16_t>(bytes[1]) << 8U));
}

[[nodiscard]] bool allZero(ByteSpan bytes) noexcept
{
    std::uint8_t combined = 0;
    for (const std::uint8_t byte : bytes)
        combined |= byte;
    return combined == 0U;
}

[[nodiscard]] bool validNtlmV2Blob(ByteSpan blob) noexcept
{
    constexpr std::size_t kFixedPrefixBytes = 28U;
    constexpr std::size_t kAvPairHeaderBytes = 4U;
    constexpr std::size_t kFinalReservedBytes = 4U;
    constexpr std::size_t kMinimumBlobBytes =
        kFixedPrefixBytes + kAvPairHeaderBytes + kFinalReservedBytes;

    if (blob.size() < kMinimumBlobBytes ||
        blob.size() >
            kMaximumNtlmV2ChallengeResponseBytes - kNtlmV2KeyBytes ||
        blob[0] != 1U || blob[1] != 1U ||
        !allZero(blob.subspan(2U, 6U)) ||
        !allZero(blob.subspan(24U, 4U)) ||
        !allZero(blob.last(kFinalReservedBytes)))
    {
        return false;
    }

    const std::size_t avEnd =
        blob.size() - kFinalReservedBytes;
    std::size_t offset = kFixedPrefixBytes;
    while (offset + kAvPairHeaderBytes <= avEnd)
    {
        const std::uint16_t avId = loadLe16(blob.data() + offset);
        const std::uint16_t avLength =
            loadLe16(blob.data() + offset + 2U);
        offset += kAvPairHeaderBytes;
        if (avId == 0U)
            return avLength == 0U && offset == avEnd;
        if (avLength > avEnd - offset)
            return false;
        offset += avLength;
    }
    return false;
}

[[nodiscard]] bool encodeResponseKeyInput(
    std::u16string_view username,
    std::u16string_view domain,
    std::array<std::uint8_t,
        (kMaximumStandaloneNtlmUserCodeUnits +
         kMaximumStandaloneNtlmDomainCodeUnits) * 2U> &output,
    std::size_t &outputBytes) noexcept
{
    outputBytes = 0;
    if (!validAsciiUsername(username) ||
        domain.size() > kMaximumStandaloneNtlmDomainCodeUnits ||
        !validUtf16(domain, true))
        return false;

    auto append = [&output, &outputBytes](
        std::uint16_t code) noexcept {
        output[outputBytes++] =
            static_cast<std::uint8_t>(code);
        output[outputBytes++] =
            static_cast<std::uint8_t>(code >> 8U);
    };

    for (const char16_t character : username)
    {
        std::uint16_t code =
            static_cast<std::uint16_t>(character);
        if (code >= static_cast<std::uint16_t>('a') &&
            code <= static_cast<std::uint16_t>('z'))
        {
            code -= static_cast<std::uint16_t>('a' - 'A');
        }
        append(code);
    }
    for (const char16_t character : domain)
        append(static_cast<std::uint16_t>(character));
    return true;
}

constexpr char kClientSigningMagic[] =
    "session key to client-to-server signing key magic constant";
constexpr char kServerSigningMagic[] =
    "session key to server-to-client signing key magic constant";
constexpr char kClientSealingMagic[] =
    "session key to client-to-server sealing key magic constant";
constexpr char kServerSealingMagic[] =
    "session key to server-to-client sealing key magic constant";

[[nodiscard]] bool deriveSessionSecurityKeys(
    const NtlmV2Key &sessionBaseKey,
    std::uint32_t flags,
    ByteSpan encryptedRandomSessionKey,
    NtlmV2Key &exportedSessionKey,
    NtlmV2Key &clientSigningKey,
    NtlmV2Key &serverSigningKey,
    NtlmV2Key &clientSealingKey,
    NtlmV2Key &serverSealingKey) noexcept
{
    exportedSessionKey.fill(0);
    const bool keyExchange =
        (flags & kNtlmNegotiateKeyExchange) != 0U;
    if (keyExchange)
    {
        if (encryptedRandomSessionKey.size() !=
            exportedSessionKey.size())
            return false;
        Rc4State rc4(sessionBaseKey);
        rc4.crypt(encryptedRandomSessionKey, exportedSessionKey);
    }
    else
    {
        if (!encryptedRandomSessionKey.empty())
            return false;
        exportedSessionKey = sessionBaseKey;
    }

    return md5KeyAndMagic(
               exportedSessionKey, kClientSigningMagic,
               sizeof(kClientSigningMagic), clientSigningKey) &&
           md5KeyAndMagic(
               exportedSessionKey, kServerSigningMagic,
               sizeof(kServerSigningMagic), serverSigningKey) &&
           md5KeyAndMagic(
               exportedSessionKey, kClientSealingMagic,
               sizeof(kClientSealingMagic), clientSealingKey) &&
           md5KeyAndMagic(
               exportedSessionKey, kServerSealingMagic,
               sizeof(kServerSealingMagic), serverSealingKey);
}

} // namespace

void cleanseStandalonePasswordInput(
    std::span<char16_t> password) noexcept
{
    if (!password.empty())
        OPENSSL_cleanse(password.data(), password.size_bytes());
}

NtlmV2SecurityContext::~NtlmV2SecurityContext()
{
    clear();
}

void NtlmV2SecurityContext::initializeRc4Stream(
    Rc4StreamState &state,
    std::span<const std::uint8_t, kNtlmV2KeyBytes> key) noexcept
{
    for (std::size_t index = 0; index < state.permutation.size(); ++index)
        state.permutation[index] = static_cast<std::uint8_t>(index);
    std::uint8_t j = 0;
    for (std::size_t index = 0; index < state.permutation.size(); ++index)
    {
        j = static_cast<std::uint8_t>(
            j + state.permutation[index] + key[index % key.size()]);
        std::swap(state.permutation[index], state.permutation[j]);
    }
    state.i = 0;
    state.j = 0;
    state.initialized = true;
}

void NtlmV2SecurityContext::cryptRc4Stream(
    Rc4StreamState &state,
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output) noexcept
{
    if (!state.initialized || input.size() != output.size())
        return;
    for (std::size_t index = 0; index < input.size(); ++index)
    {
        state.i = static_cast<std::uint8_t>(state.i + 1U);
        state.j = static_cast<std::uint8_t>(
            state.j + state.permutation[state.i]);
        std::swap(state.permutation[state.i], state.permutation[state.j]);
        const std::uint8_t keyByte =
            state.permutation[static_cast<std::uint8_t>(
                state.permutation[state.i] + state.permutation[state.j])];
        output[index] = input[index] ^ keyByte;
    }
}

void NtlmV2SecurityContext::activate(
    const NtlmV2Key &sessionBaseKey,
    const NtlmV2Key &exportedSessionKey,
    const NtlmV2Key &clientSigningKey,
    const NtlmV2Key &serverSigningKey,
    const NtlmV2Key &clientSealingKey,
    const NtlmV2Key &serverSealingKey,
    std::uint32_t negotiateFlags) noexcept
{
    clear();
    sessionBaseKey_ = sessionBaseKey;
    exportedSessionKey_ = exportedSessionKey;
    clientSigningKey_ = clientSigningKey;
    serverSigningKey_ = serverSigningKey;
    clientSealingKey_ = clientSealingKey;
    serverSealingKey_ = serverSealingKey;
    negotiateFlags_ = negotiateFlags;
    initializeRc4Stream(clientRc4_, clientSealingKey_);
    initializeRc4Stream(serverRc4_, serverSealingKey_);
    active_ = true;
}

bool NtlmV2SecurityContext::verifyAuthenticateMessageMic(
    std::span<const std::uint8_t> negotiateMessage,
    std::span<const std::uint8_t> challengeMessage,
    std::span<const std::uint8_t> authenticateMessage,
    std::size_t micOffset) const noexcept
{
    if (!active_ || negotiateMessage.empty() || challengeMessage.empty() ||
        micOffset > authenticateMessage.size() ||
        kNtlmMessageSignatureBytes > authenticateMessage.size() - micOffset)
        return false;

    constexpr std::array<std::uint8_t, kNtlmMessageSignatureBytes> zeroMic{};
    const std::array<ByteSpan, 5> parts{
        ByteSpan{negotiateMessage}, ByteSpan{challengeMessage},
        ByteSpan{authenticateMessage.first(micOffset)}, ByteSpan{zeroMic},
        ByteSpan{authenticateMessage.subspan(
            micOffset + kNtlmMessageSignatureBytes)}};
    ScopedSecret<kNtlmV2KeyBytes> expectedMic;
    if (!hmacMd5(exportedSessionKey_, parts, expectedMic.bytes))
        return false;
    const auto receivedMic = authenticateMessage.subspan(
        micOffset, kNtlmMessageSignatureBytes);
    return CRYPTO_memcmp(
               expectedMic.bytes.data(), receivedMic.data(),
               expectedMic.bytes.size()) == 0;
}

bool NtlmV2SecurityContext::makeMessageSignature(
    std::span<const std::uint8_t> message,
    const NtlmV2Key &signingKey,
    Rc4StreamState &stream,
    std::uint32_t sequence,
    std::span<std::uint8_t, kNtlmMessageSignatureBytes> signature) noexcept
{
    std::array<std::uint8_t, 4> sequenceBytes{};
    storeLe32(sequenceBytes.data(), sequence);
    const std::array<ByteSpan, 2> macParts{
        ByteSpan{sequenceBytes}, ByteSpan{message}};
    ScopedSecret<kNtlmV2KeyBytes> digest;
    if (!hmacMd5(signingKey, macParts, digest.bytes))
        return false;

    std::array<std::uint8_t, 8> checksum{};
    std::copy_n(
        digest.bytes.begin(), checksum.size(), checksum.begin());
    if ((negotiateFlags_ & kNtlmNegotiateKeyExchange) != 0U)
    {
        cryptRc4Stream(
            stream,
            {checksum.data(), checksum.size()},
            checksum);
    }

    std::fill(
        signature.begin(), signature.end(), std::uint8_t{0});
    storeLe32(signature.data(), 1U);
    std::copy(
        checksum.begin(), checksum.end(),
        signature.begin() + 4);
    storeLe32(signature.data() + 12U, sequence);
    OPENSSL_cleanse(checksum.data(), checksum.size());
    return true;
}

NtlmMessageSecurityResult
NtlmV2SecurityContext::verifyClientMessageSignature(
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t, kNtlmMessageSignatureBytes>
        signature) noexcept
{
    if (!active_)
        return NtlmMessageSecurityResult::Inactive;
    if (message.empty())
        return NtlmMessageSecurityResult::InvalidInput;
    if (clientSequence_ == (std::numeric_limits<std::uint32_t>::max)())
    {
        clear();
        return NtlmMessageSecurityResult::SequenceExhausted;
    }
    if (loadLe32(signature.data()) != 1U ||
        loadLe32(signature.data() + 12U) != clientSequence_)
    {
        clear();
        return NtlmMessageSecurityResult::InvalidSignature;
    }

    std::array<std::uint8_t, kNtlmMessageSignatureBytes> expected{};
    if (!makeMessageSignature(
            message, clientSigningKey_, clientRc4_,
            clientSequence_, expected))
    {
        clear();
        return NtlmMessageSecurityResult::CryptoFailure;
    }
    if (CRYPTO_memcmp(
            expected.data(), signature.data(), expected.size()) != 0)
    {
        OPENSSL_cleanse(expected.data(), expected.size());
        clear();
        return NtlmMessageSecurityResult::InvalidSignature;
    }
    OPENSSL_cleanse(expected.data(), expected.size());
    ++clientSequence_;
    return NtlmMessageSecurityResult::Processed;
}

NtlmMessageSecurityResult NtlmV2SecurityContext::signServerMessage(
    std::span<const std::uint8_t> message,
    std::span<std::uint8_t, kNtlmMessageSignatureBytes> signature) noexcept
{
    if (!active_)
        return NtlmMessageSecurityResult::Inactive;
    if (message.empty())
        return NtlmMessageSecurityResult::InvalidInput;
    if (serverSequence_ == (std::numeric_limits<std::uint32_t>::max)())
    {
        clear();
        return NtlmMessageSecurityResult::SequenceExhausted;
    }
    if (!makeMessageSignature(
            message, serverSigningKey_, serverRc4_,
            serverSequence_, signature))
    {
        clear();
        return NtlmMessageSecurityResult::CryptoFailure;
    }
    ++serverSequence_;
    return NtlmMessageSecurityResult::Processed;
}

NtlmMessageSecurityResult NtlmV2SecurityContext::unwrapClientMessage(
    std::span<const std::uint8_t> sealedMessage,
    std::span<const std::uint8_t, kNtlmMessageSignatureBytes> signature,
    std::span<std::uint8_t> plaintext) noexcept
{
    if (!active_)
        return NtlmMessageSecurityResult::Inactive;
    if (sealedMessage.empty() || sealedMessage.size() != plaintext.size())
        return NtlmMessageSecurityResult::InvalidInput;
    if (clientSequence_ == (std::numeric_limits<std::uint32_t>::max)())
    {
        clear();
        return NtlmMessageSecurityResult::SequenceExhausted;
    }
    if (loadLe32(signature.data()) != 1U ||
        loadLe32(signature.data() + 12U) != clientSequence_)
    {
        clear();
        return NtlmMessageSecurityResult::InvalidSignature;
    }

    cryptRc4Stream(clientRc4_, sealedMessage, plaintext);
    const auto result =
        verifyClientMessageSignature(plaintext, signature);
    if (result != NtlmMessageSecurityResult::Processed)
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
    return result;
}

NtlmMessageSecurityResult NtlmV2SecurityContext::wrapServerMessage(
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> sealedMessage,
    std::span<std::uint8_t, kNtlmMessageSignatureBytes> signature) noexcept
{
    if (!active_)
        return NtlmMessageSecurityResult::Inactive;
    if (plaintext.empty() || plaintext.size() != sealedMessage.size())
        return NtlmMessageSecurityResult::InvalidInput;
    if (serverSequence_ == (std::numeric_limits<std::uint32_t>::max)())
    {
        clear();
        return NtlmMessageSecurityResult::SequenceExhausted;
    }

    cryptRc4Stream(serverRc4_, plaintext, sealedMessage);
    const auto result = signServerMessage(plaintext, signature);
    if (result != NtlmMessageSecurityResult::Processed)
        OPENSSL_cleanse(sealedMessage.data(), sealedMessage.size());
    return result;
}

void NtlmV2SecurityContext::clear() noexcept
{
    OPENSSL_cleanse(
        sessionBaseKey_.data(), sessionBaseKey_.size());
    OPENSSL_cleanse(
        exportedSessionKey_.data(), exportedSessionKey_.size());
    OPENSSL_cleanse(
        clientSigningKey_.data(), clientSigningKey_.size());
    OPENSSL_cleanse(
        serverSigningKey_.data(), serverSigningKey_.size());
    OPENSSL_cleanse(
        clientSealingKey_.data(), clientSealingKey_.size());
    OPENSSL_cleanse(
        serverSealingKey_.data(), serverSealingKey_.size());
    OPENSSL_cleanse(clientRc4_.permutation.data(), clientRc4_.permutation.size());
    OPENSSL_cleanse(serverRc4_.permutation.data(), serverRc4_.permutation.size());
    clientRc4_ = {};
    serverRc4_ = {};
    negotiateFlags_ = 0;
    clientSequence_ = 0;
    serverSequence_ = 0;
    active_ = false;
}

EphemeralNtlmV2Credential::~EphemeralNtlmV2Credential()
{
    revoke();
}

bool EphemeralNtlmV2Credential::configure(
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    PasswordCleanser passwordCleanser(password);
    revoke();

    if (!validAsciiUsername(username) ||
        password.empty() ||
        password.size() > kMaximumStandalonePasswordCodeUnits ||
        !validUtf16(
            {password.data(), password.size()}, false))
    {
        return false;
    }

    md4Utf16Le(
        {password.data(), password.size()}, ntHash_);
    std::copy(
        username.begin(), username.end(), username_.begin());
    usernameLength_ = username.size();
    configured_ = true;
    return true;
}

void EphemeralNtlmV2Credential::revoke() noexcept
{
    OPENSSL_cleanse(
        username_.data(), username_.size() * sizeof(username_[0]));
    OPENSSL_cleanse(ntHash_.data(), ntHash_.size());
    usernameLength_ = 0;
    configured_ = false;
}

bool EphemeralNtlmV2Credential::deriveResponseKeyNt(
    std::u16string_view domain,
    NtlmV2Key &output) const noexcept
{
    output.fill(0);
    if (!configured_ || usernameLength_ == 0)
        return false;

    ScopedSecret<
        (kMaximumStandaloneNtlmUserCodeUnits +
         kMaximumStandaloneNtlmDomainCodeUnits) * 2U> input;
    std::size_t inputBytes = 0;
    if (!encodeResponseKeyInput(
            {username_.data(), usernameLength_}, domain,
            input.bytes, inputBytes))
        return false;

    const std::array<ByteSpan, 1> parts{
        ByteSpan{input.bytes.data(), inputBytes}};
    return hmacMd5(ntHash_, parts, output);
}

bool EphemeralNtlmV2Credential::matchesDelegatedPassword(
    std::span<const std::uint8_t> domainUtf16Le,
    std::span<const std::uint8_t> userUtf16Le,
    std::span<const std::uint8_t> passwordUtf16Le) const noexcept
{
    if (!configured_ || !domainUtf16Le.empty() ||
        userUtf16Le.size() != usernameLength_ * 2U ||
        passwordUtf16Le.empty() ||
        passwordUtf16Le.size() >
            kMaximumStandalonePasswordCodeUnits * 2U ||
        (passwordUtf16Le.size() % 2U) != 0U)
    {
        return false;
    }

    for (std::size_t index = 0; index < usernameLength_; ++index)
    {
        const std::size_t offset = index * 2U;
        if (userUtf16Le[offset + 1U] != 0U ||
            userUtf16Le[offset] == 0U ||
            userUtf16Le[offset] > 0x7fU)
        {
            return false;
        }

        auto configuredCode =
            static_cast<std::uint16_t>(username_[index]);
        auto presentedCode =
            static_cast<std::uint16_t>(userUtf16Le[offset]);
        if (configuredCode >= static_cast<std::uint16_t>('a') &&
            configuredCode <= static_cast<std::uint16_t>('z'))
        {
            configuredCode -=
                static_cast<std::uint16_t>('a' - 'A');
        }
        if (presentedCode >= static_cast<std::uint16_t>('a') &&
            presentedCode <= static_cast<std::uint16_t>('z'))
        {
            presentedCode -=
                static_cast<std::uint16_t>('a' - 'A');
        }
        if (configuredCode != presentedCode)
            return false;
    }

    ScopedSecret<kNtlmV2KeyBytes> candidateHash;
    Md4State md4;
    md4.update(passwordUtf16Le);
    md4.finish(candidateHash.bytes);
    return CRYPTO_memcmp(
               candidateHash.bytes.data(),
               ntHash_.data(),
               candidateHash.bytes.size()) == 0;
}

StandalonePasswordCredentialOwner::~StandalonePasswordCredentialOwner()
{
    revoke();
}

bool StandalonePasswordCredentialOwner::advanceGeneration() noexcept
{
    if (generationExhausted_ ||
        generation_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        generationExhausted_ = true;
        return false;
    }
    ++generation_;
    return true;
}

bool StandalonePasswordCredentialOwner::configure(
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    if (!advanceGeneration())
    {
        credential_.revoke();
        cleanseStandalonePasswordInput(password);
        return false;
    }

    return credential_.configure(username, password);
}

void StandalonePasswordCredentialOwner::revoke() noexcept
{
    const bool hadCredential = credential_.configured();
    credential_.revoke();
    if (!hadCredential)
        return;

    if (!advanceGeneration())
        generationExhausted_ = true;
}

bool StandalonePasswordCredentialOwner::visit(
    std::uint64_t expectedGeneration,
    StandalonePasswordCredentialVisitor visitor,
    void* context) const noexcept
{
    return !generationExhausted_ &&
           expectedGeneration != 0U &&
           expectedGeneration == generation_ &&
           credential_.configured() &&
           visitor != nullptr &&
           visitor(credential_, context);
}

NtlmV2VerifyResult
EphemeralNtlmV2Credential::verifyAndDeriveSecurityContext(
    const NtlmV2AuthenticateRequest &request,
    NtlmV2SecurityContext &output) const noexcept
{
    output.clear();
    if (!configured_)
        return NtlmV2VerifyResult::NotConfigured;

    if (!validAsciiUsername(request.username) ||
        request.username.size() != usernameLength_)
    {
        return NtlmV2VerifyResult::UsernameMismatch;
    }
    for (std::size_t index = 0; index < usernameLength_; ++index)
    {
        auto configuredCode = static_cast<std::uint16_t>(username_[index]);
        auto presentedCode =
            static_cast<std::uint16_t>(request.username[index]);
        if (configuredCode >= static_cast<std::uint16_t>('a') &&
            configuredCode <= static_cast<std::uint16_t>('z'))
            configuredCode -= static_cast<std::uint16_t>('a' - 'A');
        if (presentedCode >= static_cast<std::uint16_t>('a') &&
            presentedCode <= static_cast<std::uint16_t>('z'))
            presentedCode -= static_cast<std::uint16_t>('a' - 'A');
        if (configuredCode != presentedCode)
            return NtlmV2VerifyResult::UsernameMismatch;
    }

    if ((request.negotiateFlags &
         kRequiredStandaloneCredSspNtlmFlags) !=
        kRequiredStandaloneCredSspNtlmFlags)
    {
        return NtlmV2VerifyResult::UnsupportedFlags;
    }

    if (request.ntChallengeResponse.size() <
            kNtlmV2KeyBytes + 36U ||
        request.ntChallengeResponse.size() >
            kMaximumNtlmV2ChallengeResponseBytes)
    {
        return NtlmV2VerifyResult::InvalidInput;
    }

    const ByteSpan receivedProof =
        request.ntChallengeResponse.first(kNtlmV2KeyBytes);
    const ByteSpan blob =
        request.ntChallengeResponse.subspan(kNtlmV2KeyBytes);
    if (!validNtlmV2Blob(blob))
        return NtlmV2VerifyResult::InvalidResponse;

    ScopedSecret<kNtlmV2KeyBytes> responseKey;
    if (!deriveResponseKeyNt(request.domain, responseKey.bytes))
        return NtlmV2VerifyResult::InvalidInput;

    ScopedSecret<kNtlmV2KeyBytes> expectedProof;
    const std::array<ByteSpan, 2> proofParts{
        ByteSpan{request.serverChallenge},
        blob};
    if (!hmacMd5(
            responseKey.bytes, proofParts, expectedProof.bytes))
    {
        return NtlmV2VerifyResult::CryptoFailure;
    }
    if (CRYPTO_memcmp(
            expectedProof.bytes.data(), receivedProof.data(),
            expectedProof.bytes.size()) != 0)
    {
        return NtlmV2VerifyResult::ProofMismatch;
    }

    ScopedSecret<kNtlmV2KeyBytes> sessionBaseKey;
    const std::array<ByteSpan, 1> sessionParts{receivedProof};
    if (!hmacMd5(
            responseKey.bytes, sessionParts,
            sessionBaseKey.bytes))
    {
        return NtlmV2VerifyResult::CryptoFailure;
    }

    ScopedSecret<kNtlmV2KeyBytes> exportedSessionKey;
    ScopedSecret<kNtlmV2KeyBytes> clientSigningKey;
    ScopedSecret<kNtlmV2KeyBytes> serverSigningKey;
    ScopedSecret<kNtlmV2KeyBytes> clientSealingKey;
    ScopedSecret<kNtlmV2KeyBytes> serverSealingKey;
    if (!deriveSessionSecurityKeys(
            sessionBaseKey.bytes, request.negotiateFlags,
            request.encryptedRandomSessionKey,
            exportedSessionKey.bytes,
            clientSigningKey.bytes,
            serverSigningKey.bytes,
            clientSealingKey.bytes,
            serverSealingKey.bytes))
    {
        return NtlmV2VerifyResult::InvalidInput;
    }

    output.activate(
        sessionBaseKey.bytes, exportedSessionKey.bytes,
        clientSigningKey.bytes, serverSigningKey.bytes,
        clientSealingKey.bytes, serverSealingKey.bytes,
        request.negotiateFlags);
    return NtlmV2VerifyResult::Verified;
}

} // namespace rdp_server::server::security
