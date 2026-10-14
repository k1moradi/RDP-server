// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/credssp_binding.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::server::security;

namespace
{

[[nodiscard]] std::uint8_t hexNibble(char character)
{
    if (character >= '0' && character <= '9')
    {
        return static_cast<std::uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f')
    {
        return static_cast<std::uint8_t>(character - 'a' + 10);
    }
    assert(false && "expected lowercase hexadecimal");
    return 0;
}

[[nodiscard]] CredSspHash fromHex(std::string_view text)
{
    assert(text.size() == 64);
    CredSspHash result{};
    for (std::size_t i = 0; i < result.size(); ++i)
    {
        result[i] = static_cast<std::uint8_t>(
            (hexNibble(text[2 * i]) << 4U) | hexNibble(text[2 * i + 1]));
    }
    return result;
}

[[nodiscard]] constexpr std::array<std::uint8_t, 32> nonce() noexcept
{
    std::array<std::uint8_t, 32> result{};
    for (std::size_t i = 0; i < result.size(); ++i)
    {
        result[i] = static_cast<std::uint8_t>(i);
    }
    return result;
}

// Reference input/digests calculated independently using Python hashlib:
//   hashlib.sha256(b"CredSSP Client-To-Server Binding Hash\\x00"
//                  + bytes(range(32)) + bytes.fromhex(key_hex)).digest()
// Server-To-Client changes only the direction-specific label.
constexpr std::array<std::uint8_t, 15> kSubjectPublicKey{
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6,
};

void testReferenceVectors()
{
    const auto n = nonce();
    const auto expectedClient = fromHex(
        "b86efe445be986acbc9325ebc36a2aed"
        "78e746df933956a0e3dc0cb554f2775c");
    const auto expectedServer = fromHex(
        "4dc337e3725a9f81aabe07d8fdc44b2"
        "9e18ba6408eab532f41273a6a72703ea6");
    CredSspHash client{};
    CredSspHash server{};
    assert(computeCredSspBindingHash(
        CredSspBindingDirection::ClientToServer,
        n, kSubjectPublicKey, client));
    assert(computeCredSspBindingHash(
        CredSspBindingDirection::ServerToClient,
        n, kSubjectPublicKey, server));
    assert(client == expectedClient);
    assert(server == expectedServer);
    assert(client != server);  // a response cannot be reflected as a request
    assert(verifyCredSspClientBindingHash(
        n, kSubjectPublicKey, expectedClient));
    assert(!verifyCredSspClientBindingHash(
        n, kSubjectPublicKey, expectedServer));
}

void testNonceAndKeyAreBound()
{
    const auto n = nonce();
    CredSspHash original{};
    assert(computeCredSspBindingHash(
        CredSspBindingDirection::ClientToServer, n,
        kSubjectPublicKey, original));
    for (std::size_t i = 0; i < n.size(); ++i)
    {
        auto otherNonce = n;
        otherNonce[i] ^= 0x01U;
        assert(!verifyCredSspClientBindingHash(
            otherNonce, kSubjectPublicKey, original));
    }
    for (std::size_t i = 0; i < kSubjectPublicKey.size(); ++i)
    {
        auto otherPublicKey = kSubjectPublicKey;
        otherPublicKey[i] ^= 0x80U;
        assert(!verifyCredSspClientBindingHash(
            n, otherPublicKey, original));
    }
    for (std::size_t i = 0; i < original.size(); ++i)
    {
        auto mutatedHash = original;
        mutatedHash[i] ^= 0x01U;
        assert(!verifyCredSspClientBindingHash(
            n, kSubjectPublicKey, mutatedHash));
    }
}

void testFailClosedLengthsAndOutput()
{
    const auto n = nonce();
    CredSspHash output{};
    assert(!computeCredSspBindingHash(
        CredSspBindingDirection::ClientToServer,
        std::span(n).first(31), kSubjectPublicKey, output));
    assert(std::all_of(output.begin(), output.end(),
                       [](std::uint8_t octet) { return octet == 0; }));
    output.fill(0xaa);
    assert(!computeCredSspBindingHash(
        CredSspBindingDirection::ClientToServer,
        n, std::span<const std::uint8_t>{}, output));
    assert(std::all_of(output.begin(), output.end(),
                       [](std::uint8_t octet) { return octet == 0; }));
    const std::vector<std::uint8_t> hugeKey(
        kMaximumCredSspPublicKeyBytes + 1, 0x41);
    output.fill(0xaa);
    assert(!computeCredSspBindingHash(
        CredSspBindingDirection::ServerToClient,
        n, hugeKey, output));
    assert(std::all_of(output.begin(), output.end(),
                       [](std::uint8_t octet) { return octet == 0; }));
    output.fill(0xaa);
    assert(!computeCredSspBindingHash(
        static_cast<CredSspBindingDirection>(0xff),
        n, kSubjectPublicKey, output));
    assert(std::all_of(output.begin(), output.end(),
                       [](std::uint8_t octet) { return octet == 0; }));
    assert(!verifyCredSspClientBindingHash(
        n, kSubjectPublicKey, std::span(output).first(31)));
    assert(!verifyCredSspClientBindingHash(
        n, kSubjectPublicKey, std::span(output).first(0)));
    assert(!verifyCredSspClientBindingHash(
        std::span(n).first(0), kSubjectPublicKey, output));

    // Strict limit is inclusive; permitted certificate keys are not
    // truncated and the digest should remain deterministic.
    std::vector<std::uint8_t> maximalKey(
        kMaximumCredSspPublicKeyBytes, 0x53);
    assert(computeCredSspBindingHash(
        CredSspBindingDirection::ClientToServer,
        n, maximalKey, output));
    const auto first = output;
    assert(computeCredSspBindingHash(
        CredSspBindingDirection::ClientToServer,
        n, maximalKey, output));
    assert(first == output);
}

} // namespace

int main()
{
    testReferenceVectors();
    testNonceAndKeyAreBound();
    testFailClosedLengthsAndOutput();
}
