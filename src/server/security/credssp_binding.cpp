// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_binding.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <memory>

namespace rdp_server::server::security
{
namespace
{

// sizeof() intentionally includes the terminating NUL octet as required
// by MS-CSSP 3.1.5. These are NOT interchangeable for the two directions.
constexpr char kClientToServerMagic[] =
    "CredSSP Client-To-Server Binding Hash";
constexpr char kServerToClientMagic[] =
    "CredSSP Server-To-Client Binding Hash";

} // namespace

bool computeCredSspBindingHash(
    CredSspBindingDirection direction,
    std::span<const std::uint8_t> clientNonce,
    std::span<const std::uint8_t> tlsSubjectPublicKey,
    CredSspHash &output) noexcept
{
    output.fill(0);
    if (clientNonce.size() != kCredSspNonceBytes ||
        tlsSubjectPublicKey.empty() ||
        tlsSubjectPublicKey.size() > kMaximumCredSspPublicKeyBytes)
    {
        return false;
    }
    const char *magic = nullptr;
    std::size_t magicLength = 0;
    switch (direction)
    {
        case CredSspBindingDirection::ClientToServer:
            magic = kClientToServerMagic;
            magicLength = sizeof(kClientToServerMagic);
            break;
        case CredSspBindingDirection::ServerToClient:
            magic = kServerToClientMagic;
            magicLength = sizeof(kServerToClientMagic);
            break;
        default:
            return false;
    }

    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context)
    {
        return false;
    }
    CredSspHash calculated{};
    unsigned int hashSize = 0;
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), magic, magicLength) != 1 ||
        EVP_DigestUpdate(context.get(), clientNonce.data(),
                         clientNonce.size()) != 1 ||
        EVP_DigestUpdate(context.get(), tlsSubjectPublicKey.data(),
                         tlsSubjectPublicKey.size()) != 1 ||
        EVP_DigestFinal_ex(context.get(), calculated.data(), &hashSize) != 1 ||
        hashSize != calculated.size())
    {
        OPENSSL_cleanse(calculated.data(), calculated.size());
        return false;
    }
    output = calculated;
    OPENSSL_cleanse(calculated.data(), calculated.size());
    return true;
}

bool verifyCredSspClientBindingHash(
    std::span<const std::uint8_t> clientNonce,
    std::span<const std::uint8_t> tlsSubjectPublicKey,
    std::span<const std::uint8_t> alreadyUnwrappedClientHash) noexcept
{
    // Encrypted TSRequest.pubKeyAuth can be any size. Never treat it as a
    // plaintext SHA-256 value without the GSS provider's integrity check.
    if (alreadyUnwrappedClientHash.size() != kCredSspBindingHashBytes)
    {
        return false;
    }
    CredSspHash expected{};
    if (!computeCredSspBindingHash(
            CredSspBindingDirection::ClientToServer, clientNonce,
            tlsSubjectPublicKey, expected))
    {
        return false;
    }
    const bool matches = CRYPTO_memcmp(
        expected.data(), alreadyUnwrappedClientHash.data(),
        expected.size()) == 0;
    OPENSSL_cleanse(expected.data(), expected.size());
    return matches;
}

} // namespace rdp_server::server::security
