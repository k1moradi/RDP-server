// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_spnego_acceptor.h"

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace rdp_server::server::security
{

namespace
{
[[nodiscard]] bool permittedBindingRequest(
    const TsRequestResult &request) noexcept
{
    return request &&
           request.value.version >= 5 && request.value.version <= 6 &&
           request.value.hasPubKeyAuth && request.value.hasClientNonce &&
           !request.value.hasAuthInfo && !request.value.hasErrorCode &&
           request.value.tokenCount == 0 &&
           !request.value.encryptedPubKeyAuth.empty() &&
           request.value.encryptedPubKeyAuth.size() <= kMaximumSpnegoInputBytes &&
           request.value.clientNonce.size() == kCredSspNonceBytes;
}
} // namespace

bool isCredSspPublicKeyAuthRequest(
    std::span<const std::uint8_t> der) noexcept
{
    return permittedBindingRequest(parseCredSspTsRequest(der));
}

CredSspProtectedReply GssapiSpnegoAcceptor::processProtectedBinding(
    const SSL *activeServerTls,
    std::span<const std::uint8_t> protectedRequestDer) noexcept
{
    const auto request = parseCredSspTsRequest(protectedRequestDer);
    // This call is legal ONLY after the actual system GSS provider completed
    // the Kerberos mechanism and checked mutual/conf/integ/replay/sequence
    // flags. Never accept an arbitrary raw hash or a parser-only token.
    if (stage_ != SpnegoStage::MechanismVerified ||
        context_ == GSS_C_NO_CONTEXT ||
        activeServerTls == nullptr ||
        SSL_is_server(activeServerTls) != 1 ||
        SSL_is_init_finished(activeServerTls) != 1 ||
        !permittedBindingRequest(request))
    {
        reject();
        return {};
    }

    // Both input spans borrow the caller's original DER TSRequest buffer.
    // This must never turn TSRequest.pubKeyAuth ciphertext directly into a
    // plaintext hash comparison. Only GSS unwrap is permitted to do that.
    const auto wrapped = request.value.encryptedPubKeyAuth;
    gss_buffer_desc encrypted{
        wrapped.size(), const_cast<std::uint8_t *>(wrapped.data())};
    gss_buffer_desc unwrapped = GSS_C_EMPTY_BUFFER;
    int wasConfidential = 0;
    OM_uint32 minor = 0;
    const OM_uint32 unwrappedStatus =
        gss_unwrap(&minor, context_, &encrypted, &unwrapped,
                   &wasConfidential, nullptr);

    bool matches = false;
    if (unwrappedStatus == GSS_S_COMPLETE &&
        wasConfidential != 0 &&
        unwrapped.value != nullptr &&
        unwrapped.length == kCredSspBindingHashBytes)
    {
        const auto hash = std::span(
            static_cast<const std::uint8_t *>(unwrapped.value),
            unwrapped.length);
        matches = verifyCredSspClientBindingForActiveServerTls(
            activeServerTls, request.value.clientNonce, hash);
    }
    if (unwrapped.value != nullptr && unwrapped.length != 0)
    {
        // Provider-allocated plaintext: erase before releasing its buffer.
        OPENSSL_cleanse(unwrapped.value, unwrapped.length);
    }
    (void)gss_release_buffer(&minor, &unwrapped);
    if (!matches)
    {
        reject();
        return {};
    }

    CredSspHash serverHash{};
    if (!computeCredSspBindingForActiveServerTls(
            activeServerTls, CredSspBindingDirection::ServerToClient,
            request.value.clientNonce, serverHash))
    {
        reject();
        return {};
    }
    gss_buffer_desc plaintext{serverHash.size(), serverHash.data()};
    gss_buffer_desc encryptedReply = GSS_C_EMPTY_BUFFER;
    int replyIsConfidential = 0;
    const OM_uint32 wrappedStatus = gss_wrap(
        &minor, context_, 1, GSS_C_QOP_DEFAULT, &plaintext,
        &replyIsConfidential, &encryptedReply);
    OPENSSL_cleanse(serverHash.data(), serverHash.size());

    CredSspProtectedReply result{};
    bool copied = false;
    if (wrappedStatus == GSS_S_COMPLETE &&
        replyIsConfidential != 0 &&
        encryptedReply.value != nullptr &&
        encryptedReply.length > 0 &&
        encryptedReply.length <= kMaximumSpnegoOutputBytes)
    {
        try
        {
            const auto *start =
                static_cast<const std::uint8_t *>(encryptedReply.value);
            result.encryptedServerBinding.assign(
                start, start + encryptedReply.length);
            copied = true;
        }
        catch (...)
        {
            copied = false;
        }
    }
    (void)gss_release_buffer(&minor, &encryptedReply);
    if (!copied)
    {
        reject();
        return {};
    }

    // The GSS binding exchange completed, not authentication of an RDP
    // desktop user. TSCredentials, identity authorization, policy, and
    // MCS response are intentionally absent in this diagnostic milestone.
    stage_ = SpnegoStage::ServerBindingPrepared;
    result.ready = true;
    return result;
}

} // namespace rdp_server::server::security
