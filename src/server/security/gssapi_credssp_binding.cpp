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
    const TsRequestResult &request, bool combinedFinal) noexcept
{
    if (!request)
        return false;
    if (combinedFinal)
        return request.value.finalNegoAndBindingOnly();
    return (request.value.version == 5 || request.value.version == 6) &&
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
    return permittedBindingRequest(parseCredSspTsRequest(der), false);
}

CredSspProtectedReply GssapiSpnegoAcceptor::processProtectedBinding(
    const SSL *activeServerTls,
    std::span<const std::uint8_t> protectedRequestDer) noexcept
{
    // Caller-supplied DER has no authenticated TLS read provenance. Do not
    // allow any provider state, even a genuine GSS context, to turn it into
    // a successful binding response. The old API is terminal/deny-only.
    (void)activeServerTls;
    (void)protectedRequestDer;
    reject();
    return {};
}

CredSspProtectedReply GssapiSpnegoAcceptor::processFramedProtectedBinding(
    TsRequestFrameReader &reader) noexcept
{
    // The reader is the SINGLE TLS provenance and DER lifetime owner.
    // completedFrameServerTls() also checks the pinned selected X.509
    // fingerprint; a caller cannot inject or swap a TLS identity.
    const SSL *sourceTls = reader.completedFrameServerTls();
    if (sourceTls == nullptr || negotiatedServerTls_ == nullptr ||
        sourceTls != negotiatedServerTls_)
    {
        reader.close();
        reject();
        return {};
    }
    const auto parsed = parseCredSspTsRequest(reader.completeDer());
    if (!parsed || !permittedBindingRequest(parsed, false) ||
        negotiatedVersion_ != parsed.value.version)
    {
        reader.close();
        reject();
        return {};
    }

    // No transient plaintext is exported; processVerifiedBinding performs
    // real confidential GSS unwrap, active TLS cert/nonce comparison and
    // server GSS wrap before we erase the ONE framed DER input.
    auto result = processVerifiedBinding(sourceTls, parsed, false);
    if (!result.ready || !reader.releaseFrame())
    {
        reader.close();
        reject();
        return {};
    }
    return result;
}

CredSspProtectedReply GssapiSpnegoAcceptor::processFinalFramedNegoAndBinding(
    TsRequestFrameReader &reader) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    const auto parsed = parseCredSspTsRequest(reader.completeDer());
    if (stage_ != SpnegoStage::ContinueNeeded ||
        negotiatedServerTls_ == nullptr ||
        sourceTls == nullptr || sourceTls != negotiatedServerTls_ ||
        negotiatedVersion_ != parsed.value.version ||
        !parsed || !parsed.value.finalNegoAndBindingOnly())
    {
        reader.close();
        reject();
        return {};
    }

    // All views, including the encrypted binding and GSS input token, are
    // borrowed from the SINGLE TLS-derived frame, kept alive until GSS
    // acceptance, unwrap and wrap have all completed synchronously.
    auto mechanism = accept(parsed.value.tokens[0]);
    const bool verified = mechanism.status == SpnegoStatus::MechanismVerified;
    const bool noOutstandingToken = mechanism.outputToken.empty();
    // The server binding-only TSRequest cannot silently discard an
    // outstanding SPNEGO output token from the final accept step. Wipe
    // that ephemeral provider output even on a terminal rejection.
    if (!mechanism.outputToken.empty())
    {
        OPENSSL_cleanse(mechanism.outputToken.data(),
                        mechanism.outputToken.size());
        mechanism.outputToken.clear();
    }
    if (!verified || !noOutstandingToken)
    {
        reader.close();
        reject();
        return {};
    }
    auto result = processVerifiedBinding(sourceTls, parsed, true);
    if (!result.ready || !reader.releaseFrame())
    {
        reader.close();
        reject();
        return {};
    }
    return result;
}


bool GssapiSpnegoAcceptor::processFinalFramedNegoAndQueueBindingReply(
    TsRequestFrameReader &reader, TsRequestTlsReplyWriter &writer) noexcept
{
    return queueFramedProtectedReply(reader, writer, true);
}

bool GssapiSpnegoAcceptor::processFramedProtectedBindingAndQueueReply(
    TsRequestFrameReader &reader, TsRequestTlsReplyWriter &writer) noexcept
{
    return queueFramedProtectedReply(reader, writer, false);
}

bool GssapiSpnegoAcceptor::queueFramedProtectedReply(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    bool combinedFinal) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    if (sourceTls == nullptr ||
        writer.status() != TsRequestTlsWriteStatus::Idle)
    {
        reader.close();
        writer.close();
        reject();
        return false;
    }

    auto result = combinedFinal
        ? processFinalFramedNegoAndBinding(reader)
        : processFramedProtectedBinding(reader);
    const bool validBinding =
        result.ready &&
        stage_ == SpnegoStage::ServerBindingPrepared &&
        negotiatedServerTls_ == sourceTls &&
        (negotiatedVersion_ == 5 || negotiatedVersion_ == 6) &&
        !result.encryptedServerBinding.empty();

    bool queued = false;
    if (validBinding)
    {
        // The only reply source is this exact GSS context's confidential
        // gss_wrap result, after same-TLS client binding verification.
        queued = writer.queueReply(
            const_cast<SSL *>(sourceTls),
            static_cast<std::uint8_t>(negotiatedVersion_),
            CredSspServerReplyField::EncryptedServerBinding,
            result.encryptedServerBinding);
    }
    if (!result.encryptedServerBinding.empty())
    {
        OPENSSL_cleanse(result.encryptedServerBinding.data(),
                        result.encryptedServerBinding.size());
        result.encryptedServerBinding.clear();
    }
    if (!queued)
    {
        reader.close();
        writer.close();
        reject();
        return false;
    }
    return true;
}

CredSspProtectedReply GssapiSpnegoAcceptor::processVerifiedBinding(
    const SSL *activeServerTls,
    const TsRequestResult &request, bool combinedFinal) noexcept
{
    // This call is legal ONLY after the actual system GSS provider completed
    // the Kerberos mechanism and checked mutual/conf/integ/replay/sequence
    // flags. Never accept an arbitrary raw hash or a parser-only token.
    if (stage_ != SpnegoStage::MechanismVerified ||
        context_ == GSS_C_NO_CONTEXT ||
        activeServerTls == nullptr ||
        negotiatedServerTls_ == nullptr ||
        activeServerTls != negotiatedServerTls_ ||
        negotiatedVersion_ != request.value.version ||
        SSL_is_server(activeServerTls) != 1 ||
        SSL_is_init_finished(activeServerTls) != 1 ||
        !permittedBindingRequest(request, combinedFinal))
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
