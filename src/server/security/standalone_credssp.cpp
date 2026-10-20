// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_credssp.h"

#include "credssp_tls_certificate.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{
namespace
{

constexpr std::array<std::uint8_t, 9> kCanonicalEmptyAcceptCompleted{
    0xa1,0x07,0x30,0x05,0xa0,0x03,0x0a,0x01,0x00};

[[nodiscard]] bool bindingOnlyRequest(
    const TsRequestResult &request) noexcept
{
    return request &&
           (request.value.version == 5 || request.value.version == 6) &&
           request.value.tokenCount == 0 &&
           request.value.hasPubKeyAuth &&
           !request.value.encryptedPubKeyAuth.empty() &&
           request.value.encryptedPubKeyAuth.size() <=
               kMaximumCredSspTokenBytes &&
           request.value.hasClientNonce &&
           request.value.clientNonce.size() == kCredSspNonceBytes &&
           !request.value.hasAuthInfo &&
           !request.value.hasErrorCode;
}

} // namespace

StandaloneCredSspNtlmAcceptor::~StandaloneCredSspNtlmAcceptor()
{
    reset();
}

bool StandaloneCredSspNtlmAcceptor::configureChallenge(
    const StandaloneSpnegoChallengeConfiguration &configuration) noexcept
{
    if (stage_ != StandaloneCredSspStage::Unconfigured ||
        !mechanism_.configureChallenge(configuration))
    {
        stage_ = StandaloneCredSspStage::Failed;
        return false;
    }
    stage_ = StandaloneCredSspStage::AwaitInitialNego;
    return true;
}

void StandaloneCredSspNtlmAcceptor::reset() noexcept
{
    mechanism_.reset();
    OPENSSL_cleanse(
        pinnedCertificate_.data(), pinnedCertificate_.size());
    boundReader_ = nullptr;
    boundWriter_ = nullptr;
    boundServerTls_ = nullptr;
    negotiatedVersion_ = 0;
    stage_ = StandaloneCredSspStage::Unconfigured;
}

bool StandaloneCredSspNtlmAcceptor::matchesPinnedTls(
    const SSL *serverTls) const noexcept
{
    if (serverTls == nullptr ||
        serverTls != boundServerTls_ ||
        boundServerTls_ == nullptr)
    {
        return false;
    }

    CredSspTlsCertificateFingerprint current{};
    if (!fingerprintActiveCredSspServerTlsCertificate(
            serverTls, current))
    {
        return false;
    }
    const bool matches = CRYPTO_memcmp(
        current.data(), pinnedCertificate_.data(),
        current.size()) == 0;
    OPENSSL_cleanse(current.data(), current.size());
    return matches;
}

bool StandaloneCredSspNtlmAcceptor::bindOrMatchFrameProvenance(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const TsRequestResult &request) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    if (!request ||
        (request.value.version != 5 && request.value.version != 6) ||
        sourceTls == nullptr ||
        writer.status() != TsRequestTlsWriteStatus::Idle)
    {
        return false;
    }

    if (boundReader_ == nullptr)
    {
        CredSspTlsCertificateFingerprint fingerprint{};
        if (!fingerprintActiveCredSspServerTlsCertificate(
                sourceTls, fingerprint))
        {
            return false;
        }
        boundReader_ = &reader;
        boundWriter_ = &writer;
        boundServerTls_ = sourceTls;
        pinnedCertificate_ = fingerprint;
        OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
        negotiatedVersion_ = request.value.version;
        return true;
    }

    return boundReader_ == &reader &&
           boundWriter_ == &writer &&
           negotiatedVersion_ == request.value.version &&
           matchesPinnedTls(sourceTls);
}

StandaloneCredSspFrameStatus StandaloneCredSspNtlmAcceptor::reject(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer) noexcept
{
    reader.close();
    writer.close();
    mechanism_.reset();
    OPENSSL_cleanse(
        pinnedCertificate_.data(), pinnedCertificate_.size());
    boundReader_ = nullptr;
    boundWriter_ = nullptr;
    boundServerTls_ = nullptr;
    negotiatedVersion_ = 0;
    stage_ = StandaloneCredSspStage::Failed;
    return StandaloneCredSspFrameStatus::Rejected;
}

StandaloneCredSspFrameStatus
StandaloneCredSspNtlmAcceptor::processBinding(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const TsRequestResult &request,
    bool combinedFinal) noexcept
{
    const bool permitted = combinedFinal
        ? request && request.value.finalNegoAndBindingOnly()
        : bindingOnlyRequest(request);
    if (!permitted ||
        mechanism_.stage() != StandaloneSpnegoStage::MechanismVerified ||
        !matchesPinnedTls(reader.completedFrameServerTls()) ||
        request.value.version != negotiatedVersion_)
    {
        return reject(reader, writer);
    }

    const auto protectedBinding =
        request.value.encryptedPubKeyAuth;
    constexpr std::size_t kProtectedBindingBytes =
        kNtlmMessageSignatureBytes + kCredSspBindingHashBytes;
    if (protectedBinding.size() != kProtectedBindingBytes)
        return reject(reader, writer);

    const auto clientSignature =
        std::span<const std::uint8_t, kNtlmMessageSignatureBytes>{
            protectedBinding.data(), kNtlmMessageSignatureBytes};
    const auto clientCiphertext =
        protectedBinding.subspan(kNtlmMessageSignatureBytes);

    CredSspHash clientHash{};
    if (mechanism_.unwrapClientMessage(
            clientCiphertext,
            clientSignature,
            clientHash) != NtlmMessageSecurityResult::Processed)
    {
        OPENSSL_cleanse(clientHash.data(), clientHash.size());
        return reject(reader, writer);
    }

    const SSL *sourceTls = reader.completedFrameServerTls();
    const bool clientBindingMatches =
        verifyCredSspClientBindingForActiveServerTls(
            sourceTls, request.value.clientNonce, clientHash);
    OPENSSL_cleanse(clientHash.data(), clientHash.size());
    if (!clientBindingMatches)
        return reject(reader, writer);

    CredSspHash serverHash{};
    std::array<std::uint8_t, kCredSspBindingHashBytes>
        serverCiphertext{};
    std::array<std::uint8_t, kNtlmMessageSignatureBytes>
        serverSignature{};
    std::array<std::uint8_t, kProtectedBindingBytes>
        protectedReply{};

    const bool serverHashReady =
        computeCredSspBindingForActiveServerTls(
            sourceTls,
            CredSspBindingDirection::ServerToClient,
            request.value.clientNonce,
            serverHash);
    const auto wrapResult = serverHashReady
        ? mechanism_.wrapServerMessage(
              serverHash, serverCiphertext, serverSignature)
        : NtlmMessageSecurityResult::CryptoFailure;
    OPENSSL_cleanse(serverHash.data(), serverHash.size());
    if (wrapResult != NtlmMessageSecurityResult::Processed)
    {
        OPENSSL_cleanse(
            serverCiphertext.data(), serverCiphertext.size());
        OPENSSL_cleanse(
            serverSignature.data(), serverSignature.size());
        return reject(reader, writer);
    }

    std::copy(
        serverSignature.begin(), serverSignature.end(),
        protectedReply.begin());
    std::copy(
        serverCiphertext.begin(), serverCiphertext.end(),
        protectedReply.begin() +
            static_cast<std::ptrdiff_t>(
                kNtlmMessageSignatureBytes));
    OPENSSL_cleanse(
        serverCiphertext.data(), serverCiphertext.size());
    OPENSSL_cleanse(
        serverSignature.data(), serverSignature.size());

    const bool queued = writer.queueReply(
        const_cast<SSL *>(sourceTls),
        static_cast<std::uint8_t>(negotiatedVersion_),
        CredSspServerReplyField::EncryptedServerBinding,
        protectedReply);
    OPENSSL_cleanse(
        protectedReply.data(), protectedReply.size());
    if (!queued || !reader.releaseFrame())
        return reject(reader, writer);

    stage_ = StandaloneCredSspStage::ServerBindingReplyQueued;
    return StandaloneCredSspFrameStatus::BindingReplyQueued;
}

StandaloneCredSspFrameStatus
StandaloneCredSspNtlmAcceptor::processNego(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const TsRequestResult &request,
    const EphemeralNtlmV2Credential &credential) noexcept
{
    const bool tokenOnly =
        request.value.initialNegoTokenOnly() &&
        request.value.tokenCount == 1;
    const bool combinedFinal =
        stage_ == StandaloneCredSspStage::NegoContinue &&
        request.value.finalNegoAndBindingOnly();
    if (!tokenOnly && !combinedFinal)
        return reject(reader, writer);

    std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes>
        mechanismReply{};
    const auto token = request.value.tokens[0];
    StandaloneSpnegoStep step;
    if (stage_ == StandaloneCredSspStage::AwaitInitialNego)
    {
        if (!tokenOnly)
            return reject(reader, writer);
        step = mechanism_.acceptInitialToken(
            token, mechanismReply);
    }
    else if (stage_ == StandaloneCredSspStage::NegoContinue)
    {
        step = mechanism_.acceptContinuationToken(
            token, credential, mechanismReply);
    }
    else
    {
        return reject(reader, writer);
    }

    if (!step ||
        step.bytesWritten == 0 ||
        step.bytesWritten > mechanismReply.size())
    {
        OPENSSL_cleanse(
            mechanismReply.data(), mechanismReply.size());
        return reject(reader, writer);
    }

    if (combinedFinal)
    {
        const bool suppressibleTerminalReply =
            step.status ==
                StandaloneSpnegoStatus::MechanismVerified &&
            step.bytesWritten ==
                kCanonicalEmptyAcceptCompleted.size() &&
            std::equal(
                kCanonicalEmptyAcceptCompleted.begin(),
                kCanonicalEmptyAcceptCompleted.end(),
                mechanismReply.begin());
        OPENSSL_cleanse(
            mechanismReply.data(), mechanismReply.size());
        if (!suppressibleTerminalReply)
            return reject(reader, writer);

        // MS-CSSP 3.1.5 requires the server binding reply to omit
        // negoTokens. The only suppressed SPNEGO bytes are our canonical
        // empty accept-completed envelope; any responseToken or server
        // mechListMIC requires a separate negotiation reply instead.
        return processBinding(
            reader, writer, request, true);
    }

    const auto replyBytes =
        std::span<const std::uint8_t>{mechanismReply}.first(
            step.bytesWritten);
    const bool queued = writer.queueReply(
        const_cast<SSL *>(boundServerTls_),
        static_cast<std::uint8_t>(negotiatedVersion_),
        CredSspServerReplyField::NegoToken,
        replyBytes);
    OPENSSL_cleanse(
        mechanismReply.data(), mechanismReply.size());
    if (!queued || !reader.releaseFrame())
        return reject(reader, writer);

    stage_ = step.status ==
            StandaloneSpnegoStatus::MechanismVerified
        ? StandaloneCredSspStage::AwaitBinding
        : StandaloneCredSspStage::NegoContinue;
    return StandaloneCredSspFrameStatus::NegoReplyQueued;
}

StandaloneCredSspFrameStatus
StandaloneCredSspNtlmAcceptor::processCompleteFrame(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const EphemeralNtlmV2Credential &credential) noexcept
{
    if (stage_ != StandaloneCredSspStage::AwaitInitialNego &&
        stage_ != StandaloneCredSspStage::NegoContinue &&
        stage_ != StandaloneCredSspStage::AwaitBinding)
    {
        return reject(reader, writer);
    }

    const auto request =
        parseCredSspTsRequest(reader.completeDer());
    if (!bindOrMatchFrameProvenance(
            reader, writer, request))
    {
        return reject(reader, writer);
    }

    if (stage_ == StandaloneCredSspStage::AwaitBinding)
    {
        return processBinding(
            reader, writer, request, false);
    }
    return processNego(
        reader, writer, request, credential);
}

} // namespace rdp_server::server::security
