// SPDX-License-Identifier: GPL-3.0-or-later
#include "standalone_credssp.h"

#include "credssp_tls_certificate.h"
#include "transport/nonblocking_tcp_adapter.h"
#include "credssp_credentials_internal.h"

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

struct StandalonePasswordMatchContext final
{
    const EphemeralNtlmV2Credential *credential{};
    bool matched{};
};

void matchStandalonePasswordFields(
    std::span<const std::uint8_t> domainUtf16Le,
    std::span<const std::uint8_t> userUtf16Le,
    std::span<const std::uint8_t> passwordUtf16Le,
    void *opaqueContext) noexcept
{
    auto *context =
        static_cast<StandalonePasswordMatchContext *>(opaqueContext);
    if (context == nullptr || context->credential == nullptr)
        return;
    context->matched = context->credential->matchesDelegatedPassword(
        domainUtf16Le, userUtf16Le, passwordUtf16Le);
}

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

[[nodiscard]] bool hasOwnedHybridNlaProvenance(
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection) noexcept
{
    using namespace rdp_server::server::transport;
    const auto provenance = connection.securityNegotiationProvenance();
    return connection.active() &&
           connection.establishedTls() != nullptr &&
           provenance.has_value() &&
           (provenance->clientRequestedProtocols & kRdpProtocolHybrid) != 0 &&
           provenance->serverSelectedProtocol == kRdpProtocolHybrid;
}

[[nodiscard]] constexpr StandaloneAuthenticationFailureStage
mapSpnegoFailureStage(StandaloneSpnegoFailureStage stage) noexcept
{
    switch (stage)
    {
    case StandaloneSpnegoFailureStage::None:
        return StandaloneAuthenticationFailureStage::None;
    case StandaloneSpnegoFailureStage::Spnego:
        return StandaloneAuthenticationFailureStage::Spnego;
    case StandaloneSpnegoFailureStage::NtlmNegotiation:
        return StandaloneAuthenticationFailureStage::NtlmNegotiation;
    case StandaloneSpnegoFailureStage::Mic:
        return StandaloneAuthenticationFailureStage::Mic;
    }
    return StandaloneAuthenticationFailureStage::Spnego;
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
        failureStage_ =
            StandaloneAuthenticationFailureStage::NtlmNegotiation;
        stage_ = StandaloneCredSspStage::Failed;
        return false;
    }
    failureStage_ = StandaloneAuthenticationFailureStage::None;
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
    boundConnection_ = nullptr;
    negotiatedVersion_ = 0;
    stage_ = StandaloneCredSspStage::Unconfigured;
    failureStage_ = StandaloneAuthenticationFailureStage::None;
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
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        *connection,
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const TsRequestResult &request) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    const bool ownerBound = reader.completedFrameUsesOwnedTransport();
    if (!request ||
        (request.value.version != 5 && request.value.version != 6) ||
        sourceTls == nullptr ||
        writer.status() != TsRequestTlsWriteStatus::Idle ||
        (connection == nullptr && ownerBound) ||
        (connection != nullptr &&
         (!ownerBound ||
          !reader.completedFrameOwnedBy(*connection) ||
          !hasOwnedHybridNlaProvenance(*connection) ||
          connection->establishedTls() != sourceTls)))
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
        boundConnection_ = connection;
        pinnedCertificate_ = fingerprint;
        OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
        negotiatedVersion_ = request.value.version;
        return true;
    }

    return boundReader_ == &reader &&
           boundWriter_ == &writer &&
           boundConnection_ == connection &&
           negotiatedVersion_ == request.value.version &&
           matchesPinnedTls(sourceTls);
}

bool StandaloneCredSspNtlmAcceptor::queueReply(
    TsRequestTlsReplyWriter &writer,
    CredSspServerReplyField field,
    std::span<const std::uint8_t> providerOutput) noexcept
{
    if (boundConnection_ != nullptr)
    {
        return writer.queueReply(
            *boundConnection_,
            static_cast<std::uint8_t>(negotiatedVersion_),
            field, providerOutput);
    }
    return writer.queueReply(
        const_cast<SSL *>(boundServerTls_),
        static_cast<std::uint8_t>(negotiatedVersion_),
        field, providerOutput);
}

StandaloneCredSspFrameStatus StandaloneCredSspNtlmAcceptor::reject(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer) noexcept
{
    if (failureStage_ == StandaloneAuthenticationFailureStage::None)
    {
        switch (stage_)
        {
        case StandaloneCredSspStage::AwaitInitialNego:
        case StandaloneCredSspStage::NegoContinue:
            failureStage_ = StandaloneAuthenticationFailureStage::Spnego;
            break;
        case StandaloneCredSspStage::AwaitBinding:
            failureStage_ = StandaloneAuthenticationFailureStage::PubKeyAuth;
            break;
        case StandaloneCredSspStage::ServerBindingReplyQueued:
            failureStage_ = StandaloneAuthenticationFailureStage::AuthInfo;
            break;
        case StandaloneCredSspStage::Unconfigured:
        case StandaloneCredSspStage::CredentialsVerified:
        case StandaloneCredSspStage::Failed:
            failureStage_ = StandaloneAuthenticationFailureStage::Admission;
            break;
        }
    }
    reader.close();
    writer.close();
    mechanism_.reset();
    OPENSSL_cleanse(
        pinnedCertificate_.data(), pinnedCertificate_.size());
    boundReader_ = nullptr;
    boundWriter_ = nullptr;
    boundServerTls_ = nullptr;
    boundConnection_ = nullptr;
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
    failureStage_ = StandaloneAuthenticationFailureStage::PubKeyAuth;
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
    failureStage_ = StandaloneAuthenticationFailureStage::SignSeal;
    if (mechanism_.unwrapClientMessage(
            clientCiphertext,
            clientSignature,
            clientHash) != NtlmMessageSecurityResult::Processed)
    {
        OPENSSL_cleanse(clientHash.data(), clientHash.size());
        return reject(reader, writer);
    }
    failureStage_ = StandaloneAuthenticationFailureStage::PubKeyAuth;

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
    if (!serverHashReady)
    {
        OPENSSL_cleanse(serverHash.data(), serverHash.size());
        return reject(reader, writer);
    }

    failureStage_ = StandaloneAuthenticationFailureStage::SignSeal;
    const auto wrapResult = mechanism_.wrapServerMessage(
        serverHash, serverCiphertext, serverSignature);
    OPENSSL_cleanse(serverHash.data(), serverHash.size());
    if (wrapResult != NtlmMessageSecurityResult::Processed)
    {
        OPENSSL_cleanse(
            serverCiphertext.data(), serverCiphertext.size());
        OPENSSL_cleanse(
            serverSignature.data(), serverSignature.size());
        return reject(reader, writer);
    }
    failureStage_ = StandaloneAuthenticationFailureStage::PubKeyAuth;

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

    const bool queued = queueReply(
        writer,
        CredSspServerReplyField::EncryptedServerBinding,
        protectedReply);
    OPENSSL_cleanse(
        protectedReply.data(), protectedReply.size());
    if (!queued || !reader.releaseFrame())
        return reject(reader, writer);

    failureStage_ = StandaloneAuthenticationFailureStage::None;
    stage_ = StandaloneCredSspStage::ServerBindingReplyQueued;
    return StandaloneCredSspFrameStatus::BindingReplyQueued;
}

StandaloneCredSspFrameStatus
StandaloneCredSspNtlmAcceptor::processAuthInfo(
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const TsRequestResult &request,
    const EphemeralNtlmV2Credential &credential) noexcept
{
    failureStage_ = StandaloneAuthenticationFailureStage::AuthInfo;
    if (!request || !request.value.finalAuthInfoOnly() ||
        request.value.version != negotiatedVersion_ ||
        mechanism_.stage() != StandaloneSpnegoStage::MechanismVerified ||
        !matchesPinnedTls(reader.completedFrameServerTls()) ||
        writer.status() != TsRequestTlsWriteStatus::Idle)
    {
        return reject(reader, writer);
    }

    const auto protectedAuthInfo = request.value.encryptedAuthInfo;
    if (protectedAuthInfo.size() <= kNtlmMessageSignatureBytes ||
        protectedAuthInfo.size() >
            kNtlmMessageSignatureBytes +
                kMaximumDecryptedCredentialsBytes)
    {
        return reject(reader, writer);
    }

    const auto signature =
        std::span<const std::uint8_t, kNtlmMessageSignatureBytes>{
            protectedAuthInfo.data(), kNtlmMessageSignatureBytes};
    const auto ciphertext =
        protectedAuthInfo.subspan(kNtlmMessageSignatureBytes);
    std::array<std::uint8_t, kMaximumDecryptedCredentialsBytes>
        plaintextStorage{};
    auto plaintext =
        std::span<std::uint8_t>{plaintextStorage}.first(
            ciphertext.size());
    SensitiveBytesGuard plaintextGuard{plaintext};

    failureStage_ = StandaloneAuthenticationFailureStage::SignSeal;
    if (mechanism_.unwrapClientMessage(
            ciphertext, signature, plaintext) !=
        NtlmMessageSecurityResult::Processed)
    {
        return reject(reader, writer);
    }
    failureStage_ = StandaloneAuthenticationFailureStage::AuthInfo;

    StandalonePasswordMatchContext match{
        &credential, false};
    const auto visitStatus = visitCredSspValidatedPasswordFields(
        plaintext, &matchStandalonePasswordFields, &match);
    const bool verified =
        visitStatus == CredSspPasswordFieldVisitStatus::Visited &&
        match.matched &&
        credential.configured() &&
        matchesPinnedTls(reader.completedFrameServerTls());
    if (!verified || !reader.releaseFrame())
        return reject(reader, writer);

    // authInfo is the final CredSSP protected message. Retire the mechanism
    // keys and framing helpers immediately; the caller may use only the outer
    // CredentialsVerified state as non-authorizing evidence for later R2
    // composition. The configured credential itself remains owned by the GUI
    // service lifetime and is revoked separately on Stop.
    mechanism_.reset();
    reader.close();
    writer.close();
    failureStage_ = StandaloneAuthenticationFailureStage::None;
    stage_ = StandaloneCredSspStage::CredentialsVerified;
    return StandaloneCredSspFrameStatus::CredentialsVerified;
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
        failureStage_ = mapSpnegoFailureStage(
            mechanism_.failureStage());
        if (failureStage_ ==
            StandaloneAuthenticationFailureStage::None)
        {
            failureStage_ =
                StandaloneAuthenticationFailureStage::Spnego;
        }
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
    const bool queued = queueReply(
        writer, CredSspServerReplyField::NegoToken, replyBytes);
    OPENSSL_cleanse(
        mechanismReply.data(), mechanismReply.size());
    if (!queued || !reader.releaseFrame())
        return reject(reader, writer);

    failureStage_ = StandaloneAuthenticationFailureStage::None;
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
    return processCompleteFrameImpl(
        nullptr, reader, writer, credential);
}

StandaloneCredSspFrameStatus
StandaloneCredSspNtlmAcceptor::processCompleteOwnedFrame(
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const EphemeralNtlmV2Credential &credential) noexcept
{
    return processCompleteFrameImpl(
        &connection, reader, writer, credential);
}

StandaloneCredSspFrameStatus
StandaloneCredSspNtlmAcceptor::processCompleteFrameImpl(
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        *connection,
    TsRequestFrameReader &reader,
    TsRequestTlsReplyWriter &writer,
    const EphemeralNtlmV2Credential &credential) noexcept
{
    if (stage_ != StandaloneCredSspStage::AwaitInitialNego &&
        stage_ != StandaloneCredSspStage::NegoContinue &&
        stage_ != StandaloneCredSspStage::AwaitBinding &&
        stage_ != StandaloneCredSspStage::ServerBindingReplyQueued)
    {
        return reject(reader, writer);
    }

    const auto request =
        parseCredSspTsRequest(reader.completeDer());
    if (!bindOrMatchFrameProvenance(
            connection, reader, writer, request))
    {
        return reject(reader, writer);
    }

    if (stage_ == StandaloneCredSspStage::AwaitBinding)
    {
        return processBinding(
            reader, writer, request, false);
    }
    if (stage_ == StandaloneCredSspStage::ServerBindingReplyQueued)
    {
        return processAuthInfo(
            reader, writer, request, credential);
    }
    return processNego(
        reader, writer, request, credential);
}

bool StandaloneCredSspNtlmAcceptor::credentialsVerifiedForOwnedConnection(
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection) const noexcept
{
    return stage_ == StandaloneCredSspStage::CredentialsVerified &&
           boundConnection_ == &connection &&
           hasOwnedHybridNlaProvenance(connection) &&
           connection.establishedTls() == boundServerTls_ &&
           matchesPinnedTls(boundServerTls_);
}

StandalonePasswordAuthenticatedPrincipalProof::
    ~StandalonePasswordAuthenticatedPrincipalProof()
{
    revokeAuthenticatedProof();
}

bool StandalonePasswordAuthenticatedPrincipalProof::credentialGenerationCurrent()
    const noexcept
{
    if (credentialOwner_ == nullptr || credentialGeneration_ == 0)
        return false;
    const auto observation = credentialOwner_->observation();
    return observation.configured &&
           observation.generation == credentialGeneration_;
}

bool StandalonePasswordAuthenticatedPrincipalProof::bind(
    StandaloneCredSspNtlmAcceptor &acceptor,
    const StandalonePasswordCredentialOwner &credentialOwner,
    std::uint64_t credentialGeneration,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection) noexcept
{
    if (acceptor_ != nullptr || credentialOwner_ != nullptr ||
        connection_ != nullptr || credentialGeneration == 0 ||
        !acceptor.credentialsVerifiedForOwnedConnection(connection))
    {
        acceptor.reset();
        return false;
    }

    const auto observation = credentialOwner.observation();
    if (!observation.configured ||
        observation.generation != credentialGeneration)
    {
        acceptor.reset();
        return false;
    }

    acceptor_ = &acceptor;
    credentialOwner_ = &credentialOwner;
    connection_ = &connection;
    credentialGeneration_ = credentialGeneration;
    return true;
}

bool StandalonePasswordAuthenticatedPrincipalProof::
    pendingNativeAdmissionMatches(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) const noexcept
{
    return !nativeAdmissionComplete_ &&
           policyGeneration != 0 &&
           request.authenticationKind ==
               ConsoleEvidenceAuthenticationKind::StandalonePassword &&
           request.kerberosPrincipal.empty() &&
           acceptor_ != nullptr &&
           connection_ == &connection &&
           credentialGenerationCurrent() &&
           acceptor_->credentialsVerifiedForOwnedConnection(connection);
}

bool StandalonePasswordAuthenticatedPrincipalProof::completeNativeAdmission(
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    const ConsoleEvidenceRequest &request,
    std::uint64_t policyGeneration) noexcept
{
    if (!pendingNativeAdmissionMatches(
            connection, request, policyGeneration))
    {
        return false;
    }
    policyGeneration_ = policyGeneration;
    nativeAdmissionComplete_ = true;
    return true;
}

bool StandalonePasswordAuthenticatedPrincipalProof::revalidatesNativeAdmission(
    const SSL *activeServerTls,
    const ConsoleEvidenceRequest &request,
    std::uint64_t policyGeneration) const noexcept
{
    return nativeAdmissionComplete_ &&
           policyGeneration != 0 &&
           policyGeneration_ == policyGeneration &&
           request.authenticationKind ==
               ConsoleEvidenceAuthenticationKind::StandalonePassword &&
           request.kerberosPrincipal.empty() &&
           connection_ != nullptr &&
           activeServerTls != nullptr &&
           connection_->establishedTls() == activeServerTls &&
           credentialGenerationCurrent() &&
           acceptor_ != nullptr &&
           acceptor_->credentialsVerifiedForOwnedConnection(*connection_);
}

void StandalonePasswordAuthenticatedPrincipalProof::
    revokeAuthenticatedProof() noexcept
{
    if (acceptor_ != nullptr)
        acceptor_->reset();
    acceptor_ = nullptr;
    credentialOwner_ = nullptr;
    connection_ = nullptr;
    credentialGeneration_ = 0;
    policyGeneration_ = 0;
    nativeAdmissionComplete_ = false;
}

} // namespace rdp_server::server::security
