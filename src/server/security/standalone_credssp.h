// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "credssp_tsrequest.h"
#include "linux_authenticated_principal_proof.h"
#include "native_desktop_authorization.h"
#include "standalone_spnego.h"

#include <openssl/ssl.h>

#include <array>
#include <cstdint>

namespace rdp_server::server::security
{

enum class StandaloneCredSspStage : std::uint8_t
{
    Unconfigured,
    AwaitInitialNego,
    NegoContinue,
    AwaitBinding,
    ServerBindingReplyQueued,
    CredentialsVerified,
    Failed,
};

enum class StandaloneCredSspFrameStatus : std::uint8_t
{
    NegoReplyQueued,
    BindingReplyQueued,
    CredentialsVerified,
    Rejected,
};

// Redacted R2 acceptance boundary. Admission is recorded by the composed
// runtime after CredSSP has produced CredentialsVerified.
enum class StandaloneAuthenticationFailureStage : std::uint8_t
{
    None,
    NtlmNegotiation,
    Mic,
    SignSeal,
    Spnego,
    PubKeyAuth,
    AuthInfo,
    Admission,
};

struct StandaloneCredSspInitialNegoObservation final
{
    bool observed{};
    std::uint32_t tsRequestVersion{};
    std::size_t tokenCount{};
    StandaloneSpnegoInitialTokenObservation spnego{};
};

// Connection-scoped, noncopyable CredSSP wrapper for the standalone
// application-password NTLM mechanism.
//
// This owner accepts only COMPLETE TLS-derived TSRequest frames from one
// TsRequestFrameReader and queues replies through one TsRequestTlsReplyWriter.
// The first frame pins the exact established server SSL object, selected X.509
// certificate fingerprint and CredSSP version; every later frame must match.
//
// This owner also consumes the final protected TSPasswordCreds after the
// binding reply has been fully written/released. Matching credentials prove
// only equivalence to the configured memory-only standalone password; they do
// not grant R2 admission, create a native desktop owner, or enable the
// product's independent-password credential mode.
class StandaloneCredSspNtlmAcceptor final
{
public:
    StandaloneCredSspNtlmAcceptor() noexcept = default;
    ~StandaloneCredSspNtlmAcceptor();

    StandaloneCredSspNtlmAcceptor(
        const StandaloneCredSspNtlmAcceptor &) = delete;
    StandaloneCredSspNtlmAcceptor &operator=(
        const StandaloneCredSspNtlmAcceptor &) = delete;
    StandaloneCredSspNtlmAcceptor(
        StandaloneCredSspNtlmAcceptor &&) = delete;
    StandaloneCredSspNtlmAcceptor &operator=(
        StandaloneCredSspNtlmAcceptor &&) = delete;

    [[nodiscard]] bool configureChallenge(
        const StandaloneSpnegoChallengeConfiguration &configuration) noexcept;

    // Consume exactly one already-complete TLS-derived TSRequest. The caller
    // must fully write and release each queued reply before presenting another
    // frame. Token-only negotiation is accepted until the NTLM mechanism is
    // complete. For the NTLM-first CredSSP fast path, the final SPNEGO token
    // may share the TSRequest with pubKeyAuth/clientNonce as required by
    // MS-CSSP 3.1.5; only the canonical empty accept-completed SPNEGO response
    // may then be suppressed because the server binding reply MUST omit
    // negoTokens.
    [[nodiscard]] StandaloneCredSspFrameStatus processCompleteFrame(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const EphemeralNtlmV2Credential &credential) noexcept;

    // Production-only counterpart. The completed frame must have been read by
    // TsRequestFrameReader through this exact R1 connection owner, and every
    // queued reply remains bound to that owner. Direct-SSL test frames can
    // never qualify for credentialsVerifiedForOwnedConnection().
    [[nodiscard]] StandaloneCredSspFrameStatus processCompleteOwnedFrame(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const EphemeralNtlmV2Credential &credential) noexcept;

    [[nodiscard]] bool credentialsVerifiedForOwnedConnection(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection) const noexcept;

    [[nodiscard]] StandaloneCredSspStage stage() const noexcept
    {
        return stage_;
    }

    [[nodiscard]] StandaloneAuthenticationFailureStage failureStage() const noexcept
    {
        return failureStage_;
    }

    // Redacted parser outcome captured before terminal mechanism cleansing.
    // This is diagnostic only and never authorizes fallback or admission.
    [[nodiscard]] StandaloneSpnegoStatus lastSpnegoStatus() const noexcept
    {
        return lastSpnegoStatus_;
    }
    [[nodiscard]] StandaloneSpnegoRejectionReason spnegoRejectionReason()
        const noexcept
    {
        return spnegoRejectionReason_;
    }

    [[nodiscard]] StandaloneCredSspInitialNegoObservation
    initialNegoObservation() const noexcept
    {
        return initialNegoObservation_;
    }

    void reset() noexcept;

private:
    [[nodiscard]] bool bindOrMatchFrameProvenance(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            *connection,
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const TsRequestResult &request) noexcept;
    [[nodiscard]] bool queueReply(
        TsRequestTlsReplyWriter &writer,
        CredSspServerReplyField field,
        std::span<const std::uint8_t> providerOutput) noexcept;
    [[nodiscard]] StandaloneCredSspFrameStatus processCompleteFrameImpl(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            *connection,
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const EphemeralNtlmV2Credential &credential) noexcept;
    [[nodiscard]] StandaloneCredSspFrameStatus processNego(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const TsRequestResult &request,
        const EphemeralNtlmV2Credential &credential) noexcept;
    [[nodiscard]] StandaloneCredSspFrameStatus processBinding(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const TsRequestResult &request,
        bool combinedFinal) noexcept;
    [[nodiscard]] StandaloneCredSspFrameStatus processAuthInfo(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const TsRequestResult &request,
        const EphemeralNtlmV2Credential &credential) noexcept;
    [[nodiscard]] StandaloneCredSspFrameStatus reject(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer) noexcept;
    [[nodiscard]] bool matchesPinnedTls(const SSL *serverTls) const noexcept;

    StandaloneSpnegoNtlmAcceptor mechanism_{};
    StandaloneSpnegoStatus lastSpnegoStatus_{
        StandaloneSpnegoStatus::Continue};
    StandaloneSpnegoRejectionReason spnegoRejectionReason_{
        StandaloneSpnegoRejectionReason::None};
    TsRequestFrameReader *boundReader_{};
    TsRequestTlsReplyWriter *boundWriter_{};
    const SSL *boundServerTls_{};
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        *boundConnection_{};
    CredSspTlsCertificateFingerprint pinnedCertificate_{};
    std::uint32_t negotiatedVersion_{};
    StandaloneCredSspStage stage_{StandaloneCredSspStage::Unconfigured};
    StandaloneAuthenticationFailureStage failureStage_{
        StandaloneAuthenticationFailureStage::None};
    StandaloneCredSspInitialNegoObservation initialNegoObservation_{};
};


// Connection-scoped R2 proof for the independent application password.
// It borrows the already-verified standalone CredSSP owner and the service-
// lifetime credential owner at one exact generation. It owns no password/hash,
// native session, owner consent, lease or R3 state.
class StandalonePasswordAuthenticatedPrincipalProof final
    : public LinuxAuthenticatedPrincipalProof,
      public NativeDesktopAuthenticatedSessionProof
{
public:
    StandalonePasswordAuthenticatedPrincipalProof() noexcept = default;
    ~StandalonePasswordAuthenticatedPrincipalProof() override;

    StandalonePasswordAuthenticatedPrincipalProof(
        const StandalonePasswordAuthenticatedPrincipalProof &) = delete;
    StandalonePasswordAuthenticatedPrincipalProof &operator=(
        const StandalonePasswordAuthenticatedPrincipalProof &) = delete;

    [[nodiscard]] bool bind(
        StandaloneCredSspNtlmAcceptor &acceptor,
        const StandalonePasswordCredentialOwner &credentialOwner,
        std::uint64_t credentialGeneration,
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection) noexcept;

    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept override
    {
        return NativeDesktopAuthenticationKind::StandalonePassword;
    }
    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override;
    [[nodiscard]] bool revalidatesAuthenticatedSession()
        const noexcept override;

private:
    [[nodiscard]] bool credentialGenerationCurrent() const noexcept;
    [[nodiscard]] bool pendingNativeAdmissionMatches(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) const noexcept override;
    [[nodiscard]] bool completeNativeAdmission(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) noexcept override;
    [[nodiscard]] bool revalidatesNativeAdmission(
        const SSL *activeServerTls,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) const noexcept override;
    void revokeAuthenticatedProof() noexcept override;

    StandaloneCredSspNtlmAcceptor *acceptor_{};
    const StandalonePasswordCredentialOwner *credentialOwner_{};
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        *connection_{};
    std::uint64_t credentialGeneration_{};
    std::uint64_t activeAuthenticationGeneration_{};
    std::uint64_t nextAuthenticationGeneration_{};
    std::uint64_t policyGeneration_{};
    bool nativeAdmissionComplete_{};
};

} // namespace rdp_server::server::security
