// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "credssp_tsrequest.h"
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
    Failed,
};

enum class StandaloneCredSspFrameStatus : std::uint8_t
{
    NegoReplyQueued,
    BindingReplyQueued,
    Rejected,
};

// Connection-scoped, noncopyable CredSSP wrapper for the standalone
// application-password NTLM mechanism.
//
// This owner accepts only COMPLETE TLS-derived TSRequest frames from one
// TsRequestFrameReader and queues replies through one TsRequestTlsReplyWriter.
// The first frame pins the exact established server SSL object, selected X.509
// certificate fingerprint and CredSSP version; every later frame must match.
//
// This increment ends after a verified v5/v6 TLS public-key binding reply has
// been queued. It does not consume authInfo, grant R2 admission, create a native
// desktop owner, or enable the product's independent-password credential mode.
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

    [[nodiscard]] StandaloneCredSspStage stage() const noexcept
    {
        return stage_;
    }

    void reset() noexcept;

private:
    [[nodiscard]] bool bindOrMatchFrameProvenance(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const TsRequestResult &request) noexcept;
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
    [[nodiscard]] StandaloneCredSspFrameStatus reject(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer) noexcept;
    [[nodiscard]] bool matchesPinnedTls(const SSL *serverTls) const noexcept;

    StandaloneSpnegoNtlmAcceptor mechanism_{};
    TsRequestFrameReader *boundReader_{};
    TsRequestTlsReplyWriter *boundWriter_{};
    const SSL *boundServerTls_{};
    CredSspTlsCertificateFingerprint pinnedCertificate_{};
    std::uint32_t negotiatedVersion_{};
    StandaloneCredSspStage stage_{StandaloneCredSspStage::Unconfigured};
};

} // namespace rdp_server::server::security
