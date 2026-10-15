// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "credssp_tsrequest.h"
#include "credssp_tls_certificate.h"
#include "credssp_credentials.h"

#include <gssapi/gssapi.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rdp_server::server::security
{

// A Linux MIT GSSAPI acceptor adapter, not a CredSSP/NLA authorization
// decision. Only explicit keytabs and exact TERMSRV/host@REALM service principals
// may be used. No implicit default keytab, host login or credentials.
enum class SpnegoStage : std::uint8_t
{
    Unconfigured,
    AwaitInitialToken,
    ContinueNeeded,
    MechanismVerified,
    ServerBindingPrepared,
    Failed,
};

enum class SpnegoStatus : std::uint8_t
{
    Rejected,
    Continue,
    MechanismVerified,
};

enum class GssConfigurationFailure : std::uint8_t
{
    None,
    InvalidOptions,
    ImportService,
    AcquireCredentials,
    Allocation,
};

struct GssConfigurationDiagnostics
{
    GssConfigurationFailure stage{GssConfigurationFailure::None};
    std::uint32_t major{};
    std::uint32_t minor{};
};

struct SpnegoStep
{
    SpnegoStatus status{SpnegoStatus::Rejected};
    // Wire output from GSS; never sent unless the surrounding CredSSP
    // state machine has produced a matching TSRequest envelope.
    std::vector<std::uint8_t> outputToken{};
};

// An encrypted, integrity-protected GSS token containing the expected
// SERVER-to-client binding digest. Its existence is not user/session
// authorization and no method here handles TSCredentials.
// Syntax/policy check only; does not unwrap credentials or verify identity.
[[nodiscard]] bool isCredSspPublicKeyAuthRequest(
    std::span<const std::uint8_t> der) noexcept;

struct CredSspProtectedReply
{
    bool ready{};
    std::vector<std::uint8_t> encryptedServerBinding{};
};

inline constexpr std::size_t kMaximumSpnegoInputBytes = 8192;
inline constexpr std::size_t kMaximumSpnegoOutputBytes = 8192;
inline constexpr std::size_t kMaximumSpnegoRoundTrips = 16;

// RFC 4178 GSS-API initial token must advertise SPNEGO OID 1.3.6.1.5.5.2.
// Token bytes thereafter belong ONLY to GSSAPI, not a handwritten ASN.1
// mechanism parser. Subsequent mechanism tokens are not re-encapsulated.
[[nodiscard]] bool isInitialSpnegoToken(
    std::span<const std::uint8_t> token) noexcept;

class GssapiSpnegoAcceptor final
{
public:
    GssapiSpnegoAcceptor() noexcept = default;
    GssapiSpnegoAcceptor(const GssapiSpnegoAcceptor &) = delete;
    GssapiSpnegoAcceptor &operator=(const GssapiSpnegoAcceptor &) = delete;
    GssapiSpnegoAcceptor(GssapiSpnegoAcceptor &&) = delete;
    GssapiSpnegoAcceptor &operator=(GssapiSpnegoAcceptor &&) = delete;
    ~GssapiSpnegoAcceptor();

    // serviceName: e.g. TERMSRV/rdp.example.test@EXAMPLE.TEST.
    // Exact Kerberos service principal and realm; no DNS canonicalization.
    // keytabFile: explicit absolute FILE path only, never host default.
    // Failed configuration permanently poisons this object.
    [[nodiscard]] bool configure(std::string_view serviceName,
                                 std::string_view keytabFile) noexcept;

    // Call exactly once per incoming CredSSP TSRequest negoToken. Only a
    // COMPLETE GSS context with authenticated Kerberos, mutual, confidentiality,
    // integrity, replay and sequencing flags can reach MechanismVerified.
    // This still does NOT prove TLS pubKeyAuth binding or allow MCS.
    [[nodiscard]] SpnegoStep accept(
        std::span<const std::uint8_t> token) noexcept;

    // Convenient checked handoff: rejects arbitrary TSRequest fields and
    // multiple tokens rather than treating encrypted authInfo as SPNEGO.
    [[nodiscard]] SpnegoStep acceptInitialRequest(
        const TsRequestResult &request) noexcept;

    // Consume exactly one TLS-derived CredSSP DER frame synchronously.
    // Pin the SSL identity and version on the first request. Reject all
    // synthetic/manual buffers, SSL substitution, version changes or
    // premature handoffs; the frame is wiped before returning. The caller
    // keeps the SSL alive while this acceptor is active and cannot
    // substitute an independent TLS connection at the public-key gate.
    // This does NOT grant GSS or OS authorization.
    [[nodiscard]] SpnegoStep acceptFramedNegoRequest(
        TsRequestFrameReader &reader) noexcept;

    // MS-CSSP 3.1.5 SPNEGO continuation -> server negoTokens reply.
    // Only a REAL GSS continuation result on the completed TLS-derived
    // frame can queue a response. A full GSS completion without the
    // mandatory combined final client binding is rejected here.
    // The caller must drive the existing writer's SSL_write_ex readiness
    // loop and release the completed reply before accepting another token.
    // Rejected results permanently close reader, writer and GSS context.
    [[nodiscard]] SpnegoStatus acceptFramedNegoAndQueueReply(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer) noexcept;

    // Historical caller-supplied DER binding entry point. Intentionally
    // deny-only: a matching SSL* argument does NOT prove that these bytes
    // were actually read over that TLS connection. Retained solely so old
    // callers fail closed rather than silently using a bypass.
    // Prefer processFramedProtectedBinding for all binding-only messages.
    [[nodiscard]] CredSspProtectedReply processProtectedBinding(
        const SSL *activeServerTls,
        std::span<const std::uint8_t> protectedRequestDer) noexcept;

    // Binding-only (no negoTokens) MS-CSSP 2.2.1 request. Requires a
    // COMPLETE TSRequest frame genuinely read from the original TLS
    // server connection and unchanged selected certificate, following a
    // real GSS MechanismVerified step with the pinned v5/v6 version.
    // The same borrowed frame is synchronously GSS-unwrapped, compared
    // with the active certificate/nonce and wiped on success; failed
    // GSS/context/pinning/DER checks terminate reader and provider.
    // This proves TLS framing, never OS identity authorization.
    [[nodiscard]] CredSspProtectedReply processFramedProtectedBinding(
        TsRequestFrameReader &reader) noexcept;

    // Equivalent provider-sourced reply queue, never a direct socket
    // write. Requires idle writer and same proven server TLS identity.
    [[nodiscard]] bool processFramedProtectedBindingAndQueueReply(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer) noexcept;

    // MS-CSSP 3.1.5 final client message: exactly one last negoToken,
    // encrypted pubKeyAuth and a 32-byte nonce in the SAME TLS-derived
    // TSRequest. Requires an already continuing GSS context. Complete
    // the GSS step, unwrap/verify active TLS binding, and seal the server
    // binding reply synchronously before wiping the frame. A required
    // extra GSS output token cannot be omitted: reject rather than
    // send an incomplete public-key-only server response.
    // Neither success nor failure constitutes OS user authorization.
    [[nodiscard]] CredSspProtectedReply processFinalFramedNegoAndBinding(
        TsRequestFrameReader &reader) noexcept;

    // Final combined client negoTokens+pubKeyAuth -> GSS-protected
    // server pubKeyAuth on the same pinned TLS. No caller-supplied
    // ciphertext or claimed GSS identity may reach the writer.
    // False is terminal for all three objects. True queues but DOES
    // NOT send a TLS record, authenticate OS identity or admit MCS.
    [[nodiscard]] bool processFinalFramedNegoAndQueueBindingReply(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer) noexcept;

    // One-shot protected-credential boundary, ONLY after the GSS-bound
    // server response. Parses raw DER, GSS-unwraps with confidentiality,
    // examines structure without exposing secrets, securely erases the
    // provider's plaintext, and ALWAYS closes/rejects. There is no
    // credential delegation authorization or console-session policy yet.
    // There is deliberately no success/authorization return value.
    void consumeAndDenyDelegatedCredentials(
        std::span<const std::uint8_t> protectedRequestDer) noexcept;

    [[nodiscard]] SpnegoStage stage() const noexcept { return stage_; }
    // Non-sensitive GSS numeric status for diagnostics; no token, keytab
    // contents or identity string is returned or written to a log.
    [[nodiscard]] GssConfigurationDiagnostics configurationDiagnostics()
        const noexcept { return configDiagnostics_; }
    [[nodiscard]] std::string_view verifiedPrincipal() const noexcept
    {
        return (stage_ == SpnegoStage::MechanismVerified ||
                stage_ == SpnegoStage::ServerBindingPrepared)
                   ? std::string_view(principal_) : std::string_view{};
    }
    void reject() noexcept;

private:
    // Shared protected-binding implementation; combinedFinal permits the
    // one final GSS token ONLY after the one-shot framed GSS completion.
    [[nodiscard]] CredSspProtectedReply processVerifiedBinding(
        const SSL *activeServerTls,
        const TsRequestResult &request,
        bool combinedFinal) noexcept;
    [[nodiscard]] bool queueFramedProtectedReply(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        bool combinedFinal) noexcept;
    void deleteContext() noexcept;
    [[nodiscard]] bool keepAuthenticatedPrincipal(gss_name_t name) noexcept;
    // A caller may replace the frame reader while retaining the SAME SSL*.
    // Pin the selected server X.509 independently for this GSS transcript.
    [[nodiscard]] bool matchesNegotiatedCertificate(
        const SSL *serverTls) const noexcept;

    SpnegoStage stage_{SpnegoStage::Unconfigured};
    // Borrowed from the one TLS-bound framing owner, never owning SSL.
    const SSL *negotiatedServerTls_{};
    CredSspTlsCertificateFingerprint negotiatedCertificate_{};
    bool hasNegotiatedCertificate_{};
    std::uint32_t negotiatedVersion_{};
    gss_cred_id_t credentials_{GSS_C_NO_CREDENTIAL};
    gss_ctx_id_t context_{GSS_C_NO_CONTEXT};
    std::string principal_{};
    std::uint32_t rounds_{};
    GssConfigurationDiagnostics configDiagnostics_{};
};

} // namespace rdp_server::server::security
