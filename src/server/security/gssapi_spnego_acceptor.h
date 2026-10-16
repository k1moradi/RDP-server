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
    // A real GSS provider rejected a version-6 TLS-bound token;
    // the 15-byte terminal failure was QUEUED (not written). No
    // authentication, session admission or further GSS retry.
    FailureQueued,
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
    // Only the internal gss_accept_sec_context call can set this;
    // malformed/caller-supplied DER, missing configured credentials,
    // TLS identity mismatch and local buffer failures cannot trigger
    // a server errorCode. No caller may use this to claim identity.
    bool providerRejected{};
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

// One bounded event-loop step for the production R1-owned CredSSP/GSS path.
// BindingVerified means the Kerberos mechanism and CredSSP public-key proof
// completed on the exact TLS transcript and its server reply was fully sent.
// The required final authInfo step has NOT completed at that point.
// UnsupportedFinalCredentials means the same owner subsequently delivered a
// structurally valid, bounded final authInfo to the existing deny-only
// credential processor. Any provider plaintext is securely wiped before R2
// terminates. Neither outcome is native authorization or an R3 capability.
enum class OwnedCredSspHandshakeStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    BindingVerified,
    UnsupportedFinalCredentials,
    Rejected,
    TransportClosed,
};

struct OwnedCredSspHandshakeResult
{
    OwnedCredSspHandshakeStatus status{
        OwnedCredSspHandshakeStatus::Rejected};
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
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
    // Protocol/identity rejections permanently close all three objects.
    // ONLY a real backend GSS rejection on a valid, pinned TLS
    // version-6 negotiation frame may return FailureQueued: the
    // provider is already terminal; the writer owns a canonical
    // STATUS_LOGON_FAILURE TSRequest until the caller explicitly
    // flushes/releases it. No auto-write or authenticated success.
    // Version 5, missing keytab, wrong TLS/certificate, malformed DER,
    // local errors and an unexpected complete SPNEGO exchange remain
    // silent terminal rejection, without an error record.
    [[nodiscard]] SpnegoStatus acceptFramedNegoAndQueueReply(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer) noexcept;

    // Production R2 event-loop boundary. The exact R1 owner supplies both
    // immutable HYBRID negotiation provenance and all TLS application I/O.
    // Each call performs at most one bounded R1 application read OR write;
    // GSS/DER processing and queue/release bookkeeping may complete in the
    // same call but never advance OpenSSL directly. The same connection,
    // reader and writer must outlive the exchange and remain unchanged.
    //
    // No CredSSP bytes are consumed or emitted unless the client offered
    // PROTOCOL_HYBRID and R1 actually selected PROTOCOL_HYBRID.
    // BindingVerified proves only the TLS-bound GSS/public-key handshake.
    // A later call consumes the final authInfo on this same owner. The current
    // delegated-credential policy is deny-only, so a bounded final credential
    // step returns UnsupportedFinalCredentials and terminally revokes R2.
    // Native authorization and R3 admission remain separate.
    [[nodiscard]] OwnedCredSspHandshakeResult advanceOwnedCredSspHandshake(
        transport::OwnedPreauthTcpConnection &connection,
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

    // The ONLY credential-decryption entry point. Requires a complete
    // TSRequest received over the SAME pinned server TLS and X.509 as
    // the genuine GSS/CredSSP public-key exchange, in version 5 or 6.
    // GSS-unwraps the protected authInfo synchronously, inspects bounded
    // credential structure without exporting secrets, securely erases
    // GSS plaintext and terminally closes both reader and provider.
    // Even a genuine decrypted credential is NEVER OS/session admission:
    // no audited delegated-credential authorization exists yet.
    void consumeFramedAndDenyDelegatedCredentials(
        TsRequestFrameReader &reader) noexcept;

    // Legacy raw-DER interface has no TLS provenance. It MUST NOT
    // GSS-decrypt caller-supplied bytes, regardless of provider state.
    // Retained only as terminal deny-only compatibility, never handoff.
    void consumeAndDenyDelegatedCredentials(
        std::span<const std::uint8_t> protectedRequestDer) noexcept;

    [[nodiscard]] SpnegoStage stage() const noexcept { return stage_; }
    // Non-sensitive GSS numeric status for diagnostics; no token, keytab
    // contents or identity string is returned or written to a log.
    [[nodiscard]] GssConfigurationDiagnostics configurationDiagnostics()
        const noexcept { return configDiagnostics_; }
    // Provider-derived GSS name, borrowed only after successful CredSSP
    // public-key proof on the pinned ACTIVE TLS certificate. A completed
    // Kerberos mechanism alone cannot supply an OS identity candidate.
    // The caller must keep this acceptor and its borrowed SSL alive.
    // This is still NOT OS authorization or an RDP admission capability.
    [[nodiscard]] std::string_view verifiedPrincipal() const noexcept
    {
        if (stage_ != SpnegoStage::ServerBindingPrepared ||
            context_ == GSS_C_NO_CONTEXT || principal_.empty() ||
            (negotiatedVersion_ != 5 && negotiatedVersion_ != 6) ||
            !matchesNegotiatedCertificate(negotiatedServerTls_))
            return {};
        return std::string_view(principal_);
    }

    // Same provider-derived identity, additionally requiring the exact
    // active server TLS object pinned by this GSS/CredSSP transcript.
    // verifiedPrincipal() rechecks selected-certificate continuity.
    [[nodiscard]] std::string_view verifiedPrincipalForTls(
        const SSL *activeServerTls) const noexcept
    {
        if (activeServerTls == nullptr ||
            activeServerTls != negotiatedServerTls_)
        {
            return {};
        }
        return verifiedPrincipal();
    }

    // Binding-level identity observation additionally requires that the
    // server binding reply completed through this exact live R1 owner.
    // It remains diagnostic evidence only; native admission has a stricter,
    // private R2 completion requirement.
    [[nodiscard]] std::string_view verifiedPrincipalForOwnedConnection(
        const transport::OwnedPreauthTcpConnection &connection) const noexcept;

    void reject() noexcept;

private:
    friend class LinuxConsoleAdmissionBroker;

    // Native admission must not be derived from the public binding-level
    // identity observations above. These private borrows are nonempty only
    // after an R2-owned final-credential authorization policy completes.
    // The current deny-only policy never sets that completion state.
    [[nodiscard]] std::string_view nativeAdmissionPrincipalForTls(
        const SSL *activeServerTls) const noexcept;
    [[nodiscard]] std::string_view nativeAdmissionPrincipalForOwnedConnection(
        const transport::OwnedPreauthTcpConnection &connection) const noexcept;

    // Shared protected-binding implementation; combinedFinal permits the
    // one final GSS token ONLY after the one-shot framed GSS completion.
    [[nodiscard]] CredSspProtectedReply processVerifiedBinding(
        const SSL *activeServerTls,
        const TsRequestResult &request,
        bool combinedFinal) noexcept;
    [[nodiscard]] SpnegoStatus acceptFramedNegoAndQueueReplyImpl(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        const transport::OwnedPreauthTcpConnection *connection) noexcept;
    [[nodiscard]] bool queueFramedProtectedReply(
        TsRequestFrameReader &reader,
        TsRequestTlsReplyWriter &writer,
        bool combinedFinal,
        const transport::OwnedPreauthTcpConnection *connection) noexcept;
    void deleteContext() noexcept;
    [[nodiscard]] bool keepAuthenticatedPrincipal(gss_name_t name) noexcept;
    // A caller may replace the frame reader while retaining the SAME SSL*.
    // Pin the selected server X.509 independently for this GSS transcript.
    [[nodiscard]] bool matchesNegotiatedCertificate(
        const SSL *serverTls) const noexcept;

    // Borrowed only while advanceOwnedCredSspHandshake is active. These
    // pointers fence object/owner substitution; no object is owned here.
    const transport::OwnedPreauthTcpConnection *ownedCredSspConnection_{};
    TsRequestFrameReader *ownedCredSspReader_{};
    TsRequestTlsReplyWriter *ownedCredSspWriter_{};
    bool ownedCredSspReplyPending_{};
    bool ownedCredSspBindingVerified_{};
    // Deliberately false until a future reviewed policy positively authorizes
    // the final CredSSP credential step. No caller-facing setter exists.
    bool ownedCredSspCredentialAuthorizationComplete_{};

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
