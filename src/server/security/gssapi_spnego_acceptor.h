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

    // Once SPNEGO/Kerberos completes, require a DER TSRequest holding
    // EXACTLY a v5/v6 pubKeyAuth + 32-byte clientNonce (no authInfo).
    // gss_unwrap MUST verify integrity and confidentiality *before* any
    // comparison with the active TLS selected certificate. The server hash
    // MUST then be sealed with gss_wrap(conf_req_flag=1). One-shot: success
    // enters ServerBindingPrepared; all failures permanently reject.
    //
    // Neither state grants a user account, MCS domain or desktop access.
    [[nodiscard]] CredSspProtectedReply processProtectedBinding(
        const SSL *activeServerTls,
        std::span<const std::uint8_t> protectedRequestDer) noexcept;

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
    void deleteContext() noexcept;
    [[nodiscard]] bool keepAuthenticatedPrincipal(gss_name_t name) noexcept;

    SpnegoStage stage_{SpnegoStage::Unconfigured};
    gss_cred_id_t credentials_{GSS_C_NO_CREDENTIAL};
    gss_ctx_id_t context_{GSS_C_NO_CONTEXT};
    std::string principal_{};
    std::uint32_t rounds_{};
    GssConfigurationDiagnostics configDiagnostics_{};
};

} // namespace rdp_server::server::security
