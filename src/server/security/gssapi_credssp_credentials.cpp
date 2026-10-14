// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_spnego_acceptor.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] bool permittedCredentialMessage(
    const TsRequestResult &request) noexcept
{
    return request && request.value.version >= 5 &&
           request.value.version <= 6 &&
           request.value.hasAuthInfo && !request.value.hasPubKeyAuth &&
           !request.value.hasClientNonce && !request.value.hasErrorCode &&
           request.value.tokenCount == 0 &&
           !request.value.encryptedAuthInfo.empty() &&
           request.value.encryptedAuthInfo.size() <=
               kMaximumDecryptedCredentialsBytes;
}

} // namespace

void GssapiSpnegoAcceptor::consumeAndDenyDelegatedCredentials(
    std::span<const std::uint8_t> protectedRequestDer) noexcept
{
    // The GSS security context and an active TLS server key must already
    // have completed the protected pubKeyAuth exchange. Reparse raw DER:
    // caller-constructed "valid" structs cannot bypass envelope policy.
    const auto parsed = parseCredSspTsRequest(protectedRequestDer);
    if (stage_ != SpnegoStage::ServerBindingPrepared ||
        context_ == GSS_C_NO_CONTEXT ||
        !permittedCredentialMessage(parsed))
    {
        reject();
        return;
    }

    const auto encryptedBytes = parsed.value.encryptedAuthInfo;
    gss_buffer_desc encrypted{
        encryptedBytes.size(),
        const_cast<std::uint8_t *>(encryptedBytes.data())};
    gss_buffer_desc plaintext = GSS_C_EMPTY_BUFFER;
    int confidential = 0;
    OM_uint32 minor = 0;
    const OM_uint32 major = gss_unwrap(
        &minor, context_, &encrypted, &plaintext, &confidential, nullptr);

    if (plaintext.value != nullptr && plaintext.length != 0)
    {
        // No plaintext view survives the GSS release. Even malformed or
        // oversized messages are wiped without logging their content.
        auto mutableBytes = std::span(
            static_cast<std::uint8_t *>(plaintext.value),
            plaintext.length);
        {
            SensitiveBytesGuard cleanse{mutableBytes};
            if (major == GSS_S_COMPLETE && confidential != 0 &&
                mutableBytes.size() <= kMaximumDecryptedCredentialsBytes)
            {
                // Metadata-only parser. The result never contains domain,
                // username, password or any borrowed secret bytes.
                const auto inspected =
                    inspectCredSspCredentials(mutableBytes);
                (void)inspected;
            }
        }
    }
    (void)gss_release_buffer(&minor, &plaintext);

    // No authorized PAM/session adapter or supported credential-delegation
    // policy exists yet. ALWAYS erase the GSS context and deny, even if
    // GSS authenticated a syntactically valid set of credentials.
    reject();
}

} // namespace rdp_server::server::security
