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
    return request && request.value.finalAuthInfoOnly() &&
           request.value.encryptedAuthInfo.size() <=
               kMaximumDecryptedCredentialsBytes;
}

} // namespace

void GssapiSpnegoAcceptor::consumeAndDenyDelegatedCredentials(
    std::span<const std::uint8_t> protectedRequestDer) noexcept
{
    // Caller-provided DER is not necessarily TLS-derived. Never attempt
    // GSS decryption or a credential-origin claim through this old API.
    (void)protectedRequestDer;
    reject();
}

void GssapiSpnegoAcceptor::consumeFramedAndDenyDelegatedCredentials(
    TsRequestFrameReader &reader) noexcept
{
    // The single TLS framing owner establishes transport provenance. The
    // GSS owner must ALSO recheck its entire negotiated TLS certificate
    // identity: a different reader could have been used for this frame.
    const SSL *sourceTls = reader.completedFrameServerTls();
    if (sourceTls == nullptr ||
        stage_ != SpnegoStage::ServerBindingPrepared ||
        context_ == GSS_C_NO_CONTEXT ||
        negotiatedServerTls_ != sourceTls ||
        (negotiatedVersion_ != 5 && negotiatedVersion_ != 6) ||
        verifiedPrincipal().empty() ||
        !matchesNegotiatedCertificate(sourceTls))
    {
        reader.close();
        reject();
        return;
    }

    // Reject every field combination other than the one final encrypted
    // authInfo. Never borrow caller-created DER or a detached GSS token.
    const auto parsed = parseCredSspTsRequest(reader.completeDer());
    if (!permittedCredentialMessage(parsed) ||
        parsed.value.version != negotiatedVersion_)
    {
        reader.close();
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

    // There is no OS delegate or permission capability. Erase the one
    // TLS-derived DER frame as well as all provider context before return;
    // a caller cannot reuse these ciphertext bytes with a new transcript.
    reader.close();
    reject();
}

} // namespace rdp_server::server::security
