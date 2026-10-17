// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_spnego_acceptor.h"

#include <gssapi/gssapi.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

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
}

void GssapiSpnegoAcceptor::consumeAndDenyDelegatedCredentials(
    std::span<const std::uint8_t> protectedRequestDer) noexcept
{
    (void)protectedRequestDer;
    reject();
}

void GssapiSpnegoAcceptor::consumeFramedAndDenyDelegatedCredentials(
    TsRequestFrameReader &reader) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    std::string_view authenticatedPrincipal;
    if (ownedCredSspConnection_ != nullptr &&
        ownedCredSspReader_ == &reader &&
        ownedCredSspWriter_ != nullptr &&
        ownedCredSspBindingVerified_ &&
        identityPolicy_ != nullptr &&
        identityPolicyGeneration_ != 0)
    {
        authenticatedPrincipal =
            verifiedPrincipalForOwnedConnection(*ownedCredSspConnection_);
    }

    if (sourceTls == nullptr ||
        stage_ != SpnegoStage::ServerBindingPrepared ||
        context_ == GSS_C_NO_CONTEXT ||
        negotiatedServerTls_ != sourceTls ||
        (negotiatedVersion_ != 5 && negotiatedVersion_ != 6) ||
        authenticatedPrincipal.empty() ||
        !matchesNegotiatedCertificate(sourceTls) ||
        identityPolicy_->generation() != identityPolicyGeneration_)
    {
        reader.close();
        reject();
        return;
    }

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
        auto bytes = std::span<std::uint8_t>(
            static_cast<std::uint8_t *>(plaintext.value), plaintext.length);
        SensitiveBytesGuard cleanse{bytes};
        if (major == GSS_S_COMPLETE && confidential != 0 &&
            bytes.size() <= kMaximumDecryptedCredentialsBytes)
        {
            const auto account = inspectCredSspDelegatedAccount(bytes);
            if (account)
            {
                const bool exactCandidate =
                    identityPolicy_->matchPrincipalAccountCandidate(
                        authenticatedPrincipal, account.accountName(),
                        identityPolicyGeneration_) ==
                    ConsolePolicyMatch::CandidateOnly;
                // CandidateOnly is intentionally not persisted. A future PAM
                // call must remain synchronous inside this plaintext lifetime.
                (void)exactCandidate;
            }
        }
    }

    (void)gss_release_buffer(&minor, &plaintext);
    reader.close();
    reject();
}

} // namespace rdp_server::server::security
