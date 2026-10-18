// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_spnego_acceptor.h"
#include "credssp_credentials_internal.h"
#include "authentication_attempt_limiter.h"

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
#include "linux_pam_password_verifier.h"
#endif

#include <gssapi/gssapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{
namespace
{
struct DelegatedPasswordVerificationContext final
{
    const ConsoleIdentityPolicy *policy{};
    std::string_view authenticatedPrincipal{};
    std::uint64_t policyGeneration{};
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    const LinuxPamPasswordVerifier *passwordVerifier{};
    AuthenticationAttemptLimiter *attemptLimiter{};
    LinuxPamPasswordVerificationStatus passwordStatus{
        LinuxPamPasswordVerificationStatus::InvalidInput};
    std::array<char, kMaximumDelegatedUnixAccountBytes + 1U>
        authorizedAccount{};
    std::size_t authorizedAccountLength{};
#endif
    bool exactCandidate{};
};

void verifyDelegatedPasswordCandidate(
    std::string_view unixAccount,
    std::span<const std::uint8_t> passwordUtf16Le,
    void *opaqueContext) noexcept
{
    auto &context = *static_cast<DelegatedPasswordVerificationContext *>(
        opaqueContext);
    if (context.policy == nullptr)
    {
        return;
    }

    context.exactCandidate =
        context.policy->matchPrincipalAccountCandidate(
            context.authenticatedPrincipal, unixAccount,
            context.policyGeneration) == ConsolePolicyMatch::CandidateOnly;
    if (!context.exactCandidate)
    {
        return;
    }

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    if (context.passwordVerifier != nullptr)
    {
        // The delegated local account already matches R2 policy. Charge the
        // real TLS-bound GSS principal, never caller-controlled username
        // text, before PAM sees the delegated plaintext password.
        if (context.attemptLimiter != nullptr &&
            !context.attemptLimiter->reserveVerifiedAccountAttempt(
                context.authenticatedPrincipal,
                AuthenticationAttemptLimiter::Clock::now()))
            return;

        // PAM is invoked only while passwordUtf16Le still borrows the live,
        // GSS-unwrapped plaintext guarded by SensitiveBytesGuard. Persist only
        // the already-validated account when PAM authorizes; never password
        // bytes, a provider handle or a caller-supplied success flag.
        context.passwordStatus = context.passwordVerifier->verify(
            unixAccount, passwordUtf16Le);
        if (context.passwordStatus ==
                LinuxPamPasswordVerificationStatus::Authorized &&
            unixAccount.size() < context.authorizedAccount.size())
        {
            std::copy(
                unixAccount.begin(), unixAccount.end(),
                context.authorizedAccount.begin());
            context.authorizedAccountLength = unixAccount.size();
        }
    }
#else
    (void)passwordUtf16Le;
#endif
}

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

bool GssapiSpnegoAcceptor::consumeFramedDelegatedCredentialsForAuthorization(
    TsRequestFrameReader &reader) noexcept
{
    clearPendingCredentialAuthorization();

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
        return false;
    }

    const auto parsed = parseCredSspTsRequest(reader.completeDer());
    if (!permittedCredentialMessage(parsed) ||
        parsed.value.version != negotiatedVersion_)
    {
        reader.close();
        reject();
        return false;
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

    bool authorizationPending = false;
    if (plaintext.value != nullptr && plaintext.length != 0)
    {
        auto bytes = std::span<std::uint8_t>(
            static_cast<std::uint8_t *>(plaintext.value), plaintext.length);
        SensitiveBytesGuard cleanse{bytes};
        if (major == GSS_S_COMPLETE && confidential != 0 &&
            bytes.size() <= kMaximumDecryptedCredentialsBytes)
        {
            DelegatedPasswordVerificationContext verification;
            verification.policy = identityPolicy_;
            verification.authenticatedPrincipal = authenticatedPrincipal;
            verification.policyGeneration = identityPolicyGeneration_;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
            verification.passwordVerifier = passwordVerifier_;
            verification.attemptLimiter = verifiedAccountAttemptLimiter_;
#endif
            const auto visitStatus = visitCredSspPasswordCredential(
                bytes, &verifyDelegatedPasswordCandidate, &verification);
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
            const bool providerAuthorized =
                visitStatus == CredSspPasswordFieldVisitStatus::Visited &&
                verification.exactCandidate &&
                verification.passwordStatus ==
                    LinuxPamPasswordVerificationStatus::Authorized &&
                verification.authorizedAccountLength != 0 &&
                identityPolicy_->generation() == identityPolicyGeneration_ &&
                verifiedPrincipalForOwnedConnection(
                    *ownedCredSspConnection_) == authenticatedPrincipal &&
                matchesNegotiatedCertificate(sourceTls);
            if (providerAuthorized)
            {
                std::copy_n(
                    verification.authorizedAccount.begin(),
                    verification.authorizedAccountLength,
                    ownedCredSspAuthorizedAccount_.begin());
                ownedCredSspAuthorizedAccountLength_ =
                    verification.authorizedAccountLength;
                ownedCredSspCredentialAuthorizationPending_ = true;
                authorizationPending = true;
            }
#else
            (void)visitStatus;
            (void)verification.exactCandidate;
#endif
        }
    }

    (void)gss_release_buffer(&minor, &plaintext);
    reader.close();
    if (!authorizationPending)
    {
        reject();
        return false;
    }
    return true;
}

void GssapiSpnegoAcceptor::consumeFramedAndDenyDelegatedCredentials(
    TsRequestFrameReader &reader) noexcept
{
    (void)consumeFramedDelegatedCredentialsForAuthorization(reader);
    reject();
}

} // namespace rdp_server::server::security
