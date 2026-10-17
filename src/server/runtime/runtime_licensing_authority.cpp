// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_licensing_authority.h"
#include "runtime_licensing_authority_internal.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace rdp_server::server::runtime
{
namespace
{
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderBeginStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderCompletionStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderCompletionView;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderVerificationStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderVerificationView;
using rdp_server::server::transport::RdpServerLicenseGrantKind;

constexpr std::array<std::uint8_t, 40U> kAuthorityFingerprintDomain{
    'r','d','p','-','s','e','r','v','e','r','/',
    'l','i','c','e','n','s','i','n','g','-','a','u','t','h','o','r','i','t','y',
    '/','v','1','/','p','o','l','i','c','y'};
constexpr std::array<std::uint8_t, 39U> kGrantDigestDomain{
    'r','d','p','-','s','e','r','v','e','r','/',
    'l','i','c','e','n','s','i','n','g','-','a','u','t','h','o','r','i','t','y',
    '/','v','1','/','g','r','a','n','t'};

struct DigestContextDeleter
{
    void operator()(EVP_MD_CTX *context) const noexcept
    {
        ::EVP_MD_CTX_free(context);
    }
};

using OwnedDigestContext =
    std::unique_ptr<EVP_MD_CTX, DigestContextDeleter>;

[[nodiscard]] bool updateDigest(
    EVP_MD_CTX *context,
    std::span<const std::uint8_t> bytes) noexcept
{
    return context != nullptr &&
           (bytes.empty() ||
            ::EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1);
}

[[nodiscard]] bool updateBe32(
    EVP_MD_CTX *context, std::uint32_t value) noexcept
{
    const std::array<std::uint8_t, 4U> encoded{
        static_cast<std::uint8_t>((value >> 24U) & 0xffU),
        static_cast<std::uint8_t>((value >> 16U) & 0xffU),
        static_cast<std::uint8_t>((value >> 8U) & 0xffU),
        static_cast<std::uint8_t>(value & 0xffU)};
    return updateDigest(context, encoded);
}

[[nodiscard]] bool updateLengthPrefixed(
    EVP_MD_CTX *context,
    std::span<const std::uint8_t> bytes) noexcept
{
    if (bytes.size() >
        static_cast<std::size_t>(
            (std::numeric_limits<std::uint32_t>::max)()))
    {
        return false;
    }
    return updateBe32(context, static_cast<std::uint32_t>(bytes.size())) &&
           updateDigest(context, bytes);
}

[[nodiscard]] bool finishSha256(
    OwnedDigestContext &context,
    std::span<std::uint8_t, 32U> digest) noexcept
{
    unsigned int digestLength = 0U;
    return context &&
           ::EVP_DigestFinal_ex(
               context.get(), digest.data(), &digestLength) == 1 &&
           digestLength == digest.size();
}

[[nodiscard]] bool allZero(
    std::span<const std::uint8_t> bytes) noexcept
{
    std::uint8_t combined = 0U;
    for (const std::uint8_t byte : bytes)
        combined = static_cast<std::uint8_t>(combined | byte);
    return combined == 0U;
}

[[nodiscard]] bool validVerification(
    const RuntimeLicensingProviderVerificationView &verification) noexcept
{
    return verification.status ==
               RuntimeLicensingProviderVerificationStatus::Verified &&
           !verification.providerIdentity.empty() &&
           verification.providerIdentity.size() <=
               kMaximumRuntimeLicensingIssuerIdentityBytes &&
           !verification.trustConfiguration.empty() &&
           verification.trustConfiguration.size() <=
               kMaximumRuntimeLicensingTrustConfigurationBytes;
}

[[nodiscard]] bool validRequestCorrelation(
    std::span<const std::uint8_t> requestCorrelation) noexcept
{
    return requestCorrelation.size() ==
               kRuntimeLicensingAuthorityRequestCorrelationBytes &&
           !allZero(requestCorrelation);
}

} // namespace

RuntimeLicensingAuthority::~RuntimeLicensingAuthority()
{
    revoke();
}

bool RuntimeLicensingAuthority::capturePolicy(
    const rdp_server::server::transport::RdpServerLicenseIdentity
        &licensingIdentity) noexcept
{
    if (!licensingIdentity.configured())
        return false;

    const auto companyName = licensingIdentity.companyNameUtf16();
    const auto productId = licensingIdentity.productIdUtf16();
    const auto scope = licensingIdentity.scopeAnsi();
    if (licensingIdentity.productVersion() == 0U ||
        companyName.empty() || productId.empty() || scope.empty() ||
        companyName.size() > companyNameUtf16_.size() ||
        productId.size() > productIdUtf16_.size() ||
        scope.size() > scopeAnsi_.size())
    {
        return false;
    }

    productVersion_ = licensingIdentity.productVersion();
    companyNameUtf16Length_ = companyName.size();
    productIdUtf16Length_ = productId.size();
    scopeAnsiLength_ = scope.size();
    std::copy(companyName.begin(), companyName.end(),
              companyNameUtf16_.begin());
    std::copy(productId.begin(), productId.end(), productIdUtf16_.begin());
    std::copy(scope.begin(), scope.end(), scopeAnsi_.begin());
    return true;
}

bool RuntimeLicensingAuthority::configureUnavailable(
    const rdp_server::server::transport::RdpServerLicenseIdentity
        &licensingIdentity) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;
    if (!capturePolicy(licensingIdentity))
    {
        state_ = RuntimeLicensingAuthorityState::Revoked;
        return false;
    }

    configured_ = true;
    state_ = RuntimeLicensingAuthorityState::NoVerifiedIssuer;
    return true;
}

bool RuntimeLicensingAuthority::configureVerifiedProvider(
    const rdp_server::server::transport::RdpServerLicenseIdentity
        &licensingIdentity,
    std::unique_ptr<detail::RuntimeLicensingAuthorityProvider>
        provider) noexcept
{
    if (attempted_)
    {
        if (provider)
            provider->close();
        return false;
    }
    attempted_ = true;
    provider_ = std::move(provider);
    if (!provider_ || !capturePolicy(licensingIdentity))
    {
        failClosed();
        return false;
    }

    if (!refreshProviderAuthentication() ||
        !generateAuthorityGeneration())
    {
        failClosed();
        return false;
    }

    configured_ = true;
    state_ = RuntimeLicensingAuthorityState::VerifiedIssuerReady;
    return true;
}

bool RuntimeLicensingAuthority::computeAuthorityFingerprint(
    std::span<const std::uint8_t> providerIdentity,
    std::span<const std::uint8_t> trustConfiguration,
    std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
        &fingerprint) const noexcept
{
    if (providerIdentity.empty() ||
        providerIdentity.size() >
            kMaximumRuntimeLicensingIssuerIdentityBytes ||
        trustConfiguration.empty() ||
        trustConfiguration.size() >
            kMaximumRuntimeLicensingTrustConfigurationBytes)
    {
        return false;
    }

    OwnedDigestContext context{::EVP_MD_CTX_new()};
    if (!context ||
        ::EVP_DigestInit_ex(context.get(), ::EVP_sha256(), nullptr) != 1 ||
        !updateDigest(context.get(), kAuthorityFingerprintDomain) ||
        !updateLengthPrefixed(context.get(), providerIdentity) ||
        !updateLengthPrefixed(context.get(), trustConfiguration) ||
        !updateBe32(context.get(), productVersion_) ||
        !updateLengthPrefixed(
            context.get(),
            std::span<const std::uint8_t>{
                companyNameUtf16_.data(), companyNameUtf16Length_}) ||
        !updateLengthPrefixed(
            context.get(),
            std::span<const std::uint8_t>{
                productIdUtf16_.data(), productIdUtf16Length_}) ||
        !updateLengthPrefixed(
            context.get(),
            std::span<const std::uint8_t>{
                scopeAnsi_.data(), scopeAnsiLength_}) ||
        !finishSha256(context, fingerprint))
    {
        fingerprint.fill(0U);
        return false;
    }

    if (allZero(fingerprint))
    {
        fingerprint.fill(0U);
        return false;
    }
    return true;
}

bool RuntimeLicensingAuthority::computeGrantDigest(
    RdpServerLicenseGrantKind kind,
    std::span<const std::uint8_t> issuedCal,
    std::array<std::uint8_t, 32U> &digest) noexcept
{
    if (issuedCal.empty() ||
        issuedCal.size() >
            rdp_server::server::transport::
                kMaximumRdpServerLicenseGrantCalBytes)
    {
        return false;
    }

    const std::array<std::uint8_t, 1U> encodedKind{
        static_cast<std::uint8_t>(kind)};
    OwnedDigestContext context{::EVP_MD_CTX_new()};
    if (!context ||
        ::EVP_DigestInit_ex(context.get(), ::EVP_sha256(), nullptr) != 1 ||
        !updateDigest(context.get(), kGrantDigestDomain) ||
        !updateDigest(context.get(), encodedKind) ||
        !updateLengthPrefixed(context.get(), issuedCal) ||
        !finishSha256(context, digest))
    {
        digest.fill(0U);
        return false;
    }
    return true;
}

bool RuntimeLicensingAuthority::refreshProviderAuthentication() noexcept
{
    if (!provider_)
        return false;

    const auto verification = provider_->verification();
    if (!validVerification(verification))
        return false;

    std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
        fingerprint{};
    if (!computeAuthorityFingerprint(
            verification.providerIdentity,
            verification.trustConfiguration,
            fingerprint))
    {
        return false;
    }

    authorityFingerprint_ = fingerprint;
    return true;
}

bool RuntimeLicensingAuthority::providerAuthenticationMatchesCurrent() noexcept
{
    if (!provider_ || !currentAuthorityValid())
        return false;

    const auto verification = provider_->verification();
    if (!validVerification(verification))
        return false;

    std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
        currentFingerprint{};
    if (!computeAuthorityFingerprint(
            verification.providerIdentity,
            verification.trustConfiguration,
            currentFingerprint))
    {
        return false;
    }

    return ::CRYPTO_memcmp(
               currentFingerprint.data(),
               authorityFingerprint_.data(),
               authorityFingerprint_.size()) == 0;
}

bool RuntimeLicensingAuthority::generateAuthorityGeneration() noexcept
{
    std::array<std::uint8_t, sizeof(std::uint64_t)> randomBytes{};
    constexpr std::size_t maximumAttempts = 4U;
    for (std::size_t attempt = 0U; attempt < maximumAttempts; ++attempt)
    {
        if (::RAND_priv_bytes(
                randomBytes.data(),
                static_cast<int>(randomBytes.size())) != 1)
        {
            return false;
        }

        std::uint64_t generation = 0U;
        for (const std::uint8_t byte : randomBytes)
        {
            generation =
                (generation << 8U) | static_cast<std::uint64_t>(byte);
        }
        if (generation != 0U)
        {
            authorityGeneration_ = generation;
            ::OPENSSL_cleanse(randomBytes.data(), randomBytes.size());
            return true;
        }
    }

    ::OPENSSL_cleanse(randomBytes.data(), randomBytes.size());
    return false;
}

bool RuntimeLicensingAuthority::currentAuthorityValid() const noexcept
{
    return configured_ && provider_ &&
           state_ != RuntimeLicensingAuthorityState::Revoked &&
           authorityGeneration_ != 0U &&
           !allZero(authorityFingerprint_);
}

bool RuntimeLicensingAuthority::issuerVerified() const noexcept
{
    return currentAuthorityValid();
}

bool RuntimeLicensingAuthority::requestCorrelationMatches(
    std::span<const std::uint8_t> requestCorrelation) const noexcept
{
    return validRequestCorrelation(requestCorrelation) &&
           ::CRYPTO_memcmp(
               requestCorrelation.data(),
               requestCorrelation_.data(),
               requestCorrelation_.size()) == 0;
}

bool RuntimeLicensingAuthority::releasedCorrelationMatches(
    std::span<const std::uint8_t> requestCorrelation) const noexcept
{
    return validRequestCorrelation(requestCorrelation) &&
           ::CRYPTO_memcmp(
               requestCorrelation.data(),
               releasedRequestCorrelation_.data(),
               releasedRequestCorrelation_.size()) == 0;
}

RuntimeLicensingAuthorityOperation RuntimeLicensingAuthority::beginIssuance(
    RdpServerLicenseGrantKind kind,
    std::span<const std::uint8_t> requestCorrelation) noexcept
{
    if (!configured_)
        return RuntimeLicensingAuthorityOperation::Rejected;
    if (state_ == RuntimeLicensingAuthorityState::NoVerifiedIssuer)
        return RuntimeLicensingAuthorityOperation::Unavailable;
    if (!currentAuthorityValid())
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Rejected;
    }
    if (!validRequestCorrelation(requestCorrelation) ||
        requestPending_ ||
        state_ == RuntimeLicensingAuthorityState::IssuanceResultAvailable)
    {
        return RuntimeLicensingAuthorityOperation::Rejected;
    }
    if (kind != RdpServerLicenseGrantKind::NewLicense &&
        kind != RdpServerLicenseGrantKind::UpgradeLicense)
    {
        return RuntimeLicensingAuthorityOperation::Rejected;
    }
    if (requestSequence_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Failed;
    }
    if (!providerAuthenticationMatchesCurrent())
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Failed;
    }

    ++requestSequence_;
    if (requestSequence_ == 0U)
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Failed;
    }

    requestKind_ = kind;
    std::copy(requestCorrelation.begin(), requestCorrelation.end(),
              requestCorrelation_.begin());
    clearPendingResult();

    const detail::RuntimeLicensingProviderRequestView request{
        kind,
        requestSequence_,
        authorityGeneration_,
        authorityFingerprint_,
        requestCorrelation_,
        productVersion_,
        std::span<const std::uint8_t>{
            companyNameUtf16_.data(), companyNameUtf16Length_},
        std::span<const std::uint8_t>{
            productIdUtf16_.data(), productIdUtf16Length_},
        std::span<const std::uint8_t>{
            scopeAnsi_.data(), scopeAnsiLength_}};

    switch (provider_->begin(request))
    {
    case RuntimeLicensingProviderBeginStatus::Accepted:
        requestPending_ = true;
        state_ = RuntimeLicensingAuthorityState::VerifiedIssuerReady;
        return RuntimeLicensingAuthorityOperation::InProgress;
    case RuntimeLicensingProviderBeginStatus::Denied:
        state_ = RuntimeLicensingAuthorityState::IssuanceDenied;
        return RuntimeLicensingAuthorityOperation::Denied;
    case RuntimeLicensingProviderBeginStatus::Unavailable:
        failClosed();
        return RuntimeLicensingAuthorityOperation::Unavailable;
    case RuntimeLicensingProviderBeginStatus::Failed:
        failClosed();
        return RuntimeLicensingAuthorityOperation::Failed;
    }

    failClosed();
    return RuntimeLicensingAuthorityOperation::Failed;
}

RuntimeLicensingAuthorityOperation
RuntimeLicensingAuthority::pollIssuance() noexcept
{
    if (!requestPending_ || !currentAuthorityValid())
        return RuntimeLicensingAuthorityOperation::Rejected;

    const RuntimeLicensingProviderCompletionView completion =
        provider_->poll();

    if (completion.status ==
        RuntimeLicensingProviderCompletionStatus::Pending)
    {
        return RuntimeLicensingAuthorityOperation::InProgress;
    }

    if (completion.status ==
        RuntimeLicensingProviderCompletionStatus::Denied)
    {
        requestPending_ = false;
        clearPendingResult();
        state_ = RuntimeLicensingAuthorityState::IssuanceDenied;
        return RuntimeLicensingAuthorityOperation::Denied;
    }
    if (completion.status ==
        RuntimeLicensingProviderCompletionStatus::Cancelled)
    {
        requestPending_ = false;
        clearPendingResult();
        state_ = RuntimeLicensingAuthorityState::IssuanceDenied;
        return RuntimeLicensingAuthorityOperation::Cancelled;
    }
    if (completion.status ==
        RuntimeLicensingProviderCompletionStatus::TimedOut)
    {
        requestPending_ = false;
        clearPendingResult();
        state_ = RuntimeLicensingAuthorityState::IssuanceDenied;
        return RuntimeLicensingAuthorityOperation::TimedOut;
    }
    if (completion.status ==
            RuntimeLicensingProviderCompletionStatus::Unavailable ||
        completion.status ==
            RuntimeLicensingProviderCompletionStatus::Failed)
    {
        failClosed();
        return completion.status ==
                   RuntimeLicensingProviderCompletionStatus::Unavailable
            ? RuntimeLicensingAuthorityOperation::Unavailable
            : RuntimeLicensingAuthorityOperation::Failed;
    }
    if (completion.status !=
        RuntimeLicensingProviderCompletionStatus::Issued)
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Rejected;
    }

    if (completion.requestSequence != requestSequence_ ||
        completion.kind != requestKind_ ||
        !requestCorrelationMatches(completion.requestCorrelation) ||
        completion.issuedCal.empty() ||
        completion.issuedCal.size() >
            rdp_server::server::transport::
                kMaximumRdpServerLicenseGrantCalBytes)
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Rejected;
    }

    std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
        completionFingerprint{};
    if (!computeAuthorityFingerprint(
            completion.providerIdentity,
            completion.trustConfiguration,
            completionFingerprint) ||
        ::CRYPTO_memcmp(
            completionFingerprint.data(),
            authorityFingerprint_.data(),
            authorityFingerprint_.size()) != 0)
    {
        failClosed();
        return RuntimeLicensingAuthorityOperation::Rejected;
    }

    std::copy(completion.issuedCal.begin(), completion.issuedCal.end(),
              issuedCal_.begin());
    issuedCalLength_ = completion.issuedCal.size();
    requestPending_ = false;
    resultReleased_ = false;
    state_ = RuntimeLicensingAuthorityState::IssuanceResultAvailable;
    return RuntimeLicensingAuthorityOperation::Issued;
}

RuntimeLicensingAuthorityOperation
RuntimeLicensingAuthority::cancelIssuance() noexcept
{
    if (!requestPending_ || !provider_ ||
        state_ == RuntimeLicensingAuthorityState::Revoked)
    {
        return RuntimeLicensingAuthorityOperation::Rejected;
    }

    provider_->cancel();
    requestPending_ = false;
    clearPendingResult();
    state_ = RuntimeLicensingAuthorityState::IssuanceDenied;
    return RuntimeLicensingAuthorityOperation::Cancelled;
}

bool RuntimeLicensingAuthority::releaseIssuedGrant(
    std::span<const std::uint8_t> requestCorrelation,
    rdp_server::server::transport::RdpLicensingAuthorityGrant
        &grant) noexcept
{
    const bool authenticationCurrent =
        providerAuthenticationMatchesCurrent();
    if (state_ != RuntimeLicensingAuthorityState::IssuanceResultAvailable ||
        requestPending_ || resultReleased_ ||
        issuedCalLength_ == 0U ||
        !requestCorrelationMatches(requestCorrelation) ||
        !authenticationCurrent)
    {
        if (currentAuthorityValid() &&
            state_ == RuntimeLicensingAuthorityState::IssuanceResultAvailable &&
            !authenticationCurrent)
        {
            failClosed();
        }
        return false;
    }

    std::array<std::uint8_t, 32U> grantDigest{};
    const auto issuedCal = std::span<const std::uint8_t>{
        issuedCal_.data(), issuedCalLength_};
    if (!computeGrantDigest(requestKind_, issuedCal, grantDigest))
    {
        failClosed();
        return false;
    }

    const auto configureResult = grant.configure(
        requestKind_,
        authorityGeneration_,
        authorityFingerprint_,
        issuedCal);
    if (configureResult !=
        rdp_server::server::transport::
            RdpLicensingAuthorityGrantError::None)
    {
        return false;
    }

    releasedGrantDigest_ = grantDigest;
    releasedKind_ = requestKind_;
    releasedRequestCorrelation_ = requestCorrelation_;
    resultReleased_ = true;
    clearPendingResult();
    return true;
}

bool RuntimeLicensingAuthority::authorizeReleasedGrant(
    std::span<const std::uint8_t> requestCorrelation,
    const rdp_server::server::transport::RdpLicensingAuthorityGrant
        &grant) noexcept
{
    const bool authenticationCurrent =
        providerAuthenticationMatchesCurrent();
    if (state_ != RuntimeLicensingAuthorityState::IssuanceResultAvailable ||
        !resultReleased_ ||
        !releasedCorrelationMatches(requestCorrelation) ||
        !grant.configured() ||
        grant.kind() != releasedKind_ ||
        !grant.matchesAuthority(
            authorityGeneration_, authorityFingerprint_) ||
        !authenticationCurrent)
    {
        if (resultReleased_ && currentAuthorityValid() &&
            !authenticationCurrent)
        {
            failClosed();
        }
        return false;
    }

    std::array<std::uint8_t, 32U> grantDigest{};
    if (!computeGrantDigest(grant.kind(), grant.issuedCal(), grantDigest))
        return false;

    return ::CRYPTO_memcmp(
               grantDigest.data(),
               releasedGrantDigest_.data(),
               releasedGrantDigest_.size()) == 0;
}

bool RuntimeLicensingAuthority::retireReleasedGrant(
    std::span<const std::uint8_t> requestCorrelation) noexcept
{
    if (state_ != RuntimeLicensingAuthorityState::IssuanceResultAvailable ||
        !resultReleased_ ||
        !releasedCorrelationMatches(requestCorrelation))
    {
        return false;
    }

    clearReleasedGrant();
    requestCorrelation_.fill(0U);
    state_ = RuntimeLicensingAuthorityState::VerifiedIssuerReady;
    return true;
}

void RuntimeLicensingAuthority::clearPendingResult() noexcept
{
    if (issuedCalLength_ != 0U)
        ::OPENSSL_cleanse(issuedCal_.data(), issuedCalLength_);
    issuedCalLength_ = 0U;
}

void RuntimeLicensingAuthority::clearReleasedGrant() noexcept
{
    releasedGrantDigest_.fill(0U);
    releasedRequestCorrelation_.fill(0U);
    resultReleased_ = false;
}

void RuntimeLicensingAuthority::closeProvider() noexcept
{
    if (!provider_)
        return;
    provider_->close();
    provider_.reset();
}

void RuntimeLicensingAuthority::failClosed() noexcept
{
    if (requestPending_ && provider_)
        provider_->cancel();
    requestPending_ = false;
    clearPendingResult();
    clearReleasedGrant();
    closeProvider();
    authorityFingerprint_.fill(0U);
    authorityGeneration_ = 0U;
    requestCorrelation_.fill(0U);
    state_ = RuntimeLicensingAuthorityState::Revoked;
}

void RuntimeLicensingAuthority::revoke() noexcept
{
    if (state_ == RuntimeLicensingAuthorityState::Revoked &&
        !provider_)
    {
        return;
    }
    failClosed();
}

} // namespace rdp_server::server::runtime
