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
    RuntimeLicensingExistingCalProviderCompletionStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingExistingCalProviderCompletionView;
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
constexpr std::array<std::uint8_t, 46U> kExistingCalRequestDigestDomain{
    'r','d','p','-','s','e','r','v','e','r','/',
    'l','i','c','e','n','s','i','n','g','-','a','u','t','h','o','r','i','t','y',
    '/','v','1','/','e','x','i','s','t','i','n','g','-','c','a','l'};

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

[[nodiscard]] bool updateBe64(
    EVP_MD_CTX *context, std::uint64_t value) noexcept
{
    const std::array<std::uint8_t, 8U> encoded{
        static_cast<std::uint8_t>((value >> 56U) & 0xffU),
        static_cast<std::uint8_t>((value >> 48U) & 0xffU),
        static_cast<std::uint8_t>((value >> 40U) & 0xffU),
        static_cast<std::uint8_t>((value >> 32U) & 0xffU),
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

[[nodiscard]] bool validExistingCalDecision(
    RuntimeLicensingExistingCalDecision decision) noexcept
{
    switch (decision)
    {
    case RuntimeLicensingExistingCalDecision::Denied:
    case RuntimeLicensingExistingCalDecision::ValidPermanentNoUpgrade:
    case RuntimeLicensingExistingCalDecision::UpgradeRequired:
        return true;
    }
    return false;
}

} // namespace

bool RuntimeLicensingExistingCalValidationResult::configure(
    RuntimeLicensingExistingCalDecision decision,
    std::uint64_t authorityGeneration,
    std::span<const std::uint8_t> authorityFingerprint,
    std::span<const std::uint8_t> requestDigest) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;

    if (!validExistingCalDecision(decision) ||
        authorityGeneration == 0U ||
        authorityFingerprint.size() != authorityFingerprint_.size() ||
        requestDigest.size() != requestDigest_.size() ||
        allZero(authorityFingerprint) ||
        allZero(requestDigest))
    {
        return false;
    }

    decision_ = decision;
    authorityGeneration_ = authorityGeneration;
    std::copy(
        authorityFingerprint.begin(),
        authorityFingerprint.end(),
        authorityFingerprint_.begin());
    std::copy(
        requestDigest.begin(),
        requestDigest.end(),
        requestDigest_.begin());
    configured_ = true;
    return true;
}

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

bool RuntimeLicensingAuthority::computeExistingCalRequestDigest(
    std::span<const std::uint8_t> presentedCal,
    std::span<const std::uint8_t> protectedHardwareId,
    std::int64_t verificationUnixSeconds,
    std::span<const std::uint8_t> requestCorrelation,
    std::array<std::uint8_t, 32U> &digest) const noexcept
{
    if (requestSequence_ == 0U ||
        authorityGeneration_ == 0U ||
        allZero(authorityFingerprint_) ||
        presentedCal.empty() ||
        presentedCal.size() >
            rdp_server::server::transport::kMaximumRdpClientCalBytes ||
        protectedHardwareId.size() !=
            rdp_server::server::transport::kRdpLicensingHardwareIdBytes ||
        !validRequestCorrelation(requestCorrelation))
    {
        return false;
    }

    OwnedDigestContext context{::EVP_MD_CTX_new()};
    if (!context ||
        ::EVP_DigestInit_ex(context.get(), ::EVP_sha256(), nullptr) != 1 ||
        !updateDigest(context.get(), kExistingCalRequestDigestDomain) ||
        !updateBe64(context.get(), requestSequence_) ||
        !updateBe64(context.get(), authorityGeneration_) ||
        !updateLengthPrefixed(context.get(), authorityFingerprint_) ||
        !updateLengthPrefixed(context.get(), requestCorrelation) ||
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
        !updateBe64(
            context.get(),
            static_cast<std::uint64_t>(verificationUnixSeconds)) ||
        !updateLengthPrefixed(context.get(), protectedHardwareId) ||
        !updateLengthPrefixed(context.get(), presentedCal) ||
        !finishSha256(context, digest))
    {
        digest.fill(0U);
        return false;
    }

    if (allZero(digest))
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
        existingCalValidationPending_ ||
        state_ == RuntimeLicensingAuthorityState::IssuanceResultAvailable ||
        state_ ==
            RuntimeLicensingAuthorityState::
                ExistingCalValidationResultAvailable)
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

RuntimeLicensingExistingCalOperation
RuntimeLicensingAuthority::beginExistingCalValidation(
    std::span<const std::uint8_t> presentedCal,
    std::span<const std::uint8_t> protectedHardwareId,
    std::int64_t verificationUnixSeconds,
    std::span<const std::uint8_t> requestCorrelation) noexcept
{
    if (!configured_)
        return RuntimeLicensingExistingCalOperation::Rejected;
    if (state_ == RuntimeLicensingAuthorityState::NoVerifiedIssuer)
        return RuntimeLicensingExistingCalOperation::Unavailable;
    if (!currentAuthorityValid())
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Rejected;
    }
    if (presentedCal.empty() ||
        presentedCal.size() >
            rdp_server::server::transport::kMaximumRdpClientCalBytes ||
        protectedHardwareId.size() !=
            rdp_server::server::transport::kRdpLicensingHardwareIdBytes ||
        !validRequestCorrelation(requestCorrelation) ||
        requestPending_ ||
        existingCalValidationPending_ ||
        state_ == RuntimeLicensingAuthorityState::IssuanceResultAvailable ||
        state_ ==
            RuntimeLicensingAuthorityState::
                ExistingCalValidationResultAvailable)
    {
        return RuntimeLicensingExistingCalOperation::Rejected;
    }
    if (requestSequence_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Failed;
    }
    if (!providerAuthenticationMatchesCurrent())
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Failed;
    }

    ++requestSequence_;
    if (requestSequence_ == 0U)
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Failed;
    }

    std::copy(
        requestCorrelation.begin(),
        requestCorrelation.end(),
        requestCorrelation_.begin());
    std::copy(
        presentedCal.begin(), presentedCal.end(), existingCal_.begin());
    existingCalLength_ = presentedCal.size();
    std::copy(
        protectedHardwareId.begin(),
        protectedHardwareId.end(),
        existingCalHardwareId_.begin());
    existingCalVerificationUnixSeconds_ = verificationUnixSeconds;
    existingCalDecision_ = RuntimeLicensingExistingCalDecision::Denied;
    existingCalRequestDigest_.fill(0U);

    if (!computeExistingCalRequestDigest(
            std::span<const std::uint8_t>{
                existingCal_.data(), existingCalLength_},
            existingCalHardwareId_,
            existingCalVerificationUnixSeconds_,
            requestCorrelation_,
            existingCalRequestDigest_))
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Failed;
    }

    const detail::RuntimeLicensingExistingCalProviderRequestView request{
        requestSequence_,
        authorityGeneration_,
        authorityFingerprint_,
        requestCorrelation_,
        existingCalRequestDigest_,
        productVersion_,
        std::span<const std::uint8_t>{
            companyNameUtf16_.data(), companyNameUtf16Length_},
        std::span<const std::uint8_t>{
            productIdUtf16_.data(), productIdUtf16Length_},
        std::span<const std::uint8_t>{
            scopeAnsi_.data(), scopeAnsiLength_},
        std::span<const std::uint8_t>{
            existingCal_.data(), existingCalLength_},
        existingCalHardwareId_,
        existingCalVerificationUnixSeconds_};

    switch (provider_->beginExistingCalValidation(request))
    {
    case RuntimeLicensingProviderBeginStatus::Accepted:
        existingCalValidationPending_ = true;
        state_ = RuntimeLicensingAuthorityState::VerifiedIssuerReady;
        return RuntimeLicensingExistingCalOperation::InProgress;
    case RuntimeLicensingProviderBeginStatus::Denied:
        clearExistingCalRequest();
        requestCorrelation_.fill(0U);
        state_ = RuntimeLicensingAuthorityState::ExistingCalValidationDenied;
        return RuntimeLicensingExistingCalOperation::Denied;
    case RuntimeLicensingProviderBeginStatus::Unavailable:
        failClosed();
        return RuntimeLicensingExistingCalOperation::Unavailable;
    case RuntimeLicensingProviderBeginStatus::Failed:
        failClosed();
        return RuntimeLicensingExistingCalOperation::Failed;
    }

    failClosed();
    return RuntimeLicensingExistingCalOperation::Failed;
}

RuntimeLicensingExistingCalOperation
RuntimeLicensingAuthority::pollExistingCalValidation() noexcept
{
    if (!existingCalValidationPending_ || !currentAuthorityValid())
        return RuntimeLicensingExistingCalOperation::Rejected;

    const RuntimeLicensingExistingCalProviderCompletionView completion =
        provider_->pollExistingCalValidation();

    if (completion.status ==
        RuntimeLicensingExistingCalProviderCompletionStatus::Pending)
    {
        return RuntimeLicensingExistingCalOperation::InProgress;
    }
    if (completion.status ==
        RuntimeLicensingExistingCalProviderCompletionStatus::Cancelled)
    {
        existingCalValidationPending_ = false;
        clearExistingCalRequest();
        requestCorrelation_.fill(0U);
        state_ = RuntimeLicensingAuthorityState::ExistingCalValidationDenied;
        return RuntimeLicensingExistingCalOperation::Cancelled;
    }
    if (completion.status ==
        RuntimeLicensingExistingCalProviderCompletionStatus::TimedOut)
    {
        existingCalValidationPending_ = false;
        clearExistingCalRequest();
        requestCorrelation_.fill(0U);
        state_ = RuntimeLicensingAuthorityState::ExistingCalValidationDenied;
        return RuntimeLicensingExistingCalOperation::TimedOut;
    }
    if (completion.status ==
            RuntimeLicensingExistingCalProviderCompletionStatus::Unavailable ||
        completion.status ==
            RuntimeLicensingExistingCalProviderCompletionStatus::Failed)
    {
        const auto operation =
            completion.status ==
                    RuntimeLicensingExistingCalProviderCompletionStatus::
                        Unavailable
                ? RuntimeLicensingExistingCalOperation::Unavailable
                : RuntimeLicensingExistingCalOperation::Failed;
        failClosed();
        return operation;
    }
    if (completion.status !=
        RuntimeLicensingExistingCalProviderCompletionStatus::Decision)
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Rejected;
    }

    if (!validExistingCalDecision(completion.decision) ||
        completion.requestSequence != requestSequence_ ||
        !requestCorrelationMatches(completion.requestCorrelation) ||
        completion.requestDigest.size() !=
            existingCalRequestDigest_.size() ||
        ::CRYPTO_memcmp(
            completion.requestDigest.data(),
            existingCalRequestDigest_.data(),
            existingCalRequestDigest_.size()) != 0)
    {
        failClosed();
        return RuntimeLicensingExistingCalOperation::Rejected;
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
        return RuntimeLicensingExistingCalOperation::Rejected;
    }

    existingCalValidationPending_ = false;
    existingCalDecision_ = completion.decision;
    existingCalResultReleased_ = false;
    clearExistingCalInput();
    state_ =
        RuntimeLicensingAuthorityState::ExistingCalValidationResultAvailable;
    return RuntimeLicensingExistingCalOperation::DecisionAvailable;
}

RuntimeLicensingExistingCalOperation
RuntimeLicensingAuthority::cancelExistingCalValidation() noexcept
{
    if (!existingCalValidationPending_ || !provider_ ||
        state_ == RuntimeLicensingAuthorityState::Revoked)
    {
        return RuntimeLicensingExistingCalOperation::Rejected;
    }

    provider_->cancelExistingCalValidation();
    existingCalValidationPending_ = false;
    clearExistingCalRequest();
    requestCorrelation_.fill(0U);
    state_ = RuntimeLicensingAuthorityState::ExistingCalValidationDenied;
    return RuntimeLicensingExistingCalOperation::Cancelled;
}

bool RuntimeLicensingAuthority::releaseExistingCalValidationResult(
    std::span<const std::uint8_t> requestCorrelation,
    RuntimeLicensingExistingCalValidationResult &result) noexcept
{
    const bool authenticationCurrent =
        providerAuthenticationMatchesCurrent();
    if (state_ !=
            RuntimeLicensingAuthorityState::
                ExistingCalValidationResultAvailable ||
        existingCalValidationPending_ ||
        existingCalResultReleased_ ||
        allZero(existingCalRequestDigest_) ||
        !requestCorrelationMatches(requestCorrelation) ||
        !authenticationCurrent)
    {
        if (currentAuthorityValid() &&
            state_ ==
                RuntimeLicensingAuthorityState::
                    ExistingCalValidationResultAvailable &&
            !authenticationCurrent)
        {
            failClosed();
        }
        return false;
    }

    if (!result.configure(
            existingCalDecision_,
            authorityGeneration_,
            authorityFingerprint_,
            existingCalRequestDigest_))
    {
        return false;
    }

    releasedExistingCalRequestDigest_ = existingCalRequestDigest_;
    releasedExistingCalRequestCorrelation_ = requestCorrelation_;
    releasedExistingCalDecision_ = existingCalDecision_;
    existingCalResultReleased_ = true;
    existingCalRequestDigest_.fill(0U);
    return true;
}

bool RuntimeLicensingAuthority::
authorizeReleasedExistingCalValidationResult(
    std::span<const std::uint8_t> requestCorrelation,
    const RuntimeLicensingExistingCalValidationResult &result) noexcept
{
    const bool authenticationCurrent =
        providerAuthenticationMatchesCurrent();
    const auto resultFingerprint = result.authorityFingerprint();
    const auto resultDigest = result.requestDigest();
    const bool fingerprintMatches =
        resultFingerprint.size() == authorityFingerprint_.size() &&
        ::CRYPTO_memcmp(
            resultFingerprint.data(),
            authorityFingerprint_.data(),
            authorityFingerprint_.size()) == 0;
    const bool digestMatches =
        resultDigest.size() == releasedExistingCalRequestDigest_.size() &&
        ::CRYPTO_memcmp(
            resultDigest.data(),
            releasedExistingCalRequestDigest_.data(),
            releasedExistingCalRequestDigest_.size()) == 0;

    if (state_ !=
            RuntimeLicensingAuthorityState::
                ExistingCalValidationResultAvailable ||
        !existingCalResultReleased_ ||
        !validRequestCorrelation(requestCorrelation) ||
        ::CRYPTO_memcmp(
            requestCorrelation.data(),
            releasedExistingCalRequestCorrelation_.data(),
            releasedExistingCalRequestCorrelation_.size()) != 0 ||
        !result.configured() ||
        result.decision() != releasedExistingCalDecision_ ||
        result.authorityGeneration() != authorityGeneration_ ||
        !fingerprintMatches ||
        !digestMatches ||
        !authenticationCurrent)
    {
        if (existingCalResultReleased_ &&
            currentAuthorityValid() &&
            !authenticationCurrent)
        {
            failClosed();
        }
        return false;
    }

    return true;
}

bool RuntimeLicensingAuthority::retireReleasedExistingCalValidationResult(
    std::span<const std::uint8_t> requestCorrelation) noexcept
{
    if (state_ !=
            RuntimeLicensingAuthorityState::
                ExistingCalValidationResultAvailable ||
        !existingCalResultReleased_ ||
        !validRequestCorrelation(requestCorrelation) ||
        ::CRYPTO_memcmp(
            requestCorrelation.data(),
            releasedExistingCalRequestCorrelation_.data(),
            releasedExistingCalRequestCorrelation_.size()) != 0)
    {
        return false;
    }

    clearReleasedExistingCalValidationResult();
    requestCorrelation_.fill(0U);
    existingCalDecision_ = RuntimeLicensingExistingCalDecision::Denied;
    state_ = RuntimeLicensingAuthorityState::VerifiedIssuerReady;
    return true;
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

void RuntimeLicensingAuthority::clearExistingCalInput() noexcept
{
    if (existingCalLength_ != 0U)
        ::OPENSSL_cleanse(existingCal_.data(), existingCalLength_);
    existingCalLength_ = 0U;
    ::OPENSSL_cleanse(
        existingCalHardwareId_.data(), existingCalHardwareId_.size());
    existingCalVerificationUnixSeconds_ = 0;
}

void RuntimeLicensingAuthority::clearExistingCalRequest() noexcept
{
    clearExistingCalInput();
    existingCalRequestDigest_.fill(0U);
    existingCalDecision_ = RuntimeLicensingExistingCalDecision::Denied;
}

void RuntimeLicensingAuthority::
clearReleasedExistingCalValidationResult() noexcept
{
    releasedExistingCalRequestDigest_.fill(0U);
    releasedExistingCalRequestCorrelation_.fill(0U);
    releasedExistingCalDecision_ =
        RuntimeLicensingExistingCalDecision::Denied;
    existingCalResultReleased_ = false;
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
    if (existingCalValidationPending_ && provider_)
        provider_->cancelExistingCalValidation();
    requestPending_ = false;
    existingCalValidationPending_ = false;
    clearPendingResult();
    clearReleasedGrant();
    clearExistingCalRequest();
    clearReleasedExistingCalValidationResult();
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


RuntimeExistingCalValidationBinding::~RuntimeExistingCalValidationBinding()
{
    revoke();
}

bool RuntimeExistingCalValidationBinding::generationsMatch(
    std::uint64_t liveAdmissionGeneration,
    std::uint64_t liveSessionGeneration) const noexcept
{
    return active() && liveAdmissionGeneration != 0U &&
           liveSessionGeneration != 0U &&
           liveAdmissionGeneration == admissionGeneration_ &&
           liveSessionGeneration == sessionGeneration_;
}

void RuntimeExistingCalValidationBinding::clearRequestState() noexcept
{
    requestCorrelation_.fill(0U);
    result_.reset();
    admissionGeneration_ = 0U;
    sessionGeneration_ = 0U;
    pending_ = false;
    resultReleased_ = false;
}

RuntimeLicensingExistingCalOperation
RuntimeExistingCalValidationBinding::begin(
    const rdp_server::server::transport::
        RdpExistingClientCalAuthorityRequest &request,
    const rdp_server::server::transport::RdpServerLicenseIdentity
        &expectedIdentity,
    std::uint64_t liveAdmissionGeneration,
    std::uint64_t liveSessionGeneration) noexcept
{
    if (closed_ || authority_ == nullptr || active())
        return RuntimeLicensingExistingCalOperation::Rejected;

    const auto correlation = request.requestCorrelation();
    if (!request.active() ||
        !request.matchesProductIdentity(expectedIdentity) ||
        !request.matchesRequest(
            correlation, liveAdmissionGeneration, liveSessionGeneration) ||
        correlation.size() != requestCorrelation_.size())
    {
        clearRequestState();
        closed_ = true;
        return RuntimeLicensingExistingCalOperation::Rejected;
    }

    const auto operation = authority_->beginExistingCalValidation(
        request.licenseInfo(), request.hardwareId(),
        request.verificationUnixSeconds(), correlation);
    if (operation != RuntimeLicensingExistingCalOperation::InProgress)
    {
        clearRequestState();
        closed_ = true;
        return operation;
    }

    std::copy(correlation.begin(), correlation.end(),
              requestCorrelation_.begin());
    admissionGeneration_ = liveAdmissionGeneration;
    sessionGeneration_ = liveSessionGeneration;
    pending_ = true;
    return operation;
}

RuntimeLicensingExistingCalOperation
RuntimeExistingCalValidationBinding::poll(
    std::uint64_t liveAdmissionGeneration,
    std::uint64_t liveSessionGeneration) noexcept
{
    if (closed_ || !pending_ || authority_ == nullptr)
        return RuntimeLicensingExistingCalOperation::Rejected;
    if (!generationsMatch(liveAdmissionGeneration, liveSessionGeneration))
    {
        revoke();
        return RuntimeLicensingExistingCalOperation::Cancelled;
    }

    const auto operation = authority_->pollExistingCalValidation();
    if (operation == RuntimeLicensingExistingCalOperation::InProgress)
        return operation;

    pending_ = false;
    if (operation != RuntimeLicensingExistingCalOperation::DecisionAvailable)
    {
        clearRequestState();
        closed_ = true;
        return operation;
    }

    result_.emplace();
    if (!authority_->releaseExistingCalValidationResult(
            requestCorrelation_, *result_))
    {
        result_.reset();
        authority_->revoke();
        clearRequestState();
        closed_ = true;
        return RuntimeLicensingExistingCalOperation::Rejected;
    }
    resultReleased_ = true;
    return RuntimeLicensingExistingCalOperation::DecisionAvailable;
}

std::optional<RuntimeLicensingExistingCalDecision>
RuntimeExistingCalValidationBinding::authorizeReleasedDecision(
    std::uint64_t liveAdmissionGeneration,
    std::uint64_t liveSessionGeneration) noexcept
{
    if (closed_ || !resultReleased_ || !result_ || authority_ == nullptr)
        return std::nullopt;
    if (!generationsMatch(liveAdmissionGeneration, liveSessionGeneration) ||
        !authority_->authorizeReleasedExistingCalValidationResult(
            requestCorrelation_, *result_))
    {
        revoke();
        return std::nullopt;
    }
    return result_->decision();
}

bool RuntimeExistingCalValidationBinding::retireReleasedDecision(
    std::uint64_t liveAdmissionGeneration,
    std::uint64_t liveSessionGeneration) noexcept
{
    if (closed_ || !resultReleased_ || !result_ || authority_ == nullptr)
        return false;
    if (!generationsMatch(liveAdmissionGeneration, liveSessionGeneration))
    {
        revoke();
        return false;
    }

    const bool retired =
        authority_->retireReleasedExistingCalValidationResult(
            requestCorrelation_);
    clearRequestState();
    closed_ = true;
    return retired;
}

RuntimeLicensingExistingCalOperation
RuntimeExistingCalValidationBinding::cancel(
    std::uint64_t liveAdmissionGeneration,
    std::uint64_t liveSessionGeneration) noexcept
{
    if (closed_ || !active() || authority_ == nullptr)
        return RuntimeLicensingExistingCalOperation::Rejected;

    const bool exactGeneration =
        generationsMatch(liveAdmissionGeneration, liveSessionGeneration);
    if (pending_)
    {
        const auto operation = authority_->cancelExistingCalValidation();
        clearRequestState();
        closed_ = true;
        return exactGeneration
            ? operation
            : RuntimeLicensingExistingCalOperation::Cancelled;
    }

    const bool retired =
        authority_->retireReleasedExistingCalValidationResult(
            requestCorrelation_);
    clearRequestState();
    closed_ = true;
    return retired || !exactGeneration
        ? RuntimeLicensingExistingCalOperation::Cancelled
        : RuntimeLicensingExistingCalOperation::Rejected;
}

void RuntimeExistingCalValidationBinding::revoke() noexcept
{
    if (closed_)
        return;
    if (authority_ != nullptr)
    {
        if (pending_)
            (void)authority_->cancelExistingCalValidation();
        else if (resultReleased_)
            (void)authority_->retireReleasedExistingCalValidationResult(
                requestCorrelation_);
    }
    clearRequestState();
    closed_ = true;
}

} // namespace rdp_server::server::runtime
