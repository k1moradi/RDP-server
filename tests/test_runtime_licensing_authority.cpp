// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_licensing_authority.h"
#include "server/runtime/runtime_licensing_authority_internal.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace rdp_server::server::runtime
{

class RuntimeLicensingAuthorityTestAccess final
{
public:
    [[nodiscard]] static bool configureVerified(
        RuntimeLicensingAuthority &authority,
        const rdp_server::server::transport::RdpServerLicenseIdentity
            &licensingIdentity,
        std::unique_ptr<detail::RuntimeLicensingAuthorityProvider>
            provider) noexcept
    {
        return authority.configureVerifiedProvider(
            licensingIdentity, std::move(provider));
    }

    [[nodiscard]] static std::uint64_t generation(
        const RuntimeLicensingAuthority &authority) noexcept
    {
        return authority.authorityGeneration_;
    }

    [[nodiscard]] static std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
    fingerprint(const RuntimeLicensingAuthority &authority) noexcept
    {
        return authority.authorityFingerprint_;
    }

    static void forceGeneration(
        RuntimeLicensingAuthority &authority,
        std::uint64_t generation) noexcept
    {
        authority.authorityGeneration_ = generation;
    }
};

} // namespace rdp_server::server::runtime

namespace
{
using rdp_server::server::runtime::RuntimeLicensingAuthority;
using rdp_server::server::runtime::RuntimeLicensingAuthorityOperation;
using rdp_server::server::runtime::RuntimeLicensingAuthorityState;
using rdp_server::server::runtime::RuntimeLicensingExistingCalDecision;
using rdp_server::server::runtime::RuntimeLicensingExistingCalOperation;
using rdp_server::server::runtime::
    RuntimeLicensingExistingCalValidationResult;
using rdp_server::server::runtime::RuntimeLicensingAuthorityTestAccess;
using rdp_server::server::runtime::
    kRuntimeLicensingAuthorityRequestCorrelationBytes;
using rdp_server::server::runtime::detail::
    RuntimeLicensingAuthorityProvider;
using rdp_server::server::runtime::detail::
    RuntimeLicensingExistingCalProviderCompletionStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingExistingCalProviderCompletionView;
using rdp_server::server::runtime::detail::
    RuntimeLicensingExistingCalProviderRequestView;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderBeginStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderCompletionStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderCompletionView;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderRequestView;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderVerificationStatus;
using rdp_server::server::runtime::detail::
    RuntimeLicensingProviderVerificationView;
using rdp_server::server::transport::RdpLicensingAuthorityGrant;
using rdp_server::server::transport::RdpLicensingAuthorityGrantError;
using rdp_server::server::transport::RdpServerLicenseGrantKind;
using rdp_server::server::transport::RdpServerLicenseIdentity;
using rdp_server::server::transport::kMaximumRdpClientCalBytes;
using rdp_server::server::transport::
    kMaximumRdpServerLicenseGrantCalBytes;
using rdp_server::server::transport::
    kRdpLicensingAuthorityFingerprintBytes;
using rdp_server::server::transport::kRdpLicensingHardwareIdBytes;

struct ProviderCounters
{
    std::size_t verificationCalls{};
    std::size_t beginCalls{};
    std::size_t pollCalls{};
    std::size_t cancelCalls{};
    std::size_t existingCalBeginCalls{};
    std::size_t existingCalPollCalls{};
    std::size_t existingCalCancelCalls{};
    std::size_t closeCalls{};
    std::size_t destructorCalls{};
};

class TestLicensingProvider final : public RuntimeLicensingAuthorityProvider
{
public:
    explicit TestLicensingProvider(ProviderCounters &counters) noexcept
        : counters_(&counters)
    {
        setProviderIdentity("issuer-A");
        setTrustConfiguration("trust-root-A");
    }

    ~TestLicensingProvider() override
    {
        ++counters_->destructorCalls;
    }

    void setProviderIdentity(std::string_view value) noexcept
    {
        assert(value.size() <= providerIdentity_.size());
        providerIdentityLength_ = value.size();
        std::copy(value.begin(), value.end(), providerIdentity_.begin());
    }

    void setTrustConfiguration(std::string_view value) noexcept
    {
        assert(value.size() <= trustConfiguration_.size());
        trustConfigurationLength_ = value.size();
        std::copy(value.begin(), value.end(), trustConfiguration_.begin());
    }

    void setCal(std::initializer_list<std::uint8_t> bytes) noexcept
    {
        assert(bytes.size() <= issuedCal_.size());
        issuedCalLength_ = bytes.size();
        std::copy(bytes.begin(), bytes.end(), issuedCal_.begin());
    }

    void fillCal(std::size_t bytes, std::uint8_t value) noexcept
    {
        assert(bytes <= issuedCal_.size());
        issuedCalLength_ = bytes;
        std::fill_n(issuedCal_.begin(), bytes, value);
    }

    void mutateCal(std::uint8_t value) noexcept
    {
        std::fill_n(issuedCal_.begin(), issuedCalLength_, value);
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingCal() const noexcept
    {
        return std::span<const std::uint8_t>{
            capturedExistingCal_.data(), capturedExistingCalLength_};
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingHardwareId() const noexcept
    {
        return capturedExistingHardwareId_;
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingRequestDigest() const noexcept
    {
        return capturedExistingRequestDigest_;
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingCorrelation() const noexcept
    {
        return capturedExistingCorrelation_;
    }

    [[nodiscard]] std::uint32_t capturedExistingProductVersion() const noexcept
    {
        return capturedExistingProductVersion_;
    }

    [[nodiscard]] std::int64_t
    capturedExistingVerificationTime() const noexcept
    {
        return capturedExistingVerificationTime_;
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingCompanyName() const noexcept
    {
        return std::span<const std::uint8_t>{
            capturedExistingCompanyName_.data(),
            capturedExistingCompanyNameLength_};
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingProductId() const noexcept
    {
        return std::span<const std::uint8_t>{
            capturedExistingProductId_.data(),
            capturedExistingProductIdLength_};
    }

    [[nodiscard]] std::span<const std::uint8_t>
    capturedExistingScope() const noexcept
    {
        return std::span<const std::uint8_t>{
            capturedExistingScope_.data(),
            capturedExistingScopeLength_};
    }

    void corruptExistingCompletionDigest() noexcept
    {
        capturedExistingRequestDigest_[0] ^= 0x80U;
    }

    [[nodiscard]] RuntimeLicensingProviderVerificationView
    verification() noexcept override
    {
        ++counters_->verificationCalls;
        return {
            verificationStatus_,
            std::span<const std::uint8_t>{
                providerIdentity_.data(), providerIdentityLength_},
            std::span<const std::uint8_t>{
                trustConfiguration_.data(), trustConfigurationLength_}};
    }

    [[nodiscard]] RuntimeLicensingProviderBeginStatus begin(
        const RuntimeLicensingProviderRequestView &request) noexcept override
    {
        ++counters_->beginCalls;
        capturedRequestSequence_ = request.requestSequence;
        capturedKind_ = request.kind;
        assert(request.requestCorrelation.size() ==
               capturedCorrelation_.size());
        std::copy(
            request.requestCorrelation.begin(),
            request.requestCorrelation.end(),
            capturedCorrelation_.begin());
        return beginStatus_;
    }

    [[nodiscard]] RuntimeLicensingProviderCompletionView
    poll() noexcept override
    {
        ++counters_->pollCalls;
        return {
            completionStatus_,
            capturedKind_,
            capturedRequestSequence_,
            std::span<const std::uint8_t>{
                capturedCorrelation_.data(),
                completionCorrelationLength_},
            std::span<const std::uint8_t>{
                providerIdentity_.data(), providerIdentityLength_},
            std::span<const std::uint8_t>{
                trustConfiguration_.data(), trustConfigurationLength_},
            std::span<const std::uint8_t>{
                issuedCal_.data(), issuedCalLength_}};
    }

    void cancel() noexcept override
    {
        ++counters_->cancelCalls;
    }

    [[nodiscard]] RuntimeLicensingProviderBeginStatus
    beginExistingCalValidation(
        const RuntimeLicensingExistingCalProviderRequestView &request)
        noexcept override
    {
        ++counters_->existingCalBeginCalls;
        assert(request.authorityGeneration != 0U);
        assert(request.authorityFingerprint.size() ==
               kRdpLicensingAuthorityFingerprintBytes);
        assert(request.requestCorrelation.size() ==
               capturedExistingCorrelation_.size());
        assert(request.requestDigest.size() ==
               capturedExistingRequestDigest_.size());
        assert(!request.presentedCal.empty());
        assert(request.presentedCal.size() <=
               capturedExistingCal_.size());
        assert(request.protectedHardwareId.size() ==
               capturedExistingHardwareId_.size());
        assert(request.companyNameUtf16.size() <=
               capturedExistingCompanyName_.size());
        assert(request.productIdUtf16.size() <=
               capturedExistingProductId_.size());
        assert(request.scopeAnsi.size() <=
               capturedExistingScope_.size());

        capturedExistingRequestSequence_ = request.requestSequence;
        capturedExistingProductVersion_ = request.productVersion;
        capturedExistingVerificationTime_ =
            request.verificationUnixSeconds;
        capturedExistingCalLength_ = request.presentedCal.size();
        std::copy(
            request.presentedCal.begin(),
            request.presentedCal.end(),
            capturedExistingCal_.begin());
        std::copy(
            request.protectedHardwareId.begin(),
            request.protectedHardwareId.end(),
            capturedExistingHardwareId_.begin());
        std::copy(
            request.requestCorrelation.begin(),
            request.requestCorrelation.end(),
            capturedExistingCorrelation_.begin());
        std::copy(
            request.requestDigest.begin(),
            request.requestDigest.end(),
            capturedExistingRequestDigest_.begin());

        capturedExistingCompanyNameLength_ =
            request.companyNameUtf16.size();
        std::copy(
            request.companyNameUtf16.begin(),
            request.companyNameUtf16.end(),
            capturedExistingCompanyName_.begin());
        capturedExistingProductIdLength_ = request.productIdUtf16.size();
        std::copy(
            request.productIdUtf16.begin(),
            request.productIdUtf16.end(),
            capturedExistingProductId_.begin());
        capturedExistingScopeLength_ = request.scopeAnsi.size();
        std::copy(
            request.scopeAnsi.begin(),
            request.scopeAnsi.end(),
            capturedExistingScope_.begin());
        return existingCalBeginStatus_;
    }

    [[nodiscard]] RuntimeLicensingExistingCalProviderCompletionView
    pollExistingCalValidation() noexcept override
    {
        ++counters_->existingCalPollCalls;
        return {
            existingCalCompletionStatus_,
            existingCalDecision_,
            capturedExistingRequestSequence_,
            std::span<const std::uint8_t>{
                capturedExistingCorrelation_.data(),
                existingCalCompletionCorrelationLength_},
            std::span<const std::uint8_t>{
                capturedExistingRequestDigest_.data(),
                existingCalCompletionRequestDigestLength_},
            std::span<const std::uint8_t>{
                providerIdentity_.data(), providerIdentityLength_},
            std::span<const std::uint8_t>{
                trustConfiguration_.data(), trustConfigurationLength_}};
    }

    void cancelExistingCalValidation() noexcept override
    {
        ++counters_->existingCalCancelCalls;
    }

    void close() noexcept override
    {
        if (!closed_)
        {
            closed_ = true;
            ++counters_->closeCalls;
        }
    }

    RuntimeLicensingProviderVerificationStatus verificationStatus_{
        RuntimeLicensingProviderVerificationStatus::Verified};
    RuntimeLicensingProviderBeginStatus beginStatus_{
        RuntimeLicensingProviderBeginStatus::Accepted};
    RuntimeLicensingProviderCompletionStatus completionStatus_{
        RuntimeLicensingProviderCompletionStatus::Issued};
    RuntimeLicensingProviderBeginStatus existingCalBeginStatus_{
        RuntimeLicensingProviderBeginStatus::Accepted};
    RuntimeLicensingExistingCalProviderCompletionStatus
        existingCalCompletionStatus_{
            RuntimeLicensingExistingCalProviderCompletionStatus::Decision};
    RuntimeLicensingExistingCalDecision existingCalDecision_{
        RuntimeLicensingExistingCalDecision::Denied};
    std::size_t existingCalCompletionCorrelationLength_{
        kRuntimeLicensingAuthorityRequestCorrelationBytes};
    std::size_t existingCalCompletionRequestDigestLength_{32U};
    std::size_t providerIdentityLength_{};
    std::size_t trustConfigurationLength_{};
    std::size_t completionCorrelationLength_{
        kRuntimeLicensingAuthorityRequestCorrelationBytes};
    std::size_t issuedCalLength_{};

private:
    ProviderCounters *counters_{};
    std::array<std::uint8_t, 128U> providerIdentity_{};
    std::array<std::uint8_t, 128U> trustConfiguration_{};
    std::array<std::uint8_t,
        kMaximumRdpServerLicenseGrantCalBytes + 1U>
        issuedCal_{};
    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        capturedCorrelation_{};

    std::array<std::uint8_t, kMaximumRdpClientCalBytes>
        capturedExistingCal_{};
    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes>
        capturedExistingHardwareId_{};
    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        capturedExistingCorrelation_{};
    std::array<std::uint8_t, 32U> capturedExistingRequestDigest_{};
    std::array<std::uint8_t, 128U> capturedExistingCompanyName_{};
    std::array<std::uint8_t, 128U> capturedExistingProductId_{};
    std::array<std::uint8_t, 128U> capturedExistingScope_{};
    std::size_t capturedExistingCalLength_{};
    std::size_t capturedExistingCompanyNameLength_{};
    std::size_t capturedExistingProductIdLength_{};
    std::size_t capturedExistingScopeLength_{};
    std::uint64_t capturedExistingRequestSequence_{};
    std::uint32_t capturedExistingProductVersion_{};
    std::int64_t capturedExistingVerificationTime_{};

    std::uint64_t capturedRequestSequence_{};
    RdpServerLicenseGrantKind capturedKind_{
        RdpServerLicenseGrantKind::NewLicense};
    bool closed_{};
};

void configureIdentity(
    RdpServerLicenseIdentity &identity,
    std::uint32_t productVersion = 0x00060001U,
    std::uint8_t productCharacter = 'A',
    std::uint8_t scopeCharacter = 'S')
{
    const std::array<std::uint8_t, 4U> companyName{
        'R', 0U, 0U, 0U};
    const std::array<std::uint8_t, 4U> productId{
        productCharacter, 0U, 0U, 0U};
    const std::array<std::uint8_t, 1U> certificate{0x30U};
    const std::array<std::uint8_t, 2U> scope{
        scopeCharacter, 0U};
    assert(identity.configure(
        productVersion,
        companyName,
        productId,
        certificate,
        scope));
}

[[nodiscard]] std::array<std::uint8_t,
    kRuntimeLicensingAuthorityRequestCorrelationBytes>
makeCorrelation(std::uint8_t seed) noexcept
{
    assert(seed != 0U);
    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        correlation{};
    for (std::size_t index = 0U; index < correlation.size(); ++index)
    {
        correlation[index] = static_cast<std::uint8_t>(
            seed + static_cast<std::uint8_t>(index));
    }
    return correlation;
}

[[nodiscard]] std::array<std::uint8_t, kRdpLicensingHardwareIdBytes>
makeHardwareId(std::uint8_t seed) noexcept
{
    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> hardwareId{};
    for (std::size_t index = 0U; index < hardwareId.size(); ++index)
    {
        hardwareId[index] = static_cast<std::uint8_t>(
            seed + static_cast<std::uint8_t>(index));
    }
    return hardwareId;
}

[[nodiscard]] TestLicensingProvider *configureVerifiedAuthority(
    RuntimeLicensingAuthority &authority,
    const RdpServerLicenseIdentity &identity,
    ProviderCounters &counters)
{
    auto provider = std::make_unique<TestLicensingProvider>(counters);
    TestLicensingProvider *const borrowedProvider = provider.get();
    assert(RuntimeLicensingAuthorityTestAccess::configureVerified(
        authority, identity, std::move(provider)));
    assert(authority.configured());
    assert(authority.issuerVerified());
    assert(authority.state() ==
           RuntimeLicensingAuthorityState::VerifiedIssuerReady);
    assert(RuntimeLicensingAuthorityTestAccess::generation(authority) != 0U);
    return borrowedProvider;
}

void testUnconfiguredDenials()
{
    const auto correlation = makeCorrelation(1U);
    RdpLicensingAuthorityGrant grant;

    RuntimeLicensingAuthority defaultAuthority;
    assert(defaultAuthority.state() ==
           RuntimeLicensingAuthorityState::NotConfigured);
    assert(defaultAuthority.beginIssuance(
        RdpServerLicenseGrantKind::NewLicense,
        correlation) == RuntimeLicensingAuthorityOperation::Rejected);
    assert(!defaultAuthority.releaseIssuedGrant(correlation, grant));
    assert(!grant.configured());

    RdpServerLicenseIdentity invalidIdentity;
    RuntimeLicensingAuthority invalidPolicyAuthority;
    assert(!invalidPolicyAuthority.configureUnavailable(invalidIdentity));
    assert(invalidPolicyAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);

    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    assert(!invalidPolicyAuthority.configureUnavailable(identity));

    RuntimeLicensingAuthority unavailableAuthority;
    assert(unavailableAuthority.configureUnavailable(identity));
    assert(unavailableAuthority.state() ==
           RuntimeLicensingAuthorityState::NoVerifiedIssuer);
    assert(!unavailableAuthority.issuerVerified());
    assert(unavailableAuthority.beginIssuance(
        RdpServerLicenseGrantKind::NewLicense,
        correlation) == RuntimeLicensingAuthorityOperation::Unavailable);
    assert(!unavailableAuthority.releaseIssuedGrant(correlation, grant));

    RuntimeLicensingAuthority missingBackendAuthority;
    assert(!RuntimeLicensingAuthorityTestAccess::configureVerified(
        missingBackendAuthority, identity, {}));
    assert(missingBackendAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);

    ProviderCounters missingIdentityCounters;
    RuntimeLicensingAuthority missingIdentityAuthority;
    auto missingIdentityProvider =
        std::make_unique<TestLicensingProvider>(
            missingIdentityCounters);
    missingIdentityProvider->providerIdentityLength_ = 0U;
    assert(!RuntimeLicensingAuthorityTestAccess::configureVerified(
        missingIdentityAuthority,
        identity,
        std::move(missingIdentityProvider)));
    assert(missingIdentityCounters.closeCalls == 1U);

    ProviderCounters missingTrustCounters;
    RuntimeLicensingAuthority missingTrustAuthority;
    auto missingTrustProvider =
        std::make_unique<TestLicensingProvider>(missingTrustCounters);
    missingTrustProvider->trustConfigurationLength_ = 0U;
    assert(!RuntimeLicensingAuthorityTestAccess::configureVerified(
        missingTrustAuthority,
        identity,
        std::move(missingTrustProvider)));
    assert(missingTrustCounters.closeCalls == 1U);

    ProviderCounters invalidProviderCounters;
    RuntimeLicensingAuthority invalidProviderAuthority;
    auto invalidProvider =
        std::make_unique<TestLicensingProvider>(invalidProviderCounters);
    invalidProvider->verificationStatus_ =
        RuntimeLicensingProviderVerificationStatus::Unavailable;
    assert(!RuntimeLicensingAuthorityTestAccess::configureVerified(
        invalidProviderAuthority,
        identity,
        std::move(invalidProvider)));
    assert(invalidProviderAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);
    assert(invalidProviderCounters.closeCalls == 1U);

    assert(!grant.configured());
}

void testIssuerPolicyCorrelation()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    ProviderCounters baseCounters;
    RuntimeLicensingAuthority baseAuthority;
    (void)configureVerifiedAuthority(
        baseAuthority, identity, baseCounters);
    const auto baseFingerprint =
        RuntimeLicensingAuthorityTestAccess::fingerprint(baseAuthority);
    assert(!std::all_of(
        baseFingerprint.begin(),
        baseFingerprint.end(),
        [](std::uint8_t byte) { return byte == 0U; }));

    RdpServerLicenseIdentity changedProductVersionIdentity;
    configureIdentity(changedProductVersionIdentity, 0x00070001U);
    ProviderCounters productVersionCounters;
    RuntimeLicensingAuthority productVersionAuthority;
    (void)configureVerifiedAuthority(
        productVersionAuthority,
        changedProductVersionIdentity,
        productVersionCounters);
    assert(RuntimeLicensingAuthorityTestAccess::fingerprint(
               productVersionAuthority) != baseFingerprint);

    RdpServerLicenseIdentity changedProductIdIdentity;
    configureIdentity(
        changedProductIdIdentity, 0x00060001U, 'B', 'S');
    ProviderCounters productIdCounters;
    RuntimeLicensingAuthority productIdAuthority;
    (void)configureVerifiedAuthority(
        productIdAuthority,
        changedProductIdIdentity,
        productIdCounters);
    assert(RuntimeLicensingAuthorityTestAccess::fingerprint(
               productIdAuthority) != baseFingerprint);

    RdpServerLicenseIdentity changedScopeIdentity;
    configureIdentity(
        changedScopeIdentity, 0x00060001U, 'A', 'T');
    ProviderCounters scopeCounters;
    RuntimeLicensingAuthority scopeAuthority;
    (void)configureVerifiedAuthority(
        scopeAuthority, changedScopeIdentity, scopeCounters);
    assert(RuntimeLicensingAuthorityTestAccess::fingerprint(
               scopeAuthority) != baseFingerprint);

    ProviderCounters trustCounters;
    RuntimeLicensingAuthority trustAuthority;
    auto trustProvider =
        std::make_unique<TestLicensingProvider>(trustCounters);
    trustProvider->setTrustConfiguration("trust-root-B");
    assert(RuntimeLicensingAuthorityTestAccess::configureVerified(
        trustAuthority, identity, std::move(trustProvider)));
    assert(RuntimeLicensingAuthorityTestAccess::fingerprint(
               trustAuthority) != baseFingerprint);

    ProviderCounters issuerCounters;
    RuntimeLicensingAuthority issuerAuthority;
    auto issuerProvider =
        std::make_unique<TestLicensingProvider>(issuerCounters);
    issuerProvider->setProviderIdentity("issuer-B");
    assert(RuntimeLicensingAuthorityTestAccess::configureVerified(
        issuerAuthority, identity, std::move(issuerProvider)));
    assert(RuntimeLicensingAuthorityTestAccess::fingerprint(
               issuerAuthority) != baseFingerprint);

    // Raw correlation values are deliberately insufficient. Even an R3 grant
    // fabricated with the current generation/fingerprint is not authorized
    // because R10 did not produce and release the CAL for this request.
    const std::array<std::uint8_t, 3U> fabricatedCal{1U, 2U, 3U};
    RdpLicensingAuthorityGrant fabricatedGrant;
    assert(fabricatedGrant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               RuntimeLicensingAuthorityTestAccess::generation(
                   baseAuthority),
               baseFingerprint,
               fabricatedCal) ==
           RdpLicensingAuthorityGrantError::None);
    const auto correlation = makeCorrelation(2U);
    assert(!baseAuthority.authorizeReleasedGrant(
        correlation, fabricatedGrant));
}

void testGenerationRevocation()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    const auto correlation = makeCorrelation(3U);
    const std::array<std::uint8_t, 4U> expectedCal{
        0x10U, 0x20U, 0x30U, 0x40U};

    ProviderCounters counters;
    RuntimeLicensingAuthority authority;
    TestLicensingProvider *const provider =
        configureVerifiedAuthority(authority, identity, counters);
    provider->setCal({0x10U, 0x20U, 0x30U, 0x40U});

    assert(authority.beginIssuance(
               RdpServerLicenseGrantKind::NewLicense,
               correlation) ==
           RuntimeLicensingAuthorityOperation::InProgress);
    assert(authority.pollIssuance() ==
           RuntimeLicensingAuthorityOperation::Issued);
    assert(authority.pollIssuance() ==
           RuntimeLicensingAuthorityOperation::Rejected);

    const std::uint64_t generation =
        RuntimeLicensingAuthorityTestAccess::generation(authority);
    const auto fingerprint =
        RuntimeLicensingAuthorityTestAccess::fingerprint(authority);

    RdpLicensingAuthorityGrant grant;
    assert(authority.releaseIssuedGrant(correlation, grant));
    assert(grant.configured());
    assert(grant.authorityGeneration() == generation);
    assert(std::equal(
        grant.issuedCal().begin(),
        grant.issuedCal().end(),
        expectedCal.begin(),
        expectedCal.end()));
    assert(authority.authorizeReleasedGrant(correlation, grant));

    const auto wrongCorrelation = makeCorrelation(4U);
    assert(!authority.authorizeReleasedGrant(wrongCorrelation, grant));

    RdpLicensingAuthorityGrant staleGenerationGrant;
    const std::uint64_t staleGeneration =
        generation == (std::numeric_limits<std::uint64_t>::max)()
        ? generation - 1U
        : generation + 1U;
    assert(staleGenerationGrant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               staleGeneration,
               fingerprint,
               expectedCal) ==
           RdpLicensingAuthorityGrantError::None);
    assert(!authority.authorizeReleasedGrant(
        correlation, staleGenerationGrant));

    auto changedFingerprint = fingerprint;
    changedFingerprint[0] ^= 0x80U;
    RdpLicensingAuthorityGrant changedFingerprintGrant;
    assert(changedFingerprintGrant.configure(
               RdpServerLicenseGrantKind::NewLicense,
               generation,
               changedFingerprint,
               expectedCal) ==
           RdpLicensingAuthorityGrantError::None);
    assert(!authority.authorizeReleasedGrant(
        correlation, changedFingerprintGrant));

    authority.revoke();
    authority.revoke();
    assert(authority.state() == RuntimeLicensingAuthorityState::Revoked);
    assert(!authority.authorizeReleasedGrant(correlation, grant));
    assert(authority.beginIssuance(
               RdpServerLicenseGrantKind::NewLicense,
               correlation) ==
           RuntimeLicensingAuthorityOperation::Rejected);
    assert(counters.closeCalls == 1U);

    // A result from the retired owner cannot bind to another owner even when
    // that owner has the same provider identity and product policy.
    ProviderCounters replacementCounters;
    RuntimeLicensingAuthority replacementAuthority;
    (void)configureVerifiedAuthority(
        replacementAuthority, identity, replacementCounters);
    assert(!replacementAuthority.authorizeReleasedGrant(
        correlation, grant));

    ProviderCounters changedIssuerCounters;
    RuntimeLicensingAuthority changedIssuerAuthority;
    TestLicensingProvider *const changedIssuerProvider =
        configureVerifiedAuthority(
            changedIssuerAuthority, identity, changedIssuerCounters);
    changedIssuerProvider->setCal({1U, 2U, 3U});
    assert(changedIssuerAuthority.beginIssuance(
               RdpServerLicenseGrantKind::NewLicense,
               correlation) ==
           RuntimeLicensingAuthorityOperation::InProgress);
    assert(changedIssuerAuthority.pollIssuance() ==
           RuntimeLicensingAuthorityOperation::Issued);
    changedIssuerProvider->setProviderIdentity("issuer-C");
    RdpLicensingAuthorityGrant changedIssuerGrant;
    assert(!changedIssuerAuthority.releaseIssuedGrant(
        correlation, changedIssuerGrant));
    assert(changedIssuerAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);
    assert(!changedIssuerGrant.configured());

    ProviderCounters zeroGenerationCounters;
    RuntimeLicensingAuthority zeroGenerationAuthority;
    (void)configureVerifiedAuthority(
        zeroGenerationAuthority, identity, zeroGenerationCounters);
    RuntimeLicensingAuthorityTestAccess::forceGeneration(
        zeroGenerationAuthority, 0U);
    assert(zeroGenerationAuthority.beginIssuance(
               RdpServerLicenseGrantKind::NewLicense,
               correlation) ==
           RuntimeLicensingAuthorityOperation::Rejected);
    assert(zeroGenerationAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);

    // Authority generations are independently generated, never incremented.
    // Forcing the mathematical maximum proves there is no wrap-to-zero path:
    // it remains the exact generation until terminal revocation, after which
    // this one-shot owner cannot be reconfigured.
    ProviderCounters maximumGenerationCounters;
    RuntimeLicensingAuthority maximumGenerationAuthority;
    TestLicensingProvider *const maximumGenerationProvider =
        configureVerifiedAuthority(
            maximumGenerationAuthority,
            identity,
            maximumGenerationCounters);
    RuntimeLicensingAuthorityTestAccess::forceGeneration(
        maximumGenerationAuthority,
        (std::numeric_limits<std::uint64_t>::max)());
    maximumGenerationProvider->setCal({9U, 8U, 7U});
    assert(maximumGenerationAuthority.beginIssuance(
               RdpServerLicenseGrantKind::NewLicense,
               correlation) ==
           RuntimeLicensingAuthorityOperation::InProgress);
    assert(maximumGenerationAuthority.pollIssuance() ==
           RuntimeLicensingAuthorityOperation::Issued);
    RdpLicensingAuthorityGrant maximumGenerationGrant;
    assert(maximumGenerationAuthority.releaseIssuedGrant(
        correlation, maximumGenerationGrant));
    assert(maximumGenerationGrant.authorityGeneration() ==
           (std::numeric_limits<std::uint64_t>::max)());
    maximumGenerationAuthority.revoke();
    assert(!maximumGenerationAuthority.configureUnavailable(identity));
}

void testResultBoundsAndCancellation()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    const auto correlation = makeCorrelation(5U);

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->issuedCalLength_ = 0U;
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Rejected);
        RdpLicensingAuthorityGrant grant;
        assert(!authority.releaseIssuedGrant(correlation, grant));
        assert(!grant.configured());
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->fillCal(
            kMaximumRdpServerLicenseGrantCalBytes + 1U, 0x41U);
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Rejected);
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->setCal({1U});
        provider->completionCorrelationLength_ =
            kRuntimeLicensingAuthorityRequestCorrelationBytes - 1U;
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Rejected);
    }

    for (const auto &[providerStatus, expectedOutcome] :
         std::array{
             std::pair{
                 RuntimeLicensingProviderCompletionStatus::Failed,
                 RuntimeLicensingAuthorityOperation::Failed},
             std::pair{
                 RuntimeLicensingProviderCompletionStatus::Unavailable,
                 RuntimeLicensingAuthorityOperation::Unavailable},
             std::pair{
                 RuntimeLicensingProviderCompletionStatus::TimedOut,
                 RuntimeLicensingAuthorityOperation::TimedOut},
             std::pair{
                 RuntimeLicensingProviderCompletionStatus::Incomplete,
                 RuntimeLicensingAuthorityOperation::Rejected},
             std::pair{
                 RuntimeLicensingProviderCompletionStatus::UnexpectedResult,
                 RuntimeLicensingAuthorityOperation::Rejected}})
    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->completionStatus_ = providerStatus;
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() == expectedOutcome);
        RdpLicensingAuthorityGrant grant;
        assert(!authority.releaseIssuedGrant(correlation, grant));
        assert(!grant.configured());
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->completionStatus_ =
            RuntimeLicensingProviderCompletionStatus::Cancelled;
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Cancelled);
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        (void)configureVerifiedAuthority(authority, identity, counters);
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.cancelIssuance() ==
               RuntimeLicensingAuthorityOperation::Cancelled);
        assert(counters.cancelCalls == 1U);
        RdpLicensingAuthorityGrant grant;
        assert(!authority.releaseIssuedGrant(correlation, grant));
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->setCal({1U, 2U});
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        provider->setProviderIdentity("issuer-changed-while-pending");
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Rejected);
        assert(authority.state() ==
               RuntimeLicensingAuthorityState::Revoked);
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        (void)configureVerifiedAuthority(authority, identity, counters);
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        authority.revoke();
        assert(counters.cancelCalls == 1U);
        assert(counters.closeCalls == 1U);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Rejected);
    }

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->setCal({5U, 6U});
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Issued);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Rejected);
    }
}

void testSensitiveRetirement()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    const auto correlation = makeCorrelation(6U);

    {
        ProviderCounters counters;
        RuntimeLicensingAuthority authority;
        TestLicensingProvider *const provider =
            configureVerifiedAuthority(authority, identity, counters);
        provider->setCal({0x11U, 0x22U, 0x33U});
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
        assert(authority.pollIssuance() ==
               RuntimeLicensingAuthorityOperation::Issued);

        // Provider storage is borrowed only during poll(). Mutating it before
        // release cannot change the owner's already-copied result.
        provider->mutateCal(0xeeU);
        RdpLicensingAuthorityGrant grant;
        assert(authority.releaseIssuedGrant(correlation, grant));
        const std::array<std::uint8_t, 3U> expected{
            0x11U, 0x22U, 0x33U};
        assert(std::equal(
            grant.issuedCal().begin(),
            grant.issuedCal().end(),
            expected.begin(),
            expected.end()));
        assert(authority.authorizeReleasedGrant(correlation, grant));
        assert(authority.retireReleasedGrant(correlation));
        assert(!authority.authorizeReleasedGrant(correlation, grant));
        assert(!authority.retireReleasedGrant(correlation));
    }

    ProviderCounters destructionCounters;
    {
        RuntimeLicensingAuthority authority;
        (void)configureVerifiedAuthority(
            authority, identity, destructionCounters);
        assert(authority.beginIssuance(
                   RdpServerLicenseGrantKind::NewLicense,
                   correlation) ==
               RuntimeLicensingAuthorityOperation::InProgress);
    }
    assert(destructionCounters.cancelCalls == 1U);
    assert(destructionCounters.closeCalls == 1U);
    assert(destructionCounters.destructorCalls == 1U);

    ProviderCounters partialConfigurationCounters;
    {
        RuntimeLicensingAuthority authority;
        auto provider = std::make_unique<TestLicensingProvider>(
            partialConfigurationCounters);
        provider->trustConfigurationLength_ = 0U;
        assert(!RuntimeLicensingAuthorityTestAccess::configureVerified(
            authority, identity, std::move(provider)));
        authority.revoke();
        authority.revoke();
    }
    assert(partialConfigurationCounters.closeCalls == 1U);
    assert(partialConfigurationCounters.destructorCalls == 1U);

    ProviderCounters duplicateCloseCounters;
    {
        RuntimeLicensingAuthority authority;
        (void)configureVerifiedAuthority(
            authority, identity, duplicateCloseCounters);
        authority.revoke();
        authority.revoke();
        assert(duplicateCloseCounters.closeCalls == 1U);
    }
    assert(duplicateCloseCounters.closeCalls == 1U);
    assert(duplicateCloseCounters.destructorCalls == 1U);
}


void testExistingCalProviderUnavailable()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    const std::array<std::uint8_t, 4U> cal{0x30U, 0x01U, 0x02U, 0x03U};
    const auto hardwareId = makeHardwareId(0x20U);
    const auto correlation = makeCorrelation(0x21U);

    RuntimeLicensingAuthority defaultAuthority;
    assert(defaultAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'000'000LL, correlation) ==
           RuntimeLicensingExistingCalOperation::Rejected);

    RuntimeLicensingAuthority unavailableAuthority;
    assert(unavailableAuthority.configureUnavailable(identity));
    assert(unavailableAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'000'000LL, correlation) ==
           RuntimeLicensingExistingCalOperation::Unavailable);
    RuntimeLicensingExistingCalValidationResult unavailableResult;
    assert(!unavailableAuthority.releaseExistingCalValidationResult(
        correlation, unavailableResult));
    assert(!unavailableResult.configured());

    ProviderCounters counters;
    RuntimeLicensingAuthority verifiedAuthority;
    (void)configureVerifiedAuthority(
        verifiedAuthority, identity, counters);
    const std::array<std::uint8_t, kRdpLicensingHardwareIdBytes - 1U>
        shortHardwareId{};
    const std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        zeroCorrelation{};
    assert(verifiedAuthority.beginExistingCalValidation(
               {}, hardwareId, 1'800'000'000LL, correlation) ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(verifiedAuthority.beginExistingCalValidation(
               cal, shortHardwareId, 1'800'000'000LL, correlation) ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(verifiedAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'000'000LL, zeroCorrelation) ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(counters.existingCalBeginCalls == 0U);
}

void testExistingCalRequestCorrelation()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    std::array<std::uint8_t, 6U> cal{
        0x30U, 0x04U, 0x11U, 0x22U, 0x33U, 0x44U};
    auto hardwareId = makeHardwareId(0x31U);
    const auto correlation = makeCorrelation(0x32U);
    constexpr std::int64_t verificationTime = 1'800'000'123LL;

    ProviderCounters counters;
    RuntimeLicensingAuthority authority;
    TestLicensingProvider *const provider =
        configureVerifiedAuthority(authority, identity, counters);
    provider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::ValidPermanentNoUpgrade;

    const auto expectedCal = cal;
    const auto expectedHardwareId = hardwareId;
    assert(authority.beginExistingCalValidation(
               cal, hardwareId, verificationTime, correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    assert(counters.existingCalBeginCalls == 1U);
    assert(std::equal(
        provider->capturedExistingCal().begin(),
        provider->capturedExistingCal().end(),
        expectedCal.begin(),
        expectedCal.end()));
    assert(std::equal(
        provider->capturedExistingHardwareId().begin(),
        provider->capturedExistingHardwareId().end(),
        expectedHardwareId.begin(),
        expectedHardwareId.end()));
    assert(std::equal(
        provider->capturedExistingCorrelation().begin(),
        provider->capturedExistingCorrelation().end(),
        correlation.begin(),
        correlation.end()));
    assert(provider->capturedExistingProductVersion() == 0x00060001U);
    assert(provider->capturedExistingVerificationTime() ==
           verificationTime);
    assert(provider->capturedExistingCompanyName().size() == 4U);
    assert(provider->capturedExistingProductId().size() == 4U);
    assert(provider->capturedExistingScope().size() == 2U);
    assert(!std::all_of(
        provider->capturedExistingRequestDigest().begin(),
        provider->capturedExistingRequestDigest().end(),
        [](std::uint8_t byte) { return byte == 0U; }));

    cal.fill(0xeeU);
    hardwareId.fill(0xddU);
    assert(authority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::DecisionAvailable);
    assert(counters.existingCalPollCalls == 1U);

    const auto wrongCorrelation = makeCorrelation(0x33U);
    RuntimeLicensingExistingCalValidationResult result;
    assert(!authority.releaseExistingCalValidationResult(
        wrongCorrelation, result));
    assert(authority.releaseExistingCalValidationResult(
        correlation, result));
    assert(result.configured());
    assert(result.decision() ==
           RuntimeLicensingExistingCalDecision::ValidPermanentNoUpgrade);
    assert(result.authorityGeneration() != 0U);
    assert(result.authorityFingerprint().size() ==
           kRdpLicensingAuthorityFingerprintBytes);
    assert(result.requestDigest().size() == 32U);
    assert(authority.authorizeReleasedExistingCalValidationResult(
        correlation, result));
    assert(!authority.authorizeReleasedExistingCalValidationResult(
        wrongCorrelation, result));
    assert(authority.retireReleasedExistingCalValidationResult(
        correlation));

    ProviderCounters upgradeCounters;
    RuntimeLicensingAuthority upgradeAuthority;
    TestLicensingProvider *const upgradeProvider =
        configureVerifiedAuthority(
            upgradeAuthority, identity, upgradeCounters);
    upgradeProvider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::UpgradeRequired;
    assert(upgradeAuthority.beginExistingCalValidation(
               expectedCal,
               expectedHardwareId,
               verificationTime,
               correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    assert(upgradeAuthority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::DecisionAvailable);
    RuntimeLicensingExistingCalValidationResult upgradeResult;
    assert(upgradeAuthority.releaseExistingCalValidationResult(
        correlation, upgradeResult));
    assert(upgradeResult.decision() ==
           RuntimeLicensingExistingCalDecision::UpgradeRequired);
}

void testExistingCalPolicyGenerationRevocation()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    const std::array<std::uint8_t, 3U> cal{0x30U, 0x01U, 0x7fU};
    const auto hardwareId = makeHardwareId(0x41U);
    const auto correlation = makeCorrelation(0x42U);

    ProviderCounters driftCounters;
    RuntimeLicensingAuthority driftAuthority;
    TestLicensingProvider *const driftProvider =
        configureVerifiedAuthority(
            driftAuthority, identity, driftCounters);
    driftProvider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::ValidPermanentNoUpgrade;
    assert(driftAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'001'000LL, correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    assert(driftAuthority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::DecisionAvailable);
    driftProvider->setTrustConfiguration("trust-root-drifted");
    RuntimeLicensingExistingCalValidationResult driftResult;
    assert(!driftAuthority.releaseExistingCalValidationResult(
        correlation, driftResult));
    assert(driftAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);
    assert(!driftResult.configured());

    ProviderCounters digestCounters;
    RuntimeLicensingAuthority digestAuthority;
    TestLicensingProvider *const digestProvider =
        configureVerifiedAuthority(
            digestAuthority, identity, digestCounters);
    digestProvider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::UpgradeRequired;
    assert(digestAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'001'100LL, correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    digestProvider->corruptExistingCompletionDigest();
    assert(digestAuthority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(digestAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);

    ProviderCounters zeroGenerationCounters;
    RuntimeLicensingAuthority zeroGenerationAuthority;
    (void)configureVerifiedAuthority(
        zeroGenerationAuthority, identity, zeroGenerationCounters);
    RuntimeLicensingAuthorityTestAccess::forceGeneration(
        zeroGenerationAuthority, 0U);
    assert(zeroGenerationAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'001'200LL, correlation) ==
           RuntimeLicensingExistingCalOperation::Rejected);
    assert(zeroGenerationAuthority.state() ==
           RuntimeLicensingAuthorityState::Revoked);

    ProviderCounters sourceCounters;
    RuntimeLicensingAuthority sourceAuthority;
    TestLicensingProvider *const sourceProvider =
        configureVerifiedAuthority(
            sourceAuthority, identity, sourceCounters);
    sourceProvider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::ValidPermanentNoUpgrade;
    assert(sourceAuthority.beginExistingCalValidation(
               cal, hardwareId, 1'800'001'300LL, correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    assert(sourceAuthority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::DecisionAvailable);
    RuntimeLicensingExistingCalValidationResult sourceResult;
    assert(sourceAuthority.releaseExistingCalValidationResult(
        correlation, sourceResult));

    ProviderCounters replacementCounters;
    RuntimeLicensingAuthority replacementAuthority;
    (void)configureVerifiedAuthority(
        replacementAuthority, identity, replacementCounters);
    RuntimeLicensingAuthorityTestAccess::forceGeneration(
        replacementAuthority, sourceResult.authorityGeneration());
    assert(!replacementAuthority.
        authorizeReleasedExistingCalValidationResult(
            correlation, sourceResult));
}

void testExistingCalResultRetirement()
{
    RdpServerLicenseIdentity identity;
    configureIdentity(identity);
    const std::array<std::uint8_t, 4U> cal{0x30U, 0x02U, 0x55U, 0xaaU};
    const auto hardwareId = makeHardwareId(0x51U);
    const auto correlation = makeCorrelation(0x52U);

    ProviderCounters counters;
    RuntimeLicensingAuthority authority;
    TestLicensingProvider *const provider =
        configureVerifiedAuthority(authority, identity, counters);
    provider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::Denied;
    assert(authority.beginExistingCalValidation(
               cal, hardwareId, 1'800'002'000LL, correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    assert(authority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::DecisionAvailable);

    RuntimeLicensingExistingCalValidationResult deniedResult;
    assert(authority.releaseExistingCalValidationResult(
        correlation, deniedResult));
    assert(deniedResult.configured());
    assert(deniedResult.decision() ==
           RuntimeLicensingExistingCalDecision::Denied);
    assert(authority.authorizeReleasedExistingCalValidationResult(
        correlation, deniedResult));

    RuntimeLicensingExistingCalValidationResult duplicateResult;
    assert(!authority.releaseExistingCalValidationResult(
        correlation, duplicateResult));
    const auto wrongCorrelation = makeCorrelation(0x53U);
    assert(!authority.retireReleasedExistingCalValidationResult(
        wrongCorrelation));
    assert(authority.retireReleasedExistingCalValidationResult(
        correlation));
    assert(!authority.authorizeReleasedExistingCalValidationResult(
        correlation, deniedResult));
    assert(!authority.retireReleasedExistingCalValidationResult(
        correlation));

    provider->existingCalDecision_ =
        RuntimeLicensingExistingCalDecision::UpgradeRequired;
    assert(authority.beginExistingCalValidation(
               cal, hardwareId, 1'800'002'100LL, correlation) ==
           RuntimeLicensingExistingCalOperation::InProgress);
    assert(authority.cancelExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::Cancelled);
    assert(counters.existingCalCancelCalls == 1U);
    assert(authority.pollExistingCalValidation() ==
           RuntimeLicensingExistingCalOperation::Rejected);

    ProviderCounters destructionCounters;
    {
        RuntimeLicensingAuthority pendingAuthority;
        (void)configureVerifiedAuthority(
            pendingAuthority, identity, destructionCounters);
        assert(pendingAuthority.beginExistingCalValidation(
                   cal,
                   hardwareId,
                   1'800'002'200LL,
                   correlation) ==
               RuntimeLicensingExistingCalOperation::InProgress);
    }
    assert(destructionCounters.existingCalCancelCalls == 1U);
    assert(destructionCounters.closeCalls == 1U);
    assert(destructionCounters.destructorCalls == 1U);
}

} // namespace

int main(int argumentCount, char **argumentValues)
{
    if (argumentCount != 2 || argumentValues[1] == nullptr)
        return 2;

    const std::string_view testCase{argumentValues[1]};
    if (testCase == "licensing-authority-unconfigured-denials")
    {
        testUnconfiguredDenials();
        return 0;
    }
    if (testCase == "licensing-authority-issuer-policy-correlation")
    {
        testIssuerPolicyCorrelation();
        return 0;
    }
    if (testCase == "licensing-authority-generation-revocation")
    {
        testGenerationRevocation();
        return 0;
    }
    if (testCase == "licensing-authority-result-bounds-and-cancellation")
    {
        testResultBoundsAndCancellation();
        return 0;
    }
    if (testCase == "licensing-authority-sensitive-retirement")
    {
        testSensitiveRetirement();
        return 0;
    }
    if (testCase == "licensing-existing-cal-provider-unavailable")
    {
        testExistingCalProviderUnavailable();
        return 0;
    }
    if (testCase == "licensing-existing-cal-request-correlation")
    {
        testExistingCalRequestCorrelation();
        return 0;
    }
    if (testCase ==
        "licensing-existing-cal-policy-generation-revocation")
    {
        testExistingCalPolicyGenerationRevocation();
        return 0;
    }
    if (testCase == "licensing-existing-cal-result-retirement")
    {
        testExistingCalResultRetirement();
        return 0;
    }

    std::fprintf(
        stderr, "unknown runtime licensing-authority test case\n");
    return 2;
}
