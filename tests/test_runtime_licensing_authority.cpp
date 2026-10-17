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
using rdp_server::server::runtime::RuntimeLicensingAuthorityTestAccess;
using rdp_server::server::runtime::
    kRuntimeLicensingAuthorityRequestCorrelationBytes;
using rdp_server::server::runtime::detail::
    RuntimeLicensingAuthorityProvider;
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
using rdp_server::server::transport::
    kMaximumRdpServerLicenseGrantCalBytes;
using rdp_server::server::transport::
    kRdpLicensingAuthorityFingerprintBytes;

struct ProviderCounters
{
    std::size_t verificationCalls{};
    std::size_t beginCalls{};
    std::size_t pollCalls{};
    std::size_t cancelCalls{};
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

    std::fprintf(
        stderr, "unknown runtime licensing-authority test case\n");
    return 2;
}
