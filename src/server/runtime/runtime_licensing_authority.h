// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "transport/rdp_licensing.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace rdp_server::server::runtime
{

namespace detail
{
class RuntimeLicensingAuthorityProvider;
}

class RuntimeLicensingAuthorityTestAccess;

inline constexpr std::size_t kRuntimeLicensingAuthorityRequestCorrelationBytes =
    rdp_server::server::transport::
        kRdpExistingClientCalAuthorityRequestCorrelationBytes;
static_assert(kRuntimeLicensingAuthorityRequestCorrelationBytes == 32U);
inline constexpr std::size_t kMaximumRuntimeLicensingIssuerIdentityBytes =
    1024U;
inline constexpr std::size_t kMaximumRuntimeLicensingTrustConfigurationBytes =
    4096U;

enum class RuntimeLicensingAuthorityState : std::uint8_t
{
    NotConfigured,
    NoVerifiedIssuer,
    VerifiedIssuerReady,
    IssuanceDenied,
    IssuanceResultAvailable,
    ExistingCalValidationDenied,
    ExistingCalValidationResultAvailable,
    Revoked,
};

enum class RuntimeLicensingAuthorityOperation : std::uint8_t
{
    InProgress,
    Issued,
    Denied,
    Unavailable,
    Cancelled,
    TimedOut,
    Rejected,
    Failed,
};

enum class RuntimeLicensingExistingCalDecision : std::uint8_t
{
    Denied,
    ValidPermanentNoUpgrade,
    UpgradeRequired,
};

enum class RuntimeLicensingExistingCalOperation : std::uint8_t
{
    InProgress,
    DecisionAvailable,
    Denied,
    Unavailable,
    Cancelled,
    TimedOut,
    Rejected,
    Failed,
};

// One immutable, one-shot decision released by the service authority owner.
// Callers cannot configure this object. Generation/fingerprint/requestDigest
// are correlation facts only; a future R3 consumer must still obtain fresh R2
// authorization and reauthorize the exact released decision through the
// RuntimeLicensingAuthority before changing licensing state.
class RuntimeLicensingExistingCalValidationResult final
{
public:
    RuntimeLicensingExistingCalValidationResult() noexcept = default;
    RuntimeLicensingExistingCalValidationResult(
        const RuntimeLicensingExistingCalValidationResult &) = delete;
    RuntimeLicensingExistingCalValidationResult &operator=(
        const RuntimeLicensingExistingCalValidationResult &) = delete;
    RuntimeLicensingExistingCalValidationResult(
        RuntimeLicensingExistingCalValidationResult &&) = delete;
    RuntimeLicensingExistingCalValidationResult &operator=(
        RuntimeLicensingExistingCalValidationResult &&) = delete;

    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] RuntimeLicensingExistingCalDecision decision() const noexcept
    {
        return decision_;
    }
    [[nodiscard]] std::uint64_t authorityGeneration() const noexcept
    {
        return configured_ ? authorityGeneration_ : 0U;
    }
    [[nodiscard]] std::span<const std::uint8_t>
    authorityFingerprint() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{authorityFingerprint_}
            : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] std::span<const std::uint8_t> requestDigest() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{requestDigest_}
            : std::span<const std::uint8_t>{};
    }

private:
    friend class RuntimeLicensingAuthority;

    [[nodiscard]] bool configure(
        RuntimeLicensingExistingCalDecision decision,
        std::uint64_t authorityGeneration,
        std::span<const std::uint8_t> authorityFingerprint,
        std::span<const std::uint8_t> requestDigest) noexcept;

    std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
        authorityFingerprint_{};
    std::array<std::uint8_t, 32U> requestDigest_{};
    RuntimeLicensingExistingCalDecision decision_{
        RuntimeLicensingExistingCalDecision::Denied};
    std::uint64_t authorityGeneration_{};
    bool attempted_{};
    bool configured_{};
};

// R10 service-owned licensing-authority lifetime. The public production
// configuration deliberately supports only the fail-closed "no verified
// issuer" deployment until a genuine, supportable RD Licensing backend exists.
//
// A positive provider can currently be attached only by the noninstalled test
// fixture through RuntimeLicensingAuthorityTestAccess. There is no runtime
// configuration field, callback, path, directory, CAL blob, Boolean trust
// flag, or public constructor that can turn caller input into issuer authority.
//
// Serialized service event-loop use only. Provider calls are synchronous and
// bounded; this owner creates no thread, retry loop, listener, R2 lease, R3
// session transition, or network publication.
class RuntimeLicensingAuthority final
{
public:
    RuntimeLicensingAuthority() noexcept = default;
    ~RuntimeLicensingAuthority();

    RuntimeLicensingAuthority(const RuntimeLicensingAuthority &) = delete;
    RuntimeLicensingAuthority &operator=(
        const RuntimeLicensingAuthority &) = delete;
    RuntimeLicensingAuthority(RuntimeLicensingAuthority &&) = delete;
    RuntimeLicensingAuthority &operator=(
        RuntimeLicensingAuthority &&) = delete;

    // Explicit production deployment state while no genuine issuer adapter is
    // available. The policy is copied from the immutable R3 server-license
    // identity, but that identity and its RSA key are not treated as a CAL
    // issuer and no authority generation/fingerprint is created.
    [[nodiscard]] bool configureUnavailable(
        const rdp_server::server::transport::RdpServerLicenseIdentity
            &licensingIdentity) noexcept;

    // One bounded request may be outstanding at a time. The 32-byte
    // correlation belongs to the future authorized session/request owner; it
    // is copied and must match again before an issued result can be released.
    // It is correlation only and can never establish issuer authenticity.
    [[nodiscard]] RuntimeLicensingAuthorityOperation beginIssuance(
        rdp_server::server::transport::RdpServerLicenseGrantKind kind,
        std::span<const std::uint8_t> requestCorrelation) noexcept;

    // Poll one provider completion. No background worker or hidden retry is
    // performed. Provider response memory is borrowed only for this call and a
    // successful CAL is copied into bounded owner storage before return.
    [[nodiscard]] RuntimeLicensingAuthorityOperation pollIssuance() noexcept;

    [[nodiscard]] RuntimeLicensingAuthorityOperation
    cancelIssuance() noexcept;

    // Validate one already-presented CLIENT_LICENSE_INFO CAL through the same
    // authenticated provider owner, but as a distinct provider operation.
    // The exact CAL, MAC-verified decrypted HWID, immutable licensing identity,
    // verification time and 32-byte R3 session/request correlation are copied
    // into bounded owner storage before the provider sees them.
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    beginExistingCalValidation(
        std::span<const std::uint8_t> presentedCal,
        std::span<const std::uint8_t> protectedHardwareId,
        std::int64_t verificationUnixSeconds,
        std::span<const std::uint8_t> requestCorrelation) noexcept;
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    pollExistingCalValidation() noexcept;
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    cancelExistingCalValidation() noexcept;

    // Release exactly one provider-authenticated decision. Production
    // configureUnavailable() can never reach this path because it has no
    // provider. A caller-provided generation/fingerprint/digest cannot create
    // a result because RuntimeLicensingExistingCalValidationResult has no
    // public configurator.
    [[nodiscard]] bool releaseExistingCalValidationResult(
        std::span<const std::uint8_t> requestCorrelation,
        RuntimeLicensingExistingCalValidationResult &result) noexcept;
    [[nodiscard]] bool authorizeReleasedExistingCalValidationResult(
        std::span<const std::uint8_t> requestCorrelation,
        const RuntimeLicensingExistingCalValidationResult &result) noexcept;
    [[nodiscard]] bool retireReleasedExistingCalValidationResult(
        std::span<const std::uint8_t> requestCorrelation) noexcept;

    // Release exactly one owned result into R3's existing correlation
    // snapshot. A fresh provider-authentication check must still match the
    // current provider/policy fingerprint. The result remains publication-
    // eligible only until retireReleasedGrant() or revoke().
    [[nodiscard]] bool releaseIssuedGrant(
        std::span<const std::uint8_t> requestCorrelation,
        rdp_server::server::transport::RdpLicensingAuthorityGrant
            &grant) noexcept;

    // Future live R2/R3 composition must call this before each borrowed write
    // slice and accepted-byte completion. A matching generation/fingerprint
    // alone is insufficient: exact CAL digest, grant kind and per-request
    // correlation must also match the one result this owner actually released.
    [[nodiscard]] bool authorizeReleasedGrant(
        std::span<const std::uint8_t> requestCorrelation,
        const rdp_server::server::transport::RdpLicensingAuthorityGrant
            &grant) noexcept;

    [[nodiscard]] bool retireReleasedGrant(
        std::span<const std::uint8_t> requestCorrelation) noexcept;

    void revoke() noexcept;

    [[nodiscard]] RuntimeLicensingAuthorityState state() const noexcept
    {
        return state_;
    }
    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] bool issuerVerified() const noexcept;

private:
    friend class RuntimeLicensingAuthorityTestAccess;

    [[nodiscard]] bool configureVerifiedProvider(
        const rdp_server::server::transport::RdpServerLicenseIdentity
            &licensingIdentity,
        std::unique_ptr<detail::RuntimeLicensingAuthorityProvider>
            provider) noexcept;
    [[nodiscard]] bool capturePolicy(
        const rdp_server::server::transport::RdpServerLicenseIdentity
            &licensingIdentity) noexcept;
    [[nodiscard]] bool generateAuthorityGeneration() noexcept;
    [[nodiscard]] bool refreshProviderAuthentication() noexcept;
    [[nodiscard]] bool providerAuthenticationMatchesCurrent() noexcept;
    [[nodiscard]] bool currentAuthorityValid() const noexcept;
    [[nodiscard]] bool requestCorrelationMatches(
        std::span<const std::uint8_t> requestCorrelation) const noexcept;
    [[nodiscard]] bool releasedCorrelationMatches(
        std::span<const std::uint8_t> requestCorrelation) const noexcept;
    [[nodiscard]] bool computeAuthorityFingerprint(
        std::span<const std::uint8_t> providerIdentity,
        std::span<const std::uint8_t> trustConfiguration,
        std::array<std::uint8_t,
            rdp_server::server::transport::
                kRdpLicensingAuthorityFingerprintBytes>
            &fingerprint) const noexcept;
    [[nodiscard]] static bool computeGrantDigest(
        rdp_server::server::transport::RdpServerLicenseGrantKind kind,
        std::span<const std::uint8_t> issuedCal,
        std::array<std::uint8_t, 32U> &digest) noexcept;
    [[nodiscard]] bool computeExistingCalRequestDigest(
        std::span<const std::uint8_t> presentedCal,
        std::span<const std::uint8_t> protectedHardwareId,
        std::int64_t verificationUnixSeconds,
        std::span<const std::uint8_t> requestCorrelation,
        std::array<std::uint8_t, 32U> &digest) const noexcept;
    void clearPendingResult() noexcept;
    void clearReleasedGrant() noexcept;
    void clearExistingCalInput() noexcept;
    void clearExistingCalRequest() noexcept;
    void clearReleasedExistingCalValidationResult() noexcept;
    void closeProvider() noexcept;
    void failClosed() noexcept;

    std::unique_ptr<detail::RuntimeLicensingAuthorityProvider> provider_{};

    std::array<std::uint8_t,
        rdp_server::server::transport::
            kMaximumRdpServerLicenseIdentityTextBytes>
        companyNameUtf16_{};
    std::array<std::uint8_t,
        rdp_server::server::transport::
            kMaximumRdpServerLicenseIdentityTextBytes>
        productIdUtf16_{};
    std::array<std::uint8_t,
        rdp_server::server::transport::
            kMaximumRdpServerLicenseIdentityTextBytes>
        scopeAnsi_{};
    std::size_t companyNameUtf16Length_{};
    std::size_t productIdUtf16Length_{};
    std::size_t scopeAnsiLength_{};
    std::uint32_t productVersion_{};

    std::array<std::uint8_t,
        rdp_server::server::transport::
            kRdpLicensingAuthorityFingerprintBytes>
        authorityFingerprint_{};
    std::uint64_t authorityGeneration_{};

    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        requestCorrelation_{};
    std::uint64_t requestSequence_{};
    rdp_server::server::transport::RdpServerLicenseGrantKind requestKind_{
        rdp_server::server::transport::RdpServerLicenseGrantKind::NewLicense};

    std::array<std::uint8_t,
        rdp_server::server::transport::kMaximumRdpServerLicenseGrantCalBytes>
        issuedCal_{};
    std::size_t issuedCalLength_{};

    std::array<std::uint8_t,
        rdp_server::server::transport::kMaximumRdpClientCalBytes>
        existingCal_{};
    std::array<std::uint8_t,
        rdp_server::server::transport::kRdpLicensingHardwareIdBytes>
        existingCalHardwareId_{};
    std::array<std::uint8_t, 32U> existingCalRequestDigest_{};
    std::size_t existingCalLength_{};
    std::int64_t existingCalVerificationUnixSeconds_{};
    RuntimeLicensingExistingCalDecision existingCalDecision_{
        RuntimeLicensingExistingCalDecision::Denied};

    std::array<std::uint8_t, 32U> releasedGrantDigest_{};
    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        releasedRequestCorrelation_{};
    rdp_server::server::transport::RdpServerLicenseGrantKind releasedKind_{
        rdp_server::server::transport::RdpServerLicenseGrantKind::NewLicense};

    std::array<std::uint8_t, 32U>
        releasedExistingCalRequestDigest_{};
    std::array<std::uint8_t,
        kRuntimeLicensingAuthorityRequestCorrelationBytes>
        releasedExistingCalRequestCorrelation_{};
    RuntimeLicensingExistingCalDecision releasedExistingCalDecision_{
        RuntimeLicensingExistingCalDecision::Denied};

    RuntimeLicensingAuthorityState state_{
        RuntimeLicensingAuthorityState::NotConfigured};
    bool attempted_{};
    bool configured_{};
    bool requestPending_{};
    bool resultReleased_{};
    bool existingCalValidationPending_{};
    bool existingCalResultReleased_{};
};

} // namespace rdp_server::server::runtime
