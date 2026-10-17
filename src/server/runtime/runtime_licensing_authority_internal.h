// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "runtime_licensing_authority.h"

#include <cstdint>
#include <span>

namespace rdp_server::server::runtime::detail
{

enum class RuntimeLicensingProviderVerificationStatus : std::uint8_t
{
    Verified,
    Unavailable,
    MissingIdentity,
    MissingTrustConfiguration,
    AuthenticationFailed,
};

struct RuntimeLicensingProviderVerificationView
{
    RuntimeLicensingProviderVerificationStatus status{
        RuntimeLicensingProviderVerificationStatus::Unavailable};
    std::span<const std::uint8_t> providerIdentity{};
    std::span<const std::uint8_t> trustConfiguration{};
};

enum class RuntimeLicensingProviderBeginStatus : std::uint8_t
{
    Accepted,
    Denied,
    Unavailable,
    Failed,
};

enum class RuntimeLicensingProviderCompletionStatus : std::uint8_t
{
    Pending,
    Issued,
    Denied,
    Cancelled,
    TimedOut,
    Incomplete,
    UnexpectedResult,
    Unavailable,
    Failed,
};

struct RuntimeLicensingProviderRequestView
{
    rdp_server::server::transport::RdpServerLicenseGrantKind kind{
        rdp_server::server::transport::RdpServerLicenseGrantKind::NewLicense};
    std::uint64_t requestSequence{};
    std::uint64_t authorityGeneration{};
    std::span<const std::uint8_t> authorityFingerprint{};
    std::span<const std::uint8_t> requestCorrelation{};
    std::uint32_t productVersion{};
    std::span<const std::uint8_t> companyNameUtf16{};
    std::span<const std::uint8_t> productIdUtf16{};
    std::span<const std::uint8_t> scopeAnsi{};
};

struct RuntimeLicensingProviderCompletionView
{
    RuntimeLicensingProviderCompletionStatus status{
        RuntimeLicensingProviderCompletionStatus::Pending};
    rdp_server::server::transport::RdpServerLicenseGrantKind kind{
        rdp_server::server::transport::RdpServerLicenseGrantKind::NewLicense};
    std::uint64_t requestSequence{};
    std::span<const std::uint8_t> requestCorrelation{};
    std::span<const std::uint8_t> providerIdentity{};
    std::span<const std::uint8_t> trustConfiguration{};
    std::span<const std::uint8_t> issuedCal{};
};

// Runtime-internal provider contract. No production implementation exists yet.
// The sole current implementation lives in the test executable and is never
// linked into rdp-server. A future real adapter must authenticate a supported
// RD Licensing backend before returning Verified and must own/cancel/close all
// native provider handles behind this interface.
class RuntimeLicensingAuthorityProvider
{
public:
    virtual ~RuntimeLicensingAuthorityProvider() = default;

    [[nodiscard]] virtual RuntimeLicensingProviderVerificationView
    verification() noexcept = 0;
    [[nodiscard]] virtual RuntimeLicensingProviderBeginStatus begin(
        const RuntimeLicensingProviderRequestView &request) noexcept = 0;
    [[nodiscard]] virtual RuntimeLicensingProviderCompletionView
    poll() noexcept = 0;
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;
};

} // namespace rdp_server::server::runtime::detail
