// SPDX-License-Identifier: GPL-3.0-or-later

#include "generated_tls_certificate_test_fixture.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <cstdio>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
using namespace rdp_server::tests;

constexpr std::string_view kEndpoint{"192.168.1.5"};

template <typename Reference>
class CfOwner final
{
public:
    CfOwner() noexcept = default;
    explicit CfOwner(Reference reference) noexcept : reference_(reference) {}

    ~CfOwner()
    {
        if (reference_ != nullptr)
            CFRelease(reference_);
    }

    CfOwner(const CfOwner &) = delete;
    CfOwner &operator=(const CfOwner &) = delete;

    CfOwner(CfOwner &&other) noexcept
        : reference_(std::exchange(other.reference_, nullptr))
    {
    }

    CfOwner &operator=(CfOwner &&other) noexcept
    {
        if (this == &other)
            return *this;
        if (reference_ != nullptr)
            CFRelease(reference_);
        reference_ = std::exchange(other.reference_, nullptr);
        return *this;
    }

    [[nodiscard]] Reference get() const noexcept
    {
        return reference_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return reference_ != nullptr;
    }

private:
    Reference reference_{};
};

struct TrustEvaluation final
{
    bool setupSucceeded{};
    bool accepted{};
    OSStatus setupStatus{errSecSuccess};
    CFIndex policyError{};
};

[[nodiscard]] CfOwner<SecCertificateRef> createCertificate(
    std::span<const unsigned char> der) noexcept
{
    if (der.empty())
        return {};

    CfOwner<CFDataRef> data{
        CFDataCreate(
            kCFAllocatorDefault,
            der.data(),
            static_cast<CFIndex>(der.size()))};
    if (!data)
        return {};

    return CfOwner<SecCertificateRef>{
        SecCertificateCreateWithData(
            kCFAllocatorDefault, data.get())};
}

[[nodiscard]] CfOwner<CFStringRef> createEndpointName() noexcept
{
    return CfOwner<CFStringRef>{
        CFStringCreateWithBytes(
            kCFAllocatorDefault,
            reinterpret_cast<const UInt8 *>(kEndpoint.data()),
            static_cast<CFIndex>(kEndpoint.size()),
            kCFStringEncodingASCII,
            false)};
}

[[nodiscard]] TrustEvaluation evaluateServerPolicy(
    SecCertificateRef certificate,
    CFStringRef hostname) noexcept
{
    TrustEvaluation result{};
    if (certificate == nullptr)
    {
        result.setupStatus = errSecParam;
        return result;
    }

    CfOwner<SecPolicyRef> policy{
        SecPolicyCreateSSL(true, hostname)};
    if (!policy)
    {
        result.setupStatus = errSecAllocate;
        return result;
    }

    SecTrustRef rawTrust = nullptr;
    result.setupStatus =
        SecTrustCreateWithCertificates(
            certificate, policy.get(), &rawTrust);
    CfOwner<SecTrustRef> trust{rawTrust};
    if (result.setupStatus != errSecSuccess || !trust)
        return result;

    const void *anchorValues[]{certificate};
    CfOwner<CFArrayRef> anchors{
        CFArrayCreate(
            kCFAllocatorDefault,
            anchorValues,
            1,
            &kCFTypeArrayCallBacks)};
    if (!anchors)
    {
        result.setupStatus = errSecAllocate;
        return result;
    }

    result.setupStatus =
        SecTrustSetAnchorCertificates(trust.get(), anchors.get());
    if (result.setupStatus != errSecSuccess)
        return result;

    result.setupStatus =
        SecTrustSetAnchorCertificatesOnly(trust.get(), true);
    if (result.setupStatus != errSecSuccess)
        return result;

    result.setupStatus =
        SecTrustSetNetworkFetchAllowed(trust.get(), false);
    if (result.setupStatus != errSecSuccess)
        return result;

    CFErrorRef rawError = nullptr;
    result.accepted =
        SecTrustEvaluateWithError(trust.get(), &rawError);
    CfOwner<CFErrorRef> error{rawError};
    result.policyError =
        error ? CFErrorGetCode(error.get()) : 0;
    result.setupSucceeded = true;
    return result;
}

struct CertificatePolicyObservation final
{
    bool setupSucceeded{};
    bool trustedForServerUse{};
    bool hostnameMatches{};
    OSStatus setupStatus{errSecSuccess};
    CFIndex policyError{};
};

[[nodiscard]] CertificatePolicyObservation evaluateCertificate(
    std::span<const unsigned char> der) noexcept
{
    CertificatePolicyObservation result{};
    auto certificate = createCertificate(der);
    if (!certificate)
    {
        result.setupStatus = errSecDecode;
        return result;
    }

    const TrustEvaluation trustOnly =
        evaluateServerPolicy(certificate.get(), nullptr);
    auto endpointName = createEndpointName();
    if (!endpointName)
    {
        result.setupStatus = errSecAllocate;
        return result;
    }
    const TrustEvaluation named =
        evaluateServerPolicy(certificate.get(), endpointName.get());

    result.setupSucceeded =
        trustOnly.setupSucceeded && named.setupSucceeded;
    result.trustedForServerUse = trustOnly.accepted;
    result.hostnameMatches = named.accepted;
    result.setupStatus =
        trustOnly.setupStatus != errSecSuccess
            ? trustOnly.setupStatus
            : named.setupStatus;
    result.policyError = named.policyError;
    return result;
}

void printObservation(
    const char *profile,
    const CertificatePolicyObservation &observation) noexcept
{
    std::fprintf(
        stderr,
        "macos-certificate-policy profile=%s endpoint=192.168.1.5 "
        "trust-result=%s hostname-result=%s policy-error=%ld "
        "setup-status=%d custom-anchor=in-memory-only\n",
        profile,
        observation.trustedForServerUse ? "trusted" : "not-trusted",
        observation.hostnameMatches ? "match" : "mismatch",
        static_cast<long>(observation.policyError),
        static_cast<int>(observation.setupStatus));
}

[[nodiscard]] bool accepted(
    const CertificatePolicyObservation &observation) noexcept
{
    return observation.setupSucceeded &&
           observation.trustedForServerUse &&
           observation.hostnameMatches &&
           observation.setupStatus == errSecSuccess &&
           observation.policyError == 0;
}

} // namespace

int main()
{
    const auto productionCertificate =
        productionGeneratedCertificateDer(kEndpoint);
    const auto endpointCommonNameCertificate =
        endpointCommonNameCertificateDer(kEndpoint);
    if (productionCertificate.empty() ||
        endpointCommonNameCertificate.empty())
    {
        return 1;
    }

    const auto production =
        evaluateCertificate(productionCertificate);
    const auto endpointCommonName =
        evaluateCertificate(endpointCommonNameCertificate);

    printObservation("current-cn-rdp-server-ip-san", production);
    printObservation("test-endpoint-cn-ip-san", endpointCommonName);

    const char *const differential =
        production.trustedForServerUse &&
        !production.hostnameMatches &&
        endpointCommonName.hostnameMatches
            ? "endpoint-cn-name-required"
            : production.hostnameMatches
                ? "generic-cn-not-name-defect"
                : "indeterminate";
    std::fprintf(
        stderr,
        "macos-certificate-policy differential=%s "
        "production-certificate-change-authorized=no\n",
        differential);

    return accepted(production) && accepted(endpointCommonName)
        ? 0
        : 1;
}
