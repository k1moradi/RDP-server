// SPDX-License-Identifier: GPL-3.0-or-later
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#include "generated_tls_certificate_test_fixture.h"

#include <cstdio>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

namespace
{
using namespace rdp_server::tests;

constexpr std::string_view kEndpoint{"192.168.1.5"};

class CertificatePolicyResources final
{
public:
    CertificatePolicyResources() noexcept = default;
    ~CertificatePolicyResources()
    {
        if (chain_ != nullptr)
            CertFreeCertificateChain(chain_);
        if (chainEngine_ != nullptr)
            CertFreeCertificateChainEngine(chainEngine_);
        if (certificate_ != nullptr)
            CertFreeCertificateContext(certificate_);
        if (anchorStore_ != nullptr)
            CertCloseStore(anchorStore_, 0U);
    }

    CertificatePolicyResources(
        const CertificatePolicyResources &) = delete;
    CertificatePolicyResources &operator=(
        const CertificatePolicyResources &) = delete;
    CertificatePolicyResources(
        CertificatePolicyResources &&) = delete;
    CertificatePolicyResources &operator=(
        CertificatePolicyResources &&) = delete;

    HCERTSTORE anchorStore_{};
    HCERTCHAINENGINE chainEngine_{};
    PCCERT_CONTEXT certificate_{};
    PCCERT_CHAIN_CONTEXT chain_{};
};

struct CertificatePolicyObservation final
{
    bool setupSucceeded{};
    bool trustedUnderTestAnchor{};
    bool nameMatches{};
    bool purposeMatches{};
    bool timeValid{};
    DWORD chainErrorStatus{};
    DWORD chainInfoStatus{};
    DWORD policyError{};
    DWORD setupError{};
};

[[nodiscard]] CertificatePolicyObservation evaluateCertificate(
    std::span<const unsigned char> der) noexcept
{
    CertificatePolicyObservation result{};
    if (der.empty() ||
        der.size() >
            static_cast<std::size_t>(
                (std::numeric_limits<DWORD>::max)()))
    {
        result.setupError = ERROR_INVALID_DATA;
        return result;
    }

    CertificatePolicyResources resources;
    resources.certificate_ =
        CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(),
            static_cast<DWORD>(der.size()));
    if (resources.certificate_ == nullptr)
    {
        result.setupError = GetLastError();
        return result;
    }

    resources.anchorStore_ =
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            X509_ASN_ENCODING,
            0,
            CERT_STORE_CREATE_NEW_FLAG,
            nullptr);
    if (resources.anchorStore_ == nullptr)
    {
        result.setupError = GetLastError();
        return result;
    }

    if (!CertAddCertificateContextToStore(
            resources.anchorStore_,
            resources.certificate_,
            CERT_STORE_ADD_ALWAYS,
            nullptr))
    {
        result.setupError = GetLastError();
        return result;
    }

    CERT_CHAIN_ENGINE_CONFIG engineConfiguration{};
    engineConfiguration.cbSize = sizeof(engineConfiguration);
    engineConfiguration.hExclusiveTrustedPeople =
        resources.anchorStore_;
    engineConfiguration.dwFlags =
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL |
        CERT_CHAIN_DISABLE_AIA;
    if (!CertCreateCertificateChainEngine(
            &engineConfiguration,
            &resources.chainEngine_))
    {
        result.setupError = GetLastError();
        return result;
    }

    char serverAuthenticationOid[] = szOID_PKIX_KP_SERVER_AUTH;
    LPSTR usageIdentifiers[]{serverAuthenticationOid};
    CERT_CHAIN_PARA chainParameters{};
    chainParameters.cbSize = sizeof(chainParameters);
    chainParameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    chainParameters.RequestedUsage.Usage.cUsageIdentifier = 1U;
    chainParameters.RequestedUsage.Usage.rgpszUsageIdentifier =
        usageIdentifiers;

    constexpr DWORD kChainFlags =
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL |
        CERT_CHAIN_DISABLE_AIA |
        CERT_CHAIN_ENABLE_PEER_TRUST;
    if (!CertGetCertificateChain(
            resources.chainEngine_,
            resources.certificate_,
            nullptr,
            resources.anchorStore_,
            &chainParameters,
            kChainFlags,
            nullptr,
            &resources.chain_))
    {
        result.setupError = GetLastError();
        return result;
    }

    result.chainErrorStatus =
        resources.chain_->TrustStatus.dwErrorStatus;
    result.chainInfoStatus =
        resources.chain_->TrustStatus.dwInfoStatus;
    result.purposeMatches =
        (result.chainErrorStatus &
         CERT_TRUST_IS_NOT_VALID_FOR_USAGE) == 0U;
    result.timeValid =
        (result.chainErrorStatus &
         CERT_TRUST_IS_NOT_TIME_VALID) == 0U;

    DWORD leafInfoStatus = 0U;
    if (resources.chain_->cChain != 0U &&
        resources.chain_->rgpChain[0] != nullptr &&
        resources.chain_->rgpChain[0]->cElement != 0U &&
        resources.chain_->rgpChain[0]->rgpElement[0] != nullptr)
    {
        leafInfoStatus =
            resources.chain_->rgpChain[0]
                ->rgpElement[0]
                ->TrustStatus.dwInfoStatus;
    }
    const bool fromApplicationTrust =
        (leafInfoStatus &
         (CERT_TRUST_IS_PEER_TRUSTED |
          CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE)) != 0U;
    constexpr DWORD kTrustFailureMask =
        CERT_TRUST_IS_UNTRUSTED_ROOT |
        CERT_TRUST_IS_PARTIAL_CHAIN |
        CERT_TRUST_IS_NOT_SIGNATURE_VALID |
        CERT_TRUST_IS_REVOKED |
        CERT_TRUST_IS_EXPLICIT_DISTRUST;
    result.trustedUnderTestAnchor =
        fromApplicationTrust &&
        (result.chainErrorStatus & kTrustFailureMask) == 0U;

    SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslPolicy{};
    sslPolicy.cbSize = sizeof(sslPolicy);
    sslPolicy.dwAuthType = AUTHTYPE_SERVER;
    sslPolicy.fdwChecks = 0U;
    wchar_t endpointName[] = L"192.168.1.5";
    sslPolicy.pwszServerName = endpointName;

    CERT_CHAIN_POLICY_PARA policyParameters{};
    policyParameters.cbSize = sizeof(policyParameters);
    policyParameters.pvExtraPolicyPara = &sslPolicy;

    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);
    if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            resources.chain_,
            &policyParameters,
            &policyStatus))
    {
        result.setupError = GetLastError();
        return result;
    }

    result.policyError = policyStatus.dwError;
    result.nameMatches =
        policyStatus.dwError == ERROR_SUCCESS;
    result.setupSucceeded = true;
    return result;
}

void printObservation(
    const char *profile,
    const CertificatePolicyObservation &observation) noexcept
{
    std::fprintf(
        stderr,
        "windows-certificate-policy profile=%s endpoint=192.168.1.5 "
        "trusted-under-test-anchor=%s name-match=%s purpose-match=%s "
        "time-valid=%s chain-errors=0x%08lx chain-info=0x%08lx "
        "policy-error=0x%08lx setup-error=0x%08lx "
        "custom-anchor=exclusive-memory-store\n",
        profile,
        observation.trustedUnderTestAnchor ? "yes" : "no",
        observation.nameMatches ? "yes" : "no",
        observation.purposeMatches ? "yes" : "no",
        observation.timeValid ? "yes" : "no",
        static_cast<unsigned long>(observation.chainErrorStatus),
        static_cast<unsigned long>(observation.chainInfoStatus),
        static_cast<unsigned long>(observation.policyError),
        static_cast<unsigned long>(observation.setupError));
}

[[nodiscard]] bool accepted(
    const CertificatePolicyObservation &observation) noexcept
{
    return observation.setupSucceeded &&
           observation.trustedUnderTestAnchor &&
           observation.nameMatches &&
           observation.purposeMatches &&
           observation.timeValid &&
           observation.chainErrorStatus == CERT_TRUST_NO_ERROR &&
           observation.policyError == ERROR_SUCCESS &&
           observation.setupError == ERROR_SUCCESS;
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
        production.trustedUnderTestAnchor &&
        !production.nameMatches &&
        endpointCommonName.nameMatches
            ? "endpoint-cn-name-required"
            : production.nameMatches
                ? "generic-cn-not-name-defect"
                : "indeterminate";
    std::fprintf(
        stderr,
        "windows-certificate-policy differential=%s "
        "production-certificate-change-authorized=no\n",
        differential);

    return accepted(production) && accepted(endpointCommonName)
        ? 0
        : 1;
}
