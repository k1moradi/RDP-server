// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"

#include <cstdint>

#include <openssl/ssl.h>

namespace rdp_server::server::transport
{
class OwnedPreauthTcpConnection;
}

namespace rdp_server::server::security
{

// R2-owned authentication proof boundary used by the one Linux native
// admission broker. Implementations prove one already-completed authentication
// mechanism; they do not own native NSS/logind evidence, owner consent, the
// admission lease, or R3 authorization.
//
// All methods are synchronous and allocation-free at this interface. The exact
// R1 connection/TLS owner and policy generation are supplied by the broker;
// implementations must fail closed on stale/substituted provenance.
class LinuxAuthenticatedPrincipalProof
{
public:
    virtual ~LinuxAuthenticatedPrincipalProof() = default;
    LinuxAuthenticatedPrincipalProof() = default;
    LinuxAuthenticatedPrincipalProof(
        const LinuxAuthenticatedPrincipalProof &) = delete;
    LinuxAuthenticatedPrincipalProof &operator=(
        const LinuxAuthenticatedPrincipalProof &) = delete;

    [[nodiscard]] virtual bool pendingNativeAdmissionMatches(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) const noexcept = 0;

    [[nodiscard]] virtual bool completeNativeAdmission(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) noexcept = 0;

    [[nodiscard]] virtual bool revalidatesNativeAdmission(
        const SSL *activeServerTls,
        const ConsoleEvidenceRequest &request,
        std::uint64_t policyGeneration) const noexcept = 0;

    virtual void revokeAuthenticatedProof() noexcept = 0;
};

} // namespace rdp_server::server::security
