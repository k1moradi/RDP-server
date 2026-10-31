// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "native_desktop_authorization.h"

#include <cstdint>

namespace rdp_server::server::transport
{
class OwnedPreauthTcpConnection;
}

namespace rdp_server::server::security
{

enum class MacConsoleAdmissionState : std::uint8_t
{
    Ready,
    Prepared,
    Revoked,
};

enum class MacConsoleAdmissionPrepareResult : std::uint8_t
{
    Prepared,
    InvalidState,
    InvalidPermissions,
    AuthenticationUnavailable,
    ConnectionMismatch,
    NativeAuthorizationUnavailable,
    AuthorizationChanged,
    GenerationExhausted,
};

enum class MacConsoleAdmissionRevocationReason : std::uint8_t
{
    None,
    Explicit,
    AuthenticationLost,
    OwnerStop,
    OwnerConsentReplacement,
    ConnectionExpired,
    NativeSessionChanged,
    ListenerReplacement,
    ProtectedCallbackLostAuthority,
};

// R2-owned macOS admission preparation gateway. It owns one native
// authorization lifetime bound to the exact authenticated proof and accepted
// R1 connection supplied at construction. Prepared is deliberately not an
// R1/R3 admitted state: this first-round owner calls no private R1/R3 positive
// transition. All calls are serialized on the existing host owner thread.
//
// The accepted R1 connection, authenticated proof, native evidence source and
// owner-consent authority are borrowed and MUST outlive this broker. The caller
// must revoke/destroy the broker before tearing down or replacing any of them.
class MacConsoleAdmissionBroker final
{
public:
    MacConsoleAdmissionBroker(
        NativeDesktopAuthenticatedSessionProof &authenticatedSession,
        rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
        MacNativeSessionEvidenceSource &nativeEvidence,
        CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept;
    ~MacConsoleAdmissionBroker();

    MacConsoleAdmissionBroker(const MacConsoleAdmissionBroker &) = delete;
    MacConsoleAdmissionBroker &operator=(const MacConsoleAdmissionBroker &) = delete;
    MacConsoleAdmissionBroker(MacConsoleAdmissionBroker &&) = delete;
    MacConsoleAdmissionBroker &operator=(MacConsoleAdmissionBroker &&) = delete;

    [[nodiscard]] MacConsoleAdmissionPrepareResult prepareAdmission(
        std::uint32_t requestedPermissions) noexcept;
    [[nodiscard]] bool revalidate(
        std::uint32_t requiredPermissions) noexcept;
    [[nodiscard]] bool visitNativeAuthorization(
        std::uint32_t requiredPermissions,
        MacNativeDesktopAuthorizationVisitor visitor,
        void *context) noexcept;

    // Idempotent terminal retirement. A reason describes the R10 composition
    // event but cannot supply or recreate admission authority.
    void revoke(
        MacConsoleAdmissionRevocationReason reason =
            MacConsoleAdmissionRevocationReason::Explicit) noexcept;

    [[nodiscard]] MacConsoleAdmissionState state() const noexcept
    {
        return state_;
    }
    [[nodiscard]] std::uint64_t admissionGeneration() const noexcept
    {
        return state_ == MacConsoleAdmissionState::Prepared
            ? admissionGeneration_
            : 0U;
    }
    [[nodiscard]] MacConsoleAdmissionRevocationReason revocationReason()
        const noexcept
    {
        return revocationReason_;
    }

private:
    struct PreparedLifetime final
    {
        NativeDesktopAuthenticationKind authenticationKind{
            NativeDesktopAuthenticationKind::ExistingOsAccount};
        OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch{};
        std::uint32_t permissionMask{};
        std::uint32_t nativeConsoleUserId{};
        std::uint32_t auditUserId{};
        std::uint64_t auditSessionId{};
        std::uint32_t securitySessionId{};
        std::uint32_t securitySessionAttributes{};
        std::uint64_t authenticationGeneration{};
        std::uint64_t credentialGeneration{};
        std::uint64_t authorizationGeneration{};
    };

    [[nodiscard]] bool authenticatedConnectionCurrent() const noexcept;
    [[nodiscard]] bool preparedAuthenticationCurrent() const noexcept;
    [[nodiscard]] bool viewMatchesPreparedLifetime(
        const MacNativeDesktopAuthorizationView &authorization) const noexcept;
    [[nodiscard]] bool validRequiredPermissions(
        std::uint32_t requiredPermissions) const noexcept;
    void revokeForAuthorityLoss(
        MacConsoleAdmissionRevocationReason reason) noexcept;

    NativeDesktopAuthenticatedSessionProof *authenticatedSession_{};
    rdp_server::server::transport::OwnedPreauthTcpConnection *connection_{};
    MacNativeDesktopAuthorization nativeAuthorization_;
    PreparedLifetime prepared_{};
    std::uint64_t admissionGeneration_{};
    std::uint64_t nextAdmissionGeneration_{};
    MacConsoleAdmissionState state_{MacConsoleAdmissionState::Ready};
    MacConsoleAdmissionRevocationReason revocationReason_{
        MacConsoleAdmissionRevocationReason::None};
    bool visitInProgress_{};
};

} // namespace rdp_server::server::security
