// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/security/console_identity_policy.h"
#include "server/security/console_os_evidence.h"
#include "server/security/gssapi_spnego_acceptor.h"
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
#include "server/security/linux_pam_password_verifier.h"
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace rdp_server::server::runtime
{

class RuntimeConfigurationView;
class RuntimeDeploymentPolicy;

// Non-secret pre-listener R2 facts. This is deliberately not an admission
// capability: authenticatedAdmission is false because only a live, TLS-bound
// per-client CredSSP/GSS exchange followed by PAM/NSS/logind admission can
// produce the private LinuxConsoleAdmissionLease.
struct LinuxRuntimeSecurityPreflightVerdict final
{
    bool gssAcceptorCredentialAvailable{};
    bool pamServiceConfigured{};
    bool identityPolicyConfigured{};
    bool personalDesktopPolicyConfigured{};
    bool nativeSessionEvidenceAvailable{};
    bool authenticatedAdmission{};

    [[nodiscard]] bool readyForAuthenticatedAdmissionAttempt() const noexcept
    {
        return gssAcceptorCredentialAvailable && pamServiceConfigured &&
               identityPolicyConfigured && personalDesktopPolicyConfigured &&
               nativeSessionEvidenceAvailable && !authenticatedAdmission;
    }
};

// Linux-only pre-listener security provisioning. The object owns one sealed,
// anonymous snapshot of the securely opened keytab plus the R2 identity policy.
// Service identity, keytab and PAM provider are immutable after provisioning;
// the authorized OS-account rule may be explicitly replaced/revoked through
// the generation-fenced lifecycle below. It does not own a connection, TLS,
// GSS context or R3 session. Keep it alive for every GssapiSpnegoAcceptor
// configured from it so
// FILE:/proc/self/fd/<n> continues to identify the exact immutable snapshot
// accepted during startup.
//
// All methods are externally serialized. Configuration is one-shot: a failed
// attempt cannot be retried on the same object, and successful configuration
// cannot be mutated in place. This prevents policy/keytab replacement under
// active connections.
class LinuxRuntimeSecurityConfiguration final
{
public:
    LinuxRuntimeSecurityConfiguration() noexcept = default;
    ~LinuxRuntimeSecurityConfiguration();

    LinuxRuntimeSecurityConfiguration(
        const LinuxRuntimeSecurityConfiguration &) = delete;
    LinuxRuntimeSecurityConfiguration &operator=(
        const LinuxRuntimeSecurityConfiguration &) = delete;
    LinuxRuntimeSecurityConfiguration(
        LinuxRuntimeSecurityConfiguration &&) = delete;
    LinuxRuntimeSecurityConfiguration &operator=(
        LinuxRuntimeSecurityConfiguration &&) = delete;

    // keytabUri must be an explicit FILE:/ absolute path. The opened object
    // must be a nonempty bounded regular file, owned by the current effective
    // uid, owner-readable, and inaccessible to group/other. Parent/final
    // symlinks and . / .. components are rejected. The bounded contents are
    // copied into an anonymous memfd and sealed against write/grow/shrink
    // before any credential is exposed. A temporary R2 acceptor then proves
    // that MIT GSS can acquire the exact requested TERMSRV credential through
    // this sealed descriptor. No KDC or client ticket is contacted/required.
    //
    // The rule is validated by the existing R2 ConsoleIdentityPolicy. Success
    // therefore prepares one explicit service identity and one native mapping,
    // but does not authenticate a user or authorize any session.
    [[nodiscard]] bool configure(
        std::string_view servicePrincipal,
        std::string_view keytabUri,
        const rdp_server::server::security::ConsoleIdentityRuleInput &rule)
        noexcept;

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    // Opt-in R2 password verification is provisioned by the same immutable
    // service owner. No default PAM service is selected. This only binds the
    // verifier to per-connection acceptors; it does not complete CredSSP or
    // grant native/R3 admission.
    [[nodiscard]] bool configure(
        std::string_view servicePrincipal,
        std::string_view keytabUri,
        const rdp_server::server::security::ConsoleIdentityRuleInput &rule,
        std::string_view pamServiceName) noexcept;
#endif

    // Replace the sole GUI-selected existing OS account mapping without
    // changing the service keytab, PAM provider or any OS password. Success
    // publishes a fresh policy generation, invalidating old R2 acceptors and
    // leases through their existing generation checks. No positive admission
    // or host consent is created by this call.
    // Consumer StandalonePassword mode has no Kerberos/keytab/PAM
    // prerequisite. This creates only the native-account/session selector
    // consumed after exact TLS-bound standalone authentication.
    [[nodiscard]] bool configureStandalonePersonalDesktop(
        const rdp_server::server::security::ConsoleIdentityRuleInput &rule)
        noexcept;

    [[nodiscard]] bool replaceAuthorizedIdentity(
        const rdp_server::server::security::ConsoleIdentityRuleInput &rule)
        noexcept;

    // Revoke configured access and publish a new generation. Existing
    // admissions become stale and new acceptors are refused until a valid
    // identity is explicitly installed again. This call stores no secret.
    [[nodiscard]] bool revokeAuthorizedIdentity() noexcept;

    // Configure one existing per-connection R2 acceptor from the retained
    // sealed keytab snapshot. The configuration object must outlive it.
    // False is terminal for the supplied acceptor.
    [[nodiscard]] bool configureAcceptor(
        rdp_server::server::security::GssapiSpnegoAcceptor &acceptor)
        const noexcept;

    // Samples genuine NSS/logind evidence for the configured policy and the
    // exact PersonalDesktop deployment object. It never authenticates a user,
    // starts a listener, opens X11 or creates an admission generation.
    [[nodiscard]] LinuxRuntimeSecurityPreflightVerdict
    preflightPersonalDesktopAdmission(
        const RuntimeDeploymentPolicy &deploymentPolicy,
        const rdp_server::server::security::ConsoleEvidenceRequest &request)
        const noexcept;

    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] std::string_view servicePrincipal() const noexcept;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    [[nodiscard]] std::string_view pamServiceName() const noexcept;
#endif
    [[nodiscard]]
    const rdp_server::server::security::ConsoleIdentityPolicy *policy()
        const noexcept;

private:
    [[nodiscard]] bool configureInternal(
        std::string_view servicePrincipal,
        std::string_view keytabUri,
        const rdp_server::server::security::ConsoleIdentityRuleInput &rule,
        std::string_view pamServiceName,
        bool requirePamVerifier) noexcept;
    void closeKeytab() noexcept;
    void clearServicePrincipal() noexcept;

    std::array<char, 513> servicePrincipal_{};
    std::size_t servicePrincipalLength_{};
    rdp_server::server::security::ConsoleIdentityPolicy policy_{};
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    rdp_server::server::security::LinuxPamPasswordVerifier passwordVerifier_{};
#endif
    int keytabDescriptor_{-1};
    bool attempted_{};
    bool configured_{};
};

// Service-lifetime owned copy of the non-secret R2 admission selector from the
// validated configuration callback. Returned request string_views borrow this
// object and are valid only while the exact security policy generation remains
// current. Policy replacement/revocation invalidates the snapshot.
class LinuxRuntimeAdmissionConfiguration final
{
public:
    LinuxRuntimeAdmissionConfiguration() noexcept = default;
    LinuxRuntimeAdmissionConfiguration(
        const LinuxRuntimeAdmissionConfiguration&) = delete;
    LinuxRuntimeAdmissionConfiguration& operator=(
        const LinuxRuntimeAdmissionConfiguration&) = delete;
    LinuxRuntimeAdmissionConfiguration(
        LinuxRuntimeAdmissionConfiguration&&) = delete;
    LinuxRuntimeAdmissionConfiguration& operator=(
        LinuxRuntimeAdmissionConfiguration&&) = delete;

    [[nodiscard]] bool configureFromConfiguration(
        const RuntimeConfigurationView& configuration,
        const LinuxRuntimeSecurityConfiguration& securityConfiguration)
        noexcept;

    [[nodiscard]] bool configureStandalonePersonalDesktop(
        const rdp_server::server::security::ConsoleIdentityRuleInput& rule,
        const LinuxRuntimeSecurityConfiguration& securityConfiguration)
        noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::security::ConsoleEvidenceRequest>
    request(
        const LinuxRuntimeSecurityConfiguration& securityConfiguration)
        const noexcept;

    [[nodiscard]] std::optional<
        rdp_server::server::security::ConsoleEvidenceRequest>
    request(
        const LinuxRuntimeSecurityConfiguration& securityConfiguration,
        rdp_server::server::security::ConsoleEvidenceAuthenticationKind
            authenticationKind) const noexcept;

private:
    std::array<char, 129> kerberosPrincipal_{};
    std::array<char, 33> unixAccount_{};
    std::array<char, 17> seat_{};
    std::array<char, 9> display_{};
    std::size_t kerberosPrincipalLength_{};
    std::size_t unixAccountLength_{};
    std::size_t seatLength_{};
    std::size_t displayLength_{};
    std::uint32_t permissions_{};
    const rdp_server::server::security::ConsoleIdentityPolicy* policy_{};
    std::uint64_t policyGeneration_{};
    bool attempted_{};
    bool configured_{};
};

[[nodiscard]] bool configureLinuxRuntimeSecurityFromConfiguration(
    const RuntimeConfigurationView& configuration,
    LinuxRuntimeSecurityConfiguration& linuxSecurity) noexcept;

[[nodiscard]] bool configureLinuxRuntimeAdmissionFromConfiguration(
    const RuntimeConfigurationView& configuration,
    const LinuxRuntimeSecurityConfiguration& linuxSecurity,
    LinuxRuntimeAdmissionConfiguration& admissionConfiguration) noexcept;

} // namespace rdp_server::server::runtime
