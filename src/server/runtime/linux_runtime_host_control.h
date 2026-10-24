// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "server/runtime/runtime_deployment_policy.h"
#include "server/runtime/runtime_host_control.h"
#include "server/runtime/runtime_tls_context.h"
#include "server/security/authentication_attempt_limiter.h"
#include "server/security/current_owner_sharing_authority.h"
#include "server/security/linux_logind_console_evidence.h"
#include "server/security/standalone_ntlmv2.h"
#include "server/transport/lan_listener.h"
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>

namespace rdp_server::server::runtime
{

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
class LinuxRuntimeSecurityConfiguration;
class LinuxRuntimeAdmissionConfiguration;
class LinuxRuntimeConnection;
struct LinuxRuntimeAuthenticationSelection;
#endif
class RuntimeLicensingContext;
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
struct LinuxHostNativeDesktopState;
#endif

// Parse the GUI stable name#index into the CURRENT native name used by R1.
// Returned string_view borrows stableId; this is not listener authority.
struct LinuxNativeLanInterfaceIdentity
{
    std::string_view nativeName;
    unsigned int nativeIndex{};
};
[[nodiscard]] std::optional<LinuxNativeLanInterfaceIdentity>
resolveCurrentLinuxNativeLanInterface(std::string_view stableId) noexcept;

struct LinuxRuntimeDefaultRoutePreference final
{
    std::string interfaceId;
    RuntimeHostAddressFamily family{RuntimeHostAddressFamily::Unspecified};
    std::uint32_t metric{};
};

// Recommendation-only production seam. It opens no socket and confers no R1
// bind authority; tests inject route facts here without reading host routing.
[[nodiscard]] RuntimeHostRecommendedEndpoint
recommendLinuxPrivateLanEndpoint(
    const std::vector<RuntimeHostInterface>& interfaces,
    std::span<const LinuxRuntimeDefaultRoutePreference> defaultRoutes,
    std::uint16_t port = kRuntimeDefaultListenPort);

// One serialized R10 Linux GUI facade. No owned socket may be opened before
// independent R2 host-owner consent and R1 certificate-identity verification.
// Qt status/options never confer authority. All calls use construction thread.
class LinuxRuntimeHostControl final : public RuntimeHostControl
{
public:
    LinuxRuntimeHostControl() noexcept;
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    // Borrow the already-validated service-lifetime R2/TLS owners. They must
    // outlive this controller and every connection later created from it.
    LinuxRuntimeHostControl(
        LinuxRuntimeSecurityConfiguration& securityConfiguration,
        const RuntimeServerTlsContext& tlsContext,
        const LinuxRuntimeAdmissionConfiguration& admissionConfiguration,
        const RuntimeLicensingContext& licensingContext) noexcept;
#endif
    ~LinuxRuntimeHostControl() override;
    LinuxRuntimeHostControl(const LinuxRuntimeHostControl&) = delete;
    LinuxRuntimeHostControl& operator=(const LinuxRuntimeHostControl&) = delete;
    LinuxRuntimeHostControl(LinuxRuntimeHostControl&&) = delete;
    LinuxRuntimeHostControl& operator=(LinuxRuntimeHostControl&&) = delete;

    [[nodiscard]] std::vector<RuntimeHostInterface>
    enumerateLocalInterfaces() const override;
    [[nodiscard]] RuntimeHostStatus status() const override;
    [[nodiscard]] RuntimeHostResult configure(
        const RuntimeHostOptions& options) override;
    [[nodiscard]] RuntimeHostResult requestCredentialSetup(
        rdp_server::server::security::LanCredentialChoice choice) override;

    // Internal R2P service-lifetime preparation seam. It consumes/scrubs the
    // mutable password and retains only the bounded username/NT hash. A valid
    // configuration selects the standalone mode for this R10 owner, but the
    // public GUI still exposes no IndependentApplicationPassword action.
    [[nodiscard]] bool configureStandaloneApplicationPassword(
        std::u16string_view username,
        std::span<char16_t> password) noexcept;
    [[nodiscard]]
    rdp_server::server::security::StandalonePasswordCredentialObservation
    standaloneApplicationPasswordObservation() const noexcept;
    [[nodiscard]] bool visitStandaloneApplicationPassword(
        std::uint64_t expectedGeneration,
        rdp_server::server::security::StandalonePasswordCredentialVisitor
            visitor,
        void* context) const noexcept;

    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& request = {}) override;
    [[nodiscard]] RuntimeHostResult startSharing() override;

    // Advance at most one accepted-client/native operation plus zero-wait
    // readiness observations on the owner thread. This never blocks Qt and
    // never creates a second socket/TLS/X11 owner.
    [[nodiscard]] RuntimeHostResult serviceOnce() noexcept;

    [[nodiscard]] RuntimeHostResult stopSharing() override;
    [[nodiscard]] RuntimeHostResult disconnectClient(
        std::uint64_t opaqueClientId) override;
    [[nodiscard]] RuntimeHostResult revokeSharing() override;
private:
    [[nodiscard]] bool onOwnerThread() const noexcept;
    [[nodiscard]] RuntimeHostResult deny(RuntimeHostError error) noexcept;
    [[nodiscard]] bool prepareTlsIdentityForSelection(
        std::string_view numericIpAddress) noexcept;
    void retireGeneratedTlsIdentity() noexcept;
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    enum class AcceptedClientPhase : std::uint8_t
    {
        None,
        PreAdmission,
        McsConnectInitial,
        McsConnectResponse,
        McsErectDomain,
        McsAttachUser,
        McsAttachConfirm,
        McsChannelJoins,
        ClientInfo,
        LicenseRequest,
        ClientLicensing,
        ValidClient,
        ShareActivation,
        GraphicsControl,
        GraphicsReady,
    };

    enum class ConfiguredAuthenticationMode : std::uint8_t
    {
        Unconfigured,
        ExistingOsAccount,
        StandalonePassword,
    };

    [[nodiscard]] bool selectedStandaloneCredentialReady() const noexcept;
    [[nodiscard]] bool buildAuthenticationSelection(
        LinuxRuntimeAuthenticationSelection& selection) const noexcept;
    [[nodiscard]] bool serviceCredentialsReady() const noexcept;
    [[nodiscard]] RuntimeHostResult acceptClientOnce(
        std::chrono::steady_clock::time_point now) noexcept;
    [[nodiscard]] RuntimeHostResult advanceAcceptedClientOnce() noexcept;
    [[nodiscard]] RuntimeHostResult pollAcceptedClientReadiness() noexcept;
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
    [[nodiscard]] RuntimeHostResult initializeNativeDesktop() noexcept;
    [[nodiscard]] RuntimeHostResult serviceNativeDesktopOnce() noexcept;
    void retireNativeDesktop() noexcept;
#endif
    void retireAcceptedClient(RuntimeHostError error) noexcept;
    void clearAcceptedClient() noexcept;
#endif
    void retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept;

    const std::thread::id ownerThread_;
    RuntimeHostOptions selection_{};
    RuntimeHostStage stage_{RuntimeHostStage::Stopped};
    RuntimeHostError lastError_{RuntimeHostError::HostConsentRequired};
    bool selectionConfigured_{};
    // Expert --config construction borrows its validated identity. Normal GUI
    // construction owns a generated endpoint-bound identity in this optional.
    const RuntimeServerTlsContext* tlsContext_{};
    std::optional<RuntimeServerTlsContext> generatedTlsContext_{};
    bool externalTlsContext_{};
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    LinuxRuntimeSecurityConfiguration* securityConfiguration_{};
    const LinuxRuntimeAdmissionConfiguration* admissionConfiguration_{};
#endif
    // Normal GUI startup owns a process-local R3 licensing identity before
    // any Start eligibility check. Expert --config construction borrows its
    // validated licensing owner instead. Neither path opens a listener.
    std::unique_ptr<RuntimeLicensingContext> generatedLicensingContext_{};
    const RuntimeLicensingContext* licensingContext_{};
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    std::optional<RuntimeDeploymentPolicy> deploymentPolicy_{};
    std::unique_ptr<LinuxRuntimeConnection> acceptedClient_{};
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
    // Exactly one R2-selected X11 owner may coexist with the accepted client.
    // It is retired before acceptedClient_ on every terminal path.
    std::unique_ptr<LinuxHostNativeDesktopState> nativeDesktop_{};
#endif
    rdp_server::server::security::AuthenticationAttemptLimiter authAttempts_{};
    std::chrono::steady_clock::time_point acceptedClientDeadline_{};
    AcceptedClientPhase acceptedClientPhase_{AcceptedClientPhase::None};
    std::uint64_t nextClientId_{1U};
    std::uint64_t acceptedClientId_{};
    std::string acceptedClientPeer_{};
    bool acceptedClientReadable_{};
    bool acceptedClientWritable_{};
    bool clientDisconnected_{};
    ConfiguredAuthenticationMode authenticationMode_{
        ConfiguredAuthenticationMode::Unconfigured};
    std::uint64_t standaloneCredentialGeneration_{};
    bool credentialsConfigured_{};
#endif
    // Production-native evidence owns all borrowed views. It must outlive
    // R2's host-lifetime authority and every admission broker borrowing it.
    rdp_server::server::security::LinuxLogindReadOnlyEvidenceSource
        ownerEvidence_{};
    rdp_server::server::security::CurrentOwnerSharingAuthority
        ownerSharingAuthority_{ownerEvidence_};
    // R2P service credential is memory-only and generation-fenced. R10 may
    // consume its exact selected generation in the sole accepted-socket owner;
    // the public GUI remains fail-closed until Microsoft-client acceptance.
    rdp_server::server::security::StandalonePasswordCredentialOwner
        standalonePasswordCredential_{};
    // R1's sole verified bind owner. Unopened until R2/R1 authority exists.
    rdp_server::server::transport::OwnedLanListener listener_{};
};

} // namespace rdp_server::server::runtime
