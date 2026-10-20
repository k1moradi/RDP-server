// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "server/runtime/runtime_host_control.h"
#include "server/security/current_owner_sharing_authority.h"
#include "server/security/linux_logind_console_evidence.h"
#include "server/transport/lan_listener.h"
#include <optional>
#include <string_view>
#include <thread>

namespace rdp_server::server::runtime
{

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
class LinuxRuntimeSecurityConfiguration;
class RuntimeServerTlsContext;
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
        const RuntimeServerTlsContext& tlsContext) noexcept;
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
    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& request = {}) override;
    [[nodiscard]] RuntimeHostResult startSharing() override;
    [[nodiscard]] RuntimeHostResult stopSharing() override;
    [[nodiscard]] RuntimeHostResult disconnectClient(
        std::uint64_t opaqueClientId) override;
    [[nodiscard]] RuntimeHostResult revokeSharing() override;
private:
    [[nodiscard]] bool onOwnerThread() const noexcept;
    [[nodiscard]] RuntimeHostResult deny(RuntimeHostError error) noexcept;
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    [[nodiscard]] bool serviceCredentialsReady() const noexcept;
#endif
    void retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept;

    const std::thread::id ownerThread_;
    RuntimeHostOptions selection_{};
    RuntimeHostStage stage_{RuntimeHostStage::Stopped};
    RuntimeHostError lastError_{RuntimeHostError::HostConsentRequired};
    bool selectionConfigured_{};
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    LinuxRuntimeSecurityConfiguration* securityConfiguration_{};
    const RuntimeServerTlsContext* tlsContext_{};
    bool credentialsConfigured_{};
#endif
    // Production-native evidence owns all borrowed views. It must outlive
    // R2's host-lifetime authority and every admission broker borrowing it.
    rdp_server::server::security::LinuxLogindReadOnlyEvidenceSource
        ownerEvidence_{};
    rdp_server::server::security::CurrentOwnerSharingAuthority
        ownerSharingAuthority_{ownerEvidence_};
    // R1's sole verified bind owner. Unopened until R2/R1 authority exists.
    rdp_server::server::transport::OwnedLanListener listener_{};
};

} // namespace rdp_server::server::runtime
