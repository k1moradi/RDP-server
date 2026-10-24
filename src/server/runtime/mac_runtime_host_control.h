// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_deployment_policy.h"
#include "server/runtime/runtime_host_control.h"
#include "server/runtime/runtime_licensing_context.h"
#include "server/runtime/runtime_platform_native_desktop.h"
#include "server/runtime/runtime_tls_context.h"
#include "server/security/authentication_attempt_limiter.h"
#include "server/security/current_owner_sharing_authority.h"
#include "server/security/mac_console_evidence.h"
#include "server/security/standalone_ntlmv2.h"
#include "server/transport/lan_listener.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace rdp_server::server::runtime
{

// Serialized macOS GUI RuntimeHostControl.
// Follows the same owner-thread execution model and preparation-only lifecycle as Linux.
// Qt options/views never confer authority.
class MacRuntimeHostControl final : public RuntimeHostControl
{
public:
    MacRuntimeHostControl() noexcept;
    explicit MacRuntimeHostControl(
        rdp_server::server::security::ConsoleOsEvidenceSource& ownerEvidence) noexcept;
    ~MacRuntimeHostControl() override;

    MacRuntimeHostControl(const MacRuntimeHostControl&) = delete;
    MacRuntimeHostControl& operator=(const MacRuntimeHostControl&) = delete;
    MacRuntimeHostControl(MacRuntimeHostControl&&) = delete;
    MacRuntimeHostControl& operator=(MacRuntimeHostControl&&) = delete;

    [[nodiscard]] std::vector<RuntimeHostInterface>
    enumerateLocalInterfaces() const override;

    [[nodiscard]] RuntimeHostStatus status() const override;

    [[nodiscard]] RuntimeHostResult configure(
        const RuntimeHostOptions& options) override;

    [[nodiscard]] RuntimeHostResult requestCredentialSetup(
        rdp_server::server::security::LanCredentialChoice choice) override;

    [[nodiscard]] bool configureStandaloneApplicationPassword(
        std::u16string_view username,
        std::span<char16_t> password) noexcept override;

    [[nodiscard]]
    rdp_server::server::security::StandalonePasswordCredentialObservation
    standaloneApplicationPasswordObservation() const noexcept;

    [[nodiscard]] bool visitStandaloneApplicationPassword(
        std::uint64_t expectedGeneration,
        rdp_server::server::security::StandalonePasswordCredentialVisitor visitor,
        void* context) const noexcept;

    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& request = {}) override;

    [[nodiscard]] RuntimeHostResult startSharing() override;

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
    [[nodiscard]] bool selectedStandaloneCredentialReady() const noexcept;
    void retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept;

    const std::thread::id ownerThread_;
    rdp_server::server::security::MacConsoleOsEvidenceSource defaultOwnerEvidence_{};
    rdp_server::server::security::ConsoleOsEvidenceSource* ownerEvidenceSource_{};
    mutable rdp_server::server::security::CurrentOwnerSharingAuthority ownerSharingAuthority_;
    rdp_server::server::security::StandalonePasswordCredentialOwner standalonePasswordCredential_{};
    std::uint64_t standaloneCredentialGeneration_{0U};
    rdp_server::server::security::AuthenticationAttemptLimiter authAttempts_{};

    RuntimeLicensingContext licensingContext_{};
    std::optional<RuntimeServerTlsContext> generatedTlsContext_{};
    RuntimeServerTlsContext* tlsContext_{nullptr};
    std::optional<RuntimeDeploymentPolicy> deploymentPolicy_{};

    rdp_server::server::transport::OwnedLanListener listener_{};
    RuntimePlatformNativeDesktop nativeDesktop_{};

    RuntimeHostOptions selection_{};
    bool selectionConfigured_{false};
    bool credentialsConfigured_{false};
    RuntimeHostStage stage_{RuntimeHostStage::Stopped};
    RuntimeHostError lastError_{RuntimeHostError::None};

    // Client tracking
    std::uint64_t nextClientId_{1U};
    std::uint64_t activeClientId_{0U};
    std::string activeClientPeer_{};
    bool clientDisconnected_{false};
    std::unique_ptr<rdp_server::server::transport::OwnedPreauthTcpConnection> activeConnection_{};
    std::chrono::steady_clock::time_point activeClientDeadline_{};
};

class MacPortableDesktopRuntime final
{
public:
    MacPortableDesktopRuntime() noexcept = default;
    MacPortableDesktopRuntime(const MacPortableDesktopRuntime&) = delete;
    MacPortableDesktopRuntime& operator=(const MacPortableDesktopRuntime&) = delete;
    MacPortableDesktopRuntime(MacPortableDesktopRuntime&&) = delete;
    MacPortableDesktopRuntime& operator=(MacPortableDesktopRuntime&&) = delete;

    [[nodiscard]] MacRuntimeHostControl& hostControl() noexcept
    {
        return hostControl_;
    }

    [[nodiscard]] RuntimeHostResult serviceOnce() noexcept
    {
        return hostControl_.serviceOnce();
    }

private:
    MacRuntimeHostControl hostControl_{};
};

} // namespace rdp_server::server::runtime
