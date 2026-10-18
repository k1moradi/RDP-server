// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/security/standalone_credential_policy.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rdp_server::server::runtime
{

// R10 owns the one in-process, serialized command/connection lifetime.
// R7 must marshal requests onto the R10 event-loop thread. Neither snapshots
// nor options authorize R1 listening, R2 admission or R3 Share.
enum class RuntimeHostStage : std::uint8_t
{
    Stopped, PackageInstalled, CredentialsConfigured, ListenerAvailable,
    ClientAuthenticating, ShareActivated, DesktopVisible, ClientConnected,
    Revoked
};

enum class RuntimeHostError : std::uint8_t
{
    None, ControlUnavailable, InvalidConfiguration, CredentialNotConfigured,
    UnsupportedIndependentPasswordNla, CredentialProviderUnavailable,
    HostConsentRequired, InterfaceUnavailable, ListenerPolicyDenied,
    PortUnavailable, TlsIdentityUnavailable, NativeAuthorizationDenied,
    AuthenticationRejected, ShareActivationUnavailable, GraphicsUnavailable,
    ClientNotFound, AccessRevoked, InternalFailure
};

// Map only bounded error codes to fixed redacted messages, never raw peer,
// TLS, GSS, credential, native-session or private-certificate diagnostics.
[[nodiscard]] constexpr std::string_view runtimeHostErrorMessage(
    RuntimeHostError error) noexcept
{
    switch (error)
    {
    case RuntimeHostError::None: return "No error";
    case RuntimeHostError::ControlUnavailable: return "Host control unavailable";
    case RuntimeHostError::InvalidConfiguration: return "Invalid host configuration";
    case RuntimeHostError::CredentialNotConfigured: return "Credentials not configured";
    case RuntimeHostError::UnsupportedIndependentPasswordNla:
        return "Independent application password is unsupported by RDP NLA";
    case RuntimeHostError::CredentialProviderUnavailable: return "OS credential provider unavailable";
    case RuntimeHostError::HostConsentRequired: return "Host-owner permission required";
    case RuntimeHostError::InterfaceUnavailable: return "Selected local interface unavailable";
    case RuntimeHostError::ListenerPolicyDenied: return "Listener denied by network policy";
    case RuntimeHostError::PortUnavailable: return "Requested port unavailable";
    case RuntimeHostError::TlsIdentityUnavailable: return "TLS identity unavailable";
    case RuntimeHostError::NativeAuthorizationDenied: return "Native desktop access denied";
    case RuntimeHostError::AuthenticationRejected: return "Client authentication rejected";
    case RuntimeHostError::ShareActivationUnavailable: return "Share activation unavailable";
    case RuntimeHostError::GraphicsUnavailable: return "Authorized desktop graphics unavailable";
    case RuntimeHostError::ClientNotFound: return "Active client not found";
    case RuntimeHostError::AccessRevoked: return "Sharing access revoked";
    case RuntimeHostError::InternalFailure: return "Host operation failed";
    }
    return "Host operation failed";
}

struct RuntimeHostResult
{
    RuntimeHostError error{RuntimeHostError::ControlUnavailable};
    bool retryable{};
    [[nodiscard]] constexpr bool succeeded() const noexcept
    {
        return error == RuntimeHostError::None;
    }
};

struct RuntimeHostInterface
{
    std::string stableId;
    std::string displayName;
    std::vector<std::string> localAddresses;
    bool loopback{};
    bool lanEligible{};
};

struct RuntimeHostOptions
{
    // Non-secret preferences only. R10 must verify with R1 at bind/accept.
    std::string interfaceId;
    std::string localAddress;
    std::uint16_t port{3389U};
    bool lanRequested{};
    bool afterLoginLaunchRequested{};
};

struct RuntimeHostClient
{
    // Opaque GUI handle, not an R2 lease or R3 session identifier.
    std::uint64_t opaqueId{};
    std::string peerAddress;
    bool authenticating{};
    bool shareActivated{};
    bool desktopVisible{};
};

struct RuntimeHostStatus
{
    RuntimeHostStage stage{RuntimeHostStage::Stopped};
    bool packageInstalled{};
    bool credentialsConfigured{};
    bool tlsIdentityReady{};
    bool hostOwnerAuthorized{};
    bool listenerAvailable{};
    bool nativeDesktopReady{};
    std::string boundEndpoint;
    std::vector<RuntimeHostClient> activeClients;
    RuntimeHostError lastError{RuntimeHostError::ControlUnavailable};
};

// Pure in-process facade, no second listener/poller/connection owner.
// Concrete methods must revalidate R1/R2/R3/native policy independently.
// Stop/revoke must retire R3/native input and frames before R1 transport.
class RuntimeHostControl
{
public:
    virtual ~RuntimeHostControl() = default;
    [[nodiscard]] virtual std::vector<RuntimeHostInterface>
    enumerateLocalInterfaces() const = 0;
    [[nodiscard]] virtual RuntimeHostStatus status() const = 0;
    [[nodiscard]] virtual RuntimeHostResult configure(
        const RuntimeHostOptions& options) = 0;
    [[nodiscard]] virtual RuntimeHostResult requestCredentialSetup(
        rdp_server::server::security::LanCredentialChoice choice) = 0;
    [[nodiscard]] virtual RuntimeHostResult requestHostPermissionSetup() = 0;
    [[nodiscard]] virtual RuntimeHostResult startSharing() = 0;
    [[nodiscard]] virtual RuntimeHostResult stopSharing() = 0;
    [[nodiscard]] virtual RuntimeHostResult disconnectClient(
        std::uint64_t opaqueClientId) = 0;
    [[nodiscard]] virtual RuntimeHostResult revokeSharing() = 0;
};

// Deny-only default until the live R10 owner/GUI adapter is integrated.
// No permission, positive status, socket, persistence or Share is invented.
class UnavailableRuntimeHostControl final : public RuntimeHostControl
{
public:
    [[nodiscard]] std::vector<RuntimeHostInterface>
    enumerateLocalInterfaces() const override { return {}; }
    [[nodiscard]] RuntimeHostStatus status() const override { return {}; }
    [[nodiscard]] RuntimeHostResult configure(
        const RuntimeHostOptions&) override { return {}; }
    [[nodiscard]] RuntimeHostResult requestCredentialSetup(
        rdp_server::server::security::LanCredentialChoice choice) override
    {
        using rdp_server::server::security::LanCredentialDecision;
        const auto decision =
            rdp_server::server::security::assessLanCredentialChoice(choice);
        if (decision == LanCredentialDecision::UnsupportedIndependentPasswordCredSsp)
            return {RuntimeHostError::UnsupportedIndependentPasswordNla, false};
        if (decision == LanCredentialDecision::CredentialNotConfigured)
            return {RuntimeHostError::CredentialNotConfigured, false};
        return {};
    }
    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup() override
    { return {}; }
    [[nodiscard]] RuntimeHostResult startSharing() override { return {}; }
    [[nodiscard]] RuntimeHostResult stopSharing() override { return {}; }
    [[nodiscard]] RuntimeHostResult disconnectClient(std::uint64_t) override
    { return {}; }
    [[nodiscard]] RuntimeHostResult revokeSharing() override { return {}; }
};

} // namespace rdp_server::server::runtime
