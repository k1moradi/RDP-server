// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/security/standalone_credential_policy.h"
#include "server/runtime/runtime_tls_identity_status.h"

#include <algorithm>
#include <cstddef>
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

// Descriptive GUI/status state only. This enum never authorizes CLIPRDR
// traffic or native publication. Enabled may be reported only by the live R10
// owner after fresh R2 authorization, genuine ShareActivated, the exact joined
// cliprdr route and its current native clipboard owner. Route/source retirement
// changes the state before replacement; a GUI preference can never set it.
enum class RuntimeClipboardState : std::uint8_t
{
    Unavailable,
    Enabled,
    Retired,
    Denied,
};

enum class RuntimeHostError : std::uint8_t
{
    None, ControlUnavailable, InvalidConfiguration, CredentialNotConfigured,
    UnsupportedIndependentPasswordNla, CredentialProviderUnavailable,
    HostConsentRequired, InterfaceUnavailable, ListenerPolicyDenied,
    PortUnavailable, TlsIdentityUnavailable, NativeAuthorizationDenied,
    AuthenticationRejected, ShareActivationUnavailable, GraphicsUnavailable,
    ClientNotFound, AccessRevoked, InternalFailure,
    // GUI-facing terminal session freshness and rate-limit observations.
    // Appended to retain existing numeric enum values; neither authorizes a
    // listener, verified identity, owner consent, native lease or R3 state.
    HostSessionStale, AuthenticationRateLimited
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
    case RuntimeHostError::HostSessionStale:
        return "Host desktop session changed; fresh authorization required";
    case RuntimeHostError::AuthenticationRateLimited:
        return "Authentication temporarily rate-limited";
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

struct RuntimeHostRecommendedEndpoint final
{
    std::string interfaceId;
    std::string address;
    std::uint16_t port{};

    [[nodiscard]] bool valid() const noexcept
    {
        return !interfaceId.empty() && !address.empty() && port != 0U;
    }
};

// This is a pure R10-selected bind-preflight, never listener authorization.
// A real controller must re-enumerate the selected native interface/address
// immediately before the R1 bind and revalidate the actual bound endpoint.
// Never accept a GUI display label, wildcard or duplicate stable identity
// as proof that a LAN socket belongs to the intended host interface.
[[nodiscard]] inline RuntimeHostResult assessRuntimeSelectedLanEndpoint(
    const RuntimeHostOptions& selection,
    const std::vector<RuntimeHostInterface>& interfaces) noexcept
{
    if (!selection.lanRequested || selection.port == 0U ||
        selection.interfaceId.empty() || selection.localAddress.empty() ||
        selection.localAddress == "0.0.0.0" ||
        selection.localAddress == "::" ||
        selection.localAddress == "[::]")
    {
        return {RuntimeHostError::InvalidConfiguration, false};
    }

    bool matched = false;
    for (const RuntimeHostInterface& candidate : interfaces)
    {
        if (candidate.stableId != selection.interfaceId)
            continue;
        if (candidate.loopback || !candidate.lanEligible ||
            std::find(candidate.localAddresses.begin(),
                      candidate.localAddresses.end(),
                      selection.localAddress) == candidate.localAddresses.end() ||
            matched)
        {
            return {RuntimeHostError::InterfaceUnavailable, false};
        }
        matched = true;
    }
    return matched
        ? RuntimeHostResult{RuntimeHostError::None, false}
        : RuntimeHostResult{RuntimeHostError::InterfaceUnavailable, false};
}

[[nodiscard]] inline RuntimeHostRecommendedEndpoint
recommendRuntimePrivateLanEndpoint(
    const std::vector<RuntimeHostInterface>& interfaces,
    const std::uint16_t port = 3389U)
{
    RuntimeHostRecommendedEndpoint recommended;
    bool recommendedIsIpv6 = true;
    for (const RuntimeHostInterface& candidateInterface : interfaces)
    {
        for (const std::string& address : candidateInterface.localAddresses)
        {
            const RuntimeHostOptions candidate{
                candidateInterface.stableId, address, port, true, false};
            if (!assessRuntimeSelectedLanEndpoint(
                    candidate, interfaces).succeeded())
                continue;

            const bool candidateIsIpv6 =
                address.find(':') != std::string::npos;
            const bool betterFamily =
                recommended.valid() && recommendedIsIpv6 && !candidateIsIpv6;
            const bool sameFamilyBetterIdentity =
                recommended.valid() &&
                candidateIsIpv6 == recommendedIsIpv6 &&
                (candidateInterface.stableId < recommended.interfaceId ||
                 (candidateInterface.stableId == recommended.interfaceId &&
                  address < recommended.address));
            if (!recommended.valid() || betterFamily ||
                sameFamilyBetterIdentity)
            {
                recommended.interfaceId = candidateInterface.stableId;
                recommended.address = address;
                recommended.port = port;
                recommendedIsIpv6 = candidateIsIpv6;
            }
        }
    }
    return recommended;
}

struct RuntimeHostClient
{
    // Opaque GUI handle, not an R2 lease or R3 session identifier.
    std::uint64_t opaqueId{};
    std::string peerAddress;
    bool authenticating{};
    bool shareActivated{};
    bool desktopVisible{};
};

struct RuntimeHostPermissionRequest final
{
    // View is always implicit. Input/clipboard are independently
    // owner-selectable least-privilege additions.
    bool allowInput{true};
    bool allowClipboard{true};
    std::uint64_t requestedLifetimeMilliseconds{15U * 60U * 1000U};
};

enum class RuntimeOwnerGrantState : std::uint8_t
{
    Unavailable,
    Active,
    Expired,
};

struct RuntimeOwnerGrantObservation final
{
    RuntimeOwnerGrantState state{RuntimeOwnerGrantState::Unavailable};
    std::uint32_t effectivePermissionMask{};
    std::uint64_t remainingMilliseconds{};
};

enum class RuntimeProductHostState : std::uint8_t
{
    Stopped,
    Starting,
    Listening,
    Authenticating,
    DesktopInitializing,
    Connected,
    Stopping,
    Error,
};

[[nodiscard]] constexpr bool runtimeProductStateMayHost(
    RuntimeProductHostState state) noexcept
{
    switch (state)
    {
    case RuntimeProductHostState::Starting:
    case RuntimeProductHostState::Listening:
    case RuntimeProductHostState::Authenticating:
    case RuntimeProductHostState::DesktopInitializing:
    case RuntimeProductHostState::Connected:
    case RuntimeProductHostState::Stopping:
        return true;
    case RuntimeProductHostState::Stopped:
    case RuntimeProductHostState::Error:
        return false;
    }
    return true;
}

[[nodiscard]] constexpr bool runtimeProductStateSharingToggleOn(
    RuntimeProductHostState state) noexcept
{
    switch (state)
    {
    case RuntimeProductHostState::Listening:
    case RuntimeProductHostState::Authenticating:
    case RuntimeProductHostState::DesktopInitializing:
    case RuntimeProductHostState::Connected:
    case RuntimeProductHostState::Stopping:
        return true;
    case RuntimeProductHostState::Stopped:
    case RuntimeProductHostState::Starting:
    case RuntimeProductHostState::Error:
        return false;
    }
    return false;
}

[[nodiscard]] constexpr RuntimeProductHostState runtimeProductStateFor(
    RuntimeHostStage stage, RuntimeHostError error,
    bool nativeDesktopReady) noexcept
{
    switch (stage)
    {
    case RuntimeHostStage::ListenerAvailable:
        return RuntimeProductHostState::Listening;
    case RuntimeHostStage::ClientAuthenticating:
        return RuntimeProductHostState::Authenticating;
    case RuntimeHostStage::ShareActivated:
        return RuntimeProductHostState::DesktopInitializing;
    case RuntimeHostStage::DesktopVisible:
    case RuntimeHostStage::ClientConnected:
        return nativeDesktopReady
            ? RuntimeProductHostState::Connected
            : RuntimeProductHostState::DesktopInitializing;
    case RuntimeHostStage::Revoked:
        return error == RuntimeHostError::HostSessionStale ||
                       error == RuntimeHostError::InternalFailure ||
                       error == RuntimeHostError::NativeAuthorizationDenied
            ? RuntimeProductHostState::Error
            : RuntimeProductHostState::Stopped;
    case RuntimeHostStage::Stopped:
    case RuntimeHostStage::PackageInstalled:
    case RuntimeHostStage::CredentialsConfigured:
        break;
    }

    switch (error)
    {
    case RuntimeHostError::ControlUnavailable:
    case RuntimeHostError::InvalidConfiguration:
    case RuntimeHostError::NativeAuthorizationDenied:
    case RuntimeHostError::HostSessionStale:
    case RuntimeHostError::InternalFailure:
        return RuntimeProductHostState::Error;
    case RuntimeHostError::None:
    case RuntimeHostError::CredentialNotConfigured:
    case RuntimeHostError::UnsupportedIndependentPasswordNla:
    case RuntimeHostError::CredentialProviderUnavailable:
    case RuntimeHostError::HostConsentRequired:
    case RuntimeHostError::InterfaceUnavailable:
    case RuntimeHostError::ListenerPolicyDenied:
    case RuntimeHostError::PortUnavailable:
    case RuntimeHostError::TlsIdentityUnavailable:
    case RuntimeHostError::AuthenticationRejected:
    case RuntimeHostError::ShareActivationUnavailable:
    case RuntimeHostError::GraphicsUnavailable:
    case RuntimeHostError::ClientNotFound:
    case RuntimeHostError::AccessRevoked:
    case RuntimeHostError::AuthenticationRateLimited:
        return RuntimeProductHostState::Stopped;
    }
    return RuntimeProductHostState::Error;
}

struct RuntimeCredentialCapabilities final
{
    bool existingOsAccount{};
    bool standalonePassword{};
};

inline constexpr bool kStandalonePasswordProductCapabilityApproved = false;

struct RuntimeProductHostStatus final
{
    RuntimeProductHostState state{RuntimeProductHostState::Error};
    bool controlAvailable{};
    std::vector<RuntimeHostInterface> eligibleLanInterfaces;
    RuntimeHostRecommendedEndpoint recommendedEndpoint{};
    std::string boundEndpoint;
    std::size_t clientCount{};
    std::vector<std::uint64_t> activeClientIds;
    RuntimeCredentialCapabilities credentialCapabilities{};
    bool credentialsConfigured{};
    bool ownerAuthorized{};
    RuntimeOwnerGrantObservation ownerPermission{};
    bool tlsIdentityReady{};
    RuntimeTlsCertificateFingerprint tlsFingerprint{};
    bool tlsFingerprintAvailable{};
    std::string lastErrorMessage;
};

struct RuntimeHostStatus
{
    RuntimeHostStage stage{RuntimeHostStage::Stopped};
    bool packageInstalled{};
    bool credentialsConfigured{};
    bool tlsIdentityReady{};
    // Single R1-derived non-authorizing identity observation; never
    // synthesized by Qt. Unavailable while the R10 controller is deny-only.
    RuntimeTlsIdentityStatus tlsIdentity{};
    bool hostOwnerAuthorized{};
    // Non-secret projection of the local owner's current consent grant.
    // Descriptive only: R2 still revalidates native evidence on every
    // protected operation and this value can never authorize a peer.
    RuntimeOwnerGrantObservation ownerGrant{};
    bool listenerAvailable{};
    // Exact process-local generation of the currently owned R1 listener.
    // Zero means no current listener; never an admission capability.
    std::uint64_t listenerGeneration{};
    bool nativeDesktopReady{};
    RuntimeClipboardState clipboardState{RuntimeClipboardState::Unavailable};
    // Configured intent versus getsockname-derived reality are deliberately
    // separate diagnostics; neither is listener/admission authority.
    std::string selectedEndpoint;
    std::string boundEndpoint;
    std::vector<RuntimeHostClient> activeClients;
    RuntimeHostError lastError{RuntimeHostError::ControlUnavailable};

    // Read-only milestones from R10's sole accepted-client/native owner.
    // They are presentation facts only and cannot grant Share/native authority.
    bool graphicsReady{};
    bool nativeDesktopInitializing{};
    // True only after an accepted client was actually retired while the
    // current listener remains active. Cleared on a new accept/host teardown.
    bool clientDisconnected{};

    // R10-owned product projection. R7 must not rebuild lifecycle from the
    // protocol/native diagnostics above.
    RuntimeProductHostStatus product{};
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
    [[nodiscard]] virtual RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& request = {}) = 0;
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
    [[nodiscard]] RuntimeHostStatus status() const override
    {
        RuntimeHostStatus snapshot;
        snapshot.product.state = RuntimeProductHostState::Error;
        snapshot.product.lastErrorMessage =
            std::string(runtimeHostErrorMessage(snapshot.lastError));
        return snapshot;
    }
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
    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& = {}) override
    { return {}; }
    [[nodiscard]] RuntimeHostResult startSharing() override { return {}; }
    [[nodiscard]] RuntimeHostResult stopSharing() override { return {}; }
    [[nodiscard]] RuntimeHostResult disconnectClient(std::uint64_t) override
    { return {}; }
    [[nodiscard]] RuntimeHostResult revokeSharing() override { return {}; }
};

} // namespace rdp_server::server::runtime
