// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_application_bootstrap.h"
#include "server/security/standalone_credential_policy.h"
#include "server/runtime/runtime_tls_identity_status.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
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
    case RuntimeHostError::HostConsentRequired: return "Sharing permission required";
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
    std::uint16_t port{kRuntimeDefaultListenPort};
    bool lanRequested{};
    bool afterLoginLaunchRequested{};
};

enum class RuntimeHostAddressFamily : std::uint8_t
{
    Unspecified,
    Ipv4,
    Ipv6,
};

enum class RuntimeHostRecommendationSource : std::uint8_t
{
    PreferredRoute,
    SoleEligibleInterface,
    Ambiguous,
    Unavailable,
};

// Platform-neutral input to R10's preferred-LAN recommendation policy.
// interfaceId is an opaque stable identity. Native/display names such as
// eth0, wlan0, en0 or a Windows adapter label are never ranking policy.
struct RuntimeHostLanEndpointCandidate final
{
    std::string interfaceId;
    std::string address;
    RuntimeHostAddressFamily family{RuntimeHostAddressFamily::Unspecified};
    bool privateLanEligible{};
    bool preferredRoute{};
    std::optional<std::uint32_t> routeMetric{};

    [[nodiscard]] bool valid() const noexcept
    {
        return !interfaceId.empty() && !address.empty() &&
               address != "0.0.0.0" && address != "::" &&
               address != "[::]" &&
               family != RuntimeHostAddressFamily::Unspecified &&
               privateLanEligible;
    }
};

struct RuntimeHostRecommendedEndpoint final
{
    // Recommendation-only presentation tuple. R10 may rank candidates using
    // route/default-route evidence, but none of that ranking evidence is R1
    // bind authority. Start must revalidate the exact stable interface ID and
    // numeric address against current native state before opening the listener.
    std::string interfaceId;
    std::string address;
    std::uint16_t port{};
    RuntimeHostAddressFamily family{RuntimeHostAddressFamily::Unspecified};
    bool privateLanEligible{};
    bool preferredRoute{};
    std::optional<std::uint32_t> routeMetric{};
    bool ambiguous{};
    RuntimeHostRecommendationSource source{
        RuntimeHostRecommendationSource::Unavailable};

    [[nodiscard]] bool valid() const noexcept
    {
        return !ambiguous && !interfaceId.empty() && !address.empty() &&
               port != 0U &&
               family != RuntimeHostAddressFamily::Unspecified &&
               privateLanEligible;
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

[[nodiscard]] inline bool sameRuntimeLanEndpointIdentity(
    const RuntimeHostLanEndpointCandidate& left,
    const RuntimeHostLanEndpointCandidate& right) noexcept
{
    return left.interfaceId == right.interfaceId &&
           left.address == right.address &&
           left.family == right.family;
}

// Candidate ordering is presentation policy only. A preferred/default-route
// owner outranks a non-owner. Route metric is used only when every remaining
// contender exposes one; otherwise distinct endpoint identities are
// intentionally ambiguous. Address family and opaque interface identity never
// act as tie breakers, and the returned tuple remains untrusted until Start
// repeats current-interface validation and R1 opens the exact native endpoint.
[[nodiscard]] inline RuntimeHostRecommendedEndpoint
recommendRuntimePrivateLanEndpoint(
    const std::vector<RuntimeHostLanEndpointCandidate>& candidates,
    const std::uint16_t port = kRuntimeDefaultListenPort)
{
    RuntimeHostRecommendedEndpoint recommended;
    recommended.port = port;
    if (port == 0U)
        return recommended;

    std::vector<const RuntimeHostLanEndpointCandidate*> eligible;
    eligible.reserve(candidates.size());
    for (const RuntimeHostLanEndpointCandidate& candidate : candidates)
    {
        if (candidate.valid())
            eligible.push_back(&candidate);
    }
    if (eligible.empty())
        return recommended;

    const auto ambiguous = [&recommended]() {
        recommended.ambiguous = true;
        recommended.source = RuntimeHostRecommendationSource::Ambiguous;
        return recommended;
    };
    const auto selectedResult =
        [&recommended](const RuntimeHostLanEndpointCandidate* selected,
                       const RuntimeHostRecommendationSource source) {
            recommended.interfaceId = selected->interfaceId;
            recommended.address = selected->address;
            recommended.family = selected->family;
            recommended.privateLanEligible = selected->privateLanEligible;
            recommended.preferredRoute = selected->preferredRoute;
            recommended.routeMetric = selected->routeMetric;
            recommended.source = source;
            return recommended;
        };

    const bool hasPreferredRoute = std::ranges::any_of(
        eligible,
        [](const RuntimeHostLanEndpointCandidate* candidate) {
            return candidate->preferredRoute;
        });

    if (hasPreferredRoute)
    {
        std::vector<const RuntimeHostLanEndpointCandidate*> contenders;
        contenders.reserve(eligible.size());
        for (const RuntimeHostLanEndpointCandidate* candidate : eligible)
        {
            if (candidate->preferredRoute)
                contenders.push_back(candidate);
        }

        const bool allMetricsAvailable = std::ranges::all_of(
            contenders,
            [](const RuntimeHostLanEndpointCandidate* candidate) {
                return candidate->routeMetric.has_value();
            });
        if (allMetricsAvailable && contenders.size() > 1U)
        {
            const auto best = std::min_element(
                contenders.begin(), contenders.end(),
                [](const RuntimeHostLanEndpointCandidate* left,
                   const RuntimeHostLanEndpointCandidate* right) {
                    return *left->routeMetric < *right->routeMetric;
                });
            const std::uint32_t bestMetric = *(*best)->routeMetric;
            std::erase_if(
                contenders,
                [bestMetric](const RuntimeHostLanEndpointCandidate* candidate) {
                    return *candidate->routeMetric != bestMetric;
                });
        }

        const RuntimeHostLanEndpointCandidate* selected = contenders.front();
        if (std::ranges::any_of(
                contenders,
                [selected](const RuntimeHostLanEndpointCandidate* candidate) {
                    return !sameRuntimeLanEndpointIdentity(*selected, *candidate);
                }))
            return ambiguous();

        for (const RuntimeHostLanEndpointCandidate* candidate : contenders)
        {
            if (!selected->routeMetric.has_value() &&
                candidate->routeMetric.has_value())
                selected = candidate;
        }
        return selectedResult(
            selected, RuntimeHostRecommendationSource::PreferredRoute);
    }

    // No trustworthy route winner: only one eligible private interface may be
    // selected automatically. IPv4 is preferred only within that one
    // interface, never as a tie-break between different interfaces.
    std::vector<std::string_view> interfaceIds;
    interfaceIds.reserve(eligible.size());
    for (const RuntimeHostLanEndpointCandidate* candidate : eligible)
    {
        if (std::ranges::find(interfaceIds, candidate->interfaceId) ==
            interfaceIds.end())
            interfaceIds.push_back(candidate->interfaceId);
    }
    if (interfaceIds.size() != 1U)
        return ambiguous();

    const RuntimeHostAddressFamily family =
        std::ranges::any_of(
            eligible,
            [](const RuntimeHostLanEndpointCandidate* candidate) {
                return candidate->family == RuntimeHostAddressFamily::Ipv4;
            })
            ? RuntimeHostAddressFamily::Ipv4
            : RuntimeHostAddressFamily::Ipv6;

    const RuntimeHostLanEndpointCandidate* selected = nullptr;
    for (const RuntimeHostLanEndpointCandidate* candidate : eligible)
    {
        if (candidate->family != family)
            continue;
        if (selected == nullptr)
        {
            selected = candidate;
            continue;
        }
        if (!sameRuntimeLanEndpointIdentity(*selected, *candidate))
            return ambiguous();
    }
    if (selected == nullptr)
        return recommended;

    return selectedResult(
        selected, RuntimeHostRecommendationSource::SoleEligibleInterface);
}

// Compatibility projection for today's interface-only inventory. It supplies
// no synthetic route preference or metric. Consequently multiple distinct
// eligible endpoints are ambiguous until a native platform collector provides
// the semantic route facts above.
[[nodiscard]] inline RuntimeHostRecommendedEndpoint
recommendRuntimePrivateLanEndpoint(
    const std::vector<RuntimeHostInterface>& interfaces,
    const std::uint16_t port = kRuntimeDefaultListenPort)
{
    std::vector<RuntimeHostLanEndpointCandidate> candidates;
    for (const RuntimeHostInterface& runtimeInterface : interfaces)
    {
        for (const std::string& address : runtimeInterface.localAddresses)
        {
            const RuntimeHostOptions selection{
                runtimeInterface.stableId, address, port, true, false};
            if (!assessRuntimeSelectedLanEndpoint(
                    selection, interfaces).succeeded())
                continue;

            RuntimeHostLanEndpointCandidate candidate;
            candidate.interfaceId = runtimeInterface.stableId;
            candidate.address = address;
            candidate.family = address.find(':') == std::string::npos
                ? RuntimeHostAddressFamily::Ipv4
                : RuntimeHostAddressFamily::Ipv6;
            candidate.privateLanEligible = true;
            candidates.emplace_back(std::move(candidate));
        }
    }
    return recommendRuntimePrivateLanEndpoint(candidates, port);
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

// Exact, redacted R10 projection of the accepted connection's pre-auth
// diagnostics. These enums mirror the owning R1/R2 categories one-for-one;
// presentation must not rewrite TLS, SPNEGO or NTLM failures into each other.
enum class RuntimeAcceptedClientPreauthStage : std::uint8_t
{
    AwaitConnectionRequest,
    AwaitTls,
    AwaitCredSsp,
    AwaitMcsConnectInitial,
    Closed,
};

enum class RuntimeAcceptedClientTlsHandshakeStage : std::uint8_t
{
    NotStarted,
    Handshaking,
    Established,
    Closed,
};

enum class RuntimeAcceptedClientCredSspTransition : std::uint8_t
{
    NotStarted,
    AwaitingToken,
    BindingVerified,
    CredentialsVerified,
    Failed,
    Closed,
};

enum class RuntimeAcceptedClientStandaloneFailureStage : std::uint8_t
{
    None,
    NtlmNegotiation,
    Mic,
    SignSeal,
    Spnego,
    PubKeyAuth,
    AuthInfo,
    Admission,
};

enum class RuntimeAcceptedClientTermination : std::uint8_t
{
    Open,
    OrderlyTlsClose,
    TransportError,
    TlsFailure,
    ProtocolError,
    Cancelled,
};

struct RuntimeAcceptedClientPreauthDiagnostics final
{
    bool available{};
    RuntimeAcceptedClientPreauthStage preauthStage{
        RuntimeAcceptedClientPreauthStage::Closed};
    RuntimeAcceptedClientTlsHandshakeStage tlsHandshakeStage{
        RuntimeAcceptedClientTlsHandshakeStage::Closed};
    RuntimeAcceptedClientCredSspTransition credSspTransition{
        RuntimeAcceptedClientCredSspTransition::NotStarted};
    RuntimeAcceptedClientStandaloneFailureStage standaloneFailureStage{
        RuntimeAcceptedClientStandaloneFailureStage::None};
    RuntimeAcceptedClientTermination termination{
        RuntimeAcceptedClientTermination::Cancelled};
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

// Product-only permission projection. It carries no R2 enum, native identity,
// permission bitmask or clipboard capability into R7.
enum class RuntimeSharingPermissionDenial : std::uint8_t
{
    None,
    PermissionRequired,
    PermissionExpired,
    ComputerLocked,
    LoggedInDesktopChanged,
    PermissionRevoked,
    Unavailable,
};

struct RuntimeSharingPermissionStatus final
{
    bool canRequest{};
    bool activeGrant{};
    bool viewAllowed{};
    bool inputAllowed{};
    std::uint64_t remainingMilliseconds{};
    RuntimeSharingPermissionDenial denial{
        RuntimeSharingPermissionDenial::Unavailable};
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

// Product-level acceptance instrumentation. This deliberately avoids R1/R2/R3
// terminology so an owner test can observe normal application readiness
// without treating a diagnostic as authorization.
enum class RuntimeProductReadinessStage : std::uint8_t
{
    Stopped,
    Provisioned,
    CredentialsConfigured,
    PermissionGranted,
    Starting,
    Listening,
    Authenticating,
    Connected,
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

// Credential editability is a lifecycle fact, not a credential-readiness
// fact. A configured password remains replaceable while the host is stopped;
// active or transitional hosting states and terminal Revoked state lock edits.
[[nodiscard]] constexpr bool runtimeProductCredentialEditingAllowed(
    RuntimeHostStage stage, RuntimeProductHostState productState) noexcept
{
    if (runtimeProductStateMayHost(productState))
        return false;

    switch (stage)
    {
    case RuntimeHostStage::Stopped:
    case RuntimeHostStage::PackageInstalled:
    case RuntimeHostStage::CredentialsConfigured:
        return true;
    case RuntimeHostStage::ListenerAvailable:
    case RuntimeHostStage::ClientAuthenticating:
    case RuntimeHostStage::ShareActivated:
    case RuntimeHostStage::DesktopVisible:
    case RuntimeHostStage::ClientConnected:
    case RuntimeHostStage::Revoked:
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
    // Public Release qualification. Keep false until the required real-client
    // acceptance receipt exists.
    bool standalonePassword{};
    // Availability of the production generation-fenced credential owner is
    // independent of public qualification and configured credential state.
    bool standalonePasswordConfigurationAvailable{};
};

inline constexpr bool kStandalonePasswordProductCapabilityApproved = false;

struct RuntimeProductHostStatus final
{
    RuntimeProductHostState state{RuntimeProductHostState::Error};
    RuntimeProductReadinessStage readinessStage{
        RuntimeProductReadinessStage::Stopped};
    bool controlAvailable{};
    // Normal no-config construction owns the local application prerequisites
    // needed to accept a Session Password later. This is preparation only:
    // no consent, endpoint, listener, client or native desktop is implied.
    bool automaticRuntimeProvisioned{};
    std::vector<RuntimeHostInterface> eligibleLanInterfaces;
    RuntimeHostRecommendedEndpoint recommendedEndpoint{};
    std::string boundEndpoint;
    std::size_t clientCount{};
    std::vector<std::uint64_t> activeClientIds;
    RuntimeCredentialCapabilities credentialCapabilities{};
    bool credentialsConfigured{};
    bool ownerAuthorized{};
    RuntimeSharingPermissionStatus sharingPermission{};
    // Read-only platform-selected desktop target. This is never R2 authority.
    bool nativeDesktopTargetAvailable{};
    std::string nativeDesktopTarget;
    bool tlsIdentityReady{};
    RuntimeTlsCertificateFingerprint tlsFingerprint{};
    bool tlsFingerprintAvailable{};
    std::string lastErrorMessage;
    // Lifecycle-only UI mutation permission. This never means that
    // credentials are configured and never grants consent or listener access.
    // Appended to preserve existing aggregate-initializer field positions.
    bool credentialEditingAllowed{};
};

struct RuntimeFirstLiveGraphicsTrace final
{
    // Read-only first-client correlation facts. These fields never authorize
    // capture, frame publication, transport progress or ACK credit.
    bool firstFramebufferAvailable{};
    bool firstClearCodecFramePrepared{};
    bool firstExactTlsWriteCommitted{};
    std::size_t outstandingFrameAcknowledgements{};
    bool firstGenuineMatchingFrameAcknowledge{};
};

[[nodiscard]] constexpr RuntimeFirstLiveGraphicsTrace
projectRuntimeFirstLiveGraphicsTrace(
    const bool firstFramebufferAvailable,
    const bool firstClearCodecFramePrepared,
    const bool firstExactTlsWriteCommitted,
    const std::size_t outstandingFrameAcknowledgements,
    const bool firstGenuineMatchingFrameAcknowledge) noexcept
{
    return {
        firstFramebufferAvailable,
        firstClearCodecFramePrepared,
        firstExactTlsWriteCommitted,
        outstandingFrameAcknowledgements,
        firstGenuineMatchingFrameAcknowledge};
}

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
    // R10-only read-only correlation for the first physical graphics trace.
    // R4 remains the sole frame/ACK owner; this projection cannot advance it.
    RuntimeFirstLiveGraphicsTrace firstLiveGraphicsTrace{};
    // True only after an accepted client was actually retired while the
    // current listener remains active. Cleared on a new accept/host teardown.
    bool clientDisconnected{};

    // R10-owned product projection. R7 must not rebuild lifecycle from the
    // protocol/native diagnostics above.
    RuntimeProductHostStatus product{};

    // Current/last accepted-client pre-auth observation for diagnostics only.
    // It contains no protocol bytes, credential material or authority.
    RuntimeAcceptedClientPreauthDiagnostics acceptedClientPreauthDiagnostics{};
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

    // One production R2P memory-only standalone credential command. Product
    // visibility is a separate capability gate. This portable deny fallback
    // deliberately carries no optional authentication-backend link dependency;
    // volatile writes ensure caller-owned password storage is still wiped.
    [[nodiscard]] virtual bool configureStandaloneApplicationPassword(
        std::u16string_view,
        std::span<char16_t> password) noexcept
    {
        for (char16_t& codeUnit : password)
        {
            volatile char16_t* const volatileCodeUnit = &codeUnit;
            *volatileCodeUnit = u'\0';
        }
        return false;
    }

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
