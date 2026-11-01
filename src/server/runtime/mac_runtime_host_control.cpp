// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_runtime_host_control.h"
#include "server/security/standalone_credential_consent.h"
#include "server/security/mac_console_admission.h"
#include "server/security/standalone_credssp.h"
#include "server/security/credssp_tsrequest.h"
#include "server/transport/mcs_channel_connection.h"

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#if defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#endif

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <utility>

namespace rdp_server::server::runtime
{
namespace
{

void cleansePassword(std::span<char16_t> password) noexcept
{
    for (char16_t& codeUnit : password)
    {
        volatile char16_t* const volatileCodeUnit = &codeUnit;
        *volatileCodeUnit = u'\0';
    }
}

[[nodiscard]] bool validateStandaloneCredentialVisit(
    const rdp_server::server::security::EphemeralNtlmV2Credential& credential,
    void* context) noexcept
{
    auto* visited = static_cast<bool*>(context);
    if (visited == nullptr)
        return false;
    *visited = credential.configured();
    return *visited;
}

[[nodiscard]] constexpr RuntimeHostError listenerRuntimeError(
    rdp_server::server::transport::LanListenerError error) noexcept
{
    using Error = rdp_server::server::transport::LanListenerError;
    switch (error)
    {
    case Error::None: return RuntimeHostError::None;
    case Error::InvalidSelection: return RuntimeHostError::InvalidConfiguration;
    case Error::InterfaceUnavailable: return RuntimeHostError::InterfaceUnavailable;
    case Error::PermissionDenied: return RuntimeHostError::ListenerPolicyDenied;
    case Error::PortOccupied: return RuntimeHostError::PortUnavailable;
    case Error::ListenerNotReady: return RuntimeHostError::InternalFailure;
    case Error::TerminalDisconnect: return RuntimeHostError::InternalFailure;
    case Error::CertificateMismatch: return RuntimeHostError::TlsIdentityUnavailable;
    }
    return RuntimeHostError::InternalFailure;
}

[[nodiscard]] bool isEligibleAddress(const sockaddr* address)
{
    if (address == nullptr)
        return false;
    if (address->sa_family == AF_INET)
    {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        const auto bytes =
            reinterpret_cast<const std::uint8_t*>(&ipv4->sin_addr);
        return (bytes[0] == 10U) ||
               (bytes[0] == 172U && bytes[1] >= 16U && bytes[1] <= 31U) ||
               (bytes[0] == 192U && bytes[1] == 168U);
    }
    if (address->sa_family == AF_INET6)
    {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        const auto* bytes = ipv6->sin6_addr.s6_addr;
        const bool linkLocal =
            bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
        const bool ula = (bytes[0] & 0xfe) == 0xfc;
        return linkLocal || ula;
    }
    return false;
}

[[nodiscard]] std::string numericAddress(const sockaddr* address)
{
    if (!isEligibleAddress(address))
        return {};
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (address->sa_family == AF_INET)
    {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, address, sizeof(ipv4));
        if (::inet_ntop(AF_INET, &ipv4.sin_addr,
                        buffer.data(), buffer.size()) == nullptr)
            return {};
    }
    else
    {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, address, sizeof(ipv6));
        if (::inet_ntop(AF_INET6, &ipv6.sin6_addr,
                        buffer.data(), buffer.size()) == nullptr)
            return {};
    }
    return buffer.data();
}

[[nodiscard]] std::string endpointText(
    std::string_view address, std::uint16_t port)
{
    if (address.empty() || port == 0U)
        return {};
    const bool ipv6 = address.find(':') != std::string_view::npos;
    std::string endpoint;
    endpoint.reserve(address.size() + 8U);
    if (ipv6)
        endpoint.push_back('[');
    endpoint.append(address);
    if (ipv6)
        endpoint.push_back(']');
    endpoint.push_back(':');
    endpoint.append(std::to_string(port));
    return endpoint;
}

[[nodiscard]] std::string boundEndpointText(
    const rdp_server::server::transport::TcpPeerEndpoint &endpoint)
{
    if (!endpoint.valid() || endpoint.port == 0U)
        return {};

    int family = 0;
    if (endpoint.family ==
        rdp_server::server::transport::TcpPeerAddressFamily::Ipv4)
        family = AF_INET;
    else if (endpoint.family ==
             rdp_server::server::transport::TcpPeerAddressFamily::Ipv6)
        family = AF_INET6;
    if (family == 0)
        return {};

    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (::inet_ntop(family, endpoint.address.data(),
                    buffer.data(), buffer.size()) == nullptr)
        return {};
    return endpointText(buffer.data(), endpoint.port);
}

[[nodiscard]] bool allAllocatedMcsChannelsJoined(
    const rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    const std::uint32_t allocatedUserId = session.allocatedUserId();
    if (allocatedUserId == 0U ||
        allocatedUserId >
            static_cast<std::uint32_t>(
                (std::numeric_limits<std::uint16_t>::max)()))
        return false;

    const auto userChannelId = static_cast<std::uint16_t>(allocatedUserId);
    const std::uint16_t ioChannelId = session.allocatedIoChannelId();
    if (ioChannelId == 0U ||
        !session.channelJoinConfirmed(userChannelId) ||
        !session.channelJoinConfirmed(ioChannelId))
        return false;

    // R3 owns the allocated join set and independently rechecks it before
    // Client Info. R10 reads this bounded snapshot only to schedule the next
    // protected broker operation; it never confers channel authority.
    const auto staticChannelIds = session.allocatedStaticChannelIds();
    return std::all_of(
        staticChannelIds.begin(), staticChannelIds.end(),
        [&session](std::uint16_t channelId) noexcept {
            return channelId != 0U &&
                   session.channelJoinConfirmed(channelId);
        });
}

[[nodiscard]] RuntimeSharingPermissionStatus sharingPermissionStatus(
    const rdp_server::server::security::OwnerSharingPermissionObservation&
        observation) noexcept
{
    using rdp_server::server::security::OwnerSharingReadOnlyDenial;
    RuntimeSharingPermissionStatus status;
    status.canRequest = observation.canRequest;
    status.activeGrant = observation.activeGrant;
    status.viewAllowed =
        (observation.effectivePermissionMask &
         rdp_server::server::security::kConsoleViewPermission) != 0U;
    status.inputAllowed =
        (observation.effectivePermissionMask &
         rdp_server::server::security::kConsoleInputPermission) != 0U;
    status.remainingMilliseconds = observation.remainingMilliseconds;
    switch (observation.denial)
    {
    case OwnerSharingReadOnlyDenial::None:
        status.denial = RuntimeSharingPermissionDenial::None;
        break;
    case OwnerSharingReadOnlyDenial::PermissionRequired:
        status.denial = RuntimeSharingPermissionDenial::PermissionRequired;
        break;
    case OwnerSharingReadOnlyDenial::PermissionExpired:
        status.denial = RuntimeSharingPermissionDenial::PermissionExpired;
        break;
    case OwnerSharingReadOnlyDenial::ComputerLocked:
        status.denial = RuntimeSharingPermissionDenial::ComputerLocked;
        break;
    case OwnerSharingReadOnlyDenial::LoggedInDesktopChanged:
        status.denial = RuntimeSharingPermissionDenial::LoggedInDesktopChanged;
        break;
    case OwnerSharingReadOnlyDenial::PermissionRevoked:
        status.denial = RuntimeSharingPermissionDenial::PermissionRevoked;
        break;
    case OwnerSharingReadOnlyDenial::EvidenceUnavailable:
        status.denial = RuntimeSharingPermissionDenial::Unavailable;
        break;
    }
    return status;
}

} // namespace

// One R2 verifier/framer attached to the sole R1 accepted socket. This holds
// no second TLS reader, server listener, R3 session or native authorization.
struct MacRuntimeCredSspState final
{
    rdp_server::server::security::StandaloneCredSspNtlmAcceptor acceptor{};
    rdp_server::server::security::TsRequestFrameReader reader{};
    rdp_server::server::security::TsRequestTlsReplyWriter writer{};
    rdp_server::server::security::StandalonePasswordAuthenticatedPrincipalProof
        authenticatedProof{};
    bool replyPending{};
    bool bindingReplyPending{};
    // Exact first MCS TPKT framing after R2 transport admission only.
    // This is bounded byte storage, not a second MCS/session state machine.
    std::array<std::uint8_t,
        rdp_server::server::transport::kMaximumInitialMcsTpktBytes>
        firstMcsTpkt{};
    std::size_t firstMcsBytes{};
    std::size_t firstMcsExpectedBytes{};
    bool connectResponseWriteNeedsRead{};
    bool attachConfirmWriteNeedsRead{};
    bool channelJoinConfirmWriteNeedsRead{};
    // These are R1 WANT direction hints only, not R3 licensing state.
    bool serverLicenseRequestWriteNeedsRead{};
    bool validClientWriteNeedsRead{};
    bool shareActivationWriteNeedsRead{};
    // R1 WANT direction hints only; R3 owns graphics replies and slices.
    bool graphicsControlWriteNeedsRead{};
    bool graphicsFrameWriteNeedsRead{};

    [[nodiscard]] bool prepareChallenge() noexcept
    {
        using namespace rdp_server::server::security;
        StandaloneSpnegoChallengeConfiguration challenge{};
        challenge.netbiosDomainName = kStandaloneNtlmPortableDomainName;
        challenge.netbiosComputerName = kStandaloneNtlmPortableServerName;
        const auto nanoseconds = std::chrono::duration_cast<
            std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        if (nanoseconds <= 0)
            return false;
        constexpr std::uint64_t kFileTimeUnixOffset = 116444736000000000ULL;
        const std::uint64_t ticks =
            static_cast<std::uint64_t>(nanoseconds) / 100U;
        if (ticks > (std::numeric_limits<std::uint64_t>::max)() -
                        kFileTimeUnixOffset)
            return false;
        challenge.timestampFileTime = kFileTimeUnixOffset + ticks;
        if (::RAND_bytes(
                challenge.serverChallenge.data(),
                static_cast<int>(challenge.serverChallenge.size())) != 1 ||
            std::all_of(
                challenge.serverChallenge.begin(),
                challenge.serverChallenge.end(),
                [](std::uint8_t byte) { return byte == 0U; }))
            return false;
        return acceptor.configureChallenge(challenge);
    }
};

void MacRuntimeHostControl::retireAcceptedClient() noexcept
{
    // R2 can synchronously close its enrolled R3 and R1 on revocation.
    // Destroy all borrowed relationships before the proof/SSL/BIO/socket.
    activeAdmissionBroker_.reset();
    if (activeMcsSession_ != nullptr)
        activeMcsSession_->close();
    // Native authorization may borrow the verified proof and sharing
    // authority. This is the sole accepted-client native retirement point:
    // retire after R2/R3 close, before the proof owner or R1 is destroyed.
    (void)nativeDesktop_.retireAfterAuthorizationLoss();
    activeMcsSession_.reset();
    activeCredSsp_.reset();
    if (activeConnection_ != nullptr)
    {
        activeConnection_->cancel();
        activeConnection_.reset();
        clientDisconnected_ = true;
    }
    activeConsentEpoch_.reset();
    activeAdmissionPermissionMask_ = 0U;
    activeListenerGeneration_ = 0U;
    activeCredentialsVerified_ = false;
    activeAdmissionStage_ = AcceptedClientAdmissionStage::None;
    activeGraphicsResizeDeadline_.reset();
    activeNextGraphicsFrameId_ = 1U;
    activeLastNativeFrameSequence_ = 0U;
    activeGraphicsFrameWritePending_ = false;
    activeFirstFramebufferAvailable_ = false;
    if (acceptedClientDiagnostics_.available)
    {
        acceptedClientDiagnostics_.preauthStage =
            RuntimeAcceptedClientPreauthStage::Closed;
        if (acceptedClientDiagnostics_.termination ==
            RuntimeAcceptedClientTermination::Open)
            acceptedClientDiagnostics_.termination =
                RuntimeAcceptedClientTermination::OwnerCancellation;
    }
    activeClientId_ = 0U;
    activeClientPeer_.clear();
}

RuntimeHostResult
MacRuntimeHostControl::failClosedAfterAllocationFailure() noexcept
{
    // Both serialized scheduler boundaries are noexcept. Allocation failure
    // must retire every borrowed client/native owner before reporting the
    // internal failure rather than crossing noexcept and terminating.
    retireAcceptedClient();
    if (stage_ != RuntimeHostStage::Revoked)
    {
        stage_ = listener_.valid()
            ? RuntimeHostStage::ListenerAvailable
            : RuntimeHostStage::Stopped;
    }
    customErrorMessage_.clear();
    return deny(RuntimeHostError::InternalFailure);
}

RuntimeHostResult
MacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try
{
    using namespace rdp_server::server;
    using Interest = transport::TcpConnectionIoInterest;
    using PreauthStage = transport::PreauthStage;
    using WriteStatus = security::TsRequestTlsWriteStatus;
    using ReadStatus = security::TsRequestTlsReadStatus;
    using FrameStatus = security::StandaloneCredSspFrameStatus;

    if (activeConnection_ == nullptr || activeCredSsp_ == nullptr ||
        activeConsentEpoch_ == std::nullopt ||
        (activeAdmissionPermissionMask_ &
         security::kConsoleViewPermission) == 0U ||
        (activeAdmissionPermissionMask_ &
         ~(security::kConsoleViewPermission |
           security::kConsoleInputPermission)) != 0U ||
        tlsContext_ == nullptr || !activeConnection_->active() ||
        !selectedStandaloneCredentialReady() ||
        !ownerSharingAuthority_.authorizesAtEpoch(
            activeAdmissionPermissionMask_, *activeConsentEpoch_) ||
        !listener_.valid() ||
        listener_.generation() != activeListenerGeneration_ ||
        !listener_.interfaceStillMatches() ||
        !tlsContext_->boundIdentityStatus(listener_)
            .boundIdentityMatchesGeneration(activeListenerGeneration_))
    {
        retireAcceptedClient();
        stage_ = RuntimeHostStage::ListenerAvailable;
        return deny(RuntimeHostError::HostSessionStale);
    }

    // CredSSP is not native Admission. The production broker alone can
    // complete R1 and privately enroll R3 against fresh native/consent proof.
    // A synthetic owner source never creates a broker, so queued first-MCS
    // bytes remain unread throughout its authenticated lifetime.
    if (activeCredentialsVerified_)
    {
        const auto rejectAdmission = [this]() noexcept -> RuntimeHostResult {
            retireAcceptedClient();
            stage_ = RuntimeHostStage::ListenerAvailable;
            return deny(RuntimeHostError::AuthenticationRejected);
        };
        if (!activeCredSsp_->authenticatedProof.revalidatesAuthenticatedSession() ||
            (activeAdmissionBroker_ != nullptr &&
             !activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_)))
            return rejectAdmission();

        if (activeAdmissionStage_ == AcceptedClientAdmissionStage::CredentialsVerified)
            return {RuntimeHostError::None, true};
        if (activeAdmissionBroker_ == nullptr)
            return rejectAdmission();

        if (activeAdmissionStage_ == AcceptedClientAdmissionStage::Prepared)
        {
            // Construct R3 before R2 borrows it; R2 will terminally close
            // this exact owner and R1 if its protected completion loses proof.
            activeMcsSession_ =
                std::make_unique<transport::McsSessionLifecycle>();
            if (!activeAdmissionBroker_->authorizeR1CredSspAdmission(
                    *activeMcsSession_) ||
                activeConnection_->stage() != PreauthStage::AwaitMcsConnectInitial ||
                !activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_))
                return rejectAdmission();
            activeAdmissionStage_ = AcceptedClientAdmissionStage::TransportAdmitted;
            acceptedClientDiagnostics_.preauthStage =
                RuntimeAcceptedClientPreauthStage::AwaitMcsConnectInitial;
            acceptedClientDiagnostics_.authenticationStage =
                RuntimeAcceptedClientAuthenticationStage::Admission;
            acceptedClientDiagnostics_.protocolStage =
                RuntimeAcceptedClientProtocolStage::NativeAdmissionVerified;
            return {RuntimeHostError::None, false};
        }

        // The existing immutable R10 policy and service-lifetime licensing
        // identity are borrowed, never recreated for an accepted peer.
        // Only the original concrete R2 broker may choose the no-CAL mode.
        if (activeAdmissionStage_ ==
            AcceptedClientAdmissionStage::ClientInfoAccepted)
        {
            if (activeMcsSession_ == nullptr || !deploymentPolicy_ ||
                !deploymentPolicy_->usesPersonalTerminalServerLicensingFlow() ||
                !licensingContext_.configured() ||
                licensingContext_.identity() == nullptr ||
                licensingContext_.credential() == nullptr ||
                activeMcsSession_->phase() !=
                    transport::McsSessionPhase::AwaitServerLicenseRequest ||
                !activeAdmissionBroker_->authorizeR3PersonalDesktopLicensingMode(
                    *activeMcsSession_, *deploymentPolicy_) ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();
            activeAdmissionStage_ =
                AcceptedClientAdmissionStage::ServerLicenseRequestPending;
            return {RuntimeHostError::None, false};
        }
        if (activeAdmissionStage_ ==
            AcceptedClientAdmissionStage::ClientLicenseResponseAccepted)
        {
            if (activeMcsSession_ == nullptr ||
                activeMcsSession_->phase() !=
                    transport::McsSessionPhase::AwaitPersonalDesktopValidClientWrite)
                return rejectAdmission();
            activeAdmissionStage_ =
                AcceptedClientAdmissionStage::ValidClientPending;
            return {RuntimeHostError::None, false};
        }
        if (activeAdmissionStage_ ==
            AcceptedClientAdmissionStage::ValidClientDelivered)
        {
            if (activeMcsSession_ == nullptr || !deploymentPolicy_ ||
                activeMcsSession_->phase() !=
                    transport::McsSessionPhase::AwaitDemandActive)
                return rejectAdmission();

            using Feature = transport::RdpDemandActiveFeature;
            Feature features = Feature::DynamicVirtualChannels;
            if ((activeAdmissionPermissionMask_ &
                 security::kConsoleInputPermission) != 0U)
                features = features | Feature::SlowPathInput;

            const auto profile =
                activeAdmissionBroker_->
                    authorizeR3PersonalDesktopMacDemandActiveProfile(
                        *activeMcsSession_, *deploymentPolicy_, features);
            if (!profile)
                return rejectAdmission();
            const auto first =
                activeAdmissionBroker_->
                    authorizeR3PersonalDesktopShareActivation(
                        *activeMcsSession_, *deploymentPolicy_, *profile);
            if (!first || !*first ||
                first->kind != transport::RdpShareServerWriteKind::DemandActive ||
                activeMcsSession_->phase() !=
                    transport::McsSessionPhase::ShareActivation ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();

            activeAdmissionStage_ =
                AcceptedClientAdmissionStage::ShareActivationWritePending;
            acceptedClientDiagnostics_.protocolStage =
                RuntimeAcceptedClientProtocolStage::ShareActivation;
            return {RuntimeHostError::None, false};
        }

        if (activeAdmissionStage_ ==
            AcceptedClientAdmissionStage::ShareActivated)
        {
            if (activeMcsSession_ == nullptr || !deploymentPolicy_ ||
                activeMcsSession_->phase() !=
                    transport::McsSessionPhase::ShareActivated ||
                !activeAdmissionBroker_->
                    authorizeR3GraphicsDynamicVirtualChannel(
                        *activeMcsSession_, *deploymentPolicy_) ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();
            activeAdmissionStage_ =
                AcceptedClientAdmissionStage::GraphicsControlWritePending;
            return {RuntimeHostError::None, false};
        }

        const bool readingFirstMcs =
            activeAdmissionStage_ == AcceptedClientAdmissionStage::TransportAdmitted;
        const bool writingConnectResponse =
            activeAdmissionStage_ == AcceptedClientAdmissionStage::Admitted;
        const bool readingErectDomain =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ConnectResponseDelivered;
        const bool readingAttachUser =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ErectDomainAccepted;
        const bool writingAttachConfirm =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::AttachUserAccepted;
        const bool readingChannelJoin =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::AttachConfirmDelivered;
        const bool writingChannelJoinConfirm =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ChannelJoinConfirmPending;
        const bool readingClientInfo =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ClientInfoExpected;
        const bool writingServerLicenseRequest =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ServerLicenseRequestPending;
        const bool readingClientLicenseResponse =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ServerLicenseRequestDelivered;
        const bool writingValidClient =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ValidClientPending;
        const bool writingShareActivation =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ShareActivationWritePending;
        const bool readingShareActivation =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::ShareActivationClientExpected;
        const bool writingGraphicsControl =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::GraphicsControlWritePending;
        const bool readingGraphicsControl =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::GraphicsControlClientExpected;
        if (activeMcsSession_ == nullptr)
            return rejectAdmission();

        if (!readingFirstMcs && !writingConnectResponse &&
            !readingErectDomain && !readingAttachUser &&
            !writingAttachConfirm && !readingChannelJoin &&
            !writingChannelJoinConfirm && !readingClientInfo &&
            !writingServerLicenseRequest && !readingClientLicenseResponse &&
            !writingValidClient && !writingShareActivation &&
            !readingShareActivation && !writingGraphicsControl &&
            !readingGraphicsControl)
        {
            // Mapped R3 Graphics control is the first point where R10 may
            // construct the downstream native owner. Native authorization
            // independently re-reads macOS audit/session evidence and the
            // current owner epoch; no R3 scalar can manufacture this grant.
            if (activeAdmissionStage_ !=
                    AcceptedClientAdmissionStage::GraphicsReady)
                return rejectAdmission();

            if (!nativeDesktop_.active())
            {
                const auto graphicsProof =
                    activeMcsSession_->firstClientAcceptanceObservability();
                if (!graphicsProof.shareActivated ||
                    !graphicsProof.graphicsDynamicVirtualChannelActivated ||
                    !graphicsProof.graphicsControlReady ||
                    !graphicsProof.surfaceCreated ||
                    !graphicsProof.surfaceMapped ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                const RuntimeHostResult nativeAttach =
                    nativeDesktop_.attachAuthenticatedSession(
                        activeCredSsp_->authenticatedProof,
                        ownerSharingAuthority_,
                        activeAdmissionPermissionMask_);
                if (!nativeAttach.succeeded())
                {
                    retireAcceptedClient();
                    stage_ = RuntimeHostStage::ListenerAvailable;
                    return deny(nativeAttach.error);
                }
                if (!activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                // Attachment is not frame delivery. Keep the public stage at
                // ShareActivated until a later exact R3/R4 frame receipt and
                // client ACK prove visibility.
                return {RuntimeHostError::None, false};
            }
            return {RuntimeHostError::None, true};
        }
        auto& connection = *activeConnection_;
        auto& credSsp = *activeCredSsp_;
        auto& session = *activeMcsSession_;
        if ((writingServerLicenseRequest || readingClientLicenseResponse ||
             writingValidClient || writingShareActivation ||
             readingShareActivation || writingGraphicsControl ||
             readingGraphicsControl) &&
            (!deploymentPolicy_ || !licensingContext_.configured() ||
             licensingContext_.identity() == nullptr ||
             licensingContext_.credential() == nullptr ||
             !deploymentPolicy_->usesPersonalTerminalServerLicensingFlow()))
            return rejectAdmission();
        if (!connection.active() ||
            connection.stage() != PreauthStage::AwaitMcsConnectInitial ||
            session.phase() == transport::McsSessionPhase::Closed)
            return rejectAdmission();

        // Existing R1 SSL/BIO owns every application read/write. A WANT_READ
        // during a pending write must poll Read; new writes start on Write.
        const bool readingMcsTpkt =
            readingFirstMcs || readingErectDomain || readingAttachUser ||
            readingChannelJoin || readingClientInfo ||
            readingClientLicenseResponse || readingShareActivation ||
            readingGraphicsControl;
        const bool writeNeedsRead = writingServerLicenseRequest
            ? credSsp.serverLicenseRequestWriteNeedsRead
            : (writingValidClient
                   ? credSsp.validClientWriteNeedsRead
                   : (writingShareActivation
                          ? credSsp.shareActivationWriteNeedsRead
                          : (writingGraphicsControl
                                 ? credSsp.graphicsControlWriteNeedsRead
                                 : (writingConnectResponse
                                        ? credSsp.connectResponseWriteNeedsRead
                                        : (writingAttachConfirm
                                               ? credSsp.attachConfirmWriteNeedsRead
                                               : credSsp.channelJoinConfirmWriteNeedsRead)))));
        const Interest interest = readingMcsTpkt
            ? connection.ioInterest()
            : (writeNeedsRead ? Interest::Read : Interest::Write);
        if (interest != Interest::Read && interest != Interest::Write)
            return rejectAdmission();
        // Erect or Attach may already be decrypted in a preceding TLS record;
        // a new socket POLLIN is not required once R1 owns buffered plaintext.
        const bool ready = readingMcsTpkt &&
                           interest == Interest::Read &&
                           connection.tlsApplicationReadReady();
        if (!ready)
        {
            const std::uintptr_t socket = connection.nativeSocket();
            if (socket > static_cast<std::uintptr_t>(
                             (std::numeric_limits<int>::max)()))
                return rejectAdmission();
            pollfd descriptor{};
            descriptor.fd = static_cast<int>(socket);
            descriptor.events = interest == Interest::Read ? POLLIN : POLLOUT;
            const int count = ::poll(&descriptor, 1U, 0);
            if (count < 0 && errno == EINTR)
                return {RuntimeHostError::None, true};
            if (count < 0 || (descriptor.revents & (POLLNVAL | POLLERR)) != 0)
                return rejectAdmission();
            if (count == 0 ||
                (descriptor.revents & (descriptor.events | POLLHUP)) == 0)
                return {RuntimeHostError::None, true};
        }

        if (!activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_))
            return rejectAdmission();
        if (readingMcsTpkt)
        {
            // Reuse one accepted-client TPKT buffer. Read only the 4-byte
            // RFC1006 header, then exactly its bounded declared packet length.
            // A coalesced following PDU remains owned by R1 for a later tick.
            const std::size_t target = credSsp.firstMcsExpectedBytes == 0U
                ? 4U : credSsp.firstMcsExpectedBytes;
            if (credSsp.firstMcsBytes >= target ||
                target > credSsp.firstMcsTpkt.size())
                return rejectAdmission();
            const std::size_t remaining = target - credSsp.firstMcsBytes;
            const auto intake = connection.readTlsApplicationData(
                std::span(credSsp.firstMcsTpkt)
                    .subspan(credSsp.firstMcsBytes, remaining));
            using TlsOutcome = transport::TlsApplicationIoOutcome;
            if (intake.outcome == TlsOutcome::NeedRead ||
                intake.outcome == TlsOutcome::NeedWrite)
                return {RuntimeHostError::None, true};
            if (intake.outcome != TlsOutcome::Progress ||
                intake.bytes == 0U || intake.bytes > remaining ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();
            credSsp.firstMcsBytes += intake.bytes;
            if (credSsp.firstMcsExpectedBytes == 0U &&
                credSsp.firstMcsBytes == 4U)
            {
                if (credSsp.firstMcsTpkt[0] != 3U ||
                    credSsp.firstMcsTpkt[1] != 0U)
                    return rejectAdmission();
                credSsp.firstMcsExpectedBytes =
                    (static_cast<std::size_t>(credSsp.firstMcsTpkt[2]) << 8U) |
                    static_cast<std::size_t>(credSsp.firstMcsTpkt[3]);
                if (credSsp.firstMcsExpectedBytes < 7U ||
                    credSsp.firstMcsExpectedBytes > credSsp.firstMcsTpkt.size())
                    return rejectAdmission();
            }
            if (credSsp.firstMcsExpectedBytes == 0U ||
                credSsp.firstMcsBytes < credSsp.firstMcsExpectedBytes)
                return {RuntimeHostError::None, false};
            const auto completeTpkt =
                std::span(credSsp.firstMcsTpkt)
                    .first(credSsp.firstMcsExpectedBytes);
            if (readingFirstMcs)
            {
                const auto admitted =
                    activeAdmissionBroker_->authorizeR3McsConnectInitial(
                        session, completeTpkt);
                if (admitted !=
                        transport::McsSessionIntake::AdmittedConnectInitial ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                // R3 copied all semantic state; never retain the borrowed TPKT.
                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                activeAdmissionStage_ = AcceptedClientAdmissionStage::Admitted;
                acceptedClientDiagnostics_.authenticationStage =
                    RuntimeAcceptedClientAuthenticationStage::Mcs;
                acceptedClientDiagnostics_.protocolStage =
                    RuntimeAcceptedClientProtocolStage::McsConnectInitialReceived;
                acceptedClientDiagnostics_.mcsSessionAdvanced = true;
                return {RuntimeHostError::None, false};
            }

            if (readingErectDomain)
            {
                const auto erect =
                    activeAdmissionBroker_->authorizeR3ErectDomain(
                        session, completeTpkt);
                if (erect != transport::McsSessionIntake::ErectDomainAccepted ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::ErectDomainAccepted;
                acceptedClientDiagnostics_.protocolStage =
                    RuntimeAcceptedClientProtocolStage::McsErectDomainReceived;
                return {RuntimeHostError::None, false};
            }

            if (readingAttachUser)
            {
                const auto attach =
                    activeAdmissionBroker_->authorizeR3AttachUser(
                        session, completeTpkt);
                if (attach != transport::McsSessionIntake::AttachUserAccepted ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::AttachUserAccepted;
                acceptedClientDiagnostics_.protocolStage =
                    RuntimeAcceptedClientProtocolStage::McsAttachUserReceived;
                return {RuntimeHostError::None, false};
            }

            if (readingChannelJoin)
            {
                const auto join =
                    activeAdmissionBroker_->authorizeR3ChannelJoin(
                        session, completeTpkt);
                if (join == transport::McsJoinStartOutcome::Rejected ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                if (join == transport::McsJoinStartOutcome::ReplyPending)
                {
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::ChannelJoinConfirmPending;
                }
                else if (join != transport::McsJoinStartOutcome::AlreadyJoined)
                {
                    // R10 never consumes another Join while a confirmation is
                    // pending. Buffered/AlreadyPending therefore indicate
                    // owner-state divergence and retire fail closed.
                    return rejectAdmission();
                }
                return {RuntimeHostError::None, false};
            }

            if (readingClientLicenseResponse)
            {
                // The sole R1 reader has received exactly one bounded TPKT
                // only after R3 committed the complete Server License Request.
                const auto intake =
                    activeAdmissionBroker_->
                        authorizeR3PersonalDesktopClientLicensingMessage(
                            session, *deploymentPolicy_,
                            *licensingContext_.credential(), completeTpkt);
                if (!intake ||
                    (*intake != transport::RdpLicensingIntake::ClientLicenseInfoAccepted &&
                     *intake != transport::RdpLicensingIntake::ClientNewLicenseRequestAccepted) ||
                    session.phase() !=
                        transport::McsSessionPhase::AwaitPersonalDesktopValidClientWrite ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::ClientLicenseResponseAccepted;
                return {RuntimeHostError::None, false};
            }

            if (readingGraphicsControl)
            {
                const auto intake =
                    activeAdmissionBroker_->
                        authorizeR3GraphicsDynamicVirtualChannelPdu(
                            session, *deploymentPolicy_, completeTpkt);
                if (!activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                using GraphicsIntake = transport::RdpGraphicsDvcClientIntake;
                switch (intake)
                {
                case GraphicsIntake::CapabilitiesAccepted:
                case GraphicsIntake::GraphicsCapabilitiesAccepted:
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::GraphicsControlWritePending;
                    break;
                case GraphicsIntake::CreateAccepted:
                case GraphicsIntake::GraphicsDataFragmentAccepted:
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::GraphicsControlClientExpected;
                    break;
                case GraphicsIntake::CreateRejected:
                case GraphicsIntake::GraphicsDataAccepted:
                case GraphicsIntake::Rejected:
                case GraphicsIntake::Closed:
                    return rejectAdmission();
                }
                return {RuntimeHostError::None, false};
            }

            if (readingShareActivation)
            {
                const auto intake =
                    activeAdmissionBroker_->
                        authorizeR3PersonalDesktopShareActivationPdu(
                            session, *deploymentPolicy_, completeTpkt);
                if (intake ==
                        transport::RdpShareActivationClientIntake::Rejected ||
                    intake ==
                        transport::RdpShareActivationClientIntake::Closed ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                credSsp.firstMcsBytes = 0U;
                credSsp.firstMcsExpectedBytes = 0U;
                switch (intake)
                {
                case transport::RdpShareActivationClientIntake::
                    ConfirmActiveAccepted:
                case transport::RdpShareActivationClientIntake::
                    RequestControlAccepted:
                case transport::RdpShareActivationClientIntake::
                    FontListAccepted:
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::
                            ShareActivationWritePending;
                    break;
                case transport::RdpShareActivationClientIntake::
                    SynchronizeAccepted:
                case transport::RdpShareActivationClientIntake::
                    CooperateAccepted:
                case transport::RdpShareActivationClientIntake::
                    InputIgnoredUntilActivated:
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::
                            ShareActivationClientExpected;
                    break;
                case transport::RdpShareActivationClientIntake::Rejected:
                case transport::RdpShareActivationClientIntake::Closed:
                    return rejectAdmission();
                }
                return {RuntimeHostError::None, false};
            }

            const auto clientInfo =
                activeAdmissionBroker_->authorizeR3ClientInfoPacket(
                    session, completeTpkt);
            if (!clientInfo ||
                session.phase() !=
                    transport::McsSessionPhase::AwaitServerLicenseRequest ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();
            credSsp.firstMcsBytes = 0U;
            credSsp.firstMcsExpectedBytes = 0U;
            activeAdmissionStage_ =
                AcceptedClientAdmissionStage::ClientInfoAccepted;
            return {RuntimeHostError::None, false};
        }

        if (writingServerLicenseRequest || writingValidClient ||
            writingShareActivation || writingGraphicsControl)
        {
            using TlsOutcome = transport::TlsApplicationIoOutcome;
            if (writingServerLicenseRequest)
            {
                const auto pending =
                    activeAdmissionBroker_->
                        authorizeR3PersonalDesktopServerLicenseRequestWrite(
                            session, *deploymentPolicy_,
                            *licensingContext_.identity(),
                            *licensingContext_.credential());
                if (!pending || !*pending)
                    return rejectAdmission();
                const auto sent = connection.writeTlsApplicationData(
                    pending->bytes);
                if (sent.outcome == TlsOutcome::NeedRead ||
                    sent.outcome == TlsOutcome::NeedWrite)
                {
                    if (sent.bytes != 0U)
                        return rejectAdmission();
                    credSsp.serverLicenseRequestWriteNeedsRead =
                        sent.outcome == TlsOutcome::NeedRead;
                    return {RuntimeHostError::None, true};
                }
                if (sent.outcome != TlsOutcome::Progress ||
                    sent.bytes == 0U || sent.bytes > pending->bytes.size() ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                credSsp.serverLicenseRequestWriteNeedsRead = false;
                const auto receipt =
                    activeAdmissionBroker_->
                        completeR3PersonalDesktopServerLicenseRequestWrite(
                            session, *deploymentPolicy_,
                            pending->replySequence, pending->writeSliceSequence,
                            sent.bytes);
                if (receipt ==
                        transport::RdpServerLicenseRequestWriteOutcome::Rejected ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                if (receipt ==
                    transport::RdpServerLicenseRequestWriteOutcome::Delivered)
                {
                    if (session.phase() !=
                        transport::McsSessionPhase::AwaitClientLicenseResponse)
                        return rejectAdmission();
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::ServerLicenseRequestDelivered;
                }
                return {RuntimeHostError::None, false};
            }

            if (writingGraphicsControl)
            {
                const auto pending =
                    activeAdmissionBroker_->
                        pendingR3GraphicsDynamicVirtualChannelWrite(
                            session, *deploymentPolicy_);
                if (!pending || !*pending ||
                    pending->kind ==
                        transport::RdpGraphicsDvcWriteKind::GraphicsFrameData)
                    return rejectAdmission();

                const auto sent =
                    connection.writeTlsApplicationData(pending->bytes);
                if (sent.outcome == TlsOutcome::NeedRead ||
                    sent.outcome == TlsOutcome::NeedWrite)
                {
                    if (sent.bytes != 0U)
                        return rejectAdmission();
                    credSsp.graphicsControlWriteNeedsRead =
                        sent.outcome == TlsOutcome::NeedRead;
                    return {RuntimeHostError::None, true};
                }
                if (sent.outcome != TlsOutcome::Progress ||
                    sent.bytes == 0U || sent.bytes > pending->bytes.size() ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                credSsp.graphicsControlWriteNeedsRead = false;
                const auto completedKind = pending->kind;
                const auto receipt =
                    activeAdmissionBroker_->
                        completeR3GraphicsDynamicVirtualChannelWrite(
                            session, *deploymentPolicy_,
                            pending->replySequence,
                            pending->writeSliceSequence, sent.bytes);
                if (receipt ==
                        transport::RdpGraphicsDvcWriteOutcome::Rejected ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                if (receipt == transport::RdpGraphicsDvcWriteOutcome::Pending)
                    return {RuntimeHostError::None, false};

                if (completedKind ==
                        transport::RdpGraphicsDvcWriteKind::CapabilitiesRequest ||
                    completedKind ==
                        transport::RdpGraphicsDvcWriteKind::CreateRequest)
                {
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::GraphicsControlClientExpected;
                    return {RuntimeHostError::None, false};
                }

                // R3 itself commits the final MAP write before projecting
                // control readiness. No native pixels or frame are borrowed.
                if (completedKind !=
                        transport::RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput ||
                    session.phase() != transport::McsSessionPhase::ShareActivated ||
                    !activeAdmissionBroker_->authorizeR3ApplicationTrafficReady(
                        session, *deploymentPolicy_))
                    return rejectAdmission();
                const auto observed =
                    session.firstClientAcceptanceObservability();
                if (!observed.graphicsDynamicVirtualChannelActivated ||
                    !observed.graphicsControlReady ||
                    !observed.surfaceCreated || !observed.surfaceMapped ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::GraphicsReady;
                activeGraphicsResizeDeadline_.reset();
                return {RuntimeHostError::None, false};
            }

            if (writingShareActivation)
            {
                const auto pending =
                    activeAdmissionBroker_->
                        authorizeR3PersonalDesktopShareActivationWrite(
                            session, *deploymentPolicy_);
                if (!pending || !*pending)
                    return rejectAdmission();

                const auto sent =
                    connection.writeTlsApplicationData(pending->bytes);
                if (sent.outcome == TlsOutcome::NeedRead ||
                    sent.outcome == TlsOutcome::NeedWrite)
                {
                    if (sent.bytes != 0U)
                        return rejectAdmission();
                    credSsp.shareActivationWriteNeedsRead =
                        sent.outcome == TlsOutcome::NeedRead;
                    return {RuntimeHostError::None, true};
                }
                if (sent.outcome != TlsOutcome::Progress ||
                    sent.bytes == 0U || sent.bytes > pending->bytes.size() ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();

                credSsp.shareActivationWriteNeedsRead = false;
                const auto completedKind = pending->kind;
                const auto receipt =
                    activeAdmissionBroker_->
                        completeR3PersonalDesktopShareActivationWrite(
                            session, *deploymentPolicy_,
                            pending->replySequence,
                            pending->writeSliceSequence, sent.bytes);
                if (receipt ==
                        transport::RdpShareActivationWriteOutcome::Rejected ||
                    !activeAdmissionBroker_->revalidate(
                        activeAdmissionPermissionMask_))
                    return rejectAdmission();
                if (receipt ==
                    transport::RdpShareActivationWriteOutcome::Pending)
                    return {RuntimeHostError::None, false};
                if (receipt ==
                    transport::RdpShareActivationWriteOutcome::Activated)
                {
                    if (session.phase() !=
                            transport::McsSessionPhase::ShareActivated ||
                        !activeAdmissionBroker_->
                            authorizeR3ApplicationTrafficReady(
                                session, *deploymentPolicy_) ||
                        !activeAdmissionBroker_->revalidate(
                            activeAdmissionPermissionMask_))
                        return rejectAdmission();

                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::ShareActivated;
                    activeGraphicsControlDeadline_ =
                        std::chrono::steady_clock::now() +
                        std::chrono::seconds{30};
                    acceptedClientDiagnostics_.protocolStage =
                        RuntimeAcceptedClientProtocolStage::ShareActivated;
                    acceptedClientDiagnostics_.shareActivated = true;
                    stage_ = RuntimeHostStage::ShareActivated;
                    lastError_ = RuntimeHostError::None;
                    return {RuntimeHostError::None, false};
                }

                if (receipt !=
                    transport::RdpShareActivationWriteOutcome::Delivered)
                    return rejectAdmission();

                switch (completedKind)
                {
                case transport::RdpShareServerWriteKind::DemandActive:
                case transport::RdpShareServerWriteKind::Cooperate:
                case transport::RdpShareServerWriteKind::GrantedControl:
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::
                            ShareActivationClientExpected;
                    break;
                case transport::RdpShareServerWriteKind::Synchronize:
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::
                            ShareActivationWritePending;
                    break;
                case transport::RdpShareServerWriteKind::FontMap:
                case transport::RdpShareServerWriteKind::None:
                    return rejectAdmission();
                }
                return {RuntimeHostError::None, false};
            }

            const auto pending =
                activeAdmissionBroker_->
                    authorizeR3PersonalDesktopValidClientWrite(
                        session, *deploymentPolicy_);
            if (!pending || !*pending)
                return rejectAdmission();
            const auto sent = connection.writeTlsApplicationData(pending->bytes);
            if (sent.outcome == TlsOutcome::NeedRead ||
                sent.outcome == TlsOutcome::NeedWrite)
            {
                if (sent.bytes != 0U)
                    return rejectAdmission();
                credSsp.validClientWriteNeedsRead =
                    sent.outcome == TlsOutcome::NeedRead;
                return {RuntimeHostError::None, true};
            }
            if (sent.outcome != TlsOutcome::Progress || sent.bytes == 0U ||
                sent.bytes > pending->bytes.size() ||
                !activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_))
                return rejectAdmission();
            credSsp.validClientWriteNeedsRead = false;
            const auto receipt =
                activeAdmissionBroker_->completeR3PersonalDesktopValidClientWrite(
                    session, *deploymentPolicy_,
                    pending->replySequence, pending->writeSliceSequence,
                    sent.bytes);
            if (receipt ==
                    transport::RdpPersonalDesktopValidClientWriteOutcome::Rejected ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();
            if (receipt ==
                transport::RdpPersonalDesktopValidClientWriteOutcome::Delivered)
            {
                if (session.phase() !=
                    transport::McsSessionPhase::AwaitDemandActive)
                    return rejectAdmission();
                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::ValidClientDelivered;
            }
            return {RuntimeHostError::None, false};
        }

        const auto pending = writingConnectResponse
            ? activeAdmissionBroker_->authorizeR3ConnectResponseWrite(session)
            : (writingAttachConfirm
                   ? activeAdmissionBroker_->authorizeR3AttachUserConfirmWrite(
                         session)
                   : activeAdmissionBroker_->authorizeR3ChannelJoinConfirmWrite(
                         session));
        if (!pending || !*pending)
            return rejectAdmission();
        const auto sent = connection.writeTlsApplicationData(pending->bytes);
        using TlsOutcome = transport::TlsApplicationIoOutcome;
        bool& currentWriteNeedsRead = writingConnectResponse
            ? credSsp.connectResponseWriteNeedsRead
            : (writingAttachConfirm
                   ? credSsp.attachConfirmWriteNeedsRead
                   : credSsp.channelJoinConfirmWriteNeedsRead);
        if (sent.outcome == TlsOutcome::NeedRead ||
            sent.outcome == TlsOutcome::NeedWrite)
        {
            currentWriteNeedsRead = sent.outcome == TlsOutcome::NeedRead;
            return {RuntimeHostError::None, true};
        }
        if (sent.outcome != TlsOutcome::Progress || sent.bytes == 0U ||
            sent.bytes > pending->bytes.size() ||
            !activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_))
            return rejectAdmission();
        currentWriteNeedsRead = false;
        if (writingChannelJoinConfirm)
        {
            const auto receipt =
                activeAdmissionBroker_->completeR3ChannelJoinConfirmWrite(
                    session, pending->replySequence,
                    pending->writeSliceSequence, sent.bytes);
            if (receipt == transport::McsJoinWriteOutcome::Rejected ||
                !activeAdmissionBroker_->revalidate(
                    activeAdmissionPermissionMask_))
                return rejectAdmission();
            if (receipt == transport::McsJoinWriteOutcome::Confirmed)
            {
                if (session.phase() !=
                    transport::McsSessionPhase::AwaitChannelJoin)
                    return rejectAdmission();
                if (allAllocatedMcsChannelsJoined(session))
                {
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::ClientInfoExpected;
                    acceptedClientDiagnostics_.protocolStage =
                        RuntimeAcceptedClientProtocolStage::McsEstablished;
                }
                else
                {
                    activeAdmissionStage_ =
                        AcceptedClientAdmissionStage::AttachConfirmDelivered;
                    acceptedClientDiagnostics_.protocolStage =
                        RuntimeAcceptedClientProtocolStage::McsChannelJoin;
                }
            }
            return {RuntimeHostError::None, false};
        }

        const auto receipt = writingConnectResponse
            ? activeAdmissionBroker_->completeR3ConnectResponseWrite(
                  session, pending->replySequence, pending->writeSliceSequence,
                  sent.bytes)
            : activeAdmissionBroker_->completeR3AttachUserConfirmWrite(
                  session, pending->replySequence, pending->writeSliceSequence,
                  sent.bytes);
        if (receipt == transport::McsConnectResponseWriteOutcome::Rejected ||
            !activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_))
            return rejectAdmission();
        if (receipt == transport::McsConnectResponseWriteOutcome::Delivered)
        {
            if (writingConnectResponse)
            {
                if (session.phase() != transport::McsSessionPhase::AwaitErectDomain)
                    return rejectAdmission();
                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::ConnectResponseDelivered;
                acceptedClientDiagnostics_.protocolStage =
                    RuntimeAcceptedClientProtocolStage::McsConnectResponseSent;
            }
            else
            {
                if (session.phase() != transport::McsSessionPhase::AwaitChannelJoin)
                    return rejectAdmission();
                activeAdmissionStage_ =
                    AcceptedClientAdmissionStage::AttachConfirmDelivered;
            }
        }
        return {RuntimeHostError::None, false};
    }

    auto fail = [this]() noexcept -> RuntimeHostResult {
        if (activeCredSsp_ != nullptr)
        {
            using Failure = security::StandaloneAuthenticationFailureStage;
            using Projected = RuntimeAcceptedClientStandaloneFailureStage;
            const auto failure = activeCredSsp_->acceptor.failureStage();
            switch (failure)
            {
            case Failure::None:
                break;
            case Failure::NtlmNegotiation:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::NtlmNegotiation;
                break;
            case Failure::Mic:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::Mic;
                break;
            case Failure::SignSeal:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::SignSeal;
                break;
            case Failure::Spnego:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::Spnego;
                break;
            case Failure::PubKeyAuth:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::PubKeyAuth;
                break;
            case Failure::AuthInfo:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::AuthInfo;
                break;
            case Failure::Admission:
                acceptedClientDiagnostics_.standaloneFailureStage =
                    Projected::Admission;
                break;
            }
        }
        const auto termination = activeConnection_ != nullptr
            ? activeConnection_->termination()
            : transport::TcpConnectionTermination::Cancelled;
        acceptedClientDiagnostics_.preauthStage =
            RuntimeAcceptedClientPreauthStage::Closed;
        acceptedClientDiagnostics_.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        switch (termination)
        {
        case transport::TcpConnectionTermination::PeerEof:
            acceptedClientDiagnostics_.termination =
                RuntimeAcceptedClientTermination::PeerEof;
            acceptedClientDiagnostics_.credSspTransition =
                RuntimeAcceptedClientCredSspTransition::Closed;
            break;
        case transport::TcpConnectionTermination::PeerReset:
            acceptedClientDiagnostics_.termination =
                RuntimeAcceptedClientTermination::PeerReset;
            break;
        case transport::TcpConnectionTermination::PeerTlsAlert:
            acceptedClientDiagnostics_.termination =
                RuntimeAcceptedClientTermination::PeerTlsAlert;
            break;
        case transport::TcpConnectionTermination::TlsFailure:
        case transport::TcpConnectionTermination::LocalTlsFailure:
            acceptedClientDiagnostics_.termination =
                RuntimeAcceptedClientTermination::TlsFailure;
            break;
        default:
            acceptedClientDiagnostics_.termination =
                RuntimeAcceptedClientTermination::ProtocolError;
            break;
        }
        retireAcceptedClient();
        stage_ = RuntimeHostStage::ListenerAvailable;
        return deny(
            termination == transport::TcpConnectionTermination::PeerEof
                ? RuntimeHostError::AuthenticationIncompletePeerClosed
                : RuntimeHostError::AuthenticationRejected);
    };

    auto& connection = *activeConnection_;
    auto& credSsp = *activeCredSsp_;
    const auto stage = connection.stage();
    if (stage == PreauthStage::Closed ||
        stage == PreauthStage::AwaitMcsConnectInitial)
        return fail();

    Interest interest = connection.ioInterest();
    if (interest == Interest::ConfigureTls)
    {
        // R1 takes unique SSL ownership. Its BIO uses the same accepted socket
        // and the selected certificate must match the live listener identity.
        auto serverTls = tlsContext_->createServerTls();
        RuntimeTlsCertificateFingerprint configuredFingerprint{};
        RuntimeTlsCertificateFingerprint selectedFingerprint{};
        unsigned int selectedFingerprintSize = 0U;
        const bool certificateMatches =
            serverTls &&
            tlsContext_->certificateSha256Fingerprint(configuredFingerprint) &&
            ::SSL_get_certificate(serverTls.get()) != nullptr &&
            ::X509_digest(
                ::SSL_get_certificate(serverTls.get()), ::EVP_sha256(),
                selectedFingerprint.data(), &selectedFingerprintSize) == 1 &&
            selectedFingerprintSize == selectedFingerprint.size() &&
            ::CRYPTO_memcmp(
                configuredFingerprint.data(), selectedFingerprint.data(),
                configuredFingerprint.size()) == 0;
        if (!certificateMatches ||
            !connection.attachServerTls(std::move(serverTls)))
            return fail();
        acceptedClientDiagnostics_.preauthStage =
            RuntimeAcceptedClientPreauthStage::AwaitTls;
        acceptedClientDiagnostics_.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::Handshaking;
        return {RuntimeHostError::None, false};
    }
    if (interest == Interest::Closed)
        return fail();

    if (stage == PreauthStage::AwaitCredSsp &&
        credSsp.replyPending)
    {
        switch (credSsp.writer.status())
        {
        case WriteStatus::Progress:
        case WriteStatus::NeedWrite:
            interest = Interest::Write;
            break;
        case WriteStatus::NeedRead:
            interest = Interest::Read;
            break;
        case WriteStatus::Complete:
        {
            if (!credSsp.writer.releaseReply())
                return fail();
            credSsp.replyPending = false;
            if (credSsp.bindingReplyPending)
            {
                credSsp.bindingReplyPending = false;
                acceptedClientDiagnostics_.credSspTransition =
                    RuntimeAcceptedClientCredSspTransition::BindingVerified;
            }
            return {RuntimeHostError::None, false};
        }
        case WriteStatus::Idle:
        case WriteStatus::Invalid:
        case WriteStatus::Closed:
            return fail();
        }
    }

    // Nonblocking, zero-wait readiness: the existing Qt owner-thread service
    // tick is the scheduler. No worker, sleep or independent 25ms polling loop.
    bool ready = stage == PreauthStage::AwaitCredSsp &&
                 !credSsp.replyPending &&
                 connection.tlsApplicationReadReady() &&
                 interest == Interest::Read;
    if (!ready)
    {
        const std::uintptr_t socket = connection.nativeSocket();
        if (socket > static_cast<std::uintptr_t>(
                         (std::numeric_limits<int>::max)()))
            return fail();
        pollfd descriptor{};
        descriptor.fd = static_cast<int>(socket);
        descriptor.events = interest == Interest::Read ? POLLIN : POLLOUT;
        const int count = ::poll(&descriptor, 1U, 0);
        if (count < 0)
        {
            if (errno == EINTR)
                return {RuntimeHostError::None, true};
            return fail();
        }
        if (count == 0)
            return {RuntimeHostError::None, true};
        if ((descriptor.revents & (POLLNVAL | POLLERR)) != 0)
            return fail();
        ready = (descriptor.revents & descriptor.events) != 0 ||
                (descriptor.revents & POLLHUP) != 0;
        if (!ready)
            return {RuntimeHostError::None, true};
    }

    if (stage != PreauthStage::AwaitCredSsp)
    {
        (void)connection.onSocketReady(
            interest == Interest::Read, interest == Interest::Write);
        if (!connection.active())
            return fail();
        if (connection.establishedTls() != nullptr)
        {
            acceptedClientDiagnostics_.preauthStage =
                RuntimeAcceptedClientPreauthStage::AwaitCredSsp;
            acceptedClientDiagnostics_.tlsHandshakeStage =
                RuntimeAcceptedClientTlsHandshakeStage::Established;
            acceptedClientDiagnostics_.credSspTransition =
                RuntimeAcceptedClientCredSspTransition::AwaitingToken;
        }
        return {RuntimeHostError::None, false};
    }

    if (credSsp.replyPending)
    {
        const auto written = credSsp.writer.writeOneTlsStep(connection);
        switch (written.status)
        {
        case WriteStatus::Progress:
        case WriteStatus::NeedRead:
        case WriteStatus::NeedWrite:
            return {RuntimeHostError::None, false};
        case WriteStatus::Complete:
            if (!credSsp.writer.releaseReply())
                return fail();
            credSsp.replyPending = false;
            if (credSsp.bindingReplyPending)
            {
                credSsp.bindingReplyPending = false;
                acceptedClientDiagnostics_.credSspTransition =
                    RuntimeAcceptedClientCredSspTransition::BindingVerified;
            }
            return {RuntimeHostError::None, false};
        case WriteStatus::Idle:
        case WriteStatus::Invalid:
        case WriteStatus::Closed:
            return fail();
        }
    }

    const auto read = credSsp.reader.readOneTlsStep(connection);
    switch (read.status)
    {
    case ReadStatus::Progress:
    case ReadStatus::NeedRead:
    case ReadStatus::NeedWrite:
        return {RuntimeHostError::None, false};
    case ReadStatus::Invalid:
    case ReadStatus::Closed:
        return fail();
    case ReadStatus::Complete:
        break;
    }

    struct CredentialVisit final
    {
        MacRuntimeCredSspState* credSsp{};
        transport::OwnedPreauthTcpConnection* connection{};
        FrameStatus result{FrameStatus::Rejected};
    } visit{&credSsp, &connection};

    const auto process = +[](
        const security::EphemeralNtlmV2Credential& credential,
        void* opaque) noexcept -> bool {
        auto* const current = static_cast<CredentialVisit*>(opaque);
        if (current == nullptr || current->credSsp == nullptr ||
            current->connection == nullptr)
            return false;
        current->result =
            current->credSsp->acceptor.processCompleteOwnedFrame(
                *current->connection, current->credSsp->reader,
                current->credSsp->writer, credential);
        return true;
    };

    if (!standalonePasswordCredential_.visit(
            standaloneCredentialGeneration_, process, &visit))
        return fail();

    switch (visit.result)
    {
    case FrameStatus::NegoReplyQueued:
    case FrameStatus::BindingReplyQueued:
        if (credSsp.writer.status() != WriteStatus::NeedWrite)
            return fail();
        credSsp.replyPending = true;
        credSsp.bindingReplyPending =
            visit.result == FrameStatus::BindingReplyQueued;
        return {RuntimeHostError::None, false};
    case FrameStatus::CredentialsVerified:
    {
        if (!credSsp.authenticatedProof.bind(
                credSsp.acceptor, standalonePasswordCredential_,
                standaloneCredentialGeneration_, connection))
            return fail();

        // R10 retains only a prepared R2 lifetime; R2 alone may later
        // invoke private R1/R3 positive operations. Synthetic owner evidence
        // is permitted for denial tests, never for broker construction.
        if (ownerEvidenceSource_ == &defaultOwnerEvidence_)
        {
            auto preparedBroker =
                std::make_unique<security::MacConsoleAdmissionBroker>(
                    credSsp.authenticatedProof, connection, nativeSessionEvidence_,
                    ownerSharingAuthority_);
            if (preparedBroker->prepareAdmission(
                    activeAdmissionPermissionMask_) ==
                security::MacConsoleAdmissionPrepareResult::Prepared)
            {
                // Preparation synchronously reads native evidence and consent.
                // Check original owner identity before retaining any borrow.
                if (activeConnection_.get() != &connection ||
                    activeCredSsp_.get() != &credSsp ||
                    !activeConsentEpoch_.has_value() ||
                    !selectedStandaloneCredentialReady() ||
                    !connection.active() ||
                    !ownerSharingAuthority_.authorizesAtEpoch(
                        activeAdmissionPermissionMask_, *activeConsentEpoch_) ||
                    !preparedBroker->revalidate(
                        activeAdmissionPermissionMask_) ||
                    !activeConsentEpoch_.has_value() ||
                    !ownerSharingAuthority_.authorizesAtEpoch(
                        activeAdmissionPermissionMask_, *activeConsentEpoch_))
                    return fail();
                activeAdmissionBroker_ = std::move(preparedBroker);
                activeAdmissionStage_ = AcceptedClientAdmissionStage::Prepared;
            }
        }
        if (activeAdmissionBroker_ == nullptr)
            activeAdmissionStage_ = AcceptedClientAdmissionStage::CredentialsVerified;
        activeCredentialsVerified_ = true;
        acceptedClientDiagnostics_.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        acceptedClientDiagnostics_.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Authenticated;
        // Prepared R2 is not native Admission. The next serialized tick may
        // invoke only the broker's protected R1 transport completion.
        return {RuntimeHostError::None, false};
    }
    case FrameStatus::Rejected:
        return fail();
    }
    return fail();
}
catch (const std::bad_alloc&)
{
    return failClosedAfterAllocationFailure();
}

RuntimeHostResult
MacRuntimeHostControl::serviceAcceptedClientGraphicsOnce(
    const rdp::macos::MacNativeDesktopServiceObservation& observation) noexcept try
{
    using namespace rdp_server::server;
    using Interest = transport::TcpConnectionIoInterest;
    using TlsOutcome = transport::TlsApplicationIoOutcome;
    using GraphicsWrite = transport::RdpGraphicsDvcWriteOutcome;
    using GraphicsIntake = transport::RdpGraphicsDvcClientIntake;
    using FrameAcknowledge = transport::RdpGraphicsFrameAcknowledgeIntake;
    using Reconfiguration = transport::RdpGraphicsSurfaceReconfiguration;
    using Readiness = transport::RdpGraphicsFramePublicationReadiness;

    const auto retireGraphics =
        [this](RuntimeHostError error) noexcept -> RuntimeHostResult {
            retireAcceptedClient();
            stage_ = listener_.valid()
                ? RuntimeHostStage::ListenerAvailable
                : RuntimeHostStage::Stopped;
            return deny(error);
        };
    const auto retireStaleHost = [this]() noexcept -> RuntimeHostResult {
        retireAcceptedClient();
        stage_ = listener_.valid()
            ? RuntimeHostStage::ListenerAvailable
            : RuntimeHostStage::Stopped;
        return deny(RuntimeHostError::HostSessionStale);
    };

    if (activeAdmissionStage_ != AcceptedClientAdmissionStage::GraphicsReady ||
        activeConnection_ == nullptr || activeCredSsp_ == nullptr ||
        activeMcsSession_ == nullptr || activeAdmissionBroker_ == nullptr ||
        !deploymentPolicy_ || !activeConsentEpoch_.has_value() ||
        !nativeDesktop_.active())
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    auto& connection = *activeConnection_;
    auto& credSsp = *activeCredSsp_;
    auto& session = *activeMcsSession_;
    if (!connection.active() ||
        connection.stage() != transport::PreauthStage::AwaitMcsConnectInitial ||
        session.phase() != transport::McsSessionPhase::ShareActivated)
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    if (!ownerSharingAuthority_.authorizesAtEpoch(
            activeAdmissionPermissionMask_, *activeConsentEpoch_) ||
        !activeAdmissionBroker_->revalidate(security::kConsoleViewPermission))
        return retireStaleHost();

    const auto retireTransport =
        [this](RuntimeHostError fallback) noexcept -> RuntimeHostResult {
            using Termination = transport::TcpConnectionTermination;
            const Termination termination = activeConnection_ != nullptr
                ? activeConnection_->termination()
                : Termination::Cancelled;
            switch (termination)
            {
            case Termination::Open:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::ProtocolError;
                break;
            case Termination::OrderlyTlsClose:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::OrderlyTlsClose;
                break;
            case Termination::TransportError:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::TransportError;
                break;
            case Termination::TlsFailure:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::TlsFailure;
                break;
            case Termination::ProtocolError:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::ProtocolError;
                break;
            case Termination::Cancelled:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::Cancelled;
                break;
            case Termination::PeerEof:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::PeerEof;
                break;
            case Termination::PeerReset:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::PeerReset;
                break;
            case Termination::PeerTlsAlert:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::PeerTlsAlert;
                break;
            case Termination::LocalTlsFailure:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::LocalTlsFailure;
                break;
            case Termination::Timeout:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::Timeout;
                break;
            case Termination::OwnerCancellation:
                acceptedClientDiagnostics_.termination =
                    RuntimeAcceptedClientTermination::OwnerCancellation;
                break;
            }
            const bool orderly =
                termination == Termination::PeerEof ||
                termination == Termination::OrderlyTlsClose;
            retireAcceptedClient();
            stage_ = listener_.valid()
                ? RuntimeHostStage::ListenerAvailable
                : RuntimeHostStage::Stopped;
            if (orderly)
            {
                lastError_ = RuntimeHostError::None;
                return {RuntimeHostError::None, false};
            }
            return deny(fallback);
        };

    enum class SocketReadiness : std::uint8_t
    {
        Ready,
        NoEvent,
        Failure,
    };
    const auto pollSocket =
        [&connection](Interest interest, bool bufferedRead) noexcept {
            if (interest != Interest::Read && interest != Interest::Write)
                return SocketReadiness::Failure;
            if (bufferedRead && interest == Interest::Read &&
                connection.tlsApplicationReadReady())
                return SocketReadiness::Ready;

            const std::uintptr_t socket = connection.nativeSocket();
            if (socket > static_cast<std::uintptr_t>(
                             (std::numeric_limits<int>::max)()))
                return SocketReadiness::Failure;
            pollfd descriptor{};
            descriptor.fd = static_cast<int>(socket);
            descriptor.events =
                interest == Interest::Read ? POLLIN : POLLOUT;
            errno = 0;
            const int count = ::poll(&descriptor, 1U, 0);
            if (count < 0)
                return errno == EINTR
                    ? SocketReadiness::NoEvent
                    : SocketReadiness::Failure;
            if (count == 0)
                return SocketReadiness::NoEvent;
            if ((descriptor.revents & POLLNVAL) != 0)
                return SocketReadiness::Failure;
            return (descriptor.revents &
                    (descriptor.events | POLLERR | POLLHUP)) != 0
                ? SocketReadiness::Ready
                : SocketReadiness::NoEvent;
        };

    if (activeGraphicsFrameWritePending_)
    {
        const auto pending =
            activeAdmissionBroker_->pendingR3GraphicsDynamicVirtualChannelWrite(
                session, *deploymentPolicy_);
        if (!pending || !*pending ||
            pending->kind !=
                transport::RdpGraphicsDvcWriteKind::GraphicsFrameData)
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);

        const Interest writeInterest =
            credSsp.graphicsFrameWriteNeedsRead
                ? Interest::Read
                : Interest::Write;
        const SocketReadiness ready = pollSocket(writeInterest, false);
        if (ready == SocketReadiness::Failure)
            return connection.active()
                ? retireGraphics(RuntimeHostError::GraphicsUnavailable)
                : retireTransport(RuntimeHostError::GraphicsUnavailable);
        if (ready == SocketReadiness::NoEvent)
            return {RuntimeHostError::None, true};

        const auto sent = connection.writeTlsApplicationData(pending->bytes);
        if (sent.outcome == TlsOutcome::NeedRead ||
            sent.outcome == TlsOutcome::NeedWrite)
        {
            if (sent.bytes != 0U)
                return retireGraphics(RuntimeHostError::GraphicsUnavailable);
            credSsp.graphicsFrameWriteNeedsRead =
                sent.outcome == TlsOutcome::NeedRead;
            return {RuntimeHostError::None, true};
        }
        if (sent.outcome != TlsOutcome::Progress)
            return retireTransport(RuntimeHostError::GraphicsUnavailable);
        if (sent.bytes == 0U || sent.bytes > pending->bytes.size())
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);

        credSsp.graphicsFrameWriteNeedsRead = false;
        const GraphicsWrite outcome =
            activeAdmissionBroker_->completeR3GraphicsDynamicVirtualChannelWrite(
                session, *deploymentPolicy_, pending->replySequence,
                pending->writeSliceSequence, sent.bytes);
        if (outcome == GraphicsWrite::Rejected)
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);
        if (outcome == GraphicsWrite::Pending)
            return {RuntimeHostError::None, false};

        activeGraphicsFrameWritePending_ = false;
        return {RuntimeHostError::None, false};
    }

    const Interest readInterest = connection.ioInterest();
    if (readInterest == Interest::Closed)
        return retireTransport(RuntimeHostError::GraphicsUnavailable);
    if (readInterest != Interest::Read && readInterest != Interest::Write)
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    const SocketReadiness networkReady = pollSocket(readInterest, true);
    if (networkReady == SocketReadiness::Failure)
        return connection.active()
            ? retireGraphics(RuntimeHostError::GraphicsUnavailable)
            : retireTransport(RuntimeHostError::GraphicsUnavailable);
    if (networkReady == SocketReadiness::Ready)
    {
        const std::size_t target =
            credSsp.firstMcsExpectedBytes == 0U
                ? 4U
                : credSsp.firstMcsExpectedBytes;
        if (credSsp.firstMcsBytes >= target ||
            target > credSsp.firstMcsTpkt.size())
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);

        const std::size_t remaining = target - credSsp.firstMcsBytes;
        const auto intake = connection.readTlsApplicationData(
            std::span(credSsp.firstMcsTpkt)
                .subspan(credSsp.firstMcsBytes, remaining));
        if (intake.outcome == TlsOutcome::NeedRead ||
            intake.outcome == TlsOutcome::NeedWrite)
            return {RuntimeHostError::None, true};
        if (intake.outcome != TlsOutcome::Progress)
            return retireTransport(RuntimeHostError::GraphicsUnavailable);
        if (intake.bytes == 0U || intake.bytes > remaining)
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);

        credSsp.firstMcsBytes += intake.bytes;
        if (credSsp.firstMcsExpectedBytes == 0U &&
            credSsp.firstMcsBytes == 4U)
        {
            if (credSsp.firstMcsTpkt[0] != 3U ||
                credSsp.firstMcsTpkt[1] != 0U)
                return retireGraphics(RuntimeHostError::GraphicsUnavailable);
            credSsp.firstMcsExpectedBytes =
                (static_cast<std::size_t>(credSsp.firstMcsTpkt[2]) << 8U) |
                static_cast<std::size_t>(credSsp.firstMcsTpkt[3]);
            if (credSsp.firstMcsExpectedBytes < 7U ||
                credSsp.firstMcsExpectedBytes > credSsp.firstMcsTpkt.size())
                return retireGraphics(RuntimeHostError::GraphicsUnavailable);
        }
        if (credSsp.firstMcsExpectedBytes == 0U ||
            credSsp.firstMcsBytes < credSsp.firstMcsExpectedBytes)
            return {RuntimeHostError::None, false};

        const auto completeTpkt =
            std::span(credSsp.firstMcsTpkt)
                .first(credSsp.firstMcsExpectedBytes);
        const auto route =
            activeAdmissionBroker_->classifyR3PostShareTpkt(
                session, *deploymentPolicy_, completeTpkt);
        using RouteKind = transport::RdpPostShareTpktRouteKind;
        if (route.kind == RouteKind::UnsupportedOrMalformed)
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);

        if (route.kind == RouteKind::GraphicsDynamicVirtualChannel)
        {
            const GraphicsIntake graphics =
                activeAdmissionBroker_->authorizeR3GraphicsDynamicVirtualChannelPdu(
                    session, *deploymentPolicy_, completeTpkt);
            credSsp.firstMcsBytes = 0U;
            credSsp.firstMcsExpectedBytes = 0U;
            if (graphics == GraphicsIntake::GraphicsDataFragmentAccepted)
                return {RuntimeHostError::None, false};
            if (graphics != GraphicsIntake::GraphicsDataAccepted)
                return retireGraphics(RuntimeHostError::GraphicsUnavailable);

            const FrameAcknowledge acknowledged =
                activeAdmissionBroker_->consumeR3GraphicsFrameAcknowledge(
                    session, *deploymentPolicy_);
            if (acknowledged == FrameAcknowledge::Rejected)
                return retireGraphics(RuntimeHostError::GraphicsUnavailable);
            // One bounded inbound packet must not starve a ready native frame.
            // Continue into the same tick's R2/R3/R4 preflight after ACK.
        }
        else if (route.kind == RouteKind::SlowPathInput ||
                 route.kind == RouteKind::ClipboardStaticChannel)
        {
            // R3 already bounded and classified these packets. This P1
            // increment creates no native input or Clipboard authority, so
            // consume only the bounded R1 packet and continue native service.
            credSsp.firstMcsBytes = 0U;
            credSsp.firstMcsExpectedBytes = 0U;
        }
        else
        {
            return retireGraphics(RuntimeHostError::GraphicsUnavailable);
        }
    }

    using NativeState = rdp::macos::MacNativeDesktopOwnerState;
    if (observation.state != NativeState::Ready)
        return {RuntimeHostError::None, true};
    if (observation.pixelGeometry.widthPixels == 0U ||
        observation.pixelGeometry.heightPixels == 0U ||
        observation.geometryGeneration == 0U ||
        observation.admittedSessionGeneration == 0U ||
        observation.admittedSessionGeneration !=
            nativeDesktop_.authorizationGeneration())
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    const auto now = std::chrono::steady_clock::now();
    if (activeGraphicsResizeDeadline_.has_value() &&
        now >= *activeGraphicsResizeDeadline_)
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    const Reconfiguration reconfiguration =
        activeAdmissionBroker_->beginR3GraphicsSurfaceReconfiguration(
            session, *deploymentPolicy_, observation.pixelGeometry);
    switch (reconfiguration)
    {
    case Reconfiguration::Unchanged:
        activeGraphicsResizeDeadline_.reset();
        break;
    case Reconfiguration::Deferred:
        if (!activeGraphicsResizeDeadline_)
            activeGraphicsResizeDeadline_ = now + std::chrono::seconds{6};
        return {RuntimeHostError::None, true};
    case Reconfiguration::Started:
        if (!activeGraphicsResizeDeadline_)
            activeGraphicsResizeDeadline_ = now + std::chrono::seconds{6};
        activeGraphicsControlDeadline_ = *activeGraphicsResizeDeadline_;
        activeAdmissionStage_ =
            AcceptedClientAdmissionStage::GraphicsControlWritePending;
        return {RuntimeHostError::None, false};
    case Reconfiguration::Rejected:
        return activeAdmissionBroker_->revalidate(
                   security::kConsoleViewPermission)
            ? retireGraphics(RuntimeHostError::GraphicsUnavailable)
            : retireStaleHost();
    }

    if (!observation.frameAvailable ||
        observation.latestFrameSequence == 0U ||
        observation.latestFrameSequence == activeLastNativeFrameSequence_)
        return {RuntimeHostError::None, true};
    if (observation.latestFrameSequence < activeLastNativeFrameSequence_ ||
        activeNextGraphicsFrameId_ == 0U)
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    const Readiness readiness =
        activeAdmissionBroker_->preflightR3GraphicsFramePublication(
            session, *deploymentPolicy_, activeNextGraphicsFrameId_);
    if (readiness == Readiness::DeferredForFrameAcknowledge)
        return {RuntimeHostError::None, true};
    if (readiness != Readiness::Ready ||
        !activeAdmissionBroker_->revalidate(
            security::kConsoleViewPermission) ||
        observation.admittedSessionGeneration !=
            nativeDesktop_.authorizationGeneration())
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    const std::size_t width = observation.pixelGeometry.widthPixels;
    if (width > (std::numeric_limits<std::size_t>::max)() / 4U)
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);
    const std::size_t minimumStrideBytes = width * 4U;

    struct FramePublicationContext final
    {
        security::MacConsoleAdmissionBroker* broker{};
        transport::McsSessionLifecycle* session{};
        const RuntimeDeploymentPolicy* policy{};
        std::uint32_t frameId{};
        PixelSize pixelGeometry{};
        std::uint64_t geometryGeneration{};
        std::uint64_t admittedSessionGeneration{};
        std::uint64_t frameSequence{};
        std::size_t minimumStrideBytes{};
        bool* firstFramebufferAvailable{};
        bool callbackReached{};
        bool publicationPrepared{};
    } frameContext{
        activeAdmissionBroker_.get(), &session, &*deploymentPolicy_,
        activeNextGraphicsFrameId_, observation.pixelGeometry,
        observation.geometryGeneration, observation.admittedSessionGeneration,
        observation.latestFrameSequence, minimumStrideBytes,
        &activeFirstFramebufferAvailable_, false, false};

    const auto publishFrame = +[](
        void* rawContext, const FramebufferView& framebuffer,
        std::uint64_t geometryGeneration,
        std::uint64_t admittedSessionGeneration,
        std::uint64_t frameSequence) noexcept -> bool {
        auto* context = static_cast<FramePublicationContext*>(rawContext);
        if (context == nullptr)
            return false;
        // Only a pre-callback stale mailbox is retryable. If invoked,
        // invalid metadata or failed R3 preparation must retire the client.
        context->callbackReached = true;
        if (context->broker == nullptr ||
            context->session == nullptr || context->policy == nullptr ||
            context->firstFramebufferAvailable == nullptr ||
            context->frameId == 0U || !framebuffer.valid() ||
            framebuffer.widthPixels != context->pixelGeometry.widthPixels ||
            framebuffer.heightPixels != context->pixelGeometry.heightPixels ||
            framebuffer.strideBytes < context->minimumStrideBytes ||
            geometryGeneration != context->geometryGeneration ||
            admittedSessionGeneration != context->admittedSessionGeneration ||
            frameSequence != context->frameSequence)
            return false;

        *context->firstFramebufferAvailable = true;
        const auto pending =
            context->broker->beginR3GraphicsClearCodecFramePublication(
                *context->session, *context->policy,
                context->frameId, framebuffer);
        context->publicationPrepared =
            pending.has_value() && *pending &&
            pending->kind ==
                transport::RdpGraphicsDvcWriteKind::GraphicsFrameData;
        return context->publicationPrepared;
    };

    const bool borrowed = nativeDesktop_.borrowFramebuffer(
        observation.latestFrameSequence,
        rdp::macos::MacNativeDesktopFrameConsumer{
            &frameContext, publishFrame});
    if (!borrowed)
    {
        if (frameContext.publicationPrepared)
            (void)activeAdmissionBroker_->abortR3GraphicsFrame(
                session, *deploymentPolicy_);
        if (!nativeDesktop_.active())
            return retireGraphics(RuntimeHostError::NativeAuthorizationDenied);
        return frameContext.callbackReached
            ? retireGraphics(RuntimeHostError::GraphicsUnavailable)
            : RuntimeHostResult{RuntimeHostError::None, true};
    }
    if (!frameContext.publicationPrepared)
        return retireGraphics(RuntimeHostError::GraphicsUnavailable);

    // The native mailbox borrow has ended. Only owned R3/R4 bytes remain.
    if (!ownerSharingAuthority_.authorizesAtEpoch(
            activeAdmissionPermissionMask_, *activeConsentEpoch_) ||
        !activeAdmissionBroker_->revalidate(security::kConsoleViewPermission))
    {
        (void)activeAdmissionBroker_->cancelR3UnwrittenGraphicsFrame(
            session, *deploymentPolicy_);
        return retireStaleHost();
    }

    activeLastNativeFrameSequence_ = observation.latestFrameSequence;
    ++activeNextGraphicsFrameId_;
    activeGraphicsFrameWritePending_ = true;
    credSsp.graphicsFrameWriteNeedsRead = false;
    return {RuntimeHostError::None, false};
}
catch (const std::bad_alloc&)
{
    return failClosedAfterAllocationFailure();
}

MacRuntimeHostControl::MacRuntimeHostControl() noexcept
    : ownerThread_(std::this_thread::get_id()),
      ownerEvidenceSource_(&defaultOwnerEvidence_),
      ownerSharingAuthority_(*ownerEvidenceSource_)
{
    (void)licensingContext_.configureGeneratedApplicationIdentity();
}

MacRuntimeHostControl::MacRuntimeHostControl(
    rdp_server::server::security::ConsoleOsEvidenceSource& ownerEvidence) noexcept
    : ownerThread_(std::this_thread::get_id()),
      ownerEvidenceSource_(&ownerEvidence),
      ownerSharingAuthority_(*ownerEvidenceSource_)
{
    (void)licensingContext_.configureGeneratedApplicationIdentity();
}

MacRuntimeHostControl::~MacRuntimeHostControl()
{
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
}

void MacRuntimeHostControl::setScreenCaptureProbeForTesting(
    ScreenCaptureProbe probe) noexcept
{
    screenCaptureProbe_ = probe;
}

void MacRuntimeHostControl::setInputPermissionProbeForTesting(
    InputPermissionProbe probe) noexcept
{
    inputPermissionProbe_ = probe;
}

bool MacRuntimeHostControl::onOwnerThread() const noexcept
{
    return ownerThread_ == std::this_thread::get_id();
}

RuntimeHostResult MacRuntimeHostControl::deny(RuntimeHostError error) noexcept
{
    lastError_ = error;
    return {error, false};
}

bool MacRuntimeHostControl::prepareTlsIdentityForSelection(
    std::string_view numericIpAddress) noexcept
{
    retireGeneratedTlsIdentity();
    RuntimeServerTlsContext generated =
        RuntimeServerTlsContext::fromGeneratedIpAddress(numericIpAddress);
    if (!generated)
        return false;

    generatedTlsContext_.emplace(std::move(generated));
    tlsContext_ = &*generatedTlsContext_;
    return true;
}

void MacRuntimeHostControl::retireGeneratedTlsIdentity() noexcept
{
    tlsContext_ = nullptr;
    generatedTlsContext_.reset();
}

bool MacRuntimeHostControl::selectedStandaloneCredentialReady() const noexcept
{
    if (standaloneCredentialGeneration_ == 0U)
        return false;

    const auto observation = standalonePasswordCredential_.observation();
    if (!observation.configured ||
        observation.generation != standaloneCredentialGeneration_)
    {
        return false;
    }

    bool visited = false;
    return standalonePasswordCredential_.visit(
               standaloneCredentialGeneration_,
               &validateStandaloneCredentialVisit, &visited) &&
           visited;
}

void MacRuntimeHostControl::retireStoppedRuntime(
    rdp_server::server::security::OwnerConsentRevocationReason reason) noexcept
{
    ownerSharingAuthority_.revoke(reason);
    // Borrowed R2 state must be destroyed before terminal credential teardown.
    retireAcceptedClient();
    // Match Linux service-lifetime semantics: ordinary Stop retains the
    // memory-only credential, while terminal authority loss/destruction
    // securely retires the exact generation.
    if (rdp_server::server::security::
            shouldRetireStandaloneApplicationCredential(reason))
    {
        standalonePasswordCredential_.revoke();
        standaloneCredentialSessionBinding_.clear();
        standaloneCredentialGeneration_ = 0U;
        credentialsConfigured_ = false;
    }
    listener_.close();
    retireGeneratedTlsIdentity();
    deploymentPolicy_.reset();
}

std::vector<MacRuntimeDefaultRoutePreference>
readMacDefaultRoutePreferences()
{
    std::vector<MacRuntimeDefaultRoutePreference> routes;
    SCDynamicStoreRef store = SCDynamicStoreCreate(
        kCFAllocatorDefault, CFSTR("rdp_default_route_preference"), nullptr, nullptr);
    if (store == nullptr)
        return routes;

    const std::unique_ptr<const __SCDynamicStore, decltype(&CFRelease)>
        storeOwner(store, &CFRelease);

    const void* patternList[] = {
        CFSTR("State:/Network/Service/.*/IPv4"),
        CFSTR("State:/Network/Service/.*/IPv6")
    };
    CFArrayRef patterns = CFArrayCreate(
        kCFAllocatorDefault, patternList, 2, &kCFTypeArrayCallBacks);
    if (patterns == nullptr)
        return routes;
    const std::unique_ptr<const __CFArray, decltype(&CFRelease)>
        patternsOwner(patterns, &CFRelease);

    CFDictionaryRef matches = SCDynamicStoreCopyMultiple(store, nullptr, patterns);
    if (matches == nullptr)
        return routes;
    const std::unique_ptr<const __CFDictionary, decltype(&CFRelease)>
        matchesOwner(matches, &CFRelease);

    const CFIndex count = CFDictionaryGetCount(matches);
    if (count <= 0)
        return routes;

    std::vector<const void*> keys(static_cast<std::size_t>(count));
    std::vector<const void*> values(static_cast<std::size_t>(count));
    CFDictionaryGetKeysAndValues(matches, keys.data(), values.data());

    for (CFIndex i = 0; i < count; ++i)
    {
        auto dict = static_cast<CFDictionaryRef>(values[i]);
        if (dict == nullptr || CFGetTypeID(dict) != CFDictionaryGetTypeID())
            continue;

        auto ifNameRef = static_cast<CFStringRef>(
            CFDictionaryGetValue(dict, CFSTR("InterfaceName")));
        auto routerRef = static_cast<CFStringRef>(
            CFDictionaryGetValue(dict, CFSTR("Router")));
        if (ifNameRef == nullptr || routerRef == nullptr)
            continue;

        char ifNameBuf[IFNAMSIZ]{};
        if (!CFStringGetCString(ifNameRef, ifNameBuf, sizeof(ifNameBuf),
                                kCFStringEncodingUTF8))
            continue;

        const unsigned int index = ::if_nametoindex(ifNameBuf);
        if (index == 0U)
            continue;

        const std::string stableId =
            std::string(ifNameBuf) + "#" + std::to_string(index);

        auto keyRef = static_cast<CFStringRef>(keys[i]);
        char keyBuf[128]{};
        CFStringGetCString(keyRef, keyBuf, sizeof(keyBuf),
                           kCFStringEncodingUTF8);
        const bool isIpv6 = (std::strstr(keyBuf, "IPv6") != nullptr);
        const auto family = isIpv6 ? RuntimeHostAddressFamily::Ipv6
                                   : RuntimeHostAddressFamily::Ipv4;

        if (std::ranges::any_of(
                routes,
                [&](const MacRuntimeDefaultRoutePreference& route) {
                    return route.interfaceId == stableId &&
                           route.family == family;
                }))
            continue;

        routes.push_back({stableId, family, 10U});
    }
    return routes;
}

RuntimeHostRecommendedEndpoint
recommendMacPrivateLanEndpoint(
    const std::vector<RuntimeHostInterface>& interfaces,
    const std::span<const MacRuntimeDefaultRoutePreference> defaultRoutes,
    const std::uint16_t port)
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

            bool matchedDefaultRoute = false;
            for (const MacRuntimeDefaultRoutePreference& route : defaultRoutes)
            {
                if (route.interfaceId != candidate.interfaceId ||
                    route.family != candidate.family)
                    continue;
                candidate.preferredRoute = true;
                matchedDefaultRoute = true;
                if (!candidate.routeMetric.has_value() ||
                    route.metric < *candidate.routeMetric)
                    candidate.routeMetric = route.metric;
            }

            // In absence of an explicit default route from SCDynamicStore,
            // physical Ethernet/Wi-Fi interfaces (en*) outrank virtual bridges.
            if (!matchedDefaultRoute)
            {
                if (runtimeInterface.displayName.starts_with("en"))
                {
                    candidate.preferredRoute = true;
                    candidate.routeMetric = 50U;
                }
                else
                {
                    candidate.routeMetric = 100U;
                }
            }

            candidates.emplace_back(std::move(candidate));
        }
    }
    return recommendRuntimePrivateLanEndpoint(candidates, port);
}

std::vector<RuntimeHostInterface>
MacRuntimeHostControl::enumerateLocalInterfaces() const
{
    if (!onOwnerThread())
        return {};
    ifaddrs* addressList = nullptr;
    if (::getifaddrs(&addressList) != 0 || addressList == nullptr)
        return {};
    const std::unique_ptr<ifaddrs, decltype(&::freeifaddrs)>
        addressOwner(addressList, &::freeifaddrs);
    std::vector<RuntimeHostInterface> interfaces;
    for (const ifaddrs* current = addressOwner.get(); current != nullptr;
         current = current->ifa_next)
    {
        if (current->ifa_name == nullptr ||
            (current->ifa_flags & (IFF_UP | IFF_RUNNING)) !=
                (IFF_UP | IFF_RUNNING) ||
            (current->ifa_flags & IFF_LOOPBACK) != 0 ||
            (current->ifa_flags & IFF_POINTOPOINT) != 0 ||
            !isEligibleAddress(current->ifa_addr))
            continue;
        const unsigned index = ::if_nametoindex(current->ifa_name);
        if (index == 0U)
            continue;
        std::string address = numericAddress(current->ifa_addr);
        if (address.empty())
            continue;
        const std::string interfaceName(current->ifa_name);
        const std::string stableId =
            interfaceName + "#" + std::to_string(index);
        auto found = std::find_if(interfaces.begin(), interfaces.end(),
            [&stableId](const RuntimeHostInterface& candidate) {
                return candidate.stableId == stableId;
            });
        if (found == interfaces.end())
        {
            RuntimeHostInterface candidate;
            candidate.stableId = stableId;
            candidate.displayName = interfaceName;
            candidate.lanEligible = true;
            interfaces.emplace_back(std::move(candidate));
            found = std::prev(interfaces.end());
        }
        if (std::find(found->localAddresses.begin(),
                      found->localAddresses.end(), address) ==
            found->localAddresses.end())
            found->localAddresses.emplace_back(std::move(address));
    }
    return interfaces;
}

RuntimeHostStatus MacRuntimeHostControl::status() const
{
    RuntimeHostStatus snapshot;
    snapshot.product.lastErrorMessage =
        std::string(runtimeHostErrorMessage(snapshot.lastError));
    if (!onOwnerThread())
        return snapshot;
    snapshot.stage = stage_;
    snapshot.lastError = lastError_;
    const bool listenerCurrent =
        listener_.valid() && listener_.interfaceStillMatches();
    snapshot.listenerAvailable = listenerCurrent;
    snapshot.listenerGeneration =
        listenerCurrent ? listener_.generation() : 0U;
    if (selectionConfigured_)
        snapshot.selectedEndpoint =
            endpointText(selection_.localAddress, selection_.port);
    if (listenerCurrent)
        snapshot.boundEndpoint = boundEndpointText(listener_.boundEndpoint());

    const auto ownerGrant = ownerSharingAuthority_.grantObservation();
    using rdp_server::server::security::OwnerSharingGrantExpiryState;
    switch (ownerGrant.expiryState)
    {
    case OwnerSharingGrantExpiryState::Active:
        snapshot.ownerGrant.state = RuntimeOwnerGrantState::Active;
        snapshot.ownerGrant.effectivePermissionMask =
            ownerGrant.effectivePermissionMask;
        snapshot.ownerGrant.remainingMilliseconds =
            ownerGrant.remainingMilliseconds;
        break;
    case OwnerSharingGrantExpiryState::Expired:
        snapshot.ownerGrant.state = RuntimeOwnerGrantState::Expired;
        break;
    case OwnerSharingGrantExpiryState::Unavailable:
        break;
    }
    snapshot.hostOwnerAuthorized =
        ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission);
    const auto ownerPermission =
        ownerSharingAuthority_.permissionObservation();

    snapshot.product.nativeDesktopTargetAvailable = true;
    snapshot.product.nativeDesktopTarget = "macOS ScreenCaptureKit Desktop";

    snapshot.credentialsConfigured = credentialsConfigured_ && selectedStandaloneCredentialReady();

    if (tlsContext_ != nullptr)
    {
        if (listener_.valid())
        {
            snapshot.tlsIdentity = tlsContext_->boundIdentityStatus(listener_);
            snapshot.tlsIdentityReady =
                listenerCurrent &&
                snapshot.tlsIdentity.boundIdentityMatchesGeneration(
                    snapshot.listenerGeneration);
        }
        else
        {
            snapshot.tlsIdentity = tlsContext_->identityStatus();
            snapshot.tlsIdentityReady =
                snapshot.tlsIdentity.fingerprintAvailable &&
                snapshot.tlsIdentity.state ==
                    RuntimeTlsIdentityState::ConfiguredUnbound;
        }
    }

    // Only the original R2-protected R3 exact MAP receipt may mark protocol
    // graphics ready. Neither native resources nor a prepared frame suffice.
    const bool graphicsControlCommitted =
        activeAdmissionStage_ == AcceptedClientAdmissionStage::GraphicsReady &&
        activeMcsSession_ != nullptr && activeAdmissionBroker_ != nullptr &&
        activeAdmissionBroker_->state() ==
            rdp_server::server::security::MacConsoleAdmissionState::Admitted &&
        activeConsentEpoch_.has_value() &&
        ownerSharingAuthority_.authorizesAtEpoch(
            activeAdmissionPermissionMask_, *activeConsentEpoch_);
    if (graphicsControlCommitted)
    {
        const auto proof =
            activeMcsSession_->firstClientAcceptanceObservability();
        snapshot.graphicsReady = proof.shareActivated &&
            proof.graphicsDynamicVirtualChannelActivated &&
            proof.graphicsControlReady && proof.surfaceCreated &&
            proof.surfaceMapped;
    }
    snapshot.nativeDesktopReady = nativeDesktop_.ready();
    snapshot.nativeDesktopInitializing =
        nativeDesktop_.active() && !snapshot.nativeDesktopReady;
    snapshot.acceptedClientPreauthDiagnostics = acceptedClientDiagnostics_;
    if (activeMcsSession_ != nullptr &&
        activeAdmissionStage_ == AcceptedClientAdmissionStage::GraphicsReady)
    {
        const auto acceptance =
            activeMcsSession_->firstClientAcceptanceObservability();
        snapshot.firstLiveGraphicsTrace =
            projectRuntimeFirstLiveGraphicsTrace(
                activeFirstFramebufferAvailable_,
                acceptance.firstClearCodecFramePrepared,
                acceptance.firstExactFrameWriteCommitted,
                acceptance.outstandingFrameAcknowledgements,
                acceptance.firstGenuineFrameAcknowledge);
    }

    snapshot.clientDisconnected = listenerCurrent && activeConnection_ == nullptr && clientDisconnected_;
    if (activeConnection_ != nullptr && activeClientId_ != 0U)
    {
        RuntimeHostClient client;
        client.opaqueId = activeClientId_;
        client.peerAddress = activeClientPeer_;
        client.authenticating = (stage_ == RuntimeHostStage::ClientAuthenticating);
        client.shareActivated = (stage_ == RuntimeHostStage::ShareActivated ||
                                 stage_ == RuntimeHostStage::DesktopVisible ||
                                 stage_ == RuntimeHostStage::ClientConnected);
        client.desktopVisible = snapshot.nativeDesktopReady &&
            (stage_ == RuntimeHostStage::DesktopVisible || stage_ == RuntimeHostStage::ClientConnected);
        snapshot.activeClients.emplace_back(std::move(client));
    }

    snapshot.product.controlAvailable = true;
    snapshot.product.eligibleLanInterfaces = enumerateLocalInterfaces();
    const std::uint16_t recommendedPort =
        selectionConfigured_ ? selection_.port : 3389U;
    const std::vector<MacRuntimeDefaultRoutePreference> defaultRoutes =
        readMacDefaultRoutePreferences();
    snapshot.product.recommendedEndpoint =
        recommendMacPrivateLanEndpoint(
            snapshot.product.eligibleLanInterfaces, defaultRoutes,
            recommendedPort);
    snapshot.product.boundEndpoint = snapshot.boundEndpoint;
    snapshot.product.clientCount = snapshot.activeClients.size();
    snapshot.product.activeClientIds.reserve(snapshot.activeClients.size());
    for (const RuntimeHostClient& client : snapshot.activeClients)
    {
        if (client.opaqueId != 0U)
            snapshot.product.activeClientIds.emplace_back(client.opaqueId);
    }

    snapshot.product.credentialCapabilities.existingOsAccount = false;
    snapshot.product.credentialCapabilities.standalonePassword =
        kStandalonePasswordProductCapabilityApproved;
    snapshot.product.credentialCapabilities
        .standalonePasswordConfigurationAvailable = true;
    snapshot.product.automaticRuntimeProvisioned =
        licensingContext_.configured();

    snapshot.product.credentialsConfigured = snapshot.credentialsConfigured;
    snapshot.product.ownerAuthorized = snapshot.hostOwnerAuthorized;
    snapshot.product.sharingPermission =
        sharingPermissionStatus(ownerPermission);
    if (snapshot.stage == RuntimeHostStage::Revoked)
        snapshot.product.sharingPermission.canRequest = false;
    snapshot.product.tlsIdentityReady = snapshot.tlsIdentityReady;
    if (snapshot.tlsIdentity.fingerprintAvailable)
    {
        snapshot.product.tlsFingerprint =
            snapshot.tlsIdentity.certificateSha256;
        snapshot.product.tlsFingerprintAvailable = true;
    }
    snapshot.product.state = runtimeProductStateFor(
        snapshot.stage, snapshot.lastError, snapshot.nativeDesktopReady);
    snapshot.product.credentialEditingAllowed =
        snapshot.product.controlAvailable &&
        runtimeProductCredentialEditingAllowed(
            snapshot.stage, snapshot.product.state);

    using Readiness = RuntimeProductReadinessStage;
    if (snapshot.nativeDesktopReady &&
        (snapshot.stage == RuntimeHostStage::DesktopVisible ||
         snapshot.stage == RuntimeHostStage::ClientConnected))
        snapshot.product.readinessStage = Readiness::Connected;
    else if (snapshot.stage == RuntimeHostStage::ClientAuthenticating ||
             snapshot.stage == RuntimeHostStage::ShareActivated ||
             snapshot.stage == RuntimeHostStage::DesktopVisible ||
             snapshot.stage == RuntimeHostStage::ClientConnected)
        snapshot.product.readinessStage = Readiness::Authenticating;
    else if (listenerCurrent)
        snapshot.product.readinessStage = Readiness::Listening;
    else if (selectionConfigured_ && snapshot.product.credentialsConfigured &&
             snapshot.product.ownerAuthorized &&
             snapshot.product.tlsIdentityReady)
        snapshot.product.readinessStage = Readiness::Starting;
    else if (snapshot.product.ownerAuthorized)
        snapshot.product.readinessStage = Readiness::PermissionGranted;
    else if (snapshot.product.credentialsConfigured)
        snapshot.product.readinessStage = Readiness::CredentialsConfigured;
    else if (snapshot.product.automaticRuntimeProvisioned)
        snapshot.product.readinessStage = Readiness::Provisioned;
    else
        snapshot.product.readinessStage = Readiness::Stopped;

    if (!customErrorMessage_.empty())
        snapshot.product.lastErrorMessage = customErrorMessage_;
    else
        snapshot.product.lastErrorMessage =
            std::string(runtimeHostErrorMessage(snapshot.lastError));
    return snapshot;
}

RuntimeHostResult MacRuntimeHostControl::configure(
    const RuntimeHostOptions& options)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (listener_.valid())
        return deny(RuntimeHostError::InvalidConfiguration);

    const auto preflight = assessRuntimeSelectedLanEndpoint(
        options, enumerateLocalInterfaces());
    if (!preflight.succeeded())
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(preflight.error);
    }

    if (!prepareTlsIdentityForSelection(options.localAddress))
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    }

    selection_ = options;
    selectionConfigured_ = true;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::requestCredentialSetup(
    rdp_server::server::security::LanCredentialChoice choice)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (listener_.valid() || activeConnection_ != nullptr)
        return deny(RuntimeHostError::InvalidConfiguration);
    ownerSharingAuthority_.revoke(
        rdp_server::server::security::OwnerConsentRevocationReason::CredentialChange);
    standalonePasswordCredential_.revoke();
    standaloneCredentialSessionBinding_.clear();
    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;

    const auto decision = rdp_server::server::security::assessLanCredentialChoice(choice);
    if (decision == rdp_server::server::security::LanCredentialDecision::UnsupportedIndependentPasswordCredSsp)
        return deny(RuntimeHostError::UnsupportedIndependentPasswordNla);
    if (decision == rdp_server::server::security::LanCredentialDecision::CredentialNotConfigured)
        return deny(RuntimeHostError::CredentialNotConfigured);

    return deny(RuntimeHostError::CredentialProviderUnavailable);
}

bool MacRuntimeHostControl::configureStandaloneApplicationPassword(
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    if (!onOwnerThread() ||
        stage_ == RuntimeHostStage::Revoked ||
        listener_.valid())
    {
        cleansePassword(password);
        return false;
    }

    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;
    standaloneCredentialSessionBinding_.clear();

    const auto observation =
        rdp_server::server::security::replaceStandaloneApplicationCredential(
            standalonePasswordCredential_, ownerSharingAuthority_,
            username, password);
    if (!observation.configured || observation.generation == 0U)
    {
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

    standaloneCredentialGeneration_ = observation.generation;
    credentialsConfigured_ = true;
    if (!selectedStandaloneCredentialReady())
    {
        standaloneCredentialGeneration_ = 0U;
        credentialsConfigured_ = false;
        standalonePasswordCredential_.revoke();
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

    (void)rdp_server::server::security::
        refreshStandaloneCredentialSessionBinding(
            standaloneCredentialSessionBinding_,
            *ownerEvidenceSource_, true);
    stage_ = RuntimeHostStage::CredentialsConfigured;
    lastError_ = RuntimeHostError::None;
    return true;
}

rdp_server::server::security::StandalonePasswordCredentialObservation
MacRuntimeHostControl::standaloneApplicationPasswordObservation() const noexcept
{
    return standalonePasswordCredential_.observation();
}

bool MacRuntimeHostControl::visitStandaloneApplicationPassword(
    std::uint64_t expectedGeneration,
    rdp_server::server::security::StandalonePasswordCredentialVisitor visitor,
    void* context) const noexcept
{
    return standalonePasswordCredential_.visit(
        expectedGeneration, visitor, context);
}

RuntimeHostResult MacRuntimeHostControl::requestHostPermissionSetup(
    const RuntimeHostPermissionRequest& request)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);

    if (selectedStandaloneCredentialReady())
    {
        using StandaloneCredentialSessionState =
            rdp_server::server::security::StandaloneCredentialSessionState;
        const auto sessionState =
            rdp_server::server::security::
                refreshStandaloneCredentialSessionBinding(
                    standaloneCredentialSessionBinding_,
                    *ownerEvidenceSource_, true);
        if (sessionState == StandaloneCredentialSessionState::LockOrUnknown ||
            sessionState ==
                StandaloneCredentialSessionState::TerminalSessionChanged)
        {
            retireStoppedRuntime(
                sessionState ==
                        StandaloneCredentialSessionState::LockOrUnknown
                    ? rdp_server::server::security::
                          OwnerConsentRevocationReason::LockOrUnknown
                    : rdp_server::server::security::
                          OwnerConsentRevocationReason::SessionReplacement);
            stage_ = RuntimeHostStage::Stopped;
            lastError_ = RuntimeHostError::CredentialNotConfigured;
            return {lastError_, false};
        }
    }

    const bool enforceTcc = (ownerEvidenceSource_ == &defaultOwnerEvidence_) ||
                            (screenCaptureProbe_ != nullptr) ||
                            (inputPermissionProbe_ != nullptr);
    if (enforceTcc)
    {
#if defined(__APPLE__)
        const auto captureStatus = screenCaptureProbe_ != nullptr
            ? screenCaptureProbe_()
            : ::rdp::macos::queryNativeScreenCapturePreflight();
        if (captureStatus == ::rdp::macos::ScreenCapturePreflightStatus::NotGranted)
        {
            if (!screenCapturePromptRequested_)
            {
                screenCapturePromptRequested_ = true;
                (void)::CGRequestScreenCaptureAccess();
            }
            customErrorMessage_ =
                "Screen Recording permission required. Enable Screen Recording in System Settings > Privacy & Security.";
            lastError_ = RuntimeHostError::NativeAuthorizationDenied;
            return {RuntimeHostError::NativeAuthorizationDenied, false};
        }

        if (request.allowInput)
        {
            const auto inputStatus = inputPermissionProbe_ != nullptr
                ? inputPermissionProbe_()
                : ::rdp::macos::queryNativeMacInputPermissionStatus();
            if (inputStatus != ::rdp::macos::MacInputPermissionStatus::Trusted)
            {
                if (!accessibilityPromptRequested_)
                {
                    accessibilityPromptRequested_ = true;
                    const void* keys[] = { kAXTrustedCheckOptionPrompt };
                    const void* values[] = { kCFBooleanTrue };
                    CFDictionaryRef options = CFDictionaryCreate(
                        kCFAllocatorDefault, keys, values, 1,
                        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                    if (options != nullptr)
                    {
                        (void)::AXIsProcessTrustedWithOptions(options);
                        ::CFRelease(options);
                    }
                }
                customErrorMessage_ =
                    "Accessibility permission required for remote control. Enable Accessibility in System Settings > Privacy & Security.";
                lastError_ = RuntimeHostError::NativeAuthorizationDenied;
                return {RuntimeHostError::NativeAuthorizationDenied, false};
            }
        }
#endif
    }
    customErrorMessage_.clear();

    std::uint32_t permissions =
        rdp_server::server::security::kConsoleViewPermission;
    if (request.allowInput)
        permissions |= rdp_server::server::security::kConsoleInputPermission;
    if (request.allowClipboard)
        permissions |= rdp_server::server::security::kConsoleClipboardPermission;
    const auto result = ownerSharingAuthority_.requestConsent(
        {permissions, request.requestedLifetimeMilliseconds});
    using rdp_server::server::security::OwnerConsentRequestResult;
    switch (result)
    {
    case OwnerConsentRequestResult::Granted:
        lastError_ = RuntimeHostError::None;
        return {RuntimeHostError::None, false};
    case OwnerConsentRequestResult::InvalidIntent:
        return deny(RuntimeHostError::InvalidConfiguration);
    case OwnerConsentRequestResult::GenerationExhausted:
        return deny(RuntimeHostError::InternalFailure);
    case OwnerConsentRequestResult::TrustedOwnerProofUnavailable:
    case OwnerConsentRequestResult::NativeSessionUnavailable:
    case OwnerConsentRequestResult::LockStateNotUnlocked:
        lastError_ = RuntimeHostError::HostConsentRequired;
        return {RuntimeHostError::HostConsentRequired, true};
    }
    return deny(RuntimeHostError::HostConsentRequired);
}

RuntimeHostResult MacRuntimeHostControl::startSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (!selectionConfigured_)
        return deny(RuntimeHostError::InvalidConfiguration);
    if (!licensingContext_.configured())
        return deny(RuntimeHostError::InternalFailure);
    if (!credentialsConfigured_ || !selectedStandaloneCredentialReady())
        return deny(RuntimeHostError::CredentialNotConfigured);

    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    const auto current = assessRuntimeSelectedLanEndpoint(
        selection_, enumerateLocalInterfaces());
    if (!current.succeeded())
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(current.error);
    }

    if (tlsContext_ == nullptr)
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    const RuntimeTlsIdentityStatus unboundIdentity =
        tlsContext_->identityStatus();
    if (!unboundIdentity.fingerprintAvailable ||
        unboundIdentity.state != RuntimeTlsIdentityState::ConfiguredUnbound)
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    std::string_view nativeName = selection_.interfaceId;
    const auto hashPos = nativeName.find('#');
    if (hashPos != std::string_view::npos)
        nativeName = nativeName.substr(0, hashPos);

    auto listenerResult =
        rdp_server::server::transport::openLanListener({
            nativeName, selection_.localAddress, selection_.port});
    if (listenerResult.error !=
        rdp_server::server::transport::LanListenerError::None)
        return deny(listenerRuntimeError(listenerResult.error));

    auto candidate = std::move(listenerResult.listener);
    const RuntimeTlsIdentityStatus boundIdentity =
        tlsContext_->boundIdentityStatus(candidate);
    if (!boundIdentity.boundIdentityMatchesGeneration(candidate.generation()))
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    if (deploymentPolicy_.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);
    deploymentPolicy_.emplace();
    if (!deploymentPolicy_->configurePersonalDesktopPrivateLan(selection_.port))
    {
        deploymentPolicy_.reset();
        return deny(RuntimeHostError::InvalidConfiguration);
    }

    listener_ = std::move(candidate);
    stage_ = RuntimeHostStage::ListenerAvailable;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::serviceOnce() noexcept try
{
    if (!onOwnerThread())
        return deny(RuntimeHostError::ControlUnavailable);
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);

    if (selectedStandaloneCredentialReady())
    {
        using StandaloneCredentialSessionState =
            rdp_server::server::security::StandaloneCredentialSessionState;
        const auto sessionState =
            rdp_server::server::security::
                refreshStandaloneCredentialSessionBinding(
                    standaloneCredentialSessionBinding_,
                    *ownerEvidenceSource_, true);
        if (sessionState != StandaloneCredentialSessionState::Matches)
        {
            retireStoppedRuntime(
                sessionState ==
                        StandaloneCredentialSessionState::LockOrUnknown
                    ? rdp_server::server::security::
                          OwnerConsentRevocationReason::LockOrUnknown
                    : rdp_server::server::security::
                          OwnerConsentRevocationReason::SessionReplacement);
            stage_ = RuntimeHostStage::Stopped;
            lastError_ = RuntimeHostError::CredentialNotConfigured;
            customErrorMessage_.clear();
            return {lastError_, false};
        }
    }

    if (!listener_.valid())
        return {RuntimeHostError::None, true};

    if (stage_ == RuntimeHostStage::ListenerAvailable ||
        stage_ == RuntimeHostStage::ClientAuthenticating ||
        stage_ == RuntimeHostStage::ClientConnected)
    {
        const bool enforceTcc = (ownerEvidenceSource_ == &defaultOwnerEvidence_) ||
                                (screenCaptureProbe_ != nullptr);
        if (enforceTcc)
        {
#if defined(__APPLE__)
            const auto currentCapture = screenCaptureProbe_ != nullptr
                ? screenCaptureProbe_()
                : ::rdp::macos::queryNativeScreenCapturePreflight();
            if (currentCapture == ::rdp::macos::ScreenCapturePreflightStatus::NotGranted)
            {
                retireStoppedRuntime(
                    rdp_server::server::security::OwnerConsentRevocationReason::
                        NativeAuthorizationLost);
                stage_ = RuntimeHostStage::Revoked;
                customErrorMessage_ =
                    "Screen Recording permission was revoked in System Settings.";
                lastError_ = RuntimeHostError::AccessRevoked;
                return {lastError_, false};
            }
#endif
        }

        if (!ownerSharingAuthority_.authorizes(
                rdp_server::server::security::kConsoleViewPermission))
        {
            retireStoppedRuntime(
                rdp_server::server::security::OwnerConsentRevocationReason::AuthorityExpired);
            stage_ = RuntimeHostStage::Revoked;
            lastError_ = RuntimeHostError::HostConsentRequired;
            return {lastError_, false};
        }
    }

    const auto now = std::chrono::steady_clock::now();

    if (activeConnection_ == nullptr)
    {
        auto accepted = rdp_server::server::transport::acceptNonblockingTcpConnection(
            listener_.nativeSocket());
        if (accepted.outcome == rdp_server::server::transport::TcpAcceptOutcome::WouldBlock)
        {
            return {RuntimeHostError::None, true};
        }
        if (accepted.outcome != rdp_server::server::transport::TcpAcceptOutcome::Accepted ||
            !accepted.connection.valid())
        {
            return {RuntimeHostError::None, true};
        }

        const auto peer = accepted.connection.peerEndpoint();
        std::span<const std::uint8_t> peerAddr;
        if (peer.family == rdp_server::server::transport::TcpPeerAddressFamily::Ipv4)
            peerAddr = std::span<const std::uint8_t>{peer.address}.first(4U);
        else if (peer.family == rdp_server::server::transport::TcpPeerAddressFamily::Ipv6)
            peerAddr = std::span<const std::uint8_t>{peer.address};
        else
            return {RuntimeHostError::None, true};

        if (deploymentPolicy_.has_value() &&
            !deploymentPolicy_->permitsPrivateLanTransportCandidate(peerAddr))
        {
            return {RuntimeHostError::None, true};
        }

        if (!authAttempts_.reservePeerAuthenticationAttempt(peerAddr, now))
        {
            lastError_ = RuntimeHostError::AuthenticationRateLimited;
            return {lastError_, true};
        }

        // Grant observation is only scope selection, never authorization.
        // The current native macOS issuer supports View and optional Input,
        // not Clipboard even if requested by the original owner.
        const auto ownerGrant = ownerSharingAuthority_.grantObservation();
        const std::uint32_t selectedPermissionMask =
            rdp_server::server::security::kConsoleViewPermission |
            (ownerGrant.effectivePermissionMask &
             rdp_server::server::security::kConsoleInputPermission);
        const auto consentEpoch = ownerSharingAuthority_.authorizationEpoch(
            selectedPermissionMask);
        if (!consentEpoch || !selectedStandaloneCredentialReady() ||
            tlsContext_ == nullptr || nextClientId_ == 0U ||
            nextClientId_ == (std::numeric_limits<std::uint64_t>::max)())
            return deny(RuntimeHostError::HostSessionStale);

        auto credentialState = std::make_unique<MacRuntimeCredSspState>();
        if (!credentialState->prepareChallenge())
            return deny(RuntimeHostError::AuthenticationRejected);
        activeClientId_ = nextClientId_++;
        activeClientDeadline_ = now + std::chrono::seconds{30};
        activeClientPeer_ = boundEndpointText(peer);
        activeListenerGeneration_ = listener_.generation();
        activeConsentEpoch_ = *consentEpoch;
        activeAdmissionPermissionMask_ = selectedPermissionMask;
        activeCredentialsVerified_ = false;
        activeAdmissionStage_ = AcceptedClientAdmissionStage::None;
        activeCredSsp_ = std::move(credentialState);
        activeConnection_ = std::make_unique<
            rdp_server::server::transport::OwnedPreauthTcpConnection>(
                std::move(accepted.connection),
                rdp_server::server::transport::SecurityNegotiationPolicy::HybridNla);
        acceptedClientDiagnostics_ = {};
        acceptedClientDiagnostics_.available = true;
        acceptedClientDiagnostics_.termination =
            RuntimeAcceptedClientTermination::Open;
        acceptedClientDiagnostics_.preauthStage =
            RuntimeAcceptedClientPreauthStage::AwaitConnectionRequest;
        acceptedClientDiagnostics_.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::NotStarted;
        acceptedClientDiagnostics_.standaloneCredentialGeneration =
            standaloneCredentialGeneration_;
        acceptedClientDiagnostics_.acceptedClientId = activeClientId_;
        stage_ = RuntimeHostStage::ClientAuthenticating;
    }

    if (activeConnection_ != nullptr)
    {
        const bool graphicsNegotiating =
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::GraphicsControlWritePending ||
            activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::GraphicsControlClientExpected;
        if ((activeAdmissionStage_ !=
                 AcceptedClientAdmissionStage::ShareActivated &&
             activeAdmissionStage_ !=
                 AcceptedClientAdmissionStage::GraphicsReady &&
             !graphicsNegotiating &&
             activeConnection_->cancelIfExpired(now, activeClientDeadline_)) ||
            (graphicsNegotiating && now >= activeGraphicsControlDeadline_))
        {
            retireAcceptedClient();
            stage_ = RuntimeHostStage::ListenerAvailable;
            return {RuntimeHostError::None, false};
        }

        const RuntimeHostResult preAdmission =
            advanceAcceptedClientPreAdmissionOnce();
        if (!preAdmission.succeeded())
            return preAdmission;

        if (nativeDesktop_.active())
        {
            // Initialization is itself stateful native work, so an attached
            // owner must be serviced before it reports Ready. Retain only this
            // tick's R7 observation; it is freshness, never frame authority.
            rdp::macos::MacNativeDesktopServiceObservation nativeObservation{};
            const auto nativeResult =
                nativeDesktop_.serviceOnce(&nativeObservation);
            if (!nativeResult.succeeded())
            {
                retireAcceptedClient();
                stage_ = RuntimeHostStage::ListenerAvailable;
                return deny(nativeResult.error);
            }
            if (activeAdmissionStage_ ==
                AcceptedClientAdmissionStage::GraphicsReady)
                return serviceAcceptedClientGraphicsOnce(nativeObservation);
        }
    }

    return {RuntimeHostError::None, false};
}
catch (const std::bad_alloc&)
{
    return failClosedAfterAllocationFailure();
}

RuntimeHostResult MacRuntimeHostControl::stopSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::Stop);
    stage_ = RuntimeHostStage::Stopped;
    lastError_ = RuntimeHostError::None;
    customErrorMessage_.clear();
    return {RuntimeHostError::None, false};
}

RuntimeHostResult MacRuntimeHostControl::disconnectClient(
    std::uint64_t opaqueClientId)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (activeConnection_ != nullptr && activeClientId_ == opaqueClientId)
    {
        retireAcceptedClient();
        stage_ = RuntimeHostStage::ListenerAvailable;
        return {RuntimeHostError::None, false};
    }
    return deny(RuntimeHostError::ClientNotFound);
}

RuntimeHostResult MacRuntimeHostControl::revokeSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
    stage_ = RuntimeHostStage::Revoked;
    lastError_ = RuntimeHostError::AccessRevoked;
    customErrorMessage_.clear();
    return {RuntimeHostError::None, false};
}

} // namespace rdp_server::server::runtime
