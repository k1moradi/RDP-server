// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_host_control.h"
#include "runtime_licensing_context.h"
#include "runtime_tls_context.h"
#include "server/security/standalone_credential_consent.h"
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
#include "linux_runtime_connection.h"
#include "linux_runtime_security.h"
#include <openssl/rand.h>
#endif
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
#include "x11/x11_desktop_resources.h"
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
#include "linux_prepared_clipboard_owner.h"
#endif
#if defined(RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT)
#include "x11/x11_authorized_input_route.h"
#endif
#endif
#include <algorithm>
#include <array>
#include <charconv>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <pwd.h>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
#include <poll.h>
#endif

namespace rdp_server::server::runtime
{
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
struct LinuxHostNativeDesktopState final
{
    std::optional<X11DesktopResources> desktop{};
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    // Declared after desktop so destruction also retires clipboard state first.
    LinuxPreparedClipboardOwner clipboard{};
#endif
    std::uint64_t admissionGeneration{};
    std::uint64_t sessionGeneration{};
    std::uint32_t nextFrameId{1U};
    bool graphicsWritePending{};
    bool framePublicationPending{};
    bool firstFramebufferAvailable{};
    bool nativeWorkMayRemain{true};
    std::optional<std::chrono::steady_clock::time_point> resizeDeadline{};
    std::chrono::steady_clock::time_point nextCapture{};
};
#endif

namespace
{
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
inline constexpr std::uint64_t kWindowsFileTimeUnixEpochOffset{
    116444736000000000ULL};

[[nodiscard]] bool validateStandaloneCredentialVisit(
    const rdp_server::server::security::EphemeralNtlmV2Credential& credential,
    void* rawContext) noexcept
{
    auto* valid = static_cast<bool*>(rawContext);
    if (valid == nullptr || !credential.configured())
        return false;
    *valid = true;
    return true;
}

struct CurrentConsoleAccount final
{
    std::array<char, 33> name{};
    std::size_t length{};

    [[nodiscard]] std::string_view view() const noexcept
    {
        return {name.data(), length};
    }
};

[[nodiscard]] std::optional<CurrentConsoleAccount>
currentConsoleAccount(const std::uint32_t uid) noexcept
{
    if (uid == 0U || !std::in_range<uid_t>(uid))
        return std::nullopt;

    constexpr std::size_t kPasswordDatabaseBufferBytes = 16U * 1024U;
    std::array<char, kPasswordDatabaseBufferBytes> buffer{};
    passwd record{};
    passwd* result = nullptr;
    if (::getpwuid_r(
            static_cast<uid_t>(uid), &record, buffer.data(), buffer.size(),
            &result) != 0 ||
        result != &record || record.pw_name == nullptr)
        return std::nullopt;

    const std::string_view name{record.pw_name};
    if (name.empty() || name.size() >= CurrentConsoleAccount{}.name.size() ||
        name == "root")
        return std::nullopt;

    CurrentConsoleAccount account;
    std::copy(name.begin(), name.end(), account.name.begin());
    account.length = name.size();
    account.name[account.length] = '\0';
    return account;
}

[[nodiscard]] std::uint64_t currentWindowsFileTime() noexcept
{
    const auto nanosecondsSinceUnixEpoch =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    if (nanosecondsSinceUnixEpoch <= 0)
        return 0U;

    const std::uint64_t ticksSinceUnixEpoch =
        static_cast<std::uint64_t>(nanosecondsSinceUnixEpoch) / 100U;
    if (ticksSinceUnixEpoch >
        (std::numeric_limits<std::uint64_t>::max)() -
            kWindowsFileTimeUnixEpochOffset)
    {
        return 0U;
    }
    return kWindowsFileTimeUnixEpochOffset + ticksSinceUnixEpoch;
}
#endif

[[nodiscard]] RuntimeSharingPermissionStatus sharingPermissionStatus(
    const rdp_server::server::security::OwnerSharingPermissionObservation&
        observation) noexcept
{
    using rdp_server::server::security::OwnerSharingReadOnlyDenial;
    using namespace rdp_server::server::security;

    RuntimeSharingPermissionStatus result{};
    result.canRequest = observation.canRequest;

    const bool validScope =
        observation.activeGrant &&
        (observation.effectivePermissionMask & kConsoleViewPermission) != 0U &&
        (observation.effectivePermissionMask & ~kConsoleAllowedPermissions) == 0U;
    if (validScope)
    {
        result.activeGrant = true;
        result.viewAllowed = true;
        result.inputAllowed =
            (observation.effectivePermissionMask &
             kConsoleInputPermission) != 0U;
        result.remainingMilliseconds = observation.remainingMilliseconds;
        result.denial = RuntimeSharingPermissionDenial::None;
        return result;
    }

    switch (observation.denial)
    {
    case OwnerSharingReadOnlyDenial::None:
        result.denial = RuntimeSharingPermissionDenial::Unavailable;
        break;
    case OwnerSharingReadOnlyDenial::PermissionRequired:
        result.denial = RuntimeSharingPermissionDenial::PermissionRequired;
        break;
    case OwnerSharingReadOnlyDenial::PermissionExpired:
        result.denial = RuntimeSharingPermissionDenial::PermissionExpired;
        break;
    case OwnerSharingReadOnlyDenial::ComputerLocked:
        result.denial = RuntimeSharingPermissionDenial::ComputerLocked;
        break;
    case OwnerSharingReadOnlyDenial::LoggedInDesktopChanged:
        result.denial =
            RuntimeSharingPermissionDenial::LoggedInDesktopChanged;
        break;
    case OwnerSharingReadOnlyDenial::PermissionRevoked:
        result.denial = RuntimeSharingPermissionDenial::PermissionRevoked;
        break;
    case OwnerSharingReadOnlyDenial::EvidenceUnavailable:
        result.denial = RuntimeSharingPermissionDenial::Unavailable;
        break;
    }
    return result;
}

// Mirror R1's private-LAN selection filter; R1 remains the bind authority.
[[nodiscard]] bool isEligibleAddress(const sockaddr* address) noexcept
{
    if (address == nullptr)
        return false;
    if (address->sa_family == AF_INET)
    {
        sockaddr_in ipv4{};
        std::memcpy(&ipv4, address, sizeof(ipv4));
        const std::uint32_t numeric = ntohl(ipv4.sin_addr.s_addr);
        return (numeric & 0xff000000U) == 0x0a000000U ||
               (numeric & 0xfff00000U) == 0xac100000U ||
               (numeric & 0xffff0000U) == 0xc0a80000U;
    }
    if (address->sa_family == AF_INET6)
    {
        sockaddr_in6 ipv6{};
        std::memcpy(&ipv6, address, sizeof(ipv6));
        const auto* bytes = ipv6.sin6_addr.s6_addr;
        return (bytes[0] & 0xfeU) == 0xfcU ||
               (bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U);
    }
    return false;
}

[[nodiscard]] std::optional<std::uint32_t> parseRouteNumber(
    const std::string_view text, const int base) noexcept
{
    if (text.empty())
        return std::nullopt;
    std::uint32_t value{};
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size())
        return std::nullopt;
    return value;
}

void appendLinuxDefaultRoute(
    std::vector<LinuxRuntimeDefaultRoutePreference>& routes,
    const std::string& interfaceName,
    const RuntimeHostAddressFamily family,
    const std::uint32_t metric)
{
    if (interfaceName.empty())
        return;
    const unsigned int index = ::if_nametoindex(interfaceName.c_str());
    if (index == 0U)
        return;

    const std::string stableId =
        interfaceName + "#" + std::to_string(index);
    if (std::ranges::any_of(
            routes,
            [&](const LinuxRuntimeDefaultRoutePreference& route) {
                return route.interfaceId == stableId &&
                       route.family == family &&
                       route.metric == metric;
            }))
        return;
    routes.push_back({stableId, family, metric});
}

[[nodiscard]] std::vector<LinuxRuntimeDefaultRoutePreference>
readLinuxDefaultRoutePreferences()
{
    // Read-only kernel routing snapshots. No network socket, connectivity
    // probe, DNS lookup or external request occurs here.
    constexpr std::uint32_t kRouteFlagUp = 0x1U;
    constexpr std::uint32_t kRouteFlagReject = 0x200U;
    std::vector<LinuxRuntimeDefaultRoutePreference> routes;

    {
        std::ifstream input("/proc/net/route");
        std::string line;
        (void)std::getline(input, line);
        while (std::getline(input, line))
        {
            std::istringstream row(line);
            std::string interfaceName;
            std::string destination;
            std::string gateway;
            std::string flagsText;
            std::string refCount;
            std::string useCount;
            std::string metricText;
            std::string mask;
            if (!(row >> interfaceName >> destination >> gateway >> flagsText >>
                  refCount >> useCount >> metricText >> mask))
                continue;
            if (destination != "00000000" || mask != "00000000")
                continue;
            const auto flags = parseRouteNumber(flagsText, 16);
            const auto metric = parseRouteNumber(metricText, 10);
            if (!flags || !metric || (*flags & kRouteFlagUp) == 0U ||
                (*flags & kRouteFlagReject) != 0U)
                continue;
            appendLinuxDefaultRoute(
                routes, interfaceName, RuntimeHostAddressFamily::Ipv4,
                *metric);
        }
    }

    {
        std::ifstream input("/proc/net/ipv6_route");
        std::string line;
        while (std::getline(input, line))
        {
            std::istringstream row(line);
            std::string destination;
            std::string destinationPrefixLength;
            std::string source;
            std::string sourcePrefixLength;
            std::string nextHop;
            std::string metricText;
            std::string refCount;
            std::string useCount;
            std::string flagsText;
            std::string interfaceName;
            if (!(row >> destination >> destinationPrefixLength >>
                  source >> sourcePrefixLength >> nextHop >> metricText >>
                  refCount >> useCount >> flagsText >> interfaceName))
                continue;
            if (destination != "00000000000000000000000000000000" ||
                destinationPrefixLength != "00")
                continue;
            const auto flags = parseRouteNumber(flagsText, 16);
            const auto metric = parseRouteNumber(metricText, 16);
            if (!flags || !metric || (*flags & kRouteFlagUp) == 0U ||
                (*flags & kRouteFlagReject) != 0U)
                continue;
            appendLinuxDefaultRoute(
                routes, interfaceName, RuntimeHostAddressFamily::Ipv6,
                *metric);
        }
    }
    return routes;
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

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
[[nodiscard]] constexpr const char *tlsHandshakeResultName(
    rdp_server::server::transport::TlsHandshakeResultClass result) noexcept
{
    using Result = rdp_server::server::transport::TlsHandshakeResultClass;
    switch (result)
    {
    case Result::NotAttempted: return "not-attempted";
    case Result::NeedRead: return "want-read";
    case Result::NeedWrite: return "want-write";
    case Result::Established: return "established";
    case Result::PeerEof: return "peer-eof";
    case Result::PeerTlsAlert: return "peer-tls-alert";
    case Result::TransportFailure: return "transport-failure";
    case Result::LocalTlsFailure: return "local-tls-failure";
    case Result::InvalidState: return "invalid-state";
    }
    return "invalid-state";
}

[[nodiscard]] constexpr const char *terminationName(
    rdp_server::server::transport::TcpConnectionTermination termination)
    noexcept
{
    using Termination =
        rdp_server::server::transport::TcpConnectionTermination;
    switch (termination)
    {
    case Termination::Open: return "open";
    case Termination::OrderlyTlsClose: return "tls-close-notify";
    case Termination::TransportError: return "transport-error";
    case Termination::TlsFailure: return "tls-failure";
    case Termination::ProtocolError: return "protocol-error";
    case Termination::Cancelled: return "owner-cancellation";
    case Termination::PeerEof: return "peer-eof";
    case Termination::PeerReset: return "peer-reset";
    case Termination::PeerTlsAlert: return "peer-tls-alert";
    case Termination::LocalTlsFailure: return "local-tls-failure";
    case Termination::Timeout: return "timeout";
    case Termination::OwnerCancellation: return "owner-cancellation";
    }
    return "transport-error";
}

[[nodiscard]] constexpr const char *endpointIdentityStatusName(
    RuntimeTlsEndpointIdentityStatus status) noexcept
{
    switch (status)
    {
    case RuntimeTlsEndpointIdentityStatus::Match: return "match";
    case RuntimeTlsEndpointIdentityStatus::Mismatch: return "mismatch";
    case RuntimeTlsEndpointIdentityStatus::InvalidEndpoint: return "invalid";
    case RuntimeTlsEndpointIdentityStatus::CertificateUnavailable:
        return "certificate-unavailable";
    }
    return "invalid";
}

[[nodiscard]] constexpr const char *tlsProtocolVersionName(
    int protocolVersion) noexcept
{
    switch (protocolVersion)
    {
    case TLS1_2_VERSION: return "TLS1.2";
#if defined(TLS1_3_VERSION)
    case TLS1_3_VERSION: return "TLS1.3";
#endif
    default: return "unavailable";
    }
}

[[nodiscard]] constexpr const char *tlsCertificateCommonNameClassName(
    LinuxRuntimeTlsCertificateCommonNameClass commonNameClass) noexcept
{
    switch (commonNameClass)
    {
    case LinuxRuntimeTlsCertificateCommonNameClass::Unavailable:
        return "unavailable";
    case LinuxRuntimeTlsCertificateCommonNameClass::Generic:
        return "generic";
    case LinuxRuntimeTlsCertificateCommonNameClass::Endpoint:
        return "endpoint";
    case LinuxRuntimeTlsCertificateCommonNameClass::Other:
        return "other";
    case LinuxRuntimeTlsCertificateCommonNameClass::Redacted:
        return "redacted";
    }
    return "unavailable";
}

[[nodiscard]] std::string_view boundedTlsDiagnosticText(
    const std::array<char, kLinuxRuntimeTlsDiagnosticTextCapacity> &storage,
    std::size_t bytes,
    std::string_view fallback) noexcept
{
    return bytes <= storage.size() && bytes != 0U
        ? std::string_view{storage.data(), bytes}
        : fallback;
}

[[nodiscard]] std::string_view ntlmChallengeAvIdsText(
    const rdp_server::server::security::NtlmChallengeMessageObservation
        &observation,
    std::array<char, 128> &storage) noexcept
{
    char *cursor = storage.data();
    char *const end = storage.data() + storage.size();
    const std::size_t count = std::min(
        observation.targetInfoAvIdCount,
        observation.targetInfoAvIds.size());
    if (count == 0U)
    {
        if (cursor != end)
            *cursor++ = '-';
        return {storage.data(),
                static_cast<std::size_t>(cursor - storage.data())};
    }

    for (std::size_t index = 0U; index < count; ++index)
    {
        if (index != 0U)
        {
            if (cursor == end)
                break;
            *cursor++ = ',';
        }
        const auto converted = std::to_chars(
            cursor, end,
            static_cast<unsigned int>(
                observation.targetInfoAvIds[index]));
        if (converted.ec != std::errc{})
            break;
        cursor = converted.ptr;
    }
    return {storage.data(),
            static_cast<std::size_t>(cursor - storage.data())};
}

[[nodiscard]] std::array<char, 65> tlsFingerprintText(
    const RuntimeTlsCertificateFingerprint &fingerprint,
    bool available) noexcept
{
    constexpr char kHex[] = "0123456789abcdef";
    std::array<char, 65> text{};
    if (!available)
    {
        constexpr std::string_view unavailable{"unavailable"};
        std::copy(unavailable.begin(), unavailable.end(), text.begin());
        return text;
    }
    for (std::size_t index = 0; index < fingerprint.size(); ++index)
    {
        text[index * 2U] = kHex[fingerprint[index] >> 4U];
        text[index * 2U + 1U] = kHex[fingerprint[index] & 0x0fU];
    }
    return text;
}
#endif

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
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
[[nodiscard]] RuntimeHostError listenerRuntimeError(
    rdp_server::server::transport::LanListenerError error) noexcept
{
    using rdp_server::server::transport::LanListenerError;
    switch (error)
    {
    case LanListenerError::None:
        return RuntimeHostError::None;
    case LanListenerError::InvalidSelection:
        return RuntimeHostError::InvalidConfiguration;
    case LanListenerError::InterfaceUnavailable:
        return RuntimeHostError::InterfaceUnavailable;
    case LanListenerError::PermissionDenied:
    case LanListenerError::PortOccupied:
        return RuntimeHostError::PortUnavailable;
    case LanListenerError::CertificateMismatch:
        return RuntimeHostError::TlsIdentityUnavailable;
    case LanListenerError::ListenerNotReady:
    case LanListenerError::TerminalDisconnect:
        return RuntimeHostError::InternalFailure;
    }
    return RuntimeHostError::InternalFailure;
}
#endif

#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
constexpr std::uint64_t kMaximumHostX11CapturePixels =
    16U * 1024U * 1024U;
constexpr std::size_t kHostX11EventBudget = 128U;
constexpr std::chrono::milliseconds kHostCaptureInterval{100};
constexpr std::chrono::seconds kHostResizeMaximumLifetime{6};

[[nodiscard]] bool constructHostAuthorizedX11Desktop(
    const rdp_server::server::security::LinuxNativeDesktopSelectionView&
        selection,
    void* rawContext) noexcept
{
    auto* state = static_cast<LinuxHostNativeDesktopState*>(rawContext);
    if (state == nullptr || state->desktop.has_value() ||
        selection.display().empty() ||
        selection.admissionGeneration() == 0U ||
        selection.sessionGeneration() == 0U)
        return false;
    state->desktop.emplace(
        selection.display(), kMaximumHostX11CapturePixels);
    if (!state->desktop->valid())
    {
        state->desktop.reset();
        return false;
    }
    state->admissionGeneration = selection.admissionGeneration();
    state->sessionGeneration = selection.sessionGeneration();
    state->nextCapture = std::chrono::steady_clock::now();
    return true;
}

struct LinuxHostPostShareDispatchContext final
{
    LinuxRuntimeConnection* connection{};
    const RuntimeDeploymentPolicy* policy{};
    X11DesktopResources* desktop{};
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    LinuxPreparedClipboardOwner* clipboard{};
#endif
};

[[nodiscard]] bool dispatchHostPostShareRoute(
    void* rawContext,
    rdp_server::server::transport::RdpPostShareTpktRouteKind kind,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Kind =
        rdp_server::server::transport::RdpPostShareTpktRouteKind;
    auto* context =
        static_cast<LinuxHostPostShareDispatchContext*>(rawContext);
    if (context == nullptr || context->connection == nullptr ||
        context->policy == nullptr || context->desktop == nullptr ||
        !context->desktop->valid() ||
        context->desktop->captureGeneration() == 0U)
        return false;

    switch (kind)
    {
    case Kind::GraphicsDynamicVirtualChannel:
        return context->connection->
            dispatchPersonalDesktopPostShareGraphicsTpkt(
                *context->policy, completeTpkt);
    case Kind::SlowPathInput:
#if defined(RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT)
        return X11AuthorizedInputRoute::
            dispatchAuthenticatedSlowPathTpkt(
                *context->connection, *context->policy,
                *context->desktop,
                context->desktop->captureGeneration(),
                completeTpkt);
#else
        return false;
#endif
    case Kind::ClipboardStaticChannel:
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        return context->clipboard != nullptr &&
               context->clipboard->active() &&
               context->clipboard->dispatchAuthenticatedTpkt(
                   *context->connection, *context->policy, completeTpkt);
#else
        return false;
#endif
    case Kind::UnsupportedOrMalformed:
        return false;
    }
    return false;
}

struct LinuxHostFramePublicationContext final
{
    LinuxRuntimeConnection* connection{};
    const RuntimeDeploymentPolicy* policy{};
    std::uint32_t frameId{};
    std::uint64_t expectedGeneration{};
    bool* firstFramebufferAvailable{};
};

[[nodiscard]] bool publishHostCapturedFrame(
    void* rawContext, const FramebufferView& framebuffer,
    std::uint64_t captureGeneration) noexcept
{
    auto* context =
        static_cast<LinuxHostFramePublicationContext*>(rawContext);
    if (context == nullptr || context->connection == nullptr ||
        context->policy == nullptr || context->frameId == 0U ||
        context->firstFramebufferAvailable == nullptr ||
        captureGeneration != context->expectedGeneration)
        return false;

    // R5 invoked the synchronous current-generation framebuffer callback.
    // This sticky bit is diagnostic only and cannot authorize R3/R4 work.
    *context->firstFramebufferAvailable = true;
    return context->connection->
        startPersonalDesktopClearCodecFramePublication(
            *context->policy, context->frameId, framebuffer);
}
#endif
} // namespace

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
[[nodiscard]] constexpr const char* protocolDiagnosticName(
    RuntimeAcceptedClientProtocolStage stage) noexcept
{
    switch (stage)
    {
    case RuntimeAcceptedClientProtocolStage::PreAdmission:
        return "pre-admission";
    case RuntimeAcceptedClientProtocolStage::NativeAdmissionVerified:
        return "native-admission-verified";
    case RuntimeAcceptedClientProtocolStage::McsConnectInitialReceived:
        return "mcs-connect-initial-received";
    case RuntimeAcceptedClientProtocolStage::McsConnectResponseSent:
        return "mcs-connect-response-sent";
    case RuntimeAcceptedClientProtocolStage::McsErectDomainReceived:
        return "mcs-erect-domain";
    case RuntimeAcceptedClientProtocolStage::McsAttachUserReceived:
        return "mcs-attach-user";
    case RuntimeAcceptedClientProtocolStage::McsChannelJoin:
        return "mcs-channel-join";
    case RuntimeAcceptedClientProtocolStage::McsEstablished:
        return "mcs-established";
    case RuntimeAcceptedClientProtocolStage::ShareActivation:
        return "share-activation";
    case RuntimeAcceptedClientProtocolStage::ShareActivated:
        return "share-activated";
    }
    return "pre-admission";
}

[[nodiscard]] constexpr bool directNtlmTypeOneWasReceived(
    const RuntimeAcceptedClientPreauthDiagnostics& diagnostics) noexcept
{
    using Stage = RuntimeAcceptedClientAuthenticationStage;
    if (diagnostics.ntlmEnvelope != RuntimeAcceptedClientNtlmEnvelope::DirectNtlm)
        return false;
    switch (diagnostics.authenticationStage)
    {
    case Stage::CredSspDirectNtlm:
    case Stage::NtlmChallenge:
    case Stage::NtlmAuthenticate:
    case Stage::CredSspBinding:
    case Stage::CredentialDelegation:
    case Stage::Authenticated:
    case Stage::Admission:
    case Stage::Mcs:
        return true;
    case Stage::Transport:
    case Stage::Tls:
    case Stage::CredSsp:
    case Stage::CredSspSpnego:
        return false;
    }
    return false;
}

[[nodiscard]] constexpr bool directNtlmTypeThreeWasReceived(
    const RuntimeAcceptedClientPreauthDiagnostics& diagnostics) noexcept
{
    using Stage = RuntimeAcceptedClientAuthenticationStage;
    if (diagnostics.ntlmEnvelope != RuntimeAcceptedClientNtlmEnvelope::DirectNtlm)
        return false;
    switch (diagnostics.authenticationStage)
    {
    case Stage::NtlmAuthenticate:
    case Stage::CredSspBinding:
    case Stage::CredentialDelegation:
    case Stage::Authenticated:
    case Stage::Admission:
    case Stage::Mcs:
        return true;
    case Stage::Transport:
    case Stage::Tls:
    case Stage::CredSsp:
    case Stage::CredSspSpnego:
    case Stage::CredSspDirectNtlm:
    case Stage::NtlmChallenge:
        return false;
    }
    return false;
}

[[nodiscard]] constexpr const char* authenticationDiagnosticStageName(
    const RuntimeAcceptedClientPreauthDiagnostics& diagnostics) noexcept
{
    using Stage = RuntimeAcceptedClientAuthenticationStage;
    using Termination = RuntimeAcceptedClientTermination;
    switch (diagnostics.authenticationStage)
    {
    case Stage::Transport: return "transport";
    case Stage::Tls: return "tls";
    case Stage::CredSsp: return "credssp";
    case Stage::CredSspSpnego: return "spnego";
    case Stage::CredSspDirectNtlm: return "ntlm-negotiate";
    case Stage::NtlmChallenge:
        switch (diagnostics.termination)
        {
        case Termination::OrderlyTlsClose:
        case Termination::PeerEof:
        case Termination::PeerReset:
        case Termination::PeerTlsAlert:
            return "peer-closed-after-type2";
        case Termination::Open:
        case Termination::TransportError:
        case Termination::TlsFailure:
        case Termination::ProtocolError:
        case Termination::Cancelled:
        case Termination::LocalTlsFailure:
        case Termination::Timeout:
        case Termination::OwnerCancellation:
            return "awaiting-type3";
        }
        return "awaiting-type3";
    case Stage::NtlmAuthenticate: return "ntlm-authenticate";
    case Stage::CredSspBinding: return "pubkeyauth";
    case Stage::CredentialDelegation: return "authinfo";
    case Stage::Authenticated: return "credentials-verified";
    case Stage::Admission: return "admission";
    case Stage::Mcs: return "mcs";
    }
    return "transport";
}

[[nodiscard]] constexpr bool peerAuthenticationIncompleteAfterDeliveredTypeTwo(
    const RuntimeAcceptedClientPreauthDiagnostics& diagnostics) noexcept
{
    using AuthenticationStage = RuntimeAcceptedClientAuthenticationStage;
    using ProtocolStage = RuntimeAcceptedClientProtocolStage;
    using AdmissionReason = RuntimeAcceptedClientAdmissionFailureReason;
    using Termination = RuntimeAcceptedClientTermination;

    if (!diagnostics.available ||
        diagnostics.ntlmEnvelope != RuntimeAcceptedClientNtlmEnvelope::DirectNtlm ||
        diagnostics.authenticationStage != AuthenticationStage::NtlmChallenge ||
        diagnostics.protocolStage != ProtocolStage::PreAdmission ||
        diagnostics.admissionFailureReason != AdmissionReason::None ||
        !diagnostics.directNtlmTypeTwoDelivered)
    {
        return false;
    }

    switch (diagnostics.termination)
    {
    case Termination::OrderlyTlsClose:
    case Termination::PeerEof:
    case Termination::PeerReset:
    case Termination::PeerTlsAlert:
        return true;
    case Termination::Open:
    case Termination::TransportError:
    case Termination::TlsFailure:
    case Termination::ProtocolError:
    case Termination::Cancelled:
    case Termination::LocalTlsFailure:
    case Termination::Timeout:
    case Termination::OwnerCancellation:
        return false;
    }
    return false;
}

RuntimeAcceptedClientPreauthDiagnostics
projectLinuxAcceptedClientPreauthDiagnostics(
    const LinuxRuntimeConnectionAcceptanceDiagnostics& source) noexcept
{
    RuntimeAcceptedClientPreauthDiagnostics projected;
    projected.available = true;
    projected.directNtlmTypeTwoQueued = source.directNtlmTypeTwoQueued;
    projected.directNtlmTypeTwoDelivered = source.directNtlmTypeTwoDelivered;
    projected.directNtlmTypeTwoCreationToDeliveryAgeAvailable =
        source.directNtlmTypeTwoCreationToDeliveryAgeAvailable;
    projected.directNtlmTypeTwoCreationToDeliveryMicroseconds =
        source.directNtlmTypeTwoCreationToDeliveryMicroseconds;
    projected.preauthElapsedAtPeerEofAvailable =
        source.preauthElapsedAtPeerEofAvailable;
    projected.preauthElapsedAtPeerEofMicroseconds =
        source.preauthElapsedAtPeerEofMicroseconds;
    projected.directNtlmTypeTwoToPeerEofAvailable =
        source.directNtlmTypeTwoToPeerEofAvailable;
    projected.directNtlmTypeTwoToPeerEofMicroseconds =
        source.directNtlmTypeTwoToPeerEofMicroseconds;
    projected.postTypeTwoFirstClientTlsByteAvailable =
        source.postTypeTwoFirstClientTlsByteAvailable;
    projected.postTypeTwoFirstClientTlsByteMicroseconds =
        source.postTypeTwoFirstClientTlsByteMicroseconds;
    projected.postTypeTwoCompleteTsRequestCount =
        source.postTypeTwoCompleteTsRequestCount;
    projected.postTypeTwoPlaintextBytes =
        source.postTypeTwoPlaintextBytes;

    using SourcePreauth = rdp_server::server::transport::PreauthStage;
    switch (source.preauthStage)
    {
    case SourcePreauth::AwaitConnectionRequest:
        projected.preauthStage =
            RuntimeAcceptedClientPreauthStage::AwaitConnectionRequest;
        break;
    case SourcePreauth::AwaitTls:
        projected.preauthStage = RuntimeAcceptedClientPreauthStage::AwaitTls;
        break;
    case SourcePreauth::AwaitCredSsp:
        projected.preauthStage =
            RuntimeAcceptedClientPreauthStage::AwaitCredSsp;
        break;
    case SourcePreauth::AwaitMcsConnectInitial:
        projected.preauthStage =
            RuntimeAcceptedClientPreauthStage::AwaitMcsConnectInitial;
        break;
    case SourcePreauth::Closed:
        projected.preauthStage = RuntimeAcceptedClientPreauthStage::Closed;
        break;
    }

    switch (source.tlsHandshakeStage)
    {
    case LinuxRuntimeTlsHandshakeDiagnosticStage::NotStarted:
        projected.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::NotStarted;
        break;
    case LinuxRuntimeTlsHandshakeDiagnosticStage::Handshaking:
        projected.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::Handshaking;
        break;
    case LinuxRuntimeTlsHandshakeDiagnosticStage::Established:
        projected.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::Established;
        break;
    case LinuxRuntimeTlsHandshakeDiagnosticStage::Closed:
        projected.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::Closed;
        break;
    }

    switch (source.negotiatedTlsProtocolVersion)
    {
    case TLS1_2_VERSION:
        projected.tlsConnection.protocolVersion =
            RuntimeAcceptedClientTlsProtocolVersion::Tls12;
        break;
#if defined(TLS1_3_VERSION)
    case TLS1_3_VERSION:
        projected.tlsConnection.protocolVersion =
            RuntimeAcceptedClientTlsProtocolVersion::Tls13;
        break;
#endif
    default:
        projected.tlsConnection.protocolVersion =
            RuntimeAcceptedClientTlsProtocolVersion::Unavailable;
        break;
    }
    if (source.negotiatedTlsCipherSuiteBytes > 0U &&
        source.negotiatedTlsCipherSuiteBytes <=
            kMaximumRuntimeTlsCipherNameBytes)
    {
        std::copy_n(
            source.negotiatedTlsCipherSuite.begin(),
            source.negotiatedTlsCipherSuiteBytes,
            projected.tlsConnection.cipherName.begin());
        projected.tlsConnection.cipherNameBytes =
            source.negotiatedTlsCipherSuiteBytes;
    }
    projected.tlsConnection.cipherProtocolId =
        source.negotiatedTlsCipherProtocolId;
    switch (source.clientSniClass)
    {
    case LinuxRuntimeTlsClientSniClass::None:
        projected.tlsConnection.sniClass =
            RuntimeAcceptedClientTlsSniClass::None;
        break;
    case LinuxRuntimeTlsClientSniClass::Ip:
        projected.tlsConnection.sniClass =
            RuntimeAcceptedClientTlsSniClass::Ip;
        break;
    case LinuxRuntimeTlsClientSniClass::Dns:
        projected.tlsConnection.sniClass =
            RuntimeAcceptedClientTlsSniClass::Dns;
        break;
    }

    if (source.standaloneNtlmTypeOneObserved)
    {
        projected.ntlmTypeOne.observed = true;
        projected.ntlmTypeOne.versionPresent =
            source.standaloneNtlmTypeOne.versionPresent;
        projected.ntlmTypeOne.majorVersion =
            source.standaloneNtlmTypeOne.majorVersion;
        projected.ntlmTypeOne.minorVersion =
            source.standaloneNtlmTypeOne.minorVersion;
        projected.ntlmTypeOne.buildNumber =
            source.standaloneNtlmTypeOne.buildNumber;
        projected.ntlmTypeOne.ntlmRevision =
            source.standaloneNtlmTypeOne.ntlmRevision;
    }

    switch (source.credSspTransition)
    {
    case LinuxRuntimeCredSspDiagnosticTransition::NotStarted:
        projected.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::NotStarted;
        break;
    case LinuxRuntimeCredSspDiagnosticTransition::AwaitingToken:
        projected.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::AwaitingToken;
        break;
    case LinuxRuntimeCredSspDiagnosticTransition::BindingVerified:
        projected.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::BindingVerified;
        break;
    case LinuxRuntimeCredSspDiagnosticTransition::CredentialsVerified:
        projected.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        break;
    case LinuxRuntimeCredSspDiagnosticTransition::Failed:
        projected.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        break;
    case LinuxRuntimeCredSspDiagnosticTransition::Closed:
        projected.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Closed;
        break;
    }

    using SourceEnvelope = rdp_server::server::security::
        StandaloneNtlmNegotiationEnvelope;
    switch (source.standaloneNegotiationEnvelope)
    {
    case SourceEnvelope::Undetermined:
        projected.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::Undetermined;
        break;
    case SourceEnvelope::Spnego:
        projected.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::Spnego;
        break;
    case SourceEnvelope::DirectNtlm:
        projected.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        break;
    }

    using SourceProgress = LinuxRuntimeAuthenticationProgress;
    switch (source.authenticationProgress)
    {
    case SourceProgress::Transport:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Transport;
        break;
    case SourceProgress::Tls:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Tls;
        break;
    case SourceProgress::CredSsp:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredSsp;
        break;
    case SourceProgress::CredSspSpnego:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredSspSpnego;
        break;
    case SourceProgress::CredSspDirectNtlm:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredSspDirectNtlm;
        break;
    case SourceProgress::NtlmChallenge:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge;
        break;
    case SourceProgress::NtlmAuthenticate:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmAuthenticate;
        break;
    case SourceProgress::CredSspBinding:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredSspBinding;
        break;
    case SourceProgress::CredentialDelegation:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredentialDelegation;
        break;
    case SourceProgress::Authenticated:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Authenticated;
        break;
    case SourceProgress::Mcs:
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Mcs;
        break;
    }
    using SourceProtocol = LinuxRuntimeProtocolDiagnosticStage;
    switch (source.protocolStage)
    {
    case SourceProtocol::PreAdmission:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::PreAdmission;
        break;
    case SourceProtocol::NativeAdmissionVerified:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::NativeAdmissionVerified;
        break;
    case SourceProtocol::McsConnectInitialReceived:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::McsConnectInitialReceived;
        break;
    case SourceProtocol::McsConnectResponseSent:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::McsConnectResponseSent;
        break;
    case SourceProtocol::McsErectDomainReceived:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::McsErectDomainReceived;
        break;
    case SourceProtocol::McsAttachUserReceived:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::McsAttachUserReceived;
        break;
    case SourceProtocol::McsChannelJoin:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::McsChannelJoin;
        break;
    case SourceProtocol::McsEstablished:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::McsEstablished;
        break;
    case SourceProtocol::ShareActivation:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::ShareActivation;
        break;
    case SourceProtocol::ShareActivated:
        projected.protocolStage = RuntimeAcceptedClientProtocolStage::ShareActivated;
        break;
    }

    using SourceMcsPhase = rdp_server::server::transport::McsSessionPhase;
    projected.mcsSessionAdvanced =
        source.mcsPhase != SourceMcsPhase::AwaitVerifiedR2Admission &&
        source.mcsPhase != SourceMcsPhase::Closed;
    projected.shareActivated = source.shareActivated;

    projected.standaloneCredentialGeneration =
        source.standaloneCredentialGeneration;

    using SourceFailure = rdp_server::server::security::
        StandaloneAuthenticationFailureStage;
    switch (source.standaloneAuthenticationFailureStage)
    {
    case SourceFailure::None:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::None;
        break;
    case SourceFailure::NtlmNegotiation:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation;
        break;
    case SourceFailure::Mic:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::Mic;
        break;
    case SourceFailure::SignSeal:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::SignSeal;
        break;
    case SourceFailure::Spnego:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::Spnego;
        break;
    case SourceFailure::PubKeyAuth:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::PubKeyAuth;
        break;
    case SourceFailure::AuthInfo:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::AuthInfo;
        break;
    case SourceFailure::Admission:
        projected.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::Admission;
        projected.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Admission;
        break;
    }

    using SourceAdmissionFailure = rdp_server::server::security::
        LinuxConsoleAdmissionFailureReason;
    switch (source.admissionFailureReason)
    {
    case SourceAdmissionFailure::None:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::None;
        break;
    case SourceAdmissionFailure::OwnerConsentMissing:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::OwnerConsentMissing;
        break;
    case SourceAdmissionFailure::HybridTlsProvenanceInvalid:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::HybridTlsProvenanceInvalid;
        break;
    case SourceAdmissionFailure::AuthenticationProofMismatch:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::AuthenticationProofMismatch;
        break;
    case SourceAdmissionFailure::AdmissionRequestInvalid:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::AdmissionRequestInvalid;
        break;
    case SourceAdmissionFailure::SessionMonitorUnavailable:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::SessionMonitorUnavailable;
        break;
    case SourceAdmissionFailure::SessionChangedBeforeSample:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::SessionChangedBeforeSample;
        break;
    case SourceAdmissionFailure::AccountEvidenceUnavailable:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::AccountEvidenceUnavailable;
        break;
    case SourceAdmissionFailure::AccountIdentityMismatch:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::AccountIdentityMismatch;
        break;
    case SourceAdmissionFailure::ConsoleSessionUnavailable:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::ConsoleSessionUnavailable;
        break;
    case SourceAdmissionFailure::ConsoleNotActive:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::ConsoleNotActive;
        break;
    case SourceAdmissionFailure::ConsoleNotPhysical:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::ConsoleNotPhysical;
        break;
    case SourceAdmissionFailure::ConsoleSessionInvalid:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::ConsoleSessionInvalid;
        break;
    case SourceAdmissionFailure::SeatMismatch:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::SeatMismatch;
        break;
    case SourceAdmissionFailure::DisplayMismatch:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::DisplayMismatch;
        break;
    case SourceAdmissionFailure::ConsoleOwnerMismatch:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::ConsoleOwnerMismatch;
        break;
    case SourceAdmissionFailure::EvidenceTooOld:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::EvidenceTooOld;
        break;
    case SourceAdmissionFailure::PolicyMismatch:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::PolicyMismatch;
        break;
    case SourceAdmissionFailure::PolicyGenerationChanged:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::PolicyGenerationChanged;
        break;
    case SourceAdmissionFailure::NativeProofCompletionFailed:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::NativeProofCompletionFailed;
        break;
    case SourceAdmissionFailure::CredSspAdmissionCompletionFailed:
        projected.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::CredSspAdmissionCompletionFailed;
        break;
    }

    using SourceTermination =
        rdp_server::server::transport::TcpConnectionTermination;
    switch (source.termination)
    {
    case SourceTermination::Open:
        projected.termination = RuntimeAcceptedClientTermination::Open;
        break;
    case SourceTermination::OrderlyTlsClose:
        projected.termination =
            RuntimeAcceptedClientTermination::OrderlyTlsClose;
        break;
    case SourceTermination::TransportError:
        projected.termination =
            RuntimeAcceptedClientTermination::TransportError;
        break;
    case SourceTermination::TlsFailure:
        projected.termination = RuntimeAcceptedClientTermination::TlsFailure;
        break;
    case SourceTermination::ProtocolError:
        projected.termination =
            RuntimeAcceptedClientTermination::ProtocolError;
        break;
    case SourceTermination::Cancelled:
        projected.termination = RuntimeAcceptedClientTermination::Cancelled;
        break;
    case SourceTermination::PeerEof:
        projected.termination = RuntimeAcceptedClientTermination::PeerEof;
        break;
    case SourceTermination::PeerReset:
        projected.termination = RuntimeAcceptedClientTermination::PeerReset;
        break;
    case SourceTermination::PeerTlsAlert:
        projected.termination = RuntimeAcceptedClientTermination::PeerTlsAlert;
        break;
    case SourceTermination::LocalTlsFailure:
        projected.termination =
            RuntimeAcceptedClientTermination::LocalTlsFailure;
        break;
    case SourceTermination::Timeout:
        projected.termination = RuntimeAcceptedClientTermination::Timeout;
        break;
    case SourceTermination::OwnerCancellation:
        projected.termination =
            RuntimeAcceptedClientTermination::OwnerCancellation;
        break;
    }

    const bool directNtlmBeforeTypeThree =
        projected.ntlmEnvelope == RuntimeAcceptedClientNtlmEnvelope::DirectNtlm &&
        projected.authenticationStage ==
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge &&
        projected.directNtlmTypeTwoDelivered;
    if (directNtlmBeforeTypeThree)
    {
        using PreType3 = RuntimeAcceptedClientPreType3Termination;
        switch (projected.termination)
        {
        case RuntimeAcceptedClientTermination::PeerEof:
            projected.preType3Termination = PreType3::PeerEof;
            break;
        case RuntimeAcceptedClientTermination::PeerReset:
            projected.preType3Termination = PreType3::PeerReset;
            break;
        case RuntimeAcceptedClientTermination::OrderlyTlsClose:
            projected.preType3Termination = PreType3::TlsCloseNotify;
            break;
        case RuntimeAcceptedClientTermination::PeerTlsAlert:
            projected.preType3Termination = PreType3::TlsAlert;
            break;
        case RuntimeAcceptedClientTermination::Cancelled:
        case RuntimeAcceptedClientTermination::OwnerCancellation:
            projected.preType3Termination = PreType3::LocalClose;
            break;
        case RuntimeAcceptedClientTermination::Open:
        case RuntimeAcceptedClientTermination::TransportError:
        case RuntimeAcceptedClientTermination::TlsFailure:
        case RuntimeAcceptedClientTermination::ProtocolError:
        case RuntimeAcceptedClientTermination::LocalTlsFailure:
        case RuntimeAcceptedClientTermination::Timeout:
            break;
        }
    }
    return projected;
}
#endif

RuntimeHostRecommendedEndpoint recommendLinuxPrivateLanEndpoint(
    const std::vector<RuntimeHostInterface>& interfaces,
    const std::span<const LinuxRuntimeDefaultRoutePreference> defaultRoutes,
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

            for (const LinuxRuntimeDefaultRoutePreference& route :
                 defaultRoutes)
            {
                if (route.interfaceId != candidate.interfaceId ||
                    route.family != candidate.family)
                    continue;
                candidate.preferredRoute = true;
                if (!candidate.routeMetric.has_value() ||
                    route.metric < *candidate.routeMetric)
                    candidate.routeMetric = route.metric;
            }
            candidates.emplace_back(std::move(candidate));
        }
    }
    return recommendRuntimePrivateLanEndpoint(candidates, port);
}

std::optional<LinuxNativeLanInterfaceIdentity>
resolveCurrentLinuxNativeLanInterface(std::string_view stableId) noexcept
{
    // R10's GUI stable ID is not R1's native interface name. Validate its
    // exact present kernel index before taking the name; R1 will recheck at
    // the eventual authorized bind. No allocation or network side effects.
    const auto separator = stableId.rfind('#');
    if (separator == std::string_view::npos || separator == 0U ||
        separator >= IFNAMSIZ || separator + 1U == stableId.size() ||
        stableId.substr(0, separator).find('#') != std::string_view::npos ||
        stableId.find('\0') != std::string_view::npos ||
        stableId.find('/') != std::string_view::npos)
        return std::nullopt;

    const std::string_view digits = stableId.substr(separator + 1U);
    if (digits.front() == '0')
        return std::nullopt;
    unsigned int index{};
    const auto [end, error] = std::from_chars(
        digits.data(), digits.data() + digits.size(), index);
    if (error != std::errc{} || end != digits.data() + digits.size() ||
        index == 0U)
        return std::nullopt;

    std::array<char, IFNAMSIZ> nativeName{};
    std::memcpy(nativeName.data(), stableId.data(), separator);
    if (::if_nametoindex(nativeName.data()) != index)
        return std::nullopt;
    return LinuxNativeLanInterfaceIdentity{
        stableId.substr(0, separator), index};
}

LinuxRuntimeHostControl::LinuxRuntimeHostControl() noexcept
    : ownerThread_(std::this_thread::get_id()),
      generatedLicensingContext_(
          new (std::nothrow) RuntimeLicensingContext{})
{
    if (generatedLicensingContext_ != nullptr &&
        generatedLicensingContext_->configureGeneratedApplicationIdentity())
    {
        licensingContext_ = generatedLicensingContext_.get();
    }
    else
    {
        generatedLicensingContext_.reset();
        lastError_ = RuntimeHostError::InternalFailure;
    }
}

LinuxRuntimeHostControl::LinuxRuntimeHostControl(
    rdp_server::server::security::ConsoleOsEvidenceSource& ownerEvidence)
    noexcept
    : LinuxRuntimeHostControl(
          ownerEvidence, kRuntimeAcceptedClientPreauthTimeout)
{
}

LinuxRuntimeHostControl::LinuxRuntimeHostControl(
    rdp_server::server::security::ConsoleOsEvidenceSource& ownerEvidence,
    std::chrono::milliseconds acceptedClientPreauthTimeout) noexcept
    : ownerThread_(std::this_thread::get_id()),
      generatedLicensingContext_(
          new (std::nothrow) RuntimeLicensingContext{}),
      acceptedClientPreauthTimeout_(
          (std::max)(
              acceptedClientPreauthTimeout, std::chrono::milliseconds{1})),
      ownerEvidenceSource_(&ownerEvidence),
      ownerSharingAuthority_(ownerEvidence)
{
    if (generatedLicensingContext_ != nullptr &&
        generatedLicensingContext_->configureGeneratedApplicationIdentity())
    {
        licensingContext_ = generatedLicensingContext_.get();
    }
    else
    {
        generatedLicensingContext_.reset();
        lastError_ = RuntimeHostError::InternalFailure;
    }
}
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
LinuxRuntimeHostControl::LinuxRuntimeHostControl(
    LinuxRuntimeSecurityConfiguration& securityConfiguration,
    const RuntimeServerTlsContext& tlsContext,
    const LinuxRuntimeAdmissionConfiguration& admissionConfiguration,
    const RuntimeLicensingContext& licensingContext) noexcept
    : ownerThread_(std::this_thread::get_id()),
      tlsContext_(&tlsContext),
      externalTlsContext_(true),
      securityConfiguration_(&securityConfiguration),
      admissionConfiguration_(&admissionConfiguration),
      externalSecurityConfiguration_(true),
      licensingContext_(&licensingContext)
{
}
#endif
LinuxRuntimeHostControl::~LinuxRuntimeHostControl()
{
    // The owning event-loop thread destroys this after GUI shutdown. R2 is
    // invalidated before any later-stage R1 listener retirement.
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
}

bool LinuxRuntimeHostControl::prepareTlsIdentityForSelection(
    std::string_view numericIpAddress) noexcept
{
    if (externalTlsContext_)
    {
        return tlsContext_ != nullptr &&
               tlsContext_->validateEndpointIdentity(numericIpAddress) ==
                   RuntimeTlsEndpointIdentityStatus::Match;
    }

    retireGeneratedTlsIdentity();
    RuntimeServerTlsContext generated =
        RuntimeServerTlsContext::fromGeneratedIpAddress(numericIpAddress);
    if (!generated)
        return false;

    generatedTlsContext_.emplace(std::move(generated));
    tlsContext_ = &*generatedTlsContext_;
    return true;
}

void LinuxRuntimeHostControl::retireGeneratedTlsIdentity() noexcept
{
    if (externalTlsContext_)
        return;
    tlsContext_ = nullptr;
    generatedTlsContext_.reset();
}

bool LinuxRuntimeHostControl::onOwnerThread() const noexcept
{
    return ownerThread_ == std::this_thread::get_id();
}
RuntimeHostResult LinuxRuntimeHostControl::deny(RuntimeHostError error) noexcept
{
    lastError_ = error;
    return {error, false};
}
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
bool LinuxRuntimeHostControl::selectedStandaloneCredentialReady() const noexcept
{
    if (authenticationMode_ != ConfiguredAuthenticationMode::StandalonePassword ||
        standaloneCredentialGeneration_ == 0U)
    {
        return false;
    }

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

bool LinuxRuntimeHostControl::selectedCredentialConfigured() const noexcept
{
    if (!credentialsConfigured_)
        return false;

    switch (authenticationMode_)
    {
    case ConfiguredAuthenticationMode::StandalonePassword:
        return selectedStandaloneCredentialReady();
    case ConfiguredAuthenticationMode::ExistingOsAccount:
        return serviceCredentialsReady();
    case ConfiguredAuthenticationMode::Unconfigured:
        return false;
    }
    return false;
}

bool LinuxRuntimeHostControl::prepareAutomaticStandaloneAdmission() noexcept
{
    if (externalSecurityConfiguration_)
    {
        return securityConfiguration_ != nullptr &&
               securityConfiguration_->configured() &&
               admissionConfiguration_ != nullptr;
    }

    // R5 owns the one no-config physical X11 selector. Reuse that exact
    // trusted logind observation instead of creating a second session policy.
    const auto desktop =
        rdp_server::server::security::selectCurrentPhysicalX11Desktop(
            *ownerEvidenceSource_);
    if (!desktop.eligible())
        return false;

    const auto account = currentConsoleAccount(desktop.ownerUid);
    if (!account)
        return false;

    using namespace rdp_server::server::security;
    const ConsoleIdentityRuleInput rule{
        {}, account->view(), "seat0", desktop.display(), desktop.ownerUid,
        kConsoleViewPermission | kConsoleInputPermission};

    auto security =
        std::make_unique<LinuxRuntimeSecurityConfiguration>();
    auto admission =
        std::make_unique<LinuxRuntimeAdmissionConfiguration>();
    if (!security->configureStandalonePersonalDesktop(rule) ||
        !admission->configureStandalonePersonalDesktop(rule, *security))
        return false;

    generatedAdmissionConfiguration_ = std::move(admission);
    generatedSecurityConfiguration_ = std::move(security);
    securityConfiguration_ = generatedSecurityConfiguration_.get();
    admissionConfiguration_ = generatedAdmissionConfiguration_.get();
    return true;
}

bool LinuxRuntimeHostControl::connectionTargetIdentityMatchesActiveListener()
    const noexcept
{
    return selectionConfigured_ && listener_.valid() &&
           connectionTargetIdentity_.matchesStart(
               selection_.localAddress, selection_.port,
               listener_.generation());
}

void LinuxRuntimeHostControl::applyConnectionTargetDiagnostics(
    RuntimeAcceptedClientPreauthDiagnostics& diagnostics) const noexcept
{
    if (!diagnostics.available ||
        !connectionTargetIdentityMatchesActiveListener())
    {
        return;
    }

    diagnostics.clientTargetClass = connectionTargetIdentity_.targetClass;
    diagnostics.serviceClass = connectionTargetIdentity_.serviceClass;
    diagnostics.serviceIdentityProfile =
        connectionTargetIdentity_.serviceIdentityProfile;
    diagnostics.connectionTargetGeneration =
        connectionTargetIdentity_.startGeneration;
}

void LinuxRuntimeHostControl::applyConnectionCertificateDiagnostics(
    RuntimeAcceptedClientPreauthDiagnostics& diagnostics) const noexcept
{
    diagnostics.tlsConnection.certificateProfile =
        RuntimeTlsCertificateProfile::Unavailable;
    diagnostics.tlsConnection.certificateEndpointGeneration = 0U;
    if (!diagnostics.available || tlsContext_ == nullptr || !listener_.valid())
        return;

    if (!externalTlsContext_)
    {
        diagnostics.tlsConnection.certificateProfile =
            RuntimeTlsCertificateProfile::SelfSignedExactIpSan;
    }

    const RuntimeTlsIdentityStatus identity =
        tlsContext_->boundIdentityStatus(listener_);
    if (identity.boundIdentityMatchesGeneration(listener_.generation()))
    {
        diagnostics.tlsConnection.certificateEndpointGeneration =
            identity.endpointGeneration;
    }
}

bool LinuxRuntimeHostControl::buildAuthenticationSelection(
    LinuxRuntimeAuthenticationSelection& selection) const noexcept
{
    selection = {};
    if (!connectionTargetIdentityMatchesActiveListener())
        return false;

    switch (authenticationMode_)
    {
    case ConfiguredAuthenticationMode::ExistingOsAccount:
        selection.mode = LinuxRuntimeAuthenticationMode::ExistingOsAccount;
        return true;

    case ConfiguredAuthenticationMode::StandalonePassword:
    {
        if (!selectedStandaloneCredentialReady() ||
            (connectionTargetIdentity_.serviceIdentityProfile !=
                 RuntimeServiceIdentityProfile::FixedName &&
             connectionTargetIdentity_.serviceIdentityProfile !=
                 RuntimeServiceIdentityProfile::EndpointBound))
        {
            return false;
        }

        selection.mode = LinuxRuntimeAuthenticationMode::StandalonePassword;
        selection.standaloneCredentialOwner = &standalonePasswordCredential_;
        selection.standaloneCredentialGeneration =
            standaloneCredentialGeneration_;
        selection.standaloneChallenge.netbiosDomainName =
            rdp_server::server::security::kStandaloneNtlmPortableDomainName;
        selection.standaloneChallenge.netbiosComputerName =
            std::u16string_view{
                connectionTargetIdentity_.protocolServerIdentity.data(),
                connectionTargetIdentity_.protocolServerIdentity.size()};
        selection.standaloneChallenge.timestampFileTime =
            currentWindowsFileTime();
        if (selection.standaloneChallenge.timestampFileTime == 0U)
            return false;

        auto& challenge = selection.standaloneChallenge.serverChallenge;
        if (RAND_bytes(
                challenge.data(), static_cast<int>(challenge.size())) != 1 ||
            std::all_of(
                challenge.begin(), challenge.end(),
                [](std::uint8_t value) { return value == 0U; }))
        {
            return false;
        }
        return true;
    }

    case ConfiguredAuthenticationMode::Unconfigured:
        return false;
    }
    return false;
}

bool LinuxRuntimeHostControl::serviceCredentialsReady() const noexcept
{
    if (securityConfiguration_ == nullptr ||
        !securityConfiguration_->configured() ||
        admissionConfiguration_ == nullptr ||
        licensingContext_ == nullptr ||
        !licensingContext_->configured())
        return false;

    using Kind =
        rdp_server::server::security::ConsoleEvidenceAuthenticationKind;
    Kind authenticationKind{};
    switch (authenticationMode_)
    {
    case ConfiguredAuthenticationMode::ExistingOsAccount:
        authenticationKind = Kind::KerberosPrincipal;
        break;
    case ConfiguredAuthenticationMode::StandalonePassword:
        if (!selectedStandaloneCredentialReady())
            return false;
        authenticationKind = Kind::StandalonePassword;
        break;
    case ConfiguredAuthenticationMode::Unconfigured:
        return false;
    }

    const auto* policy = securityConfiguration_->policy();
    return policy != nullptr && policy->size() != 0U &&
           policy->generation() != 0U &&
           admissionConfiguration_->request(
               *securityConfiguration_, authenticationKind).has_value();
}
#endif

std::vector<RuntimeHostInterface>
LinuxRuntimeHostControl::enumerateLocalInterfaces() const
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

RuntimeHostStatus LinuxRuntimeHostControl::status() const
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
    // Status observes the same R2 owner used by admission. The grant snapshot
    // is intentionally descriptive; only the fresh authorizes() check below
    // can report current protected-operation authority.
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
    const auto currentDesktop =
        rdp_server::server::security::selectCurrentPhysicalX11Desktop(
            *ownerEvidenceSource_);
    snapshot.product.nativeDesktopTargetAvailable =
        currentDesktop.eligible();
    if (currentDesktop.eligible())
        snapshot.product.nativeDesktopTarget =
            std::string(currentDesktop.display());
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    snapshot.credentialsConfigured = selectedCredentialConfigured();
    if (listenerCurrent &&
        connectionTargetIdentityMatchesActiveListener())
    {
        snapshot.connectionTargetIdentity = connectionTargetIdentity_;
    }
    snapshot.acceptedClientPreauthDiagnostics =
        acceptedClientPreauthDiagnostics_;
    if (acceptedClient_ != nullptr)
    {
        snapshot.acceptedClientPreauthDiagnostics =
            projectLinuxAcceptedClientPreauthDiagnostics(
                acceptedClient_->acceptanceDiagnostics());
    }
    applyConnectionTargetDiagnostics(
        snapshot.acceptedClientPreauthDiagnostics);
    applyConnectionCertificateDiagnostics(
        snapshot.acceptedClientPreauthDiagnostics);
#endif
    if (tlsContext_ != nullptr)
    {
        snapshot.tlsCertificateProfile =
            externalTlsContext_
                ? RuntimeTlsCertificateProfile::Unavailable
                : RuntimeTlsCertificateProfile::SelfSignedExactIpSan;
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
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    snapshot.graphicsReady =
        acceptedClient_ != nullptr &&
        acceptedClientPhase_ == AcceptedClientPhase::GraphicsReady;
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
    snapshot.nativeDesktopReady =
        snapshot.graphicsReady && nativeDesktop_ != nullptr &&
        nativeDesktop_->desktop.has_value() &&
        nativeDesktop_->desktop->valid() &&
        nativeDesktop_->admissionGeneration != 0U &&
        nativeDesktop_->sessionGeneration != 0U;
    snapshot.nativeDesktopInitializing =
        snapshot.graphicsReady && !snapshot.nativeDesktopReady;
#endif
    if (acceptedClient_ != nullptr)
    {
        const auto acceptance =
            acceptedClient_->firstClientAcceptanceObservability();
        bool firstFramebufferAvailable = false;
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
        firstFramebufferAvailable =
            nativeDesktop_ != nullptr &&
            nativeDesktop_->firstFramebufferAvailable;
#endif
        snapshot.firstLiveGraphicsTrace =
            projectRuntimeFirstLiveGraphicsTrace(
                firstFramebufferAvailable,
                acceptance.firstClearCodecFramePrepared,
                acceptance.firstExactFrameWriteCommitted,
                acceptance.outstandingFrameAcknowledgements,
                acceptance.firstGenuineFrameAcknowledge);
    }
    snapshot.clientDisconnected =
        listenerCurrent && acceptedClient_ == nullptr && clientDisconnected_;
    if (acceptedClient_ != nullptr && acceptedClientId_ != 0U)
    {
        RuntimeHostClient client;
        client.opaqueId = acceptedClientId_;
        client.peerAddress = acceptedClientPeer_;
        client.authenticating =
            stage_ == RuntimeHostStage::ClientAuthenticating;
        client.shareActivated =
            stage_ == RuntimeHostStage::ShareActivated ||
            stage_ == RuntimeHostStage::DesktopVisible ||
            stage_ == RuntimeHostStage::ClientConnected;
        // A protocol-stage label cannot manufacture native desktop visibility.
        client.desktopVisible =
            snapshot.nativeDesktopReady &&
            (stage_ == RuntimeHostStage::DesktopVisible ||
             stage_ == RuntimeHostStage::ClientConnected);
        snapshot.activeClients.emplace_back(std::move(client));
    }
#endif
    // Graphics readiness is an R3/RDPGFX fact. Native readiness above is
    // projected only from the one live R2-selected X11 owner; neither grants
    // authority and neither implies that a frame has completed delivery.

    snapshot.product.controlAvailable = true;
    snapshot.product.eligibleLanInterfaces = enumerateLocalInterfaces();
    const std::uint16_t recommendedPort =
        selectionConfigured_ ? selection_.port : 3389U;
    const std::vector<LinuxRuntimeDefaultRoutePreference> defaultRoutes =
        readLinuxDefaultRoutePreferences();
    snapshot.product.recommendedEndpoint =
        recommendLinuxPrivateLanEndpoint(
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
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    snapshot.product.credentialCapabilities.existingOsAccount =
        externalSecurityConfiguration_ &&
        securityConfiguration_ != nullptr && tlsContext_ != nullptr &&
        admissionConfiguration_ != nullptr && licensingContext_ != nullptr;
#endif
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    snapshot.product.credentialCapabilities.standalonePassword =
        kStandalonePasswordProductCapabilityApproved;
    snapshot.product.credentialCapabilities
        .standalonePasswordConfigurationAvailable = true;
    snapshot.product.automaticRuntimeProvisioned =
        !externalSecurityConfiguration_ &&
        generatedLicensingContext_ != nullptr &&
        licensingContext_ == generatedLicensingContext_.get() &&
        licensingContext_->configured();
#else
    snapshot.product.credentialCapabilities.standalonePassword = false;
    snapshot.product.credentialCapabilities
        .standalonePasswordConfigurationAvailable = false;
    snapshot.product.automaticRuntimeProvisioned = false;
#endif
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

    snapshot.product.lastErrorMessage =
        snapshot.lastError == RuntimeHostError::None
        ? std::string{}
        : std::string(runtimeHostErrorMessage(snapshot.lastError));
    return snapshot;
}

RuntimeHostResult LinuxRuntimeHostControl::configure(
    const RuntimeHostOptions& options)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (listener_.valid())
        return deny(RuntimeHostError::InvalidConfiguration);
    if (licensingContext_ == nullptr || !licensingContext_->configured())
        return deny(RuntimeHostError::InternalFailure);

    // Automatic identities are selection-scoped. A new preparation attempt
    // retires the previous key/certificate and Start-scoped service identity
    // before evaluating the new address.
    retireGeneratedTlsIdentity();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    connectionTargetIdentity_ = {};
#endif

    // A rejected new selection must not retain a previously approved
    // interface/address preference for a later independent Start request.
    // Never invalidate an already-owned live listener during reconfiguration.
    selection_ = {};
    selectionConfigured_ = false;
    if (options.afterLoginLaunchRequested)
        return deny(RuntimeHostError::ListenerPolicyDenied);
    const auto preflight = assessRuntimeSelectedLanEndpoint(
        options, enumerateLocalInterfaces());
    if (!preflight.succeeded())
        return deny(preflight.error);
    if (!resolveCurrentLinuxNativeLanInterface(options.interfaceId))
        return deny(RuntimeHostError::InterfaceUnavailable);
    if (!prepareTlsIdentityForSelection(options.localAddress))
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    selection_ = options;
    selectionConfigured_ = true;
    lastError_ = RuntimeHostError::HostConsentRequired;
    return {RuntimeHostError::None, false};
}

bool LinuxRuntimeHostControl::configureStandaloneApplicationPassword(
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    using namespace rdp_server::server::security;
    if (!onOwnerThread() ||
        stage_ == RuntimeHostStage::Revoked ||
        listener_.valid())
    {
        cleanseStandalonePasswordInput(password);
        return false;
    }

    // Credential configuration is independent of native admission readiness.
    // Replacement always revokes the previous owner-consent generation and
    // consumes/scrubs caller input through the production credential owner.
    standaloneCredentialSessionBinding_.clear();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    authenticationMode_ = ConfiguredAuthenticationMode::Unconfigured;
    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;
#endif

    const auto observation = replaceStandaloneApplicationCredential(
        standalonePasswordCredential_, ownerSharingAuthority_,
        username, password);
    if (!observation.configured || observation.generation == 0U)
    {
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    authenticationMode_ = ConfiguredAuthenticationMode::StandalonePassword;
    standaloneCredentialGeneration_ = observation.generation;
    credentialsConfigured_ = true;
    if (!selectedStandaloneCredentialReady())
    {
        authenticationMode_ = ConfiguredAuthenticationMode::Unconfigured;
        standaloneCredentialGeneration_ = 0U;
        credentialsConfigured_ = false;
        standalonePasswordCredential_.revoke();
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return false;
    }

    (void)refreshStandaloneCredentialSessionBinding(
        standaloneCredentialSessionBinding_, *ownerEvidenceSource_, true);
    stage_ = RuntimeHostStage::CredentialsConfigured;
#else
    stage_ = RuntimeHostStage::Stopped;
#endif
    lastError_ = RuntimeHostError::None;
    return true;
}

rdp_server::server::security::StandalonePasswordCredentialObservation
LinuxRuntimeHostControl::standaloneApplicationPasswordObservation()
    const noexcept
{
    if (!onOwnerThread())
        return {};
    return standalonePasswordCredential_.observation();
}

bool LinuxRuntimeHostControl::visitStandaloneApplicationPassword(
    std::uint64_t expectedGeneration,
    rdp_server::server::security::StandalonePasswordCredentialVisitor visitor,
    void* context) const noexcept
{
    return onOwnerThread() &&
           standalonePasswordCredential_.visit(
               expectedGeneration, visitor, context);
}

RuntimeHostResult LinuxRuntimeHostControl::requestCredentialSetup(
    rdp_server::server::security::LanCredentialChoice choice)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    using namespace rdp_server::server::security;
    // Any credential-mode/configuration action invalidates prior consent and
    // retires the alternate standalone credential mode before evaluating the
    // requested product credential choice.
    ownerSharingAuthority_.revoke(
        OwnerConsentRevocationReason::CredentialChange);
    standalonePasswordCredential_.revoke();
    standaloneCredentialSessionBinding_.clear();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    authenticationMode_ = ConfiguredAuthenticationMode::Unconfigured;
    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;
#endif
    const auto decision = assessLanCredentialChoice(choice);
    if (decision == LanCredentialDecision::UnsupportedIndependentPasswordCredSsp)
        return deny(RuntimeHostError::UnsupportedIndependentPasswordNla);
    if (decision == LanCredentialDecision::CredentialNotConfigured)
        return deny(RuntimeHostError::CredentialNotConfigured);
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (securityConfiguration_ == nullptr ||
        !securityConfiguration_->configured())
        return deny(RuntimeHostError::CredentialProviderUnavailable);

    authenticationMode_ = ConfiguredAuthenticationMode::ExistingOsAccount;
    if (!serviceCredentialsReady())
    {
        authenticationMode_ = ConfiguredAuthenticationMode::Unconfigured;
        return deny(RuntimeHostError::CredentialNotConfigured);
    }
    credentialsConfigured_ = true;
    stage_ = RuntimeHostStage::CredentialsConfigured;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
#else
    return deny(RuntimeHostError::CredentialProviderUnavailable);
#endif
}

RuntimeHostResult LinuxRuntimeHostControl::requestHostPermissionSetup(
    const RuntimeHostPermissionRequest& request)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);

#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (authenticationMode_ ==
            ConfiguredAuthenticationMode::StandalonePassword &&
        selectedStandaloneCredentialReady())
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
#endif

    // This call is reachable from the locally running GUI, never from an
    // accepted peer. M1 trusts that explicit click, then R2 binds it to fresh
    // process-UID/physical-seat0/session/unlocked native evidence.
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

RuntimeHostResult LinuxRuntimeHostControl::startSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return deny(RuntimeHostError::AccessRevoked);
    if (!selectionConfigured_)
        return deny(RuntimeHostError::InvalidConfiguration);
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    return deny(RuntimeHostError::CredentialProviderUnavailable);
#else
    // No listener or native capture is created unless the current desktop is
    // a fresh same-owner unlocked physical X11 session from native evidence.
    if (!rdp_server::server::security::selectCurrentPhysicalX11Desktop(
            *ownerEvidenceSource_).eligible())
        return deny(RuntimeHostError::NativeAuthorizationDenied);
    if (licensingContext_ == nullptr || !licensingContext_->configured())
        return deny(RuntimeHostError::InternalFailure);
    // Native admission is a Start prerequisite, not a credential-configured
    // fact. Rebuild it from fresh owner/X11 evidence at the explicit Start.
    if (authenticationMode_ == ConfiguredAuthenticationMode::StandalonePassword &&
        !prepareAutomaticStandaloneAdmission())
        return deny(RuntimeHostError::NativeAuthorizationDenied);
    if (securityConfiguration_ == nullptr ||
        !securityConfiguration_->configured())
        return deny(RuntimeHostError::CredentialProviderUnavailable);
    if (!credentialsConfigured_ || !serviceCredentialsReady())
        return deny(RuntimeHostError::CredentialNotConfigured);

    // R2 owner consent precedes the fresh native interface/address check.
    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    const auto current = assessRuntimeSelectedLanEndpoint(
        selection_, enumerateLocalInterfaces());
    const auto nativeIdentity =
        resolveCurrentLinuxNativeLanInterface(selection_.interfaceId);
    if (!current.succeeded() || !nativeIdentity)
    {
        selection_ = {};
        selectionConfigured_ = false;
        retireGeneratedTlsIdentity();
        return deny(current.succeeded()
            ? RuntimeHostError::InterfaceUnavailable : current.error);
    }

    if (tlsContext_ == nullptr)
        return deny(RuntimeHostError::TlsIdentityUnavailable);
    const RuntimeTlsIdentityStatus unboundIdentity =
        tlsContext_->identityStatus();
    if (!unboundIdentity.fingerprintAvailable ||
        unboundIdentity.state != RuntimeTlsIdentityState::ConfiguredUnbound)
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    // Build the one non-secret product target tuple before opening a socket.
    // Current production deliberately stays on the already-qualified fixed
    // NTLM server identity. EndpointBound remains dormant until Microsoft
    // full-CredSSP IP-target evidence selects it.
    RuntimeServiceIdentityProfile targetIdentityProfile{
        RuntimeServiceIdentityProfile::Unavailable};
    std::u16string_view protocolServerIdentity;
    switch (authenticationMode_)
    {
    case ConfiguredAuthenticationMode::ExistingOsAccount:
        break;
    case ConfiguredAuthenticationMode::StandalonePassword:
        targetIdentityProfile = RuntimeServiceIdentityProfile::FixedName;
        protocolServerIdentity =
            rdp_server::server::security::kStandaloneNtlmPortableServerName;
        break;
    case ConfiguredAuthenticationMode::Unconfigured:
        return deny(RuntimeHostError::CredentialNotConfigured);
    }

    auto targetIdentity = prepareRuntimeConnectionTargetIdentity(
        selection_.localAddress,
        selection_.port,
        targetIdentityProfile,
        protocolServerIdentity);
    if (!targetIdentity.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);

    auto listenerResult =
        rdp_server::server::transport::openLanListener({
            nativeIdentity->nativeName, selection_.localAddress,
            selection_.port});
    if (listenerResult.error !=
        rdp_server::server::transport::LanListenerError::None)
        return deny(listenerRuntimeError(listenerResult.error));

    auto candidate = std::move(listenerResult.listener);
    const RuntimeTlsIdentityStatus boundIdentity =
        tlsContext_->boundIdentityStatus(candidate);
    if (!boundIdentity.boundIdentityMatchesGeneration(
            candidate.generation()))
        return deny(RuntimeHostError::TlsIdentityUnavailable);

    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
        return deny(RuntimeHostError::HostConsentRequired);

    if (deploymentPolicy_.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);
    deploymentPolicy_.emplace();
    if (!deploymentPolicy_->configurePersonalDesktopPrivateLan(
            selection_.port))
    {
        deploymentPolicy_.reset();
        return deny(RuntimeHostError::InvalidConfiguration);
    }

    targetIdentity->startGeneration = candidate.generation();
    if (!targetIdentity->valid())
    {
        deploymentPolicy_.reset();
        return deny(RuntimeHostError::InternalFailure);
    }

    listener_ = std::move(candidate);
    connectionTargetIdentity_ = std::move(*targetIdentity);
    acceptedClientPreauthDiagnostics_ = {};
    stage_ = RuntimeHostStage::ListenerAvailable;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
#endif
}


#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
void LinuxRuntimeHostControl::retireNativeDesktop() noexcept
{
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    if (nativeDesktop_ != nullptr)
        nativeDesktop_->clipboard.retire();
#endif
    if (nativeDesktop_ != nullptr &&
        nativeDesktop_->desktop.has_value())
        nativeDesktop_->desktop->retireAfterAuthorizationLoss();
    nativeDesktop_.reset();
}

RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept
{
    if (acceptedClient_ == nullptr || !acceptedClient_->ready() ||
        !deploymentPolicy_.has_value() ||
        acceptedClientPhase_ != AcceptedClientPhase::GraphicsReady ||
        nativeDesktop_ != nullptr)
        return deny(RuntimeHostError::GraphicsUnavailable);

    auto candidate = std::make_unique<LinuxHostNativeDesktopState>();
    if (!acceptedClient_->visitNativeDesktopSelection(
            &constructHostAuthorizedX11Desktop, candidate.get()) ||
        !candidate->desktop.has_value() ||
        !candidate->desktop->valid() ||
        candidate->admissionGeneration == 0U ||
        candidate->sessionGeneration == 0U)
    {
        if (candidate->desktop.has_value())
            candidate->desktop->retireAfterAuthorizationLoss();
        retireAcceptedClient(RuntimeHostError::GraphicsUnavailable);
        return {RuntimeHostError::GraphicsUnavailable, false};
    }

#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    if (!candidate->clipboard.prepare(
            *candidate->desktop, candidate->admissionGeneration,
            candidate->sessionGeneration))
    {
        candidate->clipboard.retire();
        candidate->desktop->retireAfterAuthorizationLoss();
        retireAcceptedClient(RuntimeHostError::GraphicsUnavailable);
        return {RuntimeHostError::GraphicsUnavailable, false};
    }
#endif

    nativeDesktop_ = std::move(candidate);
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept
{
    using Clock = std::chrono::steady_clock;
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using ReadStep = LinuxPostShareApplicationReadStatus;
    using FrameStep = LinuxPersonalDesktopGraphicsDvcStepStatus;
    using Reconfiguration =
        rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration;
    using Readiness =
        rdp_server::server::transport::RdpGraphicsFramePublicationReadiness;

    const auto retireClient =
        [this](RuntimeHostError error) noexcept -> RuntimeHostResult {
            retireAcceptedClient(error);
            return {error, false};
        };
    const auto retireStaleHost =
        [this]() noexcept -> RuntimeHostResult {
            retireStoppedRuntime(
                rdp_server::server::security::
                    OwnerConsentRevocationReason::NativeAuthorizationLost);
            stage_ = RuntimeHostStage::Revoked;
            lastError_ = RuntimeHostError::HostSessionStale;
            return {lastError_, false};
        };

    if (acceptedClient_ == nullptr || !acceptedClient_->ready() ||
        !deploymentPolicy_.has_value() || nativeDesktop_ == nullptr ||
        !nativeDesktop_->desktop.has_value() ||
        !nativeDesktop_->desktop->valid())
        return retireClient(RuntimeHostError::GraphicsUnavailable);

    if (!acceptedClient_->authorizePersonalDesktopApplicationTraffic(
            *deploymentPolicy_))
        return retireStaleHost();

    const auto now = Clock::now();
    if (nativeDesktop_->resizeDeadline &&
        now >= *nativeDesktop_->resizeDeadline)
        return retireClient(RuntimeHostError::GraphicsUnavailable);

    const int socketDescriptor =
        acceptedClient_->nativeSocketPollDescriptor();
    const Interest socketInterest = acceptedClient_->ioInterest();
    if (socketDescriptor < 0 ||
        (socketInterest != Interest::Read &&
         socketInterest != Interest::Write))
        return retireClient(RuntimeHostError::AuthenticationRejected);

    const auto nativeChange = acceptedClient_->registerNativeChange();
    if (!nativeChange)
        return retireStaleHost();

    if (nativeChange->admissionGeneration !=
            nativeDesktop_->admissionGeneration ||
        nativeChange->sessionGeneration !=
            nativeDesktop_->sessionGeneration ||
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        !nativeDesktop_->clipboard.generationsMatch(
            nativeChange->admissionGeneration,
            nativeChange->sessionGeneration) ||
#endif
        nativeChange->events >
            static_cast<int>((std::numeric_limits<short>::max)()))
    {
        if (acceptedClient_->unregisterNativeChange(*nativeChange))
            (void)acceptedClient_->releaseNativeChangeWithoutDispatch(
                *nativeChange);
        return retireStaleHost();
    }

    std::array<pollfd, 3U> pollDescriptors{{
        {nativeChange->descriptor,
         static_cast<short>(nativeChange->events), 0},
        {nativeDesktop_->desktop->fileDescriptor(), POLLIN, 0},
        {socketDescriptor,
         static_cast<short>(
             socketInterest == Interest::Read ? POLLIN : POLLOUT),
         0},
    }};
    errno = 0;
    const int polled = ::poll(
        pollDescriptors.data(),
        static_cast<nfds_t>(pollDescriptors.size()), 0);
    const int pollError = errno;
    const short nativeChangeEvents = pollDescriptors[0].revents;
    const short x11Events = pollDescriptors[1].revents;
    const short socketEvents = pollDescriptors[2].revents;

    // The zero-wait poll set is dead before any R2, X11 or TLS callback.
    if (!acceptedClient_->unregisterNativeChange(*nativeChange))
        return retireStaleHost();

    if (polled < 0)
    {
        if (!acceptedClient_->releaseNativeChangeWithoutDispatch(
                *nativeChange))
            return retireStaleHost();
        if (pollError == EINTR)
            return {RuntimeHostError::None, true};
        return retireClient(RuntimeHostError::InternalFailure);
    }

    const bool nativeChangeReady =
        polled > 0 && nativeChangeEvents != 0;
    if (nativeChangeReady)
    {
        if ((nativeChangeEvents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            !acceptedClient_->dispatchNativeChangeReady(*nativeChange))
            return retireStaleHost();
    }
    else if (!acceptedClient_->releaseNativeChangeWithoutDispatch(
                 *nativeChange))
    {
        return retireStaleHost();
    }

    if ((x11Events & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        return retireClient(RuntimeHostError::GraphicsUnavailable);
    // Only an invalid descriptor is a scheduler failure. POLLERR/POLLHUP
    // must reach the sole R1 read/write owner once so it can classify the
    // actual transport/TLS termination instead of being pre-cancelled here.
    if ((socketEvents & POLLNVAL) != 0)
        return retireClient(RuntimeHostError::AuthenticationRejected);

    if (!acceptedClient_->ready() ||
        !acceptedClient_->authorizePersonalDesktopApplicationTraffic(
            *deploymentPolicy_))
        return retireStaleHost();

    bool moreX11Events = false;
    X11EventSink* additionalEventSink = nullptr;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    additionalEventSink = nativeDesktop_->clipboard.eventSink();
#endif
    if (nativeDesktop_->desktop->processEvents(
            kHostX11EventBudget, &moreX11Events,
            (x11Events & POLLIN) != 0, additionalEventSink) !=
            ConnectionStatus::Ok ||
        !nativeDesktop_->desktop->valid() ||
        nativeDesktop_->desktop->captureGeneration() == 0U)
        return retireClient(RuntimeHostError::GraphicsUnavailable);
    nativeDesktop_->nativeWorkMayRemain = moreX11Events;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    if (!nativeDesktop_->clipboard.serviceNative(
            *acceptedClient_, *deploymentPolicy_, Clock::now(),
            !nativeDesktop_->graphicsWritePending))
        return retireClient(RuntimeHostError::GraphicsUnavailable);
#endif

    // The event batch can invalidate geometry/input; refresh R2 before any
    // classified network input or framebuffer work in this same tick.
    if (!acceptedClient_->authorizePersonalDesktopApplicationTraffic(
            *deploymentPolicy_))
        return retireStaleHost();

    const bool terminalTransportEvent =
        (socketEvents & (POLLERR | POLLHUP)) != 0;
    const bool socketReadable =
        (socketEvents & POLLIN) != 0 || terminalTransportEvent;
    const bool socketWritable =
        (socketEvents & POLLOUT) != 0 || terminalTransportEvent;

#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    if (nativeDesktop_->clipboard.writePending())
    {
        if (!nativeDesktop_->clipboard.advanceTlsWrite(
                *acceptedClient_, *deploymentPolicy_,
                socketReadable, socketWritable))
            return retireClient(RuntimeHostError::GraphicsUnavailable);
        // One actual R1/R3 write step per bounded Qt tick. A still-pending
        // clipboard write keeps ownership of WANT_READ/WANT_WRITE.
        if (nativeDesktop_->clipboard.writePending())
            return {RuntimeHostError::None, true};
    }
    else
#endif
    if (nativeDesktop_->graphicsWritePending)
    {
        const auto written =
            acceptedClient_->
                advancePersonalDesktopGraphicsDynamicVirtualChannel(
                    *deploymentPolicy_, socketReadable, socketWritable);
        switch (written.status)
        {
        case FrameStep::Ready:
            nativeDesktop_->graphicsWritePending = false;
            if (nativeDesktop_->framePublicationPending)
            {
                nativeDesktop_->framePublicationPending = false;
                stage_ = RuntimeHostStage::DesktopVisible;
            }
            break;
        case FrameStep::Progress:
        case FrameStep::NeedRead:
        case FrameStep::NeedWrite:
            return {RuntimeHostError::None, true};
        case FrameStep::AdmissionDenied:
            return retireStaleHost();
        case FrameStep::Invalid:
        case FrameStep::Closed:
            return retireClient(RuntimeHostError::GraphicsUnavailable);
        }
    }
    else
    {
        LinuxHostPostShareDispatchContext dispatchContext{
            acceptedClient_.get(), &*deploymentPolicy_,
            &*nativeDesktop_->desktop};
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        dispatchContext.clipboard = &nativeDesktop_->clipboard;
#endif
        const LinuxPostShareTpktSink sink{
            &dispatchContext, &dispatchHostPostShareRoute};
        const auto read =
            acceptedClient_->advancePersonalDesktopPostShareApplicationRead(
                *deploymentPolicy_, socketReadable, socketWritable, sink);
        switch (read.status)
        {
        case ReadStep::Progress:
        case ReadStep::Routed:
        case ReadStep::NeedRead:
        case ReadStep::NeedWrite:
            break;
        case ReadStep::AdmissionDenied:
            return retireStaleHost();
        case ReadStep::Invalid:
        case ReadStep::Closed:
            return retireClient(RuntimeHostError::AuthenticationRejected);
        }
    }

#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    if (!nativeDesktop_->clipboard.serviceAfterNetworkDispatch(
            *acceptedClient_, *deploymentPolicy_, Clock::now()) ||
        (nativeDesktop_->clipboard.writePending() &&
         !nativeDesktop_->clipboard.advanceTlsWrite(
             *acceptedClient_, *deploymentPolicy_, false, false)))
        return retireClient(RuntimeHostError::GraphicsUnavailable);
#endif

    if (!acceptedClient_->ready() ||
        !acceptedClient_->authorizePersonalDesktopApplicationTraffic(
            *deploymentPolicy_))
        return retireStaleHost();

    const auto postIoNow = Clock::now();
    if (nativeDesktop_->resizeDeadline &&
        postIoNow >= *nativeDesktop_->resizeDeadline)
        return retireClient(RuntimeHostError::GraphicsUnavailable);
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    if (nativeDesktop_->clipboard.writePending())
        return {RuntimeHostError::None, true};
#endif
    if (nativeDesktop_->graphicsWritePending ||
        postIoNow < nativeDesktop_->nextCapture)
        return {RuntimeHostError::None, true};

    const std::uint64_t currentNativeSessionGeneration =
        nativeChange->sessionGeneration;
    const X11NativeGeometryObservation geometry =
        nativeDesktop_->desktop->observeNativeGeometry(
            currentNativeSessionGeneration);
    if (!geometry.valid() ||
        !nativeDesktop_->desktop->nativeGeometryIsCurrent(
            geometry, currentNativeSessionGeneration))
        return retireClient(RuntimeHostError::GraphicsUnavailable);

    const Reconfiguration reconfiguration =
        acceptedClient_->
            beginPersonalDesktopGraphicsSurfaceReconfiguration(
                *deploymentPolicy_, geometry.pixelGeometry);
    switch (reconfiguration)
    {
    case Reconfiguration::Unchanged:
        nativeDesktop_->resizeDeadline.reset();
        break;
    case Reconfiguration::Deferred:
        if (!nativeDesktop_->resizeDeadline)
            nativeDesktop_->resizeDeadline =
                postIoNow + kHostResizeMaximumLifetime;
        nativeDesktop_->nextCapture =
            postIoNow + kHostCaptureInterval;
        return {RuntimeHostError::None, true};
    case Reconfiguration::Started:
        if (!nativeDesktop_->resizeDeadline)
            nativeDesktop_->resizeDeadline =
                postIoNow + kHostResizeMaximumLifetime;
        nativeDesktop_->graphicsWritePending = true;
        nativeDesktop_->nextCapture =
            postIoNow + kHostCaptureInterval;
        return {RuntimeHostError::None, false};
    case Reconfiguration::Rejected:
        return retireClient(RuntimeHostError::GraphicsUnavailable);
    }

    if (nativeDesktop_->nextFrameId == 0U)
        return retireClient(RuntimeHostError::GraphicsUnavailable);

    const Readiness readiness =
        acceptedClient_->
            preflightPersonalDesktopGraphicsFramePublication(
                *deploymentPolicy_, nativeDesktop_->nextFrameId);
    if (readiness == Readiness::DeferredForFrameAcknowledge)
    {
        nativeDesktop_->nextCapture =
            Clock::now() + kHostCaptureInterval;
        return {RuntimeHostError::None, true};
    }
    if (readiness != Readiness::Ready ||
        !nativeDesktop_->desktop->nativeGeometryIsCurrent(
            geometry, currentNativeSessionGeneration))
        return retireClient(RuntimeHostError::GraphicsUnavailable);

    LinuxHostFramePublicationContext frameContext{
        acceptedClient_.get(), &*deploymentPolicy_,
        nativeDesktop_->nextFrameId, geometry.captureGeneration,
        &nativeDesktop_->firstFramebufferAvailable};
    if (!nativeDesktop_->desktop->consumeR4Frame(
            geometry, currentNativeSessionGeneration,
            X11R4BgraFrameConsumer{
                &frameContext, &publishHostCapturedFrame}))
        return retireClient(RuntimeHostError::GraphicsUnavailable);

    ++nativeDesktop_->nextFrameId;
    nativeDesktop_->graphicsWritePending = true;
    nativeDesktop_->framePublicationPending = true;
    nativeDesktop_->nextCapture =
        Clock::now() + kHostCaptureInterval;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}
#endif

void LinuxRuntimeHostControl::clearAcceptedClient() noexcept
{
    acceptedClient_.reset();
    acceptedClientDeadline_ = {};
    acceptedClientPhase_ = AcceptedClientPhase::None;
    acceptedClientId_ = 0U;
    acceptedClientPeer_.clear();
    acceptedClientReadable_ = false;
    acceptedClientWritable_ = false;
}

void LinuxRuntimeHostControl::retireAcceptedClient(
    RuntimeHostError error) noexcept
{
    RuntimeHostError retainedError = error;
    const bool hadAcceptedClient =
        acceptedClient_ != nullptr && acceptedClientId_ != 0U;
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
    retireNativeDesktop();
#endif
    if (acceptedClient_ != nullptr)
    {
        // Snapshot before the explicit owner cancellation below. R1 may
        // already have classified peer EOF/reset/alert, local TLS failure or
        // timeout; a later aggregate revoke must not overwrite that evidence.
        const auto diagnostics = acceptedClient_->acceptanceDiagnostics();
        acceptedClientPreauthDiagnostics_ =
            projectLinuxAcceptedClientPreauthDiagnostics(diagnostics);
        applyConnectionTargetDiagnostics(
            acceptedClientPreauthDiagnostics_);
        applyConnectionCertificateDiagnostics(
            acceptedClientPreauthDiagnostics_);
        if (error == RuntimeHostError::AuthenticationRejected &&
            peerAuthenticationIncompleteAfterDeliveredTypeTwo(
                acceptedClientPreauthDiagnostics_))
        {
            retainedError =
                RuntimeHostError::AuthenticationIncompletePeerClosed;
        }

        if (acceptedClientId_ != 0U &&
            (error != RuntimeHostError::None ||
             diagnostics.termination !=
                 rdp_server::server::transport::TcpConnectionTermination::Open))
        {
            const auto fingerprint = tlsFingerprintText(
                diagnostics.certificateSha256,
                diagnostics.certificateFingerprintAvailable);
            const std::string selectedEndpoint =
                boundEndpointText(listener_.boundEndpoint());
            const char *const selectedCertificateCheck =
                !diagnostics.selectedCertificateIdentityChecked
                    ? "not-run"
                    : diagnostics.selectedCertificateMatchesRuntimeIdentity
                        ? "match"
                        : "mismatch";
            const auto admissionReason =
                runtimeAcceptedClientAdmissionFailureReasonName(
                    acceptedClientPreauthDiagnostics_.admissionFailureReason);
            const auto preType3Termination =
                runtimeAcceptedClientPreType3TerminationName(
                    acceptedClientPreauthDiagnostics_.preType3Termination);
            const auto clientTargetClass =
                runtimeConnectionTargetClassName(
                    acceptedClientPreauthDiagnostics_.clientTargetClass);
            const auto serviceClass =
                runtimeConnectionServiceClassName(
                    acceptedClientPreauthDiagnostics_.serviceClass);
            const auto serviceIdentityProfile =
                runtimeServiceIdentityProfileName(
                    acceptedClientPreauthDiagnostics_.serviceIdentityProfile);
            const bool directNtlmTypeOneReceived =
                directNtlmTypeOneWasReceived(acceptedClientPreauthDiagnostics_);
            const bool directNtlmTypeThreeReceived =
                directNtlmTypeThreeWasReceived(acceptedClientPreauthDiagnostics_);
            const bool directNtlmAwaitTypeThreeReached =
                directNtlmTypeOneReceived &&
                acceptedClientPreauthDiagnostics_.directNtlmTypeTwoDelivered;
            const char *const directNtlmTypeTwoState =
                acceptedClientPreauthDiagnostics_.directNtlmTypeTwoDelivered
                    ? "delivered"
                    : acceptedClientPreauthDiagnostics_.directNtlmTypeTwoQueued
                        ? "queued"
                        : "none";
            const auto &ntlmChallenge = diagnostics.standaloneNtlmChallenge;
            std::array<char, 128> ntlmAvIdStorage{};
            const std::string_view ntlmAvIds =
                ntlmChallengeAvIdsText(ntlmChallenge, ntlmAvIdStorage);
            const std::string_view tlsCipherSuite = boundedTlsDiagnosticText(
                diagnostics.negotiatedTlsCipherSuite,
                diagnostics.negotiatedTlsCipherSuiteBytes, "unavailable");
            const std::string_view certificateCommonName =
                boundedTlsDiagnosticText(
                    diagnostics.certificateSubjectCommonName,
                    diagnostics.certificateSubjectCommonNameBytes,
                    diagnostics.certificateSubjectCommonNameClass ==
                            LinuxRuntimeTlsCertificateCommonNameClass::Redacted
                        ? "redacted"
                        : "unavailable");

            // One bounded fail-only record. Never add credentials, hashes,
            // NTLM/TSRequest bytes, TLS secrets or certificate private data.
            std::fprintf(
                stderr,
                "rdp-server: connection terminal: connection=%llu endpoint=%s "
                "protocol-stage=%s authentication-stage=%s admission=%.*s "
                "client-target-class=%.*s service-class=%.*s "
                "service-identity-profile=%.*s target-start-generation=%llu "
                "direct-ntlm-type1=%s direct-ntlm-type2-queued=%s "
                "direct-ntlm-type2=%s direct-ntlm-type2-tls=%s "
                "type2-creation-to-delivery-us=%llu "
                "type2-creation-to-delivery-available=%s "
                "direct-ntlm-await-type3=%s direct-ntlm-type3=%s "
                "pre-type3-termination=%.*s "
                "preauth-peer-eof-elapsed-us=%llu "
                "preauth-peer-eof-elapsed-available=%s "
                "type2-to-peer-eof-us=%llu "
                "type2-to-peer-eof-available=%s "
                "post-type2-client-data=%s "
                "post-type2-first-client-data-us=%llu "
                "post-type2-first-client-data-available=%s "
                "post-type2-complete-tsrequest-count=%llu "
                "post-type2-plaintext-bytes=%llu "
                "ntlm-type1-flags=0x%08x ntlm-version-present=%s "
                "ntlm-version=%u.%u.%u ntlm-revision=0x%02x "
                "ntlm-type2-flags=0x%08x "
                "ntlm-target-name-code-units=%zu ntlm-target-info-bytes=%zu "
                "ntlm-type2-bytes=%zu ntlm-av-ids=%.*s "
                "ntlm-server-target=%s ntlm-target-name-present=%s "
                "tls-version=%s tls-cipher-id=0x%04x tls-cipher=%.*s "
                "client-sni=%s client-sni-class=%s "
                "cert-cn-class=%s cert-cn=%.*s cert-san-ip=%s cert-san-dns=%s "
                "certificate-profile=%.*s certificate-generation=%llu "
                "fingerprint=%s "
                "ip-self-check=%s selected-cert=%s handshake-step=%llu "
                "handshake-result=%s ssl-error=%d openssl-reason=%u "
                "termination=%s host-error=%u\n",
                static_cast<unsigned long long>(acceptedClientId_),
                selectedEndpoint.empty() ? "unavailable"
                                         : selectedEndpoint.c_str(),
                protocolDiagnosticName(
                    acceptedClientPreauthDiagnostics_.protocolStage),
                authenticationDiagnosticStageName(
                    acceptedClientPreauthDiagnostics_),
                static_cast<int>(admissionReason.size()),
                admissionReason.data(),
                static_cast<int>(clientTargetClass.size()),
                clientTargetClass.data(),
                static_cast<int>(serviceClass.size()),
                serviceClass.data(),
                static_cast<int>(serviceIdentityProfile.size()),
                serviceIdentityProfile.data(),
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .connectionTargetGeneration),
                directNtlmTypeOneReceived ? "received" : "not-received",
                acceptedClientPreauthDiagnostics_.directNtlmTypeTwoQueued
                    ? "yes" : "no",
                directNtlmTypeTwoState,
                acceptedClientPreauthDiagnostics_.directNtlmTypeTwoDelivered
                    ? "committed" : "not-committed",
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .directNtlmTypeTwoCreationToDeliveryMicroseconds),
                acceptedClientPreauthDiagnostics_
                        .directNtlmTypeTwoCreationToDeliveryAgeAvailable
                    ? "yes" : "no",
                directNtlmAwaitTypeThreeReached ? "reached" : "not-reached",
                directNtlmTypeThreeReceived ? "received" : "not-received",
                static_cast<int>(preType3Termination.size()),
                preType3Termination.data(),
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .preauthElapsedAtPeerEofMicroseconds),
                acceptedClientPreauthDiagnostics_.preauthElapsedAtPeerEofAvailable
                    ? "yes" : "no",
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .directNtlmTypeTwoToPeerEofMicroseconds),
                acceptedClientPreauthDiagnostics_
                        .directNtlmTypeTwoToPeerEofAvailable
                    ? "yes" : "no",
                acceptedClientPreauthDiagnostics_
                        .postTypeTwoFirstClientTlsByteAvailable
                    ? "yes" : "no",
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .postTypeTwoFirstClientTlsByteMicroseconds),
                acceptedClientPreauthDiagnostics_
                        .postTypeTwoFirstClientTlsByteAvailable
                    ? "yes" : "no",
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .postTypeTwoCompleteTsRequestCount),
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .postTypeTwoPlaintextBytes),
                static_cast<unsigned int>(
                    ntlmChallenge.clientNegotiateFlags),
                acceptedClientPreauthDiagnostics_.ntlmTypeOne.versionPresent
                    ? "yes" : "no",
                static_cast<unsigned int>(
                    acceptedClientPreauthDiagnostics_.ntlmTypeOne.majorVersion),
                static_cast<unsigned int>(
                    acceptedClientPreauthDiagnostics_.ntlmTypeOne.minorVersion),
                static_cast<unsigned int>(
                    acceptedClientPreauthDiagnostics_.ntlmTypeOne.buildNumber),
                static_cast<unsigned int>(
                    acceptedClientPreauthDiagnostics_.ntlmTypeOne.ntlmRevision),
                static_cast<unsigned int>(ntlmChallenge.negotiateFlags),
                ntlmChallenge.targetNameCodeUnits,
                ntlmChallenge.targetInfoBytes,
                ntlmChallenge.totalBytes,
                static_cast<int>(ntlmAvIds.size()), ntlmAvIds.data(),
                ntlmChallenge.targetTypeServer ? "yes" : "no",
                ntlmChallenge.targetNamePresent ? "yes" : "no",
                tlsProtocolVersionName(diagnostics.negotiatedTlsProtocolVersion),
                static_cast<unsigned int>(
                    acceptedClientPreauthDiagnostics_
                        .tlsConnection.cipherProtocolId),
                static_cast<int>(tlsCipherSuite.size()), tlsCipherSuite.data(),
                acceptedClientPreauthDiagnostics_.tlsConnection.sniClass ==
                        RuntimeAcceptedClientTlsSniClass::None
                    ? "absent" : "present",
                runtimeAcceptedClientTlsSniClassName(
                    acceptedClientPreauthDiagnostics_
                        .tlsConnection.sniClass).data(),
                tlsCertificateCommonNameClassName(
                    diagnostics.certificateSubjectCommonNameClass),
                static_cast<int>(certificateCommonName.size()),
                certificateCommonName.data(),
                diagnostics.certificateSanIpPresent ? "yes" : "no",
                diagnostics.certificateSanDnsPresent ? "yes" : "no",
                static_cast<int>(
                    runtimeTlsCertificateProfileName(
                        acceptedClientPreauthDiagnostics_
                            .tlsConnection.certificateProfile).size()),
                runtimeTlsCertificateProfileName(
                    acceptedClientPreauthDiagnostics_
                        .tlsConnection.certificateProfile).data(),
                static_cast<unsigned long long>(
                    acceptedClientPreauthDiagnostics_
                        .tlsConnection.certificateEndpointGeneration),
                fingerprint.data(),
                endpointIdentityStatusName(
                    diagnostics.certificateExactIpSelfCheck),
                selectedCertificateCheck,
                static_cast<unsigned long long>(
                    diagnostics.tlsHandshake.step),
                tlsHandshakeResultName(
                    diagnostics.tlsHandshake.resultClass),
                diagnostics.tlsHandshake.sslError,
                diagnostics.tlsHandshake.opensslReason,
                terminationName(diagnostics.termination),
                static_cast<unsigned int>(retainedError));
        }
        acceptedClient_->revoke();
    }
    clearAcceptedClient();
    clientDisconnected_ = hadAcceptedClient && listener_.valid();
    stage_ = listener_.valid()
        ? RuntimeHostStage::ListenerAvailable
        : RuntimeHostStage::Stopped;
    lastError_ = retainedError;
}

RuntimeHostResult LinuxRuntimeHostControl::pollAcceptedClientReadiness() noexcept
{
    if (acceptedClient_ == nullptr)
        return deny(RuntimeHostError::ClientNotFound);

    const auto ready = acceptedClient_->pollSocketReadinessOnce(
        acceptedClientDeadline_, std::chrono::milliseconds{0});
    using PollStatus = LinuxRuntimeSocketPollStatus;
    switch (ready.status)
    {
    case PollStatus::Ready:
        acceptedClientReadable_ = ready.readable;
        acceptedClientWritable_ = ready.writable;
        return {RuntimeHostError::None, false};
    case PollStatus::NoEvent:
        return {RuntimeHostError::None, true};
    case PollStatus::Expired:
    case PollStatus::Closed:
    case PollStatus::Failure:
        retireAcceptedClient(RuntimeHostError::AuthenticationRejected);
        return {lastError_, false};
    }
    retireAcceptedClient(RuntimeHostError::InternalFailure);
    return {RuntimeHostError::InternalFailure, false};
}

RuntimeHostResult LinuxRuntimeHostControl::acceptClientOnce(
    std::chrono::steady_clock::time_point now) noexcept
{
    using namespace rdp_server::server::transport;
    if (acceptedClient_ != nullptr || !listener_.valid() ||
        securityConfiguration_ == nullptr || tlsContext_ == nullptr ||
        admissionConfiguration_ == nullptr || licensingContext_ == nullptr ||
        !deploymentPolicy_.has_value())
        return deny(RuntimeHostError::InvalidConfiguration);

    auto accepted =
        acceptNonblockingTcpConnection(listener_.nativeSocket());
    if (accepted.outcome == TcpAcceptOutcome::WouldBlock)
        return {RuntimeHostError::None, true};
    if (accepted.outcome != TcpAcceptOutcome::Accepted ||
        !accepted.connection.valid())
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::InternalFailure;
        return {lastError_, false};
    }

    const TcpPeerEndpoint peer = accepted.connection.peerEndpoint();
    std::span<const std::uint8_t> peerAddress;
    if (peer.family == TcpPeerAddressFamily::Ipv4)
        peerAddress = std::span<const std::uint8_t>{peer.address}.first(4U);
    else if (peer.family == TcpPeerAddressFamily::Ipv6)
        peerAddress = std::span<const std::uint8_t>{peer.address};
    else
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::ListenerPolicyDenied;
        return {lastError_, false};
    }

    if (!deploymentPolicy_->permitsPrivateLanTransportCandidate(peerAddress))
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::ListenerPolicyDenied;
        return {lastError_, false};
    }

    if (!authAttempts_.reservePeerAuthenticationAttempt(peerAddress, now))
    {
        lastError_ = RuntimeHostError::AuthenticationRateLimited;
        return {lastError_, true};
    }

    if (nextClientId_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::InternalFailure;
        return {lastError_, false};
    }

    LinuxRuntimeAuthenticationSelection authenticationSelection{};
    if (!buildAuthenticationSelection(authenticationSelection))
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                CredentialChange);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::CredentialNotConfigured;
        return {lastError_, false};
    }

    auto connection = std::make_unique<LinuxRuntimeConnection>(
        *securityConfiguration_, std::move(accepted.connection),
        &authAttempts_, &ownerSharingAuthority_, authenticationSelection);
    if (!connection->ready())
    {
        lastError_ = RuntimeHostError::AuthenticationRejected;
        return {lastError_, false};
    }

    connection->configureTlsIdentityDiagnostics(
        *tlsContext_, selection_.localAddress);
    acceptedClient_ = std::move(connection);
    acceptedClientPreauthDiagnostics_ =
        projectLinuxAcceptedClientPreauthDiagnostics(
            acceptedClient_->acceptanceDiagnostics());
    applyConnectionTargetDiagnostics(
        acceptedClientPreauthDiagnostics_);
    applyConnectionCertificateDiagnostics(
        acceptedClientPreauthDiagnostics_);
    acceptedClientDeadline_ = now + acceptedClientPreauthTimeout_;
    acceptedClientPhase_ = AcceptedClientPhase::PreAdmission;
    acceptedClientId_ = nextClientId_++;
    acceptedClientPeer_ = boundEndpointText(peer);
    acceptedClientReadable_ = false;
    acceptedClientWritable_ = false;
    clientDisconnected_ = false;
    stage_ = RuntimeHostStage::ClientAuthenticating;
    lastError_ = RuntimeHostError::None;
    return {RuntimeHostError::None, false};
}

RuntimeHostResult LinuxRuntimeHostControl::advanceAcceptedClientOnce() noexcept
{
    if (acceptedClient_ == nullptr || !acceptedClient_->ready() ||
        !deploymentPolicy_.has_value() || securityConfiguration_ == nullptr ||
        tlsContext_ == nullptr || admissionConfiguration_ == nullptr ||
        licensingContext_ == nullptr)
    {
        retireAcceptedClient(RuntimeHostError::AuthenticationRejected);
        return {lastError_, false};
    }

    const bool readable = std::exchange(acceptedClientReadable_, false);
    const bool writable = std::exchange(acceptedClientWritable_, false);

    const auto hostSessionStale = [this]() noexcept {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::HostSessionStale;
        return RuntimeHostResult{lastError_, false};
    };
    const auto peerFailure = [this](RuntimeHostError error) noexcept {
        retireAcceptedClient(error);
        return RuntimeHostResult{lastError_, false};
    };
    const auto admissionRequest = [this]() noexcept
        -> std::optional<
            rdp_server::server::security::ConsoleEvidenceRequest> {
        if (securityConfiguration_ == nullptr ||
            admissionConfiguration_ == nullptr)
        {
            return std::nullopt;
        }

        using Kind =
            rdp_server::server::security::ConsoleEvidenceAuthenticationKind;
        Kind authenticationKind{};
        switch (authenticationMode_)
        {
        case ConfiguredAuthenticationMode::ExistingOsAccount:
            authenticationKind = Kind::KerberosPrincipal;
            break;
        case ConfiguredAuthenticationMode::StandalonePassword:
            if (!selectedStandaloneCredentialReady())
                return std::nullopt;
            authenticationKind = Kind::StandalonePassword;
            break;
        case ConfiguredAuthenticationMode::Unconfigured:
            return std::nullopt;
        }
        return admissionConfiguration_->request(
            *securityConfiguration_, authenticationKind);
    };

    switch (acceptedClientPhase_)
    {
    case AcceptedClientPhase::None:
        return peerFailure(RuntimeHostError::ClientNotFound);

    case AcceptedClientPhase::PreAdmission:
    {
        const auto step = acceptedClient_->advancePreAdmission(
            readable, writable, *tlsContext_);
        using Step = LinuxPreAdmissionStepStatus;
        switch (step.status)
        {
        case Step::Progress:
        case Step::TlsEstablished:
        case Step::BindingVerified:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::CredentialsVerified:
        {
            const auto request = admissionRequest();
            if (!request)
                return hostSessionStale();
            if (!acceptedClient_->issueAdmission(*request))
            {
                if (!ownerSharingAuthority_.authorizes(
                        rdp_server::server::security::
                            kConsoleViewPermission))
                    return hostSessionStale();
                return peerFailure(RuntimeHostError::AuthenticationRejected);
            }
            acceptedClientPhase_ = AcceptedClientPhase::McsConnectInitial;
            return {RuntimeHostError::None, false};
        }
        case Step::UnsupportedFinalCredentials:
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsConnectInitial:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsConnectInitial(
                readable, writable);
        using Step = LinuxPostAdmissionMcsStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::AdmittedConnectInitial:
            acceptedClientPhase_ = AcceptedClientPhase::McsConnectResponse;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsConnectResponse:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsConnectResponseWrite(
                readable, writable);
        using Step = LinuxPostAdmissionMcsResponseStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
            acceptedClientPhase_ = AcceptedClientPhase::McsErectDomain;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsErectDomain:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsErectDomain(
                readable, writable);
        using Step = LinuxPostAdmissionMcsErectStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::ErectDomainAccepted:
            acceptedClientPhase_ = AcceptedClientPhase::McsAttachUser;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsAttachUser:
    {
        const auto step = acceptedClient_->advancePostAdmissionMcsAttachUser(
            *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsAttachStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::AttachUserAccepted:
            acceptedClientPhase_ = AcceptedClientPhase::McsAttachConfirm;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsAttachConfirm:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsAttachConfirmWrite(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsAttachConfirmStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
            acceptedClientPhase_ = AcceptedClientPhase::McsChannelJoins;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::McsChannelJoins:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsChannelJoins(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsChannelJoinStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::AllChannelsJoined:
            acceptedClientPhase_ = AcceptedClientPhase::ClientInfo;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::ClientInfo:
    {
        const auto step =
            acceptedClient_->advancePostAdmissionMcsClientInfo(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPostAdmissionMcsClientInfoStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::ClientInfoAccepted:
            if (!acceptedClient_->selectPersonalDesktopLicensingMode(
                    *deploymentPolicy_))
                return peerFailure(
                    RuntimeHostError::ShareActivationUnavailable);
            acceptedClientPhase_ = AcceptedClientPhase::LicenseRequest;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::AuthenticationRejected);
        }
        break;
    }

    case AcceptedClientPhase::LicenseRequest:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopServerLicenseRequestWrite(
                *deploymentPolicy_, *licensingContext_,
                readable, writable);
        using Step = LinuxPersonalDesktopLicenseWriteStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
            acceptedClientPhase_ = AcceptedClientPhase::ClientLicensing;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::ClientLicensing:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopClientLicensingIntake(
                *deploymentPolicy_, *licensingContext_,
                readable, writable);
        using Step = LinuxPersonalDesktopClientLicensingStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::ClientLicenseInfoAccepted:
        case Step::ClientNewLicenseRequestAccepted:
            acceptedClientPhase_ = AcceptedClientPhase::ValidClient;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::ValidClient:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopValidClientWrite(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPersonalDesktopValidClientWriteStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Delivered:
        {
            const auto request = admissionRequest();
            if (!request)
                return hostSessionStale();

            using Feature =
                rdp_server::server::transport::RdpDemandActiveFeature;
            auto features = Feature::DynamicVirtualChannels;
            if ((request->requestedPermissions &
                 rdp_server::server::security::
                    kConsoleInputPermission) != 0U)
                features = features | Feature::SlowPathInput;

            const auto profile =
                acceptedClient_->preparePersonalDesktopDemandActiveProfile(
                    *deploymentPolicy_, features);
            if (!profile ||
                !acceptedClient_->startPersonalDesktopShareActivation(
                    *deploymentPolicy_, *profile))
                return peerFailure(
                    RuntimeHostError::ShareActivationUnavailable);

            acceptedClientPhase_ = AcceptedClientPhase::ShareActivation;
            return {RuntimeHostError::None, false};
        }
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::ShareActivation:
    {
        const auto step =
            acceptedClient_->advancePersonalDesktopShareActivation(
                *deploymentPolicy_, readable, writable);
        using Step = LinuxPersonalDesktopShareActivationStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Activated:
            stage_ = RuntimeHostStage::ShareActivated;
            if (!acceptedClient_->
                    startPersonalDesktopGraphicsDynamicVirtualChannel(
                        *deploymentPolicy_))
                return peerFailure(RuntimeHostError::GraphicsUnavailable);
            acceptedClientPhase_ = AcceptedClientPhase::GraphicsControl;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(
                RuntimeHostError::ShareActivationUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::GraphicsControl:
    {
        const auto step =
            acceptedClient_->
                advancePersonalDesktopGraphicsDynamicVirtualChannel(
                    *deploymentPolicy_, readable, writable);
        using Step = LinuxPersonalDesktopGraphicsDvcStepStatus;
        switch (step.status)
        {
        case Step::Progress:
            return {RuntimeHostError::None, false};
        case Step::NeedRead:
        case Step::NeedWrite:
            return pollAcceptedClientReadiness();
        case Step::Ready:
            if (!acceptedClient_->authorizePersonalDesktopApplicationTraffic(
                    *deploymentPolicy_))
                return hostSessionStale();
            acceptedClientPhase_ = AcceptedClientPhase::GraphicsReady;
            stage_ = RuntimeHostStage::ShareActivated;
            lastError_ = RuntimeHostError::None;
            return {RuntimeHostError::None, false};
        case Step::AdmissionDenied:
            return hostSessionStale();
        case Step::Invalid:
        case Step::Closed:
            return peerFailure(RuntimeHostError::GraphicsUnavailable);
        }
        break;
    }

    case AcceptedClientPhase::GraphicsReady:
        if (!acceptedClient_->authorizePersonalDesktopApplicationTraffic(
                *deploymentPolicy_))
            return hostSessionStale();
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
        if (nativeDesktop_ == nullptr)
            return initializeNativeDesktop();
        return serviceNativeDesktopOnce();
#else
        return peerFailure(RuntimeHostError::GraphicsUnavailable);
#endif
    }

    return peerFailure(RuntimeHostError::InternalFailure);
}
#endif

RuntimeHostResult LinuxRuntimeHostControl::serviceOnce() noexcept
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    if (stage_ == RuntimeHostStage::Revoked)
        return {RuntimeHostError::AccessRevoked, false};
#if !defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    return {RuntimeHostError::CredentialProviderUnavailable, false};
#else
    if (authenticationMode_ ==
            ConfiguredAuthenticationMode::StandalonePassword &&
        selectedStandaloneCredentialReady())
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
            return {lastError_, false};
        }
    }

    if (!listener_.valid())
        return {RuntimeHostError::None, true};
    if (!listener_.interfaceStillMatches())
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::InterfaceUnavailable;
        return {lastError_, false};
    }
    if (!ownerSharingAuthority_.authorizes(
            rdp_server::server::security::kConsoleViewPermission))
    {
        retireStoppedRuntime(
            rdp_server::server::security::OwnerConsentRevocationReason::
                NativeAuthorizationLost);
        stage_ = RuntimeHostStage::Revoked;
        lastError_ = RuntimeHostError::HostSessionStale;
        return {lastError_, false};
    }

    if (acceptedClient_ == nullptr)
        return acceptClientOnce(std::chrono::steady_clock::now());
    return advanceAcceptedClientOnce();
#endif
}

void LinuxRuntimeHostControl::retireStoppedRuntime(
    rdp_server::server::security::OwnerConsentRevocationReason reason,
    StoppedRuntimeCredentialPolicy credentialPolicy) noexcept
{
    // Security-significant host teardown order: invalidate host-owner R2
    // first, then retire the accepted R3/R2/R1 aggregate, then close R1's
    // listener. No accepted TLS/socket or later native owner may outlive Stop.
    // Credential lifetime is explicit: ordinary Stop opts into preservation;
    // terminal loss and destruction take the default revoke policy.
    ownerSharingAuthority_.revoke(reason);
    if (credentialPolicy == StoppedRuntimeCredentialPolicy::RevokeCredentials)
    {
        standalonePasswordCredential_.revoke();
        standaloneCredentialSessionBinding_.clear();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
        authenticationMode_ = ConfiguredAuthenticationMode::Unconfigured;
        standaloneCredentialGeneration_ = 0U;
        credentialsConfigured_ = false;
#endif
    }
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
    retireNativeDesktop();
#endif
    if (acceptedClient_ != nullptr)
    {
        acceptedClient_->revoke();
        acceptedClientPreauthDiagnostics_ =
            projectLinuxAcceptedClientPreauthDiagnostics(
                acceptedClient_->acceptanceDiagnostics());
        applyConnectionTargetDiagnostics(
            acceptedClientPreauthDiagnostics_);
        applyConnectionCertificateDiagnostics(
            acceptedClientPreauthDiagnostics_);
    }
    clearAcceptedClient();
    clientDisconnected_ = false;
#endif
    listener_.close();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    connectionTargetIdentity_ = {};
#endif
    // Generated key/certificate ownership is session preparation state, not a
    // process-global secret. Stop retires it after accepted TLS and listener.
    retireGeneratedTlsIdentity();
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    deploymentPolicy_.reset();
#endif
}
RuntimeHostResult LinuxRuntimeHostControl::stopSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::Stop,
        StoppedRuntimeCredentialPolicy::KeepCredentials);
    if (stage_ != RuntimeHostStage::Revoked)
    {
        stage_ = RuntimeHostStage::Stopped;
        lastError_ = RuntimeHostError::None;
    }
    return {RuntimeHostError::None, false};
}
RuntimeHostResult LinuxRuntimeHostControl::disconnectClient(
    std::uint64_t opaqueClientId)
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (opaqueClientId == 0U || acceptedClient_ == nullptr ||
        acceptedClientId_ != opaqueClientId)
        return deny(RuntimeHostError::ClientNotFound);

    retireAcceptedClient(RuntimeHostError::None);
    return {RuntimeHostError::None, false};
#else
    (void)opaqueClientId;
    return deny(RuntimeHostError::ClientNotFound);
#endif
}
RuntimeHostResult LinuxRuntimeHostControl::revokeSharing()
{
    if (!onOwnerThread())
        return {RuntimeHostError::ControlUnavailable, false};
    retireStoppedRuntime(
        rdp_server::server::security::OwnerConsentRevocationReason::
            NativeAuthorizationLost);
    selection_ = {};
    selectionConfigured_ = false;
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    authenticationMode_ = ConfiguredAuthenticationMode::Unconfigured;
    standaloneCredentialGeneration_ = 0U;
    credentialsConfigured_ = false;
#endif
    stage_ = RuntimeHostStage::Revoked;
    lastError_ = RuntimeHostError::AccessRevoked;
    return {RuntimeHostError::None, false};
}

} // namespace rdp_server::server::runtime
