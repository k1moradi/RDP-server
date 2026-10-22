// SPDX-License-Identifier: GPL-3.0-or-later
// R10 process entry point. Listener startup is explicit and loopback-only.
// TCP accept alone is never admission: only the serialized R1 TLS/CredSSP
// owner plus genuine R2 native authorization can cross that boundary.
// Offline configuration checks still do not authenticate or start a user.
#include "runtime_tls_context.h"
#include "runtime_configuration.h"
#include "runtime_licensing_context.h"
#if defined(RDP_SERVER_HAVE_PLATFORM_NATIVE_DESKTOP)
#include "runtime_platform_native_desktop.h"
#endif
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#include "linux_runtime_security.h"
#include "linux_runtime_connection.h"
#include "linux_serve_listener.h"
#include "runtime_deployment_policy.h"
#include "server/transport/nonblocking_tcp_adapter.h"
#include "server/security/authentication_attempt_limiter.h"
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
#include "x11/x11_desktop_resources.h"
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
#include "linux_prepared_clipboard_owner.h"
#endif
#if defined(RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT)
#include "x11/x11_authorized_input_route.h"
#endif
#endif
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <poll.h>
#include <signal.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <cstdint>
#endif

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#endif

#ifndef RDP_SERVER_VERSION
#error "The build system must provide the RDP server version"
#endif

namespace {
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
using rdp_server::server::runtime::LinuxListenerOwner;
using rdp_server::server::runtime::hasLinuxServeDescriptorBudget;
using rdp_server::server::runtime::openVerifiedLinuxLoopbackListener;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
using rdp_server::server::runtime::LinuxPreparedClipboardOwner;
#endif
#endif
constexpr int kSecureStartupUnavailableExitCode = 2;
constexpr int kInvalidConfigurationExitCode = 3;
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
constexpr std::chrono::seconds kLinuxSerializedConnectionDeadline{30};
// Bounded scheduler deadlines; no post-Share connection-idle timeout is
// fabricated. R2 native-session revocation and R1 EOF remain authoritative.
constexpr std::chrono::milliseconds kLinuxPostSharePollQuantum{25};
constexpr std::chrono::milliseconds kLinuxPostShareCaptureInterval{100};
constexpr std::chrono::seconds kLinuxPostShareResizeMaximumLifetime{6};

// The signal handler is scalar-only: no R1 TLS, R2 lease, R3 Share, R5 X11
// or allocation operation is permitted except on the serialized owner.
volatile std::sig_atomic_t gLinuxServeStopSignal = 0;
void recordLinuxServeTerminationSignal(int) noexcept {
    gLinuxServeStopSignal = 1;
}
[[nodiscard]] bool linuxServeStopRequested() noexcept {
    return gLinuxServeStopSignal != 0;
}
class ScopedLinuxServeTerminationHandlers final {
public:
    ScopedLinuxServeTerminationHandlers() noexcept {
        gLinuxServeStopSignal = 0;
        struct sigaction replacement {};
        replacement.sa_handler = &recordLinuxServeTerminationSignal;
        if (::sigemptyset(&replacement.sa_mask) != 0 ||
            ::sigaction(SIGINT, &replacement, &oldInterrupt_) != 0) {
            return;
        }
        if (::sigaction(SIGTERM, &replacement, &oldTerminate_) != 0) {
            (void)::sigaction(SIGINT, &oldInterrupt_, nullptr);
            return;
        }
        installed_ = true;
    }
    ScopedLinuxServeTerminationHandlers(
        const ScopedLinuxServeTerminationHandlers&) = delete;
    ScopedLinuxServeTerminationHandlers& operator=(
        const ScopedLinuxServeTerminationHandlers&) = delete;
    ~ScopedLinuxServeTerminationHandlers() noexcept {
        if (installed_) {
            (void)::sigaction(SIGTERM, &oldTerminate_, nullptr);
            (void)::sigaction(SIGINT, &oldInterrupt_, nullptr);
        }
    }
    [[nodiscard]] bool installed() const noexcept { return installed_; }
private:
    struct sigaction oldInterrupt_ {};
    struct sigaction oldTerminate_ {};
    bool installed_{};
};
#endif

#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
// R10's verified listener is now shared with a future in-process GUI
// controller; the existing CLI still owns exactly one local descriptor.
struct LinuxServeAcceptContext final {
    const rdp_server::server::runtime::RuntimeDeploymentPolicy* policy{};
    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration*
        securityConfiguration{};
    const rdp_server::server::runtime::RuntimeServerTlsContext* tlsContext{};
    const rdp_server::server::runtime::RuntimeLicensingContext*
        licensingContext{};
    const rdp_server::server::security::ConsoleEvidenceRequest*
        admissionRequest{};
    bool endpointViolation{};
    // One serialized, allocation-free service-lifetime R2 admission budget.
    rdp_server::server::security::AuthenticationAttemptLimiter authAttempts{};
};

#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
// Bound the sole XShm arena to 64 MiB at the supported four-byte BGRX layout.
// This is a resource ceiling only: it grants no native/session authority.
// Full-frame capture above this limit fails closed instead of allocating an
// unbounded client- or desktop-sized shared-memory segment.
constexpr std::uint64_t kMaximumSerializedX11CapturePixels =
    16U * 1024U * 1024U;

struct LinuxAuthorizedX11DesktopOwner final {
    std::optional<X11DesktopResources> desktop{};
    std::uint64_t admissionGeneration{};
    std::uint64_t sessionGeneration{};
};

[[nodiscard]] bool constructAuthorizedX11Desktop(
    const rdp_server::server::security::LinuxNativeDesktopSelectionView&
        selection,
    void* rawContext) noexcept {
    auto* context =
        static_cast<LinuxAuthorizedX11DesktopOwner*>(rawContext);
    if (context == nullptr || context->desktop.has_value() ||
        selection.display().empty() ||
        selection.admissionGeneration() == 0U ||
        selection.sessionGeneration() == 0U) {
        return false;
    }

    // The R2 visitor's display is the only native selector accepted here.
    // Never consult configured DISPLAY, environment variables or client data.
    context->desktop.emplace(
        selection.display(), kMaximumSerializedX11CapturePixels);
    if (!context->desktop->valid()) {
        context->desktop.reset();
        return false;
    }

    context->admissionGeneration = selection.admissionGeneration();
    context->sessionGeneration = selection.sessionGeneration();
    return true;
}


#endif

#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
// Borrowed R10 stack-only callbacks. The R2 lease, R3 route and R5 capture
// generation are rechecked synchronously; no callback survives this call.
struct LinuxPostShareDispatchContext final {
    rdp_server::server::runtime::LinuxRuntimeConnection* connection{};
    const rdp_server::server::runtime::RuntimeDeploymentPolicy* policy{};
    X11DesktopResources* desktop{};
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    LinuxPreparedClipboardOwner* clipboard{};
#endif
};

[[nodiscard]] bool dispatchLinuxPostShareRoute(
    void* rawContext,
    rdp_server::server::transport::RdpPostShareTpktRouteKind kind,
    std::span<const std::uint8_t> completeTpkt) noexcept {
    using Kind =
        rdp_server::server::transport::RdpPostShareTpktRouteKind;
    auto* context = static_cast<LinuxPostShareDispatchContext*>(rawContext);
    if (context == nullptr || context->connection == nullptr ||
        context->policy == nullptr || context->desktop == nullptr ||
        !context->desktop->valid() ||
        context->desktop->captureGeneration() == 0U) {
        return false;
    }
    switch (kind) {
    case Kind::GraphicsDynamicVirtualChannel:
        return context->connection->dispatchPersonalDesktopPostShareGraphicsTpkt(
            *context->policy, completeTpkt);
    case Kind::SlowPathInput:
#if defined(RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT)
        return X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt(
            *context->connection, *context->policy, *context->desktop,
            context->desktop->captureGeneration(), completeTpkt);
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

struct LinuxFramePublicationContext final {
    rdp_server::server::runtime::LinuxRuntimeConnection* connection{};
    const rdp_server::server::runtime::RuntimeDeploymentPolicy* policy{};
    std::uint32_t frameId{};
    std::uint64_t expectedGeneration{};
};

[[nodiscard]] bool publishLinuxCapturedFrame(
    void* rawContext, const FramebufferView& framebuffer,
    std::uint64_t captureGeneration) noexcept {
    auto* context = static_cast<LinuxFramePublicationContext*>(rawContext);
    return context != nullptr && context->connection != nullptr &&
           context->policy != nullptr && context->frameId != 0U &&
           captureGeneration == context->expectedGeneration &&
           context->connection->startPersonalDesktopClearCodecFramePublication(
               *context->policy, context->frameId, framebuffer);
}
#endif

[[nodiscard]] bool runSerializedLinuxCandidate(
    rdp_server::server::transport::OwnedNativeTcpSocket accepted,
    void* rawContext) noexcept {
    using PollStatus =
        rdp_server::server::runtime::LinuxRuntimeSocketPollStatus;
    using PreStep =
        rdp_server::server::runtime::LinuxPreAdmissionStepStatus;
    using McsStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsStepStatus;
    using ResponseStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsResponseStepStatus;
    using ErectStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsErectStepStatus;
    using LicenseWriteStep =
        rdp_server::server::runtime::LinuxPersonalDesktopLicenseWriteStepStatus;
    using ClientLicenseStep =
        rdp_server::server::runtime::
            LinuxPersonalDesktopClientLicensingStepStatus;
    using ValidClientStep =
        rdp_server::server::runtime::
            LinuxPersonalDesktopValidClientWriteStepStatus;
    using ShareStep =
        rdp_server::server::runtime::
            LinuxPersonalDesktopShareActivationStepStatus;
    using GraphicsStep =
        rdp_server::server::runtime::
            LinuxPersonalDesktopGraphicsDvcStepStatus;

    auto* context = static_cast<LinuxServeAcceptContext*>(rawContext);
    if (context == nullptr || context->policy == nullptr ||
        context->securityConfiguration == nullptr ||
        context->tlsContext == nullptr || context->licensingContext == nullptr ||
        context->admissionRequest == nullptr || !accepted.valid() ||
        linuxServeStopRequested()) {
        return false;
    }

    const auto peer = accepted.peerEndpoint();
    std::span<const std::uint8_t> peerAddress;
    if (peer.family ==
        rdp_server::server::transport::TcpPeerAddressFamily::Ipv4) {
        peerAddress = std::span<const std::uint8_t>{peer.address}.first(4U);
    } else if (
        peer.family ==
        rdp_server::server::transport::TcpPeerAddressFamily::Ipv6) {
        peerAddress = std::span<const std::uint8_t>{peer.address};
    } else {
        context->endpointViolation = true;
        return false;
    }

    if (!context->policy->permitsLoopbackTransportCandidate(peerAddress)) {
        context->endpointViolation = true;
        return false;
    }

    // Reserve a service-wide peer/global NLA attempt BEFORE creating TLS/GSS.
    // The rejected socket is closed by its RAII owner without an identifying
    // diagnostic or an R2 admission lease. This does not prove credentials.
    if (!context->authAttempts.reservePeerAuthenticationAttempt(
            peerAddress, std::chrono::steady_clock::now())) {
        return true;
    }

    rdp_server::server::runtime::LinuxRuntimeConnection connection{
        *context->securityConfiguration, std::move(accepted),
        &context->authAttempts};
    if (!connection.ready()) {
        return true;
    }

    const auto deadline =
        std::chrono::steady_clock::now() +
        kLinuxSerializedConnectionDeadline;
    bool readable = false;
    bool writable = false;
    bool admitted = false;

    while (connection.ready() && !admitted &&
           !linuxServeStopRequested()) {
        const auto step = connection.advancePreAdmission(
            readable, writable, *context->tlsContext);
        readable = false;
        writable = false;

        switch (step.status) {
        case PreStep::Progress:
        case PreStep::TlsEstablished:
        case PreStep::BindingVerified:
            continue;
        case PreStep::CredentialsVerified:
            admitted = connection.issueAdmission(*context->admissionRequest);
            if (!admitted) {
                return true;
            }
            continue;
        case PreStep::NeedRead:
        case PreStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case PreStep::UnsupportedFinalCredentials:
        case PreStep::Invalid:
        case PreStep::Closed:
            return true;
        }
    }

    if (!admitted || !connection.hasAdmissionLease()) {
        return true;
    }

    readable = false;
    writable = false;
    bool acceptedConnectInitial = false;
    while (connection.ready() && !acceptedConnectInitial &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePostAdmissionMcsConnectInitial(
                readable, writable);
        readable = false;
        writable = false;

        switch (step.status) {
        case McsStep::Progress:
            continue;
        case McsStep::NeedRead:
        case McsStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case McsStep::AdmittedConnectInitial:
            acceptedConnectInitial = true;
            break;
        case McsStep::AdmissionDenied:
        case McsStep::Invalid:
        case McsStep::Closed:
            return true;
        }
    }
    if (!acceptedConnectInitial || !connection.hasAdmissionLease()) {
        return true;
    }

    // The R3 response writer owns all plaintext and reply/slice identities.
    // R1 alone performs SSL writes; R2 reauthorizes every accepted-byte
    // receipt before R3 commits progress.
    readable = false;
    writable = false;
    bool deliveredResponse = false;
    while (connection.ready() && !deliveredResponse &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePostAdmissionMcsConnectResponseWrite(
                readable, writable);
        readable = false;
        writable = false;

        switch (step.status) {
        case ResponseStep::Progress:
            continue;
        case ResponseStep::NeedRead:
        case ResponseStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ResponseStep::Delivered:
            deliveredResponse = true;
            break;
        case ResponseStep::AdmissionDenied:
        case ResponseStep::Invalid:
        case ResponseStep::Closed:
            return true;
        }
    }
    if (!deliveredResponse || !connection.hasAdmissionLease()) {
        return true;
    }

    // The next exact TLS TPKT is Erect Domain. No buffering of the following
    // Attach/User PDU is allowed, and only R2 can advance R3's phase.
    readable = false;
    writable = false;
    bool acceptedErectDomain = false;
    while (connection.ready() && !acceptedErectDomain &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePostAdmissionMcsErectDomain(
                readable, writable);
        readable = false;
        writable = false;

        switch (step.status) {
        case ErectStep::Progress:
            continue;
        case ErectStep::NeedRead:
        case ErectStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ErectStep::ErectDomainAccepted:
            acceptedErectDomain = true;
            break;
        case ErectStep::AdmissionDenied:
        case ErectStep::Invalid:
        case ErectStep::Closed:
            return true;
        }
    }
    if (!acceptedErectDomain || !connection.hasAdmissionLease()) {
        return true;
    }
    using AttachStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsAttachStepStatus;
    {
    // Attach User: only current R2/R3 authority may advance this stage.
    readable = false;
    writable = false;
    bool stageAccepted = false;
    while (connection.ready() && !stageAccepted &&
           !linuxServeStopRequested()) {
        const auto step = connection.advancePostAdmissionMcsAttachUser(
            *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case AttachStep::Progress:
            continue;
        case AttachStep::NeedRead:
        case AttachStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case AttachStep::AttachUserAccepted:
            stageAccepted = true;
            break;
        case AttachStep::AdmissionDenied:
        case AttachStep::Invalid:
        case AttachStep::Closed:
            return true;
        }
    }
    if (!stageAccepted || !connection.hasAdmissionLease()) {
        return true;
    }
    }
    using ConfirmStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsAttachConfirmStepStatus;
    // Attach User Confirm: only current R2/R3 authority may advance this stage.
    readable = false;
    writable = false;
    bool deliveredAttachConfirm = false;
    while (connection.ready() && !deliveredAttachConfirm &&
           !linuxServeStopRequested()) {
        const auto step = connection.advancePostAdmissionMcsAttachConfirmWrite(
            *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case ConfirmStep::Progress:
            continue;
        case ConfirmStep::NeedRead:
        case ConfirmStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ConfirmStep::Delivered:
            deliveredAttachConfirm = true;
            break;
        case ConfirmStep::AdmissionDenied:
        case ConfirmStep::Invalid:
        case ConfirmStep::Closed:
            return true;
        }
    }
    if (!deliveredAttachConfirm || !connection.hasAdmissionLease()) {
        return true;
    }

    // R3's private join gate owns the expected channels, reply correlation
    // and exact accepted plaintext receipts. Stop only after real joins.
    using JoinStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsChannelJoinStepStatus;
    readable = false;
    writable = false;
    bool allChannelsJoined = false;
    while (connection.ready() && !allChannelsJoined &&
           !linuxServeStopRequested()) {
        const auto step = connection.advancePostAdmissionMcsChannelJoins(
            *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case JoinStep::Progress:
            continue;
        case JoinStep::NeedRead:
        case JoinStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case JoinStep::AllChannelsJoined:
            allChannelsJoined = true;
            break;
        case JoinStep::AdmissionDenied:
        case JoinStep::Invalid:
        case JoinStep::Closed:
            return true;
        }
    }
    if (!allChannelsJoined || !connection.hasAdmissionLease()) {
        return true;
    }

    // Client Info is an actual protected client PDU, never fabricated by R10.
    // R2/R3 consume the full TPKT and keep sensitive strings private.
    using InfoStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsClientInfoStepStatus;
    readable = false;
    writable = false;
    bool clientInfoAccepted = false;
    while (connection.ready() && !clientInfoAccepted &&
           !linuxServeStopRequested()) {
        const auto step = connection.advancePostAdmissionMcsClientInfo(
            *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case InfoStep::Progress:
            continue;
        case InfoStep::NeedRead:
        case InfoStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case InfoStep::ClientInfoAccepted:
            clientInfoAccepted = true;
            break;
        case InfoStep::AdmissionDenied:
        case InfoStep::Invalid:
        case InfoStep::Closed:
            return true;
        }
    }
    if (!clientInfoAccepted || !connection.hasAdmissionLease() ||
        !connection.selectPersonalDesktopLicensingMode(*context->policy)) {
        return true;
    }

    // PersonalDesktop licensing is one existing R3 state machine: send the
    // real Server License Request through R1, consume one actual client
    // licensing packet through R2/R3, then publish STATUS_VALID_CLIENT.
    readable = false;
    writable = false;
    bool serverLicenseDelivered = false;
    while (connection.ready() && !serverLicenseDelivered &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePersonalDesktopServerLicenseRequestWrite(
                *context->policy, *context->licensingContext,
                readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case LicenseWriteStep::Progress:
            continue;
        case LicenseWriteStep::NeedRead:
        case LicenseWriteStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case LicenseWriteStep::Delivered:
            serverLicenseDelivered = true;
            break;
        case LicenseWriteStep::AdmissionDenied:
        case LicenseWriteStep::Invalid:
        case LicenseWriteStep::Closed:
            return true;
        }
    }
    if (!serverLicenseDelivered || !connection.hasAdmissionLease()) {
        return true;
    }

    readable = false;
    writable = false;
    bool clientLicensingAccepted = false;
    while (connection.ready() && !clientLicensingAccepted &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePersonalDesktopClientLicensingIntake(
                *context->policy, *context->licensingContext,
                readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case ClientLicenseStep::Progress:
            continue;
        case ClientLicenseStep::NeedRead:
        case ClientLicenseStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ClientLicenseStep::ClientLicenseInfoAccepted:
        case ClientLicenseStep::ClientNewLicenseRequestAccepted:
            clientLicensingAccepted = true;
            break;
        case ClientLicenseStep::AdmissionDenied:
        case ClientLicenseStep::Invalid:
        case ClientLicenseStep::Closed:
            return true;
        }
    }
    if (!clientLicensingAccepted || !connection.hasAdmissionLease()) {
        return true;
    }

    readable = false;
    writable = false;
    bool validClientDelivered = false;
    while (connection.ready() && !validClientDelivered &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePersonalDesktopValidClientWrite(
                *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case ValidClientStep::Progress:
            continue;
        case ValidClientStep::NeedRead:
        case ValidClientStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ValidClientStep::Delivered:
            validClientDelivered = true;
            break;
        case ValidClientStep::AdmissionDenied:
        case ValidClientStep::Invalid:
        case ValidClientStep::Closed:
            return true;
        }
    }
    if (!validClientDelivered || !connection.hasAdmissionLease()) {
        return true;
    }

    // R10 selects only implemented high-level features. R3 derives the
    // canonical Demand Active geometry from the admitted GCC Client Core and
    // owns every Share/session ID and capability byte. Graphics requires the
    // actually joined drdynvc route; input advertisement additionally requires
    // current R2 input permission and is revalidated again inside the broker.
    using DemandFeature =
        rdp_server::server::transport::RdpDemandActiveFeature;
    auto demandActiveFeatures = DemandFeature::DynamicVirtualChannels;
    if ((context->admissionRequest->requestedPermissions &
         rdp_server::server::security::kConsoleInputPermission) != 0U) {
        demandActiveFeatures =
            demandActiveFeatures | DemandFeature::SlowPathInput;
    }

    const auto demandActiveProfile =
        connection.preparePersonalDesktopDemandActiveProfile(
            *context->policy, demandActiveFeatures);
    if (!demandActiveProfile || !connection.hasAdmissionLease() ||
        !connection.startPersonalDesktopShareActivation(
            *context->policy, *demandActiveProfile)) {
        return true;
    }

    readable = false;
    writable = false;
    bool shareActivated = false;
    while (connection.ready() && !shareActivated &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePersonalDesktopShareActivation(
                *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case ShareStep::Progress:
            continue;
        case ShareStep::NeedRead:
        case ShareStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ShareStep::Activated:
            shareActivated = true;
            break;
        case ShareStep::AdmissionDenied:
        case ShareStep::Invalid:
        case ShareStep::Closed:
            return true;
        }
    }
    if (!shareActivated || !connection.hasAdmissionLease()) {
        return true;
    }

    // Share is now genuinely active. Continue on the same serialized owner
    // through the existing R3 DRDYNVC / Microsoft::Windows::RDS::Graphics
    // control transcript. This still publishes no desktop frame.
    if (!connection.startPersonalDesktopGraphicsDynamicVirtualChannel(
            *context->policy)) {
        return true;
    }

    readable = false;
    writable = false;
    bool graphicsControlReady = false;
    while (connection.ready() && !graphicsControlReady &&
           !linuxServeStopRequested()) {
        const auto step =
            connection.advancePersonalDesktopGraphicsDynamicVirtualChannel(
                *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case GraphicsStep::Progress:
            continue;
        case GraphicsStep::NeedRead:
        case GraphicsStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case GraphicsStep::Ready:
            graphicsControlReady = true;
            break;
        case GraphicsStep::AdmissionDenied:
        case GraphicsStep::Invalid:
        case GraphicsStep::Closed:
            return true;
        }
    }
    if (!graphicsControlReady || !connection.hasAdmissionLease() ||
        !connection.authorizePersonalDesktopApplicationTraffic(
            *context->policy)) {
        return true;
    }

    // DRDYNVC capabilities, Graphics CREATE and RDPGFX CAPS are now composed.
    // Next bind exactly one native owner from R2's synchronous selected-desktop
    // visitor. The owner never observes configured DISPLAY or client metadata.
#if defined(RDP_SERVER_HAVE_LINUX_X11_DESKTOP)
    LinuxAuthorizedX11DesktopOwner nativeOwner{};
    if (!connection.visitNativeDesktopSelection(
            &constructAuthorizedX11Desktop, &nativeOwner) ||
        !nativeOwner.desktop.has_value()) {
        return true;
    }

#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    LinuxPreparedClipboardOwner clipboardOwner{};
    if (!clipboardOwner.prepare(
            *nativeOwner.desktop, nativeOwner.admissionGeneration,
            nativeOwner.sessionGeneration)) {
        nativeOwner.desktop->retireAfterAuthorizationLoss();
        connection.revoke();
        return true;
    }
#endif

    // One persistent serialized owner for the admitted R1 TLS connection,
    // R2 lease/logind monitor, R3 Graphics presentation and R5 XCB desktop.
    // Native poll records borrow descriptors for exactly one bounded call;
    // none may outlive R2 or R5 or remain registered during callbacks.
    using Interest =
        rdp_server::server::transport::TcpConnectionIoInterest;
    using ReadStep =
        rdp_server::server::runtime::LinuxPostShareApplicationReadStatus;
    using FrameStep =
        rdp_server::server::runtime::LinuxPersonalDesktopGraphicsDvcStepStatus;
    using Clock = std::chrono::steady_clock;
    LinuxPostShareDispatchContext dispatchContext{
        &connection, context->policy, &*nativeOwner.desktop};
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
    dispatchContext.clipboard = &clipboardOwner;
#endif
    const rdp_server::server::runtime::LinuxPostShareTpktSink sink{
        &dispatchContext, &dispatchLinuxPostShareRoute};
    const auto retireNativeCandidate = [&]() noexcept {
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        clipboardOwner.retire();
#endif
        nativeOwner.desktop->retireAfterAuthorizationLoss();
        connection.revoke();
    };
    std::uint32_t nextFrameId = 1U;
    bool frameWritePending = false;
    bool nativeWorkMayRemain = true;
    std::optional<Clock::time_point> resizeDeadline{};
    auto nextCapture = Clock::now();
    while (connection.ready() && nativeOwner.desktop->valid()) {
        // Stop before another native operation; terminal cleanup never posts XTEST.
        if (linuxServeStopRequested()) {
            break;
        }
        if (!connection.authorizePersonalDesktopApplicationTraffic(
                *context->policy)) {
            break;
        }
        if (resizeDeadline && Clock::now() >= *resizeDeadline) {
            retireNativeCandidate();
            return true;
        }
        const int socketDescriptor = connection.nativeSocketPollDescriptor();
        const auto socketInterest = connection.ioInterest();
        if (socketDescriptor < 0 ||
            (socketInterest != Interest::Read &&
             socketInterest != Interest::Write)) {
            break;
        }
        const auto nativeChange = connection.registerNativeChange();
        if (!nativeChange) {
            break;
        }
        if (nativeChange->admissionGeneration != nativeOwner.admissionGeneration ||
            nativeChange->sessionGeneration != nativeOwner.sessionGeneration ||
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
            !clipboardOwner.generationsMatch(
                nativeChange->admissionGeneration,
                nativeChange->sessionGeneration) ||
#endif
            nativeChange->events >
                static_cast<int>((std::numeric_limits<short>::max)())) {
            // A borrowed descriptor has been registered but was never added
            // to poll: explicitly retire it before connection revocation.
            if (connection.unregisterNativeChange(*nativeChange)) {
                (void)connection.releaseNativeChangeWithoutDispatch(
                    *nativeChange);
            }
            break;
        }

        std::array<pollfd, 3U> nativePoll{{
            {nativeChange->descriptor,
             static_cast<short>(nativeChange->events), 0},
            {nativeOwner.desktop->fileDescriptor(), POLLIN, 0},
            {socketDescriptor,
             static_cast<short>(
                 socketInterest == Interest::Read ? POLLIN : POLLOUT), 0},
        }};
        const auto now = Clock::now();
        bool clipboardWritePending = false;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        clipboardWritePending = clipboardOwner.writePending();
#endif
        const bool outboundWritePending =
            frameWritePending || clipboardWritePending;
        const bool bufferedApplicationData = !outboundWritePending &&
            connection.bufferedTlsApplicationReadReady();
        // An outstanding TLS Graphics/clipboard write is not eligible for
        // capture: the expired capture deadline must never turn
        // WANT_READ/WANT_WRITE into a zero-timeout busy poll. Socket and
        // logind/X11 events still wake the sole serialized owner immediately.
        const auto untilCapture = !outboundWritePending && nextCapture > now
            ? std::chrono::duration_cast<std::chrono::milliseconds>(
                  nextCapture - now)
            : std::chrono::milliseconds{0};
        std::optional<std::chrono::milliseconds> untilResizeDeadline{};
        if (resizeDeadline) {
            untilResizeDeadline =
                *resizeDeadline > now
                    ? std::chrono::duration_cast<std::chrono::milliseconds>(
                          *resizeDeadline - now)
                    : std::chrono::milliseconds{0};
        }
        const auto wait =
            rdp_server::server::runtime::detail::selectLinuxPostSharePollWait(
                kLinuxPostSharePollQuantum, untilCapture,
                outboundWritePending, bufferedApplicationData,
                nativeWorkMayRemain,
                untilResizeDeadline);
        const int timeoutMilliseconds = static_cast<int>(wait.count());
        errno = 0;
        const int polled = ::poll(
            nativePoll.data(), static_cast<nfds_t>(nativePoll.size()),
            timeoutMilliseconds);
        const int pollError = errno;

        // The stack poll set is no longer live. Retire its exact borrowed
        // logind registration before R2, R3, X11 or TLS callbacks can revoke.
        const bool watcherReady = polled > 0 &&
            nativePoll[0].revents != 0;
        const short x11Events = nativePoll[1].revents;
        const short socketEvents = nativePoll[2].revents;
        if (!connection.unregisterNativeChange(*nativeChange)) {
            break;
        }
        if (watcherReady) {
            if ((nativePoll[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
                !connection.dispatchNativeChangeReady(*nativeChange)) {
                break;
            }
        } else if (!connection.releaseNativeChangeWithoutDispatch(
                       *nativeChange)) {
            break;
        }
        if ((polled < 0 && pollError != EINTR) ||
            (x11Events & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (socketEvents & (POLLERR | POLLNVAL)) != 0) {
            break;
        }
        if (polled < 0) {
            continue; // EINTR; no I/O or callbacks from stale poll results.
        }
        if (linuxServeStopRequested() || !connection.ready() ||
            !connection.authorizePersonalDesktopApplicationTraffic(
                *context->policy)) {
            break;
        }

        bool moreX11Events = false;
        X11EventSink* additionalEventSink = nullptr;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        additionalEventSink = clipboardOwner.eventSink();
#endif
        if (nativeOwner.desktop->processEvents(
                128U, &moreX11Events, (x11Events & POLLIN) != 0,
                additionalEventSink) != ConnectionStatus::Ok ||
            !nativeOwner.desktop->valid() ||
            nativeOwner.desktop->captureGeneration() == 0U) {
            break;
        }
        nativeWorkMayRemain = moreX11Events;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        if (!clipboardOwner.serviceNative(
                connection, *context->policy, Clock::now(),
                !frameWritePending)) {
            retireNativeCandidate();
            return true;
        }
#endif

        // A pending R3/R1 Graphics or clipboard write owns
        // WANT_READ/WANT_WRITE until its exact accepted-byte receipt finishes;
        // never reinterpret that WANT_READ as an application TPKT read.
        const bool socketReadable =
            (socketEvents & (POLLIN | POLLHUP)) != 0;
        const bool socketWritable =
            (socketEvents & (POLLOUT | POLLHUP)) != 0;
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        if (clipboardOwner.writePending()) {
            if (!clipboardOwner.advanceTlsWrite(
                    connection, *context->policy,
                    socketReadable, socketWritable)) {
                retireNativeCandidate();
                return true;
            }
        } else
#endif
        if (frameWritePending) {
            const auto written =
                connection.advancePersonalDesktopGraphicsDynamicVirtualChannel(
                    *context->policy, socketReadable, socketWritable);
            switch (written.status) {
            case FrameStep::Ready:
                frameWritePending = false;
                break;
            case FrameStep::Progress:
            case FrameStep::NeedRead:
            case FrameStep::NeedWrite:
                break;
            case FrameStep::AdmissionDenied:
            case FrameStep::Invalid:
            case FrameStep::Closed:
                retireNativeCandidate();
                return true;
            }
        } else {
            const auto read =
                connection.advancePersonalDesktopPostShareApplicationRead(
                    *context->policy, socketReadable, socketWritable, sink);
            switch (read.status) {
            case ReadStep::Progress:
            case ReadStep::Routed:
            case ReadStep::NeedRead:
            case ReadStep::NeedWrite:
                break;
            case ReadStep::AdmissionDenied:
            case ReadStep::Invalid:
            case ReadStep::Closed:
                retireNativeCandidate();
                return true;
            }
        }
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        if (!clipboardOwner.serviceAfterNetworkDispatch(
                connection, *context->policy, Clock::now()) ||
            (clipboardOwner.writePending() &&
             !clipboardOwner.advanceTlsWrite(
                 connection, *context->policy, false, false))) {
            retireNativeCandidate();
            return true;
        }
#endif
        if (linuxServeStopRequested() || !connection.ready() ||
            !connection.authorizePersonalDesktopApplicationTraffic(
                *context->policy)) {
            break;
        }

        // Geometry is reconciled before every eligible capture. The R5
        // observation is inert provenance only: R2 was freshly reauthorized
        // above, and R5 must still match the exact session/capture generation.
        // R3 owns DELETE/CREATE/MAP and R4 owns ACK membership; R10 owns only
        // the 100 ms retry cadence and the original six-second elapsed bound.
        const auto postIoNow = Clock::now();
        if (resizeDeadline && postIoNow >= *resizeDeadline) {
            retireNativeCandidate();
            return true;
        }
#if defined(RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD)
        if (clipboardOwner.writePending()) {
            continue;
        }
#endif
        if (!frameWritePending && postIoNow >= nextCapture) {
            const std::uint64_t currentNativeSessionGeneration =
                nativeChange->sessionGeneration;
            const X11NativeGeometryObservation geometry =
                nativeOwner.desktop->observeNativeGeometry(
                    currentNativeSessionGeneration);
            if (!geometry.valid() ||
                !nativeOwner.desktop->nativeGeometryIsCurrent(
                    geometry, currentNativeSessionGeneration)) {
                retireNativeCandidate();
                return true;
            }

            using Reconfiguration = rdp_server::server::transport::
                RdpGraphicsSurfaceReconfiguration;
            const auto reconfiguration =
                connection.beginPersonalDesktopGraphicsSurfaceReconfiguration(
                    *context->policy, geometry.pixelGeometry);
            switch (reconfiguration) {
            case Reconfiguration::Unchanged:
                // Only a fresh R3 equality decision ends the unresolved resize
                // lifetime. Completing an older MAP alone must not extend a
                // deadline when a newer RandR generation is already current.
                resizeDeadline.reset();
                break;
            case Reconfiguration::Deferred:
                if (!resizeDeadline) {
                    resizeDeadline =
                        postIoNow + kLinuxPostShareResizeMaximumLifetime;
                }
                nextCapture =
                    postIoNow + kLinuxPostShareCaptureInterval;
                continue; // Keep servicing R1 FRAME_ACK/client DATA.
            case Reconfiguration::Started:
                if (!resizeDeadline) {
                    resizeDeadline =
                        postIoNow + kLinuxPostShareResizeMaximumLifetime;
                }
                frameWritePending = true;
                nextCapture =
                    postIoNow + kLinuxPostShareCaptureInterval;
                continue; // Existing writer drains DELETE -> CREATE -> MAP.
            case Reconfiguration::Rejected:
                retireNativeCandidate();
                return true;
            }

            if (nextFrameId == 0U) {
                break; // Never wrap a live Graphics frame ID.
            }
            using Readiness = rdp_server::server::transport::
                RdpGraphicsFramePublicationReadiness;
            // R3/R4 owns outstanding ACK credit. Defer before XShm capture;
            // no frame ID, write reservation or native authority is consumed.
            const auto readiness =
                connection.preflightPersonalDesktopGraphicsFramePublication(
                    *context->policy, nextFrameId);
            if (readiness == Readiness::DeferredForFrameAcknowledge) {
                nextCapture =
                    Clock::now() + kLinuxPostShareCaptureInterval;
                continue; // Keep reading FRAME_ACK through the sole R1 owner.
            }
            if (readiness != Readiness::Ready ||
                !nativeOwner.desktop->nativeGeometryIsCurrent(
                    geometry, currentNativeSessionGeneration)) {
                retireNativeCandidate();
                return true;
            }
            LinuxFramePublicationContext frameContext{
                &connection, context->policy, nextFrameId,
                geometry.captureGeneration};
            if (!nativeOwner.desktop->consumeR4Frame(
                    geometry, currentNativeSessionGeneration,
                    X11R4BgraFrameConsumer{
                        &frameContext, &publishLinuxCapturedFrame})) {
                break;
            }
            ++nextFrameId;
            frameWritePending = true;
            nextCapture = Clock::now() + kLinuxPostShareCaptureInterval;
        }
    }
    // Authorization may have expired inside a callback. Retire R8's native
    // selection/INCR/paste state before R5 and before a replacement client can
    // activate another R3 route. Do not post cleanup input after closure.
    retireNativeCandidate();
#else
    // Without the complete R5 X11 aggregate this build cannot publish a Linux
    // desktop even after genuine Share and Graphics control activation.
    connection.revoke();
#endif
    return true;
}

[[nodiscard]] bool runLinuxPersonalDesktopServe(
    const rdp_server::server::runtime::RuntimeConfigurationView&
        configuration) noexcept {
    using Field =
        rdp_server::server::runtime::RuntimeConfigurationField;
    unsigned parsedPort = 0U;
    unsigned maxConnections = 0U;
    if (!rdp_server::server::runtime::parseRuntimeConfigurationDecimal(
            configuration.field(Field::ListenPort),
            1U, 65535U, parsedPort) ||
        !rdp_server::server::runtime::parseRuntimeConfigurationDecimal(
            configuration.field(Field::MaxConnections),
            1U, 64U, maxConnections) ||
        maxConnections != 1U) {
        return false;
    }

    rdp_server::server::runtime::RuntimeDeploymentPolicy deploymentPolicy;
    if (!deploymentPolicy.configurePersonalDesktop(
            true, static_cast<std::uint16_t>(parsedPort))) {
        return false;
    }

    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration
        linuxSecurity;
    if (!rdp_server::server::runtime::
            configureLinuxRuntimeSecurityFromConfiguration(
                configuration, linuxSecurity)) {
        return false;
    }

    const auto tlsContext =
        rdp_server::server::runtime::RuntimeServerTlsContext::
            fromCredentialFiles(
                configuration.field(Field::TlsCertificate),
                configuration.field(Field::TlsPrivateKey));
    if (!tlsContext) {
        return false;
    }

    rdp_server::server::runtime::RuntimeLicensingContext licensingContext;
    if (!rdp_server::server::runtime::
            configureRuntimeLicensingContextFromConfiguration(
                configuration, licensingContext)) {
        return false;
    }

    rdp_server::server::runtime::LinuxRuntimeAdmissionConfiguration
        admissionConfiguration;
    if (!rdp_server::server::runtime::
            configureLinuxRuntimeAdmissionFromConfiguration(
                configuration, linuxSecurity, admissionConfiguration))
        return false;
    const auto request = admissionConfiguration.request(linuxSecurity);
    if (!request)
        return false;

    const auto preflight =
        linuxSecurity.preflightPersonalDesktopAdmission(
            deploymentPolicy, *request);
    if (!preflight.readyForAuthenticatedAdmissionAttempt() ||
        preflight.authenticatedAdmission ||
        !hasLinuxServeDescriptorBudget(maxConnections)) {
        return false;
    }

    const int listenerDescriptor = openVerifiedLinuxLoopbackListener(
        configuration.field(Field::ListenAddress),
        static_cast<std::uint16_t>(parsedPort));
    if (listenerDescriptor < 0) {
        return false;
    }
    LinuxListenerOwner listener{listenerDescriptor};
    // Only request Stop here; the one serialized connection/native owner
    // handles retirement after its next bounded readiness step.
    ScopedLinuxServeTerminationHandlers terminationHandlers;
    if (!terminationHandlers.installed()) {
        return false;
    }

    LinuxServeAcceptContext acceptContext{
        &deploymentPolicy, &linuxSecurity, &tlsContext, &licensingContext,
        &*request, false};
    using Clock = std::chrono::steady_clock;
    using namespace std::chrono_literals;
    while (!linuxServeStopRequested()) {
        const auto result =
            rdp_server::server::transport::pollNonblockingTcpAcceptBatch(
                static_cast<std::uintptr_t>(listener.descriptor()), 1U,
                runSerializedLinuxCandidate, &acceptContext,
                Clock::now() + 25ms, 25ms);
        if (acceptContext.endpointViolation) {
            return false;
        }

        using Outcome =
            rdp_server::server::transport::TcpListenerPollOutcome;
        switch (result.outcome) {
        case Outcome::NoEvent:
        case Outcome::Expired:
            break;
        case Outcome::BatchCompleted: {
            using Batch =
                rdp_server::server::transport::TcpAcceptBatchOutcome;
            if (result.batch.outcome == Batch::Drained ||
                result.batch.outcome == Batch::BudgetReached ||
                result.batch.outcome == Batch::WouldBlock) {
                break;
            }
            return false;
        }
        case Outcome::InvalidInput:
        case Outcome::Failure:
            return false;
        }
    }
    // The validated listener closes by RAII on controlled Stop.
    return true;
}
#endif

[[nodiscard]] constexpr
rdp_server::server::runtime::RuntimeConfigurationCapabilities
runtimeConfigurationCapabilities() noexcept
{
    rdp_server::server::runtime::RuntimeConfigurationCapabilities
        capabilities{};
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    capabilities.linuxSecurity = true;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    capabilities.linuxPam = true;
#endif
#endif
    return capabilities;
}

[[nodiscard]] bool checkLicensingConfiguration(
    const rdp_server::server::runtime::RuntimeConfigurationView&
        configuration) noexcept
{
    rdp_server::server::runtime::RuntimeLicensingContext licensingContext;
    return rdp_server::server::runtime::
        configureRuntimeLicensingContextFromConfiguration(
            configuration, licensingContext);
}

#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
[[nodiscard]] bool checkLinuxSecurityConfiguration(
    const rdp_server::server::runtime::RuntimeConfigurationView&
        configuration) noexcept
{
    using Field =
        rdp_server::server::runtime::RuntimeConfigurationField;
    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration
        linuxSecurity;
    if (!rdp_server::server::runtime::
            configureLinuxRuntimeSecurityFromConfiguration(
                configuration, linuxSecurity))
        return false;

    const auto tlsContext =
        rdp_server::server::runtime::RuntimeServerTlsContext::
            fromCredentialFiles(
                configuration.field(Field::TlsCertificate),
                configuration.field(Field::TlsPrivateKey));
    return tlsContext && linuxSecurity.policy() != nullptr;
}
#endif

// Configuration checks do not establish certificate trust, hostname,
// revocation, R2 admission or an R3 session decision. LinuxServe is the sole
// mode below allowed to bind/listen, and only after the genuine R2 preflight.
enum class ConfigurationCheckMode {
    Syntax,
    TlsMetadata,
    TlsCredentials,
    LicensingCredentials,
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    LinuxSecurity,
    LinuxServe,
#endif
};

struct ConfigurationCheckContext final
{
    ConfigurationCheckMode mode{ConfigurationCheckMode::Syntax};
};

[[nodiscard]] bool evaluateConfiguration(
    const rdp_server::server::runtime::RuntimeConfigurationView&
        configuration,
    void* rawContext) noexcept
{
    auto* context = static_cast<ConfigurationCheckContext*>(rawContext);
    if (context == nullptr)
        return false;

    using Field =
        rdp_server::server::runtime::RuntimeConfigurationField;
    switch (context->mode)
    {
    case ConfigurationCheckMode::Syntax:
        return true;
    case ConfigurationCheckMode::TlsMetadata:
        return rdp_server::server::runtime::validateTlsFileReferences(
            configuration.field(Field::TlsCertificate),
            configuration.field(Field::TlsPrivateKey));
    case ConfigurationCheckMode::TlsCredentials:
        return rdp_server::server::runtime::validateTlsCredentialContents(
            configuration.field(Field::TlsCertificate),
            configuration.field(Field::TlsPrivateKey));
    case ConfigurationCheckMode::LicensingCredentials:
        return checkLicensingConfiguration(configuration);
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    case ConfigurationCheckMode::LinuxSecurity:
        return checkLinuxSecurityConfiguration(configuration);
    case ConfigurationCheckMode::LinuxServe:
        return runLinuxPersonalDesktopServe(configuration);
#endif
    }
    return false;
}

[[nodiscard]] bool checkConfigurationFile(
    const char* path,
    ConfigurationCheckMode mode) noexcept
{
    ConfigurationCheckContext context{mode};
    return rdp_server::server::runtime::visitRuntimeConfigurationFile(
        path, runtimeConfigurationCapabilities(),
        &evaluateConfiguration, &context);
}

void printUsage() noexcept {
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    std::fputs("Usage: rdp-server [--help | --version | --check-config FILE | --check-tls-files FILE | --check-tls-credentials FILE | --check-licensing-credentials FILE | --check-linux-security FILE | serve --config FILE]\n"
               "--check-config validates syntax. --check-tls-files checks file metadata.\n"
               "--check-tls-credentials verifies certificate validity, server purpose and private-key match.\n"
               "--check-licensing-credentials validates explicit RDP licensing identity plus its matching RSA private key.\n"
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
               "--check-linux-security additionally acquires the explicit Linux GSS acceptor credential, provisions the configured PAM service and validates one native identity-policy rule.\n"
#else
               "--check-linux-security additionally acquires the explicit Linux GSS acceptor credential and validates one native identity-policy rule.\n"
#endif
               "serve opens only a verified loopback listener, requires genuine R2 native admission and R3 Share/Graphics activation, then conditionally publishes protected X11 frames/input. SIGINT/SIGTERM request serialized native/RDP/TLS teardown. GUI LAN configuration reuses this validated file boundary when the production security graph is built; live client servicing remains a separate R10 gate.\n", stdout);
#else
    std::fputs("Usage: rdp-server [--help | --version | --check-config FILE | --check-tls-files FILE | --check-tls-credentials FILE | --check-licensing-credentials FILE]\n"
               "--check-config validates syntax. --check-tls-files checks file metadata.\n"
               "--check-tls-credentials additionally verifies the current certificate validity window and private-key match.\n"
               "--check-licensing-credentials validates explicit RDP licensing identity plus its matching RSA private key.\n"
               "Trust, Microsoft-client acceptance, licensing authority, OS authorization and server startup are not verified.\n", stdout);
#endif
}
} // namespace

int main(int argumentCount, char* argumentValues[]) noexcept {
#if defined(RDP_SERVER_HAVE_PLATFORM_NATIVE_DESKTOP)
    // Exactly one inactive R10 platform-native owner follows the production
    // process lifetime. No native target is constructed until a real bound R2
    // authorization is explicitly attached by a future serialized serve path.
    rdp_server::server::runtime::RuntimePlatformNativeDesktop
        platformNativeDesktopLifetime;
    (void)platformNativeDesktopLifetime;
#endif

    if (argumentCount >= 2 && argumentValues[1] != nullptr) {
        const std::string_view option{argumentValues[1]};
        if (argumentCount == 2 && option == "--help") {
            printUsage();
            return 0;
        }
        if (argumentCount == 2 && option == "--version") {
            std::printf("rdp-server %s\n", RDP_SERVER_VERSION);
            return 0;
        }
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
        if (argumentCount == 4 && option == "serve" &&
            argumentValues[2] != nullptr &&
            std::string_view{argumentValues[2]} == "--config" &&
            argumentValues[3] != nullptr) {
            if (checkConfigurationFile(
                    argumentValues[3], ConfigurationCheckMode::LinuxServe)) {
                return 0;
            }
            // Never reveal configuration contents, credential paths or
            // native-session details on secure-startup denial.
            std::fputs(
                "rdp-server: refusing to start: authenticated OS authorization "
                "and authoritative live RDP sessions are unavailable.\n",
                stderr);
            return kSecureStartupUnavailableExitCode;
        }
#endif
        bool configurationCheckOption =
            option == "--check-config" || option == "--check-tls-files" ||
            option == "--check-tls-credentials" ||
            option == "--check-licensing-credentials";
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
        configurationCheckOption =
            configurationCheckOption || option == "--check-linux-security";
#endif
        if (argumentCount == 3 && configurationCheckOption) {
            ConfigurationCheckMode mode = ConfigurationCheckMode::Syntax;
            if (option == "--check-tls-files") {
                mode = ConfigurationCheckMode::TlsMetadata;
            } else if (option == "--check-tls-credentials") {
                mode = ConfigurationCheckMode::TlsCredentials;
            } else if (option == "--check-licensing-credentials") {
                mode = ConfigurationCheckMode::LicensingCredentials;
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
            } else if (option == "--check-linux-security") {
                mode = ConfigurationCheckMode::LinuxSecurity;
#endif
            }
            if (checkConfigurationFile(argumentValues[2], mode)) {
                if (mode == ConfigurationCheckMode::LicensingCredentials) {
                    std::fputs(
                        "rdp-server: licensing certificate, matching RSA private key and product identity accepted by the offline R3 credential validator; Microsoft-client trust or acceptance, license issuance, user authentication, RDP session authorization and listener readiness not verified; service remains disabled.\n",
                        stdout);
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
                } else if (mode == ConfigurationCheckMode::LinuxSecurity) {
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
                    std::fputs("rdp-server: TLS identity, explicit Linux GSS acceptor credential, PAM service configuration and native identity policy accepted; no user authenticated or session authorized; service remains disabled.\n",
                               stdout);
#else
                    std::fputs("rdp-server: TLS identity, explicit Linux GSS acceptor credential and native identity policy accepted; no user authenticated or session authorized; service remains disabled.\n",
                               stdout);
#endif
#endif
                } else if (mode == ConfigurationCheckMode::TlsCredentials) {
                    std::fputs("rdp-server: TLS certificate is currently valid and matches the private key; "
                               "trust, hostname, revocation and OS authorization not verified; service remains disabled.\n",
                               stdout);
                } else if (mode == ConfigurationCheckMode::TlsMetadata) {
                    std::fputs("rdp-server: TLS file metadata accepted; cryptographic contents "
                               "and OS authorization not verified; service remains disabled.\n",
                               stdout);
                } else {
                    std::fputs("rdp-server: configuration syntax accepted; credentials and "
                               "OS authorization not verified; service remains disabled.\n",
                               stdout);
                }
                return 0;
            }
            // Never reveal configuration contents, paths or secrets in logs.
            std::fputs("rdp-server: configuration check failed; "
                       "service remains disabled.\n", stderr);
            return kInvalidConfigurationExitCode;
        }
    }

    // Reject service startup, missing or chained arguments, and security-
    // weakening options. No sockets, credentials, or desktop are accessed.
    std::fputs("rdp-server: refusing to start: authenticated OS authorization "
               "and authoritative live RDP sessions are unavailable.\n", stderr);
    return kSecureStartupUnavailableExitCode;
}
