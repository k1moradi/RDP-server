// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_authorized_input_route.h"
#include "x11_rdp_slow_path_input.h"
#include "server/runtime/linux_runtime_connection.h"
#include "server/runtime/runtime_deployment_policy.h"

#include <optional>

using rdp_server::server::security::kConsoleInputPermission;

bool
X11AuthorizedInputRoute::dispatch(
    rdp_server::server::security::LinuxConsoleAdmissionBroker &broker,
    const rdp_server::server::security::LinuxConsoleAdmissionLease *lease,
    rdp_server::server::security::LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    X11DesktopResources &desktop,
    std::uint64_t expectedNativeGeneration,
    const X11InputEvent &event) noexcept
{
    // Capture and XTEST are geometry-bound children of the same R5 owner.
    // Reuse that existing epoch so a decoded event queued before RandR cannot
    // reach the replacement input controller. This scalar is freshness only;
    // matching it cannot substitute for the concrete R2/R3 authorization.
    if (!desktop.valid() || expectedNativeGeneration == 0 ||
        desktop.captureGeneration() != expectedNativeGeneration)
    {
        desktop.retireAfterAuthorizationLoss();
        broker.revokeR3Session(principalProof, session);
        return false;
    }

    // Missing concrete admission is terminal even when native freshness
    // matches. Retire native input without any cleanup XTEST request, then
    // close R3/R2/authentication proof.
    if (lease == nullptr)
    {
        desktop.retireAfterAuthorizationLoss();
        broker.revokeR3Session(principalProof, session);
        return false;
    }

    // Revalidate the exact lease generation, native session generation,
    // R1-owned TLS/authentication/NLA provenance, policy and input permission
    // immediately before native injection. The broker closes R3/R2/authentication proof on
    // any denial; a caller-selected SSL pointer is not an authority input.
    if (!broker.authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session, kConsoleInputPermission))
    {
        desktop.retireAfterAuthorizationLoss();
        return false;
    }

    if (!desktop.handleAuthorizedInput(expectedNativeGeneration, event))
    {
        // Native injection may have failed after an uncertain XCB/geometry
        // transition. Never use graceful disconnect here: only a currently
        // authorized explicit Stop can emit held-key/button XTEST releases.
        desktop.retireAfterAuthorizationLoss();
        broker.revokeR3Session(principalProof, session);
        return false;
    }

    return true;
}


namespace
{
// Lives entirely on R10's serialized event stack; the R2 broker's per-event
// authorization call is synchronous and this context never escapes it.
struct R5AuthorizedSlowPathContext final
{
    X11DesktopResources *desktop{};
    std::uint64_t captureGeneration{};
};
} // namespace

bool X11AuthorizedInputRoute::onAuthenticatedInput(
    void *opaqueContext,
    const rdp_server::server::transport::RdpSlowPathInputEvent &event)
    noexcept
{
    using Kind = rdp_server::server::transport::RdpSlowPathInputEventKind;
    auto *context = static_cast<R5AuthorizedSlowPathContext *>(opaqueContext);
    if (context == nullptr || context->desktop == nullptr)
        return false;

    X11DesktopResources &desktop = *context->desktop;
    if (!desktop.valid() || context->captureGeneration == 0U ||
        desktop.captureGeneration() != context->captureGeneration)
    {
        desktop.retireAfterAuthorizationLoss();
        return false;
    }

    // RDP TS_INPUT_EVENT UNUSED is an explicitly ignored event. It has no
    // native counterpart and is still authorized per-event by R2/R3.
    if (event.kind == Kind::Unused)
        return true;

    const std::optional<X11InputEvent> input =
        translateRdpSlowPathX11Input(event, desktop.sourceGeometry());
    if (!input)
    {
        // The client can negotiate other input formats, but they are not
        // enabled until a spec-reviewed R5 native translation exists.
        desktop.retireAfterAuthorizationLoss();
        return false;
    }

    if (!desktop.handleAuthorizedInput(context->captureGeneration, *input))
    {
        desktop.retireAfterAuthorizationLoss();
        return false;
    }
    return true;
}

bool X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt(
    rdp_server::server::runtime::LinuxRuntimeConnection &connection,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy &policy,
    X11DesktopResources &desktop,
    std::uint64_t expectedNativeGeneration,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    // Native freshness never grants R2 or R3 authority. Reject before even
    // asking the sole R2 broker to parse a decoded-client packet.
    if (!desktop.valid() || expectedNativeGeneration == 0U ||
        desktop.captureGeneration() != expectedNativeGeneration ||
        completeTpkt.empty())
    {
        desktop.retireAfterAuthorizationLoss();
        connection.revoke();
        return false;
    }

    R5AuthorizedSlowPathContext context{&desktop, expectedNativeGeneration};
    const rdp_server::server::transport::RdpSlowPathInputEventSink sink{
        &context, &X11AuthorizedInputRoute::onAuthenticatedInput};

    // This is the ONLY code path invoking our private native XTEST sink.
    // R2 checks the live lease, R1/TLS/authentication provenance, R3 session, negotiated
    // capabilities and kConsoleInputPermission before EACH callback.
    if (!connection.dispatchPersonalDesktopSlowPathInputPdu(
            policy, completeTpkt, sink))
    {
        desktop.retireAfterAuthorizationLoss();
        connection.revoke();
        return false;
    }

    if (!desktop.valid() ||
        desktop.captureGeneration() != expectedNativeGeneration)
    {
        desktop.retireAfterAuthorizationLoss();
        connection.revoke();
        return false;
    }
    return true;
}
