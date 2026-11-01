#!/usr/bin/env python3
"""Offline macOS native-authorization borrow lifetime retirement contract."""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--check-centralized-callers", action="store_true")
    parser.add_argument("--check-share-without-graphics", action="store_true")
    parser.add_argument("--check-graphics-native-attach", action="store_true")
    args = parser.parse_args()
    text = args.source.read_text(encoding="utf-8")
    start = text.find("void MacRuntimeHostControl::retireAcceptedClient() noexcept")
    stop = text.find("RuntimeHostResult\nMacRuntimeHostControl::failClosedAfterAllocationFailure() noexcept", start)
    if start < 0 or stop <= start:
        raise SystemExit("cannot isolate accepted-client retirement")
    body = text[start:stop]

    # R2/R3 must close before native teardown; the proof and transport must
    # remain valid until native authorization is retired.
    required = (
        "activeAdmissionBroker_.reset();",
        "activeMcsSession_->close();",
        "nativeDesktop_.retireAfterAuthorizationLoss();",
        "activeMcsSession_.reset();",
        "activeCredSsp_.reset();",
        "activeConnection_->cancel();",
        "activeConnection_.reset();",
    )
    positions = [body.find(token) for token in required]
    if any(position < 0 for position in positions):
        raise SystemExit("accepted-client retirement lost R2/R3/native/proof/R1 cleanup")
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise SystemExit("native teardown must precede proof/SSL retirement")
    if body.count("nativeDesktop_.retireAfterAuthorizationLoss();") != 1:
        raise SystemExit("native authorization must retire exactly once inside accepted-client teardown")

    if args.check_centralized_callers:
        native_retirement = "nativeDesktop_.retireAfterAuthorizationLoss();"
        # Accepted-client teardown is the sole direct native-retirement owner.
        # Native service failure must retire the complete accepted client,
        # rather than dropping only the native child and leaving R2/R3 live.
        if text.count(native_retirement) != 1:
            raise SystemExit("macOS HostControl has duplicate native retirement owners")

        caller_ranges = (
            (
                "RuntimeHostResult\nMacRuntimeHostControl::failClosedAfterAllocationFailure() noexcept",
                "RuntimeHostResult\nMacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try",
                "allocation failure",
            ),
            (
                "void MacRuntimeHostControl::retireStoppedRuntime(",
                "std::vector<MacRuntimeDefaultRoutePreference>",
                "stopped runtime",
            ),
            (
                "RuntimeHostResult MacRuntimeHostControl::disconnectClient(",
                "RuntimeHostResult MacRuntimeHostControl::revokeSharing()",
                "explicit disconnect",
            ),
        )
        for start_marker, stop_marker, label in caller_ranges:
            caller_start = text.find(start_marker)
            caller_stop = text.find(stop_marker, caller_start)
            if caller_start < 0 or caller_stop <= caller_start:
                raise SystemExit(f"cannot isolate {label} retirement caller")
            caller = text[caller_start:caller_stop]
            if "retireAcceptedClient();" not in caller:
                raise SystemExit(f"{label} bypassed accepted-client retirement")
            if native_retirement in caller:
                raise SystemExit(f"{label} duplicated native retirement")

        service_start = text.find(
            "RuntimeHostResult MacRuntimeHostControl::serviceOnce() noexcept try")
        service_stop = text.find(
            "RuntimeHostResult MacRuntimeHostControl::stopSharing()", service_start)
        if service_start < 0 or service_stop <= service_start:
            raise SystemExit("cannot isolate macOS HostControl service scheduler")
        service = text[service_start:service_stop]
        # The pre-auth deadline now expires only before genuine
        # ShareActivated. Keep the original cancel/retire ordering while
        # allowing the condition to span multiple C++ source lines.
        timeout_start = service.find("if (activeConnection_ != nullptr)")
        timeout_stop = service.find(
            "const RuntimeHostResult preAdmission", timeout_start)
        if timeout_start < 0 or timeout_stop <= timeout_start:
            raise SystemExit("cannot isolate accepted-client timeout retirement")
        timeout = service[timeout_start:timeout_stop]
        if (
            "AcceptedClientAdmissionStage::ShareActivated" not in timeout
            or "activeConnection_->cancelIfExpired(" not in timeout
            or "retireAcceptedClient();" not in timeout
            or native_retirement in timeout
        ):
            raise SystemExit("pre-Share timeout must use only accepted-client retirement")

        native_service_start = service.find("if (nativeDesktop_.active())")
        if native_service_start < 0:
            raise SystemExit("cannot isolate active native service path")
        native_service = service[native_service_start:]
        if (
            "nativeDesktop_.serviceOnce()" not in native_service or
            "retireAcceptedClient();" not in native_service or
            native_retirement in native_service
        ):
            raise SystemExit(
                "native service failure must use complete accepted-client retirement")

        print("macOS accepted-client native retirement single-owner PASS")
    elif args.check_graphics_native_attach:
        scheduler_start = text.find(
            "MacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try")
        scheduler_stop = text.find("catch (const std::bad_alloc&)", scheduler_start)
        if scheduler_start < 0 or scheduler_stop <= scheduler_start:
            raise SystemExit("cannot isolate macOS protected Graphics scheduler")
        scheduler = text[scheduler_start:scheduler_stop]

        attach = "nativeDesktop_.attachAuthenticatedSession("
        if scheduler.count(attach) != 1:
            raise SystemExit("GraphicsReady must own exactly one native attach call")
        for required in (
            "AcceptedClientAdmissionStage::GraphicsReady",
            "graphicsProof.shareActivated",
            "graphicsProof.graphicsDynamicVirtualChannelActivated",
            "graphicsProof.graphicsControlReady",
            "graphicsProof.surfaceCreated",
            "graphicsProof.surfaceMapped",
            "activeCredSsp_->authenticatedProof",
            "ownerSharingAuthority_",
            "activeAdmissionPermissionMask_",
        ):
            if required not in scheduler:
                raise SystemExit(f"GraphicsReady native attach contract missing: {required}")
        if "nativeDesktop_.borrowFramebuffer(" in scheduler:
            raise SystemExit("native attach must not publish a framebuffer")

        status_start = text.find("RuntimeHostStatus MacRuntimeHostControl::status() const")
        status_stop = text.find(
            "RuntimeHostResult MacRuntimeHostControl::configure(", status_start)
        if status_start < 0 or status_stop <= status_start:
            raise SystemExit("cannot isolate native status projection")
        status = text[status_start:status_stop]
        if (
            "snapshot.nativeDesktopInitializing =" not in status or
            "nativeDesktop_.active() && !snapshot.nativeDesktopReady" not in status
        ):
            raise SystemExit("attached native initialization status is not projected")
        if "client.desktopVisible = snapshot.nativeDesktopReady" not in status:
            raise SystemExit("native attachment must not imply desktop visibility")

        service_start = text.find(
            "RuntimeHostResult MacRuntimeHostControl::serviceOnce() noexcept try")
        service_stop = text.find(
            "RuntimeHostResult MacRuntimeHostControl::stopSharing()", service_start)
        if service_start < 0 or service_stop <= service_start:
            raise SystemExit("cannot isolate native service scheduler")
        service = text[service_start:service_stop]
        if (
            "if (nativeDesktop_.active())" not in service or
            "nativeDesktop_.serviceOnce()" not in service or
            "retireAcceptedClient();" not in service
        ):
            raise SystemExit("active native initialization is not serviced fail-closed")

        print("macOS GraphicsReady native attachment composition PASS")
    elif args.check_share_without_graphics:
        # A receipt-complete ShareActivated is a protocol fact, not a native
        # framebuffer borrow, Graphics DVC channel, or first-frame delivery.
        scheduler_start = text.find(
            "MacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try")
        scheduler_stop = text.find("catch (const std::bad_alloc&)", scheduler_start)
        if scheduler_start < 0 or scheduler_stop <= scheduler_start:
            raise SystemExit("cannot isolate macOS protected Share scheduler")
        scheduler = text[scheduler_start:scheduler_stop]
        if (
            "authorizeR3ApplicationTrafficReady(" not in scheduler or
            "stage_ = RuntimeHostStage::ShareActivated;" not in scheduler or
            "acceptedClientDiagnostics_.shareActivated = true;" not in scheduler
        ):
            raise SystemExit("macOS Share activation lost its original R2/R3 receipt")

        status_start = text.find("RuntimeHostStatus MacRuntimeHostControl::status() const")
        status_stop = text.find(
            "RuntimeHostResult MacRuntimeHostControl::configure(", status_start)
        if status_start < 0 or status_stop <= status_start:
            raise SystemExit("cannot isolate macOS HostControl status projection")
        status = text[status_start:status_stop]
        # A completed Share alone cannot create GraphicsReady. R10 now
        # permits the positive projection only after the original mapped
        # R3 Graphics control transcript and its pinned R2 authorization.
        if (
            "activeAdmissionStage_ == AcceptedClientAdmissionStage::GraphicsReady"
            not in status or
            "snapshot.graphicsReady = proof.shareActivated" not in status or
            "proof.graphicsDynamicVirtualChannelActivated" not in status or
            "proof.graphicsControlReady" not in status or
            "proof.surfaceCreated" not in status or
            "proof.surfaceMapped" not in status
        ):
            raise SystemExit(
                "Share without mapped R3 Graphics control must not report GraphicsReady")
        if status.count("snapshot.nativeDesktopReady = nativeDesktop_.ready();") != 1:
            raise SystemExit("native desktop status must remain independent")

        share_start = status.find("client.shareActivated =")
        share_stop = status.find(";", share_start)
        visible_start = status.find("client.desktopVisible =")
        visible_stop = status.find(";", visible_start)
        if min(share_start, share_stop, visible_start, visible_stop) < 0:
            raise SystemExit("cannot isolate client Share/desktop status")
        share_projection = status[share_start:share_stop]
        visible_projection = status[visible_start:visible_stop]
        if "RuntimeHostStage::ShareActivated" not in share_projection:
            raise SystemExit("genuine ShareActivated is no longer projected")
        if (
            "RuntimeHostStage::ShareActivated" in visible_projection or
            "snapshot.nativeDesktopReady" not in visible_projection or
            "RuntimeHostStage::DesktopVisible" not in visible_projection or
            "RuntimeHostStage::ClientConnected" not in visible_projection
        ):
            raise SystemExit("Share alone must not project a visible desktop")
        print("macOS Share without GraphicsReady/native-first-frame status PASS")
    else:
        print("macOS native-proof borrow teardown ordering PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
