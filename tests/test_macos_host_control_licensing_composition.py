#!/usr/bin/env python3
"""Pin macOS HostControl PersonalDesktop licensing composition and lifetimes."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--header", required=True, type=Path)
    parser.add_argument("--check-share-activation", action="store_true")
    parser.add_argument("--check-graphics-control", action="store_true")
    parser.add_argument("--check-frame-pump", action="store_true")
    args = parser.parse_args()

    source = args.source.read_text(encoding="utf-8")
    header = args.header.read_text(encoding="utf-8")

    begin = source.find(
        "MacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try"
    )
    end = source.find("catch (const std::bad_alloc&)", begin)
    require(begin >= 0 and end > begin, "cannot isolate macOS accepted-client scheduler")
    scheduler = source[begin:end]

    # R10 must consume only the existing R2-protected licensing API and the
    # service-lifetime policy/context. No direct R3 licensing transition belongs
    # in HostControl.
    required_once = (
        "authorizeR3PersonalDesktopLicensingMode(",
        "authorizeR3PersonalDesktopServerLicenseRequestWrite(",
        "completeR3PersonalDesktopServerLicenseRequestWrite(",
        "authorizeR3PersonalDesktopClientLicensingMessage(",
        "authorizeR3PersonalDesktopValidClientWrite(",
        "completeR3PersonalDesktopValidClientWrite(",
    )
    for token in required_once:
        require(
            scheduler.count(token) == 1,
            f"macOS HostControl licensing call count changed: {token}",
        )

    for forbidden in (
        "selectVerifiedR2PersonalDesktopLicensingMode(",
        "prepareServerLicenseRequestWrite(",
        "completeServerLicenseRequestWrite(",
        "acceptVerifiedR2ClientLicensingMessage(",
        "preparePersonalDesktopValidClientWrite(",
        "completePersonalDesktopValidClientWrite(",
    ):
        require(
            forbidden not in scheduler,
            f"HostControl bypassed R2 with a direct R3 licensing call: {forbidden}",
        )

    for required in (
        "ClientInfoAccepted",
        "ServerLicenseRequestPending",
        "ServerLicenseRequestDelivered",
        "ClientLicenseResponseAccepted",
        "ValidClientPending",
        "ValidClientDelivered",
        "McsSessionPhase::AwaitServerLicenseRequest",
        "McsSessionPhase::AwaitClientLicenseResponse",
        "McsSessionPhase::AwaitPersonalDesktopValidClientWrite",
        "McsSessionPhase::AwaitDemandActive",
        "*deploymentPolicy_",
        "*licensingContext_.identity()",
        "*licensingContext_.credential()",
        "activeAdmissionBroker_->revalidate(activeAdmissionPermissionMask_)",
    ):
        require(required in scheduler, f"macOS licensing scheduler contract missing: {required}")

    # Licensing completion may hand off only to the protected Share path. It
    # still grants no native desktop, GraphicsReady, input dispatch or Clipboard.
    terminal = scheduler.find("AcceptedClientAdmissionStage::ValidClientDelivered")
    demand = scheduler.find("transport::McsSessionPhase::AwaitDemandActive")
    share_begin = scheduler.find(
        "authorizeR3PersonalDesktopMacDemandActiveProfile(", terminal
    )
    require(
        terminal >= 0 and demand >= 0 and share_begin > terminal,
        "licensed-to-Share protected handoff is missing or reordered",
    )

    if args.check_share_activation:
        share_required_once = (
            "authorizeR3PersonalDesktopMacDemandActiveProfile(",
            "authorizeR3PersonalDesktopShareActivation(",
            "authorizeR3PersonalDesktopShareActivationWrite(",
            "completeR3PersonalDesktopShareActivationWrite(",
            "authorizeR3PersonalDesktopShareActivationPdu(",
        )
        for token in share_required_once:
            require(
                scheduler.count(token) == 1,
                f"macOS HostControl Share call count changed: {token}",
            )

        # Graphics readiness legitimately reuses the same application-traffic
        # gate after MAP. Scope the Share assertion to the Share write branch
        # rather than coupling this older contract to later protocol stages.
        share_write = scheduler.find("if (writingShareActivation)")
        valid_write = scheduler.find(
            "authorizeR3PersonalDesktopValidClientWrite(", share_write
        )
        require(
            share_write >= 0 and valid_write > share_write,
            "cannot isolate macOS Share write branch",
        )
        share_write_block = scheduler[share_write:valid_write]
        require(
            share_write_block.count("authorizeR3ApplicationTrafficReady(") == 1,
            "macOS Share activation must publish application traffic exactly once",
        )

        for forbidden in (
            "prepareVerifiedR2MacDemandActiveProfile(",
            "beginVerifiedR2ShareActivation(",
            "pendingVerifiedR2ShareActivationWrite(",
            "completeVerifiedR2ShareActivationWrite(",
            "acceptVerifiedR2ShareActivationPdu(",
            "verifiedR2ApplicationTrafficReady(",
        ):
            require(
                forbidden not in scheduler,
                f"HostControl bypassed R2 with a direct R3 Share call: {forbidden}",
            )

        for required in (
            "ShareActivationWritePending",
            "ShareActivationClientExpected",
            "AcceptedClientAdmissionStage::ShareActivated",
            "RdpShareServerWriteKind::DemandActive",
            "RdpShareServerWriteKind::Synchronize",
            "RdpShareServerWriteKind::Cooperate",
            "RdpShareServerWriteKind::GrantedControl",
            "RdpShareServerWriteKind::FontMap",
            "Feature::DynamicVirtualChannels",
            "Feature::SlowPathInput",
            "stage_ = RuntimeHostStage::ShareActivated",
            "acceptedClientDiagnostics_.shareActivated = true",
        ):
            require(required in scheduler, f"macOS Share scheduler contract missing: {required}")

        # These switch labels split the qualified enum and enumerator
        # across C++ source lines. Match the actual case syntax, not a
        # single-line source fragment that is absent despite valid code.
        for accepted in (
            "ConfirmActiveAccepted",
            "SynchronizeAccepted",
            "CooperateAccepted",
            "RequestControlAccepted",
            "FontListAccepted",
        ):
            require(
                re.search(
                    r"case\s+transport::RdpShareActivationClientIntake::\s+"
                    + accepted + r":",
                    scheduler,
                ) is not None,
                f"macOS Share intake dispatch missing: {accepted}",
            )

        # The scheduler now continues into Graphics and, after mapped
        # GraphicsReady, may attach the native owner. Scope this Share contract
        # to Share-owned branches rather than rejecting later native work.
        # The scheduler now continues into Graphics after ShareActivated.
        # Keep the older Share contract strict at each Share-owned source
        # boundary instead of rejecting the later protected Graphics branch.
        graphics_stage = scheduler.find(
            "if (activeAdmissionStage_ ==\n"
            "            AcceptedClientAdmissionStage::ShareActivated)",
            share_begin,
        )
        require(
            graphics_stage > share_begin,
            "cannot isolate post-Share Graphics transition",
        )
        share_transition_block = scheduler[share_begin:graphics_stage]
        share_read = scheduler.find("if (readingShareActivation)")
        client_info = scheduler.find("const auto clientInfo =", share_read)
        require(
            share_read >= 0 and client_info > share_read,
            "cannot isolate macOS Share client-intake branch",
        )
        share_read_block = scheduler[share_read:client_info]
        for share_block in (
            share_transition_block,
            share_write_block,
            share_read_block,
        ):
            require(
                "authorizeR3Graphics" not in share_block,
                "Share scheduler must not start Graphics before ShareActivated",
            )
            require(
                "nativeDesktop_" not in share_block,
                "Share scheduler must not attach native state before GraphicsReady",
            )

    if args.check_graphics_control:
        for token in (
            "authorizeR3GraphicsDynamicVirtualChannel(",
            "pendingR3GraphicsDynamicVirtualChannelWrite(",
            "completeR3GraphicsDynamicVirtualChannelWrite(",
            "authorizeR3GraphicsDynamicVirtualChannelPdu(",
        ):
            require(
                scheduler.count(token) == 1,
                f"macOS Graphics control call count changed: {token}",
            )
        for forbidden in (
            "beginVerifiedR2GraphicsDynamicVirtualChannel(",
            "completeVerifiedR2GraphicsDynamicVirtualChannelWrite(",
            "acceptVerifiedR2GraphicsDynamicVirtualChannelPdu(",
            "beginR3GraphicsClearCodecFramePublication(",
        ):
            require(
                forbidden not in scheduler,
                f"Graphics control bypassed R2 or published pixels: {forbidden}",
            )
        for required in (
            "GraphicsControlWritePending",
            "GraphicsControlClientExpected",
            "AcceptedClientAdmissionStage::GraphicsReady",
            "RdpGraphicsDvcWriteKind::CapabilitiesRequest",
            "RdpGraphicsDvcWriteKind::CreateRequest",
            "RdpGraphicsDvcWriteKind::GraphicsMapSurfaceToOutput",
            "activeGraphicsControlDeadline_",
            "observed.surfaceMapped",
        ):
            require(required in scheduler, f"macOS Graphics contract missing: {required}")
        require(
            "nativeDesktop_.borrowFramebuffer(" not in scheduler,
            "Graphics control/native attach must not publish framebuffer pixels",
        )
        require(
            scheduler.count("nativeDesktop_.attachAuthenticatedSession(") == 1,
            "mapped GraphicsReady must have one downstream native attach seam",
        )
        status = source[source.find("RuntimeHostStatus MacRuntimeHostControl::status()"): ]
        require("snapshot.graphicsReady = proof.shareActivated" in status,
                "GraphicsReady status requires mapped R3 evidence")
        require("snapshot.nativeDesktopReady = nativeDesktop_.ready()" in status,
                "nativeDesktopReady must remain separate")

    if args.check_frame_pump:
        frame_begin = source.find(
            "MacRuntimeHostControl::serviceAcceptedClientGraphicsOnce("
        )
        frame_end = source.find("catch (const std::bad_alloc&)", frame_begin)
        require(
            frame_begin >= 0 and frame_end > frame_begin,
            "cannot isolate macOS post-Graphics frame pump",
        )
        frame_pump = source[frame_begin:frame_end]
        for token in (
            "beginR3GraphicsSurfaceReconfiguration(",
            "preflightR3GraphicsFramePublication(",
            "nativeDesktop_.borrowFramebuffer(",
            "beginR3GraphicsClearCodecFramePublication(",
            "pendingR3GraphicsDynamicVirtualChannelWrite(",
            "completeR3GraphicsDynamicVirtualChannelWrite(",
            "classifyR3PostShareTpkt(",
            "authorizeR3GraphicsDynamicVirtualChannelPdu(",
            "consumeR3GraphicsFrameAcknowledge(",
            "connection.writeTlsApplicationData(",
            "connection.readTlsApplicationData(",
            "cancelR3UnwrittenGraphicsFrame(",
            "abortR3GraphicsFrame(",
        ):
            require(token in frame_pump, f"macOS frame pump missing: {token}")
        for forbidden in (
            "beginVerifiedR2GraphicsClearCodecFramePublication(",
            "completeVerifiedR2GraphicsDynamicVirtualChannelWrite(",
            "consumeVerifiedR2GraphicsFrameAcknowledge(",
            "RuntimeHostStage::DesktopVisible",
        ):
            require(
                forbidden not in frame_pump,
                f"macOS frame pump bypassed owner/visibility boundary: {forbidden}",
            )
        require(
            frame_pump.find("connection.writeTlsApplicationData(") <
            frame_pump.find("preflightR3GraphicsFramePublication(") <
            frame_pump.find("nativeDesktop_.borrowFramebuffer("),
            "pending R3 DATA must drain before a new preflight/native borrow",
        )
        require(
            "activeGraphicsFrameWritePending_" in frame_pump
            and "graphicsFrameWriteNeedsRead" in frame_pump,
            "frame pump must preserve one pending R3 write and R1 WANT direction",
        )
        service_begin = source.find(
            "RuntimeHostResult MacRuntimeHostControl::serviceOnce() noexcept try"
        )
        service_end = source.find("catch (const std::bad_alloc&)", service_begin)
        require(
            service_begin >= 0 and service_end > service_begin,
            "cannot isolate macOS HostControl serviceOnce",
        )
        service = source[service_begin:service_end]
        require(
            "nativeDesktop_.serviceOnce(&nativeObservation)" in service
            and "serviceAcceptedClientGraphicsOnce(nativeObservation)" in service,
            "R10 must consume only the current R7 service observation",
        )
        require(
            "POLLERR | POLLHUP" in frame_pump and "POLLNVAL" in frame_pump,
            "terminal socket readiness must be handed to the original R1 owner",
        )

        status_begin = source.find(
            "RuntimeHostStatus MacRuntimeHostControl::status() const"
        )
        status_end = source.find(
            "RuntimeHostResult MacRuntimeHostControl::configure(", status_begin
        )
        require(
            status_begin >= 0 and status_end > status_begin,
            "cannot isolate macOS HostControl status projection",
        )
        status = source[status_begin:status_end]
        require(
            "snapshot.firstLiveGraphicsTrace =" in status,
            "first-live graphics trace must project to RuntimeHostStatus",
        )
        require(
            "acceptedClientPreauthDiagnostics.firstLiveGraphicsTrace" not in status,
            "pre-auth diagnostics must not own post-Graphics frame trace",
        )

    # C++ member destruction is reverse declaration order. Service policy and
    # licensing material therefore must be declared before every accepted-client
    # borrower so R2/R3/proof/R1 retire before those borrowed objects.
    licensing = header.find("RuntimeLicensingContext licensingContext_{};")
    policy = header.find("std::optional<RuntimeDeploymentPolicy> deploymentPolicy_{};")
    connection = header.find("activeConnection_{};")
    proof = header.find("activeCredSsp_{};")
    session = header.find("activeMcsSession_{};")
    broker = header.find("activeAdmissionBroker_{};")
    positions = (licensing, policy, connection, proof, session, broker)
    require(all(position >= 0 for position in positions), "macOS licensing lifetime member missing")
    require(
        licensing < policy < connection < proof < session < broker,
        "service licensing/policy lifetime no longer outlives accepted-client borrowers",
    )

    # RuntimeLicensingContext exposes an immutable credential object, not its PEM
    # bytes. HostControl may borrow that object but must never name private-key
    # material or log it.
    for forbidden in ("privateKeyPem", "private_key", "licensing_private_key"):
        require(
            forbidden not in scheduler,
            f"macOS licensing scheduler exposed private-key material: {forbidden}",
        )

    print("macOS HostControl PersonalDesktop licensing composition contract PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
