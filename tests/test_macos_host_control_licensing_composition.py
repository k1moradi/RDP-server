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

        require(
            "nativeDesktop_" not in scheduler,
            "Share scheduler must not attach or service the native desktop",
        )
        require(
            "authorizeR3Graphics" not in scheduler,
            "Share scheduler must not start Graphics",
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
        require("nativeDesktop_" not in scheduler,
                "Graphics control must not borrow the macOS desktop")
        status = source[source.find("RuntimeHostStatus MacRuntimeHostControl::status()"): ]
        require("snapshot.graphicsReady = proof.shareActivated" in status,
                "GraphicsReady status requires mapped R3 evidence")
        require("snapshot.nativeDesktopReady = nativeDesktop_.ready()" in status,
                "nativeDesktopReady must remain separate")

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
