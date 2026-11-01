#!/usr/bin/env python3
"""Pin macOS HostControl PersonalDesktop licensing composition and lifetimes."""
from __future__ import annotations

import argparse
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--header", required=True, type=Path)
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

    # Licensing completion is deliberately not Share/native authority. The
    # scheduler must stop after STATUS_VALID_CLIENT/AwaitDemandActive.
    terminal = scheduler.find("AcceptedClientAdmissionStage::ValidClientDelivered")
    demand = scheduler.find("transport::McsSessionPhase::AwaitDemandActive")
    require(terminal >= 0 and demand >= 0, "licensed terminal boundary is missing")
    require(
        "RuntimeHostResult{RuntimeHostError::None, true}" in scheduler,
        "licensed scheduler boundary must yield without entering Share",
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
