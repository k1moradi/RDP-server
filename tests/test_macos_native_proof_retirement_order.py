#!/usr/bin/env python3
"""Offline macOS native-authorization borrow lifetime retirement contract."""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--check-centralized-callers", action="store_true")
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
        # Accepted-client teardown owns native retirement. The only other
        # direct call is the live native-service failure path, which does not
        # destroy the accepted R1/R2/R3 owners.
        if text.count(native_retirement) != 2:
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
        timeout_start = service.find("if (activeConnection_->cancelIfExpired")
        timeout_stop = service.find(
            "const RuntimeHostResult preAdmission", timeout_start)
        if timeout_start < 0 or timeout_stop <= timeout_start:
            raise SystemExit("cannot isolate accepted-client timeout retirement")
        timeout = service[timeout_start:timeout_stop]
        if "retireAcceptedClient();" not in timeout or native_retirement in timeout:
            raise SystemExit("timeout must use only accepted-client retirement")

        native_service_start = service.find("if (nativeDesktop_.ready())")
        if native_service_start < 0:
            raise SystemExit("cannot isolate direct native service failure")
        native_service = service[native_service_start:]
        if native_service.count(native_retirement) != 1:
            raise SystemExit("native service failure must retain one direct retirement")

        print("macOS accepted-client native retirement single-owner PASS")
    else:
        print("macOS native-proof borrow teardown ordering PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
