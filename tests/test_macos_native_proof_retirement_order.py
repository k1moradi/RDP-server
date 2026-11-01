#!/usr/bin/env python3
"""Offline macOS native-authorization borrow lifetime retirement contract."""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
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
    print("macOS native-proof borrow teardown ordering PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
