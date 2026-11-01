#!/usr/bin/env python3
"""Pin fail-closed allocation handling at macOS HostControl noexcept boundaries."""
from __future__ import annotations

import argparse
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")

    require(
        "MacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try"
        in source,
        "pre-admission noexcept boundary is not allocation-guarded",
    )
    require(
        "RuntimeHostResult MacRuntimeHostControl::serviceOnce() noexcept try"
        in source,
        "serviceOnce noexcept boundary is not allocation-guarded",
    )
    require(
        source.count("catch (const std::bad_alloc&)") >= 2,
        "both noexcept scheduler boundaries must catch std::bad_alloc",
    )
    require(
        source.count("return failClosedAfterAllocationFailure();") >= 2,
        "both allocation catches must share fail-closed retirement",
    )

    helper_start = source.find(
        "MacRuntimeHostControl::failClosedAfterAllocationFailure() noexcept"
    )
    helper_end = source.find(
        "MacRuntimeHostControl::advanceAcceptedClientPreAdmissionOnce() noexcept try",
        helper_start,
    )
    require(helper_start >= 0 and helper_end > helper_start,
            "allocation failure helper is missing")
    helper = source[helper_start:helper_end]
    for required in (
        "retireAcceptedClient();",
        "stage_ != RuntimeHostStage::Revoked",
        "RuntimeHostStage::ListenerAvailable",
        "RuntimeHostStage::Stopped",
        "customErrorMessage_.clear();",
        "deny(RuntimeHostError::InternalFailure)",
    ):
        require(required in helper, f"allocation failure helper missing: {required}")

    require(
        "nativeDesktop_.retireAfterAuthorizationLoss()" not in helper,
        "allocation failure helper duplicated accepted-client native retirement",
    )
    require("catch (...)" not in source,
            "allocation policy must not hide unrelated exceptions")
    print("macOS HostControl allocation-failure retirement contract PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
