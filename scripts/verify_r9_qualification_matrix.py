#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify exact-SHA hosted jobs without promoting artifacts to client acceptance.

The input files are GitHub REST run, paginated jobs and artifacts JSON
snapshots. This tool never contacts GitHub or reads credential-bearing logs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
MAX_INPUT_BYTES = 2 * 1024 * 1024

# GitHub matrix entries are distinct jobs. A green combined job is *not* a
# separate proof of each internal CTest, sanitizer case or physical client.
REQUIRED_JOBS = (
    ("linux_debug_release", "protocol (ubuntu-latest)"),
    ("macos_debug_release", "protocol (macos-latest)"),
    ("windows_msvc_debug_release", "protocol (windows-latest)"),
    ("windows_clang23", "r6-windows-clang23"),
    ("security_asan_ubsan", "r9-security-protocol-sanitizers"),
    ("linux_gui_zip", "r5-linux-gui-zip"),
    ("macos_portable_gui", "r7-macos-portable-gui"),
    ("windows_clean_portable_gui", "r9-clean-windows-portable-gui"),
    ("gui_bootstrap", "r9-portable-gui-bootstrap-acceptance"),
    ("gui_round2", "r9-gui-round2-acceptance"),
    ("documentation_policy", "documentation-policy"),
    ("workflow_structure", "ci-workflow-structure"),
    ("owner_candidate_manual", "r9-credssp-owner-candidate"),
)


def checked_sha(value: object) -> bool:
    return isinstance(value, str) and SHA_PATTERN.fullmatch(value) is not None


def classify_job(job: object) -> str:
    if not isinstance(job, dict):
        return "INVALID"
    status = job.get("status")
    conclusion = job.get("conclusion")
    if status == "queued":
        return "QUEUED"
    if status == "in_progress":
        return "IN_PROGRESS"
    if status not in {"completed", "waiting", "pending", "requested"}:
        return "INVALID"
    if status != "completed":
        return "PENDING"
    return {
        "success": "JOB_PASS",
        "failure": "FAIL",
        "timed_out": "FAIL",
        "action_required": "BLOCKED",
        "cancelled": "CANCELED",
        "skipped": "SKIPPED",
        "neutral": "NEUTRAL",
        "stale": "STALE",
    }.get(conclusion, "INVALID")


def evaluate(expected_sha: str, current_sha: str,
             run: object, jobs_payload: object,
             artifacts_payload: object) -> dict[str, object]:
    """Return only a closed, non-secret status vocabulary."""
    if not checked_sha(expected_sha) or not checked_sha(current_sha):
        raise ValueError("INVALID_SHA")
    if not isinstance(run, dict) or not checked_sha(run.get("head_sha")):
        raise ValueError("INVALID_RUN")
    if not isinstance(jobs_payload, dict) or not isinstance(jobs_payload.get("jobs"), list):
        raise ValueError("INVALID_JOBS")
    if not isinstance(artifacts_payload, dict) or not isinstance(artifacts_payload.get("artifacts"), list):
        raise ValueError("INVALID_ARTIFACTS")
    source_matches = run["head_sha"] == expected_sha
    jobs = jobs_payload["jobs"]
    artifacts = artifacts_payload["artifacts"]
    if len(jobs) > 100 or len(artifacts) > 100:
        raise ValueError("TOO_MANY_RECORDS")

    lanes: dict[str, str] = {}
    for lane, name in REQUIRED_JOBS:
        matching = [job for job in jobs if isinstance(job, dict) and job.get("name") == name]
        if not source_matches:
            lanes[lane] = "SHA_MISMATCH"
        elif len(matching) > 1:
            lanes[lane] = "AMBIGUOUS"
        elif not matching:
            lanes[lane] = "NOT_RUN"
        else:
            lanes[lane] = classify_job(matching[0])

    # An artifact name/metadata alone never authenticates its contents. The
    # Windows protocol job may be green even if its SSPI result is incomplete.
    artifact_name = "r9-microsoft-interop-" + expected_sha
    matching_artifacts = [
        artifact for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("name") == artifact_name
    ]
    if not source_matches:
        sspi_artifact = "SHA_MISMATCH"
    elif len(matching_artifacts) > 1:
        sspi_artifact = "AMBIGUOUS"
    elif not matching_artifacts:
        sspi_artifact = "NOT_PRESENT"
    elif matching_artifacts[0].get("expired") is not False:
        sspi_artifact = "EXPIRED_OR_INVALID"
    else:
        sspi_artifact = "PRESENT_UNINSPECTED"

    return {
        "source_sha": expected_sha,
        "current_sha": current_sha,
        "source_binding": "EXACT" if source_matches else "SHA_MISMATCH",
        "current_head": "EXACT" if expected_sha == current_sha else "DIFFERENT_SHA",
        "lanes": lanes,
        "sspi_artifact": sspi_artifact,
        "sspi_result": "NOT_VERIFIED_FROM_METADATA",
        "owner_same_sha": "NOT_VERIFIED",
        "physical_windows_app_login": "NOT_VERIFIED",
        "m1_acceptance": "NOT_ESTABLISHED",
    }


def self_test() -> None:
    sha = "a" * 40
    other = "b" * 40
    jobs = {"jobs": [
        {"name": "protocol (ubuntu-latest)", "status": "completed", "conclusion": "success"},
        {"name": "protocol (macos-latest)", "status": "completed", "conclusion": "cancelled"},
        {"name": "protocol (windows-latest)", "status": "queued", "conclusion": None},
        {"name": "r9-security-protocol-sanitizers", "status": "completed", "conclusion": "skipped"},
    ]}
    artifacts = {"artifacts": [{"name": "r9-microsoft-interop-" + sha, "expired": False}]}
    run = {"head_sha": sha}
    report = evaluate(sha, sha, run, jobs, artifacts)
    assert report["lanes"]["linux_debug_release"] == "JOB_PASS"
    assert report["lanes"]["macos_debug_release"] == "CANCELED"
    assert report["lanes"]["windows_msvc_debug_release"] == "QUEUED"
    assert report["lanes"]["security_asan_ubsan"] == "SKIPPED"
    assert report["lanes"]["windows_clang23"] == "NOT_RUN"
    assert report["sspi_artifact"] == "PRESENT_UNINSPECTED"
    assert report["sspi_result"] == "NOT_VERIFIED_FROM_METADATA"
    assert report["physical_windows_app_login"] == "NOT_VERIFIED"
    assert report["m1_acceptance"] == "NOT_ESTABLISHED"
    assert evaluate(sha, other, run, jobs, artifacts)["current_head"] == "DIFFERENT_SHA"
    wrong = evaluate(sha, sha, {"head_sha": other}, jobs, artifacts)
    assert all(value == "SHA_MISMATCH" for value in wrong["lanes"].values())
    assert wrong["sspi_artifact"] == "SHA_MISMATCH"
    duplicate = {"jobs": jobs["jobs"] + [jobs["jobs"][0]]}
    assert evaluate(sha, sha, run, duplicate, artifacts)["lanes"]["linux_debug_release"] == "AMBIGUOUS"
    assert evaluate(sha, sha, run, jobs, {"artifacts": []})["sspi_artifact"] == "NOT_PRESENT"
    assert classify_job({"status": "completed", "conclusion": "failure"}) == "FAIL"
    assert classify_job({"status": "in_progress", "conclusion": None}) == "IN_PROGRESS"
    for bad in ({"jobs": "invalid"}, [], None):
        try:
            evaluate(sha, sha, run, bad, artifacts)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed evidence accepted")


def read_json(path: Path) -> object:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("OVERSIZED_INPUT")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--sha")
    parser.add_argument("--current-sha")
    parser.add_argument("--run", type=Path)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        if any(value is None for value in
               (args.sha, args.current_sha, args.run, args.jobs, args.artifacts)):
            raise ValueError("MISSING_INPUT")
        report = evaluate(args.sha, args.current_sha,
                          read_json(args.run), read_json(args.jobs),
                          read_json(args.artifacts))
    except (OSError, UnicodeError, ValueError, AssertionError, TypeError):
        # No private path, JSON field or OS/Python exception is reflected.
        print("R9 qualification evidence invalid", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
