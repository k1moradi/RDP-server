#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify exact-SHA hosted jobs without promoting artifacts to client acceptance.

The input files are GitHub REST run, complete paginated jobs and artifacts JSON
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
    ("linux_debug", "protocol (ubuntu-latest)", "Run Debug protocol and project-policy tests"),
    ("linux_release", "protocol (ubuntu-latest)", "Run Release protocol tests"),
    ("macos_debug", "protocol (macos-latest)", "Run Debug protocol and project-policy tests"),
    ("macos_release", "protocol (macos-latest)", "Run Release protocol tests"),
    ("windows_msvc_debug", "protocol (windows-latest)", "Run Debug protocol and project-policy tests"),
    ("windows_msvc_release", "protocol (windows-latest)", "Run Release protocol tests"),
    ("windows_clang23_debug", "r6-windows-clang23", "Run full Debug CTest under CLANG64"),
    ("windows_clang23_release", "r6-windows-clang23", "Run full Release CTest under CLANG64"),
    ("windows_gui_staged", "r6-windows-clang23", "Stage Windows PORTABLE-GUI candidate (internal only)"),
    ("security_asan_ubsan", "r9-security-protocol-sanitizers", None),
    ("r2_linux_security_complete", "r2-linux-production-runtime-security (complete)", None),
    ("r2_linux_security_missing_systemd", "r2-linux-production-runtime-security (missing-systemd)", None),
    ("r7_macos_native_lifecycle", "r7-macos-native-lifecycle", None),
    ("r7_macos_session_sanitizers", "r7-macos-session-sanitizers", None),
    ("linux_gui_zip", "r5-linux-gui-zip", None),
    ("macos_portable_gui", "r7-macos-portable-gui", None),
    ("windows_clean_portable_gui", "r9-clean-windows-portable-gui", None),
    ("gui_bootstrap", "r9-portable-gui-bootstrap-acceptance", None),
    ("gui_round2", "r9-gui-round2-acceptance", None),
    ("gui_credential_parity_linux", "r9-owner-gui-credential-parity (ubuntu-latest)", None),
    ("gui_credential_parity_macos", "r9-owner-gui-credential-parity (macos-latest)", None),
    ("windows_powershell_parser", "r9-windows-powershell-parser", None),
    ("documentation_policy", "documentation-policy", None),
    ("workflow_structure", "ci-workflow-structure", None),
    ("owner_candidate_manual", "r9-credssp-owner-candidate", None),
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



def classify_run_fallback(
    run: dict[str, object], completed_absent_state: str
) -> str:
    """Classify unavailable per-run evidence without inventing execution."""
    status = run.get("status")
    if status == "queued":
        return "RUN_QUEUED"
    if status == "in_progress":
        return "RUN_IN_PROGRESS"
    if status in {"pending", "requested", "waiting"}:
        return "RUN_PENDING"
    if status == "completed":
        if run.get("conclusion") == "cancelled":
            return "RUN_CANCELED"
        if run.get("conclusion") == "skipped":
            return "RUN_SKIPPED"
    return completed_absent_state


def classify_unscheduled_lane(run: dict[str, object]) -> str:
    """Run-level lifecycle is not evidence that an individual job executed."""
    return classify_run_fallback(run, "NOT_RUN")


def classify_missing_artifact(run: dict[str, object]) -> str:
    """Distinguish an artifact still pending from one absent after the run."""
    return classify_run_fallback(run, "NOT_PRESENT")


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
    # Matching SHA alone cannot bind independently obtained job and artifact
    # JSON snapshots to this specific Actions run.
    run_id = run.get("id")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise ValueError("INVALID_RUN")
    source_matches = run["head_sha"] == expected_sha
    jobs = jobs_payload["jobs"]
    artifacts = artifacts_payload["artifacts"]
    if len(jobs) > 100 or len(artifacts) > 100:
        raise ValueError("TOO_MANY_RECORDS")

    # A partial REST page cannot establish complete exact-run evidence.
    for payload, records in ((jobs_payload, jobs), (artifacts_payload, artifacts)):
        total_count = payload.get("total_count")
        if total_count is not None and (
            type(total_count) is not int or total_count != len(records)
        ):
            raise ValueError("INCOMPLETE_SNAPSHOT")

    lanes: dict[str, str] = {}
    for lane, name, required_step in REQUIRED_JOBS:
        matching = [job for job in jobs if isinstance(job, dict) and job.get("name") == name]
        if not source_matches:
            lanes[lane] = "SHA_MISMATCH"
        elif len(matching) > 1:
            lanes[lane] = "AMBIGUOUS"
        elif not matching:
            lanes[lane] = classify_unscheduled_lane(run)
        elif matching[0].get("run_id") != run_id:
            lanes[lane] = "RUN_MISMATCH"
        else:
            job_status = classify_job(matching[0])
            if job_status != "JOB_PASS" or required_step is None:
                lanes[lane] = job_status
                continue
            steps = matching[0].get("steps")
            if not isinstance(steps, list) or len(steps) > 100:
                lanes[lane] = "STEPS_UNVERIFIED"
                continue
            matching_steps = [
                step for step in steps
                if isinstance(step, dict) and step.get("name") == required_step
            ]
            if len(matching_steps) > 1:
                lanes[lane] = "AMBIGUOUS"
            elif not matching_steps:
                lanes[lane] = "STEPS_UNVERIFIED"
            else:
                lanes[lane] = classify_job(matching_steps[0])

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
        sspi_artifact = classify_missing_artifact(run)
    elif (not isinstance(matching_artifacts[0].get("workflow_run"), dict)
          or matching_artifacts[0]["workflow_run"].get("id") != run_id
          or matching_artifacts[0]["workflow_run"].get("head_sha") != expected_sha):
        sspi_artifact = "RUN_MISMATCH"
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
        {"name": "protocol (ubuntu-latest)", "status": "completed", "conclusion": "success",
         "steps": [
             {"name": "Run Debug protocol and project-policy tests", "status": "completed", "conclusion": "success"},
             {"name": "Run Release protocol tests", "status": "completed", "conclusion": "skipped"},
         ]},
        {"name": "protocol (macos-latest)", "status": "completed", "conclusion": "cancelled"},
        {"name": "protocol (windows-latest)", "status": "queued", "conclusion": None},
        {"name": "r9-security-protocol-sanitizers", "status": "completed", "conclusion": "skipped"},
        {"name": "r2-linux-production-runtime-security (complete)",
         "status": "completed", "conclusion": "success"},
        {"name": "r2-linux-production-runtime-security (missing-systemd)",
         "status": "completed", "conclusion": "skipped"},
        {"name": "r7-macos-native-lifecycle", "status": "queued", "conclusion": None},
        {"name": "r7-macos-session-sanitizers", "status": "completed", "conclusion": "cancelled"},
        {"name": "r9-owner-gui-credential-parity (ubuntu-latest)",
         "status": "completed", "conclusion": "success"},
        {"name": "r9-owner-gui-credential-parity (macos-latest)",
         "status": "completed", "conclusion": "skipped"},
        {"name": "r9-windows-powershell-parser", "status": "completed", "conclusion": "success"},
        {"name": "r9-clean-windows-portable-gui", "status": "queued", "conclusion": None},
        {"name": "r9-credssp-owner-candidate", "status": "completed", "conclusion": "skipped"},
    ]}
    run_id = 41318750637
    for job in jobs["jobs"]:
        job["run_id"] = run_id
    artifacts = {"artifacts": [
        {"name": "r9-microsoft-interop-" + sha, "expired": False,
         "workflow_run": {"id": run_id, "head_sha": sha}}
    ]}
    run = {"id": run_id, "head_sha": sha}
    report = evaluate(sha, sha, run, jobs, artifacts)
    if not (report["lanes"]["linux_debug"] == "JOB_PASS"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["linux_release"] == "SKIPPED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["macos_debug"] == "CANCELED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["windows_msvc_debug"] == "QUEUED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["windows_clean_portable_gui"] == "QUEUED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["owner_candidate_manual"] == "SKIPPED"):
        raise AssertionError("R9 self-test denial failed")
    # Every independent producer must be visible, not hidden inside a green
    # aggregate protocol job or silently omitted from the owner gate.
    expected_producers = {
        "r2_linux_security_complete": "JOB_PASS",
        "r2_linux_security_missing_systemd": "SKIPPED",
        "r7_macos_native_lifecycle": "QUEUED",
        "r7_macos_session_sanitizers": "CANCELED",
        "gui_credential_parity_linux": "JOB_PASS",
        "gui_credential_parity_macos": "SKIPPED",
        "windows_powershell_parser": "JOB_PASS",
        "windows_gui_staged": "NOT_RUN",
    }
    if any(report["lanes"][name] != state
           for name, state in expected_producers.items()):
        raise AssertionError("R9 independent producer classification failed")
    staged_only = evaluate(sha, sha, run, {"jobs": [{
        "name": "r6-windows-clang23", "run_id": run_id,
        "status": "completed", "conclusion": "success",
        "steps": [{"name": "Stage Windows PORTABLE-GUI candidate (internal only)",
                   "status": "completed", "conclusion": "skipped"}],
    }]}, artifacts)
    if staged_only["lanes"]["windows_gui_staged"] != "SKIPPED":
        raise AssertionError("R9 Windows staged ZIP step was promoted")
    missing_step_report = evaluate(sha, sha, run, {"jobs": [
        {"name": "protocol (ubuntu-latest)", "status": "completed", "conclusion": "success",
         "run_id": run_id, "steps": []}
    ]}, artifacts)
    if not (missing_step_report["lanes"]["linux_debug"] == "STEPS_UNVERIFIED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["security_asan_ubsan"] == "SKIPPED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["lanes"]["windows_clang23_debug"] == "NOT_RUN"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["sspi_artifact"] == "PRESENT_UNINSPECTED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["sspi_result"] == "NOT_VERIFIED_FROM_METADATA"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["physical_windows_app_login"] == "NOT_VERIFIED"):
        raise AssertionError("R9 self-test denial failed")
    if not (report["m1_acceptance"] == "NOT_ESTABLISHED"):
        raise AssertionError("R9 self-test denial failed")
    if not (evaluate(sha, other, run, jobs, artifacts)["current_head"] == "DIFFERENT_SHA"):
        raise AssertionError("R9 self-test denial failed")
    wrong = evaluate(sha, sha, {"id": run_id, "head_sha": other}, jobs, artifacts)
    if not (all(value == "SHA_MISMATCH" for value in wrong["lanes"].values())):
        raise AssertionError("R9 self-test denial failed")
    if not (wrong["sspi_artifact"] == "SHA_MISMATCH"):
        raise AssertionError("R9 self-test denial failed")
    # A different run at the same SHA cannot supply a green job or artifact.
    foreign_job = {"jobs": [{**jobs["jobs"][0], "run_id": run_id + 1}]}
    if evaluate(sha, sha, run, foreign_job, artifacts)["lanes"]["linux_debug"] != "RUN_MISMATCH":
        raise AssertionError("foreign job accepted")
    unbound_job = {"jobs": [{key: value for key, value in jobs["jobs"][0].items()
                            if key != "run_id"}]}
    if evaluate(sha, sha, run, unbound_job, artifacts)["lanes"]["linux_debug"] != "RUN_MISMATCH":
        raise AssertionError("unbound job accepted")
    for foreign_binding in ({"id": run_id + 1, "head_sha": sha},
                            {"id": run_id, "head_sha": other}, None):
        foreign_artifacts = {"artifacts": [
            {**artifacts["artifacts"][0], "workflow_run": foreign_binding}
        ]}
        if evaluate(sha, sha, run, jobs, foreign_artifacts)["sspi_artifact"] != "RUN_MISMATCH":
            raise AssertionError("foreign artifact accepted")
    try:
        evaluate(sha, sha, {"head_sha": sha}, jobs, artifacts)
    except ValueError:
        pass
    else:
        raise AssertionError("unbound run accepted")
    duplicate = {"jobs": jobs["jobs"] + [jobs["jobs"][0]]}
    if not (evaluate(sha, sha, run, duplicate, artifacts)["lanes"]["linux_debug"] == "AMBIGUOUS"):
        raise AssertionError("R9 self-test denial failed")
    if not (evaluate(sha, sha, run, jobs, {"artifacts": []})["sspi_artifact"] == "NOT_PRESENT"):
        raise AssertionError("R9 self-test denial failed")
    if not (classify_job({"status": "completed", "conclusion": "failure"}) == "FAIL"):
        raise AssertionError("R9 self-test denial failed")
    if not (classify_job({"status": "in_progress", "conclusion": None}) == "IN_PROGRESS"):
        raise AssertionError("R9 self-test denial failed")
    self_test_unscheduled_run_state()
    # Complete GitHub REST pages pass; truncated or invalid totals fail.
    complete_jobs = {**jobs, "total_count": len(jobs["jobs"])}
    complete_artifacts = {**artifacts, "total_count": len(artifacts["artifacts"])}
    complete = evaluate(sha, sha, run, complete_jobs, complete_artifacts)
    if (complete["lanes"]["linux_debug"] != "JOB_PASS"
            or complete["sspi_artifact"] != "PRESENT_UNINSPECTED"):
        raise AssertionError("complete REST snapshot rejected")
    for collection_name, records in (("jobs", jobs["jobs"]),
                                     ("artifacts", artifacts["artifacts"])):
        for invalid_count in (len(records) + 1, -1, True):
            candidate_jobs = dict(complete_jobs)
            candidate_artifacts = dict(complete_artifacts)
            if collection_name == "jobs":
                candidate_jobs["total_count"] = invalid_count
            else:
                candidate_artifacts["total_count"] = invalid_count
            try:
                evaluate(sha, sha, run, candidate_jobs, candidate_artifacts)
            except ValueError as error:
                if str(error) != "INCOMPLETE_SNAPSHOT":
                    raise
            else:
                raise AssertionError("incomplete REST snapshot accepted")
    for bad in ({"jobs": "invalid"}, [], None):
        try:
            evaluate(sha, sha, run, bad, artifacts)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed evidence accepted")



def self_test_unscheduled_run_state() -> None:
    sha = "c" * 40
    other_sha = "d" * 40
    run_id = 41318750637
    base_run = {"id": run_id, "head_sha": sha}
    missing_jobs = {"jobs": []}
    no_artifacts = {"artifacts": []}

    for status, conclusion, expected_lane, expected_artifact in (
        ("queued", None, "RUN_QUEUED", "RUN_QUEUED"),
        ("in_progress", None, "RUN_IN_PROGRESS", "RUN_IN_PROGRESS"),
        ("pending", None, "RUN_PENDING", "RUN_PENDING"),
        ("requested", None, "RUN_PENDING", "RUN_PENDING"),
        ("waiting", None, "RUN_PENDING", "RUN_PENDING"),
        ("completed", "cancelled", "RUN_CANCELED", "RUN_CANCELED"),
        ("completed", "skipped", "RUN_SKIPPED", "RUN_SKIPPED"),
        ("completed", "success", "NOT_RUN", "NOT_PRESENT"),
        ("completed", "failure", "NOT_RUN", "NOT_PRESENT"),
    ):
        run = {**base_run, "status": status, "conclusion": conclusion}
        report = evaluate(sha, sha, run, missing_jobs, no_artifacts)
        if not all(value == expected_lane for value in report["lanes"].values()):
            raise AssertionError("unscheduled workflow was promoted to job evidence")
        if report["sspi_artifact"] != expected_artifact:
            raise AssertionError("missing SSPI archive lost workflow lifecycle")
        if report["physical_windows_app_login"] != "NOT_VERIFIED":
            raise AssertionError("run scheduling was promoted to physical acceptance")
        if expected_lane == "RUN_QUEUED":
            mismatch = evaluate(sha, other_sha, run, missing_jobs, no_artifacts)
            if mismatch["current_head"] != "DIFFERENT_SHA":
                raise AssertionError("ancestor scheduling was treated as current")
            wrong_source = evaluate(
                sha, sha, {**run, "head_sha": other_sha},
                missing_jobs, no_artifacts)
            if any(value != "SHA_MISMATCH"
                   for value in wrong_source["lanes"].values()):
                raise AssertionError("foreign workflow scheduling was accepted")

    # A present job is authoritative over the run-level fallback.
    run = {**base_run, "status": "queued", "conclusion": None}
    present_job = {"jobs": [{
        "run_id": run_id, "name": "r9-clean-windows-portable-gui",
        "status": "completed", "conclusion": "skipped",
    }]}
    report = evaluate(sha, sha, run, present_job, no_artifacts)
    if report["lanes"]["windows_clean_portable_gui"] != "SKIPPED":
        raise AssertionError("present job status replaced by run fallback")
    if report["lanes"]["linux_debug"] != "RUN_QUEUED":
        raise AssertionError("missing job status lost queued-run origin")

    # A matching artifact remains visible even while other workflow work is queued.
    present_artifacts = {"artifacts": [{
        "name": "r9-microsoft-interop-" + sha,
        "expired": False,
        "workflow_run": {"id": run_id, "head_sha": sha},
    }]}
    artifact_report = evaluate(
        sha, sha, run, missing_jobs, present_artifacts)
    if artifact_report["sspi_artifact"] != "PRESENT_UNINSPECTED":
        raise AssertionError("present SSPI artifact was hidden by run fallback")


def read_json(path: Path) -> object:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("OVERSIZED_INPUT")
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-run-state", action="store_true")
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
        if args.self_test_run_state:
            self_test_unscheduled_run_state()
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