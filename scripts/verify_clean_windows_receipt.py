#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline verifier for R9 CLEAN Windows portable-GUI acceptance receipts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

MAX_RECEIPT_BYTES = 1 << 20
MAX_SIDECAR_BYTES = 4096
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_CLEAN_PATH_CHECKS = frozenset({
    "initial_development_entries_absent",
    "forbidden_toolchain_directories_absent",
    "child_windows_system_only",
    "developer_environment_cleared",
})
REQUIRED_ACCEPTANCE_CHECKS = frozenset({
    "archive_outer_sidecar_match",
    "archive_internal_hashes_match",
    "manifest_and_notices_present",
    "windows_platform_plugin_present",
    "launch_close_relaunch",
    "offline_hidden_self_tests",
    "unicode_space_extraction",
    "no_process_tcp_udp_before_start",
    "firewall_rules_profiles_unchanged",
    "services_unchanged",
    "termservice_unchanged",
    "rdp_policy_port_unchanged",
    "no_install_or_elevation",
})
EVIDENCE_LABELS = {
    "manual-owner-native": "MANUAL CLEAN PASS",
    "self-hosted-clean-runner": "SELF-HOSTED CLEAN PASS",
}
REQUIRED_TOP_LEVEL_FIELDS = frozenset({
    "schema", "status", "gate", "evidence_origin", "acceptance_label",
    "exact_git_sha", "archive", "archive_sha256", "machine",
    "windows_version", "os_architecture", "process_architecture",
    "session_id", "non_admin_interactive", "explorer_session",
    "clean_path", "checks",
})


class ReceiptVerificationError(ValueError):
    """Fail-closed receipt verification error."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ReceiptVerificationError(f"Cannot stat {path}: {error}") from error
    if size <= 0 or size > maximum_bytes:
        raise ReceiptVerificationError(f"Unexpected size for {path.name}: {size}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ReceiptVerificationError(f"Cannot read {path}: {error}") from error


def _load_json_without_duplicates(raw: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReceiptVerificationError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except ReceiptVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptVerificationError(f"Malformed receipt JSON: {error}") from error
    if not isinstance(value, dict):
        raise ReceiptVerificationError("Receipt root must be a JSON object")
    return value


def _verify_sha256_sidecar(target: Path, expected_digest: str) -> None:
    sidecar = Path(f"{target}.sha256")
    raw = _read_bounded(sidecar, MAX_SIDECAR_BYTES)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReceiptVerificationError(f"{sidecar.name} must be ASCII") from error
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\r?\n?", text)
    if match is None:
        raise ReceiptVerificationError(f"Malformed SHA-256 sidecar: {sidecar.name}")
    if match.group(2) != target.name:
        raise ReceiptVerificationError(
            f"SHA-256 sidecar names the wrong file: {sidecar.name}"
        )
    if match.group(1) != expected_digest:
        raise ReceiptVerificationError(
            f"SHA-256 sidecar digest mismatch: {sidecar.name}"
        )


def _require_true_map(
    value: Any,
    expected_keys: frozenset[str],
    field_name: str,
) -> None:
    if not isinstance(value, dict) or frozenset(value) != expected_keys:
        raise ReceiptVerificationError(
            f"{field_name} must contain exactly the v1 required checks"
        )
    if any(check is not True for check in value.values()):
        raise ReceiptVerificationError(f"{field_name} contains a failed check")


def verify_receipt(
    receipt_path: Path,
    archive_path: Path,
    exact_git_sha: str,
) -> tuple[str, str]:
    if GIT_SHA_PATTERN.fullmatch(exact_git_sha) is None:
        raise ReceiptVerificationError("Expected source SHA must be 40 lowercase hex")

    receipt_path = receipt_path.resolve(strict=True)
    archive_path = archive_path.resolve(strict=True)
    receipt_raw = _read_bounded(receipt_path, MAX_RECEIPT_BYTES)
    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
    _verify_sha256_sidecar(receipt_path, receipt_digest)

    receipt = _load_json_without_duplicates(receipt_raw)
    if frozenset(receipt) != REQUIRED_TOP_LEVEL_FIELDS:
        raise ReceiptVerificationError("Receipt fields do not match the v1 CLEAN schema")
    if receipt.get("schema") != "rdp-server-clean-windows-receipt-v1":
        raise ReceiptVerificationError("Unsupported CLEAN receipt schema")
    if receipt.get("status") != "PASS":
        raise ReceiptVerificationError("CLEAN receipt status is not PASS")
    if receipt.get("gate") != "clean-windows-portable-gui":
        raise ReceiptVerificationError("Unexpected CLEAN receipt gate")
    if receipt.get("exact_git_sha") != exact_git_sha:
        raise ReceiptVerificationError("Receipt source SHA does not match expected SHA")

    evidence_origin = receipt.get("evidence_origin")
    acceptance_label = EVIDENCE_LABELS.get(evidence_origin)
    if acceptance_label is None:
        raise ReceiptVerificationError("Unknown CLEAN evidence origin")
    if receipt.get("acceptance_label") != acceptance_label:
        raise ReceiptVerificationError("Receipt evidence label/origin mismatch")

    archive_digest = _sha256_file(archive_path)
    if receipt.get("archive") != archive_path.name:
        raise ReceiptVerificationError("Receipt archive name does not match input ZIP")
    if receipt.get("archive_sha256") != archive_digest:
        raise ReceiptVerificationError("Receipt ZIP SHA-256 does not match input ZIP")
    _verify_sha256_sidecar(archive_path, archive_digest)

    machine_name = receipt.get("machine")
    windows_version = receipt.get("windows_version")
    process_architecture = receipt.get("process_architecture")
    if not isinstance(machine_name, str) or not machine_name.strip():
        raise ReceiptVerificationError("Receipt machine name is absent")
    if not isinstance(windows_version, str) or not windows_version.strip():
        raise ReceiptVerificationError("Receipt Windows version is absent")
    if receipt.get("os_architecture") != "X64":
        raise ReceiptVerificationError("CLEAN evidence must come from x86-64 Windows")
    if not isinstance(process_architecture, str) or not process_architecture.strip():
        raise ReceiptVerificationError("Receipt process architecture is absent")

    session_id = receipt.get("session_id")
    if type(session_id) is not int or session_id <= 0:
        raise ReceiptVerificationError("Receipt interactive session id is invalid")
    if receipt.get("non_admin_interactive") is not True:
        raise ReceiptVerificationError("Receipt is not non-admin interactive evidence")
    if receipt.get("explorer_session") is not True:
        raise ReceiptVerificationError("Receipt lacks same-session Explorer evidence")

    _require_true_map(receipt.get("clean_path"), REQUIRED_CLEAN_PATH_CHECKS, "clean_path")
    _require_true_map(receipt.get("checks"), REQUIRED_ACCEPTANCE_CHECKS, "checks")
    return acceptance_label, receipt_digest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--exact-git-sha", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        label, receipt_digest = verify_receipt(
            args.receipt, args.archive, args.exact_git_sha
        )
    except (OSError, ReceiptVerificationError) as error:
        print(f"R9 CLEAN receipt verification FAILED: {error}", file=sys.stderr)
        return 1
    print(f"R9 CLEAN receipt verified: {label}")
    print(f"receipt_sha256={receipt_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
