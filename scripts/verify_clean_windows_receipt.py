#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline verifier for R9 CLEAN Windows portable-GUI acceptance receipts."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

MAX_RECEIPT_BYTES = 1 << 20
MAX_SIDECAR_BYTES = 4096
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_TOP_LEVEL_FIELDS = frozenset({
    "receipt_format_version",
    "status",
    "gate",
    "evidence_path",
    "execution_origin",
    "acceptance_label",
    "generated_utc",
    "exact_git_sha",
    "archive",
    "archive_sha256",
    "verifier_script_sha256",
    "smoke_script_sha256",
    "machine",
    "user",
    "development_environment",
    "observations",
    "non_admin_interactive",
    "checks",
})
REQUIRED_MACHINE_FIELDS = frozenset({
    "computer_name",
    "windows_caption",
    "windows_version",
    "windows_build",
    "os_architecture",
    "process_architecture",
    "powershell_version",
})
REQUIRED_USER_FIELDS = frozenset({
    "name",
    "session_id",
    "administrator_token_active",
    "interactive_explorer_session",
})
REQUIRED_DEVELOPMENT_ENVIRONMENT_FIELDS = frozenset({
    "path_pattern",
    "process_path_clean",
    "forbidden_directories",
    "forbidden_directories_absent",
})
REQUIRED_OBSERVATION_FIELDS = frozenset({
    "required_files",
    "expected_files_verified",
    "first_window_observed",
    "ordinary_close_observed",
    "relaunch_observed",
    "no_process_tcp_udp_before_start",
    "child_path_windows_system_only",
    "developer_environment_cleared",
    "system_state_before_sha256",
    "system_state_after_sha256",
    "system_state_unchanged",
})

REQUIRED_PORTABLE_FILES = (
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY.md",
    r"metadata\SHA256SUMS.txt",
    r"metadata\DEPENDENCIES.txt",
    r"metadata\PLATFORM-MINIMUMS.json",
    "qt.conf",
    "Qt6Core.dll",
    "Qt6Gui.dll",
    "Qt6Widgets.dll",
    r"plugins\platforms\qwindows.dll",
    "RDP-server-GUI.exe",
)
FORBIDDEN_DEVELOPMENT_DIRECTORIES = (
    r"C:\msys64",
    r"C:\Qt",
    r"C:\Program Files\LLVM",
)
REQUIRED_CHECKS = frozenset({
    "outer-and-inner-sha256",
    "notices-and-manifest",
    "windows-plugin-load",
    "first-window-close-relaunch",
    "hidden-self-tests",
    "unicode-spaces",
    "no-tcp-udp",
    "firewall-unchanged",
    "termservice-unchanged",
    "rdp-policy-unchanged",
    "service-inventory-unchanged",
    "no-install-or-elevation",
    "development-paths-absent",
    "system-only-child-path",
    "receipt-sha256",
})
EVIDENCE_LABELS = {
    "manual-owner-native": "MANUAL CLEAN PASS",
    "self-hosted-clean-runner": "SELF-HOSTED CLEAN PASS",
}


class ReceiptVerificationError(ValueError):
    """Fail-closed receipt verification error."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ReceiptVerificationError(f"Cannot read {path}: {error}") from error
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


def _require_exact_fields(
    value: Any,
    expected_fields: frozenset[str],
    field_name: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != expected_fields:
        raise ReceiptVerificationError(
            f"{field_name} fields do not match CLEAN receipt format 2"
        )
    return value


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReceiptVerificationError(f"{field_name} is absent")
    return value


def _require_sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ReceiptVerificationError(f"{field_name} is not lowercase SHA-256")
    return value


def _verify_sha256_sidecar(target: Path, expected_digest: str) -> None:
    sidecar = Path(f"{target}.sha256")
    raw = _read_bounded(sidecar, MAX_SIDECAR_BYTES)
    try:
        sidecar_text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReceiptVerificationError(f"{sidecar.name} must be ASCII") from error
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\r?\n?", sidecar_text)
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


def _verify_generated_utc(value: Any) -> None:
    generated_utc = _require_nonempty_string(value, "generated_utc")
    try:
        parsed = datetime.fromisoformat(generated_utc.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReceiptVerificationError("generated_utc is not ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReceiptVerificationError("generated_utc must include a UTC offset")
    if parsed.utcoffset().total_seconds() != 0:
        raise ReceiptVerificationError("generated_utc must be UTC")


def _verify_machine(receipt: dict[str, Any]) -> None:
    machine = _require_exact_fields(
        receipt.get("machine"), REQUIRED_MACHINE_FIELDS, "machine"
    )
    for field_name in (
        "computer_name",
        "windows_caption",
        "windows_version",
        "windows_build",
        "os_architecture",
        "process_architecture",
        "powershell_version",
    ):
        _require_nonempty_string(machine.get(field_name), f"machine.{field_name}")
    if machine["os_architecture"] != "X64":
        raise ReceiptVerificationError("CLEAN evidence must come from x86-64 Windows")


def _verify_user(receipt: dict[str, Any]) -> None:
    user = _require_exact_fields(receipt.get("user"), REQUIRED_USER_FIELDS, "user")
    _require_nonempty_string(user.get("name"), "user.name")
    session_id = user.get("session_id")
    if type(session_id) is not int or session_id <= 0:
        raise ReceiptVerificationError("user.session_id must be a positive integer")
    if user.get("administrator_token_active") is not False:
        raise ReceiptVerificationError("CLEAN evidence must be non-admin")
    if user.get("interactive_explorer_session") is not True:
        raise ReceiptVerificationError(
            "CLEAN evidence requires Explorer in the same session"
        )
    if receipt.get("non_admin_interactive") is not True:
        raise ReceiptVerificationError(
            "Receipt lacks non-admin interactive confirmation"
        )


def _verify_development_environment(receipt: dict[str, Any]) -> None:
    development = _require_exact_fields(
        receipt.get("development_environment"),
        REQUIRED_DEVELOPMENT_ENVIRONMENT_FIELDS,
        "development_environment",
    )
    _require_nonempty_string(
        development.get("path_pattern"), "development_environment.path_pattern"
    )
    if development.get("process_path_clean") is not True:
        raise ReceiptVerificationError(
            "Development PATH contamination was not excluded"
        )
    if development.get("forbidden_directories_absent") is not True:
        raise ReceiptVerificationError(
            "Forbidden development directories were not excluded"
        )
    directories = development.get("forbidden_directories")
    if (
        not isinstance(directories, list)
        or tuple(directories) != FORBIDDEN_DEVELOPMENT_DIRECTORIES
    ):
        raise ReceiptVerificationError(
            "Forbidden development directory inventory changed"
        )


def _verify_observations(receipt: dict[str, Any]) -> None:
    observations = _require_exact_fields(
        receipt.get("observations"), REQUIRED_OBSERVATION_FIELDS, "observations"
    )
    required_files = observations.get("required_files")
    if (
        not isinstance(required_files, list)
        or tuple(required_files) != REQUIRED_PORTABLE_FILES
    ):
        raise ReceiptVerificationError("Required portable-file inventory changed")
    for field_name in (
        "expected_files_verified",
        "first_window_observed",
        "ordinary_close_observed",
        "relaunch_observed",
        "no_process_tcp_udp_before_start",
        "child_path_windows_system_only",
        "developer_environment_cleared",
        "system_state_unchanged",
    ):
        if observations.get(field_name) is not True:
            raise ReceiptVerificationError(f"observations.{field_name} is not true")

    before_digest = _require_sha256(
        observations.get("system_state_before_sha256"),
        "observations.system_state_before_sha256",
    )
    after_digest = _require_sha256(
        observations.get("system_state_after_sha256"),
        "observations.system_state_after_sha256",
    )
    if before_digest != after_digest:
        raise ReceiptVerificationError("Windows safety-state hashes changed")


def _verify_checks(receipt: dict[str, Any]) -> None:
    checks = receipt.get("checks")
    if (
        not isinstance(checks, list)
        or any(not isinstance(item, str) for item in checks)
    ):
        raise ReceiptVerificationError("checks must be a JSON string array")
    if len(checks) != len(set(checks)) or frozenset(checks) != REQUIRED_CHECKS:
        raise ReceiptVerificationError(
            "checks do not match the required CLEAN set"
        )


def verify_receipt(
    receipt_path: Path,
    archive_path: Path,
    exact_git_sha: str,
    clean_script_path: Path | None = None,
    smoke_script_path: Path | None = None,
) -> tuple[str, str]:
    if GIT_SHA_PATTERN.fullmatch(exact_git_sha) is None:
        raise ReceiptVerificationError(
            "Expected source SHA must be 40 lowercase hex"
        )

    receipt_path = receipt_path.resolve(strict=True)
    archive_path = archive_path.resolve(strict=True)
    script_directory = Path(__file__).resolve().parent
    if clean_script_path is None:
        clean_script_path = script_directory / "clean_windows_portable_gui.ps1"
    if smoke_script_path is None:
        smoke_script_path = script_directory / "smoke_windows_portable_gui.ps1"
    clean_script_path = clean_script_path.resolve(strict=True)
    smoke_script_path = smoke_script_path.resolve(strict=True)

    receipt_raw = _read_bounded(receipt_path, MAX_RECEIPT_BYTES)
    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
    _verify_sha256_sidecar(receipt_path, receipt_digest)
    receipt = _load_json_without_duplicates(receipt_raw)

    if frozenset(receipt) != REQUIRED_TOP_LEVEL_FIELDS:
        raise ReceiptVerificationError(
            "Receipt fields do not match CLEAN receipt format 2"
        )
    if receipt.get("receipt_format_version") != 2:
        raise ReceiptVerificationError("Unsupported CLEAN receipt format")
    if receipt.get("status") != "PASS":
        raise ReceiptVerificationError("CLEAN receipt status is not PASS")
    if receipt.get("gate") != "clean-windows-portable-gui":
        raise ReceiptVerificationError("Unexpected CLEAN receipt gate")
    if receipt.get("evidence_path") != "manual-or-self-hosted-clean-windows":
        raise ReceiptVerificationError("Unexpected CLEAN evidence path")
    if receipt.get("exact_git_sha") != exact_git_sha:
        raise ReceiptVerificationError(
            "Receipt source SHA does not match expected SHA"
        )
    _verify_generated_utc(receipt.get("generated_utc"))

    execution_origin = receipt.get("execution_origin")
    acceptance_label = EVIDENCE_LABELS.get(execution_origin)
    if acceptance_label is None:
        raise ReceiptVerificationError("Unknown CLEAN execution origin")
    if receipt.get("acceptance_label") != acceptance_label:
        raise ReceiptVerificationError("Receipt evidence label/origin mismatch")

    archive_digest = _sha256_file(archive_path)
    if receipt.get("archive") != archive_path.name:
        raise ReceiptVerificationError(
            "Receipt archive name does not match input ZIP"
        )
    if receipt.get("archive_sha256") != archive_digest:
        raise ReceiptVerificationError(
            "Receipt ZIP SHA-256 does not match input ZIP"
        )
    _verify_sha256_sidecar(archive_path, archive_digest)

    if receipt.get("verifier_script_sha256") != _sha256_file(clean_script_path):
        raise ReceiptVerificationError(
            "Receipt CLEAN script SHA-256 does not match source"
        )
    if receipt.get("smoke_script_sha256") != _sha256_file(smoke_script_path):
        raise ReceiptVerificationError(
            "Receipt smoke script SHA-256 does not match source"
        )

    _verify_machine(receipt)
    _verify_user(receipt)
    _verify_development_environment(receipt)
    _verify_observations(receipt)
    _verify_checks(receipt)
    return acceptance_label, receipt_digest


def _parse_args() -> argparse.Namespace:
    script_directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--exact-git-sha", required=True)
    parser.add_argument(
        "--clean-script",
        type=Path,
        default=script_directory / "clean_windows_portable_gui.ps1",
    )
    parser.add_argument(
        "--smoke-script",
        type=Path,
        default=script_directory / "smoke_windows_portable_gui.ps1",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        label, receipt_digest = verify_receipt(
            args.receipt,
            args.archive,
            args.exact_git_sha,
            args.clean_script,
            args.smoke_script,
        )
    except (OSError, ReceiptVerificationError) as error:
        print(
            f"R9 CLEAN receipt verification FAILED: {error}",
            file=sys.stderr,
        )
        return 1
    print(f"R9 CLEAN receipt verified: {label}")
    print(f"receipt_sha256={receipt_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
