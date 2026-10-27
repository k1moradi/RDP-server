# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only manifest helper for a macOS Windows App owner evidence attempt.

The helper never changes Keychain, trust settings, Windows App preferences, or
the supplied log directory. It reads the explicitly supplied .app Info.plist,
inventories existing files in an explicitly supplied log directory, hashes
their bytes, and writes one JSON manifest to stdout. It intentionally has no
password input: credential evidence records state and matching intent only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import platform
import re
import sys

MAX_LOG_FILES = 256
MAX_TOTAL_LOG_BYTES = 512 * 1024 * 1024
MAX_TEXT_BYTES = 4096
_HASH_CHUNK_BYTES = 1024 * 1024
_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_NOT_APPLICABLE = "not-applicable"


def _bounded_text(value: str, name: str) -> str:
    encoded = value.encode("utf-8")
    if not value or len(encoded) > MAX_TEXT_BYTES:
        raise ValueError(f"{name} must contain 1..{MAX_TEXT_BYTES} UTF-8 bytes")
    return value


def _validated_server_sha(value: str) -> str:
    if _SHA40.fullmatch(value) is None:
        raise ValueError("server SHA must be exactly 40 hexadecimal characters")
    return value.lower()


def _validated_attempt_time(value: str, name: str = "attempt time") -> tuple[str, str]:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include an explicit UTC offset")
    return parsed.isoformat(), parsed.astimezone(timezone.utc).isoformat()


def _read_app_metadata(app_path: Path) -> dict[str, str]:
    info_path = app_path / "Contents" / "Info.plist"
    if app_path.suffix != ".app" or not app_path.is_dir():
        raise ValueError("app path must name an existing .app bundle")
    if info_path.is_symlink() or not info_path.is_file():
        raise ValueError("app bundle must contain a regular Contents/Info.plist")
    with info_path.open("rb") as stream:
        info = plistlib.load(stream)

    version = info.get("CFBundleShortVersionString")
    build = info.get("CFBundleVersion")
    bundle_identifier = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    required = {
        "version": version,
        "build": build,
        "bundle_identifier": bundle_identifier,
        "executable": executable,
    }
    for name, value in required.items():
        if not isinstance(value, str) or not value:
            raise ValueError(f"Info.plist missing non-empty {name}")
        _bounded_text(value, f"Info.plist {name}")
    return required


def _hash_regular_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _inventory_log_directory(log_directory: Path) -> tuple[list[dict[str, object]], int]:
    if log_directory.is_symlink() or not log_directory.is_dir():
        raise ValueError("log directory must be an existing non-symlink directory")

    entries: list[dict[str, object]] = []
    total_bytes = 0
    for candidate in sorted(log_directory.rglob("*")):
        if candidate.is_symlink():
            raise ValueError(f"log directory contains symlink: {candidate}")
        if not candidate.is_file():
            continue

        relative = candidate.relative_to(log_directory).as_posix()
        size = candidate.stat().st_size
        total_bytes += size
        if len(entries) >= MAX_LOG_FILES:
            raise ValueError(f"log directory exceeds {MAX_LOG_FILES} regular files")
        if total_bytes > MAX_TOTAL_LOG_BYTES:
            raise ValueError(
                f"log directory exceeds {MAX_TOTAL_LOG_BYTES} total bytes"
            )
        entries.append(
            {
                "path": relative,
                "bytes": size,
                "sha256": _hash_regular_file(candidate),
            }
        )

    if not entries:
        raise ValueError("log directory contains no regular files")
    return entries, total_bytes


def _validated_saved_credential(options: argparse.Namespace) -> dict[str, object]:
    state = options.saved_credential_state
    username = options.saved_credential_username
    newly_created = options.saved_credential_newly_created
    intentionally_matched = options.server_client_credentials_intentionally_matched

    if state == "explicit-saved-selected":
        if username == _NOT_APPLICABLE:
            raise ValueError(
                "saved credential username is required when an explicit saved credential is selected"
            )
        if newly_created == _NOT_APPLICABLE:
            raise ValueError(
                "saved credential newly-created state must be yes or no for an explicit saved credential"
            )
        if intentionally_matched == _NOT_APPLICABLE:
            raise ValueError(
                "server/client credential match state must be yes or no for an explicit saved credential"
            )
        username_exact: str | None = _bounded_text(
            username, "saved credential username"
        )
    elif state == "ask-when-required-or-none":
        if username != _NOT_APPLICABLE:
            raise ValueError(
                "saved credential username must be not-applicable when no saved credential is selected"
            )
        if newly_created != _NOT_APPLICABLE:
            raise ValueError(
                "saved credential newly-created state must be not-applicable when no saved credential is selected"
            )
        if intentionally_matched != _NOT_APPLICABLE:
            raise ValueError(
                "server/client credential match state must be not-applicable when no saved credential is selected"
            )
        username_exact = None
    else:
        username_exact = (
            None
            if username == _NOT_APPLICABLE
            else _bounded_text(username, "saved credential username")
        )

    return {
        "state": state,
        "username_exact": username_exact,
        "newly_created_for_attempt": newly_created,
        "server_client_credentials_intentionally_matched": intentionally_matched,
    }


def build_manifest(options: argparse.Namespace) -> dict[str, object]:
    warning_shown = options.certificate_warning == "yes"
    if warning_shown and options.certificate_warning_accepted == _NOT_APPLICABLE:
        raise ValueError("warning acceptance must be yes or no when a warning appeared")
    if not warning_shown and options.certificate_warning_accepted != _NOT_APPLICABLE:
        raise ValueError("warning acceptance must be not-applicable when no warning appeared")

    if (options.logs is None) == (options.logs_unavailable_reason is None):
        raise ValueError("provide exactly one of --logs or --logs-unavailable-reason")

    attempt_local, attempt_utc = _validated_attempt_time(options.attempt_time)
    linux_local, linux_utc = _validated_attempt_time(
        options.linux_terminal_time, "Linux terminal time"
    )
    app_metadata = _read_app_metadata(options.app)

    logs: dict[str, object]
    if options.logs is not None:
        files, total_bytes = _inventory_log_directory(options.logs)
        logs = {
            "available": True,
            "files": files,
            "file_count": len(files),
            "total_bytes": total_bytes,
        }
    else:
        logs = {
            "available": False,
            "reason": _bounded_text(
                options.logs_unavailable_reason, "logs unavailable reason"
            ),
        }

    return {
        "schema": "rdp-server.macos-windows-app-owner-evidence.v2",
        "server_sha": _validated_server_sha(options.server_sha),
        "attempt_time_local": attempt_local,
        "attempt_time_utc": attempt_utc,
        "destination_exact": _bounded_text(options.destination, "destination"),
        "saved_credential": _validated_saved_credential(options),
        "certificate_warning": {
            "appeared": warning_shown,
            "accepted": options.certificate_warning_accepted,
        },
        "client_error_text_exact": _bounded_text(
            options.error_text, "client error text"
        ),
        "windows_app": app_metadata,
        "logging": {
            "core_level": _bounded_text(options.core_log_level, "core log level"),
            "ui_level": _bounded_text(options.ui_log_level, "UI log level"),
            "started_before_attempt": options.logging_started == "yes",
            "stopped_after_attempt": options.logging_stopped == "yes",
            **logs,
        },
        "linux_correlation": {
            "connection_id": _bounded_text(
                options.linux_connection_id, "Linux connection ID"
            ),
            "terminal_time_local": linux_local,
            "terminal_time_utc": linux_utc,
        },
        "collector": {
            "mode": "read-only",
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Emit a read-only macOS Windows App physical-attempt evidence manifest"
        )
    )
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--server-sha", required=True)
    parser.add_argument("--attempt-time", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument(
        "--saved-credential-state",
        choices=("explicit-saved-selected", "ask-when-required-or-none", "other"),
        required=True,
    )
    parser.add_argument("--saved-credential-username", required=True)
    parser.add_argument(
        "--saved-credential-newly-created",
        choices=("yes", "no", _NOT_APPLICABLE),
        required=True,
    )
    parser.add_argument(
        "--server-client-credentials-intentionally-matched",
        choices=("yes", "no", _NOT_APPLICABLE),
        required=True,
    )
    parser.add_argument("--certificate-warning", choices=("yes", "no"), required=True)
    parser.add_argument(
        "--certificate-warning-accepted",
        choices=("yes", "no", _NOT_APPLICABLE),
        required=True,
    )
    parser.add_argument("--error-text", required=True)
    parser.add_argument("--core-log-level", required=True)
    parser.add_argument("--ui-log-level", required=True)
    parser.add_argument("--logging-started", choices=("yes", "no"), required=True)
    parser.add_argument("--logging-stopped", choices=("yes", "no"), required=True)
    parser.add_argument("--linux-connection-id", required=True)
    parser.add_argument("--linux-terminal-time", required=True)
    logs = parser.add_mutually_exclusive_group(required=True)
    logs.add_argument("--logs", type=Path)
    logs.add_argument("--logs-unavailable-reason")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        manifest = build_manifest(parse_args(argv))
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        print(f"macOS Windows App evidence manifest: {exc}", file=sys.stderr)
        return 2
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
