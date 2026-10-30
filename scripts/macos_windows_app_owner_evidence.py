# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only manifest helper for a macOS Windows App owner evidence attempt.

The helper never changes Keychain, trust settings, Windows App preferences, or
the supplied log directory. It reads the explicitly supplied .app Info.plist,
inventories existing files in an explicitly supplied log directory, hashes
their bytes, and writes one private JSON manifest to stdout. A separate
validate mode reads that private manifest and emits a redacted diagnostic
summary suitable for R2/R6 without usernames, exact UI text, log paths/hashes,
or Linux connection identifiers.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import plistlib
import platform
import re
import sys

MAX_LOG_FILES = 256
MAX_TOTAL_LOG_BYTES = 512 * 1024 * 1024
MAX_TEXT_BYTES = 4096
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CORRELATION_DELTA_SECONDS = 120.0
_HASH_CHUNK_BYTES = 1024 * 1024
_SHA40 = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_NOT_APPLICABLE = "not-applicable"
_NOT_RECORDED = "not-recorded"
_NOT_OBSERVED = "not-observed"
_STAGE_VALUES = ("PASS", "FAIL", "NOT_REACHED", "NOT_RECORDED")
_FIRST_ERROR_CATEGORIES = (
    "credential",
    "trust",
    "negotiation",
    "cancellation",
    "transport",
    "unknown",
    _NOT_OBSERVED,
)
_FIRST_ERROR_SOURCES = ("core", "ui", "ui-error", "core-and-ui", _NOT_OBSERVED)


def _bounded_text(value: str, name: str) -> str:
    encoded = value.encode("utf-8")
    if not value or len(encoded) > MAX_TEXT_BYTES:
        raise ValueError(f"{name} must contain 1..{MAX_TEXT_BYTES} UTF-8 bytes")
    return value


def _validated_server_sha(value: str) -> str:
    if _SHA40.fullmatch(value) is None:
        raise ValueError("server SHA must be exactly 40 hexadecimal characters")
    return value.lower()


def _validated_certificate_sha256(value: str | None) -> str | None:
    if value is None or value == _NOT_RECORDED:
        return None
    normalized = value.replace(":", "").replace(" ", "")
    if _SHA256.fullmatch(normalized) is None:
        raise ValueError(
            "server certificate SHA-256 must contain exactly 64 hexadecimal characters"
        )
    return normalized.lower()


def _validated_attempt_time(value: str, name: str = "attempt time") -> tuple[str, str]:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include an explicit UTC offset")
    return parsed.isoformat(), parsed.astimezone(timezone.utc).isoformat()


def _validated_optional_time(value: str | None, name: str) -> tuple[str, str] | None:
    if value is None or value == _NOT_OBSERVED:
        return None
    return _validated_attempt_time(value, name)


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


def _validated_first_client_error(options: argparse.Namespace) -> dict[str, object]:
    category = options.first_client_error_category
    source = options.first_client_error_source
    provider_category = options.first_client_provider_category
    provider_code = options.first_client_provider_code
    event_time = _validated_optional_time(
        options.first_client_error_time, "first client error time"
    )

    if category == _NOT_OBSERVED:
        if source != _NOT_OBSERVED:
            raise ValueError(
                "first client error source must be not-observed when no typed error was observed"
            )
        if provider_category is not None or provider_code is not None or event_time is not None:
            raise ValueError(
                "provider category/code/time must be absent when no typed client error was observed"
            )
    else:
        if source == _NOT_OBSERVED:
            raise ValueError(
                "first client error source is required when a typed/unknown client error is recorded"
            )
        if category not in ("unknown", _NOT_OBSERVED) and provider_category is None:
            raise ValueError(
                "a specific first client error category requires the exact private provider category"
            )

    return {
        "normalized_category": category,
        "source": source,
        "provider_category_exact": (
            None
            if provider_category is None
            else _bounded_text(provider_category, "first client provider category")
        ),
        "provider_code_exact": (
            None
            if provider_code is None
            else _bounded_text(provider_code, "first client provider code")
        ),
        "event_time_local": None if event_time is None else event_time[0],
        "event_time_utc": None if event_time is None else event_time[1],
    }


def _validated_u64(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    if value < 0 or value > ((1 << 64) - 1):
        raise ValueError(f"{name} must be in 0..18446744073709551615")
    return value


def _validated_service_timing(
    options: argparse.Namespace, prefix: str, display_name: str
) -> dict[str, int | None]:
    return {
        "application_reschedule_wait_microseconds": _validated_u64(
            getattr(options, f"{prefix}_app_wait_us"),
            f"{display_name} application-reschedule wait",
        ),
        "peer_readiness_wait_upper_bound_microseconds": _validated_u64(
            getattr(options, f"{prefix}_peer_wait_upper_us"),
            f"{display_name} peer-readiness wait upper bound",
        ),
        "service_execution_microseconds": _validated_u64(
            getattr(options, f"{prefix}_service_work_us"),
            f"{display_name} service work",
        ),
        "native_maintenance_microseconds": _validated_u64(
            getattr(options, f"{prefix}_native_maintenance_us"),
            f"{display_name} native maintenance",
        ),
        "service_invocations": _validated_u64(
            getattr(options, f"{prefix}_service_calls"),
            f"{display_name} service calls",
        ),
        "maximum_application_reschedule_wait_microseconds": _validated_u64(
            getattr(options, f"{prefix}_max_app_gap_us"),
            f"{display_name} maximum application gap",
        ),
    }


def _validated_server_timing_attribution(
    options: argparse.Namespace,
) -> dict[str, object]:
    return {
        "accepted_to_tls_microseconds": _validated_u64(
            options.accepted_to_tls_us, "accepted-to-TLS duration"
        ),
        "tls_to_type1_microseconds": _validated_u64(
            options.tls_to_type1_us, "TLS-to-Type-1 duration"
        ),
        "type1_to_type2_queued_microseconds": _validated_u64(
            options.type1_to_type2_queued_us, "Type-1-to-Type-2 queue duration"
        ),
        "type2_creation_to_delivery_microseconds": _validated_u64(
            options.type2_creation_to_delivery_us,
            "Type-2 creation-to-delivery duration",
        ),
        "type2_to_peer_eof_microseconds": _validated_u64(
            options.type2_to_peer_eof_us, "Type-2-to-peer-EOF duration"
        ),
        "preauth_elapsed_at_peer_eof_microseconds": _validated_u64(
            options.preauth_elapsed_at_peer_eof_us,
            "pre-auth elapsed-at-peer-EOF duration",
        ),
        "post_type2_first_client_tls_byte_microseconds": _validated_u64(
            options.post_type2_first_client_tls_byte_us,
            "post-Type-2 first client TLS byte duration",
        ),
        "pre_tls": {
            "read_wait_microseconds": _validated_u64(
                options.pre_tls_read_wait_us, "pre-TLS read wait"
            ),
            "write_wait_microseconds": _validated_u64(
                options.pre_tls_write_wait_us, "pre-TLS write wait"
            ),
            "active_work_microseconds": _validated_u64(
                options.pre_tls_active_work_us, "pre-TLS active work"
            ),
            "tls_handshake_active_work_microseconds": _validated_u64(
                options.tls_handshake_active_work_us,
                "TLS handshake active work",
            ),
            "unattributed_microseconds": _validated_u64(
                options.pre_tls_unattributed_us, "pre-TLS unattributed time"
            ),
            "socket_poll_microseconds": _validated_u64(
                options.pre_tls_socket_poll_us, "pre-TLS socket poll"
            ),
            "read_ready_to_service_microseconds": _validated_u64(
                options.pre_tls_read_ready_to_service_us,
                "pre-TLS read ready-to-service time",
            ),
            "write_ready_to_service_microseconds": _validated_u64(
                options.pre_tls_write_ready_to_service_us,
                "pre-TLS write ready-to-service time",
            ),
        },
        "accepted_to_tls_service": _validated_service_timing(
            options, "accepted_to_tls", "accepted-to-TLS"
        ),
        "tls_to_type1_service": _validated_service_timing(
            options, "tls_to_type1", "TLS-to-Type-1"
        ),
    }


def _validated_server_stage_matrix(options: argparse.Namespace) -> dict[str, object]:
    post_type_two_bytes = options.post_type2_client_bytes
    if post_type_two_bytes is not None and not 0 <= post_type_two_bytes <= (1 << 30):
        raise ValueError("post-Type-2 client bytes must be in 0..1073741824")
    terminal_outcome = options.typed_terminal_outcome
    return {
        "tls_established": options.stage_tls_established,
        "type1_received": options.stage_type1_received,
        "type2_fully_committed": options.stage_type2_committed,
        "post_type2_client_bytes": post_type_two_bytes,
        "type3_received": options.stage_type3_received,
        "pubkeyauth_reached": options.stage_pubkeyauth_reached,
        "authinfo_reached": options.stage_authinfo_reached,
        "credentials_verified": options.stage_credentials_verified,
        "typed_terminal_outcome": (
            None
            if terminal_outcome == _NOT_RECORDED
            else _bounded_text(terminal_outcome, "typed terminal outcome")
        ),
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

    ui_error_code = options.client_error_code
    if ui_error_code == _NOT_RECORDED:
        ui_error_code = None
    elif ui_error_code is not None:
        ui_error_code = _bounded_text(ui_error_code, "client error code")

    return {
        "schema": "rdp-server.macos-windows-app-owner-evidence.v2",
        "server_sha": _validated_server_sha(options.server_sha),
        "server_certificate_sha256": _validated_certificate_sha256(
            options.server_certificate_sha256
        ),
        "attempt_time_local": attempt_local,
        "attempt_time_utc": attempt_utc,
        "destination_exact": _bounded_text(options.destination, "destination"),
        "saved_credential": _validated_saved_credential(options),
        "certificate_warning": {
            "appeared": warning_shown,
            "accepted": options.certificate_warning_accepted,
        },
        # Kept for schema-v2 compatibility. This exact text stays in the private
        # manifest and is deliberately omitted from the redacted summary.
        "client_error_text_exact": _bounded_text(
            options.error_text, "client error text"
        ),
        "client_error_code": ui_error_code,
        "first_client_error": _validated_first_client_error(options),
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
        "server_stage_matrix": _validated_server_stage_matrix(options),
        "server_timing_attribution": _validated_server_timing_attribution(options),
        "collector": {
            "mode": "read-only",
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
        },
    }


def _parse_utc(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def _destination_digest(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stage_matrix_failures(stage_matrix: object) -> list[str]:
    if not isinstance(stage_matrix, dict):
        return ["SERVER_STAGE_MATRIX_INCOMPLETE"]

    stage_names = (
        "tls_established",
        "type1_received",
        "type2_fully_committed",
        "type3_received",
        "pubkeyauth_reached",
        "authinfo_reached",
        "credentials_verified",
    )
    stages: dict[str, str] = {}
    for name in stage_names:
        value = stage_matrix.get(name)
        if value not in _STAGE_VALUES:
            return ["SERVER_STAGE_MATRIX_INCOMPLETE"]
        stages[name] = value

    if any(value == "NOT_RECORDED" for value in stages.values()):
        return ["SERVER_STAGE_MATRIX_INCOMPLETE"]
    if stage_matrix.get("post_type2_client_bytes") is None or not isinstance(
        stage_matrix.get("typed_terminal_outcome"), str
    ):
        return ["SERVER_STAGE_MATRIX_INCOMPLETE"]

    order = [
        "tls_established",
        "type1_received",
        "type2_fully_committed",
        "type3_received",
        "pubkeyauth_reached",
        "authinfo_reached",
        "credentials_verified",
    ]
    reached = False
    for index in range(len(order) - 1, -1, -1):
        if stages[order[index]] == "PASS":
            reached = True
        if reached and index > 0 and stages[order[index - 1]] != "PASS":
            return ["SERVER_STAGE_MATRIX_INCONSISTENT"]

    if stages["type2_fully_committed"] != "PASS" and stage_matrix.get(
        "post_type2_client_bytes"
    ) not in (None, 0):
        return ["SERVER_STAGE_MATRIX_INCONSISTENT"]
    return []


_TIMING_REQUIRED_TOP = (
    "accepted_to_tls_microseconds",
    "tls_to_type1_microseconds",
    "type1_to_type2_queued_microseconds",
    "type2_creation_to_delivery_microseconds",
    "type2_to_peer_eof_microseconds",
    "preauth_elapsed_at_peer_eof_microseconds",
)
_TIMING_PRE_TLS_NAMES = (
    "read_wait_microseconds",
    "write_wait_microseconds",
    "active_work_microseconds",
    "tls_handshake_active_work_microseconds",
    "unattributed_microseconds",
    "socket_poll_microseconds",
    "read_ready_to_service_microseconds",
    "write_ready_to_service_microseconds",
)
_TIMING_SERVICE_NAMES = (
    "application_reschedule_wait_microseconds",
    "peer_readiness_wait_upper_bound_microseconds",
    "service_execution_microseconds",
    "native_maintenance_microseconds",
    "service_invocations",
    "maximum_application_reschedule_wait_microseconds",
)



def _is_u64(value: object) -> bool:
    # Private JSON is not necessarily produced by this collector; bool is not
    # a valid timing scalar even though Python treats it as an int.
    return type(value) is int and 0 <= value <= ((1 << 64) - 1)


def _redacted_stage_matrix(stage_matrix: object) -> dict[str, object]:
    if not isinstance(stage_matrix, dict):
        return {}
    stage_names = (
        "tls_established",
        "type1_received",
        "type2_fully_committed",
        "type3_received",
        "pubkeyauth_reached",
        "authinfo_reached",
        "credentials_verified",
    )
    redacted = {
        name: stage_matrix.get(name)
        if stage_matrix.get(name) in _STAGE_VALUES
        else _NOT_RECORDED
        for name in stage_names
    }
    byte_count = stage_matrix.get("post_type2_client_bytes")
    redacted["post_type2_client_bytes"] = (
        byte_count if _is_u64(byte_count) and byte_count <= (1 << 30) else None
    )
    outcome = stage_matrix.get("typed_terminal_outcome")
    redacted["typed_terminal_outcome"] = (
        outcome
        if isinstance(outcome, str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,63}", outcome)
        else None
    )
    return redacted


def _redacted_server_timing_attribution(timing: object) -> dict[str, object]:
    if not isinstance(timing, dict):
        return {}
    # Project the documented scalars only. Never serialize an entire private
    # JSON object: an injected field may contain a username, path or raw log.
    redacted: dict[str, object] = {
        name: timing.get(name) if _is_u64(timing.get(name)) else None
        for name in _TIMING_REQUIRED_TOP
    }
    first_client_byte = timing.get("post_type2_first_client_tls_byte_microseconds")
    redacted["post_type2_first_client_tls_byte_microseconds"] = (
        first_client_byte if _is_u64(first_client_byte) else None
    )
    for group_name, field_names in (
        ("pre_tls", _TIMING_PRE_TLS_NAMES),
        ("accepted_to_tls_service", _TIMING_SERVICE_NAMES),
        ("tls_to_type1_service", _TIMING_SERVICE_NAMES),
    ):
        group = timing.get(group_name)
        redacted[group_name] = (
            {
                name: group.get(name) if _is_u64(group.get(name)) else None
                for name in field_names
            }
            if isinstance(group, dict)
            else {}
        )
    return redacted


def _timing_attribution_failures(
    timing: object, post_type2_client_bytes: object
) -> tuple[list[str], list[str], dict[str, object]]:
    if not isinstance(timing, dict):
        return ["SERVER_TIMING_ATTRIBUTION_INCOMPLETE"], [], {}

    required_top = _TIMING_REQUIRED_TOP
    pre_tls_names = _TIMING_PRE_TLS_NAMES
    service_names = _TIMING_SERVICE_NAMES

    if any(not _is_u64(timing.get(name)) for name in required_top):
        return ["SERVER_TIMING_ATTRIBUTION_INCOMPLETE"], [], timing

    pre_tls = timing.get("pre_tls")
    accepted_service = timing.get("accepted_to_tls_service")
    type1_service = timing.get("tls_to_type1_service")
    if (
        not isinstance(pre_tls, dict)
        or not isinstance(accepted_service, dict)
        or not isinstance(type1_service, dict)
        or any(not _is_u64(pre_tls.get(name)) for name in pre_tls_names)
        or any(
            not _is_u64(accepted_service.get(name)) for name in service_names
        )
        or any(not _is_u64(type1_service.get(name)) for name in service_names)
    ):
        return ["SERVER_TIMING_ATTRIBUTION_INCOMPLETE"], [], timing

    failures: list[str] = []
    findings: list[str] = []
    first_client_byte = timing.get(
        "post_type2_first_client_tls_byte_microseconds"
    )
    if first_client_byte is not None and not _is_u64(first_client_byte):
        failures.append("SERVER_TIMING_ATTRIBUTION_INCOMPLETE")
    if post_type2_client_bytes == 0 and first_client_byte is not None:
        failures.append("SERVER_TIMING_ATTRIBUTION_INCONSISTENT")
    if isinstance(post_type2_client_bytes, int) and post_type2_client_bytes > 0:
        if first_client_byte is None:
            failures.append("SERVER_TIMING_ATTRIBUTION_INCOMPLETE")

    peer_eof = timing["preauth_elapsed_at_peer_eof_microseconds"]
    if (
        timing["type2_creation_to_delivery_microseconds"] > peer_eof
        or timing["type2_to_peer_eof_microseconds"] > peer_eof
    ):
        failures.append("SERVER_TIMING_ATTRIBUTION_INCONSISTENT")

    # These are measured subsets, not independent additive totals. A smaller
    # elapsed bucket cannot contain a larger child observation.
    if (
        pre_tls["tls_handshake_active_work_microseconds"]
        > pre_tls["active_work_microseconds"]
        or pre_tls["read_ready_to_service_microseconds"]
        > pre_tls["read_wait_microseconds"]
        or pre_tls["write_ready_to_service_microseconds"]
        > pre_tls["write_wait_microseconds"]
        or pre_tls["socket_poll_microseconds"]
        > pre_tls["read_wait_microseconds"] + pre_tls["write_wait_microseconds"]
        or any(
            service["native_maintenance_microseconds"]
            > service["service_execution_microseconds"]
            or service["maximum_application_reschedule_wait_microseconds"]
            > service["application_reschedule_wait_microseconds"]
            for service in (accepted_service, type1_service)
        )
    ):
        failures.append("SERVER_TIMING_ATTRIBUTION_INCONSISTENT")

    accepted_native = accepted_service["native_maintenance_microseconds"]
    type1_native = type1_service["native_maintenance_microseconds"]
    if accepted_native != 0 or type1_native != 0:
        findings.append("EARLY_NATIVE_MAINTENANCE_OBSERVED")

    isolation = {
        "accepted_to_tls_native_maintenance_zero": accepted_native == 0,
        "tls_to_type1_native_maintenance_zero": type1_native == 0,
        "qualified": accepted_native == 0 and type1_native == 0,
    }
    return list(dict.fromkeys(failures)), findings, isolation


def _pair_failures(
    manifest: dict[str, object], pair: argparse.Namespace | None
) -> tuple[list[str], dict[str, object]]:
    if pair is None:
        return [], {"supplied": False}

    values = (
        pair.peer_server_sha,
        pair.peer_destination,
        pair.peer_certificate_sha256,
        pair.peer_username,
        pair.peer_session_password_matched,
        pair.peer_certificate_warning,
        pair.peer_certificate_warning_accepted,
    )
    if any(value is None for value in values):
        return ["PAIR_COMPARISON_INPUT_INCOMPLETE"], {
            "supplied": True,
            "valid": False,
        }

    peer_sha = _validated_server_sha(pair.peer_server_sha)
    peer_fingerprint = _validated_certificate_sha256(
        pair.peer_certificate_sha256
    )
    if peer_fingerprint is None:
        raise ValueError("peer certificate fingerprint is required")

    warning_shown = pair.peer_certificate_warning == "yes"
    if warning_shown and pair.peer_certificate_warning_accepted == _NOT_APPLICABLE:
        raise ValueError(
            "peer warning acceptance must be yes or no when a warning appeared"
        )
    if not warning_shown and pair.peer_certificate_warning_accepted != _NOT_APPLICABLE:
        raise ValueError(
            "peer warning acceptance must be not-applicable when no warning appeared"
        )

    saved = manifest.get("saved_credential")
    local_warning = manifest.get("certificate_warning")
    local_username = saved.get("username_exact") if isinstance(saved, dict) else None
    local_credential_valid = (
        isinstance(saved, dict)
        and saved.get("state") == "explicit-saved-selected"
        and saved.get("server_client_credentials_intentionally_matched") == "yes"
        and isinstance(local_username, str)
        and local_username == pair.peer_username
        and pair.peer_session_password_matched == "yes"
    )
    local_warning_shown = (
        local_warning.get("appeared") if isinstance(local_warning, dict) else None
    )
    local_warning_accepted = (
        local_warning.get("accepted") if isinstance(local_warning, dict) else None
    )
    certificate_decision_comparable = (
        isinstance(local_warning_shown, bool)
        and local_warning_shown == warning_shown
        and (
            not warning_shown
            or local_warning_accepted == pair.peer_certificate_warning_accepted
        )
    )

    checks = {
        "server_sha_match": manifest.get("server_sha") == peer_sha,
        "destination_match": manifest.get("destination_exact") == pair.peer_destination,
        "certificate_fingerprint_match": (
            manifest.get("server_certificate_sha256") == peer_fingerprint
        ),
        "credential_control_valid": local_credential_valid,
        "certificate_decision_comparable": certificate_decision_comparable,
    }
    failures: list[str] = []
    if not checks["server_sha_match"]:
        failures.append("AB_SERVER_SHA_MISMATCH")
    if not checks["destination_match"]:
        failures.append("AB_DESTINATION_MISMATCH")
    if not checks["certificate_fingerprint_match"]:
        failures.append("AB_CERTIFICATE_FINGERPRINT_MISMATCH")
    if not checks["credential_control_valid"]:
        failures.append("AB_INVALID_CREDENTIAL_CONTROL")
    if not checks["certificate_decision_comparable"]:
        failures.append("CERTIFICATE_DECISION_NOT_COMPARABLE")
    return failures, {"supplied": True, "valid": not failures, **checks}


def build_redacted_summary(
    manifest: dict[str, object], pair: argparse.Namespace | None = None
) -> dict[str, object]:
    failures: list[str] = []
    limitations: list[str] = []

    if manifest.get("schema") != "rdp-server.macos-windows-app-owner-evidence.v2":
        failures.append("MANIFEST_SCHEMA_UNSUPPORTED")

    try:
        server_sha = _validated_server_sha(str(manifest.get("server_sha", "")))
    except ValueError:
        server_sha = None
        failures.append("SERVER_SHA_INVALID")

    try:
        fingerprint = _validated_certificate_sha256(
            manifest.get("server_certificate_sha256")
            if isinstance(manifest.get("server_certificate_sha256"), str)
            else None
        )
    except ValueError:
        fingerprint = None
        failures.append("SERVER_CERTIFICATE_FINGERPRINT_INVALID")
    if fingerprint is None:
        failures.append("SERVER_CERTIFICATE_FINGERPRINT_MISSING")

    destination = manifest.get("destination_exact")
    destination_digest = _destination_digest(destination)
    if destination_digest is None:
        failures.append("DESTINATION_MISSING")
    else:
        try:
            ipaddress.ip_address(str(destination))
        except ValueError:
            failures.append("DESTINATION_NOT_NUMERIC_IP")

    windows_app = manifest.get("windows_app")
    if not isinstance(windows_app, dict) or not isinstance(
        windows_app.get("version"), str
    ) or not isinstance(windows_app.get("build"), str):
        failures.append("CLIENT_VERSION_MISSING")
        client_version = None
        client_build = None
    else:
        client_version = windows_app["version"]
        client_build = windows_app["build"]

    saved = manifest.get("saved_credential")
    credential_valid = (
        isinstance(saved, dict)
        and saved.get("state") == "explicit-saved-selected"
        and saved.get("server_client_credentials_intentionally_matched") == "yes"
        and isinstance(saved.get("username_exact"), str)
        and bool(saved.get("username_exact"))
    )
    if not credential_valid:
        failures.append("INVALID_CREDENTIAL_CONTROL")

    warning = manifest.get("certificate_warning")
    warning_appeared = warning.get("appeared") if isinstance(warning, dict) else None
    warning_accepted = warning.get("accepted") if isinstance(warning, dict) else None
    warning_consistent = (
        isinstance(warning_appeared, bool)
        and (
            (warning_appeared and warning_accepted in ("yes", "no"))
            or (not warning_appeared and warning_accepted == _NOT_APPLICABLE)
        )
    )
    if not warning_consistent:
        failures.append("CERTIFICATE_DECISION_INCONSISTENT")

    logging = manifest.get("logging")
    logging_available = isinstance(logging, dict) and logging.get("available") is True
    if not logging_available:
        failures.append("CLIENT_LOGS_MISSING")
    if not isinstance(logging, dict) or not logging.get("started_before_attempt") or not logging.get(
        "stopped_after_attempt"
    ):
        failures.append("LOGGING_LIFECYCLE_INCOMPLETE")

    linux = manifest.get("linux_correlation")
    linux_connection_id_present = (
        isinstance(linux, dict)
        and isinstance(linux.get("connection_id"), str)
        and bool(linux.get("connection_id"))
    )
    if not linux_connection_id_present:
        failures.append("LINUX_CONNECTION_CORRELATION_MISSING")

    correlation_delta_seconds: float | None = None
    try:
        attempt_time = _parse_utc(manifest.get("attempt_time_utc"), "attempt time")
        terminal_time = _parse_utc(
            linux.get("terminal_time_utc") if isinstance(linux, dict) else None,
            "Linux terminal time",
        )
        correlation_delta_seconds = abs((terminal_time - attempt_time).total_seconds())
        if correlation_delta_seconds > MAX_CORRELATION_DELTA_SECONDS:
            failures.append("CLOCK_SKEW_OR_ATTEMPT_MISMATCH")
    except ValueError:
        failures.append("CORRELATION_TIMESTAMP_INVALID")

    stage_matrix_value = manifest.get("server_stage_matrix")
    failures.extend(_stage_matrix_failures(stage_matrix_value))
    post_type2_client_bytes = (
        stage_matrix_value.get("post_type2_client_bytes")
        if isinstance(stage_matrix_value, dict)
        else None
    )
    timing_failures, timing_findings, native_isolation = (
        _timing_attribution_failures(
            manifest.get("server_timing_attribution"),
            post_type2_client_bytes,
        )
    )
    failures.extend(timing_failures)

    ui_error_code = manifest.get("client_error_code")
    first_error = manifest.get("first_client_error")
    if not isinstance(first_error, dict):
        first_error = {}
        limitations.append("FIRST_CLIENT_ERROR_NOT_OBSERVED")
    first_category = first_error.get("normalized_category", _NOT_OBSERVED)
    first_source = first_error.get("source", _NOT_OBSERVED)
    provider_category_present = isinstance(
        first_error.get("provider_category_exact"), str
    ) and bool(first_error.get("provider_category_exact"))
    provider_code_present = isinstance(
        first_error.get("provider_code_exact"), str
    ) and bool(first_error.get("provider_code_exact"))
    event_time_present = isinstance(first_error.get("event_time_utc"), str)

    if first_category == _NOT_OBSERVED:
        limitations.append("FIRST_CLIENT_ERROR_NOT_OBSERVED")
    elif first_category == "unknown":
        limitations.append("FIRST_CLIENT_ERROR_UNTYPED")
    elif not provider_category_present:
        failures.append("FIRST_CLIENT_ERROR_CLASSIFICATION_UNGROUNDED")

    if isinstance(ui_error_code, str) and ui_error_code.lower() == "0x204" and (
        first_category in ("unknown", _NOT_OBSERVED) or not provider_category_present
    ):
        limitations.append("BARE_0X204_NOT_TYPED")
    if first_category not in (_NOT_OBSERVED,) and not event_time_present:
        limitations.append("FIRST_CLIENT_ERROR_TIME_UNAVAILABLE")

    pair_failures, pair_summary = _pair_failures(manifest, pair)
    failures.extend(pair_failures)

    failures = list(dict.fromkeys(failures))
    limitations = list(dict.fromkeys(limitations))
    timing_findings = list(dict.fromkeys(timing_findings))
    stage_matrix = manifest.get("server_stage_matrix")
    redacted_stages = _redacted_stage_matrix(stage_matrix)

    return {
        "schema": "rdp-server.macos-windows-app-redacted-diagnostic.v1",
        "evidence_status": "FAIL" if failures else "PASS",
        "evidence_failures": failures,
        "diagnostic_limitations": limitations,
        "diagnostic_findings": timing_findings,
        "server_sha": server_sha,
        "server_certificate_sha256": fingerprint,
        "attempt_time_utc": manifest.get("attempt_time_utc"),
        "destination": {
            "exact_value_redacted": True,
            "sha256": destination_digest,
        },
        "windows_app": {
            "version": client_version,
            "build": client_build,
        },
        "credential_control": {
            "explicit_saved_selected": (
                isinstance(saved, dict)
                and saved.get("state") == "explicit-saved-selected"
            ),
            "server_client_credentials_intentionally_matched": (
                saved.get("server_client_credentials_intentionally_matched")
                if isinstance(saved, dict)
                else None
            ),
            "username_redacted": True,
        },
        "certificate_warning": {
            "appeared": warning_appeared,
            "accepted": warning_accepted,
        },
        "client_error": {
            "ui_code": ui_error_code,
            "exact_text_redacted": True,
            "first_typed_category": first_category,
            "source": first_source,
            "provider_category_present": provider_category_present,
            "provider_code_present": provider_code_present,
            "event_time_utc": first_error.get("event_time_utc"),
            "cross_source_order": "ORDER_UNDETERMINED",
        },
        "logging": {
            "available": logging_available,
            "core_level": logging.get("core_level") if isinstance(logging, dict) else None,
            "ui_level": logging.get("ui_level") if isinstance(logging, dict) else None,
            "file_count": logging.get("file_count") if isinstance(logging, dict) else None,
            "raw_logs_preserved_outside_summary": True,
        },
        "linux_correlation": {
            "connection_id_present": linux_connection_id_present,
            "connection_id_redacted": True,
            "terminal_time_utc": (
                linux.get("terminal_time_utc") if isinstance(linux, dict) else None
            ),
            "absolute_timestamp_delta_seconds": correlation_delta_seconds,
            "maximum_allowed_delta_seconds": MAX_CORRELATION_DELTA_SECONDS,
        },
        "server_stage_matrix": redacted_stages,
        "server_timing_attribution": _redacted_server_timing_attribution(
            manifest.get("server_timing_attribution")
        ),
        "server_pre_auth_native_isolation": native_isolation,
        "pair_comparison": pair_summary,
    }


def _read_private_manifest(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("manifest path must be an existing non-symlink regular file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_MANIFEST_BYTES:
        raise ValueError(f"manifest must contain 1..{MAX_MANIFEST_BYTES} bytes")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("manifest root must be a JSON object")
    return value


def parse_collect_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Emit a private read-only macOS Windows App physical-attempt evidence manifest"
        )
    )
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--server-sha", required=True)
    parser.add_argument(
        "--server-certificate-sha256",
        default=_NOT_RECORDED,
        help="Exact server certificate SHA-256 fingerprint; ':' separators are accepted.",
    )
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
    parser.add_argument("--client-error-code", default=_NOT_RECORDED)
    parser.add_argument(
        "--first-client-error-category",
        choices=_FIRST_ERROR_CATEGORIES,
        default=_NOT_OBSERVED,
    )
    parser.add_argument(
        "--first-client-error-source",
        choices=_FIRST_ERROR_SOURCES,
        default=_NOT_OBSERVED,
    )
    parser.add_argument("--first-client-provider-category")
    parser.add_argument("--first-client-provider-code")
    parser.add_argument("--first-client-error-time")
    parser.add_argument("--core-log-level", required=True)
    parser.add_argument("--ui-log-level", required=True)
    parser.add_argument("--logging-started", choices=("yes", "no"), required=True)
    parser.add_argument("--logging-stopped", choices=("yes", "no"), required=True)
    parser.add_argument("--linux-connection-id", required=True)
    parser.add_argument("--linux-terminal-time", required=True)
    parser.add_argument(
        "--stage-tls-established", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument(
        "--stage-type1-received", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument(
        "--stage-type2-committed", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument("--post-type2-client-bytes", type=int)
    parser.add_argument(
        "--stage-type3-received", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument(
        "--stage-pubkeyauth-reached", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument(
        "--stage-authinfo-reached", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument(
        "--stage-credentials-verified", choices=_STAGE_VALUES, default="NOT_RECORDED"
    )
    parser.add_argument("--typed-terminal-outcome", default=_NOT_RECORDED)
    parser.add_argument("--accepted-to-tls-us", type=int)
    parser.add_argument("--tls-to-type1-us", type=int)
    parser.add_argument("--type1-to-type2-queued-us", type=int)
    parser.add_argument("--type2-creation-to-delivery-us", type=int)
    parser.add_argument("--type2-to-peer-eof-us", type=int)
    parser.add_argument("--preauth-elapsed-at-peer-eof-us", type=int)
    parser.add_argument("--post-type2-first-client-tls-byte-us", type=int)
    parser.add_argument("--pre-tls-read-wait-us", type=int)
    parser.add_argument("--pre-tls-write-wait-us", type=int)
    parser.add_argument("--pre-tls-active-work-us", type=int)
    parser.add_argument("--tls-handshake-active-work-us", type=int)
    parser.add_argument("--pre-tls-unattributed-us", type=int)
    parser.add_argument("--pre-tls-socket-poll-us", type=int)
    parser.add_argument("--pre-tls-read-ready-to-service-us", type=int)
    parser.add_argument("--pre-tls-write-ready-to-service-us", type=int)
    parser.add_argument("--accepted-to-tls-app-wait-us", type=int)
    parser.add_argument("--accepted-to-tls-peer-wait-upper-us", type=int)
    parser.add_argument("--accepted-to-tls-service-work-us", type=int)
    parser.add_argument("--accepted-to-tls-native-maintenance-us", type=int)
    parser.add_argument("--accepted-to-tls-service-calls", type=int)
    parser.add_argument("--accepted-to-tls-max-app-gap-us", type=int)
    parser.add_argument("--tls-to-type1-app-wait-us", type=int)
    parser.add_argument("--tls-to-type1-peer-wait-upper-us", type=int)
    parser.add_argument("--tls-to-type1-service-work-us", type=int)
    parser.add_argument("--tls-to-type1-native-maintenance-us", type=int)
    parser.add_argument("--tls-to-type1-service-calls", type=int)
    parser.add_argument("--tls-to-type1-max-app-gap-us", type=int)
    logs = parser.add_mutually_exclusive_group(required=True)
    logs.add_argument("--logs", type=Path)
    logs.add_argument("--logs-unavailable-reason")
    return parser.parse_args(argv)


def parse_validate_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a private owner-evidence manifest and emit a redacted R2/R6 summary"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--peer-server-sha")
    parser.add_argument("--peer-destination")
    parser.add_argument("--peer-certificate-sha256")
    parser.add_argument("--peer-username")
    parser.add_argument("--peer-session-password-matched", choices=("yes", "no"))
    parser.add_argument("--peer-certificate-warning", choices=("yes", "no"))
    parser.add_argument(
        "--peer-certificate-warning-accepted",
        choices=("yes", "no", _NOT_APPLICABLE),
    )
    return parser.parse_args(argv)


def _pair_namespace_or_none(options: argparse.Namespace) -> argparse.Namespace | None:
    names = (
        "peer_server_sha",
        "peer_destination",
        "peer_certificate_sha256",
        "peer_username",
        "peer_session_password_matched",
        "peer_certificate_warning",
        "peer_certificate_warning_accepted",
    )
    if not any(getattr(options, name) is not None for name in names):
        return None
    return options


def main(argv: list[str]) -> int:
    try:
        if argv and argv[0] == "validate":
            options = parse_validate_args(argv[1:])
            manifest = _read_private_manifest(options.manifest)
            summary = build_redacted_summary(
                manifest, _pair_namespace_or_none(options)
            )
            json.dump(summary, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0 if summary["evidence_status"] == "PASS" else 3

        manifest = build_manifest(parse_collect_args(argv))
    except (OSError, ValueError, json.JSONDecodeError, plistlib.InvalidFileException) as exc:
        print(f"macOS Windows App evidence: {exc}", file=sys.stderr)
        return 2
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
