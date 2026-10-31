# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only, privacy-safe comparison of physical Windows App and mstsc attempts.

The macOS input is the existing private R5 schema-v2 manifest. The second
input is a private A/B supplement containing a Windows row and only the macOS
facts absent from R5. Neither input is a credential or admission authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

import macos_windows_app_owner_evidence as macos

SCHEMA = "rdp-server.windows-client-ab-pair.v1"
SUMMARY_SCHEMA = "rdp-server.windows-client-ab-redacted.v1"
STAGES = (
    "tls_established", "type1_received", "type2_fully_committed",
    "type3_received", "pubkeyauth_reached", "authinfo_reached",
    "credentials_verified",
)
STAGE_STATES = {"PASS", "FAIL", "NOT_REACHED"}
ERROR_CATEGORIES = {
    "credential", "trust", "negotiation", "cancellation", "transport",
    "unknown", "not-observed",
}
ERROR_SOURCES = {"core", "ui", "ui-error", "core-and-ui", "windows-ui",
                 "owner-approved-diagnostic", "not-observed"}
SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
PROFILE = re.compile(r"[a-zA-Z0-9._-]{1,96}\Z")


def _fields(value: object, required: set[str], name: str) -> dict:
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(f"{name} has missing or unapproved fields")
    return value


def _text(value: object, name: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} is missing or exceeds its bound")
    return value


def _utc(value: object, name: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(_text(value, name, 64))
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return timestamp.astimezone(timezone.utc)


def _stage_failures(stage: object, native_admission: object,
                    transport: object, client_type3_claimed: object, prefix: str) -> list[str]:
    failures: list[str] = []
    if (not isinstance(stage, dict) or set(stage) != set(STAGES) | {"post_type2_client_bytes", "typed_terminal_outcome"}
            or any(stage.get(name) not in STAGE_STATES for name in STAGES)):
        return [f"{prefix}_STAGES_INCOMPLETE"]
    bytes_after_type2 = stage.get("post_type2_client_bytes")
    if type(bytes_after_type2) is not int or not 0 <= bytes_after_type2 <= (1 << 30):
        return [f"{prefix}_POST_TYPE2_BYTES_INVALID"]
    if not isinstance(stage.get("typed_terminal_outcome"), str) or not stage["typed_terminal_outcome"]:
        return [f"{prefix}_TERMINAL_OUTCOME_MISSING"]
    if any(stage[STAGES[index]] == "PASS" and
           any(stage[earlier] != "PASS" for earlier in STAGES[:index])
           for index in range(1, len(STAGES))):
        failures.append(f"{prefix}_STAGE_ORDER_CONTRADICTORY")
    if stage["type2_fully_committed"] != "PASS" and bytes_after_type2 != 0:
        failures.append(f"{prefix}_POST_TYPE2_BEFORE_COMMIT")
    if stage["type3_received"] == "PASS" and bytes_after_type2 == 0:
        failures.append(f"{prefix}_TYPE3_WITHOUT_POST_TYPE2_BYTES")
    if client_type3_claimed is not None and type(client_type3_claimed) is not bool:
        failures.append(f"{prefix}_CLIENT_TYPE3_CLAIM_INVALID")
    elif client_type3_claimed is True and (
            stage["type3_received"] != "PASS" or bytes_after_type2 == 0):
        failures.append(f"{prefix}_CLIENT_TYPE3_UNCORROBORATED")
    elif client_type3_claimed is False and stage["type3_received"] == "PASS":
        failures.append(f"{prefix}_SERVER_TYPE3_CONTRADICTS_CLIENT_CLAIM")
    if native_admission not in STAGE_STATES:
        failures.append(f"{prefix}_NATIVE_ADMISSION_INVALID")
    elif native_admission != "NOT_REACHED" and stage["credentials_verified"] != "PASS":
        failures.append(f"{prefix}_NATIVE_BEFORE_CREDENTIALS_VERIFIED")
    if not isinstance(transport, dict) or set(transport) != {
        "peer_fin_observed", "tls_alert_observed", "terminal_attribution"
    }:
        failures.append(f"{prefix}_TRANSPORT_INCOMPLETE")
    elif (type(transport["peer_fin_observed"]) is not bool or
          type(transport["tls_alert_observed"]) is not bool or
          transport["terminal_attribution"] not in {
              "peer-fin", "tls-alert", "other", "unknown"
          }):
        failures.append(f"{prefix}_TRANSPORT_INVALID")
    else:
        if transport["terminal_attribution"] == "tls-alert" and not transport["tls_alert_observed"]:
            failures.append(f"{prefix}_TLS_ALERT_NOT_OBSERVED")
        if transport["terminal_attribution"] == "peer-fin" and not transport["peer_fin_observed"]:
            failures.append(f"{prefix}_PEER_FIN_NOT_OBSERVED")
    return failures


def _first_error_failures(first_error: object) -> list[str]:
    if not isinstance(first_error, dict):
        return ["WINDOWS_FIRST_ERROR_INVALID"]
    if set(first_error) != {"normalized_category", "source", "provider_category_exact",
                             "provider_code_exact", "event_time_utc"}:
        return ["WINDOWS_FIRST_ERROR_INVALID"]
    category = first_error["normalized_category"]
    source = first_error["source"]
    if category not in ERROR_CATEGORIES or source not in ERROR_SOURCES:
        return ["WINDOWS_FIRST_ERROR_INVALID"]
    if category == "not-observed":
        if source != "not-observed" or any(first_error[name] is not None for name in (
            "provider_category_exact", "provider_code_exact", "event_time_utc"
        )):
            return ["WINDOWS_FIRST_ERROR_CONTRADICTORY"]
    else:
        if source == "not-observed":
            return ["WINDOWS_FIRST_ERROR_CONTRADICTORY"]
        if category != "unknown" and not first_error["provider_category_exact"]:
            return ["WINDOWS_FIRST_ERROR_UNGROUNDED"]
        for name in ("provider_category_exact", "provider_code_exact"):
            if first_error[name] is not None:
                _text(first_error[name], name, 128)
        if first_error["event_time_utc"] is not None:
            _utc(first_error["event_time_utc"], "Windows first-error event time")
    return []


def validate_pair(macos_manifest: dict, pair: dict) -> dict:
    """Validate evidence, never infer server/client event ordering or cause."""
    failures: list[str] = []
    macos_summary = macos.build_redacted_summary(macos_manifest)
    if macos_summary["evidence_status"] != "PASS":
        failures.append("MACOS_R5_EVIDENCE_INVALID")

    _fields(pair, {"schema", "macos", "windows"}, "pair")
    if pair["schema"] != SCHEMA:
        failures.append("PAIR_SCHEMA_UNSUPPORTED")
    macos_row = _fields(pair["macos"], {"server_tls_configuration_profile",
                         "credential_source_claim", "deliberately_reentered",
                         "server_transport_observation", "native_admission",
                         "client_type3_claimed"}, "macOS supplement")
    windows = _fields(pair["windows"], {
        "server_sha", "server_certificate_sha256", "destination_exact",
        "server_tls_configuration_profile", "windows_11_build", "mstsc_file_version",
        "attempt_time_utc", "credential", "certificate_warning", "first_client_error",
        "client_visible_result", "linux_correlation", "server_stage_matrix",
        "server_transport_observation", "native_admission",
        "client_type3_claimed"
    }, "Windows row")
    credential = _fields(windows["credential"], {
        "source", "deliberately_reentered", "username_exact",
        "session_password_intentionally_matched"
    }, "Windows credential control")
    warning = _fields(windows["certificate_warning"], {"appeared", "accepted"}, "Windows warning")
    correlation = _fields(windows["linux_correlation"], {"connection_id", "terminal_time_utc"}, "Windows correlation")

    for field in ("windows_11_build", "mstsc_file_version", "client_visible_result"):
        _text(windows[field], field)
    if (not PROFILE.fullmatch(_text(macos_row["server_tls_configuration_profile"], "macOS profile")) or
            not PROFILE.fullmatch(_text(windows["server_tls_configuration_profile"], "Windows profile"))):
        failures.append("SERVER_PROFILE_INVALID")
    if macos_row["server_tls_configuration_profile"] != windows["server_tls_configuration_profile"]:
        failures.append("AB_SERVER_PROFILE_MISMATCH")
    if not isinstance(windows["server_sha"], str) or not SHA40.fullmatch(windows["server_sha"]):
        failures.append("WINDOWS_SERVER_SHA_INVALID")
    elif windows["server_sha"].lower() != macos_manifest.get("server_sha", "").lower():
        failures.append("AB_SERVER_SHA_MISMATCH")
    if not isinstance(windows["server_certificate_sha256"], str) or not SHA256.fullmatch(windows["server_certificate_sha256"]):
        failures.append("WINDOWS_CERTIFICATE_INVALID")
    elif windows["server_certificate_sha256"].lower() != macos_manifest.get("server_certificate_sha256"):
        failures.append("AB_CERTIFICATE_FINGERPRINT_MISMATCH")
    if windows["destination_exact"] != macos_manifest.get("destination_exact"):
        failures.append("AB_DESTINATION_MISMATCH")
    if (macos_row["credential_source_claim"] != macos_manifest.get("saved_credential", {}).get("state") or
            type(macos_row["deliberately_reentered"]) is not bool or
            macos_row["deliberately_reentered"]):
        failures.append("MACOS_SAVED_PRESENTED_AS_REENTERED")
    if (credential["source"] != "explicitly-entered" or
            credential["deliberately_reentered"] is not True):
        failures.append("WINDOWS_INVALID_CREDENTIAL_CONTROL")
    if (credential["username_exact"] != macos_manifest.get("saved_credential", {}).get("username_exact") or
            credential["session_password_intentionally_matched"] is not True):
        failures.append("AB_STANDALONE_CREDENTIAL_MISMATCH")
    macos_warning = macos_manifest.get("certificate_warning", {})
    if (type(warning["appeared"]) is not bool or
            warning["accepted"] not in {"yes", "no", "not-applicable"} or
            (warning["appeared"] and warning["accepted"] == "not-applicable") or
            (not warning["appeared"] and warning["accepted"] != "not-applicable")):
        failures.append("WINDOWS_CERTIFICATE_DECISION_INVALID")
    elif warning != macos_warning:
        failures.append("CERTIFICATE_DECISION_NOT_COMPARABLE")
    failures.extend(_first_error_failures(windows["first_client_error"]))

    windows_stage = windows["server_stage_matrix"]
    failures.extend(_stage_failures(macos_manifest.get("server_stage_matrix"),
                    macos_row["native_admission"], macos_row["server_transport_observation"],
                    macos_row["client_type3_claimed"], "MACOS"))
    failures.extend(_stage_failures(windows_stage, windows["native_admission"],
                    windows["server_transport_observation"], windows["client_type3_claimed"], "WINDOWS"))

    try:
        start = _utc(windows["attempt_time_utc"], "Windows attempt")
        terminal = _utc(correlation["terminal_time_utc"], "Windows terminal")
        macos_start = _utc(macos_manifest.get("attempt_time_utc"), "macOS attempt")
        _text(correlation["connection_id"], "Windows connection ID")
        if abs((terminal - start).total_seconds()) > macos.MAX_CORRELATION_DELTA_SECONDS:
            failures.append("WINDOWS_ATTEMPT_CORRELATION_MISMATCH")
        first_event = windows["first_client_error"]["event_time_utc"]
        if first_event is not None and abs((_utc(first_event, "Windows first error") - start).total_seconds()) > macos.MAX_CORRELATION_DELTA_SECONDS:
            failures.append("WINDOWS_FIRST_ERROR_ATTEMPT_MISMATCH")
        if start <= macos_start:
            failures.append("AB_ATTEMPT_ORDER_INVALID")
        if correlation["connection_id"] == macos_manifest.get("linux_correlation", {}).get("connection_id"):
            failures.append("AB_CONNECTION_ID_REUSED")
    except ValueError:
        failures.append("WINDOWS_ATTEMPT_CORRELATION_INVALID")

    # Treat every input string as private. Only enumerated, redacted facts enter stdout.
    macos_type3 = macos_manifest.get("server_stage_matrix", {}).get("type3_received")
    windows_type3 = windows_stage.get("type3_received") if isinstance(windows_stage, dict) else None
    comparison = "INCONCLUSIVE"
    if not failures:
        if macos_type3 == "PASS" and windows_type3 == "PASS":
            comparison = "BOTH_TYPE3_RECEIVED"
        elif macos_type3 != "PASS" and windows_type3 == "PASS":
            comparison = "WINDOWS_ONLY_TYPE3_RECEIVED"
        elif macos_type3 != "PASS" and windows_type3 != "PASS":
            comparison = "NEITHER_TYPE3_RECEIVED"
    return {
        "schema": SUMMARY_SCHEMA,
        "evidence_status": "FAIL" if failures else "PASS",
        "evidence_failures": sorted(set(failures)),
        "comparison": comparison,
        "server_sha": macos_summary.get("server_sha"),
        "destination_sha256": macos_summary.get("destination", {}).get("sha256"),
        "certificate_fingerprint_match": (
            isinstance(windows["server_certificate_sha256"], str)
            and windows["server_certificate_sha256"].lower() == macos_manifest.get("server_certificate_sha256")
        ),
        "cross_source_event_order": "ORDER_UNDETERMINED",
        "macos": {
            "app": "Windows App", "version": macos_summary.get("windows_app"),
            "first_client_error_category": macos_summary.get("client_error", {}).get("first_typed_category"),
            "type3_received": macos_type3, "native_admission": macos_row["native_admission"],
        },
        "windows": {
            "app": "mstsc.exe", "windows_11_build": windows["windows_11_build"],
            "mstsc_file_version": windows["mstsc_file_version"],
            "first_client_error_category": windows["first_client_error"].get("normalized_category"),
            "type3_received": windows_type3, "native_admission": windows["native_admission"],
        },
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("macos_manifest", type=Path)
    parser.add_argument("private_pair_record", type=Path)
    options = parser.parse_args(argv)
    try:
        macos_manifest = macos._read_private_manifest(options.macos_manifest)
        pair = macos._read_private_manifest(options.private_pair_record)
        summary = validate_pair(macos_manifest, pair)
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError) as error:
        print(f"client A/B evidence: {error}", file=sys.stderr)
        return 2
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if summary["evidence_status"] == "PASS" else 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
