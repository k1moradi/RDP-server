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

SCHEMA = "rdp-server.windows-client-ab-pair.v3"
SUMMARY_SCHEMA = "rdp-server.windows-client-ab-redacted.v3"
STAGES = (
    "tls_established", "type1_received", "type2_fully_committed",
    "type3_received", "pubkeyauth_reached", "authinfo_reached",
    "credentials_verified",
)
STAGE_STATES = {"PASS", "FAIL", "NOT_REACHED"}
CLIENT_SECURITY_STAGES = (
    "type2_received", "type2_accepted_by_credssp",
    "type3_generated", "type3_delivered",
)
CLIENT_STAGE_STATES = {"PASS", "FAIL", "NOT_OBSERVED"}
SOURCE_BINDING_FIELDS = {
    "server_sha", "server_certificate_sha256", "destination_exact",
    "service_endpoint_exact", "attempt_time_utc", "connection_id",
    "terminal_time_utc", "observation_window_start_utc",
    "observation_window_end_utc", "attempt_id_exact",
    "client_application_exact", "client_version_exact",
    "target_identity_exact", "credential_source_choice",
}
CLIENT_EVENT_FIELDS = {
    "source_kind", "source_record_sha256", "client_application_exact",
    "client_version_exact", "attempt_id_exact", "connection_id",
    "event_time_utc",
}
SERVER_TYPE3_FIELDS = {
    "source_record_sha256", "attempt_id_exact", "connection_id",
    "event_time_utc",
}
CLIENT_EVENT_SOURCES = {"client-provider-event", "owner-approved-client-diagnostic"}
ERROR_CATEGORIES = {
    "credential", "trust", "negotiation", "cancellation", "transport",
    "unknown", "not-observed",
}
ERROR_SOURCES = {"core", "ui", "ui-error", "core-and-ui", "windows-ui",
                 "owner-approved-diagnostic", "not-observed"}
MACOS_FIRST_ERROR_FIELDS = {
    "normalized_category", "source", "provider_category_exact",
    "provider_code_exact", "event_time_local", "event_time_utc",
}
SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
PROFILE = re.compile(r"[a-zA-Z0-9._-]{1,96}\Z")
WINDOWS_VERSION = re.compile(r"[0-9]{1,8}(?:\.[0-9]{1,8}){0,5}\Z")


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


def _is_allowed(value: object, allowed: set[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _private_mapping(value: object) -> dict:
    # A malformed private section is not a dictionary and has no usable fields.
    return value if isinstance(value, dict) else {}


def _redacted_stage(value: object, allowed: set[str], fallback: str) -> str:
    # Malformed private input must never be mirrored into shared output.
    return value if _is_allowed(value, allowed) else fallback


def _redacted_client_stages(stages: object) -> dict[str, str]:
    observed = stages if isinstance(stages, dict) else {}
    return {
        name: _redacted_stage(observed.get(name), CLIENT_STAGE_STATES, "NOT_OBSERVED")
        for name in CLIENT_SECURITY_STAGES
    }


def _redacted_windows_version(value: object) -> str:
    # Only dotted numeric OS/file versions are safe to project verbatim.
    return value if isinstance(value, str) and WINDOWS_VERSION.fullmatch(value) else "INVALID"


def _stage_failures(stage: object, native_admission: object,
                    transport: object, prefix: str) -> list[str]:
    failures: list[str] = []
    if (not isinstance(stage, dict) or set(stage) != set(STAGES) | {"post_type2_client_bytes", "typed_terminal_outcome"}
            or any(not _is_allowed(stage.get(name), STAGE_STATES) for name in STAGES)):
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
    if not _is_allowed(native_admission, STAGE_STATES):
        failures.append(f"{prefix}_NATIVE_ADMISSION_INVALID")
    elif native_admission != "NOT_REACHED" and stage["credentials_verified"] != "PASS":
        failures.append(f"{prefix}_NATIVE_BEFORE_CREDENTIALS_VERIFIED")
    if not isinstance(transport, dict) or set(transport) != {
        "peer_fin_observed", "tls_alert_observed", "terminal_attribution"
    }:
        failures.append(f"{prefix}_TRANSPORT_INCOMPLETE")
    elif (type(transport["peer_fin_observed"]) is not bool or
          type(transport["tls_alert_observed"]) is not bool or
          not _is_allowed(transport["terminal_attribution"], {
              "peer-fin", "tls-alert", "other", "unknown"
          })):
        failures.append(f"{prefix}_TRANSPORT_INVALID")
    else:
        if transport["terminal_attribution"] == "tls-alert" and not transport["tls_alert_observed"]:
            failures.append(f"{prefix}_TLS_ALERT_NOT_OBSERVED")
        if transport["terminal_attribution"] == "peer-fin" and not transport["peer_fin_observed"]:
            failures.append(f"{prefix}_PEER_FIN_NOT_OBSERVED")
    return failures


def _client_stage_failures(stages: object, prefix: str) -> list[str]:
    if (not isinstance(stages, dict) or set(stages) != set(CLIENT_SECURITY_STAGES)
            or any(not _is_allowed(stages.get(name), CLIENT_STAGE_STATES)
                   for name in CLIENT_SECURITY_STAGES)):
        return [f"{prefix}_CLIENT_STAGES_INCOMPLETE"]

    # NOT_OBSERVED is deliberately not treated as failure. Client-side receipt,
    # CredSSP acceptance, token generation and local delivery are independent
    # evidence. Server FIN or server-side silence must not fill these fields.
    for index in range(1, len(CLIENT_SECURITY_STAGES)):
        if (stages[CLIENT_SECURITY_STAGES[index]] == "PASS" and
                any(stages[earlier] == "FAIL"
                    for earlier in CLIENT_SECURITY_STAGES[:index])):
            return [f"{prefix}_CLIENT_STAGE_ORDER_CONTRADICTORY"]
    return []


def _source_binding_failures(binding: object, expected: dict, prefix: str) -> list[str]:
    if not isinstance(binding, dict) or set(binding) != SOURCE_BINDING_FIELDS:
        return [f"{prefix}_SOURCE_BINDING_INCOMPLETE"]

    failures: list[str] = []
    server_sha = binding["server_sha"]
    if not isinstance(server_sha, str) or not SHA40.fullmatch(server_sha):
        failures.append(f"{prefix}_SOURCE_SHA_INVALID")
    elif server_sha.lower() != str(expected["server_sha"]).lower():
        failures.append(f"{prefix}_SOURCE_SHA_MISMATCH")

    fingerprint = binding["server_certificate_sha256"]
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        failures.append(f"{prefix}_SOURCE_CERTIFICATE_INVALID")
    elif fingerprint.lower() != str(expected["server_certificate_sha256"]).lower():
        failures.append(f"{prefix}_SOURCE_CERTIFICATE_MISMATCH")

    for field, code in (
        ("destination_exact", "DESTINATION"),
        ("service_endpoint_exact", "SERVICE_ENDPOINT"),
        ("connection_id", "CONNECTION"),
        ("attempt_id_exact", "ATTEMPT_ID"),
        ("client_application_exact", "CLIENT_APPLICATION"),
        ("client_version_exact", "CLIENT_VERSION"),
        ("target_identity_exact", "TARGET_IDENTITY"),
        ("credential_source_choice", "CREDENTIAL_SOURCE"),
    ):
        try:
            observed = _text(binding[field], f"{prefix} source {field}", 256)
            required = _text(expected[field], f"{prefix} expected {field}", 256)
            if observed != required:
                failures.append(f"{prefix}_SOURCE_{code}_MISMATCH")
        except ValueError:
            failures.append(f"{prefix}_SOURCE_{code}_INVALID")

    try:
        attempt = _utc(binding["attempt_time_utc"], f"{prefix} source attempt")
        expected_attempt = _utc(expected["attempt_time_utc"], f"{prefix} expected attempt")
        terminal = _utc(binding["terminal_time_utc"], f"{prefix} source terminal")
        expected_terminal = _utc(expected["terminal_time_utc"], f"{prefix} expected terminal")
        window_start = _utc(
            binding["observation_window_start_utc"], f"{prefix} source window start")
        window_end = _utc(
            binding["observation_window_end_utc"], f"{prefix} source window end")
        if attempt != expected_attempt:
            failures.append(f"{prefix}_SOURCE_ATTEMPT_TIME_MISMATCH")
        if terminal != expected_terminal:
            failures.append(f"{prefix}_SOURCE_TERMINAL_TIME_MISMATCH")
        if (window_start > attempt or attempt > terminal or terminal > window_end or
                (window_end - window_start).total_seconds() >
                macos.MAX_CORRELATION_DELTA_SECONDS):
            failures.append(f"{prefix}_SOURCE_OBSERVATION_WINDOW_MISMATCH")
    except ValueError:
        failures.append(f"{prefix}_SOURCE_TIME_INVALID")
    return failures


def _client_event_failures(stages: object, evidence: object, binding: object,
                           prefix: str) -> list[str]:
    """A positive client stage needs a same-attempt client-origin receipt.

    A digest and owner correlation are not a cryptographic attestation of the
    underlying event. The original client log must be checked independently.
    """
    if not isinstance(stages, dict) or not isinstance(evidence, dict) or (
            set(evidence) != set(CLIENT_SECURITY_STAGES)):
        return [f"{prefix}_CLIENT_EVENT_PROVENANCE_INCOMPLETE"]
    if not isinstance(binding, dict):
        return [f"{prefix}_CLIENT_EVENT_BINDING_MISSING"]

    failures: list[str] = []
    for stage in CLIENT_SECURITY_STAGES:
        state = stages.get(stage)
        event = evidence[stage]
        label = f"{prefix}_CLIENT_{stage.upper()}"
        if state == "NOT_OBSERVED":
            if event is not None:
                failures.append(f"{label}_UNOBSERVED_EVENT_CONTRADICTION")
            continue
        if not _is_allowed(state, {"PASS", "FAIL"}):
            continue
        if not isinstance(event, dict) or set(event) != CLIENT_EVENT_FIELDS:
            failures.append(f"{label}_PROVENANCE_MISSING")
            continue
        if not _is_allowed(event["source_kind"], CLIENT_EVENT_SOURCES):
            failures.append(f"{label}_SOURCE_UNSUPPORTED")
        if not isinstance(event["source_record_sha256"], str) or not SHA256.fullmatch(
                event["source_record_sha256"]):
            failures.append(f"{label}_SOURCE_DIGEST_INVALID")
        for field, code in (
            ("client_application_exact", "APPLICATION"),
            ("client_version_exact", "VERSION"),
            ("attempt_id_exact", "ATTEMPT"),
            ("connection_id", "CONNECTION"),
        ):
            try:
                if _text(event[field], f"{label} {field}", 256) != _text(
                        binding.get(field), f"{label} original {field}", 256):
                    failures.append(f"{label}_{code}_MISMATCH")
            except ValueError:
                failures.append(f"{label}_{code}_INVALID")
        try:
            event_time = _utc(event["event_time_utc"], f"{label} event")
            start = _utc(binding.get("observation_window_start_utc"), f"{label} start")
            end = _utc(binding.get("observation_window_end_utc"), f"{label} end")
            if not start <= event_time <= end:
                failures.append(f"{label}_EVENT_OUTSIDE_ATTEMPT")
        except ValueError:
            failures.append(f"{label}_EVENT_TIME_INVALID")
    return failures


def _server_type3_failures(stage: object, evidence: object, binding: object,
                           prefix: str) -> list[str]:
    """Server Type 3 must be pinned to its originating attempt, not a neighbor."""
    type3 = stage.get("type3_received") if isinstance(stage, dict) else None
    if type3 != "PASS":
        return [f"{prefix}_TYPE3_SOURCE_UNEXPECTED"] if evidence is not None else []
    if not isinstance(evidence, dict) or set(evidence) != SERVER_TYPE3_FIELDS:
        return [f"{prefix}_TYPE3_SOURCE_MISSING"]
    if not isinstance(binding, dict):
        return [f"{prefix}_TYPE3_SOURCE_BINDING_MISSING"]
    failures: list[str] = []
    if not isinstance(evidence["source_record_sha256"], str) or not SHA256.fullmatch(
            evidence["source_record_sha256"]):
        failures.append(f"{prefix}_TYPE3_SOURCE_DIGEST_INVALID")
    for field, code in (
        ("attempt_id_exact", "ATTEMPT"),
        ("connection_id", "CONNECTION"),
    ):
        try:
            if _text(evidence[field], f"{prefix} Type 3 {field}", 256) != _text(
                    binding.get(field), f"{prefix} original {field}", 256):
                failures.append(f"{prefix}_TYPE3_SOURCE_{code}_MISMATCH")
        except ValueError:
            failures.append(f"{prefix}_TYPE3_SOURCE_{code}_INVALID")
    try:
        timestamp = _utc(evidence["event_time_utc"], f"{prefix} Type 3 event")
        start = _utc(binding.get("observation_window_start_utc"), f"{prefix} start")
        end = _utc(binding.get("observation_window_end_utc"), f"{prefix} end")
        if not start <= timestamp <= end:
            failures.append(f"{prefix}_TYPE3_SOURCE_WINDOW_MISMATCH")
    except ValueError:
        failures.append(f"{prefix}_TYPE3_SOURCE_TIME_INVALID")
    return failures


def _first_error_failures(first_error: object) -> list[str]:
    if not isinstance(first_error, dict) or set(first_error) != {
            "normalized_category", "source", "provider_category_exact",
            "provider_code_exact", "event_time_utc"}:
        return ["WINDOWS_FIRST_ERROR_INVALID"]

    category = first_error["normalized_category"]
    source = first_error["source"]
    if not _is_allowed(category, ERROR_CATEGORIES) or not _is_allowed(source, ERROR_SOURCES):
        return ["WINDOWS_FIRST_ERROR_INVALID"]
    if category == "not-observed":
        if source != "not-observed" or any(first_error[name] is not None for name in (
                "provider_category_exact", "provider_code_exact", "event_time_utc")):
            return ["WINDOWS_FIRST_ERROR_CONTRADICTORY"]
    else:
        if source == "not-observed":
            return ["WINDOWS_FIRST_ERROR_CONTRADICTORY"]
        if category != "unknown" and not first_error["provider_category_exact"]:
            return ["WINDOWS_FIRST_ERROR_UNGROUNDED"]
        try:
            # Never mirror nested private provider values or their exception text.
            for name in ("provider_category_exact", "provider_code_exact"):
                if first_error[name] is not None:
                    _text(first_error[name], name, 128)
            if first_error["event_time_utc"] is not None:
                _utc(first_error["event_time_utc"], "Windows first-error event time")
        except ValueError:
            return ["WINDOWS_FIRST_ERROR_INVALID"]
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
    macos_row = _fields(pair["macos"], {
        "server_tls_configuration_profile", "service_endpoint_exact",
        "credential_source_claim", "deliberately_reentered", "source_binding",
        "client_security_stages", "client_stage_evidence",
        "server_type3_evidence", "target_identity_exact", "attempt_id_exact",
        "server_transport_observation", "native_admission",
    }, "macOS supplement")
    windows_required_fields = {
        "server_sha", "server_certificate_sha256", "destination_exact",
        "service_endpoint_exact", "server_tls_configuration_profile",
        "windows_11_build", "mstsc_file_version", "attempt_time_utc",
        "credential", "certificate_warning", "first_client_error",
        "client_visible_result", "linux_correlation", "source_binding",
        "client_security_stages", "client_stage_evidence",
        "server_type3_evidence", "target_identity_exact", "attempt_id_exact",
        "server_stage_matrix", "server_transport_observation", "native_admission",
    }
    windows_record = pair["windows"]
    if (isinstance(windows_record, dict) and
            set(windows_record) == windows_required_fields - {"first_client_error"}):
        # Absent private error observation must result in a typed FAIL.
        windows_record = {**windows_record, "first_client_error": None}
    windows = _fields(windows_record, windows_required_fields, "Windows row")
    credential = _fields(windows["credential"], {
        "source", "deliberately_reentered", "saved_credential_use",
        "username_exact", "session_password_intentionally_matched"
    }, "Windows credential control")
    warning = _fields(windows["certificate_warning"], {"appeared", "accepted"}, "Windows warning")
    correlation = _fields(windows["linux_correlation"], {"connection_id", "terminal_time_utc"}, "Windows correlation")

    for field in ("windows_11_build", "mstsc_file_version", "client_visible_result"):
        _text(windows[field], field)
    if any(_redacted_windows_version(windows[field]) == "INVALID"
           for field in ("windows_11_build", "mstsc_file_version")):
        failures.append("WINDOWS_VERSION_INVALID")
    if (not PROFILE.fullmatch(_text(macos_row["server_tls_configuration_profile"], "macOS profile")) or
            not PROFILE.fullmatch(_text(windows["server_tls_configuration_profile"], "Windows profile"))):
        failures.append("SERVER_PROFILE_INVALID")
    if macos_row["server_tls_configuration_profile"] != windows["server_tls_configuration_profile"]:
        failures.append("AB_SERVER_PROFILE_MISMATCH")
    try:
        if _text(macos_row["target_identity_exact"], "macOS target identity", 256) != _text(
                windows["target_identity_exact"], "Windows target identity", 256):
            failures.append("AB_TARGET_IDENTITY_MISMATCH")
        if _text(macos_row["attempt_id_exact"], "macOS attempt ID", 256) == _text(
                windows["attempt_id_exact"], "Windows attempt ID", 256):
            failures.append("AB_ATTEMPT_ID_REUSED")
    except ValueError:
        failures.append("AB_TARGET_OR_ATTEMPT_INVALID")
    try:
        macos_endpoint = _text(
            macos_row["service_endpoint_exact"], "macOS service endpoint", 256)
        windows_endpoint = _text(
            windows["service_endpoint_exact"], "Windows service endpoint", 256)
        if macos_endpoint != windows_endpoint:
            failures.append("AB_SERVICE_ENDPOINT_MISMATCH")
    except ValueError:
        failures.append("AB_SERVICE_ENDPOINT_INVALID")
    if not isinstance(windows["server_sha"], str) or not SHA40.fullmatch(windows["server_sha"]):
        failures.append("WINDOWS_SERVER_SHA_INVALID")
    elif (not isinstance(macos_manifest.get("server_sha"), str)
          or windows["server_sha"].lower() != macos_manifest["server_sha"].lower()):
        failures.append("AB_SERVER_SHA_MISMATCH")
    if not isinstance(windows["server_certificate_sha256"], str) or not SHA256.fullmatch(windows["server_certificate_sha256"]):
        failures.append("WINDOWS_CERTIFICATE_INVALID")
    elif windows["server_certificate_sha256"].lower() != macos_manifest.get("server_certificate_sha256"):
        failures.append("AB_CERTIFICATE_FINGERPRINT_MISMATCH")
    if windows["destination_exact"] != macos_manifest.get("destination_exact"):
        failures.append("AB_DESTINATION_MISMATCH")
    macos_saved = _private_mapping(macos_manifest.get("saved_credential"))
    if (macos_row["credential_source_claim"] != macos_saved.get("state") or
            type(macos_row["deliberately_reentered"]) is not bool):
        failures.append("MACOS_CREDENTIAL_CONTROL_INVALID")
    elif macos_row["deliberately_reentered"] is not True:
        failures.append("MACOS_CREDENTIAL_NOT_REENTERED")
    if (macos_saved.get("state") != "explicit-saved-selected" or
            macos_saved.get("newly_created_for_attempt") != "yes" or
            macos_saved.get("server_client_credentials_intentionally_matched") != "yes"):
        failures.append("MACOS_INVALID_CREDENTIAL_CONTROL")
    if (credential["source"] != "explicitly-entered" or
            credential["deliberately_reentered"] is not True or
            credential["saved_credential_use"] != "none"):
        failures.append("WINDOWS_INVALID_CREDENTIAL_CONTROL")
    if (credential["username_exact"] != macos_saved.get("username_exact") or
            credential["session_password_intentionally_matched"] is not True):
        failures.append("AB_STANDALONE_CREDENTIAL_MISMATCH")
    macos_warning = macos_manifest.get("certificate_warning", {})
    if (type(warning["appeared"]) is not bool or
            not _is_allowed(warning["accepted"], {"yes", "no", "not-applicable"}) or
            (warning["appeared"] and warning["accepted"] == "not-applicable") or
            (not warning["appeared"] and warning["accepted"] != "not-applicable")):
        failures.append("WINDOWS_CERTIFICATE_DECISION_INVALID")
    elif warning != macos_warning:
        failures.append("CERTIFICATE_DECISION_NOT_COMPARABLE")
    first_error_record = windows["first_client_error"]
    failures.extend(_first_error_failures(first_error_record))

    macos_correlation = _private_mapping(macos_manifest.get("linux_correlation"))
    macos_application = _private_mapping(macos_manifest.get("windows_app"))
    macos_version = macos_application.get("version")
    macos_build = macos_application.get("build")
    failures.extend(_source_binding_failures(
        macos_row["source_binding"],
        {
            "server_sha": macos_manifest.get("server_sha"),
            "server_certificate_sha256": macos_manifest.get("server_certificate_sha256"),
            "destination_exact": macos_manifest.get("destination_exact"),
            "service_endpoint_exact": macos_row["service_endpoint_exact"],
            "attempt_time_utc": macos_manifest.get("attempt_time_utc"),
            "connection_id": macos_correlation.get("connection_id"),
            "terminal_time_utc": macos_correlation.get("terminal_time_utc"),
            "attempt_id_exact": macos_row["attempt_id_exact"],
            "client_application_exact": "Windows App",
            "client_version_exact": (
                f"{macos_version}+{macos_build}"
                if isinstance(macos_version, str) and isinstance(macos_build, str)
                else None
            ),
            "target_identity_exact": macos_row["target_identity_exact"],
            "credential_source_choice": macos_row["credential_source_claim"],
        },
        "MACOS",
    ))
    failures.extend(_source_binding_failures(
        windows["source_binding"],
        {
            "server_sha": windows["server_sha"],
            "server_certificate_sha256": windows["server_certificate_sha256"],
            "destination_exact": windows["destination_exact"],
            "service_endpoint_exact": windows["service_endpoint_exact"],
            "attempt_time_utc": windows["attempt_time_utc"],
            "connection_id": correlation["connection_id"],
            "terminal_time_utc": correlation["terminal_time_utc"],
            "attempt_id_exact": windows["attempt_id_exact"],
            "client_application_exact": "mstsc.exe",
            "client_version_exact": windows["mstsc_file_version"],
            "target_identity_exact": windows["target_identity_exact"],
            "credential_source_choice": credential["source"],
        },
        "WINDOWS",
    ))
    failures.extend(_client_stage_failures(
        macos_row["client_security_stages"], "MACOS"))
    failures.extend(_client_stage_failures(
        windows["client_security_stages"], "WINDOWS"))
    failures.extend(_client_event_failures(
        macos_row["client_security_stages"], macos_row["client_stage_evidence"],
        macos_row["source_binding"], "MACOS"))
    failures.extend(_client_event_failures(
        windows["client_security_stages"], windows["client_stage_evidence"],
        windows["source_binding"], "WINDOWS"))
    failures.extend(_server_type3_failures(
        macos_manifest.get("server_stage_matrix"),
        macos_row["server_type3_evidence"], macos_row["source_binding"], "MACOS"))
    failures.extend(_server_type3_failures(
        windows["server_stage_matrix"],
        windows["server_type3_evidence"], windows["source_binding"], "WINDOWS"))

    windows_stage = windows["server_stage_matrix"]
    failures.extend(_stage_failures(
        macos_manifest.get("server_stage_matrix"),
        macos_row["native_admission"], macos_row["server_transport_observation"],
        "MACOS"))
    failures.extend(_stage_failures(
        windows_stage, windows["native_admission"],
        windows["server_transport_observation"], "WINDOWS"))

    try:
        start = _utc(windows["attempt_time_utc"], "Windows attempt")
        terminal = _utc(correlation["terminal_time_utc"], "Windows terminal")
        macos_start = _utc(macos_manifest.get("attempt_time_utc"), "macOS attempt")
        _text(correlation["connection_id"], "Windows connection ID")
        if abs((terminal - start).total_seconds()) > macos.MAX_CORRELATION_DELTA_SECONDS:
            failures.append("WINDOWS_ATTEMPT_CORRELATION_MISMATCH")
        first_event = (first_error_record.get("event_time_utc")
                       if isinstance(first_error_record, dict) else None)
        if first_event is not None and abs((_utc(first_event, "Windows first error") - start).total_seconds()) > macos.MAX_CORRELATION_DELTA_SECONDS:
            failures.append("WINDOWS_FIRST_ERROR_ATTEMPT_MISMATCH")
        if start <= macos_start:
            failures.append("AB_ATTEMPT_ORDER_INVALID")
        if correlation["connection_id"] == macos_correlation.get("connection_id"):
            failures.append("AB_CONNECTION_ID_REUSED")
    except ValueError:
        failures.append("WINDOWS_ATTEMPT_CORRELATION_INVALID")

    # The macOS collector summary is also untrusted private input.
    macos_version = macos_summary.get("windows_app")
    if not isinstance(macos_version, dict):
        macos_version = {}
    redacted_macos_version = {
        name: _redacted_windows_version(macos_version.get(name))
        for name in ("version", "build")
    }
    if "INVALID" in redacted_macos_version.values():
        failures.append("MACOS_CLIENT_VERSION_INVALID")
    macos_error = macos_summary.get("client_error")
    macos_error_category = (
        macos_error.get("first_typed_category") if isinstance(macos_error, dict) else None
    )
    macos_first_error = macos_manifest.get("first_client_error")
    if (not _is_allowed(macos_error_category, ERROR_CATEGORIES)
            or not isinstance(macos_first_error, dict)
            or set(macos_first_error) != MACOS_FIRST_ERROR_FIELDS
            or not _is_allowed(macos_first_error.get("source"), ERROR_SOURCES)):
        failures.append("MACOS_FIRST_ERROR_INVALID")
    else:
        try:
            for name in ("provider_category_exact", "provider_code_exact"):
                if macos_first_error[name] is not None:
                    _text(macos_first_error[name], f"macOS first error {name}")
            local_time = macos_first_error["event_time_local"]
            utc_time = macos_first_error["event_time_utc"]
            if (local_time is None) != (utc_time is None):
                raise ValueError("macOS first error time pair is incomplete")
            if local_time is not None and (
                    _utc(local_time, "macOS first error local time") !=
                    _utc(utc_time, "macOS first error UTC time")):
                raise ValueError("macOS first error time pair is inconsistent")
        except ValueError:
            failures.append("MACOS_FIRST_ERROR_INVALID")

    # Treat every input string as private. Only enumerated, redacted facts enter stdout.
    macos_type3 = _redacted_stage(
        _private_mapping(macos_manifest.get("server_stage_matrix")).get("type3_received"),
        STAGE_STATES, "NOT_REACHED")
    windows_type3 = _redacted_stage(
        windows_stage.get("type3_received") if isinstance(windows_stage, dict) else None,
        STAGE_STATES, "NOT_REACHED")
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
            "app": "Windows App", "version": redacted_macos_version,
            "first_client_error_category": _redacted_stage(
                macos_error_category, ERROR_CATEGORIES, "unknown"),
            "type3_received": macos_type3,
            "client_security_stages": _redacted_client_stages(
                macos_row["client_security_stages"]),
            "native_admission": _redacted_stage(
                macos_row["native_admission"], STAGE_STATES, "NOT_REACHED"),
        },
        "windows": {
            "app": "mstsc.exe",
            "windows_11_build": _redacted_windows_version(windows["windows_11_build"]),
            "mstsc_file_version": _redacted_windows_version(windows["mstsc_file_version"]),
            "first_client_error_category": _redacted_stage(
                first_error_record.get("normalized_category")
                if isinstance(first_error_record, dict) else None,
                ERROR_CATEGORIES, "unknown"),
            "type3_received": windows_type3,
            "client_security_stages": _redacted_client_stages(
                windows["client_security_stages"]),
            "native_admission": _redacted_stage(
                windows["native_admission"], STAGE_STATES, "NOT_REACHED"),
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
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        # Filesystem/JSON exceptions may contain private paths or source text.
        print("client A/B evidence: private record invalid", file=sys.stderr)
        return 2
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if summary["evidence_status"] == "PASS" else 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
