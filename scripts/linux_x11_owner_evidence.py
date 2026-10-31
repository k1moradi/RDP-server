#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline, fail-closed validator and redactor for Linux/X11 owner-private receipts.

This module has no runtime, socket, desktop, credential, or native-event imports.
It consumes copied scalar observations only; it cannot prolong X11/R2 borrows.
"""

import argparse
import json
import re
import sys
from pathlib import Path

PRIVATE_SCHEMA = "rdp-server.linux-x11-owner-evidence.v1"
PUBLIC_SCHEMA = "rdp-server.linux-x11-owner-evidence-redacted.v1"
STAGE_OUTCOMES = frozenset({"PASS", "FAIL", "NOT_OBSERVED"})
STAGE_ORDER = (
    "tls", "type1", "type2", "type3", "pubkeyauth", "authinfo",
    "credentials_verified", "native_admission", "mcs", "share",
    "graphics_ready", "first_frame", "matching_ack",
)
ADDITIONAL_STAGES = ("keyboard_dispatch", "mouse_dispatch", "randr_replacement")
RECONNECT_STAGES = ("credentials_verified", "native_admission", "share", "graphics_ready", "first_frame", "matching_ack")
RETIREMENT_KINDS = frozenset({"stop", "lock", "logout", "switch_user"})
MAXIMUM_MANIFEST_BYTES = 256 * 1024


class EvidenceError(ValueError):
    """A malformed or contradictory private attempt (messages contain no values)."""


def require_fields(value, expected, location):
    if type(value) is not dict or set(value) != set(expected):
        raise EvidenceError(f"invalid fields at {location}")
    return value


def require_bool(value, location, nullable=False):
    if type(value) is bool or (nullable and value is None):
        return value
    raise EvidenceError(f"invalid boolean at {location}")


def require_generation(value, location, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not int or not 0 < value <= (1 << 64) - 1:
        raise EvidenceError(f"invalid generation at {location}")
    return value


def require_counter(value, location):
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise EvidenceError(f"invalid counter at {location}")
    return value


def require_stages(stages, names, location):
    require_fields(stages, names, location)
    for name in names:
        if type(stages[name]) is not str or stages[name] not in STAGE_OUTCOMES:
            raise EvidenceError(f"invalid stage at {location}.{name}")


def require_pass(stages, prerequisite, dependent):
    if stages[dependent] == "PASS" and stages[prerequisite] != "PASS":
        raise EvidenceError(f"{dependent} requires {prerequisite}")


def validate(record):
    """Return a safe public projection, or raise without leaking private data."""
    require_fields(record, (
        "schema", "source_sha", "client", "sharing", "credentials", "seat",
        "generations", "stages", "frame", "input", "randr", "retirements", "reconnect",
    ), "record")
    if record["schema"] != PRIVATE_SCHEMA:
        raise EvidenceError("unsupported private schema")
    if type(record["source_sha"]) is not str or not re.fullmatch(r"[0-9a-fA-F]{40}", record["source_sha"]):
        raise EvidenceError("invalid exact source SHA")

    client = require_fields(record["client"], ("type", "version"), "client")
    for name in ("type", "version"):
        value = client[name]
        if type(value) is not str or not (1 <= len(value) <= 80) or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise EvidenceError(f"invalid client {name}")

    sharing = require_fields(record["sharing"], (
        "initial", "enabled", "owner_grant_recorded", "consent_generation",
    ), "sharing")
    if sharing["initial"] != "OFF":
        raise EvidenceError("Sharing must begin OFF")
    for name in ("enabled", "owner_grant_recorded"):
        require_bool(sharing[name], f"sharing.{name}")
    require_generation(sharing["consent_generation"], "sharing.consent_generation", nullable=True)
    if sharing["enabled"] and not sharing["owner_grant_recorded"]:
        raise EvidenceError("Sharing ON requires explicit owner grant")
    if (sharing["consent_generation"] is not None) != sharing["owner_grant_recorded"]:
        raise EvidenceError("consent generation must track owner grant")

    credentials = require_fields(record["credentials"], (
        "username_matches", "session_password_matches", "selected_credential_matches",
    ), "credentials")
    for name, value in credentials.items():
        require_bool(value, f"credentials.{name}", nullable=True)

    seat = require_fields(record["seat"], (
        "graphical", "seat0", "unlocked", "current_session", "process_uid_matches_owner",
    ), "seat")
    for name, value in seat.items():
        require_bool(value, f"seat.{name}", nullable=True)

    generations = require_fields(record["generations"], (
        "linux_session", "r2_admission", "native_capture", "admission_consent",
    ), "generations")
    for name, value in generations.items():
        require_generation(value, f"generations.{name}", nullable=True)

    stages = record["stages"]
    require_stages(stages, STAGE_ORDER + ADDITIONAL_STAGES, "stages")
    for prerequisite, dependent in zip(STAGE_ORDER, STAGE_ORDER[1:]):
        require_pass(stages, prerequisite, dependent)
    for name in ADDITIONAL_STAGES:
        require_pass(stages, "graphics_ready", name)

    if stages["credentials_verified"] == "PASS" and any(value is not True for value in credentials.values()):
        raise EvidenceError("CredentialsVerified requires matching credential facts")
    if stages["native_admission"] == "PASS":
        if not sharing["enabled"] or not sharing["owner_grant_recorded"]:
            raise EvidenceError("native Admission requires explicit Sharing ON")
        if any(value is not True for value in seat.values()):
            raise EvidenceError("native Admission requires unlocked graphical seat0 and matching owner")
        if any(generations[name] is None for name in ("linux_session", "r2_admission", "admission_consent")):
            raise EvidenceError("native Admission requires current native generation and R2 consent")
        if generations["admission_consent"] != sharing["consent_generation"]:
            raise EvidenceError("native Admission owner consent epoch mismatch")
    elif generations["admission_consent"] is not None:
        raise EvidenceError("unverified native Admission cannot claim a consent epoch")
    if generations["native_capture"] is not None and stages["native_admission"] != "PASS":
        raise EvidenceError("native capture without Admission")
    if stages["first_frame"] == "PASS" and generations["native_capture"] is None:
        raise EvidenceError("first frame requires native capture generation")

    frame = require_fields(record["frame"], ("first_frame_capture_generation", "ack_capture_generation"), "frame")
    for name in frame:
        require_generation(frame[name], f"frame.{name}", nullable=True)
    if (stages["first_frame"] == "PASS") != (frame["first_frame_capture_generation"] is not None):
        raise EvidenceError("frame generation disagrees with first-frame stage")
    if frame["first_frame_capture_generation"] is not None and frame["first_frame_capture_generation"] != generations["native_capture"]:
        raise EvidenceError("first frame does not match native capture generation")
    if (stages["matching_ack"] == "PASS") != (frame["ack_capture_generation"] is not None):
        raise EvidenceError("ACK generation disagrees with matching-ACK stage")
    if frame["ack_capture_generation"] is not None and frame["ack_capture_generation"] != frame["first_frame_capture_generation"]:
        raise EvidenceError("ACK generation does not match first-frame generation")

    input_facts = require_fields(record["input"], (
        "keyboard_posts", "mouse_posts", "posts_after_revocation",
    ), "input")
    for name, value in input_facts.items():
        require_counter(value, f"input.{name}")
    if input_facts["posts_after_revocation"] != 0:
        raise EvidenceError("input posted after revocation")
    for name, counter in (("keyboard_dispatch", "keyboard_posts"), ("mouse_dispatch", "mouse_posts")):
        if (stages[name] == "PASS") != (input_facts[counter] > 0):
            raise EvidenceError(f"{name} contradicts post count")

    randr = require_fields(record["randr"], ("replacement_capture_generation",), "randr")
    replacement = require_generation(randr["replacement_capture_generation"], "randr.replacement_capture_generation", nullable=True)
    if (stages["randr_replacement"] == "PASS") != (replacement is not None):
        raise EvidenceError("RandR replacement stage disagrees with generation")
    if replacement is not None and replacement == generations["native_capture"]:
        raise EvidenceError("RandR replacement reused old capture generation")

    retirements = record["retirements"]
    if type(retirements) is not list or len(retirements) > 1:
        raise EvidenceError("invalid retirement sequence")
    seen_kinds = set()
    for event in retirements:
        require_fields(event, (
            "kind", "r2_retired", "capture_retired", "posts_after_revocation", "frames_after_revocation",
            "linux_session_generation_after",
        ), "retirement")
        kind = event["kind"]
        if type(kind) is not str or kind not in RETIREMENT_KINDS or kind in seen_kinds:
            raise EvidenceError("invalid or duplicate retirement kind")
        seen_kinds.add(kind)
        for name in ("r2_retired", "capture_retired"):
            require_bool(event[name], f"retirement.{name}")
        require_counter(event["posts_after_revocation"], "retirement.posts_after_revocation")
        require_counter(event["frames_after_revocation"], "retirement.frames_after_revocation")
        require_generation(event["linux_session_generation_after"], "retirement.linux_session_generation_after", nullable=True)
        if event["posts_after_revocation"] != 0:
            raise EvidenceError("retired owner received input posts")
        if event["frames_after_revocation"] != 0:
            raise EvidenceError("retired owner published frames")
        if stages["native_admission"] == "PASS" and not (event["r2_retired"] and event["capture_retired"]):
            raise EvidenceError("retirement must invalidate R2 and capture")
        if kind in ("logout", "switch_user") and event["linux_session_generation_after"] == generations["linux_session"]:
            raise EvidenceError("logout or switch-user reused old session generation")

    reconnect = require_fields(record["reconnect"], (
        "observed", "owner_grant_recorded", "consent_generation", "admission_consent_generation", "linux_session_generation",
        "r2_admission_generation", "native_capture_generation", "seat", "stages",
        "first_frame_capture_generation", "ack_capture_generation", "posts_after_revocation",
    ), "reconnect")
    for name in ("observed", "owner_grant_recorded"):
        require_bool(reconnect[name], f"reconnect.{name}")
    for name in ("consent_generation", "admission_consent_generation", "linux_session_generation", "r2_admission_generation", "native_capture_generation"):
        require_generation(reconnect[name], f"reconnect.{name}", nullable=True)
    reconnect_seat = require_fields(reconnect["seat"], seat.keys(), "reconnect.seat")
    for name, value in reconnect_seat.items():
        require_bool(value, f"reconnect.seat.{name}", nullable=True)
    require_stages(reconnect["stages"], RECONNECT_STAGES, "reconnect.stages")
    for name, stage in (("first_frame_capture_generation", "first_frame"), ("ack_capture_generation", "matching_ack")):
        require_generation(reconnect[name], f"reconnect.{name}", nullable=True)
        if (reconnect["stages"][stage] == "PASS") != (reconnect[name] is not None):
            raise EvidenceError("reconnect frame or ACK generation disagrees with stage")
    if reconnect["first_frame_capture_generation"] is not None and reconnect["first_frame_capture_generation"] != reconnect["native_capture_generation"]:
        raise EvidenceError("reconnect frame has stale capture generation")
    if reconnect["ack_capture_generation"] is not None and reconnect["ack_capture_generation"] != reconnect["first_frame_capture_generation"]:
        raise EvidenceError("reconnect ACK does not match new frame")
    require_counter(reconnect["posts_after_revocation"], "reconnect.posts_after_revocation")
    if reconnect["posts_after_revocation"] != 0:
        raise EvidenceError("reconnect posted input after revocation")
    for prerequisite, dependent in zip(RECONNECT_STAGES, RECONNECT_STAGES[1:]):
        require_pass(reconnect["stages"], prerequisite, dependent)

    if reconnect["stages"]["native_admission"] == "PASS":
        if any(value is not True for value in reconnect_seat.values()):
            raise EvidenceError("reconnect native Admission requires fresh unlocked owner seat evidence")
        if (not reconnect["observed"] or not reconnect["owner_grant_recorded"] or
                reconnect["admission_consent_generation"] is None or
                reconnect["admission_consent_generation"] != reconnect["consent_generation"]):
            raise EvidenceError("reconnect native Admission owner consent epoch mismatch")
    elif reconnect["admission_consent_generation"] is not None:
        raise EvidenceError("unverified reconnect Admission cannot claim a consent epoch")

    if reconnect["observed"]:
        if not retirements or stages["native_admission"] != "PASS":
            raise EvidenceError("reconnect requires previously admitted retired owner")
        if not reconnect["owner_grant_recorded"]:
            raise EvidenceError("reconnect needs fresh explicit owner grant")
        if any(reconnect[name] is None for name in (
            "consent_generation", "linux_session_generation", "r2_admission_generation", "native_capture_generation",
        )):
            raise EvidenceError("reconnect requires generation observations")
        if reconnect["consent_generation"] <= sharing["consent_generation"]:
            raise EvidenceError("reconnect reused retired consent generation")
        if reconnect["r2_admission_generation"] == generations["r2_admission"]:
            raise EvidenceError("reconnect reused retired R2 admission generation")
        if reconnect["native_capture_generation"] in (generations["native_capture"], replacement):
            raise EvidenceError("reconnect reused retired capture generation")
        if any(event["kind"] in ("logout", "switch_user") for event in retirements) and reconnect["linux_session_generation"] == generations["linux_session"]:
            raise EvidenceError("session-changing reconnect reused old Linux session")
    elif (any(value is not None for value in reconnect_seat.values()) or
          reconnect["owner_grant_recorded"] or
          any(reconnect[name] is not None for name in (
              "consent_generation", "admission_consent_generation", "linux_session_generation", "r2_admission_generation", "native_capture_generation", "first_frame_capture_generation", "ack_capture_generation")) or
          any(stage != "NOT_OBSERVED" for stage in reconnect["stages"].values())):
        raise EvidenceError("unobserved reconnect contains claimed evidence")

    # All public keys and values are selected from a constant allowlist. Do not
    # serialize source_sha, versions, counters, IDs, or anything from event data.
    return {
        "schema": PUBLIC_SCHEMA,
        "stages": dict(stages),
        "reconnect_stages": dict(reconnect["stages"]),
        "retirement_outcomes": {kind: "PASS" for kind in sorted(seen_kinds)},
        "input_after_revocation": "PASS" if retirements else "NOT_OBSERVED",
        "generation_matches": {
            "initial_frame_matches_capture": frame["first_frame_capture_generation"] is not None and frame["first_frame_capture_generation"] == generations["native_capture"],
            "initial_ack_matches_frame": frame["ack_capture_generation"] is not None and frame["ack_capture_generation"] == frame["first_frame_capture_generation"],
            "reconnect_frame_matches_capture": reconnect["first_frame_capture_generation"] is not None and reconnect["first_frame_capture_generation"] == reconnect["native_capture_generation"],
            "reconnect_ack_matches_frame": reconnect["ack_capture_generation"] is not None and reconnect["ack_capture_generation"] == reconnect["first_frame_capture_generation"],
            "randr_capture_replaced": replacement is not None,
            "reconnect_consent_changed": reconnect["observed"] and reconnect["consent_generation"] != sharing["consent_generation"],
            "reconnect_r2_changed": reconnect["observed"] and reconnect["r2_admission_generation"] != generations["r2_admission"],
            "reconnect_capture_changed": reconnect["observed"] and reconnect["native_capture_generation"] != generations["native_capture"],
            "reconnect_linux_session_changed": reconnect["observed"] and reconnect["linux_session_generation"] != generations["linux_session"],
        },
    }


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="owner-private JSON file (never uploaded)")
    options = parser.parse_args(argv)
    try:
        with options.input.open("rb") as source:
            data = source.read(MAXIMUM_MANIFEST_BYTES + 1)
        if len(data) > MAXIMUM_MANIFEST_BYTES:
            raise EvidenceError("private record exceeds size limit")
        record = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
        redacted = validate(record)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, EvidenceError) as error:
        # Do not echo paths or untrusted record values to stderr.
        if isinstance(error, EvidenceError):
            print(f"rejected: {error}", file=sys.stderr)
        else:
            print("rejected: invalid or unreadable private JSON", file=sys.stderr)
        return 1
    print(json.dumps(redacted, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
