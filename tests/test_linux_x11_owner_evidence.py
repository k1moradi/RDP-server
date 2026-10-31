#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline acceptance-evidence behavior denials; never opens a desktop/client."""

import argparse
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def load_validator(path):
    spec = importlib.util.spec_from_file_location("linux_x11_owner_evidence", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admitted_attempt(evidence):
    return {
        "schema": evidence.PRIVATE_SCHEMA,
        "source_sha": "a" * 40,
        "client": {"type": "Windows App", "version": "11.4"},
        "sharing": {"initial": "OFF", "enabled": True, "owner_grant_recorded": True, "consent_generation": 10},
        "credentials": {"username_matches": True, "session_password_matches": True, "selected_credential_matches": True},
        "seat": {"graphical": True, "seat0": True, "unlocked": True, "current_session": True, "process_uid_matches_owner": True},
        "generations": {"linux_session": 20, "r2_admission": 30, "native_capture": 40},
        "stages": {name: "PASS" for name in evidence.STAGE_ORDER + evidence.ADDITIONAL_STAGES},
        "frame": {"first_frame_capture_generation": 40, "ack_capture_generation": 40},
        "input": {"keyboard_posts": 1, "mouse_posts": 2, "posts_after_revocation": 0},
        "randr": {"replacement_capture_generation": 41},
        "retirements": [{"kind": "stop", "r2_retired": True, "capture_retired": True,
                         "posts_after_revocation": 0, "linux_session_generation_after": 20}],
        "reconnect": {"observed": True, "owner_grant_recorded": True, "consent_generation": 11,
                      "linux_session_generation": 20, "r2_admission_generation": 31,
                      "native_capture_generation": 42,
                      "stages": {name: "PASS" for name in evidence.RECONNECT_STAGES},
                      "first_frame_capture_generation": 42, "ack_capture_generation": 42,
                      "posts_after_revocation": 0},
    }


class LinuxX11OwnerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = load_validator(Path(cls.script))

    def setUp(self):
        self.record = admitted_attempt(self.evidence)

    def reject(self, change):
        record = copy.deepcopy(self.record)
        change(record)
        with self.assertRaises(self.evidence.EvidenceError):
            self.evidence.validate(record)

    def test_valid_attempt_redacts_every_private_identifier_and_count(self):
        record = self.record
        record["source_sha"] = "e" * 40
        record["client"]["version"] = "SECRET_VERSION_MARKER"
        public = self.evidence.validate(record)
        serialized = json.dumps(public)
        for secret in ("e" * 40, "SECRET_VERSION_MARKER", "Windows App", "keyboard_posts", "consent_generation", "source_sha"):
            self.assertNotIn(secret, serialized)
        self.assertTrue(public["generation_matches"]["reconnect_r2_changed"])
        self.assertTrue(public["generation_matches"]["randr_capture_replaced"])

    def test_frame_without_graphics_or_share(self):
        self.reject(lambda record: record["stages"].update(graphics_ready="NOT_OBSERVED"))
        self.reject(lambda record: record["stages"].update(share="FAIL"))

    def test_admission_without_credentials(self):
        self.reject(lambda record: record["stages"].update(credentials_verified="FAIL"))
        self.reject(lambda record: record["credentials"].update(session_password_matches=False))

    def test_ack_without_frame(self):
        self.reject(lambda record: record["stages"].update(first_frame="NOT_OBSERVED"))
        self.reject(lambda record: record["reconnect"]["stages"].update(first_frame="FAIL"))

    def test_exact_first_frame_and_matching_ack_generations(self):
        self.reject(lambda record: record["frame"].update(first_frame_capture_generation=41))
        self.reject(lambda record: record["frame"].update(ack_capture_generation=41))
        self.reject(lambda record: record["reconnect"].update(first_frame_capture_generation=40))
        self.reject(lambda record: record["reconnect"].update(ack_capture_generation=41))

    def test_input_post_after_revocation(self):
        self.reject(lambda record: record["input"].update(posts_after_revocation=1))
        self.reject(lambda record: record["retirements"][0].update(posts_after_revocation=1))
        self.reject(lambda record: record["reconnect"].update(posts_after_revocation=1))

    def test_reconnect_reuses_retired_ownership_generation(self):
        self.reject(lambda record: record["reconnect"].update(r2_admission_generation=30))
        self.reject(lambda record: record["reconnect"].update(native_capture_generation=40))
        self.reject(lambda record: record["reconnect"].update(native_capture_generation=41))
        self.reject(lambda record: record["reconnect"].update(consent_generation=10))

    def test_sharing_on_without_owner_grant(self):
        self.reject(lambda record: record["sharing"].update(owner_grant_recorded=False))
        self.reject(lambda record: record["sharing"].update(initial="ON"))
        self.reject(lambda record: record["reconnect"].update(owner_grant_recorded=False))

    def test_locked_or_mismatched_seat0_owner(self):
        for name in ("graphical", "seat0", "unlocked", "current_session", "process_uid_matches_owner"):
            with self.subTest(name=name):
                self.reject(lambda record: record["seat"].update({name: False}))
                self.reject(lambda record: record["seat"].update({name: None}))

    def test_retirement_and_session_change(self):
        self.reject(lambda record: record["retirements"][0].update(capture_retired=False))
        def switch_without_session_change(record):
            record["retirements"][0]["kind"] = "switch_user"
        self.reject(switch_without_session_change)

    def test_bad_randr_and_input_count(self):
        self.reject(lambda record: record["randr"].update(replacement_capture_generation=40))
        self.reject(lambda record: record["input"].update(keyboard_posts=0))

    def test_extra_private_raw_fields_and_nonboolean_types_rejected(self):
        self.reject(lambda record: record.update(uid=1000))
        self.reject(lambda record: record["client"].update(destination="10.0.0.5"))
        self.reject(lambda record: record["seat"].update(unlocked=1))
        self.reject(lambda record: record["generations"].update(r2_admission=True))
        self.reject(lambda record: record.update(source_sha="a" * 39))

    def test_unobserved_attempt_allowed_without_implicit_success(self):
        record = copy.deepcopy(self.record)
        record["sharing"] = {"initial": "OFF", "enabled": False, "owner_grant_recorded": False, "consent_generation": None}
        record["credentials"] = {name: None for name in record["credentials"]}
        record["seat"] = {name: None for name in record["seat"]}
        record["generations"] = {name: None for name in record["generations"]}
        record["stages"] = {name: "NOT_OBSERVED" for name in record["stages"]}
        record["frame"] = {name: None for name in record["frame"]}
        record["input"] = {name: 0 for name in record["input"]}
        record["randr"] = {"replacement_capture_generation": None}
        record["retirements"] = []
        record["reconnect"] = {"observed": False, "owner_grant_recorded": False,
                               "consent_generation": None, "linux_session_generation": None,
                               "r2_admission_generation": None, "native_capture_generation": None,
                               "stages": {name: "NOT_OBSERVED" for name in self.evidence.RECONNECT_STAGES},
                               "first_frame_capture_generation": None, "ack_capture_generation": None,
                               "posts_after_revocation": 0}
        public = self.evidence.validate(record)
        self.assertEqual(public["stages"]["native_admission"], "NOT_OBSERVED")
        self.assertEqual(public["input_after_revocation"], "NOT_OBSERVED")

    def test_cli_denies_duplicate_keys_and_never_echoes_private_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "private.json"
            source.write_text('{"password":"SECRETPAYLOAD", "password":"again"}', encoding="utf-8")
            result = subprocess.run([sys.executable, str(self.script), "--input", str(source)],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("SECRETPAYLOAD", result.stderr + result.stdout)
            source.write_text(json.dumps(self.record), encoding="utf-8")
            accepted = subprocess.run([sys.executable, str(self.script), "--input", str(source)],
                                      capture_output=True, text=True, check=False)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(json.loads(accepted.stdout)["schema"], self.evidence.PUBLIC_SCHEMA)
            self.assertNotIn("Windows App", accepted.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", required=True, type=Path)
    options, remaining = parser.parse_known_args()
    LinuxX11OwnerEvidenceTests.script = options.script
    unittest.main(argv=[sys.argv[0], *remaining])
