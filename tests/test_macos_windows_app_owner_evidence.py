# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the read-only macOS Windows App evidence manifest."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--script", type=Path, required=True)
args, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("macos_windows_app_owner_evidence", args.script)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class OwnerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "Windows App.app"
        contents = self.app / "Contents"
        contents.mkdir(parents=True)
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(
                {
                    "CFBundleShortVersionString": "11.4.4",
                    "CFBundleVersion": "3132",
                    "CFBundleIdentifier": "example.windows-app",
                    "CFBundleExecutable": "Windows App",
                },
                stream,
            )
        self.logs = self.root / "logs"
        self.logs.mkdir()
        (self.logs / "client.log").write_bytes(b"same-attempt-log\n")
        self.options = argparse.Namespace(
            app=self.app,
            server_sha="a" * 40,
            server_certificate_sha256="b" * 64,
            attempt_time="2026-10-27T05:30:00-07:00",
            destination="192.0.2.10",
            saved_credential_state="explicit-saved-selected",
            saved_credential_username="rdp-owner",
            saved_credential_newly_created="yes",
            server_client_credentials_intentionally_matched="yes",
            certificate_warning="yes",
            certificate_warning_accepted="yes",
            error_text="We couldn't connect. Error code: 0x204",
            client_error_code="0x204",
            first_client_error_category="unknown",
            first_client_error_source="ui-error",
            first_client_provider_category=None,
            first_client_provider_code=None,
            first_client_error_time=None,
            core_log_level="Info",
            ui_log_level="Info",
            logging_started="yes",
            logging_stopped="yes",
            linux_connection_id="connection-42",
            linux_terminal_time="2026-10-27T05:30:07-07:00",
            stage_tls_established="PASS",
            stage_type1_received="PASS",
            stage_type2_committed="PASS",
            post_type2_client_bytes=0,
            stage_type3_received="NOT_REACHED",
            stage_pubkeyauth_reached="NOT_REACHED",
            stage_authinfo_reached="NOT_REACHED",
            stage_credentials_verified="NOT_REACHED",
            typed_terminal_outcome="peer-eof-await-type3",
            accepted_to_tls_us=4_825_323,
            tls_to_type1_us=1_176_476,
            type1_to_type2_queued_us=4,
            type2_creation_to_delivery_us=25_324,
            type2_to_peer_eof_us=48_702,
            preauth_elapsed_at_peer_eof_us=7_586_602,
            post_type2_first_client_tls_byte_us=None,
            pre_tls_read_wait_us=4_500_000,
            pre_tls_write_wait_us=5_000,
            pre_tls_active_work_us=40_000,
            tls_handshake_active_work_us=120_000,
            pre_tls_unattributed_us=160_323,
            pre_tls_socket_poll_us=500,
            pre_tls_read_ready_to_service_us=2_400_000,
            pre_tls_write_ready_to_service_us=0,
            accepted_to_tls_app_wait_us=2_300_000,
            accepted_to_tls_peer_wait_upper_us=2_200_000,
            accepted_to_tls_service_work_us=100_000,
            accepted_to_tls_native_maintenance_us=0,
            accepted_to_tls_service_calls=12,
            accepted_to_tls_max_app_gap_us=75_000,
            tls_to_type1_app_wait_us=500_000,
            tls_to_type1_peer_wait_upper_us=500_000,
            tls_to_type1_service_work_us=150_000,
            tls_to_type1_native_maintenance_us=0,
            tls_to_type1_service_calls=8,
            tls_to_type1_max_app_gap_us=70_000,
            logs=self.logs,
            logs_unavailable_reason=None,
        )

    def test_manifest_records_exact_attempt_and_hash_without_mutation(self):
        app_info = self.app / "Contents" / "Info.plist"
        log_file = self.logs / "client.log"
        before = (
            app_info.stat().st_mtime_ns,
            app_info.stat().st_size,
            log_file.stat().st_mtime_ns,
            log_file.stat().st_size,
        )
        manifest = evidence.build_manifest(self.options)
        after = (
            app_info.stat().st_mtime_ns,
            app_info.stat().st_size,
            log_file.stat().st_mtime_ns,
            log_file.stat().st_size,
        )
        self.assertEqual(before, after)
        self.assertEqual(manifest["schema"], "rdp-server.macos-windows-app-owner-evidence.v2")
        self.assertEqual(manifest["server_sha"], "a" * 40)
        self.assertEqual(manifest["server_certificate_sha256"], "b" * 64)
        self.assertEqual(manifest["attempt_time_utc"], "2026-10-27T12:30:00+00:00")
        self.assertEqual(manifest["destination_exact"], "192.0.2.10")
        self.assertEqual(manifest["windows_app"]["version"], "11.4.4")
        self.assertEqual(manifest["windows_app"]["build"], "3132")
        self.assertEqual(manifest["saved_credential"]["state"], "explicit-saved-selected")
        self.assertEqual(manifest["saved_credential"]["username_exact"], "rdp-owner")
        self.assertEqual(manifest["saved_credential"]["newly_created_for_attempt"], "yes")
        self.assertEqual(
            manifest["saved_credential"]["server_client_credentials_intentionally_matched"],
            "yes",
        )
        self.assertTrue(manifest["logging"]["started_before_attempt"])
        self.assertTrue(manifest["logging"]["stopped_after_attempt"])
        self.assertEqual(manifest["linux_correlation"]["connection_id"], "connection-42")
        self.assertEqual(
            manifest["linux_correlation"]["terminal_time_utc"],
            "2026-10-27T12:30:07+00:00",
        )
        self.assertEqual(manifest["logging"]["file_count"], 1)
        self.assertEqual(
            manifest["logging"]["files"][0]["sha256"],
            hashlib.sha256(b"same-attempt-log\n").hexdigest(),
        )
        self.assertEqual(
            manifest["server_stage_matrix"]["type2_fully_committed"], "PASS"
        )
        timing = manifest["server_timing_attribution"]
        self.assertEqual(timing["accepted_to_tls_microseconds"], 4_825_323)
        self.assertEqual(timing["tls_to_type1_microseconds"], 1_176_476)
        self.assertEqual(
            timing["accepted_to_tls_service"]["native_maintenance_microseconds"],
            0,
        )
        self.assertEqual(
            timing["tls_to_type1_service"]["native_maintenance_microseconds"],
            0,
        )
        self.assertNotIn("password", json.dumps(manifest).lower())

    def test_explicit_saved_credential_requires_typed_metadata(self):
        self.options.saved_credential_username = "not-applicable"
        with self.assertRaisesRegex(ValueError, "username is required"):
            evidence.build_manifest(self.options)
        self.options.saved_credential_username = "rdp-owner"
        self.options.saved_credential_newly_created = "not-applicable"
        with self.assertRaisesRegex(ValueError, "newly-created state"):
            evidence.build_manifest(self.options)
        self.options.saved_credential_newly_created = "no"
        self.options.server_client_credentials_intentionally_matched = "not-applicable"
        with self.assertRaisesRegex(ValueError, "match state"):
            evidence.build_manifest(self.options)

    def test_ask_when_required_has_no_saved_credential_metadata(self):
        self.options.saved_credential_state = "ask-when-required-or-none"
        self.options.saved_credential_username = "not-applicable"
        self.options.saved_credential_newly_created = "not-applicable"
        self.options.server_client_credentials_intentionally_matched = "not-applicable"
        manifest = evidence.build_manifest(self.options)
        self.assertIsNone(manifest["saved_credential"]["username_exact"])
        self.options.saved_credential_username = "rdp-owner"
        with self.assertRaisesRegex(ValueError, "must be not-applicable"):
            evidence.build_manifest(self.options)

    def test_no_warning_requires_not_applicable_acceptance(self):
        self.options.certificate_warning = "no"
        self.options.certificate_warning_accepted = "no"
        with self.assertRaisesRegex(ValueError, "not-applicable"):
            evidence.build_manifest(self.options)
        self.options.certificate_warning_accepted = "not-applicable"
        self.assertFalse(
            evidence.build_manifest(self.options)["certificate_warning"]["appeared"]
        )

    def test_log_unavailable_reason_is_explicit(self):
        self.options.logs = None
        self.options.logs_unavailable_reason = "Logging UI unavailable in this build."
        manifest = evidence.build_manifest(self.options)
        self.assertFalse(manifest["logging"]["available"])
        self.assertIn("unavailable", manifest["logging"]["reason"])
        summary = evidence.build_redacted_summary(manifest)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("CLIENT_LOGS_MISSING", summary["evidence_failures"])

    def test_symlinked_log_input_is_rejected(self):
        target = self.root / "outside.log"
        target.write_text("outside", encoding="utf-8")
        (self.logs / "link.log").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            evidence.build_manifest(self.options)

    def test_sha_and_timestamps_are_bounded_and_typed(self):
        self.options.server_sha = "short"
        with self.assertRaisesRegex(ValueError, "40 hexadecimal"):
            evidence.build_manifest(self.options)
        self.options.server_sha = "b" * 40
        self.options.server_certificate_sha256 = "not-a-fingerprint"
        with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
            evidence.build_manifest(self.options)
        self.options.server_certificate_sha256 = "c" * 64
        self.options.attempt_time = "2026-10-27T05:30:00"
        with self.assertRaisesRegex(ValueError, "UTC offset"):
            evidence.build_manifest(self.options)
        self.options.attempt_time = "2026-10-27T05:30:00-07:00"
        self.options.linux_terminal_time = "2026-10-27T05:30:07"
        with self.assertRaisesRegex(ValueError, "Linux terminal time.*UTC offset"):
            evidence.build_manifest(self.options)


    def test_redacted_summary_preserves_actionable_facts_without_private_text(self):
        manifest = evidence.build_manifest(self.options)
        summary = evidence.build_redacted_summary(manifest)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertEqual(summary["server_sha"], "a" * 40)
        self.assertEqual(summary["server_certificate_sha256"], "b" * 64)
        self.assertEqual(summary["client_error"]["ui_code"], "0x204")
        self.assertEqual(summary["client_error"]["first_typed_category"], "unknown")
        self.assertIn("BARE_0X204_NOT_TYPED", summary["diagnostic_limitations"])
        self.assertEqual(
            summary["linux_correlation"]["absolute_timestamp_delta_seconds"], 7.0
        )
        self.assertTrue(summary["server_pre_auth_native_isolation"]["qualified"])
        self.assertEqual(
            summary["server_timing_attribution"]["accepted_to_tls_service"][
                "maximum_application_reschedule_wait_microseconds"
            ],
            75_000,
        )
        serialized = json.dumps(summary)
        self.assertNotIn("rdp-owner", serialized)
        self.assertNotIn("We couldn't connect", serialized)
        self.assertNotIn("connection-42", serialized)
        self.assertNotIn("client.log", serialized)
        self.assertNotIn(
            hashlib.sha256(b"same-attempt-log\n").hexdigest(), serialized
        )

    def test_clock_skew_is_an_explicit_evidence_failure(self):
        self.options.linux_terminal_time = "2026-10-27T05:40:07-07:00"
        summary = evidence.build_redacted_summary(
            evidence.build_manifest(self.options)
        )
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn(
            "CLOCK_SKEW_OR_ATTEMPT_MISMATCH", summary["evidence_failures"]
        )

    def test_specific_client_error_requires_private_provider_category(self):
        self.options.first_client_error_category = "credential"
        self.options.first_client_error_source = "core"
        with self.assertRaisesRegex(
            ValueError, "requires the exact private provider category"
        ):
            evidence.build_manifest(self.options)

        self.options.first_client_provider_category = "CredentialProvider"
        self.options.first_client_provider_code = "example-status"
        self.options.first_client_error_time = "2026-10-27T05:30:05-07:00"
        summary = evidence.build_redacted_summary(
            evidence.build_manifest(self.options)
        )
        self.assertEqual(
            summary["client_error"]["first_typed_category"], "credential"
        )
        self.assertTrue(summary["client_error"]["provider_category_present"])
        self.assertNotIn("CredentialProvider", json.dumps(summary))

    def test_inconsistent_server_stage_matrix_fails_validation(self):
        self.options.stage_type3_received = "NOT_REACHED"
        self.options.stage_pubkeyauth_reached = "PASS"
        summary = evidence.build_redacted_summary(
            evidence.build_manifest(self.options)
        )
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn(
            "SERVER_STAGE_MATRIX_INCONSISTENT", summary["evidence_failures"]
        )

    def test_pair_comparison_rejects_invalid_ab_attempt(self):
        manifest = evidence.build_manifest(self.options)
        pair = argparse.Namespace(
            peer_server_sha="a" * 40,
            peer_destination="192.0.2.11",
            peer_certificate_sha256="c" * 64,
            peer_username="rdp-owner",
            peer_session_password_matched="yes",
            peer_certificate_warning="no",
            peer_certificate_warning_accepted="not-applicable",
        )
        summary = evidence.build_redacted_summary(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("AB_DESTINATION_MISMATCH", summary["evidence_failures"])
        self.assertIn(
            "AB_CERTIFICATE_FINGERPRINT_MISMATCH",
            summary["evidence_failures"],
        )
        self.assertIn(
            "CERTIFICATE_DECISION_NOT_COMPARABLE",
            summary["evidence_failures"],
        )

    def test_missing_server_timing_is_an_explicit_evidence_failure(self):
        self.options.accepted_to_tls_us = None
        summary = evidence.build_redacted_summary(
            evidence.build_manifest(self.options)
        )
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn(
            "SERVER_TIMING_ATTRIBUTION_INCOMPLETE",
            summary["evidence_failures"],
        )

    def test_post_type2_first_byte_must_match_server_byte_count(self):
        self.options.post_type2_first_client_tls_byte_us = 123
        summary = evidence.build_redacted_summary(
            evidence.build_manifest(self.options)
        )
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn(
            "SERVER_TIMING_ATTRIBUTION_INCONSISTENT",
            summary["evidence_failures"],
        )

    def test_early_native_maintenance_is_reported_without_guessing_cause(self):
        self.options.accepted_to_tls_native_maintenance_us = 9
        summary = evidence.build_redacted_summary(
            evidence.build_manifest(self.options)
        )
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertFalse(summary["server_pre_auth_native_isolation"]["qualified"])
        self.assertIn(
            "EARLY_NATIVE_MAINTENANCE_OBSERVED",
            summary["diagnostic_findings"],
        )

    def test_complete_pair_comparison_is_redacted_and_valid(self):
        manifest = evidence.build_manifest(self.options)
        pair = argparse.Namespace(
            peer_server_sha="a" * 40,
            peer_destination="192.0.2.10",
            peer_certificate_sha256="b" * 64,
            peer_username="rdp-owner",
            peer_session_password_matched="yes",
            peer_certificate_warning="yes",
            peer_certificate_warning_accepted="yes",
        )
        summary = evidence.build_redacted_summary(manifest, pair)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertTrue(summary["pair_comparison"]["valid"])
        self.assertNotIn("rdp-owner", json.dumps(summary))
        self.assertNotIn("192.0.2.10", json.dumps(summary))


if __name__ == "__main__":
    unittest.main(argv=["owner-evidence-tests", *remaining])
