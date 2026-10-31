# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the read-only macOS Windows App evidence manifest."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import sys
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--script", type=Path, required=True)
args, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("macos_windows_app_owner_evidence", args.script)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)

# Reuse the existing R5 fixture; only the paired validator is new.
sys.path.insert(0, str(args.script.parent))
paired_spec = importlib.util.spec_from_file_location("windows_client_ab_evidence", args.script.with_name("windows_client_ab_evidence.py"))
ab_evidence = importlib.util.module_from_spec(paired_spec)
paired_spec.loader.exec_module(ab_evidence)


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
            pre_tls_active_work_us=160_000,
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

    def test_timing_attribution_subset_denials_and_private_metadata_redaction(self):
        impossible_subsets = (
            ("tls_handshake_active_work_us", 160_001),
            ("pre_tls_read_ready_to_service_us", 4_500_001),
            ("pre_tls_write_ready_to_service_us", 5_001),
            ("pre_tls_socket_poll_us", 4_505_001),
            ("accepted_to_tls_native_maintenance_us", 100_001),
            ("tls_to_type1_max_app_gap_us", 500_001),
        )
        for name, impossible_value in impossible_subsets:
            with self.subTest(name=name):
                original_value = getattr(self.options, name)
                try:
                    setattr(self.options, name, impossible_value)
                    summary = evidence.build_redacted_summary(
                        evidence.build_manifest(self.options)
                    )
                finally:
                    setattr(self.options, name, original_value)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn(
                    "SERVER_TIMING_ATTRIBUTION_INCONSISTENT",
                    summary["evidence_failures"],
                )

        manifest = evidence.build_manifest(self.options)
        private_marker = "/private/client/username-and-raw-log"
        manifest["server_timing_attribution"]["private_log_path"] = private_marker
        manifest["server_timing_attribution"]["pre_tls"]["username"] = private_marker
        manifest["server_stage_matrix"]["client_identity"] = private_marker
        summary = evidence.build_redacted_summary(manifest)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertNotIn(private_marker, json.dumps(summary))
        self.assertNotIn(
            "private_log_path", summary["server_timing_attribution"]
        )
        self.assertNotIn("username", summary["server_timing_attribution"]["pre_tls"])
        self.assertNotIn("client_identity", summary["server_stage_matrix"])

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


    def _paired_record(self, manifest):
        # Fictitious offline comparison, never a physical admission claim.
        client_unobserved = {
            "type2_received": "NOT_OBSERVED",
            "type2_accepted_by_credssp": "NOT_OBSERVED",
            "type3_generated": "NOT_OBSERVED",
            "type3_delivered": "NOT_OBSERVED",
        }
        service_endpoint = "192.0.2.10:3389"
        windows_attempt = "2026-10-27T12:32:00+00:00"
        windows_terminal = "2026-10-27T12:32:07+00:00"
        return {
            "schema": "rdp-server.windows-client-ab-pair.v2",
            "macos": {
                "server_tls_configuration_profile": "same-server-default-tls",
                "service_endpoint_exact": service_endpoint,
                "credential_source_claim": "explicit-saved-selected",
                "deliberately_reentered": True,
                "source_binding": {
                    "server_sha": manifest["server_sha"],
                    "server_certificate_sha256": manifest["server_certificate_sha256"],
                    "destination_exact": manifest["destination_exact"],
                    "service_endpoint_exact": service_endpoint,
                    "attempt_time_utc": manifest["attempt_time_utc"],
                    "connection_id": manifest["linux_correlation"]["connection_id"],
                    "terminal_time_utc": manifest["linux_correlation"]["terminal_time_utc"],
                    "observation_window_start_utc": manifest["attempt_time_utc"],
                    "observation_window_end_utc": manifest["linux_correlation"]["terminal_time_utc"],
                },
                "client_security_stages": client_unobserved.copy(),
                "server_transport_observation": {
                    "peer_fin_observed": True,
                    "tls_alert_observed": False,
                    "terminal_attribution": "peer-fin",
                },
                "native_admission": "NOT_REACHED",
            },
            "windows": {
                "server_sha": manifest["server_sha"],
                "server_certificate_sha256": manifest["server_certificate_sha256"],
                "destination_exact": manifest["destination_exact"],
                "service_endpoint_exact": service_endpoint,
                "server_tls_configuration_profile": "same-server-default-tls",
                "windows_11_build": "22631.4317",
                "mstsc_file_version": "10.0.22621.1",
                "attempt_time_utc": windows_attempt,
                "credential": {
                    "source": "explicitly-entered",
                    "deliberately_reentered": True,
                    "saved_credential_use": "none",
                    "username_exact": manifest["saved_credential"]["username_exact"],
                    "session_password_intentionally_matched": True,
                },
                "certificate_warning": {"appeared": True, "accepted": "yes"},
                "first_client_error": {
                    "normalized_category": "unknown",
                    "source": "windows-ui",
                    "provider_category_exact": None,
                    "provider_code_exact": None,
                    "event_time_utc": None,
                },
                "client_visible_result": "0x204",
                "linux_correlation": {
                    "connection_id": "connection-43",
                    "terminal_time_utc": windows_terminal,
                },
                "source_binding": {
                    "server_sha": manifest["server_sha"],
                    "server_certificate_sha256": manifest["server_certificate_sha256"],
                    "destination_exact": manifest["destination_exact"],
                    "service_endpoint_exact": service_endpoint,
                    "attempt_time_utc": windows_attempt,
                    "connection_id": "connection-43",
                    "terminal_time_utc": windows_terminal,
                    "observation_window_start_utc": windows_attempt,
                    "observation_window_end_utc": windows_terminal,
                },
                "client_security_stages": client_unobserved.copy(),
                "server_stage_matrix": manifest["server_stage_matrix"].copy(),
                "server_transport_observation": {
                    "peer_fin_observed": True,
                    "tls_alert_observed": False,
                    "terminal_attribution": "peer-fin",
                },
                "native_admission": "NOT_REACHED",
            },
        }

    def test_paired_valid_redacts_credentials_and_attempt_ids(self):
        manifest = evidence.build_manifest(self.options)
        summary = ab_evidence.validate_pair(manifest, self._paired_record(manifest))
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertEqual(summary["comparison"], "NEITHER_TYPE3_RECEIVED")
        for private_value in ("rdp-owner", "192.0.2.10", "connection-43", "0x204"):
            self.assertNotIn(private_value, json.dumps(summary))

    def test_paired_type3_without_post_type2_bytes_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["server_stage_matrix"]["type3_received"] = "PASS"
        self.assertIn("WINDOWS_TYPE3_WITHOUT_POST_TYPE2_BYTES",
                      ab_evidence.validate_pair(manifest, pair)["evidence_failures"])

    def test_paired_client_stages_do_not_infer_server_receipt(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["client_security_stages"] = {
            "type2_received": "PASS",
            "type2_accepted_by_credssp": "PASS",
            "type3_generated": "PASS",
            "type3_delivered": "PASS",
        }
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertEqual(summary["windows"]["type3_received"], "NOT_REACHED")
        self.assertEqual(
            summary["windows"]["client_security_stages"]["type3_delivered"], "PASS"
        )

    def test_paired_client_stage_order_contradictions_are_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["client_security_stages"].update(
            type2_received="FAIL", type2_accepted_by_credssp="PASS"
        )
        self.assertIn(
            "WINDOWS_CLIENT_STAGE_ORDER_CONTRADICTORY",
            ab_evidence.validate_pair(manifest, pair)["evidence_failures"],
        )

    def test_paired_verified_without_authinfo_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["server_stage_matrix"].update(
            post_type2_client_bytes=128, type3_received="PASS",
            credentials_verified="PASS")
        self.assertIn("WINDOWS_STAGE_ORDER_CONTRADICTORY",
                      ab_evidence.validate_pair(manifest, pair)["evidence_failures"])

    def test_paired_native_admission_before_verified_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["native_admission"] = "PASS"
        self.assertIn("WINDOWS_NATIVE_BEFORE_CREDENTIALS_VERIFIED",
                      ab_evidence.validate_pair(manifest, pair)["evidence_failures"])

    def test_paired_server_sha_endpoint_certificate_profile_controls(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["server_sha"] = "c" * 40
        pair["windows"]["destination_exact"] = "192.0.2.99"
        pair["windows"]["service_endpoint_exact"] = "192.0.2.99:3389"
        pair["windows"]["server_certificate_sha256"] = "d" * 64
        pair["windows"]["server_tls_configuration_profile"] = "different"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        for code in ("AB_SERVER_SHA_MISMATCH", "AB_DESTINATION_MISMATCH",
                     "AB_SERVICE_ENDPOINT_MISMATCH",
                     "AB_CERTIFICATE_FINGERPRINT_MISMATCH", "AB_SERVER_PROFILE_MISMATCH"):
            self.assertIn(code, failures)

    def test_paired_nonreentered_or_saved_credential_controls_are_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["macos"]["deliberately_reentered"] = False
        pair["windows"]["credential"]["source"] = "saved-or-default"
        pair["windows"]["credential"]["saved_credential_use"] = "preexisting-selected"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("MACOS_CREDENTIAL_NOT_REENTERED", failures)
        self.assertIn("WINDOWS_INVALID_CREDENTIAL_CONTROL", failures)

    def test_paired_fin_cannot_be_unobserved_tls_alert(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["server_transport_observation"]["terminal_attribution"] = "tls-alert"
        self.assertIn("WINDOWS_TLS_ALERT_NOT_OBSERVED",
                      ab_evidence.validate_pair(manifest, pair)["evidence_failures"])

    def test_paired_attempt_correlation_and_order_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["attempt_time_utc"] = "2026-10-27T12:29:00+00:00"
        pair["windows"]["linux_correlation"]["terminal_time_utc"] = "2026-10-27T13:00:00+00:00"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("AB_ATTEMPT_ORDER_INVALID", failures)
        self.assertIn("WINDOWS_ATTEMPT_CORRELATION_MISMATCH", failures)

    def test_paired_source_binding_rejects_cross_attempt_splicing(self):
        manifest = evidence.build_manifest(self.options)

        pair = self._paired_record(manifest)
        pair["macos"]["source_binding"]["connection_id"] = "connection-other"
        self.assertIn(
            "MACOS_SOURCE_CONNECTION_MISMATCH",
            ab_evidence.validate_pair(manifest, pair)["evidence_failures"],
        )

        pair = self._paired_record(manifest)
        pair["macos"]["source_binding"]["server_certificate_sha256"] = "d" * 64
        self.assertIn(
            "MACOS_SOURCE_CERTIFICATE_MISMATCH",
            ab_evidence.validate_pair(manifest, pair)["evidence_failures"],
        )

        pair = self._paired_record(manifest)
        pair["windows"]["source_binding"]["destination_exact"] = "192.0.2.99"
        self.assertIn(
            "WINDOWS_SOURCE_DESTINATION_MISMATCH",
            ab_evidence.validate_pair(manifest, pair)["evidence_failures"],
        )

        pair = self._paired_record(manifest)
        pair["windows"]["source_binding"]["observation_window_start_utc"] = (
            "2026-10-27T13:32:00+00:00"
        )
        self.assertIn(
            "WINDOWS_SOURCE_OBSERVATION_WINDOW_MISMATCH",
            ab_evidence.validate_pair(manifest, pair)["evidence_failures"],
        )

    def test_paired_source_binding_rejects_credential_and_target_mix(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["macos"]["credential_source_claim"] = "ask-when-required-or-none"
        pair["windows"]["service_endpoint_exact"] = "192.0.2.10:3390"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("MACOS_CREDENTIAL_CONTROL_INVALID", failures)
        self.assertIn("AB_SERVICE_ENDPOINT_MISMATCH", failures)

    def test_paired_windows_only_type3_stops_before_authinfo(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["server_stage_matrix"].update(
            type3_received="PASS", post_type2_client_bytes=64)
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertEqual(summary["comparison"], "WINDOWS_ONLY_TYPE3_RECEIVED")

    def test_paired_unapproved_private_secret_field_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["credential"]["password"] = "do-not-collect"
        with self.assertRaises(ValueError):
            ab_evidence.validate_pair(manifest, pair)

    def test_paired_typed_client_error_requires_provider(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["first_client_error"]["normalized_category"] = "trust"
        self.assertIn("WINDOWS_FIRST_ERROR_UNGROUNDED",
                      ab_evidence.validate_pair(manifest, pair)["evidence_failures"])

if __name__ == "__main__":
    unittest.main(argv=["owner-evidence-tests", *remaining])
