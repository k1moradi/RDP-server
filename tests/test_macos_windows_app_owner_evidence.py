# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the read-only macOS Windows App evidence manifest."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
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
        target_identity = "TERMSRV/RDP-SERVER"
        windows_attempt = "2026-10-27T12:32:00+00:00"
        windows_terminal = "2026-10-27T12:32:07+00:00"
        return {
            "schema": "rdp-server.windows-client-ab-pair.v3",
            "macos": {
                "server_tls_configuration_profile": "same-server-default-tls",
                "service_endpoint_exact": service_endpoint,
                "credential_source_claim": "explicit-saved-selected",
                "deliberately_reentered": True,
                "target_identity_exact": target_identity,
                "attempt_id_exact": "attempt-macos",
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
                    "attempt_id_exact": "attempt-macos",
                    "client_application_exact": "Windows App",
                    "client_version_exact": "11.4.4+3132",
                    "target_identity_exact": target_identity,
                    "credential_source_choice": "explicit-saved-selected",
                },
                "client_security_stages": client_unobserved.copy(),
                "client_stage_evidence": dict.fromkeys(client_unobserved),
                "server_type3_evidence": None,
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
                "target_identity_exact": target_identity,
                "attempt_id_exact": "attempt-windows",
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
                    "attempt_id_exact": "attempt-windows",
                    "client_application_exact": "mstsc.exe",
                    "client_version_exact": "10.0.22621.1",
                    "target_identity_exact": target_identity,
                    "credential_source_choice": "explicitly-entered",
                },
                "client_security_stages": client_unobserved.copy(),
                "client_stage_evidence": dict.fromkeys(client_unobserved),
                "server_type3_evidence": None,
                "server_stage_matrix": manifest["server_stage_matrix"].copy(),
                "server_transport_observation": {
                    "peer_fin_observed": True,
                    "tls_alert_observed": False,
                    "terminal_attribution": "peer-fin",
                },
                "native_admission": "NOT_REACHED",
            },
        }

    @staticmethod
    def _client_event(pair, platform):
        binding = pair[platform]["source_binding"]
        return {
            "source_kind": "owner-approved-client-diagnostic",
            "source_record_sha256": "f" * 64,
            "client_application_exact": binding["client_application_exact"],
            "client_version_exact": binding["client_version_exact"],
            "attempt_id_exact": binding["attempt_id_exact"],
            "connection_id": binding["connection_id"],
            "event_time_utc": binding["attempt_time_utc"],
        }

    @staticmethod
    def _server_type3_event(pair, platform):
        binding = pair[platform]["source_binding"]
        return {
            "source_record_sha256": "e" * 64,
            "attempt_id_exact": binding["attempt_id_exact"],
            "connection_id": binding["connection_id"],
            "event_time_utc": binding["attempt_time_utc"],
        }

    @staticmethod
    def _configure_valid_credssp_failure_first_error(
            manifest, pair, platform, stage_event, provider_category):
        if platform == "macos":
            first_error = manifest["first_client_error"]
            first_error.update({
                "normalized_category": "negotiation",
                "source": "core",
                "provider_category_exact": provider_category,
                "provider_code_exact": None,
                "event_time_local": manifest["attempt_time_local"],
                "event_time_utc": stage_event["event_time_utc"],
            })
        else:
            first_error = pair["windows"]["first_client_error"]
            first_error.update({
                "normalized_category": "negotiation",
                "source": "owner-approved-diagnostic",
                "provider_category_exact": provider_category,
                "provider_code_exact": None,
                "event_time_utc": stage_event["event_time_utc"],
            })
        return first_error

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
        pair["windows"]["client_stage_evidence"] = {
            stage: self._client_event(pair, "windows")
            for stage in ab_evidence.CLIENT_SECURITY_STAGES
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
        pair["windows"]["server_type3_evidence"] = self._server_type3_event(
            pair, "windows")
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertEqual(summary["comparison"], "WINDOWS_ONLY_TYPE3_RECEIVED")

    def test_paired_provenance_rotated_certificate_generation_denials(self):
        # Each new synthetic certificate generation needs fresh original-source
        # identity, regardless of an unchanged server profile or Type-2 flags.
        for platform in ("macos", "windows"):
            for stage in ab_evidence.CLIENT_SECURITY_STAGES:
                with self.subTest(platform=platform, stage=stage):
                    manifest = evidence.build_manifest(self.options)
                    manifest["server_certificate_sha256"] = "c" * 64
                    pair = self._paired_record(manifest)
                    row = pair[platform]
                    row["client_security_stages"][stage] = "PASS"
                    original_event = self._client_event(pair, platform)
                    original_event["source_record_sha256"] = (
                        "d" if platform == "macos" else "e") * 64
                    row["client_stage_evidence"][stage] = original_event

                    positive = ab_evidence.validate_pair(manifest, pair)
                    self.assertEqual(positive["evidence_status"], "PASS")
                    self.assertEqual(
                        positive[platform]["client_security_stages"][stage],
                        "PASS")

                    row["source_binding"]["server_certificate_sha256"] = "b" * 64
                    previous_certificate = ab_evidence.validate_pair(manifest, pair)
                    self.assertEqual(previous_certificate["evidence_status"], "FAIL")
                    self.assertIn(
                        f"{platform.upper()}_SOURCE_CERTIFICATE_MISMATCH",
                        previous_certificate["evidence_failures"])
                    self.assertTrue(all(
                        state == "NOT_OBSERVED"
                        for state in previous_certificate[platform][
                            "client_security_stages"].values()))
                    row["source_binding"]["server_certificate_sha256"] = "c" * 64

                    original_event["attempt_id_exact"] = "private-prior-attempt"
                    original_event["connection_id"] = "private-prior-connection"
                    previous_attempt = ab_evidence.validate_pair(manifest, pair)
                    self.assertEqual(previous_attempt["evidence_status"], "FAIL")
                    for failure in (
                        f"{platform.upper()}_CLIENT_{stage.upper()}_ATTEMPT_MISMATCH",
                        f"{platform.upper()}_CLIENT_{stage.upper()}_CONNECTION_MISMATCH",
                    ):
                        self.assertIn(failure, previous_attempt["evidence_failures"])
                    self.assertTrue(all(
                        state == "NOT_OBSERVED"
                        for state in previous_attempt[platform][
                            "client_security_stages"].values()))
                    self.assertNotIn("private-prior-", json.dumps(previous_attempt))

        manifest = evidence.build_manifest(self.options)
        manifest["server_certificate_sha256"] = "c" * 64
        pair = self._paired_record(manifest)
        private_provider = "private-generation-provider-secret"
        manifest["first_client_error"].update({
            "normalized_category": "trust",
            "source": "core",
            "provider_category_exact": private_provider,
            "provider_code_exact": None,
            "event_time_local": manifest["attempt_time_local"],
            "event_time_utc": manifest["attempt_time_utc"],
        })
        pair["windows"]["first_client_error"].update({
            "normalized_category": "trust",
            "source": "owner-approved-diagnostic",
            "provider_category_exact": private_provider,
            "provider_code_exact": None,
            "event_time_utc": pair["windows"]["attempt_time_utc"],
        })
        for platform, digest in (("macos", "d"), ("windows", "e")):
            pair[platform]["client_security_stages"]["type2_received"] = "PASS"
            client_event = self._client_event(pair, platform)
            client_event["source_record_sha256"] = digest * 64
            pair[platform]["client_stage_evidence"]["type2_received"] = client_event

        same_generation = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(same_generation["evidence_status"], "PASS")
        for platform in ("macos", "windows"):
            self.assertEqual(
                same_generation[platform]["first_client_error_category"], "trust")
            self.assertEqual(
                same_generation[platform]["client_security_stages"]["type2_received"],
                "PASS")
        self.assertNotIn(private_provider, json.dumps(same_generation))

        # The pair-level mismatch used to FAIL but still project both rows'
        # individually valid stages and typed errors as if they were comparable.
        pair["windows"]["server_certificate_sha256"] = "b" * 64
        pair["windows"]["source_binding"]["server_certificate_sha256"] = "b" * 64
        mixed_generation = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(mixed_generation["evidence_status"], "FAIL")
        self.assertIn("AB_CERTIFICATE_FINGERPRINT_MISMATCH",
                      mixed_generation["evidence_failures"])
        self.assertFalse(mixed_generation["certificate_fingerprint_match"])
        self.assertEqual(mixed_generation["comparison"], "INCONCLUSIVE")
        for platform in ("macos", "windows"):
            self.assertEqual(
                mixed_generation[platform]["first_client_error_category"], "unknown")
            self.assertTrue(all(
                state == "NOT_OBSERVED"
                for state in mixed_generation[platform][
                    "client_security_stages"].values()))
        self.assertNotIn(private_provider, json.dumps(mixed_generation))
        self.assertNotIn("rdp-owner", json.dumps(mixed_generation))

        # A neighboring Windows client cannot impersonate Windows App's record.
        pair = self._paired_record(manifest)
        pair["windows"]["client_security_stages"]["type3_generated"] = "PASS"
        pair["windows"]["client_stage_evidence"]["type3_generated"] = (
            self._client_event(pair, "macos"))
        neighboring_client = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(neighboring_client["evidence_status"], "FAIL")
        for failure in (
            "WINDOWS_CLIENT_TYPE3_GENERATED_APPLICATION_MISMATCH",
            "WINDOWS_CLIENT_TYPE3_GENERATED_ATTEMPT_MISMATCH",
            "WINDOWS_CLIENT_TYPE3_GENERATED_CONNECTION_MISMATCH",
        ):
            self.assertIn(failure, neighboring_client["evidence_failures"])
        self.assertTrue(all(
            state == "NOT_OBSERVED"
            for state in neighboring_client["windows"][
                "client_security_stages"].values()))

    def test_paired_provenance_rotated_credssp_typed_error_requires_client_source(self):
        # A first error remains independent from source-bound original client
        # evidence, even with a valid certificate and plausible provider name.
        private_provider = "private-rotated-provider-secret"
        for platform in ("macos", "windows"):
            with self.subTest(platform=platform):
                manifest = evidence.build_manifest(self.options)
                manifest["server_certificate_sha256"] = "c" * 64
                pair = self._paired_record(manifest)
                row = pair[platform]
                row["client_security_stages"]["type2_accepted_by_credssp"] = "FAIL"
                original_event = self._client_event(pair, platform)
                original_event["source_record_sha256"] = (
                    "d" if platform == "macos" else "e") * 64
                row["client_stage_evidence"]["type2_accepted_by_credssp"] = original_event
                first_error = self._configure_valid_credssp_failure_first_error(
                    manifest, pair, platform, original_event, private_provider)

                valid = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(valid["evidence_status"], "PASS")
                self.assertEqual(
                    valid[platform]["first_client_error_category"], "negotiation")
                self.assertEqual(
                    valid[platform]["client_security_stages"][
                        "type2_accepted_by_credssp"], "FAIL")
                self.assertNotIn(private_provider, json.dumps(valid))

                original_event["source_record_sha256"] = ""
                missing_digest = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(missing_digest["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CLIENT_TYPE2_ACCEPTED_BY_CREDSSP_SOURCE_DIGEST_INVALID",
                    missing_digest["evidence_failures"])
                self.assertEqual(
                    missing_digest[platform]["first_client_error_category"], "unknown")
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in missing_digest[platform][
                        "client_security_stages"].values()))
                self.assertNotIn(private_provider, json.dumps(missing_digest))
                original_event["source_record_sha256"] = (
                    "d" if platform == "macos" else "e") * 64

                # A previous error within the allowed attempt window still
                # cannot qualify a FAIL for a different original event instant.
                if platform == "macos":
                    first_error["event_time_local"] = (
                        "2026-10-27T05:30:01-07:00")
                    first_error["event_time_utc"] = (
                        "2026-10-27T12:30:01+00:00")
                else:
                    first_error["event_time_utc"] = (
                        "2026-10-27T12:32:01+00:00")
                wrong_error = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(wrong_error["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CREDSSP_FAILURE_EVENT_TIME_MISMATCH",
                    wrong_error["evidence_failures"])
                self.assertEqual(
                    wrong_error[platform]["first_client_error_category"], "unknown")
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in wrong_error[platform][
                        "client_security_stages"].values()))
                self.assertNotIn(private_provider, json.dumps(wrong_error))

    def test_paired_provenance_fin_only_keeps_client_stages_unobserved(self):
        # Synthetic server Type 2/FIN is not evidence of four client failures.
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "PASS")
        self.assertEqual(summary["comparison"], "NEITHER_TYPE3_RECEIVED")
        for platform in ("macos", "windows"):
            self.assertTrue(pair[platform]["server_transport_observation"][
                "peer_fin_observed"])
            self.assertEqual(
                summary[platform]["client_security_stages"],
                dict.fromkeys(ab_evidence.CLIENT_SECURITY_STAGES, "NOT_OBSERVED"))
            self.assertEqual(summary[platform]["type3_received"], "NOT_REACHED")

    def test_paired_provenance_original_client_record_reused_across_attempts_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        for platform in ("macos", "windows"):
            pair[platform]["client_security_stages"]["type2_received"] = "PASS"
            pair[platform]["client_stage_evidence"]["type2_received"] = self._client_event(
                pair, platform)
        # Independent metadata cannot turn a single original source record
        # into two client-origin events, even with alternate hex case.
        pair["windows"]["client_stage_evidence"]["type2_received"][
            "source_record_sha256"] = "F" * 64
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("AB_CLIENT_SOURCE_RECORD_REUSED", summary["evidence_failures"])
        self.assertEqual(summary["comparison"], "INCONCLUSIVE")
        self.assertNotIn("attempt-windows", json.dumps(summary))

        # Distinct client-origin records remain eligible for ordinary correlation.
        pair["windows"]["client_stage_evidence"]["type2_received"][
            "source_record_sha256"] = "a" * 64
        corrected_summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(corrected_summary["evidence_status"], "PASS")
        self.assertNotIn("AB_CLIENT_SOURCE_RECORD_REUSED",
                         corrected_summary["evidence_failures"])

        # The same digest cannot be a provider event and a diagnostic
        # for two stages of one attempt.
        pair = self._paired_record(manifest)
        for stage in ("type2_received", "type2_accepted_by_credssp"):
            pair["windows"]["client_security_stages"][stage] = "PASS"
            pair["windows"]["client_stage_evidence"][stage] = self._client_event(
                pair, "windows")
        second = pair["windows"]["client_stage_evidence"]["type2_accepted_by_credssp"]
        second["source_kind"] = "client-provider-event"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("WINDOWS_CLIENT_SOURCE_KIND_CONFLICT", failures)
        second["source_record_sha256"] = "a" * 64
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertNotIn("WINDOWS_CLIENT_SOURCE_KIND_CONFLICT", failures)

    def test_paired_provenance_original_record_timestamp_splice_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)

        # A single original record may establish multiple stages, but must
        # have one event instant regardless of which UTC offset writes it.
        for stage in ("type2_received", "type2_accepted_by_credssp"):
            pair["windows"]["client_security_stages"][stage] = "PASS"
            pair["windows"]["client_stage_evidence"][stage] = self._client_event(
                pair, "windows")

        second_event = pair["windows"]["client_stage_evidence"][
            "type2_accepted_by_credssp"]
        second_event["source_record_sha256"] = "F" * 64
        second_event["event_time_utc"] = "2026-10-27T12:32:01+00:00"
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn(
            "WINDOWS_CLIENT_SOURCE_EVENT_TIME_CONFLICT",
            summary["evidence_failures"])
        for stage in ("type2_received", "type2_accepted_by_credssp"):
            self.assertEqual(
                summary["windows"]["client_security_stages"][stage],
                "NOT_OBSERVED")
        self.assertNotIn("F" * 64, json.dumps(summary))

        # Different textual offsets identifying the same UTC instant are valid.
        second_event["event_time_utc"] = "2026-10-27T05:32:00-07:00"
        same_instant = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(same_instant["evidence_status"], "PASS")
        self.assertNotIn(
            "WINDOWS_CLIENT_SOURCE_EVENT_TIME_CONFLICT",
            same_instant["evidence_failures"])

        # Distinct original client records can truthfully have distinct times.
        second_event["source_record_sha256"] = "a" * 64
        second_event["event_time_utc"] = "2026-10-27T12:32:01+00:00"
        independent_record = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(independent_record["evidence_status"], "PASS")

    def test_paired_provenance_local_type2_commit_cannot_substitute_client_event(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        # A server-local write is not a client-side receipt/decrypt observation.
        pair["windows"]["client_security_stages"]["type2_received"] = "PASS"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("WINDOWS_CLIENT_TYPE2_RECEIVED_PROVENANCE_MISSING", failures)

    def test_paired_provenance_each_client_stage_is_independently_source_bound(self):
        manifest = evidence.build_manifest(self.options)

        for stage in ab_evidence.CLIENT_SECURITY_STAGES:
            with self.subTest(stage=stage, source="client-origin"):
                pair = self._paired_record(manifest)
                pair["windows"]["client_security_stages"][stage] = "PASS"
                pair["windows"]["client_stage_evidence"][stage] = self._client_event(
                    pair, "windows")
                summary = ab_evidence.validate_pair(manifest, pair)

                self.assertEqual(summary["evidence_status"], "PASS")
                for observed_stage in ab_evidence.CLIENT_SECURITY_STAGES:
                    self.assertEqual(
                        summary["windows"]["client_security_stages"][observed_stage],
                        "PASS" if observed_stage == stage else "NOT_OBSERVED",
                    )

            with self.subTest(stage=stage, source="server-transport"):
                pair = self._paired_record(manifest)
                pair["windows"]["client_security_stages"][stage] = "PASS"
                server_event = self._client_event(pair, "windows")
                server_event["source_kind"] = "server-transport"
                pair["windows"]["client_stage_evidence"][stage] = server_event
                summary = ab_evidence.validate_pair(manifest, pair)

                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn(
                    f"WINDOWS_CLIENT_{stage.upper()}_SOURCE_UNSUPPORTED",
                    summary["evidence_failures"],
                )
                self.assertEqual(
                    summary["windows"]["client_security_stages"][stage],
                    "NOT_OBSERVED",
                )

    def test_paired_provenance_macos_four_stages_require_original_client_event(self):
        # Each macOS stage is independently observable as PASS or FAIL.
        # Neither a server-local record nor a neighboring attempt is a
        # client-origin event, even when the server's Type 2 was committed.
        for stage in ab_evidence.CLIENT_SECURITY_STAGES:
            for observed_state in ("PASS", "FAIL"):
                with self.subTest(stage=stage, state=observed_state):
                    manifest = evidence.build_manifest(self.options)
                    pair = self._paired_record(manifest)
                    macos_row = pair["macos"]
                    macos_row["client_security_stages"][stage] = observed_state
                    original_event = self._client_event(pair, "macos")
                    macos_row["client_stage_evidence"][stage] = original_event
                    if (stage == "type2_accepted_by_credssp"
                            and observed_state == "FAIL"):
                        self._configure_valid_credssp_failure_first_error(
                            manifest,
                            pair,
                            "macos",
                            original_event,
                            "private-provider-first-error",
                        )

                    valid = ab_evidence.validate_pair(manifest, pair)
                    self.assertEqual(valid["evidence_status"], "PASS")
                    self.assertEqual(
                        valid["macos"]["client_security_stages"][stage],
                        observed_state,
                    )
                    self.assertTrue(all(
                        state == "NOT_OBSERVED"
                        for state in valid["windows"]["client_security_stages"].values()
                    ))

                    original_event["source_kind"] = "server-transport"
                    server_substitution = ab_evidence.validate_pair(manifest, pair)
                    self.assertEqual(server_substitution["evidence_status"], "FAIL")
                    self.assertIn(
                        f"MACOS_CLIENT_{stage.upper()}_SOURCE_UNSUPPORTED",
                        server_substitution["evidence_failures"],
                    )
                    self.assertTrue(all(
                        state == "NOT_OBSERVED"
                        for state in server_substitution["macos"]["client_security_stages"].values()
                    ))

                    original_event["source_kind"] = "client-provider-event"
                    original_event["attempt_id_exact"] = pair["windows"]["attempt_id_exact"]
                    neighboring_attempt = ab_evidence.validate_pair(manifest, pair)
                    self.assertEqual(neighboring_attempt["evidence_status"], "FAIL")
                    self.assertIn(
                        f"MACOS_CLIENT_{stage.upper()}_ATTEMPT_MISMATCH",
                        neighboring_attempt["evidence_failures"],
                    )
                    self.assertTrue(all(
                        state == "NOT_OBSERVED"
                        for state in neighboring_attempt["macos"]["client_security_stages"].values()
                    ))
                    self.assertNotIn("attempt-windows", json.dumps(neighboring_attempt))

    def test_paired_provenance_credssp_failure_requires_same_typed_first_error_event(self):
        private_provider = "private-provider-first-error"
        for platform in ("macos", "windows"):
            with self.subTest(platform=platform, case="generic-error-denied"):
                manifest = evidence.build_manifest(self.options)
                pair = self._paired_record(manifest)
                row = pair[platform]
                row["client_security_stages"]["type2_accepted_by_credssp"] = "FAIL"
                stage_event = self._client_event(pair, platform)
                row["client_stage_evidence"]["type2_accepted_by_credssp"] = stage_event

                generic = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(generic["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CREDSSP_FAILURE_TYPED_ERROR_MISSING",
                    generic["evidence_failures"],
                )
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in generic[platform]["client_security_stages"].values()
                ))

            with self.subTest(platform=platform, case="same-event-valid"):
                first_error = self._configure_valid_credssp_failure_first_error(
                    manifest, pair, platform, stage_event, private_provider
                )

                valid = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(valid["evidence_status"], "PASS")
                self.assertEqual(
                    valid[platform]["client_security_stages"][
                        "type2_accepted_by_credssp"
                    ],
                    "FAIL",
                )
                self.assertNotIn(private_provider, json.dumps(valid))

            with self.subTest(platform=platform, case="different-event-denied"):
                if platform == "macos":
                    first_error["event_time_local"] = "2026-10-27T05:30:01-07:00"
                    first_error["event_time_utc"] = "2026-10-27T12:30:01+00:00"
                else:
                    first_error["event_time_utc"] = "2026-10-27T12:32:01+00:00"

                mismatch = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(mismatch["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CREDSSP_FAILURE_EVENT_TIME_MISMATCH",
                    mismatch["evidence_failures"],
                )
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in mismatch[platform]["client_security_stages"].values()
                ))
                self.assertNotIn(private_provider, json.dumps(mismatch))

            with self.subTest(platform=platform, case="invalid-first-error-denied"):
                if platform == "macos":
                    first_error["event_time_local"] = "2026-10-27T05:30:00-07:00"
                    first_error["event_time_utc"] = stage_event["event_time_utc"]
                else:
                    first_error["event_time_utc"] = stage_event["event_time_utc"]
                first_error["normalized_category"] = "private-invalid-category"

                invalid = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(invalid["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CREDSSP_FAILURE_TYPED_ERROR_INVALID",
                    invalid["evidence_failures"],
                )
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in invalid[platform]["client_security_stages"].values()
                ))
                self.assertNotIn("private-invalid-category", json.dumps(invalid))
                self.assertNotIn(private_provider, json.dumps(invalid))

            with self.subTest(platform=platform, case="invalid-first-error-source-denied"):
                first_error["normalized_category"] = "negotiation"
                first_error["source"] = "private-invalid-source"

                invalid_source = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(invalid_source["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CREDSSP_FAILURE_TYPED_ERROR_INVALID",
                    invalid_source["evidence_failures"],
                )
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in invalid_source[platform]["client_security_stages"].values()
                ))
                self.assertNotIn("private-invalid-source", json.dumps(invalid_source))
                self.assertNotIn(private_provider, json.dumps(invalid_source))

            with self.subTest(platform=platform, case="cross-attempt-stage-denied"):
                first_error["source"] = (
                    "core" if platform == "macos" else "owner-approved-diagnostic"
                )
                stage_event["attempt_id_exact"] = "previous-attempt"

                cross_attempt = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(cross_attempt["evidence_status"], "FAIL")
                self.assertIn(
                    f"{platform.upper()}_CLIENT_TYPE2_ACCEPTED_BY_CREDSSP_ATTEMPT_MISMATCH",
                    cross_attempt["evidence_failures"],
                )
                self.assertTrue(all(
                    state == "NOT_OBSERVED"
                    for state in cross_attempt[platform]["client_security_stages"].values()
                ))
                self.assertNotIn("previous-attempt", json.dumps(cross_attempt))
                self.assertNotIn(private_provider, json.dumps(cross_attempt))

    def test_paired_provenance_type3_source_from_neighboring_attempt_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["server_stage_matrix"].update(
            post_type2_client_bytes=128, type3_received="PASS")
        pair["windows"]["server_type3_evidence"] = self._server_type3_event(
            pair, "windows")
        pair["windows"]["server_type3_evidence"]["connection_id"] = "previous-connection"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("WINDOWS_TYPE3_SOURCE_CONNECTION_MISMATCH", failures)

        # Reusing the same original server transcript across independent
        # macOS/Windows attempts cannot establish two different Type 3s.
        manifest["server_stage_matrix"].update(
            post_type2_client_bytes=128, type3_received="PASS")
        pair = self._paired_record(manifest)
        pair["macos"]["server_type3_evidence"] = self._server_type3_event(
            pair, "macos")
        pair["windows"]["server_type3_evidence"] = self._server_type3_event(
            pair, "windows")
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("AB_SERVER_TYPE3_SOURCE_RECORD_REUSED", failures)
        pair["windows"]["server_type3_evidence"]["source_record_sha256"] = "d" * 64
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertNotIn("AB_SERVER_TYPE3_SOURCE_RECORD_REUSED", failures)

    def test_paired_provenance_client_record_cannot_substitute_server_type3_record(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["client_security_stages"]["type2_received"] = "PASS"
        pair["windows"]["client_stage_evidence"]["type2_received"] = self._client_event(
            pair, "windows")
        pair["windows"]["server_stage_matrix"].update(
            post_type2_client_bytes=128, type3_received="PASS")
        pair["windows"]["server_type3_evidence"] = self._server_type3_event(
            pair, "windows")

        # A client diagnostic and a server transcript are independent original
        # records even when both describe the same accepted connection.
        pair["windows"]["server_type3_evidence"]["source_record_sha256"] = "F" * 64
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn(
            "AB_CLIENT_SERVER_SOURCE_RECORD_REUSED",
            summary["evidence_failures"])
        self.assertEqual(summary["comparison"], "INCONCLUSIVE")
        self.assertNotIn("F" * 64, json.dumps(summary))

        # Independent original records remain valid for the same attempt.
        pair["windows"]["server_type3_evidence"]["source_record_sha256"] = "e" * 64
        independent_records = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(independent_records["evidence_status"], "PASS")
        self.assertNotIn(
            "AB_CLIENT_SERVER_SOURCE_RECORD_REUSED",
            independent_records["evidence_failures"])

    def test_paired_provenance_client_type3_from_neighboring_attempt_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        for stage in ab_evidence.CLIENT_SECURITY_STAGES:
            pair["windows"]["client_security_stages"][stage] = "PASS"
            pair["windows"]["client_stage_evidence"][stage] = self._client_event(
                pair, "windows")
        pair["windows"]["client_stage_evidence"]["type3_generated"][
            "attempt_id_exact"] = "previous-attempt"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("WINDOWS_CLIENT_TYPE3_GENERATED_ATTEMPT_MISMATCH", failures)

    def test_paired_provenance_source_binding_identity_splices_are_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        binding = pair["windows"]["source_binding"]

        # These fields identify the original client attempt. A neighboring
        # source record cannot satisfy this row even when its stage values look
        # otherwise plausible.
        binding["server_sha"] = "c" * 40
        binding["service_endpoint_exact"] = "192.0.2.10:3390"
        binding["attempt_id_exact"] = "previous-attempt"
        binding["client_application_exact"] = "Windows App"

        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        for failure in (
            "WINDOWS_SOURCE_SHA_MISMATCH",
            "WINDOWS_SOURCE_SERVICE_ENDPOINT_MISMATCH",
            "WINDOWS_SOURCE_ATTEMPT_ID_MISMATCH",
            "WINDOWS_SOURCE_CLIENT_APPLICATION_MISMATCH",
        ):
            self.assertIn(failure, failures)

    def test_paired_provenance_target_version_and_credential_mix_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["target_identity_exact"] = "TERMSRV/other-host"
        pair["windows"]["source_binding"]["client_version_exact"] = "other-version"
        pair["windows"]["source_binding"]["credential_source_choice"] = "saved"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        for failure in (
            "AB_TARGET_IDENTITY_MISMATCH",
            "WINDOWS_SOURCE_TARGET_IDENTITY_MISMATCH",
            "WINDOWS_SOURCE_CLIENT_VERSION_MISMATCH",
            "WINDOWS_SOURCE_CREDENTIAL_SOURCE_MISMATCH",
        ):
            self.assertIn(failure, failures)

    def test_paired_provenance_unobserved_stage_cannot_carry_false_receipt(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["macos"]["client_stage_evidence"]["type2_received"] = self._client_event(
            pair, "macos")
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("MACOS_CLIENT_TYPE2_RECEIVED_UNOBSERVED_EVENT_CONTRADICTION",
                      failures)

    def test_paired_provenance_client_event_outside_attempt_is_denied(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        pair["windows"]["client_security_stages"]["type2_received"] = "PASS"
        pair["windows"]["client_stage_evidence"]["type2_received"] = self._client_event(
            pair, "windows")
        pair["windows"]["client_stage_evidence"]["type2_received"][
            "event_time_utc"] = "2026-10-27T15:00:00+00:00"
        failures = ab_evidence.validate_pair(manifest, pair)["evidence_failures"]
        self.assertIn("WINDOWS_CLIENT_TYPE2_RECEIVED_EVENT_OUTSIDE_ATTEMPT",
                      failures)

    def test_paired_private_invalid_values_cannot_leak_into_shared_summary(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        private_marker = "private-session-password-sentinel"
        pair["macos"]["client_security_stages"]["type2_received"] = private_marker
        pair["macos"]["native_admission"] = private_marker
        pair["windows"]["client_security_stages"]["type3_generated"] = private_marker
        pair["windows"]["server_stage_matrix"]["type3_received"] = private_marker
        pair["windows"]["native_admission"] = private_marker
        pair["windows"]["windows_11_build"] = private_marker
        pair["windows"]["mstsc_file_version"] = private_marker

        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("WINDOWS_VERSION_INVALID", summary["evidence_failures"])
        self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))
        self.assertEqual(summary["macos"]["client_security_stages"]["type2_received"],
                         "NOT_OBSERVED")
        self.assertEqual(summary["windows"]["client_security_stages"]["type3_generated"],
                         "NOT_OBSERVED")
        self.assertEqual(summary["windows"]["type3_received"], "NOT_REACHED")
        self.assertEqual(summary["macos"]["native_admission"], "NOT_REACHED")
        self.assertEqual(summary["windows"]["native_admission"], "NOT_REACHED")
        self.assertEqual(summary["windows"]["windows_11_build"], "INVALID")
        self.assertEqual(summary["windows"]["mstsc_file_version"], "INVALID")

    def test_paired_private_invalid_first_error_category_is_redacted(self):
        manifest = evidence.build_manifest(self.options)
        private_marker = "private-session-password-sentinel"
        for invalid_category, invalid_source in (
            (private_marker, "windows-ui"),
            ([private_marker], "windows-ui"),
            ("unknown", [private_marker]),
        ):
            with self.subTest(invalid_category=type(invalid_category).__name__,
                              invalid_source=type(invalid_source).__name__):
                pair = self._paired_record(manifest)
                first_error = pair["windows"]["first_client_error"]
                first_error["normalized_category"] = invalid_category
                first_error["source"] = invalid_source
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn("WINDOWS_FIRST_ERROR_INVALID",
                              summary["evidence_failures"])
                self.assertEqual(summary["windows"]["first_client_error_category"],
                                 "unknown")
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

    def test_paired_first_error_attempt_window_and_untrusted_receipt_denials(self):
        # Prior-client error timestamps cannot be assigned to a newer attempt,
        # even when they meet the former loose 120-second comparison bound.
        pristine = evidence.build_manifest(self.options)
        original_keys = set(ab_evidence.validate_pair(
            pristine, self._paired_record(pristine)))

        self.options.first_client_error_time = "2026-10-27T05:29:59-07:00"
        previous_error_manifest = evidence.build_manifest(self.options)
        macos_summary = ab_evidence.validate_pair(
            previous_error_manifest, self._paired_record(previous_error_manifest))
        self.assertEqual(macos_summary["evidence_status"], "FAIL")
        self.assertIn("MACOS_FIRST_ERROR_OUTSIDE_ATTEMPT",
                      macos_summary["evidence_failures"])
        self.assertEqual(macos_summary["macos"]["first_client_error_category"],
                         "unknown")
        self.assertEqual(set(macos_summary), original_keys)

        pair = self._paired_record(pristine)
        first_error = pair["windows"]["first_client_error"]
        first_error["normalized_category"] = "trust"
        first_error["provider_category_exact"] = "private-provider-trust"
        first_error["event_time_utc"] = "2026-10-27T12:31:59+00:00"
        windows_summary = ab_evidence.validate_pair(pristine, pair)
        self.assertEqual(windows_summary["evidence_status"], "FAIL")
        self.assertIn("WINDOWS_FIRST_ERROR_OUTSIDE_ATTEMPT",
                      windows_summary["evidence_failures"])
        self.assertEqual(windows_summary["windows"]["first_client_error_category"],
                         "unknown")
        self.assertNotIn("private-provider-trust", json.dumps(windows_summary))
        self.assertEqual(set(windows_summary), original_keys)

        # A typed UI error just after FIN remains possible, not attributed.
        first_error["event_time_utc"] = "2026-10-27T12:32:08+00:00"
        valid_followup = ab_evidence.validate_pair(pristine, pair)
        self.assertNotIn("WINDOWS_FIRST_ERROR_OUTSIDE_ATTEMPT",
                         valid_followup["evidence_failures"])

        # The post-terminal allowance is terminal-relative, not another
        # attempt-start cap. A valid 110-second attempt plus the full bounded
        # UI/provider delay must remain representable without splicing.
        long_attempt_pair = self._paired_record(pristine)
        long_attempt_pair["windows"]["linux_correlation"]["terminal_time_utc"] = (
            "2026-10-27T12:33:50+00:00"
        )
        long_binding = long_attempt_pair["windows"]["source_binding"]
        long_binding["terminal_time_utc"] = "2026-10-27T12:33:50+00:00"
        long_binding["observation_window_end_utc"] = "2026-10-27T12:33:50+00:00"
        long_error = long_attempt_pair["windows"]["first_client_error"]
        long_error["normalized_category"] = "trust"
        long_error["provider_category_exact"] = "private-provider-trust"
        long_error["event_time_utc"] = "2026-10-27T12:35:50+00:00"
        boundary_summary = ab_evidence.validate_pair(pristine, long_attempt_pair)
        self.assertEqual(boundary_summary["evidence_status"], "PASS")
        self.assertEqual(
            boundary_summary["windows"]["first_client_error_category"], "trust"
        )
        self.assertNotIn("private-provider-trust", json.dumps(boundary_summary))

        # One second beyond the same terminal-relative allowance fails closed.
        long_error["event_time_utc"] = "2026-10-27T12:35:51+00:00"
        late_summary = ab_evidence.validate_pair(pristine, long_attempt_pair)
        self.assertEqual(late_summary["evidence_status"], "FAIL")
        self.assertIn("WINDOWS_FIRST_ERROR_OUTSIDE_ATTEMPT",
                      late_summary["evidence_failures"])
        self.assertEqual(
            late_summary["windows"]["first_client_error_category"], "unknown"
        )
        self.assertNotIn("private-provider-trust", json.dumps(late_summary))

        # R1 committed Type 2 and FIN cannot prove client-side decryption.
        pair = self._paired_record(pristine)
        pair["macos"]["client_security_stages"]["type2_received"] = "PASS"
        server_event = self._client_event(pair, "macos")
        server_event["source_kind"] = "server-transport"
        pair["macos"]["client_stage_evidence"]["type2_received"] = server_event
        receipt_summary = ab_evidence.validate_pair(pristine, pair)
        self.assertEqual(receipt_summary["evidence_status"], "FAIL")
        self.assertIn("MACOS_CLIENT_TYPE2_RECEIVED_SOURCE_UNSUPPORTED",
                      receipt_summary["evidence_failures"])
        self.assertEqual(
            receipt_summary["macos"]["client_security_stages"]["type2_received"],
            "NOT_OBSERVED")
        self.assertEqual(set(receipt_summary["macos"]),
                         set(macos_summary["macos"]))

    def test_paired_unicode_private_first_error_denials(self):
        # Escaped Unicode surrogates, nested provider lists/dicts and missing
        # fields must produce typed FAIL, not exception text or a public type.
        manifest = evidence.build_manifest(self.options)
        sentinel = "private-error-field-sentinel"
        expected = ab_evidence.validate_pair(manifest, self._paired_record(manifest))
        for field, bad_value in (
            ("provider_category_exact", chr(0xD800)),
            ("provider_code_exact", chr(0xD800)),
            ("event_time_utc", chr(0xD800)),
            ("provider_category_exact", [sentinel]),
            ("provider_code_exact", {"detail": sentinel}),
            ("provider_code_exact", "absent"),
        ):
            with self.subTest(field=field, kind=type(bad_value).__name__):
                pair = self._paired_record(manifest)
                first_error = pair["windows"]["first_client_error"]
                first_error["normalized_category"] = "trust"
                first_error["provider_category_exact"] = "provider-trust"
                if bad_value == "absent":
                    del first_error[field]
                else:
                    first_error[field] = bad_value
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn("WINDOWS_FIRST_ERROR_INVALID",
                              summary["evidence_failures"])
                self.assertEqual(summary["windows"]["first_client_error_category"],
                                 "unknown")
                self.assertEqual(summary["comparison"], "INCONCLUSIVE")
                self.assertEqual(set(summary), set(expected))
                self.assertEqual(set(summary["windows"]), set(expected["windows"]))
                public_text = json.dumps(summary, ensure_ascii=False)
                self.assertNotIn(sentinel, public_text)
                self.assertNotIn(chr(0xD800), public_text)

        # The read-only CLI returns the typed FAIL JSON, not a traceback.
        pair = self._paired_record(manifest)
        pair["windows"]["first_client_error"]["normalized_category"] = "trust"
        pair["windows"]["first_client_error"]["provider_category_exact"] = chr(0xD800)
        manifest_file = self.root / "private-macos.json"
        pair_file = self.root / "private-pair.json"
        manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
        pair_file.write_text(json.dumps(pair), encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = ab_evidence.main([str(manifest_file), str(pair_file)])
        self.assertEqual(exit_code, 3)
        self.assertEqual(stderr.getvalue(), "")
        cli_summary = json.loads(stdout.getvalue())
        self.assertEqual(cli_summary["evidence_status"], "FAIL")
        self.assertIn("WINDOWS_FIRST_ERROR_INVALID", cli_summary["evidence_failures"])
        self.assertEqual(cli_summary["windows"]["first_client_error_category"], "unknown")
        self.assertNotIn(chr(0xD800), stdout.getvalue())

    def test_macos_private_first_error_summary_fields_fail_closed(self):
        # Collector manifests are private, even if generated by a trusted CLI.
        private_marker = "private-session-password-sentinel"
        original = evidence.build_manifest(self.options)
        expected_keys = set(evidence.build_redacted_summary(original))
        mutations = (
            ("client_error_code", None, private_marker, "CLIENT_UI_CODE_INVALID"),
            ("client_error_code", None, [private_marker], "CLIENT_UI_CODE_INVALID"),
            ("client_error_code", None, {"detail": private_marker}, "CLIENT_UI_CODE_INVALID"),
            ("first_client_error", "normalized_category", private_marker,
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "normalized_category", [private_marker],
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "source", {"detail": private_marker},
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "provider_category_exact", [private_marker],
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "provider_code_exact", {"detail": private_marker},
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "provider_category_exact", chr(0xD800),
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "event_time_utc", private_marker,
             "FIRST_CLIENT_ERROR_INVALID"),
            ("first_client_error", "event_time_utc", [private_marker],
             "FIRST_CLIENT_ERROR_INVALID"),
        )
        for section, field, value, error in mutations:
            with self.subTest(section=section, field=field, type=type(value).__name__):
                manifest = evidence.build_manifest(self.options)
                if field is None:
                    manifest[section] = value
                else:
                    manifest[section][field] = value
                summary = evidence.build_redacted_summary(manifest)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn(error, summary["evidence_failures"])
                self.assertEqual(set(summary), expected_keys)
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))
                if field is None:
                    self.assertEqual(summary["client_error"]["ui_code"], "not-recorded")
                else:
                    self.assertEqual(summary["client_error"]["first_typed_category"],
                                     "unknown")
                    self.assertEqual(summary["client_error"]["source"], "not-observed")
                    self.assertIsNone(summary["client_error"]["event_time_utc"])
                    self.assertFalse(summary["client_error"]["provider_category_present"])
                    self.assertFalse(summary["client_error"]["provider_code_present"])

        # Public metadata is also sourced from the private manifest.
        # Invalid fields must never reflect a private marker or nested value.
        private_metadata = (
            (None, "attempt_time_utc", private_marker,
             "CORRELATION_TIMESTAMP_INVALID", "attempt_time_utc", None),
            ("linux_correlation", "terminal_time_utc", [private_marker],
             "CORRELATION_TIMESTAMP_INVALID", "linux_correlation", "terminal_time_utc"),
            ("windows_app", "version", private_marker,
             "CLIENT_VERSION_INVALID", "windows_app", "version"),
            ("windows_app", "build", {"secret": private_marker},
             "CLIENT_VERSION_MISSING", "windows_app", "build"),
            ("saved_credential", "server_client_credentials_intentionally_matched",
             private_marker, "INVALID_CREDENTIAL_CONTROL",
             "credential_control", "server_client_credentials_intentionally_matched"),
            ("certificate_warning", "appeared", [private_marker],
             "CERTIFICATE_DECISION_INCONSISTENT", "certificate_warning", "appeared"),
            ("certificate_warning", "accepted", private_marker,
             "CERTIFICATE_DECISION_INCONSISTENT", "certificate_warning", "accepted"),
            ("logging", "core_level", private_marker,
             "CLIENT_LOG_LEVEL_INVALID", "logging", "core_level"),
            ("logging", "ui_level", [private_marker],
             "CLIENT_LOG_LEVEL_INVALID", "logging", "ui_level"),
            ("logging", "file_count", {"secret": private_marker},
             "CLIENT_LOG_FILE_COUNT_INVALID", "logging", "file_count"),
        )
        for private_section, private_field, private_value, denial, public_section, public_field in private_metadata:
            with self.subTest(metadata=private_field, type=type(private_value).__name__):
                manifest = evidence.build_manifest(self.options)
                if private_section is None:
                    manifest[private_field] = private_value
                else:
                    manifest[private_section][private_field] = private_value
                summary = evidence.build_redacted_summary(manifest)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn(denial, summary["evidence_failures"])
                self.assertEqual(set(summary), expected_keys)
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))
                projected = (summary[public_section] if public_field is None
                             else summary[public_section][public_field])
                expected = ("not-recorded" if private_section == "logging"
                            and private_field in ("core_level", "ui_level") else None)
                self.assertEqual(projected, expected)

        # A truthy private string is not evidence of logging lifecycle.
        for lifecycle_field in ("started_before_attempt", "stopped_after_attempt"):
            manifest = evidence.build_manifest(self.options)
            manifest["logging"][lifecycle_field] = private_marker
            summary = evidence.build_redacted_summary(manifest)
            self.assertEqual(summary["evidence_status"], "FAIL")
            self.assertIn("LOGGING_LIFECYCLE_INCOMPLETE", summary["evidence_failures"])
            self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

        for missing in ("first_client_error", "provider_code_exact"):
            with self.subTest(missing=missing):
                manifest = evidence.build_manifest(self.options)
                if missing == "first_client_error":
                    del manifest["first_client_error"]
                else:
                    del manifest["first_client_error"][missing]
                summary = evidence.build_redacted_summary(manifest)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn("FIRST_CLIENT_ERROR_INVALID", summary["evidence_failures"])
                self.assertEqual(summary["client_error"]["first_typed_category"],
                                 "unknown")

        stderr = io.StringIO()
        stdout = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(stdout):
            exit_status = evidence.main([
                "validate", str(self.root / f"{private_marker}.json")
            ])
        self.assertEqual(exit_status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "macOS Windows App evidence: private record invalid\n"
        )
        self.assertNotIn(private_marker, stderr.getvalue())

    def test_paired_private_original_macos_category_invalid_after_redaction(self):
        # Redacting a malformed private category to public "unknown" must not
        # obscure the typed original-source denial in the paired validator.
        private_marker = "private-session-password-sentinel"
        for private_category in (
            private_marker, [private_marker], {"detail": private_marker}
        ):
            with self.subTest(category_type=type(private_category).__name__):
                manifest = evidence.build_manifest(self.options)
                pair = self._paired_record(manifest)
                manifest["first_client_error"]["normalized_category"] = private_category
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn("MACOS_R5_EVIDENCE_INVALID", summary["evidence_failures"])
                self.assertIn("MACOS_FIRST_ERROR_INVALID", summary["evidence_failures"])
                self.assertEqual(summary["macos"]["first_client_error_category"],
                                 "unknown")
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

    def test_paired_private_malformed_nested_evidence_denials(self):
        manifest = evidence.build_manifest(self.options)
        private_marker = "private-session-password-sentinel"
        malformed = (
            ("first_client_error", "provider_category_exact",
             [private_marker], "WINDOWS_FIRST_ERROR_INVALID"),
            ("first_client_error", "provider_code_exact",
             {"detail": private_marker}, "WINDOWS_FIRST_ERROR_INVALID"),
            ("first_client_error", "event_time_utc",
             [private_marker], "WINDOWS_FIRST_ERROR_INVALID"),
            ("first_client_error", "normalized_category",
             {"detail": private_marker}, "WINDOWS_FIRST_ERROR_INVALID"),
            ("server_stage_matrix", "type3_received",
             [private_marker], "WINDOWS_STAGES_INCOMPLETE"),
            ("server_transport_observation", "terminal_attribution",
             {"detail": private_marker}, "WINDOWS_TRANSPORT_INVALID"),
            ("client_security_stages", "type2_received",
             [private_marker], "WINDOWS_CLIENT_STAGES_INCOMPLETE"),
            ("certificate_warning", "accepted",
             [private_marker], "WINDOWS_CERTIFICATE_DECISION_INVALID"),
        )
        for section, field, value, expected in malformed:
            with self.subTest(section=section, field=field):
                pair = self._paired_record(manifest)
                pair["windows"][section][field] = value
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn(expected, summary["evidence_failures"])
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

        for missing in ("first_client_error", "provider_code_exact"):
            with self.subTest(missing=missing):
                pair = self._paired_record(manifest)
                if missing == "first_client_error":
                    del pair["windows"]["first_client_error"]
                else:
                    del pair["windows"]["first_client_error"][missing]
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn("WINDOWS_FIRST_ERROR_INVALID", summary["evidence_failures"])
                self.assertEqual(summary["windows"]["first_client_error_category"],
                                 "unknown")

        pair = self._paired_record(manifest)
        pair["windows"]["client_security_stages"]["type2_received"] = "PASS"
        pair["windows"]["client_stage_evidence"]["type2_received"] = self._client_event(
            pair, "windows")
        pair["windows"]["client_stage_evidence"]["type2_received"][
            "source_kind"] = {"detail": private_marker}
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertIn("WINDOWS_CLIENT_TYPE2_RECEIVED_SOURCE_UNSUPPORTED",
                      summary["evidence_failures"])
        self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

        # Values in a private collector's summary do not become public.
        manifest["windows_app"]["version"] = private_marker
        manifest["first_client_error"]["normalized_category"] = private_marker
        pair = self._paired_record(manifest)
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("MACOS_CLIENT_VERSION_INVALID", summary["evidence_failures"])
        self.assertIn("MACOS_FIRST_ERROR_INVALID", summary["evidence_failures"])
        self.assertEqual(summary["macos"]["first_client_error_category"], "unknown")
        self.assertEqual(summary["macos"]["version"]["version"], "INVALID")
        self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

    def test_paired_private_missing_client_stage_remains_fail_closed(self):
        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        del pair["windows"]["client_security_stages"]["type2_received"]

        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("WINDOWS_CLIENT_STAGES_INCOMPLETE",
                      summary["evidence_failures"])
        self.assertEqual(summary["windows"]["client_security_stages"]["type2_received"],
                         "NOT_OBSERVED")

    def test_paired_malformed_macos_sources_and_absent_windows_error_fail_closed(self):
        # Private nested sections must never trigger an exception, copy a
        # sentinel into shared output or change the closed public v3 schema.
        private_marker = "private-source-field-sentinel"
        pristine = evidence.build_manifest(self.options)
        expected_schema = ab_evidence.validate_pair(
            pristine, self._paired_record(pristine))
        malformed = (
            ("macos", "windows_app", [private_marker], "MACOS_CLIENT_VERSION_INVALID"),
            ("macos", "saved_credential", [private_marker], "MACOS_R5_EVIDENCE_INVALID"),
            ("macos", "linux_correlation", [private_marker], "MACOS_R5_EVIDENCE_INVALID"),
            ("macos", "server_sha", [private_marker], "AB_SERVER_SHA_MISMATCH"),
            ("macos", "server_stage_matrix", [private_marker], "MACOS_STAGES_INCOMPLETE"),
            ("macos", "first_client_error", [private_marker], "MACOS_FIRST_ERROR_INVALID"),
            ("windows", "first_client_error", [private_marker], "WINDOWS_FIRST_ERROR_INVALID"),
            ("windows", "first_client_error", None, "WINDOWS_FIRST_ERROR_INVALID"),
            ("windows", "first_client_error", "absent", "WINDOWS_FIRST_ERROR_INVALID"),
        )
        for platform, field, value, expected_failure in malformed:
            with self.subTest(platform=platform, field=field, kind=type(value).__name__):
                manifest = evidence.build_manifest(self.options)
                pair = self._paired_record(manifest)
                if platform == "macos":
                    manifest[field] = value
                elif value == "absent":
                    del pair["windows"][field]
                else:
                    pair["windows"][field] = value
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn(expected_failure, summary["evidence_failures"])
                self.assertEqual(set(summary), set(expected_schema))
                self.assertEqual(set(summary["macos"]), set(expected_schema["macos"]))
                self.assertEqual(set(summary["windows"]), set(expected_schema["windows"]))
                self.assertEqual(summary["comparison"], "INCONCLUSIVE")
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))
                if platform == "windows":
                    self.assertEqual(
                        summary["windows"]["first_client_error_category"], "unknown")

        # The macOS collector owns a six-field private first-error schema:
        # local and UTC timestamps are a pair and provider values stay private.
        for field, value in (
            ("provider_category_exact", [private_marker]),
            ("provider_code_exact", {"detail": private_marker}),
            ("event_time_local", [private_marker]),
            ("event_time_utc", {"detail": private_marker}),
            ("source", [private_marker]),
        ):
            with self.subTest(platform="macos", first_error_field=field):
                manifest = evidence.build_manifest(self.options)
                pair = self._paired_record(manifest)
                manifest["first_client_error"][field] = value
                summary = ab_evidence.validate_pair(manifest, pair)
                self.assertEqual(summary["evidence_status"], "FAIL")
                self.assertIn("MACOS_FIRST_ERROR_INVALID",
                              summary["evidence_failures"])
                self.assertEqual(summary["macos"]["first_client_error_category"],
                                 "unknown")
                self.assertNotIn(private_marker, json.dumps(summary, sort_keys=True))

        manifest = evidence.build_manifest(self.options)
        pair = self._paired_record(manifest)
        del manifest["first_client_error"]["event_time_local"]
        summary = ab_evidence.validate_pair(manifest, pair)
        self.assertEqual(summary["evidence_status"], "FAIL")
        self.assertIn("MACOS_FIRST_ERROR_INVALID", summary["evidence_failures"])

        # An unreadable private path must not be reflected in CLI stderr.
        error_output = io.StringIO()
        normal_output = io.StringIO()
        with redirect_stderr(error_output), redirect_stdout(normal_output):
            status = ab_evidence.main([
                str(self.root / f"{private_marker}.json"),
                str(self.root / "pair.json"),
            ])
        self.assertEqual(status, 2)
        self.assertEqual(normal_output.getvalue(), "")
        self.assertEqual(error_output.getvalue(),
                         "client A/B evidence: private record invalid\n")
        self.assertNotIn(private_marker, error_output.getvalue())

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
