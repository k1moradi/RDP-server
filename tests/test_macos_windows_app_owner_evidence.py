# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the read-only macOS Windows App evidence manifest."""
import argparse
import hashlib
import importlib.util
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
            attempt_time="2026-10-27T05:30:00-07:00",
            destination="192.0.2.10",
            certificate_warning="yes",
            certificate_warning_accepted="yes",
            error_text="Connection failed.",
            core_log_level="Info",
            ui_log_level="Info",
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
        self.assertEqual(manifest["server_sha"], "a" * 40)
        self.assertEqual(manifest["attempt_time_utc"], "2026-10-27T12:30:00+00:00")
        self.assertEqual(manifest["destination_exact"], "192.0.2.10")
        self.assertEqual(manifest["windows_app"]["version"], "11.4.4")
        self.assertEqual(manifest["windows_app"]["build"], "3132")
        self.assertEqual(manifest["logging"]["file_count"], 1)
        self.assertEqual(
            manifest["logging"]["files"][0]["sha256"],
            hashlib.sha256(b"same-attempt-log\n").hexdigest(),
        )

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

    def test_symlinked_log_input_is_rejected(self):
        target = self.root / "outside.log"
        target.write_text("outside", encoding="utf-8")
        (self.logs / "link.log").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            evidence.build_manifest(self.options)

    def test_sha_and_timestamp_are_bounded_and_typed(self):
        self.options.server_sha = "short"
        with self.assertRaisesRegex(ValueError, "40 hexadecimal"):
            evidence.build_manifest(self.options)
        self.options.server_sha = "b" * 40
        self.options.attempt_time = "2026-10-27T05:30:00"
        with self.assertRaisesRegex(ValueError, "UTC offset"):
            evidence.build_manifest(self.options)


if __name__ == "__main__":
    unittest.main(argv=["owner-evidence-tests", *remaining])
