#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline SERVER-TEST bundle integrity and lifecycle regressions."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("--script", type=Path, required=True)
arguments, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("server_test_bundle", arguments.script)
bundle = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bundle)


class ServerTestBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def make_archive(
        self, platform_name: str = "linux", source_sha: str = "a" * 40
    ) -> Path:
        artifact_name = (
            f"rdp-server-test-0.1.0-{platform_name}-x86_64-{source_sha[:12]}"
        )
        stage = self.root / "stage" / artifact_name
        stage.mkdir(parents=True)
        executable_relative = (
            "bin/rdp-server.exe" if platform_name == "windows" else "bin/rdp-server"
        )
        runtime_dependencies = (
            ["libcrypto-3-x64.dll"]
            if platform_name == "windows"
            else ["libc.so.6"]
        )
        payload = {
            executable_relative: b"offline-synthetic-server-test-payload",
            "config/rdp-server.conf.example": b"listen_address=127.0.0.1\n",
            "metadata/DEPENDENCIES.txt": b"synthetic runtime dependency\n",
            "docs/INSTALL-START-STOP-UNINSTALL.md": b"startup disabled\n",
            "licenses/LICENSE": b"GPL-3.0-or-later\n",
        }
        if platform_name == "windows":
            payload["bin/libcrypto-3-x64.dll"] = b"offline-synthetic-runtime"
            payload["platform/windows/rdp-server-test.ps1"] = (
                b"# offline synthetic lifecycle fixture\n"
            )
        for relative, data in payload.items():
            bundle.write_payload_file(
                stage, relative, data, bundle.mode_for_relative(relative)
            )
        manifest = {
            "schema_version": bundle.SCHEMA_VERSION,
            "artifact_family": bundle.ARTIFACT_FAMILY,
            "artifact_name": artifact_name,
            "classification": "startup-disabled-preview",
            "production_ready": False,
            "startup_enabled": False,
            "exact_git_sha": source_sha,
            "version": "0.1.0",
            "platform": platform_name,
            "architecture": "x86_64",
            "abi": (
                "PE32+ Windows ABI"
                if platform_name == "windows"
                else "ELF64; synthetic"
            ),
            "compiler": {
                "id": "Test",
                "version": "1",
                "executable": "test++",
                "generator": "test",
                "build_configuration": "Release",
            },
            "build_configuration": "Release",
            "executable": executable_relative,
            "runtime_dependencies": runtime_dependencies,
            "install": bundle.install_contract(platform_name),
            "files": bundle.payload_metadata(stage, list(payload)),
        }
        manifest_relative = "metadata/SERVER-TEST-MANIFEST.json"
        bundle.write_payload_file(
            stage,
            manifest_relative,
            (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(),
            0o644,
        )
        checksum_relative = "metadata/SHA256SUMS.txt"
        bundle.write_payload_file(
            stage,
            checksum_relative,
            bundle.checksum_text(stage, [*payload, manifest_relative]).encode(),
            0o644,
        )
        archive = self.root / f"{artifact_name}.zip"
        bundle.write_zip(archive, stage, artifact_name)
        return archive

    def test_verified_archive_install_and_uninstall_are_idempotent(self) -> None:
        archive = self.make_archive()
        manifest, _ = bundle.validated_archive(archive)
        self.assertEqual(manifest["artifact_family"], "SERVER-TEST")
        destination = self.root / "install"
        installed = bundle.install_archive(archive, destination)
        self.assertTrue((installed / "bin/rdp-server").is_file())
        self.assertEqual(bundle.install_archive(archive, destination), installed)
        bundle.uninstall_archive(archive, destination)
        bundle.uninstall_archive(archive, destination)
        self.assertFalse(installed.exists())

    def test_modified_install_is_not_silently_removed(self) -> None:
        archive = self.make_archive()
        destination = self.root / "install"
        installed = bundle.install_archive(archive, destination)
        (installed / "bin/rdp-server").write_bytes(b"tampered")
        with self.assertRaisesRegex(bundle.BundleError, "installed content mismatch"):
            bundle.uninstall_archive(archive, destination)
        self.assertTrue(installed.exists())

    def test_windows_dependency_report_marks_os_supplied_boundary(self) -> None:
        report = bundle.dependency_report(
            [Path("C:/OpenSSL/bin/libcrypto-3-x64.dll")], "windows"
        )
        self.assertIn("Windows/System32", report)
        self.assertIn("libcrypto-3-x64.dll", report)

    def test_sensitive_payload_markers_and_unsafe_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(bundle.BundleError, "sensitive marker"):
            bundle.write_payload_file(
                self.root,
                "config/secret.txt",
                b"-----BEGIN PRIVATE KEY-----\n",
                0o600,
            )
        self.assertFalse(bundle.safe_relative_path("../escape"))
        archive = self.root / "bad.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("../escape", b"x")
        with self.assertRaises(bundle.BundleError):
            bundle.validated_archive(archive)

    def test_exact_sha_status_acceptance_requires_all_three_platforms(self) -> None:
        status_directory = self.root / "statuses"
        status_directory.mkdir()
        sha = "b" * 40
        for platform_name in ("linux", "windows", "macos"):
            archive = self.make_archive(platform_name, sha)
            copied_archive = status_directory / archive.name
            copied_archive.write_bytes(archive.read_bytes())
            archive_digest = bundle.sha256_file(copied_archive)
            checksum = status_directory / (archive.name + ".sha256")
            checksum.write_text(
                f"{archive_digest}  {archive.name}\n", encoding="utf-8"
            )
            artifact_name = archive.stem
            status = {
                "artifact_family": "SERVER-TEST",
                "artifact_name": artifact_name,
                "exact_git_sha": sha,
                "platform": platform_name,
                "architecture": "x86_64",
                "archive_sha256": archive_digest,
                "status": "PASS",
                "startup_status": "DISABLED",
                "deployment_status": "NOT VERIFIED; NOT CLAIMED",
                "checks": {
                    check: "PASS"
                    for check in (
                        bundle.REQUIRED_COMMON_SMOKE_CHECKS
                        | (
                            bundle.REQUIRED_WINDOWS_SMOKE_CHECKS
                            if platform_name == "windows"
                            else frozenset()
                        )
                    )
                },
            }
            (status_directory / f"{artifact_name}-STATUS.json").write_text(
                json.dumps(status), encoding="utf-8"
            )
        bundle.verify_status_directory(status_directory, sha)
        first_status = next(status_directory.glob("*-STATUS.json"))
        changed = json.loads(first_status.read_text(encoding="utf-8"))
        changed["exact_git_sha"] = "c" * 40
        first_status.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(bundle.BundleError):
            bundle.verify_status_directory(status_directory, sha)

        changed["exact_git_sha"] = sha
        changed["checks"].pop("packaged_sample_serve_refusal")
        first_status.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(bundle.BundleError, "smoke inventory mismatch"):
            bundle.verify_status_directory(status_directory, sha)

        changed["checks"]["packaged_sample_serve_refusal"] = "FAIL"
        first_status.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(bundle.BundleError, "smoke acceptance failed"):
            bundle.verify_status_directory(status_directory, sha)

        changed["checks"]["packaged_sample_serve_refusal"] = "PASS"
        changed["checks"]["unreviewed_test"] = "PASS"
        first_status.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(bundle.BundleError, "smoke inventory mismatch"):
            bundle.verify_status_directory(status_directory, sha)


if __name__ == "__main__":
    unittest.main(argv=["server-test-bundle-tests", *remaining])
