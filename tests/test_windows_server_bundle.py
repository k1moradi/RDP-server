#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline R6 Windows SERVER-TEST packaging and lifecycle regressions."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--script", type=Path, required=True)
parser.add_argument("--lifecycle-script", type=Path, required=True)
arguments, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("server_test_bundle", arguments.script)
bundle = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bundle)


class WindowsServerBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lifecycle_script = arguments.lifecycle_script.resolve()

    def make_archive(self, source_sha: str = "6" * 40) -> Path:
        artifact_name = (
            f"rdp-server-test-0.1.0-windows-x86_64-{source_sha[:12]}"
        )
        stage = self.root / "stage" / artifact_name
        stage.mkdir(parents=True)
        payload = {
            "bin/rdp-server.exe": b"offline-synthetic-windows-server-test",
            "bin/libcrypto-3-x64.dll": b"offline-synthetic-openssl-runtime",
            "config/rdp-server.conf.example": (
                b"listen_address=127.0.0.1\nauthentication=required\n"
                b"os_authorization=required\n"
            ),
            "metadata/DEPENDENCIES.txt": (
                b"libcrypto-3-x64.dll is bundled; Windows system DLLs are OS-supplied.\n"
            ),
            "docs/INSTALL-START-STOP-UNINSTALL.md": b"startup blocked\n",
            "licenses/LICENSE": b"GPL-3.0-or-later\n",
            "platform/windows/rdp-server-test.ps1": self.lifecycle_script.read_bytes(),
        }
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
            "platform": "windows",
            "architecture": "x86_64",
            "abi": "PE32+ Windows ABI",
            "compiler": {
                "id": "MSVC",
                "version": "19.51.36260.0",
                "executable": "cl.exe",
                "generator": "Visual Studio 18 2026",
                "build_configuration": "Release",
            },
            "build_configuration": "Release",
            "executable": "bin/rdp-server.exe",
            "runtime_dependencies": ["libcrypto-3-x64.dll"],
            "install": bundle.install_contract("windows"),
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
        archive.with_suffix(".zip.sha256").write_text(
            f"{bundle.sha256_file(archive)}  {archive.name}\n", encoding="utf-8"
        )
        return archive

    def powershell(self) -> str | None:
        return shutil.which("pwsh") or shutil.which("powershell.exe")

    def run_lifecycle(
        self,
        action: str,
        *,
        archive: Path | None = None,
        expect: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        shell = self.powershell()
        if shell is None:
            self.skipTest("PowerShell lifecycle execution is Windows-native evidence")
        environment = dict(os.environ)
        environment["LOCALAPPDATA"] = str(self.root / "localappdata")
        command = [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.lifecycle_script),
            "-Action",
            action,
        ]
        if archive is not None:
            command.extend(["-ArchivePath", str(archive)])
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=30,
        )
        self.assertEqual(
            result.returncode,
            expect,
            msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        return result

    def test_windows_install_contract_is_user_level_and_startup_disabled(self) -> None:
        contract = bundle.install_contract("windows")
        self.assertEqual(contract["owner"], "R6")
        self.assertEqual(contract["mode"], "per-user-script-preview")
        self.assertEqual(
            contract["lifecycle_script"], "platform/windows/rdp-server-test.ps1"
        )
        self.assertFalse(contract["service_registration"])
        self.assertFalse(contract["autostart"])
        self.assertFalse(contract["firewall_rules"])
        self.assertIn("%LOCALAPPDATA%", contract["install_root"])

    def test_windows_runtime_dll_payloads_reject_alias_collisions(self) -> None:
        first = self.root / "a" / "libcrypto-3-x64.dll"
        first.parent.mkdir()
        first.write_bytes(b"first")
        second = self.root / "b" / "LIBCRYPTO-3-X64.DLL"
        second.parent.mkdir()
        second.write_bytes(b"second")
        with self.assertRaisesRegex(bundle.BundleError, "duplicate Windows runtime DLL"):
            bundle.windows_runtime_dependency_payloads([first, second])
        self.assertEqual(
            bundle.windows_runtime_dependency_payloads([first]),
            [("bin/libcrypto-3-x64.dll", first)],
        )

    def test_windows_archive_requires_bundled_runtime_and_lifecycle(self) -> None:
        archive = self.make_archive()
        manifest, _ = bundle.validated_archive(archive)
        self.assertIn("bin/libcrypto-3-x64.dll", manifest["files"])
        self.assertIn("platform/windows/rdp-server-test.ps1", manifest["files"])

    def test_lifecycle_script_does_not_self_trigger_bundle_secret_scan(self) -> None:
        data = self.lifecycle_script.read_bytes()
        for marker in bundle.FORBIDDEN_BYTE_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, data)
        bundle.scan_for_secrets("platform/windows/rdp-server-test.ps1", data)

    def test_lifecycle_script_has_no_network_autostart_service_or_firewall_actions(self) -> None:
        text = self.lifecycle_script.read_text(encoding="utf-8")
        for required in (
            "Install', 'Verify', 'Start', 'Status', 'Stop', 'Uninstall",
            "LocalApplicationData",
            "Get-FileHash",
            "ReparsePoint",
            "genuine Windows R2 SSPI/CredSSP SID-bound admission",
            "serialized R10 interactive-session ownership",
        ):
            self.assertIn(required, text)
        for forbidden in (
            "Invoke-WebRequest",
            "Invoke-RestMethod",
            "Start-BitsTransfer",
            "System.Net.WebClient",
            "New-NetFirewallRule",
            "Set-NetFirewallRule",
            "New-Service",
            "Start-Service",
            "Register-ScheduledTask",
            "schtasks",
            "Start-Process",
            "CurrentVersion\\Run",
        ):
            self.assertNotIn(forbidden.casefold(), text.casefold())

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell lifecycle test")
    def test_native_powershell_install_verify_blocked_start_stop_uninstall(self) -> None:
        archive = self.make_archive()
        install = self.run_lifecycle("Install", archive=archive)
        self.assertIn("startup remains BLOCKED", install.stdout)
        self.run_lifecycle("Install", archive=archive)
        self.run_lifecycle("Verify", archive=archive)
        status = self.run_lifecycle("Status")
        self.assertIn("startup status is BLOCKED", status.stdout)
        blocked = self.run_lifecycle("Start", expect=3)
        self.assertIn("No listener was started", blocked.stderr)
        self.run_lifecycle("Stop")
        self.run_lifecycle("Uninstall")
        self.run_lifecycle("Uninstall")

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell lifecycle test")
    def test_native_powershell_rejects_bad_checksum_without_echoing_sensitive_data(self) -> None:
        archive = self.make_archive()
        archive.with_suffix(".zip.sha256").write_text(
            f"{'0' * 64}  {archive.name}\n", encoding="utf-8"
        )
        result = self.run_lifecycle("Install", archive=archive, expect=1)
        combined = result.stdout + result.stderr
        self.assertIn("failed closed", combined)
        self.assertNotIn("PRIVATE KEY", combined)
        self.assertNotIn("tls_private_key", combined)


if __name__ == "__main__":
    unittest.main(argv=["windows-server-bundle-tests", *remaining])
