#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-level R9 public artifact gate and mutation-denial regressions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHA_EXPR = "$" + "{{ github.sha }}"


def require_release_gate(workflow: str, verifier: str) -> None:
    identifier = "  r9-clean-windows-portable-gui:\n"
    if workflow.count(identifier) != 1:
        raise AssertionError("R9 clean consumer job missing or duplicated")
    import re
    suffix = workflow.split(identifier, 1)[1]
    next_job = re.search(r"^  [A-Za-z0-9_-]+:\s*$", suffix, re.MULTILINE)
    job = suffix[:next_job.start()] if next_job else suffix
    for required in (
        "needs: [ci-workflow-structure, r6-windows-clang23]",
        "runs-on: [self-hosted, Windows, X64, r9-clean-windows-gui]",
        "actions/download-artifact@v4",
        "name: r9-windows-unverified-" + SHA_EXPR,
        "scripts/clean_windows_portable_gui.ps1",
        "name: rdp-server-portable-gui-windows-x86_64",
        "actions/upload-artifact@v4",
        "r9-clean-windows-receipt-" + SHA_EXPR,
    ):
        if required not in job:
            raise AssertionError(f"Missing release prerequisite: {required}")
    if "msys2/setup-msys2" in job or "windeployqt" in job:
        raise AssertionError("Consumer must not install/fix dependencies")
    if workflow.count("name: rdp-server-portable-gui-windows-x86_64") != 1:
        raise AssertionError("Only the consumer may publish the Windows ZIP")
    if workflow.count("name: r9-windows-unverified-" + SHA_EXPR) != 2:
        raise AssertionError("The producer/consumer must use one exact archive")
    for required in (
        "IsInRole", "Get-Process explorer", "SessionId",
        "Get-FileHash", "PORTABLE-GUI-MANIFEST.json", "SHA256SUMS.txt",
        "[regex]::Match", "Groups[2].Value",
        "LICENSE", "NOTICE", "THIRD_PARTY.md", "qwindows.dll",
        "Expand-Archive", "Get-NetFirewallRule", "Get-NetFirewallProfile",
        "TermService", "fDenyTSConnections", "PortNumber",
        "Get-NetTCPConnection", "Get-NetUDPEndpoint",
        "smoke_windows_portable_gui.ps1", "offline-unsupported-password-test",
        "QT_PLUGIN_PATH", "System32", "Start-Process",
    ):
        if required not in verifier:
            raise AssertionError(f"Consumer security guard absent: {required}")


class CleanWindowsReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.verifier = (ROOT / "scripts/clean_windows_portable_gui.ps1").read_text(encoding="utf-8")

    def test_real_gate(self) -> None:
        require_release_gate(self.workflow, self.verifier)

    def test_missing_release_job_denied(self) -> None:
        changed = self.workflow.replace("  r9-clean-windows-portable-gui:\n", "  disabled-r9-job:\n", 1)
        with self.assertRaises(AssertionError):
            require_release_gate(changed, self.verifier)

    def test_provisioned_runner_denied(self) -> None:
        changed = self.workflow.replace(
            "runs-on: [self-hosted, Windows, X64, r9-clean-windows-gui]",
            "runs-on: windows-latest", 1)
        with self.assertRaises(AssertionError):
            require_release_gate(changed, self.verifier)

    def test_removed_firewall_snapshot_denied(self) -> None:
        changed = self.verifier.replace("Get-NetFirewallRule", "no-firewall-audit")
        with self.assertRaises(AssertionError):
            require_release_gate(self.workflow, changed)

    def test_checksum_match_capture_denied(self) -> None:
        changed = self.verifier.replace("[regex]::Match", "NoValidatedRegex")
        with self.assertRaises(AssertionError):
            require_release_gate(self.workflow, changed)

    def test_removed_qt_env_guard_denied(self) -> None:
        changed = self.verifier.replace("QT_PLUGIN_PATH", "unrestricted-qt-path")
        with self.assertRaises(AssertionError):
            require_release_gate(self.workflow, changed)


if __name__ == "__main__":
    unittest.main()
