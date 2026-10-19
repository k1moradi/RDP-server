#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-level R9 public artifact gate and mutation-denial regressions."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHA_EXPR = "$" + "{{ github.sha }}"


def require_release_gate(workflow: str, verifier: str) -> None:
    for unique_guard in (
        "$hashes = @{}",
        "[regex]::Match",
        "Groups[2].Value",
        "Write-Host 'R9 clean Windows portable GUI acceptance PASS'",
    ):
        if verifier.count(unique_guard) != 1:
            raise AssertionError(
                f"Clean consumer guard missing or duplicated: {unique_guard}")
    if not verifier.rstrip().endswith(
            "Write-Host 'R9 clean Windows portable GUI acceptance PASS'"):
        raise AssertionError("Clean consumer tail is truncated or duplicated")
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


def require_fail_closed_socket_observation(smoke: str) -> None:
    # Runtime enumeration must propagate read/permission failures, not report
    # an empty set when Get-NetTCPConnection/Get-NetUDPEndpoint fails.
    marker = "function Assert-NoProcessSockets([int]$ProcessId) {"
    if smoke.count(marker) != 1:
        raise AssertionError("socket-observation owner absent/duplicated")
    block = smoke.split(marker, 1)[1].split(
        "function Invoke-FirstScreenSmoke", 1)[0]
    for required in (
        "Get-NetTCPConnection -ErrorAction Stop",
        "Get-NetUDPEndpoint -ErrorAction Stop",
        "Where-Object { $_.OwningProcess -eq $ProcessId }",
        "throw \"GUI opened a TCP/UDP socket",
    ):
        if required not in block:
            raise AssertionError(f"Fail-closed socket query missing: {required}")
    if "-ErrorAction SilentlyContinue" in block:
        raise AssertionError("Windows socket-query errors were suppressed")


class CleanWindowsReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.verifier = (ROOT / "scripts/clean_windows_portable_gui.ps1").read_text(encoding="utf-8")
        cls.socket_smoke = (ROOT / "scripts/smoke_windows_portable_gui.ps1").read_text(encoding="utf-8")

    def test_socket_enumeration_fails_closed(self) -> None:
        require_fail_closed_socket_observation(self.socket_smoke)

    def test_silent_socket_error_mutation_denied(self) -> None:
        mutated = self.socket_smoke.replace(
            "Get-NetTCPConnection -ErrorAction Stop",
            "Get-NetTCPConnection -ErrorAction SilentlyContinue")
        with self.assertRaises(AssertionError):
            require_fail_closed_socket_observation(mutated)


    @unittest.skipUnless(os.name == "nt", "native PowerShell parser requires Windows")
    def test_clean_consumer_powershell_syntax(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell executable unavailable")
        verifier_path = str(
            (ROOT / "scripts/clean_windows_portable_gui.ps1").resolve()
        ).replace("'", "''")
        command = (
            "$tokens = $null; $parseErrors = $null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{verifier_path}', "
            "[ref]$tokens, [ref]$parseErrors) | Out-Null; "
            "if ($parseErrors.Count -ne 0) { "
            "$parseErrors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
        )
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"PowerShell parse failure:\n{result.stdout}\n{result.stderr}",
        )

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


    def test_duplicated_checksum_parser_denied(self) -> None:
        changed = self.verifier.replace(
            "[regex]::Match", "[regex]::Match [regex]::Match", 1
        )
        with self.assertRaises(AssertionError):
            require_release_gate(self.workflow, changed)

    def test_duplicated_consumer_tail_denied(self) -> None:
        changed = self.verifier + "\n" + (
            "Write-Host 'R9 clean Windows portable GUI acceptance PASS'\n"
        )
        with self.assertRaises(AssertionError):
            require_release_gate(self.workflow, changed)

    def test_removed_qt_env_guard_denied(self) -> None:
        changed = self.verifier.replace("QT_PLUGIN_PATH", "unrestricted-qt-path")
        with self.assertRaises(AssertionError):
            require_release_gate(self.workflow, changed)


if __name__ == "__main__":
    unittest.main()
