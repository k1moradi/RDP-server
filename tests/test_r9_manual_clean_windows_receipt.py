#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline denial tests for the R9 format-2 clean-Windows receipt verifier."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_clean_windows_receipt.py"
spec = importlib.util.spec_from_file_location(
    "verify_clean_windows_receipt", VERIFIER_PATH
)
if spec is None or spec.loader is None:
    raise RuntimeError("Cannot import CLEAN receipt verifier")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

EXACT_SHA = "1" * 40
STATE_SHA = "a" * 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_sidecar(path: Path) -> None:
    Path(f"{path}.sha256").write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="ascii",
        newline="\n",
    )


def valid_receipt(
    archive: Path,
    clean_script: Path,
    smoke_script: Path,
    origin: str = "manual-owner-native",
) -> dict[str, object]:
    return {
        "receipt_format_version": 2,
        "status": "PASS",
        "gate": "clean-windows-portable-gui",
        "evidence_path": "manual-or-self-hosted-clean-windows",
        "execution_origin": origin,
        "acceptance_label": verifier.EVIDENCE_LABELS[origin],
        "generated_utc": "2026-10-21T23:59:59.0000000Z",
        "exact_git_sha": EXACT_SHA,
        "archive": archive.name,
        "archive_sha256": sha256_file(archive),
        "verifier_script_sha256": sha256_file(clean_script),
        "smoke_script_sha256": sha256_file(smoke_script),
        "machine": {
            "computer_name": "OWNER-CLEAN-VM",
            "windows_caption": "Microsoft Windows 11 Pro",
            "windows_version": "10.0.26100",
            "windows_build": "26100",
            "os_architecture": "X64",
            "process_architecture": "X64",
            "powershell_version": "5.1.26100.1",
        },
        "user": {
            "name": r"OWNER-CLEAN-VM\\owner",
            "session_id": 2,
            "administrator_token_active": False,
            "interactive_explorer_session": True,
        },
        "development_environment": {
            "path_pattern": (
                "(?i)(msys|mingw|clang|llvm|qt[56]|cmake|openssl|vcpkg|"
                "windows kits|sdk)"
            ),
            "process_path_clean": True,
            "forbidden_directories": list(
                verifier.FORBIDDEN_DEVELOPMENT_DIRECTORIES
            ),
            "forbidden_directories_absent": True,
        },
        "observations": {
            "required_files": list(verifier.REQUIRED_PORTABLE_FILES),
            "expected_files_verified": True,
            "first_window_observed": True,
            "ordinary_close_observed": True,
            "relaunch_observed": True,
            "no_process_tcp_udp_before_start": True,
            "child_path_windows_system_only": True,
            "developer_environment_cleared": True,
            "system_state_before_sha256": STATE_SHA,
            "system_state_after_sha256": STATE_SHA,
            "system_state_unchanged": True,
        },
        "non_admin_interactive": True,
        "checks": sorted(verifier.REQUIRED_CHECKS),
    }


class ManualCleanWindowsReceiptVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.archive = self.root / "rdp-server-portable-gui.zip"
        self.archive.write_bytes(b"exact portable GUI archive bytes\n")
        write_sidecar(self.archive)

        self.clean_script = self.root / "clean_windows_portable_gui.ps1"
        self.clean_script.write_bytes(b"# exact CLEAN script\n")
        self.smoke_script = self.root / "smoke_windows_portable_gui.ps1"
        self.smoke_script.write_bytes(b"# exact smoke script\n")

        self.receipt = self.root / "clean-receipt.json"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_receipt(self, receipt: dict[str, object]) -> None:
        raw = (
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.receipt.write_bytes(raw)
        write_sidecar(self.receipt)

    def verify(self) -> tuple[str, str]:
        return verifier.verify_receipt(
            self.receipt,
            self.archive,
            EXACT_SHA,
            self.clean_script,
            self.smoke_script,
        )

    def test_valid_manual_receipt_is_labeled_manual(self) -> None:
        self.write_receipt(
            valid_receipt(self.archive, self.clean_script, self.smoke_script)
        )
        label, digest = self.verify()
        self.assertEqual(label, "MANUAL CLEAN PASS")
        self.assertEqual(digest, sha256_file(self.receipt))

    def test_self_hosted_receipt_is_not_labeled_manual(self) -> None:
        self.write_receipt(
            valid_receipt(
                self.archive,
                self.clean_script,
                self.smoke_script,
                "self-hosted-clean-runner",
            )
        )
        label, _ = self.verify()
        self.assertEqual(label, "SELF-HOSTED CLEAN PASS")
        self.assertNotEqual(label, "MANUAL CLEAN PASS")

    def test_tampered_receipt_hash_is_denied(self) -> None:
        self.write_receipt(
            valid_receipt(self.archive, self.clean_script, self.smoke_script)
        )
        self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_wrong_source_sha_is_denied(self) -> None:
        receipt = valid_receipt(
            self.archive, self.clean_script, self.smoke_script
        )
        receipt["exact_git_sha"] = "2" * 40
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_archive_mutation_is_denied(self) -> None:
        self.write_receipt(
            valid_receipt(self.archive, self.clean_script, self.smoke_script)
        )
        self.archive.write_bytes(b"modified archive")
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_clean_script_mutation_is_denied(self) -> None:
        self.write_receipt(
            valid_receipt(self.archive, self.clean_script, self.smoke_script)
        )
        self.clean_script.write_bytes(b"# changed CLEAN script\n")
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_smoke_script_mutation_is_denied(self) -> None:
        self.write_receipt(
            valid_receipt(self.archive, self.clean_script, self.smoke_script)
        )
        self.smoke_script.write_bytes(b"# changed smoke script\n")
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_missing_socket_check_is_denied(self) -> None:
        receipt = valid_receipt(
            self.archive, self.clean_script, self.smoke_script
        )
        receipt["checks"].remove("no-tcp-udp")
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_changed_system_state_hash_is_denied(self) -> None:
        receipt = valid_receipt(
            self.archive, self.clean_script, self.smoke_script
        )
        receipt["observations"]["system_state_after_sha256"] = "b" * 64
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_wrong_manual_label_is_denied(self) -> None:
        receipt = valid_receipt(
            self.archive, self.clean_script, self.smoke_script
        )
        receipt["acceptance_label"] = "AUTOMATED CI PASS"
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_non_x64_os_is_denied(self) -> None:
        receipt = valid_receipt(
            self.archive, self.clean_script, self.smoke_script
        )
        receipt["machine"]["os_architecture"] = "Arm64"
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()

    def test_duplicate_json_key_is_denied(self) -> None:
        receipt = valid_receipt(
            self.archive, self.clean_script, self.smoke_script
        )
        self.write_receipt(receipt)
        raw = self.receipt.read_text(encoding="utf-8").replace(
            f'"exact_git_sha": "{EXACT_SHA}",',
            f'"exact_git_sha": "{EXACT_SHA}",\n'
            f'  "exact_git_sha": "{EXACT_SHA}",',
            1,
        )
        self.receipt.write_text(raw, encoding="utf-8", newline="\n")
        write_sidecar(self.receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
