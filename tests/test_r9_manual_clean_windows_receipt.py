#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline denial tests for the R9 manual clean-Windows receipt verifier."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_clean_windows_receipt.py"
spec = importlib.util.spec_from_file_location("verify_clean_windows_receipt", VERIFIER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("Cannot import CLEAN receipt verifier")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
EXACT_SHA = "1" * 40


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_sidecar(path: Path, digest: str) -> None:
    Path(f"{path}.sha256").write_text(
        f"{digest}  {path.name}\n", encoding="ascii", newline="\n"
    )


def valid_receipt(archive: Path, origin: str = "manual-owner-native") -> dict[str, object]:
    return {
        "schema": "rdp-server-clean-windows-receipt-v1",
        "status": "PASS",
        "gate": "clean-windows-portable-gui",
        "evidence_origin": origin,
        "acceptance_label": verifier.EVIDENCE_LABELS[origin],
        "exact_git_sha": EXACT_SHA,
        "archive": archive.name,
        "archive_sha256": sha256_bytes(archive.read_bytes()),
        "machine": "OWNER-CLEAN-VM",
        "windows_version": "Microsoft Windows NT 10.0.26100.0",
        "os_architecture": "X64",
        "process_architecture": "X64",
        "session_id": 2,
        "non_admin_interactive": True,
        "explorer_session": True,
        "clean_path": {key: True for key in verifier.REQUIRED_CLEAN_PATH_CHECKS},
        "checks": {key: True for key in verifier.REQUIRED_ACCEPTANCE_CHECKS},
    }


class ManualCleanWindowsReceiptVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.archive = self.root / "rdp-server-portable-gui.zip"
        self.archive.write_bytes(b"exact portable GUI archive bytes\n")
        write_sidecar(self.archive, sha256_bytes(self.archive.read_bytes()))
        self.receipt = self.root / "clean-receipt.json"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_receipt(self, receipt: dict[str, object]) -> None:
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self.receipt.write_bytes(raw)
        write_sidecar(self.receipt, sha256_bytes(raw))

    def test_valid_manual_receipt_is_labeled_manual(self) -> None:
        self.write_receipt(valid_receipt(self.archive))
        label, digest = verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)
        self.assertEqual(label, "MANUAL CLEAN PASS")
        self.assertEqual(digest, sha256_bytes(self.receipt.read_bytes()))

    def test_self_hosted_receipt_is_not_labeled_manual(self) -> None:
        self.write_receipt(valid_receipt(self.archive, "self-hosted-clean-runner"))
        label, _ = verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)
        self.assertEqual(label, "SELF-HOSTED CLEAN PASS")
        self.assertNotEqual(label, "MANUAL CLEAN PASS")

    def test_tampered_receipt_hash_is_denied(self) -> None:
        self.write_receipt(valid_receipt(self.archive))
        self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
        with self.assertRaises(verifier.ReceiptVerificationError):
            verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)

    def test_wrong_source_sha_is_denied(self) -> None:
        receipt = valid_receipt(self.archive)
        receipt["exact_git_sha"] = "2" * 40
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)

    def test_archive_mutation_is_denied(self) -> None:
        self.write_receipt(valid_receipt(self.archive))
        self.archive.write_bytes(b"modified archive")
        with self.assertRaises(verifier.ReceiptVerificationError):
            verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)

    def test_failed_required_check_is_denied(self) -> None:
        receipt = valid_receipt(self.archive)
        receipt["checks"]["no_process_tcp_udp_before_start"] = False
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)

    def test_wrong_manual_label_is_denied(self) -> None:
        receipt = valid_receipt(self.archive)
        receipt["acceptance_label"] = "AUTOMATED CI PASS"
        self.write_receipt(receipt)
        with self.assertRaises(verifier.ReceiptVerificationError):
            verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)

    def test_duplicate_json_key_is_denied(self) -> None:
        receipt = valid_receipt(self.archive)
        self.write_receipt(receipt)
        raw = self.receipt.read_text(encoding="utf-8").replace(
            f'"exact_git_sha": "{EXACT_SHA}",',
            f'"exact_git_sha": "{EXACT_SHA}",\n  "exact_git_sha": "{EXACT_SHA}",',
            1,
        )
        self.receipt.write_text(raw, encoding="utf-8", newline="\n")
        write_sidecar(self.receipt, sha256_bytes(self.receipt.read_bytes()))
        with self.assertRaises(verifier.ReceiptVerificationError):
            verifier.verify_receipt(self.receipt, self.archive, EXACT_SHA)


if __name__ == "__main__":
    unittest.main()
