# SPDX-License-Identifier: GPL-3.0-or-later
"""Dedicated offline macOS test-bundle denial and lifecycle checks."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

parser = argparse.ArgumentParser()
parser.add_argument("--script", type=Path, required=True)
args, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("macos_test_bundle", args.script)
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "test.zip"
        self.payload = b"offline-static-library"
        self.manifest = {
            "kind": bundle.BUNDLE_KIND, "version": "0.1.0",
            "source_sha": "a" * 40, "architecture": "arm64", "minimum_macos": "13.0",
            "runtime": "protocol only", "licenses": "GPL-3.0-or-later",
            "files": {"payload/lib/libexample.a": bundle.digest(self.payload)},
        }
        self.write_archive()

    def write_archive(self):
        with zipfile.ZipFile(self.archive, "w") as zipped:
            zipped.writestr("manifest.json", json.dumps(self.manifest))
            zipped.writestr("payload/lib/libexample.a", self.payload)

    def test_checksum_and_architecture_denials(self):
        with zipfile.ZipFile(self.archive) as zipped:
            self.assertEqual(bundle.validated_manifest(zipped)["architecture"], "arm64")
        self.manifest["files"]["payload/lib/libexample.a"] = "0" * 64
        self.write_archive()
        with zipfile.ZipFile(self.archive) as zipped:
            with self.assertRaisesRegex(ValueError, "checksum"):
                bundle.validated_manifest(zipped)
        self.manifest["files"]["payload/lib/libexample.a"] = bundle.digest(self.payload)
        self.manifest["architecture"] = "universal"
        self.write_archive()
        with zipfile.ZipFile(self.archive) as zipped:
            with self.assertRaisesRegex(ValueError, "unsupported bundle"):
                bundle.validated_manifest(zipped)

    def test_idempotent_install_remove_without_activation(self):
        options = argparse.Namespace(home=self.root, archive=self.archive)
        with patch.object(bundle.platform, "system", return_value="Darwin"), patch.object(
                bundle.platform, "machine", return_value="arm64"), patch.object(
                bundle.subprocess, "run", side_effect=AssertionError("process started")):
            bundle.install(options)
            bundle.install(options)
            self.assertTrue((self.root / bundle.INSTALL_SUBPATH / "manifest.json").is_file())
            bundle.remove(options)
            bundle.remove(options)
        self.assertFalse((self.root / bundle.INSTALL_SUBPATH).exists())

    def test_malformed_archive_denied_without_side_effects(self):
        options = argparse.Namespace(home=self.root, archive=self.archive)
        self.manifest["files"] = {"payload/../escape": bundle.digest(self.payload)}
        self.write_archive()
        with patch.object(bundle.platform, "system", return_value="Darwin"):
            with self.assertRaises(ValueError):
                bundle.install(options)
        self.assertFalse((self.root / bundle.INSTALL_SUBPATH).exists())

    def test_foreign_install_denied(self):
        options = argparse.Namespace(home=self.root, archive=self.archive)
        with patch.object(bundle.platform, "system", return_value="Darwin"), patch.object(
                bundle.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(ValueError, "mismatch"):
                bundle.install(options)
        self.assertFalse((self.root / bundle.INSTALL_SUBPATH).exists())


if __name__ == "__main__":
    unittest.main(argv=["bundle-tests", *remaining])
