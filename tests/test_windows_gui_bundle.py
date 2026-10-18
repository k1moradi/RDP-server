#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""R6/R9 Windows portable GUI staging and integrity denials."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
import sys

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bundle = load(
    "windows_gui_bundle", ROOT / "packaging/windows/gui_bundle.py")
portable = load(
    "verify_portable_gui", ROOT / "scripts/verify_portable_gui.py")


class WindowsGuiBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="RDP Windows GUI Ω spaced path ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.gui = self.root / bundle.GUI_NAME
        self.gui.write_bytes(b"MZ" + b"GUI fixture")
        self.sha = "b" * 40
        self.version = "0.1.0"
        self.output = self.root / (
            f"rdp-server-portable-gui-{self.version}-windows-x86_64-"
            f"{self.sha[:12]}.zip")

    def deploy(self, gui: Path, staging: Path, _tool: Path):
        shutil.copyfile(gui, staging / bundle.GUI_NAME)
        for name in ("Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll",
                     "vcruntime140.dll"):
            (staging / name).write_bytes(
                b"MZ" + name.encode("ascii"))
        plugin = staging / "plugins/platforms"
        plugin.mkdir(parents=True)
        (plugin / "qwindows.dll").write_bytes(b"MZ Qt platform")

    def build(self, deployer=None):
        return bundle.bundle(
            self.output, self.gui, self.root / "windeployqt.exe",
            self.sha, self.version, deployer=deployer or self.deploy)

    def test_unicode_space_path_integrity_extract_and_remove(self):
        digest = self.build()
        manifest = portable.verify_archive(
            self.output, self.sha, digest)
        self.assertEqual(
            manifest["runtime_integration"],
            "r10-production-host-control")
        self.assertFalse(manifest["startup_enabled"])
        self.assertFalse(manifest["native_host_ready"])
        self.assertFalse(manifest["r2_windows_admission_included"])
        checksum = self.output.with_suffix(".zip.sha256")
        self.assertTrue(checksum.is_file())
        self.assertIn(
            digest, checksum.read_text(encoding="ascii"))

        extracted = self.root / "Extracted GUI Ω Folder With Spaces"
        extracted.mkdir()
        with zipfile.ZipFile(self.output) as archive:
            for member in archive.infolist():
                destination = extracted / member.filename
                destination.parent.mkdir(
                    parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
        self.assertTrue(
            (extracted / bundle.GUI_NAME).is_file())
        self.assertTrue(
            (extracted / bundle.QT_PLATFORM).is_file())
        self.assertFalse(
            (extracted / "rdp-server.exe").exists())

        config = json.loads(
            (extracted / "config/example.json").read_text(
                encoding="utf-8"))
        self.assertFalse(config["autostart"])
        self.assertFalse(config["listen"])
        helpers = [
            path for path in extracted.rglob("*")
            if path.is_file() and path.suffix.lower() in
            (".bat", ".cmd", ".ps1", ".msi")
        ]
        self.assertEqual(helpers, [])

        shutil.rmtree(extracted)
        self.assertFalse(extracted.exists())
        self.assertTrue(self.gui.is_file())

    def test_missing_qwindows_is_rejected(self):
        def missing_plugin(gui: Path, staging: Path, tool: Path):
            self.deploy(gui, staging, tool)
            (staging / bundle.QT_PLATFORM).unlink()

        with self.assertRaisesRegex(
                bundle.WindowsGuiBundleError,
                "regular non-reparse"):
            self.build(missing_plugin)

    def test_unexpected_executable_helper_is_rejected(self):
        def helper(gui: Path, staging: Path, tool: Path):
            self.deploy(gui, staging, tool)
            (staging / "elevate.exe").write_bytes(b"MZ helper")

        with self.assertRaisesRegex(
                bundle.WindowsGuiBundleError,
                "unexpected executable helper"):
            self.build(helper)

    def test_case_alias_and_wrong_output_name_are_rejected(self):
        def alias(gui: Path, staging: Path, tool: Path):
            self.deploy(gui, staging, tool)
            (staging / "qt6core.DLL").write_bytes(b"MZ alias")

        with self.assertRaisesRegex(
                bundle.WindowsGuiBundleError,
                "case-colliding"):
            self.build(alias)

        wrong = self.root / "portable.zip"
        with self.assertRaisesRegex(
                bundle.WindowsGuiBundleError,
                "filename must bind exact SHA"):
            bundle.bundle(
                wrong, self.gui, self.root / "tool.exe",
                self.sha, self.version, deployer=self.deploy)

    def test_packager_contains_no_network_or_privilege_mutator(self):
        sources = (
            (ROOT / "packaging/windows/gui_bundle.py").read_text(
                encoding="utf-8")
            + (ROOT / "src/windows/windows_gui_main.cpp").read_text(
                encoding="utf-8")
            + (ROOT / "src/windows/windows_runtime_host_control_adapter.cpp")
              .read_text(encoding="utf-8")
        ).casefold()
        for forbidden in (
                "new-netfirewallrule", "netsh advfirewall",
                "shellexecuteex", "runas", "schtasks",
                "create service"):
            self.assertNotIn(forbidden, sources)


if __name__ == "__main__":
    unittest.main()
