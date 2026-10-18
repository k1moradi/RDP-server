#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""R7/R9 macOS .app portable GUI staging and integrity denials."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import plistlib
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


bundle = load("macos_gui_bundle", ROOT / "packaging/macos/gui_bundle.py")
portable = load("verify_portable_gui", ROOT / "scripts/verify_portable_gui.py")


class MacGuiBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="RDP macOS GUI Ω spaced path ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / bundle.APP_NAME
        executable = self.app / "Contents/MacOS/rdp-server-desktop"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"\xcf\xfa\xed\xfeGUI fixture")
        executable.chmod(0o755)
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "rdp-server-desktop",
            "CFBundleIdentifier": "org.rdp-server.desktop",
            "CFBundleName": "RDP Server",
            "CFBundlePackageType": "APPL",
        }))
        self.sha = "c" * 40
        self.version = "0.1.0"
        self.output = self.root / (
            f"rdp-server-portable-gui-{self.version}-macos-arm64-"
            f"{self.sha[:12]}.zip")

    @staticmethod
    def architectures(_path: Path) -> set[str]:
        return {"arm64"}

    def deploy(self, app: Path, staging: Path, _tool: Path):
        staged = staging / bundle.APP_NAME
        shutil.copytree(app, staged)
        plugin = staged / "Contents/PlugIns/platforms"
        plugin.mkdir(parents=True)
        (plugin / "libqcocoa.dylib").write_bytes(
            b"\xcf\xfa\xed\xfeQt Cocoa")
        for framework in ("QtCore.framework", "QtGui.framework",
                          "QtWidgets.framework"):
            binary = framework.removesuffix(".framework")
            target = (staged / "Contents/Frameworks" / framework /
                      "Versions/A" / binary)
            target.parent.mkdir(parents=True)
            target.write_bytes(b"\xcf\xfa\xed\xfe" + framework.encode())

    def build(self, deployer=None):
        return bundle.bundle(
            self.output, self.app, self.root / "macdeployqt",
            self.sha, self.version, "13.0",
            deployer=deployer or self.deploy,
            architecture_inspector=self.architectures)

    def test_real_app_shape_integrity_extract_and_remove(self):
        digest = self.build()
        manifest = portable.verify_archive(self.output, self.sha, digest)
        self.assertEqual(manifest["platform"], "macos")
        self.assertFalse(manifest["startup_enabled"])
        self.assertFalse(manifest["native_host_ready"])
        self.assertFalse(manifest["r2_macos_admission_included"])

        extracted = self.root / "Extracted RDP GUI Ω"
        extracted.mkdir()
        with zipfile.ZipFile(self.output) as archive:
            for member in archive.infolist():
                destination = extracted / member.filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
        self.assertTrue((extracted / bundle.EXECUTABLE).is_file())
        plist_path = extracted / bundle.INFO_PLIST
        self.assertEqual(
            plistlib.loads(plist_path.read_bytes())["CFBundleExecutable"],
            "rdp-server-desktop")
        self.assertTrue((extracted / bundle.QT_PLATFORM).is_file())
        self.assertFalse((extracted / "rdp-server").exists())
        config = json.loads(
            (extracted / "config/example.json").read_text("utf-8"))
        self.assertFalse(config["autostart"])
        self.assertFalse(config["listen"])
        signing = json.loads(
            (extracted / "metadata/SIGNING-TRUST.json").read_text("utf-8"))
        self.assertFalse(signing["signed"])
        self.assertFalse(signing["notarized"])
        self.assertTrue(signing["ad_hoc_signed"])
        shutil.rmtree(extracted)
        self.assertFalse(extracted.exists())
        self.assertTrue(self.app.is_dir())

    def test_missing_cocoa_plugin_is_rejected(self):
        def missing(app: Path, staging: Path, tool: Path):
            self.deploy(app, staging, tool)
            (staging / bundle.QT_PLATFORM).unlink()

        with self.assertRaisesRegex(
                bundle.MacGuiBundleError, "regular non-symlink"):
            self.build(missing)

    def test_unexpected_macos_helper_is_rejected(self):
        def helper(app: Path, staging: Path, tool: Path):
            self.deploy(app, staging, tool)
            path = staging / bundle.APP_NAME / "Contents/MacOS/helper"
            path.write_bytes(b"\xcf\xfa\xed\xfehelper")
            path.chmod(0o755)

        with self.assertRaisesRegex(
                bundle.MacGuiBundleError, "unexpected executable helper"):
            self.build(helper)

    def test_bad_plist_and_wrong_output_name_are_rejected(self):
        plist_path = self.app / "Contents/Info.plist"
        metadata = plistlib.loads(plist_path.read_bytes())
        metadata["CFBundleExecutable"] = "wrong"
        plist_path.write_bytes(plistlib.dumps(metadata))
        with self.assertRaisesRegex(
                bundle.MacGuiBundleError, "executable mismatch"):
            self.build()

        metadata["CFBundleExecutable"] = "rdp-server-desktop"
        plist_path.write_bytes(plistlib.dumps(metadata))
        wrong = self.root / "portable.zip"
        with self.assertRaisesRegex(
                bundle.MacGuiBundleError, "filename must bind exact SHA"):
            bundle.bundle(
                wrong, self.app, self.root / "macdeployqt",
                self.sha, self.version, "13.0",
                deployer=self.deploy,
                architecture_inspector=self.architectures)

    @unittest.skipIf(
        sys.platform == "win32",
        "Windows symlink creation is irrelevant to the macOS deployment tool")
    def test_macdeployqt_symlink_resolution_requires_executable_target(self):
        tool_directory = self.root / "Homebrew Cellar" / "qt" / "bin"
        tool_directory.mkdir(parents=True)
        target = tool_directory / "macdeployqt-real"
        target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        target.chmod(0o755)
        link = self.root / "Homebrew opt macdeployqt"
        link.symlink_to(target)

        self.assertEqual(
            bundle.resolve_macdeployqt(link),
            target.resolve(strict=True))

        target.chmod(0o644)
        with self.assertRaisesRegex(
                bundle.MacGuiBundleError, "target must be executable"):
            bundle.resolve_macdeployqt(link)

        broken = self.root / "broken-macdeployqt"
        broken.symlink_to(self.root / "missing-macdeployqt")
        with self.assertRaisesRegex(
                bundle.MacGuiBundleError, "path is unavailable"):
            bundle.resolve_macdeployqt(broken)

    @unittest.skipIf(
        sys.platform == "win32",
        "macOS deployment-tool execution is not meaningful on Windows")
    def test_macdeployqt_minimal_cocoa_deployment_command(self):
        prefix = self.root / "Homebrew opt qt"
        binary_dir = prefix / "bin"
        plugin_dir = prefix / "plugins/platforms"
        binary_dir.mkdir(parents=True)
        plugin_dir.mkdir(parents=True)

        qmake = binary_dir / "qmake"
        qmake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        qmake.chmod(0o755)
        tool = binary_dir / "macdeployqt"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tool.chmod(0o755)
        cocoa = plugin_dir / "libqcocoa.dylib"
        cocoa.write_bytes(b"\xcf\xfa\xed\xfeQt Cocoa source")

        calls = []
        class Result:
            stdout = ""

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            result = Result()
            if command[0] == str(qmake.resolve(strict=True)):
                result.stdout = str((prefix / "plugins").resolve(strict=True)) + "\n"
            elif command[:2] == ["otool", "-D"]:
                result.stdout = f"{command[2]}:\n"
                if command[2].endswith("libqcocoa.dylib"):
                    result.stdout += (
                        "/opt/homebrew/opt/qtbase/plugins/platforms/"
                        "libqcocoa.dylib\n")
            return result

        staging = self.root / "staging"
        staging.mkdir()
        bundle.deploy_with_macdeployqt(
            self.app, staging, tool, runner=runner)

        staged_plugin = staging / bundle.QT_PLATFORM
        self.assertTrue(staged_plugin.is_file())
        self.assertEqual(staged_plugin.read_bytes(), cocoa.read_bytes())
        commands = [call[0] for call in calls]
        self.assertEqual(
            commands[0],
            [str(qmake.resolve(strict=True)), "-query", "QT_INSTALL_PLUGINS"])
        deployment = commands[1]
        self.assertEqual(deployment[0], str(tool.resolve(strict=True)))
        self.assertIn("-no-plugins", deployment)
        self.assertIn("-no-codesign", deployment)
        self.assertIn(f"-executable={staged_plugin}", deployment)
        self.assertNotIn("-qmldir", " ".join(deployment))
        self.assertIn(
            ["install_name_tool", "-id", "@rpath/libqcocoa.dylib",
             str(staged_plugin.resolve(strict=True))],
            commands)
        self.assertEqual(
            commands[-1],
            ["codesign", "--force", "--deep", "--sign", "-",
             str((staging / bundle.APP_NAME))])

    def test_absolute_install_ids_normalized_before_adhoc_signing(self):
        staged = self.root / bundle.APP_NAME
        framework = (
            staged / "Contents/Frameworks/QtGui.framework/"
            "Versions/A/QtGui")
        framework.parent.mkdir(parents=True)
        framework.write_bytes(b"\xcf\xfa\xed\xfeQtGui")
        plugin = staged / "Contents/PlugIns/platforms/libqcocoa.dylib"
        plugin.parent.mkdir(parents=True)
        plugin.write_bytes(b"\xcf\xfa\xed\xfeCocoa")
        executable = staged / "Contents/MacOS/rdp-server-desktop"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"\xcf\xfa\xed\xfeGUI")
        (staged / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleExecutable": "rdp-server-desktop",
            "CFBundlePackageType": "APPL",
        }))

        calls = []
        class Result:
            stdout = ""

        def runner(command, **kwargs):
            calls.append(command)
            result = Result()
            if command[:2] == ["otool", "-D"]:
                result.stdout = f"{command[2]}:\n"
                # Native path separators vary on hosted Windows and macOS.
                if Path(command[2]).name == "QtGui":
                    result.stdout += (
                        "/opt/homebrew/opt/qtbase/lib/"
                        "QtGui.framework/Versions/A/QtGui\n")
                elif command[2].endswith("libqcocoa.dylib"):
                    result.stdout += (
                        "/opt/homebrew/opt/qtbase/plugins/platforms/"
                        "libqcocoa.dylib\n")
            return result

        bundle.normalize_macho_install_ids(staged, runner)
        bundle.adhoc_sign_app(staged, runner)

        self.assertIn(
            ["install_name_tool", "-id",
             "@rpath/QtGui.framework/Versions/A/QtGui",
             str(framework.resolve(strict=True))],
            calls)
        self.assertIn(
            ["install_name_tool", "-id", "@rpath/libqcocoa.dylib",
             str(plugin.resolve(strict=True))],
            calls)
        self.assertEqual(
            calls[-1],
            ["codesign", "--force", "--deep", "--sign", "-", str(staged)])

    def test_packager_has_no_host_activation_or_permission_mutator(self):
        source = (
            ROOT / "packaging/macos/gui_bundle.py"
        ).read_text(encoding="utf-8").casefold()
        for forbidden in (
                "launchctl load", "launchctl bootstrap", "tccutil reset",
                "osascript", "systemsetup", "networksetup", "sudo "):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
