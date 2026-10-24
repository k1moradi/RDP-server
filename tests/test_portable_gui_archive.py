#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Production verifier regression: exact source/outer hash and tamper denials."""
from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path
import tempfile
import unittest
import zipfile
import sys

script = Path(__file__).resolve().parents[1] / "scripts/verify_portable_gui.py"
spec = importlib.util.spec_from_file_location("verify_portable_gui", script)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class PortableGuiArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="portable gui spaced path ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source_sha = "a" * 40
        self.payload = {
            "VERSION": b"0.1.0\n", "LICENSE": b"license", "NOTICE": b"notice",
            "THIRD_PARTY.md": b"attribution",
            "config/example.json": b'{"autostart":false,"listen":false}',
            "metadata/DEPENDENCIES.txt": b"Qt6 dependency closure receipt",
            "metadata/PLATFORM-MINIMUMS.json": b'{"glibc":"2.35","graphics_libraries":["X11"],"launch_permissions":"user"}',
            "bin/rdp-server-desktop": b"\x7fELFmock GUI executable",
            "run-gui.sh": b"#!/bin/sh\nexit 0\n",
            "RDP Server.desktop": b"[Desktop Entry]",
            "plugins/platforms/libqxcb.so": b"mock Qt platform plugin",
        }

    def archive(self, *, platform="linux", runtime="r10-production-host-control",
                modifications=None, symlink_targets=None):
        payload = dict(self.payload)
        if platform == "windows":
            for name in module.PLATFORM_FILES[("linux", "x86_64")]:
                payload.pop(name, None)
            payload["RDP-server-GUI.exe"] = b"MZ GUI"
            payload["plugins/platforms/qwindows.dll"] = b"MZ Qt"
        if platform == "macos":
            for name in module.PLATFORM_FILES[("linux", "x86_64")]:
                payload.pop(name, None)
            payload.update({
                "rdp-server-desktop.app/Contents/MacOS/rdp-server-desktop": b"MachO",
                "rdp-server-desktop.app/Contents/Info.plist": b"plist",
                "rdp-server-desktop.app/Contents/PlugIns/platforms/libqcocoa.dylib": b"Qt",
                "metadata/SIGNING-TRUST.json": b'{"signed":false,"notarized":false,"trust":"unsigned test"}',
            })
        if modifications:
            payload.update(modifications)
        if symlink_targets:
            payload.update({name: target.encode("utf-8")
                            for name, target in symlink_targets.items()})
        import hashlib
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()}
        architecture = "arm64" if platform == "macos" else "x86_64"
        manifest = {
            "artifact_family": "PORTABLE-GUI", "classification": "portable-gui-host",
            "version": "0.1.0", "platform": platform, "architecture": architecture,
            "exact_git_sha": self.source_sha, "runtime_integration": runtime,
            "startup_enabled": False, "mutable_state_location": "user-private-os-location",
            "canonical_startup_arguments": [],
            "configuration_required": False,
            "session_password_storage": "memory-only",
            "automatic_listener_start": False,
            "read_only_extraction_supported": True,
            "files": hashes,
        }
        payload[module.MANIFEST] = json.dumps(manifest, sort_keys=True).encode()
        hashes[module.MANIFEST] = hashlib.sha256(payload[module.MANIFEST]).hexdigest()
        payload[module.CHECKSUMS] = ("\n".join(f"{value}  {name}" for name, value in sorted(hashes.items())) + "\n").encode()
        path = self.root / (f"rdp-server-portable-gui-0.1.0-{platform}-{architecture}-{self.source_sha[:12]}.zip")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in payload.items():
                if symlink_targets and name in symlink_targets:
                    link = zipfile.ZipInfo(name)
                    link.create_system = 3
                    link.external_attr = ((stat.S_IFLNK | 0o777) << 16)
                    archive.writestr(link, data)
                else:
                    archive.writestr(name, data)
        return path, module.digest_file(path)

    def test_three_platform_archive_contracts(self):
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                archive, digest = self.archive(platform=platform)
                result = module.verify_archive(archive, self.source_sha, digest)
                self.assertEqual(result["platform"], platform)

    def test_macos_framework_links_are_bounded_and_resolved(self):
        prefix = "rdp-server-desktop.app/Contents/Frameworks/QtCore.framework/"
        files = {
            prefix + "Versions/A/QtCore": b"QtCore",
            prefix + "Versions/A/Resources/Info.plist": b"framework plist",
        }
        links = {
            prefix + "Versions/Current": "A",
            prefix + "QtCore": "Versions/Current/QtCore",
            prefix + "Resources": "Versions/Current/Resources",
        }
        archive, digest = self.archive(
            platform="macos", modifications=files, symlink_targets=links)
        self.assertEqual(
            module.verify_archive(archive, self.source_sha, digest)["platform"],
            "macos")

        attempts = (
            {prefix + "QtCore": "../../escape"},
            {prefix + "Versions/Current": "Missing"},
            {prefix + "Versions/Current": "Current"},
            {"rdp-server-desktop.app/Contents/MacOS/unsafe": "rdp-server-desktop"},
            {"plugins/platforms/libqxcb.so": "another-plugin"},
        )
        for bad in attempts:
            with self.subTest(bad=bad):
                archive, digest = self.archive(
                    platform="macos", modifications=files, symlink_targets=bad)
                with self.assertRaisesRegex(
                        module.PortableGuiError,
                        "unsafe framework|unresolved|cyclic|directory or link"):
                    module.verify_archive(archive, self.source_sha, digest)

        colliding = dict(files)
        colliding[prefix + "Versions/Current/Injected"] = b"alias collision"
        archive, digest = self.archive(
            platform="macos", modifications=colliding, symlink_targets=links)
        with self.assertRaisesRegex(module.PortableGuiError,
                                    "entry under framework link"):
            module.verify_archive(archive, self.source_sha, digest)

        archive, digest = self.archive(
            platform="linux",
            symlink_targets={"plugins/platforms/unsafe-link": "libqxcb.so"})
        with self.assertRaisesRegex(module.PortableGuiError, "directory or link"):
            module.verify_archive(archive, self.source_sha, digest)

    def test_missing_production_control_rejected(self):
        archive, digest = self.archive(runtime="unavailable-host-control")
        with self.assertRaisesRegex(module.PortableGuiError, "GUI shell"):
            module.verify_archive(archive, self.source_sha, digest)

    def test_modified_zip_even_with_manifest_is_rejected_by_external_sha(self):
        archive, digest = self.archive()
        with zipfile.ZipFile(archive, "a") as file:
            file.writestr("config/tampered.txt", b"malicious")
        with self.assertRaisesRegex(module.PortableGuiError, "outer archive"):
            module.verify_archive(archive, self.source_sha, digest)

    def test_wrong_checkout_sha_or_unsafe_path_rejected(self):
        archive, digest = self.archive()
        with self.assertRaisesRegex(module.PortableGuiError, "manifest source SHA"):
            module.verify_archive(archive, "b" * 40, digest)
        archive, digest = self.archive(modifications={"../escape": b"bad"})
        with self.assertRaisesRegex(module.PortableGuiError, "unsafe archive path"):
            module.verify_archive(archive, self.source_sha, digest)

    def test_missing_plugin_and_unconfigured_start_rejected(self):
        archive, digest = self.archive(modifications={"config/example.json": b'{"autostart":true,"listen":true}'})
        with self.assertRaisesRegex(module.PortableGuiError, "example config"):
            module.verify_archive(archive, self.source_sha, digest)
        self.payload.pop("plugins/platforms/libqxcb.so")
        archive, digest = self.archive()
        with self.assertRaisesRegex(module.PortableGuiError, "Qt platform plugin"):
            module.verify_archive(archive, self.source_sha, digest)


if __name__ == "__main__":
    unittest.main()
