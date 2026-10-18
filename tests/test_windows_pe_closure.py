#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable unit tests for the R9 Windows PE dependency-closure verifier."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "verify_windows_pe_closure",
    ROOT / "scripts/verify_windows_pe_closure.py")
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class WindowsPeClosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="RDP Windows PE closure spaced path ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write_pe(self, name: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"MZ synthetic PE")

    def test_recursive_non_system_closure(self):
        for name in (
                "RDP-server-GUI.exe", "Qt6Widgets.dll", "Qt6Gui.dll",
                "Qt6Core.dll", "libc++.dll",
                "plugins/platforms/qwindows.dll"):
            self.write_pe(name)
        imports = {
            "rdp-server-gui.exe":
                ("KERNEL32.dll", "Qt6Widgets.dll", "libc++.dll"),
            "qt6widgets.dll": ("Qt6Gui.dll", "USER32.dll"),
            "qt6gui.dll": ("Qt6Core.dll", "api-ms-win-core-file-l1-2-0.dll"),
            "qwindows.dll": ("Qt6Gui.dll", "Qt6Core.dll"),
        }
        pe_count, import_count = module.verify_closure(
            self.root,
            lambda path: imports.get(path.name.casefold(), ()))
        self.assertEqual(pe_count, 6)
        self.assertEqual(import_count, 9)

    def test_missing_non_system_runtime_is_rejected(self):
        self.write_pe("RDP-server-GUI.exe")
        with self.assertRaisesRegex(
                module.WindowsPeClosureError, "libc[+][+]\\.dll"):
            module.verify_closure(
                self.root, lambda _path: ("KERNEL32.dll", "libc++.dll"))

    def test_system_and_api_set_imports_need_no_bundle_copy(self):
        self.write_pe("RDP-server-GUI.exe")
        self.assertEqual(
            module.verify_closure(
                self.root,
                lambda _path: (
                    "KERNEL32.dll", "AUTHZ.dll", "d3d9.dll",
                    "ncrypt.dll",
                    "api-ms-win-core-synch-l1-2-0.dll",
                    "ext-ms-win-ntuser-window-l1-1-0.dll")),
            (1, 6))

    def test_objdump_import_parser_is_bounded_to_dll_name_records(self):
        output = (
            "PE format\n"
            "    DLL Name: KERNEL32.dll\n"
            "\tDLL Name: Qt6Core.dll\n"
            "not a DLL record\n")
        self.assertEqual(
            module.parse_imports(output),
            ("KERNEL32.dll", "Qt6Core.dll"))


if __name__ == "__main__":
    unittest.main()
