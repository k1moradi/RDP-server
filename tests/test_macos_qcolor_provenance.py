#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline R7 QColorSpace provenance parser/redaction regressions."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/diagnose_macos_qcolor_provenance.py"


def load_probe():
    spec = importlib.util.spec_from_file_location("macos_qcolor_probe", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load provenance probe")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load_probe()


class MacQColorProvenanceTests(unittest.TestCase):
    def test_icc_profile_class_is_bounded_and_closed(self):
        header = bytearray(128)
        header[0:4] = (128).to_bytes(4, byteorder="big")
        header[12:16] = b"mntr"
        self.assertEqual(probe.profile_class_signature(bytes(header)), "mntr")

        header[12:16] = b"evil"
        self.assertEqual(probe.profile_class_signature(bytes(header)), "unknown")
        self.assertEqual(
            probe.profile_class_signature(bytes(header[:64])), "unavailable")

        header[0:4] = (4096).to_bytes(4, byteorder="big")
        self.assertEqual(
            probe.profile_class_signature(bytes(header), 128), "invalid")

    def test_qt_warning_summary_drops_paths_and_chromaticity_values(self):
        raw = (
            'qt.core.plugin: loaded library '
            '"/Users/private-owner/Library/RDP/libqcocoa.dylib"\n'
            "RDP_QCOLOR|warning|qt.gui.icc|"
            "/private/tmp/qt/src/gui/painting/qcolorspace.cpp|765|"
            "QColorSpace attempted constructed from invalid primaries "
            "QPointF(0.1,0.2) QPointF(0.3,0.4)\n"
        )
        result = probe.parse_qt_diagnostics(raw)
        self.assertEqual(result["platform_plugin_observed"], "yes")
        self.assertEqual(result["warning"], "REPRODUCED")
        self.assertEqual(result["warning_source"], "qcolorspace.cpp")
        self.assertEqual(result["warning_line"], "765")
        self.assertEqual(result["warning_category"], "qt.gui.icc")

        result.update({
            "server_sha": "a" * 40,
            "qt_core_version": "6.12.0",
            "qt_gui_version": "6.12.0",
            "display_color_model": "rgb",
            "display_profile_class": "mntr",
            "stderr_capture_truncated": "no",
        })
        import contextlib
        import io
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            probe.print_summary(result)
        summary = output.getvalue()
        self.assertNotIn("/Users/", summary)
        self.assertNotIn("/private/", summary)
        self.assertNotIn("QPointF", summary)
        self.assertNotIn("0.1", summary)
        self.assertIn("warning-source=qcolorspace.cpp:765", summary)
        self.assertIn("warning-caller=UNATTRIBUTED", summary)

    def test_diagnostic_environment_removes_external_qt_and_dyld_overrides(self):
        environment = probe.diagnostic_environment({
            "HOME": "/Users/private-owner",
            "QT_QPA_PLATFORM": "offscreen",
            "QT_PLUGIN_PATH": "/Users/private-owner/plugins",
            "QT_QPA_PLATFORM_PLUGIN_PATH": "/Users/private-owner/platforms",
            "QT_LOGGING_RULES": "*.warning=false",
            "QT_FATAL_WARNINGS": "1",
            "DYLD_LIBRARY_PATH": "/Users/private-owner/lib",
            "DYLD_FRAMEWORK_PATH": "/Users/private-owner/frameworks",
            "DYLD_INSERT_LIBRARIES": "/Users/private-owner/inject.dylib",
        })
        self.assertEqual(environment["HOME"], "/Users/private-owner")
        for name in probe.ENVIRONMENT_OVERRIDES:
            if name == "QT_MESSAGE_PATTERN":
                continue
            self.assertNotIn(name, environment)
        self.assertEqual(environment["QT_DEBUG_PLUGINS"], "1")
        self.assertEqual(
            environment["QT_MESSAGE_PATTERN"], probe.MESSAGE_PATTERN)

    def test_framework_version_and_manifest_sha_have_no_path_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / probe.APP_NAME
            info = (
                app / "Contents/Frameworks/QtCore.framework/"
                "Versions/A/Resources/Info.plist"
            )
            info.parent.mkdir(parents=True)
            info.write_bytes(plistlib.dumps({
                "CFBundleShortVersionString": "6.12.0"}))
            self.assertEqual(
                probe._framework_version(app, "QtCore"), "6.12.0")
            self.assertEqual(
                probe._framework_version(app, "QtGui"), "unavailable")
            self.assertEqual(probe._manifest_sha(app), "unavailable")


if __name__ == "__main__":
    unittest.main()
