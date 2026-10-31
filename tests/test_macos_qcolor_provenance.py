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
        header[36:40] = b"acsp"
        self.assertEqual(probe.profile_class_signature(bytes(header)), "mntr")
        self.assertEqual(probe.inspect_profile_header(bytes(header)),
                         ("mntr", "recognized-header"))

        header[12:16] = b"evil"
        self.assertEqual(probe.profile_class_signature(bytes(header)), "unknown")
        self.assertEqual(probe.inspect_profile_header(bytes(header)),
                         ("unknown", "unknown-class"))
        self.assertEqual(
            probe.profile_class_signature(bytes(header[:64])), "unavailable")
        self.assertEqual(probe.inspect_profile_header(bytes(header[:64])),
                         ("unavailable", "truncated-header"))

        header[0:4] = (4096).to_bytes(4, byteorder="big")
        self.assertEqual(
            probe.profile_class_signature(bytes(header), 128), "invalid")
        self.assertEqual(probe.inspect_profile_header(bytes(header), 128),
                         ("invalid", "truncated-profile"))

        # Reject malformed ICC magic, undersized and oversized profiles,
        # and a header claiming more bytes than the caller actually has.
        header[0:4] = (128).to_bytes(4, byteorder="big")
        header[36:40] = b"NOPE"
        self.assertEqual(probe.profile_class_signature(bytes(header)), "invalid")
        self.assertEqual(probe.inspect_profile_header(bytes(header)),
                         ("invalid", "invalid-signature"))
        header[36:40] = b"acsp"
        header[0:4] = (127).to_bytes(4, byteorder="big")
        self.assertEqual(probe.profile_class_signature(bytes(header)), "invalid")
        self.assertEqual(probe.inspect_profile_header(bytes(header)),
                         ("invalid", "invalid-length"))
        header[0:4] = (probe.MAX_ICC_PROFILE_BYTES + 1).to_bytes(
            4, byteorder="big")
        self.assertEqual(probe.profile_class_signature(bytes(header)), "invalid")
        header[0:4] = (128).to_bytes(4, byteorder="big")
        self.assertEqual(probe.profile_class_signature(bytes(header), 127), "invalid")

    def test_active_display_enumeration_is_bounded_and_fail_closed(self):
        class FakeCoreGraphics:
            def __init__(
                self, display_ids=(), first_error=0, second_error=0,
                second_count=None
            ):
                self.display_ids = tuple(display_ids)
                self.first_error = first_error
                self.second_error = second_error
                self.second_count = second_count

            def CGGetActiveDisplayList(
                self, maximum, display_ids, display_count
            ):
                if display_ids is None:
                    display_count._obj.value = len(self.display_ids)
                    return self.first_error
                returned = (
                    len(self.display_ids)
                    if self.second_count is None else self.second_count
                )
                display_count._obj.value = returned
                for index, display_id in enumerate(
                    self.display_ids[:min(maximum, returned)]
                ):
                    display_ids[index] = display_id
                return self.second_error

        self.assertEqual(
            probe._enumerate_active_display_ids(FakeCoreGraphics((7, 9))),
            ("observed", 2, (7, 9)))
        self.assertEqual(
            probe._enumerate_active_display_ids(
                FakeCoreGraphics(first_error=1)),
            ("enumeration-unavailable", 0, ()))
        self.assertEqual(
            probe._enumerate_active_display_ids(
                FakeCoreGraphics((7, 9), second_error=1)),
            ("enumeration-unavailable", 0, ()))
        self.assertEqual(
            probe._enumerate_active_display_ids(FakeCoreGraphics(())),
            ("no-active-displays", 0, ()))

        too_many = tuple(range(probe.MAX_ACTIVE_DISPLAYS + 1))
        status, count, display_ids = probe._enumerate_active_display_ids(
            FakeCoreGraphics(too_many))
        self.assertEqual(status, "display-limit-exceeded")
        self.assertEqual(count, len(too_many))
        self.assertEqual(display_ids, ())

        self.assertEqual(
            probe._enumerate_active_display_ids(
                FakeCoreGraphics((7, 9), second_count=1)),
            ("display-set-changed", 2, ()))

    def test_active_display_profile_summary_distinguishes_malformed_metadata(self):
        statuses = (
            "recognized-header",
            "invalid-signature",
            "truncated-profile",
            "profile-unavailable",
        )
        self.assertEqual(
            probe.format_profile_header_status_counts(statuses),
            "invalid-signature:1,truncated-profile:1,"
            "profile-unavailable:1,recognized-header:1")
        self.assertEqual(
            probe.classify_active_display_profile_evidence(statuses),
            "malformed-active-profile-observed")
        self.assertEqual(
            probe.classify_active_display_profile_evidence(
                ("recognized-header", "unknown-class")),
            "plausible-headers-only")
        self.assertEqual(
            probe.classify_active_display_profile_evidence(
                ("recognized-header", "profile-unavailable")),
            "incomplete-profile-metadata")
        self.assertEqual(
            probe.classify_active_display_profile_evidence(
                ("profile-unavailable",)),
            "profile-metadata-unavailable")
        self.assertEqual(
            probe.format_profile_header_status_counts(("unexpected",)),
            "unavailable")

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
        self.assertEqual(result["warning_emitter"], "qt-qcolorspace-reported")
        self.assertEqual(result["cocoa_load_before_warning"], "observed")

        result.update({
            "server_sha": "a" * 40,
            "qt_core_version": "6.12.0",
            "qt_gui_version": "6.12.0",
            "display_color_model": "rgb",
            "display_profile_class": "mntr",
            "display_profile_header_status": "recognized-header",
            "active_display_enumeration": "observed",
            "active_display_count": "2",
            "active_display_profile_headers":
                "invalid-signature:1,recognized-header:1",
            "active_display_profile_evidence":
                "malformed-active-profile-observed",
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
        self.assertIn("warning-emitter=qt-qcolorspace-reported", summary)
        self.assertIn("cocoa-load-before-warning=observed", summary)
        self.assertIn("display-profile-header-status=recognized-header", summary)
        self.assertIn("active-display-enumeration=observed", summary)
        self.assertIn("active-display-count=2", summary)
        self.assertIn(
            "active-display-profile-headers="
            "invalid-signature:1,recognized-header:1", summary)
        self.assertIn(
            "coregraphics-profile-evidence=malformed-active-profile-observed",
            summary)
        self.assertIn("first-party-qcolorspace-caller=STACK_REQUIRED", summary)
        self.assertIn("qt-cocoa-caller=STACK_REQUIRED", summary)
        self.assertIn("colorsync-caller=STACK_REQUIRED", summary)

    def test_failed_cocoa_plugin_lookup_is_not_loaded_provenance(self):
        diagnostics = (
            'qt.core.plugin: Cannot load library '
            '"/Users/private-owner/libqcocoa.dylib"\n'
            'qt.core.plugin: checking directory "/Users/private-owner/platforms"\n'
        )
        self.assertEqual(
            probe.parse_qt_diagnostics(diagnostics)["platform_plugin_observed"],
            "no")

    def test_warning_before_cocoa_load_does_not_assign_platform_caller(self):
        diagnostics = (
            "RDP_QCOLOR|warning|qt.gui|/private/qt/qcolorspace.cpp|15|"
            "QColorSpace attempted constructed from invalid primaries\n"
            'qt.core.plugin: loaded library "/private/libqcocoa.dylib"\n'
        )
        result = probe.parse_qt_diagnostics(diagnostics)
        self.assertEqual(result["platform_plugin_observed"], "yes")
        self.assertEqual(result["cocoa_load_before_warning"], "not-observed")
        self.assertEqual(result["warning_emitter"], "qt-qcolorspace-reported")

    def test_lookalike_structured_prefix_does_not_claim_emitter_metadata(self):
        diagnostic = (
            "NOT_RDP_QCOLOR|warning|qt.gui.icc|"
            "/private/qt/qcolorspace.cpp|765|"
            "QColorSpace attempted constructed from invalid primaries\n"
        )
        result = probe.parse_qt_diagnostics(diagnostic)
        self.assertEqual(result["warning"], "REPRODUCED")
        self.assertEqual(result["warning_source"], "unavailable")
        self.assertEqual(result["warning_line"], "unavailable")
        self.assertEqual(result["warning_category"], "unavailable")
        self.assertEqual(result["warning_emitter"], "unavailable")

    def test_windows_path_and_oversized_warning_line_are_redacted(self):
        diagnostic = (
            'RDP_QCOLOR|warning|qt.gui.icc|'
            r'C:\Users\private-owner\qcolorspace.cpp'
            '|12345678901234567890|'
            'QColorSpace attempted constructed from invalid primaries\n'
        )
        result = probe.parse_qt_diagnostics(diagnostic)
        self.assertEqual(result["warning"], "REPRODUCED")
        self.assertEqual(result["warning_source"], "qcolorspace.cpp")
        self.assertEqual(result["warning_line"], "unavailable")
        self.assertNotIn("private-owner", str(result))
        self.assertNotIn("12345678901234567890", str(result))

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

    def test_failure_summary_never_stringifies_private_exception_paths(self):
        private_error = FileNotFoundError(
            2, "No such file or directory",
            "/Users/private-owner/RDP/rdp-server-desktop")
        self.assertEqual(
            probe.safe_failure_reason(private_error),
            "runtime probe operation failed")
        self.assertNotIn(
            "/Users/private-owner",
            probe.safe_failure_reason(private_error))
        self.assertEqual(
            probe.safe_failure_reason(probe.ProbeError("app path is unavailable")),
            "app path is unavailable")

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
