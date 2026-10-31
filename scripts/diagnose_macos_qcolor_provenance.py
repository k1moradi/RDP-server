#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""R7 opt-in macOS QColorSpace provenance probe for a Sharing-OFF GUI launch.

The probe launches only the extracted zero-argument desktop executable, records
bounded Qt/Cocoa color-profile provenance, verifies that the process opens no
TCP listener, and then terminates it. It never clicks Sharing, requests TCC,
captures pixels, injects input, or prints ICC payloads or private host paths.
"""
from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import threading
import time

APP_NAME = "rdp-server-desktop.app"
EXECUTABLE_NAME = "rdp-server-desktop"
WARNING_SIGNATURE = "QColorSpace attempted constructed from invalid primaries"
MESSAGE_PREFIX = "RDP_QCOLOR"
MESSAGE_PATTERN = (
    "RDP_QCOLOR|%{type}|%{category}|%{file}|%{line}|%{message}"
)
MAX_DIAGNOSTIC_BYTES = 256 * 1024
MAX_PROFILE_HEADER_BYTES = 128
MAX_ICC_PROFILE_BYTES = 64 * 1024 * 1024
KNOWN_PROFILE_CLASSES = {
    b"scnr": "scnr",
    b"mntr": "mntr",
    b"prtr": "prtr",
    b"link": "link",
    b"spac": "spac",
    b"abst": "abst",
    b"nmcl": "nmcl",
}
COLOR_MODELS = {
    -1: "unknown",
    0: "monochrome",
    1: "rgb",
    2: "cmyk",
    3: "lab",
    4: "device-n",
    5: "indexed",
    6: "pattern",
    7: "xyz",
}
ENVIRONMENT_OVERRIDES = (
    "QT_QPA_PLATFORM",
    "QT_PLUGIN_PATH",
    "QT_QPA_PLATFORM_PLUGIN_PATH",
    "QT_MESSAGE_PATTERN",
    "QT_LOGGING_RULES",
    "QT_FATAL_WARNINGS",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_INSERT_LIBRARIES",
)


class ProbeError(ValueError):
    pass


class BoundedPipeCapture:
    """Drain a child pipe while retaining only a fixed-size prefix."""

    def __init__(self, limit: int = MAX_DIAGNOSTIC_BYTES) -> None:
        self._limit = limit
        self._buffer = bytearray()
        self.truncated = False

    def drain(self, pipe) -> None:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                return
            remaining = self._limit - len(self._buffer)
            if remaining > 0:
                self._buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.truncated = True

    def text(self) -> str:
        return self._buffer.decode("utf-8", errors="replace")


def _safe_token(value: str, maximum: int = 80) -> str:
    value = value.strip()
    if not value:
        return "unavailable"
    safe = "".join(
        character if character.isalnum() or character in "._-+" else "_"
        for character in value[:maximum]
    )
    return safe or "unavailable"


def _framework_version(app: Path, framework: str) -> str:
    info = (
        app / "Contents/Frameworks" / f"{framework}.framework" /
        "Versions/A/Resources/Info.plist"
    )
    try:
        metadata = plistlib.loads(info.read_bytes())
    except (OSError, plistlib.InvalidFileException, TypeError, ValueError):
        return "unavailable"
    version = metadata.get("CFBundleShortVersionString")
    if not isinstance(version, str):
        version = metadata.get("CFBundleVersion")
    return _safe_token(version) if isinstance(version, str) else "unavailable"


def _manifest_sha(app: Path) -> str:
    manifest = app.parent / "metadata/PORTABLE-GUI-MANIFEST.json"
    try:
        import json
        metadata = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return "unavailable"
    value = metadata.get("exact_git_sha")
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value):
        return value
    return "unavailable"


def profile_class_signature(header: bytes, total_length: int | None = None) -> str:
    """Return only the ICC device-class signature from a bounded header."""
    if len(header) < MAX_PROFILE_HEADER_BYTES:
        return "unavailable"
    declared_size = int.from_bytes(header[0:4], byteorder="big", signed=False)
    available = len(header) if total_length is None else total_length
    if (
        declared_size < MAX_PROFILE_HEADER_BYTES or
        declared_size > available or
        declared_size > MAX_ICC_PROFILE_BYTES
    ):
        return "invalid"
    return KNOWN_PROFILE_CLASSES.get(header[12:16], "unknown")


def query_display_profile_class() -> tuple[str, str]:
    """Read only the main display's color model and ICC header class."""
    if sys.platform != "darwin":
        return ("unavailable", "unavailable")

    try:
        core_graphics = ctypes.CDLL(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")

        core_graphics.CGMainDisplayID.restype = ctypes.c_uint32
        core_graphics.CGDisplayCopyColorSpace.argtypes = [ctypes.c_uint32]
        core_graphics.CGDisplayCopyColorSpace.restype = ctypes.c_void_p
        core_graphics.CGColorSpaceGetModel.argtypes = [ctypes.c_void_p]
        core_graphics.CGColorSpaceGetModel.restype = ctypes.c_int32
        core_graphics.CGColorSpaceCopyICCData.argtypes = [ctypes.c_void_p]
        core_graphics.CGColorSpaceCopyICCData.restype = ctypes.c_void_p
        core_graphics.CGColorSpaceRelease.argtypes = [ctypes.c_void_p]
        core_graphics.CGColorSpaceRelease.restype = None

        core_foundation.CFDataGetLength.argtypes = [ctypes.c_void_p]
        core_foundation.CFDataGetLength.restype = ctypes.c_long
        core_foundation.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        core_foundation.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_uint8)
        core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        core_foundation.CFRelease.restype = None

        display_id = core_graphics.CGMainDisplayID()
        color_space = core_graphics.CGDisplayCopyColorSpace(display_id)
        if not color_space:
            return ("unavailable", "unavailable")
        try:
            model = COLOR_MODELS.get(
                int(core_graphics.CGColorSpaceGetModel(color_space)), "unknown")
            profile_data = core_graphics.CGColorSpaceCopyICCData(color_space)
            if not profile_data:
                return (model, "unavailable")
            try:
                length = int(core_foundation.CFDataGetLength(profile_data))
                if (
                    length < MAX_PROFILE_HEADER_BYTES or
                    length > MAX_ICC_PROFILE_BYTES
                ):
                    return (model, "invalid")
                pointer = core_foundation.CFDataGetBytePtr(profile_data)
                if not pointer:
                    return (model, "unavailable")
                header = ctypes.string_at(pointer, MAX_PROFILE_HEADER_BYTES)
                return (model, profile_class_signature(header, length))
            finally:
                core_foundation.CFRelease(profile_data)
        finally:
            core_graphics.CGColorSpaceRelease(color_space)
    except (AttributeError, OSError, TypeError, ValueError):
        return ("unavailable", "unavailable")


def diagnostic_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for name in ENVIRONMENT_OVERRIDES:
        environment.pop(name, None)
    environment["QT_DEBUG_PLUGINS"] = "1"
    environment["QT_MESSAGE_PATTERN"] = MESSAGE_PATTERN
    return environment


def parse_qt_diagnostics(text: str) -> dict[str, str]:
    """Reduce private Qt output to a bounded non-path provenance summary."""
    result = {
        "warning": "NOT_REPRODUCED",
        "warning_source": "unavailable",
        "warning_line": "unavailable",
        "warning_category": "unavailable",
        "platform_plugin_observed": "no",
    }
    for line in text.splitlines():
        if "libqcocoa.dylib" in line:
            result["platform_plugin_observed"] = "yes"
        if WARNING_SIGNATURE not in line or result["warning"] == "REPRODUCED":
            continue

        result["warning"] = "REPRODUCED"
        fields = line.split("|", 5)
        if len(fields) == 6 and fields[0].strip().endswith(MESSAGE_PREFIX):
            result["warning_category"] = _safe_token(fields[2])
            source = fields[3].strip()
            if source:
                result["warning_source"] = _safe_token(Path(source).name)
            line_number = fields[4].strip()
            if line_number.isdigit():
                result["warning_line"] = line_number
    return result


def _validate_app(app: Path) -> Path:
    try:
        resolved = app.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ProbeError("app path is unavailable") from error
    executable = resolved / "Contents/MacOS" / EXECUTABLE_NAME
    plugin = resolved / "Contents/PlugIns/platforms/libqcocoa.dylib"
    if resolved.name != APP_NAME:
        raise ProbeError("expected extracted rdp-server-desktop.app")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ProbeError("expected executable in extracted app")
    if not plugin.is_file():
        raise ProbeError("bundled Cocoa Qt platform plugin is missing")
    return resolved


def _no_tcp_listener(pid: int) -> bool:
    result = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid),
         "-iTCP", "-sTCP:LISTEN"],
        capture_output=True, text=True, timeout=10)
    return (
        result.returncode == 1 and
        not result.stdout.strip() and
        not result.stderr.strip()
    )


def run_probe(app: Path, duration_seconds: float) -> dict[str, str]:
    app = _validate_app(app)
    executable = app / "Contents/MacOS" / EXECUTABLE_NAME
    model, profile_class = query_display_profile_class()

    process = subprocess.Popen(
        [str(executable)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=diagnostic_environment(),
        text=False)
    if process.stderr is None:
        process.kill()
        process.wait(timeout=5)
        raise ProbeError("failed to capture bounded Qt diagnostics")

    capture = BoundedPipeCapture()
    reader = threading.Thread(
        target=capture.drain, args=(process.stderr,), daemon=True)
    reader.start()

    deadline = time.monotonic() + duration_seconds
    try:
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is not None:
            raise ProbeError("zero-argument GUI exited before provenance window")
        if not _no_tcp_listener(process.pid):
            raise ProbeError("Sharing-OFF GUI opened a TCP listener or audit failed")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        reader.join(timeout=2)
        if reader.is_alive():
            process.stderr.close()
            reader.join(timeout=1)
            raise ProbeError("bounded Qt diagnostics did not drain")
        process.stderr.close()

    diagnostics = parse_qt_diagnostics(capture.text())
    diagnostics.update({
        "server_sha": _manifest_sha(app),
        "qt_core_version": _framework_version(app, "QtCore"),
        "qt_gui_version": _framework_version(app, "QtGui"),
        "display_color_model": model,
        "display_profile_class": profile_class,
        "stderr_capture_truncated": "yes" if capture.truncated else "no",
    })
    return diagnostics


def safe_failure_reason(error: BaseException) -> str:
    """Return only controlled diagnostic text; never stringify path-bearing errors."""
    if isinstance(error, ProbeError):
        return str(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return "bounded subprocess timeout"
    return "runtime probe operation failed"


def print_summary(result: dict[str, str]) -> None:
    print("macos-qcolor-provenance=PASS")
    print(f"server-sha={result['server_sha']}")
    print(f"qt-core-version={result['qt_core_version']}")
    print(f"qt-gui-version={result['qt_gui_version']}")
    print("platform-plugin-bundle=libqcocoa.dylib")
    print(f"platform-plugin-observed={result['platform_plugin_observed']}")
    print(f"display-color-model={result['display_color_model']}")
    print(f"display-profile-class={result['display_profile_class']}")
    print(f"qcolor-warning={result['warning']}")
    print(
        "warning-source="
        f"{result['warning_source']}:{result['warning_line']}")
    print(f"warning-category={result['warning_category']}")
    print("warning-caller=UNATTRIBUTED")
    print(f"stderr-capture-truncated={result['stderr_capture_truncated']}")
    print("sharing=OFF")
    print("tcp-listener=absent")
    print("native-capture=NOT_RUN")
    print("native-input=NOT_RUN")
    print("backtrace=NOT_RUN")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument(
        "--duration-seconds", type=float, default=3.0,
        help="bounded no-Sharing observation window (1..10 seconds)")
    arguments = parser.parse_args()

    if sys.platform != "darwin":
        print("macos-qcolor-provenance=SKIP (macOS only)")
        return 77
    if not 1.0 <= arguments.duration_seconds <= 10.0:
        print("macos-qcolor-provenance: rejected: invalid duration", file=sys.stderr)
        return 2
    try:
        print_summary(run_probe(arguments.app, arguments.duration_seconds))
    except (OSError, ProbeError, subprocess.SubprocessError) as error:
        print(
            "macos-qcolor-provenance: rejected: "
            + safe_failure_reason(error),
            file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
