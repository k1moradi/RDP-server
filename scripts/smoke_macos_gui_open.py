#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""R7 macOS LaunchServices smoke for the extracted, deny-only Qt Cocoa app.

This runs only on a macOS CI runner with an available Aqua login session.
LaunchServices is an automated approximation, not a human Finder double-click,
Gatekeeper quarantine assessment, credential admission or live RDP test.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

APP_NAME = "rdp-server-desktop.app"
EXECUTABLE_NAME = "rdp-server-desktop"


def app_processes(executable: Path) -> list[int]:
    """Locate only the executable from this exact extracted app bundle."""
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,command="],
        capture_output=True, text=True, check=True, timeout=10)
    matches: list[int] = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) == 2 and str(executable) in fields[1]:
            matches.append(int(fields[0]))
    return matches


def smoke(app: Path) -> None:
    app = app.resolve(strict=True)
    executable = app / "Contents/MacOS" / EXECUTABLE_NAME
    if app.name != APP_NAME or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("expected executable in an extracted R7 Cocoa .app")
    if app_processes(executable):
        raise ValueError("unexpected already-running extracted GUI process")

    launched_pid: int | None = None
    try:
        subprocess.run(
            ["/usr/bin/open", "-n", "-a", str(app)], check=True,
            capture_output=True, text=True, timeout=20)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            candidates = app_processes(executable)
            if len(candidates) > 1:
                raise ValueError("multiple extracted GUI processes launched")
            if candidates:
                launched_pid = candidates[0]
                break
            time.sleep(0.25)
        if launched_pid is None:
            raise ValueError("LaunchServices did not keep the extracted Cocoa GUI running")

        # A returning open(1) command alone does not establish app readiness.
        time.sleep(2)
        if launched_pid not in app_processes(executable):
            raise ValueError("extracted Cocoa GUI exited immediately after launch")

        listeners = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-a", "-p", str(launched_pid),
             "-iTCP", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=10)
        if (listeners.returncode != 1 or listeners.stdout.strip() or
                listeners.stderr.strip()):
            raise ValueError(
                "extracted GUI opened a TCP listener or listener audit failed: "
                + listeners.stdout.strip() + " " + listeners.stderr.strip())
        print("macOS extracted Cocoa LaunchServices/no-TCP-listener smoke PASS; "
              "normal human Finder double-click and Gatekeeper trust NOT VERIFIED")
    finally:
        if launched_pid is not None:
            try:
                os.kill(launched_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(20):
                if launched_pid not in app_processes(executable):
                    break
                time.sleep(0.25)
            else:
                raise ValueError("extracted GUI did not terminate after smoke")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    args = parser.parse_args()
    try:
        smoke(args.app)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"macos-gui-open: rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
