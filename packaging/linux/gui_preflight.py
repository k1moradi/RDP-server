#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only Linux GUI prerequisite report. Never authorizes native input."""
import ctypes.util
import json
import os
import subprocess
import sys


def report(environment=None, session_query=None, library_lookup=None):
    environment = os.environ if environment is None else environment
    library_lookup = ctypes.util.find_library if library_lookup is None else library_lookup
    session = environment.get("XDG_SESSION_ID", "")
    display = environment.get("DISPLAY", "")
    properties = {}
    if session and session_query is None:
        try:
            output = subprocess.run(
                ["loginctl", "show-session", session, "--no-pager",
                 "-p", "Seat", "-p", "Type", "-p", "Active",
                 "-p", "Remote", "-p", "Display", "-p", "State"],
                capture_output=True, text=True, timeout=2, check=True).stdout
        except (OSError, subprocess.SubprocessError):
            output = ""
    elif session and session_query is not None:
        output = session_query(session)
    else:
        output = ""
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    physical_x11_seat0 = (
        bool(session) and properties.get("Seat") == "seat0"
        and properties.get("Type") == "x11"
        and properties.get("Active") == "yes"
        and properties.get("Remote") == "no"
        and properties.get("State") == "active"
        and environment.get("XDG_SESSION_TYPE") == "x11"
        and bool(display) and display == properties.get("Display")
    )
    libraries = {
        name: bool(library_lookup(name))
        for name in ("X11", "Xext", "Xrandr", "Xtst")
    }
    return {
        "physical_x11_seat0": physical_x11_seat0,
        "display": display,
        "logind_display": properties.get("Display", ""),
        "session": session,
        "session_active": properties.get("Active") == "yes",
        "capture_input_libraries": libraries,
        "capture_input_prerequisites": physical_x11_seat0 and all(libraries.values()),
        "r2_authenticated_selection": False,
        "admission_generation": None,
        "after_login_launch": "not_configured",
        "ready_to_share": False,
        "reason": "GUI inspection is not an R2 desktop selection or ShareActivated admission",
    }


if __name__ == "__main__":
    json.dump(report(), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
