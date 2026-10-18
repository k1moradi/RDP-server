#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline negative checks; never launch X11, serve, systemd or R2."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
script = root / "packaging/linux/gui_preflight.py"
spec = importlib.util.spec_from_file_location("gui_preflight", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

base = {"XDG_SESSION_ID": "42", "XDG_SESSION_TYPE": "x11", "DISPLAY": ":0"}
admitted = "Seat=seat0\nType=x11\nActive=yes\nRemote=no\nDisplay=:0\nState=active\n"
libraries = lambda name: "lib" + name + ".so"
check = lambda env, properties: module.report(env, lambda _: properties, libraries)
status = check(base, admitted)
assert status["physical_x11_seat0"]
assert status["capture_input_prerequisites"]
assert not status["r2_authenticated_selection"]
assert not status["ready_to_share"]
assert status["admission_generation"] is None
for broken in (
    {**base, "XDG_SESSION_TYPE": "wayland"},
    {**base, "DISPLAY": ":99"},
    {**base, "XDG_SESSION_ID": ""},
):
    assert not check(broken, admitted)["physical_x11_seat0"]
for fragment in ("Seat=seat1", "Type=wayland", "Active=no",
                 "Remote=yes", "Display=:99", "State=closing"):
    key = fragment.split("=")[0]
    changed = "\n".join(fragment if line.startswith(key + "=") else line
                        for line in admitted.strip().splitlines()) + "\n"
    assert not check(base, changed)["physical_x11_seat0"]
assert not module.report(base, lambda _: admitted, lambda name: None)["capture_input_prerequisites"]

launcher = root / "packaging/linux/run-gui.sh"
text = launcher.read_text()
assert 'rdp-server-desktop' in text and 'serve' not in text.split('exec "$gui"')[0].replace("# Open only the GUI binary beside this launcher. Never fall back to 'serve'.", "")
with tempfile.TemporaryDirectory() as temporary:
    work = Path(temporary)
    (work / "run-gui.sh").write_text(text)
    result = subprocess.run(["sh", str(work / "run-gui.sh")],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "no listener was started" in result.stderr
print("Linux GUI inspection denial and missing-payload launcher: PASS")
