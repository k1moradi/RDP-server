#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure offline GUI archive/lifecycle tests; no Qt, login, X11 or sockets."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "gui_bundle", ROOT / "packaging/linux/gui_bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def rejects(operation):
    try:
        operation()
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile):
        return
    raise AssertionError("expected fail-closed bundle rejection")


with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    gui = root / "rdp-server-desktop"
    plugin = root / "libqxcb.so"
    widgets = root / "libQt6Widgets.so.6"
    qtgui = root / "libQt6Gui.so.6"
    gui.write_bytes(b"\x7fELF" + b"gui fixture")
    plugin.write_bytes(b"\x7fELF" + b"XCB plugin fixture")
    widgets.write_bytes(b"Qt Widgets fixture")
    qtgui.write_bytes(b"Qt GUI fixture")
    gui.chmod(0o755)
    plugin.chmod(0o644)
    paths = {"libQt6Widgets.so.6": widgets, "libQt6Gui.so.6": qtgui}
    resolver = lambda _: paths
    target = root / "linux-gui.zip"
    source_sha = "a" * 40
    bundle.bundle(target, gui, plugin, source_sha, "0.1.0", resolver)
    manifest = bundle.verify(target)
    assert manifest["source_sha"] == source_sha
    assert manifest["auto_share"] is False
    assert manifest["r2_admission_included"] is False
    assert manifest["canonical_startup_arguments"] == []
    assert manifest["configuration_required"] is False
    assert manifest["session_password_storage"] == "memory-only"
    assert manifest["automatic_listener_start"] is False
    assert manifest["read_only_extraction_supported"] is True
    assert manifest["mutable_state_location"] == "user-private-os-location"
    assert manifest["fuse_required"] is False
    assert manifest["systemd_install"] is False
    assert not any("systemd/" in name or "server.conf" in name
                   for name in manifest["files"])
    with zipfile.ZipFile(target) as source:
        names = source.namelist()
        assert "bin/rdp-server-desktop" in names
        assert "plugins/platforms/libqxcb.so" in names
        assert "bin/rdp-server" not in names
        assert set(names) == set(manifest["files"]) | {"manifest.json"}
        for name in ("bin/rdp-server-desktop", "run-gui.sh",
                     "RDP Server.desktop"):
            info = source.getinfo(name)
            assert info.create_system == 3
            assert (info.external_attr >> 16) & 0o777 == 0o755
        assert "Prefix=.." in source.read("bin/qt.conf").decode()
        launcher_lines = source.read("run-gui.sh").splitlines()
        launcher_code = b"\n".join(
            line for line in launcher_lines
            if not line.lstrip().startswith(b"#"))
        assert b"systemctl" not in launcher_code
        assert b"AppImage" not in launcher_code
        assert b"fuse" not in launcher_code.lower()

    # The user can extract to any folder, without a service or installer.
    extracted = root / "extracted"
    extracted.mkdir()
    with zipfile.ZipFile(target) as source:
        for info in source.infolist():
            destination = extracted / info.filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read(info.filename))
            destination.chmod((info.external_attr >> 16) & 0o777)

    # Replace the inert synthetic ELF with a harmless GUI-exec marker.
    # This tests launcher resolution, never the real GUI or R2 admission.
    executable = extracted / "bin/rdp-server-desktop"
    private_home = root / "private-home"
    private_home.mkdir(mode=0o700)
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$#\" -ne 0 ]; then\n"
        "  printf 'unexpected consumer arguments\\n' >&2\n"
        "  exit 64\n"
        "fi\n"
        "mkdir -p \"$XDG_DATA_HOME/RDP-server\" \"$XDG_CONFIG_HOME/RDP-server\"\n"
        ": > \"$XDG_DATA_HOME/RDP-server/bootstrap.marker\"\n"
        ": > \"$XDG_CONFIG_HOME/RDP-server/preferences.conf\"\n"
        "printf 'GUI_LAUNCH_OK:%s\\n' \"$LD_LIBRARY_PATH\"\n")
    executable.chmod(0o755)
    private_data_root = root / "private-data"
    private_config_root = root / "private-config"
    extracted_before = {
        path.relative_to(extracted) for path in extracted.rglob("*")
    }

    # Canonical consumer launch is no-argument and must work when the ZIP
    # extraction tree itself is read-only. Mutable state belongs outside it.
    for path in extracted.rglob("*"):
        if path.is_dir():
            path.chmod(0o555)
        else:
            path.chmod(0o555 if os.access(path, os.X_OK) else 0o444)
    extracted.chmod(0o555)
    try:
        launch = subprocess.run(
            [str(extracted / "run-gui.sh")], capture_output=True,
            text=True, timeout=5,
            env={**os.environ, "QT_QPA_PLATFORM": "xcb",
                 "HOME": str(private_home),
                 "XDG_DATA_HOME": str(private_data_root),
                 "XDG_CONFIG_HOME": str(private_config_root)})
    finally:
        extracted.chmod(0o755)
        for path in extracted.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
    assert launch.returncode == 0, launch.stderr
    assert "GUI_LAUNCH_OK:" + str(extracted / "lib") in launch.stdout
    assert {path.relative_to(extracted) for path in extracted.rglob("*")} == \
        extracted_before

    private_data = private_data_root / "RDP-server/bootstrap.marker"
    private_config = private_config_root / "RDP-server/preferences.conf"
    assert private_data.is_file() and not private_data.is_symlink()
    assert private_config.is_file() and not private_config.is_symlink()
    assert stat.S_IMODE(private_data.stat().st_mode) == 0o600
    assert stat.S_IMODE(private_config.stat().st_mode) == 0o600
    assert stat.S_IMODE(private_data.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(private_config.parent.stat().st_mode) == 0o700

    # Broken archive, metadata or runtime closure never passes verify.
    with zipfile.ZipFile(target) as source:
        contents = {item.filename: (item, source.read(item.filename))
                    for item in source.infolist()}
    broken = root / "tampered.zip"
    with zipfile.ZipFile(broken, "w") as destination:
        for name, (info, data) in contents.items():
            destination.writestr(
                info, b"tampered" if name == "bin/rdp-server-desktop" else data)
    rejects(lambda: bundle.verify(broken))

    wrong_mode = root / "wrong-mode.zip"
    with zipfile.ZipFile(wrong_mode, "w") as destination:
        for name, (info, data) in contents.items():
            if name == "run-gui.sh":
                info.external_attr = ((stat.S_IFLNK | 0o777) << 16)
            destination.writestr(info, data)
    rejects(lambda: bundle.verify(wrong_mode))

    rejects(lambda: bundle.bundle(root / "bad.zip", gui, plugin, "bad",
                                  "0.1.0", resolver))
    rejects(lambda: bundle.bundle(root / "missing-closure.zip", gui, plugin,
                                  source_sha, "0.1.0", lambda _: {}))
    rejects(lambda: bundle.bundle(target, gui, plugin,
                                  source_sha, "0.1.0", resolver))
    gui.chmod(0o644)
    rejects(lambda: bundle.bundle(root / "not-executable.zip", gui, plugin,
                                  source_sha, "0.1.0", resolver))

print("Linux GUI ZIP permission, closure, no-start and tamper denials: PASS")
