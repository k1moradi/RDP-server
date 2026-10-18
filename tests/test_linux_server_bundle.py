# SPDX-License-Identifier: GPL-3.0-or-later
"""Isolated offline install/remove test; payload fails if ever executed."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import warnings
import zipfile

def main():
    program = Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        marker = root / "payload_was_executed"
        executable = root / "rdp-server"
        executable.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
        executable.chmod(0o700)
        bundle = root / "bundle.zip"
        def invoke(*arguments, success=True):
            result = subprocess.run([sys.executable, str(program), *map(str, arguments)],
                env={**os.environ, "HOME": str(home)}, capture_output=True, timeout=15)
            assert (result.returncode == 0) == success, (arguments, result.stderr)
        invoke("bundle", "--executable", executable, "--source-sha", "a"*40,
               "--version", "0.1.0", "--output", bundle)
        with zipfile.ZipFile(bundle) as archive:
            assert "bin/rdp-server" in archive.namelist()
            assert '"source_sha": "' + "a"*40 + '"' in archive.read("manifest.json").decode()

        duplicate_bundle = root / "duplicate-member.zip"
        duplicate_bundle.write_bytes(bundle.read_bytes())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate_bundle, "a") as archive:
                archive.writestr("manifest.json", archive.read("manifest.json"))
        invoke("install", "--bundle", duplicate_bundle, success=False)
        assert not marker.exists()

        invoke("install", "--bundle", bundle)
        invoke("verify", "--bundle", bundle)
        invoke("install", "--bundle", bundle, success=False)
        unit = home / ".config/systemd/user/rdp-server-test.service"
        example = home / ".config/rdp-server-test/server.conf.example"
        assert unit.stat().st_mode & 0o777 == 0o600
        assert example.stat().st_mode & 0o777 == 0o600
        assert not (unit.parent / "graphical-session.target.wants").exists()
        assert not marker.exists()
        unit.write_text("tampered")
        invoke("verify", "--bundle", bundle, success=False)
        invoke("uninstall", "--bundle", bundle, success=False)
        with zipfile.ZipFile(bundle) as archive:
            unit.write_bytes(archive.read("systemd/rdp-server-test.service"))
        invoke("uninstall", "--bundle", bundle)
        assert not unit.exists() and not example.exists() and not marker.exists()
        example.symlink_to(executable)
        invoke("install", "--bundle", bundle, success=False)
        assert example.is_symlink() and not marker.exists()

if __name__ == "__main__":
    main()
