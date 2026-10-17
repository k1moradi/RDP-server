#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline-only Linux test bundle: never runs its payload, systemd or X11."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
PATHS = {
    "bin/rdp-server": ".local/share/rdp-server-test/bin/rdp-server",
    "systemd/rdp-server-test.service": ".config/systemd/user/rdp-server-test.service",
    "config/server.conf.example": ".config/rdp-server-test/server.conf.example",
}

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def payload_from_bundle(bundle):
    with zipfile.ZipFile(bundle) as archive:
        if set(archive.namelist()) != set(PATHS) | {"manifest.json"}:
            raise ValueError("invalid bundle members")
        if any(member.file_size > 64 * 1024 * 1024 for member in archive.infolist()):
            raise ValueError("oversized bundle")
        manifest = json.loads(archive.read("manifest.json"))
        payload = {name: archive.read(name) for name in PATHS}
    expected = {name: {"bytes": len(content), "sha256": sha256(content)}
                for name, content in payload.items()}
    if manifest.get("format") != 1 or manifest.get("files") != expected:
        raise ValueError("invalid checksum manifest")
    return payload

def user_home():
    home = Path.home()
    if not home.is_dir() or home.is_symlink():
        raise ValueError("unsafe home")
    return home

def target_path(home, relative):
    current = home
    segments = Path(relative).parts
    for index, segment in enumerate(segments):
        current = current / segment
        if current.is_symlink():
            raise ValueError("symlinked target")
        if current.exists():
            if index + 1 == len(segments) and not current.is_file():
                raise ValueError("invalid file type")
            if index + 1 != len(segments) and not current.is_dir():
                raise ValueError("invalid directory type")
    return current

def ensure_parents(home, relative):
    current = home
    for segment in Path(relative).parts[:-1]:
        current /= segment
        if current.is_symlink():
            raise ValueError("symlinked parent")
        if not current.exists():
            current.mkdir(mode=0o700)
        if not current.is_dir() or current.stat().st_uid != os.geteuid():
            raise ValueError("unsafe directory owner")
        if segment in ("rdp-server-test", "bin"):
            current.chmod(0o700)

def bundle(args):
    executable = Path(args.executable)
    if not executable.is_file() or executable.is_symlink() or not executable.stat().st_mode & stat.S_IXUSR:
        raise ValueError("not a built executable")
    if len(args.source_sha) != 40 or any(character not in "0123456789abcdef" for character in args.source_sha):
        raise ValueError("invalid source SHA")
    content = {"bin/rdp-server": executable.read_bytes(),
               "systemd/rdp-server-test.service": (ROOT / "rdp-server-test.service").read_bytes(),
               "config/server.conf.example": (ROOT / "server.conf.example").read_bytes()}
    manifest = {"format": 1, "version": args.version, "source_sha": args.source_sha,
                "files": {name: {"bytes": len(data), "sha256": sha256(data)}
                          for name, data in content.items()},
                "allowed_runtime_dependencies": ["glibc", "libstdc++", "OpenSSL",
                    "GSSAPI/Kerberos", "PAM", "libsystemd", "XCB/X11/XTEST"]}
    if Path(args.output).exists() or Path(args.output).is_symlink():
        raise ValueError("output exists")
    with zipfile.ZipFile(args.output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in content.items():
            archive.writestr(name, data)
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
    payload_from_bundle(args.output)

def verify_contents(bundle_path, home):
    payload = payload_from_bundle(bundle_path)
    for member, relative in PATHS.items():
        target = target_path(home, relative)
        mode = 0o700 if member == "bin/rdp-server" else 0o600
        if (not target.is_file() or target.stat().st_uid != os.geteuid()
                or stat.S_IMODE(target.stat().st_mode) != mode
                or sha256(target.read_bytes()) != sha256(payload[member])):
            raise ValueError("installed content or permissions changed")

def install(args):
    home = user_home()
    payload = payload_from_bundle(args.bundle)
    if any(target_path(home, relative).exists() for relative in PATHS.values()):
        raise ValueError("installation target already exists")
    created = []
    try:
        for member, relative in PATHS.items():
            ensure_parents(home, relative)
            target = target_path(home, relative)
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created.append(target)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload[member])
            target.chmod(0o700 if member == "bin/rdp-server" else 0o600)
    except Exception:
        for target in reversed(created):
            target.unlink(missing_ok=True)
        raise

def main():
    argument_parser = argparse.ArgumentParser(description=__doc__)
    actions = argument_parser.add_subparsers(dest="action", required=True)
    creator = actions.add_parser("bundle")
    for option in ("executable", "source-sha", "version", "output"):
        creator.add_argument("--" + option, required=True)
    for action in ("install", "verify", "uninstall"):
        actions.add_parser(action).add_argument("--bundle", required=True)
    args = argument_parser.parse_args()
    try:
        if args.action == "bundle":
            bundle(args)
        elif args.action == "install":
            install(args)
        else:
            home = user_home()
            verify_contents(args.bundle, home)
            if args.action == "uninstall":
                for relative in PATHS.values():
                    target_path(home, relative).unlink()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print("rdp-server-test-bundle: offline operation rejected; no service started", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
