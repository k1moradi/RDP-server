#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline, non-serving macOS protocol test-bundle packaging and user install."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile

BUNDLE_KIND = "macos-protocol-test-only"
INSTALL_SUBPATH = Path("Library/Application Support/RDP-server/test-bundle")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def valid_relative(name):
    path = PurePosixPath(name)
    return (name and not name.startswith("/") and not name.endswith("/")
            and "\\" not in name and all(part not in ("", ".", "..") for part in path.parts)
            and str(path) == name)


def validated_manifest(archive):
    names = archive.namelist()
    if len(names) != len(set(names)) or any(not valid_relative(name) for name in names):
        raise ValueError("unsafe or duplicate archive entry")
    if "manifest.json" not in names:
        raise ValueError("missing manifest")
    manifest = json.loads(archive.read("manifest.json"))
    if set(manifest) != {"kind", "version", "source_sha", "architecture", "minimum_macos",
                          "runtime", "licenses", "files"}:
        raise ValueError("unknown manifest contract")
    if manifest["kind"] != BUNDLE_KIND or manifest["architecture"] not in ("arm64", "x86_64"):
        raise ValueError("unsupported bundle identity")
    if not isinstance(manifest["source_sha"], str) or len(manifest["source_sha"]) != 40 or any(
            ch not in "0123456789abcdef" for ch in manifest["source_sha"]):
        raise ValueError("invalid source SHA")
    if not isinstance(manifest["files"], dict) or not manifest["files"]:
        raise ValueError("empty bundle")
    if sorted(names) != sorted(["manifest.json", *manifest["files"]]):
        raise ValueError("manifest entries do not match archive")
    for name, expected_hash in manifest["files"].items():
        if not name.startswith("payload/") or not valid_relative(name):
            raise ValueError("unsafe payload path")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64 or digest(
                archive.read(name)) != expected_hash:
            raise ValueError("checksum mismatch: " + name)
    return manifest


def package(args):
    if platform.system() != "Darwin":
        raise ValueError("packaging requires an actual macOS host")
    if not args.stage.is_dir() or not args.source_sha:
        raise ValueError("staged installation and source SHA required")
    files = sorted(path for path in args.stage.rglob("*") if path.is_file())
    libraries = [path for path in files if path.suffix == ".a"]
    if not libraries:
        raise ValueError("no built static protocol archive")
    architectures = set()
    for library in libraries:
        result = subprocess.run(["lipo", "-archs", str(library)], capture_output=True,
                                text=True, check=True)
        reported = set(result.stdout.split())
        if len(reported) != 1 or not reported <= {"arm64", "x86_64"}:
            raise ValueError("multi-architecture or unknown library: " + str(library))
        architectures.update(reported)
    if len(architectures) != 1:
        raise ValueError("mixed architectures")
    architecture = architectures.pop()
    manifest = {
        "kind": BUNDLE_KIND, "version": args.version, "source_sha": args.source_sha,
        "architecture": architecture, "minimum_macos": args.minimum_macos,
        "runtime": "Protocol static SDK only; no server binary, listener or GUI service",
        "licenses": "GPL-3.0-or-later; bundled LICENSE, NOTICE and THIRD_PARTY notices",
        "files": {},
    }
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            name = "payload/" + path.relative_to(args.stage).as_posix()
            if not valid_relative(name):
                raise ValueError("invalid stage path")
            data = path.read_bytes()
            manifest["files"][name] = digest(data)
            archive.writestr(name, data)
        archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    with zipfile.ZipFile(args.output) as archive:
        validated_manifest(archive)
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(
        digest(args.output.read_bytes()) + "  " + args.output.name + "\n")


def install(args):
    destination = args.home / INSTALL_SUBPATH
    with zipfile.ZipFile(args.archive) as archive:
        manifest = validated_manifest(archive)
        if platform.system() != "Darwin" or platform.machine() != manifest["architecture"]:
            raise ValueError("bundle architecture/host mismatch")
        if destination.is_symlink() or any(parent.is_symlink() for parent in
                                           (destination.parent, destination.parent.parent)):
            raise ValueError("symlinked install path refused")
        if destination.exists():
            existing = destination / "manifest.json"
            if existing.is_file() and json.loads(existing.read_text()) == manifest:
                for name, checksum in manifest["files"].items():
                    path = destination / name
                    if not path.is_file() or path.is_symlink() or digest(path.read_bytes()) != checksum:
                        raise ValueError("existing bundle altered; remove explicitly")
                return
            raise ValueError("different install exists; remove explicitly")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".rdp-test-", dir=destination.parent) as temporary:
            root = Path(temporary)
            for name in manifest["files"]:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
            (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            root.rename(destination)


def remove(args):
    destination = args.home / INSTALL_SUBPATH
    if destination.is_symlink():
        raise ValueError("symlinked bundle path refused")
    if not destination.exists():
        return
    manifest_path = destination / "manifest.json"
    if not manifest_path.is_file() or json.loads(manifest_path.read_text()).get("kind") != BUNDLE_KIND:
        raise ValueError("refusing to remove unknown directory")
    shutil.rmtree(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("package")
    pack.add_argument("--stage", required=True, type=Path)
    pack.add_argument("--output", required=True, type=Path)
    pack.add_argument("--source-sha", required=True)
    pack.add_argument("--version", required=True)
    pack.add_argument("--minimum-macos", required=True)
    for command in ("install", "remove", "status"):
        item = commands.add_parser(command)
        item.add_argument("--home", type=Path, default=Path.home())
        if command == "install":
            item.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "package":
            package(args)
        elif args.command == "install":
            install(args)
        elif args.command == "remove":
            remove(args)
        else:
            destination = args.home / INSTALL_SUBPATH
            print("INSTALLED (protocol-only, not running)" if (destination / "manifest.json").is_file()
                  else "NOT INSTALLED")
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print("macOS test bundle: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
