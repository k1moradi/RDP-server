#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package an existing Qt6 Linux GUI; never execute GUI/server or manage services."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SYSTEM_ABI = frozenset({
    "libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2",
    "librt.so.1", "libresolv.so.2", "libutil.so.1",
})
SOURCE_FILES = {
    "run-gui.sh": ROOT / "packaging/linux/run-gui.sh",
    "RDP Server.desktop": ROOT / "packaging/linux/RDP Server.desktop",
    "LICENSE": ROOT / "LICENSE",
    "NOTICE": ROOT / "NOTICE",
}
CONFIG = b"[Paths]\nPrefix=..\nPlugins=plugins\n"
MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_ARCHIVE_SIZE = 512 * 1024 * 1024


def digest(stream):
    checksum = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        checksum.update(block)
    return checksum.hexdigest()


def linked_libraries(binary):
    """Only trusted locally built ELF/Qt libraries are inspected with ldd."""
    result = subprocess.run(
        ["ldd", str(binary)], capture_output=True, text=True,
        timeout=15, check=True)
    libraries = {}
    for line in result.stdout.splitlines():
        if "not found" in line:
            raise ValueError("unresolved native dependency")
        if "=>" not in line:
            continue
        match = re.fullmatch(
            r"\s*(\S+)\s+=>\s+(/\S+)\s+\(0x[0-9a-fA-F]+\)\s*", line)
        if not match:
            raise ValueError("unrecognized native dependency")
        soname, location = match.groups()
        if soname not in SYSTEM_ABI:
            libraries[soname] = Path(location)
    return libraries


def regular_binary(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or symlinked executable")
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise ValueError("expected native ELF binary")
    if path.stat().st_size > MAX_MEMBER_SIZE:
        raise ValueError("oversized binary")


def bundle(output, gui, xcb_plugin, source_sha, version, resolver=linked_libraries):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("invalid source SHA")
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", version):
        raise ValueError("invalid version")
    if output.exists() or output.is_symlink():
        raise ValueError("output exists")
    regular_binary(gui)
    regular_binary(xcb_plugin)
    if not gui.stat().st_mode & stat.S_IXUSR:
        raise ValueError("GUI is not executable")
    if xcb_plugin.name != "libqxcb.so":
        raise ValueError("expected Qt XCB platform plugin")

    dependencies = {}
    for binary in (gui, xcb_plugin):
        for soname, location in resolver(binary).items():
            if "/" in soname or soname in (".", ".."):
                raise ValueError("invalid shared-library soname")
            prior = dependencies.get(soname)
            if prior is not None and prior.resolve() != location.resolve():
                raise ValueError("ambiguous shared-library soname")
            dependencies[soname] = location
    if not any(name.startswith("libQt6Widgets.so") for name in dependencies):
        raise ValueError("GUI Qt6 Widgets runtime closure unavailable")
    if not any(name.startswith("libQt6Gui.so") for name in dependencies):
        raise ValueError("Qt6 GUI runtime closure unavailable")

    sources = dict(SOURCE_FILES)
    sources["bin/rdp-server-desktop"] = gui
    sources["plugins/platforms/libqxcb.so"] = xcb_plugin
    for soname, location in sorted(dependencies.items()):
        sources["lib/" + soname] = location
    contents = {"bin/qt.conf": CONFIG}
    records = {}
    total_bytes = 0
    for name in sorted(set(sources) | set(contents)):
        path = sources.get(name)
        if path is not None:
            if not path.is_file():
                raise ValueError("missing runtime dependency")
            size = path.stat().st_size
            with path.open("rb") as stream:
                checksum = digest(stream)
        else:
            size = len(contents[name])
            checksum = hashlib.sha256(contents[name]).hexdigest()
        total_bytes += size
        if size > MAX_MEMBER_SIZE or total_bytes > MAX_ARCHIVE_SIZE:
            raise ValueError("GUI bundle exceeds size bound")
        mode = 0o755 if name in ("bin/rdp-server-desktop", "run-gui.sh",
                                  "RDP Server.desktop") else 0o644
        records[name] = {"bytes": size, "sha256": checksum, "mode": mode}

    manifest = {
        "format": 1, "kind": "linux-qt6-gui",
        "version": version, "source_sha": source_sha,
        "files": records, "system_abi": sorted(SYSTEM_ABI),
        "fuse_required": False, "systemd_install": False,
        "auto_share": False, "r2_admission_included": False,
    }
    try:
        with zipfile.ZipFile(output, "x") as archive:
            for name, record in records.items():
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = ((stat.S_IFREG | record["mode"]) << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                with archive.open(info, "w") as destination:
                    if name in contents:
                        destination.write(contents[name])
                    else:
                        with sources[name].open("rb") as source:
                            shutil.copyfileobj(source, destination, 1024 * 1024)
            archive.writestr(
                "manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
        verify(output)
    except Exception:
        output.unlink(missing_ok=True)
        raise


def verify(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise ValueError("duplicate/missing ZIP member")
        # Bound untrusted manifest parsing before allocation or decompression.
        manifest_member = archive.getinfo("manifest.json")
        manifest_mode = manifest_member.external_attr >> 16
        if (len(names) > 512 or manifest_member.file_size > 1024 * 1024
                or stat.S_IFMT(manifest_mode) == stat.S_IFLNK):
            raise ValueError("unsafe GUI manifest")
        manifest = json.loads(archive.read("manifest.json"))
        records = manifest.get("files")
        if (manifest.get("format") != 1 or manifest.get("kind") != "linux-qt6-gui"
                or not isinstance(records, dict)
                or set(names) != set(records) | {"manifest.json"}
                or manifest.get("fuse_required") is not False
                or manifest.get("systemd_install") is not False
                or manifest.get("auto_share") is not False
                or manifest.get("r2_admission_included") is not False):
            raise ValueError("invalid Linux GUI manifest")
        required = {"run-gui.sh", "RDP Server.desktop",
                    "bin/rdp-server-desktop", "bin/qt.conf",
                    "plugins/platforms/libqxcb.so", "LICENSE", "NOTICE"}
        if not required.issubset(records):
            raise ValueError("incomplete GUI payload")
        total_bytes = 0
        for member in archive.infolist():
            if member.filename == "manifest.json":
                continue
            name = member.filename
            if (name.startswith("/") or "\\" in name
                    or any(part in ("", ".", "..") for part in name.split("/"))):
                raise ValueError("unsafe ZIP member path")
            expected = records[name]
            mode = (member.external_attr >> 16) & 0o7777
            kind = (member.external_attr >> 16) & stat.S_IFMT(0o170000)
            if (kind != stat.S_IFREG or mode != expected["mode"]
                    or member.file_size != expected["bytes"]
                    or member.file_size > MAX_MEMBER_SIZE):
                raise ValueError("unsafe ZIP member permissions or size")
            total_bytes += member.file_size
            if total_bytes > MAX_ARCHIVE_SIZE:
                raise ValueError("oversized GUI archive")
            with archive.open(member) as source:
                if digest(source) != expected["sha256"]:
                    raise ValueError("GUI bundle integrity failure")
        if not any(name.startswith("lib/libQt6Widgets.so") for name in records):
            raise ValueError("missing bundled Qt Widgets runtime")
        return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("bundle")
    for name in ("gui", "xcb-plugin", "output", "source-sha", "version"):
        builder.add_argument("--" + name, required=True)
    verifier = commands.add_parser("verify")
    verifier.add_argument("--bundle", required=True)
    args = parser.parse_args()
    try:
        if args.command == "bundle":
            bundle(Path(args.output), Path(args.gui), Path(args.xcb_plugin),
                   args.source_sha, args.version)
        else:
            verify(Path(args.bundle))
    except (OSError, ValueError, subprocess.SubprocessError,
            zipfile.BadZipFile, KeyError, TypeError) as error:
        print("linux-gui-bundle: offline operation rejected; GUI not started",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
