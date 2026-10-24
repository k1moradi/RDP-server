#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed PORTABLE-GUI ZIP integrity gate; native GUI smoke is separate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MANIFEST = "metadata/PORTABLE-GUI-MANIFEST.json"
CHECKSUMS = "metadata/SHA256SUMS.txt"
COMMON = {"VERSION", "LICENSE", "NOTICE", "THIRD_PARTY.md",
          "config/example.json", "metadata/DEPENDENCIES.txt",
          "metadata/PLATFORM-MINIMUMS.json", MANIFEST, CHECKSUMS}
PLATFORM_FILES = {
    ("windows", "x86_64"): {"RDP-server-GUI.exe", "plugins/platforms/qwindows.dll"},
    ("macos", "arm64"): {
        "rdp-server-desktop.app/Contents/MacOS/rdp-server-desktop",
        "rdp-server-desktop.app/Contents/Info.plist",
        "rdp-server-desktop.app/Contents/PlugIns/platforms/libqcocoa.dylib",
        "metadata/SIGNING-TRUST.json"},
    ("linux", "x86_64"): {"bin/rdp-server-desktop", "run-gui.sh",
                           "RDP Server.desktop", "plugins/platforms/libqxcb.so"},
}
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_ENTRIES = 4096


class PortableGuiError(ValueError):
    """The archive cannot be accepted as a verified portable GUI."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise PortableGuiError(reason)


def safe_name(name: str) -> bool:
    # Deny Windows alternate streams, absolute/drive paths, Unicode case
    # aliases, and path normalization surprises before any extraction.
    path = PurePosixPath(name)
    return (bool(name) and not name.startswith("/") and "\\" not in name
            and ":" not in name and "\x00" not in name and not name.endswith("/")
            and all(part not in ("", ".", "..") for part in name.split("/"))
            and str(path) == name)


def validate_macos_framework_links(
        links: dict[str, str], names: set[str]) -> None:
    """Allow only self-contained Qt framework aliases, never arbitrary ZIP links."""
    root = "rdp-server-desktop.app/Contents/Frameworks/"
    # No archive file may be written *through* a link during extraction.
    # Qt's directory symlink aliases are entries, never duplicate subtrees.
    for name in names:
        parents = name.split("/")
        for component_count in range(1, len(parents)):
            require("/".join(parents[:component_count]) not in links,
                    f"entry under framework link: {name!r}")
    for name, target in links.items():
        relative = name.removeprefix(root)
        parts = relative.split("/")
        require(name.startswith(root) and (
            (len(parts) >= 2 and parts[0].endswith(".framework")) or
            (len(parts) == 1 and parts[0].endswith(".dylib"))),
            f"directory or link entry: {name!r}")
        require(len(target.encode("utf-8")) <= 256 and safe_name(target),
                f"unsafe framework link target: {name!r}")
        # Keep framework aliases inside their own .framework; dylib aliases
        # may resolve only under the app's dedicated Frameworks directory.
        allowed = (root + parts[0] + "/") if len(parts) > 1 else root

        pending = name.split("/")
        resolved: list[str] = []
        visited: set[str] = set()
        while pending:
            component = pending.pop(0)
            resolved.append(component)
            path = "/".join(resolved)
            if path not in links:
                continue
            require(path not in visited, f"cyclic framework link: {name!r}")
            visited.add(path)
            replacement = links[path]
            require(safe_name(replacement),
                    f"unsafe framework link target: {path!r}")
            resolved.pop()
            pending = replacement.split("/") + pending
            require(len(visited) <= len(links),
                    f"cyclic framework link: {name!r}")

        destination = "/".join(resolved)
        require(destination.startswith(allowed) and (
            destination in names and destination not in links or
            any(other.startswith(destination + "/") for other in names)),
            f"unresolved or escaping framework link: {name!r}")


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive(path: Path, expected_git_sha: str,
                   expected_archive_sha256: str) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", expected_git_sha) is not None,
            "expected Git SHA must contain 40 lowercase hex characters")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256) is not None,
            "a separately trusted outer SHA-256 digest is required")
    require(path.is_file() and not path.is_symlink(), "archive must be a regular file")
    require(digest_file(path) == expected_archive_sha256,
            "outer archive SHA-256 mismatch")

    try:
        with zipfile.ZipFile(path) as archive:
            records = archive.infolist()
            require(0 < len(records) <= MAX_ENTRIES, "archive entry count out of bounds")
            names: set[str] = set()
            folded: set[str] = set()
            total = 0
            hashes: dict[str, str] = {}
            framework_links: dict[str, str] = {}
            for record in records:
                name = record.filename
                require(safe_name(name), f"unsafe archive path: {name!r}")
                require(name not in names and name.casefold() not in folded,
                        f"duplicate or case-colliding path: {name!r}")
                names.add(name)
                folded.add(name.casefold())
                mode = record.external_attr >> 16
                require(not record.is_dir(),
                        f"directory or link entry: {name!r}")
                if stat.S_ISLNK(mode):
                    require(record.file_size <= 256,
                            f"oversized framework link: {name!r}")
                    framework_links[name] = archive.read(record).decode("utf-8")
                require(not (record.flag_bits & 1), "encrypted ZIP entry")
                require(record.file_size <= MAX_FILE, f"oversized file: {name}")
                total += record.file_size
                require(total <= MAX_TOTAL, "archive exceeds unpacked byte limit")
                require(record.compress_size > 0 or record.file_size == 0,
                        f"invalid compressed size: {name}")
                require(record.file_size <= max(1, record.compress_size) * 200,
                        f"suspicious compression ratio: {name}")
                digest = hashlib.sha256()
                with archive.open(record) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                hashes[name] = digest.hexdigest()
            require(COMMON <= names, "missing required license/config/metadata files")
            manifest = json.loads(archive.read(MANIFEST))
            require(isinstance(manifest, dict), "manifest must be a JSON object")
            platform = manifest.get("platform")
            architecture = manifest.get("architecture")
            required = PLATFORM_FILES.get((platform, architecture))
            require(required is not None, "unsupported platform/architecture")
            require(required <= names, "missing genuine GUI entrypoint or Qt platform plugin")
            if platform == "macos":
                validate_macos_framework_links(framework_links, names)
            else:
                require(not framework_links, "directory or link entry outside macOS")
            require(manifest.get("artifact_family") == "PORTABLE-GUI"
                    and manifest.get("classification") == "portable-gui-host",
                    "not a PORTABLE-GUI host artifact")
            require(manifest.get("exact_git_sha") == expected_git_sha,
                    "manifest source SHA does not match checkout")
            require(manifest.get("runtime_integration") == "r10-production-host-control"
                    and manifest.get("startup_enabled") is False,
                    "GUI shell without production runtime or startup-disabled policy")
            require(manifest.get("mutable_state_location") == "user-private-os-location",
                    "mutable state must not reside in ZIP install tree")
            require(manifest.get("canonical_startup_arguments") == []
                    and manifest.get("configuration_required") is False
                    and manifest.get("session_password_storage") == "memory-only"
                    and manifest.get("automatic_listener_start") is False
                    and manifest.get("read_only_extraction_supported") is True,
                    "portable automatic-bootstrap contract mismatch")
            require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+",
                                 str(manifest.get("version", ""))) is not None,
                    "missing semantic version")
            expected_filename = (f"rdp-server-portable-gui-{manifest['version']}-"
                                 f"{platform}-{architecture}-{expected_git_sha[:12]}.zip")
            require(path.name == expected_filename, "archive filename does not bind exact SHA")
            expected_payload = names - {MANIFEST, CHECKSUMS}
            require(manifest.get("files") == {name: hashes[name] for name in expected_payload},
                    "manifest payload inventory or SHA-256 mismatch")
            expected_lines = {f"{hashes[name]}  {name}" for name in names - {CHECKSUMS}}
            actual_lines = archive.read(CHECKSUMS).decode("utf-8").splitlines()
            require(len(actual_lines) == len(expected_lines)
                    and set(actual_lines) == expected_lines,
                    "SHA256SUMS incomplete, duplicated, or modified")
            example = json.loads(archive.read("config/example.json"))
            require(isinstance(example, dict)
                    and example.get("autostart") is False
                    and example.get("listen") is False,
                    "example config may enable networking at first run")
            if platform == "macos":
                signing = json.loads(archive.read("metadata/SIGNING-TRUST.json"))
                require(all(key in signing for key in ("signed", "notarized", "trust")),
                        "macOS signing/notarization/trust status must be explicit")
            if platform == "linux":
                minimums = json.loads(archive.read("metadata/PLATFORM-MINIMUMS.json"))
                require(all(minimums.get(key) for key in
                            ("glibc", "graphics_libraries", "launch_permissions")),
                        "Linux glibc/graphics/permission minimums missing")
            return manifest
    except (OSError, zipfile.BadZipFile, UnicodeError, json.JSONDecodeError,
            KeyError, TypeError) as error:
        raise PortableGuiError(f"invalid portable archive: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--outer-sha256", required=True,
                        help="digest supplied independently by the trusted CI receipt")
    arguments = parser.parse_args()
    try:
        manifest = verify_archive(arguments.archive, arguments.git_sha,
                                  arguments.outer_sha256)
    except PortableGuiError as error:
        parser.exit(1, f"PORTABLE-GUI rejection: {error}\n")
    print(f"PORTABLE-GUI archive structure PASS: {manifest['exact_git_sha']}; "
          "native offline GUI smoke, dependency closure and release approval are separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
