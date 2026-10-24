#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a deterministic, startup-disabled Windows Qt portable GUI ZIP."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "metadata/PORTABLE-GUI-MANIFEST.json"
CHECKSUMS = "metadata/SHA256SUMS.txt"
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_ENTRIES = 4096
GUI_NAME = "RDP-server-GUI.exe"
QT_PLATFORM = "plugins/platforms/qwindows.dll"
QT_CONF = b"[Paths]\nPlugins=plugins\n"
FORBIDDEN_HELPER_SUFFIXES = (".bat", ".cmd", ".ps1", ".msi")


class WindowsGuiBundleError(ValueError):
    """Windows GUI staging is unsafe or incomplete."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise WindowsGuiBundleError(reason)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (bool(name) and not name.startswith("/") and "\\" not in name
            and ":" not in name and "\x00" not in name
            and all(part not in ("", ".", "..") and
                    not part.endswith((" ", "."))
                    for part in name.split("/"))
            and str(path) == name)


def is_reparse_or_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except AttributeError:
        return False
    return bool(attributes &
                getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def regular_pe(path: Path) -> None:
    require(path.is_file() and not is_reparse_or_link(path),
            "GUI/dependency must be a regular non-reparse file")
    require(path.stat().st_size <= MAX_FILE, "oversized GUI/dependency")
    with path.open("rb") as source:
        require(source.read(2) == b"MZ", "expected Windows PE image")


def deploy_with_windeployqt(gui: Path, staging: Path,
                            windeployqt: Path) -> None:
    require(windeployqt.is_file() and not is_reparse_or_link(windeployqt),
            "windeployqt must be a regular file")
    staged_gui = staging / GUI_NAME
    shutil.copyfile(gui, staged_gui)
    subprocess.run(
        [str(windeployqt), "--dir", str(staging),
         "--plugindir", str(staging / "plugins"),
         "--no-translations", str(staged_gui)],
        check=True, timeout=180, cwd=staging, stdin=subprocess.DEVNULL)


def cmake_runtime_dependencies(staging: Path,
                               windeployqt: Path) -> tuple[Path, ...]:
    """Resolve the recursive non-system PE closure from the staged Qt tree."""
    cmake = shutil.which("cmake")
    require(cmake is not None,
            "cmake runtime dependency resolver is unavailable")
    records = collect_staged_files(staging)
    libraries = [
        path for name, path in records.items()
        if name.casefold().endswith(".dll")
    ]
    require(libraries, "windeployqt produced no runtime DLLs")

    work = staging.parent
    report = work / "resolved-runtime-dependencies.txt"
    helper = work / "collect-runtime-dependencies.cmake"
    search_directories: list[Path] = [staging, windeployqt.parent]
    openssl_root = os.environ.get("OPENSSL_ROOT_DIR", "")
    if openssl_root:
        search_directories.append(Path(openssl_root) / "bin")
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry:
            search_directories.append(Path(entry))

    def append_lines(variable: str, values: list[Path]) -> str:
        return "\n".join(
            f"list(APPEND {variable} [==[{value}]==])"
            for value in dict.fromkeys(values))

    helper.write_text(
        """cmake_minimum_required(VERSION 3.22)
if(POLICY CMP0207)
  cmake_policy(SET CMP0207 NEW)
endif()
set(executables)
""" + append_lines("executables", [staging / GUI_NAME]) + """
set(libraries)
""" + append_lines("libraries", libraries) + """
set(search_directories)
""" + append_lines("search_directories", search_directories) + f"""
file(GET_RUNTIME_DEPENDENCIES
  EXECUTABLES ${{executables}}
  LIBRARIES ${{libraries}}
  DIRECTORIES ${{search_directories}}
  PRE_EXCLUDE_REGEXES "^api-ms-" "^ext-ms-"
  POST_EXCLUDE_REGEXES "^[A-Za-z]:/[Ww][Ii][Nn][Dd][Oo][Ww][Ss]/"
  RESOLVED_DEPENDENCIES_VAR resolved_dependencies
  UNRESOLVED_DEPENDENCIES_VAR unresolved_dependencies)
if(unresolved_dependencies)
  list(JOIN unresolved_dependencies ", " unresolved_text)
  message(FATAL_ERROR
    "unresolved Windows GUI runtime dependencies: ${{unresolved_text}}")
endif()
list(REMOVE_DUPLICATES resolved_dependencies)
list(SORT resolved_dependencies)
file(WRITE [==[{report}]==] "")
foreach(dependency IN LISTS resolved_dependencies)
  file(APPEND [==[{report}]==] "${{dependency}}\\n")
endforeach()
""",
        encoding="utf-8",
        newline="\n")
    result = subprocess.run(
        [cmake, "-P", str(helper)],
        capture_output=True, text=True, check=False, timeout=90,
        cwd=work, stdin=subprocess.DEVNULL)
    require(
        result.returncode == 0,
        "runtime dependency resolution failed" +
        (f": {result.stderr.strip()}" if result.stderr.strip() else ""))
    dependencies = tuple(
        Path(line) for line in report.read_text(
            encoding="utf-8").splitlines() if line.strip())
    require(dependencies,
            "runtime dependency resolver returned no dependencies")
    return dependencies


def stage_runtime_dependencies(
        staging: Path, windeployqt: Path,
        resolver=cmake_runtime_dependencies) -> None:
    """Copy resolved non-system DLLs missing from windeployqt staging."""
    staging_resolved = staging.resolve()
    for dependency in resolver(staging, windeployqt):
        regular_pe(dependency)
        require(
            re.fullmatch(r"[A-Za-z0-9_.+\-]+\.dll",
                         dependency.name, flags=re.IGNORECASE) is not None,
            f"unsupported runtime dependency name: {dependency.name}")
        try:
            dependency.resolve().relative_to(staging_resolved)
            continue
        except ValueError:
            pass

        target = staging / dependency.name
        if target.exists() or target.is_symlink():
            require(
                target.is_file() and not is_reparse_or_link(target),
                "runtime dependency collides with unsafe staged entry")
            require(
                sha256_file(target) == sha256_file(dependency),
                f"conflicting runtime dependency basename: {dependency.name}")
            continue
        shutil.copyfile(dependency, target)
        regular_pe(target)


def collect_staged_files(staging: Path) -> dict[str, Path]:
    records: dict[str, Path] = {}
    folded: set[str] = set()
    total = 0
    for path in sorted(staging.rglob("*")):
        if path.is_dir() and not is_reparse_or_link(path):
            continue
        require(path.is_file() and not is_reparse_or_link(path),
                "runtime staging contains a link/reparse/non-file entry")
        name = path.relative_to(staging).as_posix()
        require(safe_relative_name(name), f"unsafe staged path: {name!r}")
        require(name.casefold() not in folded,
                f"case-colliding staged path: {name!r}")
        folded.add(name.casefold())
        if name.lower().endswith(FORBIDDEN_HELPER_SUFFIXES):
            raise WindowsGuiBundleError("installer/script helper is forbidden")
        if (name.lower().endswith(".exe") and
                name.casefold() != GUI_NAME.casefold()):
            raise WindowsGuiBundleError(
                "unexpected executable helper in GUI ZIP")
        size = path.stat().st_size
        require(size <= MAX_FILE, "oversized staged file")
        total += size
        require(total <= MAX_TOTAL and len(records) < MAX_ENTRIES,
                "staged runtime exceeds package bounds")
        records[name] = path
    return records


def bundle(output: Path, gui: Path, windeployqt: Path, source_sha: str,
           version: str, architecture: str = "x86_64",
           deployer=deploy_with_windeployqt,
           runtime_resolver=cmake_runtime_dependencies) -> str:
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
            "invalid source SHA")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
            "invalid semantic version")
    require(architecture == "x86_64",
            "unsupported Windows GUI architecture")
    require(not output.exists() and not output.is_symlink(),
            "output exists")
    expected_name = (
        f"rdp-server-portable-gui-{version}-windows-{architecture}-"
        f"{source_sha[:12]}.zip")
    require(output.name == expected_name,
            "output filename must bind exact SHA")
    regular_pe(gui)
    require(gui.name.casefold() == GUI_NAME.casefold(),
            "unexpected Windows GUI executable name")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
            prefix="rdp portable gui ", dir=output.parent) as temporary:
        staging = Path(temporary) / "stage"
        staging.mkdir()
        deployer(gui, staging, windeployqt)

        regular_pe(staging / GUI_NAME)
        regular_pe(staging / QT_PLATFORM)
        stage_runtime_dependencies(
            staging, windeployqt, resolver=runtime_resolver)
        (staging / "qt.conf").write_bytes(QT_CONF)
        records = collect_staged_files(staging)

        # Keep package spelling deterministic across case-sensitive and
        # case-insensitive staging filesystems.
        for required in (GUI_NAME, QT_PLATFORM, "Qt6Core.dll",
                         "Qt6Gui.dll", "Qt6Widgets.dll"):
            require(required in records,
                    f"missing deployed runtime: {required}")

        sources = {
            "VERSION": version.encode("utf-8") + b"\n",
            "LICENSE": (ROOT / "LICENSE").read_bytes(),
            "NOTICE": (ROOT / "NOTICE").read_bytes(),
            "THIRD_PARTY.md": (ROOT / "docs/THIRD_PARTY.md").read_bytes(),
            "config/example.json": json.dumps(
                {"autostart": False, "listen": False, "port": 0},
                sort_keys=True, separators=(",", ":")).encode("utf-8"),
            "metadata/PLATFORM-MINIMUMS.json": json.dumps(
                {"platform": "windows", "privilege": "standard-user",
                 "installation": "none-required"},
                sort_keys=True, separators=(",", ":")).encode("utf-8"),
        }
        dependency_names = sorted(
            name for name in records if name.lower().endswith(".dll"))
        sources["metadata/DEPENDENCIES.txt"] = (
            "windeployqt plus CMake GET_RUNTIME_DEPENDENCIES staged the "
            "local non-system runtime closure; R9 PE import scan is the "
            "native closure authority.\n" +
            "\n".join(dependency_names) + "\n").encode("utf-8")

        payload: dict[str, bytes] = dict(sources)
        for name, path in records.items():
            require(name not in payload,
                    "staged file collides with metadata")
            payload[name] = path.read_bytes()

        hashes = {
            name: sha256_bytes(data) for name, data in payload.items()
        }
        manifest = {
            "artifact_family": "PORTABLE-GUI",
            "classification": "portable-gui-host",
            "version": version,
            "platform": "windows",
            "architecture": architecture,
            "exact_git_sha": source_sha,
            "runtime_integration": "r10-production-host-control",
            "startup_enabled": False,
            "mutable_state_location": "user-private-os-location",
            "canonical_startup_arguments": [],
            "configuration_required": False,
            "session_password_storage": "memory-only",
            "automatic_listener_start": False,
            "read_only_extraction_supported": True,
            "r2_windows_admission_included": False,
            "native_host_ready": False,
            "files": hashes,
        }
        payload[MANIFEST] = json.dumps(
            manifest, sort_keys=True, indent=2).encode("utf-8")
        hashes[MANIFEST] = sha256_bytes(payload[MANIFEST])
        payload[CHECKSUMS] = (
            "\n".join(
                f"{hashes[name]}  {name}" for name in sorted(hashes))
            + "\n").encode("utf-8")

        folded: set[str] = set()
        total = 0
        try:
            with zipfile.ZipFile(
                    output, "x", compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9) as archive:
                for name in sorted(payload):
                    require(safe_relative_name(name),
                            "unsafe payload path")
                    require(name.casefold() not in folded,
                            "case-colliding payload path")
                    folded.add(name.casefold())
                    data = payload[name]
                    total += len(data)
                    require(len(data) <= MAX_FILE and total <= MAX_TOTAL,
                            "portable GUI payload exceeds size bounds")
                    info = zipfile.ZipInfo(
                        name, (2026, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = (
                        (stat.S_IFREG | 0o644) << 16)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, data)
        except Exception:
            output.unlink(missing_ok=True)
            raise

    outer_digest = sha256_file(output)
    checksum_path = output.with_suffix(
        output.suffix + ".sha256")
    checksum_path.write_text(
        f"{outer_digest}  {output.name}\n",
        encoding="ascii", newline="\n")
    return outer_digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", type=Path, required=True)
    parser.add_argument("--windeployqt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    try:
        digest = bundle(
            arguments.output, arguments.gui, arguments.windeployqt,
            arguments.source_sha, arguments.version)
    except (OSError, ValueError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        print(f"windows-gui-bundle: rejected: {error}",
              file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
