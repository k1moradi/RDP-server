#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a deterministic startup-disabled macOS Qt .app portable GUI ZIP."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
APP_NAME = "rdp-server-desktop.app"
EXECUTABLE = f"{APP_NAME}/Contents/MacOS/rdp-server-desktop"
INFO_PLIST = f"{APP_NAME}/Contents/Info.plist"
QT_PLATFORM = f"{APP_NAME}/Contents/PlugIns/platforms/libqcocoa.dylib"
MANIFEST = "metadata/PORTABLE-GUI-MANIFEST.json"
CHECKSUMS = "metadata/SHA256SUMS.txt"
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_ENTRIES = 4096
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


class MacGuiBundleError(ValueError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise MacGuiBundleError(reason)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (bool(name) and not name.startswith("/") and "\\" not in name
            and ":" not in name and "\x00" not in name
            and all(part not in ("", ".", "..") for part in name.split("/"))
            and str(path) == name)


def inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def regular_macho(path: Path) -> None:
    require(path.is_file() and not path.is_symlink(),
            "Mach-O input must be a regular non-symlink file")
    require(path.stat().st_size <= MAX_FILE, "oversized Mach-O input")
    with path.open("rb") as source:
        require(source.read(4) in MACHO_MAGICS, "expected Mach-O image")


def inspect_architectures(path: Path) -> set[str]:
    result = subprocess.run(
        ["lipo", "-archs", str(path)], capture_output=True, text=True,
        timeout=30, check=True, stdin=subprocess.DEVNULL)
    result_set = set(result.stdout.split())
    require(bool(result_set), "lipo reported no architecture")
    return result_set


def validate_app_identity(app: Path) -> None:
    require(app.name == APP_NAME and app.is_dir() and not app.is_symlink(),
            "expected rdp-server-desktop.app")
    regular_macho(app / "Contents/MacOS/rdp-server-desktop")
    plist_path = app / "Contents/Info.plist"
    require(plist_path.is_file() and not plist_path.is_symlink(),
            "missing regular Info.plist")
    try:
        metadata = plistlib.loads(plist_path.read_bytes())
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise MacGuiBundleError("invalid Info.plist") from error
    require(metadata.get("CFBundleExecutable") == "rdp-server-desktop",
            "Info.plist executable mismatch")
    require(metadata.get("CFBundlePackageType") in (None, "APPL"),
            "Info.plist is not an application bundle")


def validate_source_app(app: Path) -> None:
    validate_app_identity(app)
    for path in app.rglob("*"):
        require(not path.is_symlink(), "input app contains a symlink")
        require(inside(path, app), "input app escapes its root")


def resolve_regular_executable(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise MacGuiBundleError(f"{label} path is unavailable") from error
    require(resolved.is_file() and not resolved.is_symlink(),
            f"{label} must resolve to a regular file")
    require(os.access(resolved, os.X_OK),
            f"{label} target must be executable")
    return resolved


def resolve_macdeployqt(macdeployqt: Path) -> Path:
    return resolve_regular_executable(macdeployqt, "macdeployqt")


def query_qt_plugin_root(macdeployqt: Path, runner=subprocess.run) -> Path:
    qmake = resolve_regular_executable(macdeployqt.parent / "qmake", "qmake")
    result = runner(
        [str(qmake), "-query", "QT_INSTALL_PLUGINS"],
        capture_output=True, text=True, timeout=30, check=True,
        stdin=subprocess.DEVNULL)
    lines = [line.strip() for line in result.stdout.splitlines()
             if line.strip()]
    require(len(lines) == 1 and "\x00" not in lines[0],
            "qmake returned an invalid Qt plugin root")
    try:
        plugin_root = Path(lines[0]).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise MacGuiBundleError("Qt plugin root is unavailable") from error
    require(plugin_root.is_dir() and not plugin_root.is_symlink(),
            "Qt plugin root must resolve to a directory")
    return plugin_root


def is_macho(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        with path.open("rb") as source:
            return source.read(4) in MACHO_MAGICS
    except OSError:
        return False


def unique_staged_machos(staged_app: Path) -> list[Path]:
    root = staged_app.resolve(strict=True)
    seen: set[Path] = set()
    result: list[Path] = []
    for candidate in sorted(staged_app.rglob("*")):
        if candidate.is_dir():
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise MacGuiBundleError(
                "deployed app contains an unavailable entry") from error
        require(inside(resolved, staged_app),
                "deployed app contains an escaping link")
        if resolved in seen or not is_macho(resolved):
            continue
        seen.add(resolved)
        result.append(resolved)
    return result


def portable_install_id(path: Path, staged_app: Path) -> str | None:
    relative = path.relative_to(staged_app.resolve(strict=True))
    parts = relative.parts
    if len(parts) >= 3 and parts[:2] == ("Contents", "Frameworks"):
        return "@rpath/" + PurePosixPath(*parts[2:]).as_posix()
    if len(parts) >= 4 and parts[:2] == ("Contents", "PlugIns"):
        return "@rpath/" + path.name
    return None


def normalize_macho_install_ids(staged_app: Path,
                                runner=subprocess.run) -> None:
    for binary in unique_staged_machos(staged_app):
        desired = portable_install_id(binary, staged_app)
        if desired is None:
            continue
        result = runner(
            ["otool", "-D", str(binary)], capture_output=True, text=True,
            timeout=30, check=True, stdin=subprocess.DEVNULL)
        lines = [line.strip() for line in result.stdout.splitlines()
                 if line.strip()]
        if len(lines) < 2:
            continue
        current = lines[1]
        if not current.startswith("/"):
            continue
        runner(
            ["install_name_tool", "-id", desired, str(binary)],
            check=True, timeout=30, stdin=subprocess.DEVNULL)


def adhoc_sign_app(staged_app: Path, runner=subprocess.run) -> None:
    runner(
        ["codesign", "--force", "--deep", "--sign", "-", str(staged_app)],
        check=True, timeout=120, stdin=subprocess.DEVNULL)


def deploy_with_macdeployqt(app: Path, staging: Path,
                            macdeployqt: Path, runner=subprocess.run) -> None:
    deployment_tool = resolve_macdeployqt(macdeployqt)
    plugin_root = query_qt_plugin_root(macdeployqt, runner)
    source_plugin = (
        plugin_root / "platforms/libqcocoa.dylib").resolve(strict=True)
    regular_macho(source_plugin)

    staged_app = staging / APP_NAME
    shutil.copytree(app, staged_app, symlinks=False)
    staged_plugin = staged_app / "Contents/PlugIns/platforms/libqcocoa.dylib"
    staged_plugin.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_plugin, staged_plugin, follow_symlinks=True)
    regular_macho(staged_plugin)

    runner(
        [str(deployment_tool), str(staged_app), "-always-overwrite",
         "-no-plugins", "-no-codesign", f"-executable={staged_plugin}"],
        check=True, timeout=240, cwd=staging, stdin=subprocess.DEVNULL)
    normalize_macho_install_ids(staged_app, runner)
    adhoc_sign_app(staged_app, runner)


def valid_framework_symlink(path: Path, staged_app: Path) -> bool:
    """Allow only resolved in-bundle Qt framework aliases or local dylib aliases."""
    if not path.is_symlink():
        return False
    relative = path.relative_to(staged_app)
    parts = relative.parts
    if len(parts) < 3 or parts[:2] != ("Contents", "Frameworks"):
        return False
    try:
        target = os.readlink(path)
        target_path = PurePosixPath(target)
        if (not target or target_path.is_absolute() or "\\" in target or
                ":" in target or "\x00" in target or
                any(part in (".", "..") for part in target.split("/"))):
            return False
        resolved = path.resolve(strict=True)
        framework_root = staged_app / "Contents/Frameworks" / parts[2]
        if parts[2].endswith(".framework") and len(parts) >= 4:
            return resolved.is_relative_to(framework_root.resolve(strict=True))
        if len(parts) == 3 and parts[2].endswith(".dylib"):
            return resolved.is_relative_to((staged_app / "Contents/Frameworks").resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    return False


def collect_files(staged_app: Path) -> dict[str, Path]:
    records: dict[str, Path] = {}
    folded: set[str] = set()
    total = 0
    root = staged_app.parent
    for path in sorted(staged_app.rglob("*")):
        require(inside(path, staged_app),
                "deployed app contains an escaping link")
        if path.is_symlink():
            require(valid_framework_symlink(path, staged_app),
                    "deployed app contains an unsafe framework link")
        elif path.is_dir():
            continue
        else:
            require(path.is_file(), "deployed app contains a non-file entry")
        name = path.relative_to(root).as_posix()
        require(safe_name(name), f"unsafe staged path: {name!r}")
        require(name.casefold() not in folded,
                f"case-colliding staged path: {name!r}")
        folded.add(name.casefold())
        if name.startswith(f"{APP_NAME}/Contents/MacOS/") and name != EXECUTABLE:
            raise MacGuiBundleError("unexpected executable helper in app bundle")
        size = (len(os.readlink(path).encode("utf-8"))
                if path.is_symlink() else path.stat().st_size)
        total += size
        require(size <= MAX_FILE and total <= MAX_TOTAL,
                "deployed app exceeds size bounds")
        require(len(records) < MAX_ENTRIES, "deployed app exceeds entry bound")
        records[name] = path
    return records


def bundle(output: Path, app: Path, macdeployqt: Path, source_sha: str,
           version: str, minimum_macos: str, architecture: str = "arm64",
           deployer=deploy_with_macdeployqt,
           architecture_inspector=inspect_architectures) -> str:
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
            "invalid source SHA")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None,
            "invalid semantic version")
    require(re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", minimum_macos)
            is not None, "invalid minimum macOS version")
    require(architecture == "arm64",
            "only the initial macOS arm64 GUI package is supported")
    require(not output.exists() and not output.is_symlink(), "output exists")
    expected = (f"rdp-server-portable-gui-{version}-macos-{architecture}-"
                f"{source_sha[:12]}.zip")
    require(output.name == expected, "output filename must bind exact SHA")
    validate_source_app(app)
    require(architecture_inspector(
        app / "Contents/MacOS/rdp-server-desktop") == {architecture},
        "GUI executable architecture mismatch")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
            prefix="rdp macos gui ", dir=output.parent) as temporary:
        staging = Path(temporary) / "stage"
        staging.mkdir()
        deployer(app, staging, macdeployqt)
        staged_app = staging / APP_NAME
        validate_app_identity(staged_app)
        plugin = staged_app / "Contents/PlugIns/platforms/libqcocoa.dylib"
        regular_macho(plugin)
        require(architecture in architecture_inspector(plugin),
                "Qt Cocoa plugin lacks package architecture")
        records = collect_files(staged_app)
        for framework in ("QtCore.framework", "QtGui.framework",
                          "QtWidgets.framework"):
            require(any(
                f"/Contents/Frameworks/{framework}/" in f"/{name}"
                for name in records),
                f"missing deployed {framework}")

        payload: dict[str, bytes] = {
            "VERSION": version.encode() + b"\n",
            "LICENSE": (ROOT / "LICENSE").read_bytes(),
            "NOTICE": (ROOT / "NOTICE").read_bytes(),
            "THIRD_PARTY.md": (ROOT / "docs/THIRD_PARTY.md").read_bytes(),
            "config/example.json": json.dumps(
                {"autostart": False, "listen": False, "port": 0},
                sort_keys=True, separators=(",", ":")).encode(),
            "metadata/PLATFORM-MINIMUMS.json": json.dumps(
                {"platform": "macos", "architecture": architecture,
                 "minimum_macos": minimum_macos,
                 "privilege": "standard-user",
                 "installation": "none-required"},
                sort_keys=True, separators=(",", ":")).encode(),
            "metadata/SIGNING-TRUST.json": json.dumps(
                {"signed": False, "notarized": False,
                 "ad_hoc_signed": True,
                 "trust": "ad-hoc signed for local arm64 execution only; release signing/notarization not verified"},
                sort_keys=True, separators=(",", ":")).encode(),
        }
        dependencies = sorted(
            name for name in records
            if "/Contents/Frameworks/" in name
            or "/Contents/PlugIns/" in name)
        payload["metadata/DEPENDENCIES.txt"] = (
            "macdeployqt staged local Qt runtime closure; "
            "R9 native otool/codesign launch verification is authoritative.\n"
            + "\n".join(dependencies) + "\n").encode()

        modes = {name: 0o644 for name in payload}
        framework_links: set[str] = set()
        for name, path in records.items():
            require(name not in payload, "staged file collides with metadata")
            if path.is_symlink():
                # ZIP stores link target bytes, not dereferenced framework data.
                payload[name] = os.readlink(path).encode("utf-8")
                modes[name] = 0o777
                framework_links.add(name)
            else:
                payload[name] = path.read_bytes()
                modes[name] = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
        modes[EXECUTABLE] = 0o755

        hashes = {name: sha256_bytes(data) for name, data in payload.items()}
        manifest = {
            "artifact_family": "PORTABLE-GUI",
            "classification": "portable-gui-host",
            "version": version,
            "platform": "macos",
            "architecture": architecture,
            "exact_git_sha": source_sha,
            "runtime_integration": "r10-production-host-control",
            "startup_enabled": False,
            "mutable_state_location": "user-private-os-location",
            "r2_macos_admission_included": False,
            "native_host_ready": False,
            "files": hashes,
        }
        payload[MANIFEST] = json.dumps(
            manifest, sort_keys=True, indent=2).encode()
        modes[MANIFEST] = 0o644
        hashes[MANIFEST] = sha256_bytes(payload[MANIFEST])
        payload[CHECKSUMS] = (
            "\n".join(f"{hashes[name]}  {name}" for name in sorted(hashes))
            + "\n").encode()
        modes[CHECKSUMS] = 0o644

        folded: set[str] = set()
        total = 0
        try:
            with zipfile.ZipFile(
                    output, "x", compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9) as archive:
                for name in sorted(payload):
                    require(safe_name(name), "unsafe payload path")
                    require(name.casefold() not in folded,
                            "case-colliding payload path")
                    folded.add(name.casefold())
                    data = payload[name]
                    total += len(data)
                    require(len(data) <= MAX_FILE and total <= MAX_TOTAL,
                            "portable GUI payload exceeds size bounds")
                    info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    entry_type = (stat.S_IFLNK if name in framework_links
                                  else stat.S_IFREG)
                    info.external_attr = ((entry_type | modes[name]) << 16)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, data)
        except Exception:
            output.unlink(missing_ok=True)
            raise

    digest = sha256_file(output)
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{digest}  {output.name}\n", encoding="ascii", newline="\n")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--macdeployqt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--minimum-macos", required=True)
    args = parser.parse_args()
    try:
        print(bundle(args.output, args.app, args.macdeployqt, args.source_sha,
                     args.version, args.minimum_macos))
    except (OSError, ValueError, subprocess.SubprocessError,
            zipfile.BadZipFile) as error:
        print(f"macos-gui-bundle: rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
