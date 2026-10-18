#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and verify startup-disabled cross-platform SERVER-TEST preview bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import zipfile

ARTIFACT_FAMILY = "SERVER-TEST"
SCHEMA_VERSION = 1
MACOS_LAUNCH_AGENT_LABEL = "org.rdpserver.server-test"
MACOS_LAUNCH_AGENT_HELPER = "tools/macos_test_launch_agent.py"
MAX_MEMBER_BYTES = 256 * 1024 * 1024
FORBIDDEN_PAYLOAD_SUFFIXES = {
    ".ccache", ".keytab", ".kirbi", ".p12", ".pfx", ".pem.key", ".private",
}
FORBIDDEN_BYTE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"github_pat_",
)
TOKEN_PATTERNS = (
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
)


class BundleError(RuntimeError):
    """Fail-closed SERVER-TEST bundle error."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalized_platform() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    raise BundleError(f"unsupported SERVER-TEST platform: {system}")


def normalized_architecture(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"x86_64", "amd64", "x64"}:
        return "x86_64"
    if lowered in {"arm64", "aarch64"}:
        return "arm64"
    raise BundleError(f"unsupported SERVER-TEST architecture: {value}")


def valid_source_sha(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{40}", value) is not None


def safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not value.startswith("/")
        and not value.endswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in path.parts)
        and str(path) == value
    )


def project_version(source_root: Path) -> str:
    text = (source_root / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(
        r"project\(RDP_server\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
        text,
    )
    if match is None:
        raise BundleError("unable to read project version")
    return match.group(1)


def executable_path(build_root: Path, build_configuration: str, os_name: str) -> Path:
    executable_name = "rdp-server.exe" if os_name == "windows" else "rdp-server"
    candidates = []
    if os_name == "windows":
        candidates.extend(
            [
                build_root / build_configuration / executable_name,
                build_root / executable_name,
            ]
        )
    else:
        candidates.extend(
            [
                build_root / executable_name,
                build_root / build_configuration / executable_name,
            ]
        )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise BundleError(
        f"actual {executable_name} target was not found in the existing build root"
    )


def parse_cmake_assignment(text: str, variable: str) -> str:
    match = re.search(
        rf'set\({re.escape(variable)}\s+"?([^"\)]+)"?\)',
        text,
    )
    return match.group(1).strip() if match is not None else ""


def compiler_identity(build_root: Path, build_configuration: str) -> dict[str, str]:
    compiler_files = sorted(build_root.glob("CMakeFiles/*/CMakeCXXCompiler.cmake"))
    if not compiler_files:
        raise BundleError("CMake C++ compiler identity file is missing")
    compiler_text = compiler_files[-1].read_text(encoding="utf-8", errors="replace")
    cache_path = build_root / "CMakeCache.txt"
    if not cache_path.is_file():
        raise BundleError("CMakeCache.txt is missing")
    cache = cache_path.read_text(encoding="utf-8", errors="replace")
    compiler_id = parse_cmake_assignment(compiler_text, "CMAKE_CXX_COMPILER_ID")
    compiler_version = parse_cmake_assignment(
        compiler_text, "CMAKE_CXX_COMPILER_VERSION"
    )
    compiler_path = parse_cmake_assignment(compiler_text, "CMAKE_CXX_COMPILER")
    generator_match = re.search(r"^CMAKE_GENERATOR:INTERNAL=(.+)$", cache, re.MULTILINE)
    generator = generator_match.group(1).strip() if generator_match else "unknown"
    if not compiler_id or not compiler_version:
        raise BundleError("incomplete C++ compiler identity")
    return {
        "id": compiler_id,
        "version": compiler_version,
        "executable": Path(compiler_path).name if compiler_path else "unknown",
        "generator": generator,
        "build_configuration": build_configuration,
    }


def run_process(
    command: list[str],
    *,
    expected_codes: set[int],
    environment: dict[str, str] | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=timeout,
        check=False,
    )
    if result.returncode not in expected_codes:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise BundleError(
            f"command failed with exit {result.returncode}: {Path(command[0]).name}"
            + (f": {stderr}" if stderr else "")
        )
    return result


def binary_identity(executable: Path, os_name: str) -> tuple[str, str]:
    data = executable.read_bytes()[:4096]
    if os_name == "linux":
        if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2:
            raise BundleError("SERVER-TEST Linux executable is not ELF64")
        byte_order = "<" if data[5] == 1 else ">" if data[5] == 2 else ""
        if not byte_order:
            raise BundleError("unsupported ELF byte order")
        machine = struct.unpack_from(byte_order + "H", data, 18)[0]
        architecture = {0x3E: "x86_64", 0xB7: "arm64"}.get(machine)
        if architecture is None:
            raise BundleError(f"unsupported ELF machine: {machine}")
        libc_name, libc_version = platform.libc_ver()
        abi = f"ELF64; {libc_name or 'libc'} {libc_version or 'unknown'}"
        return architecture, abi

    if os_name == "windows":
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise BundleError("SERVER-TEST Windows executable is not PE")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        with executable.open("rb") as source:
            source.seek(pe_offset)
            header = source.read(26)
        if len(header) < 26 or header[:4] != b"PE\0\0":
            raise BundleError("invalid PE signature")
        machine = struct.unpack_from("<H", header, 4)[0]
        optional_magic = struct.unpack_from("<H", header, 24)[0]
        architecture = {0x8664: "x86_64", 0xAA64: "arm64"}.get(machine)
        if architecture is None or optional_magic != 0x20B:
            raise BundleError("SERVER-TEST Windows executable must be PE32+")
        return architecture, "PE32+ Windows ABI"

    if os_name == "macos":
        if len(data) < 4 or data[:4] not in {
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xca\xfe\xba\xbe",
            b"\xbe\xba\xfe\xca",
        }:
            raise BundleError("SERVER-TEST macOS executable is not Mach-O")
        result = run_process(["lipo", "-archs", str(executable)], expected_codes={0})
        slices = result.stdout.decode("utf-8", errors="replace").split()
        if len(slices) != 1:
            raise BundleError("SERVER-TEST macOS preview must be single-architecture")
        architecture = normalized_architecture(slices[0])
        return architecture, "Mach-O 64-bit Darwin ABI"

    raise BundleError("unsupported executable platform")


def cmake_runtime_dependencies(
    executable: Path, output_directory: Path
) -> list[Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    report_path = output_directory / "resolved-runtime-dependencies.txt"
    helper_path = output_directory / "collect-runtime-dependencies.cmake"
    search_directories: list[Path] = [executable.parent]
    openssl_root = os.environ.get("OPENSSL_ROOT_DIR", "")
    if openssl_root:
        # Prefer the exact OpenSSL installation used by CMake over unrelated
        # same-named DLLs that may appear earlier on a hosted runner's PATH.
        search_directories.append(Path(openssl_root) / "bin")
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry:
            search_directories.append(Path(entry))
    append_lines = "\n".join(
        f"list(APPEND search_directories [==[{directory}]==])"
        for directory in dict.fromkeys(search_directories)
    )
    helper = f"""cmake_minimum_required(VERSION 3.22)
if(POLICY CMP0207)
  cmake_policy(SET CMP0207 NEW)
endif()
set(test_executable [==[{executable}]==])
set(report_path [==[{report_path}]==])
set(search_directories)
{append_lines}
if(WIN32)
  file(GET_RUNTIME_DEPENDENCIES
    EXECUTABLES "${{test_executable}}"
    DIRECTORIES ${{search_directories}}
    PRE_EXCLUDE_REGEXES "^api-ms-" "^ext-ms-"
    POST_EXCLUDE_REGEXES "^[A-Za-z]:/[Ww][Ii][Nn][Dd][Oo][Ww][Ss]/"
    RESOLVED_DEPENDENCIES_VAR resolved_dependencies
    UNRESOLVED_DEPENDENCIES_VAR unresolved_dependencies)
else()
  file(GET_RUNTIME_DEPENDENCIES
    EXECUTABLES "${{test_executable}}"
    RESOLVED_DEPENDENCIES_VAR resolved_dependencies
    UNRESOLVED_DEPENDENCIES_VAR unresolved_dependencies)
endif()
if(unresolved_dependencies)
  list(JOIN unresolved_dependencies ", " unresolved_text)
  message(FATAL_ERROR "unresolved SERVER-TEST runtime dependencies: ${{unresolved_text}}")
endif()
list(REMOVE_DUPLICATES resolved_dependencies)
list(SORT resolved_dependencies)
file(WRITE "${{report_path}}" "")
foreach(dependency IN LISTS resolved_dependencies)
  file(APPEND "${{report_path}}" "${{dependency}}\n")
endforeach()
"""
    helper_path.write_text(helper, encoding="utf-8")
    run_process(["cmake", "-P", str(helper_path)], expected_codes={0}, timeout=90)
    dependencies = [
        Path(line)
        for line in report_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not dependencies:
        raise BundleError("runtime dependency resolver returned no dependencies")
    return dependencies


def dependency_report(dependencies: list[Path], os_name: str) -> str:
    lines = [
        "# Resolved runtime dependency closure from CMake file(GET_RUNTIME_DEPENDENCIES).",
        "# Paths identify the exact hosted build environment; no dependency is implied by name alone.",
    ]
    if os_name == "windows":
        lines.append(
            "# Windows/System32 and Windows API-set DLLs are OS-supplied and excluded "
            "from the redistributable dependency closure."
        )
        lines.append(
            "# Every non-system DLL listed below is bundled beside rdp-server.exe."
        )
    lines.extend(str(path) for path in dependencies)
    return "\n".join(lines) + "\n"


def windows_runtime_dependency_payloads(
    dependencies: list[Path],
) -> list[tuple[str, Path]]:
    payloads: list[tuple[str, Path]] = []
    seen_names: set[str] = set()
    for dependency in dependencies:
        if not dependency.is_file() or dependency.is_symlink():
            raise BundleError(
                f"Windows runtime dependency is not a regular file: {dependency.name}"
            )
        name = dependency.name
        if re.fullmatch(r"[A-Za-z0-9_.+\-]+\.dll", name, re.IGNORECASE) is None:
            raise BundleError(f"unsupported Windows runtime dependency name: {name}")
        folded = name.casefold()
        if folded in seen_names:
            raise BundleError(f"duplicate Windows runtime DLL basename: {name}")
        seen_names.add(folded)
        payloads.append((f"bin/{name}", dependency))
    payloads.sort(key=lambda item: item[0].casefold())
    return payloads


def sample_config(os_name: str) -> str:
    if os_name == "windows":
        certificate = r"C:\replace\rdp-server-test\server.crt"
        private_key = r"C:\replace\rdp-server-test\server.key"
    else:
        certificate = "/replace/rdp-server-test/server.crt"
        private_key = "/replace/rdp-server-test/server.key"
    return (
        "# Safe syntax-only SERVER-TEST example. No credentials are embedded.\n"
        "# This bundled example cannot authorize serve; replace paths only for offline credential checks.\n"
        "listen_address=127.0.0.1\n"
        "listen_port=33989\n"
        f"tls_certificate={certificate}\n"
        f"tls_private_key={private_key}\n"
        "authentication=required\n"
        "os_authorization=required\n"
        "max_connections=1\n"
    )


def install_contract(os_name: str) -> dict[str, object]:
    if os_name == "linux":
        return {
            "owner": "R5",
            "mode": "extract-only-preview",
            "executable_destination": "~/.local/share/rdp-server-test/bin/rdp-server",
            "config_destination": "~/.config/rdp-server-test/server.conf.example",
            "service_template": "platform/linux/rdp-server-test.service",
            "service_registration": False,
            "autostart": False,
        }
    if os_name == "windows":
        return {
            "owner": "R6",
            "mode": "per-user-script-preview",
            "install_root": r"%LOCALAPPDATA%\RDP-server\server-test",
            "executable_destination": r"%LOCALAPPDATA%\RDP-server\server-test\bin\rdp-server.exe",
            "config_destination": r"%LOCALAPPDATA%\RDP-server\server-test\config\rdp-server.conf.example",
            "lifecycle_script": "platform/windows/rdp-server-test.ps1",
            "service_template": None,
            "service_registration": False,
            "firewall_rules": False,
            "autostart": False,
        }
    return {
        "owner": "R7",
        "mode": "extract-only-preview",
        "executable_destination": "~/Library/Application Support/RDP-server/server-test/bin/rdp-server",
        "config_destination": "~/Library/Application Support/RDP-server/server-test/config/rdp-server.conf.example",
        "service_template": None,
        "service_registration": False,
        "autostart": False,
        "launch_agent_label": MACOS_LAUNCH_AGENT_LABEL,
        "launch_agent_helper": MACOS_LAUNCH_AGENT_HELPER,
        "launch_agent_registration": False,
        "launch_agent_run_at_load": False,
        "launch_agent_keep_alive": False,
    }


def bundle_readme(
    artifact_name: str,
    git_sha: str,
    os_name: str,
    architecture: str,
    compiler: dict[str, str],
) -> str:
    contract = install_contract(os_name)
    if os_name == "linux":
        native_note = (
            "Linux additionally carries R5's disabled user-service template, but extraction does not "
            "install, enable, or start it."
        )
    elif os_name == "macos":
        native_note = (
            "macOS additionally carries R7's LaunchAgent renderer/validator. It writes only an "
            "explicit output file, refuses the user's Library/LaunchAgents registration path, "
            "and never registers or starts a job. The rendered job is Aqua-only with "
            "RunAtLoad=false and KeepAlive=false."
        )
    else:
        native_note = (
            "Windows carries R6's per-user PowerShell lifecycle verifier plus every resolved "
            "non-system runtime DLL beside rdp-server.exe. It never registers a service, "
            "scheduled task, firewall rule, login item, or autostart entry."
        )

    windows_lifecycle = ""
    if os_name == "windows":
        windows_lifecycle = """
Use the adjacent *-lifecycle.ps1 copy, or the identical script inside the
archive, with -Action Install -ArchivePath <zip>. Install/Verify/Status/Stop/
Uninstall operate only below %LOCALAPPDATA%\\RDP-server\\server-test and
reject reparse points, unsafe archive paths, checksum mismatches, modified
installed trees, or missing runtime DLLs. -Action Start intentionally returns
exit 3 and reports that genuine Windows R2 SSPI/CredSSP SID-bound admission and
serialized R10 interactive-session ownership are unavailable; it never invokes
rdp-server.exe.
"""

    macos_launch_agent = ""
    if os_name == "macos":
        macos_launch_agent = f"""
## Optional macOS GUI-user LaunchAgent

Place the verified artifact contents at
`~/Library/Application Support/RDP-server/server-test/`. Render the plist to
a review location first:

```sh
python3 tools/macos_test_launch_agent.py render --home "$HOME" \\
  --output ./org.rdpserver.server-test.plist
python3 tools/macos_test_launch_agent.py validate --home "$HOME" \\
  --plist ./org.rdpserver.server-test.plist
```

The helper refuses to write directly to `~/Library/LaunchAgents`; it never
calls a service manager. After inspection, manual registration may copy the
plist there and use `launchctl bootstrap gui/$(id -u) ...`. Registration does
not start the job because `RunAtLoad=false`, `KeepAlive=false`, and there
are no socket/MachService triggers. Manual `kickstart` is the only intended
start action. At this preview revision the `serve` command still fails closed
with exit 2; do not treat registration as native-server readiness. Stop with
`launchctl kill SIGTERM gui/$(id -u)/{MACOS_LAUNCH_AGENT_LABEL}`; uninstall
with `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/{MACOS_LAUNCH_AGENT_LABEL}.plist`
and then remove that plist. Never use a LaunchDaemon or `sudo`.
"""
    return f"""# SERVER-TEST startup-disabled preview

**Artifact:** `{artifact_name}`
**Exact Git SHA:** `{git_sha}`
**Platform / architecture:** `{os_name} / {architecture}`
**Compiler:** `{compiler['id']} {compiler['version']}` ({compiler['generator']})
**Build configuration:** `{compiler['build_configuration']}`

This archive contains the actual compiled `rdp-server` executable. It is **not**
the protocol SDK ZIP and it is **not production-ready**. The current executable
has no serving command: `rdp-server serve` must fail closed without binding a
port. A successful offline check does not authorize deployment.

## Install

Treat the ZIP itself as the installer boundary. Verify the adjacent outer
SHA-256 file, inspect `metadata/SHA256SUMS.txt`, then extract the one top-level
artifact directory into a private user-owned test location. Extraction performs
no command execution, service registration, login integration, autostart,
desktop capture, input injection, firewall mutation, or network bind. The
manifest records the platform-owner destination contract. {native_note}
{windows_lifecycle}

## Start

**Disabled. Do not enable a service from this preview.** `bin/rdp-server --help`,
`--version`, and offline configuration checks are supported. An unconfigured
`bin/rdp-server serve` is expected to exit with code 2 and a refusal message.
No RUNNABLE human-test prerelease may be published until R10 supplies secure
runtime startup, exact-head CI is green, and the owner explicitly accepts it.

## Stop

No service or background process is installed or started, so there is nothing
to stop. If a human manually launches an unsupported command, terminate that
foreground process before removing the extracted directory.

## Uninstall

Delete only the extracted SERVER-TEST top-level directory after verifying its
manifest/checksums. The CI smoke performs identical install twice and uninstall
twice to prove the extraction-only lifecycle is idempotent. No system service,
LaunchAgent/LaunchDaemon, Windows service, scheduled task, or login item is
created by this artifact.
{macos_launch_agent}
## Configuration and dependencies

`config/rdp-server.conf.example` is a loopback-only syntax sample containing
placeholder paths, never credentials. `metadata/DEPENDENCIES.txt` records the
runtime dependency closure resolved on the exact hosted build. Platform-native
desktop/capture/input libraries that are not linked into this executable are
not claimed merely because component code exists elsewhere in the repository.
"""


def mode_for_relative(relative_path: str) -> int:
    if relative_path.startswith("bin/rdp-server") and not relative_path.endswith(".dll"):
        return 0o755
    if relative_path.endswith(".conf.example"):
        return 0o600
    return 0o644


def scan_for_secrets(relative_path: str, data: bytes) -> None:
    lowered = relative_path.lower()
    for suffix in FORBIDDEN_PAYLOAD_SUFFIXES:
        if lowered.endswith(suffix):
            raise BundleError(f"forbidden sensitive payload type: {relative_path}")
    for marker in FORBIDDEN_BYTE_MARKERS:
        if marker in data:
            raise BundleError(f"sensitive marker detected in {relative_path}")
    for pattern in TOKEN_PATTERNS:
        if pattern.search(data) is not None:
            raise BundleError(f"credential-like token detected in {relative_path}")


def write_payload_file(root: Path, relative_path: str, data: bytes, mode: int) -> None:
    if not safe_relative_path(relative_path):
        raise BundleError(f"unsafe bundle path: {relative_path}")
    scan_for_secrets(relative_path, data)
    destination = root / PurePosixPath(relative_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    if os.name != "nt":
        destination.chmod(mode)


def payload_metadata(root: Path, relative_paths: list[str]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for relative_path in sorted(relative_paths):
        path = root / PurePosixPath(relative_path)
        data = path.read_bytes()
        result[relative_path] = {
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "mode": f"{mode_for_relative(relative_path):04o}",
        }
    return result


def checksum_text(root: Path, relative_paths: list[str]) -> str:
    return "".join(
        f"{sha256_file(root / PurePosixPath(relative_path))}  {relative_path}\n"
        for relative_path in sorted(relative_paths)
    )


def write_zip(archive_path: Path, artifact_root: Path, artifact_name: str) -> None:
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(item for item in artifact_root.rglob("*") if item.is_file()):
            relative = path.relative_to(artifact_root).as_posix()
            info = zipfile.ZipInfo(
                f"{artifact_name}/{relative}", date_time=(1980, 1, 1, 0, 0, 0)
            )
            mode = stat.S_IMODE(path.stat().st_mode) if os.name != "nt" else 0o644
            if relative.startswith("bin/rdp-server") and not relative.endswith(".dll"):
                mode = 0o755
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def parse_checksum_file(data: bytes) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in data.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or not safe_relative_path(match.group(2)):
            raise BundleError("invalid internal checksum manifest")
        if match.group(2) in checksums:
            raise BundleError("duplicate internal checksum entry")
        checksums[match.group(2)] = match.group(1)
    if not checksums:
        raise BundleError("empty internal checksum manifest")
    return checksums


def validated_archive(archive_path: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    if not archive_path.is_file() or archive_path.is_symlink():
        raise BundleError("SERVER-TEST archive is missing or symlinked")
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise BundleError("duplicate archive member")
        if any(info.is_dir() or info.file_size > MAX_MEMBER_BYTES for info in infos):
            raise BundleError("unsupported archive member")
        if any(not safe_relative_path(name) for name in names):
            raise BundleError("unsafe archive member")

        manifest_names = [
            name
            for name in names
            if name.endswith("/metadata/SERVER-TEST-MANIFEST.json")
        ]
        if len(manifest_names) != 1:
            raise BundleError("SERVER-TEST manifest missing or duplicated")
        manifest_name = manifest_names[0]
        artifact_name = manifest_name.split("/", 1)[0]
        if archive_path.name != artifact_name + ".zip":
            raise BundleError("archive filename does not match manifest root")

        files = {name: archive.read(name) for name in names}
        manifest = json.loads(files[manifest_name])
        required_manifest_keys = {
            "schema_version",
            "artifact_family",
            "artifact_name",
            "classification",
            "production_ready",
            "startup_enabled",
            "exact_git_sha",
            "version",
            "platform",
            "architecture",
            "abi",
            "compiler",
            "build_configuration",
            "executable",
            "runtime_dependencies",
            "install",
            "files",
        }
        if set(manifest) != required_manifest_keys:
            raise BundleError("unknown SERVER-TEST manifest contract")
        if (
            manifest["schema_version"] != SCHEMA_VERSION
            or manifest["artifact_family"] != ARTIFACT_FAMILY
            or manifest["artifact_name"] != artifact_name
            or manifest["classification"] != "startup-disabled-preview"
            or manifest["production_ready"] is not False
            or manifest["startup_enabled"] is not False
            or not valid_source_sha(manifest["exact_git_sha"])
        ):
            raise BundleError("invalid SERVER-TEST identity")

        checksum_relative = "metadata/SHA256SUMS.txt"
        checksum_name = f"{artifact_name}/{checksum_relative}"
        if checksum_name not in files:
            raise BundleError("internal SHA256SUMS missing")
        checksums = parse_checksum_file(files[checksum_name])
        payload = manifest["files"]
        if not isinstance(payload, dict) or not payload:
            raise BundleError("empty SERVER-TEST payload manifest")
        runtime_dependencies = manifest["runtime_dependencies"]
        if (
            not isinstance(runtime_dependencies, list)
            or any(not isinstance(name, str) for name in runtime_dependencies)
            or len({name.casefold() for name in runtime_dependencies})
            != len(runtime_dependencies)
        ):
            raise BundleError("invalid SERVER-TEST runtime dependency list")
        if manifest["platform"] == "windows":
            install = manifest["install"]
            if (
                not isinstance(install, dict)
                or install.get("owner") != "R6"
                or install.get("mode") != "per-user-script-preview"
                or install.get("lifecycle_script")
                != "platform/windows/rdp-server-test.ps1"
                or install.get("service_registration") is not False
                or install.get("firewall_rules") is not False
                or install.get("autostart") is not False
            ):
                raise BundleError("unsafe Windows SERVER-TEST install contract")
            if "platform/windows/rdp-server-test.ps1" not in payload:
                raise BundleError("Windows SERVER-TEST lifecycle script missing")
            expected_runtime_payloads: set[str] = set()
            for name in runtime_dependencies:
                if (
                    re.fullmatch(
                        r"[A-Za-z0-9_.+\-]+\.dll", name, re.IGNORECASE
                    )
                    is None
                ):
                    raise BundleError("invalid Windows runtime dependency name")
                expected_runtime_payloads.add(f"bin/{name}")
            if not expected_runtime_payloads.issubset(payload):
                raise BundleError("required Windows runtime DLL is not bundled")
        manifest_relative = "metadata/SERVER-TEST-MANIFEST.json"
        expected_checksum_paths = set(payload) | {manifest_relative}
        if set(checksums) != expected_checksum_paths:
            raise BundleError("internal checksum path set mismatch")
        expected_archive_names = {
            f"{artifact_name}/{relative}" for relative in payload
        } | {manifest_name, checksum_name}
        if set(names) != expected_archive_names:
            raise BundleError("archive contains unmanifested content")

        for relative_path, metadata in payload.items():
            if not safe_relative_path(relative_path) or not isinstance(metadata, dict):
                raise BundleError("invalid payload manifest entry")
            member_name = f"{artifact_name}/{relative_path}"
            data = files.get(member_name)
            if data is None:
                raise BundleError("missing payload member")
            scan_for_secrets(relative_path, data)
            if metadata.get("bytes") != len(data) or metadata.get("sha256") != sha256_bytes(data):
                raise BundleError(f"payload digest mismatch: {relative_path}")
            if checksums[relative_path] != sha256_bytes(data):
                raise BundleError(f"checksum mismatch: {relative_path}")
        if checksums[manifest_relative] != sha256_bytes(files[manifest_name]):
            raise BundleError("manifest checksum mismatch")
        return manifest, files


def install_archive(archive_path: Path, destination_parent: Path) -> Path:
    manifest, files = validated_archive(archive_path)
    artifact_name = str(manifest["artifact_name"])
    install_root = destination_parent / artifact_name
    destination_parent.mkdir(parents=True, exist_ok=True)
    if destination_parent.is_symlink() or install_root.is_symlink():
        raise BundleError("symlinked install destination")
    for member_name, data in files.items():
        relative = member_name.split("/", 1)[1]
        target = install_root / PurePosixPath(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise BundleError("symlinked installed member")
        if target.exists():
            if not target.is_file() or target.read_bytes() != data:
                raise BundleError("existing install differs from verified archive")
        else:
            target.write_bytes(data)
        mode_text = None
        if relative in manifest["files"]:
            mode_text = manifest["files"][relative].get("mode")
        if os.name != "nt":
            target.chmod(int(mode_text, 8) if mode_text else 0o644)
    verify_installed_tree(archive_path, install_root)
    return install_root


def verify_installed_tree(archive_path: Path, install_root: Path) -> None:
    manifest, files = validated_archive(archive_path)
    expected_relative = {name.split("/", 1)[1] for name in files}
    actual_relative = {
        path.relative_to(install_root).as_posix()
        for path in install_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_relative != expected_relative:
        raise BundleError("installed tree contains missing or unexpected files")
    for member_name, expected in files.items():
        relative = member_name.split("/", 1)[1]
        path = install_root / PurePosixPath(relative)
        if not path.is_file() or path.is_symlink() or path.read_bytes() != expected:
            raise BundleError(f"installed content mismatch: {relative}")
        if os.name != "nt" and relative in manifest["files"]:
            expected_mode = int(manifest["files"][relative]["mode"], 8)
            if stat.S_IMODE(path.stat().st_mode) != expected_mode:
                raise BundleError(f"installed mode mismatch: {relative}")


def uninstall_archive(archive_path: Path, destination_parent: Path) -> None:
    manifest, _ = validated_archive(archive_path)
    install_root = destination_parent / str(manifest["artifact_name"])
    if not install_root.exists():
        return
    if install_root.is_symlink():
        raise BundleError("symlinked uninstall destination")
    verify_installed_tree(archive_path, install_root)
    shutil.rmtree(install_root)


def make_config_private(config_path: Path) -> None:
    if os.name != "nt":
        config_path.chmod(0o600)
        return
    username = os.environ.get("USERNAME")
    if not username:
        raise BundleError("Windows username unavailable for config ACL smoke")
    run_process(
        ["icacls", str(config_path), "/inheritance:r", "/grant:r", f"{username}:(F)"],
        expected_codes={0},
    )


def assert_bindable_loopback_port(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))


def next_loopback_probe_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def smoke_archive(archive_path: Path, output_directory: Path) -> dict[str, str]:
    manifest, _ = validated_archive(archive_path)
    os_name = str(manifest["platform"])
    executable_relative = str(manifest["executable"])
    smoke_parent = output_directory / "smoke-install"
    if smoke_parent.exists():
        shutil.rmtree(smoke_parent)

    probe_port = next_loopback_probe_port()
    install_root = install_archive(archive_path, smoke_parent)
    install_archive(archive_path, smoke_parent)
    assert_bindable_loopback_port(probe_port)

    executable = install_root / PurePosixPath(executable_relative)
    if not executable.is_file() or executable.is_symlink():
        raise BundleError("installed executable missing")
    actual_architecture, actual_abi = binary_identity(executable, os_name)
    if actual_architecture != manifest["architecture"] or actual_abi != manifest["abi"]:
        raise BundleError("installed executable ABI does not match manifest")

    environment = dict(os.environ)
    if os_name == "windows":
        system_root = Path(environment.get("SystemRoot", r"C:\Windows"))
        environment["PATH"] = os.pathsep.join(
            [str(executable.parent), str(system_root / "System32"), str(system_root)]
        )
    else:
        environment["PATH"] = (
            str(executable.parent) + os.pathsep + environment.get("PATH", "")
        )
    version_result = run_process(
        [str(executable), "--version"], expected_codes={0}, environment=environment
    )
    expected_version = f"rdp-server {manifest['version']}\n".encode()
    if version_result.stdout.replace(b"\r\n", b"\n") != expected_version:
        raise BundleError("unexpected --version output")

    help_result = run_process(
        [str(executable), "--help"], expected_codes={0}, environment=environment
    )
    if b"Usage: rdp-server" not in help_result.stdout:
        raise BundleError("--help output missing usage contract")

    config_path = install_root / "config/rdp-server.conf.example"
    make_config_private(config_path)
    config_result = run_process(
        [str(executable), "--check-config", str(config_path)],
        expected_codes={0},
        environment=environment,
    )
    if b"service remains disabled" not in config_result.stdout:
        raise BundleError("config validation did not retain disabled status")

    serve_result = run_process(
        [str(executable), "serve"], expected_codes={2}, environment=environment
    )
    if b"refusing to start" not in serve_result.stderr:
        raise BundleError("unconfigured serve did not fail closed")

    # R10 now has an explicit Linux serve --config path. The packaged
    # syntax-only sample must remain non-authorizing and must never become a
    # listener-capable configuration merely because the runtime gains startup.
    sample_serve_result = run_process(
        [str(executable), "serve", "--config", str(config_path)],
        expected_codes={2},
        environment=environment,
        timeout=5,
    )
    if b"refusing to start" not in sample_serve_result.stderr:
        raise BundleError("packaged sample serve did not fail closed")
    assert_bindable_loopback_port(probe_port)

    for output in (
        version_result.stdout,
        version_result.stderr,
        help_result.stdout,
        help_result.stderr,
        config_result.stdout,
        config_result.stderr,
        serve_result.stdout,
        serve_result.stderr,
        sample_serve_result.stdout,
        sample_serve_result.stderr,
    ):
        scan_for_secrets("captured-smoke-log", output)

    uninstall_archive(archive_path, smoke_parent)
    uninstall_archive(archive_path, smoke_parent)
    install_root = install_archive(archive_path, smoke_parent)
    verify_installed_tree(archive_path, install_root)
    uninstall_archive(archive_path, smoke_parent)
    if install_root.exists():
        raise BundleError("SERVER-TEST uninstall left installed content")

    return {
        "archive_integrity": "PASS",
        "executable_abi": "PASS",
        "version": "PASS",
        "help": "PASS",
        "config_validation": "PASS",
        "unconfigured_serve_refusal": "PASS",
        "packaged_sample_serve_refusal": "PASS",
        "install_no_listener": "PASS",
        "idempotent_install_uninstall": "PASS",
        "autostart_absent": "PASS",
        "secret_scan": "PASS",
    }


def build_bundle(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    source_root = args.source_root.resolve()
    build_root = args.build_root.resolve()
    output_directory = args.output_dir.resolve()
    if not valid_source_sha(args.git_sha):
        raise BundleError("exact 40-character lowercase Git SHA required")
    if build_root == source_root or source_root not in build_root.parents:
        raise BundleError("SERVER-TEST output must reuse the checkout-local build root")
    if output_directory != build_root / "server-test":
        raise BundleError("SERVER-TEST output must be build/server-test")

    if output_directory.exists():
        shutil.rmtree(output_directory)
    output_directory.mkdir(parents=True)

    os_name = normalized_platform()
    version = project_version(source_root)
    executable = executable_path(build_root, args.build_config, os_name)
    architecture, abi = binary_identity(executable, os_name)
    compiler = compiler_identity(build_root, args.build_config)
    dependencies = cmake_runtime_dependencies(
        executable, output_directory / "dependency-scan"
    )
    windows_runtime_payloads = (
        windows_runtime_dependency_payloads(dependencies)
        if os_name == "windows"
        else []
    )
    windows_lifecycle_bytes: bytes | None = None
    if os_name == "windows":
        lifecycle_source = source_root / "packaging/windows/rdp-server-test.ps1"
        if not lifecycle_source.is_file() or lifecycle_source.is_symlink():
            raise BundleError("R6 Windows lifecycle script missing")
        windows_lifecycle_bytes = lifecycle_source.read_bytes()

    artifact_name = f"rdp-server-test-{version}-{os_name}-{architecture}-{args.git_sha[:12]}"
    artifact_root = output_directory / "stage" / artifact_name
    artifact_root.mkdir(parents=True)
    executable_relative = "bin/rdp-server.exe" if os_name == "windows" else "bin/rdp-server"
    payload_paths: list[str] = []

    def add(relative_path: str, data: bytes) -> None:
        write_payload_file(artifact_root, relative_path, data, mode_for_relative(relative_path))
        payload_paths.append(relative_path)

    add(executable_relative, executable.read_bytes())
    add("config/rdp-server.conf.example", sample_config(os_name).encode())
    add(
        "metadata/DEPENDENCIES.txt",
        dependency_report(dependencies, os_name).encode(),
    )
    add(
        "docs/INSTALL-START-STOP-UNINSTALL.md",
        bundle_readme(artifact_name, args.git_sha, os_name, architecture, compiler).encode(),
    )
    for source_name, bundle_name in (
        ("LICENSE", "licenses/LICENSE"),
        ("NOTICE", "licenses/NOTICE"),
        ("docs/THIRD_PARTY.md", "licenses/THIRD_PARTY.md"),
    ):
        source_path = source_root / source_name
        if not source_path.is_file():
            raise BundleError(f"required license material missing: {source_name}")
        add(bundle_name, source_path.read_bytes())

    if os_name == "macos":
        launch_agent_helper = source_root / "scripts/macos_test_launch_agent.py"
        if not launch_agent_helper.is_file():
            raise BundleError("R7 macOS LaunchAgent helper missing")
        add(MACOS_LAUNCH_AGENT_HELPER, launch_agent_helper.read_bytes())

    if os_name == "windows":
        assert windows_lifecycle_bytes is not None
        add("platform/windows/rdp-server-test.ps1", windows_lifecycle_bytes)
        for relative_path, dependency in windows_runtime_payloads:
            add(relative_path, dependency.read_bytes())

    if os_name == "linux":
        r5_service = source_root / "packaging/linux/rdp-server-test.service"
        if not r5_service.is_file():
            raise BundleError("R5 Linux disabled service template missing")
        add("platform/linux/rdp-server-test.service", r5_service.read_bytes())

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_name": artifact_name,
        "classification": "startup-disabled-preview",
        "production_ready": False,
        "startup_enabled": False,
        "exact_git_sha": args.git_sha,
        "version": version,
        "platform": os_name,
        "architecture": architecture,
        "abi": abi,
        "compiler": compiler,
        "build_configuration": args.build_config,
        "executable": executable_relative,
        "runtime_dependencies": sorted({path.name for path in dependencies}),
        "install": install_contract(os_name),
        "files": payload_metadata(artifact_root, payload_paths),
    }
    manifest_relative = "metadata/SERVER-TEST-MANIFEST.json"
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    write_payload_file(artifact_root, manifest_relative, manifest_bytes, 0o644)

    checksum_relative = "metadata/SHA256SUMS.txt"
    checksum_bytes = checksum_text(artifact_root, payload_paths + [manifest_relative]).encode()
    write_payload_file(artifact_root, checksum_relative, checksum_bytes, 0o644)

    archive_path = output_directory / f"{artifact_name}.zip"
    write_zip(archive_path, artifact_root, artifact_name)
    validated_archive(archive_path)

    outer_checksum_path = archive_path.with_suffix(".zip.sha256")
    outer_checksum_path.write_text(
        f"{sha256_file(archive_path)}  {archive_path.name}\n", encoding="utf-8"
    )
    if os_name == "windows":
        assert windows_lifecycle_bytes is not None
        lifecycle_output = output_directory / f"{artifact_name}-lifecycle.ps1"
        lifecycle_output.write_bytes(windows_lifecycle_bytes)
        lifecycle_checksum = lifecycle_output.with_suffix(".ps1.sha256")
        lifecycle_checksum.write_text(
            f"{sha256_file(lifecycle_output)}  {lifecycle_output.name}\n",
            encoding="utf-8",
        )
    checks = smoke_archive(archive_path, output_directory)
    if os_name == "windows":
        checks["windows_runtime_dlls_bundled"] = "PASS"
        checks["windows_user_lifecycle"] = "PASS"
    status_path = output_directory / f"{artifact_name}-STATUS.json"
    status = {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_name": artifact_name,
        "exact_git_sha": args.git_sha,
        "platform": os_name,
        "architecture": architecture,
        "abi": abi,
        "compiler": compiler,
        "build_configuration": args.build_config,
        "archive_sha256": sha256_file(archive_path),
        "status": "PASS",
        "startup_status": "DISABLED",
        "deployment_status": "NOT VERIFIED; NOT CLAIMED",
        "checks": checks,
    }
    status_path.write_text(
        json.dumps(status, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(f"SERVER-TEST PASS {artifact_name} sha={args.git_sha} startup=DISABLED")
    return archive_path, outer_checksum_path, status_path


def verify_status_directory(directory: Path, expected_sha: str) -> None:
    if not valid_source_sha(expected_sha):
        raise BundleError("invalid expected SHA")
    status_paths = sorted(directory.rglob("rdp-server-test-*-STATUS.json"))
    statuses = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in status_paths
    ]
    if len(statuses) != 3:
        raise BundleError(f"expected three SERVER-TEST statuses, found {len(statuses)}")
    platforms = {status.get("platform") for status in statuses}
    if platforms != {"linux", "windows", "macos"}:
        raise BundleError(f"incomplete SERVER-TEST platform set: {sorted(platforms)}")
    for status in statuses:
        if (
            status.get("artifact_family") != ARTIFACT_FAMILY
            or status.get("exact_git_sha") != expected_sha
            or status.get("status") != "PASS"
            or status.get("startup_status") != "DISABLED"
            or status.get("deployment_status") != "NOT VERIFIED; NOT CLAIMED"
        ):
            raise BundleError("SERVER-TEST status acceptance mismatch")
        artifact_name = status.get("artifact_name")
        if not isinstance(artifact_name, str):
            raise BundleError("SERVER-TEST artifact name missing from status")
        archives = list(directory.rglob(artifact_name + ".zip"))
        checksum_files = list(directory.rglob(artifact_name + ".zip.sha256"))
        if len(archives) != 1 or len(checksum_files) != 1:
            raise BundleError("SERVER-TEST archive/checksum pair missing from status set")
        archive_digest = sha256_file(archives[0])
        if archive_digest != status.get("archive_sha256"):
            raise BundleError("SERVER-TEST outer archive digest differs from status")
        expected_checksum = f"{archive_digest}  {archives[0].name}\n"
        if checksum_files[0].read_text(encoding="utf-8") != expected_checksum:
            raise BundleError("SERVER-TEST adjacent SHA-256 file mismatch")
        manifest, _ = validated_archive(archives[0])
        if (
            manifest.get("exact_git_sha") != expected_sha
            or manifest.get("platform") != status.get("platform")
            or manifest.get("architecture") != status.get("architecture")
        ):
            raise BundleError("SERVER-TEST downloaded manifest/status mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("build")
    builder.add_argument("--source-root", type=Path, required=True)
    builder.add_argument("--build-root", type=Path, required=True)
    builder.add_argument("--git-sha", required=True)
    builder.add_argument("--build-config", default="Release")
    builder.add_argument("--output-dir", type=Path, required=True)
    verifier = commands.add_parser("verify-statuses")
    verifier.add_argument("--directory", type=Path, required=True)
    verifier.add_argument("--git-sha", required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            build_bundle(args)
        else:
            verify_status_directory(args.directory, args.git_sha)
    except (
        BundleError,
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
        zipfile.BadZipFile,
    ) as error:
        print(f"SERVER-TEST FAIL: {error}; no deployment success is claimed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
