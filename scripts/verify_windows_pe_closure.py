#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify recursive non-system PE import closure in an extracted Windows GUI."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess

SYSTEM_DLLS = frozenset({
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "cabinet.dll",
    "cfgmgr32.dll", "comctl32.dll", "comdlg32.dll", "crypt32.dll",
    "cryptbase.dll", "d3d11.dll", "d3d12.dll", "dbghelp.dll", "dnsapi.dll",
    "dwmapi.dll", "dwrite.dll", "dxgi.dll", "dxva2.dll", "gdi32.dll",
    "hid.dll", "imm32.dll", "iphlpapi.dll", "kernel32.dll", "mf.dll",
    "mfcore.dll", "mfplat.dll", "mfreadwrite.dll", "mpr.dll", "msvcrt.dll",
    "netapi32.dll", "normaliz.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll",
    "powrprof.dll", "propsys.dll", "psapi.dll", "rpcrt4.dll", "secur32.dll",
    "setupapi.dll", "shell32.dll", "shlwapi.dll", "shcore.dll", "ucrtbase.dll",
    "user32.dll", "userenv.dll", "usp10.dll", "uxtheme.dll", "version.dll",
    "winhttp.dll", "wininet.dll", "winmm.dll", "winspool.drv", "wintrust.dll",
    "ws2_32.dll", "wtsapi32.dll",
})
MAX_PE_FILES = 2048


class WindowsPeClosureError(ValueError):
    """The extracted portable GUI has an unresolved or unsafe PE dependency."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise WindowsPeClosureError(reason)


def is_system_import(name: str) -> bool:
    folded = name.casefold()
    return (folded.startswith("api-ms-win-") or
            folded.startswith("ext-ms-win-") or
            folded in SYSTEM_DLLS)


def parse_imports(output: str) -> tuple[str, ...]:
    imports: list[str] = []
    for line in output.splitlines():
        match = re.fullmatch(
            r"\s*DLL Name:\s*([A-Za-z0-9_.+-]+)\s*", line,
            flags=re.IGNORECASE)
        if match:
            imports.append(match.group(1))
    return tuple(imports)


def collect_pe_files(root: Path) -> list[Path]:
    require(root.is_dir() and not root.is_symlink(),
            "extracted GUI root must be a regular directory")
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(),
                f"symlink is forbidden in extracted GUI tree: {path}")
        if not path.is_file() or path.suffix.casefold() not in (".exe", ".dll"):
            continue
        with path.open("rb") as source:
            require(source.read(2) == b"MZ", f"expected PE image: {path}")
        files.append(path)
        require(len(files) <= MAX_PE_FILES,
                "too many PE images in portable GUI tree")
    require(any(path.suffix.casefold() == ".exe" for path in files),
            "portable GUI tree contains no executable")
    return files


def verify_closure(root: Path, inspector) -> tuple[int, int]:
    files = collect_pe_files(root)
    bundled: dict[str, list[Path]] = {}
    for path in files:
        bundled.setdefault(path.name.casefold(), []).append(path)

    missing: list[str] = []
    import_count = 0
    for path in files:
        for dependency in inspector(path):
            require(re.fullmatch(r"[A-Za-z0-9_.+-]+", dependency) is not None,
                    f"unsafe PE import name: {dependency!r}")
            import_count += 1
            if is_system_import(dependency):
                continue
            if dependency.casefold() not in bundled:
                missing.append(
                    f"{path.relative_to(root).as_posix()} -> {dependency}")
    require(not missing,
            "unbundled PE imports: " + "; ".join(sorted(missing)))
    return len(files), import_count


def objdump_imports(path: Path, objdump: Path) -> tuple[str, ...]:
    result = subprocess.run(
        [str(objdump), "-p", str(path)], capture_output=True, text=True,
        timeout=30, check=True, stdin=subprocess.DEVNULL)
    return parse_imports(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--objdump", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        require(arguments.objdump.is_file(),
                "PE inspection tool must be a regular file")
        pe_count, import_count = verify_closure(
            arguments.root,
            lambda path: objdump_imports(path, arguments.objdump))
    except (OSError, subprocess.SubprocessError, WindowsPeClosureError) as error:
        parser.exit(1, f"Windows PE closure rejection: {error}\n")
    print(f"Windows PE closure PASS: {pe_count} images, "
          f"{import_count} imports inspected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
