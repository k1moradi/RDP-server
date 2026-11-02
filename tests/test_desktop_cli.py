#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise shipped desktop CLI fail-closed paths without starting Qt or R1."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MAX_OUTPUT_BYTES = 4096
TIMEOUT_SECONDS = 10
SECRET_SENTINEL = "R9_SYNTHETIC_SECRET_SENTINEL_DO_NOT_LOG"


def run_case(executable: Path, arguments: list[str], input_data: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    # Every case in this test must terminate before QApplication construction.
    environment["QT_QPA_PLATFORM"] = "rdp-intentionally-invalid"
    completed = subprocess.run(
        [str(executable), *arguments],
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=TIMEOUT_SECONDS,
        env=environment,
    )
    if len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise AssertionError("desktop CLI emitted unbounded diagnostics")
    sentinel = SECRET_SENTINEL.encode("ascii")
    if sentinel in completed.stdout or sentinel in completed.stderr:
        raise AssertionError("desktop CLI reflected private argv/stdin data")
    return completed


def require_exit(
    executable: Path,
    arguments: list[str],
    expected_code: int,
    required_stderr: bytes | None = None,
    input_data: bytes = b"",
) -> None:
    completed = run_case(executable, arguments, input_data)
    if completed.returncode != expected_code:
        raise AssertionError("desktop CLI returned unexpected status")
    if required_stderr is not None and required_stderr not in completed.stderr:
        raise AssertionError("desktop CLI returned unexpected diagnostic category")


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    executable = Path(sys.argv[1])
    if not executable.is_file():
        return 2

    help_result = run_case(executable, ["--help"])
    if help_result.returncode != 0 or b"Usage: rdp-server-desktop" not in help_result.stdout:
        raise AssertionError("desktop help did not terminate before Qt")
    if help_result.stderr:
        raise AssertionError("desktop help unexpectedly wrote stderr")

    invalid_option = b"invalid or conflicting option"
    for arguments in (
        ["--unknown", SECRET_SENTINEL],
        ["--password", SECRET_SENTINEL],
        ["--password=" + SECRET_SENTINEL],
        ["--session-password", SECRET_SENTINEL],
        ["--username", "owner", "--username", "replacement"],
        ["--username", "owner/other"],
        ["--username", "owner\\other"],
        ["--username", "u" * 257],
        ["--enable", "--enable"],
        ["--password-stdin", "--password-stdin"],
        ["--help", "--enable"],
    ):
        require_exit(executable, arguments, 2, invalid_option)

    private_input_error = b"invalid private password input"
    malformed_inputs = (
        b"",
        b"\xed\xa0\x80\n",
        SECRET_SENTINEL.encode("ascii") + b"\x00tail\n",
        b"x" * 257 + b"\n",
    )
    for private_input in malformed_inputs:
        require_exit(
            executable,
            ["--password-stdin"],
            3,
            private_input_error,
            private_input,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
