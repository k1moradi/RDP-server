#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render and validate the inert per-user macOS SERVER-TEST LaunchAgent."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import plistlib
import sys

LAUNCH_AGENT_LABEL = "org.rdpserver.server-test"
LAUNCH_AGENT_FILENAME = f"{LAUNCH_AGENT_LABEL}.plist"
SERVER_TEST_RELATIVE_ROOT = PurePosixPath(
    "Library/Application Support/RDP-server/server-test"
)
LAUNCH_AGENTS_RELATIVE_ROOT = PurePosixPath("Library/LaunchAgents")
MAXIMUM_PLIST_BYTES = 64 * 1024
EXPECTED_KEYS = frozenset(
    {
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "KeepAlive",
        "LimitLoadToSessionType",
        "ProcessType",
    }
)


class LaunchAgentError(RuntimeError):
    """Fail-closed LaunchAgent configuration error."""


def _absolute_home(value: str | Path) -> PurePosixPath:
    text = str(value)
    if "\x00" in text:
        raise LaunchAgentError("home path contains NUL")
    home = PurePosixPath(text)
    if not home.is_absolute() or home == PurePosixPath("/") or ".." in home.parts:
        raise LaunchAgentError("home path must be a non-root absolute path")
    return home


def expected_server_root(home: str | Path) -> PurePosixPath:
    return _absolute_home(home) / SERVER_TEST_RELATIVE_ROOT


def launch_agent_configuration(home: str | Path) -> dict[str, object]:
    executable = expected_server_root(home) / "bin/rdp-server"
    return {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [str(executable), "serve"],
        "RunAtLoad": False,
        "KeepAlive": False,
        "LimitLoadToSessionType": "Aqua",
        "ProcessType": "Interactive",
    }


def validate_configuration(
    configuration: object, home: str | Path
) -> dict[str, object]:
    if not isinstance(configuration, dict):
        raise LaunchAgentError("LaunchAgent plist root must be a dictionary")
    if set(configuration) != EXPECTED_KEYS:
        raise LaunchAgentError("LaunchAgent plist contains missing or unsupported keys")

    expected = launch_agent_configuration(home)
    if configuration.get("Label") != LAUNCH_AGENT_LABEL:
        raise LaunchAgentError("unexpected LaunchAgent label")
    if configuration.get("ProgramArguments") != expected["ProgramArguments"]:
        raise LaunchAgentError("LaunchAgent executable or arguments do not match")
    if configuration.get("RunAtLoad") is not False:
        raise LaunchAgentError("RunAtLoad must remain false")
    if configuration.get("KeepAlive") is not False:
        raise LaunchAgentError("KeepAlive must remain false")
    if configuration.get("LimitLoadToSessionType") != "Aqua":
        raise LaunchAgentError("LaunchAgent must be limited to the Aqua GUI session")
    if configuration.get("ProcessType") != "Interactive":
        raise LaunchAgentError("LaunchAgent process type must remain Interactive")
    return configuration


def parse_plist(data: bytes, home: str | Path) -> dict[str, object]:
    if not data or len(data) > MAXIMUM_PLIST_BYTES:
        raise LaunchAgentError("LaunchAgent plist size is invalid")
    try:
        configuration = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise LaunchAgentError("malformed LaunchAgent plist") from error
    return validate_configuration(configuration, home)


def _is_registration_destination(path: Path, home: str | Path) -> bool:
    try:
        # Resolve existing symlinked parents before checking the registration
        # boundary. Path.absolute() leaves those symlinks unresolved, allowing
        # a seemingly separate review location to write into LaunchAgents.
        output_path = path.resolve(strict=False)
        launch_agents_root = (
            Path(_absolute_home(home)) / LAUNCH_AGENTS_RELATIVE_ROOT
        ).resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise LaunchAgentError("unable to resolve LaunchAgent output path") from error
    # Any plist rendered beneath LaunchAgents is implicit installation,
    # regardless of its filename or nesting.
    return output_path.is_relative_to(launch_agents_root)


def render_plist(home: str | Path, output_path: Path) -> None:
    if _is_registration_destination(output_path, home):
        raise LaunchAgentError(
            "refusing to install directly into Library/LaunchAgents; render elsewhere first"
        )
    if output_path.exists() and output_path.is_symlink():
        raise LaunchAgentError("refusing symlinked LaunchAgent output")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    configuration = launch_agent_configuration(home)
    data = plistlib.dumps(configuration, fmt=plistlib.FMT_XML, sort_keys=True)
    parse_plist(data, home)
    output_path.write_bytes(data)
    if output_path.is_symlink():
        raise LaunchAgentError("LaunchAgent output became a symlink")
    output_path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    renderer = commands.add_parser("render")
    renderer.add_argument("--home", type=Path, default=Path.home())
    renderer.add_argument("--output", type=Path, required=True)

    validator = commands.add_parser("validate")
    validator.add_argument("--home", type=Path, default=Path.home())
    validator.add_argument("--plist", type=Path, required=True)

    arguments = parser.parse_args()
    try:
        if arguments.command == "render":
            render_plist(arguments.home, arguments.output)
        else:
            if not arguments.plist.is_file() or arguments.plist.is_symlink():
                raise LaunchAgentError("LaunchAgent plist must be a regular file")
            parse_plist(arguments.plist.read_bytes(), arguments.home)
    except (LaunchAgentError, OSError) as error:
        print(f"macOS SERVER-TEST LaunchAgent: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
