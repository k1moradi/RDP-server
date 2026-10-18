#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline R7 LaunchAgent rendering and fail-closed validation tests."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument("--script", type=Path, required=True)
arguments, remaining = parser.parse_known_args()
spec = importlib.util.spec_from_file_location("macos_test_launch_agent", arguments.script)
launch_agent = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(launch_agent)


class MacosTestLaunchAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = Path("/Users/rdp-test-user")

    def test_rendered_agent_is_user_gui_only_and_startup_disabled(self) -> None:
        output = self.root / launch_agent.LAUNCH_AGENT_FILENAME
        launch_agent.render_plist(self.home, output)
        parsed = launch_agent.parse_plist(output.read_bytes(), self.home)

        self.assertEqual(parsed["Label"], launch_agent.LAUNCH_AGENT_LABEL)
        self.assertEqual(
            parsed["ProgramArguments"],
            [
                "/Users/rdp-test-user/Library/Application Support/"
                "RDP-server/server-test/bin/rdp-server",
                "serve",
            ],
        )
        self.assertIs(parsed["RunAtLoad"], False)
        self.assertIs(parsed["KeepAlive"], False)
        self.assertEqual(parsed["LimitLoadToSessionType"], "Aqua")
        self.assertEqual(parsed["ProcessType"], "Interactive")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_malformed_or_authority_expanding_agent_is_denied(self) -> None:
        base = launch_agent.launch_agent_configuration(self.home)
        cases = []

        run_at_load = dict(base)
        run_at_load["RunAtLoad"] = True
        cases.append(run_at_load)

        keep_alive = dict(base)
        keep_alive["KeepAlive"] = True
        cases.append(keep_alive)

        external_program = dict(base)
        external_program["ProgramArguments"] = ["/tmp/rdp-server", "serve"]
        cases.append(external_program)

        privileged = dict(base)
        privileged["UserName"] = "root"
        cases.append(privileged)

        network_trigger = dict(base)
        network_trigger["Sockets"] = {"Listener": {"SockServiceName": "3389"}}
        cases.append(network_trigger)

        mach_service = dict(base)
        mach_service["MachServices"] = {"org.rdpserver.server-test": True}
        cases.append(mach_service)

        for configuration in cases:
            with self.subTest(configuration=configuration):
                with self.assertRaises(launch_agent.LaunchAgentError):
                    launch_agent.validate_configuration(configuration, self.home)

    def test_renderer_refuses_implicit_registration_or_root_home(self) -> None:
        launch_agents = self.root / "Library/LaunchAgents"
        fake_home = self.root
        registration_path = launch_agents / launch_agent.LAUNCH_AGENT_FILENAME
        with self.assertRaisesRegex(
            launch_agent.LaunchAgentError, "refusing to install directly"
        ):
            launch_agent.render_plist(fake_home, registration_path)

        # Alternate names and nested review paths are still registration
        # destinations, and a symlinked parent cannot disguise that location.
        launch_agents.mkdir(parents=True)
        for output in (
            launch_agents / "alternate.plist",
            launch_agents / "nested" / launch_agent.LAUNCH_AGENT_FILENAME,
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(
                    launch_agent.LaunchAgentError, "refusing to install directly"
                ):
                    launch_agent.render_plist(fake_home, output)
                self.assertFalse(output.exists())

        review_alias = self.root / "review-alias"
        review_alias.symlink_to(launch_agents, target_is_directory=True)
        alias_output = review_alias / launch_agent.LAUNCH_AGENT_FILENAME
        with self.assertRaisesRegex(
            launch_agent.LaunchAgentError, "refusing to install directly"
        ):
            launch_agent.render_plist(fake_home, alias_output)
        self.assertFalse(registration_path.exists())

        with self.assertRaisesRegex(
            launch_agent.LaunchAgentError, "non-root absolute"
        ):
            launch_agent.launch_agent_configuration(Path("/"))

    def test_parser_denies_unknown_keys_and_malformed_data(self) -> None:
        configuration = launch_agent.launch_agent_configuration(self.home)
        configuration["EnvironmentVariables"] = {"RDP_SERVER_ENABLE_NATIVE": "1"}
        data = plistlib.dumps(configuration)
        with self.assertRaises(launch_agent.LaunchAgentError):
            launch_agent.parse_plist(data, self.home)
        with self.assertRaisesRegex(launch_agent.LaunchAgentError, "malformed"):
            launch_agent.parse_plist(b"not a plist", self.home)

    def test_helper_has_no_activation_tcc_network_capture_or_input_primitive(self) -> None:
        source = arguments.script.read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "import socket",
            "tccutil",
            "ScreenCaptureKit",
            "CGEventPost",
            "Quartz",
            "launchctl",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main(argv=["macos-launch-agent-tests", *remaining])
