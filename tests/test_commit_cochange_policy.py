#!/usr/bin/env python3
"""Offline regression for per-commit documentation and CTest registry requirements."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch
import importlib.util
import sys

POLICY_PATH = Path(__file__).resolve().parents[1] / "scripts/check_documentation_cochange.py"


class TestImplementationCommitCochange(TestCase):
    def setUp(self) -> None:
        specification = importlib.util.spec_from_file_location("cochange_policy", POLICY_PATH)
        assert specification is not None and specification.loader is not None
        self.policy = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(self.policy)

    def check(self, changes: dict[str, tuple[str, ...]]) -> tuple[int, str, str]:
        def fake_git(*arguments: str) -> str:
            if arguments[0] == "rev-list":
                return "\n".join(changes)
            if arguments[0] == "diff-tree":
                return "\n".join(changes[arguments[-1]])
            self.fail("unexpected Git query: " + " ".join(arguments))
        output, errors = StringIO(), StringIO()
        with patch.object(self.policy, "git", side_effect=fake_git), (
            patch.object(sys, "argv", [str(POLICY_PATH), "parent", "head"])
        ), redirect_stdout(output), redirect_stderr(errors):
            status = self.policy.main()
        return status, output.getvalue(), errors.getvalue()

    def test_runtime_erect_without_new_registry_entry_rejected(self) -> None:
        status, _, errors = self.check({"r10": (
            "src/server/runtime/mac_runtime_host_control.cpp",
            "tests/test_macos_runtime_host_control.cpp",
            "docs/ROADMAP.md",
        )})
        self.assertEqual(status, 1)
        self.assertIn("Missing centralized CTest registry co-change:\nr10", errors)

    def test_header_with_docs_and_registry_accepted(self) -> None:
        status, output, errors = self.check({"native": (
            "src/server/security/mac_console_admission.h",
            "tests/CMakeLists.txt",
            "docs/testing_standards.md",
        )})
        self.assertEqual(status, 0, errors)
        self.assertIn("PASS for 1 commits", output)

    def test_source_without_docs_rejected_independently(self) -> None:
        status, _, errors = self.check({"core": (
            "src/server/runtime/mac_runtime_host_control.cpp",
            "tests/CMakeLists.txt",
        )})
        self.assertEqual(status, 1)
        self.assertIn("Missing Markdown co-change:\ncore", errors)
        self.assertNotIn("Missing centralized CTest", errors)

    def test_tests_and_scripts_do_not_require_production_registration(self) -> None:
        status, _, errors = self.check({"fixtures": (
            "tests/test_owned_preauth_session.cpp",
            "scripts/test_policy.py",
            "docs/CODEX_VALIDATION.md",
        )})
        self.assertEqual(status, 0, errors)

    def test_non_code_resource_does_not_require_registration(self) -> None:
        status, _, errors = self.check({"asset": (
            "src/gui/resources/icon.svg", "docs/ROADMAP.md",
        )})
        self.assertEqual(status, 0, errors)

    def test_multiple_commits_cannot_hide_missing_registry(self) -> None:
        status, _, errors = self.check({
            "good": ("src/core/test.cpp", "tests/CMakeLists.txt", "docs/ROADMAP.md"),
            "bad": ("src/core/test.hpp", "docs/ROADMAP.md"),
        })
        self.assertEqual(status, 1)
        self.assertIn("registry co-change:\nbad", errors)
        self.assertNotIn("registry co-change:\ngood", errors)


if __name__ == "__main__":
    main()
