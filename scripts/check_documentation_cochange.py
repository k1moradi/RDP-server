#!/usr/bin/env python3
"""Require documentation and CTest-registry co-changes in source commits."""
from __future__ import annotations
import subprocess
import sys

def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()

def relevant(path: str) -> bool:
    return path == "CMakeLists.txt" or path.startswith(
        ("src/", "tests/", "cmake/", "scripts/", ".github/workflows/")
    )

PRODUCTION_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")

def requires_test_registry(paths: list[str]) -> bool:
    # A changed test fixture alone cannot register production behavior.
    # The existing CTest registry must be reviewed in the same commit.
    return any(
        path.startswith("src/") and path.endswith(PRODUCTION_SOURCE_SUFFIXES)
        for path in paths
    )

def main() -> int:
    if len(sys.argv) != 3:
        return 2
    before, after = sys.argv[1:]
    commits = [after] if not before or set(before) == {"0"} else (
        git("rev-list", "--reverse", f"{before}..{after}").splitlines()
    )
    missing = []
    missing_registry = []
    for commit in commits:
        files = git("diff-tree", "--root", "--no-commit-id",
                    "--name-only", "-r", commit).splitlines()
        if any(relevant(path) for path in files) and not any(
            path.lower().endswith(".md") for path in files
        ):
            missing.append(commit)
        if requires_test_registry(files) and "tests/CMakeLists.txt" not in files:
            missing_registry.append(commit)
    if missing:
        print("Missing Markdown co-change:", *missing, sep="\n", file=sys.stderr)
    if missing_registry:
        print("Missing centralized CTest registry co-change:",
              *missing_registry, sep="\n", file=sys.stderr)
    if missing or missing_registry:
        return 1
    print(f"Documentation and test-registry co-change PASS for {len(commits)} commits")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
