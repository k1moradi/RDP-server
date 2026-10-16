#!/usr/bin/env python3
"""Require documentation co-changes in each implementation commit."""
from __future__ import annotations
import subprocess
import sys

def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()

def relevant(path: str) -> bool:
    return path == "CMakeLists.txt" or path.startswith(
        ("src/", "tests/", "cmake/", "scripts/", ".github/workflows/")
    )

def main() -> int:
    if len(sys.argv) != 3:
        return 2
    before, after = sys.argv[1:]
    commits = [after] if not before or set(before) == {"0"} else (
        git("rev-list", "--reverse", f"{before}..{after}").splitlines()
    )
    missing = []
    for commit in commits:
        files = git("diff-tree", "--root", "--no-commit-id",
                    "--name-only", "-r", commit).splitlines()
        if any(relevant(path) for path in files) and not any(
            path.lower().endswith(".md") for path in files
        ):
            missing.append(commit)
    if missing:
        print("Missing Markdown co-change:", *missing, sep="\n", file=sys.stderr)
        return 1
    print(f"Documentation co-change PASS for {len(commits)} commits")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
