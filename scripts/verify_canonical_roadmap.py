#!/usr/bin/env python3
"""Fail closed on an empty, truncated, or policy-free canonical roadmap."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import sys

class RoadmapIntegrityError(ValueError):
    """The current roadmap lacks mandatory authoritative structure."""

TITLE = "# RDP-server roadmap — authoritative live status"
HEADINGS = (TITLE, "## Milestone gates",
            "### M2 personal-desktop live-client compatibility matrix",
            "## P0 — M1 exact-SHA convergence",
            "## Parallel R1–R10 work board",
            "## M2 integration order and authorization contracts",
            "## Shared-main Git coordination contract",
            "## Decision ledger (current only)")

def require(condition: bool, message: str) -> None:
    if not condition:
        raise RoadmapIntegrityError(message)

def validate(contents: str) -> None:
    """Validate current meaning without pinning historic byte size."""
    require(bool(contents.strip()) and "\x00" not in contents, "empty/NUL roadmap")
    lines = contents.splitlines()
    require(sum(bool(line.strip()) for line in lines) >= 120, "roadmap truncated")
    require(len(contents.split()) >= 900, "roadmap lost substantive content")
    headings = [line.strip() for line in lines if line.lstrip().startswith("#")]
    for heading in HEADINGS:
        require(headings.count(heading) == 1, f"missing/duplicate heading: {heading}")
    def between(first: str, last: str) -> list[str]:
        beginning, end = lines.index(first), lines.index(last)
        require(beginning < end, f"invalid section order: {first}")
        return lines[beginning + 1:end]
    gates = between("## Milestone gates",
                    "### M2 personal-desktop live-client compatibility matrix")
    milestones = {m.group(1) for line in gates
                  if (m := re.match(r"^\|\s*\*\*M([1-6])\s+—", line))}
    require(milestones == set("123456"), "missing M1-M6 gate")
    board = between("## Parallel R1–R10 work board",
                    "## M2 integration order and authorization contracts")
    roads = {m.group(1) for line in board
             if (m := re.match(r"^\|\s*\*\*(R(?:10|[1-9]))\s+·", line))}
    require(roads == {f"R{i}" for i in range(1, 11)}, "missing R1-R10 row")
    policy = "\n".join(between("## Shared-main Git coordination contract",
                               "## Decision ledger (current only)"))
    for marker in ("existing `main`", "Optimistic publication:",
                   "M1 publication freeze:", "atomic", "force"):
        require(marker in policy, f"lost shared-main rule: {marker}")
    index = lines.index("## Decision ledger (current only)")
    ledger = "\n".join(lines[index + 1:index + 40])
    require("**M1:**" in ledger and "**M2:**" in ledger, "missing M1/M2 ledger")

def self_test(contents: str) -> None:
    validate(contents)
    damaged = {
        "empty": "",
        "25-line": "\n".join(contents.splitlines()[:25]),
        "no-board": contents.replace("## Parallel R1–R10 work board", "", 1),
        "no-policy": contents.replace("## Shared-main Git coordination contract", "", 1),
        "no-R8": contents.replace("| **R8 ·", "| **removed ·", 1),
        "no-M1": contents.replace("| **M1 —", "| **removed —", 1),
        "duplicate": contents + "\n" + TITLE + "\n",
    }
    for name, value in damaged.items():
        try:
            validate(value)
        except RoadmapIntegrityError:
            continue
        raise RoadmapIntegrityError(f"negative case unexpectedly passed: {name}")
    # A significant historical consolidation is allowed without fixed-size rules.
    validate(contents[contents.index(TITLE):])

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roadmap", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        contents = args.roadmap.read_text(encoding="utf-8")
        (self_test if args.self_test else validate)(contents)
    except (OSError, UnicodeError, RoadmapIntegrityError) as error:
        print(f"Canonical roadmap integrity FAIL: {error}", file=sys.stderr)
        return 1
    print("Canonical roadmap integrity PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
