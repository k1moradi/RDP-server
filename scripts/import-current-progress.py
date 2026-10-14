#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve current source progress, not old Git history, in RDP-server/main.

Imports all tracked source-main files, active clipboard changed files, and
unique development-tip changed files from a local xrdp-console checkout.
Existing maintained C++23 source/build files have priority; incompatible
originals are retained as migration/source-main-overlaps files for review.
No branch creation, force push, backup, host deployment or RDP service action.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parents[1]
KEEP_OFF_BUILD = (".github/", "patches/", "packaging/", "src/vendor/")


def git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    command = ["git", "-C", str(cwd), *args]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and result.returncode:
        raise RuntimeError(
            f"{' '.join(command)}: {result.stderr.decode(errors='replace').strip()}")
    return result


def decoded(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape").strip()


def ref_sha(source: Path, ref: str) -> str | None:
    result = git(source, "rev-parse", "--verify", "--quiet",
                 f"{ref}^{{commit}}", check=False)
    return decoded(result.stdout) if result.returncode == 0 else None


def ancestor(source: Path, older: str, newer: str) -> bool:
    result = git(source, "merge-base", "--is-ancestor", older, newer, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git merge-base failed: {decoded(result.stderr)}")
    return result.returncode == 0


def best(source: Path, refs: tuple[str, ...]) -> tuple[str, str] | None:
    candidates = [(name, sha) for name in refs if (sha := ref_sha(source, name))]
    if not candidates:
        return None
    chosen = candidates[0]
    for candidate in candidates[1:]:
        if ancestor(source, chosen[1], candidate[1]):
            chosen = candidate
    return chosen


def safe_path(path: str) -> Path:
    source_path = PurePosixPath(path)
    if (source_path.is_absolute() or ".." in source_path.parts or
            ".git" in source_path.parts or "\x00" in path):
        raise RuntimeError(f"Unsafe source path: {path!r}")
    return Path(*source_path.parts)


def archive(source: Path, sha: str) -> dict[str, tuple[bytes, str]]:
    proc = subprocess.Popen(
        ["git", "-C", str(source), "archive", "--format=tar", sha],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data: dict[str, tuple[bytes, str]] = {}
    assert proc.stdout is not None
    with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
        for entry in tar:
            safe_path(entry.name)
            if entry.isfile():
                item = tar.extractfile(entry)
                if item is None:
                    raise RuntimeError(f"Could not read {entry.name}")
                data[entry.name] = (item.read(), "file")
            elif entry.issym():
                if os.path.isabs(entry.linkname):
                    raise RuntimeError(f"Unsafe source symlink: {entry.name}")
                data[entry.name] = (entry.linkname.encode(), "link")
    proc.stdout.close()
    error = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    if proc.wait():
        raise RuntimeError(f"Could not export source snapshot {sha}: {error}")
    return data


def changed_paths(source: Path, left: str, right: str) -> set[str]:
    data = git(source, "diff", "--no-renames", "--name-only", "-z",
               left, right).stdout
    return {os.fsdecode(entry) for entry in data.split(b"\0") if entry}


def local_changes(source: Path) -> set[str]:
    data = git(source, "status", "--porcelain", "-z",
               "--untracked-files=no").stdout
    return {os.fsdecode(item[3:]) for item in data.split(b"\0") if len(item) >= 4}


def write(root: Path, name: str, payload: bytes, kind: str) -> bool:
    path = root / safe_path(name)
    if path.exists() or path.is_symlink():
        if kind == "file" and path.is_file() and path.read_bytes() == payload:
            return False
        if kind == "link" and path.is_symlink() and os.readlink(path).encode() == payload:
            return False
        raise RuntimeError(f"Refusing to overwrite different file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "link":
        path.symlink_to(payload.decode())
    else:
        path.write_bytes(payload)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", default=str(Path.home() / "xrdp-console"),
                        help="Former xrdp-console local Git checkout")
    args = parser.parse_args()
    source = Path(args.source).expanduser().resolve()
    destination = HERE

    if not (source / ".git").exists():
        raise RuntimeError(f"Original local Git checkout not found: {source}")
    if decoded(git(destination, "branch", "--show-current").stdout) != "main":
        raise RuntimeError("RDP-server must be on existing main; no branch will be created")
    if git(destination, "status", "--porcelain").stdout:
        raise RuntimeError("RDP-server working tree must be clean; no source files changed")
    origin = decoded(git(destination, "remote", "get-url", "origin").stdout)
    if not re.search(r"(?:^|[/:])RDP-server(?:\.git)?$", origin, re.IGNORECASE):
        raise RuntimeError(f"origin must be RDP-server, not {origin}")
    head = decoded(git(destination, "rev-parse", "HEAD").stdout)
    remote_line = decoded(git(destination, "ls-remote", "origin",
                              "refs/heads/main").stdout)
    if not remote_line or remote_line.split("\t")[0] != head:
        raise RuntimeError("origin/main changed; run git pull --ff-only first")

    source_main = best(source, ("refs/remotes/origin/main", "refs/heads/main"))
    if source_main is None:
        raise RuntimeError("No original main ref in the local source checkout")
    source_clipboard = best(source, (
        "refs/remotes/origin/dev/clipboard", "refs/heads/dev/clipboard",
        "refs/remotes/origin/experiment/png-prefetch-native-review-20261013",
        "refs/heads/experiment/png-prefetch-native-review-20261013"))
    if source_clipboard is None:
        raise RuntimeError(
            "Cannot find the clipboard experiment in the local clone. "
            "Inspect 'git branch -a' there; refusing to lose clipboard progress.")

    main_sha = source_main[1]
    clipboard_sha = source_clipboard[1]
    print(f"Original main: {source_main[0]}\nClipboard: {source_clipboard[0]}",
          flush=True)
    files_main = archive(source, main_sha)
    files_clip = archive(source, clipboard_sha)
    diff_clip = changed_paths(source, main_sha, clipboard_sha)

    refs = git(source, "for-each-ref", "--format=%(objectname) %(refname)",
               "refs/heads", "refs/remotes/origin").stdout.decode(
                   "utf-8", "surrogateescape")
    tips: dict[str, list[str]] = {}
    for line in refs.splitlines():
        pair = line.split(" ", 1)
        if len(pair) == 2 and re.fullmatch(r"[0-9a-f]{40}", pair[0]):
            tips.setdefault(pair[0], []).append(pair[1])
    tips.setdefault(main_sha, []).append(source_main[0])
    tips.setdefault(clipboard_sha, []).append(source_clipboard[0])
    checked_out = ref_sha(source, "HEAD")
    if checked_out:
        tips.setdefault(checked_out, []).append("checkout/HEAD")
    independent = [sha for sha in tips
                   if not ancestor(source, sha, main_sha)
                   and not ancestor(source, sha, clipboard_sha)]
    maximal = sorted(sha for sha in independent if not any(
        sha != other and ancestor(source, sha, other) for other in independent))

    root_added = 0
    collisions = 0
    for name, (payload, kind) in sorted(files_main.items()):
        target = destination / safe_path(name)
        if name.startswith(KEEP_OFF_BUILD):
            output = f"migration/source-main/{name}"
        elif target.exists() or target.is_symlink():
            if ((kind == "file" and target.is_file() and
                 target.read_bytes() == payload) or
                (kind == "link" and target.is_symlink() and
                 os.readlink(target).encode() == payload)):
                continue
            output = f"migration/source-main-overlaps/{name}"
            collisions += 1
        else:
            output = name
        root_added += int(write(destination, output, payload, kind))

    clipboard_saved = 0
    clipboard_deleted: list[str] = []
    for name in sorted(diff_clip):
        if name in files_clip:
            payload, kind = files_clip[name]
            clipboard_saved += int(write(
                destination, f"migration/clipboard-delta/{name}", payload, kind))
        else:
            clipboard_deleted.append(name)

    tip_inventory = []
    for index, sha in enumerate(maximal, start=1):
        tip_files = archive(source, sha)
        changed = changed_paths(source, main_sha, sha)
        base = f"migration/other-tip-deltas/tip-{index:02d}-{sha[:12]}"
        copied = 0
        deleted = []
        for name in sorted(changed):
            if name in tip_files:
                payload, kind = tip_files[name]
                copied += int(write(destination, f"{base}/{name}", payload, kind))
            else:
                deleted.append(name)
        tip_inventory.append(dict(source_sha=sha, references=tips[sha],
                                  copied=copied, deleted=deleted))

    # Local uncommitted tracked source modifications are important progress.
    local_edits = sorted(local_changes(source))
    local_deleted = []
    for name in local_edits:
        path = source / safe_path(name)
        if path.is_file():
            write(destination, f"migration/local-working-changes/{name}",
                  path.read_bytes(), "file")
        elif path.is_symlink():
            write(destination, f"migration/local-working-changes/{name}",
                  os.readlink(path).encode(), "link")
        else:
            local_deleted.append(name)

    inventory = dict(
        scope="Preserved source-code progress; no old Git history imported",
        original_main=dict(ref=source_main[0], sha=main_sha,
                           tracked_files=len(files_main), overlaps=collisions),
        clipboard=dict(ref=source_clipboard[0], sha=clipboard_sha,
                       changed_files=len(diff_clip), deleted=clipboard_deleted),
        independent_tips=tip_inventory,
        local_tracked_changes=dict(paths=local_edits, deleted=local_deleted),
        limitation="Untracked/ignored files and unavailable old refs are not captured.")
    index = destination / "migration" / "PROGRESS_INVENTORY.json"
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")

    git(destination, "add", "-A")
    difference = git(destination, "diff", "--cached", "--quiet",
                     check=False).returncode
    if difference == 1:
        git(destination, "commit", "-m",
            "migration: preserve full project source and independent clipboard progress")
        git(destination, "push", "origin", "HEAD:refs/heads/main")
    elif difference != 0:
        raise RuntimeError("git diff --cached failed; refusing to push")

    print(f"SUCCESS: {len(files_main)} source-main files, "
          f"{clipboard_saved} clipboard changes, {len(maximal)} "
          f"independent tip snapshots, {len(local_edits)} local tracked edits. "
          "No old history or branch created.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"IMPORT ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error
