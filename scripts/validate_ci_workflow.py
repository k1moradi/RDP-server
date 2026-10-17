#!/usr/bin/env python3
"""Fail-closed structural validation for the primary GitHub Actions workflow."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


class WorkflowError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkflowError(message)


def duplicate_check(items: list[tuple[str, int]], scope: str) -> None:
    seen: dict[str, int] = {}
    for key, line in items:
        if key in seen:
            raise WorkflowError(
                f"duplicate {scope} key {key!r} at lines {seen[key]} and {line}"
            )
        seen[key] = line


def parse_jobs(lines: list[str]) -> list[tuple[str, int]]:
    jobs_line = next((i for i, line in enumerate(lines) if line == "jobs:"), None)
    require(jobs_line is not None, "missing top-level jobs mapping")
    pattern = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
    found: list[tuple[str, int]] = []
    for index in range(jobs_line + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            break
        match = pattern.match(line)
        if match:
            found.append((match.group(1), index + 1))
    require(found, "jobs mapping contains no job IDs")
    duplicate_check(found, "job")
    return found


def validate_expressions(text: str) -> None:
    opening = "$" + "{{"
    closing = "}}"
    require(
        text.count(opening) == text.count(closing),
        "GitHub expression delimiter mismatch",
    )
    cursor = 0
    while True:
        start = text.find(opening, cursor)
        if start < 0:
            return
        end = text.find(closing, start + len(opening))
        require(end >= 0, f"unterminated GitHub expression at byte {start}")
        require(
            text.find(opening, start + len(opening), end) < 0,
            f"nested GitHub expression at byte {start}",
        )
        cursor = end + len(closing)


def run_blocks(lines: list[str]) -> list[tuple[int, str, str]]:
    marker = re.compile(r"^(\s*)run:\s*[|>][-+]?\s*$")
    result: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = marker.match(line)
        if not match:
            continue
        base = len(match.group(1))
        shell = "default"
        for prior_index in range(index - 1, -1, -1):
            prior = lines[prior_index]
            if not prior.strip():
                continue
            indent = len(prior) - len(prior.lstrip(" "))
            if indent < base:
                break
            shell_match = re.match(r"^\s*shell:\s*(\S+)", prior)
            if indent == base and shell_match:
                shell = shell_match.group(1)
                break
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                body.append("")
                continue
            indent = len(candidate) - len(candidate.lstrip(" "))
            if indent <= base:
                break
            body.append(candidate[min(len(candidate), base + 2) :])
        require(body, f"empty shell run block at line {index + 1}")
        result.append((index + 1, "\n".join(body) + "\n", shell))
    return result


def quote_fallback(script: str, line: int) -> None:
    single = double = escaped = False
    for char in script:
        if escaped:
            escaped = False
        elif char == "\\" and not single:
            escaped = True
        elif char == "'" and not double:
            single = not single
        elif char == '"' and not single:
            double = not double
    require(
        not single and not double,
        f"unterminated shell quote in run block at line {line}",
    )


def validate_shell(lines: list[str]) -> None:
    bash = shutil.which("bash")
    opening = "$" + "{{"
    expression = re.compile(re.escape(opening) + r".*?\}\}", re.S)
    for line, script, shell in run_blocks(lines):
        shell_name = shell.lower()
        if shell_name not in {"default", "bash", "sh"} and not shell_name.startswith("msys2"):
            continue
        masked = expression.sub("GITHUB_EXPRESSION", script)
        if not bash:
            quote_fallback(masked, line)
            continue
        completed = subprocess.run(
            [bash, "-n"],
            input=masked,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode:
            detail = completed.stderr.strip().splitlines()
            raise WorkflowError(
                f"bash syntax failure in run block at line {line}: "
                f"{detail[-1] if detail else 'syntax error'}"
            )


def yaml_backend(text: str) -> str:
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        return "lexical"

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise WorkflowError(f"duplicate YAML mapping key {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        yaml.load(text, Loader=UniqueKeyLoader)
    except WorkflowError:
        raise
    except Exception as exc:
        raise WorkflowError(f"YAML parse failure: {exc}") from exc
    return f"PyYAML {yaml.__version__}"


REQUIRED_JOBS = {
    "ci-workflow-structure",
    "protocol",
    "r6-windows-clang23",
    "r9-security-protocol-sanitizers",
    "r7-macos-native-lifecycle",
    "r7-macos-session-sanitizers",
    "documentation-policy",
    "publish-protocol-prerelease",
}

REQUIRED_TOKENS = (
    "transport.tcp-owned-tls-terminal-readiness",
    "security.credssp-password-field-synchronous-visitor",
    "security.credssp-pam-password-field-verifier-denials",
    "security.gssapi-pam-verifier-binding-denials",
    "transport.licensing-client-cal-chain-structure",
    "transport.licensing-client-cal-certificate-validity",
    "windows.capture-session-change-duplication-owner-retirement",
    "graphics.frame-delivery-unsent-cancellation",
    "graphics.avc420-segmented-frame-unsent-cancellation",
    "graphics.x264-segmented-unsent-cancel-idr",
    "graphics.x264-bgra-unsent-cancel-idr",
    "x11.desktop-resource-pointer-randr-stale-motion-isolation",
    "macos.desktop-geometry-epoch-generation-fence-revocation",
    "macos.capture-stream-geometry-generation-retirement",
    "macos.capture-stream-session-watch-consumer-race",
    "macos.cursor-geometry-generation-publication-denials",
    "clipboard.macos-completed-multi-file-url-handoff",
    "clipboard.windows-completed-multi-file-hdrop-handoff",
    "clipboard.x11-completed-multi-file-uri-handoff",
    "runtime.licensing-authority-unconfigured-denials",
    "runtime.windows-private-fixture-dacl-creation",
    "runtime.windows-private-fixture-broad-access-denials",
    "runtime.windows-private-fixture-owner-consistency",
    "runtime.licensing-context-secure-file-snapshots",
    "runtime.licensing-cli-valid-provisioning",
    "runtime.validates-configuration-windows-private-dacl",
    "runtime.validates-tls-files-private-regular",
    "transport.tcp-owned-runtime-tls-handshake",
    "fuzz.mcs-cliprdr-bounded",
    "fuzz.credssp-bounded",
    'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
    'test "$GITHUB_REF_NAME" = "protocol-v$version"',
    "SHA256SUMS-*.txt",
    'gh release create "$GITHUB_REF_NAME"',
)

REQUIRED_BUILD_TARGETS = (
    "test_owned_mcs_connect_initial",
    "test_owned_preauth_session",
    "test_owned_credssp_tsrequest",
    "test_linux_gssapi_spnego",
    "test_linux_pam_password_verifier",
    "test_runtime_linux_security",
    "test_runtime_licensing_authority",
    "test_x11_desktop_resources",
    "test_macos_capture_pixel_buffer",
    "fuzz_mcs_cliprdr",
    "fuzz_credssp",
)


def validate(path: Path, full: bool) -> tuple[str, int]:
    text = path.read_text(encoding="utf-8")
    require(text.endswith("\n"), "workflow must end with a newline")
    require("\t" not in text, "tabs are not allowed in workflow indentation")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    backend = yaml_backend(text)
    top = [
        (match.group(1), index + 1)
        for index, line in enumerate(lines)
        if (match := re.match(r"^([A-Za-z0-9_.-]+):(?:\s.*)?$", line))
    ]
    duplicate_check(top, "top-level")
    found_jobs = parse_jobs(lines)
    validate_expressions(text)
    validate_shell(lines)

    if full:
        missing = sorted(REQUIRED_JOBS - {job for job, _ in found_jobs})
        require(not missing, f"missing required jobs: {', '.join(missing)}")
        for token in REQUIRED_TOKENS:
            require(token in text, f"missing required workflow token: {token}")
        for target in REQUIRED_BUILD_TARGETS:
            require(target in text, f"missing sanitizer build target: {target}")
        require(
            text.count("ctest --test-dir build --build-config Debug -N") >= 10,
            "missing critical ctest -N sanitizer preflights",
        )
        require(
            "needs: [ci-workflow-structure, protocol, documentation-policy]"
            in text,
            "prerelease job lost structural/protocol/docs dependency",
        )
    return backend, len(found_jobs)


def self_test(workflow: Path, fixture_root: Path) -> None:
    backend, count = validate(workflow, True)
    validate(fixture_root / "valid.yml", False)
    validate(fixture_root / "valid-powershell.yml", False)
    expected = {
        "duplicate-jobs.yml": "duplicate",
        "unterminated-shell.yml": "syntax",
        "malformed-expression.yml": "expression",
    }
    for name, diagnostic in expected.items():
        try:
            validate(fixture_root / name, False)
        except WorkflowError as exc:
            require(
                diagnostic in str(exc).lower(),
                f"{name} failed for unexpected reason: {exc}",
            )
        else:
            raise WorkflowError(f"negative fixture {name} unexpectedly validated")
    print(
        f"CI workflow validation PASS ({backend}); "
        f"job count: {count}; duplicate-job count: 0; "
        f"negative fixtures rejected: {len(expected)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--structure-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            require(args.fixture_root is not None, "--self-test requires --fixture-root")
            self_test(args.workflow, args.fixture_root)
        else:
            backend, count = validate(args.workflow, not args.structure_only)
            print(
                f"CI workflow validation PASS ({backend}); "
                f"job count: {count}; duplicate-job count: 0"
            )
    except (OSError, UnicodeError, WorkflowError) as exc:
        print(f"CI workflow validation FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
