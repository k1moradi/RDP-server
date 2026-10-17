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
    "transport.tcp-owned-buffered-tls-credssp-mcs-readiness",
    "security.credssp-password-field-synchronous-visitor",
    "security.credssp-pam-password-field-verifier-denials",
    "security.gssapi-pam-verifier-binding-denials",
    "transport.licensing-client-cal-chain-structure",
    "transport.licensing-client-cal-certificate-validity",
    "transport.licensing-existing-cal-authority-request-ownership",
    "transport.licensing-existing-cal-live-visit-lifetime",
    "transport.licensing-existing-cal-authority-request-hwid-proof-gate",
    "transport.licensing-existing-cal-authority-request-product-and-correlation-denials",
    "transport.licensing-existing-cal-authority-request-revocation-replay",
    "windows.capture-session-change-duplication-owner-retirement",
    "windows.capture-r4-bgra-layout-contract",
    "windows.capture-r4-frame-lifetime-revocation",
    "windows.capture-r4-monitor-replacement-denials",
    "windows.input-sendinput-authority-retirement-no-native-post",
    '<<< "$selected_tests")" -eq 59',
    "Run R6 Windows native lifetime CTests with sanitizers",
    "r6_sanitizer_selection='^windows\\.(geometry|capture|cursor|input)-'",
    "steps.r6_windows_sanitizer_configure.outcome == 'success'",
    "steps.r6_windows_sanitizer_build.outcome == 'success'",
    "graphics.frame-delivery-unsent-cancellation",
    "graphics.avc420-segmented-frame-unsent-cancellation",
    "graphics.avc420-segmented-frame-owned-output-reuse-denials",
    "graphics.avc420-segmented-frame-retirement-reuse",
    "graphics.x264-segmented-unsent-cancel-idr",
    "graphics.x264-bgra-unsent-cancel-idr",
    "graphics.x264-segmented-owned-output-reuse-preflight",
    "graphics.x264-segmented-retirement-reuse",
    "graphics.x264-native-bgra-frame-ingress",
    "graphics.x264-native-bgra-resize-recovery",
    "graphics.avc420-capture-generation-denials",
    "r4_x264_expected_test_count=27",
    "test_gfx_clearcodec_fallback",
    "graphics.clearcodec-residual-frame-wire",
    "graphics.clearcodec-capability-fallback",
    "graphics.clearcodec-owned-delivery-recovery",
    "graphics.clearcodec-denials",
    "clearcodec_expected_test_count=4",
    "x11.desktop-resource-pointer-randr-stale-motion-isolation",
    "x11.capture-r4-bgra-ingress",
    "x11.capture-r4-stride-layout-denials",
    "x11.capture-r4-generation-retirement",
    "x11.input-native-generation-mismatch-denial",
    "x11.input-native-authority-retirement-no-native-post",
    "r5_expected_test_count=38",
    "macos.desktop-geometry-epoch-generation-fence-revocation",
    "macos.capture-stream-geometry-generation-retirement",
    "macos.capture-stream-session-watch-consumer-race",
    "macos.input-controller-authority-retirement-no-native-post",
    "input_session_expected_test_count=2",
    "macos.cursor-geometry-generation-publication-denials",
    "clipboard.macos-completed-multi-file-url-handoff",
    "clipboard.windows-completed-multi-file-hdrop-handoff",
    "clipboard.x11-completed-multi-file-uri-handoff",
    "clipboard.macos-clipboard-r3-retirement-source-epoch",
    "clipboard.windows-file-destination-source-epoch-revocation",
    "clipboard.windows-clipboard-r3-retirement-source-epoch",
    "clipboard.x11-r3-retirement-stale-incr-fence",
    "clipboard_expected_test_count=81",
    "runtime.licensing-authority-unconfigured-denials",
    "runtime.licensing-authority-public-header-consumer-lifetime",
    "runtime.licensing-existing-cal-provider-unavailable",
    "runtime.licensing-existing-cal-request-correlation",
    "runtime.licensing-existing-cal-policy-generation-revocation",
    "runtime.licensing-existing-cal-result-retirement",
    "runtime.licensing-existing-cal-connection-unavailable-denial",
    "runtime.licensing-existing-cal-connection-cross-generation-cancellation",
    "existing_cal_expected_test_count=6",
    "transport.licensing-personal-mode-and-malformed-denials",
    "transport.share-personal-activation-denials",
    "personal_mode_expected_test_count=6",
    "transport.dvc-graphics-create-success",
    "transport.dvc-graphics-create-response-denials",
    "transport.dvc-graphics-generation-cancellation",
    "transport.dvc-graphics-pre-share-denial",
    "graphics_dvc_expected_test_count=4",
    "runtime.personal-desktop-policy-immutable-denials",
    "runtime.personal-desktop-loopback-listener-denials",
    "deployment_policy_expected_test_count=2",
    "runtime.windows-private-fixture-dacl-creation",
    "runtime.windows-private-fixture-broad-access-denials",
    "runtime.windows-private-fixture-owner-consistency",
    "runtime.licensing-context-secure-file-snapshots",
    "runtime.licensing-cli-valid-provisioning",
    "runtime.licensing-cli-existing-check-compatibility",
    "licensing_expected_test_count=93",
    "cal_expected_test_count=8",
    "existing_cal_request_expected_test_count=5",
    "credential_expected_test_count=4",
    "delegated_account_expected_test_count=6",
    "authority_expected_test_count=7",
    "native_gss_expected_test_count=30",
    "pam_expected_test_count=3",
    "runtime.linux-connection-native-monitor-borrow-denials",
    "runtime.linux-connection-native-monitor-registration-denials",
    "native-(monitor-(borrow|registration)|desktop-selection)-denials",
    "runtime.linux-connection-native-desktop-selection-denials",
    "runtime.linux-connection-personal-desktop-r3-authority-denials",
    "runtime.linux-connection-personal-desktop-policy-receipt-denials",
    "runtime.linux-connection-personal-license-request-r1-write-denials",
    "personal-(desktop-(r3-authority|policy-receipt)|license-request-r1-write)-denials",
    "runtime.linux-connection-post-admission-mcs-framing-denials",
    "post-admission-mcs-framing-denials",
    "runtime.linux-connection-existing-cal-unadmitted-denial",
    "runtime_security_expected_test_count=20",
    "runtime.validates-configuration-windows-private-dacl",
    "runtime.validates-tls-files-private-regular",
    "transport.tcp-owned-runtime-tls-handshake",
    "steps.r9_clang_debug_build.outcome == 'success'",
    "steps.r9_clang_release_build.outcome == 'success'",
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
    "test_runtime_licensing_authority_public_header",
    "test_runtime_deployment_policy",
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
