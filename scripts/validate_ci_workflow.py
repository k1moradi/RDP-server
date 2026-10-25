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
    "r2-linux-production-runtime-security",
    "protocol",
    "server-test-preview-status",
    "r6-windows-clang23",
    "r9-security-protocol-sanitizers",
    "r9-windows-powershell-parser",
    "r9-clean-windows-portable-gui",
    "r7-macos-native-lifecycle",
    "r7-macos-session-sanitizers",
    "r7-macos-portable-gui",
    "r5-linux-gui-zip",
    "r9-portable-gui-bootstrap-acceptance",
    "r9-owner-gui-credential-parity",
    "documentation-policy",
    "publish-protocol-prerelease",
}

REQUIRED_TOKENS = (
    "r7-macos-portable-gui",
    "r9-windows-powershell-parser",
    "System.Management.Automation.Language.Parser]::ParseFile",
    "scripts\\clean_windows_portable_gui.ps1",
    "macdeployqt",
    "r2-linux-production-runtime-security",
    "-DRDP_SERVER_ENABLE_LINUX_RUNTIME_SECURITY=ON",
    "-DBUILD_TESTING=OFF",
    "-DRDP_SERVER_BUILD_TESTING=OFF",
    "-DRDP_SERVER_BUILD_DESKTOP_GUI=OFF",
    "RDP_SERVER_BUILD_DESKTOP_GUI:BOOL=ON",
    "r9-portable-gui-bootstrap-acceptance",
    "r9-owner-gui-credential-parity",
    "gui.offscreen-owner-acceptance-credential-editor-parity",
    "runtime.linux-portable-gui-bootstrap-listener-acceptance",
    "gui.offscreen-owner-acceptance-consumer-start-orchestration",
    "gui.offscreen-owner-acceptance-password-change-rerequests-owner-permission",
    "runtime.desktop-shared-configuration-feed",
    "rdp-server-owner-acceptance-linux",
    "owner-acceptance ZIP failed canonical no-argument startup smoke",
    "readelf -d build/rdp-server",
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
    "windows.geometry-single-monitor-native-target-selection",
    "windows.capture-session-change-duplication-owner-retirement",
    "windows.capture-bgra-layout-contract",
    "windows.capture-frame-lifetime-revocation",
    "windows.capture-monitor-replacement-denials",
    "windows.input-sendinput-authority-retirement-no-native-post",
    '<<< "$selected_tests")" -eq 60',
    "Run R6 Windows native lifetime CTests with sanitizers",
    "r6_sanitizer_selection='^windows\\.(geometry|capture|cursor|input)-'",
    "steps.r6_windows_sanitizer_configure.outcome == 'success'",
    "steps.r6_windows_sanitizer_build.outcome == 'success'",
    "graphics.frame-delivery-unsent-cancellation",
    "graphics.avc420-segmented-frame-unsent-cancellation",
    "graphics.avc420-segmented-frame-owned-output-reuse-denials",
    "graphics.avc420-segmented-frame-retirement-reuse",
    "graphics.x264-segmented-unsent-cancel-idr",
    "graphics.x264-segmented-external-cancel-idr",
    "graphics.x264-bgra-unsent-cancel-idr",
    "graphics.x264-segmented-owned-output-reuse-preflight",
    "graphics.x264-segmented-retirement-reuse",
    "graphics.x264-native-bgra-frame-ingress",
    "graphics.x264-native-bgra-resize-recovery",
    "graphics.x264-segmented-surface-remap-idr",
    "graphics.avc420-capture-generation-denials",
    "r4_x264_expected_test_count=29",
    "test_gfx_clearcodec_fallback",
    "graphics.clearcodec-residual-frame-wire",
    "graphics.clearcodec-capability-fallback",
    "graphics.clearcodec-owned-delivery-recovery",
    "graphics.clearcodec-denials",
    "clearcodec_expected_test_count=4",
    "x11.desktop-resource-pointer-randr-stale-motion-isolation",
    "x11.capture-bgra-ingress",
    "x11.capture-stride-layout-denials",
    "x11.capture-generation-retirement",
    "x11.native-geometry-observation-generation-retirement",
    "x11.same-pixel-randr-capture-retirement",
    "x11.randr-burst-generation-retirement-recovery",
    "x11.input-native-generation-mismatch-denial",
    "x11.input-native-authority-retirement-no-native-post",
    "x11.input-r2-authorized-slow-path-native-mapping-denials",
    "test_x11_rdp_slow_path_input",
    "r5_expected_test_count=42",
    "runtime.linux-x11-authorized-input-production-linkage",
    "runtime.linux-x11-clipboard-production-linkage",
    "native_bridge_linkage_expected_test_count=2",
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
    "clipboard.windows-clipboard-publication-midcallback-retirement",
    "clipboard.x11-r3-retirement-stale-incr-fence",
    "clipboard.x11-unicode-text-only-presentation",
    "clipboard.route-bridge-source-request-receipt",
    "clipboard.route-bridge-missing-activated-route-denial",
    "clipboard.route-bridge-old-route-generation-retirement",
    "clipboard.route-bridge-partial-positive-receipt-retirement",
    "clipboard.route-bridge-filecontents-request-receipt",
    "runtime.linux-host-control-direct-ntlm-reconnect-stop-start-lifecycle",
    "same-port-rebind-after-server-close",
    "clipboard_expected_test_count=97",
    "Run R3 static CLIPRDR route CTests with sanitizers",
    "transport.cliprdr-pre-share-denial",
    "transport.cliprdr-fragment-reassembly",
    "transport.cliprdr-generation-replacement",
    "transport.cliprdr-wrong-role-compression",
    "transport.cliprdr-fragment-abort-conditions",
    "transport.cliprdr-ignored-client-flags",
    "transport.cliprdr-outbound-write-receipts",
    "transport.cliprdr-stale-receipt-abort",
    "transport.cliprdr-terminal-partial-abort",
    "r3_clipboard_expected_test_count=9",
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
    "graphics_dvc_selection='^transport\\.dvc-graphics-'",
    "transport.dvc-graphics-create-success",
    "transport.dvc-graphics-caps-selection",
    "transport.dvc-graphics-caps-unsupported-denial",
    "transport.dvc-graphics-presentation-wire",
    "transport.dvc-graphics-frame-ack-handoff-wire",
    "transport.dvc-graphics-frame-ack-handoff-malformed",
    "transport.dvc-graphics-frame-ack-handoff-stale",
    "transport.dvc-graphics-frame-credit-preflight",
    "transport.dvc-graphics-surface-remap",
    "transport.dvc-graphics-first-client-acceptance-observability",
    "transport.dvc-graphics-frame-acceptance-status-projection",
    "transport.dvc-graphics-create-response-denials",
    "transport.dvc-graphics-generation-cancellation",
    "transport.dvc-graphics-pre-share-denial",
    "transport.dvc-graphics-frame-zero-publication",
    "transport.dvc-graphics-frame-multifragment-delivery",
    "transport.dvc-graphics-frame-header-partial-abort",
    "transport.dvc-graphics-frame-payload-partial-abort",
    "transport.dvc-graphics-frame-stale-receipt",
    "transport.dvc-graphics-frame-share-loss-abort",
    "transport.dvc-graphics-data-malformed-first",
    "transport.dvc-graphics-data-wrong-channel",
    "transport.dvc-graphics-data-fragment-ordering",
    "graphics_dvc_expected_test_count=23",
    "runtime.personal-desktop-policy-immutable-denials",
    "runtime.personal-desktop-loopback-listener-denials",
    "deployment_policy_expected_test_count=2",
    "runtime.windows-private-fixture-dacl-creation",
    "runtime.windows-private-fixture-broad-access-denials",
    "runtime.windows-private-fixture-owner-consistency",
    "runtime.licensing-context-secure-file-snapshots",
    "runtime.licensing-cli-valid-provisioning",
    "runtime.licensing-cli-existing-check-compatibility",
    "transport.tcp-owned-r3-graphics-frame-slice",
    "licensing_expected_test_count=94",
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
    "runtime.linux-connection-personal-desktop-graphics-dvc-authority-denials",
    "runtime.linux-connection-personal-license-request-r1-write-denials",
    "runtime.linux-connection-personal-client-licensing-r1-intake-denials",
    "runtime.linux-connection-personal-valid-client-r1-write-denials",
    "runtime.linux-connection-personal-share-r1-io-denials",
    "runtime.linux-connection-personal-graphics-dvc-r1-io-denials",
    "runtime.linux-connection-outbound-write-readiness",
    "runtime.linux-connection-outbound-tls-want-precedence",
    "runtime.linux-connection-outbound-cancellation-revocation",
    "personal-(desktop-(r3-authority|slow-path-input-gateway|clipboard-gateway|policy-receipt|graphics-dvc-authority)|licensing-sequence|license-request-r1-write|client-licensing-r1-intake|valid-client-r1-write|share-r1-io|graphics-dvc-r1-io)-denials|outbound-(write-readiness|tls-want-precedence|cancellation-revocation)",
    "runtime.linux-connection-post-admission-mcs-framing-denials",
    "runtime.linux-connection-post-admission-mcs-response-denials",
    "runtime.linux-connection-post-admission-erect-domain-denials",
    "runtime.linux-connection-post-admission-attach-user-denials",
    "runtime.linux-connection-post-admission-attach-confirm-write-denials",
    "runtime.linux-connection-post-admission-channel-join-denials",
    "runtime.linux-connection-post-admission-client-info-denials",
    "runtime.linux-connection-client-info-bounded-tpkt-framing",
    "runtime.linux-connection-personal-licensing-sequence-denials",
    "runtime.linux-connection-personal-desktop-slow-path-input-gateway-denials",
    "runtime.linux-connection-personal-desktop-clipboard-gateway-denials",
    "runtime.linux-connection-pre-admission-native-poll",
    "runtime.linux-connection-native-poll-expiry-revocation",
    "post-admission-(mcs-(framing-denials|response-denials)|erect-domain-denials|attach-(user|confirm-write)-denials|channel-join-denials|client-info-denials)",
    "runtime.linux-connection-existing-cal-unadmitted-denial",
    "runtime.linux-connection-standalone-authentication-selector-denials",
    "runtime_security_expected_test_count=41",
    "Run R10 post-Share reader and classifier denials with sanitizers",
    "post_share_selection=",
    "post_share_expected_test_count=2",
    "Run clipboard TLS receipt denials with sanitizers",
    "clipboard_tls_selection=",
    "clipboard_tls_expected_test_count=1",
    "runtime.linux-connection-personal-clipboard-tls-write-denials",
    "Run R10 persistent post-Share owner source guard",
    "runtime.linux-serve-persistent-post-share-single-owner",
    "persistent_owner_expected_test_count=1",
    "Run R10 Stop and R5 terminal-input source fences",
    "native_terminal_source_selection=",
    "native_terminal_source_expected_test_count=2",
    "runtime.linux-serve-cooperative-signal-stop-order",
    "x11.input-direct-route-native-failure-no-xtest",
    "Run R7 runtime PlainText constructor-order source guard",
    "gui_plain_text_source_selection=",
    "gui_plain_text_source_expected_test_count=1",
    "Run R10 R7 shared LAN endpoint selection denials",
    "lan_endpoint_selection=",
    "lan_endpoint_expected_test_count=2",
    "runtime.host-control-selected-lan-interface-denials",
    "gui.offscreen-r10-selected-lan-endpoint-preflight-denials",
    "gui.offscreen-tls-fingerprint-rotation-and-denials",
    "Pin R7 TLS fingerprint Qt regression on Windows",
    "Pin R7 TLS fingerprint Qt regression on macOS",
    "gui.runtime-label-plain-before-text-assignment",
    "runtime.linux-connection-personal-post-share-classifier-authority-denials",
    "runtime.linux-connection-personal-post-share-single-reader-denials",
    "Run R2 protected-read generation fence in focused assurance",
    "runtime.linux-connection-protected-read-generation-denials",
    "protected_read_expected_test_count=1",
    "Run R2 verified-account PAM attempt source fence in focused assurance",
    "pam_attempt_source_selection=",
    "pam_attempt_source_expected_test_count=1",
    "security.linux-verified-account-pam-attempt-fence-source",
    "Run R10 production native poll with sanitizers",
    "runtime.linux-connection-pre-admission-native-poll",
    "Run R1 native TCP reset with sanitizers",
    "Run R9 R3 slow-path input with sanitizers",
    "slow_path_selection=",
    "transport.share-input-slow-path-wire",
    "transport.share-input-slow-path-rejections",
    "transport.tcp-owned-tls-application-tcp-rst-terminal",
    "rst_selection='^transport\\.tcp-owned-tls-application-tcp-rst-terminal$'",
    "runtime.validates-configuration-windows-private-dacl",
    "runtime.validates-tls-files-private-regular",
    "transport.tcp-owned-runtime-tls-handshake",
    "steps.r9_clang_debug_build.outcome == 'success'",
    "steps.r9_clang_release_build.outcome == 'success'",
    "server_test_preview:",
    "scripts/server_test_bundle.py build",
    "server-test-package-${{ matrix.os }}",
    "rdp-server-test-*-STATUS.json",
    "server-test-preview-status",
    "Require SERVER-TEST preview producer success",
    "SERVER_TEST_STRUCTURE_RESULT: ${{ needs.ci-workflow-structure.result }}",
    "SERVER_TEST_PROTOCOL_RESULT: ${{ needs.protocol.result }}",
    "always() && ((github.event_name == 'push' && github.ref == 'refs/heads/main') ||",
    "scripts/server_test_bundle.py verify-statuses",
    "server-test-status-${{ github.sha }}",
    "fuzz.mcs-cliprdr-bounded",
    "fuzz.credssp-bounded",
    'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main',
    'test "$GITHUB_REF_NAME" = "protocol-v$version"',
    "SHA256SUMS-*.txt",
    'gh release create "$GITHUB_REF_NAME"',
)

REQUIRED_BUILD_TARGETS = (
    "rdp-server",
    "test_owned_mcs_connect_initial",
    "test_r3_clipboard_static_channel",
    "test_r8_r3_clipboard_bridge",
    "test_owned_preauth_session",
    "test_owned_credssp_tsrequest",
    "test_linux_gssapi_spnego",
    "test_linux_pam_password_verifier",
    "test_runtime_linux_security",
    "test_runtime_io_interest",
    "test_runtime_licensing_authority",
    "test_runtime_licensing_authority_public_header",
    "test_runtime_deployment_policy",
    "test_lan_listener",
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
            text.count("-DRDP_SERVER_BUILD_DESKTOP_GUI=OFF") >= 9,
            "all 9 Qt-free protocol/security/native configurations must opt out explicitly",
        )
        r6_start = next(
            line for job, line in found_jobs if job == "r6-windows-clang23"
        ) - 1
        r6_position = next(
            index for index, (job, _) in enumerate(found_jobs)
            if job == "r6-windows-clang23"
        )
        r6_end = (
            found_jobs[r6_position + 1][1] - 1
            if r6_position + 1 < len(found_jobs)
            else len(lines)
        )
        r6_job = "\n".join(lines[r6_start:r6_end])
        require(
            r6_job.count("-DRDP_SERVER_BUILD_DESKTOP_GUI=ON") == 2,
            "R6 Windows GUI producer Debug/Release configurations must keep GUI ON",
        )
        require(
            r6_job.count("-DRDP_SERVER_BUILD_DESKTOP_GUI=OFF") == 1,
            "only the R6 sanitizer reconfigure may disable the desktop GUI",
        )
        require(
            text.count("RDP_SERVER_BUILD_DESKTOP_GUI:BOOL=ON") >= 2,
            "ordinary Qt-capable application configurations must prove GUI default ON",
        )
        require(
            text.count("ctest --test-dir build --build-config Debug -N") >= 10,
            "missing critical ctest -N sanitizer preflights",
        )
        require(
            "needs: [ci-workflow-structure, protocol, documentation-policy]"
            in text,
            "prerelease job lost structural/protocol/docs dependency",
        )
        require(
            text.count("gh release create") == 1,
            "SERVER-TEST preview must not add a second release publisher",
        )
        require(
            "server-test-v" not in text,
            "SERVER-TEST preview must not introduce a release tag convention yet",
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
