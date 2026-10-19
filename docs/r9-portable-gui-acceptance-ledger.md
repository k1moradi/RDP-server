## R9 clean Windows release-blocking gate and concurrent integration (2026-10-19)

Reconciled R9 PR #26 `b45582b466de80a5423e4e38feac134266942355` (primary Actions 39232727915 PASS;
independent structure 39232727808 PASS) against main `59357e2fe6eaa4937b337b5d1e73ed82634daab9`,
preserving concurrent R4 ACK duplication repair, R5 RandR work, R6
Windows offline contracts, and R10 fail-closed HostControl changes.
The R6/R9 clean-Windows workflow introduced on main contained a truncated
PowerShell checksum expression and duplicated job graph and uploaded the
public Windows ZIP before clean verification; this integration replaces
the broken workflow with the known-valid PR #26 full workflow plus a
strict release-blocking consumer job.

CLANG64 now publishes only an internal `r9-windows-unverified-<SHA>` ZIP
after recursive PE closure and its existing extracted qwindows smoke.
A separate interactive non-administrator, genuinely unprovisioned Windows
VM with runner label `r9-clean-windows-gui` downloads the exact unchanged
ZIP. The consumer rejects missing hashes/license notices/manifest,
malformed archive or platform identity, non-app-local Qt/DLL loading,
missing first window, close/relaunch/hidden-test failure, TCP/UDP socket
activity, Unicode/spaces regressions, firewall/service/TermService/RDP
policy modifications, elevated/system session and development PATHs.
It produces an exact-source acceptance receipt before releasing the
public Windows x86_64 PORTABLE-GUI artifact; no missing-DLL dialog can
be classified as PASS.

**Release BLOCKED:** clean interactive non-admin Windows VM and its
exact-SHA PASS receipt are NOT YET VERIFIED. If no runner is registered
the public ZIP intentionally remains unpublished; hosted MSYS2 and
provisioned Windows-latest cannot replace it. Linux x86_64 and macOS
arm64 GUI artifacts remain separate from SDK and disabled SERVER-TEST.
PR #23 GUI default ON / Qt-free headless remain unmerged. Real R2 owner
consent, R10 LAN GUI Start, R3 live resize, R8 clipboard and real
Linux seat0 to Windows App/mstsc acceptance remain independent blockers.
Linux, CLANG64 and macOS27 full owner-native exact-SHA Debug CTest
remain NOT RUN for the integration SHA.

# R9 portable GUI distribution and acceptance ledger

Baseline: `7f7f6b0dc5d5c47117b0fdf4cf223d54e547af91` (primary Actions 39157893314, independent structure 39157893350). These baseline runs passed; the baseline artifact list contains `rdp-server-gui-linux`, but no separately downloadable Windows or macOS PORTABLE-GUI archives.

## R9 CI publication correction

The Windows CLANG64 packaging lane already builds and verifies a PE/DLL-closure checked x86_64 ZIP, then performs an extracted, path-with-spaces, offline GUI smoke. The macOS arm64 lane already builds, checks Mach-O closure and extracted ad-hoc signature, and performs an extracted Cocoa launch. Upload the ZIP and its SHA256 file only after the corresponding native smoke passes. Linux keeps the separately named `rdp-server-gui-linux` artifact and Linux/XCB extract/launcher preflight. These are portable GUI previews, not protocol SDK packages or startup-disabled SERVER-TEST archives.

Each candidate artifact must retain its full source SHA manifest, outer SHA256, licenses/notices, architecture, and dependency inventory. Do not claim Windows/macOS artifacts are available until a **new exact-SHA CI run** succeeds and lists them. Do not substitute hosted package checks for owner-native Debug/Release evidence. macOS ad-hoc preview signing is **not** Developer ID distribution or notarization.

The R3 DVC sanitizer selector must remain exactly **20** registered cases including `transport.dvc-graphics-frame-credit-preflight`; R8 clipboard component sanitizer selector remains exactly **87** and separately asserts native bridge/linkage source guards. R4 surface geometry, R2 IPv4-mapped IPv6 admission quota, R7 Qt client stage, and R8 stable scalar clipboard receipt require exact-HEAD CTest inventory verification; a general green matrix alone does not prove focused selection. Do not lower a pinned count to disguise changes.

## Physical/owner acceptance ledger — NOT RUN

| Acceptance gate | Status | Required evidence |
|---|---|---|
| GUI-only existing OS-account setup, authorization and seat0 owner | NOT RUN | Real logged-in owner/session receipt, no synthetic permission |
| LAN Start / Stop, no unauthorized side effects | NOT RUN | GUI action and socket/firewall before/after evidence |
| Microsoft-client CredSSP and Share | NOT RUN | Real mstsc/Windows App handshake and protected admission |
| First video frame and FRAME_ACK | NOT RUN | Correlated server/client frame ID and accepted-byte/ACK receipts |
| Keyboard/mouse input | NOT RUN | Genuine owner-authorized input and revocation |
| Resize / surface recovery | NOT RUN | Client-driven resize with surface retirement and new valid frame |
| Disconnect / Stop / exit / rerun | NOT RUN | Native lifecycle and zero post-retirement callback evidence |
| Offline-LAN operation | NOT RUN | Disconnected-from-Internet real LAN client run |
| M1 Linux/X11 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |
| M1 Windows MSYS2 CLANG64/Clang23 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |
| M1 macOS 27 owner-native Debug | OPEN | Same candidate SHA, owner hardware/toolchain, full CTest |

No candidate freeze before R10 nominates a single SHA. Hosted successes cannot advance any NOT RUN row.

## R9 focused exact-HEAD inventory — added source gates, CI NOT YET VERIFIED

R9 now explicitly builds `test_authentication_attempt_limiter` in the
Clang sanitizer job and independently pins the following registered CTests:
`security.ipv4-mapped-ipv6-peer-quota-identity`,
`graphics.surface-resize-revocation`,
`graphics.x264-native-bgra-resize-recovery`, and
`runtime.r8-r3-stable-scalar-write-receipt`. Each must match exactly one
CTest and execute with ASan/UBSan. R7's real Qt/macOS arm64 packaging job
separately pins and executes exactly one
`gui.offscreen-r10-client-stage-and-retirement-status-denials`.
The preexisting 20-case R3 Graphics DVC, 87-case R8 clipboard component,
and independent native linkage guards remain unchanged.

No hosted run, native owner receipt, or real Microsoft-client acceptance is
claimed for this addition until corresponding exact-SHA evidence exists.
`src/gui/main.cpp` still constructs `UnavailableRuntimeHostControl`;
R10 concrete GUI LAN Start/Stop and R2-backed owner admission have not landed.
The R10 candidate freeze nomination and same-SHA M1 native Debug receipts
remain OPEN.

## R9 verified hosted GUI distribution and current merged-owner inventory (2026-10-18)

Exact shared R9 SHA `aee09e5035721ff14f635e670a982392e87c53b7`, primary Actions
`39201911316`, has successful hosted Clang ASan/UBSan focused inventory
(R2 IPv4-mapped IPv6, R4 surface/resize and R8 scalar receipt), R7 Qt
client-stage, R6 Windows CLANG64 and Windows/MSVC, R5 Linux GUI, R7 macOS
arm64 portable GUI, all protocol OS jobs, and SERVER-TEST acceptance.
R3 Graphics DVC **20/20**, R8 clipboard **87/87**, and native linkage
guards remain independent; counts are not reduced.

The three separately downloadable same-SHA Actions artifacts and their
**GitHub Actions container** SHA-256 digests (not ZIP-internal hashes) are:

- Windows x86_64 `rdp-server-portable-gui-windows-x86_64` artifact
  `12163794986`: `08ad07de2b8075b7817754e702f5cd5d5c89c2a2c68c9cbcb84ba8c08228353a`
- Linux x86_64 `rdp-server-gui-linux` artifact
  `12163719180`: `8b2b5042385eebe87b4e1cf33d3b22743f030fb6305f4ee73fe7bc3b093968b1`
- macOS arm64 `rdp-server-portable-gui-macos-arm64` artifact
  `12164610862`: `ad07eab4938a1e0313b0fb809213edb925f9018429beb58979691cfb39710f9a`

Native hosted archive/Qt/PE/ELF/Mach-O closure and extracted offline smoke
checks passed in that run. The packaged ZIP and its `.zip.sha256` file
still require independent consumer validation against their manifest and
license/notices; Actions-container digests must not be represented as
the inner ZIP hash. macOS ad-hoc `codesign --verify --deep --strict`
is **not** Developer ID distribution or notarization.

Merged R7 `gui.offscreen-r10-lifecycle-and-terminal-close-denials` is also pinned exact-one in the real macOS Qt lane. Merged R2 `security.linux-seat0-session-identity-denials` and
`runtime.host-control-authentication-outcome-denials` now receive exact-one
ASan/UBSan CI selections with both real fixtures compiled; merged R7
`gui.offscreen-close-requires-explicit-owner-stop` receives exact-one
real macOS Qt offscreen CI selection; merged R8
`runtime.r8-r3-retired-route-positive-receipt-isolation` is added to the
existing focused R8 ASan/UBSan selection, remaining outside R8's fixed 87
clipboard component tests. R2's fixed 40-case direct-runtime, R3's 20-case
DVC, R8's 87-case clipboard and linkage guards remain unchanged.
The first PR-head CI attempt reached PASS for structure, Linux sanitizer, macOS portable GUI, Linux GUI, macOS protocol and R7 lifecycle jobs before this rebase; Windows jobs were still running. This rebase adds the newly merged R7 lifecycle/terminal-close exact-one CTest, so the new head is **NOT YET HOSTED VERIFIED**.

R10's `UnavailableRuntimeHostControl` is still used in production GUI
`src/gui/main.cpp`; the separate R10 ACK-credit/HostControl PR #23 and R3
geometry remap PR #24 remain draft/unmerged. The latter intends to grow
the R3 DVC selection from **20 to 21** only with its new registered test.
Physical Linux seat0 owner consent/lock proof, genuine LAN Start/Stop,
Microsoft-client CredSSP/Share/first frame/FRAME_ACK/input/resize/reconnect,
owner-native M1 Debug matrix and R10-nominated candidate freeze remain
**BLOCKED / NOT RUN**. No hosted offline preflight substitutes for them.

