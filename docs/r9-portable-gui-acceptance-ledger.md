## R6 Windows GUI producer re-enabled after R9 headless overreach (2026-10-19)

Current-main parent `1d5ff7597e5382b178fb0afa668db93849de778c` inherited R9 commit
`9e4222cfe909ad3aabee6d0bb0a99142f0354877`, which changed both
`r6-windows-clang23` Debug and Release producer configures to
`RDP_SERVER_BUILD_DESKTOP_GUI=OFF` while the very next commands required the
cache value to be `ON`. Actions `39274959607`, R6 job `118136799203`,
therefore failed in **Configure Debug with CLANG64**: CMake was invoked with
GUI OFF and the exact `RDP_SERVER_BUILD_DESKTOP_GUI:BOOL=ON` assertion exited
1. Those two producer configures are Qt-capable and must remain ON; only the R6
sanitizer reconfigure is intentionally GUI OFF. The workflow and both release
gate/structure regressions now enforce exactly that ownership.

The last fully produced R6 Windows GUI candidate remains exact source
`1b28ad3e51b761bb2f79a7066b579d6b12610ba2`, Actions
`39273084795`, R6 job `118130308229` **PASS**. Debug and Release CLANG64
full CTest each passed **691/691**; R6 native preflight passed **59/59** in each
configuration; R10 private-fixture security preflight passed **3/3** and
**5/5** groups in each configuration; unsupported-password GUI CTest passed
**1/1**; native packaging/PE closure passed **41 images / 571 imports**;
extracted GUI first-screen/no-socket/rerun/native system-state smoke **PASS**;
R6 sanitizer selection passed **59/59**. The ordinary Windows MSVC lane at the
same SHA passed Debug and Release **673/673**, including
`packaging.windows-portable-gui-clean-release-structure-denials` on native
Windows.

Internal artifact `12197052099`,
`r9-windows-unverified-1b28ad3e51b761bb2f79a7066b579d6b12610ba2`,
has Actions-container SHA-256
`f0f1b706ee388a078be3ba8b4c3b32e87cce6acc359e6513e337c0292e03fe59`.
Its exact inner user ZIP is
`rdp-server-portable-gui-0.1.0-windows-x86_64-1b28ad3e51b7.zip`, SHA-256
`d1e0ea0981fdc0b51674fbb66fa5eee3ffa39f18912a751c243aa28cf89fe532`;
the sidecar matches. Independent extraction verifies 40 bundled DLLs, 41
x86-64 PE images, 531 GNU-objdump imports and zero unbundled non-system imports;
all manifest/internal SHA-256 records match. The 40 DLL names and hashes are
identical to the prior `2fcfebee...` candidate. No owner-provided failed human
ZIP is available for byte comparison, so that specific dialog/DLL remains
unverified.

The clean non-admin Windows consumer for the `1b28...` run is still **QUEUED
/ NOT RUN** on `r9-clean-windows-gui`; only the internal unverified artifact
exists and no public `rdp-server-portable-gui-windows-x86_64` artifact has
been published. Windows portable release therefore remains **BLOCKED**. R6
read-only firewall/TermService/RDP-policy/requested-port checks are unchanged.
Positive Windows RDP serving remains independently **BLOCKED** on R2
SSPI/CredSSP authenticated revocable SID/WTS authority and a concrete R10
Windows WTS/session owner.

## R9 `9e4222cf` CI receipt — Windows compile failure (2026-10-19)

Exact SHA `9e4222cfe909ad3aabee6d0bb0a99142f0354877`, Actions
`39274959607`: hosted PowerShell parser **PASS**; primary workflow structure
**PASS**; Linux GUI build/package **PASS** with artifact `rdp-server-gui-linux`
ID `12197007323`; `protocol (windows-latest)` **FAIL** at MSVC compilation
because `std::numeric_limits<std::uint64_t>::max()` collided with the Windows
`max` macro. Therefore this SHA is not a release PASS.

The downloaded Linux artifact contains inner ZIP
`rdp-server-gui-0.1.0-linux-X64-9e4222cfe909.zip`, SHA-256
`0f9bedb20e1c52a1023e9f01bae740b2d2ce33494f5161524b6cb9d2c9e018c7`,
with `bin/rdp-server-desktop`, `run-gui.sh`, `RDP Server.desktop`, and
`plugins/platforms/libqxcb.so`; the CLI `rdp-server` is absent. Clean Windows
remains **BLOCKED / NOT RUN** and no public Windows PORTABLE-GUI receipt is
claimed.

## R9 exact checksum/parser gate and clean-runner receipt contract (2026-10-19)

Authoring parent: `1bc7dc8e779b8b003b6cde07e0efeb6a01560a1e`. On exact baseline
`2fcfebee9e94b064ebf54617cd224982060471a0` / Actions `39244189634`, macOS
arm64 PORTABLE-GUI `rdp-server-portable-gui-macos-arm64` (`12183271544`) was
downloadable. Windows had only internal exact-SHA candidate
`r9-windows-unverified-2fcfebee9e94b064ebf54617cd224982060471a0`
(`12182782501`) because clean Windows was queued; no public Windows GUI was
released. Linux GUI was absent because its build failed. `protocol-package-*`
are SDKs and `server-test-package-*` are startup-disabled SERVER-TEST bundles.

GUI entrypoints: Windows `RDP-server-GUI.exe` + `plugins/platforms/qwindows.dll`;
macOS `rdp-server-desktop.app/Contents/MacOS/rdp-server-desktop` + Cocoa plugin;
Linux `bin/rdp-server-desktop` via `run-gui.sh` / `RDP Server.desktop` +
`plugins/platforms/libqxcb.so`.

### Provisioning `r9-clean-windows-gui`
Use a disposable Windows x86_64 snapshot with a standard non-Administrators
user in a real Explorer desktop. Launch the Actions runner interactively in
that same session, never as a service/Session 0, with labels
`self-hosted,Windows,X64,r9-clean-windows-gui`. Do not provision MSYS2, Qt,
LLVM/Clang, CMake, OpenSSL, vcpkg, SDK development paths, or repair tooling.
Do not mutate firewall, TermService, RDP policy, service modes, or ports.

Consume only `r9-windows-unverified-<exact SHA>` from the same producer run;
keep the inner ZIP and `.zip.sha256` unchanged. Preserve non-admin Explorer,
OS-only child PATH, Unicode/space extraction, first window, hidden tests,
close/relaunch, process TCP/UDP checks, and firewall/service/RDP-state equality.

### Manual receipt fallback
Transfer unchanged exact producer ZIP/sidecar and exact-SHA `scripts/`, require
the hosted parser job green, then run:
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\clean_windows_portable_gui.ps1 -Archive <exact-zip> -ExactGitSha <40-hex-sha> -Receipt <receipt.json>`
Accept only exit zero with matching exact SHA/archive/outer SHA-256 and
`non_admin_interactive: true`. No operational receipt exists at authoring:
**clean Windows remains BLOCKED / NOT RUN**.

## R6 clean-gate regression follow-up (2026-10-19)

The PowerShell consumer repair in `67ea710697dfbcdc9dafb1badb047c50b61ece07`
was correct, but that commit's generated Python regression source was malformed.
Follow-up `e9c4abb43efb59ff24c9eceda594da3c6503452a` restores
`tests/test_r9_clean_windows_gate.py` from the pre-change source and reapplies
only narrow fail-closed checks: the checksum inventory owner, explicit
`[regex]::Match`, `Groups[2].Value` access and terminal clean-PASS marker
must each occur exactly once; duplicate tails are denied. On Windows, the same
ordinary full-CTest file additionally parses
`scripts/clean_windows_portable_gui.ps1` through
`System.Management.Automation.Language.Parser`.

Source inspection of the follow-up is **PASS**. Exact publication-SHA CTest/CI
is **PENDING** at authoring; clean interactive non-admin exact-ZIP execution is
still **NOT RUN / BLOCKED** pending `r9-clean-windows-gui`. The package,
OS-only child PATH, firewall/TermService/RDP-policy/requested-port read-only
contracts and the R2/R10 native-host blockers are unchanged.

## R6/R9 clean Windows verifier repair — release still blocked (2026-10-19)

Authoring parent `660068b5719e1d997b782b90a5fc928cc9e2133f`. The clean-Windows consumer on current main still
contained the malformed `e2e48f0f` splice: its SHA256SUMS regex was truncated and
the post-checksum body was duplicated, so the queued self-hosted consumer could
not provide valid PowerShell execution evidence. Restore the last known-good
consumer body and keep the intended explicit `[regex]::Match` capture object.
The existing full-CTest gate
`packaging.windows-portable-gui-clean-release-structure-denials` now rejects
a truncated/duplicated checksum parser, and on Windows additionally parses the
actual consumer with `System.Management.Automation.Language.Parser`.

Independent exact-artifact inspection remains separate from the clean-machine
gate. Main source `2fcfebee9e94b064ebf54617cd224982060471a0`, Actions
`39244189634`, R6 producer job `118032566420` **PASS**, emitted internal
artifact `12182782501`. Its GitHub Actions container SHA-256 is
`caea4cb15be32f2fac5f3bea7eed0913cd397ceb8841135c91df526465a4ed8e`;
the contained exact ZIP SHA-256 is
`61484dc968ba3d478dd66b74c1c22f482e210d1ff9e4a7a3a0e81377303240bb`.
Offline inspection finds 40 bundled DLLs, 41 PE images, all x86_64, 531 parsed
imports with GNU objdump and zero unbundled non-system imports under the R9
system-DLL policy. The 40 DLL names and hashes match the previously inspected
PR #25, PR #26 and `aee09e50` candidates. The owner-provided failed human ZIP
is still unavailable, so byte parity and its exact loader dialog/DLL remain
**UNVERIFIED**. The earlier proven packaging defect was `windeployqt` omitting
`libc++.dll` plus ICU, PCRE2, zlib/zstd, freetype/harfbuzz, PNG/JPEG,
Brotli and GLib dependencies; `ab63d1bb` already stages that recursive
non-system closure app-local.

No clean interactive non-admin Windows receipt is claimed by this source
repair. The public Windows portable release remains **BLOCKED** until the
self-hosted `r9-clean-windows-gui` job executes the exact newly produced ZIP
with Windows-system-only child PATH and publishes its matching receipt. R6's
read-only firewall/TermService/RDP-policy/requested-port observations are
unchanged. Positive Windows RDP serving remains independently **BLOCKED** on
R2 SSPI/CredSSP authenticated revocable SID/WTS authority and a concrete R10
Windows WTS/session owner.

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

