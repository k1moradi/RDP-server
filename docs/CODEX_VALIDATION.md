# CODEX_VALIDATION.md — validation ledger and agent contract

## R10 TLS server-certificate purpose authoring (2026-10-16)

**Starting main:** `d4669a0a612bf916c6f406d42f26d1174d7130c8`. Current source includes the previous Windows
CRLF and deterministic fixture-permission corrections. The latest recorded
hosted Windows/MSVC matrix reports **285/285 PASS** in both Debug and Release,
including both original configuration-positive runtime CTests. Owner Windows
MSYS2 CLANG64/Clang23 is **NOT RUN**.

**Production change:** the offline `--check-tls-credentials` command now
requires `X509_check_purpose(certificate, X509_PURPOSE_SSL_SERVER, 0) == 1`
after secure native file checks, exact bounded reads, current-time validation,
and certificate/private-key matching. No listener/session/service is activated.

**Dedicated CTest:** `runtime.rejects-tls-credentials-client-only-certificate`
uses a fixed certificate carrying clientAuth-only EKU with the existing matching
test private key and requires the existing generic exit-3 denial.

**Authoring validation:** OpenSSL 3.5.5 C++23 `-Wall -Wextra -Wpedantic
-Werror` API compile probe: **PASS**. Full checkout build/CTest, owner
Linux/X11, Windows CLANG64/Clang23, macOS27 and live TLS/server admission:
**NOT RUN** here. Exact-SHA hosted CI is pending. Trust/hostname/revocation and
secure listener/service lifecycle remain OPEN.

## R6 native duplication owner (2026-10-16; exact-SHA CI pending)

**Inspected starting main:** `e540be81f297c7f880c6b03db6ffc1a3ad8998ad`.
Added `src/windows/windows_dxgi_duplication_owner.{h,cpp}` to the
existing Windows desktop CMake target and
`tests/windows_dxgi_duplication_owner_cases.cpp` to the existing R6
test executable; updated shared CTest registration, dispatch and R6
roadmap/architecture. Deterministic injected callbacks exercise
adapter/output selection, unique native monitor matching, detached/
mismatched/ambiguous/changed output denials, creation failures, COM
cleanup order, terminal close and monotonic device epochs.

**Dedicated Windows-only tests:** 
`windows.capture-dxgi-duplication-owner-lifecycle`,
`windows.capture-dxgi-duplication-owner-selection-denials`,
`windows.capture-dxgi-duplication-owner-epoch-revocation`.
These are offline tests; no real desktop is captured.

**NOT RUN at authoring:** native Windows build/CTest (no Windows SDK
or owner CLANG64 toolchain in this workspace), full canonical CMake/
CTest (no GitHub checkout over container network), live duplication,
owner MSYS2 CLANG64 Clang23, independently authorized R2/R3 admission,
R4 hardware capture delivery, real Microsoft-client M4 acceptance.
The GitHub connector is used for atomic direct-to-main publication;
exact-SHA Actions evidence must be inspected separately. M4 OPEN.
Next R6 task: generation-safe bounded DXGI pointer shape ownership.


Read **[AGENTS.md](../AGENTS.md)** on every prompt together with
[VISION.md](VISION.md), the living TODO in
[docs/ROADMAP.md](ROADMAP.md), and the mandatory
[coding](coding_standards.md), [testing](testing_standards.md),
[compilation](compile.md) and [benchmark](benchmark.md) standards.

The detailed acceptance contracts live in `docs/testing_standards.md`.
This file records the evidence, not an alternative test policy.

## R6 Win32 cursor metadata snapshot (2026-10-16; exact-SHA CI PASS)

**Authoring parent main:** `10fff1ab437b74f7065bdd4c87dd9a5095f1f050`. Added
`src/windows/windows_cursor_snapshot.{h,cpp}` to the existing R6 native
adapter. The shared callback seam validates visible cursor dimensions/hotspot,
translates Win32 screen coordinates through the existing monitor layout,
rejects monitor gaps and preserves prior output on invalid/unavailable reads.
Hidden/suppressed cursor state clears stale visible metadata. The native
callback uses `GetCursorInfo`, `GetIconInfo` and `GetObjectW`; temporary
mask/color `HBITMAP` ownership is stack-RAII and always released. Color
bitmap dimensions must match the mask; monochrome mask height must be even
and is halved. Cursor metadata is capped at 256x256. No shape pixels,
HCURSOR lifetime, R4 scheduling, input or authorization was added.

**New Windows-only CTests:** `windows.cursor-snapshot-visible-and-hidden`
and `windows.cursor-snapshot-rejections`, in the existing R6 executable
and central registry. **PASS (isolated portable seam only):** GCC 14.2 and
Clang 17 C++23 with strict warnings, plus Clang 17 ASan/UBSan.

**Implementation SHA:** `0ee521f2802bb2f2fd3fd6fa1ebfb834f4d47287`.
**Actions run:** [38871393796](https://github.com/k1moradi/RDP-server/actions/runs/38871393796),
overall **PASS**. Windows/MSVC native R6 target compiled and registered CTest
passed **283/283** in both Debug and Release; both
`windows.cursor-snapshot-visible-and-hidden` and
`windows.cursor-snapshot-rejections` passed in both configurations.
Linux/GCC passed **281/281** Debug and Release; macOS/Clang passed
**263/263** Debug and Release. Documentation policy passed. R9 Clang
ASan/UBSan protocol tests and bounded coverage-guided MCS/CLIPRDR fuzzer
passed. Each staged installed SDK consumer passed **1/1** and packaging/
artifact upload completed; prerelease publication was skipped without a tag.

**NOT RUN:** owner Windows MSYS2 CLANG64 Clang23/Linux X11/macOS27 one-root
validation, live authorized cursor/session, Microsoft-client M4 acceptance
or performance. **Next:** bounded native cursor shape extraction
with explicit color/monochrome transparency semantics and generation-safe
R4 ownership.

## R6 target-session change revocation (2026-10-16; exact-SHA CI PASS)

**Authoring parent main:** `5510d09b31bb1aaa0697a9086edeb317e3c12b42`. The existing
`WindowsCaptureSessionGenerationGuard` now accepts a serialized
`notifySessionChange(sessionId)` revocation event. A valid target-session
change closes the guard; unrelated valid session changes are ignored;
zero/sentinel IDs fail closed; repeated target delivery is idempotent.
Target notification during a WTS observation prevents publication of the
old generation. If a guarded DXGI frame is already mapped, the next
existing capture-cycle generation check closes the cycle, unmaps staging
before `ReleaseFrame`, and publishes no caller-owned pixels.

**Changed files:** `src/windows/windows_capture_session_guard.{h,cpp}`,
`tests/windows_capture_session_guard_cases.cpp`,
`tests/test_windows_desktop_geometry.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, and this ledger.
**Implementation SHA:** `1efd3688872cc38e7c932efc661c793edfd4c4b7`.
**Actions run:** 38865710309, overall **PASS**. Linux/GCC registered CTest
**273/273** Debug and Release; Windows/MSVC **273/273** Debug and Release;
macOS/Clang **255/255** Debug and Release. Both target-session-change R6
cases passed in Windows Debug and Release. Documentation policy, R9
security/protocol sanitizers, staged SDK consumers and package steps PASS.
Owner MSYS2 CLANG64/Clang23, live WTS delivery and M4 remain NOT RUN.
**New Windows-only CTests:** `windows.capture-session-change-revocation`
and `windows.capture-session-change-denials`. They use synthetic
session/generation/frame callbacks only; ordinary CTest neither registers
for native WTS notifications nor touches a real desktop.

**PASS (isolated portable seam only):** Clang 17 C++23 with
`-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror`, and
the same seam under ASan+UBSan with leak detection. **NOT RUN at
authoring:** full canonical repository CMake/CTest, hosted exact-SHA CI,
native Windows SDK/MSVC, owner Windows MSYS2 CLANG64 Clang23/Linux
X11/macOS27, live WTS event delivery, R2/R3 Windows authorization,
Desktop Duplication, Microsoft-client M4 acceptance or performance.
The guard adds no session-notification registrar, token/desktop switch,
capture scheduler or authorization capability. **Next:** route an
independently authorized target session's native window/service WTS events
onto the existing serialized R6 owner, then bind authorized D3D11/DXGI
device/output lifetime.

## R8 nonblocking pending-paste receipt exact-SHA hosted CI (2026-10-16)

**Authoring parent main:** `46b1ca77c4c2c00bbd66e02de71896999f8c71fd`. The existing event-loop-confined
`RemoteTransfer` now owns one portable native paste receipt in addition to
its CLIPRDR generation/request state. The caller supplies monotonic
`steady_clock` time and a future deadline. Receipt sequences never reset on
disconnect. Polling completes only from current-generation verified Unicode
text/image data or returns one terminal rejection for timeout, a valid
clipboard replacement, explicit native owner loss, disconnect or channel
poison. A pending live paste blocks new `beginNextPrefetch` speculation;
an already-sent ambiguous Format Data Request still must drain before the live
paste can reuse the no-request-ID response slot. No sleeps, worker thread,
condition-variable wait, OS clipboard API, image conversion or R3 authority is
introduced.

**Changed:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`, and this ledger.
**Dedicated CTest:** `clipboard.nonblocking-paste-readiness` covers
registration denial without an offer/with expired deadlines, live paste during
an already-in-flight speculative image request, suppression of speculative
fallback, ready Unicode and DIB completion, exact-deadline timeout, stale and
valid owner-loss cancellation, valid Format List replacement, disconnect,
monotonic reconnect receipts and channel poison.

**Implementation SHA:** `cc8e0a9cbfbbf6891720eab03f1e94b926a30285`.
**Actions run:** [38870845839](https://github.com/k1moradi/RDP-server/actions/runs/38870845839),
overall **PASS**. Linux/GCC Debug **277/277** and Release **277/277**;
macOS/Clang Debug **259/259** and Release **259/259**; Windows/MSVC Debug
**277/277** and Release **277/277**. The dedicated
`clipboard.nonblocking-paste-readiness` CTest passed in all six
configurations. R9 Clang ASan/UBSan passed **19/19 clipboard** tests and
**10/10 MCS/CredSSP** tests, and `fuzz.mcs-cliprdr-bounded` passed **1/1**.
Documentation policy passed. Each platform's staged installed-package
consumer passed **1/1**; packaging and artifact upload completed, while
prerelease publication was skipped without a release tag.

**NOT RUN:** local canonical CMake/CTest in this tool environment, owner
Linux/X11 / Windows MSYS2 CLANG64 Clang23 / macOS27 one-root commands,
native clipboard ownership/INCR, Microsoft-client/Firefox paste and
performance. Next R8 gate: bind the receipt to one R5/R6/R7 native
asynchronous clipboard adapter path with bounded lazy conversion while
preserving R3 writer authority.

## R8 validated image readiness exact-SHA hosted CI (2026-10-16)

**Starting main SHA:** `a1ae1e7aef0ca67bd155271fc760a6cff70d9a9a`. The existing R8 `RemoteTransfer`
owner now validates and owns current-generation registered PNG, CF_DIBV5
and CF_DIB response bytes without eager image expansion. Registered PNG
name resolution precedes numeric 17/8 interpretation; CF_DIBV5 requires a
124-byte BITMAPV5HEADER. The retained wire payload stays below the existing
8-MiB CLIPRDR PDU boundary, and advertised dimensions must fit a 256-MiB
prospective 32-bpp decoded working set. `validateDib` provides an
allocation-free structural path reused by `wrapDibAsBmp`.

**Changed:** `src/clipboard/clipboard_protocol.{h,cpp}`,
`src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, and this ledger.
**Dedicated CTest:** `clipboard.verified-image-readiness` covers valid
named PNG, corrupt PNG rejection, valid DIBV5/DIB, non-V5 header rejection,
decoded-size bound, generation invalidation/stale response drain, registered
PNG numeric-ID collision, disconnect and poison hiding.

**Implementation SHA:** `015217fc304dd7b4beea73a09e1f02bbe44b038f`.
**Actions run:** [38865310807](https://github.com/k1moradi/RDP-server/actions/runs/38865310807),
overall **PASS**. Linux/GCC Debug **273/273** and Release **273/273**;
macOS/Clang Debug **255/255** and Release **255/255**; Windows/MSVC Debug
**271/271** and Release **271/271**. The dedicated R8 CTest passed in all
six configurations. R9 Clang ASan/UBSan passed **18/18 clipboard** tests
(including the new readiness test) plus **10/10 MCS/CredSSP** tests.
Documentation policy passed. Each platform's staged installed-package
consumer passed **1/1** and packaging/artifact steps completed; prerelease
publication was skipped because no release tag was present.

**NOT RUN:** local compile/full CTest in this sandbox (GitHub DNS checkout
unavailable), owner Linux/X11 / Windows MSYS2 CLANG64 Clang23 / macOS27
one-root commands, genuine R2/R3 authorization, native OS clipboard,
Microsoft-client/Firefox image paste and performance. Next R8 gate is native
nonblocking presentation/conversion over the authorized R3 writer lifecycle.

## R8 verified Unicode text exact-SHA hosted CI (2026-10-16)

**Implementation SHA:** `8f5e194a5662ae2f70a849c0e451c8bbb60f87b0`.
**Actions run:** [38857378176](https://github.com/k1moradi/RDP-server/actions/runs/38857378176).
**PASS:** Linux/GCC Debug **238/238** and Release **238/238**;
Windows/MSVC Debug **239/239** and Release **239/239**;
`clipboard.verified-unicode-text-readiness` passed in all those
runs and macOS/Clang Debug; R9 clipboard ASan/UBSan tests passed;
documentation policy passed.
**FAILED overall:** macOS/Clang Debug **205/220**, 15 failures in
`transport.tcp-native-accept-*`, `transport.tcp-native-listener-*`,
`transport.tcp-listener-poll-*` and `transport.tcp-owned-*`.
The first failing boundary is `transport.tcp-native-accept-ownership`:
`test_owned_preauth_session.cpp:1564` asserts
`accepted.outcome == TcpAcceptOutcome::Accepted`; no R8 CTest failed.
macOS Release stage did not run because Debug aborted the job.
No claim of full three-platform acceptance.
**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64 Clang23,
macOS27, genuine R2/R3 admission, native OS clipboard,
Microsoft-client/Firefox paste and performance.
**Next gates:** R1/R9 triage macOS TCP listener regression and recheck
same-SHA CI; R8 proceeds with validated PNG/DIB and native adapter
integration without disguising the transport failure.

## R8 verified Unicode clipboard readiness (2026-10-16)

**Starting main SHA:** `9dd3197115bcd56d4465ec18b1bdedddcccc5336`. **Files:**
`src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md` and this ledger.
**New CTest:** `clipboard.verified-unicode-text-readiness`.
The current-generation CF_UNICODETEXT payload must be strictly
terminated and valid UTF-16LE, limited to 1 MiB on wire, copied
into UTF-8, and invalidated on reoffer/disconnect. Invalid content
is not native-paste ready and does not poison otherwise sound framing.
**NOT RUN at authoring:** complete checkout CMake/full CTest,
hosted exact-SHA CI, owner Linux/X11, Windows CLANG64/Clang23
and macOS27, native clipboard, Microsoft client and performance.
**Next:** exact-SHA CI and PNG/DIB validation before OS adapter paste.

## R9 CLIPRDR core wire codec deterministic mutation gate (2026-10-15)

**Parent main:** `8a4f466c3bab9af155da623a54dba91b7cb7529d`. **Changed files:**
`tests/test_clipboard_protocol.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/CODEX_VALIDATION.md`.
**New CTest:** `clipboard.wire-codec-mutated-boundaries`
(labels `protocol;clipboard;security;offline`), using the existing
`test_clipboard_protocol` executable and production
`encodePdu/decodePdu` functions, no duplicate test registry.

**R9 regression:** 40 codec round trips across ten packet lengths and
four type/flag pairs; all strict prefixes and one trailing-byte variant
are rejected; all 312 single-bit mutations in a 39-byte seed validate
strict declared little-endian length, correct transparent opaque fields,
read-only input and zero-copy payload span. The structural codec must
not reject unknown type/flag values itself; stateful CLIPRDR ownership
and negotiation restrictions are separately checked by RemoteTransfer.

**PASS, locally isolated ONLY:** first-party production wire-codec
function bodies tested using a minimal extracted C++23 harness in
`~/rdp-server/build/r9-wire-codec`, GCC 14.2 `-O1 -g -Werror` and
`-O3 -DNDEBUG -Werror` (test assertions active), plus Clang 17
`-O1 -g -Werror -fsanitize=address,undefined` with ASan leak detection.
A deliberate local mutant disabling `decodePdu` length equality fails
with exit 134 on the trailing-byte assertion, as expected. This mutant
is NOT a reported production defect.

**NOT RUN:** canonical full repository configure/build/CTest on the
actual source tree, GitHub Actions on the new exact commit, Windows
MSYS2 CLANG64 Clang23, owner Linux/X11, macOS27, external Microsoft
clients and authenticated OS authorization/desktop. No full local
checkout was available (GitHub DNS lookup failed), so isolated PASS
must not be equated to full CTest PASS or the RDP product acceptance.
**Next:** exact-commit hosted matrix/sanitizer receipt and owner's
three-platform same-SHA CTest, then R3/R8 joined authorization and
lifecycle fuzzing once a production admitted-session boundary exists.

## R6 active-session revocation exact-SHA hosted CI (2026-10-15)

Implementation commit `6369d8622057aa3f315af55011b52c1d74325d5b`,
[Actions 38864378401](https://github.com/k1moradi/RDP-server/actions/runs/38864378401):
overall **FAIL**, but the failing boundary is R10 runtime TLS credential
validation, not R6. Linux/GCC full registered CTest **268/268 PASS**
in Debug and Release. macOS/Clang full registered CTest **250/250 PASS**
in Debug and Release. Windows/MSVC successfully compiled/linked
`windows_capture_session_guard.cpp` with `wtsapi32`; both new cases
`windows.capture-session-generation-active-lifetime` and
`windows.capture-session-revocation-denials` PASS in Debug.
Windows full Debug is **261/266 PASS**, with exactly five failures:
`runtime.validates-tls-credentials-matching-pair`,
`runtime.rejects-tls-credentials-mismatched-key`,
`runtime.rejects-tls-credentials-malformed-certificate`,
`runtime.rejects-tls-credentials-malformed-key`, and
`runtime.rejects-tls-credentials-encrypted-key`. Windows Release and
downstream package steps were **NOT RUN** after that Debug failure.
Documentation-policy and R9 security/protocol sanitizer jobs PASS.

No R6-specific regression is observed at this SHA. This hosted MSVC
result does **not** establish owner MSYS2 CLANG64/Clang23 compatibility,
R2/R3 Windows authorization, lock/unlock revocation, live Desktop
Duplication, Microsoft-client M4 acceptance or performance. Those remain
NOT RUN.

## R6 native active-session revocation guard (2026-10-15)

**Authoring parent main:** `43953fd5aa05b9bb913430825313caf41e2ebdd5`. **Changed files:**
`src/windows/windows_capture_session_guard.{h,cpp}` (new),
`tests/windows_capture_session_guard_cases.cpp` (new),
`tests/test_windows_desktop_geometry.cpp`, `tests/CMakeLists.txt`,
`CMakeLists.txt`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/compile.md`, and this ledger.
The guard composes native/synthetic WTS-session observation with the
existing R6 `WindowsCaptureGenerationReader`: current-process session
must equal the caller-selected target, target state must be active, and
the existing session/device epochs must be nonzero. Any failure is
terminal for that guard. This is NOT an R2/R3 authorization capability.

**New registered Windows CTests:**
`windows.capture-session-generation-active-lifetime`,
`windows.capture-session-revocation-denials`.
They use only synthetic session/generation callbacks and a synthetic
one-pixel frame pipeline; the native WTS function is compiled on
Windows but is never invoked by ordinary CTest.
**NOT RUN at authoring:** complete exact-SHA hosted matrix,
owner Windows MSYS2 CLANG64 Clang23/Linux X11/macOS27, live WTS
session/lock state, real DXGI desktop, Microsoft client and benchmark.
M4 remains OPEN.

## R6 exact-commit generation-revocation hosted CI (2026-10-15)

Code/test/docs commit `fdedf92bb8e40a0626a866dfdca6210ccc3fcbc5`,
[Actions 38857611907](https://github.com/k1moradi/RDP-server/actions/runs/38857611907),
overall **FAIL**, with failures outside the R6 source:
Linux/GCC Debug and Release CTest **251/251 PASS** each;
Windows/MSVC Debug compiles the native R6 backend and executes both
new CTests **2/2 PASS**, but full Debug CTest **249/250 FAIL**
at `runtime.validates-tls-files-private-regular` (R10 runtime);
macOS/Clang Debug CTest **218/233 FAIL**, 15 native
`transport.tcp-*` aborts on expected TCP accept (R1 transport).
Windows/macOS Release and related downstream SDK/package steps were
**NOT RUN** due to their Debug test failures.
The documentation-policy and R9 security-protocol sanitizer jobs PASS.
R1 subsequently authored a separate transport correction
`c78a745aaa5180007a00a35a2858072974c2ad17` (not tested as
part of the R6 SHA; its CI must be checked independently).
No Windows CLANG64/Clang23 owner validation, real R2/R3 admission,
live desktop/client acceptance or performance benchmark has run.
R6-specific regressions observed in this exact-SHA CI: **none**.
M4 is still open.

## R6 capture generation revocation checks (2026-10-15)

**Authoring parent main:** `ea1cf468986b15bcc4ee0b43b70082cfc0862e82`. Existing
`WindowsDxgiCaptureCycle` gains revocation-only
`WindowsCaptureGenerationReader` and pinned session/device epochs.
New/changed code and tests:
`src/windows/windows_dxgi_capture_cycle.{h,cpp}`,
`tests/windows_capture_cycle_cases.cpp`,
`tests/test_windows_desktop_geometry.cpp`,
`tests/CMakeLists.txt`, plus `docs/ROADMAP.md`,
`docs/ARCHITECTURE.md` and this validation ledger.
**New offline conditional Windows CTests:**
`windows.capture-generation-pinned-frame-lifetime`,
`windows.capture-generation-revocation-denials`.
Read-only synthetic fixtures verify stable copies, terminal
pre-acquire and mid-map generation change, pre-consume and
in-consumer revocation, callback unavailability, malformed
binding, cancellation, reentrancy and exactly-once unmap/ReleaseFrame.
Guarded raw frame() borrows are suppressed. Legacy unbound
cycles remain test-only. This does NOT implement R2/R3 OS admission.

**NOT RUN at authoring:** real synchronized source-tree CMake/CTest
(GitHub clone DNS unavailable in this environment), Windows
MSYS2 CLANG64 Clang23 owner build, owner Linux/X11 and macOS27,
approved live Win32 session/device selection, R4 asynchronous
encoding, Microsoft RDP client, performance benchmarks. Hosted
Windows/MSVC Debug/Release and Linux/macOS exact-SHA CI must be
inspected after the atomic commit. M4 remains open.

## R9 wire codec exact-commit hosted CI triage (2026-10-15)

**Published R9 source:** `ab78ed83f59b64463123382da34b8b13b832c0e1`
([atomic main commit](https://github.com/k1moradi/RDP-server/commit/ab78ed83f59b64463123382da34b8b13b832c0e1)).
[Exact SHA Actions run 38857546859](https://github.com/k1moradi/RDP-server/actions/runs/38857546859):
**overall FAIL**; do not infer cross-platform milestone acceptance
from the independently passing new case.

- **R9 focused CTest PASS:** `clipboard.wire-codec-mutated-boundaries`
  passed Ubuntu/GCC, macOS/AppleClang and Windows/MSVC **Debug**;
  Ubuntu/GCC **Release** also passed. The independent
  `r9-security-protocol-sanitizers` job passed
  **17/17** clipboard tests (including the new R9 CTest) and
  **10/10** MCS/CredSSP negatives under Ubuntu/Clang 18
  ASan+UBSan with leak detection.
- **Linux matrix PASS:** full **251/251 Debug** and
  **251/251 Release**; downstream SDK consumer/package gates
  passed. **Documentation policy PASS**.
- **macOS matrix FAIL:** **218/233 Debug**. Fifteen pre-existing
  `transport.tcp-native-*` / `transport.tcp-owned-*`
  cases aborted at TCP accept expectations, first
  `test_owned_preauth_session.cpp:1564` expecting
  `TcpAcceptOutcome::Accepted`. This is an R1 native
  listener/accept boundary, not an R9 codec-case failure.
  R1 later committed a macOS listener check correction
  `c78a745aaa5180007a00a35a2858072974c2ad17`;
  verification of the corrected SHA is a distinct run.
- **Windows matrix FAIL:** **247/248 Debug**. Only
  `runtime.validates-tls-files-private-regular` failed
  (CMake script line 317, unexpected runtime exit status 3).
  This is R10 TLS-file validation, not R9 wire decoding.
- **NOT RUN:** macOS and Windows Release in this failed run,
  owner's Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
  full CTests, Microsoft real client/OS-authorized desktop.
  A green R9 unit test/sanitizer run is not an admitted RDP session.

**Next R9 gate:** confirm successful exact-SHA full matrix after
the R1/R10 repairs and collect the owner's matching SHA receipts;
continue R3/R8 admitted virtual-channel negative integration.

## R6 native DXGI damage metadata bound to one capture frame (2026-10-15)

**Remote main used for integration:** `3c09e0763d019d0423919f17d880375167bb7be7`. **Changed files:**
`CMakeLists.txt`, `tests/CMakeLists.txt`,
`src/windows/windows_dxgi_damage.{h,cpp}`,
`src/windows/windows_dxgi_capture_cycle.{h,cpp}`,
`tests/windows_capture_damage_cases.cpp` (new),
`tests/test_windows_desktop_geometry.cpp`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/compile.md`, and this ledger.
**New Windows-only CTests:**
`windows.capture-dxgi-native-damage-map-lifetime` and
`windows.capture-dxgi-native-damage-denials`. Production native
callbacks read DXGI-reported move/dirty bytes on the existing acquired
lease and normalize to existing portable rectangles, with strict
combined-size bounds and transactional publication. Bad metadata and
session cancellation unmap staging then release the existing lease.

**PASS (isolated sparse test fixture, NOT full repository):**
Linux GCC 14.2 and Clang 17 C++23 strict warnings, ASan/UBSan,
focused 2/2 each and `ctest --test-dir ~/rdp-server/build
-C Debug --output-on-failure` 8/8 sparse synthetic CTests.
**NOT RUN at authoring:** full checkout CMake/CTest, actual Windows
SDK/hosted MSVC at new SHA, owner MSYS2 CLANG64 Clang23,
Linux/X11/macOS27, R2/R3-authorized desktop, Microsoft client
and performance. M4 remains OPEN; GitHub Actions to be checked
after publication.

## R6 caller-owned packed BGRA frame snapshot (2026-10-15)

**Starting main SHA:** `b127398873a810d50957ad94537d56a4c0eb8b55`. **Actual changes:**
`src/windows/windows_dxgi_capture_cycle.{h,cpp}`,
`tests/windows_capture_cycle_cases.cpp`,
`tests/test_windows_desktop_geometry.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, and this ledger.
**New Windows-only canonical CTests:**
`windows.capture-packed-copy-lifetime`,
`windows.capture-packed-copy-denials`. The existing
`WindowsDxgiCaptureCycle` now copies mapped D3D11 BGRA visible
pixels into a caller-supplied independent buffer, packs away row
padding, rejects short or overlapping buffers and only publishes the
portable `FramebufferView` after successful unmap and DXGI release.
No queue, frame scheduler, native authorization or desktop access.

**PASS (isolated sparse fixture, NOT full-repository):** Linux GCC 14.2
`g++ -std=c++23 -O2 -Wall -Wextra -Wpedantic -Werror -UNDEBUG`
2/2, Clang 17 `-std=c++23 -O1 -g -Wall -Wextra -Wpedantic
-Werror -UNDEBUG -fsanitize=address,undefined` 2/2, and
`ctest --test-dir ~/rdp-server/build -C Debug --output-on-failure`
6/6. Compilation covered production-equivalent capture-cycle,
staging-owner, lease-owner and BGRA source via a local sparse fixture;
it was not the canonical project checkout.
**NOT RUN at authoring:** full native repository build/CTest,
Windows CLANG64 Clang23, real DXGI SDK/hardware frame, owner
Linux/X11/macOS27 acceptance, Microsoft RDP client, and benchmark.
Exact-SHA hosted Actions must be checked after publishing. M4 open.

## R6 DXGI synchronous scoped-frame handoff (2026-10-15)

**Parent main SHA inspected:** `d3a7137dcb8b4c0d2e4a036068dca04af4617de9`. The native D3D11
staging/Map owner and `WindowsDxgiCaptureCycle` already existed.
**Changed paths:** `src/windows/windows_dxgi_capture_cycle.{h,cpp}`,
`tests/windows_capture_cycle_cases.cpp`,
`tests/test_windows_desktop_geometry.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/CODEX_VALIDATION.md`. The one existing R6 native executable
now registers `windows.capture-capture-cycle-synchronous-consume-lifetime`
and `windows.capture-capture-cycle-synchronous-consume-denials`.
The callback synchronously borrows BGRA frame memory while the cycle
holds its native map. It cannot reenter capture/release and cannot
invalidate its own backing map through a cycle cancellation until it
returns. On all exits the existing stage unmaps before the DXGI lease
releases, including rejection, failed native release, and topology
revocation. R4 must own any bytes it retains asynchronously.

**PASS (isolated authoring fixture, NOT the full repository):**
Linux Clang 17 C++23 `-Wall -Wextra -Wpedantic -Werror -UNDEBUG
-fsanitize=address,undefined` build and `ctest --test-dir
~/rdp-server/build --output-on-failure` **2/2** for the focused
capture-cycle cases. The fixture compiled the production-equivalent
cycle and existing lease/map logic without native Windows D3D11 SDK.
**NOT RUN:** full exact-SHA repository CMake/CTest, Windows
MSYS2 CLANG64/Clang 23, owner Linux/X11/macOS 27, real authorized
desktop, RDP client, native GPU mapping, benchmark. Hosted CI must
be assessed at the published SHA. M4 remains open.

## R8 portable CLIPRDR Format List wire intake (2026-10-15; CI pending)

The same `RemoteTransfer` instance now owns incoming long and short Format
List validation, generation-local registered `PNG`/`FileGroupDescriptorW`
lookup and Format List Response acceptance. Long names are null-terminated
UTF-16LE when `CB_USE_LONG_FORMAT_NAMES` is jointly negotiated; short
names are 36-byte records with `CB_ASCII_NAMES` selecting ASCII versus
UTF-16LE. Wire parsing is bounded to 64 formats and 256 UTF-16 code
units per long name; duplicate identifiers or known names, bad header,
surrogates, truncation and unsupported flags fail closed. A fixed
eight-byte OK/FAIL response is generated after explicit native offer
acceptance; failed adapter offers advance generation and clear advertised
IDs while an old request's reply remains quarantined. Ordinary
Format Data Responses have no matching wire request ID.

**Files:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, this validation ledger.
**New dedicated CTests:** `clipboard.long-format-list-generation`,
`clipboard.short-format-list-negotiation`, and
`clipboard.format-list-response-native-acceptance`; the existing
`clipboard.remote-transfer` and R9's
`clipboard.remote-transfer-framing-rejections` cases are preserved.
**PASS (isolated Linux fixture harness):** GCC 14.2 and Clang 17
`-std=c++23 -Wall -Wextra -Wpedantic -Werror -O0 -g` compiled the
production `RemoteTransfer` translation unit against a local extract of
the existing CLIPRDR PDU codec; three new cases and existing legacy
cases passed under both compilers. GCC `-fsanitize=address,undefined`
with leak detection passed all three new cases. Outputs remained in
`~/rdp-server/build/`.
**NOT RUN:** complete Git checkout CMake/CTest, GitHub CI for the final
implementation SHA, owner-run Linux/X11, Windows MSYS2 CLANG64/Clang 23
and macOS 27, live client, native clipboard or browser paste, performance.
This isolated harness is not evidence for cross-platform production or
end-to-end clipboard acceptance.
**First missing boundary:** R3's authenticated admitted CLIPRDR channel
and negotiated capabilities, then R5/R6/R7 native clipboard adapters.
**Next:** consume CLIPRDR General Capability Set on the existing
coordinator with fail-closed version/flag tests and channel gating.

## R8 CLIPRDR General Capability negotiation (2026-10-15; CI pending)

**Implemented:** extend the sole portable `RemoteTransfer` owner to parse
optional MS-RDPECLIP `CB_CLIP_CAPS`, limiting capability set count to 16,
checking exact 12-byte General sets, bounded unknown sets, duplicates,
lengths, flags, and stale/repeated capability messages. Absent capabilities
assume zero general flags. Feature decisions use mutually advertised
generalFlags, never the informational version. The new
`receiveNegotiatedFormatListWithResponse` path selects name layout from
negotiated state and preserves stale-generation request isolation.

**Files:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`, `docs/CODEX_VALIDATION.md`.
**New dedicated CTest:** `clipboard.capabilities-negotiation-format-gating`,
covering Microsoft's published CLIP_CAPS example, missing/unknown sets,
default short names, flags and informational versions, malformed lengths,
duplicate general sets, disconnect reset and failure quarantine.
**PASS (focused Linux harness):** GCC 14 strict C++23 Debug, Clang 17
strict C++23 Debug, GCC optimized Release, and GCC ASan+UBSan with leak
detection; previous format-list and existing transfer cases PASS. These
used the production coordinator with a local extract of existing PDU
encode/decode behavior, not a complete repository CTest.
**NOT RUN at authoring:** exact-commit CI/full CTest, owner Linux/X11,
Windows MSYS2 CLANG64 Clang23 and macOS27 platforms, native or real-client
clipboard, Firefox PNG File and performance.
**Dependencies:** R3 authorized CLIPRDR channel and negotiation/send
lifecycle; R5/R6/R7 native clipboard adapters.
**Next:** connect the same coordinator to R3 authorized-channel routing
with explicit cancellation and an integration CTest.

## R8 joined-MCS Format List Response envelope (2026-10-15)

**Increment:** the existing `RemoteTransfer` now packages its most
recent generated eight-byte Format List Response with the standard
`CHANNEL_PDU_HEADER` (8 bytes of data, FIRST|LAST = 0x3) and invokes
R3's existing confirmed-join `encodeJoinedSendDataIndication` for
the same static virtual channel. It does not own an MCS session,
create a transport writer, assign a CLIPRDR channel ID, open TLS or
authorize an OS desktop. Packet encoding is allocation-free with a
fixed stack buffer and caller-owned output. Earlier responses are
invalidated on clipboard reoffer and disconnect. A failed
precondition leaves output untouched.

**Files:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`, and this validation ledger.
**Dedicated new CTest:**
`clipboard.format-list-response-joined-mcs-envelope`. Exact
30-byte uncompressed TPKT/X.224/MCS/CHANNEL_PDU_HEADER/CLIPRDR
response; no joined channel/no written join confirmation,
unknown channel, malformed response flags/length, insufficient
output capacity, native adapter fail ACK, stale response and
disconnect rejection with unmodified output.

**At authoring:** local full checkout build/CTest NOT RUN
(shell GitHub DNS unavailable; development runtime contains a partial
C++ fixture, not an authoritative Git checkout). The actual shared
production translation units and new CTest will run on GitHub-hosted
Linux/GCC, macOS/Clang and Windows/MSVC in the exact commit CI.
Owner Linux/X11, MSYS2 CLANG64 Clang23 and macOS27 full CTest,
real authentication, clipboard, screenshot Firefox paste, and
performance NOT RUN. Record exact-SHA hosted CI separately when
it completes. **Next:** R3 authorized/static channel ID
handoff and writer completion/cancellation; native R5/R6/R7 adapters.

## R8 joined inbound static-VC dispatch (2026-10-15; CI pending)

**Implementation:** `RemoteTransfer::receiveJoinedStaticChannelPdu`
routes only an externally admitted, complete, unsegmented R3 MCS
SendDataRequest matching the expected CLIPRDR channel ID and R3's
fully confirmed join. Check MS-RDPBCGR `CHANNEL_PDU_HEADER` uncompressed
length, FIRST|LAST, unsupported compression, and a full CLIPRDR PDU
before using the existing capability, Format List native-acceptance,
and single-flight Format Data Response handlers. Fail-closed framing
errors poison only this clipboard coordinator. Unsupported clipboard
types are ignored. Received-data spans borrow the input packet.

**Files:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`, and this ledger.
**New CTest:** `clipboard.joined-static-channel-inbound-gates`.
The previously published
`clipboard.format-list-response-joined-mcs-envelope` is also
restored to central CTest registration after concurrent edits.
The test constructs real T.125 SendDataRequest TPKTs with synthetic
CHANNEL_PDU_HEADER and clipboard PDU bytes; it checks unjoined/wrong
channel/wrong user/unauthorized/segmented denial, negotiation,
valid format offer and borrowed response, native refusal, malformed/
compressed/truncated headers, stale generation, and closed gates.
**At authoring:** full repository checkout/CMake/CTest NOT RUN
(Git transport unavailable in execution environment), exact-commit
GitHub Actions PENDING, owner's Linux/X11, Windows MSYS2 CLANG64
Clang23, and macOS27 full CTests NOT RUN. No native clipboard,
Firefox image/png File paste, actual authenticated connection,
performance benchmark or three-platform owner acceptance was run.
The caller remains responsible for verifying TLS/NLA, OS session
admission, negotiated CLIPRDR role, security headers, the one
outbound writer, and R9 multi-chunk reassembly before this boundary.

**Exact-commit GitHub Actions verification (2026-10-16):**
implementation `288f10ebd7c51616f16098c39c3fae9d7a9c090b`,
[workflow #38845220243](https://github.com/k1moradi/RDP-server/actions/runs/38845220243):
**PASS** documentation policy and all three hosted protocol jobs.
Linux/GCC **207/207 Debug and 207/207 Release**; macOS/Clang
**193/193 Debug and 193/193 Release**; Windows/MSVC
**203/203 Debug and 203/203 Release**. Both
`clipboard.joined-static-channel-inbound-gates` and
`clipboard.format-list-response-joined-mcs-envelope` PASS in each
configuration. Staged installed SDK consumer, ZIP and SHA256 artifact
steps succeeded; prerelease publishing skipped without a release tag.
The owner's Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
checks remain **NOT RUN**, as do native OS paste integration,
authenticated real-client clipboard, Firefox PNG File, and performance.

## R8 bounded Unicode/image prefetch format priority (2026-10-15; CI pending)

The one native `RemoteTransfer` owner now offers
`beginNextPrefetch(PrefetchKind, selectedFormatId, output)`:
CF_UNICODETEXT (13) for text; registered PNG by current name,
then CF_DIBV5 (17) and CF_DIB (8) for images. Only advertised
IDs are selected; a fixed four-ID generation-local history prevents
duplicate requests, including registered PNG reusing a DIB numeric
ID. Each attempt uses the existing single outstanding Format Data
Request and cannot bypass retiring an obsolete response. Offer
replacement and disconnect clear history, and there is no extra
clipboard owner, cache or OS interaction.

**Changed:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/coding_standards.md`,
`docs/CODEX_VALIDATION.md`.
**Dedicated CTest:** `clipboard.prefetch-unicode-png-dib-single-flight`
covers missing-offer denial, Unicode ID wire, one-flight denial,
PNG/DIBV5/DIB retry priorities, duplicate IDs, outstanding
old-generation reply quarantine, reset and poisoned transfer.
**NOT RUN at authoring:** complete local repo CMake/CTest, hosted
exact-commit CI (pending), owner Linux/X11, Windows MSYS2 CLANG64
Clang23, macOS27, real clipboard/client paste, verified PNG/DIB/
UTF-16 conversion and performance. Actual native content readiness
and scheduling are future R8/adapter gates.

## R8 transactional joined-MCS Format Data Request (2026-10-16; CI pending)

**Implementation:** `RemoteTransfer::prepareJoinedFormatDataRequest`
accepts only an advertised current-generation format ID on R3's
confirmed and caller-expected CLIPRDR MCS channel, stages the standard
12-byte CLIPRDR PDU via the first-party codec, wraps it with an
uncompressed single-chunk static VC header and delegates MCS
SendDataIndication serialization to R3. An output/encoder failure
leaves the caller buffer and the outstanding-request slot intact.
The returned monotonic request sequence and byte-count receipt
lets the external single R3 writer check readiness, report cumulative
bytes and reject delayed callbacks across reconnect. Safe zero-byte
cancellation is separate from ambiguous partial transmission,
which poisons R8 until genuine disconnect. Inbound response
consumption now refuses pre-completion or partially written request
states; completed obsolete-generation replies are discarded.

**Changed:** `src/server/clipboard/remote_transfer.{h,cpp}`,
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/CODEX_VALIDATION.md`, `docs/coding_standards.md`.
**New CTests:**
`clipboard.format-data-request-joined-mcs-envelope` (exact 34-byte
wire, confirmed joins, wrong role/ID, unadvertised format,
insufficient output, no phantom pending or output mutation);
`clipboard.format-data-request-generation-cancellation` (safe
unsent cancellation, partial send poisoning, stale receipt after
reconnect, old-generation reply draining and early-response rejection).
**NOT RUN at authoring:** complete checkout/local CMake/CTest (no
Git transport in execution environment), exact-commit Actions,
owner's Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, TLS/NLA
admission, R3 writer integration, clipboard bytes validation,
native paste/Firefox PNG File and performance. Follow-up requires
authorized R3 write-hand-off and payload-readiness adapter boundary.

## R8 joined-request exact-code CI verification (2026-10-16)

**R8 production SHA:** `22915cee335df7d82149728543866f45db7bc8aa`.
Its initial [workflow #38850425244](https://github.com/k1moradi/RDP-server/actions/runs/38850425244)
failed during workflow parsing with zero jobs, because a concurrent
workflow edit contained duplicate job IDs. R10 restored valid CI YAML
at `4d24b8b3b9857370fef8608cf7d7782f644df3ea`. The first
repaired run exposed a separate R10 regression:
`runtime.validates-configuration-mode-normalization` used invalid
CMake `OTHERS_WRITE`; R10 corrected it at
`a0c39e4a612c740949c05e4a9699f711061c21d0`.

**Verified complete hosted run:**
[Actions #38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646),
on code-equivalent descendant
`a0c39e4a612c740949c05e4a9699f711061c21d0`.
Linux/GCC **226/226** Debug and Release PASS; macOS/Clang
**209/209** Debug and Release PASS; Windows/MSVC
**228/228** Debug and Release PASS.
Both `clipboard.format-data-request-joined-mcs-envelope` and
`clipboard.format-data-request-generation-cancellation` PASS on
all platforms/configurations. R9's Clang sanitizer job:
**15/15** clipboard CTests plus **10/10** bounded security CTests PASS.
Documentation-policy and downstream packaging stages PASS;
prerelease publication SKIPPED without an authorized tag.

**NOT RUN:** the owner's exact Linux/X11, Windows MSYS2 CLANG64
Clang 23 and macOS27 full CTests; real TLS/NLA/OS session
admission and R3 writer integration; any native clipboard
ownership, Firefox PNG File paste, real-client interoperability,
bounded Unicode/PNG media readiness or performance benchmarks.
The corrected CI SHA is a descendant of the R8 implementation
SHA, not the original zero-job Actions attempt.

## Local validation (one reused build root)

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

No second local build folder. GitHub Actions each run from one
ephemeral checkout-local `build/`. Tests are C++23, behavior-named,
reusable and automated; run focused and whole CTest plus cross-platform
CI and documentation-policy gate. Do not mask failures.

## Historical verified snapshot

- Original migrated `main` at
  `77c94c75b467f25c3911912ff4a24690894768c8`:
  [GitHub Actions run 38516048776](https://github.com/k1moradi/RDP-server/actions/runs/38516048776)
  was successful with ten original portable protocol tests.
- The semantic test registry, single build-root guard and documentation
  co-change check passed at
  `3196a764ffbe24482ad131ad6949f1c2c23d44d9` in
  [GitHub Actions run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy jobs.
  CMake now registers ten semantic native protocol tests plus one
  project-policy test. These are **offline library tests**, not
  end-to-end desktop or OS admission acceptance.
- Full former project source and unique implementation progress import remains incomplete; historical Git ancestry is not the goal.
  A green protocol static library is **not** a functional desktop server.

## Per-task evidence

Record exact SHA and modified paths, vision/TODO objective, Microsoft
protocol boundary, exact commands/environment, PASS/FAIL/BLOCKED/NOT RUN
results, first failing transition, safety/ownership constraints,
updated documentation and next milestone. Never turn synthetic
authentication fixtures into a claim of real OS session admission.

## R10 offline runtime configuration validation (2026-10-15; CI pending)

**Exact observed parent `main`:**
`2ee2d1371a98b237c68cee061eea13811278d8f6`.
**Publication:** the containing main commit atomically delivers code,
CTests and updated documentation by non-force expected-HEAD update.
CI remains NOT RUN at authoring; no branch or service activation
was attempted.
**Files:** `CMakeLists.txt`, `tests/CMakeLists.txt`,
`src/server/runtime/main.cpp`, `tests/check_runtime_entrypoint.cmake`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/compile.md`,
`docs/CODEX_VALIDATION.md`.
**Behavior:** non-installed fail-closed native process; syntax-only
`--check-config FILE`, 4,096-byte size cap, seven mandatory unique keys,
local listener only, bounded ports/connections, absolute different TLS
path values, mandatory authentication/OS authorization *declarations*.
No crypto or OS session approval occurs on positive syntax.
**PASS — isolated Linux GCC 14.2 / Clang 17:** each compiler compiled the
production entry point with `-std=c++23 -O1 -g -Wall -Wextra -Wpedantic
-Werror -Wconversion -Wsign-conversion`, then the executable passed
**25/25** direct `cmake -DRDP_RUNTIME_EXECUTABLE=<binary>
-DRDP_RUNTIME_VERSION=0.1.0 -DRDP_RUNTIME_TEST_CASE=<name>
-DRDP_RUNTIME_FIXTURE_DIRECTORY=~/rdp-server/build/config-fixtures
-P tests/check_runtime_entrypoint.cmake` runs. Recompiled with
`-fno-omit-frame-pointer -fsanitize=address,undefined` and reran
**25/25 with each compiler** using `ASAN_OPTIONS=detect_leaks=1
UBSAN_OPTIONS=halt_on_error=1`. These are standalone CMake-script
checks, **not** registered full repository CTests. The new checks
cover valid and CRLF/comment formats plus failure for missing/disabled auth/OS
policy, public binding, duplicate/unknown keys, bad port/limit,
oversized file, comment control bytes, relative/traversal/same key path,
missing file and option smuggling; existing seven fail-closed/CLI cases
remain. All local outputs stayed in `~/rdp-server/build/`.
**PASS — scratch isolated CTest registration:** a temporary harness
inside `~/rdp-server/build/r10-offline-ctest-harness` mirrors the
proposed 25 `runtime.*` registrations and compiles the same production
entry point without the unavailable full protocol checkout: 25/25
CTest PASS in Debug and again 25/25 PASS in Release (GCC 14.2).
This is NOT the project's central registry executing in the full
repository; no installed package or native adapter was built.
**NOT RUN:** complete current-main configure/build/full registered
CTest, Windows/MSVC, macOS/Clang, owner Windows CLANG64 Clang 23,
macOS 27, Linux/X11 owner test, SDK consumer/ZIP CI for this change,
real TLS cert verification, GSS/Kerberos, independent OS admission,
Microsoft real-client desktop or deployment.
**Milestones:** M1 open; M2–M6 not accepted.
**Next gate:** exact-SHA Linux, Windows and macOS full CI,
then authorized OS/session integration.
## R10 Windows CRLF fixture correction (2026-10-15)

**FAIL:** R10 implementation `a7234f40c4e2188b1170daf363136a6ac159c025`,
[Actions 38796098450](https://github.com/k1moradi/RDP-server/actions/runs/38796098450):
Linux/GCC and macOS/Clang jobs PASS; Windows/MSVC compiled Debug but
full CTest finished 153/154 PASS, failing only
`runtime.validates-configuration-comments-crlf` (expected 0, exit 3).
Release and package gates on Windows were NOT RUN after the failure.
**Corrected test-only increment:** normalize CR bytes in the synthetic
configuration fixture before emitting CRLF; compare raw written bytes
with `file(READ HEX)` and `string(HEX)` instead of CMake's newline-
normalizing ordinary `file(READ)`. Preserve all 25 runtime CTests.
**Local PASS:** Linux GCC 14.2 and Clang 17 focused CRLF test; offline
Release CTest harness 25/25 PASS. No production code or server security
policy changed. **Corrected full CI and owner platforms: NOT RUN at
authoring.** Next gate: inspect the corrective commit's exact-SHA
Linux, macOS and Windows full Debug/Release CI, SDK package regression,
and the owner's independent testing.

## R10 second Windows CRLF compatibility correction (2026-10-15)

**FAIL:** first correction `b90baa6d76d769fce18a216d055c081375cd9b89`,
[Actions 38797088304](https://github.com/k1moradi/RDP-server/actions/runs/38797088304):
Linux/GCC and macOS/Clang PASS; Windows/MSVC Debug 164/165 registered
CTests PASS, only `runtime.validates-configuration-comments-crlf`
failed, now at the raw-fixture HEX comparison. Release and packaging
Windows gates NOT RUN following the failure.
**Correction:** preserve the stringent production parser and exact-HEX
fixture assertion, but account for CMake Windows `file(WRITE)` text
conversion by passing LF and expecting CRLF output; on POSIX, write
CRLF explicitly. No other CTests removed, and no runtime code changed.
**Local PASS:** Linux isolated CTest harness 25/25 Debug and 25/25
Release. **NOT RUN at authoring:** corrected exact-SHA three-platform CI,
owner Linux/X11, Windows CLANG64/Clang 23, macOS 27. Next: examine the
new commit's full Debug/Release CI and SDK packaging, then owner CTest.

## Verified R10 runtime configuration CI after Windows correction (2026-10-15)

**PASS:** exact implementation/correction `853e572dafdeab18161afa3926db2f29d2ec3a34`,
[GitHub Actions 38797522248](https://github.com/k1moradi/RDP-server/actions/runs/38797522248).
Linux/GCC: **170/170** registered CTests in EACH Debug and Release;
Windows/MSVC: **166/166** in EACH Debug and Release;
macOS/Clang: **158/158** in EACH Debug and Release.
The previously failing `runtime.validates-configuration-comments-crlf`
passed on Windows in both configurations. On each OS the installed
protocol SDK's downstream consumer CTest **1/1 PASS**, ZIP package,
SHA-256 artifact generation/upload, and documentation policy PASS.
The protocol prerelease job SKIPPED (no tag). R10's native executable
is **not** installed or packaged as a working service; `--check-config`
remains syntax-only, and every attempt to start a protected desktop
fails closed. **NOT RUN:** the owner's Linux/X11, Windows CLANG64
Clang 23 and macOS 27 one-liner, authorized Microsoft-client login,
actual OS admission, desktop, service, upgrade/rollback, and production
measurements. M1–M6 remain OPEN. Next R10 increment: secure certificate
and configuration-file provisioning checks without listener activation.

## Verified strict local-path policy CI (2026-10-14)

The stricter home-checkout and single-build-root guard in
`e1843b07c8772588f29e45a9b8e328e51c59e2ff` passed all four
[Actions run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
jobs: Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
CMake enforces the checkout-local `build/` and requires ordinary
non-CI checkouts at `~/rdp-server`; GitHub-hosted CI has a documented
workspace exception. Direct verification on the owner's local computer
remains NOT RUN. No live client or authenticated desktop acceptance is
implied by these green jobs.

## New transport stream intake milestone (pending CI)

This commit adds `PreauthConnectionStream` on top of the existing
X.224 parser and preauthentication session, with bounded first-packet
reassembly and exact consumed-byte accounting. The reused
`transport.preauth-session` CTest was extended with fragment,
coalescing, malformed-length, TLS-dispatch and terminal-close negatives.
**PASS:** [exact-head GitHub Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879),
commit `988938a90f8adbae4e07714ac636af3eb0640011`, passed
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy CTests.
This verifies the existing compiled preauth protocol suite and the
new bounded-fragment intake negative cases. The first **unimplemented**
boundary is a network listener coupled to a real TLS provider and
authenticated post-negotiation session. Real TLS/credential validation,
desktop admission and external RDP clients remain **NOT RUN**;
no production activation.

## X.224 write-completion ordering (pending exact-head CI)

In the existing `PreauthConnectionStream`, the connection reply
completion gate now precedes the preauthentication TLS transition.
Tests were added to the existing `transport.preauth-session` CTest:
premature TLS, write failure, duplicate reply completion, early
completion report and accepted one-shot completion. **PASS:** [Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
completed successfully for exact commit
`18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`, with
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy jobs
green. This is a tested **offline preauthentication ordering rule**,
not a listening socket, real TLS handshake, CredSSP, user authentication
or OS session access; those categories remain NOT RUN.

## Verified bounded decrypted MCS/GCC intake (2026-10-14)

New reusable `PreauthConnectionStream::consumeDecryptedMcsConnectInitial`
uses one fixed buffer for the initial plaintext and the subsequent
decrypted MCS/GCC envelope. Existing `transport.preauth-session`
gains every-split, truncation, coalesced-packet, invalid header,
malformed BER, wrong-state and replay tests against production code.
**PASS:** [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607) at `49c6006d47476184f7448028cd332e377ec9bd0b` completed Linux/GCC, macOS/Clang, Windows/MSVC CMake builds and full CTests, plus documentation-policy. **NOT RUN:** owner's local `~/rdp-server/build/`, host networking, real TLS certificates, CredSSP/NLA, external RDP clients and OS admission. **Next:** authenticated TLS provider and MCS response lifecycle.

## Verified CI/CD protocol SDK automation (2026-10-14)

The unified `.github/workflows/ci.yml` now runs Debug and Release
builds/full CTests on Linux/GCC, macOS/Clang and Windows/MSVC, followed
by one staged install per runner, a nested downstream CMake consumer
configure/compile/CTest, CPack ZIP creation and artifact SHA-256
publication. A matching `protocol-vX.Y.Z` tag reachable from
`main` publishes a GitHub **prerelease** only after all platform
and documentation-policy jobs have succeeded. The new consumer tests
that the installed `RDPServer::protocol` target is usable.

**PASS:** [GitHub Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777)
at exact commit `1aa025960288d40f476e85c5a9c5f97b06bebf20`
completed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
For each OS the workflow configured/built/ran CTest in Debug,
reconfigured the **same** `build/` root for Release, ran Release
CTest, installed the SDK under `build/stage/`, compiled and ran the
downstream `tests/consumer` CTest under `build/consumer/`, and
successfully generated/uploaded CPack ZIP and SHA-256 manifests.
Artifacts: `protocol-package-ubuntu-latest`,
`protocol-package-macos-latest`, and
`protocol-package-windows-latest` (3 packages confirmed).

**SKIPPED / NOT RUN:** the gated GitHub release publishing job
(no `protocol-vX.Y.Z` tag was pushed), owner's local PC build,
live server/socket/service, real TLS/NLA, OS authorization, and
external RDP desktop acceptance. The next delivery gate is
a reviewed version tag to test the prerelease publish step;
the next functional gate is an authenticated native RDP server.

## Documentation relocation and CMake script-mode policy (2026-10-14)

Root docs were moved to `docs/` at commit
`e3e6a7576f530280a1095f8e15f058d7da07f52d`. All 47
internal documentation hyperlinks were rebased; root entrypoints
were preserved. **FAIL:** [Actions run 38544805819](https://github.com/k1moradi/RDP-server/actions/runs/38544805819)
failed `project.policy` on Ubuntu during Debug CTest because
`cmake -P` did not enable CMP0057 for `if(IN_LIST)`.
Ten native protocol suites passed on Ubuntu. Changed the root-layout
policy guard to `list(FIND)` in this follow-up implementation.
**PASS:** the corrected `cmake -P` root-layout guard at
`f68d1d417424823eed7856761ff95f0ebe1eabb2` passed
[GitHub Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
Each runner passed Debug and Release full CTests, staged SDK install,
downstream CMake consumer, CPack ZIP and SHA-256 artifact upload.
`project.policy` now checks required relocated docs and permits only
five canonical root-level Markdown entrypoints.
**NOT RUN:** owner-local `~/rdp-server/build/`, real clients, RDP
network listener, OS admission and service deployment.

## OpenSSL server TLS transition evidence (pending exact-head CI)

The previous `PreauthConnectionStream::onTlsHandshake(bool)` could
proceed on a caller-supplied synthetic signal. This transport API
now requires a fully handshaken server-side OpenSSL `SSL*` with a
selected certificate, cipher, and negotiated TLS 1.2+.
The existing `transport.preauth-session` CTest performs a real
in-memory OpenSSL client/server handshake and checks wrong role,
unfinished handshake, missing pointer, send-before-TLS and replay.

**NOT RUN** until exact-head CI verifies Linux/GCC, macOS/Clang,
Windows/MSVC, documentation-policy, Debug/Release, downstream
consumer and SDK packaging. **NOT RUN:** local owner checkout,
actual TCP listener, certificate enrollment, CredSSP/NLA,
OS identity authorization and external RDP clients.

## TLS boundary Windows compatibility failure (2026-10-14)

**Initial FAIL:** commit `a25b5186398e4a5619baea2998a61596fa7b2887`
[Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680)
reported MSVC C2589/C2059 in
`src/server/transport/preauth_session.cpp` at `std::min`,
due to platform macro leakage from an OpenSSL header.
macOS and documentation-policy PASS. Corrected the public
include to `openssl/types.h`, included `ssl.h` only in
translation units using OpenSSL, and protected the two
`std::min` expressions with parenthesized function names.
**Next:** cross-platform Debug/Release full CTests, downstream
SDK consumer and ZIP packages on the corrected exact head.

## Verified OpenSSL TLS preauth stream gate (2026-10-14)

Initial security implementation
`a25b5186398e4a5619baea2998a61596fa7b2887` introduced a
completed-OpenSSL-server SSL check after X.224 reply completion and
a real memory-BIO client/server TLS handshake regression.
**First FAIL:** [Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680)
on Windows/MSVC Compile Debug (Windows macro expanded in `std::min`).
Header isolation and parenthesized `std::min` at
`edfaf2e7ea684ab5adc77bf58441ff467288f818` corrected it.
**Exact-head PASS:** [Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release CTests, installed SDK consumer and ZIP upload.
This verifies that a completed in-memory **server-side OpenSSL
handshake** advances the offline stream when in order and rejects
null, client-role, unfinished, premature and repeated transitions.
It does **not** verify live socket TLS I/O, user authentication,
CredSSP/NLA, real external RDP client, OS admission or desktop.
The user-reported 11/11 local CTests preceded this TLS change;
local tests of the new exact commit remain **NOT RUN**.

## Verified OpenSSL application-record MCS intake (2026-10-14)

Added `PreauthConnectionStream::consumeMcsConnectInitialFromTls`
to read from the exact completed OpenSSL server connection and
feed its decrypted bytes into the existing bounded 8,192-byte
TPKT/X.224/MCS/GCC state machine. The existing
`transport.preauth-session` suite sends encrypted OpenSSL
application records through memory BIOs and tests every
Microsoft example split, coalescing, TLS EOF, early errors,
wrong/foreign SSL handles and malformed TPKT. The server
still does not listen on a socket, authorize users, emit MCS
responses or deliver a desktop.

**PASS:** exact code commit
`a226f15827e9da48ad7a91b7cfa53528c3498802`,
[GitHub Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241)
completed Ubuntu/GCC, macOS/Clang, Windows/MSVC and
documentation-policy, the Debug/Release CTests, staged installation,
downstream SDK consumer, and three ZIP/checksum package uploads.
**NOT RUN:** user's local build on this new commit, external RDP
clients, nonblocking TCP socket, CredSSP/NLA identity/authorization,
MCS Connect-Response and desktop access.
**First remaining boundary:** real I/O adapter and OS-independent
authenticated RDP session policy.

## Verified CTest behavior reporting transparency (2026-10-14)

User reported a successful owner-local Debug CMake build and CTest at
`28b0d2b53949236eff4e483c2ca9706c25d93895`: **11/11 PASS**.
This is user-provided evidence for that local checkout, not evidence
for a later commit. The consolidated preauth executable still ran
new encrypted TLS tests but appeared as one CTest, lasting roughly
1.67 seconds in the provided output.

Now one binary accepts a documented behavior selector (or no argument
to run all groups), and the existing CMake test registry names
ten independent preauth behavior cases. Expected registered total:
20 (formerly 11), with unchanged protocol implementation and retained
assertions. **PASS:** implementation commit
`1e11327f2b74ff7e676fbb3bb7200491718a779f`,
[Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423):
Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release CTests, installed downstream package consumer and
SDK ZIP/sha256 artifacts. Ubuntu's CTest logs explicitly show
**20/20 tests passed** for each Debug and Release run.
**NOT RUN:** owner's local CTest after this registration change,
external RDP clients, real TCP listener, CredSSP/NLA,
OS authorization or desktop acceptance.

## Verified partial X.224 output accounting (2026-10-14)

Removed the Boolean send-completion escape hatch from
`PreauthConnectionStream`. The existing owner tracks each
of the exact 19 negotiation-response bytes accepted by a
future nonblocking socket writer; it only allows SSL/TLS after
the last Confirm byte, or allows the Failure response to
drain before terminal close. The new named CTest validates
all split boundaries, bytewise writes, would-block, duplicate,
overrun, premature TLS, explicit failure and rejection output.
**PASS:** code commit `98f6fdc60d513d47a87a78fadf1aa6be387da28b`,
[GitHub Actions run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release CTests, downstream SDK consumer and three packages.
Ubuntu's Debug and Release CTests each logged **21/21 PASS**.
**NOT RUN:** owner-local new build, active TCP listener, CredSSP/NLA,
MCS Connect-Response, external clients, OS/desktop authorization.
**First remaining boundary:** native nonblocking socket adapter
and authenticated RDP session lifecycle.

## Verified portable preauth TCP adapter (2026-10-14)

New `src/server/transport/nonblocking_tcp_adapter.{h,cpp}`
provides `NativeTcpIo` borrowed nonblocking Winsock/POSIX
socket calls, and `PreauthTcpAdapter` which drives the sole
existing `PreauthConnectionStream` state machine with exact
first-request prefix reads and bounded X.224 reply writes.
The existing native test binary registers two independent
behavior CTests for fragments/backpressure and rejected failure
output; expected CTest count increases from **21 to 23**.

**PASS:** implementation `dd3a806f97b13e6db18affd689c6321bfa009813`,
[Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
completed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
both Debug/Release full CTests, installed SDK downstream consumer,
and three platform package ZIPs/checksums. Ubuntu explicitly logged
**23/23 CTests PASS** for both build modes.
**NOT RUN:** owner's local build on this new exact code,
connected live native socket runtime, listening TCP RDP server,
live TLS network handshake, CredSSP/NLA, MCS responses,
real clients or independently authorized desktop admission.
**Next gate:** actual TLS-over-socket lifecycle with bounded
cancellation and then authenticated connection semantics.

## OpenSSL 4 fixture compile failure (2026-10-14)

**FAIL:** evidence-only commit `4578a4549b9a04638206264a0c5ac752ef5e844b`,
[run 38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
macOS Compile Debug, first failing call: the prior in-memory TLS
fixture assigned OpenSSL 4's `const X509_NAME*` return from
`X509_get_subject_name` to a mutable `X509_NAME*`. The
actual native TCP adapter implementation had independently passed
[run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
on all three OSes and 23/23 Debug/Release tests on Ubuntu.
The fix creates a temporary RAII `X509_NAME` and sets both
certificate subject and issuer using OpenSSL APIs; no
`const_cast` or reduced test assertion.
**PASS:** fixed implementation `5c4f3ad7273d17948327b7d351ff9840de2b0395`,
[Actions run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002):
Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
both Debug/Release **23 CTests**, downstream installed SDK consumer
and three platform ZIP/checksum artifacts.
**Caveat:** the successful macOS run found OpenSSL **3.6.4**;
post-fix compilation with 4.0.3 is **NOT RUN** and needs a
separate explicit CI check. **NOT RUN:** owner's local new tests,
actual native connected socket, real RDP clients, TLS-over-socket,
NLA, MCS Connect-Response and independently authorized OS desktop.
**Next functional boundary:** live socket TLS provider lifecycle
and authenticated session sequencing, then MCS response.

## Verified nonblocking OpenSSL handshake through sole connection owner (2026-10-14)

At parent `357add02b32eec5593b8a078d8ec56a4f7a6291e`,
the owner-reported local Linux Debug build and
`ctest --test-dir build -C Debug --output-on-failure`
completed **23/23 PASS**, including native TCP adapter tests.
This is supplied user-local evidence for that checkout, not
local execution of the new implementation.

This implementation adds `PreauthConnectionStream::advanceTlsHandshake`
and forwards it from `PreauthTcpAdapter::onTlsIoReady`.
It uses OpenSSL's server `SSL_do_handshake` once per event,
handles WANT_READ/WRITE without spinning, pins the original
borrowed SSL pointer, rejects wrong role, premature calls,
provider failure or replay, and advances only after the
existing completed-server-TLS evidence gate. Two new behavior
CTests use a real in-memory TLS BIO pair, one then decrypts
the Microsoft 416-byte MCS/GCC packet. Expected total:
**25 registered CTests**.

**PASS:** exact code commit
`fcd05f8e903a459ca85f13807bd35f7091f3fd70`,
[Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099):
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
succeeded. Ubuntu explicitly logged **25/25 PASS** in Debug and
Release; all three OSes passed the full CTests, staged install,
downstream consumer and CPack ZIP/checksums. No release tag,
server activation or machine changes took place.
**NOT RUN:** owner's updated local build, real connected TCP
TLS session, external RDP clients, CredSSP/NLA identity,
OS desktop admission and MCS server response.
**Next:** safe loopback native TLS I/O/regression; full secure
connection and authenticated RDP session remain open.


## Native loopback OpenSSL/TCP integration (pending exact-head CI)

User-provided owner-local Linux output for `91e066b8214dd04299e94ccfd8167c940148e2a4`:
reused `~/rdp-server/build/`, Debug C++23 compilation and
`ctest --test-dir build -C Debug --output-on-failure` were
**PASS 25/25**. This local evidence predates this change.

The implementation adds a borrowed nonblocking OpenSSL BIO atop
`TcpNonblockingIo`, then tests real short-lived IPv4 loopback
socket exchange of X.224 CR/Confirm, server-side TLS handshake
and encrypted 416-byte MCS/GCC frame. Native EOF and
NEG_FAILURE delivery are separate negative test behavior.
Expected CTest registration **27**. OpenSSL BIO callbacks
follow its documented retry/ownership semantics; no socket
handle narrowing, persistent listener or user authorization.

**NOT RUN:** this commit's Linux/GCC, macOS/Clang and Windows/MSVC
Debug/Release hosted CTests, SDK consumer/package and
documentation-policy until the exact-head Actions run completes.
**NOT RUN:** user's local update, external RDP client handshake,
certificate enrollment/validation, CredSSP/NLA, licensing,
MCS Connect-Response, approved OS identity and desktop.
First remaining server boundary: independent authenticated
session policy followed by standards-compliant MCS response.

## Loopback TCP readiness timing regression (2026-10-14)

**FAIL:** `c53a591c8d5b6dbb4cd63f742bddb2c3eeb2ede8`,
[CI 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083):
macOS Debug `transport.tcp-native-loopback-tls` and
`transport.tcp-native-loopback-close` expected TCP recv/readable
FIN synchronously after client send/close. Actual native nonblocking
sockets may return WouldBlock first. Linux and Windows passed
all 27 CTests, packaging and documentation-policy passed.
Correct the **test event driver** to retry only in bounded
short sleeps with unchanged exact packet, EOF and protocol
acceptance assertions; no production behavior is altered.
**NOT RUN:** post-fix CI on the corrected commit, new
owner-local tests and any external RDP client or desktop.

## Verified nonblocking native OpenSSL/TCP loopback bridge (2026-10-14)

**First FAIL:** code commit `c53a591c8d5b6dbb4cd63f742bddb2c3eeb2ede8`,
[run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
passed Linux/GCC, Windows/MSVC and documentation-policy but failed
two macOS Debug native-loopback CTests. The test driver incorrectly
assumed a nonblocking recv or FIN would be visible immediately
after its peer's send/close. There was no proved production transport
bug. Fixed only the test harness: bounded waits for the expected
readability and TCP EOF outcomes, preserving exact-packet and
fail-closed assertions.

**PASS:** corrected exact code commit
`7ce64737ccef439af2f0cfd383208181cc0e9513`,
[Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
completed Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
both Debug/Release full CTests, staged SDK install, downstream consumer,
and three ZIP/checksum package artifacts. Ubuntu logs explicitly
show **27/27 CTests PASS** in both configurations, including
`transport.tcp-native-loopback-tls` and
`transport.tcp-native-loopback-close`.

The verified boundary is real **local-only connected TCP** X.224
negotiation, an OpenSSL server handshake across those native sockets
and decrypted MCS/GCC example intake. The test's ephemeral
127.0.0.1 listener was closed before TLS; it did not activate any
persistent service. **NOT RUN:** owner's build after this new change,
external RDP client admission, production certificate enrollment/trust,
CredSSP/NLA identity, MCS Connect-Response, licensing,
OS desktop authorization or graphics.
**Next:** authenticated RDP session sequencing and real server-side
MCS response, without confusing local transport security with OS
authorization.

## MCS domain parameter merge (2026-10-14; pending exact-head CI)

User-provided owner-local Linux Debug build and CTest on
`03d72824e87c5f6e608e1d27ff2711bb8a88b1e0`:
**PASS 27/27** with the sole persistent
`~/rdp-server/build/`. This evidence predates the new change.

The implementation extends the maintained MCS Connect-Initial
parser with Microsoft MS-RDPBCGR 3.3.5.3.3/T.125 domain
parameter merge. It returns a value only, never admits an OS
session, allocates channels or sends a response. The existing
preauth owner now rejects a BER-valid MCS Connect-Initial if
its requested domain cannot negotiate version 2 or any
required domain minimum. Four existing MCS test behavior
groups are reported separately, with two new groups for
negotiation and malformed values; expected **32 CTests**.

**NOT RUN:** CI on exact new implementation SHA,
owner-local updated build, authenticated CredSSP/NLA/OS
identity, MCS Connect-Response, external Microsoft clients
and desktop access. First next wire boundary: bounded
standards-compliant server MCS Connect-Response and GCC
Conference Create Response, gated by secure authorization.

## Offline MCS Connect-Response encoder (2026-10-14; CI pending)

**Owner-local evidence:** at
`865c56c548526f4514207a4af1b192f3b3637c9a`,
the user's reused `~/rdp-server/build/` Debug compile and
`ctest --test-dir build -C Debug --output-on-failure`
completed **32/32 PASS**. The same implementation completed
cross-platform Debug/Release and SDK gates in
[CI 38582674975](https://github.com/k1moradi/RDP-server/actions/runs/38582674975):
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
all PASS. That is prior-code evidence, not evidence for this encoder.

**New implementation:** a bounded offline encoder of the
MS-RDPBCGR 2.2.1.4 TPKT/X.224, BER MCS Connect-Response and
PER GCC Conference Create Response containing `McDn`,
`SC_CORE`, `SC_NET` and Enhanced TLS `SC_SECURITY`. It
requires a checked merged domain and GCC client data plus
caller-provided nonduplicated channel IDs. Tests include
a full independently specified 108-byte example and
rejection paths. Expected CTest registration **34**.
**NOT RUN:** exact-head cross-platform Debug/Release CI,
owner-local post-change build, actual output to a TLS
socket, CredSSP/NLA and independently authorized OS session,
MCS Erect/Attach/Join lifecycle, external Microsoft clients
or desktop acceptance. This is not an authenticated server.

## Pure MCS Channel Connection Request decoding (2026-10-14; pending CI)

**Owner-local baseline:** at `ddfc2d372285c397c52dca0197d30bf1c61c338e`,
the owner's Linux Debug command reused `~/rdp-server/build/`
and confirmed **34/34 CTests PASS**, including the offline
MCS response wire/negative tests. The earlier implementation
`e25cd3a05f46b7eaa2a259eb2da8ddb3b7459a87` had Linux,
Windows and documentation-policy PASS in
[CI 38586253181](https://github.com/k1moradi/RDP-server/actions/runs/38586253181).
These are prior-code results, not proof of this change.

**New scope:** pure, bounded T.125 Channel Connection request
parser for ErectDomain/AttachUser/ChannelJoin. Reuse existing
TPKT/X.224 parser and MCS fixture executable; add three CTests
from Microsoft wire examples with truncated/invalid negative
cases; expected **37 registered CTests**. No MCS channel state,
live response emission, OS admission, independent identity
or credential acceptance was implemented.
**PASS:** corrected implementation
`6effdb76229e2514511ebe5dd8cb404841403b1b`
in [Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653):
Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
Debug/Release **37 registered CTests**, installed SDK consumer
and all three platform packages/checksums.
**NOT RUN:** owner-local corrected tests, external clients,
CredSSP/NLA or authenticated OS desktop.
**Next:** authoritative, independent authentication gate
before server-owned MCS channel/join replies.

## First MCS Erect-domain fixture failure (2026-10-14)

**FAIL:** initial implementation
`d5bc7d3b03906890da483dd1a480677a4fbaf73b`,
[Actions run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504),
Ubuntu Debug `transport.mcs-erect-request` asserted a valid
expanded Erect-domain example. Its subInterval PER length
determinant was incorrectly 4 for three following octets,
so the production decoder correctly rejected it.
Other 36 CTests PASS on Ubuntu. Fix only the test vector to
encode length 3 for 0x010203; no production code changes,
no weakened input bounds or removed assertions.
**PASS:** corrected code
`6effdb76229e2514511ebe5dd8cb404841403b1b`,
[CI run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653):
Linux, macOS, Windows and documentation-policy PASS with
Debug/Release **37/37 CTests** on Ubuntu and full tests on
other platforms, staged installation, downstream consumer and
three SDK ZIPs/checksums. No code path grants user access
or sends an MCS channel response. **NOT RUN:** owner-local
new CTests, external Microsoft clients, credential/session
authorization and graphics.

## Verified offline T.125 Attach/Channel response wire encoders (2026-10-14)

**User-provided prior evidence:** `3135d66e557ecc8144fba02a8a69b5054b62ede9`
at the single `~/rdp-server/build/` Debug configuration
compiled and passed **37/37 CTests**. Hosted CI on that
same SHA [38588943436](https://github.com/k1moradi/RDP-server/actions/runs/38588943436)
also passed Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release,
SDK consumer/package and documentation policy. Those
results do not verify the present changes.

**New implementation:** add offline fixed-array T.125
`rt-successful` Attach User Confirm and Channel Join
Confirm encoders beside the existing request decoders.
Test exact Microsoft 11- and 15-byte positive example
packets and negative allocation/UserId checks in two
additional CTest cases (expected **39**). The returned
buffer is not an authenticated session or permission to
transmit. **PASS:** exact implementation
`4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`,
[Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498):
Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
full Debug/Release CTests (Ubuntu **39/39 PASS** in each),
staged installed SDK downstream consumer and all three
platform package ZIP/checksum uploads. Prerelease publishing
was SKIPPED; no release tag.
**NOT RUN:** owner's local rebuild at this commit,
CredSSP/NLA identity verification, independently authorized
OS session, live encrypted MCS responses, external client
acceptance, licensing/share activation or desktop.
**Next:** real CredSSP/NLA and OS authorization in the
single existing connection owner, then enforce MCS reply
ordering and live transport admission.

## First-party CredSSP TSRequest incremental framing (2026-10-14; CI NOT RUN)

**Prior evidence:** main commit
`7ffe0609fe25b15e07f1c49755a4b37b3b7a41b9`
passed Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy, Debug/Release 39 CTests,
downstream SDK consumer and all three packages in
[CI 38590674716](https://github.com/k1moradi/RDP-server/actions/runs/38590674716).
The owner reports all tests passed on that prior code,
without attaching a new CTest log. Not verification of this
implementation.

**New implementation:** bounded `TsRequestFrameReader` in
the existing `credssp_tsrequest` translation unit; exact
DER frame intake across TLS plaintext fragments with
canonical length checks, complete-frame non-replay,
borrowed frame handoff and `OPENSSL_cleanse` on release,
close or destructor. Tests reuse the existing CredSSP
executable; three new named behaviors plus separate
registration of five existing groups. Expected CTest total
**46**. **PASS:** exact implementation
`c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
[Actions run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562):
Linux/GCC, macOS/Clang, Windows/MSVC and
documentation-policy, both Debug/Release full CTests,
installed downstream SDK consumer and three ZIP/SHA-256
packages. Ubuntu explicitly logged **46/46 CTests PASS**
in both configurations. No release tag or service activation.
**NOT RUN:** owner's local updated build, real GSS/SPNEGO
handshake, TLS public-key binding, credential verification,
OS session authorization, NLA security selection, MCS
response emission, external client and desktop access.
**Next:** a trusted authenticated CredSSP/SPNEGO and OS
authorization provider within the sole preauth owner.

## Verified offline CredSSP server TSRequest reply serializer (2026-10-14)

**Prior verified head:** `f3f2d727334a254f7970c5eefe3c91a25d82c41e`,
[CI 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation policy,
46/46 Debug/Release CTests and SDK consumer/package gates for
the prior TSRequest framing implementation.

**New increment:** one `encodeCredSspServerTsRequest` entry point
in existing portable CredSSP module, accepting an opaque
GSS provider output for one of two distinct MS-CSSP server
response types, versions 5/6 only. It returns a complete
canonical bounded DER frame or no output; it owns no
authentication authority. The same CredSSP test executable
adds exact-wire, long-length, framing, empty/oversize,
unsupported-version/field regressions. Expected 48 named
CTests. **PASS:** exact code/test implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
[CI run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778) passed documentation-policy
and Linux/GCC, macOS/Clang, Windows/MSVC full Debug/Release
**48/48 CTests** each. SDK install, consumer configure/link/
execute, ZIP/checksum and artifact upload passed for all three
platforms; prerelease publication was SKIPPED because this
is not a protocol version tag. CI commands included:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug --output-on-failure`,
then reconfiguration with `-DCMAKE_BUILD_TYPE=Release`,
the same build root and corresponding Release build/CTest.
An unrelated Ubuntu Release preauthentication test source
logged a pre-existing `-Wstringop-overflow` warning at
`tests/test_owned_preauth_session.cpp:582`; it did not
fail the compilation or tests.
**NOT RUN:** owner-local build, genuine SPNEGO/GSS,
TLS key binding, OS account authorization or Microsoft
desktop connection. **Next:** a verified authenticated
security provider and independent OS-authorized single
session owner; do not send positive responses from offline
serialization.

## Verified Linux GSSAPI provider compile and framed DER handoff (2026-10-14)

**Previous baseline:** `35698b939bb2d26a66ca80ba237a55dc70e2da54`
passed 48/48 CTests on three platforms in
[CI 38597459891](https://github.com/k1moradi/RDP-server/actions/runs/38597459891).

**Implementation:** `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`
adds the Linux-only real MIT GSSAPI build/test target
and synchronous completed v5/v6 CredSSP DER frame handoff,
with terminal rejection and wipe on all invalid/unsupported
steps. No credentials, positive Kerberos handshake, or
admission authority is introduced.
**PASS:** [CI 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133)
with Linux/GCC Debug/Release **50/50** CTests, macOS/Clang
and Windows/MSVC Debug/Release **48/48** each; verified
both native GSSAPI named suites on Linux, documentation
co-change, staged SDK install, downstream consumer and
all three ZIP/SHA-256 uploads. In the one CI `build/`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
-DRDP_SERVER_TEST_LINUX_GSSAPI=ON` (Linux; OFF elsewhere),
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug --output-on-failure`;
reconfigure the same root for Release, build and retest.
Ubuntu's unrelated, previously reported
`tests/test_owned_preauth_session.cpp:582`
Release compiler warning remains nonfatal.
**NOT RUN:** owner-local updated build, configured real
Kerberos keytab/tickets, positive GSS mutual/authenticated
exchange, SSL certificate binding, independent OS user
authorization or Microsoft desktop.
**Next:** a controlled positive GSS/TLS certificate-bound
provider integration, with independently verified OS
session admission kept closed until explicit evidence.

## Verified native TLS -> CredSSP DER intake (2026-10-14)

**Prior baseline:** `c753b7d205647374c14e24be52b9f9f22fa8efcc`,
[CI 38604244975](https://github.com/k1moradi/RDP-server/actions/runs/38604244975),
Linux/GCC 50/50, macOS/Clang and Windows/MSVC
48/48 in Debug/Release, installed SDK, all packages
and policy PASS.

**New code and tests:** exact implementation
`d2885363502e34e52c71c41342902908b781fd58`.
Changed `src/server/security/credssp_tsrequest.{h,cpp}`,
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt`, plus same-commit roadmap,
architecture and standards. Add single bounded
`SSL_read_ex` from established server SSL directly
to the owned DER TSRequest framer; pin TLS identity,
separate `Progress` from WANT_READ/WANT_WRITE, never
read a coalesced second frame before release, reject
mixed plaintext/TLS sources and TLS EOF and wipe buffers.
Add three dedicated positive/negative real in-memory
OpenSSL TLS CTests (not simply reusing prior assertions).
**PASS:** [Actions run 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062),
completed all four jobs successfully: Linux/GCC
**53/53** Debug and Release, macOS/Clang and Windows/MSVC
**51/51** each in Debug and Release. Each new
`transport.credssp-tls-fragments`,
`transport.credssp-tls-coalesced` and
`transport.credssp-tls-rejections` passed on all
three systems. SDK installed downstream consumer,
per-OS ZIP/SHA-256 uploads and policy PASS. Commands
within the sole CI `build/` root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON -DRDP_SERVER_TEST_LINUX_GSSAPI=ON`
(Linux, OFF for macOS/Windows), `cmake --build build
--config Debug --parallel 2`, `ctest --test-dir build
--build-config Debug --output-on-failure`,
then reconfigure same root for Release, build,
CTest, install/consumer, CPack and SHA-256/upload.
The earlier Ubuntu Release preauth test fixture
warning `-Wstringop-overflow` remains nonfatal
(line shifted from 582 to 584).
**NOT RUN:** owner-local updated build, real
CredSSP/GSS provider ticket/keytab, TLS public-key
binding, independent OS identity authority, or
external Microsoft RDP desktop acceptance.
**Next:** authenticated real GSS/TLS binding and
OS session policy, not a synthetic admission.

## Verified GSS TLS provenance and version pinning (2026-10-14)

**Previous green head:** `82193719abd23e87abfcaa6a0932a11ca499d15a`,
[CI 38607454966](https://github.com/k1moradi/RDP-server/actions/runs/38607454966):
Linux 53/53 and macOS/Windows 51/51 Debug/Release
CTests plus portable SDK consumer, package uploads
and documentation gate.

**New implementation:** `6e11b25224e1a5e6c3f45778436afc3950a3e866` changes
`src/server/security/credssp_tsrequest.h`,
`src/server/security/gssapi_spnego_acceptor.{h,cpp}`,
`src/server/security/gssapi_credssp_binding.cpp`,
`tests/test_owned_preauth_session.cpp` and
`tests/CMakeLists.txt`, together with authoritative
roadmap, architecture, coding/testing standards and
this ledger. Carries real server-TLS completed-frame
provenance from the single framer to the actual Linux
MIT GSSAPI acceptor, pins SSL and version 5/6
across SPNEGO tokens, and refuses protected GSS
pubKeyAuth without that same SSL/version.
**PASS:** [CI 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612)
completed SUCCESS: Linux/GCC **55/55**, macOS/Clang
and Windows/MSVC **52/52** CTests in both Debug
and Release, including both new `transport.credssp-tls-provenance`
and Linux-only `security.gssapi-tls-ownership`.
All 4 jobs passed: 3 platforms and documentation-policy;
staged installed SDK consumer, ZIP and SHA-256 artifact
uploads each succeeded, prerelease publisher SKIPPED
(no tag). CI commands:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
with `-DRDP_SERVER_TEST_LINUX_GSSAPI=ON` on Linux
(OFF for macOS/Windows), `cmake --build build --config
Debug --parallel 2`, `ctest --test-dir build
--build-config Debug --output-on-failure`, then
reconfigure and re-use the same `build/` root in
Release and rerun builds, CTests, SDK installation,
consumer, CPack packaging and checksum upload.
A pre-existing nonfatal Ubuntu Release test compiler
warning at `tests/test_owned_preauth_session.cpp:587`
remains open. **NOT RUN:** owner's local updated
build, real Kerberos ticket/keytab and successful
GSS session, TLS public-key binding, OS account
authorization, Windows App/FreeRDP or desktop.
**Next:** authenticated positive GSS/TLS transcript,
combined final client negoTokens/pubKeyAuth
interoperability and independently verified OS
identity before a live MCS or desktop.

## Verified combined final SPNEGO + TLS pubKeyAuth (2026-10-14)

**Prior main:** `5a17ed4bd38a4af818f2541c2d1f858f5765d92c`,
[CI 38610037109](https://github.com/k1moradi/RDP-server/actions/runs/38610037109)
passed Linux/GCC 55/55 and macOS/Windows 52/52
Debug/Release CTests, policy, installed SDK consumers
and three ZIP/checksum packages.

**Exact implementation:**
`ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`.
Changed `src/server/security/credssp_tsrequest.h`,
`src/server/security/gssapi_spnego_acceptor.h`,
`src/server/security/gssapi_credssp_binding.cpp`,
`tests/test_owned_credssp_tsrequest.cpp`,
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt`, plus canonical roadmap,
architecture, coding/testing standards and validation.
The MS-CSSP 3.1.5 combined final v5/v6 client request
now requires exactly one GSS token, encrypted pubKeyAuth
and a 32-byte nonce in one TLS-derived frame. A
continuing and pinned SSL/GSS context must finish
GSS security verification and unwrap/compare the
client binding, wrap the server binding, and wipe/release
the same frame. Outstanding GSS reply tokens, bad
field shapes, wrong order or failed provider remain
terminal, never yielding desktop authorization.

**PASS:** [Actions run 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453),
all four jobs SUCCESS, with Linux/GCC Debug and
Release **58/58**, macOS/Clang and Windows/MSVC Debug
and Release **54/54** CTests. Linux's real GSSAPI
`security.gssapi-final-combined-denials` and
portable `security.credssp-final-negotiation-binding`
and `security.credssp-final-binding-rejections`
passed in BOTH configurations. The staged SDK
installation, downstream consumer configure/link/
execute, CPack ZIP/SHA-256 and artifact upload each
passed on all three OSes; documentation policy passed.
In CI's sole checkout-local `build/`: 
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON` (Linux additionally
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`, OFF elsewhere),
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug
--output-on-failure`, same-root Release reconfigure,
build and CTest, SDK/consumer/CPack/upload.
Existing Linux Release `-Wstringop-overflow` warning
at `tests/test_owned_preauth_session.cpp:587`
persists but is nonfatal.
**NOT RUN:** owner's local new checkout build,
real keytab/tickets, positive Kerberos mechanism
and TLS binding verification, independently authorized
OS identity, external Windows App/FreeRDP or desktop.
**Next:** verify real successful GSS/Kerberos + active
TLS pubKeyAuth and independent OS policy before
enabling live MCS domain response emission.

## Verified nonblocking CredSSP server TLS reply transport (2026-10-14)

**Previous green head:** `a3f841a572aa861cbaa1ff890b228598e612fccc`,
[CI 38612678888](https://github.com/k1moradi/RDP-server/actions/runs/38612678888):
Linux/GCC 58/58 and macOS/Windows 54/54
full Debug/Release CTests and all SDK/policy/
packaging gates PASS.

**Initial code implementation:**
`915cd2bfac59d7e775b458b7deed3d94db17ad93`.
Added one bounded `TsRequestTlsReplyWriter`
to `src/server/security/credssp_tsrequest.{h,cpp}`,
alongside 3 new behavior-named CTests in
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt`, with roadmap,
architecture, coding/testing standards and
this validation ledger co-changed.
Single TLS-bound owned canonical server DER
response, stable buffer across `SSL_write_ex`
WANT_READ/WANT_WRITE, no duplicate frames,
and explicit wipe-on-release/fail/close.

**Initial CI FAIL:** [CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856).
The test fixture's attempt to resize an already
connected BIO pair with `BIO_set_write_buf_size`
after the TLS handshake failed on macOS Debug.
No claim of passing backpressure was made.
**Corrective commit:**
`afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
constructs the same OpenSSL memory-BIO pair
with optional 2048-byte server write capacity
BEFORE real TLS handshake and keeps all test
assertions.

**PASS:** [CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824)
completed successfully for all four jobs:
Linux/GCC **61/61** and macOS/Clang,
Windows/MSVC **57/57** CTests in BOTH Debug
and Release, including ALL three new
`transport.credssp-tls-reply-wire`,
`transport.credssp-tls-reply-backpressure`
and `transport.credssp-tls-reply-rejections`.
The Linux-only real GSS provider rejection
cases remain green. Installed SDK consumer,
three ZIP/SHA256 artifact uploads and
documentation policy passed. Commands within
the sole CI `build/` root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON` (Linux: 
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`, OFF
for macOS/Windows), `cmake --build build
--config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug
--output-on-failure`; reconfigure same root
in Release, build/CTest, staged install,
downstream CMake consumer, CPack ZIP,
SHA-256 digest and artifact upload.
A preexisting nonfatal Ubuntu Release warning
`-Wstringop-overflow` remains at
`tests/test_owned_preauth_session.cpp:589`.
Prerelease publication SKIPPED (no version tag).
**NOT RUN:** owner-local updated build,
valid GSS Kerberos keytab/tickets and a real
successful provider-selected TLS pubKeyAuth
exchange, independently authorized OS account,
Windows App/FreeRDP or desktop.
**Next:** controlled real GSS/TLS positive
authentication and independent OS session
policy BEFORE any real MCS channel/domain
reply or remote desktop admission.

## Verified Linux MIT GSSAPI -> bounded TLS replies (2026-10-14)

**Prior exact main:** `195603ce733724b8940523f11b59d8c328d14e66`,
[CI 38615240623](https://github.com/k1moradi/RDP-server/actions/runs/38615240623):
Linux 61/61 and macOS/Windows 57/57
Debug+Release CTests, documentation,
SDK consumer and packages PASS.

**Implementation:**
`27e8342aee0e475c3b0854330678e7c7596fc912`
changes
`src/server/security/gssapi_spnego_acceptor.{h,cpp}`,
`src/server/security/gssapi_credssp_binding.cpp`,
`tests/test_owned_preauth_session.cpp`,
`tests/CMakeLists.txt` and the existing
roadmap, architecture, coding/testing
standards and this verification ledger.
Adds two direct provider->writer methods:
`acceptFramedNegoAndQueueReply` requires
a continuing real MIT GSS context and
its nonempty provider output;
`processFinalFramedNegoAndQueueBindingReply`
requires successful combined-final
GSS context verification, confidential
client binding, matching active server
TLS certificate, and real GSS-wrapped
server binding. Both require writer
idle, same SSL/version, wipe transient
tokens and close reader/writer/provider
atomically on error. They queue DER
but do NOT call `SSL_write_ex`,
admit identity, send an MCS reply
or install a live server.

**PASS:** [Actions 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493)
completed SUCCESS with all 4 jobs:
Linux/GCC Debug and Release **64/64**,
macOS/Clang and Windows/MSVC
Debug and Release **57/57** CTests.
All 3 new Linux-only named tests
`security.gssapi-negotiation-reply-gates`,
`security.gssapi-binding-reply-gates`,
`security.gssapi-reply-order-denials`
passed. SDK installed consumer, CPack
ZIP/SHA-256 manifests and all three
artifact uploads, documentation-policy
PASSED. CI uses each checkout-local
single `build/`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON -DRDP_SERVER_TEST_LINUX_GSSAPI=ON`
(Linux; OFF on macOS/Windows);
`cmake --build build --config Debug --parallel 2`;
`ctest --test-dir build --build-config Debug
--output-on-failure`; same-root Release
reconfigure/build/CTest, staged SDK
installation, downstream consumer,
CPack and SHA-256 package upload.
Existing Ubuntu Release
`tests/test_owned_preauth_session.cpp:589`
`-Wstringop-overflow` warning
remains nonfatal. Prerelease skipped
(no tag).
**NOT RUN:** user's own persistent
local `~/rdp-server/build`, successful
positive Kerberos service keytab,
client tickets, mutually verified
GSS/TLS certificate-bound proof,
independent OS session admission,
Windows App/FreeRDP or desktop.
**Next:** controlled opt-in positive
GSS Kerberos / selected TLS proof
then independently audited OS
authorization before live RDP
channel, graphics or desktop.

## Verified selected server TLS certificate pinning (2026-10-14)

**Previous green head:** `1bfbc3452078ed1a4676551953e325366981e587`,
[CI 38618001913](https://github.com/k1moradi/RDP-server/actions/runs/38618001913)
Linux/GCC 64/64, macOS/Windows 57/57
CTests in both Debug and Release, all SDK/
policy and packaging gates PASS.

**Initial implementation:**
`d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`.
`src/server/security/credssp_tls_certificate.{h,cpp}`
adds a SHA-256 fingerprint of the selected
established server X.509 certificate and
centralizes TLS >=1.2 server-role/cipher/
certificate checks for binding computations.
`src/server/security/credssp_tsrequest.{h,cpp}`
pins the selected certificate fingerprint
alongside the original SSL handle from the
first completed server TLS read and rechecks
it before subsequent TLS reads, even after
`releaseFrame`, and again before releasing
completed frame SSL provenance to GSSAPI.
Any changed selected certificate on the
SAME SSL handle is terminal; close wipes
frame and fingerprint. One owner, no
additional connection or GSS controller.
`tests/test_owned_preauth_session.cpp`
adds three independent, behavior-named
CTests, registered in `tests/CMakeLists.txt`,
with real TLS handshakes, live certificate
hash oracles and same-SSL selected-certificate
replacement after complete or partial frame.
Roadmap, architecture, coding/testing
standards and this ledger co-changed.

**Initial CI FAIL:**
[Actions 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326)
Linux/GCC Debug test compilation failed
on `SSL_get_certificate` returning
`const X509*` versus
`SSL_use_certificate` expecting `X509*`.
The production objects compiled but
tests had NOT passed.
**Corrected commit:**
`340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`:
use `X509_dup` into the existing mutable
RAII `CertificatePointer` on both full-frame
and partial-frame certificate-swap tests;
assert matching selected live fingerprints.
No assertions disabled or skipped.

**PASS:** [Actions 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190)
all FOUR required jobs SUCCESS:
Linux/GCC **67/67**, macOS/Clang and
Windows/MSVC **60/60** CTests EACH in
Debug AND Release. All THREE new tests
`security.credssp-active-tls-binding-positive`,
`security.credssp-active-tls-binding-rejections`,
`transport.credssp-tls-certificate-pinning`
PASS on all systems. Installed SDK
downstream consumer configure/link/execute,
CPack ZIP/SHA-256, all three artifact uploads,
documentation policy PASS. CI used one
checkout-local `build/` per job:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON` (+ Linux-only
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`),
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build --build-config Debug
--output-on-failure`; then reconfigure
same root Release/build/CTest, stage install,
SDK downstream consumer, CPack and checksum.
Existing nonfatal Ubuntu Release compiler
warning in test fixture remains. No release
tag/prerelease publication.
**NOT RUN:** owner's local updated build,
actual successful Kerberos/GSS keytab
and client tickets, authenticated real
GSS unwrap/wrap of the pinned TLS
certificate hash, separately authorized
OS account or live Microsoft/FreeRDP
client and desktop.
**Next:** opt-in controlled real positive
GSS/Kerberos + TLS certificate binding,
then independent OS policy before
live MCS/session and desktop admission.

## Verified Linux GSS binding-only TLS-frame provenance (2026-10-14)

**Previous exact green main:**
`2d08e9662ed1a597a81b9e3424770cdc5fe0b335`,
[CI 38619989509](https://github.com/k1moradi/RDP-server/actions/runs/38619989509)
Linux 67/67 and macOS/Windows 60/60 CTests,
Debug+Release and SDK/policy/packages PASS.

**Implementation:**
`340b25d2352314003053ec19d467b75d578c9dbf`
changes `src/server/security/gssapi_spnego_acceptor.h`
and `src/server/security/gssapi_credssp_binding.cpp`.
The historical direct
`processProtectedBinding(SSL*, rawDer)`
has NO positive path because caller DER
lacks SSL/TLS record provenance. New
`processFramedProtectedBinding` borrows the
completed strict binding-only DER from the
single `TsRequestFrameReader`, checks its
verified original SSL and selected X.509
certificate/version, requires actual
GSS `MechanismVerified` before confidential
GSS unwrap/client nonce hash comparison
and GSS wrap, then releases/wipes the
original frame. The new
`processFramedProtectedBindingAndQueueReply`
shares the existing guarded queue
with the strict combined-final method,
never overwrites pending writer output
and always cleanses protected GSS tokens
or closes all three owners on failure.
Two independent Linux real OpenSSL
memory-BIO CTests added in the existing
`tests/test_owned_preauth_session.cpp`
and `tests/CMakeLists.txt`; relevant
roadmap, architecture, coding/testing
standards and this ledger co-changed.
No standalone executable, default service
or second GSS state machine was added.

**PASS:** [Actions 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568)
all four required jobs SUCCESS:
Linux/GCC full **69/69** CTests in Debug
and Release, including both new
`security.gssapi-framed-binding-only-denials`
and `security.gssapi-framed-binding-reply-order`;
macOS/Clang and Windows/MSVC each
**60/60** CTests, BOTH Debug and Release.
Three SDK installed downstream consumers,
CPack ZIP/SHA-256 checksum artifacts
and all package uploads and documentation
policy PASS. Per-job CI used only
checkout-local `build/`: configure Debug
with Linux `-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`
(portable OFF), compile Debug and
`ctest --test-dir build --build-config Debug
--output-on-failure`, reconfigure the
same root for Release, compile/CTest,
staged install/consumer/CPack/sha256/upload.
Preexisting nonfatal Ubuntu Release
`-Wstringop-overflow` in TLS test fixture
at `tests/test_owned_preauth_session.cpp:590`
remains unrelated.
**NOT RUN:** user's local persistent
`~/rdp-server/build/`, controlled
real positive keytab/client tickets
and GSS/TLS certificate-bound proof,
independent OS account/session policy,
Windows App or other external RDP
client or desktop. Authentication
refusal tests never authorize access.
**Next:** verified genuine positive
Kerberos/SPNEGO, GSS unwrap/wrap and
active TLS binding with explicit
test-only credentials, then separate
OS authorization before MCS replies
or remote desktop admission.

## Verified outgoing CredSSP selected TLS certificate continuity (2026-10-14)

**Prior exact known-green main:** `5777fa738fb94499356ba910643edd7f8a127026`,
[CI 38624268810](https://github.com/k1moradi/RDP-server/actions/runs/38624268810):
Linux/GCC 69/69, macOS/Clang,
Windows/MSVC 60/60 full CTests,
Debug and Release, SDK, ZIP/SHA-256
artifacts and documentation policy PASS.

**New implementation:**
`53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`
changes the ORIGINAL
`src/server/security/credssp_tsrequest.{h,cpp}`
`TsRequestTlsReplyWriter`, the existing
`tests/test_owned_preauth_session.cpp`
fixture and `tests/CMakeLists.txt`
test registration, and updates
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`,
`docs/testing_standards.md` and this
validation ledger in the same commit.
Outgoing CredSSP responses now pin
the original finished TLS server SSL*
and the selected DER X.509 SHA-256
fingerprint from the FIRST queued
canonical v5/v6 reply. The writer
checks that certificate before
EVERY TLS write/retry, idempotent
Complete, successful release and
next response queue, using existing
`fingerprintActiveCredSspServerTlsCertificate`.
A mismatch on the same SSL object
closes and wipes pending DER and
the certificate fingerprint, without
a further SSL_write_ex. Already
submitted TLS data cannot be retracted.
No new authentication context,
socket listener or OS session.

**PASS:** [Actions 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102)
completed SUCCESS for documentation
policy and all three protocol jobs:
Linux/GCC **72/72** and macOS/Clang,
Windows/MSVC **63/63** full CTests
in BOTH Debug and Release. ALL THREE
new tests
`transport.credssp-tls-reply-cert-pending`,
`transport.credssp-tls-reply-cert-completion`,
`transport.credssp-tls-reply-cert-backpressure`
PASS on all platforms. SDK installation
and downstream CMake consumer compile,
link and execution, three CPack ZIP
archives, three SHA256 checksum
manifests and artifact uploads all PASS.
CI commands: `cmake -S . -B build
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
(with Linux `-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`),
`cmake --build build --config Debug
--parallel 2`, `ctest --test-dir
build --build-config Debug
--output-on-failure`; same-root
Release reconfigure/compile/CTest,
SDK install, downstream consumer,
CPack package/SHA256/upload.
Previous nonfatal Ubuntu Release
`-Wstringop-overflow` warning in
TLS fixture around line 590
remains. Prerelease SKIPPED (no tag).
**NOT RUN:** owner's local
`~/rdp-server/build`, genuine
positive Kerberos/GSS service
keytab and client tickets with
real confidential selected-TLS
public-key binding, independently
authorized OS account/session,
Microsoft RDP client or actual
desktop. Negative TLS continuity
tests never grant admission.
**Next:** authorized opt-in isolated
positive Kerberos/GSS TLS proof
and independent OS authorization
before MCS, graphics or desktop.

## Verified GSS acceptor certificate pin and opt-in real Kerberos probe build (2026-10-14)

**Prior verified main:**
`973561cefc37f9c4d9195276da2ce84862eae4ae`,
[CI 38674782887](https://github.com/k1moradi/RDP-server/actions/runs/38674782887)
Linux/GCC 72/72, macOS/Clang and Windows/MSVC
63/63 standard CTests in both Debug and
Release, SDK/packages/policy PASS.

**Implementation:**
`1f6740452f27332303ded71d4f5f23bb599b9726`
changes the existing optional Linux
`src/server/security/gssapi_spnego_acceptor.{h,cpp}`
and `gssapi_credssp_binding.cpp`
to retain the first TLS-selected X.509
SHA-256 fingerprint IN the GSS acceptor
rather than trusting `SSL*` pointer
plus whatever new per-frame reader the
caller constructs. Constant-time recheck
gates later GSS tokens, binding-only
and combined-final public-key proofs
and outgoing provider-bound reply
handoffs. Terminal reject cleanses
digest/principal and releases the
GSS context/explicit creds.
`CMakeLists.txt` and `tests/CMakeLists.txt`
introduce opt-in
`RDP_SERVER_TEST_REAL_KERBEROS=ON`
on Linux with mandatory explicit
`RDP_TEST_KRB5_SERVICE`,
`RDP_TEST_KRB5_KEYTAB` and
`RDP_TEST_KRB5_CCACHE` environment
values; NO host defaults, automatic
KDC, service activation or live
RDP listener. A non-default case
in the existing
`tests/test_owned_preauth_session.cpp`
compiles REAL MIT GSS client and
server exchanges through the
original OpenSSL TLS fixture,
confidential binding-only proof
and a fresh-reader/same-SSL
certificate substitution denial.
The binding-only diagnostic cannot
claim normative combined-final
MS-CSSP interoperability.
Same-commit roadmap/architecture,
coding/testing standards and
this validation ledger updated.

**PASS:** exact [Actions 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820)
at implementation SHA above; all
four required jobs SUCCESS. Linux/GCC
**72/72**, macOS/Clang and
Windows/MSVC **63/63** CTests, EACH
Debug and Release, documentation
policy, three staged installed
SDK consumers and all three
CPack ZIP/SHA256 package uploads.
CI uses checkout-local `build/`:
`cmake -S . -B build
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`
plus Linux-only
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`,
build/CTest Debug; reconfigure SAME
root Release, build/CTest Release;
install/stage SDK, downstream
CMake consumer, CPack and checksums.
The optional real Kerberos probe
is COMPILED by Linux/GCC but NOT
registered/run in normal CI.
Prior nonfatal Ubuntu Release
test `-Wstringop-overflow` around
`tests/test_owned_preauth_session.cpp:594`
persists. No protocol prerelease tag.

**NOT RUN:** positive Kerberos/GSS
test with explicit separately
authorized service keytab and real
client ticket cache; confidential
GSS proof in that opt-in test,
normative last-token combined
MS-CSSP exchange with Microsoft
client, owner's local build,
independently approved OS
account/session or real desktop.
Do not call compilation positive
Kerberos acceptance.
**Next:** provision an isolated
external KDC/keytab/ticket ONLY
with explicit authorization,
execute opt-in test, verify combined
final SPNEGO/pubKeyAuth behavior,
then implement independent OS
session policy before MCS/desktop.

## Verified v6 CredSSP server failure TSRequest serializer and TLS writer (2026-10-14)

**Previously verified main:**
`c0aa5a2032da910c08ef982f5421dcc89166526e`,
[CI 38678271447](https://github.com/k1moradi/RDP-server/actions/runs/38678271447):
Linux 72/72 and macOS/Windows 63/63
CTest, Debug+Release, SDK/policy/packages PASS.

**Implementation** `6925ac11a49b3d71a6ffa120b688ca95a0a088af`:
`src/server/security/credssp_tsrequest.{h,cpp}`
adds a v6-only canonical
`encodeCredSspServerFailureTsRequest`
for [0] version plus [4] signed
32-bit unsuccessful NTSTATUS,
restricted to 0xC000006D and
0xC00000BB. Other versions,
arbitrary NTSTATUS, mixed
credentials/tokens/binding/nonce
and success-shaped error replies
cannot be emitted. The ORIGINAL
`TsRequestTlsReplyWriter` gains
`queueFailureReply`, using ONE
private `queueEncoded` for both
old provider token/binding replies
and error DER. It retains exact
SSL*/certificate continuity,
OpenSSL WANT retry buffer lifetime,
single pending reply, and securely
wipes discarded DER on failure.
Upon completed failure delivery
the reply is released and the
writer closes TERMINALLY so no
other response follows.
The code deliberately DOES NOT
automatically dispatch NTSTATUS
from unverified provider states
or authorize any client/OS session.

FOUR portable CTests were added
to the EXISTING
`tests/test_owned_credssp_tsrequest.cpp`,
`tests/test_owned_preauth_session.cpp`
and original `tests/CMakeLists.txt`,
with same-commit changes to
`docs/ROADMAP.md`, architecture,
coding and testing standards
and this ledger.
**PASS:** [Actions 38683205424](https://github.com/k1moradi/RDP-server/actions/runs/38683205424)
exact implementation commit:
documentation-policy,
Linux/GCC **76/76** Debug and
Release, macOS/Clang **67/67**
Debug and Release, Windows/MSVC
**67/67** Debug and Release,
including all four new
`security.credssp-server-failure-wire`,
`security.credssp-server-failure-rejections`,
`transport.credssp-tls-failure-reply-wire`,
`transport.credssp-tls-failure-reply-rejections`
PASS across all operating systems.
All 3 installed CMake SDK consumers
compiled/linked/ran, 3 SDK ZIP and
SHA256 archives uploaded, project
policy CTests PASS. The existing
CI commands use ONE checkout-local
`build/`: CMake configure
`-DCMAKE_BUILD_TYPE=Debug` with
`-DBUILD_TESTING=ON` and Linux-only
`-DRDP_SERVER_TEST_LINUX_GSSAPI=ON`,
build/CTest Debug, same-root
Release reconfigure/build/CTest,
installed consumer, CPack ZIP,
SHA256 and artifact upload.
Known unrelated Ubuntu Release
`-Wstringop-overflow` at TLS
fixture line 594 remains nonfatal.
Protocol prerelease SKIPPED
(no release tag).
**NOT RUN:** owner's persistent
`~/rdp-server/build/`, opt-in
genuine MIT Kerberos using an
explicit keytab and client cache,
GSS and selected TLS pubKeyAuth
positive proof, actual GSS provider
error-code dispatch, independent
OS user authorization, Microsoft
RDP client or desktop.
**Next:** real isolated/authorized
positive GSS proof test, then
explicit terminal failure-message
dispatch and separate OS session
policy BEFORE issuing live MCS.

## Verified offline server Demand Active serialization (2026-10-15)

**Prior verified base:** main
`659e0b816e8055f4bec7c87bda2816d8a614b9af`,
[CI 38715062876](https://github.com/k1moradi/RDP-server/actions/runs/38715062876)
PASS: Linux/GCC **93/93**, macOS/Clang and
Windows/MSVC **83/83** CTests Debug and Release,
plus installed SDK consumer, ZIP/SHA256 artifacts
and documentation policy. The owner confirms
**83/83 local PASS** on that prior head. These
tests do NOT validate this new serializer.

**Code:** extend the one portable
`src/server/transport/mcs_channel_connection.{h,cpp}`
with `encodeRdpDemandActivePdu`, direct into
caller-owned output. The 22-byte fixed Share
Control header/body skeleton contains
normative server pduSource 1002, version/type
0x0011, caller shareID/sessionId, source
descriptor length, combined capability length
including count+padding, and an exact counted
TS_CAPS_SET sequence. The parser and encoder
now share one checked capability-envelope
validator. Fail without mutation for invalid
count/size/length, 0x8000 legacy FlowPDU,
output shortage or overlapping source/output.
Success copies only explicit input spans and
preserves the output suffix. Does not validate
cap semantics, TLS provenance or OS authority.

**Tests:** same original MCS executable and
`tests/CMakeLists.txt` add
`transport.share-demand-active-encode-wire`
and `transport.share-demand-active-encode-rejections`.
Expected portable **85**, Linux GSSAPI **95**
CTest cases. Architecture, ROADMAP and existing
coding/testing standards are amended in the SAME
implementation commit.

**Initial FAIL:** implementation
`5c0a790ba317f592da21f457842ba6a39a6bd553`
[Actions 38716458988](https://github.com/k1moradi/RDP-server/actions/runs/38716458988)
failed the new `transport.share-demand-active-encode-wire`
test because its historical parser-only fixture has
nonzero, ignored `pad2Octets` whereas the writer's
canonical pad is zero. The new negative suite PASSED.
Correction changes ONLY the byte-exact expected oracle
to zero those ignored pad bytes; the production writer
must still emit zero and the parser still accept
nonzero padding. **Corrected PASS:** commit
`ec7261e059e699f23511f9d17d0a77762bf5d337`,
[Actions 38716746326](https://github.com/k1moradi/RDP-server/actions/runs/38716746326):
Linux/GCC **95/95** and macOS/Clang, Windows/MSVC
**85/85** full CTests in BOTH Debug and Release,
including the two new writer suites. Documentation
policy, installed SDK consumer and all three
ZIP/SHA256 packages PASS. Prerelease publish
SKIPPED (not tagged). No production code was
changed in the test-oracle correction.

**NOT RUN:** owner-local corrected-code build/CTest,
real MIT keytab/ticket GSS
positive TLS authentication, independently
authorized OS session policy, real licensing,
full share activation, MCS/TLS output and
actual Windows/macOS RDP client/desktop.
Reuse the owner's ONE existing build root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`;
`cmake --build build --config Debug --parallel 2`;
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** exact-head CI/owner local tests;
then isolated authorized GSS/TLS evidence and
independent OS authorization before live
capability negotiation/desktop transmission.

## Verified offline Demand/Confirm Active correlation (2026-10-15)

**Previous exact main:** `0e508cfad519d7f9f9f7cb0dd5e54b1c0118e465`,
[CI 38718555326](https://github.com/k1moradi/RDP-server/actions/runs/38718555326)
PASS Linux/GCC **97/97**, macOS/Clang and
Windows/MSVC **87/87** Debug/Release CTests,
installed SDK consumer, three ZIP/SHA256
artifacts and documentation policy. Owner reports
**87/87** locally on the prior head; this is
NOT evidence for the current changes.

**Increment:** add `correlateRdpActiveExchange`
to the existing first-party
`src/server/transport/mcs_channel_connection.{h,cpp}`.
It reuses `parseRdpActivePdu` for both untrusted
complete frames, checks server Demand pduSource
1002, Confirm user pduSource equal to an externally
provided 1001..65535 expected ID, mandatory
Confirm originatorID=1002 and identical shareIDs.
Reject unrepresentable 65536 T.125 user ID rather
than truncate to a valid 16-bit Share Control ID.
No allocations, new state controller, capability
semantics, TLS I/O, GSS principal assertion or
OS admission. Positive enum is explicitly
`ConsistentSyntaxOnly` and NEVER session access.
Two new `transport.share-active-exchange-correlation`
and `transport.share-active-exchange-denials`
CTest cases added to the original MCS fixture.
Expected **89 portable / 99 Linux GSS** total.
Same implementation commit updates sole ROADMAP
and architecture, coding and testing standards.

**PASS:** exact implementation
`d83549d489be2b8e49855429693d2c5d4b1a0a71`,
[Actions 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636):
Linux/GCC **99/99**, macOS/Clang and Windows/MSVC
**89/89** CTests BOTH Debug and Release, including
both new correlation cases; installed SDK consumer,
ZIP/SHA256 packages and docs-policy PASS.
Prerelease publishing SKIPPED without a tag.
**NOT RUN:** owner-local new-head compile/CTest,
real Kerberos/TLS protected binding, credentials,
independent OS authorization, licensed share,
Microsoft clients, graphics, input and desktop.
Owner's one reused build root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`;
`cmake --build build --config Debug --parallel 2`;
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** owner-local single-root CTest,
then genuinely isolated Kerberos/TLS + independently
authorized OS identity before any live activation.

## Verified Demand/Confirm Active capability envelope intake (2026-10-15)

**Previous exact main:** `ea258bfcc4a8d8d759a9bc1a882c4f0121959296`,
[CI 38713180113](https://github.com/k1moradi/RDP-server/actions/runs/38713180113)
PASS Linux/GCC **91/91** and macOS/Clang,
Windows/MSVC **81/81** full CTests each Debug
and Release, installed SDK consumer, ZIP/SHA256
packages and documentation policy. Owner reports
**81/81** PASS locally on that prior head. This
evidence does NOT include the new capability parser.

**Increment:** `parseRdpActivePdu` reuses the
original exact-boundary Share Control PDU owner
and recognizes Demand Active and Confirm Active
per MS-RDPBCGR 2.2.1.13.1.1 and 2.2.1.13.2.1.
It rejects mismatched sourceDescriptor/combined
lengths, malformed counted TS_CAPS_SET envelopes,
bad Confirm originator, absent Demand session ID,
extra/missing input and invalid outer packet.
It preserves pads, unknown cap types and the
published four-byte FONT envelope syntax, but
NEVER validates cap data semantics or admits a
session, authenticates an OS user, negotiates
H.264 or activates the share. Two tests
`transport.share-active-capabilities-wire` and
`transport.share-active-capabilities-rejections`
reuse the existing MCS executable and CTest list;
expected **83** portable / **93** Linux GSS.
Architecture, roadmap, coding and testing standards
were updated in the SAME implementation commit.

**PASS:** exact implementation `5125fcc68f7e3e9fdd496f8504a17a3a7a251953`,
[Actions 38714673332](https://github.com/k1moradi/RDP-server/actions/runs/38714673332)
Linux/GCC **93/93**, macOS/Clang and Windows/MSVC
**83/83** CTests in each Debug AND Release.
Both new Demand/Confirm capability-envelope
regressions PASS across Linux, macOS and Windows.
Documentation-policy, staged installed CMake
SDK consumer and three ZIP/SHA256 artifact
uploads PASS; prerelease publishing SKIPPED
(no release tag).
**NOT RUN:** owner-local new-code build/CTest,
opt-in genuinely authenticated Kerberos/TLS
keytab/tickets and binding, independent OS
authorization, live capability negotiation,
Share Active lifecycle, desktop graphics or input.
Reuse owner's single existing build root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** owner-local single-build-root
regressions; controlled real Kerberos/TLS binding
and independently approved OS account/session
before any live capability exchange or activation.

## Verified offline server finalization Synchronize/Control writers (2026-10-15)

**Previous exact main:** `f48332e4465b6915e1683e5ed4f3aae767d3c777`,
[CI 38717067457](https://github.com/k1moradi/RDP-server/actions/runs/38717067457)
completed SUCCESS: Linux/GCC **95/95**, macOS/Clang
and Windows/MSVC **85/85** full Debug/Release CTests,
SDK installed downstream consumer, ZIP/SHA256
packages and documentation policy. Owner reports
local **85/85** on that prior commit. These results
do not cover the new finalization writers.

**Implementation:** the one existing
`src/server/transport/mcs_channel_connection.{h,cpp}`
owner gains `encodeRdpServerSynchronizePdu` and
`encodeRdpServerControlPdu` using one common
private fixed Share Control/Data header helper:
normative pduSource=1002, no compression, zero
ignored pad, exact size 22 or 26. Synchronize
preserves any raw 16-bit targetUser, including
Microsoft's historically uninitialized sample.
Only the two server Control actions are accepted:
Cooperate requires zero assigned client ID,
Granted requires 1001..65535 user ID and writes
server controlId 1002. No caller-supplied GSS
identity is accepted as a channel grant. Both
functions check output/action bounds before
mutating the destination, do not allocate or
send TLS and never advance the session lifecycle.

Two behavior-named CTests
`transport.share-server-finalization-encode-wire`
and `transport.share-server-finalization-encode-rejections`
reuse the original MCS test binary and the single
CTest registry. Expected **87** portable and
**97** Linux GSS-enabled full CTests. The sole
ROADMAP, architecture and mandatory coding/testing
standards are updated in the SAME implementation
commit.

**PASS:** exact implementation `be87f4ba35289d881a161c0d03ac28c592f3a44f`,
[Actions 38718197674](https://github.com/k1moradi/RDP-server/actions/runs/38718197674)
Linux/GCC **97/97**, macOS/Clang and Windows/MSVC
**87/87** CTests in BOTH Debug and Release. Both
new server finalization wire/negative behavior
cases passed everywhere; installed SDK CMake
consumer, ZIP/SHA256 artifacts and docs policy
PASS. Prerelease publish SKIPPED (no release tag).
**NOT RUN:** owner-local new-head build/CTest,
controlled genuine GSS/Kerberos service keytab
and client tickets, TLS pubKeyAuth, independent
OS authorization, licensed/activated share,
real RDP clients, graphics, clipboard or console. Owner-local commands:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** owner-local single-build-root CTest;
then independently authorized isolated real
Kerberos/TLS with separate OS session policy
before live finalization dispatch or desktop.

## Verified offline T.128 finalization Synchronize/Control decoder (2026-10-15)

**Previous main:** `1c4dc32ef2bb3d1bc86aeffa1bcc7d10f57ab8ed`,
[CI 38711285093](https://github.com/k1moradi/RDP-server/actions/runs/38711285093)
PASS: Linux/GCC **87/87**, macOS/Clang and
Windows/MSVC **77/77** full CTests in BOTH Debug
and Release, plus installed SDK consumers, ZIP
SHA-256 artifacts and documentation-policy.
The owner also reports **77/77** local PASS for
the previous commit. These results DO NOT
validate the incremental code below.

**Change:** Extend existing first-party
`src/server/transport/mcs_channel_connection.{h,cpp}`
to decode standalone (already isolated/decrypted)
Microsoft T.128 22-byte Synchronize (type2 0x1f,
messageType=1, targetUser LE16) and 26-byte Control
(type2 0x14, action Request/Granted/Detach/Cooperate,
grantId LE16 and controlId LE32) on top of existing
checked Share Control + Share Data framing.
Rejected/malformed/wrong-size/unknown action/type/
stream/version and unsupported compressed PDUs
yield no activation or control state. Pure offline
syntax, no new owner or data copy. Raw identifiers
are untrusted, including a forged GrantedControl
action in a client-shaped packet; only a future
genuinely Kerberos/TLS-bound and independently
OS-authorized session owner can apply direction,
ordering and channel assignment.

**Tests:** same
`tests/test_owned_mcs_connect_initial.cpp` fixture
and `tests/CMakeLists.txt` registry gain four
portable behavior cases: `transport.share-sync-finalization-wire`,
`transport.share-sync-finalization-rejections`,
`transport.share-control-finalization-wire`,
`transport.share-control-finalization-rejections`.
Expected **81 portable / 91 Linux GSS** full CTests.
ROADMAP, architecture, coding/testing standards
are updated in this SAME implementation commit.

**PASS:** implementation `c14f47bcd63faaa37761b87ffab06388c1e1bfe7`,
[Actions 38712823857](https://github.com/k1moradi/RDP-server/actions/runs/38712823857):
Linux/GCC **91/91**, macOS/Clang and Windows/MSVC
**81/81** full CTests in Debug AND Release.
All four Sync/Control finalization behavior suites,
project documentation-policy, installed SDK
consumer and ZIP/SHA256 artifacts PASS.
Prerelease publishing SKIPPED because no
release tag was created.
**NOT RUN:** owner-local new-head build/CTest,
isolated controlled GSS/Kerberos keytab and tickets,
full CredSSP TLS pubKeyAuth, OS session policy,
licensed share activation, external RDP client,
input, graphics or desktop.
Reuse owner's ONE build directory:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** owner-local single-build-root
regressions, followed by explicitly authorized
genuine Kerberos/TLS and independent OS account/
session policy before ANY live finalization dispatch.

## Verified default GSS fail-closed v6 error queue contract (2026-10-15)

**Baseline exact main:** `ebc794738552f5411ebe4d2222000f8ae94183f2`,
[CI 38708915869](https://github.com/k1moradi/RDP-server/actions/runs/38708915869)
PASS, Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
**77/77** CTests BOTH Debug/Release, installed SDK
consumer, ZIP/SHA256 packages and docs policy.
Owner reports prior **77/77** local PASS. This is
NOT evidence for the new security functionality.

**Scope:** `src/server/security/gssapi_spnego_acceptor.{h,cpp}`
now distinguishes actual configured MIT GSS provider/
policy rejection from local syntax, configuration,
transport provenance, TLS fingerprint and allocation
errors. A rejected provider state still securely tears
down GSS credentials, context, verified principal and
pinned certificate. Only an initial/continuing
version-6 TLS-derived, syntactically valid nego-only
TSRequest on the same selected certificate can queue
the original canonical `STATUS_LOGON_FAILURE`
`TSRequest.errorCode` using the same one-pending
`TsRequestTlsReplyWriter`. New
`SpnegoStatus::FailureQueued` signifies one
15-byte DER record QUEUED for caller-managed TLS
send/release, not successful GSS, permitted OS
admission or a completed TLS record. All other
failures remain silent terminal rejection.

**Tests:** one new default Linux-only CTest
`security.gssapi-failure-reply-denials` within
existing `tests/test_owned_preauth_session.cpp`;
one more `security.gssapi-real-kerberos-tls-failure`
is registered ONLY with the already optional
`RDP_SERVER_TEST_REAL_KERBEROS=ON` and explicit
owner-controlled TERMSRV service, FILE:/ keytab
and FILE:/ client cache. Its provider rejection
and exact 15-byte TLS reply are NOT RUN in default
CI or without real credentials. Same-commit
ROADMAP, architecture, coding and test standards.
Expected default **77 portable / 87 Linux GSS** CTests.

**PASS:** implementation `b4c9f8eff73e701130cc8b92b6c1fda50aedcf11`,
[Actions 38710937644](https://github.com/k1moradi/RDP-server/actions/runs/38710937644)
Linux/GCC **87/87**, macOS/Clang and Windows/MSVC
**77/77** full CTests in Debug AND Release, including
new Linux GSS missing-keytab/manual-DER negative
reply gates. Documentation-policy, staged installed
SDK consumer, all three ZIP/SHA256 artifact packages
PASS. Publishing SKIPPED: no tagged prerelease.
**NOT RUN:** owner-local new compile/CTest,
configured real GSS provider rejection/errorCode
success-path proof, genuine Kerberos service
keytab/ticket, Microsoft client, OS authorization,
complete CredSSP combined-last-token acceptance,
MCS or desktop.
Use owner's ONE persistent `~/rdp-server/build`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** owner-local single-root CTest, then
separately authorized isolated MIT Kerberos keytab,
client cache and opt-in provider-failure/positive
TLS proof before independently authorized OS
identity and session gate.

## Verified T.128 Share Data Header syntax gate (2026-10-15)

**Prior verified baseline:** `8aea09a101fe1394c6c60145fef42fa002514315`,
[Actions 38705731398](https://github.com/k1moradi/RDP-server/actions/runs/38705731398)
PASS, with Linux/GCC **84/84** and macOS/Clang,
Windows/MSVC **75/75** full Debug/Release CTests,
installed SDK consumer/package and documentation policy.
Owner reports **75/75 local** on that prior head. This
is not evidence for the new Share Data code.

**Implementation:** extend the original first-party
`src/server/transport/mcs_channel_connection.{h,cpp}`
with a bounded, zero-copy Share Data Header parser that
REUSES the exact existing Share Control Header decoder.
MS-RDPBCGR 2.2.8.1.1.1.2's shareID, ignored pad1,
streamID, uncompressedLength, pduType2, compressedType
and compressedLength fields are decoded as syntax only;
24 normative type2 values; the stream 0/Synchronize
compatibility exception; uninitialized Client Font List
uncompressedLength never treated as a frame bound.
Compressed frames remain explicitly unsupported, with
no borrowed application payload; no TLS, MCS ownership,
decompression, graphics, authentication or OS admission.
Two CTests `transport.share-data-header-wire` and
`transport.share-data-header-rejections` are added to
the existing `test_owned_mcs_connect_initial.cpp` binary
and `tests/CMakeLists.txt` registry. Expected totals:
**77** portable / **86** Linux GSS-enabled. In the SAME
implementation commit, update the sole living ROADMAP,
architecture, coding/testing standards and validation ledger.

**PASS:** implementation `9bc9e041419b4a932dc988a51f1f3e920ac82ba3`,
[Actions 38708579033](https://github.com/k1moradi/RDP-server/actions/runs/38708579033)
Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
**77/77** CTests in BOTH Debug and Release. Both new
Share Data wire/negative behavior tests passed everywhere;
staged installed SDK consumer, packages and docs-policy
PASS. Prerelease publish SKIPPED (no release tag).
**NOT RUN:** owner's new local rebuild/CTest, sanitizer,
actual GSS/keytab/tickets, TLS live Share Data dispatch,
optional security headers, OS-authorized licensed/activated
session, nested input, graphics, clipboard or actual
Microsoft RDP client acceptance.
Local owner's one reused build root:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`;
`cmake --build build --config Debug --parallel 2`;
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** owner-local validation on the single build root,
then controlled genuine Kerberos/TLS and independent OS
session authorization before live Share Data dispatch.

## Verified offline T.128 Share Control Header decoding (2026-10-15)

**Prior verified base:** main
`424a35a8ceeb2a32fc553f334cfdcdfeebf5e2a6`,
[CI 38701851845](https://github.com/k1moradi/RDP-server/actions/runs/38701851845)
completed successfully with Linux/GCC **82/82**,
macOS/Clang and Windows/MSVC **73/73** CTests per
Debug/Release, SDK consumers, ZIP artifacts and policy.
Owner reports local **73/73** on that same earlier head.
Those tests do not prove the new parser.

**New scope:** existing portable
`src/server/transport/mcs_channel_connection.{h,cpp}`
adds `parseRdpShareControlHeader` to accept a previously
isolated complete six-byte little-endian T.128
TS_SHARECONTROLHEADER with declared-size equality, version
1 and known PDU type. `totalLength=0x8000` returns
`FlowPduIgnored` without a payload view, as MS-RDPBCGR
2.2.8.1.1.1.1 requires. The result's borrowed body
and source ID are *syntax*, not a session capability,
security-header classifier or OS admission.
Two tests in the existing
`tests/test_owned_mcs_connect_initial.cpp` executable:
`transport.share-control-header-wire` and
`transport.share-control-header-rejections`. Single
`tests/CMakeLists.txt` registry; expected **75**
portable / **84** Linux GSS-enabled CTests.
Same atomic implementation commit updates the
single living ROADMAP TODO and architecture, coding,
testing and validation docs.

**PASS:** implementation `77fd1be92c0f4dcff60962d645a39af9b23c96de`,
[Actions 38705203733](https://github.com/k1moradi/RDP-server/actions/runs/38705203733):
Linux/GCC **84/84**, macOS/Clang and Windows/MSVC
**75/75** CTests in each Debug and Release, including both
new Share Control test groups. Documentation policy,
staged SDK downstream consumer and ZIP/SHA256 packages PASS.
Prerelease publication SKIPPED because no tag was created.
**NOT RUN:** owner's new local build/CTest, sanitizers,
actual TLS security-header stripping, genuine GSS,
OS admission, nested Share Data, licensing, external
clients, desktop and clipboard.
Use the single `~/rdp-server/build/`:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** exact-commit cross-platform CI; later
real authenticated channel/security context and
independent OS session authority before dispatch.

## Pending T.125 server Send Data Indication offline encoder (2026-10-15)

**Previous exact-head baseline:** `cd50346be4df281b7fc207c5126072555a3eba63`,
[Actions 38696744690](https://github.com/k1moradi/RDP-server/actions/runs/38696744690)
PASS: Linux/GCC **80/80**, macOS/Clang and Windows/MSVC
**71/71** Debug and Release CTests, SDK packages/consumer
and documentation policy. The owner additionally reports
local **71/71** PASS at the previous main. These do NOT
constitute evidence for this increment.

**Implementation:** the existing
`src/server/transport/mcs_channel_connection.{h,cpp}`
now emits bounded T.125 server SendDataIndication
(choice 26, 0x68) into a caller-owned `std::span`,
with no heap allocation or TLS I/O. Validates assigned
UserId, channel nonzero, 2-bit priority/segmentation,
7/14-bit PER length up to 16383 and full output capacity
before changing any output. `std::memmove` handles
input/output overlap before header stores. The existing
`tests/test_owned_mcs_connect_initial.cpp` and
`tests/CMakeLists.txt` add
`transport.mcs-send-indication-wire` and
`transport.mcs-send-indication-rejections` to the
single registry. Expected portable **73** CTests,
Linux GSSAPI **82**. Architecture, roadmap, coding
and testing standards updated in SAME code commit.

**PASS:** exact implementation
`8c9fabeb02fce7ede13abfb42631d3b7f35a4fc1`,
[GitHub Actions 38701524465](https://github.com/k1moradi/RDP-server/actions/runs/38701524465):
Linux/GCC **82/82**, macOS/Clang and Windows/MSVC
**73/73** CTests in EACH Debug and Release; new
`transport.mcs-send-indication-wire` and
`transport.mcs-send-indication-rejections` PASS
everywhere. Documentation-policy, staged installed SDK
consumer execution and all three ZIP/SHA256 artifacts
PASS. Prerelease publication SKIPPED (no release tag).
**NOT RUN:** owner's new local CTest, sanitizers,
live TLS output, authorized GSS/Kerberos and OS
admission, joined MCS state, real desktop or
Microsoft client.
Owner's one build root commands:
`cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next:** exact-head CTests and SDK consumer/policy CI;
then verified true GSS/TLS + separate OS identity gate
before any live application data emission.

## Pending T.125 client Send Data Request syntax intake (2026-10-14)

**Prior exact baseline:** main
`05f2708cc8b326983c406b643bee1d47e5e166d0` passed
[CI run 38685374294](https://github.com/k1moradi/RDP-server/actions/runs/38685374294);
the owner reports **69/69** local CTests PASS for the earlier
code. These results do NOT verify this increment.

**New implementation:** existing
`src/server/transport/mcs_channel_connection.{h,cpp}`
parses T.125 SendDataRequest choice 25, validates complete
TPKT/X.224 and PER fields, and provides a read-only borrowed
userData view with no allocation. A valid syntactic packet does
not establish a joined channel, decrypted provenance, user
identity, OS desktop access, or any session admission.
Two behavior cases are added to the existing
`tests/test_owned_mcs_connect_initial.cpp` and
`tests/CMakeLists.txt`: `transport.mcs-send-data-wire` and
`transport.mcs-send-data-rejections`, with expected 71
portable CTests (80 when the Linux GSS cases are enabled).
The roadmap, architecture, coding and testing standards
are updated in the same commit.

**First CI result FAIL:** implementation
`c1f9e5458132c40b149e8ec5f0e6083addff8715`,
[Actions 38696231297](https://github.com/k1moradi/RDP-server/actions/runs/38696231297):
Linux/GCC Debug **79/80**, macOS/Clang Debug **70/71**,
both failed ONLY `transport.mcs-send-data-wire`, while
the new negative test passed. First failure:
`tests/test_owned_mcs_connect_initial.cpp:760` assertion
on `result.request.userData[0]`. Root cause is a test-only
lifetime violation: `parseMcsChannelRequest(frameDomainPdu(mcs))`
returns a borrowed span into a temporary vector that dies
at the end of the same statement. Fix test to hold the
complete TPKT in a stack-scoped `const auto frame` until
all view assertions are complete; assert the span's exact
offset as a regression against future accidental copies.
No production parser change. Windows results for that first failed attempt were not
finalized when the correction was authored.

**Verified correction:** `72af29fddc2424fcc7f4edbd579e2b313ef25f48`,
[Actions 38696503496](https://github.com/k1moradi/RDP-server/actions/runs/38696503496):
Linux/GCC **80/80** CTests; macOS/Clang and Windows/MSVC
**71/71** CTests, in BOTH Debug and Release. Both
`transport.mcs-send-data-wire` and
`transport.mcs-send-data-rejections` PASS across all
three operating systems. Installed SDK consumer, ZIP/SHA256
package upload and project documentation-policy PASS;
prerelease publishing SKIPPED (no version tag).
The only correction since initial implementation is to
keep the test input packet alive through borrowed-view
inspection; the production decoder is unchanged.

**NOT RUN:** owner-local corrected compile and CTest
(the owner machine is not mounted), new exact-head platform
CI, SDK package/consumer tests, ASan/UBSan, real Kerberos,
Microsoft RDP clients, channel authorization, licensing,
graphics and desktop. To validate on the one reused owner
build root: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`.
**Next gate:** exact-head full CI and owner-local regressions,
then independently authorized post-auth MCS lifecycle.

## Verified offline MCS Disconnect Provider Ultimatum (2026-10-14)

**Prior main and owner-local PASS:** `36926462d34726f355279367a2ba2f27e93d2095`.
The supplied Linux Debug command in the one reused
`~/rdp-server/build/` compiled successfully and CTest
reported **67/67 PASS**, including the CredSSP single-byte
tag rejection case. [GitHub Actions 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
also succeeded for that baseline. These results do
not establish acceptance of the NEW increment.

**Implementation:** `src/server/transport/mcs_channel_connection.{h,cpp}`
gains a typed, fixed-array, zero-allocation nine-byte
MCS Disconnect Provider Ultimatum encoder; incoming
requests recognize properly framed disconnects without
interpreting peer reasons. No authentication/authorization,
socket/SSL output, new binary, independent controller or
live session state is added. Two portable regression
groups in the existing `tests/test_owned_mcs_connect_initial.cpp`
are registered in `tests/CMakeLists.txt`: expected standard
test total **69**, up from 67. Same implementation commit
updates the one ROADMAP TODO and canonical architecture,
coding/testing and validation standards.

**PASS:** exact implementation
`ed4b0c0a05981f573bc6b8369893f33d1e71549d`,
[Actions 38685111404](https://github.com/k1moradi/RDP-server/actions/runs/38685111404):
Linux/GCC **78/78** CTests, macOS/Clang and Windows/MSVC
**69/69** CTests, EACH Debug and Release; both new disconnect
cases pass everywhere. Documentation-policy, installed SDK
consumer and ZIP/SHA-256 package uploads also PASS. The
prerelease publication job was SKIPPED without a release tag.
**NOT RUN:** owner's new local compile/CTest, sanitizers,
live Microsoft RDP client, actual encrypted TLS disconnect
and socket close, genuine Kerberos, independent OS
account/session authorization or desktop.
Use `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build build --config Debug --parallel 2`,
`ctest --test-dir build -C Debug --output-on-failure`
within the owner's existing checkout/build directory.
**Next gate:** full exact-head CI/owner-local tests, then
authorized TLS/session lifecycle and GSS/OS admission.

## Verified single-byte CredSSP DER fail-fast intake (2026-10-14)

**Prior verified main:** `1cce799dc1aa7a55e3cb343dd09823052a1c23a6`,
[Actions 38683456755](https://github.com/k1moradi/RDP-server/actions/runs/38683456755)
completed successfully. This incremental change uses that head as
its parent; the new commit SHA is available in GitHub history
after the atomic push.

**Change:** `src/server/security/credssp_tsrequest.cpp` now
checks the first DER tag *before* returning NeedMore at the end
of an input event. `tests/test_owned_credssp_tsrequest.cpp`
reuses `security.credssp-stream-rejections` to test all 255
invalid single-byte initial tags, exact consumed count,
fail-closed replay, and the valid first-tag control.
Affected canonical roadmap, coding and testing docs are updated
in this same implementation commit.

**PASS:** implementation
`36926462d34726f355279367a2ba2f27e93d2095`,
[Actions 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release,
SDK, package, documentation-policy and all protocol tests.
Owner-local `~/rdp-server/build/` Linux Debug build and
**67/67** CTest PASS from the supplied full command/output.
**NOT RUN:** sanitizers, positive Kerberos, Microsoft
external client or desktop admission. The specified validation commands are
`cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2`,
and `ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure`.
**Next gate:** pursue controlled GSS failure/identity handling
without granting OS session access. Verified offline CI does
not authorize an MCS session or desktop.

## Verified offline finalization transcript cross-check (2026-10-15)

**Baseline main:** `7777cc92a35cb94193eea4980285dd8153c49648`.
**Previous verified implementation:** `d83549d489be2b8e49855429693d2c5d4b1a0a71`,
[Actions 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636)
PASS: Linux/GCC 99/99, macOS/Clang and Windows/MSVC
89/89 full CTests, Debug/Release; docs-policy and SDK
consumer/install/archive gates passed. The owner reports
89 local CTests PASS on previous code; no log or local SHA
was attached. This evidence does NOT validate new code.

The new zero-allocation pure `correlateRdpFinalizationExchange`
compares six borrowed, complete finalization PDUs using
existing strict Share Data decoders and native server encoders;
no additional controller, socket handler, credential approval
or OS/session admission. Two new behavior-named suites share
the existing native test binary, expected 91 portable / 101
Linux GSS. Code, native tests, canonical roadmap, architecture,
coding/testing standards and this validation entry are staged
together in one Git tree; the final new SHA is recorded in
Git history after the atomic commit.

**NOT RUN at authoring:** CI on the new SHA, owner-local
build (the prescribed checkout is not mounted here),
ASan/UBSan, real Kerberos/pubKeyAuth, authenticated MCS
source, independent OS user rights, live ordered encrypted
finalization, licensed share, Microsoft client or desktop.
**First next gate:** exact-head cross-platform Debug/Release,
SDK and documentation-policy CI. Owner's single-root run:

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

Then obtain explicitly authorized isolated real GSS/TLS
and independent OS authorization before any live finalization.

**PASS:** exact implementation
`27996f24e5fbb497c0bee37756d34551d1a47e47`,
[Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873):
Linux/GCC **101/101**, macOS/Clang and Windows/MSVC
**91/91** CTests in BOTH Debug and Release, including
`transport.share-finalization-exchange-correlation` and
`transport.share-finalization-exchange-denials` on each OS.
Documentation-policy, installed SDK downstream consumer,
ZIP/SHA256 archive/checksum uploads PASS. Untagged release
job SKIPPED. The earlier "NOT RUN at authoring" status
correctly describes the initial pre-CI checkpoint.
**NOT RUN:** owner-local current-head build/CTest, real
Kerberos/TLS public-key proof and tickets, independently
authorized OS admission, actual ordered MCS/TLS
finalization, licensing, Windows/macOS client or desktop.
**Next:** owner-local single-root Debug CTest, then
separately authorized GSS/TLS and OS-admission gates.

## Pending TLS certificate continuity at the MCS intake boundary (2026-10-15)

**Prior known main:** `6d5148a615e22d82d263437be8547a131cfe036e`.
Previous code implementation
`27996f24e5fbb497c0bee37756d34551d1a47e47`
passed [Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873):
Linux/GCC 101/101 and macOS/Clang, Windows/MSVC 91/91
full CTests each in Debug/Release, docs-policy, staged
SDK consumer and all three ZIP/SHA256 uploads. Owner
reports 91/91 local PASS on previous code, not proof
of these new edits.

**New offline/security transport increment:** reuse the
existing first-party CredSSP SHA-256 selected-certificate
fingerprint helper from the sole `PreauthConnectionStream`;
pin the completed server's X.509 on the valid X.224->TLS
transition, and refuse a changed selected certificate on
the SAME SSL object before each direct MCS `SSL_read_ex`
event. The fixed 32-byte pin is wiped upon close.
The borrowed OpenSSL/BIO lifetime remains caller-owned;
no standalone listener, GSS principal, Kerberos tickets,
OS account authority or connected desktop is added.
Two new behavior CTests in the same preauth fixture
test continuity and in-place substituted certificate
before any read or after a partial 416-byte TLS frame.
Expected **93 portable / 103 Linux GSS** tests.
The code/test and relevant canonical standards/TODO
are staged in the same implementation commit.

**NOT RUN at authoring:** exact new-head Linux/macOS/Windows
Debug/Release CTests, SDK/policy, owner-local compilation,
positive externally provisioned Kerberos/TLS public-key
proof, independent OS admission, external Microsoft RDP
client, authenticated MCS or desktop.
**Next:** cross-platform exact-head CI and owner-local
one reused build-root, then a separately authorized
genuine GSS/TLS+OS authorization exercise. Owner command:

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

## Corrected certificate-continuity test visibility (2026-10-15; CI pending)

**First FAIL:** implementation
`5b1c9790b772923a4a4437d4f4bef4ec7f404d88`,
[Actions 38738637457](https://github.com/k1moradi/RDP-server/actions/runs/38738637457).
Debug compilation FAILED on Linux/GCC, macOS/Clang and
Windows/MSVC, before any CTests/SDK gate. The first error
was an ambiguous call to
`substituteCredSspReplyCertificate` in the existing
`tests/test_owned_preauth_session.cpp` TLS-reply test.
The newly inserted declaration was local to an unnamed
namespace while the established helper definition was
at file scope. This was a test-only scope error, not
evidence of a production TLS/transport issue.

**Correction:** relocate only the new continuity/substitution
test bodies below the existing file-scope helper, remove
the competing forward declaration, and retain every
original behavior and negative assertion. The unchanged
production change pins and wipes the selected TLS X.509
fingerprint before MCS intake; expected 93 portable /
103 Linux GSS CTests. New exact-head Debug/Release/SDK
CI and owner-local builds remain **NOT RUN at authoring**.
**Next:** full cross-platform CI then owner-local single
`~/rdp-server/build/` followed by externally authorized
real Kerberos/TLS and independent OS session evidence.

**PASS after test-only correction:** exact corrected
`850a6e9b7f2bc0a25854d31e02d0ed25332989b3`,
[Actions 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048).
Linux/GCC **103/103**, macOS/Clang and Windows/MSVC
**93/93** CTests each in Debug and Release;
`transport.mcs-tls-selected-certificate-continuity`
and `transport.mcs-tls-selected-certificate-substitution`
PASS on every platform. All Debug/Release compiles, SDK
installed downstream consumer, ZIP/SHA256 uploads
and project documentation-policy PASS.
No production change was needed after the initial
test helper visibility failure. Untagged prerelease
job SKIPPED; no RDP service launched or installed.
**NOT RUN:** owner-local corrected compile/CTest,
externally authorized real GSS/Kerberos/TLS binding,
independent OS session authorization, full authenticated
MCS, Windows/macOS RDP clients or desktop.
**Next:** owner's reused `~/rdp-server/build/`
full CTest, then genuine isolated positive Kerberos
and separately approved OS admission before network
session or application-level RDP responses.

## Verified offline General Capability extraction (2026-10-15)

**Previous main:** `911e4d3a4459f070588aadc6380d54cc2efda7f5`.
**Previous implementation CI PASS:**
`850a6e9b7f2bc0a25854d31e02d0ed25332989b3`,
[Actions 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048):
Linux/GCC **103/103**, macOS/Clang and Windows/MSVC
**93/93** CTests in BOTH Debug and Release,
documentation-policy, installed downstream SDK consumer,
ZIP/SHA256 archives and upload PASS. Owner reports
**93/93 local PASS** on the preceding code, without
a full log and exact local checkout SHA.

**New code:** one zero-heap `parseRdpGeneralCapabilityFromActive`
helper in existing MCS/Share source, after the shared
outer exact-length Active PDU/envelope validator.
Recognize MS-RDPBCGR 2.2.7.1.1 type 1, exactly 24 bytes;
require 0x0200 protocol version, Boolean 0/1 support
indicators, exactly one General set and no truncated
or coalesced extra Share Control PDU. Ignore normative
pad, preserve unknown raw extraFlags and sibling
capabilities without accepting them as negotiated.
Two new behavior-named portable CTests reuse the existing
MCS executable; expected **95 portable / 105 Linux GSS**.
Source/test/roadmap/architecture/coding/testing/validation
are staged in ONE implementation Git tree.

**NOT RUN at authoring:** exact new-head Linux/macOS/Windows
Debug/Release/SDK/docs-policy, owner's one-root compilation,
genuine isolated positive Kerberos/TLS protected binding,
independent OS authorization, licensed live capability
exchange, client H.264/graphics, Microsoft client or desktop.
**Next:** exact-head cross-platform CI, owner local full
CTest, then separately authorized real GSS/TLS/OS admission.
Run only in the existing owner's checkout/root:

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

**PASS:** exact implementation
`3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
[GitHub Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505):
Linux/GCC **105/105** and macOS/Clang, Windows/MSVC
**95/95** full CTests, both Debug and Release. New tests
`transport.share-general-capability-wire` and
`transport.share-general-capability-rejections` PASS
across all three operating systems. Documentation-policy,
installed SDK consumer, packaging, ZIP and SHA256 artifacts
PASS. Prerelease SKIPPED because no protocol version tag.
The earlier "NOT RUN at authoring" note describes the
pre-CI checkpoint and not the eventual cross-platform result.
**NOT RUN:** owner-local updated build/CTest, opt-in real
Kerberos/TLS binding, independent OS account authorization,
actual negotiated capabilities/licensing, Windows/macOS
RDP client, H.264 graphics or desktop. **Next:** owner's
single-root full CTest, separately authorized real GSS/TLS
and OS admission before sending any live RDP application data.

## Verified Bitmap Capability Set extraction (2026-10-15)

**Previous main:** `39480cb88de6b80277b9c2621ca8ddb41651dfee`.
**Previous verified code:** `3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
[Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505)
PASS: Linux/GCC **105/105**, macOS/Clang and
Windows/MSVC **95/95** full CTests in EACH Debug and
Release; installed SDK consumer, ZIP/SHA256 artifacts
and documentation policy. Owner reports **95/95**
local previous-code PASS, without matching full
terminal log or local exact SHA.

**New code:** a pure zero-allocation Bitmap Capability
decoder for one complete Demand/Confirm Active PDU
in the existing `mcs_channel_connection` first-party
module. Reuses the sole exact-length Active parser,
validates a single 28-byte Bitmap set, mandatory
compression/multiple-rectangle support, nonzero
dimensions and desktop resize Boolean. Legacy receive
depth fields, padding and highColorFlags ignored,
unknown drawing bits preserved, unknown siblings
opaque. No session/cache, graphics dispatch, framebuffer
allocation or authenticated desktop authority.
Two new behavior-named CTests reuse the MCS test
executable and canonical CTest registry; expected
**97 portable / 107 Linux GSS**. Code, tests and
canonical roadmap/architecture/coding/testing/validation
are included in one implementation tree.

**NOT RUN at authoring:** exact new-head CI, owner-local
single-root build/CTest, real positive CredSSP/Kerberos
public-key binding over TLS, independent OS authorization,
licensed activation, H.264 graphics, Microsoft client
or desktop. **Next:** exact-head cross-platform Debug
and Release CI, then owner-local single existing root
and isolated authorized Kerberos/TLS+OS identity.

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

**PASS:** exact implementation
`89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
[GitHub Actions 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146):
Linux/GCC **107/107**, macOS/Clang and Windows/MSVC
**97/97** CTests EACH in Debug and Release.
`transport.share-bitmap-capability-wire` and
`transport.share-bitmap-capability-rejections`
PASSED in all six runs; project policy, installed SDK
consumer, ZIP/SHA256 packaging and uploaded artifacts
PASSED. Prerelease publication SKIPPED (no version tag).
The earlier NOT RUN-at-authoring checkpoint was
accurate when code was first committed, but exact-code
hosted cross-platform CI is now verified.
**NOT RUN:** owner-local current code compile/CTest,
genuine Kerberos/TLS pubKeyAuth and external tickets,
independent OS user/session approval, licensed/negotiated
bitmap or H.264 graphics, external Microsoft RDP client,
interactive desktop or clipboard.
**Next gate:** owner-local single existing
`~/rdp-server/build/` full CTest, then independently
approved isolated GSS/TLS and OS-admission evidence
before attaching any live MCS session or graphics.

## Verified partial Gate A connected TCP TLS/MCS provenance (2026-10-15)

**Baseline main:** `00c70a24568098b34bcd1485e8f82fd63d0bab9a`,
which explicitly prioritizes the first real authenticated
Microsoft-client session in `docs/ROADMAP.md`.
**Previous implementation PASS:** `89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
[CI 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146):
Linux/GCC **107/107**, macOS/Clang/Windows/MSVC
**97/97** full CTests in EACH Debug and Release,
SDK install/consumer, ZIP/SHA256 and documentation
policy PASS. Owner reports **97/97** local tests
on preceding code; full log/local SHA unavailable.

**Change:** keep one sole `PreauthTcpAdapter` as the
TCP/SSL/MCS handshake intake owner. Once the 19-byte
X.224 reply is sent, `attachTlsTransport` binds ONE
server `SSL*` to this very adapter's socket BIO.
`onAttachedTlsIoReady()` and
`onAttachedMcsIoReady()` do not permit a caller-
supplied alternative TLS handle and recheck both
BIO pointer and its borrowed `TcpNonblockingIo`
before TLS handshake or MCS read. Duplicate/wrong
SSL/BIO retargeting/old-stage events terminate.
The original actual loopback socket test now uses
these strict readiness callbacks; two extra
behavior CTests deny out-of-order/changed provenance.
Expected **99 portable / 109 Linux GSS** full CTests.
Code, tests, living P0 Gate A TODO, architecture,
coding/testing standards and validation are all
present in one implementation Git tree.

**NOT RUN at authoring:** exact-head all-platform CI,
owner-local `~/rdp-server/build/` CTest,
real opted-in isolated Kerberos/TLS pubKeyAuth,
independent OS account/session admission, live
Microsoft client, licensed MCS, H.264/X11 desktop.
**Next:** exact commit CI then true authorized
GSS/TLS and OS admission before a live MCS reply.
No server executable, listening daemon, full
session state machine or graphics is claimed.

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

**PASS:** exact implementation
`45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
[GitHub Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803).
Linux/GCC **109/109** and macOS/Clang, Windows/MSVC
**99/99** CTests EACH in Debug and Release.
`transport.tcp-attached-tls-ownership-denials`,
`transport.tcp-attached-mcs-order-denials` and the
existing true socket `transport.tcp-native-loopback-tls`
PASSED on all three OSes; full project policy,
installed SDK consumer, ZIP/SHA256 and uploaded
artifacts PASS. Prerelease SKIPPED without a version tag.
The previous NOT RUN at authoring is historic
pre-CI status only; new-head cross-platform CI is
now verified. **NOT RUN:** owner-local updated
one-root build, genuinely provisioned Kerberos
and successful TLS pubKeyAuth, independent OS
session rights, licensed MCS activation,
interactive Microsoft client or H.264/X11 desktop.
**Next:** run the owner's exact-head single-root full
CTest, then explicitly authorized opt-in GSS/TLS and
OS admission before any live authenticated protocol
session or desktop.

## Pending R1 bounded TCP and BIO I/O (2026-10-15)

**Parent SHA:** `7e9b2881f66cea2b0354242b4e7ae39cb89170bc`,
docs-only ten-road parallel development policy.
**Previous tested production implementation:**
`45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
[Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803)
PASS Linux/GCC **109/109** and macOS/Clang,
Windows/MSVC **99/99** full registered CTests
in BOTH Debug and Release, SDK consumer/staged
install, ZIP/SHA256 artifact uploads, policy.
The owner reports **99/99 local PASS** of previous
code without exact local SHA/terminal transcript.

**New R1 I/O contribution:** cap all 4 production
borrowed TCP BIO/native recv/send callbacks to
18 KiB per invocation (`kMaximumTcpIoChunkBytes`).
Retain single existing socket/SSL/connection
owner, short I/O and would-block semantics,
no allocation and no narrowing of untrusted
oversize `size_t` input to Winsock `int`.
Two dedicated behavioral CTests execute actual
OpenSSL BIO read/write callbacks and real native
connected loopback send/receive with oversized
caller spans, strict short byte accounting,
progress, retry and misreport denial. Expected
**101 portable / 111 Linux GSS** CTests.
Production code, tests, Gate A/R1 living roadmap,
architecture and coding/testing lessons are staged
in one implementation commit. New-head compiled
CI and owner's reused checkout build: **NOT RUN
at authoring**; exact implementation SHA recorded
in follow-up after it is created.

**NOT RUN:** owner-local one-root current-head CTest,
owner's exact MSYS2 CLANG64 Clang23/macOS27 runs,
positive real opt-in Kerberos/TLS protected binding,
independently approved OS session, licensed live
RDP protocol, Microsoft client or interactive
desktop/graphics. **Next:** hosted full matrix
on exact implementation SHA, owner reports
one-root full CTest in his authorized environment,
then R2/R3 authenticated session integration.

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

**Exact implementation CI PASS:** 
`8ce08611d5d7b093c9d69f4b7eee5d23cd096359`,
[GitHub Actions 38752789202](https://github.com/k1moradi/RDP-server/actions/runs/38752789202).
Linux/GCC **111/111** full registered CTests
and macOS/Clang, Windows/MSVC **101/101** each in
BOTH Debug and Release. `transport.tcp-bio-chunk-bounds`
and `transport.tcp-native-chunk-bounds` PASS all OS
and both configurations. SDK staged install, downstream
consumer CTest, ZIP and SHA256 artifacts/uploads,
and docs policy PASS. Untagged prerelease SKIPPED.
The prior NOT RUN at authoring was an accurate checkpoint
before this exact-SHA hosted CI. **NOT RUN:** owner's
current-head build/CTest in `~/rdp-server/build/`,
Windows MSYS2 CLANG64/Clang23 or macOS27 owner
platform acceptance, real opt-in Kerberos/CredSSP
public-key TLS binding, independent native OS account
authorization, live licensed Microsoft-client RDP
activation, graphics/desktop or human test.
**Next:** owner-local full one-root CTest and parallel
R2/R3 integration with real authorized identity/OS
admission before sending live MCS or desktop data.

## R6 Windows monitor layout (integrated on main; 2026-10-15)

**Base main observed:** `ff71184d92f0658c2b47cb0f14471c83dc3589fe`
after the mandatory main-only policy change (no conflicting Windows files).
**Prepared files:** `src/windows/windows_desktop_geometry.{h,cpp}`,
`tests/test_windows_desktop_geometry.cpp`, top-level `CMakeLists.txt`,
`tests/CMakeLists.txt`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md` and
this validation record. Three R6 helper increments are now integrated atomically into main;
that earlier staging evidence still applies only to the sparse fixture.
**Tests added, Windows-only registry:**
`windows.geometry-negative-origin-and-monitor-gaps`,
`windows.geometry-invalid-layout-rejections`, and
`windows.geometry-order-stable-reconfiguration`.
**PASS (sparse staging, 2026-10-15):** Linux Clang 17 and GCC 14.2
C++23 warning-clean compilation, all three direct behavior fixtures
per compiler (3/3 each), all three Clang ASan+UBSan cases (3/3),
and a sparse staging CTest registry (3/3). A fake Win32 API header
and stubbed `EnumDisplayMonitors`/`GetMonitorInfoW` additionally
compiled the native callback path and passed synthetic failure/retry
checks; this is NOT Windows SDK or CLANG64 validation.
The local commands were:
`clang++ -std=c++23 -Wall -Wextra -Wpedantic -Werror -UNDEBUG -Isrc src/windows/windows_desktop_geometry.cpp tests/test_windows_desktop_geometry.cpp -o build/test_windows_desktop_geometry`,
then invoke that executable with each of the three behavior selectors.
Repeat using `g++` with the same C++23 warnings; the Clang sanitizer
build uses `-fsanitize=address,undefined -fno-omit-frame-pointer -g`
and runs all three selectors. `ctest --test-dir build -C Debug
--output-on-failure` passed 3/3 **staging-only** manually registered
cases; it is not the actual project CMake CTest registry. All outputs
live under `~/rdp-server/build/`.
**NOT RUN:** registered Windows CTests, Windows native API compilation,
MSYS2 CLANG64/Clang 23, full repository CTests (repository cannot be
cloned in this environment), Windows/MSVC GitHub Actions for this patch,
owner Linux/X11/Windows/macOS tests, capture/latency benchmarks, real
RDP session, input or desktop acceptance. No desktop was accessed.
**NOT RUN:** complete checkout/full CTest due Git clone DNS;
seven dedicated Windows-conditional CTests are included in the commit.
**First missing boundary:** R2/R3 authorized interactive Windows session
lifecycle and R4 frame/cursor ownership contract.
**Next R6:** implement a bounded Win32 capture-frame adapter against the
agreed shared R4 frame view, gated by real admission and lifecycle policy.

## R6 Windows BGRA mapped frame view (integrated on main; 2026-10-15)

**Base remote `main`:** `ff71184d92f0658c2b47cb0f14471c83dc3589fe`.
**Implementation:** existing uncommitted R6 monitor-geometry patch plus
`src/windows/windows_bgra_frame.{h,cpp}`, its Windows-only target source,
and two new conditional tests reusing `test_windows_desktop_geometry.cpp`:
`windows.geometry-capture-bgra-stride-and-pixel-order` and
`windows.geometry-capture-bgra-invalid-frame-denials`.
Pure test fixtures exercise native BGRA component order, 12-byte padded
pitch for two-pixel rows, zero-copy borrowed ownership, tight pitch,
truncated backing, invalid dimensions, 512 MiB cap, arithmetic bounds,
and unchanged output on every rejection. No live image was captured.

**PASS (sparse staging on Linux, not the full repository):**
`clang++ -std=c++23 -Wall -Wextra -Wpedantic -Werror -UNDEBUG -Isrc
 src/windows/windows_desktop_geometry.cpp src/windows/windows_bgra_frame.cpp
 tests/test_windows_desktop_geometry.cpp -o build/windows-geometry-and-frame-clang`
and the same `g++` command/output `build/windows-geometry-and-frame-gcc`;
each executable ran all five selector behaviors: **5/5 PASS**.
Sparse staging CTest with five named selector cases was generated only
inside the sole `build/` root (not added as a repository registry):
`ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
`ctest --test-dir build -C Debug -R '^windows\.geometry-capture-'
 --output-on-failure` **2/2 PASS**.
The identical Clang fixture with
`-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g`
also completed **5/5 PASS**. Build outputs reused only
`~/rdp-server/build/` in a sparse local source mirror because public
GitHub clone/network access failed; this does not attest to full
repository build/CTest.
**NOT RUN:** native Win32 SDK/MSYS2 CLANG64 Clang23, Windows/MSVC,
the published full CTest registry, owner platform convergence,
live R2 admission, R3 session activation, R4 graphics, desktop and input.
**NOT RUN:** native Windows/full CMake and owner platform checks;
under the revised main-only policy R10 approval is not required.
**Next:** independently authorized DXGI acquisition owner plus
deterministic failure/release tests, after R2/R3/R4 contract agreement.

## R6 DXGI move/dirty rectangle bridge (integrated on main; 2026-10-15)

**Remote baseline:** `ff71184d92f0658c2b47cb0f14471c83dc3589fe`;
prior unpublished Windows monitor/BGRA patches are included atomically.
**Production increment:** `src/windows/windows_dxgi_damage.{h,cpp}`
converts bounded Windows DXGI move-destination and dirty rectangles into
the portable `Rectangle` view without a graphics scheduler or capture.
Move source/destination, exclusive edge, 32-bit coordinate, bounded count
and output-capacity checks happen before output mutation; pointer-only
frames yield zero rectangles. Shared Win32/COM types do not enter R4.
**New dedicated conditional CTests:**
`windows.capture-dxgi-move-before-dirty` and
`windows.capture-dxgi-metadata-rejections` reuse the same Windows-only
`test_windows_desktop_geometry` fixture and central test registry.

**PASS (sparse staging, NOT full repo):** in `~/rdp-server` with only the
R6 source subset and sole build root `~/rdp-server/build`, compile
`src/windows/windows_desktop_geometry.cpp`, `windows_bgra_frame.cpp`,
`windows_dxgi_damage.cpp` and `tests/test_windows_desktop_geometry.cpp`
with `-std=c++23 -Wall -Wextra -Wpedantic -Werror -UNDEBUG -Isrc` using
Clang 17 and GCC 14.2, then execute all seven behavior selectors:
**7/7 PASS** for each compiler. Clang with
`-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer` and
`ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1` also
completed **7/7 PASS**. Dedicated new behavior selectors **2/2 PASS**.
Sparse fixture-only `ctest --test-dir build -C Debug --output-on-failure`
was **7/7 PASS**, with `-R '^windows\.capture-dxgi-'` **2/2 PASS**.
The R6 fixture build does not run other repository tests and cannot
substitute for canonical CMake/CTest or native Windows SDK compilation.
**NOT RUN:** native MSYS2 CLANG64 Clang 23, MSVC, full repository CTest,
owner Linux/Windows/macOS exact-SHA gates, DXGI frame acquisition,
R2 admission, R3 activated input, R4 graphics, user desktop and perf.
**NOT RUN:** full repo CTest and native SDK (Git clone DNS blocked);
code is integrated by non-force GitHub expected-HEAD update without
any branch, live desktop access or input injection.
**Next:** native frame acquisition/release with deterministic cancellation
tests after R2/R3 session and R4 frame lifetime agreement.

## R3 MCS Connect-Initial first failing boundary (2026-10-15)

**Exact corrected implementation-SHA hosted CI:**
[`4ddf21920fbd10c0185f2d4f8d405c13600426a0`](https://github.com/k1moradi/RDP-server/commit/4ddf21920fbd10c0185f2d4f8d405c13600426a0),
[Actions 38856886973, attempt 2](https://github.com/k1moradi/RDP-server/actions/runs/38856886973)
**PASS** Linux/GCC **229/229**, macOS/Clang **212/212**,
Windows/MSVC **231/231** complete Debug and Release CTests.
The `transport.mcs-session-first-failure-boundaries` case,
security/protocol sanitizers, SDK consumers and docs-policy PASS.
First macOS Release attempt FAILED at unrelated R1
`transport.tcp-native-accept-batch-budget-handoff`
(`tests/test_owned_preauth_session.cpp:2494`), while the
new R3 test passed; same-SHA macOS rerun **212/212 PASS**
in both Debug and Release. Record this intermittent R1 case
(issue #11) rather than treating it as erased.
NOT RUN: owner's independent Linux/X11, Windows CLANG64/Clang23
and macOS27 exact-SHA CTests, genuine R2 OS-authorized session,
Microsoft client or desktop. Gate A/M2 NOT ACCEPTED.

**Compilation placement correction:** the first implementation SHA placed
new `McsSessionIntake` enumerators after the enum closing brace.
The immediate follow-up moves them inside the enum, without altering
existing numeric values or test expectations. First-SHA CI is not
passing evidence; only later successful exact-SHA CI can validate this.

**Production:** `McsSessionLifecycle::onConnectInitial` now returns
`InvalidEnvelope` for BER/TPKT syntax failure,
`InvalidDomainParameters` for a valid envelope with failed
T.125 domain merge, and `InvalidGccUserData` for a valid
MCS/domain negotiation with failed GCC Conference Create data.
The previous `McsSessionIntake` numeric order remains unchanged;
the new error-only statuses are appended. All failures and a
fully valid Microsoft envelope terminate the same noncopyable
R3 owner; a successful parse still yields
`ValidButNotAdmitted`, never session authorization or a reply.

**One new centrally registered CTest:**
`transport.mcs-session-first-failure-boundaries`, using the checked-in
Microsoft MS-RDPBCGR 4.1.3 416-byte packet and the real decoders.
It separately mutates MCS BER choice, T.125 protocol-version
domain merge and GCC t124Identifier, independently proves each
parser boundary, tests unchanged valid diagnostic classification,
revocation/stale reentry and 8193-byte oversize precedence.
**NOT RUN at authoring:** exact-commit full hosted CTests, owner
independent three-platform runs, real R2 GSS/CredSSP and independent
OS authorization, licensed Microsoft client or desktop.
R3 Gate A/M2 remains NOT ACCEPTED.

## R3 domain-PDU first failing boundary classification (2026-10-15)

**First exact-SHA CI:** implementation `1f82be913b2ad7ae09134d939542ec22b3656d63`,
[Actions 38864030223](https://github.com/k1moradi/RDP-server/actions/runs/38864030223).
The new `transport.mcs-session-domain-failure-boundaries` test passed
on Linux/macOS Debug. Full Debug failed only because an older R3
ordering assertion still expected `InvalidEnvelope` for a truncated
TPKT. The production parser returns `InvalidTransport`; the correction
updates only that test oracle to `InvalidDomainTransport` and records
the parser error explicitly. Production semantics are unchanged.

**Production:** the existing deny-only `McsSessionLifecycle::onDomainPdu`
now maps `McsChannelParseError::InvalidTransport`,
`InvalidDomainPdu` and `InvalidPerValue` to appended
`McsSessionIntake::InvalidDomainTransport`,
`InvalidDomainPdu` and `InvalidDomainPerValue`.
Existing enum values and successful/peer-disconnect behavior remain
unchanged. Oversized pre-admission packets still fail before parsing.
All outcomes synchronously close the sole R3 owner and revoke joins.

**Dedicated central CTest:**
`transport.mcs-session-domain-failure-boundaries` reuses the production
parser and checks valid Join denial, X.224 Data TPDU corruption,
AttachUser-with-trailing-bytes domain shape, out-of-range PER UserId,
oversize precedence, terminal reentry and legal peer Disconnect.
No second executable, parser, state owner, live TLS output or admission.
**NOT RUN at authoring:** exact-SHA hosted full CTest, owner independent
three-platform command, genuine R2 GSS/CredSSP + OS authorization,
Microsoft client or desktop. Gate A/M2 remains NOT ACCEPTED.

## R3 pre-admission oversized domain-PDU denial (2026-10-15)

**Exact-SHA hosted CI results (2026-10-15):**
[`7cb6ac36aa7b8355dd76cdc567f7e943acfe330b`](https://github.com/k1moradi/RDP-server/commit/7cb6ac36aa7b8355dd76cdc567f7e943acfe330b),
[Actions 38849842295, attempt 2](https://github.com/k1moradi/RDP-server/actions/runs/38849842295)
completed **SUCCESS**. Linux/GCC **219/219**, macOS/Clang
**203/203**, Windows/MSVC **221/221** full CTests in
Debug AND Release, including
`transport.mcs-session-unadmitted-domain-size-bounds`;
documentation policy, downstream SDK, packaging and R9's
clipboard sanitizer workflow job PASS.
**First attempt macOS FAIL:** unrelated R1
`transport.tcp-native-accept-batch-budget-handoff` assertion
at `tests/test_owned_preauth_session.cpp:2494`. The same
R3 commit's macOS retry (attempt 2) PASSED **203/203**
in Debug and Release. Record the intermittent R1 result;
do not convert that failure into R3 session approval.
**NOT RUN:** owner independently on Linux/X11, Windows
MSYS2 CLANG64/Clang23, macOS27; real R2 GSS/CredSSP
and independent OS authorization, Microsoft client or
desktop. R3 Gate A/M2 remains NOT ACCEPTED.


**Production:** `McsSessionLifecycle::onDomainPdu` uses the existing
`kMaximumInitialMcsTpktBytes` ceiling before first-party PER parser
invocation, closing and returning `OversizedEnvelope` on 8193+ byte
pre-admission packets. The limit applies while the R2 session
authorization capability is absent; it must NOT substitute for
negotiated post-auth MCS maxMCSPDUsize. No other ownership, TLS write,
admission path or wire encoder is changed.

**Dedicated central CTest:**
`transport.mcs-session-unadmitted-domain-size-bounds` in the existing
`test_owned_mcs_connect_initial` executable. It constructs valid
full-length 8191/8192/8193/16398-byte T.125 client SendDataRequest
PDUs, checks first-party parser acceptance independently of R3
denial, verifies over-limit priority and terminal membership cleanup,
and covers huge malformed input and legal peer Disconnect.
The CTest is registered in the canonical `tests/CMakeLists.txt`.
**NOT RUN at authoring:** production-linked exact-SHA Actions,
owner full Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27,
genuine R2 identity plus OS admission, licensed Microsoft-client
activation, or desktop. R3 Gate A/M2 remains NOT ACCEPTED.

## R3 authoritative first MCS intake-size denial (2026-10-15)

**Second test-only portability correction:** size-test initializer-list
values in `mcs-preauth-first-envelope-size-bound` now use `std::size_t`
throughout. Initial CI exposed mixed unsigned integer widths on Linux,
macOS and Windows. No production behavior or assertion is weakened.

**Test-only correction:** ensure every braced initializer-list element in
`mcs-session-first-envelope-size-bounds` has `std::size_t` type;
this avoids platform-width-dependent deduction errors under C++23.
No production behavior or expectation changed.

**Code:** `kMaximumInitialMcsTpktBytes` is defined once by
`mcs_connect_initial.h` and used unchanged (8192 bytes) by
R1's bounded first TLS MCS intake and the existing R3
`McsSessionLifecycle`. Direct R3 callers receive terminal
`McsSessionIntake::OversizedEnvelope` for larger spans
before BER/domain/GCC parsing. R1's PreauthSession diagnostic
now calls that owner for all sizes after its protocol-phase check,
rather than enforcing a duplicate local early-return. Truncated,
malformed, valid-but-not-admitted and oversize inputs all close R3.

**Dedicated registered CTests:**
`transport.mcs-session-first-envelope-size-bounds` checks
exact 8 KiB, over-limit buffers, malformed/truncated, valid
published Microsoft packet, terminal revocation and no joins.
`transport.mcs-preauth-first-envelope-size-bound` exercises
the actual R1-to-R3 callback, oversized/truncated closure,
late callback denial and unchanged syntax-only valid behavior.

**NOT RUN at authoring:** complete local repository build/CTest
(no full checkout in this runtime), exact implementation-SHA
GitHub Actions, owner independent Linux/X11, Windows MSYS2
CLANG64/Clang23 and macOS27 CTests, genuine R2 OS admission,
licensed activation or real Microsoft RDP client.
The local 8192-byte envelope ceiling is NOT the normative
1024/4096-byte GCC userData limit (MS-RDPBCGR 3.3.5.3.3).
Gate A/M2 remains NOT ACCEPTED; next is true R2 authorization
and ordered post-auth MCS Connect Response writer completion.

## R3 preauth terminal revocation of MCS lifecycle (2026-10-15)

**Exact-SHA hosted CI PASS:** [implementation 84d55d00f4c49772ddaad524d078ade198cf5f03](https://github.com/k1moradi/RDP-server/commit/84d55d00f4c49772ddaad524d078ade198cf5f03),
[Actions 38844029977](https://github.com/k1moradi/RDP-server/actions/runs/38844029977)
PASS Linux/GCC **192/192**, macOS/Clang **179/179** and
Windows/MSVC **183/183** full CTests in both Debug and Release.
`transport.mcs-preauth-terminal-revocation`, installed SDK consumer,
package artifacts and documentation-policy PASS. Prerelease skipped.
NOT RUN: owner's independent exact-SHA Linux/X11, Windows MSYS2
CLANG64/Clang23 and macOS27 tests; real R2 authenticated OS
session authorization, Microsoft-client activation and desktop.
R3 Gate A/M2 NOT ACCEPTED.


**Production:** `PreauthSession::onConnectionRequest` and
`PreauthSession::onTlsHandshake` now run `close()` on rejected or
out-of-order transitions, invalidating the embedded R3 session state
in the same event-loop callback. A read-only `mcsLifecyclePhase()`
status enables explicit revocation assertions and cannot grant authority.

**Dedicated central CTest:** `transport.mcs-preauth-terminal-revocation`
in the existing `test_owned_preauth_session` executable. Checks invalid
and repeated X.224, premature TLS, failure after valid X.224, explicit
cancel/late MCS callbacks, and valid synthetic diagnostic MCS that still
tears down R3; tests real production code with no live services.
**NOT RUN at authoring:** local full repository compile/CTest (full
checkout unavailable), new-SHA hosted CI, owner three-OS exact-SHA
one-liner and real R2 GSS/CredSSP/OS-authorized Microsoft RDP.
Gate A/M2 remains NOT ACCEPTED. Next is a genuine R2-issued
TLS-bound OS admission contract and ordered Connect Response through R1.

## R3 admitted-session boundary remains deny-only (2026-10-15)

**Exact implementation CI follow-up (2026-10-15):**
[`46ef1d2282c6c78b67e37b373be77c624bf529b7`](https://github.com/k1moradi/RDP-server/commit/46ef1d2282c6c78b67e37b373be77c624bf529b7),
[Actions 38798696991](https://github.com/k1moradi/RDP-server/actions/runs/38798696991).
Both new R3 MCS session CTests PASS on Linux/GCC and macOS/Clang
Debug and compile with the production tree. Full Debug results:
Linux **172/174 FAIL**, macOS **160/162 FAIL**; the two failing
tests are R1 `tcp-owned-readiness-dispatch` and
`tcp-owned-deadline-cancellation` (exact names in the CTest log),
with `test_owned_preauth_session.cpp` assertions at lines 1967/2130.
They were **already failing at the exact parent SHA**
`209ebb6fa714b4bba61478539976719506b9b96d`,
[Actions 38798562218](https://github.com/k1moradi/RDP-server/actions/runs/38798562218).
[R1 regression #11](https://github.com/k1moradi/RDP-server/issues/11).
These failures prevent Release phases. Windows CI was still in
progress at receipt authoring; do not count Windows as PASS.
Documentation policy PASS. No real R2 OS authorization or owner
same-SHA three-platform result exists; M2 remains NOT ACCEPTED.


**Implementation:** the first already-decrypted MCS Connect-Initial in
R1's existing PreauthSession is now checked by R3's noncopyable
`McsSessionLifecycle`. It owns the one join gate, reuses the first-party
MCS/domain-merge/GCC parsers and closes after diagnostic validation.
No R2-backed authorized session capability exists in the project, so
MCS Connect Response, Erect/Attach/Join and channel traffic stay denied.
Valid Disconnect is terminal-only. Preauth's prior syntax-only Boolean
contract is preserved; true never means admission.

**New production-linked central CTests:** `transport.mcs-session-unverified-connect`
and `transport.mcs-session-unverified-ordering` in the existing
`test_owned_mcs_connect_initial` executable. They cover a published
Microsoft Connect-Initial, invalid envelopes, repeated callbacks,
fresh instances, valid Erect/Attach/Join/SendData denied out of phase,
peer Disconnect, no pending outbound data and revoked membership.
**NOT RUN at authoring:** project full CTest, exact-SHA GitHub Actions,
owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27, genuine
R2 GSS/CredSSP plus OS authorization, and real Microsoft-client desktop.
Previous implementation test results remain recorded separately.
**Next:** consume only a provider-owned, TLS-bound, independently
OS-authorized R2 lease; implement the first post-admission ordered R3
transition in THIS owner with the existing R1 writer. Gate A/M2 open.

## R3 joined outbound SendDataIndication gate (2026-10-15)

**Exact-SHA hosted CI (2026-10-15):** implementation
[`54e107bef8670c8ae3b739c442a3e6147a9b1069`](https://github.com/k1moradi/RDP-server/commit/54e107bef8670c8ae3b739c442a3e6147a9b1069),
[Actions 38796333656](https://github.com/k1moradi/RDP-server/actions/runs/38796333656).
Linux/GCC **161/161**, macOS/Clang **150/150** full CTests PASS
in BOTH Debug and Release; both new R3 tests PASS on Linux,
macOS AND Windows, documentation policy and SDK consumer PASS.
Windows/MSVC Debug **157/158 FAIL**, specifically R10-owned
`runtime.validates-configuration-comments-crlf` at
`tests/check_runtime_entrypoint.cmake:118` (expected 0,
observed 3). Windows Release NOT RUN; full workflow FAIL.
R10 correction tracked in [issue #10](https://github.com/k1moradi/RDP-server/issues/10).
This is not R3 CTest failure or proof of full integration;
owner three-platform same-SHA, R2 genuine admission and live RDP
remain NOT RUN.


The existing `McsChannelJoinWriteGate` now checks fully completed
channel membership before calling the existing production MCS server
SendDataIndication encoder. It grants no R2 authentication, OS admission,
licensed or negotiated channel routing. New central behavior-named CTests:
`transport.mcs-send-indication-joined-wire` (byte-exact valid envelope,
partial join and closed denial) and
`transport.mcs-send-indication-joined-denials` (unjoined/unknown IDs,
invalid PER priority/segmentation, short/oversized buffer, no mutation,
closure and preservation of prior membership). Old CTests retained.
**NOT RUN at authoring:** full project build/CTest, implementation
SHA hosted CI, independent owner three-platform CTests and real client.
Next: sole R3 domain-phase dispatcher with real R1 completion and
verified R2 TLS/CredSSP/OS admission. M2/Gate A remains open.

## R3 bounded MCS Join delivery and stale-write protection (2026-10-15)

**Baseline reviewed:** current `main` immediately before this implementation
commit; the exact published SHA is the parent of this implementation.
Eight new behavior-named central CTests extend the existing MCS executable:
`transport.mcs-join-write-completion`, `transport.mcs-join-write-denials`,
`transport.mcs-join-duplicate-ignored`, `transport.mcs-join-batched-requests`,
`transport.mcs-send-data-joined-membership`,
`transport.mcs-send-data-joined-denials`,
`transport.mcs-join-stale-write-receipts`,
`transport.mcs-join-stale-partial-write-slices`.

**PASS (limited local evidence):** reused the sole
`~/rdp-server/build` shadow harness, GCC 14.2 C++23 -Wall -Wextra
-Wpedantic -Wconversion -Wsign-conversion -Werror, ASan/UBSan,
`cmake -S ~/rdp-server -B ~/rdp-server/build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON && cmake --build ~/rdp-server/build --config Debug
--parallel 2 && ctest --test-dir ~/rdp-server/build -C Debug
--output-on-failure`: 8/8 PASS. Previous Clang 17 C++23 sanitizer
stand-in runs: 8/8 PASS. The local checkout is a narrow fixture with
reduced parsing/encoder logic, NOT the production repository.

**NOT RUN at authoring:** real repository Debug/full CTest and hosted
CI at the new implementation SHA (check GitHub Actions after publish);
owner Linux/X11, Windows MSYS2 CLANG64 Clang23 and macOS27 CTests;
authenticated client, independent OS admission, licensed activation,
graphics and desktop. Prior owner 101/101 is unrelated baseline evidence.

**Next:** owner R3 combines this bounded join gate with the sole R1
outbound transport completion and a genuine R2 TLS-bound CredSSP/GSS
plus OS authorization decision. M2/Gate A remain NOT ACCEPTED.

**PASS (exact implementation CI):** commit
[`469f49e5d4621017016a06095a17ca7cbfc10182`](https://github.com/k1moradi/RDP-server/commit/469f49e5d4621017016a06095a17ca7cbfc10182),
[Actions 38794591251](https://github.com/k1moradi/RDP-server/actions/runs/38794591251)
completed successfully. Linux/GCC **124/124**, macOS/Clang **114/114**
and Windows/MSVC **114/114** CTests passed in **both Debug and Release**,
including all eight new `transport.mcs-*` R3 cases.
Documentation-policy, SDK install/consumer, packaging and SHA256 passed;
untagged prerelease was skipped. **NOT RUN:** owner's independent
Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 one-liner
on this exact SHA, real Kerberos/CredSSP plus OS authorization,
Microsoft-client session activation, graphics, clipboard or desktop.

## R9 CLIPRDR response-framing regression (2026-10-15)

**Implementation parent main:** `469f49e5d4621017016a06095a17ca7cbfc10182`. Modified:
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/CODEX_VALIDATION.md`. No production change.
**New CTest:** `clipboard.remote-transfer-framing-rejections` dispatches
a distinct test function in the existing production-linked test binary,
checking every strict response prefix, malformed declared length, invalid
type/flags, unsolicited replay, permanent poison before disconnect/reset,
and successful fresh request plus borrowed-payload lifetime assertion.
The existing `clipboard.remote-transfer` continues to run its original
assertions without duplicate registration.

**PASS (isolated, not official CTest):** existing
`~/rdp-server/build/r9-clipboard-verification` harness compiled byte-for-byte
the production `RemoteTransfer` translation unit and production CLIPRDR
wire-codec excerpt with GCC 14.2 C++23 Debug and Release, Clang 17
ASan/UBSan plus leak detection; both original and added tests exit 0.
The committed test file's blob SHA equals the isolated compiled source
SHA `069f6f47bc7744d4bd524a347aebf616e361638a`.
A deliberately removed PDU length guard triggered expected assertion 134.
**NOT RUN at authoring:** canonical full project build, focused/full CTest
(no local Git checkout because github.com DNS unavailable), hosted
exact-commit CI, owner Linux, Windows MSYS2 CLANG64/Clang23 and macOS27
tests, Microsoft client, real OS authorization or desktop/clipboard.
**Next:** verify exact-commit CI, owner's unchanged single-root CTest, then
separate fragmentation/reset and R3→R8 integration security regressions.

## R6 direct-main integration receipt (2026-10-15)

**Parent `main` SHA:** `455b8b631957d2f3f9631393f2a3833e19c2c07a`. All 12 affected paths, including
six Windows adapter files, one reusable R6 behavior executable,
central CMake/CTest registration, ROADMAP, ARCHITECTURE and this ledger
are one atomic implementation increment.
**PASS:** Linux Clang 17 and GCC 14.2 C++23 strict warnings
`-std=c++23 -Wall -Wextra -Wpedantic -Werror -UNDEBUG -Isrc`
compiled the three production `.cpp` files and R6 test fixture;
7/7 direct behavior cases each. Clang ASan+UBSan 7/7 PASS.
Sparse fixture `ctest --test-dir build -C Debug --output-on-failure`
7/7 PASS inside `~/rdp-server/build` (not the canonical full CTest).
**NOT RUN:** full project CMake/CTest, Windows CLANG64 Clang 23/MSVC,
owner Linux/macOS, R2/R3 authorized session, DXGI acquisition, R4
graphics, Microsoft-client desktop and benchmarks. Next: R2/R3-bound
DXGI frame acquire/release/cancel RAII and deterministic failure CTest.

**Exact implementation CI PASS (2026-10-15):** `455b8b631957d2f3f9631393f2a3833e19c2c07a`,
[Actions 38794861230](https://github.com/k1moradi/RDP-server/actions/runs/38794861230).
Linux/GCC **125/125**, macOS/Clang and Windows/MSVC **115/115**
registered full CTests each in **Debug and Release** (hosted logs).
`clipboard.remote-transfer-framing-rejections` ran and PASSed in both
configurations on all three hosted operating systems. Project policy,
staged SDK installation, downstream single consumer CTest, ZIP package,
SHA256 digest and package artifact upload PASS. This confirms compiled
first-party offline tests, NOT live Microsoft-client interoperability.
**NOT RUN:** owner's Linux/X11/Windows MSYS2 CLANG64 Clang23/macOS27
exact-SHA runs, real GSS OS authorization, host clipboard, and desktop.
**Next:** add isolated chunk-reassembly reset/bounds dedicated CTest
on latest `main` and cross-road authenticated channel integration.

## R4 AVC420 capability exchange implementation (2026-10-15)

**Parent `main`:** `5f3cd193417c4f30fb51929aecc30b48c129cff5`. The complete atomic change adds
`src/rdp/gfx_avc420_capabilities.{h,cpp}` to the portable C++23 SDK,
registers a production-linked executable in the one test registry and
updates the living R4 TODO and architecture. The three dedicated CTests:
`graphics.avc420-capabilities-selection`,
`graphics.avc420-capabilities-rejections` and
`graphics.avc420-capabilities-header-bounds` cover exact CAPSET 8.1
negotiation/wire bytes, unsupported offers, truncation, malicious
lengths, duplicate and overlapping CAPSET headers. MS-RDPEGFX
2.2.1.5/6, 2.2.2.18/19 and 2.2.3.2 define the normative wire contract.

**PASS:** GCC 14.2 and Clang 17 each compiled the production
`gfx_avc420_capabilities.cpp` and production-linked test fixture with
`-std=c++23 -O1 -g -Wall -Wextra -Wpedantic -Werror -UNDEBUG
-D_GLIBCXX_ASSERTIONS -fsanitize=address,undefined
-fno-omit-frame-pointer -Isrc`. All three behavior cases passed
with `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1`, each compiler. An isolated staging
`ctest --test-dir "$HOME/rdp-server/build/r4_avc420_stage"
--output-on-failure` also **PASSED 3/3**; it is NOT the full
project CTest. The full checkout is unavailable in this runtime, so
the canonical full project configure/build/CTest is **NOT RUN at
authoring**. Exact-published-SHA hosted CI is to be checked after
publication. The owner's Linux/X11, Windows MSYS2 CLANG64 Clang23
and macOS27 one-liners, R3 authorized DVC session, H.264 x264 path,
Microsoft-client visible desktop and graphics benchmarks are
**NOT RUN**.

**Next gate:** inspect exact published SHA CI/full CTests, then
integrate confirmation with the R3-authorized dynamic graphics channel
and R4 surface lifecycle. Do not infer a live server from this test.

## R6 WinGDI Rectangle collision correction (2026-10-15)

**First CI failure:** `467bf6bcf4624399e4e24667d214afd738b359d6`,
[Windows/MSVC CI Debug build](https://github.com/k1moradi/RDP-server/actions/runs/38794939277),
`src/windows/windows_desktop_geometry.cpp:33`: MSVC C2146, C2923 etc.
`windows.h` declares WinGDI function `Rectangle`, hiding the portable
`struct Rectangle` in unqualified C++ lookup. Linux GCC/Clang did not
include WinGDI and thus had previously passed offline R6 fixtures.
**Correction:** `PortableRectangle = struct ::Rectangle` in the R6
native namespace; geometry and DXGI headers/source use the alias.
**New dedicated Windows-conditional CTest:**
`windows.geometry-gdi-rectangle-name-resolution`, reusing the R6
executable and a separate regression translation unit that includes
`windows.h` before R6 headers (or declares an equivalent WinGDI
function on Linux). Positive monitor/dirty rectangle interpretation and
native name lookup both covered.
**PASS:** `clang++` and `g++ -std=c++23 -Wall -Wextra -Wpedantic
-Werror -UNDEBUG -Isrc` on the three production R6 units and two
R6 test translation units; 8/8 direct cases each. Clang 17 ASan/UBSan
with `-O1 -g -fno-omit-frame-pointer`: 8/8 PASS. Sparse source only;
full canonical checkout CMake/CTest remains NOT RUN locally due Git DNS.
**NOT RUN:** corrected Windows CI/Clang 23, owner platform trio,
real authorized desktop and benchmarks at authoring time.
**Next:** inspect the exact correction-SHA CI jobs; then integrate bounded
DXGI frame lifetime/acquire/release under R2/R3 authorization and R4
frame ownership with failure/cancellation behavior test.

## R5 XShm capture geometry and reply bounds (direct-main implementation)

**Base main:** `d9a46e5cb871b8a81d8a6d057d0f60b568957f45`, exact-SHA CI pending publication.
**Source:** `src/x11/x11_capture_layout.h` and
`src/x11/x11_shared_memory_capture.cpp`; dedicated CTest:
`tests/test_x11_capture_layout.cpp` registered conditionally for Linux
in `tests/CMakeLists.txt`. `docs/ROADMAP.md` updated in same commit.
The production capture path validates XCB geometry, pixel stride,
uint32/size_t reply limits and shared-memory arena capacity and rejects
short/oversized image replies before publishing a borrowed framebuffer.
No new session owner or live X11 capture is enabled by this guard.

**PASS (isolated headless R5 fixture, NOT canonical repository):**
`cmake --build /home/oai/rdp-server/build --config Debug --parallel 2`
and `ctest --test-dir /home/oai/rdp-server/build -C Debug
--output-on-failure`: **2/2 PASS** (capture and cursor). Clang 17 C++23
`-O2 -Wall -Wextra -Wpedantic -Werror -UNDEBUG` standalone
capture compile/run: **PASS**. GCC 14 C++23 capture ASan+UBSan:
**PASS**. Pure geometry checks include exact/truncated/oversized reply,
negative/offscreen coordinates, short arena, uint16/uint32 overflow and
near-4-GiB no-allocation positive case. Borrowed buffer view checked.

**NOT RUN/BLOCKED:** full repo CMake/CTest (GitHub clone DNS failure),
native XCB source compilation (xcb/shm.h missing), exact-SHA CI,
owner Linux/X11/Windows MSYS2 CLANG64/macOS27, authorized session,
Microsoft-client desktop and performance benchmark.
**Next:** verify full-project CTest and CI on published SHA and compile
native Linux/XCB target with deterministic lifecycle tests; bind to
R2/R3 OS admission and R4 graphics consumer only afterward.

## R1 one-owner TCP/TLS lifetime (2026-10-15)

**Integration parent:** `a7234f40c4e2188b1170daf363136a6ac159c025`. **Changed files:** R1 native TCP
header/implementation, existing preauth test fixture, one central CTest
registry and affected ROADMAP, ARCHITECTURE, coding/testing standards
and this ledger. Added nonmoving `OwnedPreauthTcpConnection` with
unique server SSL/BIO ownership and fail-closed accepted-socket
cancellation; no second protocol state machine or session admission.
**Dedicated new CTests:** `transport.tcp-owned-connection-tls-lifecycle`
and `transport.tcp-owned-connection-cancellation`.
**PASS:** prior R1 accept/EOF standalone GCC/Clang strict warning
ASan+UBSan on native Linux and simulated POSIX fallback; prior R1
`b633bb0554020ff6aba6811240b75fa25c4bd69a` hosted macOS and
Windows CI 104/104 in Debug/Release.
**NOT RUN at authoring:** full new-code CMake/CTest (worker has no
GitHub-clonable checkout), new-SHA hosted CI and owner Linux/X11,
Windows MSYS2 CLANG64 Clang23, macOS27. **Next:** bounded event
readiness scheduler, R2-authenticated admission and R3 MCS session.
Publish atomically to existing main using non-force expected HEAD.

**Exact-SHA post-publication CI receipt:** implementation
[`50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb`](https://github.com/k1moradi/RDP-server/commit/50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb)
ran [GitHub Actions 38796272916](https://github.com/k1moradi/RDP-server/actions/runs/38796272916).
**PASS:** Linux/GCC **159/159 Debug and Release**, macOS/Clang
**148/148 Debug and Release**; both new R1 CTests PASS on
Windows/MSVC Debug as well as both Unix CI configurations;
documentation-policy PASS. **FAIL:** Windows Debug whole suite
**155/156**, `runtime.validates-configuration-comments-crlf`
(#139), expected 0 but runtime returned 3 at
`tests/check_runtime_entrypoint.cmake:118`. This is R10 runtime
configuration code (not the R1 TLS owner) and is tracked by
[Issue #9](https://github.com/k1moradi/RDP-server/issues/9).
Windows Release **NOT RUN** because Debug failed, owner three-platform
exact-SHA checks **NOT RUN**, real client and OS admission **NOT RUN**.
The new R1 CTests do not authorize authenticated session operation.

## R9 CLIPRDR chunk-reassembly/reset/bounds regression (2026-10-15)

**Road and parent main:** R9 quality/security, `54e107bef8670c8ae3b739c442a3e6147a9b1069`. The
production `src/clipboard/clipboard_protocol.cpp` and public header
remain unchanged. Modified files: `tests/test_clipboard_protocol.cpp`,
`tests/CMakeLists.txt`, `docs/ROADMAP.md`,
`docs/CODEX_VALIDATION.md`. New dedicated, ordinary
`clipboard.chunk-reassembly-reset-bounds` CTest runs the actual
production `ChunkReassembler::append/reset` through the existing
test executable. `clipboard.protocol` continues to run all seven
previous test functions. Cases: 256 two-chunk fragmentation cuts
of a 257-byte synthetic message; one-byte fragments; caller-owned
completed bytes after reset/reuse; unsolicited continuation;
premature LAST, changed total, too-large continuation, duplicate
FIRST, invalid pointer/length, zero advertised size and maximum+1;
all malformed cases reject cleanly before allowing new valid data.

**PASS isolated, NOT project CTest:** Existing
`~/rdp-server/build/r9-chunk-verification` harness with the
production public header and byte-identical `ChunkReassembler`
method bodies: GCC 14.2 `-std=c++23` Debug and Release with
`-Wall -Wextra -Wpedantic -Werror`; Clang 17 ASan+UBSan and
leak detection. Original reassembler passes; mutation that removes
the early-LAST total check fails at the intended assertion (exit
134). No live RDP session/clipboard operation was performed.
**NOT RUN at authoring:** direct full checkout CMake/CTest due
GitHub hostname DNS unavailability on this runner; exact-SHA
hosted CI, owner's unchanged Linux/X11, Windows MSYS2 CLANG64
Clang 23 and macOS27 compile/CTest, live authorized client and
desktop/clipboard. Follow-up exact-commit Actions evidence
must be recorded only after it completes. **Next:** obtain
exact-SHA hosted CI/owner logs, then test R3→R8 authorized
channel routing and disconnect cancellation when integrated.

## R5 XFixes cursor reply-length bounds — direct-main implementation

**Baseline main:** `d7946e2e74bf9ca7cdce66f02080b37085812be6`; exact implementation SHA/CI pending at
authoring. Files: `src/x11/cursor_image_conversion.h`,
`src/x11/x11_cursor_tracker.cpp`, `tests/test_x11_cursor_reply.cpp`,
`tests/CMakeLists.txt`, `docs/ROADMAP.md` and this ledger.

**Change:** A single C++23 constexpr `valid_xfixes_cursor_reply` checks
nonzero width/height, 32x32 maximum, hotspot within the shape, and
the GetCursorImage reply's number of 32-bit payload words against
width*height. The real `X11CursorTracker::refresh` calls the helper
before making an ARGB span. The existing unsupported-cursor fallback,
frame ownership and output conversion remain unchanged.
Dedicated Linux-only `x11.cursor-reply-length-bounds` CTest exercises
the same production helper, valid/truncated/padded replies, hotspot
and geometry failures, actual `cursor_image_conversion.cpp`, BGRX
bottom-up ordering, transparency and no writes on short spans.

**PASS (headless isolated R5 fixture, not canonical full repository):**
`cmake --build /home/oai/rdp-server/build --config Debug --parallel 2`
and `ctest --test-dir /home/oai/rdp-server/build -C Debug -R
'^x11\\.(capture-layout-bounds|cursor-reply-length-bounds)$'
--output-on-failure`: **2/2 PASS**. Strict C++23 `-O2 -Wall -Wextra
-Wpedantic -Werror -UNDEBUG` GCC 14 and Clang 17 cursor builds
and standalone execution: **PASS**. GCC ASan+UBSan cursor build
and standalone execution: **PASS**.

**BLOCKED/NOT RUN:** complete project CMake/CTest (no full checkout in
authoring environment due outbound GitHub DNS), native XCB tracker
compile (xcb/xfixes.h absent), owner Windows CLANG64/macOS 27 and
Linux/X11 exact-SHA independent validation, live Microsoft-client
desktop and performance measurements.
**Next:** verify exact-SHA CI once published; compile the native XCB
cursor translation unit and exercise resource teardown/failed reply
handling with deterministic fixtures; bind to R2/R3 authorized session
and R4 cursor consumer before M3 acceptance.

## R4 frame ACK bounded-accounting increment (2026-10-15)

**Parent `main`:** `1ef747cfd17c2e742020278b9f1731be2725ed10`. Implemented
`src/rdp/gfx_frame_acknowledge.{h,cpp}` as one portable C++23
protocol-library module and registered six new production-linked
`graphics.frame-ack-*` cases in the existing CTest registry,
alongside the relevant R4 TODO/architecture co-changes. This is
a fixed 64-ID outstanding frame bookkeeper for the *one* R4
graphics scheduler, not a second state owner. The caller must
supply trusted, nonreused R3 DVC channel generations. Normative:
MS-RDPEGFX 2.2.2.13, 3.2.1.2 and 3.2.5.13.

**PASS — focused production-code verification:** GCC 14.2 and
Clang 17 with `-std=c++23 -O1 -g -Wall -Wextra -Wpedantic -Werror
-UNDEBUG -D_GLIBCXX_ASSERTIONS -fsanitize=address,undefined
-fno-omit-frame-pointer`, the actual
`gfx_frame_acknowledge.cpp` and `test_gfx_frame_acknowledge.cpp`,
all six behaviors for each compiler, with ASan leak detection and
UBSan halt-on-error. Isolated
`ctest --test-dir "$HOME/rdp-server/build/r4_ack_stage"
--output-on-failure`: **6/6 PASS**. This local CTest is
**not** the entire project CTest.

**NOT RUN at authoring:** full canonical repository CTest
(no local Git checkout and outbound git DNS unavailable);
exact-commit hosted Actions CI (inspect after publication);
owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27;
R3 authenticated graphics DVC, x264 frame transmission,
real Microsoft client interactive desktop and benchmarks.

**Next R4:** integrate this ACK state within the single
scheduler after R3 authorized channel admission; verify
backpressure and generation reset with a dedicated behavior
CTest. Gate B/M3–M5 are not accepted.


## R9 exact-SHA CLIPRDR chunk regression CI evidence (2026-10-15)

**Implementation:** [`d7946e2e74bf9ca7cdce66f02080b37085812be6`](https://github.com/k1moradi/RDP-server/commit/d7946e2e74bf9ca7cdce66f02080b37085812be6);
[hosted Actions run 38796420558](https://github.com/k1moradi/RDP-server/actions/runs/38796420558).
**PASS:** Linux/GCC **162/162** registered CTests in both Debug and
Release; macOS/Clang **151/151** in both configurations.
`clipboard.chunk-reassembly-reset-bounds` specifically PASSed
in each configuration on both systems. The documentation-policy,
Debug/Release build and SDK package stages succeeded on Linux/macOS.
**Windows/MSVC:** Debug compile PASS and **158/159 CTests PASS**,
including the new R9 chunk/reset test, but the full CI job is
**FAIL** at CTest `runtime.validates-configuration-comments-crlf`
(#142), with `tests/check_runtime_entrypoint.cmake:118` reporting
`Unexpected runtime exit status: 3` vs required 0. This is
an independently reproduced **R10 runtime/config test boundary**
on earlier SHAs ([issue #9](https://github.com/k1moradi/RDP-server/issues/9));
no R9 production runtime files changed, and this is not a
clipboard regression. Windows Release **NOT RUN** because
Windows Debug full CTest stopped the workflow.
**NOT RUN:** owner's exact-SHA Linux/X11, Windows MSYS2 CLANG64
Clang 23, macOS27 full commands, authenticated OS session,
Microsoft RDP client and host clipboard/desktop.
**Next:** R10 corrects Windows-only offline config regression
without weakening the CTest; run full Windows Debug/Release
and monitor next exact commit before R9 integration acceptance.

## R6 Windows DXGI one-frame RAII acquisition increment (2026-10-15)

**Baseline `main` parent SHA:** `853e572dafdeab18161afa3926db2f29d2ec3a34`.
**Changes:** `src/windows/windows_dxgi_frame_owner.{h,cpp}`,
`CMakeLists.txt`, `tests/test_windows_desktop_geometry.cpp`,
`tests/CMakeLists.txt`, and existing ROADMAP/ARCHITECTURE/this ledger
(all in one atomic commit). The native callbacks wrap
`IDXGIOutputDuplication::AcquireNextFrame` and `ReleaseFrame`; one
frame COM resource is released before the duplication lease. All
production callbacks are Windows only, and ordinary tests inject
synthetic acquisition outcomes rather than accessing a real desktop.

**Dedicated new Windows-only behavior CTests (reused R6 executable):**
`windows.capture-dxgi-frame-lease-lifecycle` verifies normal acquire,
single release, busy rejection, retryable timeout, reentrancy, cancel
and destructor cleanup. `windows.capture-dxgi-frame-lease-rejections`
covers capped waits, access loss, stale owner, failed release, invalid
callbacks and unexpected resource cleanup.

**PASS:** Linux Clang 17 `clang++ -std=c++23 -Wall -Wextra -Wpedantic
-Werror -UNDEBUG -Isrc` with all four Windows helper production .cpp
sources and the two existing R6 test .cpp sources: 10/10 selectors.
Linux GCC 14.2 same switches: 10/10. Clang 17 `-O1 -g
-fsanitize=address,undefined -fno-omit-frame-pointer` with
`ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1`: 10/10.
Sparse-only fixture `ctest --test-dir ~/rdp-server/build -C Debug
--output-on-failure`: 10/10. This is not the canonical full repo CTest.

**NOT RUN at authoring:** full repository CMake/CTest (Git clone
github.com DNS unresolved), actual Windows MSYS2 CLANG64 Clang 23,
owner Linux/X11 or macOS 27, R2/R3 authorized desktop session,
native DXGI acquire against hardware, R4 frame/GPU copy, live licensed
Microsoft-client interactive desktop, and performance measurement.
GitHub Actions exact-SHA results to be verified after publication.
**Next gate:** D3D11 owned staging/map/unmap RAII with synthetic native
failure tests once R2/R3 session and R4 frame-lifetime contracts converge.

## R6 Windows frame-lease exact-commit GitHub Actions (2026-10-15)

**Implementation commit:** `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
[run 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194)
completed **SUCCESS** (examined workflow jobs and CTest summaries).
**PASS:** Ubuntu Linux Debug and Release **170/170 CTests** per
configuration; Windows GitHub-hosted MSVC Debug and Release
**168/168** (including two new
`windows.capture-dxgi-frame-lease-*` cases), macOS Debug and Release
**158/158**. Downstream SDK consumer **1/1 PASS** per platform,
documentation-policy and protocol ZIP packaging/pass digest upload
also PASS; prerelease publishing SKIPPED (no version tag).
**NOT RUN:** owner-local Linux/X11, Windows MSYS2 CLANG64 Clang 23
and macOS 27 checks on one owner-nominated SHA; real authenticated
OS session, native Desktop Duplication acquisition, Microsoft client
graphics/input, and performance. This is an offline SDK/library
verification, not M4 human-desktop acceptance.
**Next R6:** session-authorized D3D11 staging-copy/map lifetime with
bounded frame geometry, failed-map cleanup and dedicated CTests.

## R1 bounded readiness-interest and deadline dispatch (2026-10-15)

**Road:** R1 native TCP/TLS, P0 Gate A prerequisite.
**Integration parent:** `db62ec72f84c5b83adbedd72a2606b4db9470ec7`.
**Production:** add stage/SSL-WANT-derived `TcpConnectionIoInterest`,
one-event `OwnedPreauthTcpConnection::onSocketReady`, deterministic
external monotonic `cancelIfExpired` and read-only
`establishedTls` borrow. No second state controller or listener.
**Dedicated new portable CTests:**
`transport.tcp-owned-readiness-dispatch` (real loopback partial X.224,
exact Confirm and rejection, TLS BIO/handshake, MCS diagnostic close,
wrong/stale event denial) and
`transport.tcp-owned-deadline-cancellation` (deterministic clock,
partial read, attached SSL/BIO, idempotent close/listener preservation).
Reuse `tests/test_owned_preauth_session.cpp` and central CMake registry.
**Previous evidence PASS:** R1 owner CTests at
`50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb` hosted
Linux GCC 159/159 Debug+Release, macOS Clang 148/148 Debug+Release,
and both R1 cases on Windows MSVC Debug; full Windows CTest FAIL
on unrelated R10 `runtime.validates-configuration-comments-crlf`
(Issue #9). **NEW tests NOT RUN at authoring:** worker lacks clone
(https://github.com host DNS unresolved), exact-SHA hosted CI,
owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27.
**Next:** validate exact code in Linux/Windows/macOS Actions and keep
M2 R2 authentication, R3 session and human real-client gates NOT RUN.

## R9 R3→R8 joined-channel and clipboard teardown verification (2026-10-15)

**Parent main:** `46ef1d2282c6c78b67e37b373be77c624bf529b7`. **Road:** R9 quality/interoperability,
M1 portable contract and M2 security-precondition verification.
**Modified:** `tests/test_owned_remote_transfer.cpp`,
`tests/CMakeLists.txt`, `docs/ROADMAP.md`,
`docs/CODEX_VALIDATION.md`. Production code unchanged.
**New CTest:** `clipboard.mcs-joined-response-teardown`, reusing the
original production-linked clipboard test binary, exercises
`parseMcsChannelRequest`, `McsChannelJoinWriteGate` and
`RemoteTransfer::receiveResponse/resetAfterDisconnect` together.
Checks no clipboard delivery before join, after a partial JoinConfirm
writer callback, on a mismatched user/channel or malformed TPKT;
confirms data only after the final writer receipt; rejects queued
old-session frames after gate close and R8 reset and checks that a
fresh gate does not inherit old joined membership. Existing test
names, fixtures and assertions remain in place.

**No authenticated session claim:** the test's local guarded call
models a *necessary* MCS membership check only. The production gate
explicitly does not authorize transport, TLS, R2 identity, native
OS permission, licensing, complete segmentation or R3 virtual-channel
routing. In particular it does not create a second controller or
implement a live RDP server. No live desktop/clipboard/credentials.
**NOT RUN at authoring:** local complete-source configure/build/
CTest (repository Git DNS unavailable), exact-commit hosted CI,
owner Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS 27,
real licensed Microsoft client and actual R2→R3→R8 admission.
**Next:** exact-SHA hosted CI and owner one-root CTest; once the
single authorized R3 dispatch interface lands, replace fixture-only
membership acceptance with a production ingress-routing CTest.

## R9 cross-road CTest source syntax correction (2026-10-15)

**First failing SHA:** `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`,
[Actions 38798730112](https://github.com/k1moradi/RDP-server/actions/runs/38798730112).
**FAIL:** GCC Debug compile at
`tests/test_owned_remote_transfer.cpp:828`, because the test insertion
left `int main(int argumentCount} // namespace` ahead of the existing
correct `main` declaration. No new CTest executed at that SHA.
**Correction parent main:** `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`. Remove only the duplicate
broken declaration prefix; retain existing named CTest, old default
suite and all R3/R8 assertions. **NOT RUN at authoring:** exact correction
SHA CI, owner's Linux/X11, MSYS2 CLANG64/Clang23, macOS27 and live
R2/R3-authorized clipboard integration. **Next:** inspect the exact
correction SHA's GCC/Clang/MSVC Debug/Release CI before asserting PASS.

## R1 pending X.224 reply priority fix (2026-10-15)

**Parent `main`:** `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`; initial R1 readiness commit
`209ebb6fa714b4bba61478539976719506b9b96d` exact
[Actions 38798562218](https://github.com/k1moradi/RDP-server/actions/runs/38798562218)
reported new dedicated Linux transport CTests FAIL: the preauth
stage already advanced to `AwaitTls` while the Confirm suffix still
needed to be sent, so stage-first readiness incorrectly returned
`ConfigureTls`. The repair selects pending X.224 reply bytes before
consulting stage, dispatches write through the existing bounded
`PreauthTcpAdapter`, and preserves rejection failure-response flush.
**Dedicated new behavior CTest:**
`transport.tcp-owned-reply-interest-priority` (real loopback success
and failure responses, wrong-direction wakeup, exact 19-byte parity).
**PASS:** source-inspected transition and CTest registered in central
registry. **NOT RUN at authoring:** corrected full CTest, exact repair
commit CI, owner native Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27 toolchains, actual client/OS authentication. Windows baseline
R10 CRLF configuration test remains separately tracked in Issue #9.

## R5 native Linux XCB-SHM capture compilation and failure boundary

**Base main at authoring:** `aa15209c67d74814cac8c859997e623cd096691c`; exact new commit and hosted CI
pending. A Linux-only optional `rdp-server-linux-xshm` static target
compiles real `src/x11/x11_shared_memory_capture.cpp` with pkg-config
`xcb`/`xcb-shm`, separate from the portable protocol SDK.
`captureArenaPixels` is moved without algorithm changes into the
existing dependency-free `src/x11/x11_capture_layout.h`, still used
by the native header. Ubuntu CI installs `libxcb1-dev`,
`libxcb-shm0-dev` and `pkg-config`; owner builds lacking those
packages retain portable compilation and an arithmetic-only test.

**Dedicated new Linux-only CTest:**
`x11.capture-arena-and-connection-denials` checks zero-sized
geometry/limits, minimum-one-full-row arena progress, display cap
and large uint64 values. With the native XCB-SHM target built, it
also obtains an already-failed connection from
`xcb_connect_to_fd(-1, nullptr)`, checks the real native
constructor rejects it before SHM allocation, native capture
fails closed and destructor returns without contacting a display.
No real X server, credential, desktop or input injection used.

**PASS (isolated headless R5 fixture, not full repository):**
`cmake -S ~/rdp-server -B ~/rdp-server/build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON`, `cmake --build ~/rdp-server/build
--config Debug --parallel 2`, `ctest --test-dir
~/rdp-server/build -C Debug --output-on-failure`:
3/3 R5 CTests PASS. GCC14/Clang17 `-std=c++23 -O2
-Wall -Wextra -Wpedantic -Werror -UNDEBUG` standalone
compile/run PASS; GCC ASan+UBSan compile/run PASS.

**NOT RUN/BLOCKED at authoring:** full canonical checkout
(CI clone DNS blocked locally), XCB-SHM native translation-unit
compile (xcb/shm.h missing locally), owner Linux/X11, Windows
MSYS2 CLANG64 Clang23 and macOS27, real Microsoft-client
desktop and performance. **Next:** verify GitHub Actions
exact-SHA native Linux build plus CTest, test controlled native
success/reply lifecycle without display access, and subsequently
integrate R2/R3 authorization with the R4 consumer; M3 open.

## R7 macOS CoreVideo/Retina/TCC preflight implementation (2026-10-15)

**Source baseline:** `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`. Noninstalled `rdp-server-macos-capture`
on Apple only; native CoreVideo retained/read-locked 32BGRA buffer view with
bounded stride/layout, pixel-only rows, move/release RAII; a portable
16-display logical-point/physical-pixel geometry snapshot with generation
and gap rejection, and read-only CoreGraphics capture-permission preflight.
No ScreenCaptureKit stream, remote login, OS admission, injection or native
clipboard access. No user privacy settings were changed.

**Files:** `CMakeLists.txt`, `tests/CMakeLists.txt`,
`src/platform/macos/capture_pixel_layout.{h,cpp}`,
`src/platform/macos/capture_pixel_buffer.{h,cpp}`,
`src/platform/macos/desktop_display_geometry.{h,cpp}`,
`src/platform/macos/screen_capture_preflight.{h,cpp}`,
`tests/test_macos_capture_pixel_buffer.cpp`, `docs/ROADMAP.md`,
`docs/ARCHITECTURE.md`, and this ledger.
**New CTests:** `macos.capture-bgra-layout-bounds`,
`macos.capture-permission-preflight-revocation`,
`macos.desktop-retina-points`, `macos.desktop-multi-display-invalid`,
`macos.desktop-reconfiguration`,
`macos.desktop-virtual-input-coordinates` (all OS);
`macos.capture-bgra-buffer-ownership`,
`macos.capture-bgra-buffer-native-denials`,
`macos.capture-bgra-buffer-native-move-replacement` (Apple-only).

**PASS, isolated Linux R7 fixture only** (NOT the complete repository):
`cmake -S ~/rdp-server -B ~/rdp-server/build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build ~/rdp-server/build --parallel 2`,
`ctest --test-dir ~/rdp-server/build -C Debug --output-on-failure`
=> **9/9** (six portable cases plus three synthetic fake-CoreVideo cases).
Also GCC 14.2 strict C++23 `-O2 -Werror -D_GLIBCXX_ASSERTIONS`:
six portable cases PASS; Clang 17 strict C++23 ASan/UBSan: six portable
cases PASS. All simulated and fixture evidence is explicitly not a native
Apple CoreVideo SDK validation.

**NOT RUN at implementation authoring:** complete main checkout/full CTest;
GitHub Actions on this newly produced commit; owner's macOS 27 SDK/Apple
Clang, Linux/X11 or MSYS2 CLANG64 Clang23 exact-SHA test triplet; real
TCC permission changes, ScreenCaptureKit streams, authenticated RDP
Microsoft-client graphics/input/reconnect, and benchmarks.
**First missing integration boundary:** R2/R3 independently authorized
per-user interactive macOS desktop/session capability and R4 portable
frame/stride/damage/lifetime contract. **Next R7 step:** native display
sampling/normalization and deterministic change notifications, with a new
dedicated CTest; do not activate a service or infer authorization from
CGPreflightScreenCaptureAccess.


## R9 offline MCS-joined clipboard teardown exact-SHA CI (2026-10-15)

**Correction SHA:** [`396c81513363d99bb1de60c46f9b2e4bf504c8cf`](https://github.com/k1moradi/RDP-server/commit/396c81513363d99bb1de60c46f9b2e4bf504c8cf),
[Actions 38798952942](https://github.com/k1moradi/RDP-server/actions/runs/38798952942).
**PASS:** new `clipboard.mcs-joined-response-teardown` CTest
in both Linux/GCC and macOS/Clang Debug (real production
`parseMcsChannelRequest`, `McsChannelJoinWriteGate`,
`RemoteTransfer::receiveResponse` linked by normal CMake);
docs co-change policy PASS. **FAIL, not accepted:** full
Linux Debug **173/175**, macOS Debug **161/163**; two
identical R1 readiness/deadline assertions fail at
`tests/test_owned_preauth_session.cpp:1967,2130`.
These assertions failed at previous R1 parent SHA
`209ebb6fa714b4bba61478539976719506b9b96d`
and are in [R1 issue #11](https://github.com/k1moradi/RDP-server/issues/11).
Linux/macOS Release on this exact SHA **NOT RUN**
due to failing Debug. Windows/MSVC Debug compile PASS;
CTest was still **IN PROGRESS** at evidence authoring
and may not be claimed as passed. The original implementation
SHA `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`
had an R9 C++ syntax insertion error at `main`; fix
`396c81513363d99bb1de60c46f9b2e4bf504c8cf` eliminated that error and got actual native
CTest PASS on Linux/macOS. A later separate R1 transport
fix was published by the R1 owner, but cannot retroactively
change the tested earlier R9 SHA's full-suite FAIL.
**NOT RUN:** owner's Linux/X11, Windows MSYS2 CLANG64
Clang23, macOS27, actual TLS+R2 OS admission or
Microsoft-client desktop/clipboard.
**Next:** R1 full CI remediation, any remaining Windows
CI triage, then real R3→R8 authorized ingress once available.

## R1 cross-platform nonblocking test fixture correction (2026-10-15)

**Parent `main`:** `3b22e8fa018d093339f4d1f5e7c44fe90ef7b4f3`; [Actions 38799213949](https://github.com/k1moradi/RDP-server/actions/runs/38799213949)
with repaired pending-reply precedence. **PASS** Linux/GCC
**176/176** in Debug and Release, all R1 tests and downstream consumer;
Windows/MSVC Debug and Release jobs PASS; macOS/Clang Debug
**164/164 PASS**. **FAIL** macOS/Clang Release only
`transport.tcp-owned-deadline-cancellation` assertion at
`tests/test_owned_preauth_session.cpp:2170`: server callback returned
`Read` because TCP delivered a fragment of an otherwise valid X.224
request. The production behavior was correct. The dedicated test
fixture now uses a bounded 2048-step 1ms retry under nonblocking
`Read` until the same production owner advertises `Write`, and
retains byte/phase/closed-socket assertions. Other new R1 tests use
the same helper against cross-platform fragmentation.
**NOT RUN at authoring:** corrected full Debug+Release CTests,
owner Linux/X11, MSYS2 CLANG64 Clang23, macOS27, real Microsoft client
or authenticated OS session. No production-code change in this commit.


## R2 provider-derived principal requires active TLS binding (2026-10-15)

**Road R2; integration parent:** current main (the published SHA will be
checked after the atomic expected-HEAD update).
**Production:** `GssapiSpnegoAcceptor::verifiedPrincipal()` returns no
principal at GSS mechanism-only completion, with no GSS context, or after
the selected TLS X.509 changes. A genuine v5/v6 confidential GSS
public-key binding on the current pinned server TLS is required.
No native OS authorization or R3 session capability is introduced.

**Dedicated Linux GSS CTest:** `security.gssapi-principal-tls-proof-gate`,
real TLS memory-BIO input with unconfigured MIT GSSAPI, both CredSSP
versions and certificate substitution. The existing opt-in REAL Kerberos
test checks positive identity visibility only after the TLS binding
proof and immediate revocation on a same-SSL certificate change.

**PASS:** production and test source-level review / CTest registry.
**NOT RUN at authoring:** one-root developer focused/full CTests (no
mounted checkout; shell github.com DNS unavailable), exact published
CI, isolated real GSS positive credentials, native OS admission,
Microsoft client or human desktop. **Next:** check exact-SHA hosted
Debug/Release CTests, owner one-root results and authorized real
Kerberos/TLS + independently authorized OS evidence before M2.

## R7 Apple-only CoreFoundation test link correction (2026-10-15)

Initial R7 code `e13e473bf901524ff53c6e0e01b42dfef2ad041c`,
[Actions 38799661046](https://github.com/k1moradi/RDP-server/actions/runs/38799661046):
Ubuntu/GCC and documentation-policy **PASS**. macOS arm64 Apple Clang
**FAIL** during Debug synthetic CoreVideo test link:
undefined `_kCFAllocatorDefault`. All R7 production source compiled
successfully, but macOS CTests were **NOT RUN** at this SHA.
**Fix:** `tests/CMakeLists.txt` links CoreFoundation explicitly on
`test_macos_capture_pixel_buffer` for the `kCFAllocatorDefault` used in
its synthetic fixture. The production CoreVideo/CoreGraphics target and
portable RDP protocol library do not gain an additional dependency.
**NOT RUN:** corrected implementation hosted CI at authoring, owner's
macOS 27 / Linux X11 / MSYS2 CLANG64 Clang23 exact-SHA results,
live R2/R3-authorized RDP desktop/input, permission dialogs and benchmarks.
**Next:** validate corrected exact-SHA Debug/Release CI and owner test trio.

## R1 readiness / X.224 reply priority / deadline exact-SHA CI (2026-10-15)

**Production commits:** [209ebb6fa714b4bba61478539976719506b9b96d](https://github.com/k1moradi/RDP-server/commit/209ebb6fa714b4bba61478539976719506b9b96d) and [0dfc33871c8b140e07e9028d7c4fc4cb12e83fb0](https://github.com/k1moradi/RDP-server/commit/0dfc33871c8b140e07e9028d7c4fc4cb12e83fb0).
**Nonblocking test-fixture correction:** [9f3bcd369d0544c2f85aaf0964b31f912aba7bf5](https://github.com/k1moradi/RDP-server/commit/9f3bcd369d0544c2f85aaf0964b31f912aba7bf5);
[exact commit hosted Actions 38799804260](https://github.com/k1moradi/RDP-server/actions/runs/38799804260).
**PASS:** Linux/GCC full **183/183 Debug + 183/183 Release**;
Windows/MSVC full **180/180 Debug + 180/180 Release**; new
`transport.tcp-owned-readiness-dispatch`,
`transport.tcp-owned-reply-interest-priority` and
`transport.tcp-owned-deadline-cancellation` all PASS on Linux and
Windows both build types; documentation-policy and downstream installed
SDK consumer CTests PASS.
**FAIL / BLOCKED:** macOS arm64/AppleClang CI Debug build stops
during linking unrelated R7 `test_macos_capture_pixel_buffer`:
undefined symbol `_kCFAllocatorDefault` from native CoreFoundation
test fixture; `clang++` link exit 1. Reported in [R7 Issue
#7](https://github.com/k1moradi/RDP-server/issues/7) (comment 6201309589).
macOS Debug CTest and Release build/CTest **NOT RUN** on exact R1
SHA due this earlier build failure; no R1 test was reached on macOS.
**Owner-local** Linux/X11, Windows MSYS2 CLANG64 Clang23 and macOS27
terminal checks **NOT RUN**; real Microsoft RDP client, authenticated
CredSSP/GSS, independent OS admission, MCS share activation and desktop
acceptance **NOT RUN**. No TLS completion is an admission decision.
**Next R1 gate:** transport-owner readiness against an R10 bounded
listener/poller and explicit R2/R3 authenticated handoff, preserving
one state authority and cancel-before-SSL/socket teardown.

## R4 graphics presentation ordering (2026-10-15)

**Base `main` SHA:** `a08efa368fc8cd44295ce6a386e9b0e032f99dc2`. Atomic 8-file R4 increment adds
`src/rdp/gfx_presentation_lifecycle.{h,cpp}`, its dedicated
`tests/test_gfx_presentation_lifecycle.cpp`, production
`CMakeLists.txt`, central `tests/CMakeLists.txt` and
ROADMAP/ARCHITECTURE/validation co-updates.
This state object composes the existing AVC420, surface and
`GfxFrameAckWindow` code, **not** a second scheduler or R3 router.

**Dedicated CTests:** `graphics.channel-lifecycle-ordering`
(exact full send receipts gate confirm/create/map/frames),
`graphics.channel-lifecycle-denials` (untrusted timing,
malformed unsupported caps and invalid geometry),
`graphics.surface-resize-revocation` (delete/reuse,
disconnect/reconnect, stale receipts and generations),
`graphics.frame-publication-backpressure` (64 pending
frame IDs, exact ACK, suspension/resumption).

**PASS:** production source compiled with strict C++23
GCC 14.2 and Clang 17 `-O1 -g -Wall -Wextra -Wpedantic
-Werror -UNDEBUG -D_GLIBCXX_ASSERTIONS
-fsanitize=address,undefined -fno-omit-frame-pointer`,
including the actual AVC420, surface and frame-ACK .cpp
files and dedicated new fixture; 4/4 cases each with
ASan leak detection and UBSan halt-on-error.
Isolated source-only CTest in
`~/rdp-server/build/r4_presentation_stage/`: **4/4 PASS**,
NOT the canonical full repository CTest.
Git blob SHAs match local tested sources.

**NOT RUN at authoring:** full project local CTest (no
full Git checkout), exact-commit Actions, owner Linux/X11,
Windows CLANG64 Clang23 and macOS27, authenticated R2
OS admission, R3 authorized DVC, pinned static x264,
real Microsoft client graphics and performance.
**Next:** R3 must provide real admitted graphics-channel
generation and exact outbound completion callbacks; then
wire to R4 frame scheduler/encoder. Gate B/M3–M5 OPEN.

## R5 first-party XCB descriptor/event readiness (2026-10-15)

**Baseline main:** `5c885088775bcbb74b3a9083bd165b4fd17d8bf7`; exact implementation SHA/CI pending when
authored. Atomic source/test/CMake/CI/docs files: existing
`src/x11/x11_display_connection.{h,cpp}`, new
`src/x11/x11_event_dispatch.h` and `tests/test_x11_display_events.cpp`,
top-level `CMakeLists.txt`, `tests/CMakeLists.txt`,
`.github/workflows/ci.yml`, `docs/ROADMAP.md`,
`docs/ARCHITECTURE.md`, `docs/compile.md` and this ledger.

The native X11 connection removes legacy xrdp `config_ac.h`,
`os_calls.h`, tbus wait objects and any socket duplication/close.
XCB remains the sole socket owner, exposes a borrowed fd and explicit
ready-to-read dispatch. Nonblocking queued events, bounded budgets,
the may-have-more hint, typed RandR root resize notification handling,
fatal XCB error denial and idempotent descriptor/geometry invalidation
reuse one event owner. No new input, capture or RDP session is activated.
The native Linux static target (xcb + xcb-randr) is neither linked to
nor exported from the portable SDK; SDK no longer installs X11 headers.
Ubuntu CI installs XCB/RandR development packages.
The new Linux-only CTest `x11.display-event-budget-and-readiness`
uses the same production event-drain and, when built natively, exercises
the real connection's invalid-display failure and repeated teardown.

**PASS (isolated headless authoring fixture only):**
GCC 14 / Clang 17 strict C++23 compile and execute of the actual
`processX11EventBatch` production helper with synthetic XCB events;
GCC AddressSanitizer+UBSan same fixture PASS.
Earlier isolated R5 CTest fixture 3/3 PASS; this previous fixture
does NOT represent the new native CTest or a full repository build.

**BLOCKED/NOT RUN locally:** full repository configure/build/CTest
(container cannot clone github.com), actual native RandR translation
unit compile (`xcb/randr.h` and -dev linker symlink unavailable),
owner Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS 27,
authorized Microsoft-client RDP session, desktop input/capture,
and performance measurements.
**Next:** inspect exact-SHA Actions Linux Debug/Release native
compile/CTest and Windows/macOS regression; then native XShm/cursor/
damage lifetime integration with R2/R3 authorization and R4 consumption.

## R10 POSIX configuration-descriptor hardening (2026-10-15)

**Implementation baseline:** current `main` (exact parent recorded in
the containing GitHub commit). R10 modifies
`src/server/runtime/main.cpp`, `tests/check_runtime_entrypoint.cmake`,
the existing `tests/CMakeLists.txt` registry, and the canonical R10
ROADMAP/ARCHITECTURE/compile/validation documentation in one increment.

**New five dedicated behavior-named POSIX CTests:**
`runtime.validates-configuration-owner-only`,
`runtime.rejects-configuration-symlink`,
`runtime.rejects-configuration-fifo`,
`runtime.rejects-configuration-group-writable`, and
`runtime.rejects-configuration-directory`.
They exercise the production `--check-config` entry point and verify
existing generic fail-only output and exit codes. The original 25
runtime tests remain registered and unchanged in behavior; Windows
does not register POSIX-only tests. No live credentials, certificate
keys, native desktop, input, clipboard or service is accessed.

**PASS — focused local Linux isolated harness:** GCC 14.2 strict
C++23 compile (`-Wall -Wextra -Wpedantic -Werror`), full 30/30 focused
CTest, repeat 30/30; Clang 17 with `-O1 -g
-fsanitize=address,undefined -fno-omit-frame-pointer
-D_GLIBCXX_ASSERTIONS`, 30/30 focused CTest,
`ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1`.
Executed the modified production `main.cpp` with actual
`tests/check_runtime_entrypoint.cmake` (isolated harness lives
within `~/rdp-server/build/r10-posix-file-policy`). This is **not**
the full official repository CTest because no local Git checkout is
available and direct GitHub clone DNS fails.

**NOT RUN at authoring:** full repo CMake/CTest, exact-SHA GitHub Actions,
owner Linux/X11, Windows MSYS2 CLANG64 Clang 23 and macOS 27 checks,
native Windows config-file ACL/reparse-point validation, actual
certificate/private-key permissions, authenticated RDP session and
human desktop. **Security boundary:** POSIX config-file identity and
mode bits only; an accepted `--check-config` never permits startup.
**Next:** exact-commit hosted Debug/Release CI and owner normal CTest,
then Windows-native file-handle checks and real TLS key permissions;
M1–M6 remain unaccepted.

## R6 native D3D11 staging frame/map ownership (2026-10-15)

**Parent main SHA:** `19512d5fdbc0568fbd6c3333b32c770d76c6f8b4`. **Road:** R6 native Windows
desktop adapter. The atomic code/test/docs increment adds
`src/windows/windows_d3d11_staging_map.{h,cpp}` and updates
`CMakeLists.txt`, `tests/CMakeLists.txt`,
`tests/test_windows_desktop_geometry.cpp`,
`docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, and this ledger.
Native code queries the acquired DXGI frame as `ID3D11Texture2D`,
requires a single-subresource BGRA8 nonmultisample texture, copies
to a CPU-read staging texture and maps with nonblocking D3D11
Map. The fixed staging context unmaps/releases resources with
the owning frame lifetime, not through an independent scheduler.
On invalid geometry, driver failure, cancellation and reentrancy,
the view is not published and owned mappings are cleaned up.
The portably compiled fixture uses injected callbacks; it never
captures a desktop, authenticates a user or injects OS input.

**New registered Windows-only CTests:** `windows.capture-d3d11-staging-bgra-map-lifetime`
(single borrowed pitch-preserving BGRA view, one unmap, reentrant
busy rejection, retryable GPU-not-ready, cancellation/destructor);
`windows.capture-d3d11-staging-map-denials` (invalid pitch,
truncated bytes, huge dimensions, missing pointers or handles,
malformed not-ready status, failure, cancellation during callback).

**PASS, offline sparse staging only:**
- Clang 17 C++23 `-Wall -Wextra -Wpedantic -Werror -UNDEBUG`,
  five Windows helper production translation units + reused test:
  12/12 selector cases.
- GCC 14.2 same strict C++23 flags: 12/12 selector cases.
- Clang 17 `-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`,
  `ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1`:
  12/12 selector cases.
- `ctest --test-dir ~/rdp-server/build -C Debug --output-on-failure`:
  12/12 PASS **in the staging-only CTest registry**; focused
  `-R '^windows\\.capture-d3d11-'`: 2/2 PASS.

**NOT RUN at authoring:** complete GitHub checkout CMake/full
CTest due blocked Git DNS, native Windows/MSYS2 CLANG64 Clang23,
owner Linux/X11 and macOS 27 CTests, D3D11 GPU capture, authorized
R2/R3 desktop session, R4 encoded-frame handoff, actual client
graphics/input and benchmarks. GitHub Actions exact commit-SHA
results will be reported separately, not anticipated as PASS.
**Next:** fully session-authorized native capture-to-R4 frame
ownership integration with deterministic disconnect/topology
change and cancellation test. M4 human acceptance remains NOT RUN.

## R7 verified corrected CoreVideo/Retina CI (2026-10-15)

**Production base:** `e13e473bf901524ff53c6e0e01b42dfef2ad041c`.
**First failure:** [Actions 38799661046](https://github.com/k1moradi/RDP-server/actions/runs/38799661046)
macOS arm64 Debug link undefined `_kCFAllocatorDefault` from the
synthetic CoreVideo test; documentation-policy and Ubuntu/Windows jobs
passed on that source SHA.
**Fix:** `0b248c67f8c62ac31d2f94ff4c091bb527f10766` links
CoreFoundation ONLY to the Apple native test target, without changing
production R7 CoreVideo/CoreGraphics or portable protocol linkage.
**PASS:** [Actions 38800167816](https://github.com/k1moradi/RDP-server/actions/runs/38800167816)
completed Ubuntu/GCC **184/184**, macOS/Apple Clang **173/173**,
Windows/MSVC **180/180** CTests EACH in both Debug and Release,
including all nine offline R7 macOS CTests on the hosted Apple runner.
Project policy, SDK staged install/downstream consumer and ZIP/checksum
artifacts all passed. **NOT RUN:** owner macOS27 and MSYS2 CLANG64/
Clang23 exact-SHA terminal runs, real permission requests, independent
OS account admission, ScreenCaptureKit frames, Microsoft-client input
and desktop reconnect, performance benchmarks.
**Next:** native macOS display geometry sampling with a new behavior
CTest; then authorized R2/R3/R4 capture/lifetime integration.

## Exact-commit R2 GSS identity CTest follow-up (2026-10-15)

**R2 implementation:** `ec8291eb68069182d86034768618e67bb8ea3c73`;
[Actions 38799994954](https://github.com/k1moradi/RDP-server/actions/runs/38799994954)
Linux GCC Debug and Release 184/184 each, including distinct
`security.gssapi-principal-tls-proof-gate` PASS; Windows MSVC Debug
and Release 180/180 each PASS; macOS CI FAIL before CTest only at
R7 native pixel-buffer CoreFoundation link (`_kCFAllocatorDefault`).
**Cross-platform repair and follow-up PASS:** inclusion SHA
`19512d5fdbc0568fbd6c3333b32c770d76c6f8b4`,
[Actions 38800199864](https://github.com/k1moradi/RDP-server/actions/runs/38800199864):
Linux 184/184, Windows 180/180 and macOS 173/173 in Debug and
Release, documentation-policy and SDK consumer PASS.
**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27 exact-SHA terminal CTests, positive credentialed Kerberos
and separate native OS admission or Microsoft-client desktop.
The console gate remains deny-only and R2 Gate A is open.

## R5 native XCB strict compile and separate teardown CTest correction

**Base main:** `7dc34b69831a9122fda752434d5c9bfb8ee121ef`. Initial R5 native implementation
`4d4d97ec78a63e963c1bed8d7fa6513141a4f9fa`,
[Actions 38800598423](https://github.com/k1moradi/RDP-server/actions/runs/38800598423):
**FAIL** Ubuntu Debug compile at
`src/x11/x11_display_connection.cpp:222`,
`-Werror=extra` enumerated/non-enumerated ternary. The real
`rdp-server-x11-connection` target was compiled by hosted Linux CI,
exposing a previously untested native translation-unit defect.
Fix both root-window and visual invalid getter values with
explicitly typed zero XCB identifiers. New distinct dedicated
`x11.display-event-disconnect-cleanup` Linux-native CTest selects
a real invalid-display constructor/failed event dispatch/repeated
cancellation path; existing
`x11.display-event-budget-and-readiness` independently exercises
bounded queued event draining and protocol error denial.
Both use one native test executable and never require an X server.
Update the existing test registry and roadmap in the same correction.

**PASS:** locally the previously recorded GCC/Clang strict and
GCC ASan/UBSan headless dispatch tests; **NOT RUN locally:** exact
native RandR TU due missing `xcb/randr.h`; new test cases need
the hosted CI/owner machine native dependencies. No new performance,
desktop or authenticated RDP acceptance.
**Next:** inspect exact-SHA hosted Debug/Release full CTests including
both dedicated native R5 cases; resume native capture and cursor
lifecycle only when compiled target is green.

## R6 D3D11 staging map hosted CI receipt (2026-10-15)

**Exact source/test/docs commit:**
`ecce84689b2aa4801fc28348182d8e4183e6308e`.
[GitHub Actions run 38800686222](https://github.com/k1moradi/RDP-server/actions/runs/38800686222)
**completed with overall FAIL**:
- **PASS Windows GitHub-hosted MSVC:** Debug CTest **182/182**;
  Release CTest **182/182**; new R6
  `windows.capture-d3d11-staging-bgra-map-lifetime` and
  `windows.capture-d3d11-staging-map-denials` passed in both;
  native CMake compilation, SDK staging, downstream consumer and
  packaging passed.
- **PASS macOS hosted Clang:** Debug and Release CTest **178/178**
  each, downstream SDK/packaging passed. Windows-only R6 tests were
  not run on macOS.
- **PASS** documentation policy.
- **FAIL Ubuntu GCC Debug Compile:** unrelated concurrently
  published R5 native X11 code
  `src/x11/x11_display_connection.cpp:222`:
  `-Werror=extra` rejects mixed enumerated/non-enumerated types
  in `return valid() ? rootWindow_ : XCB_WINDOW_NONE;`.
  No Ubuntu full CTest or Release was reached. The R5 owner was
  notified through [Issue #4](https://github.com/k1moradi/RDP-server/issues/4);
  R6 did not alter X11 code or claim Linux CTest success.
- **NOT RUN:** owner's Linux/X11, Windows MSYS2 CLANG64 Clang23
  and macOS 27 exact-SHA local checkpoints, real D3D11/IDXGI
  hardware capture and human Microsoft-client desktop acceptance.
  No native performance measurements.

**Next:** R5 resolves its own unrelated Linux compile failure;
R6 integrates these mapped-frame lifetimes with R3-approved session
ownership and R4's one graphics scheduler, with disconnect and
display topology changes covered by new offline behavior CTests.

## R10 POSIX configuration hardening — exact-SHA CI (2026-10-15)

**Production SHA:** [`25e751b8b0c0e09905355c71e9abaf7bf20fc64c`](https://github.com/k1moradi/RDP-server/commit/25e751b8b0c0e09905355c71e9abaf7bf20fc64c);
[GitHub Actions 38800655859](https://github.com/k1moradi/RDP-server/actions/runs/38800655859),
overall **FAIL** with precise cross-road causes:
- **PASS:** Windows/MSVC complete Debug and Release **180/180** CTests
  per configuration, downstream SDK consumer **1/1**, ZIP/SHA256
  packaging and artifacts, and documentation-policy job.
- **PASS R10, FAIL other road:** macOS/Clang Debug **177/178** CTests;
  all five new R10 POSIX config-descriptor cases PASS and existing
  runtime cases PASS. Sole failure is R1-owned
  `transport.tcp-owned-reply-interest-priority` assertion at
  `tests/test_owned_preauth_session.cpp:2112`; [R1 issue #2](https://github.com/k1moradi/RDP-server/issues/2)
  received the exact failure. macOS Release and packaging **NOT RUN**.
- **FAIL:** Linux/GCC Debug build of R5-owned
  `src/x11/x11_display_connection.cpp:222`, enum vs non-enum
  expression with `-Werror=extra`; [R5 issue #4](https://github.com/k1moradi/RDP-server/issues/4)
  received the exact error. Linux full CTest/Release/package **NOT RUN**.
- **PASS (additional isolated only):** GCC 14.2 ASan+UBSan focused R10
  30/30 CTests, with leak detection and UB halt-on-error inside the
  reused local build root. No complete Git checkout in this environment.

No Windows/MSYS2 CLANG64 Clang 23, owner macOS 27, or owner Linux/X11
same-SHA checks were run here. No real NLA/OS admission, authenticated
desktop, service packaging, or release acceptance. M1–M6 remain OPEN.
**Next:** R1/R5 own their specific CI repairs on `main`; R10
rechecks exact CI and proceeds to Windows-native secure config-file
handling without enabling live server startup.

## R1 one-connection bounded native poll and deadline (2026-10-15)

**Road:** R1 Transport/TLS, P0 first-party event-loop prerequisite.
**Integration parent:** `84d55d00f4c49772ddaad524d078ade198cf5f03`. Nine changed files:
`src/server/transport/nonblocking_tcp_adapter.h/.cpp`,
`tests/test_owned_preauth_session.cpp`, `tests/CMakeLists.txt`,
existing `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`,
`docs/coding_standards.md`, `docs/testing_standards.md` and
this validation ledger. Production increment:
`OwnedPreauthTcpConnection::pollSocketOnce` performs no more than
one bounded (<=25ms) OS `poll`/`WSAPoll` on the accepted owner,
delegates one matching read/write callback to the preexisting
`onSocketReady`, returns explicit idle/needs-TLS/expired/closed/failure,
and closes SSL/BIO before socket on fatal OS error or deadline.
No process listener, second state machine, timer thread, certificate
enrollment, R2 identity, R3 admission or desktop authority.
**Dedicated CTests:** `transport.tcp-owned-bounded-poll-loopback-tls`
and `transport.tcp-owned-bounded-poll-timeout-eof`; both are ordinary
portable loopback cases under the original preauth executable and
central CTest registry.
**Preceding baseline PASS:** all GitHub-hosted Linux/GCC,
Windows/MSVC, macOS/AppleClang protocol and documentation jobs on
`991320318e681fba99ca85adf1d29039c3e3137c`
([Actions 38801211658](https://github.com/k1moradi/RDP-server/actions/runs/38801211658)).
**NOT RUN at authoring:** new code local focused or full CTest
(network git clone cannot resolve github.com and worker has no
existing clone), new implementation exact-commit GitHub Actions,
owner Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS27 checks,
human live Microsoft RDP client and R2/R3 OS admission.
**Next:** R10 integrate the single connection polling step under
a bounded listener-accept budget; R2 authorizes identity and R3 owns
MCS/channel/OS session progression independently.

**Exact-implementation hosted CI receipt:** `fb63d6c41734e3d8a5d14f35237bacee90fd72ba`,
[Actions 38844140123](https://github.com/k1moradi/RDP-server/actions/runs/38844140123)
**SUCCESS**: Linux/GCC **194/194** Debug+Release, macOS/AppleClang
**181/181** Debug+Release, Windows/MSVC **185/185** Debug+Release,
including BOTH newly registered one-step native poll R1 CTests on
each hosted platform/build configuration; documentation-policy and
installed SDK consumer verification PASS, SDK ZIP packaging PASS.
**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27,
authenticated R2/OS session or real Microsoft RDP client and desktop.
The prior authoring-time NOT RUN statements above remain historical.


## R2 GSS/TLS-owned delegated credentials denial (2026-10-15)

**Production:** the old caller-provided DER credentials API now
terminally denies without GSS unwrap. The new
`consumeFramedAndDenyDelegatedCredentials(reader)` requires genuine
GSS-authenticated and CredSSP TLS public-key-bound provider identity,
the EXACT still-pinned server SSL/X.509 and v5/v6, plus an
authInfo-only complete TLS frame before any GSS unwrap. Provider
plaintext metadata-only inspection is bounded and cleansed.
Every case terminally wipes frame and GSS context, never OS admission.

**Dedicated new Linux GSS CTest:**
`security.gssapi-tls-framed-credential-denials`, existing test binary,
real memory-BIO TLS with valid-shaped v5/v6 authInfo ciphertext but
no actual GSS credentials, negative partial/manual/certificate-swap
frames, unchanged no-reply terminal cleanup, replay denial and
historical raw API denial.
**PASS at authoring:** source/DER envelope and CTest registration
static validation. **NOT RUN at authoring:** patched local single-root
CTest (the canonical checkout is absent and container git cannot
resolve github.com), exact new-commit hosted CI (pending publication),
authorized real Kerberos/GSS positive delegation, independently
authorized native OS session or Microsoft client acceptance.
**Next gate:** exact-SHA hosted CI then genuine GSS/TLS-bound
credential provenance plus separately audited OS-session authorization,
before any R3 authenticated session output.

## R4 full logical-frame delivery receipts and lifecycle CMake restoration

**Parent main:** `063bcaa1c3cb5b49fbb4be4b84230736fcd6bf7f`. Restored the previously published
`gfx_presentation_lifecycle.cpp` to the portable protocol target
and its four `graphics.channel-lifecycle-*` /
`graphics.surface-resize-revocation` /
`graphics.frame-publication-backpressure` CTests to the single
registry after newer CMake changes lost them.
New dedicated `graphics.frame-delivery-receipt-ordering` and
`graphics.frame-delivery-abort-revocation` execute the same
production R4 lifecycle. Fixed `GfxFrameAckWindow` remains the
single ACK authority; new `canRecordFrame` preflight prevents
duplicate frame IDs and full-window sends before transmission.
R4's generation/serial-bound complete-frame receipt commits ACK
state ONLY after R3 attests the entire START_FRAME..END_FRAME send;
partial callbacks leave the frame pending and terminal abandonment
revokes the graphical channel. MS-RDPEGFX §§2.2.2.11–13 and
3.2.1.2/3.2.5.13 inform frame/ACK ordering.

**NOT RUN at authoring:** canonical full local repo CMake/CTest
(no complete local checkout; GitHub raw/clone DNS inaccessible);
owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
tests, authenticated R3 DVC writer, pinned x264, genuine H.264
NAL transmission, real Microsoft clients and benchmarks.
After publication examine exact-commit hosted Actions.

## R9 bounded MCS/CLIPRDR length mutation security regression (2026-10-15)

**Parent `main` SHA:** `3130fc9f5b57c7d57719ffaf86e9dcc252bfe6bd`. **Changed:**
`tests/test_owned_remote_transfer.cpp`, `tests/CMakeLists.txt`,
`docs/ROADMAP.md`, `docs/CODEX_VALIDATION.md`.
**CTest:** `clipboard.mcs-cliprdr-length-mutation-denials` (labels protocol/clipboard/security/offline).
This independently dispatched, headless deterministic mutation corpus
runs production `parseMcsChannelRequest`,
`McsChannelJoinWriteGate::matchesJoinedInboundSendData` and
`RemoteTransfer::receiveResponse/resetAfterDisconnect`.
Cases: every strict frame prefix; all mismatched 0..255 one-byte
outer TPKT, PER userData and inner CLIPRDR response lengths;
invalid UserId/channel, malformed PER padding; refusal/empty
borrowed result after malformed nested length, failed subsequent
request until disconnect; explicit clean-session recovery and
all 256 opaque payload byte values correctly accepted.
A successful membership result never substitutes for R2 TLS/OS
admission, licensing, native permissions, actual channel role or
a live R3 router. No real user/client or network socket is started.

**Pre-publication checks:** source blobs and single `main`
declaration/CTest registration inspected against current `main`
using GitHub API. **NOT RUN:** local full checkout build,
focused/full CTest and sanitizers because GitHub hostname
cannot resolve for direct clone from this runner; exact-SHA
hosted Linux/GCC, macOS/Clang, Windows/MSVC CI pending at
authoring; owner's Linux/X11, MSYS2 CLANG64/Clang23, macOS27,
credentialed Microsoft RDP client, authorized OS desktop/clipboard.
**Next:** obtain the actual Actions compile+CTest receipts
for this exact new implementation SHA, repair introduced failures
without hiding tests, and then extend testing to R3's
production-authenticated R8 routing when available.

## R7 native CoreGraphics display observation (2026-10-15)

**Native implementation:** `src/platform/macos/native_display_snapshot.{h,cpp}`,
separate from the installed C++23 protocol SDK; Apple `CGGetActiveDisplayList`
and associated CoreGraphics global logical bounds/backing pixel dimensions
are sampled without desktop capture, prompts, input or new callbacks.
A fixed-capacity owning two-read observation rejects changes/denials,
mirrored and intersecting displays, duplicate IDs, malformed or oversize
physical sizes, nonfinite/precision-lost logical bounds, and stale or zero
generation. It does NOT synthesize multi-display physical pixel origins.
**Changed:** top-level and tests CMake, reused
`tests/test_macos_capture_pixel_buffer.cpp`, existing R7 roadmap,
architecture and this validation ledger.
**New dedicated CTests:** `macos.display-snapshot-stable-multi-retina`,
`macos.display-snapshot-geometry-denials`, and
`macos.display-snapshot-changed-during-read` (registered on all OS).
**PASS (isolated Linux C++23 fixture, NOT full repository):** one-root
GCC14.2 CMake build and CTest 3/3; GCC14.2 optimized strict build
3/3; Clang17 strict ASan/UBSan build 3/3. The initial isolated
malformed-test fixture incorrectly treated finite 1e300+1e300 as overflow;
corrected to true infinity and separately tested precision-loss rejection.
**NOT RUN at authoring:** this increment's hosted exact-commit CI, owner
macOS27 native Apple Clang, Linux/X11, Windows MSYS2 CLANG64 Clang23,
real macOS active display enumeration, ScreenCaptureKit permissions, client
input/cursor, live capture, any performance benchmarks.
**Next:** check exact-SHA CI, then integrate safe authorized graphical
session and R4-owned physical compositor mapping without bypassing TCC.

## R10 Windows config-file native handle gate (2026-10-15)

**Road:** R10 runtime security. **Parent main:** `3274b39c85b817ef2a56215390bf19cc8aa0e5b4`.
This atomic code/test/docs increment uses Win32 `CreateFileA`
with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects non-disk,
directory and final reparse objects using native HANDLE queries,
requires drive-absolute config filenames, and transfers ownership
to RAII FILE via CRT with explicit failure cleanup.
The four new Windows-only CTests are
`runtime.validates-configuration-windows-regular`,
`runtime.rejects-configuration-windows-directory`,
`runtime.rejects-configuration-windows-relative-file`, and
`runtime.rejects-windows-device-namespace`; existing offline
runtime CTests are preserved. Syntax acceptance cannot start a listener.
**NOT RUN at authoring:** Windows native compile, full project CTest,
exact-SHA hosted CI, owner Linux/X11, Windows CLANG64/Clang23,
macOS27, real NLA/OS authorization and Microsoft-client desktop.
Agent's local environment lacks Win32 compilation and GitHub
checkout DNS. No DACL, intermediate-reparse or TLS key-permission
acceptance is claimed; M1–M6 remain open.
**Next:** exact-SHA CI, then Windows DACL permission-policy gates.

## R9 exact-commit MCS/CLIPRDR mutation CI verification (2026-10-15)

**Implementation SHA:** `4eb24cd9312e1d3e133811a8c3a9151cebab4501`.
[GitHub Actions run 38844672159](https://github.com/k1moradi/RDP-server/actions/runs/38844672159), exact head SHA
matched implementation and overall **completed SUCCESS**.
Hosted Linux/GCC **202/202** Debug and **202/202** Release CTests;
macOS/Clang **188/188** Debug and **188/188** Release;
Windows/MSVC **192/192** Debug and **192/192** Release.
New dedicated `clipboard.mcs-cliprdr-length-mutation-denials`
passed in all six CTest runs; no test was bypassed for the
R9 increment. Documentation-policy PASS. One reused CI
`build/` per runner; staged SDK install, downstream consumer
CTest and ZIP/SHA256 uploaded artifacts PASS.
Prerelease job SKIPPED because this was not a release tag.

**First failing boundary:** none on this exact implementation SHA
for the hosted build/CTest matrix. **NOT RUN:** direct
`~/rdp-server/build` local compile/full CTest and ASan/UBSan
in this execution runner (GitHub DNS unresolvable for clone),
owner three-platform same-SHA tests with specified
Windows MSYS2 CLANG64 Clang23/macOS27, real authenticated
Kerberos/NLA + OS account admission, live Microsoft-client
RDP session, clipboard/desktop or fuzzer infrastructure.
No M1–M6 milestone is promoted by this synthetic security test.
**Next:** R9 adds sanitizer/fuzzing receipts and verifies actual
R3→R8 authorized channel routing when the sole session owner exists.

## R6 ordered DXGI lease and D3D11 map integration (2026-10-16)

**Parent main SHA:** `643d62ae3758ba17494767603141a98abc3dc7b6`. New production
`windows_dxgi_capture_cycle.{h,cpp}` composes the R6 DXGI and
D3D11 RAII helpers. New `windows_capture_cycle_cases.cpp`
is linked into the **existing** R6 test executable and registered
in the one `tests/CMakeLists.txt` registry. The same atomic
commit updates `CMakeLists.txt`, `docs/ROADMAP.md`,
`docs/ARCHITECTURE.md` and this validation record.

**Dedicated conditional native Windows CTests:**
`windows.capture-frame-ordered-lifetime` checks acquire/map
and byte/stride borrow, unmap-before-release, bounded timeout,
GPU-not-ready release, changed monitor layout and destructor.
`windows.capture-frame-cancel-and-topology-rejections` checks
bad wait, reentrant map/capture, access loss, invalid BGRA,
failed release, cancellation in acquire/map/unmap callbacks
and invalid initial layout.

**PASS (sparse offline fixture, not complete project):**
`cmake -S ~/rdp-server -B ~/rdp-server/build
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build ~/rdp-server/build --parallel 2`,
`ctest --test-dir ~/rdp-server/build --output-on-failure`:
**2/2**. Separately strict Linux GCC 14.2 / Clang 17
`-std=c++23 -O1 -g -Wall -Wextra -Wpedantic
-Wconversion -Wsign-conversion -Werror -UNDEBUG` 2/2 each.
Clang 17 ASan/UBSan `-fsanitize=address,undefined
-fno-omit-frame-pointer` 2/2. The sparse fixture used
API-compatible copies of the existing two R6 owner
implementations; full repo CMake/CTest remains NOT RUN locally
because GitHub Git networking could not resolve the host.

**NOT RUN:** owner Windows MSYS2 CLANG64/Clang 23,
owner Linux/X11 and macOS 27 exact-SHA runs; real Desktop
Duplication session, R4 frame encoding/presentation, external
Microsoft client input/desktop, or benchmarks. Hosted exact-SHA
GitHub Actions results require separate verification after
publication. M4 remains open. **Next:** coordinate an explicitly
R2/R3-authorized capture lifecycle and R4 frame ownership.

## R7 native CoreGraphics display observation exact-commit CI (2026-10-15)

**Source SHA:** `3274b39c85b817ef2a56215390bf19cc8aa0e5b4`.
**Exact-source PASS:** [GitHub Actions 38844757901](https://github.com/k1moradi/RDP-server/actions/runs/38844757901):
Ubuntu/GCC **205/205**, macOS/Apple Clang **191/191**, Windows/MSVC
**195/195** full registered CTests in **both Debug and Release**. All
three new `macos.display-snapshot-stable-multi-retina`,
`macos.display-snapshot-geometry-denials`,
`macos.display-snapshot-changed-during-read` tests executed and passed
on every hosted platform. Documentation policy, installed SDK/downstream
consumer, ZIP/checksum artifacts PASS. No live desktop read, TCC prompt,
input event or service was invoked by these ordinary CTests.
**NOT RUN:** owner's independent macOS 27, MSYS2 CLANG64 Clang23,
Linux/X11 terminal one-liner at a nominated common SHA; native
interactive display/TCC/reconfiguration tests, authenticated Microsoft
RDP client and actual desktop, performance/soak. **Next:** R2/R3
authorization and R4 physical frame layout contract before live native
ScreenCaptureKit capture; then independently authorized macOS27 trial.


## R2 TLS-framed authInfo credential CI receipt (2026-10-15)

**Exact code SHA:** `063bcaa1c3cb5b49fbb4be4b84230736fcd6bf7f`.
[Actions 38844600869](https://github.com/k1moradi/RDP-server/actions/runs/38844600869)
**PASS overall:** Linux GCC Debug/Release **195/195** each,
Windows MSVC Debug/Release **185/185** each, macOS AppleClang
Debug/Release **181/181** each. Distinct
`security.gssapi-tls-framed-credential-denials` CTest PASS
on Linux in both modes. Hosted documentation policy, package
and downstream installed SDK consumer PASS. No owner-machine
commands ran; `~/rdp-server` checkout was not available.

**NOT RUN:** isolated positive Kerberos keytab/ticket exchange,
native independently audited OS console session and R3 admission,
owner local Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27,
live Microsoft client, desktop or user interaction.
Gate A remains OPEN; this increment is deny-only.

## R10 Windows handle exact-SHA hosted CI (2026-10-15)

**Code SHA:** `c7676520bb2c360d156004d458d5ed946575297b`,
[Actions 38844859211](https://github.com/k1moradi/RDP-server/actions/runs/38844859211)
**completed SUCCESS**. Hosted GCC/Linux **205/205** Debug and **205/205**
Release full CTests; Clang/macOS **191/191** Debug and **191/191**
Release; MSVC/Windows **199/199** Debug and **199/199** Release.
Windows's four new R10 CTests
`runtime.validates-configuration-windows-regular`,
`runtime.rejects-configuration-windows-directory`,
`runtime.rejects-configuration-windows-relative-file`, and
`runtime.rejects-windows-device-namespace` PASS in both configs.
Downstream installed SDK consumer **1/1 PASS** on each OS, ZIP/SHA256
package/upload and documentation-policy PASS; prerelease SKIPPED
without a protocol version tag. No runtime service was installed or run.

Owner's Linux/X11, Windows MSYS2 CLANG64 **Clang 23**, and macOS 27
terminal one-liners, same-SHA milestone gate, real Microsoft RDP
client, desktop, true OS identity authorization and TLS private-key
ACL checks are **NOT RUN**. The above is developer SDK/runtime CI,
not M1–M6 acceptance. Next R10: per-HANDLE Windows DACL screening
with a new dedicated CTest; intermediate path reparse restrictions
remain outstanding.

## R6 capture-cycle exact-SHA hosted CI receipt (2026-10-16)

Implementation `fd08bd8b5ef07b3a5b8499b1f917eeadc57ca284`,
[Actions run 38844961028](https://github.com/k1moradi/RDP-server/actions/runs/38844961028)
**SUCCESS**. Exact job logs: Ubuntu Linux Debug/Release
**205/205 CTests PASS** each, Windows/MSVC Debug/Release
**201/201 PASS** each (including the new
`windows.capture-frame-ordered-lifetime` and
`windows.capture-frame-cancel-and-topology-rejections`),
macOS Debug/Release **191/191 PASS** each. Documentation-policy,
SDK install/downstream consumer **1/1 per platform**, package
generation and uploads PASS; prerelease publication SKIPPED
(no tag). **NOT RUN:** owner three-platform exact-SHA tests
(especially Windows MSYS2 CLANG64 Clang 23), real independent
Windows session authorization, DXGI hardware frame acquisition,
Microsoft-client desktop/input, graphics presentation, and
performance. R6 M4 remains unaccepted. **Next:** use an agreed
R2/R3-authorized native session and R4's single graphics owner
for synchronous captured-frame transfer and disconnect tests.
## R5 native XFixes cursor failed-connection and cancellation increment (2026-10-15)

**Baseline main:** `991320318e681fba99ca85adf1d29039c3e3137c`; exact new implementation SHA and CI to
be verified after publication. Atomic change: native cursor tracker
`src/x11/x11_cursor_tracker.{h,cpp}`, new
`tests/test_x11_native_cursor.cpp`, Linux native CMake target and
dedicated `x11.cursor-native-connection-denials-and-cancellation`
CTest in existing `tests/CMakeLists.txt`, Linux CI XFixes packages,
and canonical roadmap/architecture/compile/validation documentation.

**Production behavior:** Reject XCB connection error before XFixes
extension negotiation. `disconnect()` clears borrowed XCB pointer,
pixel/mask cache, cursor geometry, event pending and warning state
without issuing XCB requests. Subsequent tracker getters, refresh
and event handling fail closed even after the owning XCB connection
has been destroyed. No ownership transfer or copied socket fd.

**New dedicated native CTest:** A deliberately invalid XCB file
descriptor exercises actual tracker initialization failure; then
cancellation, parent XCB destruction, idempotent cancellation and
post-destruction denied calls. Test needs XCB/XFixes development
libraries but no X server or display access. The existing headless
cursor-reply bounds and conversion tests are preserved.

**PASS (previous R5 readiness implementation, not this new code):**
`f46a9a47751aafbf30419851f4df40213d1e3f52`
[Actions 38800928607](https://github.com/k1moradi/RDP-server/actions/runs/38800928607)
Linux 191/191 Debug+Release CTests, including real XCB/RandR
compilation and native event tests; macOS 178/178 and Windows
182/182 each configuration.

**NOT RUN locally for this increment:** strict native XFixes C++
translation-unit compilation (authoring container lacks
`xcb/xfixes.h`), canonical full project CMake/CTest (no full checkout
and GitHub DNS unavailable), new exact-SHA CI, owner independent
Linux/X11, MSYS2 CLANG64/Clang23 and macOS27, live Microsoft
RDP client/authorized desktop, R2 OS admission/R3 routing/R4
graphics-cursor consumer, and performance/latency benchmarks.
**Next:** verify new exact-SHA Linux native target/CTest and full
Windows/macOS regression; integrate connected capture/cursor/damage
teardown and resize only behind R2/R3 authorization.

## R5 XFixes native cursor exact-SHA hosted validation (2026-10-15)

**Production commit:** [`c4aedf8d4dbc2e0732b43bd7df273dea47e94d85`](https://github.com/k1moradi/RDP-server/commit/c4aedf8d4dbc2e0732b43bd7df273dea47e94d85);
[GitHub Actions 38845314257](https://github.com/k1moradi/RDP-server/actions/runs/38845314257)
**completed SUCCESS** on exact implementation SHA.

**Linux/GCC Debug and Release:** real `x11_cursor_tracker.cpp`
and `cursor_image_conversion.cpp` built and linked into
`rdp-server-linux-xfixes-cursor` with XCB/XFixes development
libraries. The new dedicated native
`x11.cursor-native-connection-denials-and-cancellation` passed
in both modes. Full registered CTests **208/208 PASS** in both.
Existing native capture, XCB event tests and SDK check remained
green. No X display or protected desktop was opened.

**macOS/Clang Debug and Release:** **193/193** PASS each.
**Windows/MSVC Debug and Release:** **203/203** PASS each.
Linux-only native XFixes CTest was NOT RUN on those OSes by design.
Documentation policy and SDK install/consumer/archive/digest
workflow stages PASS.

**NOT RUN:** owner's separate three-platform exact-SHA full commands
(Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS 27), actual
authenticated Linux session and native OS authorization, licensed
Microsoft-client desktop, live XFixes shape/resize/refresh,
R4 cursor frame delivery, and performance benchmarks. M1 and M3
remain NOT ACCEPTED. **Next R5:** integrate native capture/cursor/
damage lifetimes with X11 connection ownership and R2/R3-approved
R4 graphics consumption, preserving no-capture-before-admission.

## R1 bounded nonblocking listener accept budget (2026-10-15)

**Parent `main`:** `0914dba9cab11eb6bee928915cad1d7da5435fef`. **Production:** reuse one
`acceptNonblockingTcpConnection` per iteration up to 16, preserve
caller-owned nonblocking listener, transfer each move-only handle
into a no-throw callback once, return explicit budget/drain/stop/
failure outcomes and accepted count. Does not bind/listen, poll
forever, allocate a queue or allow unauthenticated sessions.
**New dedicated CTests:**
`transport.tcp-native-accept-batch-budget-handoff` (three sequential
loopback peers, bounded budgets and exact X.224 Confirm without
assuming the OS allows more than one pending connection)
and `transport.tcp-native-accept-batch-stops-denials` (invalid
inputs, non-listener failure, callback refusal closes one accepted
socket, post-progress drain and listener preservation). Reuse
`tests/test_owned_preauth_session.cpp` and the central registry.
**PASS at baseline:** hosted Actions 38801211658 Linux,
Windows, macOS and policy jobs at source SHA
`991320318e681fba99ca85adf1d29039c3e3137c`.
**NOT RUN at authoring:** new-code CMake/CTest (worker has no
repository checkout and cannot clone github.com), new exact SHA
GitHub CI, owner's Linux/X11, Windows MSYS2 CLANG64 Clang23 and
macOS27 acceptance, live Microsoft RDP client, R2 authentication
and independent OS authorization, R3 session and desktop.
**Next:** converge the borrowed listener's fairness/budget with
R10 runtime scheduling and separately authorized R2/R3 handoff.

## R7 CoreGraphics to DesktopDisplayGeometry integration (2026-10-16)

**Production:** `native_display_geometry.{h,cpp}` uses existing
`NativeDisplaySnapshot` (new `CGDisplayRotation` evidence) and the
existing `DesktopDisplayGeometry`. CMake adds one source to existing
Apple-only adapter and portable test fixture; R7 tests reused, no new
binary/controller. Four dedicated offline CTests:
`macos.geometry-native-single-retina`,
`macos.geometry-native-uniform-multi-display`,
`macos.geometry-native-mixed-scale-denials`,
`macos.geometry-native-generation-refresh`.
**PASS, sparse local fixture only:**
`cmake -S ~/rdp-server -B ~/rdp-server/build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON`; `cmake --build ~/rdp-server/build --parallel 2`;
`ctest --test-dir ~/rdp-server/build --output-on-failure`: 4/4.
GCC14.2 C++23 -O2 strict 4/4; Clang17 ASan/UBSan 4/4.
**NOT RUN:** exact-commit hosted CI before publication, owner's macOS27,
Windows MSYS2 CLANG64 Clang23 and Linux/X11 one-root CTests; real
CoreGraphics screen reading, ScreenCaptureKit, client input/cursor,
authenticated OS admission and benchmarks. **Next:** exact-SHA Actions,
then R4 mixed-scale physical placement and R2/R3-authorized capture.

## R1 backlog-independent portable fixture adjustment (2026-10-15)

**Previous batch-accept commit:** `c3b10eecf9f76d550d09f6601c3095130ff94b95`,
[Actions run 38848654322](https://github.com/k1moradi/RDP-server/actions/runs/38848654322).
**PASS:** Linux/GCC **210/210** Debug and Release; macOS/AppleClang
**195/195** Debug and Release, including both new R1 accept-batch
tests and downstream SDK CTest. **Windows/MSVC:** Debug compiled
PASS but CTest remained in progress while fixture required three
simultaneous pending clients behind a listener initially configured
with backlog 1; do NOT claim Windows FAIL or PASS without logs.
**Adjustment:** Preserve three real clients and budget-one/two
handoff assertions, but connect client two AFTER acceptance of the
first socket, and connect client three from the callback AFTER
acceptance of client two; this never assumes any Windows/POSIX
backlog depth beyond one. No production API/implementation change,
no broad retry, no suppressed assertions. Corrected exact-SHA hosted
CI and owner Linux/X11, Windows CLANG64 Clang23 and macOS27
**NOT RUN at authoring**. R2 authenticated identity/R3 session
and real Microsoft desktop remain NOT ACCEPTED.

## R7 native display converter relative-scale and fixture correction (2026-10-16)

**Original implementation:** `2427cdea0f0aa866e1b8fe8caa53f119317225bf`.
**Correction:** Use proportional common-scale tolerance for very small
scale factors, and initialize the full mirrored pair of mixed-scale
native test observations before the expected denial. Generation CTest
now describes its actual 2x to 1.5x backing-resolution change.
**PASS (sparse fixture):** GCC14.2 one-root Debug CTest 4/4, Clang17
strict C++23 ASan/UBSan 4/4. **NOT RUN at authoring:** corrected-source
full GitHub Actions or owner macOS27/Windows CLANG64 Clang23/Linux
one-root tests; live ScreenCaptureKit, TCC, client input and performance.
No OS admission, permission or graphics scheduler behavior changed.

## R9 native Clang clipboard sanitizers CI (2026-10-15)

**Parent `main`:** `8083958d617daff00bf68f02848a11eab416bd7d`. **Files changed:**
`.github/workflows/ci.yml`, `docs/ROADMAP.md`,
`docs/CODEX_VALIDATION.md`; no production or test-source changes.
**New native CI job:** `r9-clipboard-sanitizers` (Ubuntu/Clang,
real production-linked `test_owned_remote_transfer` and
`test_clipboard_protocol`). Configure `build/` once for
C++23 Debug with `-fsanitize=address,undefined`,
`-fno-omit-frame-pointer`, and `-fno-sanitize-recover=all`,
then build both existing CMake test targets and execute
`ctest --test-dir build --build-config Debug -L clipboard
--output-on-failure` under `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`
and `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
The central CTest registry's `clipboard` label remains
the sole test enumeration. Explicitly excludes native desktop,
live OS/user state, Kerberos, RDP session activation and the
unimplemented authenticated R3 router. Linux GSSAPI opt-ins
are disabled in this focused sanitizer job, not in normal CI.
Existing normal Linux/macOS/Windows Debug+Release and package
jobs remain unchanged. Earlier R9 `4eb24cd9312e1d3e133811a8c3a9151cebab4501`
[Actions 38844672159](https://github.com/k1moradi/RDP-server/actions/runs/38844672159)
**PASS:** Linux 202/202, macOS 188/188, Windows 192/192
in both configurations; these ordinary hosted results
are NOT sanitizer evidence.

**NOT RUN at authoring:** exact-new-commit Clang ASan/UBSan
CI and full owner's `~/rdp-server/build` command (direct
GitHub clone hostname unavailable in this worker); owner's
Windows MSYS2 CLANG64 Clang23/macOS27/Linux X11 runs;
live authenticated R2/R3 admission, physical clipboard,
Microsoft RDP client and desktop. **Next:** inspect first
ASan/UBSan CI failure if any and repair at the true
production/test boundary, then record exact-SHA PASS/FAIL.

## R4 first compiled AVC420 picture and Annex-B wire packetization (2026-10-15)

**Parent `main`:** `9e4d33b60ca87606cd66625c4212b326d98b5204`. The production portable
`gfx_avc420_picture.{h,cpp}` emits one
RDPGFX_START_FRAME_PDU (16), one WIRE_TO_SURFACE_PDU_1 with AVC420
RFX_AVC420_METABLOCK/quant qualities and a complete borrower-supplied
H.264 Annex-B bitstream, and one END_FRAME_PDU (12), using checked
wire sizes and output spans. Regions are RECT16 left/top/right/bottom;
quant qualities correspond 1:1 to the mask rectangles. Minimum
Annex-B prefix and NAL header are syntax preflight only; a real
x264 encoder remains a necessary producer. Source data is moved
before writing headers to allow overlap. The older unlinked
`gfx_avc420_frame.cpp` packet builder did not contain H.264 bytes
and cannot be used for live transmission.

The sole central `tests/CMakeLists.txt` registers three new
production-backed CTests: `graphics.avc420-picture-wire`,
`graphics.avc420-picture-rejections`,
`graphics.avc420-picture-overlap`. Golden PDU field assertions,
bounds/metadata/input denials, buffer atomicity and NAL overlap
are validated offline. Normative: MS-RDPEGFX §§2.2.2.1,
2.2.2.11-12, 2.2.4.4-4.4.2.

**NOT RUN at authoring:** local full canonical repository CMake/CTest
(no complete checkout and `git ls-remote` fails DNS), owner's
Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS 27 one-root
tests, real x264 encoding, authenticated R2/R3 graphics channel,
Microsoft-client desktop and graphics benchmarks.
Verify exact commit hosted CI after publication; do not claim
that deterministic synthetic Annex-B fixture is a valid H.264
picture or accepted real-client graphics.
**Next R4:** wire production AVC420 packetization through R4's
existing single frame receipt and R3's authorized DVC writer,
then statically integrate a license-reviewed pinned x264 encoder.

## R5 native XDamage denial and teardown integration (2026-10-15)

**Baseline main:** `4d091d3d41ac74e1bf7692721c425f52317c5373`; new exact implementation SHA and
hosted CI result pending publication. Source: existing
`src/x11/x11_damage_tracker.{h,cpp}`, new
`tests/test_x11_native_damage.cpp`, noninstalled Linux-native
`rdp-server-linux-xdamage` CMake target with existing
`src/core/damage_region.cpp`, one dedicated CTest in the shared
`tests/CMakeLists.txt`, `libxcb-damage0-dev` in existing Linux CI,
and canonical roadmap, architecture, compilation and this ledger.
No new RDP process, X11 connection owner, capture engine or scheduler.

**Implementation:** reject failed XCB objects before querying
XDamage extensions. Provide `disconnect()` with deterministic
server-side XDamage resource release on healthy XCB connections,
invalidate borrowed XCB connection and local resource IDs, clear
pending/coalesced rectangles and observation history, and make
repeated teardown and subsequent handler/snapshot calls fail closed.
Destructor calls `disconnect()`. Offline test constructs tracker
against `xcb_connect_to_fd(-1,nullptr)`, checks failure reason,
snapshot rejection and no observations, calls disconnect before
`xcb_disconnect`, then verifies repeat cancellation and method
calls after the connection owner's destruction. It does not connect
to an X11 display or invoke any protected desktop operation.

**NOT RUN locally:** native `xcb/damage.h` translation-unit
compilation and full canonical project CMake/CTest (no full checkout
and missing XCB-Damage development packages); exact-new-SHA hosted
CI, owner's independent Linux/X11, MSYS2 CLANG64/Clang23, macOS 27,
real licensed Microsoft client desktop, R2 OS admission, R3 input
routing, R4 frame consumer and repeatable performance benchmarks.
Earlier published native R5 XFixes commit
`c4aedf8d4dbc2e0732b43bd7df273dea47e94d85` completed
[Actions 38845314257](https://github.com/k1moradi/RDP-server/actions/runs/38845314257)
SUCCESS but does not validate this new XDamage source.
**Next:** verify real native XDamage build and CTest on exact-SHA
Linux hosted CI, plus Windows/macOS regressions; then implement
connection-owner teardown and resize ordering across damage,
cursor and XShm without activating protected desktop access.

## R10 Windows opened-HANDLE DACL broad-write regression (2026-10-15)

**Road:** R10 secure runtime configuration, parent `2f3b0ea12d7324cfd501ec25665fc02e030b0469`.
**Production:** add `GetSecurityInfo(SE_FILE_OBJECT)` with the existing
file handle, release its descriptor via `LocalFree` RAII, reject
null/invalid DACL/owner and unexpected allow-ACE kinds, and reject
broad principals with write, append, delete, owner or DACL changes.
`rdp-server` links Advapi32 on Windows only. POSIX reader and
unconditional startup refusal remain unchanged.

**New dedicated Windows-only CTests** in the canonical registry:
`runtime.validates-configuration-windows-private-dacl`,
`runtime.rejects-configuration-windows-everyone-write`,
`runtime.rejects-configuration-windows-authenticated-write`,
`runtime.rejects-configuration-windows-users-write`. The existing
test CMake script creates private fixture ACLs and explicit broad
grants with built-in Windows `icacls` only inside `build/`.
**NOT RUN at authoring:** native Windows compilation (no Windows
toolchain available in this environment), full local repository
CTest (GitHub checkout unavailable from local container),
exact-commit GitHub Actions, owner Linux/X11 / Windows MSYS2
CLANG64 Clang23 / macOS27 tests, real credentials, NLA,
desktop and release acceptance. Next: inspect exact-SHA CI;
expand to complete effective Windows DACL trustees and TLS key
permissions. M1–M6 remain OPEN.

## R7 native-to-portable geometry exact-source hosted CI (2026-10-16)

**Initial production:** `2427cdea0f0aa866e1b8fe8caa53f119317225bf`.
**First failure:** [Actions 38849090483](https://github.com/k1moradi/RDP-server/actions/runs/38849090483)
failed Debug on Ubuntu and macOS only in
`macos.geometry-native-mixed-scale-denials`, because a synthetic
second display lacked identity/dimensions; it asserted before the
intended production converter denial was tested.
**Corrected source:** `8083958d617daff00bf68f02848a11eab416bd7d`
initializes that display, documents the actual scale-generation change,
and compares all finite Retina scale ratios with relative tolerance.
**Exact-SHA PASS:** [Actions 38849245902](https://github.com/k1moradi/RDP-server/actions/runs/38849245902)
completed Ubuntu/GCC **216/216**, macOS/Apple Clang **201/201**,
Windows/MSVC **215/215** registered CTests in **both Debug and Release**.
All four dedicated R7 native geometry tests pass on every hosted OS.
Documentation-policy, installed downstream protocol SDK consumer and
ZIP/checksum artifact tasks PASS. Hosted Apple frameworks compiled and
linked via the existing `rdp-server-macos-capture` static target.
**NOT RUN:** owner's macOS27 full one-root CTest, Windows CLANG64 Clang23
and Linux/X11 independently tested common SHA, live CoreGraphics
screen sampling, ScreenCaptureKit, genuine R2/R3 admission, remote
input/cursor/clipboard and current Microsoft client, performance.
**Next:** coordinate R4 compositor ownership for mixed Retina layouts,
then a narrowly scoped R2/R3-approved ScreenCaptureKit callback lifecycle
with generation, cancellation, permission denial and revocation tests.

## R1 native accept-batch watchdog (2026-10-15)

**Integration parent:** `927b34591d7cac9506d132ad844c2185fa419efa`. Earlier native accept-batch
`c3b10eecf9f76d550d09f6601c3095130ff94b95` CI run
[38848654322](https://github.com/k1moradi/RDP-server/actions/runs/38848654322):
**PASS Linux 210/210, macOS 195/195 Debug and Release**;
**Windows Debug IN PROGRESS** and no Windows CTest result observed.
Portability correction `16ec8326ef2be45d56f2e87e49f907635a314eb8`
[run 38849165118](https://github.com/k1moradi/RDP-server/actions/runs/38849165118):
new R1 native batch cases **PASS** Linux and macOS Debug.
Full Debug **FAIL Linux 215/216, macOS 200/201** due to unrelated
R7 `macos.geometry-native-mixed-scale-denials` at fixture
`test_macos_capture_pixel_buffer.cpp:552` ([Issue #12](https://github.com/k1moradi/RDP-server/issues/12)).
Windows full Debug still IN PROGRESS in both runs when checked.
To bound further diagnostics, register **TIMEOUT 20** on the
two existing R1 batch CTests only; no code or assertions change.
**NOT RUN:** new timeout SHA hosted CI, owner Linux/X11,
Windows MSYS2 CLANG64 Clang23, macOS27, live Microsoft client,
R2 user authorization/R3 OS session and desktop.

## R5 native XDamage exact-SHA hosted CI receipt (2026-10-15)

**Production commit:** [`2f3b0ea12d7324cfd501ec25665fc02e030b0469`](https://github.com/k1moradi/RDP-server/commit/2f3b0ea12d7324cfd501ec25665fc02e030b0469).
[GitHub Actions 38849416185](https://github.com/k1moradi/RDP-server/actions/runs/38849416185)
**completed SUCCESS** on exact implementation SHA.

**Linux/GCC Debug/Release PASS:** the actual
`src/x11/x11_damage_tracker.cpp` compiled with real XCB-Damage
development packages and linked into `rdp-server-linux-xdamage`.
The dedicated headless
`x11.damage-native-connection-denials-and-cancellation` CTest
passed in Debug and Release; full CTests **217/217 PASS** in each.
No desktop/window capture, input injection or credentials used.

**macOS/Clang full CTests:** **201/201 PASS** Debug and Release.
**Windows/MSVC full CTests:** **215/215 PASS** Debug and Release.
XCB-Damage source/test is Linux-only and NOT RUN on other OSes.
Documentation policy, SDK stage/consumer/install/package/digests
and the additional R9 clipboard sanitizer job all PASS.

**NOT RUN:** owner's independently built Linux/X11,
Windows MSYS2 CLANG64 Clang23 and macOS27 exact-SHA one-liners;
authenticated Kerberos/CredSSP and independently approved R2 OS
session, R3 remote desktop/input routing, R4 H.264 graphics and
cursor consumer, live Microsoft RDP client interaction, real
native event/damage/capture multi-component teardown and resize,
and repeatable capture/performance benchmarks. M1/M3 NOT ACCEPTED.
**Next R5:** bring one XCB owner, XShm, XFixes and XDamage
through ordered invalidation/resize using deterministic tests,
without allowing protected operations before OS authorization.

## R10 Windows DACL exact-SHA hosted CI acceptance (2026-10-15)

**Implementation:** `9dedd0b6608ec826e850dc8d8706f0af46d2b287`.
[GitHub Actions 38849455579](https://github.com/k1moradi/RDP-server/actions/runs/38849455579)
**COMPLETED SUCCESS**. Hosted Ubuntu/GCC Debug **217/217**
and Release **217/217** full CTests; hosted macOS/Clang Debug
**201/201** and Release **201/201**; hosted Windows/MSVC Debug
**219/219** and Release **219/219**. Windows runtime DACL
behavior cases `validates-configuration-windows-private-dacl`,
`rejects-configuration-windows-everyone-write`,
`rejects-configuration-windows-authenticated-write` and
`rejects-configuration-windows-users-write` explicitly
PASSed in both Windows configurations. Each OS's SDK install/
downstream consumer **1/1 PASS**, ZIP/SHA256 packaging and
artifact upload PASS. Documentation-policy PASS and R9
clipboard sanitizer job PASS. Protocol prerelease SKIPPED
because no matching version tag was created.

**NOT RUN:** owner's Linux/X11, Windows MSYS2 CLANG64 with
Clang 23 and macOS 27 same-SHA command, native authenticated
Microsoft-client/OS desktop access, TLS key/certificate file
authorization, independent R2/R3 identity/session and complete
Windows DACL effective access for unknown principals. Windows
hosted MSVC CI is not owner Clang23 acceptance.
M1–M6 remain OPEN and protocol-only SDK ZIPs are not a
deployable server. **Next R10:** secure actual certificate/
private-key files and directory-reparse/ACL boundaries with
new dedicated CTests, while startup stays disabled.


## R9 exact-SHA Clang sanitizer CI receipt (2026-10-15)

Exact SHA `9e4d33b60ca87606cd66625c4212b326d98b5204`,
[GitHub Actions 38849272774](https://github.com/k1moradi/RDP-server/actions/runs/38849272774),
completed SUCCESS. New CI job `r9-clipboard-sanitizers` used one
checkout-local `build/`, first-party Clang C++23 Debug with combined
AddressSanitizer/UndefinedBehaviorSanitizer and leak detection:
`ctest --test-dir build --build-config Debug -L clipboard --output-on-failure`
**12/12 PASS**, no sanitizer/leak diagnostics. All R9 joined-channel,
nested MCS/CLIPRDR length, format-response framing and chunk-reassembly
CTests passed. Normal Linux/GCC **216/216**, macOS/Clang **201/201**
and Windows/MSVC **215/215** Debug and Release full CTests PASS,
plus documentation policy and installed SDK packaging. No first failing
hosted CI boundary. NOT RUN: local checkout CTest (GitHub DNS unavailable),
owner Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS27, sanitizer
cases outside clipboard, unbounded libFuzzer corpus, real Microsoft client,
NLA/OS authorization and live desktop. Next R9: add bounded sanitizer
seeds or real R3-to-R8 authorized channel dispatch tests when implemented.

## R1 bounded accept-batch cross-platform full CI receipt (2026-10-15)

**Production implementation:** `c3b10eecf9f76d550d09f6601c3095130ff94b95`;
**test fixture sequencing:** `16ec8326ef2be45d56f2e87e49f907635a314eb8`;
**per-CTest timeout:** `2d03a9bd0bebf7697231322c07d0fa594ef6b0d1`.
**Exact-SHA hosted CI [Actions 38849575634](https://github.com/k1moradi/RDP-server/actions/runs/38849575634) SUCCESS:**
Linux/GCC **218/218 Debug and Release**, macOS/AppleClang
**202/202 Debug and Release**, Windows/MSVC **220/220 Debug
and Release**. Both named R1 native acceptance CTests
`transport.tcp-native-accept-batch-budget-handoff` and
`transport.tcp-native-accept-batch-stops-denials` PASS in
all six hosted configurations. Documentation-policy PASS,
R9 clipboard sanitizer PASS, all hosted installed SDK downstream
consumer checks PASS, SDK package ZIP/SHA256 PASS; prerelease
SKIPPED (no release tag).

**Commands:** hosted workflow runs ordinary `cmake -S . -B build`
with `BUILD_TESTING=ON`, builds Debug/Release in one build root,
`ctest --test-dir build -C Debug/Release --output-on-failure` and
SDK consumer tests; owner exact-command reports NOT RUN.
**NOT RUN:** owner's separately nominated Linux/X11,
Windows MSYS2 CLANG64 Clang23 and macOS27 platform checks,
real Microsoft client, server listener/service activation,
R2 authenticated identity and OS authorization, R3 channel/
share progression, graphics and desktop. Synthetic X.224/TLS
accept handoff alone does not accept Gate A or M2.
**Next R1:** R10's bounded live listener schedule and R2/R3
authorization integration under existing one-owner contracts.







## R2 native-session-change R3 revocation callback (2026-10-16)

**Authoring parent:** `aac9c86a17f7489a0523dc1ae4f0591b39b44817`. The R2->R3 Basic Settings handoff
`70897645ed1f822c081747024a847a0928e18f15` already has exact-SHA hosted
success in Actions 38873422752, and the later R3 follow-up restored its
dedicated CTest registration on current main.

This increment adds
`LinuxConsoleAdmissionBroker::onNativeSessionChangeReady()`. It is a
revocation-only event-loop hook for readiness on the concrete broker-owned
logind monitor. `Changed` or `Unavailable` closes the sole R3
`McsSessionLifecycle` before revoking R2/GSS; missing/unissued watch state
takes the same terminal path. `None` is treated only as a spurious wake and
does not replace the existing `authorizes()` check required before every
protected R3 transition.

**Dedicated CTest:** `security.gssapi-r3-native-change-revocation`, using
no real Kerberos or login. It verifies missing-watch fail-closed behavior,
R3 and licensing teardown, hidden native-fd state, GSS rejection and
late/repeated callback replay denial. The existing
`security.gssapi-r3-mcs-admission-contract` remains registered.

**NOT RUN at authoring:** local single-root build/CTest (no checkout in this
agent environment), exact-SHA hosted CI until publication, genuine positive
Kerberos/TLS/native-logind admission followed by a real session-change
event, R1 runtime disconnect composition, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27 and Microsoft client. Gate A/M2 remain
**OPEN/NOT ACCEPTED**. **Next:** re-authorize the same admission/session
generations immediately before R3 Connect Response write ownership and later
protected transitions, and preserve R3 -> R2/GSS -> R1 teardown ordering.

## R2 Linux native admission lease boundary (2026-10-16)

**Authoring parent:** `7f6d74b4ef9b03c86ecabc7c56af6f1de071ad07`. New production files:
`src/server/security/linux_console_admission.{h,cpp}`; updated the existing
GSS acceptor TLS-provenance accessor, policy generation fence, Linux GSS
target source/linkage, `test_linux_gssapi_spnego.cpp`, central CTest
registry, roadmap, architecture and this ledger.

`LinuxConsoleAdmissionLease` is move-only, non-default-constructible and
has a private constructor. Only `LinuxConsoleAdmissionBroker` can mint it.
The broker has no generic evidence-source parameter: successful issuance
requires the concrete native NSS/logind reader and concrete logind change
monitor, after a genuine provider-derived GSS principal is rechecked against
the exact active pinned TLS certificate. Policy generation, physical
session/UID/generation, freshness and watch quietness are required.
Protected use goes through `authorizes()`, which revalidates those facts
and the permission mask. Lease destruction, explicit revoke, policy epoch
change and a one-second missed-revalidation deadline are terminal. The
residual race is explicit: logind may change after the final poll but before
R3 acts, so R3 must monitor the native fd and validate immediately before
protected state.

**Dedicated CTest:**
`security.gssapi-native-os-admission-capability-denials`. It statically
checks that the lease cannot be default/copy constructed and that an
arbitrary `ConsoleOsEvidenceSource` has no issuance overload, then executes
production denial/replay paths with no verified GSS/TLS identity and checks
successful policy mutations advance the revocation epoch while rejected
mutations do not. The ordinary test does **not** fabricate a positive
production admission capability.

**NOT RUN at authoring:** local one-root compile/CTest because this agent has
no repository checkout; exact-SHA Actions until publication; real positive
Kerberos + native logged-in physical console issuance; R3 capability
consumption; owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27;
Microsoft-client desktop. This creates a genuine production-only issuance
contract but does not yet prove a positive host admission or integrate R3,
so Gate A/M2 remain OPEN/NOT ACCEPTED.

**Exact-SHA hosted CI:** implementation
`03f2edbbfaa9049e7d6a22f22c11c94d9ad91213`,
[Actions 38872022770](https://github.com/k1moradi/RDP-server/actions/runs/38872022770)
overall **FAIL**, with the sole failing platform boundary outside R2:
macOS Debug compilation of concurrent R10
`src/server/runtime/main.cpp` fails under OpenSSL 3.6 because
`X509_cmp_current_time` is deprecated and warnings are errors. R2's
optional Linux GSS target, including the new concrete admission broker,
compiled successfully. Linux/GCC full CTest **287/287 PASS** in Debug and
Release; the dedicated
`security.gssapi-native-os-admission-capability-denials` passed in both.
Windows/MSVC full CTest **285/285 PASS** in Debug and Release.
`r9-security-protocol-sanitizers` and `documentation-policy` passed;
Linux/Windows SDK downstream and package verification passed. macOS
CTest/Release/package steps were **NOT RUN** after the unrelated R10
compile failure. No R2-introduced failure is observed.

Real positive Kerberos plus matching native physical-console issuance,
R3 consumption, owner's Linux/X11, MSYS2 CLANG64/Clang23 and macOS27, and
Microsoft-client desktop remain **NOT RUN**. Gate A/M2 remain
**OPEN/NOT ACCEPTED**. **Next:** R3/R1 lifecycle consumption and disconnect
revocation of the R2 lease.

## R2 CredSSP TLS release certificate continuity (2026-10-16)

**Starting main:** `a603976a07d5a525aee20f75ba74e40f77ec9314`.
Changed `credssp_tsrequest.{h,cpp}`, the existing
`test_owned_preauth_session.cpp` fixture/dispatcher,
`tests/CMakeLists.txt`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`
and this ledger. `TsRequestFrameReader::releaseFrame()` now checks
`completedFrameServerTls()` before releasing a TLS-derived complete
frame. Same-`SSL*` certificate substitution closes and cleanses the
reader instead of releasing stale bytes; stable certificate identity can
release/reuse normally. Manual offline parser release remains compatible.

**Dedicated CTest:** `security.credssp-tls-release-certificate-denial`.
It exercises a real OpenSSL memory-BIO handshake, two stable released
frames on one unchanged SSL/certificate, same-SSL selected-certificate
substitution at the completed-frame release boundary, terminal DER/
provenance cleanup and replay denial, plus offline `consume()` release
and explicit-close behavior. No real credentials, login or desktop.

**PASS at authoring:** current-main source/test-registration review.
**NOT RUN at authoring:** local focused/full CTest because this sandbox
has no repository checkout and github.com DNS is unavailable; exact-SHA
hosted Actions until publication; real positive Kerberos; independent
native OS admission; owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27. `ConsoleAdmissionGate` remains deny-only/CandidateOnly and R3
still has no genuine revocable admission capability. Gate A and M2 remain
OPEN/NOT ACCEPTED.

**Exact-SHA hosted CI:** implementation
`ff72dbac77c881858279a2e7db753a1a5fac6c92`,
[Actions 38865066667](https://github.com/k1moradi/RDP-server/actions/runs/38865066667)
**SUCCESS**. Full ordinary CTest in both Debug and Release:
Linux/GCC **272/272**, macOS/Clang **254/254**, Windows/MSVC **270/270**.
The dedicated `security.credssp-tls-release-certificate-denial` passed
in all six configurations. `r9-security-protocol-sanitizers` and
`documentation-policy` passed; install/downstream/package verification
also passed. Prerelease publication skipped as expected without a tag.
Owner Linux/X11, MSYS2 CLANG64/Clang23 and macOS27, positive real Kerberos,
independent native OS admission, R3 authenticated activation and Microsoft
client remain **NOT RUN**. **Next:** the smallest audited native OS
authorization broker/lease boundary that cannot be minted by fake
`ConsoleOsEvidenceSource` implementations.

## R2 GSS-to-OS evidence provenance deny-only gate (2026-10-15)

**R2 main-only source+test+docs increment; exact parent** is
the publication HEAD. The optional Linux GSS target now compiles
the preexisting `ConsoleAdmissionGate`, `ConsoleIdentityPolicy`
and `ConsoleOsEvidenceInspector`. The new
`ConsoleAdmissionGate::requestWithOsEvidence` demands a
genuinely verified GSS principal with the unchanged selected
TLS X.509 before it can sample even read-only candidate OS
account/console facts. It never exports CandidateOnly or
authorizes a session and always closes/rejects its GSS provider.
The legacy caller-constructed policy snapshot cannot query
policy, grant access or avoid terminal rejection.

**New dedicated Linux GSS CTest:**
`security.gssapi-console-provenance-before-os-read` in the
existing `test_linux_gssapi_spnego` executable; it confirms
a fake source directly yields CandidateOnly while the real gate
performs ZERO OS reads on unconfigured, failed-keytab, replay
or caller-snapshot requests. No real login, keytab or desktop.

**PASS at authoring:** production-source/registry/source-build
linkage review. **NOT RUN at authoring:** owner checkout
focused/full CTest (unavailable); exact commit Actions
(until published); approved isolated positive Kerberos,
independent OS login-session authorization and owner's three
platforms. R2 Gate A remains OPEN; next verify hosted CI and
audited, revocable OS identity/session capability for R3.

## R9 MCS and CredSSP native sanitizer extension (2026-10-15)

**Implementation parent SHA:** `90c17fc19fe17ddc6e87ed712d8b22f5484eb4d6`. Updated:
`.github/workflows/ci.yml`, `docs/ROADMAP.md`,
`docs/CODEX_VALIDATION.md`. Existing production/tests and
central `tests/CMakeLists.txt` remain unchanged.
**Replaced rather than duplicated CI job:** `r9-security-protocol-sanitizers`
runs Ubuntu/Clang C++23 Debug, `-fsanitize=address,undefined
-fno-omit-frame-pointer -fno-sanitize-recover=all`,
`-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined`.
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`
apply to both CTest steps. Reuses one `build/`.
Five production-linked binaries compiled:
`test_owned_remote_transfer`, `test_clipboard_protocol`,
`test_owned_mcs_connect_initial`,
`test_owned_credssp_tsrequest`, `test_owned_credssp_binding`.
Runs all `-L clipboard` CTests and ten additional existing
named CTests: `transport.mcs-envelope-tpkt-errors`,
`transport.mcs-envelope-ber-errors`,
`transport.mcs-envelope-mutations`,
`transport.mcs-send-data-joined-denials`,
`transport.mcs-join-stale-write-receipts`,
`transport.mcs-join-stale-partial-write-slices`,
`security.credssp-der-rejections`,
`security.credssp-der-bounds`,
`security.credssp-der-mutations`, and
`security.credssp-binding`.
All are headless bounded production-contract tests using
the existing registry, not an independent fuzzing engine.

**PASS pre-implementation:** existing original clipboard
ASan+UBSan job at `9e4d33b60ca87606cd66625c4212b326d98b5204`,
[Actions 38849272774](https://github.com/k1moradi/RDP-server/actions/runs/38849272774)
12/12. **NOT RUN for this new SHA at authoring:**
actual expanded Actions sanitizer CI, normal three-OS CI,
owner single-root Linux/X11, Windows MSYS2 CLANG64 Clang23
and macOS27 commands, live TLS/NLA/OS admission and Microsoft-client
desktop or clipboard. **Next:** exact SHA build/test/sanitizer
receipts, triage first failing boundary if any, retain
existing full CTest and SDK/package gates.

## R7 fail-closed native display refresh epochs (2026-10-16)

**Production:** `src/platform/macos/native_display_refresh.{h,cpp}`;
`NativeDisplayGeometryRefresh` is a generation guard over existing
`NativeDisplaySnapshot::read` and `makeDesktopGeometry`. It owns a
complete optional mapping, not a second framebuffer/scheduler. Every
refresh invalidates old geometry before two-sample enumeration. A failed
native read, invalid configuration, explicit invalidate or stale generation
rejects virtual-to-logical input and logical-to-pixel queries. Native
`refreshNative()` only calls the previously implemented read-only Quartz
enumerator; ordinary tests do not touch the user's desktop.
**Changed together:** top-level and central tests CMake,
`tests/test_macos_capture_pixel_buffer.cpp`, existing roadmap,
architecture and this ledger. **Three dedicated CTests:**
`macos.desktop-geometry-epoch-refresh`,
`macos.desktop-geometry-epoch-invalidate`,
`macos.desktop-geometry-epoch-failed-refresh`.
**PASS (isolated Linux C++23 fixture, NOT full repository):**
`cmake -S ~/rdp-server -B ~/rdp-server/build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
`cmake --build ~/rdp-server/build --parallel 2`,
`ctest --test-dir ~/rdp-server/build -C Debug --output-on-failure`
=> **7/7 PASS** (three new + four earlier fixture cases). GCC14.2
strict `-O2 -Werror -D_GLIBCXX_ASSERTIONS`: 3/3 new behaviors PASS.
Clang17 C++23 strict ASan/UBSan: 3/3 new behaviors PASS.
**NOT RUN at authoring:** full canonical checkout CMake/CTest, exact-SHA
hosted CI, owner macOS27, MSYS2 CLANG64 Clang23, Linux/X11 one-root,
interactive ScreenCaptureKit/TCC, R2/R3 authorized session, Microsoft
client, pointer/cursor and performance. **Next:** native display-change
callback (opt-in per-user runtime) and R2/R3/R4-controlled capture
ownership/physical mixed-Retina composition; M1/M5 not accepted.

## R10 POSIX secure-fixture umask independence (2026-10-15)

**Parent GitHub main:** `2978c45dd75a18bcf30a9c30a0f6d280a29ea999`. Owner reported failure names
`runtime.validates-configuration-syntax` (#164) and
`runtime.validates-configuration-comments-crlf` (#165), without
platform or `--output-on-failure` diagnostic. **Diagnosis is
provisional:** default POSIX `file(WRITE)` permission modes depend on
the host's umask; `O_NOFOLLOW`/regular-file/mode validation rejects
group/world-writable config files as designed. The shared fixture
script now imposes `OWNER_READ OWNER_WRITE` after writing all normal
POSIX fixtures, before any negative-case override. The new dedicated
registered POSIX CTest
`runtime.validates-configuration-mode-normalization` simulates a
permissively writable preexisting file and exercises the production
`--check-config` success path after normalized file permissions.
`runtime.rejects-configuration-group-writable` remains unchanged
and must still return 3. CRLF content assertions are unchanged.

**PASS:** stand-alone Linux CMake 3.31.6 permission probe in the
single reusable `~/rdp-server/build/r10-fixture-mode` subdirectory,
executed under `umask 000`: `file(WRITE)` mode **666** before
normalization and **600** after `file(CHMOD)`.
**NOT RUN:** actual owner build and diagnostic reproduction, complete
repo CTest (local checkout inaccessible), hosted exact-SHA Actions
at authoring, owner Linux/X11 / Windows MSYS2 CLANG64 Clang23 /
macOS 27, authenticated desktop. No production behavior changed;
the existing security check remains fail-closed. **Next:** verify
exact-SHA CI and request full CTest failure text if the owner
continues to see either failure; M1–M6 remain OPEN.

## R9 sanitizer CI YAML correction (2026-10-15)

**Failed first SHA:** `2cca0ed17d8c98b5f38d5d34079f90d66ce389d4`.
[GitHub Actions 38850195312](https://github.com/k1moradi/RDP-server/actions/runs/38850195312)
returned completed FAILURE with **zero jobs**. Committed
`.github/workflows/ci.yml` had the MCS/CredSSP `-R`
selector and `documentation-policy:` joined on one YAML
line. No CI build, CTest, sanitizer, policy or package job
executed. **Corrective parent:** `22915cee335df7d82149728543866f45db7bc8aa`; fix only
the YAML line and adjacent duplicate comments. Preserve
Clang ASan/UBSan/LSan flags, five production-linked test
targets, all clipboard tests and ten MCS/CredSSP cases.
**NOT RUN yet:** corrected exact-SHA hosted results,
owner Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS27,
live Microsoft-client/OS admission/desktop. **Next:**
check actual sanitizer test log for PASS or first failure.

## R7 refresh-guard singular ownership and baseline CI startup (2026-10-16)

**Code:** The `NativeDisplayGeometryRefresh` class is noncopyable and
nonmovable; the existing `tests/test_macos_capture_pixel_buffer.cpp`
contains `std::is_copy_constructible_v` and `std::is_move_constructible_v`
compile-time checks. No native callback or runtime permission behavior was
added. **PASS (partial Linux fixture):** reconfigured/build/CTest one-root
GCC14.2 Debug **7/7**, including three new epoch behaviors.
**Hosted baseline blockage:** [Actions 38850284552](https://github.com/k1moradi/RDP-server/actions/runs/38850284552)
for implementation `19dd0e781bd558a2f9ebf4f3f76b5561d2e33e00`
completed **FAIL, zero jobs**; the workflow blob on its parent was
identical and contained TWO `publish-protocol-prerelease:` job keys.
[Issue #13](https://github.com/k1moradi/RDP-server/issues/13)
requests R9/R10 workflow syntax reconciliation. No R7 CMake/CTest
compiler/test failure can be inferred from a zero-job Actions run.
**NOT RUN:** corrected exact-SHA hosted full-repo CTest until the
workflow is runnable; owner's macOS27 and CLANG64 Clang23 terminals;
real ScreenCaptureKit/TCC, R2/R3 admission, client input and benchmarks.
**Next:** obtain exact-SHA hosted validation once R9 fixes CI and add
native user-authorized Quartz topology invalidation registration.

## R10 recovery of broken workflow job map (2026-10-15)

**Parent main:** `b97e50834e5851c66936cf9d3ad95949b3b25aa9`. The R10 owner-failure correction
`875033cdfb0b7b13d7842de711b54ba3d867ec8f` was committed
but [Actions 38850361038](https://github.com/k1moradi/RDP-server/actions/runs/38850361038)
ended **FAIL with zero jobs**, thus no full CTest validation. A
concurrent R9 sanitizer workflow edit accidentally duplicated
`documentation-policy` and `publish-protocol-prerelease` jobs
and left a stray outdented shell line. Preserve the R9 sanitizer
steps and exactly one policy and SDK tag-publish gate, remove the
duplicate malformed tail. **PASS:** text-level assertion that
preserved top-level job identifiers are unique and required gates
remain. **NOT RUN at authoring:** restored GitHub Actions, owner's
full CTest rerun and first failing stderr for owner's two R10 cases.
No production security behavior changed. Next: exact-SHA workflow
and CTest verification; M1–M6 remain OPEN.

## R10 correction to synthetic POSIX fixture chmod keyword (2026-10-15)

**Parent main:** `4d24b8b3b9857370fef8608cf7d7782f644df3ea`. Restored [Actions 38850617229](https://github.com/k1moradi/RDP-server/actions/runs/38850617229)
reached hosted macOS full Debug CTest. Both originally owner-reported
R10 cases `runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf` **PASS** on the
hosted macOS runner. New R10
`runtime.validates-configuration-mode-normalization` failed at
CMake fixture setup because `OTHERS_WRITE` is not a supported
`file(CHMOD)` keyword. Replaced it with `WORLD_WRITE`, leaving
all production security checks unchanged. **PASS** local CMake
3.31.6 script: explicit permissive 622 becomes restrictive 600.
**NOT RUN at authoring:** exact-SHA hosted CTest following this
test-only correction and owner Linux/X11/Windows CLANG64/macOS27
acceptance. Next: exact CI and original owner one-liner.

## R10 POSIX fixture normalization exact-SHA CI PASS (2026-10-15)

**Implementation correction:** `a0c39e4a612c740949c05e4a9699f711061c21d0`.
[GitHub Actions 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646)
**completed SUCCESS** across five jobs: hosted Linux/GCC full
CTest **226/226 Debug and 226/226 Release**, hosted macOS/Clang
**209/209 Debug and 209/209 Release**, hosted Windows/MSVC
**228/228 Debug and 228/228 Release**, R9 native security sanitizer
and documentation-policy PASS. All three OS downstream SDK consumers
**1/1 PASS**; ZIP packaging, digest and artifact upload PASS.
On each OS, the two owner-reported R10 tests
`runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf` now **PASS**.
The new POSIX mode-normalization test also **PASS** on Linux and
macOS. The prior local `file(CHMOD)` typo was corrected from
`OTHERS_WRITE` to supported `WORLD_WRITE`. No production code
was weakened; only private fixture modes, CI YAML integrity and
behavior-named CTest coverage changed.

**NOT RUN:** owner's original Linux/X11, Windows MSYS2 CLANG64
Clang 23, macOS27 same-SHA terminal command after a fresh pull,
external RDP client, real credentials/OS authorization, listener,
desktop, and release security gates. The likely owner umask cause
is supported by a local 666-to-600 probe but not conclusively
established for the owner's machine from a two-line failure list.
M1–M6 remain OPEN.

## R1 listener-readiness bounded accept gate (2026-10-15)

**Integration parent:** `a0c39e4a612c740949c05e4a9699f711061c21d0`; nine-file atomic increment
updates existing `nonblocking_tcp_adapter.h/.cpp`, the original
preauth fixture and CTest registry, ROADMAP, ARCHITECTURE, coding
and testing standards and this validation ledger.
**Implemented:** `pollNonblockingTcpAcceptBatch`: single POSIX
`poll`/Winsock `select` on a borrowed already-listening
nonblocking native socket, upper wait bound 25ms and external
monotonic deadline, followed by exactly one bounded native
accept-batch and move-only callback handoff when readable.
Return explicit invalid-input, idle, expired, completed-batch
and failure outcomes; no listener closure, process daemon,
authenticated identity or MCS/session state.
**New dedicated registered CTests:**
`transport.tcp-listener-poll-budget-handoff` and
`transport.tcp-listener-poll-deadline-denials`.
**Prior R1 baseline PASS:** [Actions 38849575634](https://github.com/k1moradi/RDP-server/actions/runs/38849575634)
at `2d03a9bd0bebf7697231322c07d0fa594ef6b0d1`,
Linux 218/218, macOS 202/202 and Windows 220/220 full Debug
and Release CTests, including all R1 socket batch regressions.
**NOT RUN at authoring:** new-code full hosted CI (the previous
workflow no-job syntax issue R9/R10 [Issue #13](https://github.com/k1moradi/RDP-server/issues/13)
was repaired; baseline [Actions 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646)
at `a0c39e4a612c740949c05e4a9699f711061c21d0` SUCCESS),
local checkout build (worker has no clone and github.com DNS
unavailable), owner Linux/X11, Windows MSYS2 CLANG64 Clang23,
macOS27, live Microsoft client, OS-authenticated identity and R3
admitted channel/desktop.
**Next:** R9/R10 restore CI workflow startup, then R1 verify
exact new source SHA with dedicated/full CTests; R10 may wire
listener readiness to runtime only when R2/R3 gates are ready.


## R9 MCS/CredSSP/CLIPRDR sanitizer gate exact-SHA verification

**PASS (exact SHA `a0c39e4a612c740949c05e4a9699f711061c21d0`):**
[Actions 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646)
completed SUCCESS. Native Ubuntu Clang 18.1.3 C++23
Debug build, `-fsanitize=address,undefined
-fno-omit-frame-pointer -fno-sanitize-recover=all`,
same sanitizer linker flags,
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`,
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
One ephemeral checkout-local `build/`, five existing binaries:
`test_owned_remote_transfer`, `test_clipboard_protocol`,
`test_owned_mcs_connect_initial`,
`test_owned_credssp_tsrequest` and
`test_owned_credssp_binding`. The first command
`ctest --test-dir build --build-config Debug -L clipboard
--output-on-failure` passed **15/15**.
The second command used the CTest `-R` selector
for the following ten existing tests (**10/10 PASS**):
- `transport.mcs-envelope-tpkt-errors`
- `transport.mcs-envelope-ber-errors`
- `transport.mcs-envelope-mutations`
- `transport.mcs-send-data-joined-denials`
- `transport.mcs-join-stale-write-receipts`
- `transport.mcs-join-stale-partial-write-slices`
- `security.credssp-der-rejections`
- `security.credssp-der-bounds`
- `security.credssp-der-mutations`
- `security.credssp-binding`
No ASan, UBSan or LeakSanitizer diagnostics appeared.
No separate test registry/fuzzer or live credentials.

**Same-SHA hosted full matrix SUCCESS:** Linux/GCC
**226/226** Debug and Release, macOS/Clang
**209/209** Debug and Release, Windows/MSVC
**228/228** Debug and Release, downstream installed
SDK consumer and package artifacts PASS, policy PASS.

**Failure integrity:** [Actions 38850195312](https://github.com/k1moradi/RDP-server/actions/runs/38850195312)
and [38850488920](https://github.com/k1moradi/RDP-server/actions/runs/38850488920)
FAILED with zero jobs due workflow YAML corruption caused
by a `String.replace` dollar-sign/apostrophe replacement
token, not a sanitizer fault. The concurrent
`4d24b8b3b9857370fef8608cf7d7782f644df3ea`
workflow repair restored scheduling.
[Actions 38850617229](https://github.com/k1moradi/RDP-server/actions/runs/38850617229)
then showed **25/25 sanitizer PASS** and Windows
**228/228** Debug/Release PASS, but Linux **225/226**
and macOS **208/209** Debug FAIL at R10's
`runtime.validates-configuration-mode-normalization`:
`tests/check_runtime_entrypoint.cmake:127` used unsupported
`OTHERS_WRITE`. R10 replaced it with `WORLD_WRITE`
at exact passing SHA; R9 did not alter runtime security.

**NOT RUN:** user's one-root owner Linux/X11, Windows
MSYS2 CLANG64/Clang23 and macOS 27 commands, sanitizers
outside selected protocol suite, sustained coverage-guided
fuzzing, live authenticated Microsoft-client/session
and desktop/clipboard. M1–M6 remain OPEN.
**Next:** authorized R3→R8 routing and disconnect
regression upon real production dispatch availability.

## R1 listener readiness exact-commit all-host CI (2026-10-15)

**Source SHA:** `1fb4d48e3f9a1133587d634d08ec69c5d5c19e03`
([atomic R1 production+CTest+docs commit](https://github.com/k1moradi/RDP-server/commit/1fb4d48e3f9a1133587d634d08ec69c5d5c19e03)).
**Exact source GitHub Actions:**
[run 38851057291](https://github.com/k1moradi/RDP-server/actions/runs/38851057291)
**SUCCESS** after the CI workflow-startup correction.
- Hosted Linux/GCC Debug and Release: **228/228 PASS** each.
- Hosted macOS/AppleClang Debug and Release: **211/211 PASS** each.
- Hosted Windows/MSVC Debug and Release: **230/230 PASS** each.
- Both dedicated `transport.tcp-listener-poll-budget-handoff` and
  `transport.tcp-listener-poll-deadline-denials` PASS in all six
  configurations; documentation-policy, R9 security-protocol
  sanitizers, installed SDK consumer tests and package jobs PASS.
- Commands run by hosted CI, from one `build` root:
  `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`,
  `cmake --build build --config Debug --parallel 2`,
  `ctest --test-dir build --build-config Debug --output-on-failure`;
  reconfigure the same root for `Release`, then build and CTest
  `--build-config Release`. This is hosted verification rather
  than an owner-local three-platform checkpoint.

**NOT RUN:** owner's Linux/X11, Windows MSYS2 CLANG64/Clang 23
and macOS27 exact-SHA command, live Microsoft client, service
startup, R2 credential acceptance / independent OS authorization,
R3 admitted channels, MCS share/desktop access. Successful
loopback X.224 Confirm, native listener readiness and TLS-only
diagnostics do not authorize an OS session.
**Next R1 boundary:** existing R10 runtime owns live listener
configuration, admission budgets and fairness; R1's bounded
listener/accepted-owner APIs are now tested building blocks.

## R1 intermittent macOS accept-batch drain regression (2026-10-15)

**Parent main:** `464211b1da48ce80e09e27904addce7bb40137b2`. **Previously verified source CI:**
`1fb4d48e3f9a1133587d634d08ec69c5d5c19e03`
[Actions 38851057291](https://github.com/k1moradi/RDP-server/actions/runs/38851057291)
**PASS** Linux/GCC 228/228, macOS/AppleClang 211/211 and
Windows/MSVC 230/230 Debug and Release, including both new
listener poll CTests. **Subsequent documentation-only follow-up:**
`464211b1da48ce80e09e27904addce7bb40137b2`,
[Actions 38851395036](https://github.com/k1moradi/RDP-server/actions/runs/38851395036)
**FAIL** macOS Debug **210/211**, *only*
`transport.tcp-native-accept-batch-stops-denials`:
`test_owned_preauth_session.cpp:2582` asserted immediate
`TcpAcceptBatchOutcome::Drained` after loopback connect. Native
TCP may still return WouldBlock before the pending connection is
readable. **Fixture-only fix:** use bounded `pollNonblockingTcpAcceptBatch`
(128 x <=25ms, caller steady-clock 5s) before enforcing the
same `Drained`, accepted count, callback and listener assertions.
No production transport code changed; all other CTests remain.
**NOT RUN at authorship:** corrected full exact-SHA hosted CI,
owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27,
authenticated R2/R3 admission and real RDP client/desktop.
**Next:** verify all platforms' full Debug+Release CTests.

## R1 listener-readiness corrected full hosted CI (2026-10-15)

**Production implementation:** `1fb4d48e3f9a1133587d634d08ec69c5d5c19e03`,
[Actions 38851057291](https://github.com/k1moradi/RDP-server/actions/runs/38851057291)
SUCCESS Linux 228/228, macOS 211/211, Windows 230/230
Debug+Release. A documentation-only follow-up revealed
`transport.tcp-native-accept-batch-stops-denials` as
intermittently failing macOS Debug (210/211) due to
premature direct nonblocking accept before listener readiness.

**Corrected fixture and exact validated SHA:**
`66077dd20222f6f50466b2937f90e25d500a13f1`
([test-only commit](https://github.com/k1moradi/RDP-server/commit/66077dd20222f6f50466b2937f90e25d500a13f1)).
[Hosted Actions 38851653835](https://github.com/k1moradi/RDP-server/actions/runs/38851653835)
**SUCCESS**, Linux/GCC **228/228 Debug and 228/228 Release**;
macOS/AppleClang **211/211 Debug and 211/211 Release**;
Windows/MSVC **230/230 Debug and 230/230 Release**.
The previously failing `transport.tcp-native-accept-batch-stops-denials`
and both new `transport.tcp-listener-poll-*` CTests PASS in
all six hosted configurations. Documentation policy, R9
ASan/UBSan security-protocol tests and installed SDK consumer
checks PASS; prerelease intentionally SKIPPED without tag.

**Hosted CI commands:** `cmake -S . -B build
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`, `cmake --build
build --config Debug --parallel 2`, `ctest --test-dir build
--build-config Debug --output-on-failure`, then Release
reconfiguration/build/CTest in the same `build` root.

**NOT RUN:** owner's nominated Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27 exact-SHA command; live first-party
listener runtime, external Microsoft client, R2 authenticated
identity/OS authorization and R3 admitted MCS/share/desktop.
These are independent unaccepted gates, not inferred from CI.
**Next R1:** R10 integrates the now bounded borrowed-listener
readiness and sole connection owner into the process event loop.

### R5 native XShm borrowed connection cancellation (2026-10-16)

**Base main SHA:** `4ddf21920fbd10c0185f2d4f8d405c13600426a0`. Native implementation adds the
idempotent `X11SharedMemoryCapture::disconnect()` contract: it releases
the XShm segment and invalidates the borrowed XCB pointer while still
connected; once cancelled, capture/destructor do not dereference the former
owner. Dedicated Linux native CTest
`x11.capture-native-disconnect-cancellation` is registered in the shared
CTest registry only when `rdp-server-linux-xshm` is available; it tests
failed-connection construction, explicit cancellation before parent
teardown, repeated cancellation, failed post-disconnect capture and
destructor after parent death. No DISPLAY or protected operation needed.
**NOT RUN locally:** native XCB-SHM translation-unit compile (development
headers unavailable), complete checkout/CMake/full CTest, Linux X11
human-desktop, three owner-operated platform builds or benchmark.
**Next:** verify exact implementation SHA on GitHub Actions Linux native
Debug/Release and all platform CTests, then integrate R5 resources under
the admitted display/session owner (R2/R3) and R4 graphics.

## R1 one-shot/listener-poll role and nonblocking validation (2026-10-15)

**Parent main:** `ea1cf468986b15bcc4ee0b43b70082cfc0862e82`. **Production:** single native
`acceptNonblockingTcpConnection` rejects connected sockets
and POSIX blocking listeners before `accept4/accept`. The
existing borrowed listener poll applies the same precondition
before readiness waiting; all batches still use the one-shot
acceptor. Listener flags, ownership and R2/R3 authority remain
unchanged. Windows `FIONBIO` mode must be configured by runtime;
`SO_ACCEPTCONN` is verified via Winsock `getsockopt`.
**Dedicated new CTest:** `transport.tcp-native-listener-role-and-mode-denials`
(real queued loopback peer, non-listener all-API failure,
POSIX blocking listener failure without stolen peer, sole owner
handoff after caller-controlled flag restoration), registered
in the existing central CTest list with TIMEOUT 20.
**Files:** native TCP header/implementation, existing preauth
tests, shared CMake test registry and existing ROADMAP,
ARCHITECTURE, coding/testing standards and validation ledger.
**Previous baseline:** current `main` `ea1cf468986b15bcc4ee0b43b70082cfc0862e82` hosted
CI PASS on Linux/GCC, macOS/AppleClang and Windows/MSVC.
**NOT RUN at authoring:** new-code local CMake/CTest (worker
has no clone), exact implementation Actions, owner Linux/X11,
Windows CLANG64/Clang23 and macOS27, real client, R2
identity/OS admission and R3 authorized session.
**Next:** exact-SHA hosted validation, then R10 runtime
integration gated by independent R2/R3 authorization.

## R4 AVC420 mapped surface/full-send receipt integration (2026-10-15)

**Parent `main`:** `6d5422f82dc9e644e8fa058e30e22deedb76bd84`. The production
`gfx_avc420_picture.cpp` and its existing three dedicated
`graphics.avc420-picture-*` CTests are restored to the normal
single protocol archive/CTest registry after a concurrent CMake
registration loss. `GfxPresentationLifecycle` now exposes
`prepareAvc420Picture` to gate that same production packetizer
behind its confirmed AVC420 capability, fully delivered surface
create/map, matching geometry and channel generation, and the
one `GfxFrameAckWindow` frame-ID/bounded queue. Only R3's
whole-frame delivery receipt commits pending ACK state.

**New dedicated CTests:** `graphics.avc420-mapped-frame-wire`,
`graphics.avc420-mapped-frame-denials`, and
`graphics.avc420-mapped-frame-reconnect`, using the already
production-linked `test_gfx_presentation_lifecycle` binary.
Synthetic Annex-B prefix/payload is only a framing fixture, not
a valid H.264 picture or encoder verification. Normative graphics
framing and ACK ordering: MS-RDPEGFX §§2.2.2.1, 2.2.2.11–13
and 3.2.1.2/3.2.5.13.

**NOT RUN at authoring:** local full-repository CTest because
the sandbox has no complete checkout and Github DNS is unavailable;
owner independent Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27 command; actual R2-authorized OS session, R3 admitted
DRDYNVC writer, pinned license-reviewed x264 static build, live
H.264 Microsoft-client desktop and performance benchmarks.
Verify the exact commit's hosted cross-platform CI and preserve
Gate B/M3–M5 as OPEN.

### R5 XShm borrowed XCB cancellation exact-SHA CI receipt (2026-10-16)

**Production implementation:** `ea1cf468986b15bcc4ee0b43b70082cfc0862e82`
([Actions 38856920824](https://github.com/k1moradi/RDP-server/actions/runs/38856920824)).
**SUCCESS** exact production SHA. Linux/GCC compiled the native
`rdp-server-linux-xshm` target and executed
`x11.capture-native-disconnect-cancellation` PASS; Linux **230/230**,
macOS/Clang **212/212**, Windows/MSVC **231/231** full CTests PASS
in BOTH Debug and Release. R9 sanitizer, docs policy, SDK downstream
consumer and artifact packaging PASS; prerelease publication SKIPPED.
This verifies an invalid-fd native XCB teardown regression, not a valid
DISPLAY session or positive XShm capture/resize lifecycle.
**NOT RUN:** owner Linux/X11, Windows CLANG64/Clang23, macOS27 native
platform checkpoints; authorized R2/R3 desktop/Microsoft client,
full R4 graphics delivery, performance. M3/Gate B remains OPEN.

## R10 offline TLS credential-file metadata gate (2026-10-15)

**Parent main:** `8f5e194a5662ae2f70a849c0e451c8bbb60f87b0`. New explicit offline CLI
`--check-tls-files FILE` uses existing validated bounded config
syntax, then checks configured cert/key file identities and modes.
Existing `--check-config` stays syntax-only. POSIX `O_NOFOLLOW`,
`O_NONBLOCK`, `fstat`, eUID and 0600-like key protections; Windows
`CreateFileA` with no-final-reparse, opened HANDLE metadata,
restricted private-key read DACL and file ID. Reject missing, empty,
oversized, nonregular, aliased and insecure objects; do not read
private-key bytes or reveal paths. Limit cert to 1 MiB, key 256 KiB.
**Dedicated CTests:** `runtime.validates-tls-files-private-regular`;
`runtime.rejects-tls-files-missing-certificate`,
`-missing-key`, `-empty-key`, `-oversized-key`,
`-aliased-identity`, `-key-group-readable`,
`-certificate-group-writable`, `-key-symlink`,
`-certificate-symlink`, `-key-directory`,
`-windows-key-public-read` and `-option-smuggling`.
Tests use synthetic fixture files and never start a listener.
POSIX/Windows-specific cases register conditionally; others remain
default-enabled on all three OSes. **NOT RUN at authoring:**
complete local repository CMake/CTest (Git clone DNS unavailable),
exact-commit hosted Actions, owner's Linux/X11,
Windows MSYS2 CLANG64/Clang23 and macOS27 one-root command,
real TLS certificate/key contents, trusted OS identity,
Microsoft RDP client and human desktop. M1–M6 remain OPEN.
**Next:** exact-SHA matrix CI and owner one-root validation,
then real certificate/key provisioning and end-to-end admission.

## R1 Darwin SO_ACCEPTCONN rollback to supported native checks (2026-10-15)

**Parent:** `ab78ed83f59b64463123382da34b8b13b832c0e1`. **FAIL:** original R1 `6d5422f82dc9e644e8fa058e30e22deedb76bd84`
[Actions 38857085837](https://github.com/k1moradi/RDP-server/actions/runs/38857085837),
macOS Debug **15 native transport CTests FAIL**: Apple does not
support `getsockopt(SO_ACCEPTCONN)` despite defining the macro.
Linux/GCC and Windows/MSVC full jobs, documentation and R9 sanitizers
**PASS** on the original commit. **Correction:** macOS supported
`SO_TYPE` and connected peer-state denials with unchanged POSIX
`O_NONBLOCK` guarantee, preserving Linux/Windows SO_ACCEPTCONN.
**New CTest:** `transport.tcp-native-wrong-socket-type-denials`,
UDP one-shot/batch/poll rejections plus bounded successful TCP handoff.
**NOT RUN at authoring:** corrected exact-SHA CI, owner Windows
MSYS2 CLANG64 Clang23, Linux/X11, macOS27, live credentials, R2/R3
OS authorization/session and Microsoft client.

## R10 TLS metadata initial CI/Windows file owner fixture (2026-10-15)

**Parent main:** `c78a745aaa5180007a00a35a2858072974c2ad17`. First [Actions 38857433495](https://github.com/k1moradi/RDP-server/actions/runs/38857433495)
ran R10 implementation `8a4f466c3bab9af155da623a54dba91b7cb7529d`.
Linux full CI PASS, macOS R10 TLS-file CTests all PASS but
15 native TCP accepts FAIL (R1-owned); Windows Debug R10 positive
`runtime.validates-tls-files-private-regular` FAIL (3 rather
than 0) while TLS negatives PASS. Provisional Windows issue:
test-account SID may differ from automatic fixture owner SID,
while production requires a private key's allow grants to refer
to owner, SYSTEM or Administrators. Set owner via `icacls /setowner`
on synthetic fixtures, preserving native DACL restriction.
**NOT RUN at authoring:** corrected exact-SHA hosted CI and
owner's Linux/X11, Windows CLANG64/Clang23 and macOS27 runs;
full RDP session/credential cryptography/M1–M6 acceptance OPEN.

## R1 Darwin listener-role corrected hosted CI receipt (2026-10-15)

**Original role/mode guard:** `6d5422f82dc9e644e8fa058e30e22deedb76bd84`
([Actions 38857085837](https://github.com/k1moradi/RDP-server/actions/runs/38857085837)) **FAIL** macOS Debug: 15 accepted-socket CTests rejected valid Darwin listener because SO_ACCEPTCONN cannot be queried there.
**Corrected R1 production + additional CTest:** [`c78a745aaa5180007a00a35a2858072974c2ad17`](https://github.com/k1moradi/RDP-server/commit/c78a745aaa5180007a00a35a2858072974c2ad17), [hosted Actions 38857769789](https://github.com/k1moradi/RDP-server/actions/runs/38857769789).
**PASS:** Linux/GCC **252/252 Debug and Release**, macOS/AppleClang **234/234 Debug and Release**. Both named R1 CTests `transport.tcp-native-listener-role-and-mode-denials` and `transport.tcp-native-wrong-socket-type-denials` PASS in hosted Linux/macOS Debug and Release plus Windows/MSVC Debug. Documentation-policy and R9 security-protocol sanitizer PASS. Linux/macOS downstream installed SDK consumer PASS.
**FAIL (unrelated R10):** Windows/MSVC full Debug **250/251**; only `runtime.validates-tls-files-private-regular` fails at `tests/check_runtime_entrypoint.cmake:317` (runtime exit status 3 versus expected 0), reported [Issue #14](https://github.com/k1moradi/RDP-server/issues/14). Windows Release and downstream SDK consumer **NOT RUN** because workflow stopped at Debug failure; do not infer Windows full-pass from the R1 cases.
**Owner-local** Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS27 exact-head CTest **NOT RUN**. Live Microsoft RDP client, OS certificate/identity authorization, R3 channel/session and desktop **NOT RUN**. This is an R1 transport-precondition improvement, not M2 acceptance.

## R10 TLS-file metadata cross-platform CI acceptance (2026-10-15)

**Exact tested SHA:** `2ccc1a384306359fc01a35ddfbefd89d3cbbc13b`;
[GitHub Actions 38857862786](https://github.com/k1moradi/RDP-server/actions/runs/38857862786)
**completed SUCCESS**. Linux/GCC complete Debug and Release
CTest **252/252 each**, macOS/Clang **234/234 each**,
Windows/MSVC **251/251 each**. All new R10 TLS-file positive and
security-negative cases pass where registered. Windows
`runtime.validates-tls-files-private-regular` and
`runtime.rejects-tls-files-windows-key-public-read` explicitly
PASS Debug and Release after setting the synthetic TLS fixture
file owner SID to the granted test-account SID. No production
DACL or POSIX permission requirement was reduced.
R1 native TCP accept cases PASS on macOS on this SHA after
R1's independent accept fix. R9 hosted sanitizer job,
documentation-policy, protocol SDK install/downstream consumer
(**1/1** per OS), ZIP/SHA256 and artifact uploads PASS.
Untagged protocol prerelease SKIPPED. This is **hosted CI**,
not independently run owner acceptance on Linux/X11, Windows
MSYS2 CLANG64/Clang23 and macOS27. Actual X.509 certificate
contents, private key correspondence, secure filesystem
parent-chain, authenticated OS admission and Microsoft-client
live desktop are **NOT RUN**. R10 startup remains disabled,
M1–M6 unaccepted. Next R10: path-component security review
and opt-in cryptographic key/certificate validation,
keeping syntax-only `--check-config` stable.

## R7 native CoreGraphics topology revision signal (2026-10-16)

**Source:** `src/platform/macos/native_display_reconfiguration.{h,cpp}`,
`native_display_refresh.{h,cpp}`, reused
`tests/test_macos_capture_pixel_buffer.cpp`, existing top-level and
central tests CMake. Explicit native Quartz callback registration and paired
removal are opt-in; callback only bumps a process-wide atomic revision,
never captures, prompts, queries a display, mutates an R3 session or owns
an R4 framebuffer. No userInfo pointer can dangle after watch destruction.
`NativeDisplayGeometryRefresh` binds the revision before native/synthetic
double-read, rejects mid-read notifications with `TopologyChanged`, and
automatically denies stale geometry lookups after any later notification.
**Dedicated CTests:** `macos.desktop-native-reconfiguration-stale-denial`,
`macos.desktop-native-reconfiguration-during-read`,
`macos.desktop-native-reconfiguration-revision-sequence` (all synthetic
CoreGraphics events, existing executable and central registry).
**Local PASS (sparse fixture, NOT full repository):** one-root GCC14.2
`cmake -S ~/rdp-server -B ~/rdp-server/build -DCMAKE_BUILD_TYPE=Debug
-DBUILD_TESTING=ON`, `cmake --build ~/rdp-server/build --parallel 2`,
`ctest --test-dir ~/rdp-server/build -C Debug --output-on-failure`: 8/8
(focused new static native signal smoke 2/2, earlier fixture 6/6).
Strict Clang17 C++23 ASan+UBSan new signal smoke 2/2 PASS; GCC14.2
strict -O2 signal smoke 2/2 PASS. Actual integrated refresh behavior and
Apple native framework linking **NOT RUN at authoring**, must be verified
by exact-source CI. **NOT RUN:** owner macOS27/Linux X11/Windows
MSYS2 CLANG64 Clang23 common-SHA CTest, display callback permissions,
actual user TCC/ScreenCaptureKit, authenticated desktop, live RDP client,
cursor/input and performance. **Next:** native callback registration in
R2/R3-authorized user process, first-party ScreenCaptureKit lifetime and
R4-consumer ownership, with deterministic teardown tests.

## R10 POSIX TLS ancestor symlink closure (2026-10-15)

**Parent main SHA:** `3849c8e3073822984c185aad1c996f87e448031e`. The already existing
`--check-tls-files` R10 metadata stage checks only final symlinks
using `O_NOFOLLOW` on one absolute-path `open`. This incremental
change adds `openTlsFileWithoutSymlinkParents`: for POSIX only,
open `/`, traverse each component using relative `openat` with
`O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, require `O_DIRECTORY`
on intermediate entries, and close each previous descriptor before
advancing. Invalid/dot/empty components fail closed. The returned
handle is examined using the **existing** `fstat`, effective owner,
permissions, byte bounds and same-identity rejection before closure.

**New registered runtime CTests (POSIX only):**
`runtime.validates-tls-files-nested-real-parent`,
`runtime.rejects-tls-files-key-parent-symlink`, and
`runtime.rejects-tls-files-certificate-parent-symlink`. All use
the existing CMake fixture and real `rdp-server` executable,
synthetic metadata-only contents; no listener or OS session.
**PASS local isolated Linux:** GCC 14.2 and Clang 17 strict C++23
metadata/path code compiled and a real nested parent returned exit
0 while a parent symlink returned 3, within `~/rdp-server/build/`.
**NOT RUN at authoring:** complete project Debug/Release CTests,
current exact-SHA hosted Actions, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27 one-root full commands, real TLS
certificate/key parsing, Microsoft RDP client, R2 OS admission
and R3 live session/desktop. **Security:** does not prove later
credential reload is race-safe; live loader must revalidate the
newly opened handles. `--check-config` and startup denials are
unchanged. M1–M6 remain OPEN.

## R1 Darwin listener guard full hosted CI receipt (2026-10-15)

**R1 corrected production:** `c78a745aaa5180007a00a35a2858072974c2ad17` (Darwin supported SO_TYPE/peer guard, Linux/Windows SO_ACCEPTCONN and POSIX O_NONBLOCK preserved). **Exact-source integration SHA:** [`01a9dd001dc8111668635511208a0a6a93bff622`](https://github.com/k1moradi/RDP-server/commit/01a9dd001dc8111668635511208a0a6a93bff622), [Actions run 38858078854](https://github.com/k1moradi/RDP-server/actions/runs/38858078854) **SUCCESS**. Linux/GCC full **252/252 Debug and Release**, macOS/AppleClang full **234/234 Debug and Release**, Windows/MSVC full **251/251 Debug and Release**. Both dedicated new R1 listener configuration CTests `transport.tcp-native-listener-role-and-mode-denials` and `transport.tcp-native-wrong-socket-type-denials` PASS across all six platform/build combinations. R9 security-protocol sanitizer, documentation-policy, SDK downstream consumer and artifact packaging PASS. Windows runtime `runtime.validates-tls-files-private-regular` also PASS in Debug and Release after a separately owned R10 test correction; [Issue #14](https://github.com/k1moradi/RDP-server/issues/14) CLOSED. Historical earlier failure at R1 SHA c78a remains documented above, not retroactively marked PASS.

**OWNER checkpoints NOT RUN:** Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS27 at one exact nominated SHA. Actual Microsoft RDP client, real credential validation, independent OS session authorization, MCS/channel/share activation, desktop and service operations **NOT RUN**. This is native R1 transport CI acceptance, not M2/M6 milestone acceptance.

## R7 native topology signal exact-commit hosted CI (2026-10-16)

**Code SHA:** `3849c8e3073822984c185aad1c996f87e448031e`.
**Exact-SHA PASS:** [GitHub Actions 38858255530](https://github.com/k1moradi/RDP-server/actions/runs/38858255530),
Ubuntu/GCC **255/255**, macOS/Apple Clang **237/237**, Windows/MSVC
**254/254** registered CTests **in both Debug and Release**.
All three new R7 synthetic Quartz topology tests passed on each OS.
Hosted macOS compiled and linked the actual CoreGraphics callback
registration/removal in `rdp-server-macos-capture`, which is isolated
from the portable protocol SDK. Documentation policy, R9 security
sanitizers, staged SDK consumer, ZIP/checksum artifacts PASS.
**NOT RUN:** actual native CoreGraphics callback firing/unregister against
an interactive user, macOS27 owner one-root CTest, Windows MSYS2 CLANG64
Clang23 and Linux/X11 owner exact-SHA CTests, real TCC/ScreenCaptureKit
frames, authorized Microsoft RDP client, cursor/input and benchmarks.
**First missing boundary:** R2/R3-authorized per-user session and native
listener start/stop ownership, then R4-approved BGRA frame transfer.
**Next:** deterministic native callback cancellation/race fixture and
an explicitly authorized native ScreenCaptureKit lifecycle increment.

## R10 TLS parent-symlink guard exact-SHA hosted CI (2026-10-15)

**Implementation SHA** [`88ba20c5d4581765475e9337b366469a0d9bf089`](https://github.com/k1moradi/RDP-server/commit/88ba20c5d4581765475e9337b366469a0d9bf089),
[Actions 38858338819](https://github.com/k1moradi/RDP-server/actions/runs/38858338819)
**COMPLETED SUCCESS**. Linux/GCC Debug **258/258 PASS** and Release
**258/258 PASS**; macOS/Clang Debug **240/240 PASS** and Release
**240/240 PASS**; Windows/MSVC Debug **254/254 PASS** and Release
**254/254 PASS**. New cases
`runtime.validates-tls-files-nested-real-parent`,
`runtime.rejects-tls-files-key-parent-symlink`,
`runtime.rejects-tls-files-certificate-parent-symlink`
explicitly passed on Linux/macOS in both configurations; Windows
tests remain native-only and unchanged. Windows's original
`runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf` also PASS in Debug
and Release. R9 security sanitizer PASS, documentation-policy PASS,
downstream SDK installed consumer **1/1 PASS per platform**,
protocol-only SDK ZIP/SHA256 upload PASS. No release tag was
published; prerelease job SKIPPED.

**NOT RUN:** user's Linux/X11 native X11, Windows MSYS2 CLANG64
Clang23 and macOS27 same-SHA owner one-liner, standalone real
server listener, TLS key parsing, crypto match, Microsoft real RDP
client, independent R2 authenticated OS authorization or R3
authoritative desktop. The successful preflight is not a service
deployment and cannot prevent replacement after the inspected
file handles close. No branches or force updates were used.
M1–M6 remain OPEN. **Next R10:** cryptographic PEM certificate
and private-key parsing/match through the existing independent
offline preflight, bounded and without activating a listener.

## R4 AVC420 visible/coded dimension compatibility (2026-10-15)

**Parent main:** `a604ab9ab1aa77caeb5fb74feb8fbeac0afde94a`.
Production picture serializer now serializes visible RDPGFX destRect
and region mask independently of macroblock-aligned coded picture
dimensions. Trailing zero/zero visible geometry retains old API.
Checked alignment helper refuses zero and uint16 overflow.
The one R4 lifecycle uses visible surface extent for negotiation/receipt.
Three new dedicated central CTests: `graphics.avc420-visible-crop`,
`graphics.avc420-visible-crop-rejections`,
`graphics.avc420-mapped-padded-picture`. Negative fixtures include
partial zeros, oversized visible geometry and padded-area mask rects.
Normative: MS-RDPEGFX sections 2.2.2.1, 2.2.4.4 and 2.2.4.4.1.

**NOT RUN at authoring:** full local repository checkout/CTest
(GitHub DNS unavailable), user's Linux/X11, MSYS2 CLANG64 Clang23,
macOS27 one-root CTest, real x264 SPS crop or Microsoft-client decode,
R3 admitted dynamic virtual channel and frame-send receipt, benchmark.
Inspect exact source GitHub CI after publication; Gate B remains open.


## R10 offline PEM certificate/private-key consistency (2026-10-15)

**Parent main:** `1f82be913b2ad7ae09134d939542ec22b3656d63`. R10 adds opt-in
`--check-tls-credentials FILE` while keeping `--check-config`
syntax-only and `--check-tls-files` metadata-only. Production
retains each already security-validated TLS file handle and parses
PEM directly from that open object using OpenSSL. One X.509
certificate and one unencrypted private key must parse and
`X509_check_private_key` must return success. A custom password
callback always returns zero so encrypted key input cannot trigger
an interactive prompt. No path is reopened after metadata acceptance.

**New dedicated central CTests:** `runtime.validates-tls-credentials-matching-pair`,
`runtime.rejects-tls-credentials-mismatched-key`,
`runtime.rejects-tls-credentials-malformed-certificate`,
`runtime.rejects-tls-credentials-malformed-key`,
`runtime.rejects-tls-credentials-encrypted-key`, and
`runtime.rejects-tls-credentials-option-smuggling`. Fixtures are
fixed test-only P-256 material; encrypted-key case has a 10-second
CTest timeout. **NOT RUN at authoring:** exact-SHA hosted CI, owner's
three required platform one-root commands, real PKI trust/expiry/
revocation, live credentials, authenticated desktop, listener and
M1–M6 acceptance. Next: exact hosted matrix and owner CTests,
then trust/validity policy and continuity into a future authorized
live TLS loader.

## R4 RDPGFX segmented-data server envelope (2026-10-15)

**Integrated parent main:** `6369d8622057aa3f315af55011b52c1d74325d5b`. Production
`gfx_segmented_data.{h,cpp}` emits standards-defined server
RDP_SEGMENTED_DATA around already-complete RDPGFX messages using
uncompressed RDP8 bulk-data segments. SINGLE is descriptor 0xE0,
bulk header 0x04, raw graphics bytes. MULTIPART is descriptor 0xE1,
little-endian segmentCount/uncompressedSize, then each uint32 encoded
segment size, 0x04 bulk header and raw data, with at most 65,535
uncompressed bytes per segment. Exact in-place expansion is implemented
back-to-front; partial overlap, zero/uint32-overflow input, short output
and unrepresentable segment count fail without mutation. R3 remains
the sole DRDYNVC owner.

**Focused production-code PASS before integration:** GCC 14.2 and
Clang 17 compiled the exact production/test source with strict C++23,
ASan and UBSan under `~/rdp-server/build/r4_segment_stage`; all
three cases PASS per compiler: `segmented-data-single`,
`segmented-data-multipart`, `segmented-data-denials-inplace`.
The earlier accidental staging path was deleted and validation rerun
under the mandated build root.

**Normative:** MS-RDPEGFX 2.1 and 2.2.5.1–3. Microsoft's sample
decompressor confirms type 0x04 with PACKET_COMPRESSED clear copies
the raw segment data.

**NOT RUN at authoring:** full local repo CTest, exact-source Actions
until publication, owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS27, authorized R3 Graphics DVC and DVC fragmentation/send receipt,
real x264, Microsoft client or graphics benchmark. Gate B/M3–M5 OPEN.

## R10 Windows-safe memory-BIO PEM parser correction (2026-10-15)

**Parent main:** `22866e58870f3642ae2535ebbc5cb8c9b0cacaf6`. Initial R10 crypto SHA
`0a673075a3532249cf1a53439994537e165631fa`,
[Actions 38864141629](https://github.com/k1moradi/RDP-server/actions/runs/38864141629):
Linux/macOS all six new credential cases PASS; full jobs stop on
R3's pre-existing `transport.mcs-session-unverified-ordering`,
also reproduced at exact parent SHA `1f82be913b2ad7ae09134d939542ec22b3656d63`.
Windows build succeeds but the five cases entering PEM parsing
return status 1; CLI smuggling PASSes. This correction avoids
passing an application-CRT `FILE*` into OpenSSL on Windows.
After native security checks on the same open object, exactly the
validated file size is copied into bounded nothrow storage and
parsed with `BIO_new_mem_buf` +
`PEM_read_bio_X509`/`PEM_read_bio_PrivateKey`. Short reads or
growth are rejected, file identity stays held open throughout,
and the no-password callback/key-match test is unchanged.
**NOT RUN at authoring:** corrected exact-SHA CI and owner's
Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS27 one-root tests.
No service/listener/R2/R3 desktop activation. M1–M6 remain OPEN.

## R4 segmented-data exact-commit hosted CI (2026-10-16)

**Source SHA:** `88e4c3faaff6559dea8139583890c2ef6b7694cb`.
[GitHub Actions 38864509039](https://github.com/k1moradi/RDP-server/actions/runs/38864509039)
has **overall FAILURE**, but the R4 segmented-data implementation and
all three dedicated tests pass on every hosted platform that executed
them:
- Linux/GCC Debug and Release: **271/271 PASS** each.
- macOS/AppleClang Debug and Release: **253/253 PASS** each.
- Windows/MSVC Debug: **264/269 PASS**; all
  `graphics.segmented-data-single`,
  `graphics.segmented-data-multipart`, and
  `graphics.segmented-data-denials-inplace` PASS.
  Windows Release did NOT RUN because Debug CTest failed.

The five Windows failures are R10 runtime TLS credential cases:
`runtime.validates-tls-credentials-matching-pair` and four
`runtime.rejects-tls-credentials-*` cases. They are independently
reproduced on **parent** `6369d8622057aa3f315af55011b52c1d74325d5b`,
[Actions 38864378401](https://github.com/k1moradi/RDP-server/actions/runs/38864378401),
before R4 segmented-data changes. R10 Issue #15 has the corroborating
receipt. Documentation policy and the R9 security sanitizer job PASS.
Do not report the workflow as green.

**NOT RUN:** owner's Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27 same-SHA command, authenticated R2/R3 Graphics DVC and DVC
fragmentation, real x264 H.264, Microsoft client or graphics benchmark.
Gate B/M3–M5 remain OPEN. Next R4: combine mapped AVC420 picture output
with RDP_SEGMENTED_DATA at the single R3 full-send boundary.

## R10 PEM/key-match corrected hosted CI (2026-10-15)

**Implementation SHA:** `caa767fe0550958aebd215f19fa83dae0fb7fee5`.
[GitHub Actions 38864834658](https://github.com/k1moradi/RDP-server/actions/runs/38864834658)
verifies the corrected memory-BIO credential parser. Linux/GCC
Debug and Release full CTest **271/271 PASS**. Windows/MSVC Debug and
Release **269/269 PASS**. On both, all six new R10 PEM/key-match
tests PASS; the Windows result proves the earlier status-1
cross-CRT parser failure is removed. macOS/Clang Debug **253/253
PASS**; Release **252/253**, sole failure R1
`transport.tcp-owned-reply-interest-priority` at line 2112;
R10 credential tests remain PASS in that failing Release suite.
R1 issue #2 records the exact blocker. R9 sanitizer and
documentation-policy PASS. Linux and Windows installed SDK consumers
**1/1 PASS** and SDK ZIP/SHA256 packaging/uploads PASS; macOS's
downstream/package stages are **NOT RUN** because its Release CTest
failed first. Untagged prerelease remains skipped.

No listener, service, TLS session, private-key password, external
client or OS-authorized desktop is exercised. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang23 and macOS27 same-SHA validation is
**NOT RUN**. Certificate trust chain, hostname, time validity and
revocation remain outside this increment. M1–M6 remain OPEN.

## R10 certificate validity-time gate implementation (2026-10-16)

**Starting HEAD:** `46b1ca77c4c2c00bbd66e02de71896999f8c71fd`.
Its [Actions 38867045273](https://github.com/k1moradi/RDP-server/actions/runs/38867045273)
is **PASS**: Linux/GCC 276/276, macOS/Clang 258/258 and Windows/MSVC
276/276 full CTests in both Debug and Release. The owner-reported
`runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf` both explicitly PASS
on all three hosted systems/configurations. The owner's Windows MSYS2
CLANG64/Clang 23 environment remains **NOT RUN**.

The new production check keeps the existing secure opened-file/PEM
boundary and additionally requires the parsed X.509 certificate's
current `notBefore`/`notAfter` validity window. OpenSSL comparison
errors fail closed. The private-key match is still required, so neither
an expired nor a not-yet-valid certificate can pass merely because it
matches the configured key. New dedicated CTests are
`runtime.rejects-tls-credentials-expired-certificate` and
`runtime.rejects-tls-credentials-not-yet-valid-certificate`.
A local Debian GCC 14.2/OpenSSL 3.5.5 strict C++23 API probe **PASS**:
current+matching reports valid, while expired+matching and
not-yet-valid+matching report invalid. Full repository CMake/CTest is
**NOT RUN at authoring** because this worker cannot clone GitHub through
its shell network path; exact-SHA hosted CI is required after publish.

Security limits remain explicit: no trust chain, hostname or revocation
verification, no live TLS loader, no R2/R3 admission, no listener/service
activation and no real desktop. M1-M6 remain OPEN.

**Initial exact-SHA CI:** implementation
`8dfa00a8aef833e24f6a7ad3867a16c0a37a9351`,
[Actions 38871662501](https://github.com/k1moradi/RDP-server/actions/runs/38871662501)
is **FAIL** only because the existing matching-pair CMake fixture still
expected the old success string. Linux Debug is **285/286**, macOS
**264/265**, and Windows **284/285**; in every job both new temporal
denials PASS and both owner-reported syntax/CRLF cases PASS. The
production executable compiled on all three. R9 sanitizer and
documentation-policy PASS. The correction updates only the positive
fixture's exact stdout expectation; production security behavior is
unchanged. Hosted corrected-SHA CI and owner Windows MSYS2
CLANG64/Clang 23 remain pending/NOT RUN respectively.

**Corrected exact-SHA CI:** fixture correction
`7f6d74b4ef9b03c86ecabc7c56af6f1de071ad07`,
[Actions 38871903394](https://github.com/k1moradi/RDP-server/actions/runs/38871903394)
is **PASS**. Linux/GCC **286/286**, macOS/Clang **265/265**, and
Windows/MSVC **285/285** registered CTests PASS in each Debug and
Release configuration. The two owner-reported configuration positives,
the validity-aware matching-pair success, and both new temporal denial
cases explicitly PASS on every hosted OS/configuration. R9 sanitizer,
documentation-policy, per-OS downstream SDK consumer **1/1**, protocol
ZIP/SHA256 packaging and artifact upload PASS. Untagged prerelease is
skipped. This verifies the production validity-time gate introduced at
`8dfa00a8aef833e24f6a7ad3867a16c0a37a9351` plus the test-only stdout
expectation correction; it does not verify owner Windows MSYS2
CLANG64/Clang 23, macOS27/Linux-X11 live environments, certificate
trust/hostname/revocation, live-loader continuity or service activation.

**OpenSSL 4 compatibility failure:** documentation receipt
`f249acf6d06269d895daa10db219d8c12a087e8b`,
[Actions 38872238533](https://github.com/k1moradi/RDP-server/actions/runs/38872238533)
fails macOS during Debug compilation at
`src/server/runtime/main.cpp:477/479`: Homebrew OpenSSL **4.0.3** marks
`X509_cmp_current_time` deprecated and `-Werror` turns both warnings
into errors. This is R10-owned and occurs before CTest. Linux and the
R9 sanitizer/documentation gates PASS; Windows had not completed when
the correction was authored. The follow-up uses
`X509_check_certificate_times` on OpenSSL 4+ and preserves the strict
OpenSSL 3.x comparison behind a compile-time version gate. Local
GCC 14.2/OpenSSL 3.5.5 high-warning probe **PASS**; corrected hosted
macOS/OpenSSL 4 is pending.

**Corrected OpenSSL 4 exact-SHA CI:** compatibility fix
`e540be81f297c7f880c6b03db6ffc1a3ad8998ad`,
[Actions 38872488081](https://github.com/k1moradi/RDP-server/actions/runs/38872488081)
is **PASS**. Linux/GCC **287/287**, macOS/Clang + Homebrew OpenSSL
**4.0.3** **265/265**, and Windows/MSVC **285/285** full registered
CTests PASS in each Debug and Release configuration. On all six
host/configuration combinations the two original configuration positives,
the matching TLS credential positive, and both temporal denials
explicitly PASS. R9 sanitizer and documentation-policy PASS; every
per-OS installed SDK consumer is **1/1 PASS**, and protocol ZIP/SHA256
packaging/artifact upload succeeds. Untagged prerelease is skipped.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 remain
**NOT RUN**. Certificate trust/hostname/revocation, live credential
handle continuity, R2/R3 admission and service activation remain OPEN.


## R1 bounded post-handshake TLS application I/O (2026-10-15)

**Starting main:** `1efd3688872cc38e7c932efc661c793edfd4c4b7`.
Production changes extend only the existing `OwnedPreauthTcpConnection`
SSL/BIO/socket owner with 1..18 KiB one-step application reads/writes and
explicit progress/WANT/close/fatal results. No mutable SSL/BIO/socket
handoff, protocol parsing, R2 admission, R3 authorization or R10 listener
ownership is introduced. WANT state retains only operation, exact byte count
and actual readiness direction; caller memory is never retained. Partial
writes are enabled and surfaced rather than internally retried.

New independently registered CTests:
`transport.tcp-owned-tls-application-io`,
`transport.tcp-owned-tls-application-partial-write`,
`transport.tcp-owned-tls-application-cancellation`.
They exercise real ephemeral TCP + OpenSSL TLS, byte parity, readiness,
bounds, short progress/retry rules and terminal deadline/TLS-close/FIN/fatal
paths.

**Authoring validation:** local build/CTest **NOT RUN** because this agent
sandbox has no repository checkout and cannot resolve github.com for a clone.
Exact-SHA GitHub Actions is **PENDING** immediately after the direct-to-main
publication. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27
remain **NOT RUN**. M2 remains **NOT ACCEPTED** pending genuine R2 admission,
R3 activation and Microsoft-client evidence.

## R5 native XTEST typed input boundary (2026-10-16)

**Base main at authoring:** `e6504314c87fadbb9fcf1cde7f09f9fa5b9de010`; exact implementation SHA and
hosted CI pending publication.

**Production:** `X11InputController` no longer includes xrdp message/keyboard
constant headers or libX11 keysyms. It accepts the first-party R5-native
`X11InputEvent` variant, rejects an already-failed XCB connection before
extension negotiation, catches keyboard-map allocation failure within the
`noexcept` constructor, and provides idempotent `disconnect()` that releases
held input while the XCB owner is live and then invalidates the borrowed
connection. The Linux-only noninstalled
`rdp-server-linux-xtest-input` target uses real `xcb`/`xcb-xtest` and is
not linked into the runtime; therefore this increment does not enable
unauthorized desktop input.

**Dedicated CTest:** `x11.input-native-connection-denials-and-cancellation`
links the actual controller when XTEST development files exist. It creates
`xcb_connect_to_fd(-1, nullptr)`, verifies constructor denial, checks key,
lock, pointer, button and scroll requests all fail closed, repeats
cancellation, destroys the parent XCB connection only after cancellation, and
then verifies post-owner calls/destruction remain safe. It opens no DISPLAY
and injects no live input.

**PASS locally:** GCC 14.2 C++23 `-Wall -Wextra -Wpedantic -Werror -UNDEBUG`
compile/run of the allocation-free typed event contract.

**NOT RUN locally:** actual `x11_input_controller.cpp` XTEST compilation and
the new native CTest because this authoring environment has `xcb/xcb.h` but
not `xcb/xtest.h`/`xcb-xtest.pc`; complete synchronized repository CMake/
CTest, owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27, R2/R3
authorized input routing, live Microsoft-client desktop and performance
measurements. Hosted exact-SHA CI must provide the native Linux compile/test
receipt. M3 remains unaccepted.


**Initial exact-SHA CI / const-safe test correction:** implementation
`e6504314c87fadbb9fcf1cde7f09f9fa5b9de010`,
[Actions 38865843371](https://github.com/k1moradi/RDP-server/actions/runs/38865843371)
compiled the production protocol library successfully on Linux and macOS,
and its sanitizer plus documentation-policy jobs passed. The ordinary
protocol jobs then stopped while compiling the new partial-write CTest
because `establishedTls()` intentionally returns `const SSL*`, whereas
OpenSSL 4's `SSL_get_mode` macro takes mutable `SSL*`. The correction
removes only those two test-introspection assertions; it does not cast away
constness, broaden SSL ownership, or alter production behavior. The existing
1 KiB test send fragment and required short-progress assertion remain the
behavioral proof of `SSL_MODE_ENABLE_PARTIAL_WRITE`.


**Second exact-SHA CI / nonblocking fixture timing correction:**
`68ef1e4a81284df029a4fd00a17db6d1aafdc86f`,
[Actions 38866114504](https://github.com/k1moradi/RDP-server/actions/runs/38866114504),
compiled Debug successfully on Linux and macOS; sanitizer and documentation
policy passed. The new cancellation CTest passed on both hosts and the main
application-I/O CTest passed on macOS. Linux exposed test-fixture timing:
the nonblocking client helper exhausted a yield-only retry loop before all
TLS ciphertext became readable. macOS also showed that a same-size explicit
application read retry may legitimately return WANT again before the full
record arrives. The correction keeps production one-step semantics intact:
fixture WANT loops now wait 1 ms between explicit retries, and the partial
write test resubmits the same 7-byte caller span until Progress instead of
assuming one retry is sufficient. No hidden R1 retry or retained span is
introduced.


## R9 bounded libFuzzer MCS/CLIPRDR gate (2026-10-16)

**Parent main:** `1260eb659073d5269724a4436e3a8bbfda322725`. No production behavior changes.
New `RDP_SERVER_BUILD_FUZZERS` defaults OFF and requires
Linux/Clang plus existing CTest support. `fuzz_mcs_cliprdr`
links `rdp-server-protocol` and exercises production MCS/
CLIPRDR parsing, response coordination and chunk reassembly.
`fuzz.mcs-cliprdr-bounded` runs 5000 coverage-guided
executions with fixed seed 12648430, max input 4096 bytes,
512 MiB RSS, 64 MiB allocation limit, two-second per-input
and 30-second CTest timeouts. Two binary seeds are copied
into `build/fuzz-corpus-mcs-cliprdr`; crash artifacts stay
under `build/fuzz-artifacts-mcs-cliprdr`. Existing sanitizer
CI compiles it with libFuzzer+ASan+UBSan and retains prior
15 clipboard + ten MCS/CredSSP deterministic sanitizer tests.
**NOT RUN at authoring:** exact-SHA hosted fuzz/full CI, owner
Linux/X11, Windows MSYS2 CLANG64 Clang23, macOS27, live
NLA/OS admission or Microsoft client/desktop. Any fuzzer
crash is FAIL; preserve reproducer and first production stack.

## R5 native XTEST hosted Linux receipt (2026-10-16)

**Implementation commit:** `987b4736c001edeb3cd4c2a4675080b583ca134c`.
Exact-SHA Actions run 38866079679 installed Ubuntu Noble
`libxcb-xtest0-dev` and successfully compiled/linked the real
`src/x11/x11_input_controller.cpp` target
`rdp-server-linux-xtest-input`. The shared job then stopped on the unrelated
R1 `tests/test_owned_preauth_session.cpp` OpenSSL constness compile error;
parent `e6504314c87fadbb9fcf1cde7f09f9fa5b9de010` reproduces that same
failure on Linux/GCC, Windows/MSVC and macOS/Clang.

R1 descendant `1260eb659073d5269724a4436e3a8bbfda322725` modifies only
R1 test/docs after the R5 implementation. Actions run 38866320385 builds the
unchanged XTEST production target and `test_x11_native_input`, and
`x11.input-native-connection-denials-and-cancellation` is **PASS** in
Ubuntu Debug and Release. Full Ubuntu CTests are **277/277 PASS** in Debug
and **277/277 PASS** in Release; SDK install, downstream consumer, ZIP
package/digest and upload stages PASS.

**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
same-SHA commands; authorized R2/R3 desktop/input routing; live XTEST
injection; Microsoft-client M3 acceptance; performance benchmarks. Protected
input remains disconnected from the server runtime.


**Final hosted verification:** `1260eb659073d5269724a4436e3a8bbfda322725`,
[Actions 38866320385](https://github.com/k1moradi/RDP-server/actions/runs/38866320385)
**PASS**. Linux/GCC Debug and Release each passed **277/277** CTests;
macOS/AppleClang Debug and Release each passed **258/258**; Windows/MSVC
Debug and Release each passed **276/276**. The three dedicated R1
application-I/O CTests passed in those full suites. R9 sanitizer and
documentation-policy jobs also passed; downstream installed-SDK smoke tests
passed **1/1** on each platform and the workflow concluded success. This
hosted matrix is separate from the owner's Linux/X11, Windows MSYS2
CLANG64/Clang 23 and macOS 27 environments, which remain **NOT RUN** here.
M2 remains **NOT ACCEPTED** pending genuine R2 admission, R3 activation and
real Microsoft-client evidence.

## R9 bounded libFuzzer exact-SHA CI PASS (2026-10-16)

**Exact implementation SHA:** `f3cde6d231b4f396746f3cd40628e660af5c3a3a`.
**Actions:** [38866538809](https://github.com/k1moradi/RDP-server/actions/runs/38866538809),
overall `completed/success`; `head_sha` matched implementation.
**Fuzz/sanitizer environment:** Ubuntu Clang **18.1.3**, C++23
Debug, libFuzzer plus AddressSanitizer and
UndefinedBehaviorSanitizer, LeakSanitizer enabled through
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`,
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
**PASS:** clipboard sanitizer set **18/18**, selected MCS/CredSSP
security set **10/10**, and dedicated
`fuzz.mcs-cliprdr-bounded` **1/1**. The fuzzer CTest command
is statically bounded to **5000 runs**, fixed seed 12648430,
4096-byte maximum input, 512 MiB RSS, 64 MiB allocation limit,
two-second per-input timeout and 30-second CTest timeout. Seed
corpus: valid standalone CLIPRDR Format Data Response and valid
TPKT/MCS SendDataRequest carrying that response. No ASan, UBSan,
LSan or libFuzzer crash diagnostic was present in the hosted log.

**Same exact SHA normal CI PASS:** Linux/GCC **276/276**
Debug and **276/276** Release; macOS/Clang **258/258** both;
Windows/MSVC **276/276** both. Documentation-policy, installed
SDK downstream consumer, ZIP/SHA256 and artifact upload PASS.
No first failing hosted boundary.

**Scope limit:** this 5000-run corpus is bounded coverage-guided
sampling, not exhaustive fuzzing or proof that all production
code is memory safe. The current MCS/R8 interfaces still state
that joined membership is not authenticated authorization.
**NOT RUN:** owner's unchanged Linux/X11, MSYS2 CLANG64 Clang23
and macOS27 commands, long-duration/minimized fuzz campaigns,
real CredSSP/NLA plus OS admission, Microsoft RDP client and
desktop/clipboard. M1–M6 remain open. **Next R9:** actual
authorized R3→R8 ingress and disconnect/late-response rejection
when the sole production session router exposes that contract.


## R1 immutable accepted peer endpoint (2026-10-16)

**Starting main:** `cc8e0a9cbfbbf6891720eab03f1e94b926a30285`.
Production change: the existing sole accepted socket owner now carries a
fixed-size IPv4/IPv6 `TcpPeerEndpoint` captured by the successful native
accept call itself. Address bytes remain network order; port and IPv6 scope
ID are host order. The value moves with `OwnedNativeTcpSocket`, is forwarded
by value through `OwnedPreauthTcpConnection`, and is invalidated by
close/cancel. Unsupported address-family results are closed before exposure.
No DNS, allocation, authentication, OS admission or R3 state is added.

New independently registered CTest:
`transport.tcp-native-accepted-peer-endpoint`. It checks a real ephemeral
loopback client's independently queried local address/port against the
accepted peer snapshot, move-only ownership transfer, connection-owner
continuity, and terminal cancellation invalidation while the borrowed
listener remains valid.

**Authoring status:** local repository build and CTest **NOT RUN** because
this sandbox has no mounted checkout and cannot directly clone GitHub.
Exact-SHA hosted CI **PENDING** after the direct-to-main commit. Owner
Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27 and real Microsoft-client
acceptance remain **NOT RUN**. M2 remains **NOT ACCEPTED**.


## R3 bounded licensing lifecycle authoring validation (2026-10-16)

**Starting main:** `46b1ca77c4c2c00bbd66e02de71896999f8c71fd`; reconciled without overwriting
concurrent R8/R1 work through `d4682e71e76d55dd923a8ae1e7b970e558e02f6d`. **R2 admission:**
NOT AVAILABLE; latest R2 evidence remains deny-only/CandidateOnly, so no
positive MCS admission path was added.

**Production increment:** new `src/server/transport/rdp_licensing.{h,cpp}`
plus ownership/teardown in the existing `McsSessionLifecycle`. Supported
initial client message structures are `CLIENT_NEW_LICENSE_REQUEST (0x13)`
and `CLIENT_LICENSE_INFO (0x12)`; both stop at
`AwaitServerDecision`, which is explicitly not licensing completion.
Common type/flags/16-bit total-length parsing also safely classifies all current
MS-RDPBCGR licensing message types. Hard PDU bound is 65,535 bytes; no
peer-length-driven heap allocation occurs. New-request user/machine BLOBs must
be nonempty exact null-terminated ANSI strings, and License Information must
end in exactly 16 MAC bytes.

**Focused PASS:** GCC strict C++23
`-Wall -Wextra -Wpedantic -Werror` compiled
`rdp_licensing.cpp`; a standalone production-code harness passed valid new
request and stored-license paths, every truncation prefix, declared-length
mismatch, invalid type/flags, nested BLOB length overflow/zero length, surplus,
pre-start input, duplicate server-write receipt, duplicate client input,
unexpected challenge response, post-failure/post-close input and fresh-object
reset.

**Full repository/owner platforms:** NOT RUN locally because this execution
environment cannot resolve github.com for a synchronized clone. The owner
one-root command is unchanged. Exact-SHA hosted CI is pending publication and
must be inspected separately. No real credentials, Kerberos, OS login,
listener, RDP client or desktop were used. M2 remains **NOT ACCEPTED**.


**Initial exact-SHA compile correction:** implementation
`d4682e71e76d55dd923a8ae1e7b970e558e02f6d`,
[Actions 38870971854](https://github.com/k1moradi/RDP-server/actions/runs/38870971854)
passed documentation policy but the sanitizer job stopped while compiling
`nonblocking_tcp_adapter.cpp`. The new peer parser used POSIX
`sockaddr_in`/`sockaddr_in6` without including `<netinet/in.h>`, Windows
needs `<ws2tcpip.h>` for the IPv6 socket types, and the POSIX accept branch
redeclared the shared `sockaddr_storage`. The correction is compile-only:
add the platform socket-address headers and keep one shared peer-address
storage object. Endpoint capture, ownership, fail-closed address-family
handling and the dedicated CTest semantics are unchanged.

## R5 one-XCB desktop resource owner (2026-10-16; CI pending)

**Authoring main:** `0ee521f2802bb2f2fd3fd6fa1ebfb834f4d47287`. Current source still contained the typed XTEST
controller and conditional test registration, but the concurrent R9 CMake/CI
rewrite had removed `rdp-server-linux-xtest-input` and
`libxcb-xtest0-dev`, making that native test unreachable. This change
restores them and adds the next ownership boundary.

New `X11DesktopResources` owns one `X11DisplayConnection` plus in-place
XShm, XFixes, XDamage and XTEST children. It makes no authorization decision
and is not linked into the server runtime. Child-construction failure,
explicit cancellation and destruction share one order: input, cursor,
Damage, XShm, then the XCB owner.

Dedicated `x11.desktop-resource-owner-connection-denial` uses invalid
display syntax with no server. Optional
`x11.desktop-resource-owner-lifecycle` uses ephemeral 1280x720x24 Xvfb,
verifies failed partial construction cleanup, complete construction,
idempotent explicit teardown and destructor-driven teardown, without
injecting input or consuming a real desktop frame. Hosted Ubuntu provisions
Xvfb/xauth and xcb-xtest development files.

**NOT RUN at authoring:** native composite build/CTest in this environment,
owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, R2/R3 admission,
RandR reconstruction, R4 consumers, Microsoft-client M3 and benchmarks.


### R3 bounded licensing hosted validation receipt (2026-10-16)

**Atomic R3 implementation:** `05b3814dc93360513c6c0077afa1006c1ad669a4`,
[Actions 38871063598](https://github.com/k1moradi/RDP-server/actions/runs/38871063598).
That exact-SHA workflow **FAILED at an inherited R1 compile boundary** before
the R3 CTests could link: the immediately preceding peer-endpoint change in
`nonblocking_tcp_adapter.cpp` lacked portable IPv4/IPv6 address declarations
and redeclared POSIX peer storage. Documentation policy passed, and
`rdp_licensing.cpp` itself compiled in Linux sanitizer, Linux/GCC,
macOS/Clang and Windows/MSVC builds. The three R3 licensing CTests are therefore
**NOT RUN on the implementation SHA**, not falsely counted as PASS.

R1 corrected only that compile boundary in descendant
`10fff1ab437b74f7065bdd4c87dd9a5095f1f050`,
[Actions 38871271985](https://github.com/k1moradi/RDP-server/actions/runs/38871271985).
With the R3 sources unchanged, Linux/GCC Debug and Release passed **281/281**
CTests each and Windows/MSVC Debug and Release passed **281/281** each.
`transport.licensing-preamble-and-state`,
`transport.licensing-length-bounds`, and
`transport.licensing-ordering-denials` passed in all four suites.
macOS/Clang Debug also passed all three R3 licensing tests; its full suite was
**262/263** because the unrelated R1
`transport.tcp-owned-tls-application-partial-write` aborted, so macOS Release
did not run. The descendant sanitizer job passed its configured suites; an
independent local Clang 17 ASan+UBSan+LeakSanitizer focused run of
`rdp_licensing.cpp` also passed.

Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 remain **NOT RUN**.
No real credentials, OS admission, Microsoft RDP client or desktop were used.
M2 remains **NOT ACCEPTED**.

## R5 one-XCB owner exact-SHA hosted CI PASS (2026-10-16)

Implementation `754e681a503a11c06ea60082103c3d95eb834919`,
[Actions 38871605559](https://github.com/k1moradi/RDP-server/actions/runs/38871605559):
**SUCCESS**. Linux/GCC compiled the real restored
`rdp-server-linux-xtest-input` and new `rdp-server-linux-x11-desktop`
in Debug/Release; full CTests **284/284 PASS** each. The restored
`x11.input-native-connection-denials-and-cancellation`,
`x11.desktop-resource-owner-connection-denial`, and ephemeral-Xvfb
`x11.desktop-resource-owner-lifecycle` all PASS in both. macOS/Clang full
CTest **263/263 PASS** Debug/Release; Windows/MSVC **283/283 PASS**
Debug/Release. Documentation-policy and R9 sanitizer jobs PASS; downstream
SDK consumer/package stages PASS. X11-specific tests are Linux-only.

**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
one-root commands; genuine R2/R3 admitted desktop routing; live XTEST input;
RandR geometry child reconstruction; R4 frame/cursor consumption; Microsoft
client M3 acceptance; performance benchmarks. The aggregate remains
noninstalled and unlinked from the server runtime.

## R5 bounded owner event routing and resize revocation (2026-10-16; CI pending)

**Authoring main:** `ae4f2501a1e7c42b83fafe769f6fcd049d2685e6`.

**Production:** `X11DesktopResources::processEvents` now owns one bounded,
nonblocking XCB event-service call and forwards each borrowed event to the
existing XFixes cursor and XDamage trackers. No queue, duplicate event owner,
scheduler or heap allocation is added to the dispatch path. After the display
owner applies its RandR observation, the aggregate compares source geometry
with the geometry pinned when XShm/Damage/input were constructed. Any mismatch
revokes every child and then the sole XCB connection, preventing stale capture
or input bounds. This increment deliberately revokes rather than reconstructs
the children.

`X11DisplayConnection::processEvents` no longer frees the owned connection
inside a dispatch-failure return. It immediately invalidates public readiness
and the borrowed descriptor, but retains the XCB allocation until explicit
`disconnect()`/destruction. That permits the aggregate to clear every child
borrow before the sole XCB allocation disappears.

**Dedicated CTests:** `x11.desktop-resource-event-routing` runs under
ephemeral Xvfb, modifies only its synthetic root via a checked ClearArea
request, and verifies the real production XDamage notification reaches the
aggregate. `x11.display-event-failure-defers-owner-teardown` runs under
ephemeral Xvfb, sends one invalid unchecked DestroyWindow request, observes
the protocol error through the real bounded event drain, verifies public XCB
access is revoked while the previously borrowed allocation is still alive,
then performs explicit idempotent teardown. Existing owner lifecycle and
headless denial cases remain registered. No test injects keyboard/mouse input,
uses credentials, or touches a logged-in desktop.

**NOT RUN at authoring:** synchronized local native build/full CTest in this
environment, exact-SHA hosted CI, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27, a genuine RandR geometry-change notification,
R2/R3 admitted desktop routing, R4 frame/cursor consumption, Microsoft-client
M3 acceptance, or performance benchmarks.

## R5 bounded event routing exact-SHA hosted CI PASS (2026-10-16)

Implementation `ba59c94c7ab07c688d6b19ee8d440ddcd98acee8`,
[Actions 38873077390](https://github.com/k1moradi/RDP-server/actions/runs/38873077390):
**SUCCESS**. Linux/GCC full CTest **289/289 PASS** Debug and Release.
`x11.desktop-resource-event-routing` and
`x11.display-event-failure-defers-owner-teardown` passed in both, along
with the existing XTEST and one-XCB owner cases. macOS/Clang **265/265 PASS**
Debug/Release; Windows/MSVC **285/285 PASS** Debug/Release. Documentation
policy, R9 sanitizers, installed-SDK consumer/package/digest/upload PASS.

**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
one-root commands; genuine RandR resize; R2/R3 admitted desktop routing;
live XTEST input; R4 frame/cursor consumption; Microsoft-client M3;
performance. The native aggregate remains noninstalled and unlinked.


## R1 loopback accept visibility fixture correction (2026-10-16)

**Starting main:** `9cf14768fbdda1a053c80aee5d34285f63f8a0c2`.
The immutable accepted-peer endpoint implementation itself is verified at
`10fff1ab437b74f7065bdd4c87dd9a5095f1f050`,
[Actions 38871271985](https://github.com/k1moradi/RDP-server/actions/runs/38871271985):
`transport.tcp-native-accepted-peer-endpoint` **PASS** on Linux, macOS and
Windows Debug. Linux/GCC and Windows/MSVC full Debug+Release suites each
passed **281/281**. macOS Debug passed **262/263**; its sole failure was the
R1 `transport.tcp-owned-tls-application-partial-write` fixture at
`test_owned_preauth_session.cpp:2242`, where a just-connected loopback peer
was assumed to be immediately visible to nonblocking `accept`. macOS Release
did not run because Debug failed first. Sanitizer and documentation-policy
jobs passed.

This correction changes TEST fixtures only. A shared
`waitForAcceptedLoopbackConnection` retries the existing one-step
`acceptNonblockingTcpConnection` for at most 2048 one-millisecond attempts,
accepting only `WouldBlock` until the queued peer becomes observable. It is
used by the newly added peer-endpoint test and all post-TLS application-I/O
fixtures. Production listener/accept behavior, ownership, deadlines, TLS,
R2/R3 authority and byte-stream semantics are unchanged. The bounded helper
exists solely to remove scheduler timing from the loopback oracle.


## R3 native admission handoff exact-SHA validation (2026-10-16)

**Atomic implementation:** `70897645ed1f822c081747024a847a0928e18f15`,
[Actions 38873422752](https://github.com/k1moradi/RDP-server/actions/runs/38873422752),
overall **SUCCESS**. The concrete `LinuxConsoleAdmissionBroker` is the only
friend able to enter positive MCS state. It revalidates
`kConsoleViewPermission` and live native GSS/TLS + NSS/logind provenance,
then invokes R3 synchronously. A successful complete Connect Initial binds the
lease admission generation and native session generation and stops at
`AwaitConnectResponse`; public MCS intake remains denial-only. Parse/order
failure revokes both R3 and the R2/GSS capability. The cancellation helper
closes R3 before R2/GSS, leaving R1 TLS/socket release as the caller's next
teardown step.

The dedicated Linux CTest
`security.gssapi-r3-mcs-admission-contract` statically requires the exact
`LinuxConsoleAdmissionLease const&` API and rejects a Boolean substitute;
runtime coverage verifies fresh R3 state and repeatable R3-before-R2
cancellation without fabricating a positive lease. It passed under hosted
Linux/GCC in both Debug and Release. Full hosted suites: Linux **290/290**
Debug + **290/290** Release; macOS **265/265** Debug + **265/265** Release;
Windows **285/285** Debug + **285/285** Release. The portable R3 production
sources compiled on all three hosted platforms. R9 ASan/UBSan configured
security coverage passed **19/19 clipboard**, **10/10 MCS/CredSSP**, plus
`fuzz.mcs-cliprdr-bounded` **1/1**. Documentation policy and each installed
SDK consumer passed; packaging/artifact upload succeeded.

A concurrent R6 commit based on an older shared-file snapshot later removed
the R3 documentation tail and Linux CTest registration while leaving all R3
production sources intact. This follow-up restores only those shared entries
and corrects the header comment to match the implemented rule that a valid
peer Disconnect is teardown in either open phase.

**NOT RUN:** genuine positive Kerberos + physical logind lease issuance into
R3, owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, Microsoft RDP
client and desktop activation. These are required before M2 acceptance.


### R1 loopback accept visibility final hosted result (2026-10-16)

Correction SHA `45dc57878bcc741a87bd2ba8b9b9edf15588f062`,
[Actions 38873727660](https://github.com/k1moradi/RDP-server/actions/runs/38873727660).
The bounded accept fixture correction is verified across the exact R1 cases:
macOS/AppleClang **265/265 Debug and 265/265 Release PASS**;
Windows/MSVC **288/288 Debug and 288/288 Release PASS**;
Linux/GCC **289/289 Debug PASS**. Linux Release compiled successfully and
every R1 transport test passed, including
`transport.tcp-native-accepted-peer-endpoint`,
`transport.tcp-owned-tls-application-io`,
`transport.tcp-owned-tls-application-partial-write`, and
`transport.tcp-owned-tls-application-cancellation`, but the full suite was
**288/289** because unrelated
`x11.desktop-resource-owner-lifecycle` failed at
`tests/test_x11_desktop_resources.cpp:115` on
`assert(resources.valid())`. That X11 failure is outside R1 and is not
modified here. R9 sanitizer and documentation-policy jobs **PASS**; the
overall workflow conclusion is therefore **FAIL** solely because of the
Linux Release X11 failure.

No production R1 source changed in this correction. The immutable accepted
peer endpoint, bounded post-TLS application I/O, sole socket/BIO/SSL
ownership, R2/R3 authorization separation and R10 listener ownership remain
unchanged. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27 and
real Microsoft-client validation remain **NOT RUN**; M2 remains
**NOT ACCEPTED**. **Next R1 dependency:** consume concrete R2/R3 integration
feedback; do not add another transport surface without a demonstrated
missing hook.
