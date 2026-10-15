# RDP-server protocol roadmap and acceptance gates

## Target

Develop an independently maintained, secure, standards-compliant C++23 RDP
server protocol stack, portable across OSes via system adapters. Use native
RDP capabilities, not VNC, xrdp, clipboard injection helpers, or nonstandard
screen-sharing workarounds.

## Status: foundation, not release

Current code includes X.224/TPKT, selected MCS/GCC parsers, negotiation,
CredSSP/DER and CLIPRDR helpers, verified graphics algorithms and portable
testable core. It does **not** yet operate a complete authenticated RDP
server session. The library has no shipping daemon/installer.

## Parallel delivery plan — 10 agent roads, 6 convergence milestones

**Parallel implementation, synchronized acceptance.** Ten GPT-6-High
engineering agents/workstreams may design and implement independent code
in parallel, but they contribute to **one portable C++23 RDP server** with
one authoritative connection/session owner. The human project owner is
**not** an eleventh engineering road: the owner runs the agreed build +
CTest one-liner independently on Linux/X11, Windows MSYS2 CLANG64 with
Clang 23, and macOS 27, and reports results. Platform development and
automated testing run **in parallel from the beginning**; *human desktop
acceptance* runs in order Linux/X11 -> Windows -> macOS. This order does
not delay Windows/macOS implementation or portable test coverage.

### Ten independent engineering workstreams (R1–R10)

Each row owns a bounded implementation area and its **own new, dedicated
behavior-named CTest case(s)** registered in the existing single
`tests/CMakeLists.txt` registry, normally reusing existing test
executables and fixtures. A test must execute the changed production
behavior, with meaningful positive, negative, bounds and teardown
assertions where applicable. Building the static library or passing
someone else's previous tests is **not** evidence for new code. Platform
specific tests may be registered conditionally; report them NOT RUN on
other platforms, never silently call a skip a PASS. Do not create
parallel test registries, duplicate state controllers or one executable
per tiny behavior.

| Road | Agent-owned scope and first deliverable | Interface/dependency to converge |
| --- | --- | --- |
| **R1 Transport** | Bounded native TCP accept/read/write, pinned OpenSSL TLS socket, nonblocking partial-I/O, cancellation and disconnect; test live loopback lifecycle/failures without unauthorized admission. | Supply immutable active TLS/peer identity and reliable bounded I/O to R2/R3. |
| **R2 Identity/security** | Real, opt-in Kerberos/GSS CredSSP/NLA positive path, active TLS binding, independent native OS identity/session authorization and fail-closed denials. | Provide a verified admission decision to R3; request OS-policy adapter facts from R5/R6/R7 without granting sessions by synthetic tokens. |
| **R3 RDP session/router** | **Sole** authoritative server session state, MCS/GCC attach/join, licensing, capabilities, Demand/Confirm Active, finalization and virtual-channel routing. | Consume R1 I/O + R2 admission; export bounded authorized graphics/input/clipboard channel contracts to R4/R8 and OS adapter lifecycle to R5–R7. |
| **R4 Graphics** | Static license-reviewed x264 C++23 RAII integration; negotiated RDPGFX AVC420, DVC framing, surfaces, ACK/backpressure, dirty-region frames, resize and reconnect. | Consume abstract captured-frame/cursor data from R5–R7 and channel access from R3; own the **one** frame schedule. |
| **R5 Linux/X11 adapter** | X11 capture, pointer/keyboard/cursor, display/session lifecycle and OS authorization adapter; deterministic native tests. | Implement portable frame/input/identity interfaces; first authorized desktop-acceptance target (M3). |
| **R6 Windows adapter** | Native Windows desktop capture, pointer/keyboard/cursor, identity/session policy and lifecycle; validate in **MSYS2 CLANG64, Clang 23**. | Implement the **same** interfaces as R5, not a second RDP engine; develop now, human acceptance at M4. |
| **R7 macOS adapter** | Native macOS capture, input, cursor, permissions, identity/session and lifecycle for **macOS 27**. Initial internal CoreVideo/Retina/TCC-preflight adapter compiled with dedicated offline CTests; full macOS 27 verification and live capture remain NOT RUN. | Implement the **same** interfaces as R5; develop now, human acceptance at M5. |
| **R8 Clipboard/files** | One native CLIPRDR lifecycle; text, PNG/DIB/DIBV5, generation-safe X11/Windows/macOS ownership and bounded on-demand file transfer. | Use R3's virtual-channel router and OS clipboard adapters; not a blocker for first visible Linux desktop, but required for declared full-feature release. |
| **R9 Quality/interoperability** | Independently authored dedicated CTests for new integration boundaries, fuzz/sanitizer negatives, CI triage, Microsoft-client matrix, performance/reliability regression and verification receipts. | Validate every road; maintain **one test registry** and integrate cross-road fixtures rather than duplicate behavior owners. |
| **R10 Runtime/release** | Standalone first-party server executable, secure startup/configuration, packaging, service/termination, installation, upgrades, rollback, release evidence and commit integration coordination. | Consume R1–R9 verified interfaces; SDK ZIPs alone never count as deployable server artifacts. |

**R10 secure offline runtime configuration boundary (2026-10-15;
implementation pending exact-SHA CI):** The non-installable `rdp-server` executable
links the existing portable protocol library. `--help` and `--version`
remain informational. New `--check-config FILE` validates a *syntax-only*
4,096-byte maximum configuration with required unique settings:
`listen_address`, `listen_port`, `tls_certificate`, `tls_private_key`,
`authentication`, `os_authorization`, and `max_connections`. The
preliminary policy accepts only loopback, port 1–65535, absolute and
different cert/key path strings, `authentication=required`,
`os_authorization=required`, and 1–64 connections. Malformed, unknown,
duplicate, missing, oversize, control-byte and unsafe values are
rejected. Even syntactically accepted configuration **cannot start** a
listener, authenticate a user or authorize a desktop. Real TLS key
contents, permissions, Kerberos/OS policy, and runtime service gates
have NOT been verified or implemented.

**Local isolated PASS:** Linux GCC 14.2 and Clang 17 strict C++23 builds,
25/25 direct CMake-script behavior checks each, then the same 25/25
with each compiler under ASan+UBSan. A scratch offline harness using
the *same CTest registration text* passed 25/25 tests in both Debug
and Release (GCC 14.2); it does not link/build the whole repository.
Files and executables stayed inside `~/rdp-server/build/`.
No full repository CMake/CTest, owner
three-platform checkpoints or CI ran for this pending patch; M1–M6
remain unaccepted. Parent `main`:
`2ee2d1371a98b237c68cee061eea13811278d8f6`.
**Publication:** the containing main commit delivers code, tests and
documentation atomically using non-force, expected-HEAD update.
Exact-SHA CI and owner results are NOT RUN at authoring.
**Next:** full Debug/Release CTests and SDK/package regression,
then independent same-SHA owner acceptance.
**R10 Windows CRLF fixture regression (2026-10-15):** The first
published R10 increment `a7234f40c4e2188b1170daf363136a6ac159c025`
passed the Ubuntu/GCC and macOS/Clang CI jobs, but Windows/MSVC Debug
failed `runtime.validates-configuration-comments-crlf` (test 137 of 154)
with exit 3; the other 24 R10 runtime cases passed there. This follow-up
normalizes existing CR bytes before generating CRLF and verifies the
synthetic fixture's written bytes using `file(READ HEX)`. Isolated Linux
focused CTest **25/25 PASS**; corrected exact-SHA Windows CI is
**NOT RUN at authoring**. No production policy is relaxed, and M1–M6
remain unaccepted. Next: full Debug/Release CI and owner one-root tests.

**R10 follow-up Windows newline compatibility (2026-10-15):**
The first correction `b90baa6d76d769fce18a216d055c081375cd9b89`
passed Linux/GCC and macOS/Clang in
[Actions 38797088304](https://github.com/k1moradi/RDP-server/actions/runs/38797088304),
but Windows/MSVC Debug failed the same CRLF case with a raw fixture-byte
mismatch (164/165 CTests passed). CMake `file(WRITE)` on that host
converts LF to CRLF; this test-only correction supplies LF to Windows
and explicit CRLF on POSIX, then verifies exact canonical CRLF bytes
with `file(READ HEX)`. Local Linux Debug/Release isolated harness
**25/25 PASS** each. Corrected Windows CI **NOT RUN at authoring**;
M1–M6 remain open, no production runtime security change.

**R10 exact-SHA cross-platform CI acceptance (2026-10-15):**
Corrected runtime test commit `853e572dafdeab18161afa3926db2f29d2ec3a34` passed
[Actions 38797522248](https://github.com/k1moradi/RDP-server/actions/runs/38797522248). Linux/GCC **170/170**,
Windows/MSVC **166/166**, and macOS/Clang **158/158** registered
CTests in EACH Debug and Release configuration. Downstream SDK
consumer **1/1** on all three platforms; install, ZIP/SHA256
packaging/artifact uploads and documentation-policy PASS. Protocol
SDK prerelease publication SKIPPED (no version tag). Windows CRLF
configuration fixture now passes in both configurations. This is
HOSTED CI evidence only: owner Linux/X11, Windows MSYS2 CLANG64
Clang 23 and macOS 27 independent CTests are NOT RUN; live RDP
identity, desktop, service, installer and M1–M6 milestone acceptance
remain OPEN. The executable remains non-installable and fail closed.

**Ownership discipline:** R3 alone owns the session and channel lifecycle;
R4 alone owns graphics scheduling; R8 alone owns clipboard generation;
R1 owns encrypted socket I/O; R2 owns admission decisions. R5/R6/R7
implement native OS adapters behind the same portable contracts.
Road-specific development may be offline and fixture-driven before
upstream dependencies exist, but an offline PASS cannot promote a live
end-to-end dependency to ACCEPTED. All cross-road API changes must have
an agreed owner and a minimal consumer-facing test.

### Six mandatory convergence milestones (M1–M6)

These are **integration checkpoints, not ten independent product
releases**. Existing detailed P0/P1 checkboxes and historical evidence
below remain the sole living implementation TODO; the roads specify
ownership and convergence, not a second checklist. For each milestone
record the exact same tested SHA, real environment, new CTest names,
PASS/FAIL/BLOCKED/NOT RUN and first failed boundary. Never claim a
Microsoft-client or live-OS acceptance from offline fixtures.

| Milestone | Required roads at convergence | Objective acceptance / exit criterion |
| --- | --- | --- |
| **M1 — Portable contracts and CI baseline** | R1–R10 contracts; R9 verification | All new code has its dedicated registered CTest; shared C++23 core + implemented native adapter test targets compile where supported. Same integration SHA has Linux, Windows CLANG64/Clang 23 and macOS 27 Debug/CTest owner results; existing GCC/MSVC/macOS Actions remain additional, **not substitute** coverage. Open external-client gates remain NOT RUN. |
| **M2 — Authenticated RDP activation** | R1 + R2 + R3 + R9 | A current real Microsoft client completes authorized TLS/NLA, OS identity admission, live MCS/channel joins, licensing/share activation and clean disconnect on the first isolated Linux test target. Reject bad identities/certs, downgrade, premature messages and unauthorized channels. No desktop claim yet. Windows/macOS code and CTests continue simultaneously. |
| **M3 — Linux/X11 human desktop** | M2 + R4 + R5 + R9 + minimal R10 launcher | Separately authorized human connects with a Microsoft client and sees real X11 desktop; mouse, keyboard, terminal typing/scrolling, menus, AVC420 surface updates, resize and disconnect/reconnect work. Unsupported AVC fails cleanly. R6/R7 do not wait for M3 to start coding or CTests. |
| **M4 — Windows human desktop** | Accepted shared core + R4 + R6 + R9 + R10 test launcher | Real authorized Microsoft-client interaction with the **Windows server** built/tested using MSYS2 CLANG64/Clang 23: identity/session, visible desktop, input, resize, reconnect and negative cases. Keep Linux regression coverage green. |
| **M5 — macOS human desktop and feature beta** | Accepted shared core + R4 + R7 + R8 + R9 | Real authorized Microsoft-client interaction with the **macOS 27 server**: identity, screen permissions/capture, input, resize/reconnect and negative cases; integrate and accept release-scope CLIPRDR text/image/file semantics on **each applicable OS** before calling feature beta complete. Linux/Windows automated regression stays green. |
| **M6 — Cross-platform production release** | R1–R10 accepted; R9 security + R10 operations signoff | Same release candidate passes all three specified platform CTest runs, each supported platform's human desktop/declared clipboard scope, realistic load/reconnect/soak, fuzz and supported sanitizers, security negatives, installation/upgrade/rollback, resource and performance budgets. Deploy only after explicit approval; no claim of all-platform readiness from SDK ZIPs or one OS's result. |

**Mapping of older acceptance terminology:** existing P0 annotations
labeled *Gate A* feed M2; *Gate B* feeds M3–M5; *Gate C* feeds the
human desktop acceptance in M3–M5; *Gate D* feeds M6; earlier
*Gate E* expansion is covered by R8 and M5/M6 as applicable. These
labels are historical references, **not additional milestones**.
Linux/X11 is merely the first human trial; Windows and macOS OS-server
implementation, dedicated CTests and toolchain validation begin now.
Codec expansion, Wayland and further OS support remain separately scoped,
not prerequisites for the defined three-platform release.

### Agent integration and the owner's independent platform test

**GitHub main-only development — publish working code, not patches:**
**All development and commits must occur on existing `main`; creating
ANY other Git branch (local, remote, temporary, feature, hotfix, release,
experimental, agent-specific or branch-backed worktree) is prohibited.**
Each of R1–R10 is expected to **complete and directly commit its own
implementation, newly registered dedicated CTest(s), and updated existing
roadmap/documentation together to GitHub `main`**. No agent should
conclude ordinary work by handing over a patch or asking R10 to push on
its behalf. R10 handles cross-road integration and CI triage, not
gatekeeping the publication of independent, safely prepared changes.

**Concurrency control uses GitHub's current HEAD, not manual waiting
for an exclusive publication slot.** Immediately before publishing,
fetch `main` HEAD and the actual versions of affected source, CMake,
test registry and roadmap files. Construct one complete atomic commit on
the latest HEAD and publish it through a **non-force fast-forward update
that checks the expected old HEAD SHA**. Only one concurrent update can
succeed against a given expected HEAD. If another agent won the race,
re-read `main`, reconcile/merge the intended changes into the newer
files (especially `tests/CMakeLists.txt` and `docs/ROADMAP.md`),
repeat relevant validation if available, and retry. Never force-update
a ref, blind-reset, lose another road's edits, publish stale whole-file
replacements, create a branch or split code/test/docs across separate
misleading commits. Do not mark work complete until its direct-to-main
commit SHA is verified. Report BLOCKED only for an actual non-resolvable
conflict, lack of write permissions or comparable technical obstruction,
and report exact evidence. The absence of an R10 publication slot is
**not** such a blocker. Each isolated local checkout retains its one
`build/` root; the owner's three computers each maintain their own.

**Dedicated test contract:** every source/header/runtime/build behavior
change is paired with at least one **new distinct behavior-named CTest**
registered in the central registry, normally as a case of an existing
executable. Cover new functionality with positive and fail-closed
cases, and preserve all prior registered cases. Documentation-only
planning edits do not assert execution or require a new production-code
CTest. GitHub Actions compiles/tests every published integration; report
the actual jobs and exact SHA, not an assumed pass. The owner's terminal
runs are separate authoritative environment evidence; agents must not
record them as PASS until the owner reports the results.

**Owner's normal platform test — direct from current `main`:**
On each platform, the owner opens a terminal in the required compiler
environment and runs the **exact unchanged one-liner** below after an
agent's commit reaches GitHub. This is the required everyday
development-feedback workflow; agents must publish testable code and
registered dedicated CTests before asking for owner verification.
No patch application, cherry-pick, manual integration, alternate branch,
special test flags, additional build root or live service is required.

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

**Agents are responsible for making this command pass** on supported
platforms, including adding their dedicated, deterministic and
noninteractive CTests to the existing registry. Failures reported by
the owner must be diagnosed and corrected with another direct-to-main
code+CTest+docs commit. This procedure tests the locally checked-out
`main` commit even if GitHub `main` advances subsequently. For a
same-SHA three-platform milestone, record `git rev-parse HEAD` for each
Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 test report;
if the SHAs differ, repeat affected platform runs against a common
nominated HEAD before declaring the convergence gate. Do **not**
automatically block everyday development commits pending human reports
or a coordinator-managed freeze. If the owner explicitly requests a
temporary same-SHA checkpoint freeze, honor it while in effect.
Report CMake-selected compiler and CTest counts, not assumed platform
success; a cached Windows CMake configuration may select a compiler
other than the expected Clang 23. Native-only tests are conditional, and
skipped/unavailable tests are NOT RUN rather than PASS.

The terminal one-liner authorizes ordinary compilation and noninteractive
CTest only; genuine RDP client login, native desktop capture/input,
real clipboard transfers and service modifications remain separately
authorized acceptance tests. The owner is responsible only for running
the three commands and reporting PASS/FAIL, not writing CTests, resolving
agents' Git conflicts, applying patches or doing integration.

## Acceptance policy

- Every production-code increment has at least one **new dedicated,
  behavior-named CTest** exercising the changed functionality and
  registered in the **one** existing `tests/CMakeLists.txt` registry.
  Reuse shared executables/fixtures; preserve previous tests. Tests for
  OS-specific code run on the applicable native platform and report
  NOT RUN elsewhere. Owner reports from the same exact integration SHA
  are needed for the three-platform test checkpoint.
- Offline CTest and static library compilation are foundation gates.
- Native protocol integration, TLS/NLA security, external clients, graphics,
  input, clipboard, session admission, OS backends and real desktop access
  are **not yet accepted**; never infer them from a green unit test.
- **All development and commits must target existing `main`. Creating
  any new Git branch is prohibited for everyone, including agents,
  contributors and automation.** No feature, hotfix, release, temporary,
  local/remote or branch-backed worktree branches; no exceptions under the
  current project policy. Publish to `main` only with a verified
  single-writer slot and non-force fast-forward update; never during
  the owner's exact-SHA platform-validation freeze.
- Preserve attributions and third-party licenses for upstream-inspired code,
  but do not depend on an xrdp daemon, patched chansrv or VNC runtime.
- Target **practical interoperability with current Microsoft RDP clients**,
  not an official Microsoft certification claim. The first graphics milestone
  deliberately supports only negotiated H.264 for encoded bitmaps; it does
  not claim full MS-RDPEGFX implementation conformance, which specifies
  ClearCodec support. Reject sessions lacking compatible AVC capabilities
  cleanly instead of sending an unnegotiated format or claiming success.

## Living TODO — authoritative project checklist

This is the **single current TODO list**, required context on **every
prompt**. Update the *same* item when implementation, blocker or evidence
changes; don't create another milestone list. Apply [VISION](VISION.md)
and the four mandatory [coding](coding_standards.md),
[testing](testing_standards.md), [build](compile.md) and
[benchmark](benchmark.md) standards. Checkboxes require measured
acceptance evidence; no synthetic completion claims.

**Execution priority (2026-10-15; parallelized):** maintain the existing
P0/P1 implementation checkboxes as **one authoritative TODO**, but
assign their implementation to R1–R10 above. A/B/C protocol
dependencies converge at M2 while R4/R5/R6/R7/R8 develop and register
their dedicated CTests concurrently. Linux/X11, Windows MSYS2 CLANG64
(Clang 23) and macOS 27 all receive parallel development/automated
verification; their separately authorized *human* acceptance is staged
at M3/M4/M5. Road R10 serializes main commits and freezes nominated
test SHAs while the owner runs three terminal checks. Keep prior
per-commit evidence intact and add real-client transcripts only when
actually run; another parser CTest alone is not a complete session.

### P0 — Preserve work and implement a native RDP server

- [x] Independently compile/test C++23 static protocol foundation;
  historical Actions run 38516048776 succeeded at 77c94c75b467.
  This **is not** a working RDP desktop server.
- [x] Retire the obsolete legacy-source migration guide and both import
  scripts by owner request. The original project was **not fully
  imported**; only the maintained, checked-in first-party code is in
  scope for ongoing development. Additional historical source requires
  a separately authorized and reviewed integration, not an automatic
  import. This is a cleanup gate, not a functional RDP milestone.
- [ ] Implement bounded X.224/TPKT/MCS/GCC network listener and complete
  standards-compliant server connection state machine with external-client
  handshake and malformed-packet evidence.
  **Gate A integration acceptance (NOT RUN):** bind the existing
  preauthentication parser and TLS transport to a real first-party
  listener and one connection owner. Prove a current Microsoft client
  receives correct live MCS/GCC responses and advances through the
  authenticated channel/share lifecycle; the loopback TLS intake
  diagnostic by itself remains insufficient.

  **R1 native accepted-socket implementation (2026-10-15; new-code CI pending):**
  Extend the ONLY existing native TCP adapter with a one-shot nonblocking
  accept operation returning a move-only, RAII-owned connection handle;
  the caller retains its listening socket. Linux uses atomic
  `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)`; macOS/BSD apply checked
  nonblocking/close-on-exec/SO_NOSIGPIPE configuration; Winsock applies
  nonblocking and non-inheritable handle setup. Failed configuration
  closes only the just-accepted socket. No new TLS/session controller,
  daemon, bound/listening production port, admission, or MCS response.
  Three dedicated CTests: `transport.tcp-native-accept-ownership`,
  `transport.tcp-native-accept-move-replacement` and
  `transport.tcp-native-accept-orderly-eof` reuse real loopback fixtures
  for X.224 negotiation, invalid listeners, would-block, move replacement,
  FIN after queued data, EOF, and idempotent cancellation without closing
  the borrowed listener. Expected registry: 104 portable / 114 Linux GSS
  (prior 101/111).
  Owner separately reports 101/101 existing tests PASS; exact local SHA
  and platform were not supplied, and this new CTest was not included.
  Integration parent main: `96dbdc660cc9814d086cfb3c7772850474b8f2fd`.
  **PASS:** isolated Linux GCC 14.2 / Clang 17 C++23 warning-clean,
  ASan+UBSan accept/ownership/EOF smoke (native `accept4` and simulated
  portable POSIX fallback). **NOT RUN:** full checkout build, registered
  dedicated CTests, owner Windows CLANG64/macOS27 and new-code CI at
  authoring time. Commit directly to `main` under optimistic HEAD check. First boundary remains a
  production listener/event loop feeding this accept into the one
  owned TCP/TLS session, followed by R2/R3 authenticated activation.


  **R1 accepted-socket TLS/BIO lifetime increment (2026-10-15;
  integration parent `a7234f40c4e2188b1170daf363136a6ac159c025`; exact new-code CI pending):**
  `OwnedPreauthTcpConnection` is one nonmoving, single-event-loop owner
  of the accepted native socket, existing `NativeTcpIo` /
  `PreauthTcpAdapter` and transferred server `SSL` and its borrowed BIO.
  It forwards X.224/TLS/MCS diagnostic readiness to the existing
  protocol stages; on cancellation, errors or diagnostic completion it
  clears preauth, frees SSL/BIO and only then closes the accepted socket.
  The listener is never owned. Two new registered CTests:
  `transport.tcp-owned-connection-tls-lifecycle` drives native
  loopback through X.224 Confirm, negotiated TLS and encrypted first
  MCS/GCC intake; `transport.tcp-owned-connection-cancellation`
  covers invalid handles, partial X.224, cancel before ClientHello,
  idempotence and listener preservation. No new session state controller,
  production listener, authentication or OS session access.
  **NOT RUN at authoring:** dedicated/full repository CTest, hosted
  new-code CI and owner's three platform toolchains; isolated previous
  R1 socket accept/EOF sanitizer checks PASS. Next: bounded readiness
  polling/cancellation and R2/R3 authorized lifecycle integration.

  **R1 published exact-SHA CI receipt (2026-10-15):**
  [implementation `50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb`](https://github.com/k1moradi/RDP-server/commit/50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb)
  and [Actions run 38796272916](https://github.com/k1moradi/RDP-server/actions/runs/38796272916).
  **PASS:** both dedicated R1 CTests in hosted Linux/GCC Debug+Release
  (**159/159** each), macOS/Clang Debug+Release (**148/148** each), and
  Windows/MSVC Debug (**both R1 cases passed**). Documentation-policy PASS.
  **FAIL:** hosted Windows full Debug CTest **155/156**; ONLY unrelated
  R10 `runtime.validates-configuration-comments-crlf` returns exit
  3 instead of 0, tracked in
  [R10 Issue #9](https://github.com/k1moradi/RDP-server/issues/9).
  Windows Release **NOT RUN** due to failing Debug. Owner Linux/X11,
  Windows MSYS2 CLANG64/Clang23 and macOS27 exact-SHA tests **NOT RUN**;
  R2 credential authorization and R3 authenticated activation NOT ACCEPTED.
  Next R1 boundary: bounded readiness scheduling and deterministic timeout
  release around the owned native TCP/TLS connection.


  **R1 bounded readiness dispatch and monotonic cancellation increment
  (2026-10-15; parent `db62ec72f84c5b83adbedd72a2606b4db9470ec7`; exact new-code CI pending):**
  Extend the EXISTING nonmoving `OwnedPreauthTcpConnection` with
  `ioInterest()` and `onSocketReady(readable,writable)` that derive the
  next read/write event from its one `PreauthConnectionStream` stage,
  pending X.224 response and active OpenSSL `SSL_want_write` (including
  post-handshake MCS reads). Dispatch at most ONE previously bounded
  native preauth, TLS or diagnostic-MCS callback per matching event,
  and ignore empty, wrong-direction, pre-TLS and stale events without
  opening a socket or spinning. A caller-provided steady-clock
  `cancelIfExpired(now,deadline)` releases SSL/BIO before native socket;
  a short-lived `const SSL*` borrow is available only after actual TLS
  establishment, NOT an authenticated identity decision.
  New dedicated behavior CTests
  `transport.tcp-owned-readiness-dispatch` and
  `transport.tcp-owned-deadline-cancellation` reuse the existing test
  executable and native 127.0.0.1:0 loopback; exercise split plaintext,
  no premature TLS, full Confirm/failure-response delivery, real TLS
  and encrypted MCS, wrong/stale readiness, deterministic deadline
  expiration and listener preservation. No new poller, protocol state
  authority, listener manager, TLS credential policy, R2 admission or
  R3 session. **NOT RUN at authorship:** new code CMake/full CTest,
  new exact-commit GitHub Actions and owner's Linux/X11, Windows
  CLANG64 Clang23 or macOS27 toolchains (clone DNS unavailable in
  worker). Previous R1 integration Linux GCC/macOS Clang suites and
  Windows R1-specific cases PASS at `50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb`.
  The current Windows full CTest still reports a separate R10 CRLF
  configuration test FAIL (Issue #9). Next R1: hand readiness and a
  bounded listener accept budget to R10's already authorized runtime
  without bypassing the R2/R3 security gates.

  **R1 direct-to-main readiness repair (2026-10-15; parent
  `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`):** Initial new-code [Actions run
  38798562218](https://github.com/k1moradi/RDP-server/actions/runs/38798562218)
  exposed two R1 CTest failures on Linux: dispatcher picked
  `ConfigureTls` after the Connection Request advanced to `AwaitTls`
  but its 19-byte Confirm was still queued. The same precedence applies
  to a permitted failure reply after rejection. Fix `ioInterest` and
  `onSocketReady` to prioritize any pending X.224 reply suffix
  regardless of diagnostic stage, then dispatch through the existing
  bounded `onWritable` until fully sent before TLS or terminal close.
  Add dedicated `transport.tcp-owned-reply-interest-priority` CTest
  for both successful Confirm and rejected NEG_FAILURE, wrong-direction
  wakeups, exact bytes and listener preservation. **FAIL** initial
  new-code Linux focused/full CTest; corrected code exact-SHA CI
  **NOT RUN** at authoring. This is a test-detected R1 production fix,
  not an authentication success. No second stage owner or event loop.

  **R1 portable nonblocking readiness-fixture repair (2026-10-15;
  parent `3b22e8fa018d093339f4d1f5e7c44fe90ef7b4f3`):** Exact repair-SHA [Actions
  38799213949](https://github.com/k1moradi/RDP-server/actions/runs/38799213949)
  verified **PASS Linux 176/176 Debug+Release** and
  **PASS Windows full Debug+Release**, including all three new R1
  behavior CTests. macOS Debug **164/164 PASS**; macOS Release
  **163/164 FAIL** only
  `transport.tcp-owned-deadline-cancellation`: its new test fixture
  incorrectly assumed one nonblocking receive always collects a full
  X.224 request immediately after the client's send. The actual
  transport can validly return `Read` for partial bytes on any OS.
  Repair test-only synchronization with a bounded 2,048-step retry,
  never a production poller or relaxed protocol assertion; reuse this
  helper in readiness/denial/deadline tests. Corrected exact-SHA CI
  **NOT RUN** at authoring. Owner Windows CLANG64/macOS27 tests
  **NOT RUN**. No production behavior, privilege or admission change.

  **Verified R1 bounded TCP/BIO syscall integration increment
  (2026-10-15; exact-head CI PASS):** Reuse the
  ONLY existing `NativeTcpIo` and custom OpenSSL
  `TcpNonblockingIo` BIO, without adding a listener or
  controller. Enforce an 18 KiB maximum **per native
  recv/send and BIO callback** (RFC 5246 TLS 1.2
  ciphertext maximum 2^14+2048; compatible with
  RFC 8446 TLS 1.3 maximum 2^14+256). Return actual
  short progress to OpenSSL, preserve WANT_READ/
  WANT_WRITE retry flags on would-block only, reject
  provider misreported lengths even if <= the caller's
  originally larger buffer, and avoid Windows size_t-
  to-int socket-length wrap/negative conversion. No
  payload allocation or staging; the caller/event loop
  retains all packet assembly and cancellation.
  Two new dedicated portable CTests, registered under
  the original preauth executable and single registry:
  `transport.tcp-bio-chunk-bounds` exercises real
  OpenSSL BIO read/write callbacks with overlength
  spans, 18KiB/18KiB/tail progression, would-block,
  spoofed overreported lengths and complete byte
  parity; `transport.tcp-native-chunk-bounds`
  exercises connected native loopback sockets on
  Linux/macOS/Windows with checked bounded partial
  send/read and complete byte parity.
  Expected **101 portable / 111 Linux GSS** full
  CTests, up from the independently reported 99/109.
  Parent `7e9b2881f66cea2b0354242b4e7ae39cb89170bc`
  is docs-only ten-workstream R1–R10 convergence
  policy; prior actual transport code
  `45f68c2c0fcaa163aaf242a99f5637726a023fe2`
  passed [CI 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803)
  Linux **109/109** and macOS/Windows **99/99**
  CTests in both Debug and Release. Owner reports
  **99/99** local PASS on preceding code without
  a matching local SHA or terminal log.
  **NOT RUN:** exact new-head hosted CI, owner's
  new-code single-build-root tests, Windows MSYS2
  Clang 23/macOS 27 owner-target toolchains,
  real Kerberos/CredSSP identity, OS admission,
  licensing, live Microsoft-client MCS handshake,
  H.264/X11 desktop or human test. This work
  exercises R1 I/O only and CANNOT accept a user.
  **PASS:** exact implementation
  `8ce08611d5d7b093c9d69f4b7eee5d23cd096359`,
  [GitHub Actions 38752789202](https://github.com/k1moradi/RDP-server/actions/runs/38752789202):
  Linux/GCC **111/111** and macOS/Clang,
  Windows/MSVC **101/101** registered CTests in BOTH
  Debug and Release, including both new R1 chunk
  bounds cases; documentation-policy, installed
  downstream SDK consumer, ZIP/SHA256 packaging and
  artifact uploads PASS. Untagged prerelease SKIPPED.
  Earlier NOT RUN-at-authoring status is now superseded
  for hosted CI only. **NOT RUN:** owner-local current
  SHA single-root CTest, MSYS2 CLANG64 Clang23 and
  macOS27 owner environment, positive real CredSSP/
  Kerberos+TLS binding, independent OS account/session
  admission, real Microsoft RDP client and desktop.
  **Next:** owner performs exact-head local CTest
  with his one reused build root; R1/R2/R3 converge
  only after externally authorized GSS/OS session
  and actual client acceptance evidence.
  **Verified partial Gate A single-owner TCP/TLS/MCS readiness integration
  (2026-10-15; exact-head CI PASS):** In the
  existing `PreauthTcpAdapter` alone, bind the completed
  X.224 Confirm's connected `TcpNonblockingIo` to exactly
  one attached server `SSL*` and its single shared
  OpenSSL BIO. Expose `onAttachedTlsIoReady` and
  `onAttachedMcsIoReady` so the event loop cannot supply
  a replacement SSL pointer on subsequent callbacks.
  The existing transport verifies the same borrowed BIO
  pointer and its `TcpNonblockingIo` data, and rejects
  a duplicated attach, changed BIO/socket target,
  premature TLS/MCS callbacks and replay. Existing
  synthetic memory-BIO `onTlsIoReady(SSL*)` remains
  available for offline diagnostics only; once attached,
  even that legacy callback routes through the strict
  connection identity gate. No new network listener,
  state controller, GSS identity, licensing or MCS reply.
  The existing true native nonblocking loopback test
  now drives BOTH handshake and bounded MCS/GCC intake
  through this single pinned TCP owner. Two new
  behavior CTests in the existing preauth executable
  prove premature calls, duplicate/wrong SSL and
  changed/retargeted BIO fail closed. Expected **99
  portable / 109 Linux GSS** CTests (prior 97/107).
  Baseline main `00c70a24568098b34bcd1485e8f82fd63d0bab9a`
  is the roadmap's Gate A/C real-client priority commit.
  Implementation `89ffef98b4f27ad2947b4629c9eefa49b64152a7`
  passed [CI 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146):
  Linux 107/107 and macOS/Windows 97/97 Debug/Release.
  Owner reports **97/97 local PASS** on the preceding code
  without a full log or local SHA.
  **PASS:** implementation
  `45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
  [Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803):
  Linux/GCC **109/109**, macOS/Clang and Windows/MSVC
  **99/99** CTests in BOTH Debug and Release,
  including both new TCP/TLS/MCS ownership/order denials
  and the real native socket loopback flow. Installed
  SDK consumer, ZIP/SHA256 packaging/artifact uploads
  and documentation-policy PASS. Prerelease SKIPPED
  (no protocol version tag).
  **NOT RUN:** owner-local new-code full CTest,
  human Microsoft-client authenticated negotiation,
  real GSS/CredSSP TLS public-key proof and independent
  OS account/session admission, live MCS Connect-Response,
  H.264 or X11 desktop.
  **Next:** owner-local reused single-root CTest,
  then explicitly authorized isolated Kerberos/TLS and
  OS approval before any live MCS response or
  postauth transition.
  **Completed partial increment at `988938a90f8adbae4e07714ac636af3eb0640011`:**
  bounded incremental plaintext Connection Request intake, exact TCP
  consumed-byte accounting, correct negotiation response/terminal failure,
  all request split points and malformed-length negative tests.
  **PASS:** [Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  registered protocol and policy CTests passed.
  The *overall* milestone stays **open**: a real TCP listener, TLS provider,
  authenticated session, MCS response and external-client handshake
  remain **NOT RUN / unimplemented**.
  **Additional partial increment `18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`:**
  the existing preauth owner requires exactly one completed X.224
  reply write before accepting a TLS transition. Premature TLS,
  failed/partial and repeated acknowledgments fail closed.
  **PASS:** [Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
  The overall listener/TLS/authentication milestone is still open;
  **no real socket, TLS provider or external client was tested**.
  **Verified increment at `49c6006d47476184f7448028cd332e377ec9bd0b`:** reuses the same preauth
  buffer to reassemble exactly one decrypted RFC 1006/X.224 Data TPDU
  carrying a BER MCS Connect Initial and GCC Conference Create Request.
  The native test exercises every split/truncation point, coalesced
  next-PDU bytes, invalid TPKT length/X.224 type, BER errors and
  replay/close. This is NOT a real TLS or admitted RDP session.
  **PASS:** [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607) on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy. **NOT RUN:** live TLS/NLA, host listener and external client.
  **Next boundary:** real TLS provider plus authenticated session
  policy and complete MCS response handling.
  **Current partial security increment (CI pending):**
  `PreauthConnectionStream` requires a completed, server-role
  OpenSSL TLS 1.2+ session with selected certificate/cipher, instead of
  accepting a caller-supplied Boolean. The existing transport CTest
  now exercises an actual in-memory OpenSSL TLS handshake and negative
  wrong-role, pre-handshake, null, early and replay transitions.
  This does **not** implement socket TLS I/O, trusted OS session
  authorization, CredSSP/NLA or MCS Connect-Response.
  **First CI result:** macOS and documentation-policy PASS,
  Windows Compile Debug FAIL at `a25b5186398e4a5619baea2998a61596fa7b2887`
  ([Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680))
  because OpenSSL's platform includes exposed a `min` macro
  affecting the existing `std::min(...)` intake calls.
  The follow-up fixes OpenSSL header isolation and call syntax.
  **PASS:** fixed OpenSSL include/Windows macro handling at
  `edfaf2e7ea684ab5adc77bf58441ff467288f818`, verified by
  [Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  all passed Debug/Release full CTests, downstream SDK consumer
  and per-OS ZIP/checksum artifact uploads.
  **NOT RUN:** real socket TLS peer, trusted credentials/NLA,
  OS desktop admission, external RDP clients or owner's local
  build of this new commit. **Next:** integrate an authenticated
  TLS transport/session lifecycle without permitting OS admission
  before CredSSP/identity authorization.
  **Verified TLS application-record increment `a226f15827e9da48ad7a91b7cfa53528c3498802`:** the existing
  preauth stream now associates the completed OpenSSL server `SSL*`
  with the connection and uses `SSL_read_ex` to decrypt and parse
  precisely one bounded MCS/GCC TPKT. WANT_READ/WANT_WRITE do not
  close the connection; EOF, malformed data, swapped SSL handles
  and replay fail closed. The memory-BIO test drives actual encrypted
  TLS application records at every split boundary, coalesced trailing
  PDU, invalid header and early close. Neither a socket listener
  nor CredSSP/OS admission is implemented.
  **PASS:** [Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241),
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy; all
  Debug/Release protocol and project-policy CTests, staged SDK install,
  downstream consumer and platform ZIP/checksum uploads passed.
  **NOT RUN:** user's local build of this exact head, external client,
  TCP TLS listener, OS identity admission and desktop interaction.
  **Next:** nonblocking socket adapter and authenticated session policy,
  without equating a TLS handshake with user authentication.
  **Verified partial-send protocol increment at `98f6fdc60d513d47a87a78fadf1aa6be387da28b`:**
  `PreauthConnectionStream` now owns the 19-byte X.224
  Confirm/Failure response and tracks byte-accurate nonblocking
  write progress. Zero-byte output is retryable; overrun, premature
  TLS and replay fail closed; a rejected negotiation's response
  drains before transport closure. The existing preauth executable
  has an independent `transport.x224-confirm-partial-writes` CTest
  covering all 20 split boundaries, bytewise writes, cancellation,
  malformed accounting and both negotiation outcomes. Expected
  CTest total: **21**, up from 20 for a substantive new behavior.
  **PASS:** [CI run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
  for Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  all Debug/Release CTests, installed SDK consumer, ZIP and SHA-256
  artifacts. Ubuntu logs explicitly show **21/21 PASS** in both
  configurations. **NOT RUN:** owner-local new build, real TCP listener,
  external clients, NLA, OS admission, desktop interaction.
  **Next:** nonblocking network adapter and authenticated RDP session.
  **Verified native TCP adapter increment `dd3a806f97b13e6db18affd689c6321bfa009813`:**
  `PreauthTcpAdapter` wraps the existing sole preauth owner and drives
  exact-prefix 4-byte TPKT/declared request `recv`, followed by the
  byte-accurate pending X.224 Confirm/Failure `send`. A thin native
  socket adapter maps Linux/macOS/BSD and Windows recv/send errors to
  nonblocking outcomes. No extra encrypted TLS records can be read
  prematurely, even if coalesced on TCP. Scripted event-loop regressions
  exercise all 20 CR split positions, one-byte reads/writes, would-block,
  corrupted headers, EOF, short output, overreported counts, complete
  NEG_FAILURE and cancellation.
  **PASS:** [Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
  passed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
  all Debug/Release CTests, SDK installation, downstream consumer
  and three ZIP/SHA-256 artifacts. Ubuntu explicitly reports
  **23/23 PASS** in Debug and Release.
  **NOT RUN:** owner-local new build, actual connected native
  socket runtime, listening server, live TLS network handshake,
  CredSSP/NLA, MCS Connect-Response and authenticated desktop.
  **CI compatibility note:** the documentation-evidence rerun
  [38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
  encountered a macOS Debug compile **FAIL** with OpenSSL 4.0.3:
  `X509_get_subject_name` now returns `const X509_NAME*`,
  invalidating the synthetic certificate fixture's mutable cast.
  A follow-up constructs its own `X509_NAME` and assigns it
  through `X509_set_subject_name`, avoiding reliance on
  the changed mutable return type.
  **PASS:** corrected `5c4f3ad7273d17948327b7d351ff9840de2b0395`
  in [CI run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
  Debug/Release **23 CTests**, installed consumer and three SDK ZIPs.
  macOS selected OpenSSL **3.6.4** on the passing run;
  the corrected fixture's OpenSSL 4 runtime/compiler gate remains
  **NOT RUN**. **Next:** verify OpenSSL 4 explicitly, complete
  actual live TLS/socket I/O, authentication and MCS response.
  **Verified nonblocking TLS handshake increment at
  `fcd05f8e903a459ca85f13807bd35f7091f3fd70` (25 CTests):** the sole `PreauthConnectionStream` now drives one
  `SSL_do_handshake` attempt per readiness event, returns OpenSSL
  WANT_READ/WANT_WRITE distinctly, and binds the borrowed SSL pointer
  through retries. Complete X.224 Confirm output and server-role SSL
  are mandatory. Provider errors, null/client-role/wrong-pointer
  handles and cancellation fail closed; successful handshake reuses
  the same SSL for bounded encrypted MCS/GCC intake. The existing
  event-driven TCP adapter forwards `onTlsIoReady`, without
  installing a server listener. Two named test groups cover real
  in-memory TLS handshake progress through MCS and negative/replay
  gates. **NOT RUN:** exact-head CI, owner-local build, real connected
  socket TLS I/O, NLA/identity authentication, MCS Connect-Response
  and OS desktop admission.
  **PASS:** [Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  both Debug/Release CTests, staged SDK installation, downstream
  consumer and three platform ZIP/SHA-256 artifacts. Ubuntu logs
  show **25/25 PASS** in Debug and Release.
  **NOT RUN:** owner's local post-change build, connected native
  TLS socket, independent credential/CredSSP/OS authorization,
  MCS Connect-Response or external RDP client/desktop.
  **Next:** drive the same TLS handshake over real connected
  nonblocking sockets in a safe loopback test, then authenticated
  RDP session establishment.
  **Verified native nonblocking loopback/TLS increment
  `7ce64737ccef439af2f0cfd383208181cc0e9513`
  (27 CTests):** a first-party OpenSSL custom BIO now borrows the
  existing `TcpNonblockingIo` and translates partial send/recv,
  would-block, EOF and I/O failure to OpenSSL readiness semantics
  without narrowing 64-bit Windows SOCKET handles. The existing
  `PreauthTcpAdapter` attaches this BIO only after the full X.224
  Confirm is sent; the same connection owner then drives
  `SSL_do_handshake` and bounded TLS MCS/GCC intake. Two new
  behavior-named CTests open ephemeral **127.0.0.1:0-only** TCP pairs,
  immediately close the temporary listener and verify native X.224,
  real TLS records carrying the Microsoft 416-byte MCS fixture,
  terminal EOF on a truncated CR and delivery of RDP_NEG_FAILURE.
  This is an isolated CI test, NOT installation/activation of a
  daemon or an externally reachable RDP server.
  **First CI FAIL:** [run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
  passed Ubuntu/GCC, Windows/MSVC and documentation-policy; on
  macOS/Clang two native loopback tests failed because the test
  assumed immediate recv readiness and immediate observation of TCP
  FIN. Corrected the **test driver only** to tolerate would-block
  and wait with bounded 1ms sleeps while retaining exact framing
  and terminal assertions.
  **PASS:** corrected [Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
  on Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  both Debug/Release full **27/27 CTests** (confirmed in Ubuntu logs),
  installed SDK consumer and three ZIP/SHA-256 platform packages.
  **NOT RUN:** user's local build of the new code, external RDP
  clients, production certificate trust/enrollment, CredSSP/NLA,
  MCS Connect-Response, OS authorization and desktop.
  **Next:** authenticated session policy and the standards-compliant
  MCS server response.
  **Next protocol increment — T.125 MCS domain negotiation
  (pending exact-head CI):** the first-party
  `mergeMcsDomainParameters` implements Microsoft's
  [MS-RDPBCGR 3.3.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
  eight-field target/minimum/maximum negotiation. The BER parser now
  allows min/max protocol versions other than 2 if they can negotiate
  version 2; the existing preauth diagnostic requires a successful
  merge, otherwise closes without MCS admission. Two NEW domain
  behavior tests cover the published Microsoft client fixture,
  each required fallback, unsupported version and all rejection
  branches. The four existing Connect-Initial test groups are
  individually registered without duplicating the executable:
  expected CTest total **32** (previously 27; two new behaviors,
  three additional registrations of existing behaviors).
  **PASS:** implementation `865c56c548526f4514207a4af1b192f3b3637c9a`
  in [CI 38582674975](https://github.com/k1moradi/RDP-server/actions/runs/38582674975):
  Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
  Debug/Release 32 CTests, installed downstream consumer and SDK
  ZIP/checksum gates. Owner-provided Linux Debug build and
  **32/32 CTest PASS** at the same code commit in the reused
  `~/rdp-server/build/` directory.
  **NOT RUN:** real external RDP client, CredSSP/NLA, authenticated
  OS admission or MCS Connect-Response emission.
  **Offline MCS Connect-Response encoder increment (CI pending;
  expected 34 CTests):** first-party
  `encodeMcsConnectResponse` constructs a bounded TPKT/X.224 Data TPDU,
  T.125 BER Connect-Response (APPLICATION 102), and T.124 GCC
  Conference Create Response with H.221 `McDn`. It emits
  `SC_CORE`, `SC_NET` with caller-provided, validated channel IDs,
  and `SC_SECURITY` with Enhanced TLS security values (0, 0)
  rather than a legacy RC4 certificate/random. DomainParameters
  come from the existing checked `mergeMcsDomainParameters` result.
  The encoder validates the actual client GCC settings, checks
  nodeID range 1001..65536, channel cardinality and uniqueness,
  requires the currently supported SSL offer (1), uses minimal BER
  and nonfragmented PER lengths, and returns no bytes on failure.
  **Offline only:** it does NOT send to a peer, register a domain,
  authorize credentials, or allocate a desktop or channel session.
  New `transport.mcs-response-wire` compares the whole 108-byte
  TLS-only response to an independently assembled oracle derived
  from [MS-RDPBCGR 4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3);
  `transport.mcs-response-rejections` covers malformed or
  contradictory inputs and BER integer sign padding.
  **PASS:** implementation `e25cd3a05f46b7eaa2a259eb2da8ddb3b7459a87`
  passed Linux/GCC Debug/Release **34 CTests**, Windows/MSVC
  Debug/Release CTests, SDK consumer and packaging, and
  documentation-policy in [CI run 38586253181](https://github.com/k1moradi/RDP-server/actions/runs/38586253181).
  The owner's local Linux Debug `~/rdp-server/build/` run at
  `ddfc2d372285c397c52dca0197d30bf1c61c338e` confirmed
  **34/34 CTests PASS**; macOS status for that implementation is
  not independently asserted here.
  **NOT RUN:** production response emission, CredSSP/NLA user
  authentication, MCS domain lifecycle and desktop access.
  **Next:** implement bounded offline Erect/Attach/Join decoding,
  then authenticated connection admission and response ownership.
  **Offline MCS channel-connection request decoding (pending
  cross-platform CI; expected 37 CTests):** the portable
  `parseMcsChannelRequest` parses exactly one complete RFC1006
  TPKT/X.224 Data PDU holding T.125 aligned BASIC-PER
  ErectDomainRequest (subHeight/subInterval), AttachUserRequest or
  ChannelJoinRequest (initiator UserId and requested channel ID).
  It uses existing validated `parseDataTpdu` framing, bounded
  1..4-octet PER integers, canonical encodings and exact consumed
  lengths, and rejects wrong-direction PDU types, malformed padding,
  length mismatch, trailing bytes and UserId overflow. The
  initiator offset of 1001 is decoded **without** verifying that
  the account or channel exists. New CTests reuse the same MCS
  executable and Microsoft's 4.1.5/4.1.6/4.1.8 request examples:
  `transport.mcs-erect-request`,
  `transport.mcs-attach-request`,
  `transport.mcs-channel-join-request`.
  **Initial FAIL:** implementation `d5bc7d3b03906890da483dd1a480677a4fbaf73b`
  [CI run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504)
  failed Ubuntu Debug `transport.mcs-erect-request` at the
  *test-only* extended PER integer example: its octet length
  determinant claimed 4 bytes but the fixture provided 3.
  Other 36 CTests passed. The production parser correctly
  rejected the inconsistent packet. The test vector has been
  corrected from 0x04 to 0x03 without changing the decoder.
  **PASS:** corrected implementation
  `6effdb76229e2514511ebe5dd8cb404841403b1b`,
  [Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  both Debug/Release **37 CTests**, installed downstream SDK
  consumer, and three SDK ZIP/SHA-256 uploads. Ubuntu logs
  explicitly show **37/37 PASS** in both configurations.
  **PASS (owner-local):** the user's reused
  `~/rdp-server/build/` Linux Debug configure/build/CTest
  at `3135d66e557ecc8144fba02a8a69b5054b62ede9`
  passed **37/37**. This predates the new reply encoders.
  **NOT RUN:** TLS-verified domain phase admission, CredSSP/NLA,
  live attach/channel replies, OS authorization and desktop.
  **Next:** independent authenticated session authority and
  its single-owner MCS Attach/ChannelJoin lifecycle.
  **Offline Attach User and Channel Join confirmation encoding
  (2026-10-14; 39 CTests verified):**
  the existing portable `mcs_channel_connection.{h,cpp}` now
  constructs complete bounded TPKT/X.224/T.125 aligned-PER
  `rt-successful` Server Attach User Confirm and Channel Join Confirm
  packets without mutating session/domain/channel state.
  The assigned UserId must be 1001..65536 and is serialized
  as the 16-bit PER offset. A Channel Join Confirm requires a
  previously parsed Join request, the same explicitly assigned
  UserId, a nonzero requested channel, exactly one matching
  entry in a bounded externally supplied channel list, and
  correct repeated requested/confirmed ChannelId.
  Complete Microsoft example packets in MS-RDPBCGR 4.1.7
  (11 bytes) and 4.1.8.2.2 (15 bytes) are bytewise test oracles.
  Two new behavior CTests test successful encoding, both extrema
  of UserId, mismatched/duplicate/unallocated channels, wrong
  request kind and invalid identifiers. The library **does NOT**
  use these encoders to send packets; the supplied channel list
  does not prove OS identity, credential approval or MCS admission.
  **PASS:** implementation
  `4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`,
  [Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
  passed Linux/GCC, macOS/Clang, Windows/MSVC and
  documentation-policy, full Debug/Release CTests, installed SDK
  consumer and three ZIP/SHA-256 artifacts. Ubuntu logs confirmed
  **39/39 CTests PASS** in Debug and Release.
  **NOT RUN:** owner's updated local build, real CredSSP/NLA
  and OS-authorized session, encrypted live reply emission,
  external Microsoft clients and OS desktop.
  **Next:** implement a genuine CredSSP/NLA and independent OS
  identity authority, then let the sole server connection owner
  enforce MCS ordering, allocations and reply transmission.
- [ ] Implement TLS, CredSSP/NLA and independently verified OS session
  authorization, including security downgrade and failure tests.
  **Gate A security acceptance (NOT RUN):** positive real Kerberos/GSS
  with the active TLS certificate/public-key binding plus separate OS
  user/console authorization on an explicitly approved isolated test
  host. Gate all channel/session output on both authorizations; cover
  invalid accounts, altered certificates, downgrade, expiry, denial,
  cleanup and replay. Fail closed rather than bypassing NLA or
  accepting synthetic credentials as proof of admission.
  **R2 provider/TLS identity handoff (2026-10-15; CI pending):**
  `GssapiSpnegoAcceptor::verifiedPrincipal()` now requires genuine
  GSS completion AND the selected TLS X.509-bound CredSSP v5/v6
  public-key proof. It refuses a missing GSS context, early GSS-only
  identity, or a later changed selected certificate. The dedicated
  `security.gssapi-principal-tls-proof-gate` CTest exercises negative
  real-TLS handoffs; opt-in genuine Kerberos tests cover successful
  binding and certificate-change denial. **NOT RUN at authoring:**
  patched CTests, new-head CI, opt-in Kerberos, independent OS
  authorization and R3 admission. The console gate remains deny-only.
  **CredSSP TSRequest decrypted-message framing increment (2026-10-14,
  46 CTests; exact-head CI PASS):** extend the existing
  first-party `credssp_tsrequest.{h,cpp}` with a fixed 16 KiB
  `TsRequestFrameReader`, preserving DER SEQUENCE/length boundaries
  across fragmented TLS application bytes, rejecting nonminimal,
  indefinite, oversized and unsupported DER lengths *before*
  large buffering, and leaving coalesced following-message bytes
  unconsumed. Completed bytes and SPNEGO/credential fields remain
  borrowed until explicit `releaseFrame()`; cancellation,
  malformed input and destruction wipe owned ciphertext via
  OpenSSL cleanse and terminate invalid frames. A second frame
  cannot overwrite an unreleased first frame. Three new
  behavior groups test every split, coalesced messages, DER
  0x81/0x82 lengths (including large bounded frames), invalid
  headers, EOF/cancellation and replay. Register the five
  prior CredSSP behavior groups separately without creating
  another executable (39 old registered CTests -> 46 expected).
  **This is syntax-only:** no SPNEGO acceptor, Kerberos/NTLM
  user authentication, version-5/6 TLS public-key binding,
  nonce validation, credentials decryption, OS account/session
  authorization, NLA X.224 negotiation or MCS admission is enabled.
  The existing diagnostic still selects only PROTOCOL_SSL and
  closes after MCS intake.
  **PASS:** implementation
  `c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
  [CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  Debug/Release full CTests, installed downstream SDK consumer
  and all three ZIP/checksum package artifacts. Ubuntu logs
  explicitly show **46/46 CTests PASS** in each build mode.
  **NOT RUN:** owner's local build of updated code,
  live CredSSP TSRequest TLS exchange, GSS/SPNEGO and
  independently authenticated OS session, external client
  or desktop acceptance.
  **Next:** connect this bounded DER handoff to a real
  CredSSP/SPNEGO provider and verified OS authorization in
  the sole connection owner; never treat a syntactically
  valid token as an authentication capability.
  **Verified bounded server-reply serialization (2026-10-14;
  48 CTests PASS):** within the same `credssp_tsrequest` module, an
  offline, allocation-bounded, canonical DER encoder produces
  one MS-CSSP TSRequest server `negoTokens` response OR an
  already-GSS-protected `pubKeyAuth` response for versions
  5/6. No credential or nonce output, TLS send, SPNEGO trust
  assertion or OS identity authority is added. Two additional
  existing-executable behavior CTests exercise literal DER wire
  oracles, lengths, parsing/framing and rejection bounds (expected
  **48 CTests**). **PASS:** exact implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
  [Actions run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778): 48/48 Debug and Release
  CTests on Linux/GCC, macOS/Clang and Windows/MSVC, SDK
  installed downstream consumer, all three ZIP/checksum
  uploads and documentation-policy gate. No prerelease tag.
  **NOT RUN:** owner's local build, real GSS/Kerberos,
  TLS public-key binding, OS admission or desktop.
  **Next:** connect to a trusted GSS provider and independent
  OS authorization before allowing any reply on a socket.
  **Verified Linux GSSAPI framed-token provider increment
  (2026-10-14; CI PASS):** compile the already-staged first-party
  MIT GSSAPI SPNEGO, public-key binding and deny-only credential
  sources behind explicit Linux-only `RDP_SERVER_TEST_LINUX_GSSAPI`.
  The existing GSS acceptor accepts a completed v5/v6 frame from
  `TsRequestFrameReader` synchronously, borrows only within
  the provider call and wipes the frame on return. Early,
  downgraded, malformed or GSS-rejected frames terminate both
  owners; an absent explicit keytab must never fall back to
  host credentials. The portable SDK has no mandatory GSSAPI
  dependency or newly enabled authentication path.
  **PASS:** implementation `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`,
  [CI 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133):
  Linux/GCC **50/50**, macOS/Clang and Windows/MSVC **48/48**
  CTests in both Debug and Release, SDK downstream consumer,
  three ZIP/checksum packages and documentation-policy. The two
  new Linux-only native GSS rejection suites passed.
  **NOT RUN:** owner-local updated build, live keytab/Kerberos
  credentials, positive GSS/TLS binding, OS admission, external
  client or desktop. **Next:** independently verify real
  configured provider credentials and TLS certificate binding,
  then implement independently authorized OS session admission
  before permitting live MCS responses.
  **Verified TLS->CredSSP frame intake increment (2026-10-14;
  CI PASS):** extend the existing 16 KiB `TsRequestFrameReader`
  with exactly one bounded `SSL_read_ex` per method call,
  pinning a finished server TLS identity, selected certificate,
  cipher and TLS >= 1.2. `Progress` requires immediate caller
  continuation for bytes already buffered inside OpenSSL;
  NeedRead/NeedWrite require actual transport readiness.
  Subsequent coalesced TSRequests remain unread until the
  first is released; reject SSL substitution, manual/TLS
  mixing, malformed DER and EOF terminally and wipe buffers.
  Reuse the existing OpenSSL memory-BIO fixture and add
  **three new** CTests for all fragment splits, coalesced
  envelopes and negative transport/mixed-source boundaries.
  **PASS:** implementation `d2885363502e34e52c71c41342902908b781fd58`,
  [CI 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062):
  Linux/GCC 53/53, macOS/Clang 51/51 and Windows/MSVC
  51/51 CTests in both Debug and Release; all three
  new cases passed on each platform. SDK downstream
  consumer, ZIP/SHA256 artifacts and docs-policy PASS.
  **NOT RUN:** owner-local build, real GSS credentials,
  TLS CredSSP pubKeyAuth, OS-authorized admission or
  Microsoft desktop connection. The diagnostic remains
  PROTOCOL_SSL and never grants identity. **Next:**
  authenticated GSS binding to the selected TLS
  certificate and independent OS authorization before
  any MCS response or remote desktop admission.
  **Verified TLS-owned GSS provider provenance increment
  (2026-10-14; CI PASS):** MS-CSSP 2.2.1/3.1.5
  requires SPNEGO and encrypted public-key validation
  in the same TLS session. The one `TsRequestFrameReader`
  now exposes server-SSL provenance only for a complete
  TLS-read frame, never synthetic/partial/released DER.
  The Linux `GssapiSpnegoAcceptor` requires this evidence,
  pins the SSL pointer and v5/v6 version across framed
  negotiation, rejects mismatched SSL/version, and
  checks the pinned identity and version again before
  protected-binding GSS unwrap. Rejection erases
  borrowed identity without creating extra buffers
  or granting account/session authority.
  **PASS:** implementation `6e11b25224e1a5e6c3f45778436afc3950a3e866`,
  [CI 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612):
  Linux/GCC **55/55**, macOS/Clang and Windows/MSVC
  **52/52** CTests in BOTH Debug and Release. Two
  new behavior-named tests (portable TLS provenance
  and Linux-only real-provider fail-closed handoff)
  passed. SDK downstream consumer, three ZIP/checksum
  uploads and documentation-policy also PASS.
  **NOT RUN:** owner's local updated build, real keytab
  or Kerberos tickets, positive GSS context, TLS
  public-key proof, OS authorization, Microsoft client
  and desktop. **Next:** genuine positive Kerberos/GSS
  with selected TLS certificate and interoperable
  MS-CSSP final negoToken+pubKeyAuth phase, followed
  by independent OS authorization before MCS admission.
  **Verified MS-CSSP final combined token/binding processing
  (2026-10-14; CI PASS):** Microsoft's
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  requires the last client SPNEGO token and encrypted TLS
  public-key binding together in one TSRequest. The
  first-party v5/v6 framer validates exactly one token,
  encrypted pubKeyAuth, a 32-byte nonce and no authInfo
  or errorCode. The optional Linux GSSAPI provider requires
  a continuing context and pinned SSL/version, accepts
  the final token and demands fully verified Kerberos
  security flags; it rejects a GSS output token that
  cannot be sent in the binding-only server reply,
  then uses confidential GSS unwrap/wrap and the selected
  active TLS certificate to generate a protected reply
  before securely releasing the frame. This is NOT a
  successful Kerberos exchange or desktop admission.
  **PASS:** implementation
  `ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`,
  [CI 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453):
  Linux/GCC **58/58**, macOS/Clang and Windows/MSVC
  **54/54** CTests in both Debug and Release, including
  all THREE newly registered behavior-named cases.
  SDK install/downstream consumer, ZIP+SHA-256 artifact
  uploads and documentation policy PASS across all systems.
  **NOT RUN:** owner's local new build, positive real GSS
  credentials/keytab, actual TLS pubKeyAuth validation,
  external Microsoft clients, independent OS account
  authorization or real desktop. **Next:** controlled
  positive real GSS/Kerberos and binding interoperability,
  then independent OS authorization before any MCS
  domain replies or desktop activation.
  **Verified bounded TLS server TSRequest reply transport
  (2026-10-14; CI PASS):** per
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  the existing first-party `credssp_tsrequest` module
  now writes one bounded canonical server negoToken
  or GSS-protected pubKeyAuth DER reply over pinned
  finished server TLS. It retains a stable, owned
  byte buffer across OpenSSL WANT_READ/WANT_WRITE,
  never counts unsuccessful writes, prohibits
  conflicting TLS identities or overlapping records,
  and wipes sensitive contents on release/cancel.
  This is transport only: no SPNEGO provider success,
  trusted user identity, OS authorization, NLA
  activation, positive MCS reply or desktop.
  Three NEW behavior-named CTests use real OpenSSL
  memory BIO TLS, including exact wire, WANT_WRITE
  backpressure/retry and terminal error denial.
  **Initial FAIL:** implementation
  `915cd2bfac59d7e775b458b7deed3d94db17ad93`,
  [CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856):
  the backpressure fixture attempted unsupported
  `BIO_set_write_buf_size` on an already paired
  memory BIO; this was test setup failure.
  **PASS:** corrected fixture implementation
  `afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
  [CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824):
  Linux/GCC **61/61**, macOS/Clang and Windows/MSVC
  **57/57** CTests in BOTH Debug and Release,
  including all three new cases, SDK downstream
  consumers, three ZIP/SHA-256 artifact uploads
  and policy gate. Constrained server BIO capacity
  is now established before handshake with no
  weakened assertions. Preexisting Linux Release
  test fixture compiler warning remains nonfatal.
  **NOT RUN:** owner-local new build, real positive
  GSS/Kerberos ticket/keytab and public-key binding,
  OS identity authorization, external RDP client
  or desktop. **Next:** connect the verified transport
  to a real provider-generated GSS exchange, verify
  TLS pubKeyAuth end to end, and independently
  authorize OS session access before any MCS reply.
  **Verified Linux real-GSS-to-TLS server reply handoff
  (2026-10-14; CI PASS):** per Microsoft
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  the existing optional real MIT GSS provider
  can now queue its own SPNEGO continuation
  `negoTokens` or confidentially wrapped final
  server `pubKeyAuth` on the original server
  TLS, using the existing bounded nonblocking
  `TsRequestTlsReplyWriter`. The handshake
  requires a real provider output, correct
  stage/version, matching SSL frame provenance,
  idle outgoing writer, and successful final
  client GSS/TLS certificate-bound proof.
  Transient GSS output is cleansed immediately
  after queueing; reject closes all three
  owners. This helper does NOT itself send
  TLS, enable NLA, authorize an OS user,
  generate MCS responses or admit a desktop.
  **PASS:** implementation
  `27e8342aee0e475c3b0854330678e7c7596fc912`,
  [CI 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493):
  Linux/GCC **64/64** CTests in BOTH Debug
  and Release (all **three NEW** GSS-TLS
  provider response-gate tests PASS),
  macOS/Clang and Windows/MSVC **57/57**
  each in Debug and Release, documentation
  policy PASS, three SDK downstream
  consumers, ZIP/SHA256 package uploads PASS.
  The new tests use actual TLS application
  records and real linked MIT GSSAPI, but
  deliberately assert negative results
  WITHOUT installed Kerberos credentials.
  A preexisting unrelated Linux Release
  `-Wstringop-overflow` in test fixture
  `tests/test_owned_preauth_session.cpp:589`
  remains nonfatal.
  **NOT RUN:** owner-local update build,
  genuine positive keytab/ticket mutual
  Kerberos exchange, live selected-TLS
  pubKeyAuth verification, independently
  authorized OS account/session, external
  Microsoft RDP clients or desktop.
  **Next:** controlled opt-in positive
  Kerberos/GSS+TLS public-key binding,
  then independently checked OS policy and
  single-owner live X.224/MCS transitions.
  **Verified active server TLS certificate identity pin and
  real TLS binding (2026-10-14; CI PASS):** Microsoft
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  bind the client/server proof to the selected TLS
  certificate SubjectPublicKey, 32-byte nonce and
  distinct direction labels. The existing one
  `TsRequestFrameReader` now pins the selected
  server X.509 SHA-256 fingerprint as well as
  `SSL*` on its FIRST real TLS read. It checks
  both before later TLS chunks, after frame
  completion and after release: even a different
  selected certificate on the SAME SSL pointer
  revokes handoff and closes/wipes the frame.
  The existing `credssp_tls_certificate`
  module owns finished TLS >=1.2 server-role/
  cipher/cert checks and active certificate
  SubjectPublicKey hashing, without GSS or
  OS session authority. Three new portable
  CTests use real in-memory OpenSSL TLS, comparing
  both direction-specific live-certificate hashes
  with independent SubjectPublicKey calculations;
  reject other certs, nonces, reflected/mutated
  hashes and invalid TLS roles; and reject
  completed/partial DER after same-SSL cert
  replacement while accepting unchanged identity.
  **Initial FAIL:** implementation
  `d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`,
  [CI 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326):
  new test compile failed due to OpenSSL 4-compatible
  `const X509*` source passed to `SSL_use_certificate`.
  **PASS:** correction
  `340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`
  duplicates the test-only certificate with
  `X509_dup` into existing RAII `CertificatePointer`
  and retains all assertions.
  [CI 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190):
  Linux/GCC **67/67** and macOS/Clang,
  Windows/MSVC **60/60** CTests, BOTH Debug
  and Release; three new cases, installed
  SDK consumers, ZIP/SHA256 uploads,
  documentation-policy PASS. Prior Linux
  Release fixture warning remains nonfatal.
  **NOT RUN:** owner-local new build, positive
  actual Kerberos/GSS service keytab/tickets,
  true GSS unwrap/wrap TLS public-key proof,
  independent OS account authorization,
  Microsoft client or real desktop.
  **Next:** positive controlled Kerberos/GSS
  and TLS binding, then independent OS policy
  before admitting real MCS/desktop.
  **Verified TLS-framed GSS binding-only provenance boundary
  (2026-10-14; CI PASS):** Microsoft
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  require real SPNEGO and encrypted public-key
  proof inside the original established TLS
  transcript. The Linux acceptor's historical
  `processProtectedBinding(SSL*, rawDer)` is
  now permanently deny-only: raw caller-supplied
  bytes, even with an SSL pointer and an
  otherwise authenticated provider, never
  prove TLS record provenance.
  `processFramedProtectedBinding(reader)`
  requires exactly one complete TLS-derived
  v5/v6 binding-only DER frame, unchanged
  pinned SSL/selected X.509 certificate and
  negotiation version, with successful REAL
  GSS context and confidential unwrap before
  nonce/hash comparison and protected server
  response. The existing combined-final and
  new binding-only queue methods now share
  one guarded idle-writer handoff; terminal
  failure closes reader, provider and writer.
  **PASS:** implementation
  `340b25d2352314003053ec19d467b75d578c9dbf`,
  [CI 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568):
  Linux/GCC **69/69** and macOS/Clang,
  Windows/MSVC **60/60** CTests in BOTH
  Debug and Release; TWO new Linux real
  TLS/GSS-linked denial and outgoing-order
  CTests passed, along with all previous
  regression groups, staged SDK/consumer,
  ZIP/SHA-256 uploads and documentation
  policy. The previously existing Linux
  Release test fixture warning remains
  nonfatal. These tests are **negative-only**
  for GSS authentication. No positive ticket,
  keytab, GSS unwrap success, independently
  authorized OS account, Windows App client
  or real desktop was run.
  **Next:** opt-in controlled genuine positive
  Kerberos/GSS exchange with explicit test
  keytab/client ticket and active TLS binding,
  then independent OS authorization before
  any live MCS/desktop admission.
  **Verified outgoing CredSSP TLS reply certificate continuity
  (2026-10-14; CI PASS):** per Microsoft's
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  every canonical v5/v6 `TSRequest` reply must
  remain tied to the actual server TLS-selected
  X.509 public key. The existing
  `TsRequestTlsReplyWriter` now pins one SHA-256
  fingerprint of the selected finished server
  certificate at its FIRST reply queue, in
  addition to its one `SSL*` identity.
  On EVERY subsequent SSL_write_ex readiness
  retry, idempotent Complete, reply release
  and next reply queue it rechecks the
  selected certificate in constant time
  with the existing first-party certificate
  helper. A changed selected certificate
  on the SAME SSL pointer fails terminally,
  closes and wipes pending DER/fingerprint
  BEFORE a new TLS write. Previously emitted
  TLS ciphertext cannot be retroactively
  recalled. No duplicate state controller
  or output encoder was added.
  Three NEW all-platform real TLS CTests
  cover v5/v6 SPNEGO and pubKeyAuth replies
  denied before write with zero delivered
  plaintext after certificate replacement;
  changed certificate after Complete,
  before release and after release, with
  unchanged positive multi-reply reuse;
  and a real 2048-byte memory-BIO
  SSL_ERROR_WANT_WRITE followed by same-SSL
  certificate mutation and no retry.
  **PASS:** implementation
  `53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`,
  [CI 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102):
  Linux/GCC **72/72**, macOS/Clang
  and Windows/MSVC **63/63** CTests
  in BOTH Debug and Release; all three
  new cases, documentation policy,
  installed SDK downstream consumer
  and all three ZIP/SHA256 package
  uploads PASSED. Previous unrelated
  nonfatal Ubuntu Release test fixture
  `-Wstringop-overflow` remains.
  **NOT RUN:** owner's local build,
  positive real service-keytab/client-ticket
  Kerberos/GSS and confidential
  active-TLS pubKeyAuth, independently
  authorized OS account/session,
  Windows App or actual desktop.
  **Next:** explicitly authorized
  controlled genuine Kerberos/SPNEGO
  and active TLS certificate binding,
  then independently audited OS policy
  before any MCS/session admission.
  **Verified Linux GSS acceptor transcript-wide TLS certificate pin,
  with unrun opt-in genuine Kerberos probe (2026-10-14):** per
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  and [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178.html),
  the existing Linux MIT GSS provider now pins the first
  selected server TLS X.509 DER SHA-256 fingerprint inside
  the acceptor itself, IN ADDITION to its original SSL*
  and CredSSP v5/v6 version. Every later TLS-framed
  SPNEGO request, binding-only or combined-final proof,
  confidential GSS hash check and queued server
  binding response rechecks the exact selected certificate,
  even if the caller replaces the frame reader between
  rounds on the SAME SSL*. Terminal reject cleanses
  the fingerprint and authenticated principal and
  closes the GSS context and explicit credentials.
  No new session controller or OS account authority.

  One separately gated Linux-only acceptance probe
  is compiled into the original TLS fixture and
  registered ONLY under `RDP_SERVER_TEST_REAL_KERBEROS=ON`
  with an explicitly supplied `TERMSRV/host@REALM`,
  `FILE:/` service keytab and separate `FILE:/`
  client ticket cache. It invokes real MIT
  GSS initiator/acceptor through TLS application
  records, GSS-confidential v5/v6 binding-only
  verification, and a new-reader, SAME-SSL
  X.509 swap rejection. No KDC or desktop is started;
  no default host keytab/cache or client credential
  contents are imported into the project.
  Binding-only proof is an internal diagnostic,
  NOT normative combined-last-token MS-CSSP
  interoperability or independently authorized
  account/session acceptance.

  **PASS:** implementation
  `1f6740452f27332303ded71d4f5f23bb599b9726`,
  [CI 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820):
  Linux/GCC **72/72** and macOS/Clang,
  Windows/MSVC **63/63** standard CTests,
  EACH Debug and Release, three installed SDK
  downstream consumers, ZIP/SHA256 package
  uploads and documentation-policy PASS.
  The Linux test executable compiles the new
  GSS probe code, but the opt-in case was
  NOT registered or executed with CI credentials.
  Existing Ubuntu Release nonfatal
  `-Wstringop-overflow` at TLS fixture
  line 594 remains.
  **NOT RUN:** actual positive keytab/client
  ticket authenticated GSS handshake,
  GSS-confidential pubKeyAuth probe,
  real Microsoft combined-final client,
  owner's local build, independent OS
  authorization, live RDP server or desktop.
  **Next:** with explicit authority and
  isolated real ticket/keytab, RUN the
  opt-in positive provider/TLS-binding probe
  and close any MS-CSSP combined-last-token
  interoperability gaps before independent
  OS session admission.
  **Partial real-provider CredSSP v6 SPNEGO failure dispatch
  (2026-10-15; CI PASS):** the existing
  Linux MIT GSS acceptor now marks a provider/policy
  rejection only when the configured, explicit-keytab
  `gss_accept_sec_context` was actually called on a
  TLS-derived and valid SPNEGO negotiation request.
  For version 6 ONLY, recheck the original SSL and
  selected X509 SHA256 fingerprint after GSS terminal
  cleanup; then enqueue fixed `STATUS_LOGON_FAILURE`
  using the existing single 15-byte DER error encoder
  and nonblocking `TsRequestTlsReplyWriter`.
  `SpnegoStatus::FailureQueued` means error queued,
  GSS credentials/principal already wiped, but NO
  SSL record written or authenticated session.
  Missing keytab, invalid DER/token, wrong/changed TLS,
  version 5, failed local memory or pending writer
  MUST silently terminate, not synthesize GSS denial.
  Extend original preauth TLS fixture with one default
  Linux GSS-only negative CTest, and a separately
  registered opt-in genuine MIT rejection + TLS
  15-byte error oracle (requires explicitly authorized
  service keytab and ticket cache). Default CTest
  counts: **77 portable / 87 Linux GSS** (prior 77/86);
  opt-in positive credentials and failure delivery
  still **NOT RUN** without owner authorization.
  Baseline `ebc794738552f5411ebe4d2222000f8ae94183f2`,
  [Actions 38708915869](https://github.com/k1moradi/RDP-server/actions/runs/38708915869)
  PASS; owner reports **77/77** local on prior main.
  **PASS:** implementation `b4c9f8eff73e701130cc8b92b6c1fda50aedcf11`,
  [Actions 38710937644](https://github.com/k1moradi/RDP-server/actions/runs/38710937644):
  Linux/GCC **87/87**, macOS/Clang and Windows/MSVC
  **77/77** full CTests in EACH Debug and Release,
  including new Linux GSS fail-closed behavior;
  installed SDK downstream consumer, ZIP/SHA256
  artifacts and documentation policy PASS.
  Prerelease publication SKIPPED (no release tag).
  **NOT RUN:** owner-local incremental compile/CTest,
  opt-in configured real GSS rejection/errorCode
  delivery, full Microsoft combined-last-token,
  OS admission, real RDP client or desktop.
  **Next:** owner explicitly provisions
  isolated real Kerberos keytab and client tickets
  before opt-in provider/TLS proof and independent
  OS authorization, then the one live CredSSP owner
  can govern a complete authenticated negotiation.
  **Verified version-6 CredSSP errorCode server reply transport
  (2026-10-14; CI PASS):** [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  specify a server `TSRequest.errorCode`
  on failed SPNEGO at protocol versions
  3/4/6. The current v5/v6-only native
  reply codec now supports ONLY a
  version-**6** negative NTSTATUS
  failure record. It emits exact
  15-byte DER with [0] version and
  [4] signed 32-bit failure: the fixed
  `STATUS_LOGON_FAILURE` (0xC000006D)
  or `STATUS_NOT_SUPPORTED` (0xC00000BB).
  It rejects v5/legacy versions,
  unknown codes, mixed SPNEGO/pubKeyAuth/
  authInfo/nonce fields and any success
  status. The existing, single
  `TsRequestTlsReplyWriter` queues
  canonical negotiated tokens, sealed
  bindings, and failures through ONE
  private encoder-owned guarded queue.
  It retains TLS SSL*/selected X509
  fingerprint, nonblocking retry
  pointer, one-pending-response limit,
  and wipe-on-error. A completed
  failure is released to CLOSED,
  never followed by a success response.
  FOUR new portable behavior cases
  check exact independent DER oracles,
  rejected versions/fields/nonminimal
  signed integer, real TLS delivery
  and terminal failure behavior, and
  pending-reply/wrong-TLS/same-SSL
  certificate-swap rejection.
  **PASS:** implementation
  `6925ac11a49b3d71a6ffa120b688ca95a0a088af`,
  [CI 38683205424](https://github.com/k1moradi/RDP-server/actions/runs/38683205424):
  Linux/GCC **76/76**, macOS/Clang
  and Windows/MSVC **67/67** CTests
  in BOTH Debug and Release,
  ALL four new tests PASSED on
  all three OS, installed SDK
  consumer, ZIP/SHA256 packages
  uploaded and docs policy passed.
  The earlier unrelated nonfatal
  Ubuntu Release `-Wstringop-overflow`
  in `test_owned_preauth_session.cpp:594`
  persists.
  **NOT RUN:** owner's local build,
  opt-in successful real Kerberos
  service keytab and client ticket,
  automatic server GSS failure
  dispatch to this optional message,
  authenticated TLS public-key
  binding, independent OS session
  policy, Microsoft RDP client
  or usable desktop.
  **Next:** controlled opt-in
  real Kerberos/GSS and active-TLS
  binding proof; when authorized,
  wire terminal failure response
  to explicit GSS state without
  promoting it to authentication
  success; independent OS admission
  before real MCS or desktop.
  **Verified bounded DER intake hardening (CI PASS):**
  reorder the existing CredSSP first-tag check before the
  end-of-input NeedMore return so a single wrong tag byte
  immediately closes the frame owner; a valid single 0x30
  byte continues waiting for the length. The existing
  `security.credssp-stream-rejections` CTest exhausts
  all 255 invalid first tags, exact consumption, irreversible
  close and the valid-prefix control. Based on prior main
  `1cce799dc1aa7a55e3cb343dd09823052a1c23a6`.
  **PASS:** implementation `36926462d34726f355279367a2ba2f27e93d2095`,
  [CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
  Linux/GCC, macOS/Clang, Windows/MSVC full Debug/Release,
  documentation-policy and SDK/package gates. The owner also
  provided a single-build-root Linux Debug **67/67 PASS** log
  on that exact commit. Real credentials, external clients and
  desktop acceptance remain NOT RUN.
  **Next:**
  continue explicit authenticated GSS/OS admission gates
  separately; no external-client/desktop acceptance claimed.
  **Verified partial OFFLINE connection-finalization fixed PDU decoding (2026-10-15;
  CI PASS):** after the existing canonical
  complete Share Control + uncompressed Share Data parsing,
  the first-party C++23 MCS module recognizes a strict
  22-byte `TS_SYNCHRONIZE_PDU` (type2 0x1f,
  messageType 1, raw targetUser) and 26-byte
  `TS_CONTROL_PDU` (type2 0x14, action
  Request/Granted/Detach/Cooperate, raw grantId and
  controlId). Reuse Microsoft decrypted Client Synchronize,
  Cooperate, Request Control and Server Granted Control
  wire examples. Reject malformed/truncated/extra bytes,
  unknown actions, wrong type/stream/version and
  compressed payloads. All are pure borrowed-input
  syntax without heap work, side effects, channel
  assignment or control activation. A forged
  client-shaped Granted action remains syntax only;
  an authenticated session owner must enforce direction,
  ordering, licensed share and assigned channel.
  Four behavior-named portable CTests added to the
  existing MCS registry; expected **81** portable,
  **91** Linux GSS-enabled (77/87 previously).
  Parent `1c4dc32ef2bb3d1bc86aeffa1bcc7d10f57ab8ed`
  passed [CI 38711285093](https://github.com/k1moradi/RDP-server/actions/runs/38711285093);
  owner confirms **77/77** locally on that parent.
  **PASS:** implementation `c14f47bcd63faaa37761b87ffab06388c1e1bfe7`,
  [CI run 38712823857](https://github.com/k1moradi/RDP-server/actions/runs/38712823857):
  Linux/GCC **91/91**, macOS/Clang and Windows/MSVC
  **81/81** full CTests in BOTH Debug and Release,
  including all four new Sync/Control behaviors;
  documentation policy, staged installed CMake SDK
  consumer and three ZIP/SHA256 package uploads
  PASS. Prerelease publication SKIPPED (no tag).
  **NOT RUN:** owner-local exact-code build/CTest,
  real credential-backed Kerberos/GSS/TLS,
  independently authorized OS session, actual
  Share Activation, channel state, external clients,
  DVC/H.264 graphics or usable desktop.
  **Next:** obtain
  explicitly authorized isolated Kerberos test keytab
  and client ticket cache, prove full GSS/TLS binding,
  add independent OS authorization, and only then
  transition the one session owner through finalization.
  **Partial OFFLINE Demand/Confirm Active capability envelope
  intake (2026-10-15; CI PASS):**
  Extend the first-party C++23 Share Control decoder with
  Demand Active / Confirm Active syntax per MS-RDPBCGR
  2.2.1.13.1.1, 2.2.1.13.2.1 and 2.2.1.13.1.1.1.
  Validate mandatory Confirm originatorID=1002,
  exact sourceDescriptor and combinedCapabilities
  lengths, counted TS_CAPS_SET envelopes (LE16
  size includes 4-byte type/length header), ignored
  pads and the exact trailing Demand sessionId.
  Borrow source/capability ranges from caller storage,
  never copy or allocate, reject incomplete, surplus,
  invalid size and count fields before exposing views.
  Unknown capability IDs remain opaque; four-byte
  FONT envelope mirrors a published Microsoft server
  compatibility quirk but is not typed negotiation.
  Two behavior-named portable CTests are added to
  the original MCS registry. Expected **83** portable
  and **93** Linux GSS-enabled (81/91 before).
  Baseline main `ea258bfcc4a8d8d759a9bc1a882c4f0121959296`
  passed [CI 38713180113](https://github.com/k1moradi/RDP-server/actions/runs/38713180113),
  and owner reports **81/81** local PASS for prior head.
  **PASS:** implementation `5125fcc68f7e3e9fdd496f8504a17a3a7a251953`,
  [Actions 38714673332](https://github.com/k1moradi/RDP-server/actions/runs/38714673332):
  Linux/GCC **93/93**, macOS/Clang and Windows/MSVC
  **83/83** full CTests in EACH Debug and Release;
  both new Demand/Confirm capability tests, project
  documentation-policy, SDK staged installed consumer,
  and ZIP/SHA256 package artifacts PASS. Prerelease
  publishing SKIPPED because this is not a tagged release.
  **NOT RUN:** owner-local new-head CTest, genuinely
  authorized Kerberos/TLS binding, independent OS
  session policy, live Share Active lifecycle, capability
  negotiation, H.264, input or external clients.
  **Next:** isolated explicitly
  authorized genuine Kerberos and independent OS admission
  before binding a negotiated capability set into the
  sole authenticated session owner.
  **Verified offline server Demand Active writer (2026-10-15;
  corrected CI PASS):** complement the existing bounded
  Demand/Confirm Active parser with one direct caller-buffer
  Demand Active Share Control serializer. Write server
  pduSource 1002, shareID, source descriptor, validated
  counted capability envelopes, and trailing sessionId.
  Reuse ONE validator for every nested TS_CAPS_SET on
  both inbound and outbound paths. Reject overlong
  lengths, malformed counts/envelopes, the reserved
  0x8000 FlowPDU length, insufficient output and
  input/output overlap BEFORE any mutation. No internal
  allocation; preserve unused output bytes and treat
  unknown capability IDs as opaque, not supported.
  Two behavior-named CTests in the original fixture
  verify exact 38-byte golden output, round-trip
  decoding, 32767/32769/65535 byte boundaries and
  fail-closed atomic rejection. Expected **85**
  portable, **95** Linux GSS (prior 83/93).
  **Initial CI failure:** implementation `5c0a790ba317f592da21f457842ba6a39a6bd553`,
  [Actions 38716458988](https://github.com/k1moradi/RDP-server/actions/runs/38716458988)
  failed `transport.share-demand-active-encode-wire`:
  the old decoder golden has deliberately nonzero
  ignored `pad2Octets`, while the server writer
  correctly emits zero padding. The new rejection
  suite PASS; fix the golden to canonical zero pad
  without altering production semantics. Corrected
  commit `ec7261e059e699f23511f9d17d0a77762bf5d337`
  [CI 38716746326](https://github.com/k1moradi/RDP-server/actions/runs/38716746326)
  **PASS**: Linux/GCC **95/95**, macOS/Clang and
  Windows/MSVC **85/85** full CTests in EACH Debug
  and Release, plus SDK installed downstream consumer,
  ZIP/SHA256 artifacts and documentation-policy.
  All new writer and rejection tests PASS; the
  canonical-pad test oracle was the only change.
  Baseline `659e0b816e8055f4bec7c87bda2816d8a614b9af`
  passed [CI 38715062876](https://github.com/k1moradi/RDP-server/actions/runs/38715062876);
  owner reports **83/83 local PASS** on the parent.
  **NOT RUN:** owner-local new-head build/CTest,
  authorized real Kerberos/TLS binding, independent
  OS admission, actual negotiated capabilities,
  share activation, licensing, MCS/TLS send,
  external client, H.264 graphics or desktop.
  **Next:** owner-local full CTest, then
  isolated owner-authorized Kerberos/TLS proof
  and separate OS session admission before ANY
  live capability negotiation or Demand Active send.
  **Verified partial OFFLINE server finalization output (2026-10-15;
  CI PASS):** reuse existing first-party
  C++23 Share Data/Control owner to serialize the 22-byte
  server Synchronize and 26-byte server Control Cooperate
  and Granted packets. One common private fixed header
  writer sets source 1002, Share Data type/stream,
  uncompressed lengths and canonical zero padding.
  Synchronize preserves raw targetUser, including the
  historically uninitialized Microsoft example, rather
  than trusting it as a joined MCS channel. Control
  prohibits client-only Request/Detach actions, requires
  zero ID for Cooperate and an assigned 1001..65535 user
  channel for Granted, with server controlId 1002.
  Preflight all output sizes and action/ID rules before
  any bytes change, and preserve suffix/no allocation.
  Two new behavior-named test groups compare byte-exact
  Microsoft-derived canonical oracles, round-trip the
  existing independent decoders, exercise boundary IDs
  and all insufficient output buffers/invalid actions.
  Expected **87 portable / 97 Linux GSS** CTests
  (previous 85/95). Parent main
  `f48332e4465b6915e1683e5ed4f3aae767d3c777`
  passed [CI 38717067457](https://github.com/k1moradi/RDP-server/actions/runs/38717067457);
  owner reports **85/85** local PASS on the parent.
  **PASS:** exact implementation `be87f4ba35289d881a161c0d03ac28c592f3a44f`,
  [Actions 38718197674](https://github.com/k1moradi/RDP-server/actions/runs/38718197674):
  Linux/GCC **97/97**, macOS/Clang and Windows/MSVC
  **87/87** full CTests in EACH Debug and Release;
  both new writer suites, installed SDK downstream
  consumer, ZIP/SHA256 packages, and documentation
  policy PASS. Prerelease publishing SKIPPED
  because no version tag was created.
  **NOT RUN:** owner-local new-code tests, real opt-in
  GSS/Kerberos/TLS binding, independently approved OS
  session, joined channels, licensing, live network,
  share activation, graphics or user input.
  **Next:** owner-local single-build-root CTest,
  followed by explicitly authorized isolated
  Kerberos/TLS positive acceptance and independent OS
  authorization before finalization can be dispatched
  from a single live session owner.
  **Partial OFFLINE Demand/Confirm Active transcript correlation
  (2026-10-15; CI PASS):** the existing
  first-party C++23 MCS/Share module now correlates one
  complete server Demand and one complete client Confirm
  after reusing the canonical exact-length Active parser.
  It checks server source 1002, the separately supplied
  1001..65535 client user source (65536 cannot fit
  Share Control pduSource), mandatory Confirm originator
  1002 and matching shareIDs. Success explicitly means
  `ConsistentSyntaxOnly`, NEVER that the client is the
  authenticated MCS sender, its capabilities negotiated,
  its OS account permitted, or the session activated.
  Two behavior-named portable test groups exercise
  fixture/serializer correlation, malformed transcripts,
  mismatched share and assigned user IDs, and opaque
  capability disagreement; expected **89 portable /
  99 Linux GSS-enabled** full CTests (prior 87/97).
  Baseline main `0e508cfad519d7f9f9f7cb0dd5e54b1c0118e465`
  passed [CI 38718555326](https://github.com/k1moradi/RDP-server/actions/runs/38718555326);
  owner reports **87/87 local PASS** on that head.
  **PASS:** exact implementation `d83549d489be2b8e49855429693d2c5d4b1a0a71`,
  [Actions 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636):
  Linux/GCC **99/99**, macOS/Clang and Windows/MSVC
  **89/89** full CTests in EACH Debug and Release,
  including both new Active-correlation cases;
  docs policy, installed SDK consumer and all
  three ZIP/SHA256 artifacts PASS. Untagged
  prerelease publication SKIPPED.
  **NOT RUN:** owner-local new-head build/CTest,
  real Kerberos/TLS pubKeyAuth with isolated
  tickets/keytab, independently audited OS
  authorization, licensed capability negotiation,
  activated share or desktop.
  **Next:** owner-local single-build-root CTest,
  then controlled real GSS/TLS and independent OS identity
  before a single authenticated owner may enforce
  activation order and dispatch any channel traffic.

  **Verified partial OFFLINE finalization transcript correlation (2026-10-15;
  exact-head CI PASS):** The original first-party
  Share Data parsers now support zero-allocation
  `correlateRdpFinalizationExchange` for six complete PDUs:
  client Synchronize/Cooperate/Request and server
  Synchronize/Cooperate/Granted. Each must match a caller-provided
  expected share ID and role-specific 1002 server or assigned
  1001..65535 client user source; client Request/Cooperate IDs
  must be zero, server Cooperate IDs zero, and Granted must
  address the expected client channel and server control channel.
  The server Synchronize targetUser is deliberately opaque
  because Microsoft examples include an uninitialized value.
  The six named slots are **not evidence of temporal ordering,
  actual MCS sender provenance, CredSSP/TLS identity, independent
  OS permission, licensing, capability agreement or activation**.
  No second state owner, listener or transport output is added.
  Two behavior CTests cover Microsoft examples, independent
  encoder outputs, all six truncation boundaries, extra bytes,
  role spoofing, share mismatches, invalid actions/IDs and
  unsupported compression. Expected **91 portable / 101
  Linux GSS** CTests (prior verified 89/99). Baseline main
  `7777cc92a35cb94193eea4980285dd8153c49648`,
  prior implementation `d83549d489be2b8e49855429693d2c5d4b1a0a71`
  [CI 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636)
  PASS on Linux, macOS, Windows and docs/SDK; owner reports
  **89/89 local PASS** on previous code, without full logs/SHA.
  **PASS:** exact implementation `27996f24e5fbb497c0bee37756d34551d1a47e47`,
  [Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873):
  Linux/GCC **101/101** and macOS/Clang, Windows/MSVC
  **91/91** registered CTests in EACH Debug and Release.
  Both new behavior suites, documentation-policy, SDK
  installed downstream consumer and ZIP/SHA256 packaging
  and uploads PASS; untagged prerelease SKIPPED.
  **NOT RUN:** owner-local updated build/CTest,
  real Kerberos/TLS binding, independently authorized OS user,
  live ordered encrypted finalization, licensed share,
  Microsoft client or desktop. **Next:** owner-local single-root CTest, then
  controlled real GSS/TLS and independent OS admission
  before any live PDU dispatch.

  **Partial TLS-selected-certificate continuity gate (2026-10-15;
  new-head CI NOT RUN at authoring):** The existing
  `PreauthConnectionStream` now pins the SHA-256 digest
  of the selected completed OpenSSL server X.509 certificate
  when the X.224 Confirm-to-TLS handshake is accepted,
  using the already maintained first-party CredSSP TLS
  certificate helper. Before every later direct TLS MCS/GCC
  receive callback, reject a changed certificate EVEN when
  the borrowed `SSL*` remains the same; do not read any more
  decrypted MCS bytes. Close/reset the pin and buffered state
  on all terminal paths. TLS provider/socket ownership and
  event-loop confinement remain unchanged. Direct synthetic
  plaintext parser methods remain diagnostics, not trusted
  TLS/authenticated admission. Reuse the existing real
  OpenSSL memory-BIO fixture to test WANT_READ, partial
  TPKT continuation, complete 416-byte Microsoft frame,
  and an in-place certificate substitution both before
  first read and after a partial TLS frame. Two additional
  behavior-named portable CTests: expected **93 portable /
  103 Linux GSS** (prior 91/101). The parent
  `6d5148a615e22d82d263437be8547a131cfe036e`
  retains the previous implementation
  `27996f24e5fbb497c0bee37756d34551d1a47e47`
  with [CI 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873)
  PASS (91 portable, 101 Linux GSS in Debug/Release).
  Owner reports 91/91 local tests PASS on previous code,
  without a matching log or exact local SHA. **NOT RUN:**
  new-head CI, owner-local compile/CTest, externally
  provisioned real GSS/Kerberos TLS public-key binding,
  independent OS admission, authenticated MCS session,
  Microsoft client, licensed share or desktop. This is
  defense in depth ONLY; a fingerprint is not authentication.
  **First exact-head CI FAIL:** implementation
  `5b1c9790b772923a4a4437d4f4bef4ec7f404d88`,
  [Actions 38738637457](https://github.com/k1moradi/RDP-server/actions/runs/38738637457)
  failed Debug compilation on Linux, macOS and Windows:
  a new test-only forward declaration in an anonymous
  namespace did not refer to the existing file-scope
  `substituteCredSspReplyCertificate`, creating
  ambiguous function calls. The first error is
  `tests/test_owned_preauth_session.cpp` in the
  existing TLS reply tests; no production compile
  error was identified. Release/CTest/SDK NOT RUN.
  **Correction verified:** test-only fix
  `850a6e9b7f2bc0a25854d31e02d0ed25332989b3`,
  [CI 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048),
  relocates the two new test bodies below the original
  helper definition and removes the ambiguous prototype.
  No production code or assertions were changed.
  **PASS:** Linux/GCC **103/103**, macOS/Clang and
  Windows/MSVC **93/93** CTests in EACH Debug and
  Release, both new certificate tests, documentation
  policy, staged SDK/downstream consumer, and ZIP/SHA256
  packages/uploads. Release publishing SKIPPED (no tag).
  **NOT RUN:** owner-local updated build/CTest, positive
  genuine Kerberos/TLS public-key binding, independent
  OS session authorization, external RDP client or desktop.
  **Next:** owner-local one-root CTest, then separately
  authorized real GSS/TLS and OS identity acceptance.
  **Verified partial OFFLINE General Capability Set decoding (2026-10-15;
  exact-head CI PASS):** Extend the existing
  Demand/Confirm Active Share Control decoder with one independent
  allocation-free semantic extraction of the 24-byte
  MS-RDPBCGR 2.2.7.1.1 `TS_GENERAL_CAPABILITYSET`. First reuse
  the canonical complete-PDU and counted-envelope validator;
  scan the borrowed capability list for exactly one General
  (type 1), reject absent/duplicate/incorrect size, invalid
  0x0200 protocolVersion and non-Boolean refresh/suppress
  support values. Preserve OS IDs, compression metadata
  and extraFlags without pretending they have been negotiated;
  ignore `pad2OctetsA` and skip unknown sibling capability
  types. The existing generic envelope parser remains
  permissive for artificial/opaque capabilities.
  Two new behavior-named CTests reuse the MCS executable
  and Microsoft published General capability bytes, covering
  exact server Demand output, independent client Confirm,
  ignored pad/unknown flags, all truncation boundaries,
  trailing bytes, invalid layouts, absent/duplicate
  General, version and Boolean errors. Expected **95
  portable / 105 Linux GSS** full CTests (previous 93/103).
  Previous code `850a6e9b7f2bc0a25854d31e02d0ed25332989b3`
  passed [CI 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048):
  Linux 103/103; macOS/Windows 93/93 each Debug/Release;
  owner reports **93/93 local PASS** on preceding code
  (no exact local SHA/log supplied). Baseline main
  `911e4d3a4459f070588aadc6380d54cc2efda7f5`.
  **PASS:** implementation `3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
  [Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505):
  Linux/GCC **105/105**, macOS/Clang and Windows/MSVC
  **95/95** registered CTests in EACH Debug and Release.
  Both new General capability wire/rejection cases passed
  on all platforms. Documentation-policy, staged SDK
  installation/downstream consumer, ZIP/SHA256 packages
  and uploaded artifacts PASS. Prerelease SKIPPED (no tag).
  **NOT RUN:** owner-local new compile/CTest,
  isolated positive genuine Kerberos/TLS, independent OS
  admission, licensed capability *agreement*, graphics codec,
  Microsoft client or desktop. The new parser makes no
  claim that extraFlags represent negotiation/permission.
  **Next:** owner single-root full CTest, then separately
  authorized real GSS/TLS and OS session identity before
  ANY live capability dispatch.

  **Verified partial OFFLINE Bitmap Capability Set parsing (2026-10-15;
  exact-head CI PASS):** Reuse the same existing
  MS-RDPBCGR 2.2.1.13.1.1 Demand/Confirm Active exact-PDU parser
  and counted TS_CAPS_SET envelopes to extract precisely one
  28-byte MS-RDPBCGR 2.2.7.1.2 Bitmap Capability Set
  (CAPSTYPE_BITMAP=2). Reject missing, duplicate, wrong-size,
  zero desktop dimension, invalid desktopResizeFlag (not 0/1),
  absent mandatory bitmap compression support (MUST=1)
  and absent multiple-rectangle support (MUST=1).
  Do not interpret pad2octets/pad2octetsB, legacy
  1/4/8-bpp receive flags or highColorFlags; preserve raw
  drawingFlags and preferredBitsPerPixel without selecting
  a graphics path. The helper is allocation-free and
  retains no source views, surface buffers or session state.
  Reuse the existing MCS native test binary and CTest registry
  for two new behavior suites exercising Microsoft's independent
  28-byte server Bitmap oracle, round-trip server writer, client
  Confirm, unknown sibling/pad/drawing flags, truncation/trailers,
  missing/duplicate/incorrect sizes, zero dimensions, resize
  and required-support failures. Expected **97 portable /
  107 Linux GSS** CTests (previous 95/105).
  Parent main `39480cb88de6b80277b9c2621ca8ddb41651dfee`
  follows confirmed implementation
  `3625b0daadef1f470bc0b23b3b2aff9106750a6a`:
  [CI 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505)
  Linux **105/105**, macOS and Windows **95/95**
  Debug/Release PASS, SDK and docs-policy PASS. The owner
  reports **95/95 local PASS** on preceding code, without
  a matching complete log/local SHA.
  **PASS:** exact implementation
  `89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
  [Actions 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146):
  Linux/GCC **107/107**, macOS/Clang and Windows/MSVC
  **97/97** CTests in EACH Debug and Release;
  both new Bitmap wire/rejections cases, installed SDK
  consumer, ZIP/SHA256 packaging/uploads and docs-policy PASS.
  Prerelease SKIPPED (no version tag).
  **NOT RUN:** owner-local current-head compile/CTest; real
  Kerberos/CredSSP/TLS binding, MCS sender provenance,
  independent OS session admission, licensed capabilities,
  desktop/graphics and external RDP client.
  Even mandatory Bitmap support in one packet does NOT
  grant authority or bitmap/H.264 dispatch.
  **Next:** owner-local one-root full CTest, then
  independently authorized genuine GSS/TLS and OS
  identity before any live graphics or MCS traffic.
- [ ] Implement licensing, capabilities/share activation, virtual-channel
  routing, graphics delivery, keyboard/pointer and correct lifecycle.
  **Gate A session acceptance (NOT RUN):** integrate existing offline
  serializers/parsers into one live, authenticated MCS attach/join,
  licensing, capabilities, Demand/Confirm Active, finalization and
  disconnect path with outbound TLS write completion, membership
  checks and bounded cancellation. Record a real Microsoft-client
  post-auth share activation before treating this as functional.
  **R3 Channel Join delivery gate (2026-10-15; exact-SHA CI PASS):**
  In the existing MCS module, a single event-loop-affine, bounded component
  tracks up to 33 assigned Channel Join Requests in arrival order, while
  one existing outbound writer serializes each 15-byte confirmation.
  Confirmation membership becomes true only after exact accepted-byte
  completion. Duplicate pending/already-joined requests are ignored;
  malformed/foreign joins, excess callbacks and cancellation fail closed.
  Independent reply and partial-write slice receipts prevent stale callbacks
  from advancing another reply or re-counting previously accepted bytes.
  Joined inbound SendData membership requires the attached UserId and a
  fully confirmed allocated channel; it grants no TLS, R2 identity/OS
  authorization, license, capability, reassembly or application permission.
  Eight NEW dedicated cases in the existing MCS executable and shared
  CTest registry cover completion, denial, duplicates, batching, joined
  SendData, stale replies and stale partial-write slices.
  **PASS (limited):** local GCC 14.2 C++23 ASan/UBSan stand-in 8/8 and
  Clang 17 C++23 ASan/UBSan 8/8, using a reduced parser/encoder fixture.
  **PASS (exact implementation SHA):**
  `469f49e5d4621017016a06095a17ca7cbfc10182`,
  [Actions 38794591251](https://github.com/k1moradi/RDP-server/actions/runs/38794591251):
  Linux/GCC **124/124** and macOS/Clang, Windows/MSVC **114/114**
  full CTests in BOTH Debug and Release. All eight new R3 CTests,
  documentation-policy, installed SDK consumer, ZIP packaging and
  SHA256 artifact checks PASS. Prerelease SKIPPED (no version tag).
  **NOT RUN:** owner exact-SHA Linux/X11, MSYS2 CLANG64/Clang23
  and macOS27 CTests, real TLS/CredSSP/OS-admitted Microsoft-client
  activation, licensed session or desktop.
  **Next:** compose the existing R1 writer and genuine R2 OS-authorized
  TLS/CredSSP decision into one admission-gated R3 MCS domain dispatcher.
  **Gate A/M2 is NOT accepted** from this bookkeeping or synthetic tests.
  **R3 outbound joined-channel envelope (2026-10-15; partial CI PASS):**
  The same post-attach join gate now wraps the existing T.125 server
  SendDataIndication encoder to refuse unjoined, queued, partially joined
  or closed channel IDs without output modification. Existing checked
  PER size, priority, segmentation and buffer/overlap rules are reused.
  Two new central MCS CTests check byte-exact output and fail-closed
  denials. Full project CTest and exact-SHA Actions NOT RUN at authoring.
  Membership is NOT R2 OS admission, TLS security, licensing, capability
  negotiation or data dispatch. R3 Gate A/M2 remains open.
  **R3 exact-SHA hosted verification (2026-10-15):**
  [Actions 38796333656](https://github.com/k1moradi/RDP-server/actions/runs/38796333656)
  built this implementation SHA: Linux/GCC **161/161** and
  macOS/Clang **150/150** full CTests PASS in Debug and Release,
  including both new R3 cases; docs policy and downstream SDK PASS.
  Windows/MSVC compiled and both new R3 CTests PASS, but full Debug
  was **157/158 FAIL** at unrelated R10
  `runtime.validates-configuration-comments-crlf` (expected exit 0,
  observed 3); Windows Release **NOT RUN** because Debug failed.
  Tracked in [R10 CI bug #10](https://github.com/k1moradi/RDP-server/issues/10).
  Owner MSYS2 CLANG64/Clang23, macOS27 and Linux/X11 exact-SHA
  independent tests and real OS-authorized RDP remain **NOT RUN**.
  **R3 R1-to-R2 MCS session denial boundary (2026-10-15; CI NOT RUN at authoring):**
  R1's existing bounded first decrypted Connect-Initial diagnostic now
  passes one complete packet through the R3-owned `McsSessionLifecycle`.
  This noncopyable object embeds the sole bounded Channel Join gate and
  checks the production MCS/GCC/domain parser; absent genuine R2
  TLS-bound, independently OS-authorized evidence, it ALWAYS terminates
  with no Connect Response, Attach Confirm, Channel Join, licensing or
  SendData. Even a valid encrypted packet is **not** user admission.
  Subsequent domain PDUs (Erect/Attach/Join/SendData) are explicitly
  rejected before R2; a valid Disconnect closes without advancement.
  Every malformed input and late re-entry is terminal, with no output or
  inherited channel membership. Two new dedicated central CTests cover
  first Connect-Initial denial and premature domain/teardown ordering.
  **NOT RUN at authoring:** exact-SHA hosted CI, owner three-platform,
  real GSS plus OS authorization, Microsoft-client and desktop.
  **Next:** R2 must deliver an unforgeable, live, TLS-bound OS session
  authorization interface; then R3 extends THIS owner with ordered
  Connect Response/Erect/Attach/Join and outbound write completion.
  Gate A/M2 remains open.
  **R3 exact-SHA hosted CI follow-up (2026-10-15):**
  [Actions 38798696991](https://github.com/k1moradi/RDP-server/actions/runs/38798696991)
  compiled both R3 additions and their dedicated CTests PASS on
  Linux/GCC and macOS/Clang Debug. Their full Debug suites FAIL
  **172/174 Linux** and **160/162 macOS**, at the same two R1-owned
  accepted TCP/TLS readiness/deadline CTests already failing at parent
  `209ebb6fa714b4bba61478539976719506b9b96d`
  [Actions 38798562218](https://github.com/k1moradi/RDP-server/actions/runs/38798562218).
  [R1 bug #11](https://github.com/k1moradi/RDP-server/issues/11)
  tracks those pre-existing assertions. Both Release phases are NOT RUN
  because the Debug step fails; Windows was still running when this
  receipt was prepared. Documentation-policy PASS.
  This is a partial CI result, NOT an overall green commit, and M2
  remains unaccepted pending actual R2-backed OS admission and owner CTests.
  **Verified partial offline MCS lifecycle boundary (CI PASS):**
  the existing `mcs_channel_connection` parser now recognizes
  strictly framed Disconnect Provider Ultimatum with ignored
  inbound reason; the allocation-free server serializer emits
  only provider-initiated (1) or user-requested (3) as required
  by MS-RDPBCGR 2.2.2.3 / 3.1.5.1.1. Two additional portable
  CTests exercise the published nine-byte example and exhaustive
  invalid reason/truncation/transport cases. Baseline main
  `36926462d34726f355279367a2ba2f27e93d2095`
  had owner's Linux Debug **67/67 PASS** and
  [CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
  PASS. **PASS:** implementation `ed4b0c0a05981f573bc6b8369893f33d1e71549d`,
  [CI 38685111404](https://github.com/k1moradi/RDP-server/actions/runs/38685111404):
  Linux/GCC **78/78** and macOS/Clang, Windows/MSVC **69/69**
  in EACH Debug and Release, including both new disconnect cases,
  installed SDK consumers, three ZIP/SHA-256 archives and
  documentation-policy. The prerelease publishing job was SKIPPED
  (no version tag). Owner-local tests of this **new** commit are
  NOT RUN. This is NOT an authenticated server or live teardown.
  **Next:** build the one authenticated session state machine
  with controlled GSS/Kerberos and independent OS admission;
  only then verify TLS-encrypted disconnect send completion
  followed by socket close.
  **Partial offline client SendDataRequest framing (CI NOT RUN):**
  the existing `mcs_channel_connection` parser recognizes T.125
  client DomainMCSPDU choice 25 (0x64), initiator offset from
  1001, channel, priority, segmentation and bounded 7-bit/14-bit
  PER OCTET STRING length. It returns a borrowed caller-buffer
  span without heap copies; malformed lengths, unsupported
  PER fragmentation, invalid padding, bad TPKT and initiator
  overflow fail closed. Two extra portable behavior CTests
  reuse the original MCS executable (71 portable / 80 with
  Linux GSSAPI expected). Baseline main
  `05f2708cc8b326983c406b643bee1d47e5e166d0`
  passed [CI 38685374294](https://github.com/k1moradi/RDP-server/actions/runs/38685374294)
  and the owner reports 69/69 local CTests PASS.
  **First CI FAIL** for implementation
  `c1f9e5458132c40b149e8ec5f0e6083addff8715`:
  [run 38696231297](https://github.com/k1moradi/RDP-server/actions/runs/38696231297)
  found an invalid *test* lifetime: parsing a temporary
  `frameDomainPdu` and reading its borrowed `userData`
  after the vector was destroyed. Linux Debug **79/80**
  and macOS Debug **70/71** passed; the sole failed case
  was `transport.mcs-send-data-wire`. Follow-up keeps
  that frame alive through all view assertions without
  changing the production parser, and adds an offset check.
  **PASS:** correction
  `72af29fddc2424fcc7f4edbd579e2b313ef25f48`,
  [CI 38696503496](https://github.com/k1moradi/RDP-server/actions/runs/38696503496):
  Linux/GCC **80/80**, macOS/Clang and Windows/MSVC
  **71/71** CTests in BOTH Debug and Release; both new
  SendData wire/negative cases, documentation-policy,
  installed SDK consumer and three ZIP/SHA256 packages
  PASS. Prerelease publication SKIPPED (no release tag).
  Owner-local test of the corrected exact commit NOT RUN.
  This does not enable live TLS MCS intake, authorized channel
  membership, reassembly or desktop session admission.
  **Next:** run exact-head full CI; then controlled real
  Kerberos/GSS transcript, verified OS identity/session
  policy, and one owner for all post-auth channel states
  before delivering any client Send Data payload.
  **Partial offline server SendDataIndication encoding (2026-10-15;
  CI NOT RUN at authoring):** the existing first-party MCS
  module can now serialize server-to-client T.125 DomainMCSPDU
  choice 26 to a caller-owned contiguous buffer, with checked
  UserId/channel, priority, segmentation and canonical
  unfragmented PER payload length up to 16383 bytes.
  The result is fixed-header plus one overlap-safe memory
  move, no internal allocation; reject invalid parameters
  or insufficient capacity without mutating output.
  Two additional tests (73 portable / 82 Linux GSS-enabled
  expected) cover byte-exact wire, length boundaries,
  aliasing, bounds and fail-closed output.
  Baseline parent `cd50346be4df281b7fc207c5126072555a3eba63`
  passed [CI 38696744690](https://github.com/k1moradi/RDP-server/actions/runs/38696744690);
  owner reports local **71/71 PASS** on prior code.
  **PASS:** implementation `8c9fabeb02fce7ede13abfb42631d3b7f35a4fc1`,
  [Actions run 38701524465](https://github.com/k1moradi/RDP-server/actions/runs/38701524465):
  Linux/GCC **82/82**, macOS/Clang and Windows/MSVC
  **73/73** CTests in BOTH Debug and Release, including
  both new cases; SDK install/downstream consumer,
  ZIP+SHA256 uploads and documentation policy PASS.
  Prerelease publishing SKIPPED (no release tag).
  **NOT RUN:** owner's local build of this new commit,
  independent OS admission, joined-channel enforcement,
  actual TLS sends, real client, licensing, graphics or desktop.
  **Next:** exact-head cross-platform CI; then controlled
  true GSS/Kerberos/TLS identity and separate OS policy
  before wiring any SendData indication into the one
  authorized session owner.
  **Verified partial offline Share Control Header decoder (2026-10-15;
  CI PASS):** extend the original C++23
  MCS module with a strict, zero-copy T.128
  `TS_SHARECONTROLHEADER` decoder per MS-RDPBCGR
  2.2.8.1.1.1.1. It checks six-byte LE framing,
  complete declared length, version 1 and all five
  documented PDU types, but no nested data message.
  Recognize `totalLength=0x8000` as a MUST-IGNORE
  FlowPDU without exposing body or accepting it as
  activation. Reuse the existing test executable for
  Microsoft 26-byte Control PDU and malformed/ignored
  cases; expected **75** portable and **84** Linux
  GSS-enabled CTests (73 and 82 prior). Baseline main
  `424a35a8ceeb2a32fc553f334cfdcdfeebf5e2a6`
  passed [Actions 38701851845](https://github.com/k1moradi/RDP-server/actions/runs/38701851845);
  owner reports **73/73 local PASS** on that prior code.
  **PASS:** implementation `77fd1be92c0f4dcff60962d645a39af9b23c96de`,
  [Actions 38705203733](https://github.com/k1moradi/RDP-server/actions/runs/38705203733):
  Linux/GCC **84/84**, macOS/Clang and Windows/MSVC
  **75/75** full CTests in BOTH Debug and Release;
  new Share Control cases, documentation-policy,
  installed SDK consumer and all three ZIP/SHA256
  artifacts PASS. Prerelease publishing SKIPPED
  without a version tag.
  **NOT RUN:** owner-local new compile, actual Share
  Control/Share Data dispatch, optional security-header
  handling, licensing, independent MCS/OS authorization,
  external Windows App or desktop session.
  **Next:** genuine authorized GSS
  with active TLS proof, independent OS session policy,
  and the sole authenticated owner for licensing/share
  activation and nested PDU processing.
  **Verified offline T.128 Share Data Header decoding (2026-10-15;
  CI PASS):** reuse the existing MCS/Share
  Control module to decode the 12-byte Share Data Header only
  after an explicitly isolated, complete Data PDU. Accept the
  24 normative type2 values, stream priorities 1/2/4, and
  stream 0 ONLY with Synchronize for known server behavior;
  ignore pad1; preserve uncompressedLength and compressedLength
  as metadata, never allocation or trust boundaries.
  Reject any compressedType != 0 pending real negotiated
  decompression, or any truncated/unknown/FlowPDU input,
  without exposing a borrowed application payload.
  Two behavior-named regression tests reuse the original
  MCS executable with 3 real Microsoft sample layouts;
  **77** portable and **86** Linux GSS-enabled CTests
  expected (75 and 84 prior).
  Baseline `8aea09a101fe1394c6c60145fef42fa002514315`
  passed [CI 38705731398](https://github.com/k1moradi/RDP-server/actions/runs/38705731398);
  owner reports **75/75 local PASS** on that prior main.
  **PASS:** exact implementation `9bc9e041419b4a932dc988a51f1f3e920ac82ba3`,
  [CI 38708579033](https://github.com/k1moradi/RDP-server/actions/runs/38708579033):
  Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
  **77/77** full CTests in EACH Debug and Release;
  both new Share Data groups, project policy, staged
  installed SDK consumer and three ZIP/SHA256 artifacts
  PASS. Prerelease publication SKIPPED (no version tag).
  **NOT RUN:** owner-local NEW compile/CTest, independently
  authenticated OS/session, live TLS/ShareData routing,
  negotiated decompression, licensing, client activation,
  input or desktop.
  **Next:** authorized
  opt-in genuine GSS/Kerberos + TLS certificate binding,
  independent OS session admission, and only afterward
  single-owner Share Control/Share Data lifecycle.
- [ ] Deliver the **first usable, H.264-only Microsoft-compatible RDP server**:
  **Gate B minimum vertical slice (NOT RUN):** ship the first tested
  native server executable with Linux/X11 capture, pointer/keyboard
  input and cursor, after Gate A authorization. Complete negotiated
  RDPGFX AVC420 delivery and robust resize/frame ACK/reconnect before
  adding clipboard, other OS backends or optional codecs.
  **R5 XShm capture-layout bounds increment (based on main
  `d9a46e5cb871b8a81d8a6d057d0f60b568957f45`; exact implementation CI pending):**
  Validate XCB signed-16 coordinates, nonzero unsigned-16 rectangle and
  display dimensions, on-screen geometry, packed 32-bit BGRX stride,
  size_t/uint32 byte limits and shared-memory capacity before GetImage.
  Reject mismatched short/oversized reply byte counts without publishing
  an invalid borrowed FramebufferView; preserve existing arena ownership.
  Linux-only dedicated CTest: `x11.capture-layout-bounds`; headless
  positive/negative and near-4-GiB geometry assertions (no allocation).
  **PASS:** isolated R5 fixture 2/2; GCC 14 and Clang 17 strict-warning
  C++23 capture tests; GCC ASan/UBSan capture test. These results are not
  full-project CI or authorized desktop acceptance.
  **NOT RUN:** complete project CTest, native XCB source compile (missing
  xcb/shm.h), owner Linux/Windows CLANG64/macOS27, benchmarks and live
  Microsoft-client desktop. Current container cannot clone GitHub.
  **Next R5:** native XCB capture compilation/lifecycle CTest followed by
  R2/R3-authorized backend ownership and R4 frame consumer. M3 stays open.
  **R5 XFixes cursor reply-length safety (2026-10-15; implementation
  based on `d7946e2e74bf9ca7cdce66f02080b37085812be6`; exact-head CI pending):**
  `X11CursorTracker::refresh` checks XFixes GetCursorImage reply
  `length` in 32-bit words against the cursor's width-by-height area
  before reading its ARGB pixels. Invalid dimensions and hotspots also
  fail closed; unsupported cursors retain the existing fallback.
  New Linux-only CTest `x11.cursor-reply-length-bounds` checks exact,
  truncated and padded reply lengths, hotspot/dimension rejection,
  BGRX/mask conversion and unmodified output on short spans, without
  an X server. **PASS:** isolated R5 headless CTest 2/2, strict GCC 14
  and Clang 17 C++23 cursor builds, and GCC ASan+UBSan cursor test.
  **NOT RUN:** native XCB tracker compile (xcb/xfixes.h unavailable),
  full-project CTest, owner three-platform tests, human desktop and
  performance benchmarks. **Next R5:** compile and test actual native
  XCB cursor lifecycle with controlled replies; integrate only after
  R2/R3 admission and R4 graphics routing. M3 stays NOT RUN.
  **R5 Linux XCB-SHM native compile increment (2026-10-15;
  base `aa15209c67d74814cac8c859997e623cd096691c`, exact-SHA CI pending):**
  Add separate, noninstalled `rdp-server-linux-xshm` native Linux
  target compiling the actual XShm capture translation unit where
  pkg-config finds `xcb` and `xcb-shm` development headers. The
  portable protocol archive does not link XCB. Move the unchanged
  `captureArenaPixels` algorithm into the existing XCB-free layout
  header so ordinary headless CTests can verify bounds without an
  X server. New Linux-only `x11.capture-arena-and-connection-denials`
  CTest checks zero dimensions, minimum row and capped arenas;
  when XCB-SHM is available it also instantiates native capture
  with an intentionally failed fd -1 connection and verifies
  constructor/capture refusal and safe teardown. Ubuntu CI installs
  developer packages for this compile/test without contacting DISPLAY.
  **PASS:** isolated 3/3 R5 CTests, GCC 14 and Clang 17 strict C++23
  arena test, GCC ASan/UBSan. **NOT RUN at authoring:** actual
  xcb-shm native compile locally (headers unavailable), full repo
  CTest, owner three-platform tests, live desktop, benchmarking.
  **Next R5:** controlled native XShm response/resource lifecycle
  and admitted R2/R3 backend frame access for R4. M3 not accepted.
  implement RDPGFX/DVC lifecycle, AVC420 capability selection, surface mapping,
  changed-region encoding, reference-frame correctness, frame ACK flow control,
  resizing and reconnects together with authorized desktop capture/input.
  Reuse existing first-party C++23 dirty-tile/fingerprint/NV12 scheduling;
  permit native RDPGFX fills, copies and cache reuse (not additional codecs).
  **Use x264 as the sole initial software H.264 encoder:** build a pinned,
  license-reviewed static x264 library (without its CLI/FFmpeg) within the one
  reused build root and link it into the future server executable through a
  small C++23 RAII wrapper. Verify static-link feasibility on Linux/GCC,
  macOS/Clang and Windows/MSVC; keep the current standalone protocol SDK
  independent of encoder dependencies until the runtime is implemented.
  Give one owner exclusive encoder access and lifetime, validate NV12 strides
  and dimensions, and preserve NAL output until packetization. x264 encodes
  complete H.264 pictures even when capture/conversion and RDPGFX updates
  are dirty-region-aware; preserve reference continuity across submissions.
  Defer ClearCodec, Planar and RemoteFX compression entirely; AVC444/v2 is a
  later H.264-only option **only if client negotiation or text fidelity requires
  it**. Never advertise an unsupported mode or silently fall back when AVC420
  is unavailable. **Status: NOT RUN / not a working RDP server.**
  **R4 bounded frame ACK/window (2026-10-15, implemented):**
  parse one reassembled MS-RDPEGFX FRAME_ACKNOWLEDGE command and
  maintain at most 64 exact outstanding frame IDs in the R4 owner.
  Out-of-order matches retire only that ID; duplicate/full-window
  submissions fail closed. The 0xFFFFFFFF queue-depth sentinel
  suspends ACK waiting and clears pending IDs; finite depths resume.
  The R3-authorized channel owner must supply nonreused generations
  to prevent late ACKs releasing frames after resize or reconnect;
  zero generation deactivates the window on disconnect. The client
  queue depth is buffered bytes, not a frame count. No second
  scheduler or R3 dynamic-virtual-channel router was introduced.
  Dedicated CTests: `graphics.frame-ack-wire`,
  `graphics.frame-ack-suspension`, `graphics.frame-ack-rejections`,
  `graphics.frame-ack-correlation`,
  `graphics.frame-ack-bounded-backpressure`, and
  `graphics.frame-ack-stale-generation`. **PASS:** GCC 14.2
  and Clang 17 C++23 ASan/UBSan, all 6 cases each; isolated
  CTest 6/6. **NOT RUN at authoring:** full project CTest,
  owner Linux/Windows CLANG64/macOS27, exact-SHA CI, authorized
  DVC or real Microsoft-client H.264 desktop. **Next R4:**
  integrate this window into the one graphics owner after R3's
  authorized DVC lifecycle and test resize/scheduling/backpressure.
  **R4 bounded AVC420 capability exchange (2026-10-15, implemented):**
  portable MS-RDPEGFX CAPS_ADVERTISE parsing and exact CAPS_CONFIRM
  serialization accept only advertised version 8.1 with its explicit
  AVC420_ENABLED flag. The parser checks every variable-length CAPSET
  header and data length, rejects duplicates, malformed/trailing data,
  unsupported flags and unknown-only offers. It neither opens a channel
  nor enables a session or x264 encoder. The dedicated CTests
  `graphics.avc420-capabilities-selection`,
  `graphics.avc420-capabilities-rejections`, and
  `graphics.avc420-capabilities-header-bounds` cover exact confirmation,
  truncation, overflow, unsupported features and the successive-header
  bounds regression. **PASS:** GCC 14.2 and Clang 17 strict C++23
  ASan/UBSan (3/3 each); isolated staging CTest (3/3).
  **NOT RUN at authoring:** full checkout CTest, exact-commit GitHub CI,
  owner Linux/X11, Windows CLANG64/Clang23, macOS27, authorized R3 DVC,
  real-client H.264 and performance. Gate B remains unaccepted.
  **Next R4 gate:** bind the confirmed profile to R3's authorized DVC
  lifecycle and surface creation, then validate client frame scheduling.
  **R4 surface lifecycle wire increment (2026-10-15, implemented):**
  portable allocation-free CREATE_SURFACE, MAP_SURFACE_TO_OUTPUT and
  DELETE_SURFACE encoders now implement MS-RDPEGFX 2.2.2.9/.10/.15.
  XRGB8888 creation checks nonzero dimensions and 16-bit wire bounds;
  each output buffer is validated before any byte is written.
  Dedicated registered CTests `graphics.surface-lifecycle-wire` and
  `graphics.surface-lifecycle-rejections` exercise exact golden
  bytes, capacity/geometry rejections and atomic failure.
  **PASS:** GCC 14.2 and Clang 17 strict C++23 ASan/UBSan,
  2/2 behaviors per compiler; isolated staged CTest 2/2.
  **NOT RUN:** full repository CTest, exact-commit Actions and
  owner Linux/Windows CLANG64/macOS27 tests, R3 authorized DVC,
  real-client desktop, x264 and graphics benchmarks.
  **Next R4 gate:** connect the negotiated RDPGFX channel to
  CREATE/MAP/DELETE ordering, resize and cleanup under the
  existing single graphics owner; keep Gate B open.
- [ ] Confirm H.264 capability negotiation and a genuinely interactive,
  authenticated desktop with current Windows App on Windows/macOS and
  Windows 11 Remote Desktop Connection. Record actual versions, advertised
  capability sets and failures (including AVC disabled/missing), then verify
  text/input, scrolling, menus, images, clipboard, display resize, frame
  ordering and reconnect. **Status: NOT RUN; no real-client acceptance yet.**
  **Gate C first human acceptance (NOT RUN):** with explicit permission,
  a human must authenticate using a real Microsoft client, see the
  Linux/X11 desktop, move the pointer, type and scroll in a terminal,
  open menus, resize and reconnect without stale updates. Record exact
  client/version, server SHA, negotiation/first failure and separate
  negative tests for invalid credentials and missing AVC. Clipboard,
  screenshot, file transfer and additional OS acceptance remain under
  existing P1 items, not blockers to this first desktop trial.

### P1 — Real client features and performance

**Parallel development; staged feature acceptance:** R6/R7 Windows and
macOS server adapters start immediately, not after Linux testing.
R8 CLIPRDR/file work starts independently and converges for the
declared full-feature beta at M5. Preserve these TODO items and their
real-client acceptance criteria, but do not block the first Linux/X11
interactive desktop (M3) on clipboard, file transfer, Wayland or
optional codecs. Human acceptance remains Linux, then Windows, then
macOS; all platform Debug/CTest work proceeds in parallel.

- [ ] **One native CLIPRDR clipboard session owner** (MS-RDPECLIP): reuse
  `src/server/clipboard/remote_transfer.*`, existing first-party PDU/PNG/DIB
  helpers and tests. Implement channel/capability negotiation, long/short
  named format mapping, Format List acknowledgment, Unicode text, PNG and
  DIBV5/DIB requests/responses, bounded reassembly and cancellation.
  Ordinary Format Data Responses have **no request ID**: permit only one
  outstanding format-data request, associate it with the advertised generation,
  drain obsolete replies, and fail closed on irrecoverably ambiguous timeout.
  File-content replies have separate `streamId` correlation. Do not create
  competing session controllers or depend on xrdp/FreeRDP at runtime.
  **Status: PARTIAL — R8 portable Format List wire intake added on
  2026-10-15; native channel/desktop integration NOT RUN.** The existing
  `RemoteTransfer` owner validates bounded long UTF-16LE or 36-byte short
  ASCII/UTF-16LE Format Lists using R3-negotiated capabilities. Registered
  `PNG` and `FileGroupDescriptorW` IDs are generation-scoped. Malformed
  names/headers/duplicates fail closed; an exact eight-byte
  `CB_FORMAT_LIST_RESPONSE` signals success only after explicit native
  offer acceptance. Declined offers clear advertised IDs while retaining
  stale-response quarantine. Dedicated CTests:
  `clipboard.long-format-list-generation`,
  `clipboard.short-format-list-negotiation`,
  `clipboard.format-list-response-native-acceptance`. GCC 14.2,
  Clang 17 and GCC ASan+UBSan isolated fixture checks PASS; full repo
  CTest, CI, owner platforms and live clipboard NOT RUN at authoring.
  **R8 capability negotiation (2026-10-15):** the same `RemoteTransfer`
  now parses optional bounded `CB_CLIP_CAPS`: at most 16 sets, a single
  exact 12-byte General set, checked lengths, unknown-set skip, mandatory
  short-name fallback when flags are absent, and fail-closed malformed or
  repeated advertisements. General version is informational; negotiated
  flags are the intersection of the peer flags and R3-supplied actual
  server-advertised flags. The new format-list entry point derives long
  versus short names from those flags, preserving native-offer acknowledgment
  and stale-generation isolation. Dedicated
  `clipboard.capabilities-negotiation-format-gating` CTest covers Microsoft's
  capability example, fallback, unknown versions/flags/sets, bounds,
  duplicates and disconnect. Focused GCC/Clang/ASan tests PASS; exact-SHA
  CI and owner three-platform suite NOT RUN at authoring.
  **Still outstanding:** R3 admitted CLIPRDR channel/send and R5/R6/R7
  native clipboard adapters. **Next:** test the authorized R3-to-R8
  channel handoff with real capability forwarding and cancellation.
- [ ] **Bounded eager text/image retrieval, with delayed OS presentation**:
  after a *legitimate client Format List* for generation N, prioritize
  `CF_UNICODETEXT` and registered `PNG` (look up names, not fixed IDs),
  falling back to `CF_DIBV5`/`CF_DIB` when PNG is unavailable. Serialize
  prefetch over the one-at-a-time format-data channel without starving an
  actual paste. Maintain advertised/requested/receiving/ready/failed state;
  cache only verified, size-limited UTF-8 text and compressed image bytes
  for the current generation. Decode/convert on demand with checked image
  dimensions and bounded worker resources; avoid unconditional expanded
  bitmap copies. Never publish incomplete, corrupt or superseded content.
  Client OS focus/privacy policy may delay or suppress an announcement:
  do not poll, infer unseen copies or bypass the client's policy.
  **Status: NOT RUN; screenshot/text prefetch and conversion unimplemented.**
- [ ] **Nonblocking clipboard paste readiness**: register a pending OS paste
  request and deadline; process RDP/desktop events while remote transfer or
  image conversion completes, then satisfy the *same* request or reject on
  timeout, disconnect, clipboard replacement or owner loss. Do not call
  `sleep_for` or wait on a condition variable in the event loop. Support
  X11 asynchronous SelectionRequest/SelectionNotify and INCR for large data;
  use native asynchronous data offers on Wayland/macOS/Windows adapters.
  Never return a success or an empty image before required bytes are ready.
  **Status: NOT RUN.**
- [ ] **OS clipboard ownership without competition**: one native adapter per
  OS; on X11 use the `CLIPBOARD` selection (not `PRIMARY`), XFixes owner-change
  events, timestamps, TARGETS and selection-clear rules. Claim ownership on
  a genuine new remote offer, ignore own changes, suppress echo loops with
  source/generation, and yield when a local app or clipboard manager (for
  example Qlipper) becomes owner. Do not repeatedly reclaim selection from
  a timer or mistake a manager's reoffer for fresh remote content. Test
  ownership handoff, INCR, local copies and races with disconnect/reconnect.
  **Status: NOT RUN.**
- [ ] **Native clipboard file streaming, never whole-file prefetch**:
  negotiate `CB_STREAM_FILECLIP_ENABLED`, `FileGroupDescriptorW` and
  FileContents size/range requests; use `streamId` per file-content request,
  check 64-bit sizes, offsets, bounds and filenames, and support
  `CB_LOCK_CLIPDATA`/`CB_UNLOCK_CLIPDATA` when negotiated. Retain bounded
  metadata and chunk buffers, not entire file bodies; cancel and release
  locks cleanly. CLIPRDR copies files; RDPDR is optional drive redirection.
  For Linux file managers, independently validate a usable destination
  integration (URI/file-descriptor/portal or another native adapter) since
  RDP file streaming alone does not make remote files locally openable.
  Do not require FUSE or `~/thinclient_drives` by default.
  **Status: NOT RUN.**
- [ ] **Real Microsoft-client clipboard acceptance**: macOS screenshot
  taken while Windows App is unfocused, delayed Format List after refocus,
  then remote paste on Linux/X11 into Firefox. Inspect the *synchronous*
  paste event: `clipboardData.items[].getAsFile()` must be non-null with
  MIME `image/png` and the correct screenshot bytes. Exercise immediate
  paste before prefetch completes, repeated paste, local text/image copy
  in both directions, Qlipper competition, PNG/DIB fallback, large INCR
  payloads, file-copy interoperability and clipboard changes mid-transfer.
  An X11 PNG read alone is NOT proof of Firefox file-item acceptance.
  Record client version and capabilities; live host experiments require
  separate authorization. **Status: NOT RUN.**
- [ ] Integrate isolated Linux/X11/Wayland, Windows and macOS desktop,
  clipboard and input adapters; test real Microsoft/FreeRDP clients.
  **R7 M1 increment (2026-10-15):** New, noninstalled macOS-only
  `rdp-server-macos-capture` CoreVideo BGRA read-lock owner and CoreGraphics
  read-only screen-permission preflight; portable, fixed-capacity physical/
  logical display mapping (Retina fractional scales, negative origins,
  monitor gaps, RDP virtual pointer coordinates and display generations).
  No authorization, screen permission request, capture stream, input
  injection, H.264 encoder or clipboard controller is created.
  Dedicated offline CTests: `macos.capture-bgra-layout-bounds`,
  `macos.capture-permission-preflight-revocation`,
  `macos.desktop-retina-points`,
  `macos.desktop-multi-display-invalid`,
  `macos.desktop-reconfiguration`,
  `macos.desktop-virtual-input-coordinates` (portable) and Apple-only
  `macos.capture-bgra-buffer-ownership`,
  `macos.capture-bgra-buffer-native-denials`,
  `macos.capture-bgra-buffer-native-move-replacement`.
  Isolated Linux CMake/CTest **9/9 PASS** including synthetic CoreVideo
  simulation; Clang 17 ASan/UBSan portable **6/6 PASS** and GCC 14.2
  -O2 portable **6/6 PASS**. These are not canonical repository or Apple
  SDK tests. **NOT RUN:** full exact-commit CI at authoring, owner macOS 27,
  MSYS2 CLANG64 23 and Linux exact-SHA tests, permission-dependent live
  desktop, RDP client acceptance and performance. **Next:** native
  CoreGraphics geometry sampler and authorized per-user ScreenCaptureKit
  lifecycle only after R2/R3/R4 interface convergence. M1/M5 remain open.
  **R6 exact-SHA hosted CI verification:** implementation commit
  `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
  [Actions 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194):
  Linux Ubuntu Debug/Release CTest **170/170 PASS** each,
  Windows MSVC Debug/Release **168/168 PASS** each, macOS
  Debug/Release **158/158 PASS** each; documentation-policy,
  SDK install/consumer and packaging also PASS. **NOT RUN:**
  owner Windows MSYS2 CLANG64 Clang 23, owner Linux/X11/macOS 27,
  native live DXGI and Microsoft-client desktop acceptance.
  **R6 DXGI acquired-frame RAII (2026-10-15, authored on parent
  `853e572dafdeab18161afa3926db2f29d2ec3a34`):** `src/windows/windows_dxgi_frame_owner.{h,cpp}`
  owns one native `IDXGIOutputDuplication::AcquireNextFrame` lease,
  releases the COM `IDXGIResource` then calls `ReleaseFrame` exactly
  once on normal completion, cancellation or destruction. Timeout
  remains retryable, bounded to at most 100 ms per poll; access loss,
  release failure and inconsistent native callbacks close the owner
  until a newly authorized duplication/session is constructed. One
  borrowed resource is never reused after release. The native
  duplication pointer is caller-owned and must outlive the frame
  owner. Dedicated conditional CTests, in the existing R6 binary:
  `windows.capture-dxgi-frame-lease-lifecycle` and
  `windows.capture-dxgi-frame-lease-rejections`. **PASS:** Linux
  Clang 17 and GCC 14.2 strict C++23 10/10 R6 case selectors;
  Clang ASan/UBSan 10/10; sparse-only staging CTest 10/10
  (`ctest --test-dir build -C Debug --output-on-failure`).
  **NOT RUN:** complete project CMake/CTest from a synchronized
  checkout (GitHub DNS unavailable here), Windows native SDK
  MSYS2 CLANG64 Clang 23, owner's platform trio, real DXGI desktop,
  R2/R3 session admission and R4 asynchronous graphics consumption.
  Hosted CI result must be checked at the resulting commit SHA.
  **Next:** bind acquired frame resource to a session-authorized D3D11
  staging-map owner and validate row pitch/cleanup without live capture.
  **R6 WinGDI type-name correction (2026-10-15):** At published
  `467bf6bcf4624399e4e24667d214afd738b359d6`, Windows/MSVC
  Debug CI build FAIL at `windows_desktop_geometry.cpp:33`: WinGDI's
  function named `Rectangle` hid the portable C++ type after inclusion
  of `windows.h`. R6 now binds the core `struct ::Rectangle` through
  `PortableRectangle` in its Windows namespace and adds
  `windows.geometry-gdi-rectangle-name-resolution` to the existing
  Windows-only CTest executable. **PASS:** Clang 17 and GCC 14.2 C++23
  strict warnings 8/8 direct cases, Clang ASan/UBSan 8/8; synthetic
  WinGDI-function-first header inclusion 1/1. **NOT RUN:** native
  Windows/MSYS2 CLANG64 Clang 23, owner workstation CTest and human
  desktop; GitHub Actions for the correction pending at publication.
  Next: validated DXGI acquire/release after R2/R3 and R4 contract.
  **R6 direct-main integration (2026-10-15; parent `455b8b631957d2f3f9631393f2a3833e19c2c07a`):**
  7/7 fixture selectors PASS under Clang 17 and GCC 14.2 C++23
  warnings-as-errors; Clang ASan/UBSan 7/7 PASS; sparse CTest
  7/7 PASS. Full repository/Windows CLANG64 CTests remain NOT RUN.
  Native session admission and real desktop acceptance NOT RUN.
  **R6 Windows monitor geometry increment (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_desktop_geometry.{h,cpp}` provides read-only
  `EnumDisplayMonitors`/`GetMonitorInfoW` sampling into owned, bounded
  portable `Rectangle` layouts plus signed-native/unsigned-desktop
  coordinate translation that rejects monitor gaps. Canonical ordering
  makes equivalent monitor enumerations equal for resize detection. The adapter
  remains separate from the protocol archive and cannot grant OS/RDP
  admission. New conditional CTests:
  `windows.geometry-negative-origin-and-monitor-gaps` and
  `windows.geometry-invalid-layout-rejections`, and
  `windows.geometry-order-stable-reconfiguration` (fixture-only).
  **PASS (sparse staging, 2026-10-15):** Linux Clang 17/GCC 14.2
  C++23 `-Wall -Wextra -Wpedantic -Werror` each compiled/executed all
  three fixture behaviors; Clang ASan+UBSan also PASS 3/3 under the
  sole `~/rdp-server/build/` directory. A sparse staging-only
  CTest registry PASS 3/3; synthetic Win32 callback stub also PASS.
  **NOT RUN:** actual Windows/MSYS2 CLANG64 Clang 23 compile,
  dedicated Windows CTest registration, full project CTest, Windows
  capture/input/identity integration, and human desktop acceptance.
  **NOT RUN:** full repository CTest and native Win32 SDK compilation;
  sparse fixture success does not establish M1/M4 acceptance.
  **R6 DXGI BGRA mapped-view validation (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_bgra_frame.{h,cpp}` extends the same Windows-only
  adapter target with a borrowing, zero-copy conversion of a validated
  top-down BGRA8 mapped frame into existing `FramebufferView`. The helper
  requires four bytes per pixel, sufficient mapped row pitch and complete
  backing storage, and caps one frame at 512 MiB. It preserves the previous
  output on failure and does not acquire a live DXGI image. Added dedicated
  Windows CTests `windows.geometry-capture-bgra-stride-and-pixel-order` and
  `windows.geometry-capture-bgra-invalid-frame-denials`, reusing the same
  existing R6 fixture executable and single CTest registry.
  **PASS (sparse staging, 2026-10-15):** focused source/test compilation
  and all **5/5** fixtures with Clang 17 and GCC 14.2 C++23, strict
  warnings-as-errors; Clang ASan+UBSan **5/5**. Sparse staging-only
  `ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
  its new-case `-R '^windows\.geometry-capture-'` **2/2 PASS**.
  **NOT RUN:** native
  Windows toolchain, real desktop capture, full repository CTest and
  R2/R3/R4 authorized end-to-end integration. No Windows user session,
  input or graphics is activated by the helper.
  **R6 DXGI damage metadata normalization (2026-10-15; integrated on main;
  native validation pending):** `src/windows/windows_dxgi_damage.{h,cpp}` emits bounded
  portable `Rectangle` spans from per-output Desktop Duplication move and
  dirty descriptors, in normative move-destination-before-dirty order.
  Validates non-stretched move source and destination bounds, exclusive
  edges, nonempty pixels, 1024-rectangle cap, 32-bit geometry and output
  capacity before committing; malformed late metadata leaves the prior
  output/count intact. Empty pointer-only frames emit zero rectangles.
  The helper neither accumulates damage nor owns an R4 graphics lifecycle.
  **Dedicated CTests:** `windows.capture-dxgi-move-before-dirty` and
  `windows.capture-dxgi-metadata-rejections` (Windows registration, same
  R6 fixture executable). **PASS (sparse offline fixture, Linux):** Clang
  17, GCC 14.2 and Clang ASan/UBSan compiled and executed **7/7** R6
  selectors; sparse local `ctest --test-dir build -C Debug
  --output-on-failure` **7/7 PASS** and focused
  `ctest --test-dir build -C Debug -R '^windows\.capture-dxgi-'
  --output-on-failure` **2/2 PASS**. Full canonical checkout/CTest,
  Windows Clang 23, native SDK and real capture NOT RUN.
  **NOT RUN:** native Windows toolchain and full repository CTest;
  no desktop or injected input was used. Next: native
  DXGI frame acquisition/release/cancellation with R2/R3-approved session
  and R4 borrowed/owned frame lifetime contract, tested offline first.
  **R6 exact-SHA hosted CI verification:** implementation commit
  `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
  [Actions 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194):
  Linux Ubuntu Debug/Release CTest **170/170 PASS** each,
  Windows MSVC Debug/Release **168/168 PASS** each, macOS
  Debug/Release **158/158 PASS** each; documentation-policy,
  SDK install/consumer and packaging also PASS. **NOT RUN:**
  owner Windows MSYS2 CLANG64 Clang 23, owner Linux/X11/macOS 27,
  native live DXGI and Microsoft-client desktop acceptance.
  **R6 DXGI acquired-frame RAII (2026-10-15, authored on parent
  `853e572dafdeab18161afa3926db2f29d2ec3a34`):** `src/windows/windows_dxgi_frame_owner.{h,cpp}`
  owns one native `IDXGIOutputDuplication::AcquireNextFrame` lease,
  releases the COM `IDXGIResource` then calls `ReleaseFrame` exactly
  once on normal completion, cancellation or destruction. Timeout
  remains retryable, bounded to at most 100 ms per poll; access loss,
  release failure and inconsistent native callbacks close the owner
  until a newly authorized duplication/session is constructed. One
  borrowed resource is never reused after release. The native
  duplication pointer is caller-owned and must outlive the frame
  owner. Dedicated conditional CTests, in the existing R6 binary:
  `windows.capture-dxgi-frame-lease-lifecycle` and
  `windows.capture-dxgi-frame-lease-rejections`. **PASS:** Linux
  Clang 17 and GCC 14.2 strict C++23 10/10 R6 case selectors;
  Clang ASan/UBSan 10/10; sparse-only staging CTest 10/10
  (`ctest --test-dir build -C Debug --output-on-failure`).
  **NOT RUN:** complete project CMake/CTest from a synchronized
  checkout (GitHub DNS unavailable here), Windows native SDK
  MSYS2 CLANG64 Clang 23, owner's platform trio, real DXGI desktop,
  R2/R3 session admission and R4 asynchronous graphics consumption.
  Hosted CI result must be checked at the resulting commit SHA.
  **Next:** bind acquired frame resource to a session-authorized D3D11
  staging-map owner and validate row pitch/cleanup without live capture.
  **R6 WinGDI type-name correction (2026-10-15):** At published
  `467bf6bcf4624399e4e24667d214afd738b359d6`, Windows/MSVC
  Debug CI build FAIL at `windows_desktop_geometry.cpp:33`: WinGDI's
  function named `Rectangle` hid the portable C++ type after inclusion
  of `windows.h`. R6 now binds the core `struct ::Rectangle` through
  `PortableRectangle` in its Windows namespace and adds
  `windows.geometry-gdi-rectangle-name-resolution` to the existing
  Windows-only CTest executable. **PASS:** Clang 17 and GCC 14.2 C++23
  strict warnings 8/8 direct cases, Clang ASan/UBSan 8/8; synthetic
  WinGDI-function-first header inclusion 1/1. **NOT RUN:** native
  Windows/MSYS2 CLANG64 Clang 23, owner workstation CTest and human
  desktop; GitHub Actions for the correction pending at publication.
  Next: validated DXGI acquire/release after R2/R3 and R4 contract.
  **R6 direct-main integration (2026-10-15; parent `455b8b631957d2f3f9631393f2a3833e19c2c07a`):**
  7/7 fixture selectors PASS under Clang 17 and GCC 14.2 C++23
  warnings-as-errors; Clang ASan/UBSan 7/7 PASS; sparse CTest
  7/7 PASS. Full repository/Windows CLANG64 CTests remain NOT RUN.
  Native session admission and real desktop acceptance NOT RUN.
  **R6 Windows monitor geometry increment (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_desktop_geometry.{h,cpp}` provides read-only
  `EnumDisplayMonitors`/`GetMonitorInfoW` sampling into owned, bounded
  portable `Rectangle` layouts plus signed-native/unsigned-desktop
  coordinate translation that rejects monitor gaps. Canonical ordering
  makes equivalent monitor enumerations equal for resize detection. The adapter
  remains separate from the protocol archive and cannot grant OS/RDP
  admission. New conditional CTests:
  `windows.geometry-negative-origin-and-monitor-gaps` and
  `windows.geometry-invalid-layout-rejections`, and
  `windows.geometry-order-stable-reconfiguration` (fixture-only).
  **PASS (sparse staging, 2026-10-15):** Linux Clang 17/GCC 14.2
  C++23 `-Wall -Wextra -Wpedantic -Werror` each compiled/executed all
  three fixture behaviors; Clang ASan+UBSan also PASS 3/3 under the
  sole `~/rdp-server/build/` directory. A sparse staging-only
  CTest registry PASS 3/3; synthetic Win32 callback stub also PASS.
  **NOT RUN:** actual Windows/MSYS2 CLANG64 Clang 23 compile,
  dedicated Windows CTest registration, full project CTest, Windows
  capture/input/identity integration, and human desktop acceptance.
  **NOT RUN:** full repository CTest and native Win32 SDK compilation;
  sparse fixture success does not establish M1/M4 acceptance.
  **R6 DXGI BGRA mapped-view validation (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_bgra_frame.{h,cpp}` extends the same Windows-only
  adapter target with a borrowing, zero-copy conversion of a validated
  top-down BGRA8 mapped frame into existing `FramebufferView`. The helper
  requires four bytes per pixel, sufficient mapped row pitch and complete
  backing storage, and caps one frame at 512 MiB. It preserves the previous
  output on failure and does not acquire a live DXGI image. Added dedicated
  Windows CTests `windows.geometry-capture-bgra-stride-and-pixel-order` and
  `windows.geometry-capture-bgra-invalid-frame-denials`, reusing the same
  existing R6 fixture executable and single CTest registry.
  **PASS (sparse staging, 2026-10-15):** focused source/test compilation
  and all **5/5** fixtures with Clang 17 and GCC 14.2 C++23, strict
  warnings-as-errors; Clang ASan+UBSan **5/5**. Sparse staging-only
  `ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
  its new-case `-R '^windows\.geometry-capture-'` **2/2 PASS**.
  **NOT RUN:** native
  Windows toolchain, real desktop capture, full repository CTest and
  R2/R3/R4 authorized end-to-end integration. No Windows user session,
  input or graphics is activated by the helper.
  **R6 DXGI damage metadata normalization (2026-10-15; integrated on main;
  native validation pending):** `src/windows/windows_dxgi_damage.{h,cpp}` emits bounded
  portable `Rectangle` spans from per-output Desktop Duplication move and
  dirty descriptors, in normative move-destination-before-dirty order.
  Validates non-stretched move source and destination bounds, exclusive
  edges, nonempty pixels, 1024-rectangle cap, 32-bit geometry and output
  capacity before committing; malformed late metadata leaves the prior
  output/count intact. Empty pointer-only frames emit zero rectangles.
  The helper neither accumulates damage nor owns an R4 graphics lifecycle.
  **Dedicated CTests:** `windows.capture-dxgi-move-before-dirty` and
  `windows.capture-dxgi-metadata-rejections` (Windows registration, same
  R6 fixture executable). **PASS (sparse offline fixture, Linux):** Clang
  17, GCC 14.2 and Clang ASan/UBSan compiled and executed **7/7** R6
  selectors; sparse local `ctest --test-dir build -C Debug
  --output-on-failure` **7/7 PASS** and focused
  `ctest --test-dir build -C Debug -R '^windows\.capture-dxgi-'
  --output-on-failure` **2/2 PASS**. Full canonical checkout/CTest,
  Windows Clang 23, native SDK and real capture NOT RUN.
  **NOT RUN:** native Windows toolchain and full repository CTest;
  no desktop or injected input was used. Next: native
  DXGI frame acquisition/release/cancellation with R2/R3-approved session
  and R4 borrowed/owned frame lifetime contract, tested offline first.
  **R6 exact-SHA hosted CI verification:** implementation commit
  `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
  [Actions 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194):
  Linux Ubuntu Debug/Release CTest **170/170 PASS** each,
  Windows MSVC Debug/Release **168/168 PASS** each, macOS
  Debug/Release **158/158 PASS** each; documentation-policy,
  SDK install/consumer and packaging also PASS. **NOT RUN:**
  owner Windows MSYS2 CLANG64 Clang 23, owner Linux/X11/macOS 27,
  native live DXGI and Microsoft-client desktop acceptance.
  **R6 DXGI acquired-frame RAII (2026-10-15, authored on parent
  `853e572dafdeab18161afa3926db2f29d2ec3a34`):** `src/windows/windows_dxgi_frame_owner.{h,cpp}`
  owns one native `IDXGIOutputDuplication::AcquireNextFrame` lease,
  releases the COM `IDXGIResource` then calls `ReleaseFrame` exactly
  once on normal completion, cancellation or destruction. Timeout
  remains retryable, bounded to at most 100 ms per poll; access loss,
  release failure and inconsistent native callbacks close the owner
  until a newly authorized duplication/session is constructed. One
  borrowed resource is never reused after release. The native
  duplication pointer is caller-owned and must outlive the frame
  owner. Dedicated conditional CTests, in the existing R6 binary:
  `windows.capture-dxgi-frame-lease-lifecycle` and
  `windows.capture-dxgi-frame-lease-rejections`. **PASS:** Linux
  Clang 17 and GCC 14.2 strict C++23 10/10 R6 case selectors;
  Clang ASan/UBSan 10/10; sparse-only staging CTest 10/10
  (`ctest --test-dir build -C Debug --output-on-failure`).
  **NOT RUN:** complete project CMake/CTest from a synchronized
  checkout (GitHub DNS unavailable here), Windows native SDK
  MSYS2 CLANG64 Clang 23, owner's platform trio, real DXGI desktop,
  R2/R3 session admission and R4 asynchronous graphics consumption.
  Hosted CI result must be checked at the resulting commit SHA.
  **Next:** bind acquired frame resource to a session-authorized D3D11
  staging-map owner and validate row pitch/cleanup without live capture.
  **R6 WinGDI type-name correction (2026-10-15):** At published
  `467bf6bcf4624399e4e24667d214afd738b359d6`, Windows/MSVC
  Debug CI build FAIL at `windows_desktop_geometry.cpp:33`: WinGDI's
  function named `Rectangle` hid the portable C++ type after inclusion
  of `windows.h`. R6 now binds the core `struct ::Rectangle` through
  `PortableRectangle` in its Windows namespace and adds
  `windows.geometry-gdi-rectangle-name-resolution` to the existing
  Windows-only CTest executable. **PASS:** Clang 17 and GCC 14.2 C++23
  strict warnings 8/8 direct cases, Clang ASan/UBSan 8/8; synthetic
  WinGDI-function-first header inclusion 1/1. **NOT RUN:** native
  Windows/MSYS2 CLANG64 Clang 23, owner workstation CTest and human
  desktop; GitHub Actions for the correction pending at publication.
  Next: validated DXGI acquire/release after R2/R3 and R4 contract.
  **R6 direct-main integration (2026-10-15; parent `455b8b631957d2f3f9631393f2a3833e19c2c07a`):**
  7/7 fixture selectors PASS under Clang 17 and GCC 14.2 C++23
  warnings-as-errors; Clang ASan/UBSan 7/7 PASS; sparse CTest
  7/7 PASS. Full repository/Windows CLANG64 CTests remain NOT RUN.
  Native session admission and real desktop acceptance NOT RUN.
  **R6 Windows monitor geometry increment (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_desktop_geometry.{h,cpp}` provides read-only
  `EnumDisplayMonitors`/`GetMonitorInfoW` sampling into owned, bounded
  portable `Rectangle` layouts plus signed-native/unsigned-desktop
  coordinate translation that rejects monitor gaps. Canonical ordering
  makes equivalent monitor enumerations equal for resize detection. The adapter
  remains separate from the protocol archive and cannot grant OS/RDP
  admission. New conditional CTests:
  `windows.geometry-negative-origin-and-monitor-gaps` and
  `windows.geometry-invalid-layout-rejections`, and
  `windows.geometry-order-stable-reconfiguration` (fixture-only).
  **PASS (sparse staging, 2026-10-15):** Linux Clang 17/GCC 14.2
  C++23 `-Wall -Wextra -Wpedantic -Werror` each compiled/executed all
  three fixture behaviors; Clang ASan+UBSan also PASS 3/3 under the
  sole `~/rdp-server/build/` directory. A sparse staging-only
  CTest registry PASS 3/3; synthetic Win32 callback stub also PASS.
  **NOT RUN:** actual Windows/MSYS2 CLANG64 Clang 23 compile,
  dedicated Windows CTest registration, full project CTest, Windows
  capture/input/identity integration, and human desktop acceptance.
  **NOT RUN:** full repository CTest and native Win32 SDK compilation;
  sparse fixture success does not establish M1/M4 acceptance.
  **R6 DXGI BGRA mapped-view validation (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_bgra_frame.{h,cpp}` extends the same Windows-only
  adapter target with a borrowing, zero-copy conversion of a validated
  top-down BGRA8 mapped frame into existing `FramebufferView`. The helper
  requires four bytes per pixel, sufficient mapped row pitch and complete
  backing storage, and caps one frame at 512 MiB. It preserves the previous
  output on failure and does not acquire a live DXGI image. Added dedicated
  Windows CTests `windows.geometry-capture-bgra-stride-and-pixel-order` and
  `windows.geometry-capture-bgra-invalid-frame-denials`, reusing the same
  existing R6 fixture executable and single CTest registry.
  **PASS (sparse staging, 2026-10-15):** focused source/test compilation
  and all **5/5** fixtures with Clang 17 and GCC 14.2 C++23, strict
  warnings-as-errors; Clang ASan+UBSan **5/5**. Sparse staging-only
  `ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
  its new-case `-R '^windows\.geometry-capture-'` **2/2 PASS**.
  **NOT RUN:** native
  Windows toolchain, real desktop capture, full repository CTest and
  R2/R3/R4 authorized end-to-end integration. No Windows user session,
  input or graphics is activated by the helper.
  **R6 DXGI damage metadata normalization (2026-10-15; integrated on main;
  native validation pending):** `src/windows/windows_dxgi_damage.{h,cpp}` emits bounded
  portable `Rectangle` spans from per-output Desktop Duplication move and
  dirty descriptors, in normative move-destination-before-dirty order.
  Validates non-stretched move source and destination bounds, exclusive
  edges, nonempty pixels, 1024-rectangle cap, 32-bit geometry and output
  capacity before committing; malformed late metadata leaves the prior
  output/count intact. Empty pointer-only frames emit zero rectangles.
  The helper neither accumulates damage nor owns an R4 graphics lifecycle.
  **Dedicated CTests:** `windows.capture-dxgi-move-before-dirty` and
  `windows.capture-dxgi-metadata-rejections` (Windows registration, same
  R6 fixture executable). **PASS (sparse offline fixture, Linux):** Clang
  17, GCC 14.2 and Clang ASan/UBSan compiled and executed **7/7** R6
  selectors; sparse local `ctest --test-dir build -C Debug
  --output-on-failure` **7/7 PASS** and focused
  `ctest --test-dir build -C Debug -R '^windows\.capture-dxgi-'
  --output-on-failure` **2/2 PASS**. Full canonical checkout/CTest,
  Windows Clang 23, native SDK and real capture NOT RUN.
  **NOT RUN:** native Windows toolchain and full repository CTest;
  no desktop or injected input was used. Next: native
  DXGI frame acquisition/release/cancellation with R2/R3-approved session
  and R4 borrowed/owned frame lifetime contract, tested offline first.
- [ ] Measure native server CPU/RAM, bandwidth, graphics and clipboard
  p50/p95/p99; only then claim performance improvements.
- [ ] **H.264-only interactive desktop baseline first.** Under the existing
  [benchmark standards](benchmark.md), exercise terminal typing/scrolling,
  code editing with syntax highlighting, text-heavy browser scrolling,
  file-manager navigation, menus/dialogs, and mixed text/images/video.
  These are **text-dominant graphical desktop workloads**, not a terminal-only
  protocol or an assumption that pixels have a known content type. Record
  p50/p95/p99 input-to-visible-update latency where measurable; distinguish
  RDPGFX frame ACK from actual presentation. Also record capture/encode/queue
  timings, CPU on older scalar/dual-core hardware, client decode cost,
  network bytes, RSS/allocations, text fidelity and frame drops at fixed
  resolution, load and network conditions. **Tune x264, not competing H.264
  libraries:** start with `superfast` and `zerolatency`, no B-frames/lookahead,
  persistent NV12 input and bounded in-flight work. Compare x264's
  `ultrafast`/`superfast`/`veryfast`, single-frame-thread versus low-latency
  slice threading, and `X264_MBINFO_CONSTANT` unchanged-16x16-macroblock hints
  enabled/disabled. Only set hints verified against the encoder's reference
  history; test frame skips, refresh, resize and reconnect. Compare matched
  visual quality on LAN and bandwidth-limited WAN, prioritizing end-to-end
  latency over encode-only throughput. **Exclude OpenH264 benchmarking and
  generic alternative-encoder evaluations** from this roadmap.
  **Status: NOT RUN.**
- [ ] **Only after H.264 usability is verified, evaluate ClearCodec** as an
  optional optimization, not a prerequisite. Research and test existing
  [IronRDP ClearCodecEncoder](https://docs.rs/ironrdp-graphics/0.9.0/ironrdp_graphics/clearcodec/struct.ClearCodecEncoder.html)
  (Rust, MIT OR Apache-2.0; implemented residual/RLE and small glyph cache,
  but **not** full bands/V-Bar encoding), and the
  [FreeRDP ClearCodec code](https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/clear.c)
  (decoder/reference; `clear_compress()` is unimplemented as of this review).
  First benchmark the candidate offline against the **same dirty rectangles**
  and H.264 settings; assess missing encoder features, output validity,
  client interoperability and licensing before choosing a reusable reference
  or writing a native C++23 encoder. Avoid a Rust runtime dependency in the
  production protocol library. A residual-only prototype does **not** measure
  the full ClearCodec V-Bar cache benefit. **Status: RESEARCH ONLY;
  encode/decode benchmarks and real-client tests NOT RUN.**
- [ ] **ClearCodec go/no-go after measured comparison.** If an interoperable
  implementation provides repeatable improvements in text-dominant GUI
  p95/p99 latency, total CPU/bandwidth or exact text fidelity **without
  unacceptable regressions** in mixed content, memory, security or frame
  correctness, consider an opt-in ClearCodec path and mixed-codec RDPGFX
  synchronization with H.264. Otherwise retain H.264-only graphics and do
  not add a codec for speculative benefit. Preserve the first-party C++23
  architecture and collect reproducible real-Microsoft-client evidence.
  **Status: NOT RUN; decision deferred.**

### P0 — Standards and repeatable automation

**Deployment hardening gate (NOT RUN):** after an authorized human
desktop trial, record supported sanitizer/fuzzer coverage, concurrent
connections, long-session/leak/race/timeout testing, real-client
latency/CPU/RAM/bandwidth, private-network binding, certificate/account
configuration, service packaging, upgrade and rollback evidence.
Protocol SDK ZIPs are developer packages, not server deployment.

- [x] The canonical agent policy, four mandatory domain standards,
  behavior-named CTest suites, documentation co-change checker and
  local-home-checkout/single-build-root CMake guards passed
  [Actions run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
  at `e1843b07c8772588f29e45a9b8e328e51c59e2ff`.
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  jobs all succeeded. This proves the **CI's isolated checkout
  exception** and offline protocol/policy gates only; the owner's
  persistent `~/rdp-server/build/` and real clients were NOT RUN.
- [x] Automate Debug/Release C++23 builds and full offline CTest,
  staged SDK installation, downstream package consumer verification,
  per-OS ZIP archives and SHA-256 manifests. **PASS:** commit
  `1aa025960288d40f476e85c5a9c5f97b06bebf20`,
  [Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  **three uploaded protocol SDK packages verified**.
- [ ] Exercise automatic tagged GitHub **prerelease publication**
  (`protocol-vX.Y.Z` corresponding to CMake project version, from `main`).
  Release job is configured and gated on successful matrix/maintenance
  checks, but was **SKIPPED / NOT RUN** because no release tag was
  created. Publishing an SDK is **not** installation, activation or
  authenticated end-to-end deployment of an RDP server.
- [x] Consolidate all seven non-entrypoint root Markdown documents
  under `docs/` while retaining `README.md`, `AGENTS.md`,
  `CLAUDE.md`, `CODEX.md`, `agent.md`, `LICENSE` and `NOTICE`
  at repository root. Rebase 47 links, fix attribution package
  install path and enforce the layout using the canonical policy CTest.
  **Initial FAIL:** [run 38544805819](https://github.com/k1moradi/RDP-server/actions/runs/38544805819)
  at `e3e6a7576f530280a1095f8e15f058d7da07f52d` uncovered
  missing CMP0057 in standalone `cmake -P` policy script (10 native
  protocol tests still passed on Ubuntu).
  **PASS:** corrected `list(FIND)` at
  `f68d1d417424823eed7856761ff95f0ebe1eabb2` in
  [Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  passed full Debug/Release CTests, SDK installation, downstream
  consumer and package upload.
  **NOT RUN:** owner-local builds, real clients and service deployment.
- [ ] Expand reusable sanitizer, parser-fuzz, security-negative and real
  client acceptance suites as native runtime code becomes available.
  **Verified CTest reporting increment at `1e11327f2b74ff7e676fbb3bb7200491718a779f`:** Register the existing
  preauth test executable as ten independent behavior-named CTests
  (initial state, request fragmentation/outcomes, reply ordering,
  real TLS handshake, malformed X.224, decrypted MCS fragmentation
  and rejection, encrypted TLS record fragmentation and rejection).
  Keep one shared binary and all preexisting assertions. This changes
  the displayed CTest total from **11 to 20**; it does not mean nine
  newly invented protocol features or that the server can accept users.
  **PASS:** [Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  succeeded, including Debug/Release full CTests, installed
  downstream consumer, ZIP and SHA-256 artifacts. Ubuntu logs
  explicitly confirmed **20/20 passed** in each configuration.
  **NOT RUN:** owner's local CTest after this change, external RDP
  client, authenticated session or desktop. Next development boundary:
  actual nonblocking TLS socket adapter and CredSSP/NLA admission.


  **R9 CLIPRDR Format Data Response fail-closed regression (2026-10-15):**
  A new distinct default-enabled `clipboard.remote-transfer-framing-rejections`
  CTest invokes the production `RemoteTransfer::receiveResponse` and CLIPRDR
  wire decoder in the existing test executable. It rejects all truncated
  response prefixes, malformed/hostile lengths, wrong types/flags, and
  duplicate unsolicited replies; verifies poisoned state, no stale payload
  exposure and fresh data only after an actual disconnect/reset. The
  original `clipboard.remote-transfer` test remains unchanged.
  **Implementation parent main:** `469f49e5d4621017016a06095a17ca7cbfc10182`.
  **PASS (isolated only):** GCC 14.2 Debug and Release and Clang 17
  ASan/UBSan with leak detection using byte-identical production
  `RemoteTransfer` and first-party wire decoder excerpts.
  Deliberately breaking the length check causes expected failure.
  **NOT RUN:** full project build/official CTest (repository Git DNS
  unavailable locally), exact-commit GitHub CI, owner's Linux/X11,
  Windows CLANG64/Clang23 and macOS27 tests or Microsoft RDP client.
  **Next:** exact-SHA CI, canonical one-root owner CTest, then separate
  CLIPRDR fragmentation and R3→R8 authorization regression.

  **Exact implementation CI PASS:** `455b8b631957d2f3f9631393f2a3833e19c2c07a`,
  [Actions 38794861230](https://github.com/k1moradi/RDP-server/actions/runs/38794861230).
  Linux/GCC **125/125**, macOS/Clang and Windows/MSVC **115/115**
  full CTests in **each Debug and Release**. New
  `clipboard.remote-transfer-framing-rejections` and previous
  `clipboard.remote-transfer` both PASS across the hosted matrix.
  The documentation-policy, SDK install/downstream consumer, ZIP
  packaging and artifact upload jobs PASS. Hosted CI uses Windows/MSVC,
  NOT MSYS2 CLANG64/Clang23; owner three-platform exact-SHA
  terminal runs, authentication, Microsoft-client and desktop remain
  **NOT RUN**. Next R9: separate bounded CLIPRDR chunk/recovery test,
  then R3/R8 authorized channel integration.

  **R9 CLIPRDR chunk reassembly reset/bounds regression (2026-10-15):**
  Added default-enabled `clipboard.chunk-reassembly-reset-bounds`,
  independently dispatched in the existing `test_clipboard_protocol`
  executable against first-party `ChunkReassembler::append/reset`.
  Covers all 256 split offsets of a 257-byte synthetic message,
  byte-at-a-time delivery, caller-owned completed output after reset
  and reuse; rejects premature LAST, changed advertised total,
  overrun, duplicate FIRST, continuation without FIRST, null data
  with nonzero length, zero and 8 MiB+1 advertised totals; then
  accepts a clean new first fragment without stale data.
  Existing `clipboard.protocol` assertions run unchanged.
  **Integration parent main:** `54e107bef8670c8ae3b739c442a3e6147a9b1069`. **PASS isolated:** GCC
  14.2 C++23 Debug/Release, Clang 17 ASan/UBSan plus leak detector on
  first-party `clipboard_protocol.h` and byte-identical production
  reassembler methods under `~/rdp-server/build/`. A deliberately
  removed early-LAST size check caused expected assertion exit 134.
  **NOT RUN at authoring:** complete source CMake/official CTest (Git
  clone DNS unavailable in this environment), exact-SHA hosted Actions
  and the owner's Linux/X11, MSYS2 CLANG64/Clang23 and macOS27
  checkpoint; real OS clipboard, Microsoft client and desktop.
  **Next:** verify the exact committed SHA's hosted CTests, obtain
  owner's unchanged one-root platform reports, then test
  authorization/disconnect propagation from R3 to R8.

  **R9 exact-SHA CI receipt — clipboard fragments (2026-10-15):**
  Implementation `d7946e2e74bf9ca7cdce66f02080b37085812be6`, [Actions 38796420558](https://github.com/k1moradi/RDP-server/actions/runs/38796420558).
  **PASS** Linux/GCC **162/162** and macOS/Clang **151/151**
  in EACH Debug and Release full CTest; documentation-policy PASS.
  New `clipboard.chunk-reassembly-reset-bounds` CTest PASS
  in both configurations, as did existing clipboard behavior tests.
  Windows/MSVC Debug compile PASS, **158/159 Debug CTests PASS**,
  including the new R9 regression, but full job **FAIL** at
  `runtime.validates-configuration-comments-crlf`: R10's
  `tests/check_runtime_entrypoint.cmake:118` observed offline
  configuration check exit **3** versus expected **0**. This
  R10-owned Windows failure was reproduced on earlier SHAs and
  is tracked in [issue #9](https://github.com/k1moradi/RDP-server/issues/9).
  Windows Release NOT RUN because Debug CTest stopped the CI job.
  **NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64 Clang23
  and macOS 27 on the same SHA, live OS admission/client/desktop.
  **Next:** R10 fix of the offline Windows CRLF fixture/parser and
  full Windows Debug+Release revalidation; then R9 R3→R8
  authorized-channel/teardown integration negatives.

  **R9 offline MCS joined clipboard response/teardown contract (2026-10-15):**
  Introduced `clipboard.mcs-joined-response-teardown` in the existing
  `test_owned_remote_transfer` executable. Its synthetic complete
  MS-RDPBCGR TPKT/X.224/MCS SendDataRequest contains a genuine
  CLIPRDR Format Data Response processed by R8's production
  `RemoteTransfer`, but ONLY after R3's production
  `McsChannelJoinWriteGate` confirms completion of the last
  JoinConfirm write. The test preserves a pending clipboard request
  across pre-join denial, partial-write denial, wrong user/channel
  IDs, invalid TPKT/PER framing, then checks exactly one successful
  payload, close/reset invalidation and independent new-session
  membership. No extra controller or fixture owner was created.
  **Strict limit:** membership is necessary, NOT sufficient for R2
  TLS/OS authorization, channel role, licensing, MCS fragmentation
  or live RDP delivery; currently no authenticated R3→R8 router.
  **Integration parent main:** `46ef1d2282c6c78b67e37b373be77c624bf529b7`. New test is C++23 portable,
  noninteractive and runs in ordinary full CTest. **NOT RUN at
  authoring:** full checkout local CMake/CTest (git clone DNS unavailable)
  and exact-SHA CI/owner platform runs; prior R9 chunk test has hosted
  Linux/macOS PASS but R10 Windows CRLF test remains independently
  tracked. **Next:** evaluate exact published SHA hosted Actions,
  owner Linux/X11, CLANG64/Clang23 and macOS27, then test actual
  R3 admitted channel routing when R2/R3 integration exists.

  **R9 CI syntax correction (2026-10-15):**
  First implementation SHA `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`
  failed hosted Linux/GCC **Compile Debug** because an R9 source
  insertion duplicated the `int main(int argumentCount` prefix at
  `tests/test_owned_remote_transfer.cpp:828`. No CTests on that SHA
  completed; do not credit the integration regression with a PASS.
  Restored the single original main declaration without changing
  existing assertions, the dedicated new CTest or production logic.
  **Parent main:** `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`. Exact correction-SHA hosted CI
  required before any R9 cross-boundary PASS claim; owner three-platform
  and real R3/R8 authorization remain NOT RUN.

  **R9 MCS→CLIPRDR cross-boundary exact-SHA CI (2026-10-15):**
  Fix SHA `396c81513363d99bb1de60c46f9b2e4bf504c8cf`,
  [Actions 38798952942](https://github.com/k1moradi/RDP-server/actions/runs/38798952942):
  `clipboard.mcs-joined-response-teardown` **PASS** Linux/GCC
  and macOS/Clang **Debug** compiled/native CTest, and project
  documentation policy **PASS**. **FAIL** Linux full Debug
  173/175, macOS full Debug 161/163, precisely two R1
  `test_owned_preauth_session` assertions expecting
  `onSocketReady(true, false) == Interest::Write` at lines
  1967 and 2130. These failed at earlier R1/R3 parents
  too, tracked in [issue #11](https://github.com/k1moradi/RDP-server/issues/11);
  they are not new R9 clipboard failures. Linux/macOS
  Release on this exact SHA **NOT RUN** because Debug
  full-suite failure stopped their jobs. Windows/MSVC
  compiled Debug but hosted Debug CTest **IN PROGRESS**
  at receipt authoring, so no Windows test PASS claimed.
  The initial R9 SHA `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`
  had a self-introduced malformed `main` declaration (GCC
  Compile Debug FAIL) and is superseded by the fix SHA.
  **NOT RUN:** owner's specified Linux/X11, Windows
  CLANG64/Clang23, macOS27 and live Microsoft client.
  **Next R9:** after cross-road CI returns to green,
  test authenticated R3-to-R8 routing and stale session
  teardown using the real, once-available authorized router.

Each implementation updates the relevant item with exact SHA, test
PASS/FAIL/BLOCKED/NOT RUN, first failing boundary and next smallest step.
Put detailed lessons into the appropriate domain standard, not new files.
