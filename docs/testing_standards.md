## R2 delegated-account credential tests (2026-10-16)

## R10 licensing-authority sanitizer registry (2026-10-17)

The service-owned licensing-authority boundary has one flat sanitizer
selection, `^runtime\.licensing-authority-`, rather than another alternative
inside the already-large cross-road R1/R3 licensing regular expression. The
workflow must enumerate and grep all six centrally registered behavior names
before execution: unavailable denials, issuer/policy correlation,
generation/revocation, result bounds/cancellation, sensitive retirement and
real-process startup isolation. A selector compile failure, missing name or
zero-test run is a CI failure, not sanitizer evidence.

The positive provider used by the first five cases is defined only in the test
translation unit and reaches production lifetime logic through a private friend
seam. It must never be linked into `rdp-server`, exposed as runtime
configuration, or described as genuine CAL issuance. The startup-isolation
case executes the real process and reuses the existing CLI oracle, proving
that the test seam cannot bypass normal startup refusal or any supported
offline preflight.


Credential extraction tests must call the production canonical parser, not a
parallel DER or UTF-16 implementation. Deterministic synthetic plaintext may
prove bounded account conversion, domain denial and in-place retirement, but it
is never GSS-authenticated provenance. Keep password bytes out of result objects
and logs; use production `SensitiveBytesGuard` for provider-plaintext lifetime
fixtures.

The portable security sanitizer selection must enumerate delegated-account
extraction, domain ambiguity, sensitive retirement and policy binding with
registry preflight checks. Do not apply the MIT-krb5 LSan suppression to those
tests. The Linux GSS selection separately exercises detached-origin denial and
may retain the provider-scoped suppression. Neither selection may fabricate GSS
completion, PAM authorization or a native admission lease.

## Deterministic adversarial parser corpora use independent bounded oracles

For a production parser mutation corpus, fix a small canonical seed set and an
explicit iteration ceiling. Reparse identical bytes to prove deterministic
classification, compare the caller-owned input before and after parsing, and
keep failure diagnostics free of credentials or mutated secret buffers.

Do not assert that every changed byte must be rejected. A mutation inside a
payload can produce a different structurally valid value. When production
parsing succeeds, validate only the independent properties needed by the
fixture: for example, prove the mutation stayed inside a known unchanged-length
payload and check that payload with a compact Unicode/property oracle. Do not
copy the production DER/parser state machine into the test, because matching
bugs in two parsers are not independent evidence.

Keep malformed structure evidence explicit as well as generative: cover nested
tag/length boundaries, canonical encoding transitions, nonminimal and
truncated length forms, unavailable declared lengths, parent/child
disagreement, duplicate/missing/reordered fields, and total-size boundaries.
Hostile declared lengths must not drive large allocations in the fixture.

Sanitizer CI must enumerate behavior-named registrations with a fail-closed
`ctest -N` check before execution. If a shared CTest regular expression grows
past the implementation's regex complexity/parenthesis limit, preserve the
existing cross-road selection and move the new bounded family to a small flat
selector rather than weakening coverage or treating zero selected tests as a
pass.

## Multi-file clipboard handoff tests prove atomic completed-set visibility

For a multi-file native handoff, materialize at least two files through the
real one-at-a-time `RemoteTransfer` FileContents path. Require publication to
fail while any member is partial, then verify the entire completed set appears
atomically. Cover duplicate URI rejection, exact native list delimiters,
same-generation set mutation denial and stale-generation refusal.

Keep file bytes in ordinary build-root fixtures and clipboard operations behind
the existing injected native seam. The test must not imply directory hierarchy:
current FILEDESCRIPTORW validation preserves leaf metadata only. Real
file-manager/portal directory-tree acceptance remains a separate live gate.

## Windows completed-file handoff tests stay host-clipboard free

Exercise CF_HDROP handoff through the production Windows destination and clipboard-adapter state machines with injected clipboard callbacks. Ordinary CTest must never call the real host clipboard. Require: no publication while the destination is partial; exact completed caller path retention; `DROPFILES.pFiles=20`, `fWide=TRUE`, one fully qualified UTF-16 path and the final double NUL; relative/device-path metadata rejection before native destination duplication; local owner takeover with same-generation reclaim denial; and stale-generation refusal.

Keep the real Win32 `GlobalAlloc`/`SetClipboardData` branch to hosted Windows compile/link coverage unless a separately authorized native acceptance test is requested. Synthetic CF_HDROP success is not Explorer paste acceptance or authenticated Microsoft-client file-copy proof. The R9 sanitizer preflight must enumerate the dedicated `clipboard.windows-completed-file-hdrop-handoff` registration before running the complete clipboard label.

## Completed-file handoff tests must prove partial invisibility

For native file-manager/pasteboard handoff, construct the real destination
state machine and prove its local handoff metadata is unavailable before exact
completion. Then complete the file through genuine `RemoteTransfer`
FileContents receipts/results and verify only the completed local capability is
published. Negative coverage must include malformed/nonlocal local metadata,
generation replacement, local clipboard-owner takeover and same-generation
reclaim denial.

Ordinary tests must inject pasteboard/file-manager operations rather than touch
the user's live desktop. Apple builds should still compile/link the real
AppKit URL-object path. Synthetic URL publication proves only the completed-file
handoff boundary; Finder acceptance and Microsoft-client clipboard file copy
remain separate live acceptance gates.

## R6 coordinated Windows session-retirement coverage (2026-10-16)

A native Windows session-change retirement test must compose the real
`WindowsCaptureSessionGenerationGuard`, `WindowsDxgiCaptureCycle` and
`WindowsInputController` rather than replacing the cross-component boundary
with mocks. Ordinary CTest supplies only deterministic session/generation,
staging/frame and input callbacks: it must not register WTS notifications,
capture a live desktop or call host `SendInput`.

For target or malformed-session revocation, assert the guard is closed before
input cancellation, no key/button cleanup is emitted after revocation, the
borrowed capture view is invalidated before exactly one D3D11 unmap and one
DXGI frame release, and duplicate notification/cancellation is idempotent.
When notification is delivered from a native capture callback, require logical
closure before the callback returns while allowing only the capture cycle's
existing deferred physical teardown. Keep orderly input shutdown as a separate
case: held keys/buttons are best-effort released exactly once only while the
original pinned generation remains current.

## R9 native file-destination destructor retirement

For injected native file-destination state machines that own a duplicated file
capability, explicit `cancel()` coverage is not sufficient. Also destroy an
active destination after at least one short RANGE has been materialized and
prove RAII teardown takes the same fail-closed retirement path: truncate the
partial destination, close the owned duplicate exactly once, and never flush or
publish completion. Keep the case host-state free so it runs in the shared
clipboard sanitizer label on non-native CI hosts.

## R5 native X11 capture-fidelity fixtures (2026-10-16)

Production-backed native capture tests must use an ephemeral 24-bit Xvfb
screen, never a logged-in display. An independent helper XCB connection may
produce deterministic source pixels, but XDamage observation, framebuffer
capture and RandR reconstruction must remain on one real
`X11DesktopResources` aggregate and its single production XCB owner.

Synchronize helper drawing with checked XCB requests, then use a bounded
round-trip on the aggregate's borrowed connection before nonblocking event
dispatch. Do not use arbitrary sleeps to decide that image bytes or RandR
state are ready. Validate the supported 24-bit TrueColor image as 32-bit
little-endian BGRX storage by checking the B, G and R lanes plus exact packed
row stride; the fourth byte is padding and is not an alpha oracle.

A borrowed XShm framebuffer span must be consumed or copied before the next
capture, RandR rebuild or disconnect. A resize test must copy any old-generation
oracle bytes first, require the transaction to commit the new geometry before
later queued events are routed, and then obtain a distinct new-generation
capture. Terminal capture failures must revoke the aggregate and must not
republish a stale arena view. These synthetic tests prove native source pixels
and lifetime boundaries only, not RDP graphics delivery or Microsoft-client
desktop acceptance.

When validating the RandR event-budget fence, deliberately queue a
geometry-bound event on the retiring native resource after the server-side
resize and before the aggregate consumes the RandR transition. Require the
transition to publish the complete replacement generation first, drain the
stale old-generation event without crediting it to the replacement tracker,
then generate a fresh post-rebuild event and require that one to be observed.
Keep this synchronization request/reply based and bounded rather than relying
on sleeps.

The same generation-isolation rule applies to geometry-bound XI2 pointer
observation. Queue a real helper-client pointer motion after the server-side
RandR resize but before the production aggregate consumes that transition.
After replacement, explicitly consume only the new tracker's synchronous
QueryPointer snapshot, then drain the queued old-generation motion and require
that it does not republish a pending coordinate. A fresh post-rebuild motion
must still be observed on the same production XCB connection. Use a checked
round trip to establish queue ordering; do not infer event readiness from a
sleep.

For the XShm child itself, a failed-connection cancellation test is not enough
to prove the native retirement path. Under ephemeral Xvfb, first establish a
real attached capture and finish consuming its borrowed `FramebufferView`.
Then exercise ordinary scope-exit destruction while the external XCB owner
remains live, require a bounded XCB round trip to succeed, and construct a
replacement XShm child on that exact owner. Exercise successful explicit
disconnect/idempotence separately and require another replacement generation.
Do not retain a framebuffer span across either retirement boundary, inspect a
logged-in display, or infer R4/RDP delivery from this native lifetime proof.

## macOS clipboard file-destination tests separate state from native I/O

Compile the macOS file-destination state machine on every hosted OS through
injected native operations so sanitizer coverage does not depend on Apple
runners. Cover more than one 64-KiB range, unknown-size discovery, short-range
continuation, generation replacement, cancellation, remote failure, receipt
mismatch and native write failure. Keep each complete FileContents PDU alive
until synchronous destination consumption because result RANGE bytes are
borrowed.

On Apple, additionally exercise the real descriptor callbacks against a
temporary ordinary file created only in the existing CTest build-root working
directory. Verify exact size and bytes after completion and remove the fixture.
Ordinary tests must never use a live pasteboard, Finder, file promises, user
documents or desktop state. A native-descriptor PASS proves bounded
materialization only, not file-manager paste or Microsoft-client acceptance.

## Windows clipboard file-destination coverage

Test the Windows file-destination state machine through injected native operations on every hosted OS so ASan/UBSan can cover receipt binding, generation replacement, short-range continuation, cancellation and native failure. Include a payload larger than the 64-KiB FileContents range ceiling.

On hosted Windows, additionally exercise the production Win32 callbacks against an ordinary test file created in CTest's build-root working directory. Verify exact final bytes through the caller-owned HANDLE after the destination closes its duplicate. Tests must not access a live clipboard, File Explorer state or user document. Keep broad `windows` labels off this R8 executable so R6's target-only preflight does not select an executable it intentionally has not built.

## R9 complete direct Linux runtime-security sanitizer selection (2026-10-16)

The shared Linux/Clang ASan+UBSan gate must execute every direct offline
production-backed CTest registered from `test_runtime_linux_security`, not
only the CredSSP dispatcher subset. Keep one anchored selector for the ten
behaviors: three service-keytab provisioning/snapshot/policy cases, five
CredSSP/pre-admission connection cases, and the two aggregate
ordered-revocation/premature-admission cases.

Enumerate the central CTest registry with `ctest -N` before execution and
require every one of the ten behavior names. A missing registration or regex
drift is therefore a CI failure rather than a smaller sanitizer run that still
reports green. Keep the existing MIT-krb5 leak suppression scoped to this
GSS-backed selection only; do not broaden it to portable or non-GSS tests.

These cases use build-root synthetic keytabs and loopback sockets only. Their
sanitizer PASS is lifetime, bounds and fail-closed regression evidence; it is
not real Kerberos client authentication, NSS/logind admission, listener/service
activation or Microsoft-client acceptance.



## R7 Quartz display-watch lifecycle tests are host-display free (2026-10-16)

Exercise `NativeDisplayReconfigurationWatch` registration ownership through
its Apple-only injected install/remove callbacks. Ordinary CTest may model
registration-time notifications, duplicate-owner denial, failed removal,
retry retirement, destructor retirement, and delayed callbacks, but must never
call the real CoreGraphics registration functions. When testing ambiguous
removal, prove `nativeCoverageActive()` is already false and
`refreshNative()` returns `TopologyCoverageUnavailable` before live display
enumeration. Hosted Apple compilation of `startNative()` remains SDK/API
evidence, not proof that display-change notifications were delivered.
## R1 nonblocking accept-batch visibility fixtures

A test must not infer that synchronous client `connect()` completion makes a
new peer visible to the listener's immediately following nonblocking
`accept()`. In a bounded batch, a callback may connect another peer and the
next production accept may still legitimately return would-block; the correct
batch result is then `Drained` with the already transferred count.

Keep production accept/batch helpers retry-free. If a loopback fixture needs to
observe a peer that has already connected, boundedly retry from the external
test caller, accepting only `WouldBlock` until one transfer occurs. Preserve
the production distinctions among `WouldBlock`, `Drained`,
`BudgetReached`, `CallbackStopped` and `Failure`; do not weaken those
outcomes merely to remove scheduler timing. Sanitizer coverage should include
the direct batch budget/handoff case because it exercises native descriptor
ownership and callback transfer.

## R8 completed-file X11 handoff tests

Ordinary X11 file-handoff CTests must remain desktop-independent: use the
existing deterministic XCB operation seam plus build-root regular-file
fixtures, never a live user's CLIPBOARD or file manager. Drive the real Linux
descriptor materializer and real `RemoteTransfer` FileContents result owner so
the handoff proof comes from production completion state rather than a test
Boolean.

Require an incomplete materialization to be unpublishable. After completion,
verify TARGETS contains `text/uri-list`,
`x-special/gnome-copied-files`, and
`application/x-kde-cutselection`; verify exact single-file payloads including
URI-list CRLF, GNOME's `copy\n` prefix without a trailing blank URI, and KDE
copy marker `0`. Cover malformed/nonlocal caller URIs, same-generation local
owner takeover, and remote-generation replacement. Sanitizer clipboard
selection must execute the case. This is synthetic file-manager protocol
coverage, not a claim that Nautilus/Dolphin or Wayland portals were exercised.

## R7 macOS session-watch sanitizer coverage is host-desktop free

The R7 desktop-session/watch, input-controller and portable cursor-snapshot
executables are deterministic on non-Apple hosts: they compile the production
C++ geometry/session revision and consumer lifetime state directly and inject
synthetic session/permission/registration/native-command/cursor observations.
Sanitizer CI uses a dedicated Ubuntu/GCC ASan+UBSan job that explicitly builds
`test_macos_desktop_session_guard`, `test_macos_input_controller` and
`test_macos_capture_pixel_buffer`, then runs the anchored
`^macos\.desktop-session-` family plus the exact
`macos.input-controller-session-watch-revocation` case and a fail-closed,
registry-preflighted cursor selection containing
`macos.cursor-session-watch-revocation`,
`macos.cursor-topology-publication-revocation` and
`macos.cursor-geometry-generation-publication-denials`. Keep this road-local
rather than retuning the shared R9 Clang toolchain: hosted Clang 18 with
libstdc++ does not expose the C++23 `std::expected` used by the R7 headers.

The dedicated job covers registration, retirement, delayed-callback,
partial-install, destructor, reentry, guard revocation, stale held-input
suppression, input-callback races and stale cursor publication across
GUI-session, topology and geometry-generation replacement without AppKit, TCC,
a live desktop, native cursor sampling or native input posting. Cursor tests
must distinguish owned shape lifetime from current-desktop eligibility: a
same-dimensions geometry refresh, explicit invalidation, failed refresh or
topology revision change must deny `validFor` / `pixelsFor` and a later
successful refresh must never resurrect the old snapshot.
The Apple-only
`macos.capture-stream-session-watch-frame-retirement` and
`macos.capture-stream-session-watch-consumer-race` cases use synthetic
CoreVideo buffers and injected backends, so do not claim them as Linux
sanitizer execution. Hosted Apple full builds remain deterministic
compile/link/CoreVideo evidence for those paths, while owner macOS 27 remains
the real fast-user-switch delivery gate. Do not treat synthetic coverage or
Apple SDK compilation as authenticated R2/R3 admission or live desktop
acceptance.

## Linux clipboard file-destination tests use build-root files only

Exercise the Linux file-descriptor destination through the real production
native syscalls and existing `RemoteTransfer` FileContents state. Fixtures may
create ordinary temporary test files only in CTest's existing build-root
working directory and must remove them. They must never read or mutate a live
clipboard, home-directory document, desktop portal or file-manager state.

Cover at least: a payload larger than the 64-KiB range ceiling so more than one
request is required; unknown-size SIZE discovery; short RANGE continuation;
exact final size/content; cancellation truncation; clipboard-generation
replacement; remote failure; and unsafe descriptor modes such as
`O_APPEND`. Keep each complete FileContents PDU alive until synchronous
destination consumption because RANGE bytes are borrowed. Passing these tests
proves a bounded descriptor sink, not real file-manager paste or Microsoft
client interoperability.

## R8 macOS pasteboard tests are host-pasteboard free

Exercise `MacClipboardAdapter` through injected native operations under
ordinary CTest on every hosted OS. Cover already-ready text/PNG publication,
DIB-not-PNG routing, change-count owner takeover, same-generation reclaim
denial, remote-generation revocation, disconnect fencing, native failure and
reentry. Apple builds compile/link the real AppKit callbacks, but ordinary
tests must never invoke `generalPasteboard`, read user clipboard data or
mutate the host pasteboard.

As with the Windows R8 adapter, sanitizer CI must explicitly build the macOS
clipboard test executable before running the shared `ctest -L clipboard`
selection. Compile/link success of Objective-C++ is not live macOS clipboard
acceptance, and synthetic callbacks are not authenticated CLIPRDR evidence.

## Focused CTest selectors must match the built target

A focused CI step that builds only one test executable must select only tests
provided by that executable. CTest label filters are regular expressions, so a
broad selector such as `-L windows` also matches labels such as
`windows-adapter` owned by another executable/road. Prefer an anchored
behavior-name regex or an exact road-specific label with explicit registry
ownership. This applies only to focused preflights; the complete build/full
CTest remains the authoritative cross-road gate.

## Borrowed clipboard response fixtures must pin their backing PDU

`RemoteTransfer::Response::payload` is a borrowed span into the caller's
complete CLIPRDR PDU. A test must keep that PDU buffer alive until synchronous
validation/storage has consumed the response. Do not write
`receiveResponse(makeTemporaryPdu(...))` and then inspect/store the returned
payload after the full expression; sanitizers correctly report that as
use-after-free even though production ownership is sound.

Native-adapter CTest labels must also respect focused preflight selectors. R6's
Windows target-only preflight runs `ctest -L windows` after building only its
R6 executable, so unrelated R8 cases use the narrower `win32-adapter` label
while retaining `clipboard` for full and sanitizer suites.

## R8 Windows clipboard tests are host-clipboard free

Exercise the Windows clipboard state owner through injected native operations
under ordinary CTest on every hosted platform. Cover ready-only publication,
exact CRLF UTF-16LE conversion, PNG versus DIB/DIBV5 format identity,
generation replacement, local owner takeover, `WM_RENDERALLFORMATS` owner
verification, disconnect cleanup, native-call failure and reentry. The
production Win32 callbacks still compile under Windows/MSVC, but automated
tests must not call `OpenClipboard`, alter a developer clipboard, create an
interactive HWND, or treat synthetic publication as Microsoft-client
acceptance.

The R9 sanitizer job must explicitly build the Windows clipboard test target
before running `ctest -L clipboard`; otherwise registered cases would exist
without an executable in the selected-target sanitizer build.

## Windows OpenSSL test-oracle CRT boundaries

On Windows, test helpers must not pass an application-owned `FILE*` directly
to a separately built OpenSSL DLL. That can require OpenSSL's Applink CRT
bridge and make an otherwise valid production path fail only in the oracle.
When production parses security material from bounded memory, the test oracle
must independently read its fixture bytes with the application runtime and
use OpenSSL memory-BIO APIs as well. Do not add `OPENSSL_Applink` merely to
make a fixture parse; keep the CRT boundary explicit and test the same
cross-platform object semantics without sharing production parsing helpers.

## R1-owned CredSSP transport seam coverage (2026-10-16)

Reuse the existing native loopback preauth executable for production CredSSP
framing through R1's application-I/O methods. Cover an initial WANT, split DER
progress, exact completed TLS provenance, different-owner denial, raw-SSL
downgrade denial, cancellation before another read, forced short server
writes, exact client-visible DER bytes, first-write adoption of a raw
GSS-style queued reply and cancellation before reply release.

These tests prove transport ownership and lifetime only. They must not
fabricate Kerberos success, an OS admission lease, R3 session advancement or
an externally reachable listener. If a full-suite build is blocked by another
road before these cases execute, record the R1 cases as **NOT RUN** rather
than inferring either PASS or FAIL.

## R1 terminal TLS/EOF readiness fixtures (2026-10-16)

After application TLS is established, tests for peer \`close_notify\`, raw TCP
EOF and other terminal reads must not use scheduler sleeps/yields as a readiness
oracle. Drive client-side OpenSSL WANT_READ/WANT_WRITE only from bounded native
socket readiness with a monotonic deadline. Drive the R1-owned server side only
through \`OwnedPreauthTcpConnection::pollSocketOnce\`, then explicitly resubmit
the same caller-owned span because production does not retain application
buffers or hide an SSL retry. Assert the exact terminal distinction
(\`TlsClosed\` versus \`TransportClosed\`) and that later replay remains closed.

## Runtime aggregate tests before listener activation

Before a production listener exists, exercise a future connection aggregate
with test-only ephemeral loopback sockets and synthetic service credentials.
Such tests may prove ownership transfer, fail-closed missing provisioning,
premature-admission denial and ordered R3→R2→R1 teardown, but must not fabricate
a positive R2 lease or report that evidence as authenticated service
acceptance. Positive admission still requires the real TLS-bound CredSSP/GSS
identity, exact R1 negotiation provenance and concrete native OS evidence.

## Credential continuity tests must mutate the same inode

A pathname-replacement regression proves object-identity continuity but cannot
prove that later provider loads are protected from writes to the already-opened
inode. For credentials retained across connections, add a separate
same-inode/truncate-or-rewrite regression: provision successfully, mutate the
exact source object in place, then require the later provider to consume the
original immutable snapshot. Keep this test distinct from path/symlink
substitution and from positive user-authentication acceptance.

## Synthetic service-keytab test boundary

A generated build-root-only Kerberos keytab may test exact service-credential
acquisition, file permission/path denials and retained-descriptor continuity
without a KDC or client ticket. Such a fixture proves only that the server can
load an acceptor credential. It must never be reported as a successful
Kerberos client authentication, CredSSP identity proof, native OS admission or
RDP session. Positive authentication acceptance still requires explicitly
authorized external client-ticket/KDC evidence plus the normal R2/R3 gates.

# Testing standards — reusable RDP correctness and acceptance

Read [AGENTS.md](../AGENTS.md), [VISION.md](VISION.md), and
[docs/ROADMAP.md](ROADMAP.md) **on each prompt**. This is the
single authoritative testing policy; record new acceptance lessons here.

## Reusable semantic suites

Use **one** CTest registry in `tests/CMakeLists.txt`; extend the existing
compiled C++23 tests and shared bounded fixtures, rather than creating
separate test runners per agent/milestone. CTest names indicate behavior:
`transport.x224`, `transport.mcs-connect-initial`,
`security.credssp-binding`, `clipboard.remote-transfer`.
Labels include `protocol`, `transport`, `security`,
`clipboard` and `project-policy`. Preserve source filenames where
renaming has no functional benefit. Prefer tests against production
translation units, not text-pattern assertions or pure mocks.

## Mandatory automated gates

- Configure/build/run full CTest from the same reused
  `~/rdp-server/build/`. Use `ctest -R`/`-L` for focused work;
  full suite before claiming implementation success.
- Run cross-platform C++23 compile and CTest in GitHub Actions on
  Linux/GCC, macOS/Clang and Windows/MSVC, one checkout-local CI
  `build/` per job. Fix failures instead of hiding or skipping them.
  Hosted CTest invocations use a **60-second default per-test timeout** so a
  crash/assertion that leaves a platform error dialog pending cannot consume
  the historical 1500-second CTest default and starve later validation.
  Purpose-built tests may keep a tighter explicit `TIMEOUT`; do not raise the
  bound to conceal a slow or deadlocked regression.
- Every protocol parser covers valid, truncated, malformed, unknown
  capability, oversized and integer-overflow cases; every state
  machine covers ordering, stale responses, cancel/disconnect and
  lifetime/cleanup. Validate credentials and channel boundaries.
- Add supported ASan/UBSan and bounded fuzzing as implementation
  progresses; document toolchain gaps rather than claiming coverage.
- CI checks for documentation co-changes; an offline policy CTest
  checks mandatory sources. Humans still verify that TODO and evidence
  are materially accurate.
- Real external clients and Linux/macOS/Windows desktop acceptance
  require separately authorized host experiments and recorded client
  versions/capabilities. A simulated FreeRDP peer is not automatically
  a normative Microsoft implementation.

## Synthetic native-server lifecycle fixtures

When a test deliberately destroys the last X client and then constructs a new
independent native owner on the **same** synthetic X server, run Xvfb with
`-noreset`. Without that control, the X server's last-client reset becomes a
second lifecycle transition that can race immediate reconnection and obscure
whether application-owned teardown is correct. Do not paper over that boundary
with sleeps or retries. Keep the server ephemeral, use `-noreset` only when the
test contract requires continuity across a zero-client interval, and leave it
off for tests that intentionally exercise server reset semantics.

Native lifecycle assertions should emit bounded fail-only diagnostics before
aborting: identify the construction phase and print the aggregate's existing
`failureReason()` when available. Never dump desktop pixels, unbounded protocol
buffers, credentials or other sensitive state merely to diagnose a fixture
failure.

When a native child installs event interest or another server-side registration
through a borrowed owner, lifetime tests must keep that owner alive across child
destruction and verify the registration is actually retired. Clearing only the
C++ pointer is insufficient evidence. Prefer a deterministic synthetic native
server plus an ordering round trip over sleeps: prove one event arrives while
the child is active, destroy or disconnect the child, then prove a later native
change produces no event for that client and that a replacement child can
register cleanly.

## Acceptance criteria and reporting

| Feature | Offline coverage | Real acceptance gate |
| --- | --- | --- |
| Connection | X.224/TPKT/MCS/GCC parsers/state | Real-client negotiated handshake |
| Security | TLS/CredSSP/DER/binding rejection | Authenticated AND OS-authorized session |
| Session | Licensing/share/virtual-channel lifecycle | Usable client session and clean disconnect |
| Graphics/input | Frame, codec, queues and input tests | Interactive visible desktop |
| Clipboard | Format/generation/PNG/DIB/file tests | macOS screenshot to Firefox non-null PNG File |
| Installation | Cross-OS packages/adapter tests | Secure standalone server deployment/rollback |

Label every gate **PASS/FAIL/BLOCKED/NOT RUN**, with commit SHA,
exact command/environment, first failing boundary and next TODO.
A green static-library test never proves a complete RDP server.

## Clipboard verification gates (planned; NOT RUN)

Extend the existing behavior-named CLIPRDR/PNG/DIB tests instead of adding
an independent clipboard test runner. Offline tests must cover:

- Capabilities and named-format mappings (`PNG`, `FileGroupDescriptorW`,
  Unicode text, DIBV5/DIB), valid and malformed format lists, responses,
  fragmented channel PDUs, overflow, limits and unsupported formats.
- One outstanding ordinary Format Data Request, fresh/new generations,
  delayed/stale replies, reoffers, timeout ambiguity, disconnect, retry,
  cancellation, and memory ownership. An old response must never satisfy a
  new-generation paste; `streamId` applies to file contents, not to
  ordinary Format Data Responses.
- PNG signature/chunk/CRC and decompressed-size limits, invalid DIB layouts,
  compressed PNG retention, lazy DIB/PNG conversion and bounded memory.
  Image decoding and conversion must not block the session event thread.
- Asynchronous readiness for text and images: paste-before-prefetch,
  completion, timeout, bad input, clipboard replacement, owner loss,
  concurrent local copy, INCR boundaries and cancellation without deadlock.
- X11 selection owner-change ordering, timestamps, self-echo suppression,
  Qlipper-like selection reownership, `PRIMARY` isolation, loop prevention
  and no timer-driven CLIPBOARD reclaim.
- File descriptor lists and streamed file size/range requests with distinct
  stream IDs, non-sequential chunks, >4 GiB metadata, path traversal, lock/
  unlock and disconnect, bounded transfer buffers and **no whole-file cache**.

Real-client acceptance (separately authorized) must test Windows App
on macOS and Windows 11, local-to-remote and remote-to-local text, PNG/DIB
screenshots and file copy/paste. Include the observed macOS case where a
screenshot taken while Windows App is unfocused is not announced until
refocus; record the actual timing rather than assuming a protocol guarantee.
For the Linux/X11 Firefox paste, inspect the synchronous event:
`clipboardData.items[]` must include a file item whose `getAsFile()`
is non-null, type `image/png`, with the expected image. Generic `xclip`,
X11 selection or CLIPRDR unit success is **not** acceptance. Also test a
paste requested before transfer/conversion finishes, Qlipper competition,
large INCR, file-manager destination integration, lock/cancel, slow links,
and clipboard changes during transfer. Distinguish `PASS` from
`BLOCKED/NOT RUN` with client versions, environment and exact SHA.

```sh
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
ctest --test-dir "$HOME/rdp-server/build" -C Debug -L security --output-on-failure
```

## Verified policy and cross-platform CI baseline (2026-10-14)

[GitHub Actions run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706)
passed Linux/GCC, macOS/Clang, Windows/MSVC and the documentation-policy
job at commit `3196a764ffbe24482ad131ad6949f1c2c23d44d9`.
CMake registers ten behavior-named C++23 protocol tests and a project
policy check. Do not infer external-client functionality, real session
authorization or desktop/clipboard usability from these tests.

## TCP connection-request stream regression (2026-10-14)

The existing `transport.preauth-session` suite now covers splitting
the 19-byte X.224 CR at every byte offset, one-byte TCP fragments,
coalesced CR plus TLS bytes (exact consumed length), malformed TPKT
versions, reserved bytes, short/oversize declared lengths, invalid
X.224 type, unsupported security, close and replay rejection. This is
an offline stream-intake test only; no listening socket, real TLS peer,
CredSSP, authenticated desktop or external client is included.
Cross-platform CI results must be recorded in the validation ledger.

## Verified incremental X.224 stream-intake coverage (2026-10-14)

Commit `988938a90f8adbae4e07714ac636af3eb0640011` passed
[Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
The existing `transport.preauth-session` test now exercises every
split point of a complete X.224 request, byte-at-a-time delivery,
coalesced trailing TLS bytes, size/version/type rejection,
unsupported security and terminal replay/close behavior.
No TCP listener, TLS server, session admission or external client
was exercised; these acceptance categories remain NOT RUN.

## Verified X.224 response-ordering regression (2026-10-14)

The existing `transport.preauth-session` suite also tests that a TLS
completion signal before the Connection Confirm has been fully sent is
rejected, as are failed/partial and duplicate send acknowledgments.
It verifies exactly one completed Confirm allows progression to the
existing *synthetic* TLS stage, but **not** real TLS negotiation or
authenticated desktop access.

**Exact-head PASS:** commit `18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`,
[Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
passed GCC/Linux, Clang/macOS, MSVC/Windows and the documentation gate.
This confirms the new response-write completion checks within the
synthetic C++23 transport tests; it does not validate a TLS provider.

## Verified incremental MCS stream regression (2026-10-14)

The consolidated `transport.preauth-session` CTest additionally
covers all 416 ways to split the Microsoft MCS/GCC example fixture,
single-byte delivery, every truncated prefix followed by close,
multiple TPKTs in one decrypted read, invalid version/reserved byte,
short/over-limit length, malformed X.224 type/EOT, corrupted BER and
out-of-order/replayed decrypted input. The diagnostic always closes
after the initial envelope and registers no channels; no real TLS
provider or client was executed.

**PASS:** `49c6006d47476184f7448028cd332e377ec9bd0b`, [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607), CMake configure/build/full CTest on Ubuntu/GCC, macOS/Clang and Windows/MSVC plus documentation-policy. Owner-local build and external clients **NOT RUN**.

## Automated SDK installation and consumer acceptance (2026-10-14)

The same consolidated CI compiles/tests Debug and Release for all three
operating systems. For Release it stages installation in the current
build root and configures a small **separately built downstream consumer**
under `build/consumer`. That consumer must find the installed package
with `find_package(RDPServerProtocol CONFIG REQUIRED)`, link
`RDPServer::protocol` and execute a real X.224 parser call.
This tests relocatable CMake metadata and linkage, NOT a TCP listener.
CPack ZIP archives and SHA-256 manifests are delivered only after all
runner-local gates succeed; tagged prerelease publication waits for
all OS jobs and documentation checks. A protocol library archive
is never a substitute for real-client, NLA or desktop acceptance.

## Verified automated release-package smoke gates (2026-10-14)

Commit `1aa025960288d40f476e85c5a9c5f97b06bebf20`
[Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777)
passed the full Debug and Release CTests, separately compiled and
executed the installed SDK consumer, and uploaded a CPack ZIP and
SHA-256 manifest on each of Linux/GCC, macOS/Clang and Windows/MSVC;
documentation-policy PASS. These are **offline packaging and link
checks** only. GitHub Release publication is NOT RUN pending an
explicit version tag; authenticated RDP host deployment is unavailable.

## Portable CMake script-mode checks (2026-10-14)

CTest executes the project-policy verifier with `cmake -P`.
Standalone CMake script mode does not necessarily inherit the
configuring project's minimum policy version: `if(IN_LIST)` without
CMP0057 NEW can reject valid syntax. Use policy-independent
`list(FIND ... index)` for set membership in these scripts, or
explicitly declare the script's required minimum CMake version.
Preserve the root layout assertions and check all hosted toolchains.

**PASS after correction:** commit
`f68d1d417424823eed7856761ff95f0ebe1eabb2`,
[Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535)
passed policy and full Debug/Release protocol tests, downstream
consumer installation and packaging on all three hosted OSes.
This verifies the policy-independent root document membership check.

## Real OpenSSL handshake evidence (pending exact-head CI)

`transport.preauth-session` constructs an ephemeral EC P-256 key
and self-signed X.509 certificate **in memory**, performs actual
OpenSSL client/server TLS negotiation across a BIO pair, and tests
that only the completed server SSL object can pass the stream
boundary after the entire X.224 reply. It rejects unfinished,
client-role, null, premature and repeated transitions. The fixture
does not validate certificate trust, CredSSP, user credentials
or an OS session. Hosted Linux/macOS/Windows Debug/Release
CTV and package gates remain to be verified on this commit.

**Exact-head PASS:** `edfaf2e7ea684ab5adc77bf58441ff467288f818`,
[Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274)
passed all Debug and Release protocol and policy CTests, nested
downstream install/consumer CTest, and CPack SDK packaging on
Linux/GCC, macOS/Clang, Windows/MSVC, as well as documentation-policy.
No live network client, OS admission or external server was tested.

## In-memory encrypted TLS record intake (CI pending)

Extend existing `transport.preauth-session`, not the test executable
registry. Use an ephemeral self-signed test certificate and an OpenSSL
memory BIO pair, send actual encrypted application records over
`SSL_write_ex`, and exercise `SSL_read_ex` on the server side for
every split position of the Microsoft 416-byte MCS/GCC fixture.
Assert WANT_READ retry, precise consumed plaintext bytes,
coalesced next-PDU preservation, malformed header rejected after
exactly four decrypted bytes, wrong/foreign SSL handle rejection,
premature transitions, orderly TLS close and terminal replay.
This is only a test of authenticated *record integrity* within TLS,
not CredSSP credentials, certificate enrollment, a TCP server, or
independent OS desktop authorization.

**Verified encrypted-record regression (2026-10-14):**
commit `a226f15827e9da48ad7a91b7cfa53528c3498802`,
[Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241)
passed on Linux/GCC, macOS/Clang and Windows/MSVC, plus the
documentation-policy job. The same `transport.preauth-session`
CTest exercises all 416 fragment splits as real TLS application
records, WANT_READ retry, exactly bounded TPKT consumption,
coalesced follow-up packet retention, swapped TLS handles, invalid
header and TLS close_notify during a truncated envelope. All
Debug/Release CTests and SDK install/consumer/package gates passed.
Live sockets, CredSSP/NLA and OS admission were NOT RUN.

## Verified granular behavior-named CTest reporting (2026-10-14)

`ctest` counts registered test commands, **not assertions or loops**.
Previously `transport.preauth-session` was one registered test even
though its native executable ran ten behavior groups (including all
416 Microsoft fixture TLS split points), so the visible total
remained 11. Register those groups individually via **one existing
test executable**, one CMake test registry and distinct command-line
case arguments. Preserve every existing assertion and keep direct
no-argument execution as the complete suite. A mistyped/unknown case
name exits nonzero. Expected CTest registration:
**20 tests** (nine other native test executables, ten preauth
behavior cases and one project-policy test). This count measures
reporting granularity, not server protocol coverage or authorization.

**Verified:** exact code commit
`1e11327f2b74ff7e676fbb3bb7200491718a779f`,
[Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423)
passed Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
Ubuntu's full Debug and Release CTest logs each report **20/20 PASS**;
all three platform SDK install/consumer and ZIP checks passed. No
owner-local post-change run, external client or OS admission was tested.

## Verified exact X.224 partial-write regressions (2026-10-14)

The existing `test_owned_preauth_session` executable registers
a new independent `transport.x224-confirm-partial-writes`
CTest. Verify every 0..19-byte split of the full Confirm,
every one-byte send, an EAGAIN/zero write, suffix exactness,
a partial-write TLS attempt, overreported positive counts,
terminal writer cancellation, post-completion replay and
an entirely delivered failure PDU followed by close.
The preexisting 20 CTests remain, making **21 registered
cases** with the same binary/fixture ownership. This measures
real additional wire-output behavior, not extra fake coverage
or successful network authentication.

**PASS:** code commit `98f6fdc60d513d47a87a78fadf1aa6be387da28b`,
[Actions run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
Debug/Release CTests, installed SDK consumer and all platform
ZIP/checksum gates passed. Ubuntu logged **21/21 PASS** twice.
Live network, external clients, NLA and OS admission are NOT RUN.

## Verified nonblocking TCP preauthentication adapter (2026-10-14)

The existing `test_owned_preauth_session` executable adds two
independent behavior-named CTests: `transport.tcp-adapter-fragments`
and `transport.tcp-adapter-backpressure`. A scripted socket interface
simulates exact partial recv/send progress, would-block, every split
of the 19-byte Connection Request, one-byte reads/writes,
coalesced ClientHello preservation, rejected negotiation Failure
output, malformed TPKT, EOF/hard read/write failures, invalid
overreported byte counts and terminal connection closure.
The native Winsock and POSIX adapters are cross-compiled but not
connected to an active OS TCP listener by this regression.
Expected CTest total **23**, previously 21; authentication, actual
network peers, TLS network pump and desktop remain NOT RUN.

**PASS:** code commit `dd3a806f97b13e6db18affd689c6321bfa009813`,
[GitHub Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
passed Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release full CTests, staged SDK install, downstream consumer
and all three ZIP/hash uploads. Ubuntu logs confirm
**23/23 passing** in both builds. The native OS recv/send
implementation compiles on all three platforms; scripted
TCP I/O, not connected live sockets, drives the new tests.

## OpenSSL 4 X.509 fixture compatibility (2026-10-14; CI follow-up)

[Actions run 38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
failed macOS/Clang Debug compile because Homebrew's FindOpenSSL
selected OpenSSL **4.0.3**; `X509_get_subject_name` supplies a
`const X509_NAME*` in this release, and mutating it is forbidden.
The offline TLS fixture now uses its own RAII `X509_NAME_new()`,
`X509_NAME_add_entry_by_txt()`, then
`X509_set_subject_name()` and `X509_set_issuer_name()` to
construct the self-signed ephemeral certificate. This avoids
casting away `const` and is compatible with OpenSSL 3 and 4.
The test still does not establish live certificate trust.

**PASS:** fixed implementation `5c4f3ad7273d17948327b7d351ff9840de2b0395`
[GitHub Actions run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002)
completed Linux/GCC, macOS/Clang and Windows/MSVC
Debug/Release **23/23 CTests**, documentation-policy, staged SDK
installation and downstream consumer, and three ZIP/checksum uploads.
The macOS passing runner used OpenSSL **3.6.4**, not 4.0.3; a
post-fix test specifically linked against OpenSSL 4 remains
**NOT RUN**. Preserve explicit version evidence rather than
calling an API change verified across both versions.

## Verified nonblocking OpenSSL server TLS handshake owner (2026-10-14)

Two behavior-named CTests in the **existing** preauth binary,
`transport.tls-nonblocking-handshake` and
`transport.tls-nonblocking-failures`, exercise a real
in-memory OpenSSL client/server TLS handshake via BIO pair
driven by the new one-owner event-loop handshake method.
Assert WANT_READ before ClientHello, further nonblocking
progress, eventual completed server-role TLS, and use of the
same SSL for the bounded 416-byte MCS/GCC envelope.
Negative gates: premature TLS before the X.224 response
is sent, null/client-role handle, foreign server-handle swap
after WANT_READ, explicit cancellation/replay, and
unusable socketless SSL. Expected **25 total registered
CTests**, up from 23 for two independent behaviors. These
tests use a synthetic in-memory certificate and do not
validate certificate trust, socket runtime, CredSSP,
desktop authorization or external RDP clients.

**PASS:** exact implementation
`fcd05f8e903a459ca85f13807bd35f7091f3fd70`
in [CI run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099):
Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
both Debug/Release **25/25 CTests**, staged SDK install,
downstream compiled/linked/running consumer and all three CPack
ZIP/checksum uploads. The TLS event-loop handshake is verified
against an in-memory BIO peer, not a native TCP socket or real
RDP client. An explicit OpenSSL 4.x post-fix runner is still
NOT RUN; see the compatibility gate above.

## Verified real native TCP loopback TLS/MCS transport (2026-10-14)

The existing `test_owned_preauth_session` CTest registry adds two
independently named behaviors without duplicating the executable:
`transport.tcp-native-loopback-tls` and
`transport.tcp-native-loopback-close`. Each test creates a
short-lived, OS-assigned ephemeral loopback port, connects one
client, accepts one server socket, and closes its temporary
listener before protocol traffic. The first exchanges real
TCP X.224 Request and Confirm using `NativeTcpIo`, attaches
OpenSSL through the borrowed custom BIO on **both peers**,
drives a TLS server handshake with WANT readiness, sends a
real encrypted Microsoft 416-byte MCS/GCC example and validates
the envelope without OS admission. The second verifies real
native EOF during a truncated Connection Request and a complete
protocol Negotiation Failure over connected sockets, with no TLS.
All socket resources are RAII/closed. Expected full CTest
registration: **27**, formerly 25. **PASS:** after the test-only readiness fix at
`7ce64737ccef439af2f0cfd383208181cc0e9513`,
[Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
passed Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release **27 CTests** on all OSes, staged SDK installation,
downstream consumer and platform package/checksum uploads.
Ubuntu's full CTest logs explicitly show **27/27 PASS** in both
build modes, including both native socket cases.
External RDP clients, credential verification, OS desktop admission
and service deployment are NOT RUN.

## Deterministic loopback event readiness (2026-10-14)

**First CI FAIL:** implementation
`c53a591c8d5b6dbb4cd63f742bddb2c3eeb2ede8`,
[run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
reported both `tcp-native-loopback-*` CTests failing on
macOS Debug due to an incorrect test assumption: after TCP
send or close, the very next nonblocking recv need not
observe the bytes or FIN. Ubuntu and Windows plus
documentation-policy passed. Test-only code now waits
a bounded number of short 1ms intervals until the exact
expected read/EOF readiness event, verifies the expected
prefix was actually consumed before client close, and
still fails if it never occurs. Do not hide native
callback errors or spin in production code.
**PASS after correction:** full cross-platform Debug/Release
27-CTest matrix, downstream SDK consumer and three packages in
[Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
at `7ce64737ccef439af2f0cfd383208181cc0e9513`.
The owner's new local run and real external clients remain NOT RUN.

## MCS Connect-Initial domain negotiation (CI pending)

Reuse `tests/test_owned_mcs_connect_initial.cpp` and the existing
Microsoft 416-byte fixture; no new test binary or runtime
connection controller. Test the eight-field
`mergeMcsDomainParameters` against the documented 34/3/65528
domain result, target/min/max fallback paths, protocolVersion
2 bracketed by non-2 min/max BER values, and each of eight
failure branches with zeroed result. Also feed an otherwise
valid Connect-Initial with mutually incompatible protocol
versions into the existing preauthentication diagnostic and
assert terminal invalid framing/close.
Register the four existing envelope behaviors individually
and two new domain behaviors as six CTests in the canonical
test registry: expected total **32** vs 27 (two new
behaviors, four existing now registered separately instead
of one group). Preserve no-argument execution of all six tests.
An offline domain merge is not an MCS Connect-Response, an
authenticated server or live-client acceptance.

## Standalone response-wire encoder, not admission (CI pending)

Keep the existing `tests/test_owned_mcs_connect_initial.cpp`
binary and the centralized `tests/CMakeLists.txt` registry.
Add `transport.mcs-response-wire` with a complete independent
**108-byte** Enhanced TLS Connect-Response/GCC golden packet
based on Microsoft [4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3):
exact TPKT/BER/PER lengths, McDn and SC_CORE/NET/SECURITY,
including three channel assignments and odd padding.
Also exercise upper-bound T.124 nodeID and BER sign padding
for a 32-bit domain parameter.
`transport.mcs-response-rejections` must reject illegal node IDs,
unsupported security protocols, missing/mismatched/duplicate or
reserved channels, an unmergeable domain and missing GCC
client data, returning no serialized bytes.
Expected full CTest registration **34**, up from 32.
The older parser suites remain active; no code path may
send a response or claim credential/OS admission from these
offline tests.

## Verified offline MCS Erect/Attach/ChannelJoin request regressions (2026-10-14)

In the existing `test_owned_mcs_connect_initial` binary, register
three additional behavior-named CTests without another executable:
`transport.mcs-erect-request`, `transport.mcs-attach-request`,
`transport.mcs-channel-join-request`. Use independent literal
TPKT/X.224/PER wire oracles from Microsoft's published
MS-RDPBCGR 4.1.5, 4.1.6 and 4.1.8.2.1 examples, plus 4.1.8.5.1
for channel 1006. Each test checks all byte-boundary
truncations and malformed framing, payload surplus, invalid
PER integer lengths/nonminimal values, UserId overflow,
wrong direction/choice padding and preservation of valid
channel identifiers without falsely calling them joined.
The previous 34 CTests remain; expected **37 CTests**.
Live phase ordering, authorization, send/confirm responses,
client interoperability and authenticated OS session
admission remain **NOT RUN**.

**First CI regression (2026-10-14):** the new wide-field Erect
example in `testMcsErectDomainRequest` mistakenly encoded
`0x04` as the byte length of a three-byte subInterval.
The strict PER decoder correctly rejected it. Ubuntu's
[run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504)
failed `transport.mcs-erect-request`, with 36 other
CTest commands PASS in Debug. Correct the fixture determinant
to `0x03`; preserve the assertion that the resulting value
is 0x010203 and leave production parsing unchanged.
**PASS:** corrected commit
`6effdb76229e2514511ebe5dd8cb404841403b1b`,
[run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653):
Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
Debug/Release full **37 CTests**, installed SDK consumer and
all three ZIP/checksum uploads. Ubuntu logs explicitly
confirm **37/37 passing** in both configurations.
Owner-local corrected tests and authenticated runtime remain NOT RUN.

## Verified offline MCS server confirmation wire tests (2026-10-14)

Add two separate behavior-named CTests to the existing
`test_owned_mcs_connect_initial` binary and shared
`tests/CMakeLists.txt` registry:
`transport.mcs-attach-confirm-wire` and
`transport.mcs-channel-join-confirm`. Compare full
TPKT/X.224/PER frames byte for byte to Microsoft examples:
Attach User Confirm 11 bytes for UserId 1007; Channel Join
Confirm 15 bytes for UserId 1007 and ChannelId 1003.
Check UserId boundary offsets 1001 and 65536 and the
published rdpdr 1004 variant. Reject all invalid IDs,
wrong incoming request type, foreign initiator, empty,
duplicate/omitted, or oversized approval lists, and
nonsensical auxiliary fields. Confirm these server-directed
packets remain invalid as *client* requests in the existing
parser. Full expected CTests: **39**, previously 37. No
positive test grants OS authorization or sends TLS data.

**PASS:** implementation commit
`4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db` in
[Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
completed Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy, Debug/Release **39 CTests**, installed
downstream SDK consumer and three ZIP/checksum uploads.
Both new independent confirmation-wire cases passed; Ubuntu
logs explicitly show **39/39 PASS** in Debug and Release.
This is protocol syntax verification, NOT authenticated session
admission or real client interoperability.

## Verified offline MCS Disconnect Provider Ultimatum (CI PASS)

Use existing `tests/test_owned_mcs_connect_initial.cpp` and
the single `tests/CMakeLists.txt` registry, with no new binary:
`transport.mcs-disconnect-wire` compares exact nine-byte
Microsoft user-requested and derived provider-initiated
TPKT/X.224/PER packets and recognizes both inbound frames.
`transport.mcs-disconnect-rejections` exhausts all 256
encoder reason values (only 1 and 3 valid), confirms all
four inbound reasons are parsed without being interpreted,
and rejects every truncated TPKT, extra bytes, wrong choice,
nonzero PER padding, invalid declared length and X.224.
Expected portable CTest total **69** (67 before this change);
Linux-only optional GSS builds add their existing cases.
No live SSL write, socket close, privileged session, or real
client proof. **PASS:** implementation
`ed4b0c0a05981f573bc6b8369893f33d1e71549d`,
[CI 38685111404](https://github.com/k1moradi/RDP-server/actions/runs/38685111404):
Linux/GCC **78/78**, macOS/Clang and Windows/MSVC **69/69**,
BOTH Debug and Release. Both new behavior cases, policy,
installed SDK consumer, platform ZIP/SHA256 gates PASS.
**NOT RUN:** owner's local build of the new commit,
real TLS disconnect/close, authenticated client/desktop.

## Offline T.125 client Send Data Request tests (CI NOT RUN)

Reuse `tests/test_owned_mcs_connect_initial.cpp` and the one
`tests/CMakeLists.txt` registry for two behavior-named CTests:
`transport.mcs-send-data-wire` checks the real Microsoft 4.1.16
14-byte header and a SYNTHETIC opaque payload, the exact initiator/
channel/priority/segmentation values, borrowed buffer location,
all priority/segmentation combinations, long-form short length,
and userData boundaries 0, 1, 127, 128, 16383 bytes.
`transport.mcs-send-data-rejections` rejects every truncated
TPKT prefix, inconsistent lengths, malformed PER choice and
padding, incomplete long determinants, fragmented lengths,
out-of-range initiator, invalid X.224 and trailing data.
Test output is syntax only: even a valid channel ID is never
promoted into authorized membership or application admission.

Expected portable CTest count: **71** (previous 69).
Linux GSS-enabled CTest count: **80** (previous 78).
**First exact-head CI FAIL:** implementation
`c1f9e5458132c40b149e8ec5f0e6083addff8715`,
[Actions run 38696231297](https://github.com/k1moradi/RDP-server/actions/runs/38696231297):
Linux Debug **79/80** and macOS Debug **70/71** passed,
with ONLY `transport.mcs-send-data-wire` failing at
`test_owned_mcs_connect_initial.cpp:760`. In the test's
16-case priority/segmentation loop, the `frameDomainPdu(mcs)`
temporary vector was destroyed after the parser returned,
leaving its borrowed `userData` view dangling. Production
length/bounds parsing and the negative test both passed.
Preserve the zero-copy contract; give the test an owned
local `frame` that outlives all view assertions and also
check the view offset.

**PASS:** corrected test lifetime at
`72af29fddc2424fcc7f4edbd579e2b313ef25f48`,
[CI run 38696503496](https://github.com/k1moradi/RDP-server/actions/runs/38696503496):
Linux/GCC **80/80**, macOS/Clang and Windows/MSVC
**71/71** full CTests in BOTH Debug and Release, including
both new SendData cases, installed CMake SDK consumers,
ZIP/SHA256 packages and documentation-policy PASS.
No new executable or test root; owner-local corrected
run, external client and authorized post-auth dispatch
remain NOT RUN.

## Offline server Send Data Indication encoding regressions (2026-10-15; CI NOT RUN)

Add TWO portable CTests using the existing MCS fixture executable
and canonical `tests/CMakeLists.txt`:
`transport.mcs-send-indication-wire` checks independently
specified exact 17-byte TPKT/X.224/0x68/PER frame for synthetic
three-byte opaque content, payload limits 0/1/127/128/16383,
header length determinant transitions, server-only direction,
high UserId and channel offsets, all two-bit priority and
segmentation combinations, output suffix preservation and
overlapping source/output without copies.
`transport.mcs-send-indication-rejections` checks every
out-of-range user ID, channel zero, invalid two-bit values,
userData 16384, and all shorter output capacities; every
failure must leave caller memory unchanged. No socket or
SSL writes, channel join, ticket, OS user or real client.
Expected standard **73** (from 71), Linux GSSAPI **82**
(from 80) CTests. **PASS:** implementation
`8c9fabeb02fce7ede13abfb42631d3b7f35a4fc1`,
[CI 38701524465](https://github.com/k1moradi/RDP-server/actions/runs/38701524465):
Linux/GCC **82/82** and macOS/Clang, Windows/MSVC
**73/73** CTests in BOTH Debug/Release; new tests
pass on all three. SDK installed downstream consumers,
ZIP/SHA-256 package uploads and documentation-policy PASS.
The owner-local new build, real TLS send, GSS/OS admission
and external clients are NOT RUN.

## Verified Linux GSS provider-rejection failure reply regression (2026-10-15, CI PASS)

Reuse the existing `test_owned_preauth_session.cpp` TLS
handshake fixtures and single `tests/CMakeLists.txt` CTest
registry, no new executables or test service. Add one
default, **Linux GSSAPI-only** behavioral CTest
`security.gssapi-failure-reply-denials`:
for v5 and v6 send a valid-looking initial SPNEGO
TSRequest over actual OpenSSL TLS BIOs, but omit
the explicit GSS keytab. Both MUST fail silently,
with wiped reader, CLOSED writer, failed provider,
no bogus errorCode, and no TLS application reply;
caller-constructed v6 DER also MUST be denied.
Reinforce existing GSS negotiation, pending-writer,
certificate substitution and replay tests without
weakening the old assertion contracts.

Add a second `security.gssapi-real-kerberos-tls-failure`
CTest ONLY when
`RDP_SERVER_TEST_REAL_KERBEROS=ON` and the exact,
caller-provided `RDP_TEST_KRB5_SERVICE`,
`RDP_TEST_KRB5_KEYTAB=FILE:/...` and
`RDP_TEST_KRB5_CCACHE=FILE:/...` are configured.
The real MIT provider must process and reject
a syntactically valid but defective SPNEGO token:
v6 queues exactly the independent 15-byte
`STATUS_LOGON_FAILURE` oracle over pinned live
TLS; the terminal write/release forbids reuse.
v5 remains a silent close. Real credentials are
never included in source, default builds or CI,
and this opt-in result is NOT RUN without separate
authorization and credential provisioning.

Standard portable test total remains **77**;
default Linux GSS-enabled now **87** (previous 86).
When opt-in Kerberos is explicitly enabled, two
additional private tests are registered rather than
one. **PASS:** exact implementation
`b4c9f8eff73e701130cc8b92b6c1fda50aedcf11`,
[Actions 38710937644](https://github.com/k1moradi/RDP-server/actions/runs/38710937644):
Linux/GCC **87/87**, macOS/Clang and Windows/MSVC
**77/77** full CTests in both Debug and Release.
Default `security.gssapi-failure-reply-denials`
passes on Linux in both configurations. SDK staged
consumer, ZIP/SHA256 packages, documentation policy PASS.
**NOT RUN:** owner-local new commit CTest, opt-in real
configured Kerberos provider failure/TLS reply, positive
GSS/TLS authentication, OS admission, real RDP client,
service activation or desktop acceptance.

## Verified server Demand Active serialization regressions (CI PASS, 2026-10-15)

Extend the existing `tests/test_owned_mcs_connect_initial.cpp`
executable and the sole `tests/CMakeLists.txt` registry
with TWO portable named CTests:
`transport.share-demand-active-encode-wire` checks a
byte-for-byte canonicalized, specification-derived 38-byte
Demand Active Share Control fixture, including pduSource
1002, source descriptor, counted SHARE/FONT envelopes,
sessionId and output suffix. The earlier parser fixture
deliberately carries nonzero, must-ignore pad2Octets;
the writer's canonical emitted pad MUST be zero, so
normalize only these two bytes in the byte-exact oracle.
Do not change the parser's pad acceptance. Parse its result using the
canonical decoder; test empty capability lists, unknown
opaque capability IDs, and large valid 32767/32769/65535
Share Control lengths. No fabricated packet is claimed
as a real authenticated client capture.
`transport.share-demand-active-encode-rejections`
checks all short output capacities, count mismatch,
truncated/bad-capability envelopes, declared size
overflow, 16-bit source overflow, reserved 0x8000
FlowPDU totalLength, and source/capability aliasing
with the written output; every rejection must leave
the entire caller destination unchanged. This is a
pure serializer with no credential, OS, TLS or
licensed capability activation.

Verified portable **85** full CTests (prior 83),
Linux GSSAPI **95** (prior 93).
**PASS:** corrected commit `ec7261e059e699f23511f9d17d0a77762bf5d337`,
[CI 38716746326](https://github.com/k1moradi/RDP-server/actions/runs/38716746326):
Linux/GCC **95/95**, macOS/Clang and Windows/MSVC
**85/85** CTests in each Debug/Release. Both
new named tests, SDK installed consumer,
ZIP/SHA256 artifacts and documentation policy PASS.
Initial implementation CI 38716458988 FAILED
only the golden-wire padding comparison; writer
correctly emits zero, historical decoder input pad
was nonzero and ignored. Corrected oracle PASS.
**NOT RUN:** owner-local new-build CTest, live
Kerberos/TLS, independent OS admission, licensing,
capability negotiation, desktop or client.

## Verified activation transcript-correlation regressions (CI PASS, 2026-10-15)

Add exactly two portable behavioral CTests to the original
`tests/test_owned_mcs_connect_initial.cpp` executable
and its ONE `tests/CMakeLists.txt` registry:
`transport.share-active-exchange-correlation` checks
server Demand/Confirm source and shareID matching,
round-trip serialized Demand packet, untrusted sessionId,
boundary client channel 65535 and the fact that
opaque/disjoint capability contents are NOT capability
agreement or session authorization.
`transport.share-active-exchange-denials` rejects
every byte-short prefix, coalesced/trailing bytes,
swapped message roles, wrong server/client sources,
bad Confirm originator, mismatched share IDs,
malformed capability-set lengths, FlowPDU marker,
and invalid client IDs 0/1000/65536/UINT32_MAX.
No TLS, OS, socket, console, policy or live session
is activated by either positive syntax result.

Verified portable suite **89** (prior 87),
Linux GSS-enabled **99** (prior 97).
**PASS:** exact implementation
`d83549d489be2b8e49855429693d2c5d4b1a0a71`,
[CI 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636):
Linux/GCC **99/99**, macOS/Clang and Windows/MSVC
**89/89** full Debug/Release CTests. Both new
correlation/denial cases, installed SDK consumer,
ZIP/SHA256 uploads and documentation policy PASS.
**NOT RUN:** owner-local new-head CTest,
positive Kerberos/TLS/pubKeyAuth, independent
OS authorization, live capability negotiation,
licensing and desktop. Matching syntax is never
a security credential or activation evidence.

## Verified Demand/Confirm Active capability-envelope tests (CI PASS, 2026-10-15)

Reuse ONLY `tests/test_owned_mcs_connect_initial.cpp` and the
original `tests/CMakeLists.txt` registry; add exactly two new
portable behavior cases:
`transport.share-active-capabilities-wire` checks independent
synthetic, specification-derived full Demand Active and Confirm
Active Share Control PDUs. Verify LE32 shareID, LE16 Confirm
originatorID=1002, exact source descriptor and capability
borrowed pointers, N=2 envelopes (SHARE 8 bytes and FONT
4 bytes), ignored nonzero pads, the Demand sessionID and
unknown capability type preservation. The 4-byte FONT
length mirrors a Microsoft Server Demand Active compatibility
example but the synthetic PDU is NOT a complete captured
Microsoft production trace. Test also exact empty-list
envelopes and a complete client MCS SendDataRequest wrapping
Confirm Active without manufacturing authorization.
`transport.share-active-capabilities-rejections` checks
ALL byte-short truncations, coalesced packet tails,
wrong Share Control type/version, must-ignore FlowPDU,
wrong Confirm originatorID, impossible source/combined
sizes, missing Demand session ID, cap count mismatch,
capability lengths below 4/oversize, and altered outer
total lengths with malformed nested contents.
No test disables validation to claim progress.

Verified standard total **83** (previous 81),
Linux GSSAPI **93** (previous 91) CTests.
**PASS:** exact implementation `5125fcc68f7e3e9fdd496f8504a17a3a7a251953`,
[CI 38714673332](https://github.com/k1moradi/RDP-server/actions/runs/38714673332):
Linux/GCC **93/93**, macOS/Clang and Windows/MSVC
**83/83** CTests in BOTH Debug/Release. Both new
Demand/Confirm Active tests passed on all OSes.
Documentation policy, installed SDK downstream
consumer and ZIP/SHA256 package uploads PASS.
**NOT RUN:** owner-local new-head CTest, real
capability negotiation, Kerberos/TLS and OS
session authorization, H.264, share activation,
live user input and desktop. Capability envelopes
are syntax, never channel membership or a
substitute for the real security gates.

## Verified server Synchronize and Control output tests (CI PASS, 2026-10-15)

Reuse the original `tests/test_owned_mcs_connect_initial.cpp`
executable and the ONLY `tests/CMakeLists.txt` CTest
registry; add exactly two portable test groups:
`transport.share-server-finalization-encode-wire`
compares independent canonical-padded 22-byte server
Synchronize and 26-byte Cooperate/Granted Control
oracle packets from MS-RDPBCGR 4.1.19-4.1.21,
checks shareID, pduSource, stream 0/2, type2, action,
grant/control IDs, suffix preservation and roundtrip
through the existing Synchronize/Control decoders.
Test edge-case targetUser including the Microsoft
uninitialized 0x4463 example as *untrusted raw syntax*,
and valid client assigned IDs 1001/1007/65535.
`transport.share-server-finalization-encode-rejections`
checks EVERY insufficient destination capacity,
Request Control/Detach/unknown action exclusions,
Cooperate with nonzero client ID, Granted with
invalid 0/1000/65536/out-of-range client ID and
exact destination no-write atomicity on failure.
The canonical zero pad is a new writer decision; it
does not weaken the decoder's acceptance of ignored
nonzero pad fields. No real session, account or network.

Verified portable CTests **87** (was 85) and
Linux GSS-enabled **97** (was 95).
**PASS:** exact implementation `be87f4ba35289d881a161c0d03ac28c592f3a44f`,
[Actions 38718197674](https://github.com/k1moradi/RDP-server/actions/runs/38718197674):
Linux/GCC **97/97**, macOS/Clang and Windows/MSVC
**87/87** full CTests in BOTH Debug and Release,
including both new writer suites. SDK installed
downstream consumer, ZIP/SHA256 artifact packages
and documentation policy PASS.
**NOT RUN:** owner's local CTest on this commit,
genuine Kerberos/TLS or OS authorization, licensed
share activation, external client or desktop.
A syntactically valid Granted Control output is
never a real authorization decision.

## Verified offline T.128 Synchronize/Control finalization tests (CI PASS, 2026-10-15)

Use the existing `tests/test_owned_mcs_connect_initial.cpp`
single executable, Microsoft fixture style and the canonical
`tests/CMakeLists.txt` registry. Four new portable cases:
`transport.share-sync-finalization-wire` validates the full
Microsoft Client Synchronize decrypted 22-byte PDU,
targetUser=1002, share and source IDs, STREAM_UNDEFINED
compatibility, pad1 semantics and a complete MCS nested
handoff with caller-owned backing lifetime.
`transport.share-sync-finalization-rejections` covers
all incomplete prefixes, coalesced/trailing bytes,
wrong inner size/type, invalid messageType, compressed
payload, invalid stream, T.128 FlowPDU and bad version.
`transport.share-control-finalization-wire` validates
Microsoft decrypted Client Cooperate, Request Control,
Server Granted with exact raw IDs and actions, plus
synthetic Detach syntax. It deliberately demonstrates
that a client-shaped Granted action is only syntax,
never permission to grant control.
`transport.share-control-finalization-rejections`
covers all prefix truncations, mismatched and excessive
body sizes, unknown 16-bit actions, compressed payload,
wrong nested type, bad stream/version and ignored FlowPDU.
No new executable, build root, security adapter,
channel scheduler, socket/TLS or desktop owner.

Verified portable suite **81** CTests (previous 77)
and Linux GSSAPI **91** (previous 87).
**PASS:** implementation `c14f47bcd63faaa37761b87ffab06388c1e1bfe7`,
[Actions 38712823857](https://github.com/k1moradi/RDP-server/actions/runs/38712823857):
Linux/GCC **91/91**, macOS/Clang and Windows/MSVC
**81/81** full CTests in EACH Debug and Release,
including all four new finalization wire/rejections
suites. Project docs-policy, SDK installed consumer,
and ZIP/SHA256 packages PASS. Untagged prerelease
publish SKIPPED.
**NOT RUN:** owner-local new code build/CTest,
independently authenticated Kerberos/TLS/OS session,
Share Activation, client interoperability,
DVC/RDPGFX or input. Only fixed-length header
syntax is proven; an arbitrary Granted Control
enum never admits a user.

## Verified offline T.128 Share Data Header tests (CI PASS, 2026-10-15)

Reuse `tests/test_owned_mcs_connect_initial.cpp` and the single
`tests/CMakeLists.txt` registry; add exactly TWO behavior-named
portable CTests to the original MCS executable:
`transport.share-data-header-wire` compares three
independent Microsoft full-26-byte examples (server Granted
Control, client Font List with the documented uninitialized
0xda3b uncompressedLength, server Font Map with nonzero
pad1), all 24 documented type2 values, the special stream-0
Synchronize case, retained metadata and precise borrowed
body offsets through a complete MCS/Share Control handoff.
`transport.share-data-header-rejections` rejects every
truncated prefix, short-but-valid Share Control enclosing
an incomplete Data Header, coalesced extra byte, other
Share Control kind, wrong protocol version, T.128 FlowPDU,
unsupported type2 values, invalid streams, and every
nonzero compression flag/type. A rejection must never
expose a borrowed application payload.

Full portable test count **77** (prior 75), Linux GSS
enabled **86** (prior 84).
**PASS:** implementation `9bc9e041419b4a932dc988a51f1f3e920ac82ba3`,
[CI 38708579033](https://github.com/k1moradi/RDP-server/actions/runs/38708579033):
Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
**77/77** full CTests in both Debug and Release;
both new cases pass across three OSes. Documentation
policy, SDK install/consumer and ZIP/SHA256 uploads PASS.
**NOT RUN:** owner's new local build, sanitizer, actual
decompression, MCS authorization, nested input,
licensing, genuine Kerberos or desktop acceptance.
All results are header syntax only; the buggy
uncompressedLength and ignored pad1 reflect published
Microsoft wire examples, not a trusted byte count.

## Verified offline RDP Share Control Header regression tests (2026-10-15, CI PASS)

Reuse `tests/test_owned_mcs_connect_initial.cpp` and the original
CTest registry, adding exactly TWO portable behavior-named groups:
`transport.share-control-header-wire` compares the complete
published Microsoft 26-byte Granted Control Share PDU oracle,
checking its LE16 length, `0x0017` version/Data discriminator,
source ID and the borrowed 20-byte payload location. It also
checks all five normative Share Control PDU types with zero-byte
test bodies (header-only checks do not validate semantic inner
messages) and deliberate composition with the existing T.125
SendDataRequest decoder while keeping backing TPKT alive.
`transport.share-control-header-rejections` checks every
truncated input, declared-length short/long mismatch, surplus
and coalesced data, wrong 12-bit protocol versions, all unknown
type values, and that `totalLength=0x8000` is ignored WITHOUT
returning a payload view, not dispatched or allocated.

Portable full suite **75** (prior 73), Linux GSS-enabled
suite **84** (prior 82). No new executable, build root,
security adapter or session controller.
**PASS:** implementation `77fd1be92c0f4dcff60962d645a39af9b23c96de`,
[Actions run 38705203733](https://github.com/k1moradi/RDP-server/actions/runs/38705203733):
Linux/GCC **84/84**, macOS/Clang and Windows/MSVC
**75/75** CTests in EACH Debug and Release, including
both new Share Control cases. Staged SDK consumer,
three ZIP/SHA256 uploads and docs-policy PASS.
**NOT RUN:** owner's local new compile, real security-header
stripping, real-client licensing/share activation,
GSS/OS authorization, desktop graphics or input.

## Verified incremental TLS-decrypted CredSSP TSRequest DER framing (2026-10-14)

Keep the existing `test_owned_credssp_tsrequest.cpp` executable
and register its previous five behavior groups separately,
plus three NEW tests in the canonical `tests/CMakeLists.txt`:
`security.credssp-stream-fragments` checks every split and
single-byte callbacks against the existing complete DER
parser and borrowed lifetime; `security.credssp-stream-coalesced`
checks byte-exact no-read-ahead, explicit release, DER 0x81,
0x82 and near-limit 16 KiB examples; and
`security.credssp-stream-rejections` checks wrong tag,
indefinite/nonminimal lengths, declared oversize,
semantic-invalid complete DER, interrupted/closed framing
and illegal replay of an unreleased frame. All five former
groups remain callable individually, giving expected
**46 CTests** (39 prior registered, 3 newly implemented
and 4 extra registrations for existing groups). Ensure
default no-argument invocation still executes all eight
groups. Do not use synthetic SPNEGO tokens as evidence of
Kerberos credentials, TLS binding or desktop admission.

**PASS:** exact implementation
`c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
[CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
passed Linux/GCC, macOS/Clang, Windows/MSVC and
documentation-policy; Debug/Release full CTests,
staged SDK installation, external compiled/linked/ran
consumer, and three platform ZIP/SHA-256 package uploads.
Ubuntu explicitly reports **46/46 PASS** in Debug and Release,
including all three incremental DER-framing cases.
**NOT RUN:** owner-local new build, live TLS NLA,
Kerberos authentication or OS desktop authorization.

**Verified fail-fast negative edge (2026-10-14):**
the same `security.credssp-stream-rejections` case exhaustively
feeds each of the 255 non-SEQUENCE tag bytes as its entire first
event and requires immediate Invalid/InvalidDer, exactly one consumed
byte, erased data, terminal close and refused replay. A lone valid
0x30 tag must remain NeedMore until the DER length arrives.
No new test executable or CTest registration; acceptance remains
offline parser-only. **PASS:** implementation
`36926462d34726f355279367a2ba2f27e93d2095`,
[CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429):
full Linux/GCC, macOS/Clang and Windows/MSVC Debug/Release,
SDK/package and documentation-policy gates. The owner supplied
Linux Debug **67/67 PASS** on this exact commit in the one
reused `~/rdp-server/build/`. This is not real-client authentication.

## Verified offline CredSSP server DER reply validation (2026-10-14)

Reuse the existing `test_owned_credssp_tsrequest` binary and
register two behavior-named CTests:
`security.credssp-server-reply-wire` and
`security.credssp-server-reply-rejections`.
The former compares complete literal MS-CSSP-compliant v6
NegoData and protected-binding reply bytes, checks v5, DER
length thresholds and exact parser/framer roundtrips.
The latter rejects invalid versions, empty payload, unknown
reply variants and a provider token over 8192 bytes.
**PASS:** implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
[Actions run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778)
completed both Debug and Release **48/48 CTests** on
Linux/GCC, macOS/Clang, Windows/MSVC, plus the
documentation-policy gate, staged SDK consumer smoke tests
and all three platform ZIP/SHA-256 uploads. The prior
baseline had 46 CTests.
**NOT RUN:** owner-local updated build, real GSS, TLS binding,
OS authorization or external clients. Wire serialization
alone does not grant an authenticated session.

## Verified Linux GSSAPI provider negative gates (2026-10-14)

Linux CI installs `libkrb5-dev` and sets
`RDP_SERVER_TEST_LINUX_GSSAPI=ON` in the same `build/` root.
The Linux-only `test_linux_gssapi_spnego` executable registers
`security.gssapi-configuration-rejections` and
`security.gssapi-framed-handoff`. It links the actual
MIT GSSAPI acceptor, binding and deny-only credentials
sources, not a mock authentication provider. The first
test rejects an absent explicit absolute keytab, invalid
service identity, relative keytab, and context reuse;
the second tests rejected unconfigured, partial, v4 and
malformed DER frames with terminal cleanup.
**PASS:** implementation `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`,
[CI run 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133)
completed **50/50** Linux/GCC CTests and **48/48**
macOS/Clang, Windows/MSVC CTests in Debug and Release.
SDK consumer, ZIP/checksums and documentation-policy
passed across all platforms. No positive GSS login,
OS admission or listener is implemented.
**NOT RUN:** owner-local build, live keytab/ticket,
TLS channel binding, independently authenticated desktop
or external-client acceptance.

## Verified new CredSSP TLS-read regressions (2026-10-14)

Every new production TLS/framing behavior received new tests
in the preexisting `test_owned_preauth_session` binary,
using the real in-memory OpenSSL TLS fixture:
`transport.credssp-tls-fragments` covers all 20 positive
split points with exact bytes-read accounting and released
buffer lifetime; `transport.credssp-tls-coalesced`
exercises two DER frames in a single encrypted TLS record,
no consumption past the current frame, release and
plaintext-injection denial; `transport.credssp-tls-rejections`
checks null/client/unhandshaken/swapped SSL, source mixing
in both directions, invalid DER and truncated TLS EOF.
**PASS:** code `d2885363502e34e52c71c41342902908b781fd58`,
[Actions 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062):
Debug/Release Linux/GCC **53/53**, macOS/Clang
**51/51**, Windows/MSVC **51/51** CTests and all
three added tests on each. Linux-only GSSAPI provider
regressions remain PASS. SDK consumer, per-OS package
ZIP/checksum uploads and documentation policy PASS.
**NOT RUN:** owner-local tests, real Kerberos/TLS
public-key binding, independently authorized OS session,
Microsoft client or interactive desktop. No release tag.

## Verified new TLS/GSS provenance tests (2026-10-14)

All new C++ code received new, behavior-named regression
coverage without a second TLS certificate fixture. The
preexisting `test_owned_preauth_session` OpenSSL memory-BIO
fixture drives `transport.credssp-tls-provenance` on
all platforms: manual DER has no TLS source, partial
frames have no completed source, the complete frame
carries exactly the live server SSL, and release/close
clears its exposed provenance. The same binary links
the real optional MIT GSSAPI provider on Linux and
registers `security.gssapi-tls-ownership`: both
v5 and v6 fabricated GSS tokens transported over
real TLS, caller-injected DER, and unverified protected
binding fail without credentials, outputs or admission.
**PASS:** exact implementation `6e11b25224e1a5e6c3f45778436afc3950a3e866`,
[Actions 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612)
on Linux/GCC **55/55**, macOS/Clang and Windows/MSVC
**52/52** Debug and Release CTests, installed SDK
consumer, CPack ZIP/SHA-256 artifact uploads for all
three systems and documentation-policy. The earlier
Ubuntu Release `-Wstringop-overflow` warning in
`tests/test_owned_preauth_session.cpp:587` is
preexisting and nonfatal. **NOT RUN:** owner's
local build, positive GSS Kerberos credential/keytab,
TLS pubKeyAuth, OS admission or real clients. Synthetic
negative evidence is not desktop authorization.

## Verified final combined CredSSP handshake tests (2026-10-14)

Three additional CTest groups were registered WITHOUT
removing any existing group. Reuse the existing
`test_owned_credssp_tsrequest` executable for
`security.credssp-final-negotiation-binding`
(positive v5/v6 canonical DER, borrowed token/nonce/
ciphertext, every byte-fragment boundary, oversized
request rejection) and
`security.credssp-final-binding-rejections`
(missing fields, credential/error mixing, nonce
sizes, v2/v4 downgrade, multiple tokens,
oversize pubKeyAuth and malformed DER).
Reuse the existing `test_owned_preauth_session`
memory-BIO TLS fixture for Linux-only
`security.gssapi-final-combined-denials`
with the *real* linked MIT GSSAPI provider,
fabricated final v5/v6 frames over completed TLS,
terminal denial, replay denial and manual/partial
frame rejection. The tests do NOT simulate a
successful authenticated GSS context.
**PASS:** implementation
`ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`,
[Actions 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453):
Linux **58/58**, macOS/Windows **54/54** CTests,
both Debug and Release; the three new cases passed.
All three OS SDK downstream consumers, ZIP/checksum
artifact uploads and documentation-policy PASS.
**NOT RUN:** owner's updated local build, real
Kerberos tickets/keytab, successful GSS pubKeyAuth
exchange, independently authorized OS sessions,
Microsoft client or live desktop. The previously
reported unrelated Ubuntu Release warning at
`tests/test_owned_preauth_session.cpp:587`
remains nonfatal.

## Verified CredSSP TLS reply wire and backpressure regressions (2026-10-14)

Reused the existing `test_owned_preauth_session`
real in-memory OpenSSL TLS fixture and executable.
Three new named CTests pass:
`transport.credssp-tls-reply-wire` tests
canonical v6 negoToken/binding replies with
payload lengths 1/127/128/256/8192, exact
client-decrypted DER bytes, owned provider-output
snapshot, completion idempotence and safe reuse;
`transport.credssp-tls-reply-backpressure`
forces real WANT_WRITE via a 2048-byte BIO created
BEFORE pairing/handshake while sending an
8192-byte opaque output, and verifies stable
SSL retries, exact once-only plaintext delivery
and total byte accounting;
`transport.credssp-tls-reply-rejections`
covers null, unhandshaken and client-role SSL,
unsupported versions, empty/oversized payload,
TLS substitution, duplicate pending reply and
terminal close. No CTest or assertion was removed.

**Initial FAIL:** implementation
`915cd2bfac59d7e775b458b7deed3d94db17ad93`,
[CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856),
attempted to resize an existing BIO pair after
TLS handshake; macOS (and Linux) Debug fixture
setup failed before WANT_WRITE. **PASS:** corrected
fixture at `afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
[CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824):
Linux/GCC **61/61**, macOS/Clang and Windows/MSVC
**57/57** CTests each Debug and Release,
including all three new test groups on all
systems. Downstream SDK install/consumer,
ZIP/SHA-256 package uploads and documentation
policy PASS. Preexisting unrelated Ubuntu
Release test source `-Wstringop-overflow` warning
at `tests/test_owned_preauth_session.cpp:589`
is nonfatal.
**NOT RUN:** owner-local build, positive GSS
Kerberos, TLS binding, independently authorized
OS session or Windows App interactive desktop.

## Verified real-provider CredSSP TLS reply safety tests (2026-10-14)

Three NEW Linux-only security CTests reuse
the original real OpenSSL memory-BIO TLS fixture
with the actual linked MIT GSSAPI target:
`security.gssapi-negotiation-reply-gates`
asserts v5/v6 TLS-derived initial requests,
replay and synthetically injected DER cannot
produce a server GSS `negoTokens` reply
without a configured positive Kerberos context;
`security.gssapi-binding-reply-gates`
asserts that v5/v6 combined final
`negoTokens+pubKeyAuth` frames cannot queue
a server GSS-wrapped binding without actual
provider verification, and manual/partial
DER remains rejected;
`security.gssapi-reply-order-denials`
proves a pending unflushed server TLS reply
blocks another client token and causes
terminal reader/writer/GSS cleanup with NO
client-readable TLS response. The existing
all-platform GSS framing, TLS writer,
credential and binding assertions remain
unaltered.

**PASS:** exact code commit
`27e8342aee0e475c3b0854330678e7c7596fc912`,
[Actions run 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493)
all four required jobs passed:
Linux/GCC **64/64**, macOS/Clang and
Windows/MSVC **57/57** CTests in both
Debug and Release, including all 3
new Linux-only cases; installed SDK
consumer, ZIP/SHA256 artifact upload
and policy PASS.
**NOT RUN:** owner-local tests,
positive service keytab/TGT,
successful GSS confidentiality/TLS
pubKeyAuth, independent OS
user authorization, actual client
or interactive desktop. The
preexisting nonfatal Ubuntu Release
test warning at line 589 remains.

## Verified real-TLS selected certificate binding and pinning tests (2026-10-14)

Three NEW named CTests in the same existing
`test_owned_preauth_session` executable and
ephemeral EC X.509 OpenSSL memory-BIO TLS
fixture exercise the actual selected TLS
certificate, rather than fabricated X509/GSS
identities. `security.credssp-active-tls-binding-positive`
compares both v5/v6 direction-specific
32-byte nonce hash results against
`computeCredSspBindingHash` independently
using the active selected X509
SubjectPublicKey BIT STRING, and confirms
the certificate SHA-256 fingerprint.
`security.credssp-active-tls-binding-rejections`
rejects different live server certificates,
every nonce/hash mutation, reflected
server-to-client hash, null/client-role or
unfinished SSL, malformed nonce/hash lengths,
and checks cleared output on failure.
`transport.credssp-tls-certificate-pinning`
modifies the selected X509 ON THE SAME SSL
after a completed DER frame and during
a partial frame. The TLS provenance must
disappear, reads must reject and wipe
the existing reader; a stable certificate
must remain valid after repeat frame
release. There is no GSS-success assertion
or OS login authorization.

**Initial CI FAIL:** initial
`d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`,
[CI 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326):
test compile attempted to give an OpenSSL 4
`const X509*` to `SSL_use_certificate`
which expects a mutable test-owned `X509*`.
**Corrected implementation:** exact
`340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`,
uses `X509_dup` and existing test-owned
`CertificatePointer` with equivalent
selected SHA-256 fingerprint assertion.
No negative security assertions removed.

**PASS:** [Actions 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190):
Linux/GCC **67/67**, macOS/Clang and
Windows/MSVC **60/60** CTests, each
Debug+Release, all 3 new groups PASS,
SDK downstream consumer, ZIP/SHA256 package
uploads and documentation-policy PASS.
The preexisting unrelated Linux Release
test compiler warning remains nonfatal.
**NOT RUN:** owner's local new build,
actual positive keytab/Kerberos ticket
and confidential GSS TLS pubKeyAuth,
independently authorized OS session,
real Microsoft client or desktop.

## Verified Linux TLS-framed GSS binding-only regressions (2026-10-14)

Two new Linux-only real OpenSSL memory-BIO
TLS and linked MIT GSSAPI behavior CTests
reuse the existing `test_owned_preauth_session`
executable:
`security.gssapi-framed-binding-only-denials`
delivers a syntactically valid binding-only
v5/v6 DER message through TLS, confirms
the pinned SSL provenance, then requires
denial without a real verified GSS context.
Legacy raw caller DER, manually consumed
DER, incomplete DER and replay fail
terminally, wiping buffered ciphertext.
`security.gssapi-framed-binding-reply-order`
checks that neither unverified TLS binding
nor a preexisting unflushed server reply
can produce a server application record,
and GSS, framed TLS reader and guarded
reply writer all close on rejection.
The combined-final client token+binding
positive syntax and negative GSS tests,
plus all previous portable SDK suites
remain unchanged.

**PASS:** exact implementation
`340b25d2352314003053ec19d467b75d578c9dbf`,
[Actions 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568),
Linux/GCC **69/69** and macOS/Clang,
Windows/MSVC **60/60** full CTests in BOTH
Debug and Release; both new Linux
security tests passed. Installed SDK
consumer, all 3 ZIP/SHA-256 artifact
uploads and documentation policy PASS.
Prior unrelated nonfatal Ubuntu Release
test warning near `test_owned_preauth_session.cpp:590`
remains. **NOT RUN:** owner's local build,
real positive Kerberos with ticket/keytab,
successful GSS-protected public-key proof,
independently authorized OS identity,
external client or interactive desktop.

## Verified outgoing CredSSP TLS certificate substitution (2026-10-14)

Three NEW all-platform behavior-named CTests
in the existing `tests/test_owned_preauth_session.cpp`
use real OpenSSL memory-BIO server and
client handshakes. The same SSL object
is reconfigured with a certificate
duplicated via RAII `X509_dup` from
an independent completed TLS fixture;
assert that the replacement has
the expected selected SHA-256 fingerprint.
`transport.credssp-tls-reply-cert-pending`
queues v5/v6 `negoTokens` or protected
`pubKeyAuth` and requires failure,
no plaintext transmitted, secure
wipe and no reuse if selected X.509
changes before the first write.
`transport.credssp-tls-reply-cert-completion`
requires terminal mismatch detection
after Complete (both release and
idempotent write paths) or following
release before next queue, and checks
unchanged-certificate multiple replies
still succeed. It does NOT pretend
an already sent TLS reply can be
retracted after certificate change.
`transport.credssp-tls-reply-cert-backpressure`
creates the server BIO with 2048-byte
capacity BEFORE pairing, forces REAL
WANT_WRITE while sending an 8192-byte
canonical server response, changes
the certificate ON THE SAME SSL pointer,
and checks no further TLS write retries
and terminal cleanse. No assertions
were disabled or weakened.

**PASS:** implementation
`53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`,
[Actions 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102):
Linux/GCC **72/72** CTests in BOTH
Debug and Release, macOS/Clang and
Windows/MSVC **63/63** each Debug
and Release, all 3 new cases PASS.
SDK installed downstream consumers,
ZIP/SHA256 packaging and uploads,
and documentation-policy PASS.
Existing unrelated Ubuntu Release
test warning at `tests/test_owned_preauth_session.cpp:590`
remains nonfatal. No prerelease tag.
**NOT RUN:** owner's local build,
positive real Kerberos tickets/keytab
and confirmed GSS/TLS public-key proof,
OS authorization, external RDP client
or interactive desktop.

## Verified optional Linux real GSS probe compilation (2026-10-14)

The original Linux MIT GSS linked
`test_owned_preauth_session` executable
now COMPILES an opt-in
`security.gssapi-real-kerberos-tls-mechanism`
test using `gss_acquire_cred_from` with
an explicitly specified external FILE:
client cache and the production acceptor's
independent `FILE:` service keytab.
Only with
`RDP_SERVER_TEST_LINUX_GSSAPI=ON` AND
`RDP_SERVER_TEST_REAL_KERBEROS=ON`
on Linux does CMake register this CTest;
configuration fails for missing
`RDP_TEST_KRB5_SERVICE=TERMSRV/host@REALM`,
`RDP_TEST_KRB5_KEYTAB=FILE:/absolute/path`,
or `RDP_TEST_KRB5_CCACHE=FILE:/absolute/path`.
No daemon, KDC or test ticket is created
by the repository. Only an explicitly
authorized external isolated test
realm may provision these values.
The test uses real MIT GSS
`gss_init_sec_context` and the original
provider `gss_accept_sec_context`
on OpenSSL TLS for versions 5 and 6,
then a REAL GSS-confidential
binding-only TLS client/server proof,
and rejects a genuine context if a
new TLS frame reader sees a swapped
certificate on the same SSL object.
This is a diagnostic binding-only
provider test, not a real Microsoft
combined-final client/OS acceptance test.

**PASS:** implementation
`1f6740452f27332303ded71d4f5f23bb599b9726`,
[Actions 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820):
normal Linux 72/72 and macOS/Windows
63/63 full CTests, BOTH Debug and Release,
installed SDK consumer/ZIP+SHA256/policy.
The optional code COMPILED with MIT GSSAPI
on Linux, but **NOT RUN:** the positive
case itself (no external keytab/cache
provisioned), controlled GSS positive
binding, OS session authorization,
Microsoft Windows App or actual desktop.
The existing unrelated Ubuntu Release
fixture warning remains nonfatal.

## Verified canonical v6 CredSSP failure DER/TLS replies (2026-10-14)

FOUR portable behavior-named CTests
reuse the original two test binaries
and ONE `tests/CMakeLists.txt`
registration, without new state
controllers or fake authentication:
`security.credssp-server-failure-wire`
checks independent canonical 15-byte
MS-CSSP DER for negative signed
32-bit NTSTATUS 0xC000006D and
0xC00000BB, exactly [0] and [4],
parse and frame roundtrip; never
`authInfo`, `pubKeyAuth`,
`negoTokens` or clientNonce.
`security.credssp-server-failure-rejections`
checks versions other than 6,
unknown failure enums, nonminimal
signed DER integers and invalid
normal-reply field selection.
`transport.credssp-tls-failure-reply-wire`
uses the original real TLS OpenSSL
memory BIO fixture to deliver both
error frames and to prove release
permanently closes the writer.
A previously released normal
negotiation reply may be followed
by a failure on the SAME SSL/cert,
but not vice versa.
`transport.credssp-tls-failure-reply-rejections`
checks null/unhandshaken/client-role
TLS, invalid versions/statuses,
pending reply conflict and a
different selected X.509 on the
SAME SSL, with no plaintext
delivered after that mutation.

**PASS:** implementation
`6925ac11a49b3d71a6ffa120b688ca95a0a088af`,
[Actions 38683205424](https://github.com/k1moradi/RDP-server/actions/runs/38683205424):
Linux/GCC **76/76** CTests, macOS/Clang
and Windows/MSVC **67/67** CTests
EACH Debug and Release; every new
case passed on all three platforms.
Installed downstream SDK consumer,
three ZIP+SHA256 uploads and
documentation-policy PASS. Existing
nonfatal Ubuntu Release fixture
warning at `tests/test_owned_preauth_session.cpp:594`
persists. Prerelease publication
SKIPPED because no release tag.
**NOT RUN:** owner-local persistent
build, controlled genuine Kerberos/
GSS positive keytab/client tickets,
production GSS failure dispatch,
external Microsoft RDP client,
OS authorization or desktop.

## Offline finalization six-PDU correlations (2026-10-15; CI PASS)

Reuse original `test_owned_mcs_connect_initial`, adding
`transport.share-finalization-exchange-correlation` and
`transport.share-finalization-exchange-denials`
in the canonical tests/CMakeLists.txt. Expected 91 portable /
101 Linux GSS-enabled CTests (prior verified 89/99).
Microsoft 4.1.14-16 decrypted client PDUs and existing
first-party server serializers form positive oracle inputs.
Check each of six truncation boundaries, a trailing byte,
role/source spoof, mismatched share ID, Control action,
zero/assigned IDs and compressed-data rejection. Preserve
raw Server Synchronize targetUser. No test proves the
actual arrival ordering, authorized Kerberos/TLS, OS admission,
licensing, share activation, graphics or running server.
New-head CI and owner-local build are NOT RUN at authoring.

**Exact implementation CI PASS (2026-10-15):**
`27996f24e5fbb497c0bee37756d34551d1a47e47`,
[Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873).
Linux/GCC **101/101** CTests and macOS/Clang,
Windows/MSVC **91/91** CTests in BOTH Debug and Release,
including the new finalization correlation/denial cases.
SDK consumer/install, ZIP/SHA256 uploads and documentation
policy also PASS; prerelease publishing SKIPPED (no tag).
Owner-local compile, real GSS/TLS positive Kerberos binding,
independent OS authorization and client/desktop remain
**NOT RUN**.

## Preauth TLS selected-certificate continuity tests (2026-10-15)

Add two behavior-named portable CTests to the original
`test_owned_preauth_session` executable:
`transport.mcs-tls-selected-certificate-continuity` and
`transport.mcs-tls-selected-certificate-substitution`.
Use the existing genuinely completed local-only OpenSSL
server/client memory BIO pair, already-checked 416-byte
Microsoft MCS/GCC fixture and selected-X.509 replacement
fixture (no live external listener). Verify successful
WANT_READ -> partial TPKT -> completed frame without
replacement, and zero newly consumed bytes with terminal
close when the SAME SSL pointer's certificate changes
either before the first MCS read or between callbacks.
Do not invent a successful authenticated identity.
Expected default 93 portable CTests, Linux GSS-enabled
103, up from the verified 91/101. Cross-platform new-head
CI and owner-local single build-root tests are NOT RUN
at authoring; preserve all existing assertions and tests.

## New test helper namespace visibility regression (2026-10-15)

**FAIL:** `5b1c9790b772923a4a4437d4f4bef4ec7f404d88`,
[CI 38738637457](https://github.com/k1moradi/RDP-server/actions/runs/38738637457)
failed Linux/macOS/Windows Debug test compilation:
a forward declaration in an anonymous namespace accidentally
created a different `substituteCredSspReplyCertificate` from
the existing file-scope definition, making existing tests
ambiguous. No production source failure or runtime failure
was proved; Release and full CTest were NOT RUN.

**Correction pending new CI:** place the new tests after the
existing helper's definition, preserving one function, all
original test assertions, and the two new regression groups.
Do not move or rename the shared helper, weaken warnings,
or hide CTests. Expected 93 portable / 103 Linux GSS.

**PASS:** corrected test-only commit
`850a6e9b7f2bc0a25854d31e02d0ed25332989b3`,
[Actions 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048):
Linux/GCC **103/103**, macOS/Clang and Windows/MSVC
**93/93** full CTests, in BOTH Debug and Release.
Both selected-certificate MCS tests passed everywhere;
SDK installed consumers, ZIP/SHA256 packages and
documentation-policy PASS. An untagged release
was SKIPPED. **NOT RUN:** owner-local current-head
build, positive real Kerberos/TLS binding, OS
authorization or external clients/desktop.

## Offline General Capability Set parsing tests (2026-10-15)

Add `transport.share-general-capability-wire` and
`transport.share-general-capability-rejections` in the
original `test_owned_mcs_connect_initial` binary and its
sole CTest registry. Microsoft published 24-byte General
capability and 8-byte Share capability form byte-exact
fixtures. Validate both an encoded server Demand and
independently assembled client Confirm; check raw extraFlags
0x041d, OS/platform fields, ignored nonzero pad,
unknown sibling/extra bits and read-only parser behavior.
Reject all truncated/trailing complete-PDU sizes, missing
General, type-1 wrong length, duplicate General, wrong
0x0200 version and invalid Boolean support. Every
synthetic test is OFFLINE syntax, not true client feature
agreement. Expected 95 portable and 105 Linux GSS
CTest registrations, compared with verified 93/103.
Exact-head CI, owner local build, real Kerberos and
desktop acceptance are NOT RUN at authoring.

**Exact-head CI PASS (2026-10-15):**
`3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
[Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505).
Linux/GCC **105/105** and macOS/Clang, Windows/MSVC
**95/95** CTests passed in BOTH Debug and Release,
including both new General capability cases. Installed
SDK consumer, ZIP/SHA256 package uploads and policy
PASS; no version tag, so prerelease SKIPPED.
**NOT RUN:** owner-local new-head build, genuine GSS/TLS
positive proof, independent OS authority, Microsoft
client or graphics/desktop.

## Offline Bitmap Capability Set regression suite (2026-10-15)

Use the existing `test_owned_mcs_connect_initial`
binary with two new behavioral CTests:
`transport.share-bitmap-capability-wire` and
`transport.share-bitmap-capability-rejections`.
Fixture is Microsoft's published 28-byte Bitmap
Capability Set from the Server Demand Active example,
not an independently authenticated captured client.
Test full server Demand encoder/decoder and independent
client Confirm PDU, normal and unknown sibling sets,
ignored nonzero padding and legacy receive flags,
unrecognized drawing flags, every truncated prefix,
trailing bytes, duplicate/absent/wrong-length Bitmap
envelopes, zero dimensions, invalid 0/1 resize,
required compression and multiple rectangle fields.
Expected **97 portable / 107 Linux GSS-enabled**
CTests up from verified 95/105; do not weaken any
existing parser or test assertion. New-head CI and
owner local build/CTest NOT RUN at authoring.
Neither result activates a share or graphics.

**Exact implementation CI PASS (2026-10-15):**
`89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
[GitHub Actions 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146).
Linux/GCC **107/107** and macOS/Clang,
Windows/MSVC **97/97** full CTests each in BOTH
Debug and Release. New
`transport.share-bitmap-capability-wire`
and `transport.share-bitmap-capability-rejections`
PASSED on each system; documentation-policy,
installed SDK consumer, ZIP/SHA256 packaging/upload
PASSED. Untagged prerelease SKIPPED.
**NOT RUN:** owner-local single-build-root compile,
real GSS/Kerberos/TLS binding, independently approved
OS session, licensed capabilities, graphics or desktop.

## Connected TCP/TLS/MCS owner regression cases (2026-10-15)

Reuse `test_owned_preauth_session` and the only
`tests/CMakeLists.txt` registry: add
`transport.tcp-attached-tls-ownership-denials`
and `transport.tcp-attached-mcs-order-denials`.
Require attachment only AFTER X.224 Confirm is fully
written, refuse absent/duplicate attachment, wrong
`SSL*`, mutated BIO data pointer or replaced BIO
and MCS intake before TLS establishment; failed
instances remain terminal. Change the EXISTING
`transport.tcp-native-loopback-tls` to drive
`onAttachedTlsIoReady` and `onAttachedMcsIoReady`
over real first-party native nonblocking sockets
and OpenSSL TLS records. Assert consumed plaintext
bytes == exact Microsoft 416-byte MCS/GCC frame.
No fake GSS success, OS authorization or share admission.
Expected **99 portable / 109 Linux GSS** CTests
(previous verified 97/107). Owner-local new-root
CTest and CI new SHA NOT RUN at authoring.

**Exact implementation CI PASS (2026-10-15):**
`45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
[Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803).
Linux/GCC **109/109**, macOS/Clang and
Windows/MSVC **99/99** full CTests each in BOTH
Debug and Release, including the strict connected
TLS ownership/MCS ordering denial cases and
the actual native loopback transport. Documentation
policy, installed SDK downstream consumers, ZIP/SHA256
package uploads PASS. Prerelease SKIPPED (no tag).
**NOT RUN:** owner-local exact-head CTest, real GSS/
CredSSP/TLS binding, independent OS authority,
live authenticated Microsoft RDP client and desktop.

## R1 bounded real socket and borrowed BIO I/O regressions (2026-10-15)

Add two dedicated cases in the EXISTING
`test_owned_preauth_session` test executable
and the single `tests/CMakeLists.txt` registry:
`transport.tcp-bio-chunk-bounds` proves actual
OpenSSL BIO read_ex/write_ex callback progress
is limited to at most 18 KiB per invocation,
preserves all bytes over two full chunks and a
tail, handles WANT_READ/WRITE appropriately
without accidental retry on fake >capped-length
callback reports; `transport.tcp-native-chunk-bounds`
uses real loopback TCP sockets with 2+ chunks,
native would-block handling and entire-payload
byte parity, asserting no send/receive exceeds
the same maximum. Real Linux/macOS/Windows
socket tests are diagnostics, NOT remote-client
authorization or desktop acceptance.
Expected 101 portable / 111 Linux GSS CTests
from previous 99/109. New SHA CI and owner local
new-code builds NOT RUN at authoring. Independently
required MSYS2 CLANG64/Clang23 and macOS27 owner
verification stays NOT RUN until corresponding
actual platform logs are available.

**Exact-code acceptance (2026-10-15):**
`8ce08611d5d7b093c9d69f4b7eee5d23cd096359`
passed [GitHub Actions 38752789202](https://github.com/k1moradi/RDP-server/actions/runs/38752789202):
Linux/GCC **111/111**, macOS/Clang and Windows/MSVC
**101/101** registered CTests in EACH Debug and
Release, including BIO and real loopback chunk-bound
cases. Project documentation policy, installed
SDK downstream consumer, ZIP/SHA256 artifacts
and package uploads PASS. Prerelease publishing
SKIPPED (no version tag). Owner-local current-head,
MSYS2 CLANG64 Clang23, macOS27, real GSS/CredSSP
and OS account authorization, Microsoft client and
desktop remain **NOT RUN**.

## R1 native accepted-socket ownership and EOF regressions (2026-10-15)

The dedicated `transport.tcp-native-accept-ownership` CTest
reuses the existing IPv4 loopback fixture and test executable. Verify a
nonblocking accepted descriptor, non-inheritable flag on POSIX,
would-block after draining all pending accepts, invalid listener
denial, exact X.224 Confirm through existing `PreauthTcpAdapter`,
move-only ownership and idempotent close. Platform-specific native
settings are tested only where available. A second dedicated CTest,
`transport.tcp-native-accept-move-replacement`, verifies replaced-handle
closure, two unaffected listeners, alias self-move, use of the moved socket
and idempotent close. The third `transport.tcp-native-accept-orderly-eof`
CTest covers queued bytes before peer FIN, explicit EOF, cancel and listener
ownership separation. No external client, certificate enrollment, R2
admission, or R3 activation is exercised. Expected registry on this code snapshot:
104 portable / 114 Linux GSS.

## R1 owned TCP/TLS readiness and cancellation (2026-10-15)

Dedicated portable CTests `transport.tcp-owned-connection-tls-lifecycle`
and `transport.tcp-owned-connection-cancellation` use the existing
preauthentication executable and real loopback sockets. The first
tests exact X.224 reply before TLS, pinned server SSL/BIO, completed
TLS, first encrypted MCS/GCC diagnostic and terminal closure. The
second tests missing socket, partial X.224, cancellation after server
SSL attachment but before ClientHello, inert callbacks and listener
preservation. No external client, live authorization or desktop.

## R1 interest-gated readiness and expiration CTests (2026-10-15)

New dedicated portable CTests `transport.tcp-owned-readiness-dispatch`
and `transport.tcp-owned-deadline-cancellation` reuse the sole preauth
fixture/executable. The first drives a real accepted loopback socket,
fragmented X.224 request, wrong-direction events, exact Confirm, one
server SSL/BIO and TLS handshake, encrypted MCS termination, negative
failure reply and closed callbacks. The second supplies deterministic
monotonic timestamps for a partially received X.224 request and an
attached-but-incomplete TLS handshake, validating cleanup and listener
preservation without waiting on a real timer. A green offline case
does not assert R2 credentials, R3 channel admission or desktop access.

**R1 bounded native poll CTests:**
`transport.tcp-owned-bounded-poll-loopback-tls` exercises actual
POSIX poll/WSAPoll on the accepted loopback owner from split X.224
request through exact response, one SSL/BIO handshake and encrypted
first diagnostic MCS packet. `transport.tcp-owned-bounded-poll-timeout-eof`
checks idle zero wait, bounded overly-large wait, deterministic past
deadline, stale poll denial, and peer EOF during partial negotiation.
Both live in the existing preauth executable and are registered in
`tests/CMakeLists.txt`; no service, user login or OS desktop is used.
A further dedicated `transport.tcp-owned-reply-interest-priority`
regression asserts that successful X.224 Confirm and rejected
NEG_FAILURE remain scheduled for full bounded write *after* parsing
has advanced the underlying stage, and never become premature TLS.

## R1 bounded accept batch / native handoff CTests (2026-10-15)

`transport.tcp-native-accept-batch-budget-handoff` and
`transport.tcp-native-accept-batch-stops-denials` are separately
registered in the one existing preauth executable/CMake registry.
Use only real ephemeral IPv4 loopback clients and borrowed
nonblocking listener handles: exercise three sequential incoming
connections with budget-one/two (next client connects only after
prior accepted socket), exact X.224 Confirm under the sole
`OwnedPreauthTcpConnection`, no accidental listener close,
empty-backlog would-block, the difference between exhausted and
drained, invalid/null callback, zero/oversized budget,
non-listening sockets, callback stop and accepted-handle RAII
closure. No live desktop, server, credentials or external client.

## R1 native accept-batch watchdog (2026-10-15)

Both real-loopback accepted-socket batch CTests register a 20-second
CTest TIMEOUT in the existing central list. The limit is a test
diagnostic for platform-dependent socket/listen backlog stalls,
NOT a production timeout or a relaxation of any assertion. Do not
declare an incomplete/hung Windows job PASS or FAIL without its logs.

## R1 listener readiness/deadline CTests (2026-10-15)

`transport.tcp-listener-poll-budget-handoff` and
`transport.tcp-listener-poll-deadline-denials` register in the
existing preauth test executable and central CTest list, each
with a 20-second watchdog. The former drives native read-ready
accept handoff on an ephemeral loopback listener into the sole
`OwnedPreauthTcpConnection`, verifies exact X.224 Confirm and
idle/drained outcomes, and never assumes a backlog depth beyond
one. The latter checks invalid budgets/socket/callback, an
expired deadline while a real connection remains pending,
callback-stop RAII closure, 25ms wait clamp, and a closed
borrowed listener's error. All tests are offline and require
no service, OS session, desktop or credentials.


## Native security sanitizer gate (R9; verified 2026-10-15)

Maintain the single Linux-only `r9-security-protocol-sanitizers`
CI job alongside the ordinary cross-platform Debug/Release
matrix. Verified by [Actions 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646)
on Clang 18.1.3 with **15 clipboard + 10 MCS/CredSSP
CTests PASS**. Configure first-party C++23 Debug code in
that job's single `build/` using `-fsanitize=address,undefined`,
`-fno-omit-frame-pointer` and fail-on-UB. Run the
clipboard CTest label and separately the centrally
registered bounded MCS/DER/binding cases; keep
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
Any real sanitizer finding fails CI; retain the first
stack trace and route production defects to its owner.
Within the one sanitizer job, bounded owner groups after the shared compile
must still execute when an earlier CTest group fails. Gate those later steps
with `always()` plus a successful shared-compile outcome: this preserves the
job failure while preventing one road from suppressing sanitizer evidence for
another. A failed compile must still skip dependent CTest groups rather than
manufacturing missing-executable failures.
No live client, credentials, other build roots or
special requirements for the owner's standard command.
When generating YAML from JavaScript, avoid a string
replacement whose literal contents include a CTest
regex dollar-sign immediately followed by an apostrophe:
`String.replace` can expand this as the remainder of
the source, duplicating GitHub Actions jobs. Check every
top-level job definition for uniqueness, then verify
GitHub actually schedules the new job before PASS claims.

## R1 POSIX listener readiness before nonblocking acceptance assertion (2026-10-15)

A successful loopback TCP connect does not guarantee that a subsequent
nonblocking `accept4` can consume it immediately. For the existing
`transport.tcp-native-accept-batch-stops-denials` test, wait boundedly
for the original listener to be readable via
`pollNonblockingTcpAcceptBatch` (128 attempts, 25ms maximum each)
before asserting the *same* callback count, one accepted descriptor,
`Drained` outcome and listener preservation. Do not change
production socket behavior or weaken rejection/RAII assertions. Owner-level
loopback fixtures that are not specifically testing the one-step
`WouldBlock` result must use the shared bounded accept fixture rather than
assuming a completed `connect()` is immediately observable by `accept`.

## R1 native listener role/mode denial CTest (2026-10-15)

`transport.tcp-native-listener-role-and-mode-denials` runs
under the existing preauth executable/central registry with a
20-second timeout. A real connected but non-listening loopback
socket is rejected by one-shot, batch and listener-poll APIs
on all hosts. POSIX additionally sets a genuine listening
descriptor to blocking, checks three fail-closed denials without
consuming the queued peer or modifying flags, restores its
original nonblocking mode, then proves exactly one successful
handoff to the existing sole preauth owner. No live service,
credentials, OS authorization or desktop.

## R1 native wrong-socket-type denials (2026-10-15)

`transport.tcp-native-wrong-socket-type-denials` uses a nonblocking
UDP socket and one real queued TCP peer to verify failure without
callback from one-shot, batch and borrowed listener poll, followed
by bounded successful handoff of the original TCP peer. This covers
the Darwin SO_TYPE fallback and all Windows/Linux role checks.

## Bounded coverage-guided protocol fuzzing (R9; opt-in)

`RDP_SERVER_BUILD_FUZZERS=ON` is limited to Linux/Clang sanitizer
CI or an explicitly requested compatible developer run and is OFF
for the owner's normal command. Fuzz targets stay in the sole
`tests/CMakeLists.txt`, link production code, use checked-in
reproducible seeds and write mutable corpus/artifacts only below
the one `build/` root. Fix seed, finite run count, input/resource
bounds and CTest timeout. Treat libFuzzer/ASan/UBSan crashes as
FAIL and preserve the reproducer. A bounded fuzz PASS is sampling,
not exhaustive security proof or real-client admission.


## R1 cross-road write-slice compatibility

When a higher-layer R3 writer is expected to feed R1's bounded TLS
application writer directly, keep one production-backed compatibility CTest
that proves the maximum R3 slice fits R1's public byte ceiling and that
receipt semantics survive actual OpenSSL short progress and WANT results.
Such a test must not fabricate R2 authorization: it proves only byte/receipt
compatibility. On zero-byte WANT, retain the same higher-layer receipt and
borrowed span; rotate a receipt only after positive accepted bytes. Use the
real loopback TLS owner and keep all retries explicit in the test fixture.


## R4 x264/BGRA sanitizer selection (2026-10-16)

The one Linux/Clang sanitizer job must compile both existing R4 graphics test
executables, `test_x264_avc420_encoder` and
`test_x264_avc420_segmented_frame_producer`, then run the complete
`x264` CTest label as its own failure-isolated group. The label currently
contains 20 production-backed cases covering the pinned x264 encoder,
NV12 validation/reference continuity, BGRA-to-NV12 conversion, segmented
RDP8 publication, ACK/backpressure, zero-valued wire identifiers and fixed-CFR
PTS behavior.

Configure **both** C and C++ with Clang and the same
`-fsanitize=address,undefined -fno-omit-frame-pointer
-fno-sanitize-recover=all` flags. All repository C translation units are the
vendored x264 library, so setting the sanitizer C compiler/flags is what makes
this a real codec-instrumented run rather than merely a sanitized C++ wrapper
calling uninstrumented C. Keep leak detection and halt-on-error enabled, do
not suppress x264 findings, and keep this group behind the shared compile
success with `always()` so failures do not hide later road evidence. This
does not change the owner's ordinary build command or create another build
root.


## R4 RDPGFX highest-supported capability selection (2026-10-16)

Capability-negotiation tests must distinguish the **highest advertised**
RDPGFX capability version from the **highest capability set the server
actually supports**. Per MS-RDPEGFX 3.2.5.19, CAPS_CONFIRM selects the latter.
While R4 implements only Version 8.1 AVC420, tests must place newer published
capability sets before and after a valid Version 8.1 set and require the exact
Version 8.1 confirmation. Advertisements containing only unsupported newer or
unknown sets must yield no confirmation. Do not infer support from a larger
version number or from similarly named H.264 flags.


## Protocol scalar domains are not local sentinels (R4, 2026-10-16)

Do not reject a protocol integer solely because its value is zero when the
normative wire definition does not reserve zero. Keep local object validity
separate from peer-visible scalar domains. For RDPGFX logical frames,
`frameId` is the full 32-bit unsigned wire value; the R4 lifecycle's
nonzero receipt serial and stage/generation state identify a live delivery.
Tests must cover protocol boundary values through the complete production path,
including duplicate/backpressure handling, rather than relying only on a
serializer unit check.


## R4 RDPGFX identifier-domain coverage (2026-10-16)

Do not infer sentinel semantics from zero-valued RDPGFX scalar identifiers.
Tests must cover the complete wire domains actually permitted by MS-RDPEGFX.
START/END_FRAME `frameId` spans uint32 including zero, and surface-management
/ WIRE_TO_SURFACE `surfaceId` spans uint16 including zero. Lifecycle validity
must be asserted through explicit stage/generation/receipt state rather than by
treating a legal wire identifier as an implicit "unset" value. Keep
duplicate-ID and stale-generation tests independent from scalar-domain tests.


### R4 capability negotiation sanitizer selection (2026-10-16)

The shared Linux/Clang sanitizer job must also build
`test_gfx_avc420_capabilities` and execute the complete
`^graphics\.avc420-capabilities-` CTest family as its own
failure-isolated R4 group. This directly instruments the production
CAPS_ADVERTISE parser / CAPS_CONFIRM serializer for supported selection,
highest-supported selection, malformed/unsupported rejection and
variable-length header bounds. The job must assert that
`graphics.avc420-capabilities-highest-supported-selection` is present in the
selected central registry before execution so a missing registration cannot be
mistaken for sanitizer PASS.

Keep this portable wire group separate from the x264 label: it has no codec
dependency and does not prove an authenticated Graphics DVC, live client
negotiation or R3 admission. As with other shared sanitizer groups, later
roads must still run under `always() && compile-success` if this R4 group
fails.


## R7 native macOS geometry refresh requires notification coverage (2026-10-16)

Ordinary tests must not register the real CoreGraphics display-reconfiguration
callback or enumerate live display state. The Apple-only denial regression may
call `NativeDisplayGeometryRefresh::refreshNative()` only while native coverage
is known inactive; production must reject with
`TopologyCoverageUnavailable` before any CoreGraphics enumeration. The test
should first install a synthetic geometry epoch and verify the denied native
refresh still invalidates that old epoch. Positive native coverage and real
display-change delivery remain owner-macOS acceptance, not hosted CTest.


### R4 portable RDPGFX sanitizer selection (2026-10-16)

The shared Linux/Clang ASan+UBSan job must build and execute the complete
portable R4 wire/lifecycle boundary independently from codec and capability
groups. The bounded selection contains **33** existing production-backed CTests
from exactly these executables: `test_gfx_surface_lifecycle`,
`test_gfx_frame_acknowledge`, `test_gfx_presentation_lifecycle`,
`test_gfx_avc420_picture`, `test_gfx_segmented_data`, and
`test_gfx_avc420_segmented_frame`.

The sanitizer selector must enumerate the central CTest registry before
execution and assert one representative behavior from every family is present:
zero-valued surface IDs, stale-generation ACK handling, terminal frame-delivery
abort, zero-valued frame IDs, segmented-data denial/in-place safety, and
segmented AVC420 delivery/ACK. Keep this group separate from the existing
4-case capability selector and 20-case x264/BGRA label so failures remain
attributable and one R4 group cannot hide later road evidence. No native X11,
Windows or macOS graphics test belongs in this portable selection.


## R4 FRAME_ACKNOWLEDGE backlog observation (2026-10-16)

Scheduler-facing RDPGFX backpressure tests must preserve three distinct
`queueDepth` states: positive finite values are available buffered-byte
counts, zero means depth unavailable while ACKs continue, and `0xFFFFFFFF`
suspends ACK expectation and clears outstanding-frame waiting. Malformed or
stale-generation ACKs must not mutate these observations. Test the
lifecycle-facing observation boundary as well as the parser so later
scheduling code cannot reinterpret zero as an empty queue or bytes as frames.
