## R7 real Linux HostControl Qt denial and stale listener projection (2026-10-19)

Parent main `eddf7064d7d1311616c71268bfa3dbfb86040a9c`: Linux Qt startup now constructs R10's
`LinuxRuntimeHostControl`, but R2 per-session owner consent and lock/revocation
authority and R1 TLS fingerprint/trust are absent. R7 now denies a positive
listener-readiness projection on terminal `HostSessionStale` or `AccessRevoked`
even if an old R10 snapshot still reports `listenerAvailable`. The raw
R10 stage continues to require explicit Stop/close until retirement.

New ordinary Qt offscreen tests:
`gui.offscreen-terminal-listener-readiness-denials` (all GUI platforms) and
`gui.offscreen-linux-concrete-host-control-denials` (actual production Linux
controller through Qt). They verify no invented consent, TLS, listener or
clients, and explicit Stop/Revoke without live desktop or network bind.
Source structure review PASS; native Qt/full CTest NOT RUN in this GitHub-only
workspace; exact publication-SHA hosted CI PENDING. Positive R10 LAN Start,
genuine R2 lock/consent, R1 fingerprint, PR #23 default GUI/headless fix,
owner-native M1 and real Microsoft-client acceptance remain BLOCKED / NOT RUN.

## R10 rejected Linux LAN selection retires prior preference (2026-10-19)

At source parent `e2e48f0f8fc022203fc25d83540db83e36f5f93e`, R10's Linux GUI controller now invalidates
its previously configured interface/address/port when a new Configure
request is rejected or the selected native interface goes stale at Start.
An invalid GUI request can no longer leave a formerly accepted endpoint
armed for a later Start attempt. Existing listener ownership is unchanged;
this remains entirely offline and Start still fails on missing R2 consent.
Added `runtime.linux-host-control-rejected-selection-retires-previous`
to ordinary Linux CTest. It exercises the real host interface if one is
eligible, otherwise reports SKIP (77), never a fabricated PASS.
Source review PASS; local Debug/full CTest NOT RUN; hosted exact publication
SHA CI PENDING. No TLS identity, host consent, listener or client is created.

## R9 checksum receipt parser correction (2026-10-19)

On main `c56dc95ceaf2e77fd5e7971166d02d33dfc33836`, source inspection exposed a clean-Windows consumer
PowerShell error path: negative `-cnotmatch` validation does not reliably
populate capture groups under StrictMode. Replace it with an explicit
`[regex]::Match` result and checked `Groups` before comparing every
internal SHA256SUMS entry. Add a source mutation-denial regression.
Source consistency PASS; native Windows PowerShell execution and exact-SHA
hosted consumer receipt **NOT RUN / BLOCKED** on provisioned clean VM.
No DLL fallback, PATH relaxation, native listener or installation added.

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

## R10 concrete Linux HostControl fail-closed foundation (2026-10-19)

At source parent `3133c34ca215389e6536a963171accb80b6ae706`, the Linux GUI now constructs a concrete
serialized `LinuxRuntimeHostControl`, not the inert unavailable facade.
It enumerates real UP/RUNNING private LAN interface/address candidates,
tracks exact name/index identity, rechecks selection on Start, and holds
one unopened R1 `OwnedLanListener` RAII slot. Requesting existing-account
credentials or host permission never creates an R2 consent lease. Positive
Start stays denied; there are zero client sessions, native observers, input,
frames, listeners, firewall changes, UPnP or service activation. Stop is
idempotent and Revoke terminates configuration for the controller lifetime.

Ordinary offline Linux CTests:
`runtime.linux-host-control-no-consent-start-denials`,
`runtime.linux-host-control-revalidated-interface-denials`, and
`runtime.linux-host-control-stop-revoke-retirement`.
Source review PASS; developer-local build/full CTest NOT RUN; exact publication
SHA hosted CI PENDING. No physical seat0/client evidence. R2 independent
host-owner consent/lock/revocation, R1 certificate trust/identity, and
R10 positive session ownership remain BLOCKED. R4 ACK duplicate fix is
merged, R5 native geometry change landed, PR #23 ACK/default GUI is draft
with Qt6-missing protocol CI, PR #24 corrected remap awaits approval/CI.

## R6/R9 clean Windows exact-ZIP gate (2026-10-19)

The human-reported extracted ZIP fails without MSYS2: **RELEASE BLOCKED**.
The old hosted smoke inherited compiler/Qt PATH. A new unprovisioned Windows
runner downloads the exact uploaded ZIP, verifies SHA-256 and the production
manifest, and requires ordinary GUI visible-window launch and normal close
under a Windows-system-only process PATH from two Unicode-and-spaces folders.
A dedicated native Windows CTest rejects injected developer DLL paths without
starting a GUI. Two previous hosted CI ZIPs (PR #25 run 39232722215 artifact
12178570349; PR #26 run 39232727915 artifact 12177699951) contain the same
40 DLL names and identical DLL bytes. The human ZIP remains unavailable;
exact missing DLLs, human/CI parity, clean-runner PASS, and owner-native
acceptance are **PENDING**. This work does not enable Windows hosting: real
R2 SID/WTS admission and R10 Windows session/service ownership are BLOCKED.

## R5 native geometry observation and bounded framebuffer handoff (2026-10-19)

R4 duplicate-at-64 correction PR #27 is merged into main as
`55eb5e10d706b14c61ce8a3825d611bc2269c3d4`. R3 PR #24 has new
source fixes for retired-surface terminal ACK and zero-outstanding suspended
remap but remains **draft / review and exact-head CI pending**. R10's RandR
to R3 remap call and R2-backed LAN GUI Start/Stop/physical seat0 approval
remain **BLOCKED**, so no native-to-protocol resize acceptance is claimed.

R5 adds `X11NativeGeometryObservation` (value-only native pixel size, current
capture generation and caller-supplied R2-selected native session generation),
with `observeNativeGeometry`, `nativeGeometryIsCurrent`, and an overloaded
synchronous `consumeR4Frame` that rejects stale geometry/session epochs before
borrow. The scalar session generation is **never** authorization; R10 must
obtain it from a freshly validated R2 lease, drain current X11 events,
compare again immediately before publication, and use existing R2/R1/R3
gateways. Old XShm spans may not escape a consumer callback. No R3 Graphics
owner, runtime loop, OS session selector or XTEST permission was added.
New isolated Xvfb CTest `x11.native-geometry-observation-generation-retirement`
covers repeated RandR replacement, queued pointer movement, stale generation,
wrong session, synchronous full-frame consumption and terminal no-borrow
retirement. Existing Xvfb R5 tests cover failure/no-XTEST behavior separately.

Implementation parent `55eb5e10d706b14c61ce8a3825d611bc2269c3d4`; owner-local full Debug CTest:
**NOT RUN** (no connected checkout and native XCB development dependencies
in this execution environment); exact publication-SHA hosted CI **PENDING**;
authorized physical seat0 and real Microsoft Windows App **NOT RUN**.

## R7/R6 exact-SHA Windows GUI verifier evidence (2026-10-19)

Exact SHA `6f01ee9e2d88b76aab29b1d384a163a5500ce6b4`, GitHub Actions
`39214767641`: the corrected R6/R7 Windows shared-GUI contract is exercised
successfully in the full **Release CTest**, native Windows GUI package/PE
closure and extracted qwindows offline smoke. The R7 macOS portable GUI,
native lifecycle and session-sanitizer jobs also pass, as do Ubuntu/macOS/
Windows protocol, R2 production-security, R9 sanitizers, Linux GUI packaging,
documentation and workflow structure.

The aggregate workflow remains **FAIL** because the full **Debug** CTest has
one unrelated timeout in `windows.package-user-lifecycle-offline-contract`:
its native PowerShell server-test Install subprocess exceeds the fixture's
30-second timeout. All other 663/664 Debug CTests pass. This is not an R7 GUI
assertion, credential-surface failure, listener regression or package-smoke
failure; the same workflow's Release full CTest and extracted GUI smoke pass.

Therefore the R7 password-input removal and Windows verifier correction are
now hosted-validated on their exact publication SHA. The product blockers are
unchanged: concrete R10 GUI LAN `RuntimeHostControl`, genuine R2 per-session
owner consent/lock authority, R1/R10 certificate fingerprint/trust/rotation,
and platform-owner acceptance.

## R7/R6 Windows offline verifier follows non-collecting password UI (2026-10-19)

Exact hosted SHA `84d9ac65936e83eb8644ee2461bda2764eac9c68` isolated the
aggregate CI failure to R6 Windows CLANG64 GUI offline/package smoke: the
hidden verifier still required the R7-removed `password` QWidget and returned
exit 3. The shared R7 UI itself passed macOS portable/native/session coverage,
while Ubuntu/macOS/Windows protocol, R2 production-security and R9 sanitizers
also passed.

The Windows launcher now verifies the current non-collecting contract: both
historical `password` and `confirmation` objects must be absent, the
visible `Set Application Password — Unsupported` action must exist disabled,
and Start/Stop remain denied under the unavailable runtime. New dedicated
`windows.gui-independent-password-input-unavailable` invokes a hidden
qwindows-backed command mode. Existing self-test, Start-denial and packaged
qwindows smoke keep their no-listener/no-admission behavior.

Parent: `972f0200b176fe21b28559d693e69fa8d833fea2`. Source review PASS. Publication-SHA Windows/full hosted
CI PENDING; owner-local full CTest NOT RUN. Real R10 GUI HostControl, R2
positive owner consent/lock authority and R1/R10 certificate
fingerprint/trust/rotation remain BLOCKED.

## R7 unsupported independent password has no input surface (2026-10-18)

The shared Qt credentials page no longer constructs disabled password or
confirmation text fields for the unimplemented independent application-
password mode. Until R2 proves interoperable NLA, it shows only a visibly
disabled **Set Application Password — Unsupported** action and fixed text
that the GUI does not collect or store such a password. Existing OS-account
setup remains the only credential request path. Start readiness has no
password-field branch. New ordinary offscreen
`gui.offscreen-independent-password-workflow-unavailable` asserts the
unsupported action is disabled, the former password/confirmation QObject
names do not exist, and clicking the disabled control cannot configure or
start R10. Parent `17bbd4dd86481cfd67d9c08128a80a780e8a91b7`. Source inspection PASS; native Qt/full CTest
NOT RUN; publication-SHA hosted CI PENDING. Real R10 LAN HostControl,
R2 positive owner admission and independent-password NLA proof, R1/R10
fingerprint/trust status and AppKit ownership remain BLOCKED.

## R7 typed lifecycle display and terminal-session close safety (2026-10-18)

Qt HostStatus now retains a single R10 RuntimeHostStage and listenerAvailable
observation, not a competing controller. A plain-text label distinguishes
stopped, installed, configured credentials, confirmed listener, peer
authenticating, Share activated, desktop visible, genuinely connected
visible client, and revoked. No listener readiness or connected desktop
is inferred from Share or a peer attempting authentication.

R2 terminal host-session errors can intentionally suppress GUI projected
sharing before the raw R10 stage retires. The Stop/close guard now conserves
that raw stage so an active listener or session cannot silently close or
be hidden as a consequence of a stale-authority diagnostic. Close still
requires explicit user Stop consent and a fresh retired R10 snapshot.
New ordinary offscreen
`gui.offscreen-r10-lifecycle-and-terminal-close-denials` covers all nine
stages, missing listener/client evidence, R2 stale host-session Stop,
and control unavailable. Original close-consent CTests remain registered.

Parent `6f37cbc7ea70c98b4b213ce6b8c195c5859eed7e`. Source structure PASS. Native Qt build/full CTest
NOT RUN (owner checkout unavailable). Exact-publication-SHA CI PENDING.
R10 live LAN HostControl, R2 genuine owner consent, R1/R10 authoritative
TLS fingerprint/trust/rotation and macOS AppKit owner remain BLOCKED.
macOS Developer ID/notarization and real Microsoft-client acceptance NOT RUN.

## R2/R10 explicit rate-limit and stale-session status contract (2026-10-18)

R2's OS-account GUI admission contract now exposes the two missing fixed,
redacted `RuntimeHostError` outcomes `AuthenticationRateLimited` and
`HostSessionStale`, appended without renumbering preexisting status codes.
They are non-authorizing diagnostics. R7 projects rate limiting as a
failed authentication, not a verified login; a terminal stale/revoked
host-session error suppresses stale GUI desktop authorization, clients,
endpoints, input readiness, Start and client-disconnect actions even if an
outdated runtime snapshot still contains positive flags. Neither a peer
rate limit nor another client's auth failure independently revokes
unrelated existing authorized connections. R10 remains the sole live
source of these outcomes and must publish them only after concrete
R2/R1/native events, not GUI preferences.

Dedicated ordinary cross-platform production-header CTest
`runtime.host-control-authentication-outcome-denials` pins distinct
fixed non-secret messages and the deny-only fallback, while the existing
`gui.offscreen-r10-client-stage-and-retirement-status-denials` adds
status projection and stale-host action denials without using a real
listener, credentials, seat0, GSS context or admission lease.
Source review **PASS**; owner-local configure/build/full CTest
**NOT RUN** in this GitHub-only workspace; publication-SHA hosted
CI **PENDING** at authoring. Physical-owner consent, reliable real
lock-state evidence, actual LAN HostControl and three-client Microsoft
CredSSP proof remain **BLOCKED / NOT RUN**. Standalone GUI password
remains unsupported without a compatible, reviewed mechanism.

## R8 stale positive clipboard TLS receipt isolation (2026-10-18)

R8 now ignores delayed R3-committed Pending/Delivered scalar receipts
from retired route generations, including after Stop and replacement.
They cannot retire a newer R8 route, erase its clipboard source epoch,
or clear its queued FORMAT_LIST response. Invalid zero/future generation,
reply, slice and byte receipts against a live route remain fail-closed;
R2/R3 remain the sole authorized accepted-byte owners. Dedicated offline
`runtime.r8-r3-retired-route-positive-receipt-isolation` proves
old positive-partial and full R3 receipts cannot disrupt the replacement's
valid completion. It is outside R9's unchanged 87-case clipboard sanitizer
selection. Implementation parent `c1ec383576c52629a2f094ed8a696d2280720b8c`; owner-local C++23 build/full
CTest **NOT RUN** (approved owner checkout unavailable); publication exact-SHA
hosted CI **PENDING**. Live R10 CLIPRDR dispatch/native X11 composition remains
**BLOCKED** pending first owner-authorized Linux LAN desktop video/input
acceptance. Text, images, FileContents and directory trees stay disabled.

## R7 Qt close-consent gate for future real HostControl (2026-10-18)

An active or pending remote-sharing window close now prompts explicitly
for **Stop Sharing and Close**, with **Keep Window Open** as the safe default.
Dismissing the dialog never hides the GUI or issues Stop/Revoke. Even after
explicit user consent, the GUI stays visible unless a fresh R10 snapshot
confirms available control and retired sharing. Existing R10 ownership,
startup-disabled GUI and independent app-password denial are preserved.
The existing close-retirement CTest now selects Stop explicitly, and new
`gui.offscreen-close-requires-explicit-owner-stop` exercises cancellation,
unconfirmed retirement, successful revocation, and stopped-window exit.
Parent: `2ec8ac3b8b6ca83f3748ef161b5dd8bdc608b4c5`. Native Qt build/ordinary CTest and publication-SHA
CI: **NOT RUN** in this connector environment. Live R10 GUI LAN HostControl,
R2 authenticated OS owner, R1/R10 fingerprint/trust/rotation status, macOS
AppKit owner, release notarization and real client acceptance remain
**BLOCKED / NOT RUN**. The GUI still uses UnavailableRuntimeHostControl.

## R2 repeated-read native seat0 identity fence (2026-10-18)

R2 corrected an earlier attempted lock-hint gate that referenced a
nonexistent public `sd_session_get_locked_hint` libsystemd API. The
unsupported calls and hint field have been removed before claiming any
native build success. `LockedHint` is a logind D-Bus advisory property;
its absence from the public sd-login C API means explicit desktop lock
and user consent assurance remain separate **BLOCKED** live gates.

The production `LinuxLogindReadOnlyEvidenceSource` instead now uses
existing documented `sd_session_get_uid` and
`sd_session_get_start_time` to recheck the exact same native UID and
session-start identity **after** the second seat0 observation. Missing,
failed or replaced evidence denies the native candidate without
creating an admission token. One new ordinary production-linked CTest
`security.linux-seat0-session-identity-denials` checks wrong UID,
zero session-start identity, lock-screen class, inactive, remote and
switched-seat candidates. Source review **PASS**; owner-local build/full
CTest **NOT RUN**; exact-SHA hosted CI **PENDING** at publication.

Next: R10 concrete LAN GUI HostControl, independently trustworthy per-
session owner consent/lock handling, and owner-authorized physical X11
seat0 Microsoft-client CredSSP/PAM/NSS/logind evidence. Do not add
unbounded D-Bus calls on the protected frame hot path or enable the
separate unsupported application-password path.

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

## R8 stable scalar outbound TLS receipt after R3 mutation (2026-10-18)

The authenticated persistent R10 loop, R1 clipboard write/WANT readiness
and R2/R3 committed-byte gate are now present. R8's connection-owned TLS
write result now copies route/reply/slice identity and offered-byte size
before R2/R3 advances or retires the borrowed static-VC packet. The R8
bridge observes only these R2-committed scalars, with no second TLS writer,
R3 accepted-byte offset or route owner. Zero-byte/SSL WANT/no-lease results
expose no route identity. Dedicated ordinary production-backed
`runtime.r8-r3-stable-scalar-write-receipt` exercises real R3 partial
and full receipts, verified response, reconnect stale rejection and
zero-byte denial; the existing no-lease TLS writer test asserts zero
identity. It is outside the fixed 87 clipboard sanitizer and two native
linkage selections.

**Next R8 action / BLOCKED:** `main.cpp` still terminally rejects CLIPRDR.
R10/R8 must compose fresh R2-gated inbound complete-PDU dispatch, outbound
receipt scheduling, and native X11 adapter/INCR Stop/logout/reconnect
retirement, only after owner-authorized video/input acceptance. No live
clipboard publication was enabled. Owner-local build/full CTest
**NOT RUN** (approved checkout unavailable); new SHA hosted CI **PENDING**.
Pre-change baseline `9a036d09` primary `39147713490` and structure
`39147713471` **PASS**.

## R3 non-mutating Graphics ACK-credit handoff (2026-10-18)

The original dependency-graph blocker `R3 -> R10` is resolved in source:
R10 owns the persistent single R1 TLS reader and consumes R3's authenticated
post-Share classifier. Exact `9a036d09` hosted CI is fully green, including
the four classifier cases, R3 Graphics/FRAME_ACK sanitizers and R4 ACK
backpressure. The next demonstrated R3 boundary is normal ACK-credit
saturation: R4 safely refuses the 65th pending frame, while the current R10
frame-start path treats any refusal as terminal. R3 now publishes an ephemeral,
R2-revalidated `Ready / DeferredForFrameAcknowledge / Rejected` preflight so
R10 can defer capture/publication only for that normal pressure. It does not
reserve a frame or grant authority. Geometry/RandR surface replacement and
owner-authorized physical seat0/client acceptance remain separate gates.

## R10 extracted one native Linux listener owner for GUI reuse (2026-10-18)

R10 moved the existing verified, nonblocking/CLOEXEC, exact-bound
loopback listener and its move-prohibited RAII descriptor owner out of
CLI-private `main.cpp` into the noninstalled Linux-only
`rdp-server-linux-serve-listener` component. The existing secure `serve`
path now links and uses that **same** component after R2 pre-listener
provisioning; no extra socket, thread, listener, read loop or binding mode
was introduced. A future concrete in-process LAN HostControl must reuse
this owner and additionally prove the selected physical interface/address
and actual kernel bound endpoint before advertising sharing. The public
pure `isEligibleLinuxLoopbackListenerEndpoint` retains exact literal
loopback-only CLI policy. New ordinary offline executable CTest
`runtime.linux-serve-loopback-listener-exact-endpoint-denials` checks
this policy and noncopyable/nonmovable descriptor lifetime without bind.
Parent `eeea6b751e095028ba00cc5d25526eae85a7cdda`. Owner checkout/full CTest: **NOT RUN**; hosted CI
on publication commit: **PENDING**; real authorized LAN, seat0 and
Microsoft-client trials: **NOT RUN**. GUI still denies Start/Stop via
`UnavailableRuntimeHostControl` and native R8 clipboard remains disabled.

## R9 native macOS R10/R7 LAN policy-to-Qt paired CTests (2026-10-18)

Exact earlier complete-green GitHub head:
`9a036d098bc183c051c02e4bb233733c89a33a3c`,
[primary 39147713490](https://github.com/k1moradi/RDP-server/actions/runs/39147713490),
[independent structure 39147713471](https://github.com/k1moradi/RDP-server/actions/runs/39147713471).
The R7 GUI now uses R10's pure exact stable-interface-ID/address
eligibility check before projecting LAN choices. R7's new existing
`gui.offscreen-r10-selected-lan-endpoint-preflight-denials` passed
as part of the broad macOS Qt suite, but the separately registered
`runtime.host-control-selected-lan-interface-denials` was not
explicitly built/tested in the macOS portable-GUI lane.

R9 now builds both existing fixture executables on that AppleClang/Qt
Release runner and selects exactly these **two** registered executable
CTest behaviors before native portable app packaging and extracted
signature/LaunchServices checks. The independent structure validator
pins the step, selector, both exact names and cardinality. No
duplicated tests, native socket bind, R2 credential admission or
live GUI hosting behavior is introduced. Same-SHA owner-native
Windows CLANG64, Linux X11, macOS 27 and authenticated Microsoft
client acceptance: **NOT RUN**; R10 live GUI Start/Stop and
R8 native CLIPRDR composition: **BLOCKED upstream**. New exact
publication-SHA hosted primary/structure CI: **PENDING**.
No macOS downloadable GUI ZIP or release was authorized.

## R7 client authentication-versus-connected projection and retirement (2026-10-18)

The exact-head `9a036d098bc183c051c02e4bb233733c89a33a3c`
[primary CI 39147713490](https://github.com/k1moradi/RDP-server/actions/runs/39147713490)
is **HOSTED-GREEN** across macOS, Ubuntu, Windows, R2 security,
R9 sanitizers, R5/R6 package and R7 macOS portable GUI/lifecycle
jobs. The Mac arm64 Cocoa `.app` remains a startup-deny-only GUI,
with strict extracted ad-hoc signing and successful hosted
LaunchServices/no-listener smoke. This is not macOS 27 owner-native
Finder double-click, quarantined Gatekeeper trust, Developer ID
signing, notarization or an authenticated Microsoft-client desktop.

R7 now corrects the *presentation-only* interpretation of R10's
`RuntimeHostClient` records: `authenticating` and
`shareActivated` without a visible desktop are displayed as
**pending**, not **connected**. Only records with genuine
`shareActivated && desktopVisible && !authenticating` flags
in a currently sharing R10 stage appear in the Connected clients
list. Opaque client IDs remain usable solely for R10-owned
disconnect requests, including for pending connections; neither
a click nor a returned command result is admission or disconnect proof.
If the current R10 stage is stopped/revoked, or host control becomes
unavailable, a stale `boundEndpoint`/client list in the snapshot
is not projected as an active endpoint/client and cannot be copied
or selected. This uses no new controller, socket reader, R2 lease,
native permissions, ScreenCaptureKit/Quartz activation or state cache.

New ordinary Qt offscreen behavior CTest
`gui.offscreen-r10-client-stage-and-retirement-status-denials`
exercises mixed per-client stages, global pending vs connected,
stale Stop and ControlUnavailable projections with fake R10 inputs.
Implementation parent `cf2ea3daeb028bf6d667713fd2b2bbe6c10e26c9`; owner-local C++23 Qt build/full
CTest **NOT RUN** (the owner checkout and native Qt toolchain are
unavailable to this connector environment); exact publication CI
**PENDING**.

Dependency graph: R3 post-Share classification and R10's serialized
Linux loopback CLI R1/R2/R5 frame/input/Stop have landed. R10's
`assessRuntimeSelectedLanEndpoint` shared preflight has landed and
is used by R7's UI, but the Qt executable still constructs deny-only
`UnavailableRuntimeHostControl`. R10 has not provided the
concrete GUI LAN Start/Stop owner or the AppKit console-session
owner, and R2 has no demonstrated genuine credential-bound,
revocable macOS UID lease. The R10 status contract still has no
authoritative TLS certificate SHA-256 fingerprint or client trust
field. Native macOS hosting and positive client acceptance remain
**BLOCKED** on those owners, not on package ZIP closure.

## R2 canonical peer quota across dual-stack address encodings (2026-10-18)

R2's serialized NLA attempt limiter now treats native IPv4 and exact
`::ffff:a.b.c.d` IPv4-mapped IPv6 as the **same** fixed-table peer.
Before this correction, the two address-family encodings could occupy
distinct active slots and increase the attempts allowed per peer on a
future authorized dual-stack LAN listener. Only the RFC 4291
ten-zero/two-0xff prefix canonicalizes; native and near-mapped IPv6
remain distinct. The update is zero allocation and changes neither
global nor per-GSS-principal budgets or the current deny-only LAN
host-control admission.

Dedicated ordinary production-header CTest
`security.ipv4-mapped-ipv6-peer-quota-identity` tests both directions,
shared cap, unmapped IPv6 isolation, expiry and monotonic-clock
regression. Local owner Debug/full CTest **NOT RUN** (no approved
checkout); publication-SHA hosted CI **PENDING**. Real seat0
Kerberos/PAM/logind consent, Microsoft-client traffic and independent
GUI-password interoperability remain **BLOCKED / NOT RUN**.

## R7 GUI now projects only R10-selected LAN endpoints (2026-10-18)

The earlier R10 `abe17d32310cace7b611652e4085476bbc5ca8aa`
landed the pure authoritative `assessRuntimeSelectedLanEndpoint`
preflight for an exact, eligible, nonloopback native stable interface ID,
its actual numeric address, nonwildcard binding and nonzero port.
R7 now uses this same existing R10 policy when building the Qt LAN
choices rather than displaying entries that R10 will reject on Start.
One enumerated interface may safely expose multiple eligible IPv4/IPv6
addresses, but duplicate stable interface IDs, ineligible interfaces,
loopback and wildcard address candidates cannot become selectable.
R10's existing Start preflight still revalidates the specific selected
port and interface, and the future concrete controller must revalidate
native binding and R2 consent independently.

New ordinary offscreen behavior CTest:
`gui.offscreen-r10-selected-lan-endpoint-preflight-denials`.
It uses the existing injected fake to test two addresses on one stable
ID, duplicate identities, wildcard, loopback, ineligible, zero-port,
selection removal and positive-only UI projection without interpreting
a click as sharing. No native capture, socket, TCC operation or real R2
credential authority is introduced. First authored against parent
`640bd7df42bd3913495afb337ee0910a57f717e9`. Local Qt/full CTest: **NOT RUN**; publication-SHA
CI: **PENDING**.

Prior R7 code SHA `c3a0b14e8c86df08ed7427a8651a4cad396f8236`
already **PASSed** on hosted macOS 26 arm64
[CI 39146582230](https://github.com/k1moradi/RDP-server/actions/runs/39146582230):
3/3 macOS framework/archive package CTests, 6/6 Qt offscreen CTests,
strict extracted `codesign --verify --deep --strict` with
`Signature=adhoc`, `TeamIdentifier=not set`, and the normal
LaunchServices `open -n -a` extracted Cocoa/no-TCP-listener smoke.
The macOS ordinary protocol Debug/Release CTest passed **615/615**
each, including the R7 PlainText construction guard.
The whole workflow's Windows jobs were still in progress at evidence
collection; do not claim overall PASS.

R2 has no demonstrated credential-bound revocable macOS UID lease and
R10 still has no concrete GUI LAN Start/Stop HostControl or serialized
AppKit/session owner. The GUI must continue to instantiate
`UnavailableRuntimeHostControl` and refuse serving. R10 does not yet
supply trusted TLS leaf SHA-256 fingerprint/client-trust status to GUI.
Owner native macOS 27 normal Finder double-click, quarantine/Gatekeeper
assessment, Developer ID signing/notarization and authorized
Microsoft-client desktop are **NOT RUN / NOT COMPLETE**. An ad-hoc
signature never asserts production trust.

## R5 XTEST pointer-button owner-held transition safety (2026-10-18)

R10's persistent post-Share XCB/TLS input and synchronous R4 frame
borrow are in production, and R10 `d9b835bca423` added cooperative
SIGINT/SIGTERM Stop in its existing owner thread. Native inspection
found that R5 `X11InputController::handlePointerButton` forwarded
unmatched remote releases and repeated presses to XTEST even where the
one R5 controller held no corresponding button state. This could
release an X11 button held by another input source. R5 now ignores
duplicate native makes and unmatched breaks using the **existing**
fixed held-button array. Only a successful owner-held native
ButtonPress can be followed by an XTEST ButtonRelease; no second
authority owner is introduced. Signed wheel pulses and MouseX 8/9
remain unchanged and continue through R2's per-event authorization.

The new behavior-named Xvfb test
`x11.input-native-pointer-button-owner-held-break-denials`
checks duplicate make/break, isolation of an independently simulated
foreign-held Xvfb button, graceful cleanup not releasing that button,
and fresh-owner no-adoption. It uses only isolated Xvfb; no live R2
lease, physical seat or client is fabricated. Local approved
`~/rdp-server/build` Debug/full CTest: **NOT RUN** (checkout and
XCB/XTEST development dependencies unavailable here); exact new
publication-SHA hosted CI: **PENDING**. R10 Qt LAN Start/Stop remains
deny-only, and real Kerberos/PAM/logind seat0 Microsoft Windows App
input/frame ACK remains **BLOCKED / NOT RUN** on host consent.

## R10 authoritative GUI LAN selection preflight (2026-10-18)

The R10 runtime contract now owns `assessRuntimeSelectedLanEndpoint`,
which requires a unique currently enumerated stable interface identity and
exact address plus a nonzero port, explicit LAN mode, nonloopback eligibility
and no wildcard address. R7's thin Qt adapter calls this common check
instead of maintaining its own copy; no GUI label or preference grants
permission to bind. A genuine controller must **re-enumerate and recheck**
R1's native bound endpoint and R2 consent on Start/accept; the GUI still
instantiates deny-only `UnavailableRuntimeHostControl`, so no LAN listener
or positive user authority is fabricated. New executable CTest
`runtime.host-control-selected-lan-interface-denials` covers exact match,
renamed/missing/duplicate/loopback/wildcard/disabled and zero-port cases.
Parent `b497e76ab3898aec7cbe3aff8bc6ab1e69fb49b2`; local owner build/CTest **NOT RUN**, hosted exact-head
CI **PENDING**, real approved LAN/Microsoft-client **NOT RUN**.

## R9 native Stop, terminal input, Qt PlainText focused gates (2026-10-18)

Current prior fully verified main pair `79efe8f21d7028190a678d0f584535f2ef67922b`:
[primary Actions 39145740980](https://github.com/k1moradi/RDP-server/actions/runs/39145740980)
and [independent structure Actions 39145740927](https://github.com/k1moradi/RDP-server/actions/runs/39145740927)
**PASS**. Later R10 added serialized Linux SIGINT/SIGTERM cooperative
Stop with the source CTest
`runtime.linux-serve-cooperative-signal-stop-order`. R5 added
`x11.input-direct-route-native-failure-no-xtest`, proving native XTEST
failure retires the owner and revokes R3 without an unsafe key/button
release. Both guards are now in one separate **exact-two** R9 focused
Linux CTest source gate; neither sends live signals or XTEST.

R7 added `gui.runtime-label-plain-before-text-assignment` to protect
Qt runtime endpoint/interface/peer text against transient rich-text
parsing during QLabel construction. R9 now explicitly runs it on
the **same native macOS Release Qt build** before packaging and
LaunchServices opening the extracted Cocoa app, as a distinct
**exact-one** source-level CTest. The real GUI offscreen fixture remains
unchanged. The independent workflow structure validator pins
both new gate names, CTest names and counts. They are **source guards**,
not ASan-instrumented runtime positives or authenticated native
acceptance. Existing R2 40-case, R8 87-case, 2 post-Share cases,
2 native-linkage cases, and R8 TLS receipt-denial counts stay unchanged.

Exact publication-SHA primary and independent workflow results:
**PENDING**. Linux/X11 genuine R2 credentials, Windows LAN
Microsoft clients, macOS 27 owner-native install / human Finder
and positive clipboard/GUI Start remain **NOT RUN**. No SERVER-TEST
or PORTABLE-GUI release is approved by this source-level increment.

## R2 bounded account-table exhaustion and expiry (2026-10-18)

The GSS-provider-verified principal budget is now in the live Linux
GSS-to-PAM path (`1aa476e5`), and the exact R2 parser correction
`79efe8f2` has fully green hosted primary CI
([39145740980](https://github.com/k1moradi/RDP-server/actions/runs/39145740980)).
The existing offline attempt limiter CTest exercised account 8-attempt
limits but not exhausting all 64 tracked *distinct* principal slots.
New dedicated ordinary CTest
`security.verified-account-table-exhaustion` reuses the production-backed
test executable and verifies 64 live verified-principal slots, denial of a
65th rather than unexpired eviction, budget retention on repeated
existing-principal attempts, pre-expiry overflow denial, exact-window
reuse/reset, malformed/overlong principal denial, case-sensitive identity
and independence of the original peer/global budget. It neither performs
PAM, manufactures GSS identity nor asserts native acceptance.
Local approved checkout/full Debug CTest: **NOT RUN**; exact
publication-SHA hosted CI: **PENDING**. Next genuine admission/client
gate remains owner-authorized physical X11 seat0 with real OS
credentials/consent; independent GUI password **BLOCKED**.

## R7 runtime-label PlainText ordering correction (2026-10-18)

The R7 `6648ea720cd57d3fcf9461cae127ff6b96b7e8cd` GUI commit
made projected R10 peer, interface, endpoint and error labels plain text
and registered `gui.offscreen-runtime-peer-and-endpoint-plain-text`.
Review found a **transient AutoText parsing window**: constructing a
`QLabel(message)` can interpret HTML-looking runtime text before a
later `setTextFormat(Qt::PlainText)` call. R7 now constructs an empty
`QLabel`, sets `Qt::PlainText` **first**, and only then assigns the
status text. A dedicated source-backed ordinary CTest,
`gui.runtime-label-plain-before-text-assignment`, guards the strict
order; the existing behavior-backed offscreen CTest checks literal
endpoint/client/interface rendering. No networking, R2 credentials or
OS capture is introduced.

Exact-parent `d9b835bca42354da1d3b1de9c3848984b6ae9947`;
local Qt/ordinary full CTest **NOT RUN** (no local owner checkout);
new publication-SHA hosted CI **PENDING**.
The extracted macOS 26 arm64 LaunchServices/no-TCP-listener and
strict ad-hoc-signature package jobs already **PASS** at
`c1ed4f1` and descendant `549a12c0`, but human Finder double-click,
quarantined Gatekeeper trust, Developer ID notarization, macOS 27 owner
testing and positive Microsoft-client LAN hosting remain **NOT RUN**.
R10 has added serialized Linux loopback CLI Stop handling, not concrete
GUI LAN HostControl or AppKit ownership; R2 macOS UID lease is still
missing. Native ScreenCaptureKit/Quartz serving remains blocked.

## R10 Linux loopback CLI cooperative Stop (2026-10-18)

R10 installs scoped SIGINT/SIGTERM handlers only after opening its verified
loopback listener. The handler writes a `sig_atomic_t` scalar only. Thirteen
serialized handshake-stage loops and the persistent X11/logind/SSL poll
observe the request on their existing owner thread, retire native input
without XTEST cleanup, revoke the session and close the R1 socket/listener
through existing RAII. New ordinary offline production-source CTest
`runtime.linux-serve-cooperative-signal-stop-order` checks the stop fences
and teardown ordering without sending signals or inventing an R2 lease.
Parent `6648ea720cd57d3fcf9461cae127ff6b96b7e8cd`. Local owner full CTest **NOT RUN**, hosted publication
CI **PENDING**, live seat0/real-client Stop **NOT RUN**. The GUI LAN
`RuntimeHostControl` backend remains R10-owned and **NOT IMPLEMENTED**.

## R7 exact-head extracted macOS launch acceptance and Qt plain-text status (2026-10-18)

Native macOS 26 arm64 `r7-macos-portable-gui` **PASS** at exact
R7 SHA `c1ed4f125d2c927ba8771637126836306357216b` in
[Actions 39142104657](https://github.com/k1moradi/RDP-server/actions/runs/39142104657),
job `117719372153`, and again at descendant
`549a12c0a3647708a48e51d1bb1a298745edc6e2` in
[Actions 39142229897](https://github.com/k1moradi/RDP-server/actions/runs/39142229897),
job `117719394320`: **3/3** macOS framework/archive CTests and
**5/5** R7 offscreen GUI CTests PASS; real Qt .app, macdeployqt
plugin/framework closure, verified ZIP, extracted Mach-O audit,
`codesign --verify --deep --strict` and `Signature=adhoc` PASS.
`open -n -a` kept the extracted Cocoa GUI alive with no TCP LISTEN
socket. This is **hosted automated LaunchServices**, not a human Finder
double-click or owner macOS 27 acceptance. Developer ID signing,
quarantined Gatekeeper trust and notarization remain **NOT COMPLETE**.

R7 now additionally forces `Qt::PlainText` on its shared `QLabel`
factory. R10-owned endpoint, interface names, client peer metadata and
redacted error strings must remain inert literal text even if they
contain HTML-looking markup; Qt's `AutoText` could interpret remote
peer data as rich text. A new dedicated ordinary offscreen CTest
`gui.offscreen-runtime-peer-and-endpoint-plain-text` supplies malicious
peer/endpoint/interface markup through the existing injected R10 fake
and requires plain-text labels, no synthetic R2 authority, no Start
command and no network/native side effects. Initial authoring parent
`70d3df77517d336966b39b105d829fd4ee482d1a`; local Qt compile/full CTest **NOT RUN** (no owner
checkout); publication-SHA CI **PENDING**.

**Dependency state:** R3 classifier and R10 persistent Linux loopback
CLI R1 single-reader/X11 frame/input scheduler have landed, but
`src/gui/main.cpp` still uses deny-only
`UnavailableRuntimeHostControl`. R2 has no verified macOS
credential-bound revocable UID lease and R10 has no serialized AppKit
session owner or concrete GUI LAN Start/Stop backend. The GUI neither
mints R2 access nor acts as a packet scheduler. Native macOS
ScreenCaptureKit/Quartz factories, authenticated Microsoft-client
desktop, and TLS fingerprint/trust display remain blocked until their
respective R2/R10/R1 data and owner-native prerequisites exist.

## R5 terminal protected-input route parity (2026-10-18)

The production R10 post-Share scheduler `4795c6dd` and corrected X11
resource no-post retirement `25a5671d` are landed; R5's hosted Ubuntu,
Windows/macOS protocol and Linux portable Qt ZIP cases pass on descendant
`549a12c0`, apart from one independent R2 PAM guard script error.
The formerly separate R5 `X11AuthorizedInputRoute::dispatch` gateway
still invoked graceful `desktop.disconnect()` after a native injection
failure, whereas R10's active authenticated callback always uses
terminal `retireAfterAuthorizationLoss()`. That discrepancy is now
corrected: both paths discard native key/button state with **zero
additional XTEST** on uncertain failure, then revoke their R2/R3
authority. Dedicated portable offline CTest
`x11.input-direct-route-native-failure-no-xtest` checks the direct
gateway's R2 input-permission fence, failure ordering and absence of
graceful native teardown. It is source evidence only; existing Xvfb
tests independently cover held-key/button retirement. Owner-local
full Debug CTest: **NOT RUN** (no approved checkout/toolchain); exact
publication-SHA hosted CI: **PENDING**. No R10 scheduler, R3 protocol,
live listener, GUI Start/Stop, native password or OS admission changes.
The first genuine physical X11 seat0/Windows App/mstsc acceptance
remains **BLOCKED / NOT RUN** pending explicit owner authorization.

## R9 focused R2 verified-account source-fence coverage (2026-10-18)

The last complete independently checked hosted-green SHA advanced to
`440b4e46c81b2e0341ca107dc7be51e2c0897ca5`:
[primary 39141709666](https://github.com/k1moradi/RDP-server/actions/runs/39141709666)
and [independent structure 39141709747](https://github.com/k1moradi/RDP-server/actions/runs/39141709747).
Later head `549a12c0a3647708a48e51d1bb1a298745edc6e2` failed exactly
one Ubuntu ordinary Debug CTest:
`security.linux-verified-account-pam-attempt-fence-source`, because
`tests/check_runtime_verified_account_attempt_fence.cmake` omitted
the closing `endif()` after its verified-account budget assertion.
R2 independently resolved that parsing defect at
`79efe8f21d7028190a678d0f584535f2ef67922b`, without changing
credential policy or fake-positive admission.

R9 now selects this existing R2 guard with one dedicated exact-one
focused CTest and independent CI-structure tokens. The source-level
guard is not an ASan-instrumented executable, so the R2 40-case
security sanitizer inventory, R8 87 component cases, R10 2
post-Share executable denials, R9 2 native-linkage guards,
and existing R2 protected-read generation fence remain unchanged.
This does not introduce a duplicate CTest or bypass the full ordinary
Linux suite. Exact publication-SHA primary and independent structure
workflow outcomes: **PENDING**. Owner-local Linux/X11, Windows
CLANG64 and macOS 27 acceptance **NOT RUN**; Microsoft-client,
operational GUI Start/Stop and native R8 clipboard remain unverified.

## R7 macOS extracted Cocoa normal-launch gate (2026-10-18)

R7's signed-framework ZIP-alias correction `57103ca` is hosted-green on
descendant `f57d9c68`, native macOS 26 arm64
[Actions 39140555244](https://github.com/k1moradi/RDP-server/actions/runs/39140555244):
the Qt app built, 5/5 offscreen GUI CTests passed, the archive and
extracted Mach-O dependency checks passed, and
`codesign --verify --deep --strict` on the extracted .app **PASSED**
(`Signature=adhoc`, `TeamIdentifier=not set`). This closes the prior
QtDBus.framework extracted signature failure but **not** release signing.

This R7 follow-up explicitly runs all three preexisting macOS
archive/framework-link CTests in the native packaging job, then after
archive extraction and strict signature validation invokes the exact
extracted app by LaunchServices `open -n -a`. It requires a persistent
GUI process, denies TCP LISTEN sockets for its PID and terminates it.
If the runner has no usable Aqua session, the test fails explicitly;
a successful `open` return alone is not a launch PASS. This is an
automated normal Cocoa/LaunchServices launch, **not** a human Finder
double-click, quarantined Gatekeeper trust, Developer ID signature,
notarization or live authorized session. Exact new-head CI: **PENDING**.

R3 authenticated post-Share classification and R10 persistent Linux
loopback CLI single-reader/frame/input routing have landed, but the
concrete R10 Qt LAN Start/Stop backend and serialized macOS AppKit/session
owner, as well as R2's genuine credential-bound revocable macOS UID
lease, are still absent. `src/gui/main.cpp` retains
`UnavailableRuntimeHostControl`. Neither UI launch nor TCC consent
authorizes ScreenCaptureKit/Quartz serving.

## R5 native-error terminal input retirement (2026-10-18)

R10 `4795c6dd` and `2a3f06b0` resolved the persistent
single-X11-owner/TLS input and first-frame borrow dependency; R5's
`060297641ad0` native handoff CTests pass on hosted Ubuntu. R10
`e00593e86700` now repairs its two legacy native-poll source guards;
exact descendant hosted CTest is pending. R5 found that terminal XCB
event, XShm capture, XTEST injection and failed RandR error paths
called `cancelNativeResources()` with an old graceful default that
could emit key/button releases after native authority became uncertain.
Full-owner cancellation now defaults to no-XTEST
`SuppressNativeInput`; only explicit `disconnect()` requests
`ReleaseHeldState` while still authorized, and successful RandR
geometry-only retirement is unchanged. New ordinary offline production
source CTest `x11.input-native-failure-terminal-retirement-no-xtest`
locks this contract beside existing Xvfb native held-input no-post tests.
Owner-local full CTest: **NOT RUN** (no approved checkout); exact
publication-SHA hosted CI: **PENDING**. Real seat0/GSS/PAM/logind and
Microsoft-client frame/input acceptance: **BLOCKED / NOT RUN** without
owner authorization; R10 GUI Start/Stop remains deny-only.

## R9 outbound CLIPRDR TLS receipt sanitizer selection (2026-10-18)

The R8 descendant `7c22b9a2f44ae346380ee556a1092e344f2f22ef`
adds one production-linked Linux CTest,
`runtime.linux-connection-personal-clipboard-tls-write-denials`,
for the connection-owned R1/R2/R3 clipboard transport writer's missing
R2 lease, zero accepted bytes and revoked retry denial. R9 now runs
this as a **separate exact-one ASan/UBSan focused selection** with an
independent CI structure sentinel. The existing **87** clipboard
component-case, **two** native R5/R8 linkage, **two** R10 post-Share
executable-case and **40** runtime-security inventories remain fixed.
A negative, no-lease executable proves no functional clipboard exchange;
R10 still does not compose the native R8 source and outbound writer
in its live post-Share scheduler.

R7's macOS arm64 hosted GUI archive job at
[Actions 39140555244](https://github.com/k1moradi/RDP-server/actions/runs/39140555244)
now **PASSes** following signed-framework symlink closure correction,
including extracted app `codesign --verify --deep --strict`; the
previous broken extracted signature is no longer the active packaged-GUI
blocker. Real Finder/Aqua launch, production Developer ID/notarization
and owner-local macOS 27 remain **NOT RUN**. R10's correction
`e00593e86700d816ac6aa26f5abdefbd55821fe0` also repairs false
source-guard failures from wrapped native `::poll`/watcher calls.
Exact publication-SHA primary+structure workflows **PENDING**;
real Microsoft-client and native credential acceptance **NOT RUN**.

**R2 hosted CTest parser recovery (2026-10-18):** Exact SHA `549a12c0` GitHub Actions `39142229897` ran the Ubuntu full Debug CTest: 763/764 PASS, with only `security.linux-verified-account-pam-attempt-fence-source` failing at CMake line 65 because the newly authored source guard lacked `endif()` after checking the bound account-budget pointer. All dedicated R2 complete/missing-systemd production-security jobs PASS; no auth implementation failure was reported. The corrected source guard closes that single block without relaxing the verified-principal-before-PAM assertions; no runtime code changes, no positive provider or lease. Owner-local Debug/full CTest **NOT RUN**; exact correction SHA CI **PENDING**.

## R2 GSS-to-PAM account budget regression coverage (2026-10-18)

The earlier R2 `1aa476e5` wired real service-owned per-account
attempt reservations into the final GSS/PAM credential path.
The new ordinary offline CTest
`security.linux-verified-account-pam-attempt-fence-source` now guards
the production-source ordering: R2 GSS principal/local-account policy
match, fixed-memory reservation keyed only by verified GSS identity,
then PAM password verification. It additionally checks the existing
single service-owned peer/global budget reaches the acceptor only
after provisioning and is cleared on rejection. The test does not
invent positive GSS, TLS, OS lease, native desktop or client traffic;
it is distinct from executable-based binding/expiry cases and R9's
fixed sanitizer inventory. Local full Debug CTest **NOT RUN** because
the approved checkout is unavailable here; exact publication-SHA
hosted CI **PENDING**. This does not remove real-client/host-consent
or independent GUI-password blockers.

## R10 persistent-loop test-registry recovery (2026-10-18)

The first post-Share native-owner hosted Linux run compiled the production
`rdp-server` and passed the executable-backed protected single-reader and
classifier tests but failed two R10 source guards because the real multi-line
`::poll(nativePoll.data())` and logind retirement call were incorrectly
matched as single-line text. The correction requires the syscall plus its
exact pollfd array and checks watcher retirement after unregistration;
R5's stronger independent callback-order guard remains unchanged. R10
updates the existing two CTests, not the production runtime. Parent
`7c22b9a2f44ae346380ee556a1092e344f2f22ef`; local checkout build/full CTest **NOT RUN**, exact publication
CI **PENDING**. No seat0 admission or LAN GUI Start is inferred.

## R8 protected clipboard R1 write handoff (2026-10-18)

R10's persistent post-Share Linux scheduler at `4795c6dd` and its
`2a3f06b0` retirement correction resolved the former missing runtime
session lifetime. R8 now provides a still-dormant connection-local
`advancePersonalDesktopClipboardTlsWrite` step: it reborrows the current
R2-authorized R3 static-VC write, calls only R1's established TLS writer,
commits actual positive accepted-byte receipts through the existing R2/R3
gateway, retains SSL WANT direction, and fences an unfinished clipboard
TPKT against application reads and Graphics DATA publication. Zero/uncertain
receipts and revoked authority fail terminally. The new production-backed
`runtime.linux-connection-personal-clipboard-tls-write-denials` CTest
checks missing-lease denial and late retries without any synthetic admission.

This CTest uses only the distinct runtime/security label, not the fixed
**87** R8 clipboard component tests or R9's **two** dormant native-linkage
guards. `main.cpp` still deliberately denies the CLIPRDR route and does
not instantiate the X11 clipboard adapter: native publication remains
**disabled**. The next integration boundary is R10's serialized scheduler
selecting queued R8 writes, passing the exact R2-committed receipt to
`R3ClipboardTransferBridge`, and composing the R2-permitted native
X11 owner with terminal Stop/logout/INCR retirement. Real positive
partial-write/native evidence is still required before enabling clipboard.
Owner-local configure/build/full CTest: **NOT RUN**; hosted exact-commit
CI: **PENDING**; authorized physical-X11 Microsoft-client test: **NOT RUN**.

## R7 macOS signed framework ZIP-alias correction (2026-10-18)

**Observed real blocker:** on corrective R7 SHA
`48126b53ab3179b3362977be4e10703c2562f3bb`, native
macOS 26 arm64 job `117709147567` of
[Actions 39138933501](https://github.com/k1moradi/RDP-server/actions/runs/39138933501)
built the Qt app, passed package fixture and **all five R7 Qt offscreen
CTests (5/5 PASS)**, and passed the ZIP manifest plus extracted Mach-O
absolute-dependency audit. The new strict extracted-app
`codesign --verify --deep --strict` then **FAILED**:
`invalid Info.plist (plist or signature have been modified)` in
`Contents/Frameworks/QtDBus.framework`. This is a packaging integrity
failure, **not** R2/R10 admission and not a reason to weaken signing.

**Cause and correction:** the portable ZIP writer had been flattening
Qt framework symlink file aliases and silently dropping directory aliases
(`Versions/Current`, `Resources`). Even when the staged .app had been
ad-hoc signed, extraction no longer reproduced the signed framework layout.
R7 now preserves only in-bundle `Contents/Frameworks` version/dylib
symlinks, with resolved-regular-target and nonescaping validations;
the shared R9 PORTABLE-GUI verifier accepts those links **only for macOS**,
requires relative bounded targets, validates fully expanded destinations,
rejects cycles and files beneath symlink aliases, and keeps all other
archive symlinks forbidden. Extraction with `ditto -x -k` must restore
the same framework layout before the existing strict native signature
test. This makes no change to GUI authority, Startup, R2 admission,
R10 ownership, listener, TCC, ScreenCaptureKit or Quartz.

New ordinary dedicated CTests:
`packaging.macos-portable-gui-framework-alias-integrity-denials` and
`packaging.portable-gui-macos-framework-link-verifier-denials`.
Synthetic fixtures include valid `Versions/Current` and framework
binary/resources aliases, escape rejection, unresolved/cyclic aliases,
non-Mac symlink denial and aliased-entry write denial. Targeted local
Python/CMake/Qt execution **NOT RUN** (approved local checkout/macOS
toolchain unavailable in this connector environment). Exact new-head
hosted CI and extracted strict ad-hoc signature result **PENDING**;
normal Finder/Aqua double-click, quarantined Gatekeeper approval,
Developer ID signing, notarization and owner macOS 27 run **NOT RUN**.
Ad-hoc signing remains development-only.

**Dependency graph update:** R3 authenticated classifier is landed;
R10 `4795c6dd` and `2a3f06b0` now persist a single R1 TLS/R2 logind/
R5 XCB + R3/R4 first-frame/input scheduler **for Linux loopback CLI**,
not GUI Start/Stop. R10's concrete GUI LAN HostControl backend and
serialized macOS AppKit/session owner are absent; R2's credential-bound
revocable macOS UID lease is absent. Native macOS capture/input hosting
and positive Microsoft-client access remain **BLOCKED**, independent of
the now-addressed archive bug.

## R5 live post-Share X11 handoff and CI repair (2026-10-18)

R10 `4795c6ddb55f` landed the persistent R1 single-reader / R2-selected
X11/logind / R3-classified input scheduler and synchronous R5 XShm→R4→R3
first-frame borrow. R10 `2a3f06b039c9` corrected native poll retirement
and frame-borrow lifetime. This **resolves the R5/R10 production composition
dependency**, not the owner-approved real OS admission or Microsoft-client
acceptance gate. R5's earlier
`runtime.linux-r5-x11-authorized-event-service-denials` source CTest
continued to require a one-shot `nativeDispatch` local and a graceful
`disconnect()` before revocation; on `2a3f06b` Ubuntu Debug full CTest
it fails, even though the new loop correctly uses terminal no-XTEST input
retirement. R5 now scopes its guard to the persistent loop, requires R2
borrowed-watch unregister before bounded XCB drain, fresh R2 checks on
both sides, serialized R1 application intake, and synchronous R5 capture
borrow. New CTest
`runtime.linux-r5-persistent-x11-input-frame-borrow-order` additionally
pins R3-classified slow-path input through R5's R2 sink and current
ClearCodec frame callback. Both are *source contracts*, not synthetic
positive R2 admission. Owner checkout/full CTest: **NOT RUN** in this
connector runtime. Publication-SHA hosted CI: **PENDING**; latest
pre-correction full Ubuntu run `39139376815` fails three stale native
source-guard tests (one R5, two R10). R10 owns its two separate guards.
The remaining true blockers are live `RuntimeHostControl` Start/Stop,
approved X11 seat0/Kerberos/PAM/logind and physical Microsoft-client
video/input/ACK; R8 clipboard publication stays disabled separately.

## R7 CI workflow repair (2026-10-18)

The R7 GUI/status commit `6a94a5d2010f46e84c0358a3723bd2bca7d92a78`
was published atomically but its primary workflow did not parse. Standalone
structure run [39138747361](https://github.com/k1moradi/RDP-server/actions/runs/39138747361)
reported invalid YAML at line 1940: JavaScript string replacement interpreted
the shell test selector's literal `$'` as an unmatched-source suffix,
splicing trailing workflow content after the Linux GUI job. No Qt/macOS
test on that SHA may be claimed PASS. This correction reconstructs the full
workflow from clean parent `d268d27058c027f6fe95a9318dd409a70f51df56`, inserts the same offscreen CTest
and extracted-app ad-hoc-signature verification steps using callback-based
literal replacement, and leaves all other jobs intact. Exact corrective
SHA hosted structure, Qt, macOS packaging and ordinary CTest evidence:
**PENDING**. Normal Finder/Aqua double-click and notarization remain
**NOT RUN / BLOCKED**; R10 HostControl and R2 macOS UID lease still absent.

## R7 macOS packaging convergence and Qt interface/client UI (2026-10-18)

On exact descendant `495a3371aea5e780e00c2ac6303d3a2264b8a857`,
the hosted macOS 26 arm64 `r7-macos-portable-gui` job
`117703809743` in [Actions 39137118802](https://github.com/k1moradi/RDP-server/actions/runs/39137118802)
**PASSed**: real AppleClang 21/Qt 6.11.2 .app build, corrected
R9 synthetic install-ID CTest, `macdeployqt` Cocoa/framework deployment,
extracted Mach-O `otool -L` rejection of build-host absolute dependencies,
and final ad-hoc development signing. This closes the R7/R9 fixture and
staged install-ID packaging blocker. **Normal Finder/Aqua double-click,
Gatekeeper trust on a quarantined download, Developer ID signing and Apple
notarization remain NOT RUN/NOT COMPLETE**. Hosted macOS 26 arm64 is not
owner-native macOS 27 acceptance.

R7's shared Qt GUI now displays R10's actual stable interface ID/name and
address choices and R10's actual reported bound endpoint, never an
illustrative address or a claimed listener from the configured port. A
selected active R10 client can be submitted for disconnect by its opaque
current handle; neither the click nor a successful command result is
rendered as disconnection proof. The adapter fails Start before reaching
R10 when the credential, authorized desktop, TLS/native readiness or
exact stable-ID/address tuple is absent, and rejects stale/zero disconnect
handles. These are early view-layer denials; only future concrete R10
ownership and fresh R2/R1/R3/native checks can grant access. No second
state machine, socket reader/listener, clipboard owner, TCC request,
ScreenCaptureKit/Quartz factory or GUI password-NLA provider is added.

R10's current `RuntimeHostStatus` does **not** expose a verifiable TLS
SHA-256 fingerprint or a real client-trust state. The GUI accordingly
marks those details **not supplied** rather than deriving trust from
`tlsIdentityReady`. Independent app-password NLA remains unsupported.
Dedicated offscreen CTest
`gui.offscreen-r10-interface-endpoint-client-disconnect-denials`
checks duplicate-address stable IDs, fail-closed Start, real endpoint
projection, opaque client disconnect/stale denial and fixed redacted
error presentation. Authored on parent `d268d27058c027f6fe95a9318dd409a70f51df56`; this connector
environment has no mounted `~/rdp-server` checkout or Qt headers:
local C++ build/full CTest **NOT RUN**; new publication-SHA hosted CI
**PENDING**. R10 persistent session, live HostControl Start/Stop and
R2 credential-bound macOS UID + serialized AppKit/session ownership
remain **BLOCKED** before real macOS hosting or Microsoft-client tests.

# RDP-server roadmap — authoritative live status

**Reconciled:** 2026-10-17 · **Shared branch:** `main` · **Milestones accepted:** 0/6  
**Baseline inspected before this coordination update:** `8f3c2f06b305eca60708867c9e50f9a6a59a79cb`.  
**Decision:** **M1 OPEN / NOT ACCEPTED.** Hosted tests alone cannot satisfy owner-native acceptance.  
**Status vocabulary:** DONE = component delivered with specified evidence; READY = implementation ready for its next integration; BLOCKED = external/dependency gate; ACTIVE = one bounded increment in progress; NOT RUN = missing evidence.

This file is the **only active roadmap and cross-agent communication board**. It replaces the former chronological append-only progress diary. Earlier details are recoverable in Git history; exact test/CI evidence and historical failure diagnostics reside in `docs/CODEX_VALIDATION.md`. Do not add per-agent progress documents, repeat old reports, or append a dated section for each commit.

## R2 P0 standalone Microsoft CredSSP credential decision (2026-10-18)

**Decision: A, existing OS-backed accounts for first Linux/X11 acceptance; B, an independent GUI-password verifier, is BLOCKED.** This is a feasibility decision, not a claim that the complete product works. Neither `Configure password` nor `Start Sharing` may create an R2 lease or activate a LAN listener/Share. The new production `security/standalone_credential_policy.h` exposes a deny-only GUI credential-choice assessment, and `security.lan-credential-mode-denials` CTest verifies OS-account selection, unconfigured/unknown modes and independent-password refusal. Its `mayStartSharingFromCredentialChoice` predicate is always false: actual admission continues exclusively through the private R2 native broker. Do not use this predicate as a replacement for that broker.

**Mechanism feasibility and non-goals.** Microsoft MS-CSSP uses TLS, SPNEGO with Kerberos or NTLM, TLS public-key binding and delegated credentials; a salted application password hash alone cannot answer an NTLMv2 challenge nor provide Kerberos tickets. Kerberos requires an independently accessible KDC/ticket/service key; an offline LAN with no configured realm does not have that infrastructure. Windows SSPI offers Kerberos/NTLM/Negotiate; Linux MIT/Heimdal GSS offer Kerberos and optional `gss-ntlmssp`/Samba integration; macOS GSS supports Kerberos, but an equivalent first-party NTLM server acceptor and client negotiation cannot be assumed. `gss-ntlmssp` can use a password file or winbind credentials, but this introduces plaintext/NTLM-equivalent reusable verifier material and a mechanism-specific security audit. Windows clients may reject NTLM under policy (including NTLM block policies); Windows App behavior on Windows/macOS is not verified. Do not fall back to TLS-only RDP, change client policies, claim a generic SPNEGO application-password OID is supported, or implement a proprietary login exchange. Sources: MS-CSSP, Microsoft Credential Security Support Provider/NTLM policy, gssapi/gss-ntlmssp.

**Executable feasibility ladder, with pass criteria per client.** (1) Linux opt-in isolated machine with physical logged-in X11 `seat0` owner: configure the already-existing explicit `TERMSRV/host@REALM` keytab, corresponding account-to-UID mapping and dedicated PAM service (not an unreviewed GUI password store); retain no GUI copy of delegated credentials. Offline means no internet, not necessarily no LAN KDC; verify KDC availability, otherwise mark Kerberos **BLOCKED**. (2) Run an isolated NTLMv2 acceptor spike **without** desktop/Share, using approved real credential backend, inspect GSS flags, binding/replay/session-security properties and secure verifier storage; any dependency on plaintext/NT hash requires security design review, not promotion. (3) For each Windows 11 `mstsc.exe`, Windows App Windows, Windows App macOS, record actual version/build, client policy, X.224 HYBRID, TLS certificate and first-use trust, SPNEGO selected OID, MIC/channel/public-key binding, delegated identity, failure code and packet trace ID; test Kerberos and NTLM distinctly, reject fallback. All client outcomes **NOT RUN**. (4) Only after actual complete credentials and fresh logind/NSS physical-owner consent may the existing broker mint its nonfabricable lease, then R10/R3 admit Share.

**GUI lifecycle contract.** OS-account mode selects an existing real account, never changes the OS password, uses the client's own standard credential prompt and platform keychain only if explicitly requested by the client. Configure/replace/revoke access updates an R2 policy generation; revocation retires every old lease, pending handshake and R3/desktop/input capability before renewed use. Explicit host-user consent must be per live owner session and bound to UID, seat/session ID, logind generation, unlocked/active status, and approved view/control permissions; owner logout/switch/lock, password/account disabling, policy replacement, or TLS listener identity change causes termination and fresh consent. A configured OS account does not prove physical ownership. Require bounded failed-attempt throttling per peer **and** account with global overload protection (avoid account-enumeration and memory exhaustion); maintain fixed-size/expired attempt slots and generic wire denials. Audit only status/trace, never passwords, hashes, NT responses, authInfo, tickets or bearer capabilities. GUI distinctions: `CREDENTIAL_NOT_CONFIGURED`, `UNSUPPORTED_APPLICATION_PASSWORD_NLA`, `OS_CREDENTIAL_PROVIDER_UNAVAILABLE`, `OS_AUTHENTICATION_FAILED`, `HOST_CONSENT_REQUIRED`, `HOST_SESSION_STALE`, `ACCESS_REVOKED`, `AUTH_RATE_LIMITED`, `TLS_IDENTITY_UNTRUSTED`; external authentication failures must not disclose account existence. After termination, reauthorization reruns the whole OS and transport evidence chain. Offline account verification needs an actually available OS/PAM provider and compatible Kerberos/NTLM mechanism; availability is not implied by ZIP extraction.

**TLS identity UX.** R1 owns certificate generation/persistence and configured LAN interface binding. Before client connection, GUI must show hostname/IP, certificate SHA-256 fingerprint, validity window, persistence/rotation status and whether a trusted chain exists. On first use, the native Microsoft client must show its genuine certificate warning/trust path; never auto-accept, bypass pinning or promise that all clients support in-app TOFU. Certificate rotation requires fresh user confirmation and invalidates relevant policy/transport generations.

**Future providers (not first release).** Windows: native SSPI acceptor + authenticated token SID, WTS session ID, active console owner and secure desktop/lock state, explicit user consent, logon-session revocation and ACL-backed policy, without confusing SID lookup with authenticated login. macOS: genuinely authenticated local UID, audited authorization/login provider plus console session owner, ScreenCaptureKit/TCC permissions, lock/switch revocation and keychain; do not infer authentication from username or GUI checkbox. Both require independent native R2 admission implementations and real clients. Test matrix: incorrect password, nonexistent account, no owner consent, locked/switched/stale session, replay/changed TLS identity, permission loss, revocation after Share and late input; every failure must prevent a visible frame and input. **No positive native-client result is claimed.**

**Current evidence:** source/CTest authored; local Debug build/CTest **NOT RUN** (no approved local checkout); exact publication-SHA hosted CI **PENDING**, live Windows/macOS clients **NOT RUN**. **Next gate:** R2/R10 integrate a truly authenticated OS provider and host-owner consent into start/stop + R3, then record three independent client results. Keep independent GUI password mode Start Sharing **BLOCKED** until fully reviewed interoperable verification and genuine OS authorization are demonstrated.

**R2 GSS-verified account attempt fence (2026-10-18):** The Linux
serialized serve owner now passes its existing service-lifetime
`AuthenticationAttemptLimiter` through the concrete R1/R2 connection
into the provisioned GSS acceptor before peer intake. After genuine
GSS authentication, CredSSP public-key/TLS binding and R2 identity
policy match of the decrypted delegated local account, the final
visitor reserves exactly one verified-principal attempt **before PAM**.
An exhausted per-account budget causes generic terminal rejection
without PAM, native admission or Share. It never charges caller-claimed
names or logs identity/secret material. One-shot budget binding is
cleared on GSS teardown. New Linux/PAM production-backed offline CTest
`runtime.linux-connection-verified-account-attempt-limiter-binding-denials`
tests real keytab service provisioning, duplicate-bind revocation and
no charge on unauthenticated TLS-absent input. Local full CTest
**NOT RUN** (approved checkout/GitHub DNS unavailable); exact-SHA
hosted CI **PENDING**. No owner-client success or application-password
interoperability is implied.

**R2 NLA attempt-abuse boundary (2026-10-18):** R2's fixed-capacity
`AuthenticationAttemptLimiter` now reserves a peer/global budget before
the serialized Linux serve callback constructs R1 TLS or GSS. Only exact
validated 4-byte IPv4 or 16-byte IPv6 addresses are accepted; the one
service-lifetime table has 64 peer slots, 8 attempts per peer and 128
successful reservations globally per 60-second monotonic window. A full
unexpired table and regressing clock fail closed; no network/OS/token
side effects or identity-bearing diagnostics. Separately, the same
policy offers an eight-attempt, 64-account gate that MUST receive only a
provider-verified GSS principal, never untrusted client account text.
The account gate was initially an unwired API at `1cebf889`;
`1aa476e5` now binds and charges the GSS-verified principal immediately
before PAM. Positive owner/client verification remains **NOT RUN**.
Dedicated cross-platform offline CTest
`security.bounded-peer-global-and-account-attempts` covers per-peer,
global, account, expiry, table exhaustion, invalid input and backward
time without creating a lease. Local full configure/CTest **NOT RUN**
(no approved checkout and GitHub DNS blocked in the tool container);
hosted exact-publication-SHA CI **PENDING**. This does not enable
independent GUI passwords, native admission, or real Microsoft clients.

**R2 access-policy lifecycle follow-up (2026-10-18):** R10's typed host-control request seam is now present, so the OS-backed first-release path can safely support GUI-driven **set/change/revoke of the authorized identity mapping** without introducing a password store. R2 replacement/revocation changes only the service-owned identity policy generation; it neither modifies the user's OS password nor grants host consent. Existing per-connection acceptors/leases become stale through their captured generation, and revocation prevents configuring a new acceptor until a valid mapping is installed again. Live Start remains blocked on R10's concrete backend, authenticated Share/native-owner composition and owner-authorized client testing.

**R6 Windows GUI (2026-10-18):** Windows portable packaging is now **HOSTED-GREEN**. R6 `ab63d1bbeb41e19dc447dfde4cb7c1e0260da3b1` added recursive non-system DLL staging after `windeployqt`; R9 `f8e4d056f89626f38fc611168e9ad063c4fcdf16` corrected Windows system-DLL classification; R6 `199887cdd79a0a5e5386f2f178647146ae584396` aligned hidden offline modes with the packaged `qwindows` platform. Exact descendant `aaff05a91d4b903dbf7d7469247d6ad9225a76b4`, primary run `39131193194`, Windows job `117686690036`: Debug **641/641**, Release **641/641**, R6 native preflight **59/59** in both configurations, `PORTABLE-GUI archive structure PASS`, `Windows PE closure PASS: 41 images, 571 imports inspected`, extracted deny-only + normal first-screen/no-socket/rerun/firewall smoke **PASS**, and sanitizer R6 native selector **59/59**. Current-head exact CI may still be pending because later commits are unrelated Linux/macOS/docs work; do not infer a current-head aggregate PASS from this descendant evidence. **Native hosting remains BLOCKED:** current `main` still has only observational `windows_native_session_evidence.*`; no Windows SSPI/CredSSP authenticated-SID admission provider and no concrete R10 Windows interactive-session/`RuntimeHostControl` owner exist. Start remains fail-closed until R2 issues a revocable SID + exact physical-console WTS/LUID/logon-time lease and R10 serializes WTS lifetime/revocation with fresh authorization before every R6 DXGI borrow and SendInput.

## Milestone gates

| Gate | Status | Acceptance condition / blocking dependency |
| --- | --- | --- |
| **M1 — build and portable/native test foundation** | **OPEN** | One nominated SHA with full hosted CI **and** full owner-local Debug configure/build/CTest receipts on Linux/X11, Windows MSYS2 CLANG64/Clang 23, and macOS **27**. All owner receipts must name that identical SHA. |
| **M2 — genuine authenticated personal desktop + Share** | **OPEN / BLOCKED** | Real R2 authenticated native desktop admission, authenticated Share/finalization and real Windows App / Windows 11 mstsc.exe acceptance. The selected personal-desktop mode has no RD Licensing CAL gate. |
| **M3 — interactive Linux desktop** | **OPEN / BLOCKED** | M2 + admitted R5 X11 capture/input through R4/R3 + resize, reconnect and revocation acceptance. |
| **M4 — interactive Windows desktop** | **OPEN / BLOCKED** | M2 + admitted R6 DXGI/SendInput/WTS routing + real-client acceptance. |
| **M5 — interactive macOS desktop** | **OPEN / BLOCKED** | M2 + admitted R7 ScreenCaptureKit/input/TCC/session routing + real-client acceptance. |
| **M6 — release/service** | **OPEN / BLOCKED** | Real service/listener controls, packaging/operational hardening, measurable performance, security, soak and release acceptance. |

### M2 personal-desktop live-client compatibility matrix

This matrix is **separate from M1 foundation acceptance**. M1 requires the same-SHA owner build/CTest receipts below; no live-client cell substitutes for them. Each M2 client is recorded independently through negotiation, NLA, licensing, Share activation, desktop publication, input, disconnect and reconnect. A test-only licensing provider or licensing-mode fixture is never desktop authority: positive Share/desktop/input requires the real private R2 admission path, and any personal-mode implementation must retain explicit wrong-mode and malformed-license-packet denials.

Capture the **exact server SHA**, test timestamp, installed **client OS build** and **client app/build** for each session; link packet logs/screenshots by trace ID without retaining credentials. Mark each protocol and desktop stage independently **PASS / FAIL / BLOCKED / NOT RUN**; never infer later stages from earlier ones. Record the first failing protocol boundary and its observed diagnostic, including logout versus transport disconnect. No client versions or outcomes are yet verified.

| Client | Installed OS build | Installed client build | X.224 | TLS | CredSSP/NLA | MCS (Erect/Attach/Join/Info) | Personal licensing | Share | Graphics capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Windows 11 `mstsc.exe` | NOT RECORDED | NOT RECORDED | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Windows App on Windows | NOT RECORDED | NOT RECORDED | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Windows App on macOS | NOT RECORDED | NOT RECORDED | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

| Client | Visible frame | Keyboard/pointer input | Logout | Reconnect | First failure boundary / reason | Server SHA, UTC time, trace |
| --- | --- | --- | --- | --- | --- | --- |
| Windows 11 `mstsc.exe` | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RECORDED | NOT RECORDED |
| Windows App on Windows | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RECORDED | NOT RECORDED |
| Windows App on macOS | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RECORDED | NOT RECORDED |

At starting head `8d980a202eafeefd958213f65344e955ce1b2415`, no personal-mode licensing CTest is registered on `main`; R9 therefore records that gate as **NOT PRESENT / NOT VERIFIED**, not PASS or FAIL. When that road lands, a positive licensing fixture must still terminate before Share/desktop without genuine R2 admission and must include wrong-mode plus malformed-packet denials.

This R3 publication now registers six production-backed protocol-mechanics CTests for exact Valid Client completion, presented-CAL/no-CAL personal flows, wrong-mode/malformed denial, duplicate/partial-write retirement and Share finalization ordering. They deliberately do not construct a production R2 lease; live positive advancement remains private to the broker contract in the R3 row.

**R9 P0 integration denial matrix:** primitive/offline fixtures support these
boundaries but do not accept a live desktop. Once a genuine R2/R10/R3 positive
chain exists, one production-backed integration selection must keep all rows
fail-closed.

| Boundary | Current evidence | Still required of live composition |
| --- | --- | --- |
| No R2 admission | R2 personal-runtime denial fixture | No personal licensing, Share, DVC, graphics or input |
| Wrong PersonalDesktop mode | R10 policy + R3 wrong-mode/malformed licensing | AppServer/unconfigured mode cannot select personal flow |
| Wrong TLS owner | R1/R2 HYBRID provenance and protected-transition fences | Stale/different R1 owner rejects transition/receipt |
| Stale native session | R2 generation/logind revocation fences | Logout/replacement is terminal before later progress |
| Lost Share | R3 Share denials | DVC/graphics/input unavailable after Share retirement |
| Missing Graphics DVC | R3 pre-Share DVC denial | Visible graphics impossible before exact created Graphics DVC |
| Canceled write | R1/R3 receipt cancellation; DVC generation/cancellation | Late/stale receipt cannot complete licensing, Share or DVC |
| Stale DVC ID | R3 wrong-ID + generation/cancellation denials | Retired/reused DVC identity cannot authorize graphics/input |
| Late client input | R5/R7 authority-loss no-native-post primitives | Post-R2/native/Share/DVC input never reaches native injection |

## P0 — M1 exact-SHA convergence

**Last independently checked full-green hosted SHA:** `9902199f4f09a1e8bceb9de71025414c52f10e2d`: [primary Actions 39114811432](https://github.com/k1moradi/RDP-server/actions/runs/39114811432) and [structure Actions 39114811442](https://github.com/k1moradi/RDP-server/actions/runs/39114811442) **PASS**. This descendant keeps R8 clipboard 87/87, R3 CLIPRDR 9/9, the executable-backed direct R10 runtime-security selector 38/38 and the preserved R4/R5/R6/R7 inventories green while also passing R2's new `runtime.linux-connection-protected-read-generation-denials` in ordinary full CTest. R9 found that source-level regression was absent from the focused assurance job and adds a separate exact-one sentinel without changing the meaning of the 38-case sanitizer count. All three startup-disabled exact-SHA SERVER-TEST previews and aggregate pass. This remains evidence only, **not** an M1 nomination: R10 has not requested the short coordinated freeze and all three owner-native same-SHA Debug receipts remain missing.

**Next candidate: NOT YET NOMINATED.** After this coordination commit has its own complete green hosted Actions and structure guard, R10 records its *literal* SHA and workflow link in this existing M1 section, announces the same SHA through Git, and requests a **short coordinated publication freeze**. No unrelated implementation or documentation-only receipts are published during the owner validation window. An urgent defect fix may supersede the candidate, but then **all three** owner receipts must target the new green SHA; never combine SHAs. The freeze must end after an explicit M1 decision or an owner-assigned failure, not silently remain indefinite.

| Owner-native evidence required | Status | Responsible coordination |
| --- | --- | --- |
| Linux/X11: native OS, compiler, Debug configure/build and complete CTest totals, failed/skipped/not-run | **NOT VERIFIED** | R5 + R10; R1/R2 assist on transport/security failures |
| Windows MSYS2 **CLANG64 / Clang 23**: effective compiler and exact complete Debug CTest receipt | **NOT VERIFIED** | R6 + R10; R9 verifies toolchain/selector |
| macOS **27**: `sw_vers`, Xcode, `xcrun clang++`, effective AppleClang and complete Debug CTest receipt | **NOT VERIFIED** | R7 + R10; R1 assists on native sockets |
| Exact same SHA and complete hosted CI | **OPEN** | R9 independently reviews, R10 records final M1 decision |

The owner runs the unchanged required command from `AGENTS.md` in the approved platform/toolchain shell, using only the persistent `~/rdp-server/build/`:
```sh
cd ~/rdp-server
git switch main
git pull --ff-only origin main
git rev-parse HEAD                 # must equal R10's literal nominated SHA
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --config Debug --parallel 2
ctest --test-dir build -C Debug --output-on-failure
```
Also record the effective native OS/compiler/configure identity, full test totals, failures and skipped/not-run counts. macOS must be **major version 27**; Windows must actually use **MSYS2 CLANG64 / Clang 23**. Never turn hosted macOS 26, synthetic Xvfb/DXGI fixtures, or an owner's informal “tests pass” into owner-native receipts. No opt-in real credentials, screen/input, service or listener is enabled by M1.

**Failure ownership:** R1 socket/TLS; R2 Kerberos/PAM/admission; R3 protocol/licensing; R4 encode/graphics; R5 Linux X11; R6 Windows native; R7 Apple native; R8 clipboard; R9 CI/registry/sanitizers; R10 runtime/config and coordination. Assign by first failing boundary rather than the commit that happened to trigger CI.

### R8 / R3 / R10 post-Share CLIPRDR handoff (P2, Share/native construction resolved; live publication blocked on persistent R10 app loop)

**R8 fail-closed GUI state follow-up (2026-10-18; source parent `7044183db5a12d637bbb432d035a582224d12792`):** R7 now projects R10's typed `RuntimeHostControl` status through a thin GUI adapter, so the previously blocked status-only R8 increment can proceed without creating a second authority owner. `RuntimeClipboardState` defines `Unavailable`, `Enabled`, `Retired` and `Denied` as descriptive status only. `Enabled` may be reported only by the future live R10 owner after fresh R2 authorization, genuine `ShareActivated`, the exact joined `cliprdr` route and current native clipboard owner; no GUI checkbox or preference can set it. The GUI renders all four states with fixed redacted text, while `runtime.host-control-clipboard-state-denials` proves the production deny-only facade remains `Unavailable` across rejected start/stop/revoke. The Qt offscreen fixture renders all four states without fabricating an R2 lease or touching native clipboard APIs. **Local build/CTest: NOT RUN** (no approved local checkout in this connector environment); exact publication-SHA hosted CI: **PENDING**. The former Share blocker is now **RESOLVED** by R10 `5e164e46258487b712d63bc091fa54f82a78c789`, and R10 `0257b57f862b4c7965605ac362f1d6b5306abd81` continues through post-Share Graphics DVC control. R10 `e6fa65c475b9d322984e34bd6b4cd5ec90cd1126` has since resolved that construction blocker by creating the R2-selected X11 owner and borrowed native-change watch. Live R8 publication remains **BLOCKED** because the owner is kept for only one bounded poll cycle, then disconnected/revoked; there is still no persistent post-Share application loop or native clipboard owner in which CLIPRDR ingress, outbound TLS receipts and X11 selection events can coexist.

**R8 production-linkage readiness (2026-10-18; parent `9d48ca00a42f0fefa6a6a82ffa8b78a5ffed680b`):** R10's fail-closed protected-input linkage pattern removes the remaining build-graph-only gap for R8. The production `rdp-server` target now conditionally links both the existing `rdp-server-r8-r3-clipboard` bridge and `rdp-server-linux-x11-clipboard` adapter only when Linux runtime security, the sole X11 desktop aggregate and native clipboard target are present; `RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD` reports build availability only. New offline `runtime.linux-x11-clipboard-production-linkage` requires those dependencies while forbidding any `main.cpp` construction or protected clipboard dispatch. It is a source/build linkage guard rather than a component sanitizer case, so it uses a separate `native-linkage` label and does not change the fixed 87-test R8 `clipboard` inventory. This creates no R2 lease, no CLIPRDR advertisement, no native publication and no scheduler. Live integration remains blocked on the same persistent R10 post-Share R1/TLS router and X11/logind lifetime.

**R8 integration follow-up (2026-10-18; parent `eba62f48584da008595844fe5d6fbcd8b7f83c89`):** R3's authenticated post-Share route and R2 broker gateways now satisfy the R8 dependency: exact joined `cliprdr` role, nonzero process-wide R3 route generation, bounded static-VC reassembly, whole-PDU callback, outbound R3 receipt identity and fresh R2 checks on visit/dispatch/queue/pending/completion. R8 therefore adds a noninstalled `R3ClipboardTransferBridge` that consumes only those surfaces. It never accepts `authenticatedOsSessionAdmitted`, never parses MCS/static-VC chunks, and never mints a channel generation. Five offline CTests cover source/request/receipt handoff, no activated route, stale route generation, positive-partial receipt retirement/reconnect and FileContents request/receipt. The prior Win32 callback-retirement test is corrected to preserve `sourceEpoch` at retirement and require advancement only on the replacement offer. R8's focused bridge inventory remains **87**. Genuine Demand Active/Share activation and R2-selected X11 construction are now composed by R10. This follow-up (source parent `5103e8524943309d7f6fa382dbf26c21e3cca9df`) adds the five connection-local R2/R3 clipboard gateways to `LinuxRuntimeConnection`: visit route, dispatch complete TPKT, queue application PDU, borrow pending write and commit exact accepted-byte receipt. They perform no TLS I/O or native publication and remain denial-only without the genuine lease/policy lifetime. Dedicated `runtime.linux-connection-personal-desktop-clipboard-gateway-denials` is enrolled in the direct runtime-security sanitizer selector, expanding it **38→39**. Local build/CTest: **NOT RUN** in this connector environment; publication-SHA hosted CI: **PENDING**. Runtime/native clipboard publication remains disabled pending R10's persistent post-Share application loop and one native clipboard owner.


**R3 validation follow-up (2026-10-18):** Exact-head `d85f4030` passed all **9/9** R3 CLIPRDR CTests on hosted Ubuntu. Its full Ubuntu/macOS suites remained red only at R8's Windows clipboard mid-callback retirement assertion. The R9 sanitizer job additionally caught an R3 test-label ownership mistake: eight `transport.cliprdr-*` cases were counted in R8's generic clipboard inventory (82→90). The R8 integration descendant relabels those tests `r3-cliprdr` so the R3-focused sanitizer gate cannot match R8's generic `clipboard` label. R3's former production dependency on R10 Share composition is now resolved by `5e164e46258487b712d63bc091fa54f82a78c789`; the remaining live R8 dependency is construction of a current native clipboard owner on that same R2/R3 lifetime.

**R3 CLIPRDR normative follow-up (2026-10-18):** R3 now ignores client-to-server SUSPEND/RESUME and peer SHADOW_PERSISTENT control bits per MS-RDPBCGR while still denying unknown/compressed flags, and uses a process-wide overflow-safe R3 atomic route generation so reused static channel numbers across reconnects do not resurrect old R8 source epochs. Nine offline CTests are registered, including ignored-flag handling; full exact-head PASS remains PENDING. Header-corrected `d81bcff7` compiled on hosted Linux and passed 8/8 R3 clipboard tests; its full Linux and macOS suites were still RED solely at the newly added R8 Windows clipboard callback-retirement test, independently owned by R8. R10 now composes the MCS/Share path through `ShareActivated`; physical-seat0 native-owner composition is still absent, so runtime clipboard/FileContents remains disabled.

**R3 CLIPRDR boundary authored (2026-10-18; base `9f2ef97f`, publication verification pending):** The noninstalled R3 `RdpClipboardStaticChannelRoute` now provides bounded uncompressed CHANNEL_PDU_HEADER FIRST/MIDDLE/LAST reassembly, exact decoded PDU handoff, and MCS SendDataIndication TPKT chunking with monotonic R3 route/write-slice generations. The production route is **private to `McsSessionLifecycle`** and can be reached only through `LinuxConsoleAdmissionBroker` methods that revalidate the concrete lease, exact R1 HYBRID provenance, PersonalDesktop policy, activated Share, complete configured joins, exact `cliprdr` role and clipboard permission. Null leases deny; fixture codec starts are syntax-only and never mint R2 OS admission. Broker APIs for R8: `visitR3PersonalDesktopClipboardChannel` (ephemeral channel/generation), `dispatchR3PersonalDesktopClipboardTpkt` (complete PDU callback only), `queueR3PersonalDesktopClipboardPdu`, `pendingR3PersonalDesktopClipboardWrite`, and `completeR3PersonalDesktopClipboardWrite` (exact R1-accepted positive plaintext bytes, not network ACK). Every borrow and receipt gets a fresh R2 check. Terminal partial/late receipts erase the pending packet; old generations cannot restart or publish. No R10 service-loop change and **runtime CLIPRDR/FileContents remains unadvertised and disabled**. Dedicated offline CTests exercise fragment ordering, role-channel mismatch/compression, overflow, generation replacement, partial/full/stale receipts, terminal abort, and unadmitted pre-Share denial. **Authoring verification: local build/CTest NOT RUN (checkout unavailable in this execution environment), hosted exact-head CI PENDING; owner native and live positive R2/Windows App validation NOT RUN/BLOCKED.** R8 may consume this API in offline production-code integration now. R10 has since reached a genuine R2-authorized `ShareActivated` lifetime; runtime/native publication still requires the serialized owner to construct the R2-selected native clipboard owner and bind its retirement to the current route/source generations.


**Deployment contract (R10/R9):** Human-test server bundles and runtime configuration
must expose **no clipboard or FileContents capability** until the complete
real R2 admission → R3 `ShareActivated` → R3 authenticated static-channel
route exists. A user-visible clipboard enable flag is a *preference*, never
channel authority; it cannot override absent admission, Share, confirmed join,
wrong static-channel role or missing/noncurrent generation. Do not advertise
CLIPRDR, ingest clipboard payloads, send clipboard/FileContents traffic, or
publish local text/image/file clipboard on this incomplete route. R9 must keep
a fail-closed default-off deployment/configuration test and distinguish package
presence from an activated channel. This is a required gate, **not yet verified
by a live installed bundle**; existing R8 component sanitizer tests only establish
clipboard component protections.

**Required R3 private visitor:** After an actual R2 policy-bound lease and
`ShareActivated`, R3 alone resolves the negotiated static `cliprdr` role,
verifies its exact confirmed MCS channel join and issues its **nonzero,
R3-owned static-channel generation**, bound to the current R3 admission,
connection/session and Share lifetime. Only R3's private, revocable visitor
may loan this tuple to R8; R8 never creates, increments, guesses or persists
channel authority. Revalidate the exact role, join, session and channel
generation and R2 lease for each inbound PDU, outbound borrow/accepted-byte
receipt, FileContents request/receipt and native clipboard publication; wrong
role, zero/stale generation, missing Share, disconnect, revocation or reconnect
retires the prior R8 source/request/stream and native-ready state *before*
replacement. A source epoch is a freshness fence, not proof of authorization.

**Transport boundary:** R3 alone handles the entire bounded MCS SendData /
negotiated static-virtual-channel chunk stream, including total-length,
FIRST/LAST ordering, permitted flags, size/overflow limits and complete
reassembly. R8 receives exactly **one complete CLIPRDR PDU** only after R3
validates that framing; R8 adds no parallel transport parser, scheduler or
chunk assembler. R3 owns the outbound static-VC/MCS/TPKT envelope, wire-slice
lifetime and mapping of R1 plaintext accepted bytes into exact full-PDU
receipts; a partial or late receipt can never commit R8 publication after
retirement.

**Post-dependency R8 integration:** The source/request/FileContents/receipt bridge is now authored against the private R2/R3 visitor, whole-PDU sink and exact write views. It requires a current route observation before inbound source/request work; a stale/mismatched route retires R8, and only an R2/R3 `Delivered` write permits the corresponding response. R3 retains wrong-role/missing-Share/static-VC framing ownership; existing R8 native adapter tests retain no-publication-after-retirement coverage. R10 now supplies the genuine activated lifetime; runtime text/image/file publication remains intentionally uncomposed until the same serialized owner constructs a current native clipboard owner and can retire it before route replacement or revocation. Preserve the
existing descriptor maximum **64**, hierarchy depth **16**, validated
safe-relative names, exact descriptor index/generation and terminal source
epoch protection for INCR, delayed formats, native file destinations and
FileContents. Remote relative names confer **no filesystem capability**;
native directory-tree materialization remains unsupported without separately
reviewed safe handle-relative destination creation. No second clipboard
scheduler, user-selected authorization Boolean or premature OS selection.
**Next gate:** Share and R2-selected X11 construction are complete, and the connection-local R2/R3 clipboard gateway seam is now present. R10 must keep that X11 owner plus borrowed logind registration alive in the serialized post-Share application loop so R1 can demultiplex complete TPKTs and drive exact outbound TLS accepted-byte receipts without a second scheduler. Only then may R8 construct one `X11ClipboardAdapter` on the borrowed XCB connection, bind the existing bridge through these five gateways, reauthorize before every native publication/late receipt, and retire bridge/native state before R3 route replacement. Until that persistent loop exists, CLIPRDR/FileContents stays unadvertised and native publication stays off. Clipboard is **not** a blocker for the first video/input Microsoft-client test.

**R5 packaging P0 (2026-10-17):** Added a Linux test ZIP generator/installer for the actual existing `rdp-server` executable, manifest version/source SHA and file SHA-256, disabled `systemd --user` graphical-session-only unit, private example config and dedicated offline `packaging.linux-user-bundle-offline-lifecycle` CTest (install/verify/tamper/uninstall/symlink denials). **Canonical owner build/CTest NOT RUN**; hosted publication SHA **NOT RUN / pending**. R9's common SERVER-TEST path now verifies the built executable dependency closure, ABI and artifact SHA automatically; exact publication-SHA hosted evidence remains PENDING. SDK untouched. Live **M3 BLOCKED** on R10 sole admitted X11 owner + real `serve`, R3 graphics DATA receipts/input, owner-approved authentic seat0 Kerberos/PAM/NSS/logind/TLS and all three Microsoft-client receipts. See [Linux bundle contract](linux_server_test_bundle.md).

**R9 first hosted failure (2026-10-17):** Exact SHA
`4a42e7e32dcaa1db8999b3210ed426cbaf17fe6a` passed structure,
documentation, R9 sanitizer and R7 focused gates, and the new portable
SERVER-TEST contract CTest. All three ordinary Debug full CTests plus R6
CLANG64 stopped on R7's message-only negative assertion
(diagnostic wording drift within the same fail-closed `unsupported bundle` rejection) before
SERVER-TEST Release packaging. The assertion is corrected without changing R7
production behavior. Thus that SHA has **no server bundle acceptance receipt**;
next exact-head hosted CI must produce the three disabled previews and aggregate
same-SHA status before R9 can call the preview pipeline green.

**R9 SERVER-TEST packaging P0 (2026-10-17):** The ordinary three-OS
Release matrix now emits a distinct startup-disabled
`rdp-server-test-<version>-<platform>-<architecture>-<short-sha>` ZIP from
the actual `rdp-server` executable and never from the protocol SDK package.
Manifest/checksum/compiler/ABI/dependency/license/config/lifecycle evidence and
real extracted-binary smoke are mandatory; an aggregate job requires Linux,
Windows and macOS statuses to carry the same exact SHA. Linux consumes R5's
disabled service template and paths; R6/R7 remain extraction-only because no
authorized native serving service exists. The existing R7 protocol-only bundle
stays separate. Hosted publication-SHA acceptance is **PENDING**: `ef0feac1` produced
green Linux/macOS executable previews but Windows correctly failed before
artifact creation while R9 tightened the OS-owned runtime dependency boundary.
RUNNABLE publishing remains blocked on R10 startup plus exact-head green CI and
explicit owner acceptance. M1 owner-native and M2 three-client receipts remain separate.

## Parallel R1–R10 work board

Each row has **one active next action**, one code owner and a concrete dependent road; edit the existing row when state changes. DONE here never implies milestone acceptance.

| Road / domain | Verified component state | Next action and dependency |
| --- | --- | --- |
| **R1 · TCP/TLS/X.224** | **ACTIVE / LAN listener and accepted-socket transport hosted-green; live host-control integration blocked on R10 backend.** R10 `10baf2c1` transfers the move-only accepted loopback socket into one `LinuxRuntimeConnection`, borrowing only the exact R1 descriptor for bounded readiness. R1 `25991580` extends `runtime.linux-connection-pre-admission-native-poll` over real HYBRID TLS and rejected encrypted CredSSP; R2 `4c47b268` enrolled native-poll and deadline revocation, and R2 `46405df8` now adds Connect Response no-lease/terminal denial to the 31-case direct sanitizer selector. Linux-only `transport.tcp-owned-tls-application-tcp-rst-terminal` covers real pending read/write reset, native POLLERR termination and already-decrypted plaintext revocation (`024b879a`, `4704121e`). R9 repair `4655f062` restores the exact-one-test R1 TCP-reset sanitizer sentinel after malformed `44fff0de`; neither commit is PASS evidence until the repaired descendant executes. R10 `b7f0ab66` publishes R3's exact Connect Response suffix solely through R1 TLS after genuine R2 lease; R1 WANT direction overrides POLLOUT on pending writes, with R2 checking positive receipts before R3 advances. Existing real-loopback `transport.tcp-owned-r3-connect-response-slice` proves positive 1 KiB suffix/sequence and WANT retry identity as non-authorizing transport coverage. Existing close_notify/EOF cases remain; R10 scheduler correction `76813ac4` is landed, not an open defect. **No new hosted PASS is claimed until this descendant executes.**  LAN binding increment: `transport/lan_listener.h/.cpp` offers explicit-interface numeric-address non-wildcard TCP listening without accepting, owning SSL, or authenticating peers. R10 GUI consent, SAN/fingerprint coordination and owner-native validation remain BLOCKED; this is not live LAN acceptance. R1 corrective `dfc69f48` is hosted-green across Linux/macOS/Windows; Linux Debug/Release report `702/702`, including the LAN listener, native-poll and TCP-RST selectors, with Windows/macOS listener CTests also PASS. `c9362721` adds exact validated interface identity, fixed redacted GUI errors and production IPv6 bind/scope coverage when the host owns a real eligible ULA/link-local address. Its R1 listener CTest PASSes on Linux, macOS and Windows; the overall `c9362721` primary run failed only in the unrelated R5 GUI packaging assertion later repaired by R9. Owner-native interface-removal/live-client validation remains NOT RUN. | **Next R1 action:** R1 has now audited the landed Erect Domain, Attach User/Confirm, Channel Join/Confirm, Client Info and the new R3 production Demand Active/Share writer path: WANT direction, accepted-byte suffix accounting, R2 receipt reauthorization, terminal teardown and late-event denial remain consistent with the sole R1 SSL/BIO owner. No additional R1 transport defect is demonstrated. R1 `40e2cab0` now exposes a fail-closed TLS endpoint-identity check requiring numeric IP SAN or DNS SAN (no CN fallback) plus the SHA-256 configured leaf fingerprint for R10/R7 display; this does not install trust or suppress client certificate warnings. Exact publication CI `39124493115` is fully hosted-green, including Linux/macOS/Windows. The SAN regression fixture is valid from 2020 through 2120 to avoid clock-edge acceptance. R10 `e6fa65c4` has now landed the single R2-selected X11 owner/native-watch composition; R1 audited that diff and found no second acceptor/socket/SSL/BIO/TLS-plaintext owner. Its Linux hosted failure is the stale R10 Graphics source guard expecting immediate revocation after `Ready`, while `transport.lan-listener-native-bind-denials` remains PASS. R2 `880011cf` now exposes post-Share slow-path input only through a protected `LinuxRuntimeConnection` gateway that explicitly requires complete TPKTs from R1's sole TLS reader; R5 `a5a0ac84` services bounded XCB events on the same R2-selected owner, and R3 `f6bcc214` owns Confirm Active capability state/early-input discard without adding a transport reader. R1 audited these increments and found no competing socket/SSL/BIO/TLS-plaintext owner. R8 `b44fe41e` resolved the optional-broker compile defect; on descendant `746bf766`, Ubuntu full protocol and the R9 sanitizer jobs PASS. R5 `746bf766` also consumes the protected slow-path gateway only from a caller-owned complete TPKT and adds no socket/TLS reader. That descendant exposed one R1 macOS Release CTest race: after a successful client `connect()`, the test assumed the nonblocking listener was immediately accept-ready. R1 `1eb4b3d8` fixes only the production-backed test by bounded-polling the real listener descriptor before calling the unchanged nonblocking acceptor. Exact `1eb4b3d8` macOS protocol, Ubuntu protocol, both R2 Linux production lanes and the R9 sanitizer lane PASS; the primary workflow fails only in unrelated R7 macOS GUI packaging. Descendant `aaff05a9` preserves those R1/Linux/macOS protocol PASSes. R1 also audited the new post-Share router dependency: `LinuxRuntimeMcsTpktFrameReader` already exists as an R10-owned fixed-capacity exact-TPKT framer that performs no TLS I/O or admission, while R1 already exposes the sole bounded `readTlsApplicationData()` owner. A second R1 framer/reader would duplicate ownership rather than unblock the design; the missing seam is R10's persistent single-reader packet router/lifetime. Exact `9d48ca00` hosted jobs now confirm macOS protocol, Ubuntu protocol, both R2 Linux production variants, documentation policy, R5 Linux GUI ZIP and the R9 security-protocol sanitizer lane PASS; that primary workflow's only failure is unrelated R7 macOS portable-GUI packaging. R8 `225e3a7e` subsequently production-links its dormant clipboard bridge/X11 adapter under build guards while explicitly forbidding live construction/dispatch until the same R10 persistent router exists; R1 audited this increment and found no second listener, scheduler, socket, SSL/BIO owner or TLS plaintext read path. The next live R1 integration is therefore still BLOCKED specifically until R10 provides a concrete serialized `RuntimeHostControl` Start/Stop backend that obtains consent, validates the selected TLS endpoint identity and adopts `OwnedLanListener`; the current runtime implementation remains deny-only. Positive CredSSP→MCS/Microsoft-client proof remains **BLOCKED** on an owner-authorized physical Linux X11 `seat0` with Kerberos/PAM/NSS/logind. R1 buffered-TLS readiness correction: the R10 native-socket poll now immediately surfaces the R1-owned decrypted application bytes only under effective Read interest, after deadline/terminal/native-descriptor checks; outstanding WANT/write direction retains priority. Dedicated offline `runtime.linux-connection-buffered-tls-read-dispatch` CTest guards the decision and its fail-closed branches. Source parent `197d5715ef32b9598b6cc259956a762a23b88159`; local build/full CTest **NOT RUN** (GitHub checkout cannot be resolved from the execution container), exact publication-SHA hosted CI **PENDING**. Persistent R10 post-Share router and concrete HostControl LAN Start/Stop still remain **BLOCKED**, with no real-client evidence. R1 live post-Share TLS read/write handoff (2026-10-18; source parent `57103ca14b941a6e7fb5a2c2ebb353d8a3d3c994`): R10's persistent app loop now exists, but a quiet peer leaves R1 SSL_read_ex in WANT_READ while R10 must publish R4/R3 frames. The former R1 guard rejected the subsequent SSL_write_ex. R1 now permits OpenSSL-supported read-WANT → write interleaving, preserving exact-length pending SSL-write retry and all sole SSL/BIO/socket ownership. A real loopback CTest `transport.tcp-owned-tls-read-want-interleaved-frame-write` verifies blocked reader, frame delivery, resumed client packet and cancellation. Local build/CTest **NOT RUN** (approved local checkout absent); exact publication CI **PENDING**. Next: R10 concrete GUI LAN Start/Stop and owner-authorized client/seat0 verification remain **BLOCKED**. R1/R8 clipboard TLS readiness follow-up (2026-10-18; source parent `f7226e60c1b1c55b3a485c27c8018b6b2bacdc8a`): after the protected R8 `advancePersonalDesktopClipboardTlsWrite` landed, R1's shared `ioInterest()` projection omitted its current write-in-progress and SSL-WANT retry facts. The one existing derived selector now requests Write for queued/positive-partial CLIPRDR output and yields to R1's exact SSL_write_ex WANT_READ/WANT_WRITE direction. New offline `runtime.linux-connection-clipboard-outbound-want-precedence` CTest covers queued suffix, SSL WANT, buffered-read priority and revoke; no second transport owner, R3 receipt or OS authority. Owner-local full CTest **NOT RUN**, hosted exact-SHA CI **PENDING**. R10 live clipboard composition, concrete LAN Start/Stop and owner-native Microsoft-client acceptance **BLOCKED / NOT RUN**. R1 remains the sole SSL/BIO socket and TLS application-I/O owner; do not introduce another SSL reader/writer. |
| **R2 · GSS/CredSSP/native admission** | **HOSTED-GREEN / OS-account lifecycle + protected input/status contracts consumed; live positive BLOCKED.** R2's generation-fenced OS-account policy replacement/revocation, GSS→CredSSP→PAM/NSS/logind admission broker, bounded peer/account throttling, selected-native-session freshness, protected input gateway, and redacted `AuthenticationRateLimited` / `HostSessionStale` GUI outcomes are present. Production `main.cpp` now keeps the exact R2-selected X11 owner and borrowed logind watch alive in one serialized post-Share loop, reads application TPKTs only through R1's sole TLS owner, classifies them through R2/R3, dispatches `Kind::SlowPathInput` through `X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt`, and publishes R2-gated ClearCodec frames. R7 descendants `17bbd4dd` and `f08c653b` consume the typed terminal-session lifecycle and keep unsupported independent-password collection absent. Existing ordinary/source CTests cover policy replacement/revocation, production R2/PAM ordering, persistent post-Share ownership, classified input dispatch, stale-session/rate-limit projection and unsupported application-password workflow without fabricating positive admission. | **Next dependency:** there is no remaining demonstrated offline R2 authorization primitive blocking Linux video/input composition. The product blocker is the still-absent concrete `RuntimeHostControl` LAN Start/Stop backend: `src/gui/main.cpp` continues to instantiate `UnavailableRuntimeHostControl`. That backend must reuse R10's one verified listener and invoke R2 set/change/revoke plus independently trustworthy per-live-session owner consent/lock handling; GUI state may not mint either authority. After that, positive acceptance requires explicit owner authorization for a real physical X11 `seat0`, TERMSRV Kerberos/GSS, PAM/NSS/logind, TLS/CredSSP and Microsoft `mstsc.exe` / Windows App traces. Independent GUI-password NLA remains **BLOCKED** pending a separately reviewed interoperable mechanism and secret-storage design. |
| **R3 · MCS/licensing/Share/DVC** | **OFFLINE R3 POST-SHARE ROUTER, RDPGFX PRESENTATION AND FRAME_ACK HANDOFF VERIFIED; FRAME-CREDIT HANDOFF LANDED FOR R10.** R3's authenticated, non-mutating complete-TPKT classifier routes the current joined global-I/O, DRDYNVC and CLIPRDR channel identities through R2 without mutating Share, channel or native state. R10 has consumed that classifier in its persistent single-reader Linux post-Share loop and dispatches admitted Graphics DATA/FRAME_ACK, R2-protected R5 input and synchronous captured ClearCodec frames. R3 retains the one mapped surface and R4's frame receipt/ACK window; R8 has a separate R2/R3 receipt-gated outbound clipboard TLS step, but R10 still owns native clipboard. R3's nonmutating classifier now rejects mismatched Graphics dynamic-channel IDs/commands on the shared DRDYNVC static channel. Exact `2a3f06b0` macOS protocol CI run `39139376815` PASS **610/610**, including all 3 classifier CTests, Graphics presentation, 3 FRAME_ACK handoff cases and frame publication/cancellation; its R9 sanitizer job PASS. Ubuntu ordinary CTest at the same SHA FAIL **3/754** on R10/R5 source-composition source guards (not R3 tests); Windows CI and aggregate remain unverified. No owner-native/local or real-client acceptance. | **Next R3 action:** R4's 64-frame ACK saturation boundary is the demonstrated R3→R10 gap. R3 now publishes a read-only, R2-revalidated frame-credit preflight that distinguishes Ready, DeferredForFrameAcknowledge and Rejected without preparing pixels, reserving a frame or changing ACK state. R10 must consume Deferred as scheduler backpressure rather than revocation; every actual frame begin still reauthorizes and R4 remains the sole ACK owner. R10 must deliver durable GUI Start/Stop/LAN HostControl and R8 clipboard composition independently; R2 genuine Kerberos/PAM/NSS/logind physical-X11 `seat0` with explicit owner consent remains mandatory before real mstsc.exe/Windows App testing. Neither R10's persistent loop nor synthetic CI constitutes live admission. |
| **R4 · AVC420/x264/RDPGFX** | **OFFLINE READY / R10 persistent reader and X11-first-frame source integration LANDED; real-client proof NOT RUN.** R10 `4795c6dd` and `2a3f06b0` now keep one R2-selected X11/logind desktop alive in the serialized post-Share loop, borrow XShm pixels synchronously into R3's existing ClearCodec publication, use R1's sole TLS reader/writer, dispatch R3 Graphics DATA/FRAME_ACK and R5-protected input, and retire on authorization loss. R1 `e267f42d` fixes server Graphics writes following an idle SSL_read WANT. R3 `bde4fae5` supplies the client FRAME_ACK consumer; `549a12c0` also tightens post-Share Graphics dynamic-channel ID/command routing. At R4 test SHA `33b6ae76`, that same ACK-capacity CTest is hosted-green across Linux, macOS, Windows and R9 sanitizers. The existing `graphics.clearcodec-denials` CTest now also asserts that captured geometry mismatching a mapped R3 surface refuses without mutating output, receipt, frame credit or codec sequence; after receipt-safe DELETE/CREATE/MAP the newly sized frame publishes and accepts its ACK (new exact-SHA CI PENDING). R4's existing move-only segmented frame, zero-outer-byte cancellation, partial-write terminal abort, ClearCodec lossless fallback and x264 external-cancellation IDR recovery remain authoritative; no second frame scheduler or client-ACK owner is justified. Exact `549a12c0` hosted focused R9 ASan/UBSan passes **42/42** portable graphics, **28/28** x264/BGRA, **4/4** ClearCodec, **19/19** R3 Graphics DVC/ACK and **94/94** bounded R1/R3 transport. These are offline/loopback protocol results, **not** genuine R2 OS admission or visible Microsoft-client pixels. The Ubuntu full matrix at that SHA fails one unrelated R2 PAM source CTest; R2 correction `79efe8f2` landed, exact-head full CI **PENDING**. Owner physical seat0 and local full Debug CTest **NOT RUN**. | **R4 next gate is the integrated live first-frame/FRAME_ACK and recovery trace, not a speculative codec rewrite.** R10/R3 must prevent routine ACK-window credit exhaustion (R4 safely caps at 64 pending) from becoming a terminal connection via an authorized non-mutating defer/credit decision; correctly reconcile admitted Client Core Graphics surface dimensions versus R5 X11 capture and RandR resize generation; and keep a bounded poll timeout during a pending R1 Graphics TLS WANT/partial write. R10 owns this sole scheduler, R3 owns surface/channel/receipt and R4 owns only encoder/lifecycle/ACK bookkeeping. R8 CLIPRDR remains safely disabled for native live publication and is not a first-video blocker. R10's GUI LAN Start/Stop backend is still deny-only. Final M2 requires owner-consented physical X11 seat0 Kerberos/PAM/NSS/logind and each actual Windows App/mstsc visible frame, client FRAME_ACK, input, logout/reconnect with same-SHA receipts; do not infer any of this from offline CTests. See [R4 handoff #21](https://github.com/k1moradi/RDP-server/issues/21). |
| **R5 · Linux/X11** | **R2/R10 NATIVE INPUT LINK LANDED; R5 SIGNED WHEEL MAPPING ACTIVE, LIVE INPUT/FRAMES STILL BLOCKED.** R10 owns the sole R2-selected `X11DesktopResources` and a bounded XCB dispatch after logind borrowed-watch unregistration; R2 now publishes a genuine, per-event post-Share slow-path callback gateway. R5 adds `X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt`, which accepts only one R10-owned complete TPKT and calls the private native callback exclusively through R2's `LinuxRuntimeConnection::dispatchPersonalDesktopSlowPathInputPdu`. R2/R3 rechecks the exact lease, TLS/GSS, native seat/session generations, negotiated input and permission before each callback. R5 rechecks its capture generation directly beside `handleAuthorizedInput()`; mismatch, unsupported decoded event, native failure or admission denial retires with no additional XTEST release and revokes the connection. Deterministic X11 input conversions initially cover exact TS_POINTER_EVENT MOVE, single left/right/middle press/release, and lock synchronization. Set-1 scancode keys (bounded US PC-101 baseline, modifier and E0 press/release, held-key repeat suppression and stale-first-repeat denial) now translate inside the existing R2-protected owner; E1/Pause, unknown OEM keys, Unicode and relative events remain unsupported; vertical/horizontal wheel now maps signed 9-bit RDP rotation to the existing bounded X11 scroll controller without client-coordinate pointer motion; negotiated MouseX XBUTTON1/2 maps to X11 8/9 only after R2's per-event authorization; no packet/session can grant permission by itself. Dedicated offline CTests `x11.input-r2-authorized-slow-path-native-mapping-denials`, `x11.input-rdp-mousex-side-button-bounds-and-flag-denials` and new `x11.input-rdp-wheel-sign-extension-axis-and-coordinate-denials` check supported/rejected R2-routed native conversions; previous Xvfb no-lease denials remain. Owner native full CTest: **NOT RUN**; exact publication-SHA hosted CI: **PENDING**. | **Next R5/R10:** Dedicated offline `x11.input-scancode-make-release-modifier-extended-denials` plus Xvfb `x11.input-native-keyboard-sequence-and-reconnect`, `x11.input-native-keyboard-logout-no-native-post`, `x11.input-r2-policy-replacement-keyboard-denial` and `x11.input-native-keyboard-layout-change-revokes-owner` are authored. Native owner build/full CTest **NOT RUN** (no Linux checkout/toolchain in connector environment); exact published-SHA hosted CI **PENDING**. Xvfb fixtures are not OS admission. R5's exact synchronous XShm→R4 borrow and one-XCB-owner event/retirement contract is in [Linux server bundle](linux_server_test_bundle.md). R10 must keep the one X11 owner and R2 logind watch alive in the post-Share application/TLS-read loop, forward each R1-owned complete TPKT through this R2-protected gateway and implement remaining negotiated scancode/Unicode/relative semantics with tests before enabling those formats. R10/R4/R3 also owe synchronous XShm BGRA capture into an admitted mapped Graphics surface, exact accepted-byte frame receipts, zero-write cancellation and partial-write terminal abort. R10 now conditionally links the landed `rdp-server-linux-x11-authorized-input` target into the production executable, but `main.cpp` still does NOT invoke the bridge until one post-Share R1 complete-TPKT router can distinguish input from Graphics/clipboard without a second reader. This linkage alone does NOT authenticate a real client or claim working XTEST. Host physical seat0/Microsoft-client tests remain **BLOCKED / NOT RUN** pending explicit owner authorization. |
| **R6 · Windows native** | **HOSTED PACKAGE/LIFECYCLE GREEN at `9f2ef97f`; native serving still BLOCKED.** Exact-head primary Actions `39106560615` and structure `39106560683` passed; Windows/MSVC and MSYS2 CLANG64 full Debug/Release each **597/597**, R6 native preflight each **59/59**, Windows SERVER-TEST Release dependency closure and three-OS startup-disabled aggregate PASS. `e0598ef` already added the five PowerShell native integrity/path negatives; their aggregate CTest passed but the reparse subcase could skip on restricted symlink creation. R6 now adds a junction fallback + fail-on-hosted-skip dedicated reparse CTest and deterministic candidate WTS-number reuse / LUID / logon-time denial CTest, **new publication-SHA CI NOT RUN / pending**. Existing DXGI Acquire→Map→Consume→Unmap→ReleaseFrame, child-before-parent COM retirement, generation/device replacement, and no-post SendInput teardown remain unchanged. | **R2→R10→R6 gate:** R2 must issue genuine SSPI/CredSSP-authenticated SID ownership verified against the exact active physical-console WTS, LSA LUID, logon time and revocable admission/session generations. R10 alone serializes WTS registration/event/unregistration, native owner lifetime, permission checks and terminal revocation. R6 consumes fresh view/input authorization plus matching native device/session generation for each capture or SendInput call; retirement discards held input without native post, then unmaps/releases child frames before COM parents. No fake lease, Session 0 service, autostart, elevation, firewall, scheduled task or Start enablement. Windows App/mstsc remain Linux-server clients; Windows native is not first human-test critical. |
| **R7 · macOS native + GUI shell** | **PACKAGING VERIFIED / native serving still BLOCKED.** Corrective shared implementation SHA `a948ddd32d8f774db975408468764e8cf3cf4381` is hosted-green in primary Actions `39102167839` and structure `39102167861`: macOS **557/557 Debug + 557/557 Release**, dedicated R7 native lifecycle PASS, R7 session sanitizer PASS, early pure-Python macOS bundle preflight PASS on Linux/macOS/Windows, protocol test-bundle PASS, startup-disabled arm64 SERVER-TEST PASS, and the three-platform SERVER-TEST aggregate PASS. The optional Aqua LaunchAgent remains disabled-by-default with `RunAtLoad=false` and `KeepAlive=false`; no TCC/network/capture/input authority is inferred from packaging. | **New R7 GUI increment (2026-10-18):** Optional C++23 Qt Widgets shell, deny-only production HostControl, dedicated offscreen GUI navigation/security CTest. Source delivered; new host-projected GUI choice and window-close revoke CTest added (build/CTest **NOT RUN**); R10 typed API contract **LANDED**; R7 now consumes it through one non-authorizing Qt adapter. R2's generation-fenced existing-OS-account access-policy lifecycle also **LANDED**; R7 now exposes explicit OS-account setup and host-permission requests only through R10, with authoritative status required before readiness. The only current R10 implementation remains deny-only, so live Start is still **BLOCKED**. R5 Linux relocatable GUI ZIP and R6 Windows bundle contracts landed. R7 now adds the missing macOS arm64 PORTABLE-GUI builder for a real `rdp-server-desktop.app` with local `macdeployqt` closure and R9-compatible manifest; dedicated hosted arm64 build/package/Mach-O closure assurance is authored in `r7-macos-portable-gui`; the `1b32443a` correction reached and PASSed the arm64 tool preflight, real Qt `.app` build and `packaging.macos-portable-gui-app-integrity-denials`, then exposed Homebrew's symlinked `macdeployqt` path as the next packager defect. R7 resolves that caller-supplied path to a regular executable target while keeping archive/app symlink denials unchanged. Hosted `42e14927` then built the real app and passed the archive CTest, but broad default `macdeployqt` plugin deployment pulled unused QtPdf/QtSvg/QtVirtualKeyboard/QML dependencies and left Homebrew paths/signature failures. R7 disables automatic plugin deployment/signing, stages only the required Cocoa QPA plugin, and asks `macdeployqt` to patch/deploy dependencies for the app plus that explicit plugin. Exact `a2b36360` hosted CI is otherwise green and now passes real app build, package CTest, `macdeployqt` and the common R9 archive verifier; the remaining Mach-O audit entries are staged framework/dylib absolute install IDs (`brotli`, QtCore/QtGui/QtDBus), not missing archive files. R7 now normalizes absolute staged framework/plugin install IDs to bundle-relative `@rpath` IDs and then ad-hoc signs the finished preview app; exact correction-SHA Mach-O closure evidence is pending, while extracted first-screen launch and release signing/notarization evidence remain pending. **Live native blockers:** R3 Graphics DATA source is now hosted-green as part of the same matrix, but R2 still lacks a genuine credential-bound revocable macOS UID lease and R10 still lacks the macOS AppKit/session runtime owner. Until those authority/composition gates land, Screen Recording/Accessibility remain prerequisite observations only, `retireWithoutNativeInput()` remains mandatory on authority loss, and owner macOS 27/live-client M5 is **NOT RUN**. |
| **R8 · CLIPRDR/files** | **R3 + SHARE + X11 CONSTRUCTION RESOLVED / bridge hosted-green; runtime gateway + production linkage authored, live publication safe-disabled.** `da43a967e2d547bb73e2b51b8d61211219136842` passed primary `39112263911` and structure `39112263835`, including all **87/87** bridge/native clipboard sanitizer CTests. R10 `5e164e46` reaches genuine `ShareActivated`, `0257b57f` reaches Graphics DVC `Ready`, and `e6fa65c4` constructs the exact R2-selected X11 owner/native watch. R8 now exposes only the five existing broker operations through `LinuxRuntimeConnection`, with no TLS I/O, route generation, native publication or scheduler ownership; the new deny-only runtime CTest expands the direct runtime-security sanitizer selection **38→39**. The production Linux server also conditionally links the dormant R8 bridge/X11 adapter under the complete authorized-runtime/X11 build graph; a dedicated source/build CTest forbids any live construction or dispatch before the persistent R10 router exists. Current hosted Linux compilation exposed and this correction fixes a wrapper-only type error in `completePersonalDesktopClipboardWrite()`: `broker_` is `std::optional`, so presence is checked with `has_value()` rather than a pointer/null comparison. Authorization behavior is unchanged; the existing `runtime.linux-connection-personal-desktop-clipboard-gateway-denials` CTest remains the behavior guard. Exact correction-SHA CI **PENDING**. | **Live blocker is R8/R10 native composition, not the persistent loop:** R10 keeps the R2-selected X11/logind and R1 TLS owner alive with cooperative Stop. R8 scalar-safe write receipts are staged, but R10 still rejects CLIPRDR pending fresh R2-gated inbound/outbound routing and exact native X11 clipboard/INCR lifetime. Once that lands, bind the existing bridge through these five gateways, reauthorize every native publication/late receipt, and retire R8/native state before route replacement. Directory-tree materialization remains unsupported without reviewed handle-relative creation; remote names grant no filesystem authority. |
| **R9 · assurance/CI** | **ACTIVE / R10 cooperative Stop and R5 terminal native-input source tests separately pinned at exact-two in R9 focused CI; R7 Qt PlainText constructor-order regression now pinned at exact-one in the macOS PORTABLE-GUI packaging lane.** R10's live serialized R1/R2/R3/R5 poll, input, Graphics ACK and first-frame code has landed. R9 now pins the new scheduler source guard without altering the existing two post-Share executable sanitizer denials, 40-case R2 security selection, 87-case R8 component inventory, or native input/clipboard linkage guards. Recent arm64 macOS portable-GUI Actions 39140555244 validates real framework symlink-preserving ZIP packaging and extracted `codesign --verify --deep --strict` PASS; this is hosted ad-hoc code-integrity evidence only, not a real Aqua/owner-native macOS 27 launch, production trust/notarization, release approval, or complete primary green. Exact R9 publication CI is **PENDING**; physical owner-native receipts **NOT RUN**. Windows MSVC and CLANG64 Debug/full CTest previously failed only because the test mock matched POSIX `/QtGui` and not Windows `\\QtGui`, so the mock now compares the basename via `Path(...).name`; the macOS install-ID assertions remain exact. The separate R10 sanitizer selection pins both production-backed classifier-authority and single-R1-reader denial tests with an exact-two inventory. All new exact-publication-SHA hosted results are **PENDING**, and no human-client/native-host acceptance is claimed. R3 `7b330d9` adds the 19-case Graphics sanitizer selector, but its independent structure run `39137594458` fails on R9's stale 15-case token. This R9 correction updates only the structure validator to require the presentation-wire case, three FRAME_ACK cases, and the 19-case count. Exact publication-SHA hosted PASS is **PENDING**; owner-native tests remain **NOT RUN**. Descendant `aaff05a9` proves the Windows CLANG64 job fully green, including real PORTABLE-GUI packaging, recursive PE closure and extracted deny-only/normal first-screen no-socket/firewall smoke. The R9 sanitizer lane is green with the 39-case R5 X11 inventory, and this road now also pins the two dormant production-linkage guards for R5 input and R8 clipboard without changing executable counts. R7 `19e4dfff` landed staged macOS install-ID normalization/ad-hoc preview signing, but its first hosted run fails before exercising that behavior because the new synthetic normalization fixture recreates the already-existing `Contents/MacOS` directory without `exist_ok=True`; Ubuntu and macOS ordinary CTest show the same `FileExistsError`. This R9 test-only correction makes that shared fixture directory creation idempotent while preserving every normalization/signing assertion. | **Next:** require corrected exact-head ordinary CTest plus native macOS Mach-O closure PASS; if closure is green, add only the remaining extracted Aqua first-screen and signing/notarization trust-state assurance justified by native evidence. Operational PORTABLE-GUI remains blocked on concrete live R10 host control and the persistent post-Share R1/TLS router/owner needed for first R4→R3 frame publication plus the already-linked R5 input and R8 clipboard bridges, followed by genuine R2 owner/client acceptance, same-SHA owner receipts and explicit owner approval. |
| **R10 · runtime/service/licensing/M1 lead** | **ACTIVE / MCS through PersonalDesktop licensing completion is now hosted-green in descendant `da43a967e2d547bb73e2b51b8d61211219136842`.** Primary `39112263911` passes the ordinary production tests and R9's **38/38** direct runtime-security sanitizer selection covering Erect, Attach/Confirm, ChannelJoin/Confirm, Client Info/bounded framing and the PersonalDesktop licensing sequence. This still proves only fail-closed/offline composition; no positive owner-host admission or Microsoft-client result is inferred. **R10 host-control contract (2026-10-18):** `src/server/runtime/runtime_host_control.h` now defines the in-process owner-thread `RuntimeHostControl` API for local interface inventory, redacted structured status/prerequisites/errors, non-secret settings, R2 credential/permission requests, Start/Stop, active clients, disconnect and revoke. Its initial `UnavailableRuntimeHostControl` is deny-only and grants no listener, R2 admission or Share. R7 now connects its Qt view to this contract through a thin `HostControl` adapter with no independent authority; the adapter maps only R10 status and commands and never turns a command result into sharing success. Two offline production-header CTests `runtime.host-control-unavailable-denials` and `runtime.host-control-credential-setup-denials` are registered. Authoring base `24d265f45350351cd7893b61b67731e9e4f268e1`; local checkout/build/CTest **NOT RUN** (GitHub DNS unavailable in local container); publication CI **PENDING**, owner-platform verification **NOT RUN**. Neither real interface enumeration, persisted settings nor Start/Stop backend is claimed. R3's canonical production Demand Active profile still missing and `ValidClientStep::Delivered` remains fail-closed. **R10 Share activation increment (2026-10-18):** R3 blocker `7908c02f` is consumed. The production R3 preparation path now derives bitmap geometry from the exact admitted GCC Client Core instead of accepting R10-supplied dimensions; R10 supplies only `DynamicVirtualChannels` plus `SlowPathInput` when the configured requested permissions include input, while R2 independently revalidates that permission and R3 requires the real joined `drdynvc` role. The serialized serve loop no longer revokes at `STATUS_VALID_CLIENT`: it prepares the exact session-owned profile, starts the existing Share transcript and drives R1/R2/R3 readiness until `ShareActivated`, which by construction requires the real Confirm Active, Synchronize, Control and Font transitions. It then deliberately revokes because Graphics/native publication is the next separately audited increment. New offline guard `runtime.linux-serve-share-activation-composition` checks that the live serve path uses the canonical profile and existing activation owner without caller-supplied Share/session IDs or capability bytes. Authoring base `409d50524f9b16a832e4d98a76bf9751acb6166b`; local owner build/full CTest **NOT RUN** in this connector environment; publication-SHA hosted CI **PENDING**; live Microsoft client **NOT RUN / BLOCKED** on explicit owner-authorized physical seat0 credentials/admission. **R10 Graphics control increment (2026-10-18):** after genuine `ShareActivated`, the same serialized connection now starts and drives the existing R3 Graphics DVC owner through DRDYNVC capabilities, `Microsoft::Windows::RDS::Graphics` CREATE and RDPGFX CAPS until `Ready`; fresh R2 authorization remains on every transition/receipt and `authorizePersonalDesktopApplicationTraffic()` is required afterward. No R4 frame is fabricated or published; the runtime deliberately revokes at this boundary. Dedicated offline guard `runtime.linux-serve-graphics-dvc-composition` enforces control composition while rejecting any serve-loop call to frame publication before the native owner exists. Authoring base `5e164e46258487b712d63bc091fa54f82a78c789`; owner-local build/full CTest **NOT RUN** here; hosted CI **PENDING**; live client **NOT RUN**. **R10 native-owner increment (2026-10-18):** when the complete R5 X11 aggregate target exists, the production executable now links it and constructs exactly one nonmoving `X11DesktopResources` only inside `visitNativeDesktopSelection()` from R2's ephemeral `selection.display()`; configured/environment/client DISPLAY is never consulted. R10 binds a 16,777,216-pixel / 64-MiB BGRX XShm arena ceiling, captures the exact R2 admission/session generations, registers the borrowed logind monitor, includes that descriptor plus the sole R5 XCB fd in an actual bounded poll call, acknowledges unregistration before any R2 dispatch, and uses `retireAfterAuthorizationLoss()` for change/error paths. Normal temporary shutdown disconnects while authority is current. No R4 frame or XTEST input is published yet. Dedicated offline guard `runtime.linux-serve-r2-selected-x11-owner-composition` checks this production boundary without fabricating positive admission. Authoring base `40e2cab05450aacde767ae638be0ef54e4b666c0`; owner-local build/full CTest **NOT RUN** here; exact publication-SHA hosted CI **PENDING**; live seat0 **NOT RUN / BLOCKED** on explicit owner authorization. **R10 protected-input dependency increment (2026-10-18):** R5 `746bf766` resolved the prior decoded-event→X11 adapter blocker. The production `rdp-server` target now conditionally links `rdp-server-linux-x11-authorized-input` and defines `RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT` only when the complete R2/R5 dependency target exists. Dedicated offline CTest `runtime.linux-x11-authorized-input-production-linkage` guards that dependency while explicitly forbidding a premature `main.cpp` call to `dispatchAuthenticatedSlowPathTpkt`; linkage grants no input authority. Authoring base `fac0024b37074241c1857950239c9848550ffa95`; owner-local build/full CTest **NOT RUN** here; exact publication-SHA hosted CI **PENDING**; live XTEST **NOT RUN / BLOCKED**. | **Next R10:** the remaining runtime blocker before invoking the newly linked R5 bridge is one serialized post-Share R1 complete-TPKT reader/router that can classify and hand each packet to the existing R3 Graphics, R2-protected slow-path input, or R8 clipboard gateway without destructive trial parsing or a second socket/TLS owner. R3 now supplies the authenticated R4 presentation/surface initialization and a protected ClearCodec frame start that accepts no caller generation/surface state. The remaining live blocker is the serialized post-Share R1 complete-TPKT router plus persistent X11/logind owner loop; once that lands, publish XShm→R4→R3 DATA with exact zero-write cancel/partial-write abort and dispatch input immediately before R5 XTEST. R1's LAN listener/TLS identity remains ready for the subsequent concrete HostControl backend. Positive physical-seat0 Microsoft-client acceptance remains **BLOCKED / NOT RUN**. |

## M2 integration order and authorization contracts

1. **R1 → R2:** one established HYBRID TLS owner, exact certificate/protocol context and GSS principal, final protected CredSSP `authInfo`; R2 verifies the authenticated account against fresh native interactive-console evidence and alone mints the revocable admission lifetime.
2. **R2 → R3:** active lease, exact user/session/policy generations and monitored revocation allow protected MCS/licensing/Share transitions. Logout, session replacement or owner mismatch is terminal; principal strings, UID/SID values and success Booleans never authorize.
3. **R10 product policy:** service composition selects exactly one immutable mode. `AppServerIssuerBacked` keeps the existing `RuntimeLicensingAuthority::NoVerifiedIssuer` fail-closed path unless a supported provider is separately configured. `PersonalDesktop` is a distinct MS-RDPELE personal-terminal-server mode: no CAL validation/issuance is requested, at most one interactive console session is claimed per connection, and native-session revocation remains mandatory. Policy selection alone grants no R2/R3/native authority.
4. **R2 → R3 personal path:** with the same genuine lease and exact R1 owner freshly reauthorized, R2 consumes R10's `PersonalDesktop` policy and alone invokes R3's private selector before Server License Request. R3 then owns the already-published Valid Client and Share state: after a structurally valid client licensing response it emits `STATUS_VALID_CLIENT` / `ST_NO_TRANSITION`, does not validate a presented CAL, and reaches `ShareActivated` only after exact accepted-byte and client-activation ordering.
5. **R3 application publication:** only current R2 admission plus exact completed R3 personal licensing/activation may expose DRDYNVC/Graphics/input/clipboard routes. App-server mode continues to require genuine issuer-backed licensing instead; neither mode can use a test provider or a policy object as desktop authority.
6. **R10 controlled listener seam:** personal mode may explicitly enable only an exact loopback transport candidate (127.0.0.1 or ::1) and a nonzero port. This policy opens no socket and accepts no client. A real bounded listener remains gated on published non-forgeable R2 admission and R3 activated-session capabilities and explicit owner authorization; no public bind, firewall change or live desktop action is implied.
7. **R4/R5/R6/R7/R8:** consume only current R2 admission + R3 activated session authority. Native generation replacement revokes old capture/input/output; no stale frame/input/file association crosses revocation.

**R7 macOS private R2/R10 authority contract (2026-10-17):** R2 is the only
component allowed to turn authenticated-user proof into native desktop
admission. Its macOS path must authenticate the local account through the
selected real credential mechanism, resolve the immutable local UID, then
compare it with a fresh `MacNativeSessionEvidence` observation:
`consoleUserId == authenticatedUserId == auditUserId == geteuid()`, nonzero
audit session ID, nonzero Security session ID, `sessionHasGraphicAccess`, and
neither `sessionIsRemote` nor `sessionIsRoot`. That observation is evidence,
not the capability. The private R2 lifetime must also carry exact
admission/session generations and revoke on credential/session loss or any
fresh evidence mismatch. No caller UID, Boolean, generation, AppKit/CGSession
fact or TCC status can recreate it.

R10 may compose R7 only while that current R2 lifetime and the same connection's
R3 PersonalDesktop `ShareActivated` authority are both current. R10 is the
sole serializer for `NativeSessionChangeWatch::startNative()/stop()` on a
running AppKit main loop. It derives the R7 target UID only from R2, refreshes
native geometry, owns the revocation-only `MacDesktopSessionGuard`, and checks
Screen Recording or Accessibility only as the operation-specific final OS
prerequisite. The native ScreenCaptureKit backend and Quartz posting callback
remain private/unexposed until this composition exists.

Reauthorize immediately before capture prepare/start, before accepting a
prepared R4 frame for later R3 publication, and immediately before every Quartz
command batch. R2 or R3 loss is terminal even if geometry/session/TCC still
look current: R10 first closes the authority gate, calls
`MacInputController::retireWithoutNativeInput()`, closes the one-shot capture
owner, treats late callbacks as non-publishable, cancels an exact prepared but
unpublished R4 owner when R7 returns `RetireStream`, and retires the AppKit
watch only after R7 owners are terminal. A native event already accepted when
revocation races its callback cannot be retracted, but the outer input
operation must fail and no later release or input event may be posted. Fresh
access requires a new R2 lifetime, fresh R3 Share authority and fresh R7
geometry/session binding.


**R2 production startup-security increment (2026-10-17):** on reconciled parent `d8a5cbd386ae488ec265efe89d556d7d22085a39`, Linux runtime security gains explicit production build option `RDP_SERVER_ENABLE_LINUX_RUNTIME_SECURITY`, independent of `TEST_*` and `BUILD_TESTING`. Enabling it requires Linux GSSAPI/Kerberos, PAM and libsystemd at configure time; missing dependencies fail closed. The R2-owned `preflightPersonalDesktopAdmission()` reports only non-secret GSS/PAM/PersonalDesktop/native-evidence facts and can never report authenticated admission. Dedicated `runtime.linux-security-personal-desktop-preflight-denials` covers unconfigured, wrong-mode and non-admitted native evidence without fabricating seat0 or a lease. The new `r2-linux-production-runtime-security` hosted matrix closes the previously missing production/no-tests assurance boundary: one fresh-root leg disables `BUILD_TESTING`, `RDP_SERVER_BUILD_TESTING` and both Linux `TEST_*` switches while enabling production security, builds the actual `rdp-server`, and requires direct GSSAPI/PAM/libsystemd ELF dependencies plus a resolved `ldd` closure; a second leg requires configure-time libsystemd failure when its pkg-config metadata is hidden. A nested CTest is not safe because the project permits only the sole checkout `build/` root. Publication-SHA hosted evidence is **PENDING / NOT RUN** at authoring. Canonical owner-local build/CTest and owner-authorized live Kerberos/PAM/NSS/logind X11 seat0 remain **NOT RUN**. R10 still owns consumption in the future `serve` path; R3 DATA is now landed and is no longer this R2 assurance blocker.

**R10 R2/R3 composition increment (2026-10-17):** consumed R2 `bb25af3` and R3 `6e2a84a` on reconciled parent `8f3c2f06b305eca60708867c9e50f9a6a59a79cb`. Product/version/company/product-ID/scope equality is checked against the service `RuntimeLicensingContext` identity before `beginExistingCalValidation()`; R3's borrow is never retained. The connection binding retains the 32-byte correlation and exact R2 admission/session generations, while the authority retains protected HWID, verification time, authenticated provider generation/fingerprint and request digest. Generation replacement cancels a pending request before provider poll; duplicate begin, stale result/retirement, unavailable authority and reconnect reuse fail closed. Linux composition reauthorizes through R2 before begin/poll/result use, cancels/retire authority state before R3/R2 teardown, and cannot translate a test-only decision into Share. Dedicated CTests are `runtime.licensing-existing-cal-connection-unavailable-denial`, `runtime.licensing-existing-cal-connection-cross-generation-cancellation`, `runtime.linux-connection-existing-cal-unadmitted-denial`, and `runtime.linux-connection-native-monitor-registration-denials`; the existing R2 borrow denial is also in the direct sanitizer selection. Canonical local `~/rdp-server/build/`: **NOT RUN** in this connector environment; no second build root was created. Initial publication `b35fe8cc2a1da47f917f57e1812ee459d73e03c4`: **CI FAILURE** before compile because the R10 workflow-edit authoring step duplicated a YAML job key; Actions 39040560442 (structure guard) and 39040559343 (primary workflow) failed. The correction rebuilds the intended selector edits from reconciled parent workflow content; production composition code is unchanged. Corrective descendant `b18ca13303c025e315b33787edbe5cd842a7777c`: structure/documentation gates **PASS**, but Ubuntu/macOS Debug compile failed at R3's new existing-CAL fixture because `McsSessionLifecycleTestAccess` bypassed its already-defined friend helper and called two private request methods directly. This test-only recovery routes those calls through `RdpExistingClientCalAuthorityRequestTestAccess`; production R3/R10 code is unchanged. Next descendant exact-SHA CI: **PENDING**. Next gate is CI/owner evidence plus the external issuer decision below.

**R10 app-server provider feasibility decision (2026-10-17; app-server mode only):** **BLOCKED — project-owner direction required for app-server deployments.** Microsoft [MS-RDPELE] specifies the *client ↔ terminal-server* license PDUs, not the separate *Session Host ↔ license-server* RPC. The architecture describes that RPC for new/upgrade CAL issuance, but this investigation has not identified a documented, supported, authenticated API contract that lets this independent C++23 app-server validate presented CALs and issue/upgrade licenses through Microsoft RD Licensing as an authorized non-Windows Session Host. Windows RD Licensing WMI/PowerShell management/reporting interfaces do not establish such an issuance/verification API. Accordingly **no provider is chosen** for `AppServerIssuerBacked`; that production authority stays `NoVerifiedIssuer`, with no issuer-backed positive completion. The separately approved `PersonalDesktop` mode follows MS-RDPELE personal-terminal-server semantics and does not treat itself as an issuer/provider fallback. The owner must either (a) provide vendor-confirmed interoperability/support terms and an authenticated issuer API for independent app-server use, or (b) explicitly approve a product-scope/licensing-design change before implementing a different compliant provider.

**Required provider contract if supported:** mutual authentication to a specifically pinned issuer identity (Windows/domain credential or service identity and protected transport as documented by its vendor), immutable trust roots/policy and per-request provider-generation binding; explicit signature-chain issuer verification, exact `PRODUCT_INFO` version/company/product ID plus scope, permanent/temporary/upgrade status, expiry including the seven-day upgrade threshold, MAC-verified 20-byte HWID and device/user CAL mode. The R10 authority must bind the provider's verified decision to the 32-byte R3 correlation, digest, positive verification timestamp and live R2 admission/session generations. The owner must supply an activated Windows RD Licensing role, installed and appropriately scoped CAL key packs, supported access credentials and licensing mode, reachable network/domain or workgroup infrastructure, and permission/confirmation from Microsoft or the provider for this app-server integration. An activated licensing server by itself is not a verified R10 backend. MS-RDPELE 1.3.1/3.1.5.1 and Microsoft RD Licensing activation/session-host guidance are the normative references. **External blocker:** supported non-Windows Session Host issuance + existing-CAL validation authority interface and authorization to use it.

**M1 evidence reconciliation:** Repository receipts currently enumerate hosted Actions, not a complete single-SHA set of owner-local Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 configure/build/CTest records. Informal owner-reported passes may be valid but cannot establish exact-SHA acceptance without SHA, effective OS/toolchain, configure/build outcomes, complete CTest totals and failed/skipped/not-run counts. **M1 remains OPEN, not a reason to halt unrelated M2 implementation**; request only missing receipt fields, not unnecessary reruns.

**Current personal-desktop M2 dependencies:** R2 must publish protected wrappers that consume R10's immutable `PersonalDesktop` policy only with a genuine live admission lease and exact R1 owner, then invoke R3's private personal selector/Valid Client/Share transitions. Linux real Kerberos/PAM/logind admission remains owner-environment dependent; Windows/macOS still need genuine R2 authenticated native-admission leases. The app-server issuer blocker remains applicable only to `AppServerIssuerBacked`. No synthetic authority or public listener is permitted.

## Shared-main Git coordination contract

- **All agents work directly on the existing `main`** with the canonical checkout/build root. No branches, PRs, worktrees, detached work, patches, force pushes or destructive resets. Git commits, this roadmap and the existing validation ledger are the only cross-agent handoffs; do not rely on chat reports as shared state.
- **Parallel work means independent ownership, not blind parallel writes.** Reserve the active increment's production files to its road. Cross-road integration requires the receiving owner to record the exact consumed API, lifecycle, generation and test in the relevant existing board row before writing. R1 owns TLS, R2 authorization, R3 protocol and wire writers, R4 codec, R5–R7 native owners, R8 clipboard, R9 CI assurance, R10 service/licensing composition.
- **Shared hot spots:** `docs/ROADMAP.md`, `docs/CODEX_VALIDATION.md`, `tests/CMakeLists.txt`, `.github/workflows/ci.yml`, and composition interfaces are collision-sensitive. Each implementation still publishes its own required code + dedicated registered CTest + concise edited roadmap row **atomically in one direct-main commit**. On a conflicting publication, refresh, reconcile both changes, rerun affected checks, then retry without overwrite. R9 coordinates CI selector edits; R10 coordinates only cross-road interface commitments/M1 acceptance, not every unrelated publication.
- **Optimistic publication:** start from a clean fast-forwarded `main`; fetch remote immediately before publishing; ensure the intended commit is based on that current head and changes do not overwrite other agents' updates. If HEAD moved, integrate current upstream changes first; never force, reset, drop another road's work or blindly restore an older complete file. Announce changes **through Git** by updating this board's existing row and citing the new commit/verification.
- **Status edit format:** road, status, exact committed source SHA, tests/CI PASS/FAIL/NOT RUN, blocker, next owner/dependency. Keep one compact row; place only genuinely new acceptance evidence in the existing M1/M2 sections. CI evidence belongs in the one validation ledger as a terse exact-SHA receipt, not mirrored paragraphs throughout the roadmap. Never write a predicted self-SHA into the same commit.
- **M1 publication freeze:** after R10 posts one nominated green candidate, all roads continue **parallel read-only review, local preflight, reproduction planning and dependency analysis**, but do not publish unrelated updates until the owner matrix is complete. Release an urgent real fix only with R10's explicit candidate reset and a fresh hosted + three-owner SHA convergence. Resume atomic independent publication after M1.
- **No work duplication:** inspect current `main` and CTest registrations first. If the behavior already exists and is green, report READY/blocked dependency; do not create a second seam/test/receipt commit. Every new production behavior requires one centrally registered behavior-named production-backed CTest with denial, cancellation/replay and sanitizer coverage where relevant.
- **Pruning:** delete dead code only after checking live call sites, compile variants, tests and consumers; preserve meaningful failure/security tests. Remove obsolete documentation/append-only history after consolidating its current invariant and evidence pointer; Git history is the archive. No broad code cleanup or unrelated CI rewrites during M1. R9 checks test/CI implications and the owning road performs the minimal deletion after freeze.

## Decision ledger (current only)

- **M1:** OPEN. Three owner-native exact-SHA receipts missing. Older candidate `e2c1e51d` is not current `main`.
- **M2:** OPEN. R2 real positive admission NOT RUN; R3 CAL snapshot DONE; R10 existing-CAL owner DONE but production provider unavailable; R3 authenticated licensing/Share not implemented.
- **M3–M5:** native → R4 lifetime/epoch handoffs READY; live R2/R3 publication/input/client acceptance NOT RUN.
- **Security:** HYBRID cannot jump to MCS; only one TLS/plaintext owner; R3 CAL snapshot and R4 encoded frames are non-authorizing; remote clipboard paths never grant local filesystem authority.
- **Next management check:** R10's literal M1 candidate + hosted Actions; owner Linux/X11, Windows CLANG64/Clang 23 and macOS 27 receipts; R9 independent same-SHA sign-off. Record changes by revising the above rows, not appending reports.

### Personal-desktop licensing decision (2026-10-17)

The selected Windows App / Windows 11 `mstsc.exe` personal-desktop mode does
not require an RD Licensing CAL decision and must not wait on the existing
CAL-authority work. Existing licensing code remains isolated for modes that
need it; it is not an authentication substitute. R2 authenticated identity +
native OS admission remains mandatory before any R3 Share, graphics, input or
clipboard authority.

### R5 Qt-native seat0 prerequisite view (2026-10-18)

The R7 Qt Linux permissions page now uses R5's asynchronous read-only
`loginctl show-session` probe and local library-availability check. It reports
a *candidate* active physical X11 seat0 session only with matching logind
seat/type/active/remote/state/display and the process session type. Synthetic
`DISPLAY`, Xvfb, missing logind evidence and absent libraries cannot mint R2
admission. The GUI explicitly reports that R2 generation is unavailable to
preflight, after-login autostart is not configured, and login-screen hosting
is unsupported. Refresh spawns at most one bounded probe at a time, parented
to its label; no watcher, socket, capture or XTEST owner is added. The dedicated
Qt CTest `gui.linux-readonly-seat0-prerequisite-denials` checks the production
parser and the deny-only GUI projection; Linux Qt CI builds and runs it before
its actual extracted-XCB GUI smoke. Owner-local Qt build/full CTest: NOT RUN;
exact publication-SHA CI: PENDING.

R3's canonical Demand Active and R10's authenticated Share/Graphics
control and sole R2-selected X11 owner are in source. R5 native event
dispatch now follows borrowed-watch unregistration with pre/post R2
checks; its ordinary offline CTest is
`runtime.linux-r5-x11-authorized-event-service-denials`. The live
remaining blocker is the single owner's continuing frame/input composition,
plus explicit physical seat0 host authorization; no client-visible
publication is claimed.

### R5 decoded wheel to existing native X11 scroll (2026-10-18)

MS-RDPBCGR TS_POINTER_EVENT carries signed 9-bit wheel units
(0x078=+120, 0x188=-120), gives vertical precedence when both
WHEEL/HWHEEL bits are present, and ignores other wheel pointer
flags and untrusted client x/y wheel positions. R5's stateless
R3-decoded translator now produces X11ScrollInput for its already
bounded 120-unit accumulator and XTEST button 4/5 or 6/7 owner,
using zero placeholder coordinates. XTEST uses rootX/Y for motion
only, not button events, so wheel input does not reposition the
pointer. It still requires a valid native geometry. R3 owns
negotiated horizontal-wheel gating; R2 reauthorizes every event
before R5 can reach XTEST. No parallel native owner/TLS reader is
added.

Dedicated offline CTest:
`x11.input-rdp-wheel-sign-extension-axis-and-coordinate-denials`
covers ±120, zero, signed extrema, both axes, precedence,
ignored flags/out-of-range wheel x/y, and malformed non-wheel
and zero-geometry denials. The prior base mapping test now
accepts normative WHEEL/HWHEEL. R10 still disconnects after one
bounded native poll; its persistent R1 TLS post-Share packet
router and first authenticated XShm→R4→R3 frame remain BLOCKED.
Owner full Debug/CTest **NOT RUN**; exact commit hosted CI
**PENDING**; physical seat0/client result **BLOCKED / NOT RUN**
pending explicit owner permission. R9 must separately enroll
the new test in its fixed sanitizer inventory.

### R5 R2-authorized MouseX side buttons (2026-10-18)

R3 owns MouseX negotiated-capability admission and R2 reauthorizes each
decoded input before the native R5 sink. R5 maps exactly one XBUTTON1/2
TS_POINTERX_EVENT press/release to conventional X11 side buttons 8/9
with current-desktop geometry bounds. Unknown/composite/movement/wheel
flags and out-of-range coordinates deny; no independent X11 owner, native
permission cache or TLS reader is created. New offline CTest:
`x11.input-rdp-mousex-side-button-bounds-and-flag-denials`.
R10 has linked the protected R5 input library but still needs one
persistent post-Share R1-owned input/Graphics/clipboard TPKT demultiplexer;
no input is currently injected by production `main.cpp`. R9's existing
39-case sanitizer selector does not yet enroll this second translator
fixture; add that only with R9's reviewed count. Owner full build/CTest:
**NOT RUN**; publication CI: **PENDING**; genuine physical seat0/client
acceptance: **BLOCKED / NOT RUN**.

### R5 R2-gated native slow-path input bridge (2026-10-18)

R2's `LinuxRuntimeConnection::dispatchPersonalDesktopSlowPathInputPdu`
gateway is now published, so R5 supplies a caller-ready native sink through
`X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt`. The private
sink can be reached only by the existing R2/R3 per-event authorization.
It holds no copied lease, native descriptor, session cache or second X11
owner. R5 compares the same capture generation before each native event and
retires no-post on any mismatch. An exact, bounded translator handles
ordinary pointer movement, a single left/right/middle button and lock-state
synchronization. It rejects unsupported scancode/unicode/relative/extended/
wheel formats rather than guessing native keyboard layout or using wheel
coordinates the protocol says to ignore. An `Unused` input event is a
gated no-op, not a native request.

`x11.input-r2-authorized-slow-path-native-mapping-denials` is the new
offline CTest for the production translator and the statically-typed R2
gateway interface. No R10 persistent post-Share read loop exists yet,
so input publication is still disabled. R9 and R10 must not advertise
working remote input based on this bridge or synthetic Xvfb.

## R5 portable Linux GUI launch and native prerequisite inspection (2026-10-18)

R7's opt-in Qt6 Widgets `rdp-server-desktop` is now available. R5 has
authored a Linux GUI-only ZIP builder that packages that ELF, Qt XCB plugin,
linked native dependency closure, movable GUI launcher, qt.conf, desktop
entry, LICENSE/NOTICE, per-file SHA-256, manifest, and UNIX execute modes.
The launcher sets private `umask 077`. No AppImage/FUSE mount, systemd
install, daemon, credentials, listener, capture or XTEST is included.
The dedicated offline CTest
`packaging.linux-gui-zip-offline-closure-and-modes` checks synthetic ELF,
Qt closure, ZIP extraction/modes, integrity/tamper and mock GUI execution.
A separate Linux CI job will build R7's real executable, inspect the
extracted Qt/XCB closure and smoke the GUI under Xvfb without admission.
Real extracted GUI CI result and supported distro compatibility: NOT RUN.

R9 has also authored a separate cross-platform PORTABLE-GUI **verifier**,
but its gated `r10-production-host-control` classification cannot truthfully
be claimed by R5's deny-only preview: R10's typed HostControl is not a live
implementation. R9 must reconcile/stage the real Linux GUI preview into
the common release contract and audit Qt redistribution attributions before
calling the end-user ZIP ready. R5 now presents the read-only Linux seat0/display/session and X11-library
observations inside R7's Qt GUI; R2 authenticated selection remains owned by
R10's distinct, currently deny-only host-control status. Neither Xvfb nor configured DISPLAY grants R2 native admission.

R10 now composes Demand Active/Share/Graphics control after a genuine
R2 lease, constructs the one R2-selected `X11DesktopResources`, and
unregisters the borrowed logind watcher before dispatch. R5's current
increment services one bounded native event batch using only that owner with
fresh R2 authorization before and after. **LIVE R4 FRAMES / XTEST INPUT STILL
BLOCKED** until R10 composes the continued event loop and frame/input receipt
lifetimes; no positive seat0/client test has run. After genuine
permission, R5 will bind synchronous XShm->R4 borrowing, RandR/native
generation fences, fresh R2/R3 XTEST authorization, zero-write cancellation,
partial-write terminal abort and `retireWithoutNativeInput()` on revocation.
No pre-login-screen access or live-client success is claimed.

**R3 exact-head compile blocker (2026-10-18):** the prior Graphics presentation
commit fails hosted compilation on Linux/macOS/Windows because `PixelSize` and
`FramebufferView` are global types, not `rdp_server::rdp` names. A narrow R3
qualification correction is published for hosted revalidation. Graphics and
frame/sanitizer CTests remain NOT RUN until CI executes the corrected head.

**R3 hosted-compile follow-up (2026-10-18):** Subsequent CI exposed
remaining global `FramebufferView` references at R2/R10 handoffs and a stale
R1 Graphics TLS fixture calling the old DVC presentation API. Corrected
those exact incompatibilities; full CI and affected CTests still PENDING.

**R3 post-Share classifier (2026-10-18):** R3's read-only
`McsSessionLifecycle::classifyVerifiedR2PostShareTpkt` inspects a single
complete TPKT using negotiated joined MCS roles and current clipboard/DVC
state. R2 exposes only the synchronous borrowed result via
`LinuxConsoleAdmissionBroker::classifyR3PersonalDesktopPostShareTpkt`
after two independent native admission checks. It does not invoke any
R5/R8 listener, advance the Share, create a channel, or read TLS bytes.
The external R10 single-reader integration and genuine X11 host remain
BLOCKED. New exact-SHA hosted CTests/sanitizers: PENDING.

**R10 persistent poll/borrow correction (2026-10-18):** The combined
socket/X11/logind poll now narrows runtime-dependent POSIX event masks to the
actual `short` field, rejects a bad socket interest before registering the
borrowed watcher, explicitly retires rejected watcher registrations, and
passes a mutable synchronous stack context into the existing capture callback
without `const_cast`. The Graphics source CTest checks native capture call
ordering (not declaration position); the persistent owner guard rejects
reintroduced const-discarding. Source parent `1cebf88942edd7f9e0294a40eba4eff10a574114`;
local CTest **NOT RUN**, hosted exact-head CI **PENDING**, live physical
seat0/mstsc **NOT RUN**.

**R10 persistent Linux post-Share runtime (2026-10-18):** R10 now composes the
R1 socket, R2 borrowed logind registration, one R5 XCB desktop and the R3
Share/Graphics lifetime in one bounded three-fd poll loop. The exact borrowed
logind registration is unregistered and then dispatched or discarded before
any callback that may revoke. It preserves the R1 WANT direction, services
one classified R1 TPKT step or pending R3 Graphics write per iteration,
uses R5's existing authenticated slow-path input bridge, and synchronously
publishes timed XShm full-frame borrows via the R3-owned ClearCodec surface.
Graphics DATA and client FRAME_ACK continue on the same R1 reader and R3/R4
ACK window. Clipboard remains deny-only pending R8 native source/receipt
composition, and this explicit loopback-only CLI is **not** a GUI LAN Start.
New source-backed CTest `runtime.linux-serve-persistent-post-share-single-owner`
checks the production loop and existing reader ownership alongside earlier
executable-backed no-lease denials. Base `3b899d59bb60122b4234cb75ba3a0cc867dc5505`; local
build/full CTest **NOT RUN** (GitHub DNS prevents checked-out build), hosted
publication-SHA CI **PENDING**, physical X11 Microsoft-client **NOT RUN**.
Remaining R10 P0: real GUI Start/Stop/LAN controller, durable Stop during WANT,
clipboard source/receipts and owner-authorized live acceptance; R2 OS-backed
CredSSP/consent remains the real admission prerequisite. Never represent
synthetic green CI as authenticated desktop acceptance.

**R10 serialized post-Share reader increment (2026-10-18):** On
`a80a3bc7858a934eda43e3997ce463dc8907bce7`, the runtime now reuses `personalGraphicsDvcFrameReader_`
after R3 Graphics MAP_SURFACE_TO_OUTPUT completion instead of permanently
closing it. `advancePersonalDesktopPostShareApplicationRead` reads only
through R1's sole TLS application reader, caps each read at the existing
TPKT `bytesNeeded()`, invokes the R2/R3 immutable classifier once, and
synchronously hands the one borrowed packet/route to a caller sink. The
Graphics DATA path uses R2/R3's existing reassembly and R4 FRAME_ACK
window; no second ACK owner was created. Outbound TLS WANT retains its
original direction and blocks new application reads. New production-backed
offline test `runtime.linux-connection-personal-post-share-single-reader-denials`
asserts absent R2 admission yields no callback, TLS read or ACK. Local
build/CTest **NOT RUN** (no cloneable approved checkout; GitHub DNS blocked),
hosted exact-SHA CI **PENDING**. Remaining R10 gate: call this step from a
persistent native/sock scheduler, provide R5 input and R8 clipboard sinks,
then first frame and live LAN HostControl. No positive client evidence.

**R10 R2/R3 classifier consumption (2026-10-18):** R10 now exposes
`LinuxRuntimeConnection::classifyPersonalDesktopPostShareTpkt` as the
connection-local, fail-closed synchronous wrapper around the immutable R3
classifier through the current R2 broker and PersonalDesktop/Graphics-Ready
authority. Unsupported routes and missing leases retire the connection;
no new socket/TLS reader, framer, queue or speculative dispatch was added.
Dedicated production-backed offline CTest
`runtime.linux-connection-personal-post-share-classifier-authority-denials`
uses the genuine Linux runtime aggregate without fabricating admission.
Source base `1c8f0984c446a2379e905435ddae62c6dd7ac65f`; local build/full CTest **NOT RUN** (GitHub DNS
unavailable for the approved checkout); publication-SHA CI **PENDING**.
**Remaining P0 gate:** integrate the existing sole R1 reader and TPKT frame
owner into the persistent X11/logind/R3 schedule, then frame DATA/ACK and
protected input. Physical seat0 Microsoft-client acceptance **NOT RUN**.

**R3 classifier CI follow-up (2026-10-18):** R3's test registry static extent
was updated 155 → 158 after Linux/macOS compilation detected three added
cases. Exact-head route/graphics/sanitizer tests remain PENDING.

**Separate R3 Graphics client FRAME_ACK handoff (2026-10-18):** The
post-Ready DVC DATA receiver retains the completed client PDU until the
R2-authorized `consumeR3PersonalDesktopGraphicsFrameAcknowledge` invokes
R4's existing `GfxPresentationLifecycle::onFrameAcknowledge` and clears the
DVC reassembly buffer. R4 remains sole owner of decode progress, matching
frame IDs, queue depth and ACK suspension. R10 must call this immediately
after `GraphicsDataAccepted`, before reading another DATA packet. This is a
separate bounded production commit from the non-mutating classifier; neither
changes R10's TLS reader or native admission. Exact CI PENDING.

**R3/R9 Graphics sanitizer selection (2026-10-18):** The real sanitizer
run detected an obsolete 15-test Graphics DVC registry count, already 16
after R3 presentation and 19 after the separate FRAME_ACK handoff tests.
The workflow's exact count and required test names are updated to 19.
Next hosted CI/sanitizer pass remains PENDING.
