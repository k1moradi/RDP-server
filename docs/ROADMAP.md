## R8 tray dependency resolved; FIRST still blocks activation (2026-10-21)

R7's actual one-page dashboard and tray lifecycle have now landed on shared
`main`, resolving R8's earlier inability to audit the production hide/Quit
paths. R8 now pins the real implementation: active window close hides
presentation without Stop/Revoke, explicit Quit enters Stop/Revoke before
application exit, and product consent keeps clipboard false while the R8
activation gate is disabled. The tray lifecycle fixture also verifies that
clipboard projection survives close/hide and refused retirement, then becomes
Retired only after successful explicit Quit.

This resolves the Track B dependency for the R8 lifecycle audit, but **does not
resolve the Track A activation gate**. FIRST remains frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`, and owner-authorized visible
desktop + mouse + keyboard + Stop is still NOT RUN. Therefore
`kLinuxProductionClipboardActivationApproved` remains false. After FIRST
passes, activate/test Unicode text in a separate milestone; images/files remain
later.

## R7 Windows dashboard toggle linkage correction (2026-10-21)

Dependency recheck after the one-page dashboard landed found one Windows-only
linkage gap: `rdp-server-windows-gui` compiles `DesktopWindow` directly, and
that window now instantiates the imported `ToggleSwitchWidget`, but the
Windows launcher target did not compile `src/gui/toggle_switch.cpp`. The
shared desktop-ui target already had the source, so this defect was specific to
the R6 Windows launcher/package path.

This correction adds the existing toggle implementation to that target and
registers the platform-independent offline source-contract CTest
`windows.gui-dashboard-toggle-linkage-source-contract` so the direct launcher
cannot silently drop an out-of-line dashboard widget again. It does not change
toggle semantics, host ownership, password capability, clipboard activation,
FIRST acceptance, or native Windows/macOS hosting.

Canonical owner-local configure/build/full CTest: **NOT RUN** in this
connector-only environment. Exact publication-SHA hosted CI is required, with
the Windows portable-GUI build now expected to reach the dashboard linker
instead of failing on unresolved `ToggleSwitchWidget` symbols.

**Next gate:** product-main exact-SHA ordinary hosted CI. Track C still waits
for real Microsoft-client standalone-password PASS before Session Password UI;
R8 clipboard activation still waits for FIRST; Track A FIRST remains frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`.

## R7 full workflow restoration after selector-authoring corruption (2026-10-21)

The first selector repair commit still produced an invalid primary workflow.
A full compare against last known-good parent
`02f1df7685672c2c087f601a3810ff4a21a33de1` shows the dashboard publication
had unintentionally expanded the workflow by hundreds of lines around the
replaced selector block. This correction restores the entire known-good
workflow and reapplies only the intended tray exact-one selector change.

No production C++, CTest registration, dashboard behavior or capability gate
changes in this correction. Corrective hosted CI: **PENDING**.

## R7 workflow selector syntax repair after dashboard publication (2026-10-21)

Exact dashboard publication SHA `966ab8101ff0f2c8c09bb4e669298a0192ddc3f8` failed before CI jobs were created
because the edited macOS exact-one selector block in
`.github/workflows/ci.yml` was truncated immediately after the tray-lifecycle
regular expression. This is a workflow-authoring defect only; no C++ source,
dashboard behavior, capability gate or test expectation is changed.

The correction restores the complete
`gui.offscreen-tray-close-hide-and-explicit-quit` selector block, including
exact-one enumeration and execution. Canonical owner-local build/full CTest:
**NOT RUN** in this connector environment. Corrective publication-SHA hosted CI:
**PENDING**.

## R7 one-page dashboard, authoritative toggle and tray lifecycle (2026-10-21)

Starting shared-main parent: `02f1df7685672c2c087f601a3810ff4a21a33de1`.

Track B is no longer blocked by the toggle documentation defect or tray-lifetime
ownership. The desktop UI now replaces the six-page wizard with one dashboard:
**RDP Server — Stopped/Starting/Sharing/Stopping**, automatic private-LAN
address + Copy, capability-gated Access, Sharing with the imported
`ToggleSwitchWidget` and keyboard/mouse consent, concise connected-device
status + Disconnect, and a collapsed Advanced disclosure for interface
override, port, TLS fingerprint, permission lifetime, authentication mode and
diagnostics.

The toggle never owns host truth. Start intent leaves the switch Off until the
runtime reports a hosting/listener stage; Stop/Revoke intent keeps it On until
the runtime confirms retirement. A rejected action snaps back to the observed
state and presents a human-readable error. Automatic interface choice consumes
only the existing runtime-approved private address list, preferring IPv4 while
preserving an exact surviving manual Advanced override.

Tray/menu-bar actions are Open, Copy Address, Start/Stop, connected-device
summary and Quit. Closing the window during a pending/active host hides
presentation only and makes zero Stop/Revoke calls. Explicit Quit always enters
Stop/Revoke first and cannot finish while the runtime still reports a hosting
stage. The R8 clipboard owner therefore survives hide/restore but remains
terminally ordered through the existing common retirement path.

Product capability gates are unchanged. No Session Password/confirmation field
is constructed because real unmodified Windows App/Windows 11 `mstsc.exe`
standalone-password interoperability is still NOT RUN. Clipboard has no product
control and owner-consent requests force it false while
`kLinuxProductionClipboardActivationApproved` remains false; FIRST Linux
visible-desktop + mouse + keyboard + Stop must pass before a later Unicode-text
activation change.

New ordinary cross-platform Qt offscreen CTests are
`gui.offscreen-dashboard-single-page-defaults`,
`gui.offscreen-authoritative-sharing-toggle`, and
`gui.offscreen-tray-close-hide-and-explicit-quit`. The existing R8
`gui.offscreen-hide-preserves-active-sharing` remains complementary.
The macOS packaging lane's former Stop-before-close exact-one pin is replaced by
the tray close-hide/explicit-Quit behavior.

Canonical owner-local configure/build/full CTest: **NOT RUN** in this
connector-only environment. Source-contract inspection: **PASS** for wizard
removal, toggle/tray wiring, password/clipboard gating and test registration.
Publication-SHA hosted CI: **PENDING**. No listener, desktop, input, clipboard
or credential prompt was activated.

**Next gate:** product-main exact-SHA ordinary hosted CI. Track A FIRST remains
frozen independently at `8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`;
Track C still requires real Microsoft-client standalone-password PASS before
R7 may expose Username + Session Password; Track D CLEAN Windows and Track E
native Windows/macOS hosting remain independent.

## R2 standalone Microsoft-client acceptance diagnostics prepared (2026-10-21)

Starting shared-main parent: `738d65d67356781046102fed50aed38372ddde24`.

The next R2 gate remains one real unmodified Windows App or Windows 11
`mstsc.exe` authentication through R10's production accepted-socket path.
This increment adds only the redacted evidence needed to diagnose that run; it
does **not** enable the public Session Password UI, add another authentication
owner, or change ExistingOsAccount.

Standalone failure evidence is now classified at the existing owners as
`ntlm-negotiation`, `mic`, `sign-seal`, `spnego`, `pubkeyauth`,
`authinfo`, or `admission`. The production connection emits only one
fail-only stage line and states `os-gss-fallback=disabled`; it never logs
tokens, responses, keys, delegated credentials, usernames or passwords. The
bounded acceptance snapshot also records that StandalonePassword was selected.
Offline selector coverage requires the GSS acceptor to remain
`Unconfigured` and an early standalone admission denial to remain classified
as standalone `admission`, proving there is no retry through OS-account/GSS.

The owner-authorized acceptance configuration is intentionally non-product:
use a bounded test username plus a password freshly entered into mutable memory,
call the existing internal
`configureStandaloneApplicationPassword(...)` seam, record only its exact
nonzero credential generation, and let the existing R10 selector generate the
per-connection random NTLM challenge/current FILETIME. The password must never
enter source, config, argv, environment or logs. R1's exact established TLS
owner/fingerprint, the owner-bound CredSSP frames, the standalone authenticated
principal proof, a fresh current-owner grant, and the normal NSS/logind
physical-session lease remain mandatory. A local owner harness may prepare that
one call for the physical run, but it is not a product capability and must not
be committed as a password switch.

Real Windows App/`mstsc.exe` interoperability is **NOT RUN** in this
connector session because no explicit live owner authorization was supplied.
R7 must keep password controls absent until that physical gate passes.

## R8 clipboard lifecycle audit for the one-page/tray transition (2026-10-21)

R8 remains **blocked from production activation until FIRST**. The production
gate stays `kLinuxProductionClipboardActivationApproved = false`; the prepared
surface is Unicode text only, with image/file paths still excluded.

The tray transition must treat window hiding as presentation only: hiding or
restoring the dashboard must not retire the accepted client, R5 desktop or R8
clipboard owner while sharing continues. Stop/Revoke/Quit remain terminal and
must retire R8 selection/paste/INCR plus bridge receipt state before R5, the
accepted connection and listener. Client disconnect/reconnect must destroy the
old R8 owner and prepare a new one from the replacement R2
admission/session generations.

Offline coverage now includes a hide-preserves-sharing GUI regression plus
stronger dormant-composition guards for terminal ordering, fresh replacement
ownership, X11 state clearing and stale TLS receipt retirement. These are
preparation only and do not move Track A. After owner-authorized FIRST visible
desktop + mouse + keyboard + Stop passes, enable/test Unicode plain text in a
separate milestone. Images/files remain later.

## R7 toggle import documentation-policy repair and R9 split qualification (2026-10-21)

Exact parent `82feaad284dda584d203d877f6239abf44a246e3` imports R7's shared
`ToggleSwitchWidget` and adds `src/gui/toggle_switch.cpp` to the
`rdp-server-desktop-ui` CMake source list. Its ordinary hosted build,
protocol, native/package, sanitizer and workflow-structure jobs are green, but
`documentation-policy` fails with
`Missing Markdown co-change: 82feaad284dda584d203d877f6239abf44a246e3` because that implementation
commit changed `src/` / `CMakeLists.txt` without Markdown. CLEAN Windows is
a separate queued consumer and is not evidence for or against this policy
failure.

This is the narrow canonical co-change repair for that actual policy failure.
It changes documentation only; it does not alter the imported toggle, product
behavior, tests, acceptance criteria or the frozen Linux FIRST candidate. The
repair's exact publication SHA must pass ordinary hosted CI before it qualifies
as product-main. Do not inherit PASS from the parent.

R9 now keeps qualification split. **FIRST Linux acceptance is frozen at
`8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`**: its ordinary hosted matrix,
including documentation policy, is green. Owner-authorized physical acceptance
remains NOT RUN for R1 transport trace, R3 protocol trace, R4 frame/ACK trace,
R5 X11 capture/input and R7 GUI lifecycle; later password/UX commits do not move
this candidate. **Product-main qualification** follows moving `main` for
password/UX/portability and requires its own exact-SHA ordinary hosted PASS.
CLEAN Windows remains independent and requires a qualifying clean non-admin
execution or a signed/hashed manual acceptance record; hosted Windows CI cannot
imply CLEAN.

After this process blocker is cleared, product-main R9 guards must cover the
one-page dashboard replacing the wizard, toggle source inclusion, absence of
user-facing R1/R2/R10 terminology in the default dashboard, password controls
remaining absent until capability enablement, tray/menu-bar lifecycle,
automatic address presentation, and source + Markdown co-change. Do not add
unrelated documentation-only churn while an exact-SHA qualifying run is in
progress.

## R10 HostControl selector source-contract correction after exact-head CI (2026-10-21)

Exact-main SHA `6875e7f462458d2a7da0bef0dbf1058a4301726f` landed the production
HostControl standalone-authentication selector, but hosted primary run
`39558058582` found one ordinary Ubuntu full-CTest failure:
`runtime.linux-host-control-standalone-authentication-selector`. The run
completed 839/840 tests successfully; SERVER-TEST preview then failed only
because it requires the Ubuntu protocol job. Windows, macOS, Linux production
security, GUI, sanitizer, documentation and workflow-structure jobs passed.

The failing source-composition check searched the HostControl header for the
qualified use spelling `ConfiguredAuthenticationMode::StandalonePassword`.
The enum declaration correctly contains `StandalonePassword,` and the
qualified spelling belongs to implementation use sites, where the same test
already requires the standalone branch and selection assignment. This is a
test-contract defect, not a production authentication or admission defect.

Corrective scope is deliberately test-only plus canonical documentation:
the header assertion now requires the enum declaration and unqualified
enumerator spelling while retaining the existing qualified implementation
checks. No R1/R2/R3/R4/R5/R7/R8/R10 runtime behavior changes.

Canonical owner-local configure/build/full CTest: **NOT RUN** in this connector
environment. Corrective publication-SHA hosted CI: **PENDING**. FIRST REAL
DESKTOP remains gated on an all-green exact-main SHA plus explicit owner
authorization for visible desktop + mouse + keyboard + Stop. R4 remains
blocked on that FIRST live trace; no codec, frame-ID or ACK-policy change is
authorized by this CI failure.

## R10 product authentication selector consumes standalone generation (2026-10-20)

Starting exact-main parent: `8f2667b9d4a9dd09b05486e91c3277fc3cb4af72`.

Current-source inspection found one real R10 gap despite the landed R2 selector:
`LinuxRuntimeConnection` already accepted
`LinuxRuntimeAuthenticationSelection`, but
`LinuxRuntimeHostControl::acceptClientOnce()` still called the four-argument
constructor and therefore always selected `ExistingOsAccount`.

R10 now records one explicit configured authentication mode. Existing-OS-account
setup selects the Kerberos path. Internal standalone-password preparation
captures the exact current `StandalonePasswordCredentialOwner` generation and
requires a successful synchronous visitor before it can become service-ready.
The public `IndependentApplicationPassword` choice is still rejected and still
cleans/revokes any alternate standalone credential.

For each accepted standalone connection, R10 rechecks that captured generation,
performs another exact-generation synchronous visit, creates a fresh
cryptographically random NTLM ServerChallenge with OpenSSL `RAND_bytes`, binds
a current Windows FILETIME plus bounded non-secret TargetInfo names, and passes
the resulting selection to the five-argument `LinuxRuntimeConnection`
constructor. Failure retires owner authority/client state/listener instead of
falling back to OS-account authentication. The two R2 admission-request sites
also use the selected authentication kind, so standalone admission remains
principal-free and cannot accidentally request the Kerberos identity path.

Dedicated offline source-composition CTest:
`runtime.linux-host-control-standalone-authentication-selector`. It requires
the exact-generation visitor, challenge construction, explicit five-argument
connection handoff, standalone admission kind and absence of the old default
constructor in the accepted-client slice; it also keeps the public Qt password
inputs absent.

Canonical owner-local configure/build/full CTest: **NOT RUN** in this connector
environment. Exact publication-SHA hosted CI: **PENDING**. No listener,
credential exchange, native desktop or Microsoft client was activated.

**Dependency result:** P1 selector composition is no longer blocked by R2P/R10X.
Real unmodified Windows App/`mstsc.exe` standalone-password acceptance is still
required before exposing `IndependentApplicationPassword` in the public GUI.
FIRST OS-account acceptance remains separately gated on one all-green exact-main
SHA plus explicit owner authorization for visible desktop + mouse + keyboard +
Stop.

## R7 cross-platform offscreen lifecycle assertion reconciliation (2026-10-20)

Starting exact-main parent: `d0f404a0b6080baa813b8f8ab7419c9d93954ddc`.

Exact-head primary run `39483732931` is green for Ubuntu protocol/full CTest,
R9 security sanitizers (including the R1 native TCP-reset sentinel), Linux
production runtime security, Windows protocol, macOS protocol/native lifecycle,
Linux GUI ZIP, documentation and SERVER-TEST preview. The two failing hosted
jobs, R7 macOS PORTABLE-GUI and R6 Windows CLANG64, reproduce the same two Qt
offscreen assertions in both Windows Debug/Release and macOS Release.

Production inspection shows no packaging or runtime regression. R7 commit
`9620f5b78ac753e485125197a08d80a379f27029` intentionally changed
ListenerAvailable presentation from historical "Listener ready" to
"Listening; waiting for desktop connection", and requires authoritative
`nativeDesktopReady` before a stale per-client `desktopVisible` bit can
enter the visible-client list. Two older assertions were not reconciled with
that same commit. The dedicated
`gui.offscreen-r10-graphics-native-desktop-projection` test already pins the
fail-closed native-readiness behavior.

This correction changes only those two stale assertions: terminal listener
readiness now expects "Listening", and the stale desktop-visible peer remains
"Share activated; desktop pending" until the authoritative native owner is
ready. No production C++ or packaging behavior changes.

Canonical owner-local build/full CTest: **NOT RUN** in this connector
environment. Corrective exact-publication-SHA hosted CI: **PENDING**. FIRST
REAL DESKTOP remains gated on one all-green exact-main SHA plus explicit owner
authorization for visible desktop + mouse + keyboard + Stop.

## R9 accepted-client scheduler source-scope correction (2026-10-20)

Starting reconciled shared-main parent: `8cae86f4c724fd8dd0c321a8050afaf87832d97f`.

R9's five-test reconciliation correctly moved the accepted-client ordering check
off the whole translation unit, but its new slice began at
`advanceAcceptedClientOnce()`. The ordered contract intentionally begins
earlier in `acceptClientOnce(...)`: native accept -> private-LAN policy ->
authentication-attempt reservation -> sole `LinuxRuntimeConnection`
construction -> owner authority -> bounded protocol progression. Starting at
the phase-advance function therefore made the guard unable to find its own
first six required tokens.

The guard now spans `acceptClientOnce(...)` through the point immediately
before `serviceOnce()`. Static authoring verification confirms all required
accept/pre-Share tokens occur once in the intended order inside that slice,
while the earlier post-Share Graphics helper that caused the original global
false match remains outside it. Production C++ is unchanged, including R4's
new authoritative first-frame/FRAME_ACK acceptance projection on this parent.

Canonical owner-local build/full CTest: **NOT RUN** in this connector
environment. Corrective exact-publication-SHA hosted CI: **PENDING**.
FIRST REAL DESKTOP TEST remains gated on one all-green exact-main SHA plus
explicit owner authorization for visible desktop + mouse + keyboard + Stop.

## R4 direct first-live lifecycle projection after R10X (2026-10-20)

**Starting shared-main parent:** `e826b8fae92b6a8d3e74d3e5f2de5d4e2129efb4`.

R10X is landed and source review confirms its bounded GUI lifetime preserves the
existing R4 contract: remap before frame-credit preflight, nonterminal
`DeferredForFrameAcknowledge` before capture/frame-ID advance, synchronous R5
borrow into mandatory ClearCodec publication, one R1/R3 graphics write owner,
and genuine post-Share FRAME_ACK intake through R4's sole ACK window. R8's
dormant clipboard composition introduces no second graphics/ACK owner.

The existing bounded first-client snapshot now projects R4's exact
`firstExactFrameWriteCommitted`, authoritative
`outstandingFrameAcknowledgements` and
`firstGenuineFrameAcknowledge` values alongside
`firstClearCodecFramePrepared`. Legacy first-frame/ACK summary booleans are
sourced from those same R4 values; private R3 latches remain only to de-duplicate
the bounded event ring. No frame ID, ACK set, publication credit, codec switch
or transport state is added.

Dedicated ordinary CTest:
`transport.dvc-graphics-r4-acceptance-status-projection`. The hosted
Graphics-DVC inventory advances 22 -> 23 and the independent CI structure
validator requires the same sentinel/count.

Canonical owner-local build/full CTest: **NOT RUN** in this connector
environment. Publication-SHA hosted CI: **PENDING**. FIRST REAL DESKTOP remains
blocked on one all-green nominated exact-main SHA plus explicit owner
authorization for the live test. ClearCodec remains the required first live
codec; AVC420 remains secondary.

## Exact-head five-test contract reconciliation after R8/R2 composition (2026-10-20)

Exact-main SHA `ce396d9633e54e8c4cb6188ee7f6de5c2fe32e19` compiled successfully on Ubuntu but full Debug CTest
run `39482380643` reported five failures. Review found no new runtime
authorization or native-owner defect. Four failures were source-contract tests
still naming pre-refactor spellings or searching across multiple scheduler
functions; the fifth expected GSS to become `Failed` even when service
provisioning now denies before any authentication mechanism is configured.

The corrective increment changes tests/contracts only:
- scope accepted-client phase ordering to
  `LinuxRuntimeHostControl::advanceAcceptedClientOnce()`, so the earlier
  bounded post-Share Graphics progression cannot confuse the pre-Share order;
- require the actual `context->clipboard->dispatchAuthenticatedTpkt(...)`
  dormant R8 route;
- require `principalProof` rather than the retired GSS-specific
  `acceptor` name in the R5 terminal-input fence and the sole pre-R3
  `broker_->revalidate(...)` source contract;
- keep the configured premature-admission case terminal, while the
  unconfigured-service constructor correctly leaves GSS `Unconfigured`.

No production C++ behavior changes. R10X remains landed; clipboard activation
remains false. FIRST REAL DESKTOP TEST still requires a fully green exact-main
SHA and explicit owner authorization for live execution. Corrective exact-SHA
hosted CI: **PENDING**.

## R8 dormant GUI clipboard composition after R10X (2026-10-20)

**Starting reconciled shared-main parent:** `78f518df84c40615c59cac7bded6aa8655c035b3`.

R10X is landed, so R8 now reuses one shared
`LinuxPreparedClipboardOwner` in both serialized Linux post-Share lifetimes:
the CLI candidate and the GUI `LinuxRuntimeHostControl` native-desktop state.
The GUI owner is prepared from the exact R2-selected admission/session
generations and borrows the same R5 XCB connection. It introduces no second
RDP parser, XCB connection, clipboard generation, authorization cache or TLS
writer.

Production activation remains intentionally **OFF**:
`kLinuxProductionClipboardActivationApproved = false`. The shared owner keeps
`PresentationScope::UnicodeTextOnly`; no PNG, FileContents, completed-file or
directory-transfer entry point is composed. A pending clipboard R3/R1 write has
scheduler precedence over Graphics write, application read and capture, and an
already-pending write advances at most once per bounded Qt service tick. A
newly staged response may only prime the existing writer with no readiness
flags.

Stop/Revoke/reconnect retirement is now identical in GUI and CLI:
local-owner authority -> R8 X11 selection/paste/INCR plus bridge/receipt state ->
R5 native desktop -> accepted R3/R2/R1 connection -> listener. No pending INCR
transfer, selection ownership, stale positive TLS receipt or clipboard response
route may survive the native owner.

New ordinary offline CTest:
`runtime.linux-host-control-dormant-unicode-clipboard-composition`. Existing
`runtime.linux-x11-clipboard-production-linkage` now verifies the shared owner
instead of a CLI-local duplicate.

Canonical owner command: `cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure`.
Connector-environment canonical build/full CTest: **NOT RUN**. Exact
publication-SHA hosted CI: **PENDING**. Live Windows App/`mstsc.exe` desktop,
input, Stop and clipboard: **BLOCKED / NOT RUN**; no live authorization was
requested.

**Next gate:** obtain one all-green exact-main SHA, then owner-authorize the
FIRST REAL DESKTOP TEST and require visible desktop + mouse + keyboard + Stop.
Only after that PASS may a later change flip the single activation gate for
Unicode text. Images/files remain later.

## R9 malformed runtime-security workflow reconstruction (2026-10-20)

Starting shared-main parent: `bf3755dfa119420c0c5550aac937bb68749aa0dc`.

Exact-head Actions at `bf3755dfa119420c0c5550aac937bb68749aa0dc` failed before build/test evidence:
independent structure run `39479019701` reported a YAML parse failure and the
primary workflow could not create jobs. The R2 sanitizer-inventory edit had
dropped the closing `$'` from `runtime_security_selection` and appended
roughly one thousand duplicated workflow lines after the legitimate Linux GUI
job tail.

The workflow is reconstructed from last valid parent `c1ec4c675c68ad197254e43356dce2782681cf47` and
reapplies only the intended R2 delta: add
`runtime.linux-connection-standalone-authentication-selector-denials`, require
it by exact name, and advance the executable-backed inventory from 40 to 41.
The independent structure validator advances to the same exact-name/count
contract. The landed R2 shared-proof input-route C++ and test changes on the
starting parent are preserved.

Owner-local canonical build/full CTest: **NOT RUN** in this connector
environment. Failing workflow evidence: **CONFIRMED**. Corrective exact-SHA
hosted CI: **PENDING**. R10X remains resolved; FIRST REAL DESKTOP TEST still
requires a fully green nominated exact SHA plus owner-approved live execution.

## R2/R5 shared-proof input-route compile correction (2026-10-20)

Exact-SHA CI for `c1ec4c675c68ad197254e43356dce2782681cf47` passed the production Linux security build but the
ordinary Ubuntu Debug graph found one stale R5 type dependency:
`x11_authorized_input_route.h` still named `GssapiSpnegoAcceptor` after R2
moved the broker to `LinuxAuthenticatedPrincipalProof`. Re-introducing the
GSS include would compile only the Kerberos path and would leave standalone
input outside the shared R2 proof model.

The R5 stateless authorized-input route now consumes
`LinuxAuthenticatedPrincipalProof&` directly. Existing GSS tests still pass a
real `GssapiSpnegoAcceptor` through normal derived-to-base conversion, while a
standalone connection can use the same route after admission. No input
authorization semantics change: the route still requires the exact lease,
R1 connection, R3 session, native generation and fresh input permission check.

R9's bounded direct runtime-security sanitizer selector also includes
`runtime.linux-connection-standalone-authentication-selector-denials` and is
pinned at 41 executable-backed cases instead of 40.

Owner-local build/full CTest: **NOT RUN**. The failing hosted compiler boundary
was identified at exact SHA `c1ec4c675c68ad197254e43356dce2782681cf47`; corrected exact-SHA CI is **PENDING**.

## R2/R10 per-connection authentication selector and standalone runtime composition (2026-10-20)

Starting shared-main parent: `a66ea25fbf0cfc6ac0ad5002e695c0c280064ce1`.

The production Linux connection aggregate now has one explicit
`LinuxRuntimeAuthenticationSelection`. Existing callers retain
`ExistingOsAccount` by default. R10 may instead select
`StandalonePassword` for one accepted connection by supplying the exact
service-lifetime `StandalonePasswordCredentialOwner`, its current generation,
and one bounded non-secret NTLM challenge identity. Those challenge
`string_view` fields are consumed synchronously by construction and are not
retained by R10/R2.

Standalone mode does not configure or drive the GSS acceptor. It advances the
same R1-owned TSRequest reader/writer through
`StandaloneCredSspNtlmAcceptor::processCompleteOwnedFrame`, visits the exact
credential generation synchronously for every mechanism step, binds
`StandalonePasswordAuthenticatedPrincipalProof` only after owner-bound
`CredentialsVerified`, and then issues the normal
`LinuxConsoleAdmissionBroker` lease. Every later R3 call is routed through
the one selected `LinuxAuthenticatedPrincipalProof*`; no second broker,
lease, native-session controller or R3 gateway exists.

`LinuxRuntimeAdmissionConfiguration` also exposes the exact request hook for
R10: Kerberos mode returns the configured principal/account selector, while
standalone mode returns the same configured OS account/seat/display/permission
scope with an explicitly empty Kerberos principal and
`StandalonePassword` authentication kind.

Dedicated ordinary CTest:
`runtime.linux-connection-standalone-authentication-selector-denials`.
It proves a current standalone credential/challenge can construct a scheduler-
ready connection while GSS remains unconfigured, and that stale credential
generation or an invalid challenge fails closed without a lease. The existing
admission-configuration regression additionally pins the principal-free
standalone request projection.

R2C/R2P code composition is therefore no longer blocked on R10X/R5. The product
GUI password field remains disabled: R10 still must choose this explicit hook
from a reviewed product credential flow, and acceptance still requires a real
unmodified Windows App/`mstsc.exe` authentication run. FIRST REAL DESKTOP TEST
is separately waiting on a nominated exact-main SHA with the full hosted matrix
green plus owner-approved live execution.

Canonical owner-local build/full CTest: **NOT RUN** in this connector
environment. Exact publication-SHA hosted CI: **PENDING**.

## R2 standalone authenticated-principal proof owner binding (2026-10-20)

Starting reconciled shared-main parent: `90c52e2eb5956a8b885e770018880febf8d4a69c`.

The standalone CredSSP owner now has a production-only frame path that accepts
only TSRequests read through the exact `OwnedPreauthTcpConnection`. It rejects
mixing the direct-SSL compatibility path with owner-bound frames, pins the
exact connection/TLS/certificate provenance across all CredSSP frames, and
queues every response through the same R1 owner. A direct in-memory TLS fixture
may still reach mechanism-level `CredentialsVerified`, but can never qualify
as production R2 proof.

`StandalonePasswordAuthenticatedPrincipalProof` implements the shared R2
proof contract. Binding requires the exact owner-bound CredSSP
`CredentialsVerified` state plus the exact current configured
`StandalonePasswordCredentialOwner` generation. Initial admission,
completion, and every later protected-operation revalidation recheck that
credential generation and exact active TLS owner. Revoking one connection
retires its CredSSP/proof state but does not revoke the service-lifetime
application password.

Dedicated ordinary CTest:
`security.standalone-credssp-direct-tls-cannot-bind-admission-proof`.
It proves the existing direct-SSL test path cannot be promoted into a native
admission proof even with a configured matching credential generation.

This completes the standalone proof object itself, but not the production
connection composition. R10/runtime still needs the exact per-connection hook
that selects GSS versus standalone CredSSP, visits the service credential at
its captured generation while advancing the owner-bound standalone handshake,
then passes the resulting proof to the already-shared broker. The GUI password
field remains disabled until real Windows App/mstsc acceptance.

Canonical owner-local build/full CTest: **NOT RUN**. Exact publication-SHA
hosted CI: **PENDING**.

## R7 consumes resolved R2 grant observation and R10X native status (2026-10-20)

Starting reconciled shared-main parent:
`e2329fc07321acc0d58cdf909591d962a0ff6a30`.

Two R7 dependencies have landed from other owners. R2 exposes its read-only
owner-grant observation through `RuntimeHostStatus`, and R10X owns the real
R2-selected X11 desktop after genuine Graphics readiness. R7's existing
graphics/native projection already requires the real `nativeDesktopReady`
fact before it can display a visible/connected desktop, so no second native
state machine is added.

This increment consumes the R2 grant observation in Qt. The UI renders only
R2's active/expired/unavailable state, effective permission mask and remaining
monotonic lifetime. The input, clipboard and lifetime controls remain request
intent and are never echoed as authoritative grant state. An active observation
is shown as current only when the same R10 snapshot independently reports fresh
view authorization; expiry or terminal host-session loss exposes no effective
scope/lifetime.

Dedicated ordinary offscreen CTest:
`gui.offscreen-r2-owner-grant-observation`. It deliberately makes the request
controls disagree with the R2 observation, requires the observed grant to win,
then covers expiry and terminal-session suppression.

R10X has removed the former native-composition code blocker for Desktop
Visible/FIRST. Parent exact-head structure run `39476189223`: **PASS**.
Parent main CI run `39476189243`: **QUEUED**. FIRST REAL DESKTOP therefore
still waits on a nominated exact-main SHA with all ordinary hosted lanes green
plus owner-approved live execution.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest:
**NOT RUN** in this connector environment. Exact publication-SHA hosted CI:
**PENDING**.

Session Password remains **BLOCKED**. R2 has generalized the one
`LinuxAuthenticatedPrincipalProof` broker contract, but still needs the
standalone proof implementation bound to exact TLS/CredSSP
`CredentialsVerified` plus exact `StandalonePasswordCredentialOwner`
generation, then R10's per-connection selector hook and real Windows
App/`mstsc.exe` interoperability proof before product password fields can be
enabled.

## R2 common authenticated-principal proof contract (GSS migration) (2026-10-20)

Starting reconciled shared-main parent: `5e9d6cb379232eb9b72749a77b3801df42b7f1c0`. R10X is now landed; FIRST REAL
DESKTOP TEST therefore no longer waits on native X11 composition and is blocked
only on a nominated fully green exact SHA plus owner-approved live execution.
That acceptance gate does not block this R2 work.

R2 now owns one `LinuxAuthenticatedPrincipalProof` contract for the existing
native admission broker. The contract covers pending admission proof, the
one-shot native-admission completion latch, protected-operation revalidation
against the active TLS identity/policy generation, and terminal proof
revocation. `LinuxConsoleAdmissionBroker` and all R3 protected gateways now
consume this abstraction rather than naming `GssapiSpnegoAcceptor` directly.

The existing GSS/Kerberos owner is the first implementation. It preserves the
same exact R1-owned HYBRID/TLS binding, GSS principal, PAM-authorized account,
policy-generation and terminal-reject checks. The one R2 lease also retains the
candidate authentication kind so revalidation can reconstruct the exact
identity shape.

Dedicated ordinary CTest:
`security.authenticated-principal-proof-gss-compatibility`.

The next R2 step is a standalone proof implementation bound to the exact
accepted R1 connection/TLS provenance, `CredentialsVerified`, and exact
`StandalonePasswordCredentialOwner` generation, followed by R10's
per-connection selector hook. No second broker or lease owner is introduced.

Canonical owner-local build/full CTest: **NOT RUN**. Exact publication-SHA
hosted CI: **PENDING**.

## R9 structure-validator follow-up for 88-case clipboard inventory (2026-10-20)

Starting shared-main parent: `371502512ca6748d57afa7592d6be41453b09e18`.

Corrective SHA `371502512ca6748d57afa7592d6be41453b09e18` updated the primary sanitizer workflow to the
intentional 88-case R8 clipboard inventory, but independent structure Actions
`39475811289` failed immediately because
`scripts/validate_ci_workflow.py` still required the stale literal
`clipboard_expected_test_count=87`. Primary run `39475811293` failed the
same structure prerequisite before the heavyweight matrix could qualify the SHA.

The structure validator now advances atomically with the workflow: it requires
`clipboard.x11-unicode-text-only-presentation` and
`clipboard_expected_test_count=88`. No production/runtime behavior changes.

Local canonical build/full CTest: **NOT RUN** in this connector environment.
Failing structure evidence: **CONFIRMED**. Corrective exact-SHA hosted CI:
**PENDING**. R10X remains landed; FIRST REAL DESKTOP TEST is waiting on a
fully green exact SHA and owner-approved live execution.

## R9 exact-head clipboard sanitizer inventory repair after R10X (2026-10-20)

Starting shared-main parent: `8af251c751d87a21565a02593134808d0b4a2661`.

R10X is now landed, so FIRST REAL DESKTOP TEST is no longer code-blocked on
native X11 composition. The remaining prerequisite is a nominated exact-main
SHA with every ordinary hosted lane green.

Hosted evidence on R1 SHA `75668042f27f1e596d094a29ff08fd0fab870d19`
(run `39474368698`) and its R2 descendant showed the same deterministic R9
failure before clipboard CTests executed:
`R8 clipboard registry mismatch: expected 87 tests, found 88`.

The 88th registration is intentional:
`clipboard.x11-unicode-text-only-presentation`, introduced by R8's prepared
text-only production-composition work. CI now requires that exact behavior by
name and pins the sanitizer clipboard inventory at 88. No runtime, clipboard
activation, R1 transport, R2 authority, R10X native ownership or protocol
behavior changes.

Canonical owner `~/rdp-server/build` configure/build/full CTest:
**NOT RUN** in this connector environment. Failing hosted evidence:
**CONFIRMED**. Corrective exact-publication-SHA hosted CI: **PENDING**.
After green ordinary hosted CI, the next R1/R10 gate is the owner-approved
FIRST REAL DESKTOP protocol/transport/visible-frame test.

## R10X GUI-owned X11 desktop and bounded post-Share service (2026-10-20)

**Starting reconciled shared-main parent:** `a870aab1c1708d313e38dcbe6046ec4996be0b61`.

Dependency reconciliation against the current graph found R5's native
step/lifetime prerequisite already complete at `20831e2698`: the existing
`X11DesktopResources`, typed RandR-generation borrow, authorized slow-path
input route and R2 native-change registration are sufficient. R9's stale
source-contract/compiler blockers are repaired on this parent. Intervening R1
transport classification and R2 owner-grant/standalone-candidate increments were
also reconciled: R10X preserves their behavior, and none is an external R10X
code blocker.

After genuine RDPGFX control reaches `GraphicsReady`, the GUI HostControl uses
the existing `visitNativeDesktopSelection(...)` authority boundary to construct
exactly one X11 owner from R2's selected DISPLAY and admission/session
generations. The owner lives beside the sole accepted `LinuxRuntimeConnection`;
status reports native initialization/readiness only from that concrete owner.

The 25 ms Qt service timer remains the only scheduler. Each post-Share tick
performs fresh R2 authorization, registers the current logind borrow, executes
one zero-timeout three-fd poll, unregisters the borrow before callbacks, drains
at most 128 X11 events, advances at most one existing R1/R3 application read or
Graphics write, progresses the existing resize/remap state, preflights R4 frame
credit, and performs at most one eligible typed synchronous R5 framebuffer
borrow/ClearCodec publication. `POLLERR/POLLHUP` is surfaced to R1 in its
requested direction for terminal classification; only `POLLNVAL` is a
scheduler-level socket failure. Clipboard remains explicitly fail-closed.

Terminal Stop/Revoke ordering is current-owner R2 authority -> X11 native
owner/no-XTEST retirement -> accepted R3/R2/R1 aggregate -> listener.
`disconnectClient()` uses native-before-connection retirement but keeps an
otherwise authorized listener, so reconnect constructs a fresh owner. A
completed first frame write may advance the presentation stage to
`DesktopVisible`; this is not real-client acceptance.

Dedicated offline source-composition CTest:
`runtime.linux-host-control-native-desktop-bounded-post-share`. The existing
bounded HostControl scheduler guard is tightened to include native retirement
between R2 authority and the accepted connection. Existing R1 loopback,
R5 native/Xvfb and RandR tests remain lower-level production evidence; ordinary
CI does not fabricate a positive seat0/logind lease.

Canonical `~/rdp-server/build` configure/build/full CTest: **NOT RUN** in this
connector environment. Exact publication-SHA hosted CI: **PENDING**. No live
desktop, XTEST, credential, listener or Microsoft client was exercised here.

**Next gate:** FIRST REAL DESKTOP TEST is blocked only on an exact-main SHA with
this R10X composition and all ordinary hosted lanes green. The separate clean
Windows runner remains an R6/R9 packaging acceptance dependency, not an R10X
code prerequisite.

## R2 principal-free standalone native-account candidate (2026-10-20)

Starting shared-main parent: `71c02ece1d8b32bcc4d78990076d4f018b5dbdd8`.

R2's native evidence/policy layer now distinguishes the existing Kerberos
principal path from the standalone application-password path. A standalone
candidate must carry an empty Kerberos principal and is matched only against
the configured exact Unix account, seat0/display, native UID and permission
scope. The configured rule's real Kerberos principal remains required and
unchanged for GSS admission; it is never copied or fabricated for standalone
authentication.

The common NSS/logind sampling, physical-session checks, session generation and
freshness fingerprint remain unchanged. This boundary is still candidate-only:
choosing `StandalonePassword` is not authentication and cannot issue an R2
lease. The next R2 increment must bind the exact R1 TLS/provenance,
`StandaloneCredSspNtlmAcceptor::CredentialsVerified`, and the exact
`StandalonePasswordCredentialOwner` generation into the one broker/lease
owner before this native candidate can be consumed.

Dedicated ordinary CTest:
`security.console-evidence-standalone-native-account-candidate`.

Canonical owner-local build/full CTest: **NOT RUN** in this connector
environment. Exact publication-SHA hosted CI: **PENDING**. R10X and exact-head
green CI remain the separate blockers for FIRST REAL DESKTOP TEST.

## R2 read-only owner-grant observation for R10/R7 (2026-10-20)

Starting reconciled shared-main parent: `75668042f27f1e596d094a29ff08fd0fab870d19`.

R2 now exposes a non-secret read-only observation of the one existing
`CurrentOwnerSharingAuthority` grant: active/expired/unavailable state,
effective permission mask only while active, and remaining monotonic lifetime.
The observation does not sample or cache native authorization, does not mutate
the revocation epoch, and cannot substitute for `authorizes()`. Linux R10
projects the same facts through `RuntimeHostStatus` for R7 presentation while
continuing to perform the existing fresh view-permission authorization check.

Dedicated ordinary CTest:
`security.owner-consent-read-only-grant-observation`. It proves unavailable,
active remaining lifetime, expiry with zero effective permissions, and explicit
revocation, including that merely observing expiry cannot mutate authority.

Canonical owner-local build/full CTest: **NOT RUN** in this connector
environment. Exact publication-SHA hosted CI: **PENDING**.

This removes the owner-grant-observation subtask from R2C. It does not complete
standalone-password admission: the remaining R2-owned boundary is still the
single authenticated-principal proof that must converge GSS/Kerberos and the
exact generation-fenced standalone CredSSP result on the existing native lease.
R10X/X11 remains independent of that R2 work.

## R1 peer-termination classification after accepted-client unblock (2026-10-20)

Starting shared-main parent: `bd134d748dbccbdf2b812c7ad9e20b1ad17ff247`.

Dependency recheck confirms R10's bounded GUI accepted-client scheduler is
landed, so R1 no longer waits on an accepted-socket handoff for offline
transport work. R10X native X11 composition still blocks the first real desktop
test, and exact-head ordinary hosted CI is still pending; neither blocks this
production-backed loopback/TLS increment.

Source review found one R1 diagnostic defect: Linux
`pollSocketReadinessOnce()` treated `POLLERR` as immediate generic revoke,
allowing an abortive peer reset to become `Cancelled` before the sole R1
SSL/socket owner could classify it. The scheduler now reserves immediate
failure for `POLLNVAL`; `POLLERR` and `POLLHUP` are dispatched once in
the currently requested direction so the existing R1 operation observes the
real EOF/reset.

New ordinary CTest:
`runtime.linux-connection-r1-terminal-transport-classification`. It uses real
nonblocking loopback TCP plus the production TLS context and covers graceful
`close_notify`, TCP half-close without TLS shutdown, abortive peer RST,
malformed TLS during handshake, and deliberate descriptor-number reuse after
revoke. It requires the corresponding `OrderlyTlsClose`, `TransportError`,
`TlsFailure` and `Cancelled` diagnostics and proves stale calls cannot touch
a reused fd.

Canonical owner `~/rdp-server/build` configure/build/full CTest:
**NOT RUN** in this connector environment. Exact publication-SHA hosted CI:
**PENDING**. No HostControl listener, R2 admission, native desktop, service,
firewall or Microsoft client was activated. The remaining HostControl-specific
R1 Stop/Revoke cases that require a genuinely authorized positive listener are
not fabricated by ordinary CTest; they remain for an owner-authorized live
protocol/transport trace. Desktop acceptance remains **BLOCKED on R10X plus a
green nominated exact SHA**.

## R9 source-guard follow-up from exact-SHA hosted evidence (2026-10-20)

Run `39473001753` at superseded SHA `c205913...` proved the provisioned-listener
and verified-account guards pass, but exposed three remaining formatting/scope
defects: a wrapped `requestConsent()` call, an earlier status-only
`GraphicsReady` observation, and CMake list splitting on semicolons in the
cooperative-retirement token list. R9 now anchors the consent method call
independent of argument wrapping, requires the actual scheduler assignment to
`GraphicsReady`, and compares semicolon-free call tokens inside the isolated
retirement helper. No production ownership or teardown behavior changes.

## R9 Linux GUI ZIP follow-up: Qt macro-safe limiter header (2026-10-20)

Exact-SHA run `39473001753` at `c205913e1e121dfa59572205c91466894a3b4631`
confirmed the earlier GCC 13 MD4 blocker is fixed: the standalone NTLMv2
library built successfully. The same Linux GUI ZIP lane then exposed the next
compile blocker when Qt's keyword-like `slots` macro reached
`AuthenticationAttemptLimiter::findOrReuseSlot(... &slots, ...)`.

Rename that private template parameter to `attemptSlots`; no API or limiter
behavior changes. The existing limiter test now pre-includes the header with an
empty `slots` macro after its standard dependencies, so any future
Qt-sensitive identifier regression fails in ordinary compilation rather than
only in the GUI packaging lane.

SHA `c205913...` is therefore not the nominated desktop-test SHA. A new exact
publication SHA must rerun the complete ordinary hosted matrix; clean Windows
remains separate and must use that same final artifact identity.

## R9 exact-head CI repair after concurrent R10/R5/R3/R7 work (2026-10-20)

**Publication parent:** `9620f5b78ac753e485125197a08d80a379f27029`. The failing evidence under repair remains
exact-head run `39468550998` at `4f5c9e75e15682ab38c8fa800c6cb4b6de050d10`. The intervening R5/R3/R7
commits do not change the six failing R9 production/source-guard files; the R7
HostControl additions were rechecked and preserve the Start transaction and
single current-owner authority.

R9 repairs the four Ubuntu source-contract regressions without restoring
obsolete spelling. HostControl is required to own exactly one R2 current-owner
authority; Start is checked inside `startSharing()` as the semantic transaction
credentials -> owner authorization -> endpoint revalidation -> TLS identity ->
bind -> bound identity -> policy -> listener publication; the PAM attempt
limiter remains between configured GSS and the authority-aware R2 broker; and
cooperative Stop is scoped to the actual terminal helper, preserving native
no-XTEST retirement before the accepted R3/R2/R1 aggregate and the outer
listener lifetime.

The full GUI order remains the R10X composition contract already documented by
R5: owner-authority invalidation -> R8/native X11 retirement -> accepted
R3/R2/R1 connection -> listener. R9 does not manufacture that not-yet-integrated
HostControl/X11 ownership as source evidence; the existing bounded GUI scheduler
guard pins owner-authority -> accepted-connection -> listener until R10X lands.

The same correction removes two compiler blockers without suppressing warnings.
C++ systemd errors use aggregate zero-initialization instead of the C99
compound-literal `SD_BUS_ERROR_NULL` macro, and MD4's bounded staging copies
use explicit indexed byte loops so GCC 13 cannot lower the copy through the
observed false `-Warray-bounds` path.

Exact-publication-SHA hosted CI is **PENDING**. FIRST REAL DESKTOP TEST remains
blocked on R10X plus one nominated exact SHA with every ordinary hosted lane
green. Clean Windows remains a separate self-hosted operational blocker; keep
the nominated artifact/SHA identity and do not substitute another SHA.

## R7 authoritative accepted-client / native-desktop status projection (2026-10-20)

Starting shared-main parent: `68332b57ef12b5fc6ab9e51bbec1bc7c2c91a9ae`.

R7 now consumes R10's bounded accepted-client scheduler without creating a
second lifecycle owner. The shared runtime status exposes a read-only
`graphicsReady` fact only when the sole accepted connection has reached
R10's existing `AcceptedClientPhase::GraphicsReady`. It also reserves
`nativeDesktopInitializing` for the real R10/R5 owner and reports a bounded
`clientDisconnected` observation only after an accepted client is actually
retired while the current listener remains live.

The Qt projection renders Listening, Client authenticating, Share activated,
Graphics ready, Native desktop initializing, Desktop visible, disconnected and
revoked as distinct facts. A client is never listed as connected/visible unless
R10's authoritative `nativeDesktopReady` is also true; a Share/RDPGFX-ready
stage or stale per-client `desktopVisible` bit cannot manufacture that fact.
Current Linux R10 still leaves native initialization/readiness false, so the
real Desktop visible transition remains **BLOCKED on R10 X11 composition**.

R2 still does not expose a read-only effective grant observation: permission
bits, deadline and lease generation remain private inside
`CurrentOwnerSharingAuthority`. R7 therefore continues to send the requested
scope/lifetime as intent only and explicitly does not present those UI controls
as the effective grant. Effective scope and remaining lifetime stay
**BLOCKED on the R2 observation API**.

The Session Password surface remains non-collecting. No password or
confirmation widget is constructed and no user-settable capability flag is
introduced while standalone CredSSP admission is not composed into the live
accepted-client path and no real Windows App/mstsc interoperability receipt
exists. The landed R2P memory-only credential owner therefore remains internal;
product password UI is still **BLOCKED on R2 standalone admission + real-client
proof**.

Dedicated ordinary offscreen CTest:
`gui.offscreen-r10-graphics-native-desktop-projection`. Existing lifecycle,
client-retirement, unsupported-password and owner-permission forwarding tests
are tightened around the same contract. Canonical local build/full CTest:
**NOT RUN** in this connector environment. Exact publication-SHA hosted CI:
**PENDING**.

## R3 R10 scheduler review and explicit Graphics-control observability (2026-10-20)

**Authoring parent:** `20831e2698f9849d508daceb33a5caa4f0379c0a`; R10 scheduler reviewed at
`4f5c9e75e15682ab38c8fa800c6cb4b6de050d10`. The intervening R5 lifetime audit changes documentation only
and confirms that no additional R5 service primitive is required before R10
attaches the one selected X11 owner.

Source review confirms the new Qt scheduler does not create another RDP parser,
TLS owner or Graphics state machine. One `LinuxRuntimeConnection` still owns the
R1 TLS application stream and the existing R3 `McsSessionLifecycle`; R10 only
advances one existing phase per owner-thread tick. The positive progression is
Share activation -> existing DRDYNVC begin/advance -> RDPGFX control -> the
existing application-traffic gate. R4 remains the sole frame/FRAME_ACK truth.

The review exposed one observability-only gap in R3: the bounded first-client
trace already distinguished MCS established, Share activated, peer-accepted
DRDYNVC CREATE, surface CREATE/MAP, first fully accepted frame publication and
first genuine FRAME_ACK, but it did not separately identify completion of the
RDPGFX control handshake. R3 now records `GraphicsControlReady` only after the
existing writer has fully accepted CAPS_CONFIRM and the existing Graphics owner
reports `graphicsCapabilitiesConfirmed()`. The diagnostic enum value is
appended so existing diagnostic values remain stable. No wire bytes, capability
selection, surface/frame ownership, ACK credit, authorization or scheduler
behavior changes.

The existing
`transport.dvc-graphics-first-client-acceptance-observability` CTest now pins
the distinct ordering
MCS -> Share -> DRDYNVC -> Graphics control -> surface CREATE -> surface MAP ->
first frame -> first FRAME_ACK. No new test executable or sanitizer selector is
added; the R9 Graphics-DVC inventory remains 22 cases.

The Windows App on macOS / Windows 11 `mstsc.exe` trace-analysis checklist is
canonicalized in [testing standards](testing_standards.md). Protocol changes
remain **BLOCKED** until R10 attaches the R2-selected native X11 desktop and a
real client produces a failing trace. The first missing post-Share milestone,
not speculation, determines R3's next diagnosis.

Owner-local canonical build/full CTest: **NOT RUN** in this GitHub connector
environment. Exact publication-SHA hosted CI: **PENDING**. Real Windows App,
`mstsc.exe`, physical X11 desktop and FRAME_ACK acceptance: **BLOCKED / NOT
RUN** on the remaining R10 native-owner/post-Share loop plus a green exact SHA.

## R5 Qt-service X11 owner lifetime audit (2026-10-20)

Starting shared-main parent: `4f5c9e75e15682ab38c8fa800c6cb4b6de050d10`.

R5 audited the one existing X11 desktop aggregate against R10's new 25 ms Qt
accepted-client scheduler. No missing R5 service primitive was found.
`X11DesktopResources` already provides one selected-display constructor,
one native fd, bounded/readiness-gated `processEvents()`, typed native
geometry/capture generations, synchronous callback-only framebuffer borrowing,
R2-gated slow-path XTEST dispatch, and terminal
`retireAfterAuthorizationLoss()` with input retirement first and no cleanup
XTEST. R2's existing logind change source is zero-timeout and exposes its fd;
the blocking multi-fd `poll()` belongs only to the CLI composition in
`main.cpp`, not to the R5 owner.

The exact GUI composition contract is now documented in
`docs/ARCHITECTURE.md`: after Graphics-ready and fresh R2 authorization,
construct exactly one owner inside `visitNativeDesktopSelection()`; on later
Qt ticks use zero-wait readiness, unregister the borrowed logind registration
before callbacks, drain at most 128 XCB events, reauthorize, advance the sole
R1/R3 post-Share operation, reconcile typed geometry, then synchronously borrow
the current full framebuffer. Slow-path input remains behind the existing
per-event R2 gateway. On any authority/session/connection/native retirement,
R5 retires no-XTEST before the accepted connection is destroyed.

No production R5 code or Xvfb behavior changed, so no duplicate step API and no
new native test were added. Existing constructor/native capture calls contain
synchronous local XCB request/reply boundaries; the project's required
framebuffer handoff is explicitly synchronous. The Qt contract therefore
bounds scheduler waits/work count, not worst-case wall-clock latency of a
failed X server. A hard deadline for an unresponsive X server would be a
separate asynchronous-XCB redesign, not a small wrapper around the current
owner.

Canonical owner `~/rdp-server/build` configure/build/full CTest:
**NOT RUN** in this connector environment. No live X11 desktop, listener or
Microsoft client was started. Exact publication-SHA hosted CI: **PENDING**.

**R10 remains the first desktop code blocker:** move this already-defined
lifetime into `LinuxRuntimeHostControl` after `GraphicsReady`, set native
desktop status only from that actual owner, and preserve owner-authority ->
native no-XTEST retirement -> accepted-connection -> listener teardown. R5 has
no additional prerequisite for that composition.

## R10 bounded GUI accepted-client scheduler through Graphics control (2026-10-20)

Starting shared-main parent: `c911ffd48ad1f076efa4d969edf0c47e935267d2`. The only newer dependency work was
R2P's service-lifetime standalone-password owner; the existing-OS-account
CLIENT path remained blocked in R10 at the GUI-owned accepted-socket scheduler.

R10 now accepts at most one socket directly from the exact
`OwnedLanListener`, requires the immutable private-LAN deployment policy,
reserves the existing service-wide peer/global authentication-attempt budget,
and moves the descriptor once into `LinuxRuntimeConnection` with the same
`CurrentOwnerSharingAuthority`. The HostControl stores no TLS/GSS/MCS parser
or credential duplicate.

`serviceOnce()` advances one existing connection phase per Qt owner-thread
tick. Socket readiness uses `pollSocketReadinessOnce(..., 0ms)`; no callback
blocks the UI thread and no worker/poller is added. The progression reuses the
landed R1/R2/R3 owners through HYBRID TLS/CredSSP, native R2 admission, MCS
Connect/Attach/joins, protected Client Info, PersonalDesktop licensing, Share
activation, and DRDYNVC/RDPGFX control. Every R2 admission-denial transition is
treated as terminal host-session staleness. Ordinary malformed/disconnected
peer failures retire only that client and keep the authorized listener.

Stop/Revoke invalidates local-owner authority first, explicitly revokes the
accepted R3/R2/R1 aggregate second, and closes the listener last. The GUI drives
the bounded service tick every 25 ms and refreshes presentation state separately
every 250 ms; UI refresh is not the network scheduler.

Dedicated source-composition CTest:
`runtime.linux-host-control-bounded-accepted-client-scheduler`.
Owner-local build/full CTest: **NOT RUN** in this connector environment.
Exact publication-SHA hosted CI: **PENDING**.

**Remaining R10 gate:** after RDPGFX control becomes ready, R10 still has to
construct the one R2-selected X11 owner and move the existing persistent
post-Share capture/input/logind loop into the same bounded Qt-driven lifetime.
Until that lands, `nativeDesktopReady` remains false and no desktop frame is
published. This is now the first code blocker; it is not an unresolved R1/R2/R3
or R5 dependency.

## R2 standalone application-password service owner (2026-10-20)

Starting shared-main parent: `d46e0d944814a2d1a27f890619a79a920280b390`.

Dependency recheck found the standalone password protocol core already advanced
through Type 1/2/3, SPNEGO/mechListMIC, NTLM SIGN/SEAL, TLS-bound CredSSP
`pubKeyAuth`, and final `authInfo` credential equivalence. R10 also owns the
validated Linux admission selector/private-LAN service policy. The first real
CLIENT path remains independently blocked on R10's same-owner nonblocking
accepted-socket service step from the GUI-owned `OwnedLanListener` into the
existing `LinuxRuntimeConnection` / persistent R2-selected X11 loop.

R2P now adds one service-lifetime
`StandalonePasswordCredentialOwner` around the existing
`EphemeralNtlmV2Credential`. It retains no plaintext password: configure
consumes and non-elidably scrubs the caller's mutable UTF-16 buffer, while the
owner retains only the existing bounded username and NT hash. Every replacement
advances a monotonic generation; synchronous visitors must name the exact
current generation and cannot retain a raw credential reference. Failed
replacement invalidates the prior credential, and generation exhaustion is
terminal/fail-closed.

The Linux R10 HostControl now owns this credential beside the existing
current-owner authority. Its internal standalone setup seam revokes prior owner
consent as `CredentialChange`, invalidates the existing-OS-account ready bit,
and prepares the memory-only standalone credential without projecting generic
`credentialsConfigured` or enabling the product credential selector. Switching
back through any product credential-mode request, Stop, Revoke, or HostControl
destruction revokes/cleanses the standalone credential before listener
retirement.

The product GUI remains intentionally unchanged: no password field is
constructed, `IndependentApplicationPassword` still returns unsupported, and
Start cannot be enabled from this internal owner. This preserves the existing
rule that the secret input surface stays absent until real Microsoft-client NLA
interoperability is proven.

Dedicated ordinary CTests:
`security.ntlmv2-credential-owner-generation-revocation` and
`runtime.linux-host-control-standalone-password-lifecycle`. They pin caller
buffer cleansing, generation replacement fences, synchronous credential visits,
alternate-mode revocation, Stop/revoke retirement, and post-revoke input
cleansing without opening a listener or granting R2 consent.

Canonical owner checkout/build validation: **NOT RUN**. The required clone into
`~/rdp-server` was attempted and failed with
`Could not resolve host: github.com`; no alternate build root was created.
Exact publication-SHA hosted CI: **PENDING**.

R2P remains **ACTIVE**, but the next product-critical composition now meets the
same R10 gate as CLIENT: the accepted-socket service owner must consume the
exact standalone credential generation, run the already-landed standalone
CredSSP exchange, and combine `CredentialsVerified` with fresh
`CurrentOwnerSharingAuthority` before any native admission. Only after real
Windows App/mstsc interoperability is accepted may R7 expose the GUI password
entry or enable `IndependentApplicationPassword`.

## R10 owned admission selector and private-LAN service policy (2026-10-20)

Starting shared-main parent: `95e6762af32c8f5106101fe7d8fd11dcb6f0e6d0`. R2A, provisioned HostControl Start,
TLS/listener generation binding and the persistent CLI runtime are already
landed. R2P has independently advanced through standalone CredSSP final
`authInfo` verification at `95e6762`; that remains parallel to the
existing-OS-account first-client path.

This increment removes two R10-owned prerequisites for servicing the GUI-owned
listener. The validated configuration now snapshots the non-secret
Kerberos/account/seat/display/permission selector into one bounded
`LinuxRuntimeAdmissionConfiguration`. Its returned
`ConsoleEvidenceRequest` borrows only that service-lifetime owner and becomes
unavailable when the exact `ConsoleIdentityPolicy` pointer or generation
changes. CLI and GUI both consume the same snapshot helper; no configuration
string_view escapes the visitor callback.

`RuntimeDeploymentPolicy` also gains an explicit PersonalDesktop private-LAN
scope. It accepts only the same RFC1918 IPv4 and ULA/link-local IPv6 address
classes as the verified LAN-listener policy and remains distinct from the
existing loopback-only CLI mode. The provisioned Linux HostControl constructs
that immutable policy only after TLS/listener binding and fresh owner
reauthorization, immediately before listener publication. Stop/revoke retires
the policy with the listener.

Dedicated offline CTests:
`runtime.personal-desktop-private-lan-candidate-denials` and
`runtime.linux-security-admission-request-owned-generation-fence`.
Owner-local canonical build/full CTest: **NOT RUN** in this connector
environment. Exact publication-SHA hosted CI: **PENDING**.

**Remaining R10 gate:** the GUI still needs a bounded same-thread service step
that accepts from its exact `OwnedLanListener`, moves that socket into one
`LinuxRuntimeConnection`, and incrementally advances the existing
CredSSP/R2/MCS/Share/Graphics/X11 owners without blocking the Qt event loop.
That scheduler/state-machine extraction is now the first code blocker; it is
not an unresolved R1/R2/R5 dependency.

## R2 standalone CredSSP final authInfo equivalence (2026-10-20)

Starting shared-main parent: `dd513ac1cf3789a7f3a9e993e7ae2dc0d551f76d`.

Dependency recheck found another agent had already landed the TLS-proven
standalone CredSSP public-key binding at `dd513ac1`. The first Linux desktop
CLIENT path remains independently blocked at R10's same-owner, nonblocking
accepted-socket servicing from the GUI-owned `OwnedLanListener` into the
existing `LinuxRuntimeConnection` / persistent R2-selected X11 loop. That R10
gate does not block the parallel application-password lane.

R2P now consumes the final MS-CSSP `authInfo` message after the server
public-key-binding reply has been fully written and released. The existing
TLS-derived `TsRequestFrameReader`, pinned server TLS/certificate provenance,
and established standalone NTLM connection security remain the only owners.
The protected field is required to contain one 16-byte NTLM message signature
followed by bounded ciphertext. It is unsealed with the next client sequence,
then synchronously parsed through the existing canonical
`TSCredentials/TSPasswordCreds` parser.

A new internal validated-field visitor exposes only borrowed UTF-16LE
domain/user/password spans during that synchronous parse; it does not apply the
existing Unix-account naming policy. `EphemeralNtlmV2Credential` compares the
delegated identity against its configured ASCII username using the same
case-insensitive identity rule as NTLM and requires an empty domain. It hashes
the borrowed UTF-16LE password directly to an ephemeral NT hash and compares it
in constant time against the already-retained memory-only hash. No delegated
plaintext or username copy survives the callback. The decrypted authInfo buffer
is guarded by `SensitiveBytesGuard` and is cleansed on every exit.

On a successful exact match, the CredSSP reader/writer and NTLM mechanism keys
are retired immediately and the outer owner reaches
`CredentialsVerified`. That state is deliberately **non-authorizing**: it
does not issue `CurrentOwnerSharingAuthority`, an R2 admission lease, a native
desktop owner, or enable the GUI's `IndependentApplicationPassword` choice.

Dedicated ordinary CTests:
`security.standalone-credssp-authinfo-exact-credential-match`,
`security.standalone-credssp-authinfo-credential-mismatch-revokes`, and
`security.standalone-credssp-authinfo-tamper-revokes`. They run entirely over
the existing in-memory TLS fixture and cover exact credentials, username,
password and nonempty-domain mismatches, plus protected-message tampering.

Current Microsoft MS-CSSP review: **PASS** for final TSCredentials authInfo
shape and SPNEGO-protected credential sequencing. Canonical owner
`~/rdp-server/build` configure/build/full CTest: **NOT RUN** in this connector
environment. Exact publication-SHA hosted CI: **PENDING**.

R2P remains **ACTIVE**. The PASSWORD protocol core is no longer blocked on
Type1/2/3, SPNEGO, mechListMIC, NTLM SIGN/SEAL, TLS-bound pubKeyAuth, or final
authInfo equivalence. Its next product boundary is GUI memory-only secret
ownership/configuration/revocation and composition of this verified CredSSP
result with R2's existing current-owner authority without enabling any NLA
downgrade. Real Windows App/mstsc acceptance remains required before the product
credential choice can be enabled.

## R2 standalone CredSSP TLS public-key binding (2026-10-20)

Starting shared-main parent: `cada67f186526f4a7f05f60b61528771a05363e1`.

Dependency recheck found both broad compile defects from the preceding shared
head resolved: R2 repaired its standalone NTLM compile failure at `86df5d18`,
and R10 repaired the production Linux serve preprocessor guard at
`cada67f18`. The first Linux desktop/client chain is still independently
blocked at R10's same-owner accepted-socket service handoff from the GUI-owned
`OwnedLanListener` into the existing `LinuxRuntimeConnection` / persistent
R2-selected X11 loop. That R10 blocker does not block the parallel R2P password
lane.

R2P now adds one noninstalled `StandaloneCredSspNtlmAcceptor` around the
existing standalone SPNEGO/NTLM mechanism. It reuses the project's strict
`TsRequestFrameReader` and one-reply `TsRequestTlsReplyWriter`; no second
CredSSP DER parser, TLS transport, or message-security owner is introduced.
The first complete frame pins the exact established server `SSL*`, selected
X.509 certificate fingerprint, reader/writer objects, and CredSSP version 5/6.
Every later frame must match that provenance.

The owner accepts ordinary token-only negotiation and the MS-CSSP final
combined client shape containing the last SPNEGO token, protected
`pubKeyAuth`, and 32-byte client nonce. After the existing standalone NTLM
mechanism verifies the Type 3 message, the 16-byte NTLM signature and encrypted
32-byte client binding hash are unsealed through the same directional
connection state, compared against the active TLS certificate/nonce, and the
server-to-client binding hash is sealed through the opposite direction. The
reply is queued through the existing TSRequest writer as `pubKeyAuth` only.
For the combined NTLM-first fast path, only the exact empty SPNEGO
accept-completed envelope may be suppressed; an outstanding response token or
server mechListMIC is terminal rather than silently dropped.

Dedicated ordinary CTests:
`security.standalone-credssp-tls-bound-combined-pubkeyauth`,
`security.standalone-credssp-pubkeyauth-tamper-revokes`, and
`security.standalone-credssp-manual-frame-provenance-denial`. They use a
memory-BIO TLS 1.2 client/server pair and a generated test-only certificate;
no TCP listener, host credential, native desktop, or admission lease exists.

Current Microsoft MS-CSSP/MS-NLMP review: **PASS** for the implemented
v5/v6 public-key binding boundary and NTLM protected-message layout. Canonical
owner `~/rdp-server/build` configure/build/full CTest: **NOT RUN** in this
connector environment. Exact publication-SHA hosted CI: **PENDING**.

R2P remains **ACTIVE**. The PASSWORD node is no longer blocked on SPNEGO or
TLS-bound `pubKeyAuth`; its next code boundary is protected final
`authInfo` consumption with exact standalone username/password equivalence and
immediate plaintext retirement, followed by GUI memory-only secret
ownership/revocation and real Windows App/mstsc evidence. This increment does
not enable `IndependentApplicationPassword`, issue R2 admission, or downgrade
NLA.

## R10 Linux serve compile-guard repair (2026-10-20)

Current dependency state is unchanged: R2A and positive HostControl listener
Start are resolved; first-client progress is blocked on R10 accepted-socket
servicing. Before continuing that work, hosted production-security compilation
identified an R10 regression from the shared configuration extraction:
the Linux-only CLI serve aggregate lost its opening
`RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY` guard.

The opening guard is restored and pinned by the existing
`runtime.desktop-shared-configuration-feed` source CTest. This is a compile
repair only. The next R10 production step remains the same-owner, nonblocking
handoff from the GUI-owned `OwnedLanListener` into the existing
`LinuxRuntimeConnection` / persistent X11 loop.

## R2 standalone SPNEGO fallback integrity and compile repair (2026-10-20)

Starting shared-main parent: `2552a0d20f5fa09cfff013a766a8dd3bf15062a0`.

Dependency recheck consumed R10's provisioned listener transaction and shared
desktop configuration feed. The first Linux desktop/client path is therefore no
longer blocked on R2A, HostControl credential/TLS composition, or GUI config
provisioning. Its current independent blocker is R10's same-owner nonblocking
accepted-socket handoff from the GUI-owned `OwnedLanListener` into the existing
`LinuxRuntimeConnection` / persistent R2-selected X11 loop.

The parallel R2P password lane remained actionable, but the latest R5 receipt
also exposed a concrete R2 compile regression from the previous message-security
increment: `std::span` has no `fill()`. This increment repairs that by using
bounded iterator fill and factors the existing NTLM ESS MAC into SIGN-only
client verification/server signing helpers that share the exact directional
sequence number and KEY_EXCH RC4 checksum stream with SEAL.

SPNEGO fallback now retains the exact DER `MechTypeList`, emits `request-mic`
when NTLM was not the initiator's preferred mechanism, verifies the client's
16-byte NTLM SIGN token over that exact list, returns the matching server
mechListMIC with `accept-completed`, and preserves the advanced sequence/RC4
state for the next CredSSP protected message. Microsoft NegTokenInit2 is also
accepted correctly: context field [3] is parsed as `negHints` when it contains
the NegHints SEQUENCE, while [4] is its mechListMIC; RFC 4178's legacy [3]
mechListMIC form remains recognized. Missing or tampered fallback MIC is
terminal.

Dedicated ordinary CTest:
`security.spnego-fallback-mechlistmic-roundtrip` pins request-mic selection,
Microsoft-style negHints, exact client/server MICs from the existing Microsoft
NTLMv2 KAT-derived keys, and sequence-one SIGN/SEAL continuity after the MIC
exchange. Existing fallback denial coverage now also rejects a tampered MIC.

Microsoft MS-SPNG/RFC 4178/MS-NLMP review: **PASS** for this mechanism-integrity
increment. Canonical owner `~/rdp-server/build` configure/build/full CTest:
**NOT RUN** in this connector environment. Exact publication-SHA hosted CI:
**PENDING**. The separately reported R10 `src/gui/main.cpp` preprocessor
imbalance is not modified here and may independently keep broad CI red until its
owner fixes it.

R2P remains **ACTIVE**. The PASSWORD node is no longer blocked on fallback
mechListMIC; its next code boundary is TLS-proven CredSSP TSRequest integration
of the established standalone mechanism for `pubKeyAuth` and `authInfo`,
followed by GUI memory-only secret ownership/revocation and real Windows
App/mstsc evidence. CLIENT remains independently blocked on R10 accepted-socket
servicing.

## R10 shared desktop configuration feed (2026-10-20)

Starting shared-main parent: `58080b10f44eb22e0f2e8635a16042c91d91cafe`. The R2A dependency is resolved and
R2P continues independently; this increment advances the first-desktop R10
path rather than waiting on the password lane.

The former CLI-private configuration grammar and secure file-open policy are
now one noninstalled `rdp-server-runtime-configuration` owner. It exposes only
a callback-scoped `RuntimeConfigurationView`: field string_views cannot outlive
the bounded file buffer, and both syntax-only checks and service consumers use
the same 4096-byte grammar, POSIX no-final-symlink/regular-file/write-policy and
Windows opened-handle/DACL policy. The licensing identity parser/configurer is
also shared rather than duplicated.

`LinuxRuntimeSecurityConfiguration` now consumes that same validated view
through `configureLinuxRuntimeSecurityFromConfiguration()`. The existing CLI
`--check-*` and `serve --config` paths are refactored onto the shared
visitor without changing their startup authority. On production-capable Linux,
`rdp-server-desktop --config FILE` uses that exact feed to provision the
existing sealed keytab/PAM/native identity owner, TLS context and licensing
context, then constructs the provisioned `LinuxRuntimeHostControl`. Ordinary
GUI-only builds remain unprovisioned/fail-closed, and a malformed or unavailable
`--config` request exits without showing a positive-ready controller.

New ordinary CTest `runtime.shared-configuration-grammar` exercises base
grammar, Linux/PAM capability gating, partial/duplicate groups, bounded decimal
parsing and path traversal denial. Source/composition CTest
`runtime.desktop-shared-configuration-feed` requires both CLI and GUI to
consume the shared boundary and forbids credential-field grammar duplication
inside either entry point.

No listener, credential prompt, native desktop or client was started during
authoring. Canonical owner build/full CTest: **NOT RUN** in this connector-only
environment. Exact publication-SHA hosted CI: **PENDING**.

**Next R10 gate:** the desktop can now reach the provisioned positive listener
transaction after owner credential/consent actions. R10 still needs a
same-owner, nonblocking accept/service path that moves the accepted socket into
the existing `LinuxRuntimeConnection` and persistent X11 application loop.
That is now the first code blocker before the real Windows App acceptance; it is
R10-owned, not an unresolved R2A/R2P dependency.

## R2 standalone SPNEGO/NTLM owner (2026-10-20)

Starting shared-main parent: `4ed44edf816460c5819dab6420766922d7ab9f15`.

Dependency recheck found a real R10 advance on the first-desktop chain:
`4ed44edf` now composes the already-provisioned Linux R2 credential policy,
TLS context and transactional listener inside `LinuxRuntimeHostControl`.
That clears the former HostControl credential/TLS/listener composition blocker.
Positive GUI Start is still not reachable from the shipped desktop entry point:
`src/gui/main.cpp` does not yet construct/feed those provisioned
service-lifetime owners from the validated configuration loader. The first real
desktop test remains blocked on that R10 GUI provisioning/handoff step, not on
R2A. This does not block the parallel R2P application-password work.

R2P now adds one noninstalled, noncopyable `StandaloneSpnegoNtlmAcceptor`
around the already-landed Type 1/2/3, NTLMv2 proof, transcript MIC and
directional SIGN/SEAL owners. It strictly parses the GSS InitialContextToken /
NegTokenInit and continuation NegTokenResp DER, recognizes only the Microsoft
NTLM mechanism OID, emits bounded accept-incomplete/accept-completed
NegTokenResp messages, retains the exact NTLM Type 1 and server Type 2
transcript, validates the Type 3 username/password proof and optional NTLM MIC,
and keeps the derived message-security context in the same connection owner.

The NTLM-first path can reach mechanism verification offline. A SPNEGO fallback
from an earlier offered mechanism can select NTLM and issue Type 2, but final
success is deliberately rejected until mechListMIC verification is implemented;
mechanism-list integrity is never silently skipped. The standalone credential
verifier also now binds the Type 3 username (ASCII case-insensitive under the
current username policy) to the configured memory-only username instead of
authenticating a password proof while ignoring the presented identity.

Dedicated ordinary CTests:
`security.spnego-ntlm-first-negotiate-challenge`,
`security.spnego-ntlm-authenticate-known-answer`, and
`security.spnego-fallback-integrity-and-der-denials`; the existing NTLMv2
denial fixture additionally checks username mismatch. These remain offline
protocol tests, not CredSSP/NLA or Microsoft-client acceptance.

Current Microsoft Open Specifications review: **PASS** for the implemented
MS-SPNG NegTokenInit/NegTokenResp subset and MS-CSSP's use of a negotiated
mechanism security context. Canonical owner configure/build/full CTest:
**NOT RUN** because this connector environment cannot resolve github.com for
the mandated checkout. Exact publication-SHA hosted CI: **PENDING**.

R2P remains ACTIVE. The PASSWORD node is now blocked on remaining SPNEGO
mechListMIC fallback integrity, TLS-proven CredSSP TSRequest integration for
pubKeyAuth/authInfo, GUI memory-only secret ownership/revocation and real
Windows App/mstsc evidence. The CLIENT node is independently blocked on the R10
desktop-entry-point provisioning/handoff described above.

## R10 provisioned HostControl listener transaction (2026-10-20)

Starting shared-main parent: `b9e91adbed809dea091b9a271e6be3e651520401`. Dependency recheck found the
former R2A owner-consent blocker resolved on main. R2P's standalone NTLM work
continues independently and is not required for the first Linux acceptance,
which may use the existing OS-account Kerberos/PAM path.

R10 now has a production-security-only HostControl seam that borrows the
already-provisioned `LinuxRuntimeSecurityConfiguration` and
`RuntimeServerTlsContext`; it does not create a second credential, TLS or
policy owner. Existing-account setup succeeds only while the retained R2
service configuration and nonzero identity-policy generation are current.
Positive Start is transactional: configured credentials -> genuine current
owner consent -> fresh interface/address identity -> configured TLS identity ->
local candidate `OwnedLanListener` bind -> bound certificate/listener
generation match -> fresh owner reauthorization -> sole listener publication.
Any failure before publication destroys the candidate locally. Stop/revoke
still invalidates R2 before the listener, and terminal revoke clears the
HostControl credential-ready projection.

The Qt pre-Start gate no longer requires `nativeDesktopReady`; that state is
post-accept/post-R2 by design and remains false until the existing connection
runtime constructs the one authorized native owner. The ordinary GUI-only build
remains fail-closed: the security/TLS seam is compiled only when
`rdp-server-linux-runtime-security` exists, and the current
`rdp-server-desktop` entry point still constructs the unprovisioned default
controller.

Dedicated offline CTest:
`runtime.linux-host-control-provisioned-listener-transaction` pins the
production linkage, exact transaction order and removal of the circular native
pre-Start gate without fabricating an R2 grant or opening a listener. The
existing Qt positive-workflow fixture now proves Start readiness while
`nativeDesktopReady=false`. Owner-local build/full CTest: **NOT RUN** in this
connector environment. Exact publication-SHA hosted CI: **PENDING**.

**Next R10 gate:** extract/reuse the existing validated `rdp-server.conf`
loading/provisioning boundary so `rdp-server-desktop` can construct these same
service-lifetime owners, then hand accepted sockets into the existing
`LinuxRuntimeConnection`/persistent X11 loop. Live Microsoft-client acceptance
remains **BLOCKED / NOT RUN** until that concrete GUI config feed exists and the
owner runs the physical-seat test.

## R2 standalone NTLM transcript and message security (2026-10-20)

Starting shared-main parent: `df0eb78299f5be94d1325ebb36727746f5866f28`.

Dependency recheck against the owner graph found R2A already resolved and the
corrected standalone Type 1/2/3 NTLMSSP framing landed on main. R10 positive
GUI Start is still independently blocked on its service-lifetime credential/TLS
composition, but that does not block offline R2P progress.

R2P now extends the existing single `NtlmV2SecurityContext` owner with exact
AUTHENTICATE_MESSAGE MIC verification and connection-oriented Extended Session
Security SIGN/SEAL state. MIC verification uses ExportedSessionKey over exact
NEGOTIATE || CHALLENGE || AUTHENTICATE-with-zero-MIC bytes. Client-to-server
unwrap and server-to-client wrap each own one continuous RC4 state and 32-bit
sequence counter; KEY_EXCH encrypts the eight-byte checksum on the same stream.
A consumed-stream signature failure clears keys, RC4 state and counters rather
than permitting desynchronized reuse.

Dedicated ordinary CTests:
`security.ntlmv2-transcript-mic-verification`,
`security.ntlmv2-session-security-sign-seal-known-answer`, and
`security.ntlmv2-session-security-tamper-revokes`. The keys originate from
Microsoft's published NTLMv2 known-answer example; deterministic message
security bytes are pinned independently. This still does NOT implement SPNEGO
token state, CredSSP pubKeyAuth/authInfo framing integration, GUI secret
ownership or R2 admission, and makes no mstsc/Windows App interoperability
claim.

Microsoft Open Specifications review: **PASS** for MS-NLMP connection-oriented
Extended Session Security MAC/SEAL sequencing and MIC calculation, and MS-CSSP
use of the negotiated mechanism confidentiality service. Owner-local
`~/rdp-server/build` configure/build/full CTest: **NOT RUN** because this
environment cannot resolve github.com for a checkout. Exact publication-SHA
hosted CI: **PENDING**. R2P remains ACTIVE; PASSWORD remains blocked on SPNEGO,
CredSSP integration and GUI/runtime secret ownership.

## R2 NTLMSSP fixed Version-field correction (2026-10-20)

Follow-up to `2131703acd28db77f6a6951139f18cc45fed7e01`: re-reading the
published MS-NLMP structures found that NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE
and AUTHENTICATE_MESSAGE retain their 8-byte Version field even when
NTLMSSP_NEGOTIATE_VERSION is clear; the field is then all zero. The first
framing commit incorrectly treated that field as absent when the flag was
clear, moving the server TargetInfo eight bytes early and allowing too-low
payload floors in the no-Version parser case.

The corrected wire owner uses fixed 40/56/72-byte Type 1/2/3 headers, requires
the Type 1/3 Version bytes to be zero when the flag is clear, keeps the server
Type 2 Version bytes zero, and starts a required Type 3 MIC only after the fixed
72-byte header. The dedicated challenge oracle and MIC-alias denial fixture are
updated with those exact offsets. This is a source-level correction only; no
new capability or interoperability claim is added.

Owner-local build/full CTest: **NOT RUN** in this connector environment.
Exact publication-SHA hosted CI: **PENDING**.

## R2 standalone NTLMSSP framing bridge (2026-10-20)

Starting shared-main parent: `2e2a5f5e4b4bce2364958928d2caf636dea66b4a`.

The R2P independent-session-password lane is not blocked by R2A anymore.
Current main already has the positive noncopyable CurrentOwnerSharingAuthority;
LinuxRuntimeHostControl can pass the owner-authority check and then fails closed
at CredentialProviderUnavailable because R10 still lacks its separate
service-lifetime credential/TLS composition. That R10 composition issue does not
block offline progress on the first-party application-password provider.

This increment extends the existing noninstalled standalone NTLMv2 component
with bounded connection-oriented MS-NLMP framing. It parses Type 1
NEGOTIATE_MESSAGE security buffers, emits one Type 2 CHALLENGE_MESSAGE with a
caller-owned random challenge plus NetBIOS domain/computer/timestamp TargetInfo,
and parses Type 3 AUTHENTICATE_MESSAGE into aligned bounded Unicode identity
storage plus borrowed NTLMv2/key/MIC spans. The Type 3 result feeds the existing
EphemeralNtlmV2Credential verifier without copying the NT challenge response.
Security-buffer extents/overlap, Unicode alignment, LMv2 size, KEY_EXCH key
length, canonical NTLMv2 AV framing and MIC header placement fail closed.

Dedicated ordinary CTests are:
`security.ntlmssp-negotiate-challenge-framing`,
`security.ntlmssp-microsoft-authenticate-bridge`, and
`security.ntlmssp-security-buffer-mic-denials`. The bridge uses Microsoft's
published NTLMv2 AUTHENTICATE_MESSAGE bytes and reaches the existing
proof/session-key verifier. This still does NOT implement SPNEGO token state,
NTLM message MIC verification, stateful NTLM SIGN/SEAL wrap/unwrap for CredSSP
pubKeyAuth/authInfo, GUI secret ownership, or R2 admission, and it makes no
mstsc/Windows App interoperability claim.

Dependency-graph update: R2A -> R10 is resolved at the R2 authorization
boundary. R2P remains ACTIVE. The PASSWORD node remains blocked on the
remaining SPNEGO + transcript/MIC + message-security + GUI/runtime ownership
work. The first real desktop test remains blocked by R10's independent
credential/TLS/start composition, not by absence of a positive R2 lease.

Authoring validation: Microsoft Open Specifications wire review and source
consistency **PASS**. Canonical owner build/full CTest: **NOT RUN** in this
GitHub-connector environment. Exact publication-SHA hosted CI: **PENDING**.
No listener, credential prompt, native desktop, service, firewall or client was
started.

## R1 first accepted-client diagnostic preparation (2026-10-20)

Starting shared-main parent: `a98962a8881768f2c21d100edf21149b380daae0`.

R1 adds a bounded non-authorizing diagnostic snapshot on the existing
`LinuxRuntimeConnection`: preauth/TLS stage, exact negotiated Enhanced
Security protocol, TLS protocol version, CredSSP transition, R3 Share activation
state, terminal transport classification and SHA-256 of the certificate
selected by the exact established SSL. R10 host status separately reports the
configured selected endpoint and the current getsockname-derived bound endpoint
plus listener generation. No password, NTLM/GSS response, session key,
delegated credential or private certificate material enters diagnostics.

Offline production-backed coverage adds
`runtime.linux-connection-r1-acceptance-diagnostics`: real nonblocking
loopback/TLS ownership, certificate-rotation continuity, and Stop during both
established and in-progress TLS while no R2 lease or Share can exist. Existing
R1 TLS lifecycle coverage remains authoritative for stale listener generation
and TLS identity invalidation.

**Still BLOCKED / NOT RUN:** positive R2-authorized R10 LAN Start, the first
actual LAN accepted socket, live WANT_READ/WANT_WRITE and partial TLS writes
under that Start owner, close_notify/half-close/RST, Stop race, interface
disappearance, descriptor reuse, and Microsoft Windows App/mstsc acceptance.
Do not add a second listener or bypass HostControl to obtain those claims.

### R2 standalone session-password cryptographic core (2026-10-19)

The parallel independent-password track now has a noninstalled first-party
EphemeralNtlmV2Credential core. It consumes mutable UTF-16 password storage,
scrubs the plaintext caller buffer on every configure path, retains only a
bounded username plus NT hash in memory, and non-elidably cleanses derived
credential/security keys on revoke/destruction. Empty NTLM domains are
supported; this first prototype deliberately rejects non-ASCII usernames
rather than guessing Unicode uppercase mappings.

The verifier accepts only NTLMv2 responses with canonical bounded blobs and a
CredSSP-oriented 128-bit SIGN+SEAL+extended-session-security flag set. It
validates NTProofStr in constant time, derives SessionBaseKey, handles the
KEY_EXCH encrypted random session key, and derives client/server signing and
sealing keys. Dedicated CTests use Microsoft's published User/Domain/Password
known-answer values, proof/session-key bytes, denial mutations and zeroization.

This is **not** a Microsoft-client interoperability claim. NTLM Type 1/2/3
framing, SPNEGO token state, stateful NTLM wrap/unwrap for CredSSP pubKeyAuth
and authInfo, GUI secret entry/ownership, and final R2 admission integration
remain P0. IndependentApplicationPassword therefore remains disabled in the
product UI and there is no NLA downgrade.

## R3 bounded first-client acceptance observability (2026-10-19)

Starting shared `main`: `ae757d15b77d09ddcef09bb5afabf8045dabf56c`.
R3 adds a fixed-capacity, allocation-free acceptance snapshot/event ring to the
existing `McsSessionLifecycle`, with a thin read-only R10 projection. It covers
MCS established, Share activated, Graphics DVC activated, surface created/mapped,
first fully accepted frame publication, first genuine FRAME_ACK, resize remap
started/completed/rejected and a reconnect correlation generation. The event
stream contains no protocol payloads or sensitive/native identity values and is
never consulted for authorization or scheduling.

The first-frame and first-ACK transitions consume the R4
`GfxPresentationAcceptanceStatus`; R4 remains the sole ACK/outstanding-frame
truth. Surface/remap transitions use R3's existing accepted-byte writer receipts
and replacement-surface state. ClearCodec remains the mandatory first live
publication path; AVC420 is neither enabled nor redesigned here.

New production-backed ordinary/sanitizer CTest:
`transport.dvc-graphics-first-client-acceptance-observability`. The R9 R3
Graphics DVC selector intentionally grows from 21 to 22 cases and its workflow
structure sentinel is updated in the same change. Local owner build/full CTest
is **NOT RUN** in this connector environment. Exact publication-SHA hosted CI is
**PENDING** until the commit executes. R10's host-authority lifetime wiring does
not remove the live blocker: positive Windows App/mstsc acceptance remains
**BLOCKED / NOT RUN** until R2 can issue a genuine current-owner lease and R10
can reach positive Start. Use this bounded trace only after that point, and fix
only demonstrated interoperability failures.

### R2 owner-selected M1 consent scope/lifetime (2026-10-19)

The local permissions page now sends one typed R10 request: view is mandatory,
while remote input and clipboard are independent owner checkboxes and lifetime
is owner-selected from 1–60 minutes. R10 maps only that request into R2 scope;
the network-facing runtime receives only the existing const authority borrow.
The dedicated offscreen GUI CTest verifies exact scope/lifetime forwarding and
does not fabricate positive native seat evidence.

## R2 M1 positive local-owner authority (2026-10-19)

M1 now trusts the currently logged-in local desktop-user session plus explicit
interaction with the locally running server GUI as the local consent boundary.
It does not claim resistance to malicious processes already running as the
same UID or to X11 clients capable of synthetic input; same-user/X11 compromise
is explicitly outside the M1 threat model.

R10 owns one noncopyable CurrentOwnerSharingAuthority. A positive grant requires
fresh native process UID, active physical non-remote seat0, exact session ID and
start generation/display, known-unlocked login1 LockedHint, requested scope and
a short lifetime (hard maximum one hour). Accepted connections receive only a
const authority borrow, so no network peer can grant consent. Every protected
R2 operation revalidates the native evidence. Stop, locked or unknown lock,
logout, user switch, session replacement, credential change, expiry and native
authorization loss revoke the current epoch. This consent remains additive to
HYBRID TLS/CredSSP, GSS/PAM, NSS/logind and R3 authorization.

## R8 dormant text-only production composition prepared (2026-10-19)

**Authoring parent:** `a552314401c667aa38982421b756e0a71ab1d364`.

R10's persistent post-Share loop now has one compiled R8 composition owner for
the existing chain: authenticated R3 `ClipboardStaticChannel` route -> R8
`R3ClipboardTransferBridge` -> the current R2-selected R5 X11 connection ->
R3 static-channel response queue -> `advancePersonalDesktopClipboardTlsWrite`
through the sole R1 TLS owner. No second reader, writer, route parser,
authorization cache or XCB connection is introduced. The R8 owner is stack-bound
to one serialized R10 client candidate and pins the same R2 admission/session
generations already used by the native desktop owner; every clipboard operation
still re-enters the existing R2 clipboard gateway.

Production activation is intentionally **OFF**:
`kLinuxProductionClipboardActivationApproved = false`. This gate must remain
false through M1 and may change only after the first real Windows App
video/input/Stop acceptance succeeds. The prepared first-acceptance path uses
`X11ClipboardAdapter::PresentationScope::UnicodeTextOnly`; PNG, file,
FileContents and directory publication/request entry points are not called by
the runtime. Existing richer R8 components remain available only to their
offline tests.

Stop/revoke/reconnect retirement is ordered so the X11 adapter first releases
CLIPBOARD ownership, pending paste receipts and INCR transfers, then the R8
bridge retires its source generation, pending application response and stale
receipt identity; R5 and the R1/R2/R3 connection retire afterward. A new route
cannot reuse the old stack owner. Clipboard TLS writes take scheduler precedence
only while an R3 write is pending; capture and application reads resume after the
exact R1/R2/R3 receipt is committed.

New dedicated offline behavior:
`clipboard.x11-unicode-text-only-presentation`. The production linkage guard
now requires the prepared R2/R3/R1 composition, requires the activation gate to
remain false, and forbids image/file request/publication calls from
`main.cpp`.

Canonical owner `~/rdp-server/build` configure/build/full CTest:
**NOT RUN** in this GitHub-connector environment. Exact publication-SHA hosted
CI: **PENDING**. No live listener, desktop, clipboard or Microsoft client was
started. R8 production activation remains **BLOCKED** on the first real Windows
App video/input/Stop acceptance described above.

## R10 P0 positive-Start prerequisite wiring (2026-10-19)

R10 now owns one production `CurrentOwnerSharingAuthority` in
`LinuxRuntimeHostControl`, marshals bounded full-scope GUI intent to that R2
owner, revokes R2 before its R1 listener on Stop/Revoke/destruction, and lets a
future accepted `LinuxRuntimeConnection` borrow that same host authority so
`LinuxConsoleAdmissionBroker` no longer has to use the legacy no-authority
constructor. The current Linux/X11 authority still cannot grant a positive
lease, so this change opens no listener and adds no test-only grant path.
Dedicated offline regression:
`runtime.linux-host-control-r2-authority-lifetime-handoff`.

**Still blocked for the first legitimate positive GUI Start:** R2 must land the
reviewed positive owner lease/provider. In addition, the current Qt
`LinuxRuntimeHostControl` still has no service-lifetime feed for the already
existing Kerberos/PAM identity configuration and TLS certificate/private-key
owners; `requestCredentialSetup(ExistingOsAccount)` therefore remains
`CredentialProviderUnavailable`. Do not mark credentials/TLS ready from the
button alone. The next R10 composition must reuse the existing validated
runtime-security/TLS owners and persistent Linux connection/X11 runtime rather
than invent parallel configuration, transport or session state.

## R4 first-client acceptance instrumentation authored (2026-10-19)

R4 now has a compact generation-scoped acceptance snapshot for first ClearCodec
preparation, exact full-frame write commitment, the authoritative outstanding
ACK count and first exact genuine FRAME_ACK. Frame-specific readiness is
classified by the same R4 owner as Ready / DeferredForFrameAcknowledge /
Rejected; R3 retains only its retired-surface frame-ID fence and maps that
result to its existing preflight enum. No second ACK counter, ID set, scheduler
or transport owner is added.

Existing production-backed ClearCodec and frame-publication-backpressure tests
were extended in place, so the fixed R4 CTest inventory does not grow. They
check first-event status transitions, exact commitment/ACK separation, fresh-ID
64-credit defer and duplicate-ID rejection at capacity. A first-client trace
checklist is pinned in testing_standards.md.

This authoring does not unblock live validation: Microsoft-client visible frame
and FRAME_ACK acceptance remain BLOCKED / NOT RUN until positive R2/R10 Start.
The first live frame remains ClearCodec; AVC420 stays disabled after remap
unless the integrated runtime intentionally enables it later.

## R4 integrated RandR remap offline acceptance (2026-10-19)

**Validated descendant:** `f3ffe85cbecbdbce55bd915d74b74a79155a50e2`.
This descendant contains R3's authenticated DELETE/CREATE/MAP remap,
R10's serialized native-resize scheduler, R5's typed
`X11NativeGeometryObservation` freshness handoff, and the unchanged R4
surface-ID x264 reset. The three R4 implementation/regression blobs remain
byte-identical to accepted R4 implementation
`571f77a7c862c95a0e60ef58882e26f2bced8186`.

Exact-SHA hosted evidence is green for every ordinary R4-relevant lane.
Ubuntu protocol Debug and Release each PASS **797/797**, including
`transport.dvc-graphics-surface-remap`,
`runtime.linux-connection-resize-deadline-bounded-poll`,
`runtime.linux-connection-graphics-surface-remap-denials`,
`runtime.linux-r5-persistent-x11-input-frame-borrow-order`, and
`graphics.x264-segmented-surface-remap-idr`. The production-linked
ASan/UBSan lane PASSes **42/42** portable R4 graphics, **29/29** x264/BGRA,
**4/4** AVC420 capability, **4/4** ClearCodec, **21/21** R3 Graphics DVC,
**40/40** direct Linux runtime-security, and **42/42** native X11 selections.
macOS protocol, Windows protocol, R6 Windows CLANG64, R5 Linux GUI, both R2
production-security variants, R7 lifecycle/session/portable-GUI lanes,
workflow structure and documentation policy all complete SUCCESS on this SHA.

The integrated ordering is now pinned as:
fresh R5 geometry observation -> native/session freshness check -> protected
R3 remap decision -> exact DELETE/CREATE/MAP receipt drain -> fresh equality
confirmation -> R4 frame-credit preflight -> second geometry freshness check ->
typed synchronous R5 framebuffer borrow -> mandatory ClearCodec publication.
`Deferred` and `Started` consume no frame ID or invented ACK credit. R4
remains the sole authoritative ACK-membership owner, R3 retains retired-surface
frame-ID fencing, and AVC420 remains intentionally disabled after remap despite
the validated R4 SPS/PPS/IDR reset invariant.

The GitHub primary workflow remains administratively open only because the
separate R9 clean-Windows interactive consumer job is queued; that operational
portable-GUI gate is not R4 offline acceptance evidence. The remaining R4 live
acceptance blocker is R2 positive owner authority: production still returns
`TrustedOwnerProofUnavailable`, `authorizes()` is false, and Linux
`startSharing()` returns `HostConsentRequired`. Therefore physical seat0
Windows App/mstsc visible-frame/FRAME_ACK/resize acceptance remains
**BLOCKED / NOT RUN**, and no post-remap AVC420 runtime enablement is authorized.

## R5 typed RandR-to-R3 handoff guard (2026-10-19)

R10's landed native resize scheduler at `f894dd23fdfd3598335fd85f1269fc7ae36ae17c`
clears the offline `R5 -> R10 -> R3` resize-composition dependency. Source review
confirms the serialized owner drains X11 events, obtains one
`X11NativeGeometryObservation`, checks `nativeGeometryIsCurrent()`, invokes the
R2-authenticated R3 surface-remap gateway, rechecks currentness after Graphics
preflight, and borrows the framebuffer only through R5's typed
`consumeR4Frame(observation, currentNativeSessionGeneration, ...)` overload.
No XShm span escapes that synchronous callback and no R5 generation is treated
as authorization.

The first `f894dd23...` Ubuntu full Debug run passed the R3 remap, both new R10
resize tests, every native X11 generation/RandR CTest and the R4 surface-remap
IDR regression; its only failure was the old R5 source guard confusing R10's
new remap-writer `frameWritePending = true` with the later frame-publication
assignment. R9 corrected that source guard on main at
`c8b6a9eec35261a6a7719717c6939eeed9bfae8e` without production changes.
This R5 follow-up additionally pins the typed geometry/session observation ->
R3 remap -> final freshness recheck -> typed framebuffer-borrow order so a
future scheduler refactor cannot silently fall back to the scalar generation
path. Exact publication-SHA hosted CI is pending at authoring.

The remaining live-resize blocker is not R5: positive GUI LAN Start and a
physical seat0 Microsoft-client resize trace still require R2's trusted
current-owner consent plus authoritative unlock/revocation evidence. Xvfb and
offline protocol tests do not satisfy that authority or human acceptance gate.

## R10 native RandR resize scheduler integration (2026-10-19)

**Authoring parent:** `f5d1391a75fa3f32843adcba1a31fa6dff36fae1`. R3 PR #24 is now on main via
`e24539c78f6c42be9bb1357247c1685d8161b45b`. Its exact head
`c66a561ce5b3c3acdce364b35040891c7b600c8b` passed structure Actions
`39286679881` and full primary Actions `39286679887`, including Linux/macOS/
Windows protocol, R9 sanitizers, both R2 production-security variants, R5 Linux
GUI, R7 macOS, and R6 Windows CLANG64. R4's same-generation AVC420 surface
reference reset is already on main; first live post-remap publication remains
ClearCodec.

R10 now consumes one fresh R5 `X11NativeGeometryObservation` before every
eligible capture, rechecks it against the current R2 native-session generation,
and calls R2's authenticated R3 surface-reconfiguration gateway before borrowing
pixels. `Unchanged` permits the existing frame-credit preflight; `Deferred`
skips capture/frame-ID advancement and retries no faster than 100 ms while the
single R1 reader continues FRAME_ACK/client DATA intake; `Started` drains
R3's DELETE -> CREATE -> MAP through the existing exact-receipt TLS writer;
`Rejected` retires the native owner and connection.

The first unresolved changed geometry starts one monotonic six-second deadline.
Later RandR generations do not extend it, and a completed older MAP does not
clear it; only a subsequent fresh R3 `Unchanged` decision proves the currently
observed native geometry is mapped. The poll sleep is capped by the remaining
resize lifetime even during TLS WANT_READ/WANT_WRITE. Capture uses R5's typed
geometry/session freshness overload, so stale capture generations are never
borrowed after remap.

New ordinary offline CTests:
`runtime.linux-connection-resize-deadline-bounded-poll` and
`runtime.linux-connection-graphics-surface-remap-denials`. The positive
DELETE/CREATE/MAP wire/ACK behavior remains R3's production-backed
`transport.dvc-graphics-surface-remap`.

Local owner `~/rdp-server/build` configure/build/full CTest: **NOT RUN** in
this GitHub-connector environment. Exact publication-SHA hosted CI: **PENDING**.
Positive GUI LAN Start remains independently **BLOCKED** because R2 still has no
trusted physical-owner consent + authoritative unlock provider on the supported
portable X11 target. Physical Windows App/mstsc resize acceptance is **NOT RUN**
and still requires explicit owner approval.

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

## R7 exact-SHA Qt fingerprint/compiler acceptance (2026-10-19)

R7 acceptance is now hosted-green at
`7e3250b6436db8a730476b5d0368d02a8d93bb73`: workflow structure
`39273771660` **PASS**; primary `39273777510` Linux GUI ZIP, macOS
PORTABLE-GUI and Windows CLANG64 Qt lanes all **PASS** the exact-one
`gui.offscreen-tls-fingerprint-rotation-and-denials`. Linux packaging is
restored, macOS passes the 14-case GUI suite and normal extracted launch, and
Windows passes 692/692 Debug plus 692/692 Release CTests together with package
closure/offline smoke. The new
`gui.offscreen-positive-owner-workflow-presentation` passes on the shared Qt
source without adding authority or secret collection.

All ordinary hosted jobs on that SHA are green. R9's distinct
`r9-clean-windows-portable-gui` self-hosted clean-runner gate remains queued,
so public Windows PORTABLE-GUI clean-machine acceptance is still
**BLOCKED / NOT YET RUN**. Positive R2 owner-consent issuance, live R10 LAN
Start/connected-client acceptance and native macOS hosting remain separate
blockers.

## R9 hosted parser gate and exact checksum inventory hardening (2026-10-19)

Authoring parent `1bc7dc8e779b8b003b6cde07e0efeb6a01560a1e` preserves concurrent R1/R2/R5/R7/R10/R6 work.
Exact baseline `2fcfebee9e94b064ebf54617cd224982060471a0`, Actions `39244189634`,
was **not an overall PASS**: Ubuntu protocol, R9 X11 sanitizers, Linux GUI ZIP
and SERVER-TEST aggregation failed, while clean Windows remained queued.

R9 requires anchored lowercase SHA-256 records, exact archive spelling,
Windows-safe relative names, case-insensitive uniqueness, complete non-self
inventory and explicit parsed-digest assignment before file/manifest compare.
A dedicated `windows-latest` Windows PowerShell parser job validates the real
clean script independently of the self-hosted runner. All eleven intended
Qt-free root configures are explicit OFF under R10 GUI-default-ON.

**Clean Windows remains BLOCKED / NOT RUN.** Exact publication-SHA hosted CI,
owner-native full Debug Linux X11 / Windows CLANG64-Clang23 / macOS 27, and
real Microsoft-client acceptance remain separate open gates.

## R1 current-main TLS identity lifecycle and endpoint-generation handoff (2026-10-19)

Starting shared-main parent `63e1706659cb8c461180f3210b1e0f1409c7ee75`, including current R2
X11-owner/secure-attention decisions, R7 fixed-fingerprint/TLS-workflow
repairs, R5 RandR generation repair, R10 ACK pacing/headless-CI reconciliation,
and R4 AVC420 remap evidence. R1 carries no duplicate correction for those
owners.

R1 adds a monotonic nonzero process-local generation to each successfully
validated `OwnedLanListener` bind and carries it in bound-derived
`RuntimeTlsIdentityStatus`. R10 reports only its currently revalidated listener
generation; R7 rejects stale bound/mismatch/interface observations from a
retired generation. Stop/revoke, listener replacement, and stale interface
observation fail closed without making the generation an authority token.
Fingerprints remain loaded-`SSL_CTX` observations and client trust remains
`Unknown`.

New ordinary offline CTest
`runtime.tls-identity-offline-lifecycle-denials` covers configured-but-unbound
status, wrong numeric SAN/IP identity, malformed failed handshake, rotation to
a distinct valid certificate/IP SAN, stale endpoint generation, and
zero-generation denial. The existing Qt TLS-rotation regression gains retired
listener-generation coverage; the existing LAN-listener fixture asserts
generation lifetime only inside its pre-existing optional native bind path.
Windows replacement credentials use the existing private-fixture ACL helper.

Owner-local canonical `~/rdp-server/build/` full CTest is **NOT RUN** because
that checkout is unavailable in this connector environment. Exact
publication-SHA hosted CI is **PENDING** at authoring. Positive R2 consent, GUI
LAN Start, exact accepted-SSL certificate continuity, live WANT/half-close/RST,
partial Graphics writes, interface-removal/descriptor-reuse races, and
Microsoft-client acceptance remain **BLOCKED / NOT RUN**.

## R2 Linux/X11 trusted-owner blocker and offline NLA feasibility (2026-10-19)

R10's concrete Linux `LinuxRuntimeHostControl` is already on `main`; R2 is
not waiting for an R10 interface. The specifically supported X11 environment
investigated is **Ubuntu Desktop 24.04 LTS / GNOME 46 / Ubuntu on Xorg /
physical local non-root seat0 user session**, with native UID, session ID,
session-start generation and X11 display read from logind.

**Positive-owner decision: BLOCKED for the no-install portable ZIP.** The
precise missing capability is a secure-attention / physical-origin approval
channel that an untrusted X11 client cannot synthesize. Xorg XTEST deliberately
allows clients to inject key, button and pointer events, so a portal/polkit/GTK
approval dialog in the same X11 session cannot by itself prove a physical-owner
action. GNOME `org.gnome.ScreenSaver` can add lock-state observation but does
not supply that secure-attention guarantee. Consequently no portable native
composition on this target provides all required facts in one verifiable trust
chain: affirmative physical-owner approval, exact OS/session/seat binding,
authoritative unlocked state, exact view/input/clipboard scope plus deadline,
and mandatory revocation on lock/logout/user switch/session replacement/native
authority loss. logind is
retained for session identity/lifecycle but its `LockedHint` is
desktop-supplied; XDG RemoteDesktop provides a native consent/device-scope
interaction but does not contractually bind that grant to the exact logind
session or require lock-triggered closure; polkit user authentication neither
attests desktop unlock nor preserves ZIP-only deployment for an
application-specific installed action. Qt/X11 intent is not trusted evidence.

Keep `CurrentOwnerSharingAuthority::requestConsent()` at
`TrustedOwnerProofUnavailable`, keep `authorizes()` false and keep Start
denied. Do not add a synthetic positive lease/test or a new deny-only
abstraction. Lock/unknown remains revocation; unlock never revives authority.
A future Wayland/compositor-mediated portal design or installed native policy
mode needs separate acceptance.

**R10 handoff once a qualifying provider exists:** R2 alone creates one opaque
move-only/noncopyable `OwnerSharingLease` bound to exact native owner
identity, granted permission mask, monotonic deadline, R2 generation and
native-provider generation. Consent must be asynchronous so native human
interaction never blocks the Qt/R10 owner thread. R2 re-reads the complete
native binding after positive interaction before lease issuance. R10 owns the
lease and freshly reauthorizes before Start/listener bind, after potentially
blocking bind/native work, before client admission, and at every existing R3
View/R5 Input/R8 Clipboard protected transition. Hot-path authorization is
cached/bounded; native event watchers revoke off the hot path. Stop,
lock/unknown, logout, switch, session replacement, credential-policy change,
expiry or provider loss invalidates R2 first, retires R3/native/client state,
then closes R1.

**Independent application password:** current production remains unsupported.
CredSSP establishes SPNEGO before encrypted final `TSPasswordCreds`; the
current GSS acceptor is Kerberos-only, so PAM or an application password hash
cannot by themselves authenticate unmodified Microsoft clients. A reviewed
domainless **NTLMv2-over-SPNEGO** provider is protocol-feasible in principle:
MS-NLMP supports local NT one-way-function validation and the ISC-licensed
`gssapi/gss-ntlmssp` mechanism supports local NT-hash credentials. The NT
hash is password-equivalent secret material. This candidate still requires
production integration, pinned bundled mechanism/config, secure secret
storage/rotation, CredSSP TLS/public-key binding proof and real offline client
interoperability.

Until then keep **Set Application Password — Unsupported** disabled, never
change the OS password and never downgrade NLA. The exact current OS-account
fallback is a configured/reachable Kerberos realm/KDC, explicit
`TERMSRV/<host>@REALM` acceptor keytab and principal-to-local-account R2
mapping, followed by final PAM password/account verification. A stock local
Linux username/password without Kerberos does not meet the current SPNEGO gate
and therefore does not satisfy the isolated-ZIP product requirement.

**Production-backed evidence:** exact SHA
`c1ec383576c52629a2f094ed8a696d2280720b8c` has primary Actions
`39207508411` **PASS** and structure Actions `39207508301` **PASS**,
including `r2-linux-production-runtime-security (complete)`,
`r2-linux-production-runtime-security (missing-systemd)`,
`r9-security-protocol-sanitizers` and Ubuntu/macOS/Windows protocol jobs.
This is negative/session-consistency evidence, not positive physical consent.

Required future state-machine tests: exact native-binding match/mismatch around
consent completion; move-only scope/deadline; Stop, lock/unknown, logout,
switch, replacement, credential generation, expiry and provider-loss
revocation; no unlock revival; fresh Start/protected-operation checks; and
R2-before-R3/native-before-R1 teardown. Standalone-password acceptance requires
isolated-LAN `mstsc.exe` and macOS Windows App tests for correct/wrong
credentials, rotation, restart, Unicode, replay/timestamp, TLS identity
rotation, NTLMv1 denial, no DC/KDC/cloud dependency and no NLA downgrade.

No live desktop, credential, listener, service, lock/switch or Microsoft-client
test was authorized or run by this review: **NOT RUN**. Source/document review:
**PASS**. Exact publication-SHA hosted CI: **PENDING**.

## R7 positive workflow presentation and three-OS TLS Qt gate (2026-10-19)

Parent `1b28ad3e51b761bb2f79a7066b579d6b12610ba2` already contains R10's default-on Qt shell plus explicit
Qt-free/headless CI configuration. R7 now consumes that build policy without
duplicating it. The wizard labels the existing R2/R10 request as **Local Owner
Permission**, identifies the only currently permitted credential mode as an
existing OS-account policy, and reports **Ready to share** only when the
existing fail-closed R10/R2/R1/native gates and selected LAN endpoint all pass.
It still creates no application-password input and never treats a button click
or GUI state as authorization.

New ordinary `gui.offscreen-positive-owner-workflow-presentation` covers
those presentation transitions. Hosted Linux, macOS and Windows Qt lanes now
pin exact-one execution of
`gui.offscreen-tls-fingerprint-rotation-and-denials`; Linux builds the shared
Qt fixture before packaging, macOS keeps its broad offscreen suite, and
Windows CLANG64 runs the exact shared-Qt regression after its full Debug build.
The PORTABLE-GUI archives continue to exclude the CLI `rdp-server` and expose
only their platform GUI launch surface.

Authoring/source review **PASS**. Publication-SHA three-platform Qt/CTest and
full CI evidence **PENDING**. Positive R2 owner-consent issuance, live R10 LAN
Start/client status and native macOS hosting remain **BLOCKED / NOT RUN**.

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

## R10 PR #23 integration: ACK pacing, frame credit and GUI-default split (2026-10-19)

Source parent `571f77a7c862c95a0e60ef58882e26f2bced8186`. The useful PR #23 changes are replayed onto current shared main after merged R4 duplicate-frame-ID fix #27. Before any X11 framebuffer borrow, the production post-Share scheduler now consumes R2-gated R3 frame-publication readiness: Ready proceeds to separately reauthorized frame start; DeferredForFrameAcknowledge reschedules without capture, frame-ID increment or disconnect; Rejected retires native state and the connection. R4 remains the sole ACK-window owner. Pending Graphics TLS WANT_READ/WANT_WRITE now receives a bounded positive poll quantum even after capture expiry while native/logind/socket readiness, Stop and authorization remain preemptive.

`RDP_SERVER_BUILD_DESKTOP_GUI` defaults ON and requested GUI builds still require Qt. Intentionally Qt-free protocol, production-security and sanitizer CI explicitly pass OFF; the Qt-provisioned CLANG64 application lane asserts that the unspecified option resolves ON. Dedicated CTests are `runtime.linux-connection-stalled-graphics-tls-write-bounded-poll` and `runtime.linux-connection-graphics-credit-preflight-denials`. Source reconciliation PASS; local build/full CTest NOT RUN in this connector environment; exact integrated-SHA hosted CI PENDING. Positive GUI LAN Start remains BLOCKED on a genuine R2 trusted-owner consent/unlocked-state provider. R3 PR #24/native resize remains separate.

## R6/R9 clean-Windows verifier corruption repair and exact artifact audit (2026-10-19)

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

## R7 fixed-extent R1 TLS fingerprint Qt compile repair (2026-10-19)

Parent `c286052a546491d824ac2e499debff81d2d488de` exposed a P0 portability regression in hosted
`r5-linux-gui-zip` Actions run `39244189634`: GCC rejected
`identity.certificateSha256.size()` as the non-type template argument for
the Qt fingerprint stack buffer, then emitted cascading subscript/data/size
errors. R7 now derives the digest extent from R1's
`RuntimeTlsCertificateFingerprint` type with `std::tuple_size_v`, pins the
contract to 32 bytes at compile time, and pins the colon-separated output
buffer to 95 characters. The GUI still copies only the exact R1-observed
bytes into uppercase colon-separated hexadecimal; it does not calculate,
synthesize, cache or promote a fingerprint to trust or authorization.

The existing ordinary
`gui.offscreen-tls-fingerprint-rotation-and-denials` regression now asserts
the complete 32-byte `00..1F` rendering rather than only its prefix, while
retaining certificate-rotation, missing-digest, endpoint-change and terminal
R2/R10 denial coverage. Source/test contract review **PASS**. Publication-SHA
Linux/macOS/Windows Qt build and dedicated CTest evidence **PENDING**; positive
R2 owner consent, R10 LAN Start, client trust and live Microsoft-client
acceptance remain **BLOCKED / NOT RUN**.

## R5 CI structure inventory correction (2026-10-19)

The first exact-SHA structure run for R5 correction `3ebb80eec39d4ca663d4156b48c9d98a713f2300`
(Actions `39272105951`) correctly rejected the changed 42-case sanitizer
inventory because `scripts/validate_ci_workflow.py` still required the old
literal `r5_expected_test_count=39`. Preserve that independent guard: update
its required count to 42 and require the native-geometry, same-pixel and
RandR-burst generation test names explicitly. No production X11 behavior or
acceptance gate changes in this follow-up; exact descendant hosted validation
is pending.

## R5 RandR burst-generation CI correction (2026-10-19)

Failing exact source `2fcfebee9e94b064ebf54617cd224982060471a0`, Actions `39244189634`, exposed two
obsolete exact-step assertions after R5 began observing the full authentic
RandR screen/CRTC/output/resource notification set. Xvfb's resize helper can
emit several legitimate RandR notifications for one logical resize, and the
native-geometry regression also issued the same resize twice around pointer
activity. Production retirement is not looping independently: each rebuild is
still fenced to an observed server RandR event, and an idle post-burst drain
must leave the generation unchanged.

R5 now issues the native-geometry resize once, drains each synchronized RandR
burst to quiescence, requires only monotonic fresh generations, rejects the old
typed/scalar framebuffer borrows, proves fresh capture recovery, and asserts no
extra generation retirement on an idle service pass. New ordinary Xvfb CTest
`x11.randr-burst-generation-retirement-recovery` queues two real geometry
transitions plus pointer activity before service and verifies final geometry,
stale-generation denial, fresh capture and settled-generation stability.
Same-pixel topology retirement remains mandatory. R9's native-X11 sanitizer
selection grows from 39 to 42 and now explicitly includes the affected native
geometry test plus same-pixel and burst regressions.

Authoring parent is `2fcfebee9e94b064ebf54617cd224982060471a0`. Canonical owner-local
`~/rdp-server/build/` is **NOT RUN** from this GitHub connector environment;
exact publication-SHA hosted Ubuntu/full-CTest and R9 sanitizer evidence is
**PENDING** at authoring. The independent R7 Linux GUI GCC build failure in
Actions `39244189634` is not an R5 capture regression. Physical X11 seat0,
R2 positive owner authorization, R10 live hosting and Microsoft-client resize
acceptance remain **BLOCKED / NOT RUN**.

## R5 same-root-pixel RandR resource retirement (2026-10-19)

R5 found that native RandR screen notifications with unchanged pixel bounds
and CRTC/output/resource topology changes could leave the existing XShm
capture generation valid. On the sole XCB owner, X11 now subscribes to root
screen, CRTC, output and resource changes, stops the bounded event batch
at each genuine server notification, and rebuilds XShm/Damage/input before
later events even if root width and height match. Synthetic SendEvent RandR
messages are ignored. The existing monotonic R5 capture generation remains
the sole native epoch: no new R3 graphics owner, R10 loop, R2 permission
or XTEST injection gateway.

New ordinary isolated-Xvfb CTest
`x11.same-pixel-randr-capture-retirement` changes Xvfb physical millimeters
at fixed 1280x720 root pixels, verifies generation advancement and stale
borrow denial, then checks current small-frame capture and terminal
retirement. Parent `fab2346a66de3b35828c89d701ec491b74db02b0`; native owner-local build/full CTest
**NOT RUN** (XCB RandR/XShm development headers unavailable here);
exact publication-SHA hosted CI **PENDING**. Physical multi-monitor
hotplug and Microsoft Windows App owner acceptance **NOT RUN**.
R4 #27 is merged; R3 PR #24 is still draft/unmerged and R10's native
RandR-to-R3 remap call is still absent. No full resize claim.

## R9 full-CTest clean-Windows release and fail-closed socket observation (2026-10-19)

Against source parent `1884a9cb3afa30ba2a34ff289a9459f3ef51307f`, register the existing R9 clean-Windows
artifact publication denial fixture as ordinary cross-platform Debug/Release
CTest `packaging.windows-portable-gui-clean-release-structure-denials`.
This offline Python test now also rejects silent TCP/UDP query errors in the
production packaged GUI smoke. The Windows smoke enumerates sockets with
`-ErrorAction Stop` and filters by process PID only after a successful
system query; a permission/CIM enumeration failure cannot become a false
"no listener" pass. Preserve R6's newly landed read-only Windows
firewall/TermService/RDP-policy snapshot checks and their CTests.

Source/reconciliation inspection PASS; isolated native Windows runtime and
exact integration-SHA hosted CI NOT RUN. This adds no network activity,
services, firewall mutations, privileges, live R2 admission or GUI Start.
Genuine non-admin clean-Windows runner `r9-clean-windows-gui` and its exact
ZIP+receipt remain release BLOCKED until independently executed. R10
GUI-default-ON and intentional Qt-free headless selection are integrated by R10 above; same-SHA owner-local Debug CTest and Microsoft-client matrices
remain independently NOT RUN.

## R10 current native Linux interface identity handoff (2026-10-19)

Source parent `db5f2bedd2a4d7ac7084b5f9c1a590d3834c0616`. R10 now resolves GUI `name#index` into the
borrowed current native interface name required by R1, checking canonical
nonzero decimal index, kernel interface identity, name length and embedded
NUL/aliases without allocation or a socket. Both Configure and Start deny
stale or forged identities and retire stale selection. R1 alone must still
reverify the native name/address/index on a future authorized bind.
Added ordinary offline production-backed CTest
`runtime.linux-host-control-native-interface-id-verification`; it verifies
malformed IDs and the optional current Linux loopback name/index without
promoting loopback to LAN eligibility. Review PASS; native local build/full
CTest NOT RUN; hosted CI pending exact published SHA. R2 physical owner
consent/lock/revoke is explicitly unavailable; R1 SSL_CTX fingerprint and
bound-identity observations do not establish client trust or Start authority.
PR #23 remains draft; R3 remap PR #24 has no approved exact-head handoff.

## R6 Windows native read-only host conflict observation (2026-10-19)

R6's five Windows preflight CTests, read-only Service Control Manager
TermService + IP Helper IPv4/IPv6 listener observation, and stronger actual
extracted-GUI no-mutation comparison of firewall rules, service, RDP port
and OS policy are ported to current shared main from PR #25 exact head
581d6828441b37b677a148466fe7bbcdc426d32e. That PR head passed
independent structure Actions 39232722147 and primary Actions 39232722215,
including Windows CLANG64/MSVC. The new shared SHA has not yet passed CI or
owner-native testing; retain these as distinct evidence. This preflight
never binds sockets or modifies Windows OS settings. Any future R10 host
must re-observe immediately before its own authorized listener bind.

R9's clean-Windows release barrier on main (c56dc95) holds the public
Windows portable GUI ZIP until an ordinary interactive nonadmin VM with
runner label r9-clean-windows-gui verifies the identical candidate archive
under OS-only DLL paths. No clean-machine PASS receipt was available at
publication; the human failed ZIP and exact missing DLL are unavailable.
Portable Windows release is BLOCKED independently of R2/R10. Native Windows
hosting remains disabled until authenticated revocable R2 SSPI/CredSSP
SID/WTS/LUID consent and an R10 serialized Windows WTS/session host owner.

## R7 read-only R1 TLS identity display and rotation regression (2026-10-19)

Parent `e85aeb77b184ab618077c557da1e45941c7239f7`: R1's new typed RuntimeTlsIdentityStatus is already
projected by R10/R7, but the Qt TLS label still states the fingerprint is not
supplied. R7 now renders the exact 32-byte R1-observed SHA-256 as uppercase
colon-separated hex only when present. ConfiguredUnbound is explicitly not a
listener, BoundAndMatched requires an R10-confirmed listener/endpoint for
positive bound display, and mismatch/interface-loss/invalid endpoint remain
negative. Client trust remains Unknown with independent client verification
and fresh certificate-rotation verification guidance; no local certificate
parser, trusted-client cache, new socket, credential or authority is added.
Terminal R2 session loss and ControlUnavailable suppress stale TLS identity
and tlsReady in the thin Qt adapter, preserving the raw Stop/close guard.

New ordinary `gui.offscreen-tls-fingerprint-rotation-and-denials` tests the
real Qt status label with the typed R1/R10 contract, missing digest, bound
endpoint changes, certificate rotation, revoked/stale/unavailable controller
and reconnect without retaining an old fingerprint. Source-only contract
review PASS; owner-native Qt/full CTest NOT RUN here; exact-SHA hosted CI
PENDING. Genuine R2 host consent/lock/revocation, positive R10 LAN Start,
actual TLS/certificate rotation, owner M1 and Microsoft-client acceptance
remain BLOCKED / NOT RUN.

## R2 current-owner consent authority must precede native admission (2026-10-19)

At inspected parent `e2e48f0f8fc022203fc25d83540db83e36f5f93e`, R10's concrete Linux
`LinuxRuntimeHostControl` shell has landed on main and remains Start-deny-only.
R2 adds a noninstalled, noncopyable `CurrentOwnerSharingAuthority` boundary
whose valid view/input/clipboard requests (maximum requested lifetime 24h)
are still *intent*, never proof. It contains no positive grant constructor,
GUI Boolean, synthetic native lease or client-controlled approval path.
The production `LinuxConsoleAdmissionBroker` legacy constructor defaults to
null owner authority; both real `issue()` and per-operation
`revalidationChecksPass()` now independently require its positive check.
The current provider always denies, including with genuine GSS/TLS,
PAM/NSS/logind, so no unsupported Linux positive desktop lease can escape.
Existing 1-second connection lease expiry remains separate from the future
owner-controlled sharing lifetime.

Three ordinary cross-platform CTests exercise valid-but-untrusted GUI
intent, invalid scope/lifetime and monotonic Stop/lock-unknown/logout/
user-switch/session-replacement/credential-change/native-auth-loss
revocation epochs. These are **deny-only tests**, not a synthetic positive
consent, native desktop or real client receipt. Positive admission remains
**BLOCKED** until a genuinely trusted physical owner-confirmation mechanism
AND authoritative unlocked-state evidence can be verified under the threat
model; logind `LockedHint`, X11 hints, remote responses and credentials alone
are insufficient. R10 must not start a listener or accept a peer on this
negative outcome, and must revoke R2 before retiring its socket/desktop.
R7 is a prompt/status consumer only. Windows future SID/WTS owner and
macOS UID/audit/security-session owner require their own trusted confirmation,
lock-state and lifetime providers; neither platform gains an admission grant.

Authoring evidence: header/test source inspection **PASS**; owner-local
full Debug build/CTest, new production-library/native Linux compile,
exact-publication-SHA hosted CI, trusted-owner approval, Microsoft-client
NLA and LAN desktop acceptance **NOT RUN**. Next: trusted owner/lock provider,
R10/R7 serialized request wiring, R1 TLS identity/trust then real-client gate.

## R1 TLS identity handoff without enabling LAN (2026-10-19)

Source parent `6cb354adb731`: the existing securely loaded SSL_CTX
now exposes a typed, non-secret configured certificate SHA-256 observation.
Only the existing R1 OwnedLanListener (validated getsockname endpoint and
still-live selected OS interface) can produce a bound-certificate-IP-SAN
match. An unopened listener returns ConfiguredUnbound, never listener-ready;
mismatch/interface loss fail closed. Client trust is explicitly Unknown:
fingerprints do not prove Microsoft Windows App trusted the certificate.
R10 RuntimeHostStatus and thin R7 Qt HostStatus carry the same value-only
observation; no parallel connection, certificate parser, SSL writer,
listener activation or credential authority is created. R10 remains
responsible for refresh/invalidation on certificate replacement, Stop,
endpoint/interface change and selected per-client SSL comparison.
Dedicated ordinary offline `runtime.tls-context-read-only-unbound-identity-status`
is registered with the existing synthetic TLS credential fixtures.
Source inspection PASS; developer-local build/full CTest NOT RUN (owner
checkout unavailable); hosted exact publication SHA CI NOT RUN at authoring.
Positive R2 host owner consent/lock/revoke and R10 LAN GUI Start/Stop remain
BLOCKED, as do live accepted-peer/WANT/half-close/RST testing and physical
Windows App owner acceptance.

## R5 cross-owner X11 capture-generation ABA fence (2026-10-19)

The R5 native geometry snapshot source check found a cross-owner ABA risk:
the existing X11 aggregate started each new capture epoch at 1. A previous
`{pixelGeometry, captureGeneration, nativeSessionGeneration}` observation
could match a replacement X11 owner if the same root dimensions and logind
native-session generation were reused; the legacy scalar capture borrow
had the same weakness. Capture epochs are now allocated monotonically from
one process-local atomic counter on owner creation and RandR rebuild, never
on a frame hot path. Exhaustion fails closed instead of wrapping or aliasing.
This scalar remains provenance only and never grants R2 native permission.
New isolated Xvfb CTest
`x11.native-capture-owner-replacement-aba-denial` demonstrates two sequential
native owners sharing the same pixel size/session generation, rejecting the
retired snapshot, scalar capture and framebuffer consumer before permitting a
current synchronous borrow. No new Graphics owner, native input route or
runtime server loop is introduced.

Implementation parent `793a513fe39d11c5b711367a932bb576b7067760`; source/test registration reviewed;
owner-local native Debug/full CTest **NOT RUN** (owner's X11 checkout/toolchain
unavailable in this environment); exact-publication hosted CI **PENDING**.
R4 PR #27 is merged and prior R5 `30b30195` hosted primary/structure CI
**PASS**. R3 PR #24 remap remains draft, R10 native RandR-to-R3 call is still
absent, R2 positive owner consent and physical seat0 Windows App acceptance
remain **BLOCKED / NOT RUN**. This fix does not claim complete live resize.

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
PR #23 GUI/default-headless source is superseded by the R10 direct-main integration above. Real R2 owner
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
| **R4 · AVC420/x264/RDPGFX** | **OFFLINE READY / R10 persistent reader and X11-first-frame source integration LANDED; real-client proof NOT RUN.** R10 `4795c6dd` and `2a3f06b0` now keep one R2-selected X11/logind desktop alive in the serialized post-Share loop, borrow XShm pixels synchronously into R3's existing ClearCodec publication, use R1's sole TLS reader/writer, dispatch R3 Graphics DATA/FRAME_ACK and R5-protected input, and retire on authorization loss. R1 `e267f42d` fixes server Graphics writes following an idle SSL_read WANT. R3 `bde4fae5` supplies the client FRAME_ACK consumer; `549a12c0` also tightens post-Share Graphics dynamic-channel ID/command routing. At R4 test SHA `33b6ae76`, that same ACK-capacity CTest is hosted-green across Linux, macOS, Windows and R9 sanitizers. R4's same-generation surface-ID reference fence is reconciled from legacy PR #28 onto current main parent `67ea710697dfbcdc9dafb1badb047c50b61ece07`: the x264 producer resets before the first otherwise-valid picture for a different R3-owned surface, with dedicated `graphics.x264-segmented-surface-remap-idr` and a 29-case focused x264/BGRA inventory. This does **not** activate AVC420 after remap; R3 PR #24 remains fail-closed there and mandatory ClearCodec stays first-frame-safe. Source/ownership review PASS; owner-local full CTest NOT RUN. Direct-descendant `e9c4abb43efb59ff24c9eceda594da3c6503452a` hosted acceptance PASSes 42/42 portable R4, 29/29 x264/BGRA (including `graphics.x264-segmented-surface-remap-idr` under ASan/UBSan), 4/4 AVC420 capability and 4/4 ClearCodec; Ubuntu/macOS/Windows protocol jobs complete SUCCESS. Exact authoring SHA `571f77a7c862c95a0e60ef58882e26f2bced8186` itself was compile-blocked by an inherited R6/R9 malformed Python fixture, so only the repaired direct descendant is the compile/test acceptance SHA. The existing `graphics.clearcodec-denials` CTest now also asserts that captured geometry mismatching a mapped R3 surface refuses without mutating output, receipt, frame credit or codec sequence; after receipt-safe DELETE/CREATE/MAP the newly sized frame publishes and accepts its ACK (new exact-SHA CI PENDING). R4's existing move-only segmented frame, zero-outer-byte cancellation, partial-write terminal abort, ClearCodec lossless fallback and x264 external-cancellation IDR recovery remain authoritative; no second frame scheduler or client-ACK owner is justified. Exact `549a12c0` hosted focused R9 ASan/UBSan passes **42/42** portable graphics, **28/28** x264/BGRA, **4/4** ClearCodec, **19/19** R3 Graphics DVC/ACK and **94/94** bounded R1/R3 transport. These are offline/loopback protocol results, **not** genuine R2 OS admission or visible Microsoft-client pixels. The Ubuntu full matrix at that SHA fails one unrelated R2 PAM source CTest; R2 correction `79efe8f2` landed, exact-head full CI **PENDING**. Owner physical seat0 and local full Debug CTest **NOT RUN**. | **R4 next gate is the integrated live first-frame/FRAME_ACK and recovery trace, not a speculative codec rewrite.** R10/R3 must prevent routine ACK-window credit exhaustion (R4 safely caps at 64 pending) from becoming a terminal connection via an authorized non-mutating defer/credit decision; correctly reconcile admitted Client Core Graphics surface dimensions versus R5 X11 capture and RandR resize generation; and keep a bounded poll timeout during a pending R1 Graphics TLS WANT/partial write. R10 owns this sole scheduler, R3 owns surface/channel/receipt and R4 owns only encoder/lifecycle/ACK bookkeeping. R8 CLIPRDR remains safely disabled for native live publication and is not a first-video blocker. R10's GUI LAN Start/Stop backend is still deny-only. Final M2 requires owner-consented physical X11 seat0 Kerberos/PAM/NSS/logind and each actual Windows App/mstsc visible frame, client FRAME_ACK, input, logout/reconnect with same-SHA receipts; do not infer any of this from offline CTests. See [R4 handoff #21](https://github.com/k1moradi/RDP-server/issues/21). |
| **R5 · Linux/X11** | **OFFLINE X11 CAPTURE/INPUT/RESIZE CHAIN GREEN; PHYSICAL-SEAT HARNESS PREPARED, R2 AUTHORITY + R10 POSITIVE LISTENER START LANDED, LIVE TEST BLOCKED ON R10 ACCEPTED-SOCKET SERVICING.** R10 owns the sole R2-selected `X11DesktopResources` and a bounded XCB dispatch after logind borrowed-watch unregistration; R2 now publishes a genuine, per-event post-Share slow-path callback gateway. R5 adds `X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt`, which accepts only one R10-owned complete TPKT and calls the private native callback exclusively through R2's `LinuxRuntimeConnection::dispatchPersonalDesktopSlowPathInputPdu`. R2/R3 rechecks the exact lease, TLS/GSS, native seat/session generations, negotiated input and permission before each callback. R5 rechecks its capture generation directly beside `handleAuthorizedInput()`; mismatch, unsupported decoded event, native failure or admission denial retires with no additional XTEST release and revokes the connection. Deterministic X11 input conversions initially cover exact TS_POINTER_EVENT MOVE, single left/right/middle press/release, and lock synchronization. Set-1 scancode keys (bounded US PC-101 baseline, modifier and E0 press/release, held-key repeat suppression and stale-first-repeat denial) now translate inside the existing R2-protected owner; E1/Pause, unknown OEM keys, Unicode and relative events remain unsupported; vertical/horizontal wheel now maps signed 9-bit RDP rotation to the existing bounded X11 scroll controller without client-coordinate pointer motion; negotiated MouseX XBUTTON1/2 maps to X11 8/9 only after R2's per-event authorization; no packet/session can grant permission by itself. Dedicated offline CTests `x11.input-r2-authorized-slow-path-native-mapping-denials`, `x11.input-rdp-mousex-side-button-bounds-and-flag-denials` and new `x11.input-rdp-wheel-sign-extension-axis-and-coordinate-denials` check supported/rejected R2-routed native conversions; previous Xvfb no-lease denials remain. Owner native full CTest: **NOT RUN**; exact publication-SHA hosted CI: **PENDING**. | **Next R5/R10:** Dedicated offline `x11.input-scancode-make-release-modifier-extended-denials` plus Xvfb `x11.input-native-keyboard-sequence-and-reconnect`, `x11.input-native-keyboard-logout-no-native-post`, `x11.input-r2-policy-replacement-keyboard-denial` and `x11.input-native-keyboard-layout-change-revokes-owner` are authored. Native owner build/full CTest **NOT RUN** (no Linux checkout/toolchain in connector environment); exact published-SHA hosted CI **PENDING**. Xvfb fixtures are not OS admission. The owner-authorized Ubuntu 24.04 / GNOME 46 / Xorg physical-seat run sheet is now prepared in [testing standards](testing_standards.md): the existing Qt preflight records process/session UID, seat/type/Active/Remote/State, advisory LockedHint and DISPLAY plus the GUI-selected R10 interface/address without opening an X11 owner. Capture geometry/generation is intentionally **unavailable before genuine R2 admission** and is recorded only from the one R2-selected `X11DesktopResources` owner before first publication; creating a diagnostic XCB owner early is forbidden. R2 positive current-owner authority and R10's provisioned GUI listener Start have landed. The live run remains **BLOCKED / NOT RUN** until R10 services that exact GUI-owned listener into the existing serialized `LinuxRuntimeConnection` / persistent X11 owner; listener readiness alone is not accepted-client or native-desktop evidence. R5's exact synchronous XShm→R4 borrow and one-XCB-owner event/retirement contract is in [Linux server bundle](linux_server_test_bundle.md). R10 must keep the one X11 owner and R2 logind watch alive in the post-Share application/TLS-read loop, forward each R1-owned complete TPKT through this R2-protected gateway and implement remaining negotiated scancode/Unicode/relative semantics with tests before enabling those formats. R10/R3/R4's synchronous typed XShm BGRA → mapped Graphics → accepted-byte/FRAME_ACK path and resize scheduler are already offline-green; the remaining requirement is physical-client evidence under genuine authority. Parent `4e885e06` moved terminal teardown behind R1's local `retireNativeCandidate()` helper; the R5 source sentinel is reconciled to verify that helper still retires native state before R3/R1 revoke and that its final invocation follows the persistent X11 loop, with no production change. R10's persistent post-Share loop now invokes the linked `rdp-server-linux-x11-authorized-input` bridge for authenticated slow-path input and uses the same R2-selected owner for typed XShm frame borrows; this composition still does NOT authenticate a real client, create owner consent, or claim physical-seat XTEST/frame acceptance. Host physical seat0/Microsoft-client tests remain **BLOCKED / NOT RUN** pending explicit owner authorization. |
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
