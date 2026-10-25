## R7 Type-2 peer-EOF GUI presentation gate (2026-10-25)

Owner evidence on baseline
`5a21694f8aaaf446d2b345c8fef89b94ac4542f3` is Linux local CTest
**975/975 PASS** plus a real Microsoft Windows App path:
TLS established -> raw Direct NTLM Type 1 accepted -> server Type 2 sent ->
**peer EOF**, with no Type 3. Native Admission was not reached.

The lower-layer diagnostic correction at
`73ec034c3f4231ece47400cb3b73e00c628c2dd0` now retains that peer as
`NtlmChallenge`, protocol `PreAdmission`, CredSSP `Closed`, standalone
failure `None`, admission reason `None`, termination `PeerEof`.
Keep a dedicated offscreen R7 regression
`gui.offscreen-authentication-incomplete-before-native-admission` that
requires Main to show
`Remote client authentication did not complete.`, Advanced to show
`Authentication: NTLM challenge sent; client disconnected before response.`,
and local-desktop authorization presentation to remain false.

The same regression must also feed the historical contradictory
`Admission/Failed/Admission/admission=None/PeerEof` tuple and prove R7 still
fails toward authentication presentation rather than
`Could not authorize access to the local desktop.`. In both forms, keep
Sharing ON, the current listener and configured credential intact, and both
Session Password editors blank. Do not expose Direct NTLM/NTLMSSP details on
Main.

Enroll this case in the focused owner-GUI Release lane and update its exact
inventory atomically. This R7 test does not validate the Type-2 encoder and
must not alter logind/native admission, MCS, graphics or clipboard.

## Direct NTLM Type-2 peer-EOF diagnostic gate (2026-10-25)

Keep the dedicated production-backed lifecycle CTest
`runtime.linux-direct-ntlm-type2-peer-eof-pre-admission-diagnostics`. Reuse
the shared real listener/HYBRID TLS/Direct-NTLM fixture: hold the peer after it
receives Type 2 and require `protocolStage == PreAdmission` while Type 3 is
still absent; then close the TCP connection without TLS `close_notify`.

After retirement, require Direct NTLM `NtlmChallenge`, protocol
`PreAdmission`, no standalone authentication failure, no native-admission
reason and transport `PeerEof`. Native desktop, MCS, graphics and clipboard
authority remain absent. Do not fabricate Type 3, CredentialsVerified or native
admission to make this gate pass. Owner base `5a21694f8aaaf446d2b345c8fef89b94ac4542f3` is
**975/975 PASS**; that receipt predates this CTest and does not qualify the
modified tree.

## Direct-NTLM Type-2 peer EOF is pre-admission clipboard dormancy (2026-10-25)

A client that receives a Direct NTLM Type 2 challenge and closes before sending
Type 3 has not supplied credentials and has not reached native Admission.
Regression coverage must keep the listener and configured credential lifetime
separate from that accepted peer, require no native desktop/graphics owner,
`RuntimeClipboardState::Unavailable`, and no clipboard permission, then prove
the next accepted client starts with fresh connection-local NTLM state. A
retained diagnostic such as `stage=admission; admission=none` is not evidence
that native Admission ran.

This is a stale-lifetime/dormancy gate only. It must not activate CLIPRDR,
construct a native clipboard owner, change the Direct-NTLM encoder, or modify
native-admission policy merely to satisfy clipboard coverage. Reuse the shared
production-backed reconnect/Stop->Start lifecycle rather than adding a second
clipboard scheduler or authentication fixture.

## Test-helper declaration-order guard (2026-10-24)

When a new C++ test helper calls another free function defined later in the
translation unit, move the callee earlier or add an explicit declaration before
the helper. Source-only reconciliation must still be compile-valid before
hosted CI is treated as qualification evidence.

## Hosted retry and taxonomy fixture rules (2026-10-24)

A retained terminal diagnostic snapshot describes the previous accepted peer.
A reconnect/retry CTest must first observe the new accepted-client lifetime
(e.g. a current active-client handle or equivalent generation transition)
before allowing a terminal predicate to pass; otherwise a second attempt can
falsely pass against stale Admission evidence and be released before it reaches
Direct NTLM Type 2. Keep peer-side Type 2/challenge evidence where it precedes
the server's active close, but use the authoritative server-side
`CredentialsVerified -> Admission` state for the rejection boundary.

CTest **registered names and labels** use behavior/domain taxonomy. Internal
executable fixture-mode strings may retain agent ownership identifiers when
renaming them would break dispatch; they are not user-visible CTest taxonomy.
Source-policy regexes that feed CMake lists must not include a trailing literal
semicolon in each match when exact occurrence counts are required, because the
semicolon is a list separator. Product-default GUI tests must also keep
credential editability separate from safe default-value behavior when a public
Release capability gate intentionally keeps editing closed.

## Native Admission product-language regression — 2026-10-24

Post-CredSSP native Admission failures are tested as local-desktop
authorization failures, not remote authentication failures. Main must show
`Could not authorize access to the local desktop.`; Advanced diagnostics
consume only the bounded runtime reason taxonomy and reduce it to product-safe
phrases such as `session monitor unavailable` or `active session changed`.
The listener/owner-consent state must remain authoritative so an ordinary
failed peer leaves Sharing ON when those lifetimes are still valid. Regression
coverage forbids `stage=admission`, `CandidateOnly`, and agent-road terms
from the visible GUI.

## Admission-denial active-close evidence rule (2026-10-24)

When the server has already recorded
`CredentialsVerified -> Admission denied` and deliberately closes the
rejected accepted connection, a peer-side final authInfo `SSL_write()`
completion is not a required success receipt: it can race that intentional
server active-close. Keep the earlier Direct NTLM challenge evidence and the
authoritative server-side credential/admission state assertions.

Detailed native-evidence tests must mutate the predicate they name. A valid
changed account UID is not an account-identity mismatch because caller UID is
not trusted; change the independently observed account name for
`AccountIdentityMismatch`, and use account-UID versus console-owner-UID
disagreement for `ConsoleOwnerMismatch`.

Source-order CMake policy checks should reject invalid ordering explicitly
(`first GREATER_EQUAL second`) while keeping exact occurrence counts, rather
than relying on nested `NOT ... LESS` expression parsing.

## Functional CTest names and local-username portability (2026-10-24)

The durable-taxonomy rule applies to **both CTest names and labels**. Registered
CTest output must not contain internal `r1` through `r10` ownership tokens
(including compound forms such as `r6-...` or `r10_...`). Fixture command
modes and roadmap ownership may retain internal road identifiers when needed;
the registered test summary uses only behavior/domain names. CMake checks the
resolved registry so dynamically assembled names cannot bypass the policy.

The existing desktop-GUI local-username CTest is the portability gate for the
first-launch suggestion. It requires the field to match the platform helper's
safe suggestion (or be empty when unavailable), remain user-editable, reject
representative system/service identities, and keep both Session Password fields
empty. No test may retrieve an OS password or treat the suggestion as native
admission.

Any CTest rename must update exact-name/regex CI selectors and the workflow
structure validator in the same publication without changing test behavior or
fixed inventory cardinality.

## Typed native-admission reason matrix (2026-10-24)

Every exposed native-admission first-failure reason requires a deterministic
denial assertion. Keep one positive production-backed broker fixture with
matching process/desktop-owner UID, active physical X11 seat0, unlocked and
non-remote state, valid DISPLAY, fresh generation, a usable session-change
monitor and an authenticated standalone proof. The fixture may inject native
observations only through a friend-only test seam; it is synthetic correctness
evidence, not physical desktop acceptance.

The positive fixture must use a remote StandalonePassword application username
different from the local Unix owner and still produce a lease bound only to the
selected local UID/session. This pins the rule that remote username is not
Linux account proof.

Register the fixture as
`security.native-admission-reason-taxonomy-and-positive-fixture` with labels
exactly `authentication;admission;consent;security`. Continue enforcing the
repository-wide policy test that rejects internal road/agent labels from CTest
taxonomy.

## Logind monitor environment gate correction (2026-10-24)

The physical monitor helper skips only when no booted systemd/logind
environment is available. If systemd is present, failure to create the monitor,
obtain its fd/events, flush the pre-candidate baseline, or obtain a valid
post-flush state is a **test failure**, not SKIP. A real concurrent session
change racing the baseline may remain environment-sensitive/NOT RUN; it is not
converted into authorization.

## Physical logind admission diagnostics and semantic R5 taxonomy (2026-10-24)

Keep the demonstrated real-client boundary at native `stage=admission`.
Deterministic tests pin exact Start-grant mismatches such as session generation,
display and remote-state changes while continuing to re-sample authorization.
Environment-sensitive Linux coverage exercises
`sd_login_monitor_new`, get-fd/get-events, zero-time poll, baseline flush and
post-baseline polling. A hosted machine without a qualifying environment is
SKIP/NOT RUN for that physical helper, never synthetic PASS.

Admission-denied graphics coverage requires no framebuffer, no prepared or
committed frame, zero outstanding frame acknowledgements and no matching ACK;
production codec/ACK/credit code remains unchanged.

The repository-wide CTest label guard continues to reject internal road labels.
This increment also removes remaining R5 ownership tokens from its CTest
summary names and uses `linux;x11;native-desktop;session` labels.

## Durable CTest labels and post-admission diagnostic gate (2026-10-24)

CTest labels describe stable subsystem/behavior boundaries, never temporary
agent ownership. Labels matching `r1` through `r10` (including compound
forms such as `r3-mcs` or `r10-host-control`) are prohibited. Reuse durable
labels such as `protocol`, `transport`, `tls`, `security`, `admission`,
`mcs`, `share`, `graphics`, `clipboard`, `native`, `gui`,
`packaging`, `diagnostics` and `offline`.

Owner-reported evidence on assignment base
`9fd1db518076713f30b41af2aff023308f95a925` is **966/966 PASS** locally.
The real Microsoft client reached TLS, selected Direct NTLM, accepted Type 1,
received Type 2 and progressed through CredSSP, then production failed at
native admission with `stage=admission`. This is now the first demonstrated
failure boundary. Do not reopen TLS/SPNEGO/NTLM work from this receipt and do
not classify MCS/Share/RDPGFX as reached.

A diagnostic-only regression may exercise scalar projection without creating
an admission lease. It must prove the owner-observed admission failure remains
`PreAdmission`, then map only explicitly supplied last-positive protocol
milestones. Positive runtime MCS authority still requires
`CredentialsVerified -> genuine native admission lease`; hosted CI must not
fabricate that lease merely to advance diagnostics.

## Native-admission denial preserves transport/listener truth (2026-10-24)

Owner physical evidence on assignment baseline
`9fd1db518076713f30b41af2aff023308f95a925` reports local full CTest
**966/966 PASS** and a real Microsoft client reaching established TLS, Direct
NTLM Type 1/Type 2 and CredSSP before first failing at native
`stage=admission`. The first client ended as `termination=peer-eof`.
Treat native admission as the demonstrated boundary; do not change certificate
generation, TLS, SPNEGO or DirectNtlm wire behavior without newer evidence of
an earlier failure.

Keep a production-backed behavior gate for:
`established TLS -> CredentialsVerified -> native admission denied -> accepted
peer retired -> listener still valid -> second TLS client accepted on the same
listener`. It must prove the listener generation, local owner authorization
and configured Session Password generation survive the denial, while each
accepted connection receives fresh NTLM state. The dedicated CTest is
`runtime.linux-admission-denial-retains-listener-and-accepts-second-tls`.

Transport classification is independent of authentication/admission outcome.
The existing native transport regression must keep TCP FIN without
`close_notify` as `PeerEof` and local TLS failure as a separate category.
Host retirement snapshots that transport fact before owner cancellation; an
admission rejection must never rewrite `peer-eof` as `tls-failure`.

CTest names/labels in this transport/TLS area use semantic taxonomy
(`transport;tls;security;authentication;admission;listener`), not the
internal road identifier.

## Admission-denied graphics dormancy and semantic taxonomy (2026-10-24)

A real Microsoft-client run on owner-tested SHA
`9fd1db518076713f30b41af2aff023308f95a925` progressed through TLS,
Direct NTLM and CredSSP, then failed first at native `Admission`
(`stage=admission`). Treat that as the demonstrated boundary: do not change
TLS/SPNEGO/NTLM or any graphics codec merely to move a failure that has already
been localized to native admission.

The production-backed admission-denial lifecycle regression must require
`graphicsReady == false`, no native desktop/framebuffer availability, no
committed graphics frame write, zero outstanding frame acknowledgements and no
genuine matching frame acknowledgement. These are dormancy assertions only;
they must not synthesize native authority or advance the session.

CTest names and labels exposed in summaries use behavior/domain terminology,
not the graphics road/agent identifier. For this scope use semantic
`graphics`, `frame` and `codec` labels rather than an `r4*` label.
Underlying internal source ownership terminology may remain where it is not
part of user-visible/test-summary taxonomy.

Clipboard coverage follows the same rule. Use semantic
`clipboard;lifecycle;security` labels (plus platform/runtime/offline labels
where useful), and behavior names such as `clipboard.route-bridge-*` and
`runtime.clipboard-*`. Internal R1...R10 ownership identifiers must not be
part of clipboard CTest labels or test-summary names.

## CI structural guards must move with exact-count qualification pins (2026-10-24)

When a workflow's exact test inventory or focused qualification target list is
changed intentionally, update the repository's structural validator in the
same publication. Do not make the workflow green by deleting a validator
requirement; replace the old expected token with the new exact value and add
the newly required behavior/build target so future drift remains fail-closed.

For the shared DirectNtlm lifetime increment, the structural validator must
require the 97-test clipboard inventory, the shared lifecycle test, the
same-port rebind gate, and `test_lan_listener` in the focused sanitizer build.

## Shared labeled-fixture inventories must be updated atomically (2026-10-24)

When an existing production-backed integration CTest is intentionally reused
by another milestone through an added label, update every exact-count CI
inventory in the same publication and add an explicit name check for the
newly shared test. A label-only reuse is not a new behavior test and must not
be mistaken for an unexpected registry expansion.

The DirectNtlm reconnect/Stop->Start lifecycle is intentionally shared through
semantic `clipboard;lifecycle;security` labels; the clipboard sanitizer
inventory therefore includes that test in addition to the component clipboard
cases. Keep the explicit name pin so future count changes cannot silently
absorb an unintended test.

## Same-port Stop/Start must survive a server-active TCP close (2026-10-24)

R10 Stop -> Start on an unchanged configured LAN endpoint is a behavior gate,
including when the immediately preceding accepted client was actively closed
by the server after authentication/admission failure. On POSIX, that accepted
connection may leave the local endpoint in TCP `TIME_WAIT`; the listener
implementation must allow prompt exact-address rebind without weakening live
listener exclusivity.

Use `SO_REUSEADDR` for this POSIX restart purpose, never `SO_REUSEPORT`.
The regression must prove both halves together: after a real accepted
connection is server-closed and the peer observes EOF, closing the listener
allows immediate bind/listen on the same numeric address and port with a fresh
listener generation; while that replacement listener is live, a second bind to
the same exact endpoint still fails as `PortOccupied`.

Keep this native behavior separate from CredSSP/native admission assertions.
The focused R9 gate runs it before the DirectNtlm reconnect/Stop->Start fixture
so a port-lifetime regression cannot be misreported as an authentication
failure.

## Hosted DirectNtlm lifetime tests stop at the real native-admission boundary (2026-10-24)

A hosted production-backed DirectNtlm lifecycle may use deterministic
`ConsoleOsEvidenceSource` input to qualify explicit Start, consent,
credential/session lifetime and listener behavior. It MUST NOT treat that
synthetic source as a replacement for the production
`LinuxConsoleAdmissionBroker`'s real logind evidence and real session-change
monitor.

On hosts without a qualifying physical graphical logind session, the positive
peer is successful when the real listener/TLS/CredSSP path reaches
`CredentialsVerified` and the subsequent native `Admission` step fails
closed. The fixture must then prove the accepted peer is retired without
revoking Sharing, consent or the configured Session Password, and that a fresh
peer can repeat the full DirectNtlm credential exchange on the same listener.
After ordinary Stop, fresh consent/Start must reuse only the retained credential
generation and create fresh listener/TLS/NTLM connection state.

Do not inject a fake logind lease merely to make hosted MCS assertions green.
Positive native admission/MCS remains a separate physical/native acceptance
gate. R5/R8 may consume the hosted fixture only for pre-native/pre-graphics
dormancy assertions; they must not describe it as admitted MCS evidence.

## Strict-warning binary fixture construction (2026-10-24)

Small protocol test serializers must remain warning-clean under the oldest
hosted GCC/Clang toolchains with project `-Werror` enabled. When a chained
`std::vector::insert` from short temporary ranges/span iterators triggers an
optimizer-dependent bounds diagnostic, do not suppress the warning. Preserve
the existing protocol bound, allocate the exact bounded result size, and use
explicit indexed copies so both the compiler and reviewer can prove each write
extent.

## R8 shares the DirectNtlm reconnect round trip only as a dormancy gate (2026-10-24)

When the production-backed R10 DirectNtlm lifecycle already covers failed-peer
retirement, reconnect and Stop -> Start, R8 must reuse that fixture rather than
create a competing owner. While clipboard activation is blocked, each
pre-GraphicsReady checkpoint must require clipboard `Unavailable`, no
clipboard permission bit in the current owner grant, and no graphics/native
ownership. This makes the authentication lifetime an R8 stale-state regression
without sending CLIPRDR or constructing a clipboard owner.

Keep the dedicated stale INCR and delayed R3 receipt tests as the component
round trips. Synthetic/hosted success remains regression evidence only and
cannot satisfy the separate physical activation receipt.

## R5 DirectNtlm admitted-MCS native-dormancy gate (2026-10-24)

The production-backed R10 DirectNtlm reconnect/Stop -> Start lifecycle now
provides a stronger R5 dependency check than the earlier source-only boundary:
one malformed DirectNtlm peer is retired before admission, while later valid
DirectNtlm peers reach `CredentialsVerified` and fresh R2 admission into MCS.
At every one of those states, and across ordinary Stop/restart, the test must
require both `nativeDesktopReady == false` and
`nativeDesktopInitializing == false`.

This proves that failed DirectNtlm authentication creates no X11 owner and that
successful DirectNtlm credentials plus fresh R2 admission still do not create
one. The positive native-owner transition remains owned by the existing
`GraphicsReady -> visitNativeDesktopSelection() -> initializeNativeDesktop()`
gate. Do not extend R5 with authentication-envelope branching or treat MCS
admission as graphics/native authority.

## Direct-NTLM strict-envelope negative matrix (2026-10-24)

The production-linked DirectNtlm gates must prove the classifier requires both
the exact `NTLMSSP\0` signature and a valid Type-1 structure. Keep explicit
denials for: first-byte-only `0x4e`, malformed signature, raw Type 2 as the
first client token, raw Type 3 before Type 1, oversized initial input, client
Type 2 after the challenge, duplicate Type 1 after the challenge, and
SPNEGO/raw envelope switching.

Known-answer coverage must continue through raw Type 1 -> raw Type 2 -> raw
Type 3 using the existing NTLM implementation, then through the same NTLM
security context for CredSSP pubKeyAuth wrap/unwrap, TLS channel binding and
protected authInfo. The direct final server binding reply must contain
`pubKeyAuth` and zero negotiation tokens; no synthetic SPNEGO completion is
allowed. A valid Type 3 without same-request pubKeyAuth remains a fail-closed
PubKeyAuth boundary for the supported CredSSP v5/v6 sequence.

Wrong StandalonePassword verification must report the R2
`ntlm-negotiation` boundary rather than generic SPNEGO. Preserve every
existing SPNEGO behavior/denial test in the same R9 qualification lane.

## R10 reconnect + Stop/Start authentication lifetime gate (2026-10-24)

Production HostControl changes that affect standalone authentication lifetime
must cover the combined service/connection behavior, not only isolated parser
or Stop tests. Keep a behavior-named integration CTest that drives the real
R10 listener and R1 HYBRID/TLS path through:

`Start -> bad DirectNtlm -> child retired/listener still usable -> good
DirectNtlm through pubKeyAuth/authInfo -> Stop -> fresh consent + Start without
password re-entry -> another good DirectNtlm authentication`.

The gate must assert the same configured credential generation survives the bad
peer and ordinary Stop, owner consent survives the bad peer but not Stop, the
listener generation survives the bad peer but changes after Stop/Start, and
every accepted connection gets a distinct NTLM server challenge. The failed
peer's retained diagnostics must identify DirectNtlm and the exact last reached
authentication boundary; generic `stage=spnego` is insufficient.

Use controlled native-console evidence only to reach authenticated R2/MCS in
hosted tests; do not activate X11 capture/input or claim physical desktop
acceptance. Run this native-environment binary directly in the focused R9
sanitizer owner-candidate gate so skip code 77 is a gate failure there.
Physical Microsoft-client behavior remains separate owner acceptance evidence.

## R7 authentication-failure status/retention gates (2026-10-24)

Keep an offscreen owner-acceptance regression that starts from an active
listener with a configured Session Password and a redacted direct-NTLM
negotiation failure. It must prove Main shows exactly
`Remote client authentication failed.`, Main contains no
`invalid-gss-wrapper`, `NTLMSSP` or `Direct NTLM` text, and Advanced
Diagnostics shows only
`Authentication: CredSSP — Direct NTLM — negotiation failed`.

The same regression must prove the listener and configured credential survive
the peer failure with cleared password editors, then set the accepted-client
CredSSP transition to `CredentialsVerified` while R10 remains
`Authenticating` and assert R7 does not synthesize Connected. Only an
authoritative R10 Connected state may produce the Connected presentation.

Keep a production Linux source-contract around
`retireAcceptedClient()`: it must revoke/clear only the accepted client and
return to ListenerAvailable when the listener is valid. The function must not
call host-wide retirement, revoke the standalone credential, zero its
generation/configured flag or close the listener.

The focused owner-GUI Release qualification inventory includes this regression
alongside credential-editor parity and Stop -> Start credential reuse.

## R8 blocked-state testing after DirectNtlm support (2026-10-24)

DirectNtlm support does not create a new R8 acceptance lane. While production
clipboard activation is blocked, do not add a live clipboard/client test merely
because authentication can progress farther. Failed authentication must remain
provably before native/R8 construction; existing R2/R5 ownership tests may pin
that boundary without manufacturing clipboard authority.

Continue the existing R8 stale-lifetime round-trip regressions as the active P2
scope: `runtime.r8-x11-restart-incr-isolation` for stale native INCR callbacks
and `runtime.r8-r3-repeated-restart-receipt-isolation` for delayed positive
receipts across repeated route retirement/replacement. Keep the existing
teardown and stale-receipt denials green. These tests may use synthetic/offline
state only; they do not qualify production CLIPRDR or authorize the activation
gate.

A failed-authentication regression is a failure if it can construct a clipboard
owner, advertise/dispatch CLIPRDR, or leave a nonzero clipboard
admission/session generation. Prefer proving that state is unreachable before
`GraphicsReady` rather than treating cleanup after construction as success.

## R1 direct-NTLM transport-provenance gates (2026-10-24)

Keep `transport.tcp-owned-hybrid-direct-ntlm-first-record` as the positive R1
fixture: real loopback X.224 HYBRID negotiation -> established TLS -> CredSSP v6
with one raw 40-byte `NTLMSSP\\0` Type-1 token. The frame must be read by
the exact R1 owner/SSL, the selected-certificate fingerprint must remain
unchanged, HYBRID provenance must remain available, and the transport must stay
active in `AwaitCredSsp` after the frame is released.

Keep `transport.credssp-r1-owned-transport-generation` as the stale reconnect
gate. It deliberately destroys and reconstructs the nonmoving connection owner
at the same memory address; the new accepted connection must have a different
nonzero transport generation, and a reader/writer pinned to the retired
generation must reject it without revoking the new owner. Continue running the
existing owner-substitution, raw-SSL downgrade, reply-owner substitution, and
selected-certificate pinning cases beside these gates.

The persistent production reader/writer pair in `LinuxRuntimeConnection`
provides the same provenance pin for both SPNEGO and DirectNtlm through Type 1,
Type 2, Type 3, pubKeyAuth, and authInfo. These tests are transport provenance,
not authentication or certificate-generation qualification.

## R5 authentication-envelope independence gate (2026-10-24)

Keep `runtime.linux-r5-auth-envelope-independent-native-owner` as an offline
source-backed ownership regression. It must prove that PreAdmission
authentication failures cannot call native construction, only
`CredentialsVerified` can request R2 admission, native selection requires a
live non-revoked lease plus authenticated principal proof, and X11 construction
is reachable only from the `GraphicsReady` phase.

The bounded R5 construction/selection slices must reject dependencies on
`DirectNtlm`, SPNEGO/NTLM envelope selectors or token parsers. This is the
architectural regression for both successful and failed direct-NTLM paths; do
not add a DirectNtlm branch to R5 to make the test pass.

Continue the existing three-cycle
`runtime.linux-host-control-stop-start-retains-standalone-credential`,
`runtime.linux-host-control-fresh-native-authorization-every-start`, and R9
Start/Stop/TLS interop gates. While they have listener/credential/owner-consent
readiness but no admitted GraphicsReady client, they must explicitly report no
native desktop owner/initialization.

## R9 primary Microsoft-CSSP negotiation qualification gate (2026-10-24)

The owner-candidate gate is no longer a generic "entered SPNEGO" check. The
required direct-NTLM fixture reproduces the physical Microsoft-client structure
exactly: TSRequest version 6, one negoToken, exactly 40 bytes, leading
`NTLMSSP\0`, MessageType 1. That valid token MUST select `DirectNtlm`;
classifying it as `invalid-gss-wrapper` is a regression failure. Keep
`ntlmOffered` reserved for a SPNEGO mechanism-list offer: the direct fixture
therefore observes zero mechanisms and `ntlmOffered == false`, with the
separate `directNtlmType1Accepted` checkpoint true.

The same production CredSSP translation units must then return raw Type 2,
verify the known-answer raw Type 3 into the existing NTLM security context,
accept final Type 3 together with `pubKeyAuth`, verify TLS channel binding,
return server `pubKeyAuth`, decrypt/verify protected `authInfo`, and reach
`CredentialsVerified`. Do not add a second NTLM implementation or OS/GSS
fallback.

The primary R9 sanitizer gate MUST directly run Start -> Stop -> Start, the
direct-NTLM mechanism and full CredSSP flow, the TLS-backed SPNEGO bridge, and
the complete ordinary SPNEGO matrix: NTLM-first, NegTokenInit2 with
Kerberos/NEGOEX before NTLM, mechListMIC, and malformed-DER/integrity denials.
Do not nominate another Linux owner candidate until (1) Start -> Stop -> Start
passes, (2) the direct-NTLM production-backed fixture reaches
`CredentialsVerified`, (3) the ordinary SPNEGO suite passes, and (4) the
Linux/macOS/Windows shared protocol jobs are green on one exact SHA.

Runtime diagnostics remain secret-safe and fail-only. A direct-NTLM connection
must identify itself as `credssp=direct-ntlm` and preserve
`direct-ntlm-type1=accepted`; any later failure must retain the exact
authentication failure stage instead of falling back to a generic SPNEGO
classification.

## Direct-NTLM CredSSP envelope and immutable-mode gates (2026-10-24)

Real Microsoft Windows App evidence now proves a CredSSP v6 initial
`negoTokens` payload can be the 40-byte raw NTLMSSP Type-1 message rather
than a GSS/SPNEGO wrapper. Keep production-backed coverage for both immutable
connection envelope modes.

The focused mechanism gate must prove raw Type 1 produces a raw Type 2,
raw Type 3 reaches the existing `MechanismVerified` NTLM security context
with no synthetic SPNEGO terminal bytes, and changing DirectNtlm -> SPNEGO or
Spnego -> raw NTLM on a later token fails closed. The integrated TLS/TSRequest
gate must additionally prove the direct v6 path through final raw Type 3 +
`pubKeyAuth`, TLS channel-binding verification, server binding reply and
protected `authInfo` to exact standalone credential verification. Existing
SPNEGO/NegTokenInit2 tests remain required regressions and OS-GSS fallback must
remain disabled.

Keep
`security.standalone-credssp-portable-envelope-modes-converge` registered
unconditionally so ordinary Linux/GCC, macOS/Clang and Windows/MSVC full CTest
all drive both SPNEGO-wrapped NTLM and DirectNtlm through the same production
CredSSP owner to `CredentialsVerified`. The fixture must not branch on host
platform and must link only the shared standalone CredSSP/NTLM target, never an
OS GSS provider.

The R9 owner-candidate sanitizer lane executes the new direct-NTLM integrated
flow alongside Start/Stop/Start, X.224/TLS and SPNEGO compatibility fixtures.
This is automated protocol evidence only; only a new physical Microsoft-client
receipt can advance the live acceptance boundary beyond the previous
`invalid-gss-wrapper` failure.

## Protocol ownership gate after the physical admission failure (2026-10-24)

Keep `runtime.linux-host-control-stop-retires-protocol-session-state` as the
source-contract gate for the authentication -> native admission -> protocol
boundary. TLS establishment, Direct NTLM selection, NTLM Type 1/2/3 processing,
CredSSP binding and credential verification are not MCS authority. Only
`CredentialsVerified` may invoke `issueAdmission()`, and HostControl may
enter the first MCS boundary only after that call returns a genuine,
non-revoked native admission lease.

The owner trace on
`9fd1db518076713f30b41af2aff023308f95a925` reaches the native admission
attempt and fails with `stage=admission`. Treat that as pre-protocol. No
MCS/Share/RDPGFX wire changes are justified by this failure.

The first connection-side MCS read independently requires the live lease,
`AwaitVerifiedR2Admission` and fresh broker revalidation. Diagnostic progress
is sticky only for failure classification:
`PreAdmission -> NativeAdmissionVerified -> MCS Connect-Initial received ->
Connect-Response sent -> ErectDomain -> AttachUser -> ChannelJoin/MCS
established -> Share activation`. Hosted tests may validate scalar projection,
but must not mint the positive lease needed to execute those runtime transitions.

## R1 diagnostic-independence and deterministic terminal transport (2026-10-24)

Keep a dedicated production-runtime regression proving HYBRID TLS can attach and
establish from the exact R10 TLS context without first calling the optional
endpoint diagnostic projection. The accepted SSL leaf must still match that
context. A projected fingerprint, when present, is an additional continuity
assertion only.

When a test intends to prove peer EOF after established TLS without
`close_notify`, use a write-side TCP shutdown and keep the socket alive until
the server observes EOF. Closing a socket with unread TLS state may legally
surface as an RST on some platforms and must not be used as a deterministic EOF
fixture. Separate tests own peer reset and peer TLS-alert classifications.

## R6 macOS restart must deny retained credential without fresh consent (2026-10-24)

The macOS production-listener round-trip must prove more than requesting consent
on every successful cycle. After ordinary Stop, prepare a fresh endpoint-bound
TLS identity on the same reusable port and call Start **before** requesting the
next owner grant. Start must fail with `HostConsentRequired`, keep the listener
closed and leave the retained Session Password generation unchanged. Only a new
explicit owner-consent grant may make that prepared listener eligible to bind.

This keeps the portable lifecycle semantics symmetric with Linux R5: credential
retention is convenience only and can never become sticky native/listener
authority. The denial/regrant sequence changes no RDP wire behavior.

## R5 fresh native authorization restart gate (2026-10-24)

Keep `runtime.linux-host-control-fresh-native-authorization-every-start`
as the native-environment behavior gate for A1 -> Start -> Stop -> Start. It
configures the Session Password once, proves Stop removes A1/listener/TLS/native
readiness while retaining the exact credential generation, proves Start #2
without A2 is denied after another native evidence read, then requests A2 and
restarts the same physical session without password re-entry.

The deterministic
`runtime.linux-host-control-retained-credential-lock-session-loss`
case must cover lock/unknown state, X11 DISPLAY replacement, local-user switch
and session-generation replacement while stopped. Each changed/stale native
identity is credential-terminal before any listener can exist. The existing
`runtime.linux-host-control-native-desktop-bounded-post-share`
source contract must additionally pin Stop -> `retireAfterAuthorizationLoss()`
-> no-XTEST input retirement -> input/damage/capture destruction -> native owner
reset, and require fresh native construction to remain behind an authenticated
GraphicsReady client and nonzero admission/session generations.

A native-environment skip does not qualify same-session restart on an owner
machine. These gates prove lifecycle/ownership only; they do not qualify a real
Microsoft client, R3 graphics visibility or physical XTEST input.

## R6 cross-platform Session Password Stop/Start round trip (2026-10-24)

Keep a portable policy test for the complete credential retirement matrix and
production HostControl lifecycle coverage on each implemented desktop platform.
Linux and macOS must each exercise at least three
`Start -> Stop -> Start` listener lifetimes with one configured Session
Password. Every Start requires a fresh owner-consent grant and freshly prepared
endpoint-bound TLS state; every listener generation must differ.

The first successful port is reused immediately on later cycles. Rebinding the
same endpoint is the socket-retirement assertion: a leaked listener descriptor
must make the test fail rather than choosing another port. After every Stop
require no listener generation/bound endpoint/active client, no TLS identity,
no native desktop/input owner, and no owner grant while the exact credential
generation remains visitable. Explicit Revoke must then make that generation
unvisitable. Native-interface absence may skip the platform integration case;
a skip is not platform qualification.

The shared portable matrix is compiled on every platform so a future Windows
HostControl inherits the same Stop-retain / terminal-revoke contract before it
adds its own native listener round-trip test. These tests change no RDP wire
semantics.

## R1 real-socket X.224 -> TLS interoperability gate (2026-10-24)

A production-linked compatibility regression must perform TCP, X.224 Connection
Request with HYBRID offered/selected, X.224 Confirm, then an OpenSSL client
handshake that trusts the generated leaf and verifies the exact numeric IP.
The connection must remain open after certificate verification. Reconnects
within one Sharing-session TLS context must observe the identical leaf DER and
fingerprint. Keep the existing partial-write, WANT_READ/WANT_WRITE, EOF/reset
and cancellation tests in the same semantic R1 suite.

For owner Microsoft-client captures, record the exact server SHA/client build,
configured/bound endpoint, certificate fingerprint/IP self-check, every R1
handshake step and the terminal class. The next physical run must answer whether
the peer closed/reset/alerted first or the server produced a local TLS failure
before any R2/R3/R4 diagnosis proceeds.

## R9 combined lifecycle and standalone-SPNEGO owner-candidate gate (2026-10-24)

Before another owner candidate, directly run the three production-linked R9
fixtures on one exact SHA: `r9-start-stop-start-and-tls-interop`,
`r9-microsoft-neginit2-ntlm-challenge`, and
`r9-standalone-credssp-tsrequest-v5-v6-ntlm-challenge`. Native skip 77 is a
failure for this gate, not qualifying evidence.

Together they cover repeated same-port Start/Stop with retained memory-only
credential plus fresh consent, real X.224 HYBRID/TLS, Microsoft-compatible
SPNEGO selection into NTLM challenge, and TLS-record TSRequest v5/v6 challenge
issuance. They remain focused fixtures and do not claim an unmodified client
PASS.

Real-client fail-only diagnostics must include `tls=`,
`credssp=spnego-initial`, and `spnego=`, with `accepted` or a stable
precise rejection reason. Never log token material and never enable OS-GSS
fallback as a workaround.

## Cross-platform typed protocol-version fixture rule (2026-10-24)

When iterating fixed-width protocol scalar fixtures, make the container element
type explicit. Do not rely on an untyped braced range such as `{5U, 6U}` when
the loop variable is `std::uint8_t`: GCC/Clang may accept the constant
conversion while MSVC with warnings-as-errors reports C4244. Use an explicitly
typed `std::array<std::uint8_t, N>` (or the exact protocol scalar type) so the
same ordinary behavior CTest compiles under every supported toolchain. This is
a test-portability rule only and must not alter protocol semantics or relax
warnings.

## R2 P0 credential retention, native-session retirement and SPNEGO evidence (2026-10-24)

Pin the exact lifecycle sequence: configure G1 -> obtain A1 -> ordinary Stop ->
G1 remains configured and visitable at the same generation while A1, accepted
client/admission/native state, listener and TLS identity are gone -> request a
fresh owner grant A2 -> replace the password -> G2 is newer and G1 is
unvisitable. Keep the existing three-cycle direct HostControl and Qt
Start/Stop/Start regressions; ordinary GUI OFF must never call full revoke, while
Quit/full revoke must erase the credential.

Lock behavior is explicit and fail-closed: after ordinary Stop, an observed
locked/unknown bound session must erase G1; unlocking cannot reuse it and
requires password re-entry. A changed native `sessionGeneration` must likewise
erase the retained replacement credential, covering logout/user-switch/session
replacement. The stopped service loop must enforce this fence before any
listener exists.

The owner evidence
`stage=spnego; os-gss-fallback=disabled` supersedes earlier TLS-first blocker
language. The demonstrated sequence is TCP -> X.224 HYBRID -> established TLS
application transport -> CredSSP TSRequest -> standalone SPNEGO -> rejection.
R3/MCS remains blocked until `CredentialsVerified`, but R2 standalone SPNEGO
is now the first demonstrated interoperability owner.

Keep a bounded initial-token taxonomy test covering malformed GSS wrapper,
unexpected mechanism OID, invalid NegToken choice, malformed mechanism list,
NTLM absent/duplicate, unsupported field order, malformed context flags,
malformed negHints, invalid optimistic token, oversized token and unsupported
initial integrity shape. The Microsoft-style synthetic NegTokenInit2 gate must
cover NEGOEX before NTLM, an optimistic non-NTLM token, negHints, NTLM
selection, a client NTLM Type 1 continuation and a server Type 2 challenge.
This synthetic fixture does not claim the unmodified macOS client's exact token
shape; only the new redacted live structural record may establish that.

## R10 Start/Stop/Start and pre-auth diagnostic gates (2026-10-24)

The direct production Linux HostControl regression configures one standalone
credential generation G1, then runs at least three
permission -> endpoint/TLS -> Start -> Stop cycles without re-entering the
password. After each Stop require Stopped/None,
`credentialsConfigured == true`, the same visitable G1, no current owner
grant, no listener/bound endpoint and no prepared/bound TLS identity. The
recommended LAN endpoint remains available. Final `revokeSharing()` must make
G1 unconfigured/unvisitable and enter Revoked.

Keep a deterministic R10 diagnostic mapping test that separately pins
AwaitTls/handshaking, AwaitCredSsp/TLS-established, terminal TLS failure,
terminal standalone SPNEGO failure and terminal NTLM-negotiation failure. A
generic `AuthenticationRejected` result cannot replace these diagnostics.

R7 separately owns the cleared-editor GUI round-trip and must continue proving
that ordinary Sharing OFF uses Stop rather than terminal Revoke, while Quit and
terminal host-session loss still clear the credential.

Do not request another real Microsoft-client owner test merely because CI is
green. The next owner-test gate requires both: (1) Start -> Stop -> Start works
without Session Password re-entry; and (2) the Microsoft-compatible automated
standalone path reaches at least NTLM negotiation/challenge instead of generic
SPNEGO rejection. Only then should the next owner trace classify a later
NTLMv2, mechListMIC, pubKeyAuth, authInfo or post-auth composition failure.

## R9 SPNEGO owner rejection precision (2026-10-24)

Record redacted `tls`, `credssp`, and categorized `spnego`
diagnostics when standalone authentication fails. An initial parser reject
must distinguish malformed outer DER, mechanism selection and inner field
or NTLM challenge handling. The test evidence must still show whether a
Microsoft-compatible initial TSRequest actually reached NTLM Type 2.
Synthetic NegTokenInit2 and in-memory TLS tests do not count as a live
unmodified Microsoft-client receipt.

## Admission failure is pre-protocol regardless of authentication envelope (2026-10-24)

The real client no longer fails in TLS, SPNEGO or the Direct NTLM envelope.
The first demonstrated failure is native admission after the accepted
standalone CredSSP flow. Preserve established TLS/Direct-NTLM behavior; do not
enable OS-GSS fallback or reinterpret `stage=admission` as an MCS failure.

Protocol ownership begins only after a positive native admission lease. A
diagnostic enum or log line is descriptive and never substitutes for that
capability. Start -> Stop -> Start coverage remains independently responsible
for credential reuse, fresh consent/session/listener state and terminal
credential erasure on full revoke, Quit, native-session loss or destruction.

## R7 Qt Session Password Stop/restart round-trip (2026-10-24)

The owner-acceptance Qt regression must enter Username, Password and Confirm once,
turn Sharing ON, observe listener-authoritative Listening and cleared secret
editors, then turn Sharing OFF and observe authoritative Stopped. Repeat at
least three complete ON/OFF cycles and Start once more without re-entering the
password. Exactly one standalone credential configuration is allowed; every
Start must request fresh local-owner permission.

After each ordinary Stop, require the configured credential to remain present,
the owner grant to be absent, the toggle to be OFF and enabled again when the
endpoint and permission request are available. Partial replacement input must
block Start until Confirm matches. Ordinary OFF must not invoke the terminal
revoke command; Quit and terminal host-session loss still must.

The focused Linux/macOS owner-GUI qualification must explicitly execute
`gui.offscreen-owner-acceptance-password-stop-restart-reuses-memory-credential`
from a Release build with `RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON`. A
registered skip is not qualifying evidence. Do not rely on the ordinary public
Release GUI suite for this proof because that build intentionally hides and
skips the owner-acceptance Session Password surface.

## R9 TSRequest 5/6 in-memory TLS fixture (2026-10-24)

Run `r9-standalone-credssp-tsrequest-v5-v6-challenge` for two separate
in-memory TLS sessions with the real TLS record frame reader and reply
writer. Confirm that both versioned TSRequests issue a nonempty SPNEGO
reply containing a properly tagged NTLMSSP Type 2 challenge. Pair with
the Microsoft-style NegTokenInit2 selection fixture, and do not infer
a complete real-listener chain or live-client acceptance from their
separate simulated peers. An exact-SHA owner log remains mandatory.

## R9 SPNEGO-first acceptance correction (2026-10-24)

A standalone `stage=spnego` failure after an owned TSRequest demonstrates
established TLS/HYBRID provenance and does not justify TLS-first blame.
The pre-owner R9 gate combines the three-cycle same-port host lifecycle,
X.224/TLS identity test, and synthetic Microsoft-compatible NegTokenInit2
Kerberos-first/NTLM-select/Type 2 challenge CTest. Synthetic SPNEGO coverage
does not replace TLS-bound TSRequest v5/v6 full-chain verification or actual
client logs. Do not nominate owner acceptance on a generic SPNEGO stage;
capture the redacted `tls`, `credssp` and `spnego` fields and correlate
the exact SHA and real client trace. Preserve GSS fallback disabled.

## R9 local TLS prerequisite and repeated Sharing qualification (2026-10-24)

Run `r9-start-stop-start-and-tls-interop` against the exact commit as a local
listener/TLS and credential-retention prerequisite. A native-environment skip
is not PASS. Assert three real same-port listener lifetimes with no password
re-entry, distinct listener generations, no stale owner grant, accepted client,
native desktop or TLS identity, and the same configured credential generation
after each ordinary Stop. Full Revoke must erase it.

The local OpenSSL peer proves X.224 HYBRID, certificate numeric-IP SAN and TLS
establishment only. It is no longer the first demonstrated Microsoft-client
failure boundary: owner evidence has reached standalone SPNEGO through a
TLS-derived CredSSP TSRequest. Pair this prerequisite with the Microsoft-style
standalone SPNEGO/NTLM challenge fixtures; do not enable GSS fallback and do not
nominate another owner attempt until the automated path reaches NTLM
negotiation/challenge.

## R8 repeated Stop/restart stale-lifetime gate (2026-10-24)

Keep production clipboard activation disabled while testing teardown. Repeated
Start -> Stop -> Start coverage must prove that the old prepared clipboard/
native owner is destroyed, pending X11 INCR is canceled before replacement,
old admission/session native generations are not reused, and delayed positive
clipboard delivery receipts cannot alter a replacement route/source.

`runtime.r8-x11-restart-incr-isolation` exercises the production X11 adapter
through its injected native seam. `runtime.r8-r3-repeated-restart-receipt-isolation`
preserves copied scalar receipts across two route retirements and injects both
while a third route owns its own pending PDU. The Linux HostControl source
contract separately pins clipboard-before-R5 teardown, native-owner reset,
fresh replacement construction and independence from standalone credential
readiness. These are ordinary full-CTest regressions and intentionally remain
outside the fixed clipboard sanitizer-count selection.

## Post-auth handoff and fresh-session rule (2026-10-24)

The demonstrated Microsoft-client chain is now:
**TLS established -> Direct NTLM selected -> NTLM Type 1 accepted -> Type 2
sent -> CredSSP progressed -> native admission attempted -> admission failed**.
The production diagnostic is `stage=admission`. MCS, Share, licensing and
RDPGFX are **NOT REACHED** and must remain unchanged.

After a future genuine admission succeeds, retain a bounded last-positive
diagnostic so the next physical run can distinguish native admission verified,
MCS Connect-Initial received, Connect-Response sent, ErectDomain, AttachUser,
ChannelJoin/MCS established and Share activation. This scalar contains no wire
bytes and never drives the state machine.

Ordinary Stop still destroys the accepted connection's complete
MCS/Share/channel session before listener teardown. A later accept constructs a
fresh `LinuxRuntimeConnection` and value-owned `McsSessionLifecycle`; no
MCS, licensing, Share or DVC state may be reused.

## R5 owner-situation readiness must execute in Release+acceptance CI (2026-10-24)

The Linux physical-X11 precredential integration case is not satisfied by
compiling its target. In the hosted R5 Linux GUI lane, first seal and verify the
ordinary public Release artifact with
`RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=OFF`. Then reuse the same ephemeral
`build/` root, reconfigure it as Release with the explicit owner-acceptance
surface ON, build
`test_linux_gui_physical_x11_precredential_readiness`, and execute exactly
`runtime.linux-gui-physical-x11-precredential-readiness`.

That hosted gate must observe an actual recommended private-LAN endpoint and
report the test as Passed rather than accepting CTest's native-environment skip.
The fixture itself still injects only read-only deterministic physical-X11 owner
evidence; it must use the production Linux HostControl/Qt adapter and must not
configure a credential, request consent, bind, capture or touch XTEST. Assert
R2's production standalone-credential configuration availability and R10's
lifecycle `credentialEditingAllowed` fact independently of the still-false
public Release qualification bit. A successful hosted fixture is not a physical
owner/X11 receipt and does not promote Release qualification.

## Shared source contracts must follow the R2 credential transaction (2026-10-24)

Static lifecycle/security tests must validate the current ownership boundary,
not a retired inlined implementation. When platform HostControl delegates
standalone password replacement to
`replaceStandaloneApplicationCredential()`, source contracts should require
the platform caller to clear/select the exact credential generation and should
inspect the shared R2 helper for consent revocation before production credential
configuration.

Do not weaken cross-subsystem negative assertions when following a helper.
Clipboard/R8 forbidden-operation scans for credential replacement must include
both the platform call site and the shared R2 replacement helper so refactoring
cannot hide clipboard activation behind the helper boundary.

## R7 owner credential keyboard/focus and visual-state contract (2026-10-24)

When the gated Session Password surface is visible, R7 must keep credential
entry independent of ordinary Sharing readiness. Username, Session Password and
Confirm must remain enabled, writable, StrongFocus keyboard/click targets while
R10 reports credential editing allowed, even when Sharing is blocked by an empty
password, confirmation mismatch, owner permission or endpoint readiness.
Password and Confirm remain masked.

The shared Linux/macOS owner-acceptance behavioral regression must verify the
entire enabled QWidget parent chain, enabled Main tab/QTabWidget state, Qt
enabled style state, explicit Username -> Password -> Confirm tab traversal and
real key-event editing. Linux hosted qualification must additionally execute the
same behavior through the XCB platform plugin under Xvfb rather than relying
only on Qt's offscreen backend.

Linux presentation may use palette-derived styling, but enabled, focused and
disabled credential fields must remain structurally distinguishable even when a
desktop theme assigns similar colors. Do not solve a blocked Sharing action by
graying credential entry. Public Release qualification, production credential
configuration availability and R10 credential-editing authority remain separate
gates; no GUI style or focus state authorizes credential configuration, owner
consent or a listener.

## Source contracts must follow semantic credential ownership (2026-10-24)

When production credential replacement is consolidated behind a shared R2 helper,
source-contract tests must validate the complete semantic chain rather than pin
the retired direct-call spelling. For owner acceptance this means proving Qt
forwards to `configureStandaloneApplicationPassword()`, the platform
HostControl invokes the shared replacement transaction, and that transaction
uses the production credential owner's `configure()` while revoking prior
owner consent for `CredentialChange`. Do not weaken the contract to a generic
token or require duplication of the old direct call.

## R9 owner-GUI keyboard editability parity gate (2026-10-24)

The R6 editor-property gate is necessary but not sufficient for owner usability:
visible/enabled/non-read-only/focusable QLineEdit state does not prove that user
key entry reaches the editor. For the owner-reported Linux regression, keep a
second behavior test that sends Qt key events into Username, Session Password and
Confirm and verifies the resulting text. Run that same case under explicit
`Release + RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON` on Linux and macOS.

Keep Password and Confirm masked. A mismatched confirmation must leave Sharing
unavailable and present a useful reason; matching non-empty credentials may make
Sharing actionable only when the injected product permission/network
prerequisites permit it. The GUI test double may observe command arguments and
ordering only. Pair the test with
`gui.owner-acceptance-release-gate-and-production-path`, which pins forwarding
through the real runtime standalone credential owner and prohibits test-only
authentication.

Start command success is not listener authority. Until HostControl publishes
the exact bound endpoint, the UI must remain Sharing Off, show
`Local address: <ip>`, and keep Copy disabled. Only authoritative listener
state may change that to Sharing On, `Connect to: <ip>:<port>`, and Copy
enabled. The dedicated R9 Linux/macOS gate must not depend on CLEAN Windows.

## R2 standalone credential state must be independent of native admission (2026-10-24)

A production standalone credential owner being configurable is a distinct fact
from public Release qualification, a configured credential, owner-permission
requestability, an active grant and listener readiness. Keep
`standalonePasswordConfigurationAvailable` descriptive only; it must never
authorize admission or promote
`kStandalonePasswordProductCapabilityApproved`.

`configureStandaloneApplicationPassword()` must use the production
generation-fenced credential owner, scrub the mutable caller password on every
path, select a nonzero current generation only when the credential is valid,
and revoke prior owner consent as `CredentialChange`. A valid credential must
remain reportable as configured even when current native evidence is unavailable.
Linux native X11/NSS admission is a later Start prerequisite and must be rebuilt
from fresh evidence there rather than being folded into the credential fact.

Keep
`security.standalone-credential-unconfigured-consent-independence`,
`security.standalone-credential-replacement-revokes-owner-consent` and
`runtime.linux-host-control-standalone-credential-native-admission-separation`
in ordinary CTest. These are offline state-boundary tests: no listener, capture,
input, clipboard or live client is evidence for credential configuration.

## R6 owner-acceptance editor-property parity (2026-10-24)

Do not infer editability from palette, styling or a field merely being present.
The same behavior-named Qt regression must run for Linux and macOS under an
explicit `Release + RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON` acceptance
intent. Show the real `DesktopWindow`, process pending Qt events, and require
the Username, Session Password and Confirm `QLineEdit` instances to be
`isVisible()`, `isEnabled()`, not `isReadOnly()`, focusable
(`focusPolicy() != Qt::NoFocus`), and parented beneath an enabled widget.
Username uses normal echo; both password editors use
`QLineEdit::Password`. Writing matching non-empty values must make the
Sharing action eligible only when the injected product snapshot otherwise
satisfies the genuine permission/network prerequisites.

This property regression is offline and non-authorizing: it may not configure a
credential, request owner permission, configure an endpoint or start a
listener. Separate orchestration coverage continues to prove production
credential -> fresh owner consent -> endpoint -> listener ordering. Public
Release Linux/macOS packaging must explicitly set the owner-acceptance option
`OFF`; the acceptance test must never change
`kStandalonePasswordProductCapabilityApproved`.

## Linux pre-credential physical-X11 GUI readiness (2026-10-24)

The owner-acceptance Session Password surface must remain independent of live
native-desktop creation. An eligible read-only physical-X11 observation may make
local owner consent requestable and expose the selected display, but it must not
create a credential, consent grant, listener, accepted client, framebuffer or
XTEST owner merely because the GUI is open.

Keep `runtime.linux-gui-physical-x11-precredential-readiness` as the Linux
integration regression for this boundary. It uses the production
`LinuxRuntimeHostControl` and Qt `HostControl`, injects only deterministic
active/physical/local/non-remote/unlocked seat0 X11 evidence, and consumes the
machine's genuine LAN recommendation. In Debug or explicit owner-acceptance
builds, Username, Session Password and Confirm must be visible, enabled and not
read-only before credential configuration; both password edits must use
`QLineEdit::Password`. Matching non-empty input may make the explicit Sharing
action eligible when the genuine LAN recommendation and owner requestability are
present. It must not mint owner consent or start native capture as a side
effect. Hosts without one valid LAN recommendation may use the registered skip
code rather than fabricating an interface.

This test does not promote `kStandalonePasswordProductCapabilityApproved`;
the Release product capability remains a separate qualification gate. It also
does not substitute a fake authentication backend, open a listener, capture a
desktop or exercise XTEST.

## R8 owner-acceptance credential/start clipboard-dormancy rule (2026-10-24)

The prequalification Session Password workflow must keep R8 dormant through the
entire local credential/start transaction. Owner-acceptance GUI tests must
observe `allowClipboard == false` for both initial and replacement credentials,
and a listener Start failure after successful credential configuration, owner
consent and endpoint preparation must leave
`RuntimeHostStatus::clipboardState == Unavailable`.

Linux source-contract coverage must independently prove that standalone
credential replacement invalidates the prior owner-consent generation and
cannot cross a live listener, while `startSharing()` contains no native
desktop/CLIPRDR owner construction. Native clipboard preparation remains
accepted-client/GraphicsReady-only, and Stop/Revoke must retire any prepared R8
owner before native desktop, connection and listener teardown. Do not add a GUI
clipboard preference while the production activation gate is false.

## R8 isolation assertions in deterministic HostControl evidence tests (2026-10-24)

When an R10 HostControl permission/status regression uses injected deterministic
owner evidence, it must also pin the independent R8 boundary whenever clipboard
activation is not part of the test. Assert the observable
`RuntimeHostStatus::clipboardState` remains `Unavailable` across denied
permission requests and synthetic View/Input grants, and ensure any positive
permission fixture explicitly sets `allowClipboard = false` and observes no
clipboard bit in the resulting owner-grant mask.

These assertions supplement, rather than replace, the production dormancy
contract: `kLinuxProductionClipboardActivationApproved` remains false until its
own physical FIRST receipt, and no offline owner-evidence fixture may construct
or exercise a CLIPRDR/native clipboard owner as evidence for activation.

## R7 GUI permission requestability projection gate (2026-10-24)

Keep a deterministic offscreen GUI regression for both owner-permission product
states without consulting native logind/X11 evidence. With no active owner grant
and `sharingPermission.canRequest == false`, the GUI must display the bounded
unavailable/denial text and disable main/tray Sharing plus the explicit
permission button. With an eligible owner session represented by
`canRequest == true` and no active grant, it must display
`Sharing permission required`, enable the explicit permission/Sharing action,
and remain stopped until the user acts.

The test must prove requestability is not authorization: constructing or
refreshing the window performs no permission request and no Start. Exercising
the explicit Sharing action may request local permission, but a denied fixture
must not progress to endpoint configuration or listener Start. Keep this test
independent of `tests/test_linux_runtime_host_control.cpp`, whose deterministic
native-evidence fixtures are owned by R10.

## Offline owner-consent tests must inject native evidence (2026-10-24)

Linux's default `LinuxRuntimeHostControl` is a production composition object:
it intentionally consumes live `LinuxLogindReadOnlyEvidenceSource` / physical-X11
owner evidence. Therefore an offline permission/status CTest must not construct
the default controller and assume a headless machine. Use the existing
`LinuxRuntimeHostControl(ConsoleOsEvidenceSource&)` seam with deterministic
synthetic evidence for those cases. Keep a separate integration test for the
production/default controller consuming genuine native evidence.

R2's invariant is independent of the host running CTest. Deterministic
unavailable evidence yields `permissionObservation().canRequest == false`,
no active grant, no effective permissions and
`OwnerSharingReadOnlyDenial::EvidenceUnavailable`; `requestConsent()` must
not grant. Deterministic eligible, unlocked, same-UID physical seat0 evidence
yields `canRequest == true`; only an explicit local consent request may mint
the bounded grant, after which View/Input projection follows the exact granted
permission mask. R10 maps R2 `EvidenceUnavailable` to product
`RuntimeSharingPermissionDenial::Unavailable`; the product observation is
descriptive and never substitutes for `authorizes()`.

Such offline tests must not open a listener, capture a real desktop, inject
input, or use the invoking machine's logind/X11 state as a fixture. Synthetic
positive evidence must also use fixed fixture identities rather than
`getuid()`, the logged-in account or another runner-derived identity unless
the test is explicitly classified as native-environment integration.

Apply the same hermeticity rule to HostControl platform inventory. A test that
intentionally consumes the real route/interface list, native interface identity,
NSS account database or another host-session prerequisite belongs in an
explicit native-environment integration group rather than the `offline`
group. Use `SKIP_RETURN_CODE 77` when absence of that prerequisite is a valid
environment outcome. Keep deterministic policy/algorithm assertions in a
separate offline case so native coverage cannot substitute for portable
semantics.

## R9 credential-generation replacement acceptance rule (2026-10-24)

The owner-acceptance bootstrap gate must include the password-replacement consent
regression. After `configureStandalonePassword()`, production GUI Start logic
must re-read authoritative HostControl status before evaluating owner permission;
a pre-credential GUI snapshot cannot authorize a new credential generation.
The exact Linux R9 acceptance inventory is ten tests while this regression,
the listener-Start clipboard-dormancy failure case, and the cross-platform
editor-property parity case are part of the consumer path. Any owner ZIP
candidate must be built from an exact SHA that passes that inventory plus the
packaged no-argument smoke.

## R3 platform HostControl automatic-licensing consumption (2026-10-24)

Every production platform HostControl that consumes the automatic R3 licensing
identity must keep a dedicated behavior-named integration regression in ordinary
full CTest. The regression must prove normal construction has the generated
licensing prerequisite before Start while remaining preparation-only: no
listener, bound endpoint or client may appear from construction or an idle
service iteration.

For macOS this regression is
`runtime.macos-host-control-automatic-licensing-prestart-no-listener`. Keep it
separate from generic product-projection tests so a future refactor cannot
silently replace `automaticRuntimeProvisioned` with an unrelated readiness
signal. This integration test does not replace the portable Microsoft-format
chain, temporary-marker, Server License Request or R1-TLS-separation tests.

## Owner-acceptance ZIP packaging rule (2026-10-23)

Before physical StandalonePassword qualification, do not publish the Debug/
acceptance surface as a normal Release artifact. The R9 bootstrap job may upload
an artifact named `rdp-server-owner-acceptance-linux` only from a build with
`RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON`. Reuse the ordinary Linux GUI
bundler and require exact source SHA, archive verification, digest generation,
and extracted `run-gui.sh` startup with **no arguments**. This artifact exists
only to let the owner execute the physical qualification workflow; it does not
promote the public capability or clipboard activation gates.

## R8 qualification-gate separation regression (2026-10-23)

The bootstrap clipboard-dormancy CTest must pin both independent product gates:
the public standalone-password Release capability remains literal false until a
real Microsoft-client qualification receipt exists, and the production
clipboard activation capability remains literal false until FIRST. The test
must also require the Debug/explicit
`RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI` compile-time surface so owner
qualification can exercise the exact production standalone credential path
without promoting Release.

Do not infer R8 authority from owner-acceptance availability, a hosted listener
PASS, a product readiness state, or a future standalone Release promotion.
Clipboard activation remains governed only by its own physical FIRST receipt
and generation-fenced native lifetime.

## R8 portable-runtime composition regression (2026-10-23)

Keep `runtime.linux-gui-bootstrap-clipboard-dormancy` coupled to the normal
zero-argument application wrapper. The test must read
`linux_runtime_host_control.h`, require
`LinuxPortableDesktopRuntime applicationRuntime`,
`applicationRuntime.hostControl()` and `applicationRuntime.serviceOnce()`,
reject a return to bare `LinuxRuntimeHostControl runtime;`, and isolate the
wrapper class to prove it owns only the existing HostControl rather than any
R8 prepared owner or protected clipboard/CLIPRDR API.

R9's dedicated portable-bootstrap hosted gate may include this test as
acceptance evidence for bootstrap dormancy, but that hosted PASS is not a
physical clipboard activation receipt. FIRST still requires the real
owner-authorized visible desktop + input + Stop path.

## Product hosting listener-readiness and offline GUI portability (2026-10-23)

Tests covering `DesktopWindow` and `HostControl` must observe the cross-platform
independence of the test doubles:
1. `test_desktop_gui_offline.cpp` must not link or invoke backend-specific
   credential scrubbing routines such as `cleanseStandalonePasswordInput()`.
   Use inline volatile scrubbing across caller-owned UTF-16 spans.
2. Address verification tests must differentiate pre-listener `Local address: <ip>`
   from bound listener `Connect to: <ip>:<port>`. Copy actions are enabled only
   when `snapshot.listenerReady && !snapshot.lanAddress.isEmpty()`.
3. `HostControl::status()` projects `listenerReady` when either legacy
   `runtimeStatus.listenerAvailable` is true or `productMayHost` is true
   (`Listening`, `Authenticating`, `DesktopInitializing`, `Connected`), provided
   no terminal host error or revocation is active.
4. Dedicated behavior test `gui.offscreen-product-hosting-listener-readiness` pins
   this projection across lifecycle transitions without relying on legacy fields.

## R9 Portable GUI Bootstrap acceptance gate (2026-10-23)

Keep **GUI Round 2** as presentation qualification only. The stronger
`r9-portable-gui-bootstrap-acceptance` hosted gate qualifies the normal
`rdp-server-desktop` no-argument Linux product bootstrap independently of
CLEAN Windows.

Its exact seven-test inventory covers the portable bootstrap/no-autostart
policy, the desktop-entrypoint regression that rejects a bare
`LinuxRuntimeHostControl runtime;` fallback, no-config StandalonePassword
physical-X11 selection, a production-backed real-listener bootstrap case,
dormant clipboard ownership, and both Debug owner-acceptance GUI orchestration
cases. The listener fixture may inject only a read-only
`ConsoleOsEvidenceSource`; it must still use production
`CurrentOwnerSharingAuthority`, generated licensing/TLS owners, the exact
StandalonePassword credential generation, R1 interface revalidation and the
real `OwnedLanListener`.

Require no listener before Start, a projected recommended private address,
password replacement invalidating the old generation, View/Input consent with
fresh unlocked physical-seat evidence, an actual private-LAN bind,
authoritative bound-endpoint status, and Stop closing the listener and revoking
consent. The Qt acceptance case separately pins “Local address” and disabled
Copy before bind, then “Connect to” and enabled Copy after authoritative bind.
No secret-bearing diagnostic is allowed.

## Generated licensing temporary-certificate marker regression (2026-10-23)

The automatic R3 licensing identity is process-local, so its MS-RDPBCGR
`SERVER_CERTIFICATE.dwVersion` must combine `CERT_CHAIN_VERSION_2` with the
temporary-certificate `t` bit. Keep
`runtime.licensing-autoprovision-microsoft-temporary-certificate-marker` in
ordinary full CTest and verify both fields independently: mask the low 31 bits
for the X.509 chain version and require the high temporary marker. Do not
weaken the existing root-first MS-RDPELE two-certificate/padding regression or
the R1 TLS separation test.

This is R3 provisioning metadata coverage only. It does not authorize a
listener, desktop, CAL issuer, Share transition or unrelated wire change.

## R8 no-config standalone/owner-acceptance boundary regression (2026-10-23)

`runtime.linux-gui-bootstrap-clipboard-dormancy` must consume the landed
no-config standalone composition. Isolate
`LinuxRuntimeHostControl::prepareAutomaticStandaloneAdmission()`: require the
trusted current physical-X11 selector and generated standalone security/admission
owners, but reject listener access, native desktop ownership and every
clipboard/CLIPRDR authority token. Isolate `DesktopWindow::requestStart()`:
require production standalone credential configuration, immediate clearing of
both password widgets, literal clipboard denial on the owner-permission request,
then endpoint/listener Start in that order.

This is source/lifetime evidence only. Debug/owner-acceptance GUI execution does
not qualify public StandalonePassword and does not satisfy R8's physical
desktop/video/input/Stop activation gate.

## R5 no-config StandalonePassword end-to-end offline state machine — 2026-10-23

`runtime.linux-no-config-standalone-current-x11-selection` must not stop at
the read-only selector. It must continue through the production principal-free
standalone native policy, production admission configuration, a
`ConsoleEvidenceAuthenticationKind::StandalonePassword` request and fresh
native evidence inspection/fingerprint. The request must carry no Kerberos
principal and must bind the exact selected local account, `seat0`, X11
display, View/Input permissions and current session generation.

The fixture must remain config-free and side-effect-free: no
`RuntimeConfigurationView`, config file, process `DISPLAY`, listener, X
connection, capture or XTEST. Preserve explicit denials for wrong process/owner
UID, locked/unknown state, remote session, missing display and stale evidence.

## Pre-listener denial ordering across subsystem gates (2026-10-23)

Offline tests that intentionally stop before listener creation must assert the
security property owned by the test, not a stale ordering assumption between
independent fail-closed gates. When R5 native desktop freshness precedes R2
credential provisioning, an unprovisioned HostControl may legitimately report
`NativeAuthorizationDenied` on a headless host or
`CredentialProviderUnavailable` on an eligible physical X11 host. A test
covering that boundary must constrain the accepted denial set explicitly and
still require zero listener/bound-endpoint state.

Subsystem lifecycle tests should avoid invoking unrelated later gates when not
needed. In particular, the R1 generated-TLS Stop-retirement case prepares the
identity and calls Stop directly; R5/R2 Start denials have their own tests.
This keeps ordinary CTest deterministic without weakening listener safety.

## R7 P0 consumer workflow and owner-acceptance qualification tests (2026-10-23)

The pre-qualification Microsoft-client run may use the production Main-tab
Session Password fields only in a Debug build or an explicit compile-time
owner-acceptance build. This supersedes older instructions that required the
password to be injected outside Qt. Public Release builds must still hide the
fields while `standalonePassword` product capability is unapproved. Tests
must pin the literal Release capability false, compile-time acceptance gate,
and forwarding into the exact production standalone credential owner; a mock
verifier or test-only authentication path is a failure.

Keep behavior-named GUI coverage for the one-action Start transaction:
mismatched confirmation denies before credential/permission/network commands;
success orders credential generation before owner View/Input permission,
endpoint configuration and listener Start; failure at any step leaves
authoritative Sharing Off and does not execute later steps. A credential test
double may observe GUI command ordering, but it is not authentication evidence
and must never be cited as Microsoft-client qualification.

Address tests distinguish pre-listener `Local address: <ip>` from
listener-confirmed `Connect to: <ip>:<port>`. Copy and tray Copy are disabled
for the former and enabled only for the latter. Zero-argument startup tests
must continue proving construction/service timers do not open a listener.

Real qualification remains a separate owner-authorized physical test with an
unmodified Windows App or Windows 11 `mstsc.exe`, exact SHA and the existing
R1/R2/R3 redacted evidence chain. Offline GUI PASS cannot flip the Release
capability.

## OpenSSL name-observation test portability (2026-10-23)

Tests that inspect X.509 subject/issuer names must use the supported const
accessors available across the project's OpenSSL 3/4 matrix. Do not invent
`X509_get0_subject_name()`, and do not use
`X509_NAME_get_text_by_NID()` because OpenSSL 4 deprecates it and hosted
macOS builds treat deprecation warnings as errors. Enumerate the desired entry
with `X509_NAME_get_index_by_NID()` / `X509_NAME_get_entry()`, retrieve its
ASN.1 value, and convert with `ASN1_STRING_to_UTF8()` when textual comparison
is required. Keep duplicate-entry checks explicit.

## R8 regression consumes R3 automatic licensing construction (2026-10-23)

Keep `runtime.linux-gui-bootstrap-clipboard-dormancy` coupled to the normal
Linux HostControl constructor now that R3 licensing is automatically generated.
The source guard must require
`configureGeneratedApplicationIdentity()` in that preparation boundary while
rejecting listener access, Start, native desktop/clipboard ownership, clipboard
permission and CLIPRDR routing or writes there. R3's own production-backed
licensing CTests remain responsible for certificate-chain/wire correctness and
the no-listener assertion; R8 verifies only that the new bootstrap lifetime
cannot manufacture clipboard authority.

This source/lifetime regression does not activate clipboard and does not replace
the physical FIRST desktop/video/input/Stop acceptance gate.

## Generated TLS subject/SAN portability regression (2026-10-23)

Keep
`runtime.generated-tls-identity-generic-subject-ip-san-authority` in ordinary
full CTest on every platform. It must use the production no-file generator,
read the generated subject through the const X509 name API, require the generic
`RDP Server` Common Name, require the selected numeric IP to match, and reject
a different numeric IP. This complements the IPv4/IPv6 SAN tests by ensuring
future OpenSSL API portability fixes cannot quietly turn the subject/Common
Name into endpoint authority.

A platform compile failure in the generated TLS source is an R1 failure even
when other platforms execute the behavior tests successfully; record both facts
rather than inferring cross-platform PASS.

## R8 regression consumes R1/R6 automatic-bootstrap contracts (2026-10-23)

The ordinary `runtime.linux-gui-bootstrap-clipboard-dormancy` source-policy
test must now consume the concrete R6 bootstrap header and R1 endpoint-bound
TLS preparation. Require configuration-file-free policy, explicit Sharing
before listen, no automatic listener and nonpersistent Session Password; reject
clipboard as a bootstrap material. Isolate
`LinuxRuntimeHostControl::configure()`: generated TLS preparation is allowed,
but clipboard permission, owner preparation, dispatch and outbound CLIPRDR
queueing are forbidden there. On terminal Stop, require R8/R5 retirement before
connection/listener teardown and generated TLS retirement after listener close.

This remains source/lifetime evidence only. It does not enter the fixed
executable-backed clipboard sanitizer census and does not satisfy FIRST or
clipboard activation.

## Portable GUI canonical no-argument bootstrap smoke (2026-10-23)

Packaging acceptance must launch the extracted desktop application in its
canonical consumer mode with **no arguments**. Hidden diagnostic arguments may
remain separate tests, but they do not substitute for normal startup. The
canonical smoke must prove no TCP/UDP listener exists before Sharing and must
not mutate services, firewall, Windows RDP/TermService or macOS system
configuration.

The portable bootstrap contract must independently pin both generated identity
defaults to volatile memory: R1 TLS and R3 licensing. It must also preserve
private per-user application data as the only allowed target if either identity
is explicitly persisted later, so a future persistence feature cannot silently
turn today's process-local licensing identity into a default disk secret.

Where the host permits it, make the extracted payload read-only and point the
test at isolated per-user application-data/config roots. Any persistent mutable
bootstrap state must appear only under those roots with private permissions;
creation beside the executable is a failure. Portable manifests on Linux,
Windows and macOS must declare no required configuration file, an empty
canonical argument list, memory-only Session Password persistence, no automatic
listener, per-user mutable state and read-only-extraction support.

R1's current generated TLS identity is expected to remain process memory and
therefore need not create a file in this smoke. A future persistent TLS or
licensing identity needs a separate native path-replacement/permission test in
the private application-data root. These are packaging/bootstrap facts only:
a window appearing with no arguments is not authenticated RDP desktop
acceptance.

## R1 automatic TLS identity offline gates (2026-10-23)

Automatic TLS provisioning tests must exercise the production in-memory
factory with **no credential-file arguments**. Require separate exact IPv4 and
IPv6 IP-SAN matches, wrong-address rejection, server-purpose and TLS-hardening
checks, and a generated certificate/private-key match. Retain a negative
file-backed mismatched-key case to prove the common context constructor rejects
inconsistent material.

Lifecycle coverage must prove identity generation owns no socket/listener,
Linux endpoint preparation publishes only an unbound fingerprint, rejected
endpoint replacement cannot retain a stale prepared identity, and Stop removes
the generated identity after listener retirement. GUI coverage must prove
Sharing can reach endpoint preparation when TLS is initially absent but cannot
call `startSharing()` unless a fresh post-configure status reports the exact
prepared identity. These are offline security/lifetime tests, not Microsoft
client trust or end-to-end hosting acceptance.

## R8 automatic-bootstrap clipboard dormancy regression (2026-10-23)

Keep `runtime.linux-gui-bootstrap-clipboard-dormancy` in ordinary full CTest
as a source-policy regression. It must allow zero-argument GUI bootstrap,
generated local TLS/licensing/session prerequisites and a Session Password
surface, while forbidding bootstrap code from touching the production clipboard
activation gate, R2 clipboard permission, CLIPRDR route/dispatch/write APIs or
the prepared R8 owner. The GUI owner-permission request remains
`allowClipboard = false`; Main has no clipboard checkbox while activation is
false.

The regression must also pin terminal/nonterminal ownership: Stop/Revoke retires
prepared clipboard state before R5 and before connection/listener teardown;
replacement native lifetimes prepare a fresh owner from the new admission and
session generations; Session Password replacement cannot carry a live native/R8
generation across its credential boundary; window hide is presentation-only;
explicit Quit calls Stop/Revoke before exit. Keep file/image/directory tokens
out of the composed production owner. This source-only test is not part of the
fixed executable-backed R8 clipboard sanitizer census and is never evidence of
FIRST or live clipboard acceptance.

## Linux Round 2 sharing-permission focused qualification (2026-10-22)

The `r5-linux-gui-zip` Round 2 selector must enumerate and execute exactly
seven offline cases before packaging:
`gui.offscreen-round2-tabs-and-main-simplicity`,
`gui.offscreen-round2-endpoint-refresh-fail-closed`,
`gui.offscreen-round2-advanced-groups-scrollable`,
`gui.offscreen-sharing-permission-product-language`,
`gui.round2-tab-source-contract`,
`gui.round2-qcolor-warning-classification`, and
`runtime.host-control-gui-round2-endpoint-recommendation`.

Keep the exact-name and count assertions so focused Linux GUI qualification
cannot silently omit R2's product-facing permission language while broader
platform CTest still passes it. These tests remain offline and do not request
or grant sharing permission, open a listener, attach a native desktop or enable
Session Password.

## Round 2 tray/refresh ownership regression (2026-10-22)

Keep `gui.round2-refresh-tray-function-boundary` in ordinary full CTest. `DesktopWindow::updateTray()` owns tray
presentation only; it must not acquire host snapshots, recompute the primary
address, own the authoritative sharing-toggle state, call itself, or absorb
`refresh()`. `DesktopWindow::refresh()` owns one fresh host snapshot,
authoritative toggle projection, Main/Advanced status projection, one tray
update and terminal Quit observation.

This source-level contract complements the offscreen behavior cases and catches
function-boundary merges at configuration/test time without opening a listener
or native desktop.

## Windows Round 2 hidden offline verifier (2026-10-22)

Keep `windows.gui-round2-tab-offline-verifier-source-contract` in ordinary
CTest on every platform. The Windows launcher command-mode verifier must require
the single approved `settingsTabs` container and may accept Qt's internal
`QStackedWidget` only when that stack is a descendant of the tab widget. It
must not reintroduce the retired blanket
`findChild<QStackedWidget*>() == nullptr`/wizard assumption.

The behavior remains covered on Windows by
`windows.gui-offline-no-side-effects`,
`windows.gui-start-denied-without-r2-r10`,
`windows.gui-independent-password-input-unavailable`, and
`windows.gui-offline-packaged-qwindows-selection`, plus the extracted
portable-GUI smoke. These tests remain offline and must not create listener,
native-desktop, credential, input, firewall, service or RDP-policy side effects.

## Focused R5 Linux prerequisite CI inventory (2026-10-22)

The `r5-linux-gui-zip` hosted lane must enumerate and execute exactly these
three R5 read-only prerequisite CTests before packaging:
`gui.linux-readonly-seat0-prerequisite-denials`,
`gui.linux-readonly-prerequisite-structured-projection`, and
`gui.linux-prerequisite-probe-readonly-boundary`. Assert the selected names
and count before execution so a rename, dropped registration or selector drift
cannot silently reduce qualification. These remain ordinary offline CTests and
must not open an X connection, start capture, inject input, open a listener or
request permission.

## QTabWidget runtime structure assertions (2026-10-22)

Do not assert that a Qt widget tree containing an approved `QTabWidget` has no
`QStackedWidget`: Qt uses an internal stack to implement tab pages. Keep the
source-policy test responsible for rejecting application-created wizard or
stacked-page navigation. Runtime structure tests should instead require the one
approved tab container and ensure any discovered stack remains contained by
that tab widget, so Qt implementation detail is not mistaken for product
navigation architecture.

## R1 concrete route-aware recommendation authority test (2026-10-22)

Now that R10 exposes `RuntimeHostLanEndpointCandidate`,
`RuntimeHostRecommendedEndpoint` and
`RuntimeHostRecommendationSource`,
`runtime.host-control-route-aware-recommendation-non-authority` must consume
those real types rather than fabricate a pre-landing recommendation result.
Cover a preferred physical LAN, a VPN/virtual winner and a bridge winner, then
convert each only to the exact `RuntimeHostOptions` tuple used by Start.
Route family, preferred-route, metric, ambiguity and source metadata must not
become bind authority.

The paired `runtime.r1-bind-revalidates-recommended-endpoint` source contract
must reject those ranking fields in `RuntimeHostOptions` and in the
`LinuxRuntimeHostControl::startSharing()` transaction while preserving fresh
interface enumeration, stable-ID/native-index resolution, private-LAN policy,
exact current address/up-state checks and post-bind interface continuity. These
remain offline regression contracts and do not satisfy physical FIRST.

## R10 Linux route-aware LAN recommendation regressions (2026-10-22)

Keep `runtime.linux-host-control-route-aware-lan-recommendation` in the
ordinary Linux full CTest set. It must inject route observations into the same
production ranking seam rather than depend on the CI host's live route table.
Cover: default physical LAN `192.168.1.5` over VPN `10.180.105.86`; VPN
winning when its default-route metric is lower; equal metrics becoming
ambiguous; sole eligible dual-stack interface fallback; IPv4/IPv6 default-route
metric ordering; no-route multi-interface ambiguity; and denial of a stale
recommended tuple after the preferred interface disappears.

Keep the existing
`runtime.r1-bind-revalidates-recommended-endpoint` source/behavior guard:
recommendation never authorizes binding and Start must freshly validate the exact
stable interface/address before listener ownership can begin.

R9's existing `gui.offscreen-round2-endpoint-refresh-fail-closed` must consume
the R10 recommendation source. An ambiguous refresh clears the previous
automatic choice, disables Copy/Start for the automatic endpoint and shows no
arbitrary private address; Advanced manual selection remains available. Tests
must perform no external network request. Production may read
`/proc/net/route` and `/proc/net/ipv6_route` as kernel state and must not
name-filter VPN, Docker or bridge interfaces.

## R7/R9 GUI Round 2 acceptance contract (2026-10-22)

GUI Round 2 is qualified independently of CLEAN Windows. Keep
`gui.round2-tab-source-contract`,
`gui.offscreen-round2-tabs-and-main-simplicity`,
`gui.offscreen-round2-endpoint-refresh-fail-closed`,
`gui.offscreen-round2-advanced-groups-scrollable`,
`gui.round2-qcolor-warning-classification`, and
`runtime.host-control-gui-round2-endpoint-recommendation` in ordinary CTest.

Exactly one standard Qt `QTabWidget` owns Main and Advanced. `QWizard`,
Back/Next navigation, the retired disclosure/panel and Session Password fields
remain absent. Qt's internal `QStackedWidget` child is allowed only inside the
approved tab container.

Main contains only the binary Stopped/Sharing title, prominent authoritative
address + Copy, Existing OS Account access, sharing toggle, keyboard/mouse
scope, local permission-request action and connected-device selector/Disconnect.
Interface/port, permission lifetime/status, authentication, TLS, Linux
prerequisites, client activity, lifecycle/status, protocol/native readiness and
redacted errors belong to Advanced.

Advanced groups Network, Security, Desktop and Diagnostics in one
widget-resizable `QScrollArea`; the dedicated offscreen regression forces
overflow at about 560x520 and proves the final diagnostic remains reachable.

R10's recommendation source is the sole automatic-endpoint presentation
authority. Main shows only a bound endpoint or a
`PreferredRoute`/`SoleEligibleInterface` recommendation. Manual Advanced
selection affects the next Start request only. `Ambiguous` must show
“Multiple private networks found. Choose a network in Advanced.” and disable
Main/tray Copy; `Unavailable` must not fall back to the manual combo.

Color-warning classification remains ownership-based: application source has
no `QColorSpace` construction or global warning suppression. A Qt/platform
profile warning is benign unless visible corruption is reproduced.

## R5 compact Linux prerequisite projection regression (2026-10-22)

Keep `gui.linux-readonly-prerequisite-structured-projection` in the ordinary
Linux GUI CTest set. With fully injected observation text it must render exactly
the six compact fields used by Advanced, normalize X11/Wayland presentation,
cover Yes/No/Unknown local-session/lock/physical states, and distinguish
XCB/XTEST client-runtime availability without opening an X connection.
User-visible output must not contain roadmap names, UID/generation,
authorization, logind, capture or XTEST implementation terminology.

Retain `gui.linux-readonly-seat0-prerequisite-denials` for malformed/stale
candidate evidence and
`gui.linux-prerequisite-probe-readonly-boundary` as a source-policy guard.
The latter must require the environment/library/loginctl observation primitives
and reject XCB connection/native desktop/input/capture, listener Start and
permission/consent calls. All three tests are offline and may not start
capture, inject input, open a listener, authenticate a peer or request
permission.

## Cross-platform preferred-LAN recommendation contract (2026-10-22)

Keep `runtime.host-control-cross-platform-lan-recommendation-contract` in the
ordinary full CTest set on every platform. The fixture is pure/offline: it must
not enumerate real adapters, inspect a route table, open a socket or activate a
native host.

The test must cover opaque stable interface identity, explicit IPv4 and IPv6,
private-LAN eligibility, preferred/default-route ownership, optional route
metric and ambiguity. A preferred-route candidate must beat a non-preferred
candidate regardless of identity spelling; comparable lower metrics may rank
routes; equal, cross-family or metric-incomparable distinct endpoints must
remain ambiguous in either input order. Interface names such as `eth0`,
`wlan0` or `en0` must never be portable tie breakers.

This recommendation test complements, and does not replace,
`runtime.r1-bind-revalidates-recommended-endpoint`: R1 still independently
proves that recommendation metadata cannot bypass fresh native bind checks.

## R1 route-aware endpoint recommendation boundary (2026-10-22)

Keep `runtime.host-control-route-aware-recommendation-non-authority` in the
ordinary portable registry. A default-route physical LAN recommendation must be
valid only as an exact interface/address/port selection; VPN, bridge or virtual
alternatives receive the same checks and gain no authority from recommendation
rank. Rechecking the tuple against a replacement interface snapshot must reject
interface removal, stable-identity replacement and address replacement.
Wildcard and non-LAN/public selections remain fail-closed.

Keep `runtime.r1-bind-revalidates-recommended-endpoint` as an ordinary
offline source-contract CTest. It must isolate the production
`LinuxRuntimeHostControl::startSharing()` transaction and require fresh
interface enumeration plus stable-ID resolution before the R1 listener open.
It must isolate `openLanListener()` and require private-LAN policy, exact
current native interface/address membership and platform up-state before
`bind()`, followed by the existing post-bind `interfaceStillMatches()`
check. Recommendation/ranking code must not enter the Start authority
transaction. This source guard is architecture evidence only and must never be
reported as physical FIRST acceptance.

## R8 GUI Round 2 dormant-clipboard presentation boundary (2026-10-22)

While `kLinuxProductionClipboardActivationApproved` is false, the default/Main
dashboard must expose no clipboard control and must not turn an internal
clipboard permission bit into Main-page product status. Keep
`gui.offscreen-round2-tabs-and-main-simplicity` requiring no
`allowClipboard` or clipboard-named dashboard descendant. Keep `security.owner-consent-read-only-product-facts` injecting the full
allowed permission mask, including the dormant clipboard bit, below the product
boundary. Keep `gui.offscreen-r2-owner-grant-observation` consuming only the
R10 View/Input product projection and requiring the read-only Advanced
owner-permission summary to show screen and keyboard/mouse scope with no
clipboard field.

If pre-activation clipboard diagnostics are added later, they belong under the
Advanced tab, are read-only, and must not mutate permission or activation
state. These presentation checks do not replace the existing R8 lifetime
regressions: hide-to-tray preserves the active owner, explicit Quit retires via
Stop/Revoke, stale X11 INCR/paste state retires before R5, and reconnect creates
a fresh generation-bound owner. None of these tests satisfy Linux FIRST or
authorize clipboard activation.

## R6 standalone-authenticated Windows owner regression (2026-10-22)

Keep `windows.native-owner-standalone-authenticated-session-lifecycle` in the
ordinary Windows full CTest set. It must construct the real
`WindowsNativeDesktopAuthorization` with a
`NativeDesktopAuthenticatedSessionProof` whose authentication kind is
`StandalonePassword` and which deliberately implements no Windows SID
matcher. Successful R6 owner construction therefore proves the WTS/native SID
is fresh local target evidence, not the remote standalone identity.

The same test must cover View-only versus View+Input scope. An Input request
through a View-only grant must be denied and must retire the Windows owner
fail-closed; it must never create or reach a native input controller. The test
must also terminally retire the aggregate when the standalone authentication
generation changes, the local owner grant is revoked, or fresh
`WindowsNativeSessionEvidence` changes. If input was delivered before
authorization loss, no synthetic native input may be posted afterward. The
fixture remains fully injected/offline: it must not read
live WTS/LSA state, enumerate DXGI, sample a live cursor, call SendInput, open a
listener or authenticate a real client.

## R5 standalone-authenticated macOS owner regression (2026-10-22)

Keep `macos.native-desktop-owner-standalone-authenticated-session-lifecycle`
in the ordinary Apple full CTest set. It must construct the real
`MacNativeDesktopAuthorization` with a
`NativeDesktopAuthenticatedSessionProof` whose authentication kind is
`StandalonePassword` and which deliberately implements no macOS UID matcher.
Successful R5 owner construction therefore proves the console UID is consumed
only as fresh native target evidence, not as the remote standalone identity.

The same test must cover View-only versus View+Input scope and terminally
retire the aggregate when the standalone authentication generation changes,
the local owner grant is revoked, or fresh `MacNativeSessionEvidence` changes.
If input was held before authorization loss, no synthetic Quartz release may be
posted. The fixture remains fully injected/offline: it must not enumerate a live
display, request TCC, start ScreenCaptureKit, post Quartz input, open a listener
or authenticate a real client.

## R2 P0 standalone native-authorization regression boundary (2026-10-22)

Keep the existing Track E OS-account mismatch cases unchanged: Windows
`ExistingOsAccount` must reject SID mismatch and macOS must reject UID
mismatch. Add separate standalone coverage through the same production
`WindowsNativeDesktopAuthorization` /
`MacNativeDesktopAuthorization` state machines, with a proof that implements
no SID/UID matcher. A positive standalone case must expose authentication kind
`StandalonePassword`, an empty/zero compatibility authenticated SID/UID and
the real local native-session identity only as target evidence.

Standalone denial coverage must independently reject lost/substituted TLS or
connection provenance, loss of `CredentialsVerified`, stale/replaced
`StandalonePasswordCredentialOwner` generation, owner Stop/revocation, owner
lock and native session replacement. The real
`StandalonePasswordAuthenticatedPrincipalProof` must remain derived from the
generic native authenticated-session proof and the direct-TLS memory-BIO path
must still be unable to produce a nonzero authentication generation.

These are offline state-machine tests only. They do not authorize a live
desktop, enable the product password capability, flip R6's positive Windows
activation gate or substitute for an unmodified Windows App/`mstsc.exe`
physical acceptance run.

## R1 standalone provenance-generation diagnostic regression (2026-10-22)

Keep
`runtime.linux-connection-standalone-authentication-provenance-generation`
in ordinary full Linux runtime-security CTest. It must construct the production
standalone selector with one exact credential generation, require the bounded
acceptance snapshot to report that generation, replace the service credential
and prove the accepted connection still reports its originally pinned
generation, then retain that correlation through terminal cancellation. The
ExistingOsAccount control case must report generation zero.

This is diagnostic/source-lifetime evidence only. It does not perform CredSSP
interoperability, native admission or physical FIRST and cannot substitute for
the existing owner-bound standalone proof tests. Do not add passwords, hashes,
NTLM/SPNEGO/TSRequest bytes, session keys, delegated credentials or native
identity data to the snapshot or FIRST trace.

## R6 Windows sanitizer selector cardinality tracks required cases (2026-10-22)

The mandatory CLANG64 sanitizer preflight selects
`^windows\.(geometry|capture|cursor|input)-`. When R6 intentionally adds a
new case inside that namespace, update both the explicit required-name list and
the exact cardinality assertion in the same change. Do not preserve a stale
count by excluding the new test or weakening the selector.

Current required cardinality is 60 and includes
`windows.geometry-single-monitor-native-target-selection`. The preflight
count is a coverage invariant; failure of the count must occur before sanitizer
execution rather than silently running an incomplete subset.

## Windows RPC macro compatibility for shared HostControl

Keep `runtime.host-control-windows-rpc-interface-macro-compatibility` in the
ordinary registry. Its translation unit must define the Windows RPC
`interface` macro before including `runtime_host_control.h`, then exercise
the private-LAN endpoint recommendation. This catches shared-header identifier
collisions when R10 production composition causes Windows platform headers to
precede the HostControl surface; fixing such a failure must not add a second
listener, transport or platform scheduler.

## R10 production platform-owner linkage guard (2026-10-22)

`runtime.platform-native-production-single-owner-linkage` is an ordinary
offline source-policy regression. It must require the production
`rdp-server` target to link the shared Windows/macOS R10 platform-native
library, require the platform compile definition, and find exactly one
`RuntimePlatformNativeDesktop` process-lifetime owner in the runtime entry
point. Until an authenticated serialized serve path is qualified, the guard
must also reject startup-time `platformNativeDesktopLifetime.attach(...)`.

Hosted Windows/macOS compilation remains the behavioral build proof for the
real native dependency closure. This test is not a substitute for FIRST and
must never invoke live capture, input, TCC/WTS, credentials, or a listener.

## R2 Windows SSPI identity-provider regression boundary (2026-10-22)

The production `WindowsSspiAuthenticatedIdentityProof` may bind only from an
already-accepted SSPI security context via `QuerySecurityContextToken`. Tests
must not expose a production caller-supplied SID/token bind path. The Windows
provider regressions must prove invalid-context denial, bounded TokenUser SID
extraction, nonzero monotonic generation, exact SID matching, revoke, failed
replacement invalidation and no copy/move ownership. A private test friend may
transfer the current process token solely to exercise the token/SID lifecycle;
that synthetic path is never evidence of remote CredSSP authentication or a
native authorization grant. Positive Windows hosting still requires real
accepted-client identity + fresh WTS/LSA evidence + owner authority.

## R5 macOS input privacy readiness regressions (2026-10-21)

Keep `macos.native-input-permission-readiness-contract` in ordinary full
CTest on every platform. It source-pins the production native query to both
`AXIsProcessTrustedWithOptions(nullptr)` and
`CGPreflightListenEventAccess()`, requires their conjunction, and rejects
`CGRequestListenEventAccess` or an Accessibility prompt option.

On Apple, also run
`macos.native-desktop-owner-input-permission-retirement` against the real R2
authorization state machine with injected TCC/input callbacks. After one held
key, changing the injected input permission to NotTrusted must terminally
retire capture/session/display ownership without posting a synthetic release.
Neither test requests live TCC permission or posts Quartz events.

## R5 framebuffer row-size compile regression stays in ordinary CTest (2026-10-21)

`macos.native-desktop-owner-framebuffer-row-size-bounds` is a portable
source-contract regression for the R5 aggregate. It requires framebuffer width
to be normalized to `std::size_t` before the `size_t::max()/4` overflow
guard and tight BGRA row calculation, and rejects the direct
`frame.widthPixels > size_t::max()/4` spelling that fails macOS Clang under
`-Werror`. Keep this test in ordinary full CTest on every platform so the
macOS-only compile failure is caught before native packaging lanes diverge.

## R10 Windows/macOS one-owner composition regression (2026-10-21)

When `rdp-server-runtime-platform-native-desktop` is available, register one
platform-specific ordinary CTest against the real R10 composition class:
`runtime.platform-native-desktop-windows-r2-gated-composition` on Windows or
`runtime.platform-native-desktop-macos-r2-gated-composition` on macOS.

The test uses the real R2 native-authorization object but leaves it unbound. It
proves service/input/frame/cursor calls cannot create native ownership, attach
denies a zero authorization generation, the R10 owner is noncopyable/nonmovable,
off-owner-thread retirement is refused, and owner-thread retirement is
idempotent. It must not sample live WTS/LSA, open DXGI, call SendInput,
enumerate a macOS display, request TCC, start ScreenCaptureKit, post Quartz,
open a listener or fabricate R3 Share authority.

A later positive test must use genuine R2 authorization and the platform
owner's own acceptance contract; never turn this denial test into a synthetic
substitute for FIRST or native-host acceptance.

## R5 macOS aggregate CTests use real R2 authority and injected native seams (2026-10-21)

The dedicated Apple-only aggregate tests are
`macos.native-desktop-owner-fail-closed-construction`,
`macos.native-desktop-owner-frame-input-lifecycle`,
`macos.native-desktop-owner-input-permission-retirement`, and
`macos.native-desktop-owner-display-session-retirement`. They must construct
the real `MacNativeDesktopAuthorization` with the real owner-consent state
machine, but use synthetic authenticated identity/native-session evidence and
injected display/session/TCC/capture/input callbacks. Ordinary CTest must not
enumerate a logged-in display, request Screen Recording/Accessibility
permission, start ScreenCaptureKit or post Quartz input.

Fail-closed construction covers missing R2 binding, bounded framebuffer
rejection, absence of a UID/display-only constructor and View-only capture with
no input route. Lifecycle coverage advances the one-shot capture owner, copies
a padded CoreVideo BGRA frame into the tight bounded mailbox, borrows only the
exact sequence, verifies stale frame selection does not destroy a still-current
R2 grant, dispatches input under View+Input, then replaces R2 native-session
evidence and proves terminal retirement without a synthetic modifier release.

Display/session retirement coverage independently fires the injected topology
and GUI-session watchers and requires terminal aggregate retirement. These
tests are source/lifecycle evidence only; they are not owner macOS TCC,
ScreenCaptureKit, visible-desktop or Quartz-input acceptance.

## R9 manual CLEAN evidence classification and M1 owner-authority note (2026-10-21)

## R6/R9 manual clean-Windows receipt and native-owner denial gate (2026-10-21)

The exact `clean_windows_portable_gui.ps1` invocation is an official manual
fallback for CLEAN when the dedicated `r9-clean-windows-gui` runner is
unavailable. A PASS must emit JSON receipt format 2 plus a SHA-256 sidecar.
The receipt binds exact source/ZIP/verifier/smoke hashes and records Windows
build, user/session/effective administrator-token state, clean development
PATH/install roots, required-file verification, first-window ordinary
close/relaunch and equal before/after firewall/service/TermService/RDP-policy
snapshot hashes. R9 must verify the unchanged candidate and receipt sidecar
before counting manual evidence; source inspection or hosted/provisioned
Windows CI is not a CLEAN PASS.

The aggregate native-owner CTest
`windows.native-owner-r2-grant-and-lifetime-denials` is negative-only. It
uses the real `WindowsNativeDesktopAuthorization` object in an unbound state,
pins open/bounded-service/input signatures to an expected R2 authorization
generation, proves WTS candidate evidence cannot construct the owner, and
checks inert noncopyable/nonmovable retirement. It must not manufacture a
positive authenticated identity, owner grant, live WTS/DXGI desktop, cursor
read or SendInput. The established
`^windows\.(geometry|capture|cursor|input)-` selector remains exactly 59
cases; the new `windows.native-owner-` category is intentionally separate
until positive R10 composition exists.

Manual CLEAN must execute the same `clean_windows_portable_gui.ps1` path as the dedicated clean consumer and must pass `verify_clean_windows_receipt.py`; it is recorded as **MANUAL CLEAN PASS**, not automated CI. The verifier is ordinary offline CTest coverage and does not perform a live Windows acceptance run.

Current M1 source includes positive fresh-seat0/unlocked owner-grant behavior. Synthetic positive tests prove only source/state-machine construction; they do not replace physical FIRST.

## R7 PlainText source guards must test behavior, not parentless spelling (2026-10-21)

The `gui.runtime-label-plain-before-text-assignment` source regression protects
against transient Qt AutoText parsing of runtime-controlled status strings.
Its invariant is: construct an empty shared label, select
`Qt::PlainText`, then assign runtime text. Supplying a QObject parent while
constructing that empty label is safe and must not make the test depend on the
literal `new QLabel()` spelling.

The checker therefore scopes itself to the shared `label()` helper, rejects a
QLabel constructor containing the runtime `message`, and verifies the
relative order of empty parent-aware construction, PlainText selection and
runtime assignment. Keep the runtime/offscreen property tests as complementary
coverage; they cannot by themselves detect a transient pre-PlainText parse.

## R2 Track E native authorization synthetic construction/replay tests (2026-10-21)

The portable `test_native_desktop_authorization` suite exercises the R2
Windows/macOS grant core without native side effects. Positive construction
uses a fake authenticated identity and fake native evidence only in combination
with the real `CurrentOwnerSharingAuthority` state machine. This is synthetic
capability-state coverage, not proof of a real credential, WTS/LSA login,
SecuritySession, TCC state, desktop capture or input.

The Windows stale-denial case must cover wrong authenticated SID, unavailable
evidence, reused/replaced WTS session ID, either half of the authentication
LUID, logon time/type, authenticated-identity generation, stale R2
authorization generation, owner-consent replacement, explicit owner
revocation, evidence loss, and a session replacement during the visitor. The
macOS case must cover wrong authenticated UID, console-user/console-UID
replacement, audit UID/session replacement, SecuritySession ID/attribute
replacement, authenticated-identity generation, stale R2 authorization
generation, owner-consent replacement, explicit revocation, evidence loss and
replacement during the visitor. View-only grants must deny Input; Input-only
or Clipboard-bearing bind requests must be rejected.

These four CTests are ordinary cross-platform offline tests and deliberately
do not use the platform evidence reader implementations. Platform-native reader
CTest coverage remains separate and read-only. None of these tests changes the
Track C Microsoft-client gate or permits R5/R6/R10 to claim public native
hosting.

## R7 fake product authority must be restored explicitly after contradiction (2026-10-21)

Qt tests that set `deriveProductStatusFromLegacy=false` are deliberately
asserting that R10's explicit product snapshot overrides contradictory legacy
stage/listener/native fields. When such a test later returns to the generic
legacy-derived fake path, it must explicitly set
`deriveProductStatusFromLegacy=true` before changing legacy fields. Mutating
`snapshot.stage` alone while explicit product authority remains selected is
not a runtime transition and must not be used to make a toggle assertion pass.

`gui.offscreen-authoritative-sharing-toggle` pins both halves: a refused
Stop keeps authoritative product state `Stopping` and the switch On; a later
runtime-confirmed retirement is emulated only after restoring the fixture's
normal derivation mode, then the authoritative state becomes Stopped and the
switch turns Off. Do not weaken production product-state ownership to repair a
fixture.

## R7 non-metaobject toggle lookup regression (2026-10-21)

The imported `ToggleSwitchWidget` is a `QAbstractButton` presentation widget
with no signals, properties or slots of its own and therefore no `Q_OBJECT`
macro. Qt object-name discovery in hidden launcher checks and test fixtures
must use a meta-object-bearing Qt base type, currently `QAbstractButton*`,
rather than `findChild<ToggleSwitchWidget*>()`. Validate `isCheckable()`,
`isEnabled()` and `isChecked()` through that base API. Direct production
ownership pointers may remain concretely typed because they do not invoke Qt
meta-object lookup.

`gui.toggle-object-name-base-lookup-source-contract` is the ordinary
platform-independent regression. It pins the no-`Q_OBJECT` imported widget,
rejects concrete typed `findChild` use in the Windows packaged launcher and
the shared offscreen fixture, requires object-name lookup through
`QAbstractButton`, and requires a checkability assertion. Do not introduce
AUTOMOC merely to satisfy a test/hidden-check lookup. If the widget later gains
a genuine signal/property requirement, revise this contract deliberately with
that product change rather than silently weakening the guard.

## R10 Qt fake product-capability projection (2026-10-21)

The shared `FakeRuntimeHost` used by ordinary offscreen dashboard tests must
derive every product fact needed to emulate its legacy available HostControl,
including `credentialCapabilities.existingOsAccount`. Otherwise capability-
gated controls become disabled before tests can exercise the existing typed
credential request seam, producing a fixture failure rather than a product
denial.

Contradictory product-authority cases must opt out with
`deriveProductStatusFromLegacy = false` and set their product snapshot
explicitly. Never weaken production capability gates to satisfy a fake runtime.

## R10 authoritative product-status regressions (2026-10-21)

`runtime.host-control-product-status-projection` pins the portable eight-state
product vocabulary, Start/Stop toggle semantics, deterministic R10 private-LAN
recommendation and deny-only Error projection. It also pins the standalone
product capability gate false until live Microsoft-client interoperability.

`runtime.linux-host-control-product-status-projection` exercises the concrete
Linux owner without opening a listener: product state remains Stopped while
owner consent is absent, the eligible-interface snapshot and recommendation
agree, clients/bound endpoint are empty, and unprovisioned credential
capabilities fail closed.

`gui.offscreen-r10-product-status-authority` deliberately supplies
contradictory legacy lifecycle flags. Product Stopped must keep the switch Off
and select R10's recommended endpoint even when old fields claim
ClientConnected; product Connected/Stopping/Error must then drive the dashboard
when old fields claim Stopped. This prevents R7 from rebuilding a second
lifecycle state machine.

## R8 tray lifecycle source binding (2026-10-21)

Once R7's one-page/tray implementation exists, the ordinary dormant R8
composition guard must inspect that production GUI source in addition to the
runtime owners. It must require active-window close to hide/ignore without
calling Stop/Revoke, require tray Quit to call Stop/Revoke before application
exit, and require product permission requests to keep clipboard disabled while
the activation gate is false. The offscreen tray fixture must project clipboard
Enabled across hide and refused retirement and Retired only after successful
explicit Quit. None of these offline assertions satisfy FIRST or authorize live
clipboard activation.

## R7 tabbed dashboard, authoritative toggle and tray regressions (2026-10-22)

- `gui.offscreen-round2-tabs-and-main-simplicity` pins exactly one
  Main/Advanced tab flow, no wizard/disclosure/password fields, and the
  Main/Advanced ownership split.
- `gui.offscreen-round2-advanced-groups-scrollable` pins Network, Security,
  Desktop and Diagnostics grouping plus scroll reachability at about 560x520.
- `gui.offscreen-round2-endpoint-refresh-fail-closed` pins manual override
  non-authority, explicit R10 ambiguity text and unavailable fallback denial.
- Existing authoritative toggle and tray lifecycle tests remain required.

These are presentation/lifecycle tests only; they do not prove Microsoft-client
password interoperability, native hosting, clipboard activation or Linux FIRST.

## R2 standalone-password Microsoft-client acceptance run sheet (2026-10-21)

The next positive R2 milestone is a real unmodified Windows App or Windows 11
`mstsc.exe` connection through the production R10 accepted-socket path.
Ordinary CI remains offline and cannot claim this result.

Before the client connects, record the exact source SHA and client build. Use a
controlled test username and enter a new session password only into mutable
owner-local memory; never place it in source, config, command-line arguments,
environment variables, CMake cache or logs. Feed that buffer once to
`configureStandaloneApplicationPassword(...)`, verify the returned
observation is configured with a nonzero exact generation, and verify the input
buffer has been scrubbed. Do not expose a Qt password field for this run.

Obtain fresh owner authorization through the normal R10
`requestHostPermissionSetup()` path, then Start on the selected private-LAN
interface. On accept, require the same standalone credential generation, a
fresh per-connection challenge/current FILETIME, HYBRID selection, the exact R1
TLS object and selected-certificate fingerprint, and owner-derived TSRequest
frames. After authInfo, require
`StandalonePasswordAuthenticatedPrincipalProof` to bind the exact connection
and generation, then use the normal principal-free
`ConsoleEvidenceAuthenticationKind::StandalonePassword` request and ordinary
NSS/logind physical seat/session lease. Kerberos principal must be empty.

No-fallback evidence is mandatory: the acceptance snapshot must report
StandalonePassword selected, `gssStage()` must remain
`SpnegoStage::Unconfigured`, and any terminal standalone failure must emit at
most the fixed fail-only line
`stage=<bucket>; os-gss-fallback=disabled`. Never infer no-fallback merely
from a successful client prompt.

Classify the first failure as exactly one of these R2 buckets:
`ntlm-negotiation` (NTLMSSP framing/proof), `mic` (NTLM transcript or
mechListMIC), `sign-seal` (NTLM protected-message integrity/confidentiality),
`spnego` (SPNEGO DER/mechanism exchange), `pubkeyauth` (CredSSP TLS channel
binding), `authinfo` (final delegated TSPasswordCreds equivalence), or
`admission` (authenticated proof/native broker handoff). R1 TLS/preauth
diagnostics remain separate transport evidence.

PASS requires CredentialsVerified, standalone proof binding, a fresh owner
grant, a genuine physical-session admission lease, then the normal downstream
MCS/licensing/Share path with a clean disconnect/Stop. Wrong password, stale
credential generation, TLS provenance mismatch, owner-grant loss or native
session replacement must fail closed without GSS retry. Record only bounded
stages, generations, TLS fingerprint and client/source versions; never retain
credentials or authentication wire data.

This live run is **NOT RUN** until the owner explicitly authorizes the exact
physical test. The diagnostic changes themselves are covered by existing
offline SPNEGO/CredSSP/standalone-selector CTests.

## R8 hide/nonterminal and terminal clipboard lifetime regressions (2026-10-21)

`gui.offscreen-hide-preserves-active-sharing` is a presentation-only Qt
regression. With an authoritative active R10 snapshot and clipboard state, it
hides the window and requires zero Stop/Revoke calls while sharing and
clipboard status remain active; a later explicit Stop/Revoke must retire the
projected clipboard state. The test performs no listener, native clipboard or
desktop action.

`runtime.linux-host-control-dormant-unicode-clipboard-composition` additionally
pins the terminal/reconnect source contract: each replacement native desktop
constructs a fresh prepared R8 owner; Stop/Revoke order owner authority -> R8/R5
-> accepted connection -> listener; HostControl destruction/quit enters the
same retirement helper; X11 disconnect clears ownership/paste/INCR state; and
R8/R3 bridge retirement clears route plus queued outbound/TLS-receipt identity.
The existing stale-positive-receipt and stale-INCR executable tests remain the
behavioral component evidence.

These regressions do not satisfy the live activation gate. Production
activation remains literal false and the only prepared presentation scope is
Unicode text. FIRST visible desktop + mouse + keyboard + Stop must pass first;
plain-text clipboard activation is a later, separate milestone.

## Source-composition checks distinguish declarations from qualified uses (2026-10-21)

When a source-composition CTest validates an enum declaration, assert the
declaration spelling in the declaring file: the enum type and the unqualified
enumerator token. Do not require a qualified use such as `Type::Value` inside
the declaration itself. If the architectural contract also requires that
enumerator to drive production behavior, assert the qualified spelling
separately in the implementation/use-site scope. This keeps structural tests
fail-closed without manufacturing false failures from valid C++ syntax.

## R10 HostControl standalone selector regression (2026-10-20)

`runtime.linux-host-control-standalone-authentication-selector` is the dedicated
offline composition gate for the product selector. It must prove the R10
HostControl owns an explicit standalone mode, pins and synchronously visits the
exact credential generation, constructs a fresh random NTLM challenge/current
FILETIME, hands the explicit selection to the five-argument
`LinuxRuntimeConnection` constructor, and selects principal-free standalone
R2 admission. The accepted-client source slice must not contain the old default
four-argument constructor.

This source-composition gate complements, rather than replaces,
`runtime.linux-connection-standalone-authentication-selector-denials`, which
already exercises the lower-level production constructor and stale-generation /
invalid-challenge denials. Public Qt password QObject inputs must remain absent.

Neither test is Microsoft-client interoperability evidence. Enabling
`IndependentApplicationPassword` still requires an explicitly authorized
unmodified Windows App or `mstsc.exe` run through the real accepted socket,
TLS/CredSSP, R2 native admission and clean disconnect/Stop lifetime.

## R7 offscreen assertions track authoritative lifecycle wording (2026-10-20)

Qt behavior tests must distinguish presentation wording from authority. For a
current ListenerAvailable status with authoritative listener readiness, the
lifecycle label is "Listening; waiting for desktop connection"; historical
"Listener ready" wording is not part of the current R7 contract.

A stale `RuntimeHostClient::desktopVisible` bit must not be rendered as a
visible/connected desktop while `HostStatus::nativeDesktopReady` is false.
When the peer is Share-activated but the native owner is not ready, keep it in
the pending list. The dedicated
`gui.offscreen-r10-graphics-native-desktop-projection` test remains the
authoritative regression for Share -> Graphics -> native initialization ->
native-ready visibility.

## HostControl accepted-client source guard covers accept and phase ownership (2026-10-20)

`runtime.linux-host-control-bounded-accepted-client-scheduler` must isolate
the semantic scheduler from the start of `acceptClientOnce(...)` through
accepted-client phase progression, ending before `serviceOnce()`. The
contract begins with socket accept, private-LAN policy, attempt limiting and
sole connection construction; a slice beginning only at
`advanceAcceptedClientOnce()` cannot prove those ownership gates.

Do not use whole-file token order for this test because the bounded post-Share
native scheduler legitimately calls Graphics methods elsewhere in the same
translation unit.

## Source-contract tests follow ownership boundaries, not global token order (2026-10-20)

When one source file contains both pre-Share and post-Share schedulers, order
checks must isolate the owning function before comparing tokens. A later
post-Share call appearing textually earlier in the file is not a pre-Share
ordering regression.

Mechanism-neutral R2 tests must name
`LinuxAuthenticatedPrincipalProof`/the selected `principalProof` rather than
hard-code GSS-specific `acceptor` spellings. Likewise, dormant R8 route checks
must pin the actual scoped owner expression. An unconfigured service that
denies before selecting/configuring an authentication mechanism must not invent
a terminal mechanism state merely to satisfy a historical assertion.

## R8 HostControl dormant clipboard composition regression (2026-10-20)

`runtime.linux-host-control-dormant-unicode-clipboard-composition` is an
ordinary offline source/build-graph CTest. It must require the literal false
activation gate, shared owner reuse, Unicode-text-only presentation, exact
native-generation binding, the shared X11 event sink, R2/R3 clipboard gateway,
sole R1 TLS writer handoff, clipboard-write scheduler precedence and
R8 -> R5 -> accepted-connection teardown.

The guard must reject a duplicate CLI owner, `xcb_connect`, direct
`SSL_write`, worker-thread ownership and production PNG/FileContents/file
publication calls. It does not authorize a listener, desktop, clipboard or
Microsoft client and cannot satisfy the live activation gate.

## Runtime-security sanitizer inventory changes are atomic CI structure (2026-10-20)

The direct Linux runtime-security sanitizer selector contains **41**
executable-backed cases. The 41st is
`runtime.linux-connection-standalone-authentication-selector-denials`.
Whenever this inventory changes, update the selector regex, exact-name sentinel,
numeric count and `scripts/validate_ci_workflow.py` required tokens together.

Malformed or duplicated workflow YAML is CI-authoring failure, not protocol or
sanitizer evidence. The independent structure workflow must reject it before
heavyweight jobs.

## R2 standalone selector sanitizer inventory (2026-10-20)

The bounded Linux runtime-security sanitizer selection contains 41
executable-backed cases and must explicitly include
`runtime.linux-connection-standalone-authentication-selector-denials`.
The X11 authorized-input tests continue compiling a concrete GSS proof through
the common `LinuxAuthenticatedPrincipalProof&` route, which pins backward
compatibility while preventing the native bridge from becoming GSS-specific.

## R2/R10 standalone connection-selector regression (2026-10-20)

`runtime.linux-connection-standalone-authentication-selector-denials` must use
the production `LinuxRuntimeConnection` and a real accepted loopback socket,
but perform no TLS/client authentication. With a configured service policy,
current standalone credential generation and valid bounded NTLM challenge, the
connection may become pre-auth scheduler-ready while the GSS acceptor remains
unconfigured and no lease exists. Replacing the credential generation or using
an all-zero challenge must fail construction closed. This is selector/lifetime
evidence only, not CredSSP or Microsoft-client acceptance.

The existing
`runtime.linux-security-admission-request-owned-generation-fence` also pins
that R10 can obtain a standalone request with an empty Kerberos principal while
retaining the exact configured account/seat/display/permission scope and policy
generation fence.

## R2 standalone proof direct-TLS non-promotion regression (2026-10-20)

`security.standalone-credssp-direct-tls-cannot-bind-admission-proof` must
complete the existing direct memory-BIO CredSSP/authInfo path to
`CredentialsVerified`, configure a real generation-fenced standalone
credential owner, and still prove the R2 standalone proof cannot bind without
an exact R1-owned connection transcript. Failure must retire the connection-
scoped CredSSP state. This is a negative production-provenance test and cannot
claim Microsoft-client interoperability or native admission.

## R7 authoritative owner-permission product projection regression (2026-10-20)

`gui.offscreen-r2-owner-grant-observation` must prove that Qt renders effective
View/Input scope and remaining lifetime only from R10's
`RuntimeSharingPermissionStatus`. Qt must not decode
`RuntimeOwnerGrantState`, R2 permission bits or native-session evidence.
Deliberately make request controls disagree with the product observation and
require the observation to win. Expired, locked, desktop-changed and revoked
states expose no effective scope/lifetime.

The existing `gui.offscreen-r10-graphics-native-desktop-projection` remains
the R7 presentation gate for the now-landed R10X facts: Graphics readiness
alone is not Desktop Visible; `nativeDesktopReady` is mandatory. These are
offline presentation tests and cannot substitute for the owner-approved real
desktop/client acceptance run.

## R2 authenticated-principal proof compatibility regression (2026-10-20)

`security.authenticated-principal-proof-gss-compatibility` must prove the
existing GSS owner implements the shared R2 proof contract and that an
unconfigured GSS proof plus inactive R1 connection still fails terminally
through the generalized broker, including concrete GSS owner rejection.
Existing GSS/R3 tests remain the semantic regression matrix after the broker
signatures move to the proof base type. Do not introduce a test-only positive
proof capable of minting a native lease.

## CI structure and clipboard sanitizer inventory change together (2026-10-20)

When the fixed R8 clipboard sanitizer registry changes, update all three
artifacts atomically: the workflow's explicit test-name sentinel, its exact
count, and `scripts/validate_ci_workflow.py`'s matching required tokens. A
workflow-only count update must fail the independent structure guard.

Current authoritative inventory: 88 cases, including
`clipboard.x11-unicode-text-only-presentation`.

## R9/R8 sanitizer clipboard inventory is 88 cases (2026-10-20)

The bounded Linux ASan/UBSan `-L clipboard` registry contains **88** ordinary
CTest registrations. The inventory includes
`clipboard.x11-unicode-text-only-presentation`, the R8 regression that pins
the prepared Unicode-text-only presentation scope while production clipboard
activation remains false.

R9 must require that case by exact name before checking the fixed total. A
registry mismatch is CI-structure evidence, not a sanitizer failure in any
clipboard implementation; actual sanitizer PASS/FAIL begins only when the 88
registered tests execute.

## R10X HostControl native-owner composition gate (2026-10-20)

Ordinary CI must not fabricate a positive physical seat/logind lease merely to
reach the GUI native owner. Source-composition coverage must instead pin the
production build edge and HostControl ordering: one R2-selected X11 owner,
zero-timeout native/logind/socket poll, exact unregister-before-callback
lifetime, bounded X11 batch, existing R1/R3 reader/writer, R1 ownership of
`POLLERR/POLLHUP` classification, authenticated input route, RandR generation
checks around remap/frame borrow, no clipboard activation, reconnect replacement,
and authority -> native -> connection -> listener Stop order.

Keep the existing R1 real-loopback transport classification and R5 native/Xvfb
tests as executable lower-level evidence for peer-close ownership, no-XTEST
retirement and RandR capture-generation invalidation. A passing source guard is
not FIRST REAL DESKTOP acceptance; that still requires an exact-green SHA and a
real client/owner-authorized desktop.

## R2 standalone native-account candidate regression (2026-10-20)

`security.console-evidence-standalone-native-account-candidate` must exercise
the production policy/evidence inspector with deterministic synthetic native
observations. It proves an empty-principal standalone candidate can match the
exact configured account/seat/display/UID/permission rule, the same rule still
requires the exact Kerberos principal on the GSS path, and any standalone
request carrying a principal is denied before native evidence reads. Wrong
account/seat or permission scope must remain denied. This test cannot mint an
R2 lease or claim standalone CredSSP authentication.

## R2 owner-grant observation regression (2026-10-20)

`security.owner-consent-read-only-grant-observation` must prove the owner-grant
projection is unavailable without a grant, reports the exact effective
permission mask and remaining monotonic lifetime while active, reports expired
with zero permissions at the deadline, and becomes unavailable after explicit
revocation. Reading the expired observation must not itself change the
revocation generation. This is presentation-state coverage only and cannot be
treated as native admission evidence.

## R1 terminal transport-classification regression (2026-10-20)

`runtime.linux-connection-r1-terminal-transport-classification` uses the
production `LinuxRuntimeConnection`, real nonblocking loopback TCP and the
production TLS context. It must distinguish: peer `close_notify` as
`OrderlyTlsClose`; TCP half-close without TLS shutdown and abortive peer RST
as `TransportError`; malformed post-X.224 TLS bytes as `TlsFailure`; and
explicit local revoke as `Cancelled`.

The RST case must traverse `pollSocketReadinessOnce()`; a native
`POLLERR` must be surfaced to R1 rather than preemptively revoked by the
scheduler. The descriptor-reuse case retires the connection, deliberately
reuses the old numeric fd for an unrelated socket, then proves late poll and
advance calls remain closed without touching that replacement descriptor.

This is offline transport evidence only. It does not synthesize current-owner
consent, publish a HostControl LAN listener, create an R2 lease, reach Share or
construct a native desktop. Positive HostControl Stop/Revoke races under a real
listener remain a separate owner-authorized runtime test.

## R9 CMake source-guard token rules (2026-10-20)

When a CMake source-contract test checks call order, anchor method/assignment
semantics rather than argument punctuation or a bare enum value that may also
appear in status projection. Do not place a trailing C++ semicolon inside a
CMake list token unless it is escaped; otherwise list parsing can create empty
elements and false ordering failures. Isolate the owning function/helper first,
then compare semicolon-free semantic anchors.

## R9 Qt keyword-macro header regression (2026-10-20)

Security/runtime headers that can become transitively visible from Qt code must
not use Qt keyword-macro tokens such as `slots` as identifiers. Keep the
ordinary `test_authentication_attempt_limiter` translation unit compiling the
production limiter header while an empty `slots` macro is defined, after the
header's standard-library dependencies are already included. This is a
compile-time regression only; it must not add Qt linkage or change limiter
runtime semantics.

## R9 source-contract guards after concurrent R10/R5/R3/R7 changes (2026-10-20)

Source-contract CTests must isolate the production function or helper that owns
the invariant. Do not let a first global `string(FIND)` bind to a legitimate
status-path authorization call, and do not pin initializer punctuation when the
invariant is unique typed ownership. Harmless line wrapping must not change a
guard result.

For current R9 coverage, preserve: exactly one HostControl
`CurrentOwnerSharingAuthority`; the scoped Start transaction from credentials
through listener publication; configured GSS -> verified-account limiter ->
authority-aware R2 broker; and cooperative Stop reaching the real terminal
helper with native no-XTEST retirement before aggregate connection revoke. The
CLI listener must remain an outer RAII owner around every serialized candidate.

R10X has not yet moved the native owner into HostControl, so no R9 source guard
may fake a single integrated owner-authority -> native -> connection -> listener
path. Until R10X lands, the existing bounded GUI scheduler guard independently
pins owner-authority -> accepted-connection -> listener, while the cooperative
CLI guard pins native -> connection -> listener. When R10X composes the owner,
its dedicated structural test must join those halves and preserve the full
owner-authority -> R8/native -> R3/R2/R1 -> listener order.

## R7 Graphics/native lifecycle projection gate (2026-10-20)

`gui.offscreen-r10-graphics-native-desktop-projection` must drive only the
typed R10 status seam. Prove ShareActivated without Graphics readiness,
Graphics-ready with no native owner, native initialization, a deliberately
inconsistent DesktopVisible stage while `nativeDesktopReady == false`, the
positive native-ready visible case, listener-preserving disconnect, and
revocation. A stale `RuntimeHostClient::desktopVisible` bit must never make
the connected-client list positive without `nativeDesktopReady`.

Keep the independent-password test non-collecting: no password/confirmation
QObject may exist while product capability is unavailable. Owner-permission
tests may assert request forwarding, but must also prove the GUI does not echo
the requested lifetime/scope as an effective R2 grant before a real read-only
grant observation exists.

## R3 first-client Windows App / mstsc trace-analysis checklist (2026-10-20)

Use this checklist only after R10 has attached the genuine R2-selected X11
desktop and the exact server SHA is otherwise eligible for the first real
desktop test. Run Windows App on macOS and Windows 11 `mstsc.exe` as separate
acceptance cells; success or failure in one client never substitutes for the
other.

- Record the exact server SHA, timestamp, server OS/session, client OS build,
  client application/build, and one non-secret trace identifier. Never retain
  passwords, NTLM/GSS responses, session keys or delegated credentials in the
  diagnostic record.
- Correlate one R3 `reconnectGeneration` and require ordered milestones:
  MCS established -> Share activated -> DRDYNVC activated -> Graphics control
  ready -> surface created -> surface mapped -> first frame publication accepted
  -> first genuine FRAME_ACK. Record `droppedEventCount`; any overflow makes
  the retained event prefix incomplete for diagnosis.
- If MCS or Share is absent, stop R3 Graphics triage and report the earlier
  R1/R2/R10 boundary. If Share exists but DRDYNVC does not, inspect the joined
  `drdynvc` route and CREATE exchange; do not change RDPGFX codec behavior.
- If DRDYNVC is active but Graphics control is not ready, inspect the client
  RDPGFX CAPS intake and the exact accepted CAPS_CONFIRM write boundary. This is
  the first R3 control-handshake diagnosis point.
- If Graphics control is ready but surface CREATE/MAP is missing, inspect the
  existing R3 writer receipts and R4 presentation lifecycle. Do not create a
  second surface state machine or infer success from queued bytes.
- If the surface is mapped but no first frame is accepted, first distinguish
  missing R10/R5 native capture/borrow from R3 serialization. A missing native
  frame is not evidence for a wire change.
- If the first frame is fully accepted but no genuine FRAME_ACK appears,
  correlate the exact TLS frame commitment with the client trace and R4's
  existing ACK window. Ordinary frame-credit deferral is not a protocol
  failure. If FRAME_ACK exists but the desktop is not visible, continue with
  rendering/native-lifetime diagnosis rather than changing R3 wire behavior.
- Record the first terminal disconnect/termination boundary and preserve the
  bounded event snapshot for postmortem comparison. Make a protocol change only
  for a reproducible post-Share failure demonstrated by the real-client trace.

The existing
`transport.dvc-graphics-first-client-acceptance-observability` regression must
keep DRDYNVC activation and Graphics-control readiness distinct: the latter is
false after client CAPS intake and becomes true only after the complete
CAPS_CONFIRM receipt. The R9 R3 Graphics-DVC sanitizer inventory remains 22
tests because this extends the existing behavior case rather than adding a
second observability test owner.

## R10 bounded accepted-client scheduler guard (2026-10-20)

`runtime.linux-host-control-bounded-accepted-client-scheduler` is an offline
source-composition guard because ordinary CI must not mint a positive physical
seat0 owner lease. It must require private-LAN peer validation and the shared
authentication-attempt limiter before `LinuxRuntimeConnection` construction,
the exact current-owner authority handoff, zero-wait readiness, progression
through the existing admission/MCS/licensing/Share/Graphics methods, and ordered
owner-authority -> accepted-connection -> listener retirement.

The same guard requires Qt timers to drive R10 and status projection separately,
and rejects the CLI blocking candidate loop or a new `std::thread` in the GUI
path. A passing guard is architecture evidence only; real Windows App acceptance
and R2-selected X11 frame publication remain separate positive evidence.

## R2 standalone password service-owner lifecycle tests (2026-10-20)

Ordinary offline coverage must test the memory-only owner separately from wire
interoperability. Pin that a successful and failed configure both scrub the
mutable caller password, replacement changes generation, stale generations
cannot visit the credential, and explicit revoke makes the current generation
unavailable. The visitor is synchronous only and must not retain the credential
reference.

Linux R10 coverage must additionally prove that configuring the standalone
credential remains independent of native admission, a product credential-mode
request revokes it, ordinary Stop preserves the exact configured generation
while revoking owner authorization, explicit Revoke retires it, and an
attempted configure after terminal revoke still scrubs its input. Cross-platform
HostControl coverage must keep ordinary Stop and terminal revoke distinct.
These tests must not claim Microsoft-client compatibility.

## R10 owned admission snapshot and private-LAN policy tests (2026-10-20)

`runtime.linux-security-admission-request-owned-generation-fence` must prove
that the production admission snapshot survives mutation of the configuration
source bytes, returns the exact bounded selector while the security policy
generation is current, and becomes unavailable after access policy replacement.
Oversized identity text must fail closed.

`runtime.personal-desktop-private-lan-candidate-denials` must exercise the
production deployment policy without opening a socket: permit RFC1918 IPv4 plus
ULA/link-local IPv6 only in explicitly configured private-LAN mode, reject
loopback/public/empty candidates, reject port zero and preserve one-shot policy
immutability. Neither test is R2 positive admission or live LAN evidence.

## R2 standalone CredSSP final-authInfo tests (2026-10-20)

The standalone CredSSP in-memory TLS fixture must continue through the server
public-key-binding reply before sending authInfo. Protect a canonical
TSCredentials/TSPasswordCreds message with the already-advanced client NTLM
sequence and require the server to reach only a non-authorizing
CredentialsVerified state for the configured username/password with empty
domain.

Dedicated denial coverage must use fresh complete exchanges and reject at
least: a different username with the correct password, the correct username
with a different password, a nonempty delegated domain, and tampering of the
protected authInfo ciphertext/signature. Each denial is terminal for the
CredSSP owner. These tests remain offline mechanism evidence; no listener,
native session, CurrentOwnerSharingAuthority lease, GUI password field or real
Microsoft client may be inferred from them.

## R2 standalone CredSSP TLS public-key-binding tests (2026-10-20)

The standalone CredSSP binding increment is exercised with an in-memory OpenSSL
TLS client/server BIO pair, not a TCP listener. The server side must use the
production `TsRequestFrameReader`, active selected-certificate binding helpers,
and `TsRequestTlsReplyWriter`; the client side independently protects and
checks the binding using the published NTLMv2-derived keys.

Ordinary CTest must cover: token-only Type 1 negotiation followed by a combined
Type 3 + `pubKeyAuth` + 32-byte nonce frame and exact server binding
verification; mutation of the protected client binding causing terminal
reader/writer/mechanism retirement; and denial of an otherwise valid TSRequest
fed through manual `consume()` without TLS provenance. These are mechanism and
TLS-transcript tests only. They do not consume `authInfo`, open a listener,
authenticate a local OS account, create R2 owner consent, or prove Microsoft
client interoperability.

## R2 SPNEGO fallback mechListMIC state test (2026-10-20)

The standalone SPNEGO suite must include a deterministic fallback exchange where
a mechanism precedes NTLM in MechTypeList, the initial token carries
Microsoft-style NegHints, the server requests MIC, NTLM Type 1/2/3 completes,
and exact client/server mechListMIC signatures are checked against independently
fixed vectors. The same test must prove that the next client/server protected
message uses sequence one and the already-advanced KEY_EXCH RC4 stream.

Keep missing/tampered MIC denials terminal. This remains an offline mechanism
test: no TSRequest, TLS socket, GUI password, native admission or Microsoft
client is involved, so it cannot be reported as CredSSP/NLA interoperability.

## R2 standalone SPNEGO/NTLM state tests (2026-10-20)

Standalone SPNEGO tests remain ordinary offline CTests. At minimum cover an
NTLM-first InitialContextToken through exact server challenge wrapping, a
published NTLMv2 Type 3 response through accept-completed state, and a
multi-mechanism fallback that can select NTLM but is denied final completion
without mechListMIC. Mutation coverage must reject duplicate mechanism OIDs,
noncanonical/malformed DER and username mismatch without opening TLS, reading
native session state or granting R2 admission.

Do not label these tests Microsoft-client interoperability: TSRequest/TLS
provenance, CredSSP pubKeyAuth/authInfo, GUI secret lifetime and a real
Windows App/mstsc exchange remain separate acceptance gates.

## R2 standalone NTLM MIC and message-security tests (2026-10-20)

Every standalone NTLM message-security increment must run under ordinary full
CTest without network, GUI or native login dependencies. Pin three independent
behaviors: exact transcript MIC success plus mutation denial; deterministic
client unwrap/server wrap bytes for sequence zero using the Microsoft-derived
known-answer keys; and terminal context retirement with plaintext cleansing on
a consumed-stream signature mismatch. Do not label these tests CredSSP/NLA or
Microsoft-client interoperability until SPNEGO, TSRequest integration and a
real client exchange exist.

## R2 standalone NTLMSSP framing tests (2026-10-20)

Keep Type 1/2/3 framing in the noninstalled standalone credential target and
run it in ordinary full CTest. `security.ntlmssp-negotiate-challenge-framing`
parses a published Microsoft Type 1 vector, rejects its non-CredSSP flag profile
for a protected Type 2 reply, then checks the exact bounded challenge encoding
for the required SIGN/SEAL/ESS/128 profile, TargetInfo and timestamp.
`security.ntlmssp-microsoft-authenticate-bridge` parses Microsoft's published
NTLMv2 Type 3 vector and feeds its borrowed fields into the existing independent
User/Domain/Password proof/session-key KAT.
`security.ntlmssp-security-buffer-mic-denials` mutates
signature/type/offset/Unicode state and verifies that MsvAvFlags MIC presence
reserves the 16-byte MIC header rather than allowing payload aliasing.

These are framing/cryptographic bridge tests only. They MUST NOT be called
SPNEGO, CredSSP pubKeyAuth/authInfo, NLA, R2 admission or Microsoft-client
interoperability acceptance until the later stateful mechanism owner and real
client evidence exist.

## R1 first-client runtime diagnostics / Stop preparation (2026-10-20)

`runtime.linux-connection-r1-acceptance-diagnostics` uses the production
`LinuxRuntimeConnection`, a real nonblocking loopback connection and the
production TLS context to verify the pre-TLS -> handshaking -> established
diagnostic transition, exact HYBRID selection, negotiated TLS version, selected
certificate SHA-256 continuity across configured-certificate rotation, and
Stop/revoke during both established and in-progress TLS without creating an R2
lease or Share. Host-control denial coverage also requires configured selected
endpoint observation while bound endpoint/listener generation remain absent.

This is offline preparation only. Positive R2-authorized R10 LAN Start,
accepted-socket lifetime under that owner, live WANT_READ/WANT_WRITE, partial
TLS writes, close_notify/half-close/RST, Stop race, interface disappearance,
descriptor reuse and Microsoft-client acceptance remain NOT RUN until the
positive Start path exists.

## R2 standalone NTLMv2 password-core tests (2026-10-19)

The standalone password track must keep Microsoft-published known answers
hard-coded independently of implementation output. Its positive fixture checks
ResponseKeyNT, NTProofStr acceptance, SessionBaseKey, encrypted random-session
KEY_EXCH handling and client/server sign/seal keys. Denial fixtures mutate the
proof, canonical response blob, required session-security flags and key length.
The revocation fixture checks caller plaintext erasure plus private credential
and security-context zeroization. None of these tests may be described as
Windows-client interoperability or R2 admission.

## R3 first-client acceptance observability CTest (2026-10-19)

`transport.dvc-graphics-first-client-acceptance-observability` must exercise
the existing R3 session/Graphics owner and accepted-byte receipts. It verifies
that "MCS established" means all configured joins completed, then drives the
production Graphics CREATE/CAPS/surface path, mandatory ClearCodec publication,
a genuine R4-acknowledged FRAME_ACK, and DELETE/CREATE/MAP resize remap. Expected
events are ordered and carry only local sequence numbers; reconnect correlation
must differ across R3 session objects; duplicate one-shot milestones must not
duplicate events; and more than 32 repeatable resize results must retain the
newest 32 with exact overflow accounting.

The first-frame and first-ACK assertions must come from the existing R4
acceptance status, not a test-only ACK/frame counter. The offline fixture may
stage already-completed R2/MCS/Share prerequisites only to reach the production
R3 Graphics hooks; it must not fabricate a live R2 lease, socket/TLS peer,
physical desktop owner or Microsoft client. Keep this case in R9's exact R3
Graphics DVC sanitizer inventory, which is 22 cases after this addition.
ClearCodec remains mandatory for this acceptance path and the test must not
authorize AVC420 after remap.

## R8 prepared text-only activation regression (2026-10-19)

Register `clipboard.x11-unicode-text-only-presentation` against the real
`X11ClipboardAdapter` with deterministic native operations. Feed one remote
offer containing Unicode text plus PNG/DIB, construct the adapter with
`PresentationScope::UnicodeTextOnly`, and require TARGETS to expose only
TARGETS + UTF8_STRING. A PNG SelectionRequest must fail with no property write,
while a UTF8_STRING request must produce exactly one pending
`CF_UNICODETEXT` remote fetch.

Keep `runtime.linux-x11-clipboard-production-linkage` as a production-source
guard. It must require the dormant `LinuxPreparedClipboardOwner`, exact R2/R3
clipboard dispatch and queue calls, the sole R1 clipboard TLS writer/receipt,
the shared X11 event route, and the literal
`kLinuxProductionClipboardActivationApproved = false`. It must reject
production references to completed-file publication, FileContents request
entry points or PNG paste routing.

These are offline preparation tests only. They do not satisfy live clipboard
acceptance and must never flip the production gate. First live R8 activation
remains BLOCKED until the same physical Windows App session has already passed
video, input and Stop acceptance; that later authorized run begins with plain
text only and must separately demonstrate Stop/revoke/reconnect stale-state
retirement.

## R10 production R2 host-authority lifetime handoff (2026-10-19)

`runtime.linux-host-control-r2-authority-lifetime-handoff` is an offline
source regression over the production Linux HostControl and connection
aggregate. It requires one R2 `CurrentOwnerSharingAuthority` owned by R10,
bounded consent intent routed through that owner, R2 revocation before R1
listener close, and forwarding of the same host authority into
`LinuxConsoleAdmissionBroker` for future accepted connections. It must not
construct a positive owner lease, bind a listener, authenticate a user or
substitute a GUI/test Boolean for R2. Positive HostControl tests remain blocked
until the reviewed native R2 provider can issue its real opaque lease.

## R4 first-client visible-frame/FRAME_ACK trace checklist (2026-10-19)

Use one frame ID from the existing R3/R4 publication path and preserve its
existing receipt identities. Do not add a trace-only frame counter or ACK set.

| Question | Required evidence | Diagnosis when missing |
| --- | --- | --- |
| Were pixels captured? | R5/R10 native capture/borrow succeeded for the current geometry/generation. | If absent, pixels were never captured; R4 status alone cannot manufacture this fact. |
| Was a frame serialized? | `firstClearCodecFramePrepared` becomes true and the existing frame receipt has a nonzero exact byte count. | Capture exists but this remains false: the frame never serialized; inspect mapped geometry/generation and terminal `Rejected` preflight. |
| Did the TLS write commit exactly? | `firstExactFrameWriteCommitted` becomes true only after R3 maps complete outer accepted-byte receipts back to `GfxPresentationLifecycle::completeFrameDelivery`. | Prepared=true and committed=false: the frame never reached exact write commitment; inspect R1 WANT/partial/zero-byte cancellation or terminal abort. |
| Did the client ACK the frame? | `firstGenuineFrameAcknowledge` becomes true only for an exact outstanding-ID `Acknowledged` result; outstanding count comes from the same R4 ACK window. | Committed=true, outstanding>0 and genuine-ACK=false: the client has not ACKed that publication yet. |
| Is this ordinary ACK backpressure? | Existing preflight returns `DeferredForFrameAcknowledge` and R4 reports 64 outstanding ACKs while acknowledgements are expected. | This is nonterminal: service real client DATA/ACK/SUSPEND intake and retry without capture or frame-ID advance. |
| Is publication terminally rejected? | Existing preflight returns `Rejected`, including duplicate/stale/invalid lifecycle cases; R3 also retains the retired-surface ID fence. | Do not reinterpret as backpressure or invent credit; follow the existing terminal publication path. |

The bounded first-client diagnostic snapshot must source
`firstExactFrameWriteCommitted`, `outstandingFrameAcknowledgements` and
`firstGenuineFrameAcknowledge` directly from
`GfxPresentationAcceptanceStatus`; do not cache a second ACK count or delivery
truth in R3/R10. Event-ring Boolean latches may exist only to suppress duplicate
event entries.

A full R1 plaintext commitment is not client-visible proof. The first Microsoft-
client acceptance trace must correlate native capture, ClearCodec preparation,
exact outer write completion, the authoritative outstanding count and a genuine
matching FRAME_ACK. Real client execution remains blocked until positive R2/R10
Start authority exists.

## R9 clean-Windows checksum/parser release rule (2026-10-19)

A queued self-hosted job is never the sole syntax validator for release code.
Primary CI parses the real `scripts/clean_windows_portable_gui.ps1` on
`windows-latest` with Windows PowerShell `Language.Parser.ParseFile` and no
self-hosted dependency.

`metadata/SHA256SUMS.txt` accepts only anchored `<64 lowercase hex><two spaces>`
plus a safe relative archive name. Reject absolute/backslash/colon/NUL names,
empty/dot/dot-dot components, trailing-space/dot Windows components,
case-colliding duplicates, differently-cased archive names, self-hashing and
incomplete inventory. Assign the parsed digest before comparison; retain outer
ZIP sidecar verification. All eleven intended Qt-free root configures are OFF.

## R1 TLS identity lifecycle and stale endpoint-generation regression (2026-10-19)

Register ordinary offline
`runtime.tls-identity-offline-lifecycle-denials` against the production
`RuntimeServerTlsContext` and synthetic secure credential fixture. It must
prove that a configured certificate stays `ConfiguredUnbound`, client trust
stays `Unknown`, numeric IP identity does not fall back to CN, malformed TLS
handshake cannot promote identity, certificate rotation replaces the SHA-256
observation, the rotated fixture matches only its actual IP SAN, and a
bound-derived observation is rejected when the current endpoint generation
differs or is zero. The test uses memory BIOs only: it must not bind/listen,
fabricate R2 consent or assert client trust.

The R7 offscreen TLS test must also reject a positive bound observation from a
retired listener generation before accepting the replacement generation.
The existing native LAN-listener CTest may assert generation lifetime during
its pre-existing optional real-interface bind, but this increment adds no new
live listener/client sequence. Real accepted-client certificate continuity,
WANT/close_notify/RST/half-close, Stop/accept races, interface removal and
descriptor reuse remain owner-authorized live tests only after R2 unblocks
R10 Start.

## Cross-platform R7 TLS presentation CI pin (2026-10-19)

The Linux GUI ZIP, macOS PORTABLE-GUI and Windows CLANG64 jobs must each
enumerate exactly one
`gui.offscreen-tls-fingerprint-rotation-and-denials` and execute it with the
native Qt build of the shared `desktop_window.cpp`. A platform merely
compiling the source is not enough evidence for this regression. The positive
workflow presentation is independently covered by
`gui.offscreen-positive-owner-workflow-presentation`; neither test authorizes
R2/R10 or opens a listener.

## R10 frame-credit/polling and GUI-headless CI contract (2026-10-19)

R10 consumes R2's R3 frame-publication preflight before borrowing X11 pixels. Only DeferredForFrameAcknowledge is ordinary backpressure: it consumes no capture, frame ID or R4 credit. Rejected is terminal; Ready still requires fresh frame-start authorization. R4 remains the only ACK-window owner. A pending Graphics TLS write must not turn an expired capture deadline into a zero-timeout spin; the quiet-pipe CTest requires bounded positive waits while native work/buffered data remain promptly serviceable. CI separately proves GUI default ON for Qt-capable application configuration and explicit OFF for protocol/security/sanitizer jobs. Requested GUI plus missing Qt must fail, never silently downgrade.

## R4 same-generation AVC420 surface-remap IDR (2026-10-19)

Register exactly one production-backed
`graphics.x264-segmented-surface-remap-idr` case in the existing x264
segmented producer binary. Establish a delivered/ACKed old-surface reference
chain ending in a P-frame, complete R3-style DELETE/CREATE/MAP to a different
surface ID without changing the Graphics generation, reject the old surface
without altering R4 membership, then require SPS/PPS/IDR on the first accepted
new-surface picture and a P-frame on the next picture. Full delivery and real
`GfxPresentationLifecycle::onFrameAcknowledge` calls must retire the exact
frames; do not fabricate credit or a second ACK set.

Retired-surface frame-ID monotonicity remains an R3 integration rule because
FRAME_ACK carries no surface ID. Keep it in R3's remap CTest rather than adding
an R4 high-water owner. Reuse the existing R4 regressions for malformed
geometry/NV12 preflight, duplicate pending IDs, exact zero-byte cancellation,
positive/partial terminal abort, capture-generation replacement and reconnect.
The fully provisioned R9 x264/BGRA sanitizer selector is **29** cases after this
addition; a lower green count is missing coverage. This remains offline codec
evidence and must not enable AVC420 runtime publication after remap.

## R7 exact TLS fingerprint presentation regression (2026-10-19)

`gui.offscreen-tls-fingerprint-rotation-and-denials` is the dedicated real-Qt
offscreen regression for the R1/R10 TLS identity projection. In addition to
rotation, missing-digest, endpoint-change and stale/revoked/unavailable
controller denials, it must compare the complete 32-byte R1 observation as a
95-character uppercase colon-separated SHA-256 string. Prefix-only assertions
are insufficient for the fixed-extent rendering contract. This test never
creates a certificate, listener, R2 lease or client-trust result.

## R5 RandR notification-burst generation assertions (2026-10-19)

A native X11 generation regression must not require an exact `+1` epoch step
after a RandR operation. One logical X server change may legally produce
multiple subscribed ScreenChange/CRTC/output/resource notifications, and each
observed topology boundary may retire the old XShm/Damage/input generation.
Tests must instead prove monotonic freshness, rejection of every stale
observation/framebuffer generation, successful capture from the settled
generation, and no further retirement once the synchronized notification
burst is drained. When queuing pointer traffic behind a resize, issue the
resize once so the fixture does not manufacture duplicate topology changes.
Keep same-pixel topology retirement covered independently.

## R5 same-size RandR topology invalidation (2026-10-19)

Do not treat an unchanged root PixelSize as proof that a RandR monitor,
CRTC or output generation is unchanged. Production R5 event dispatch must
invalidate and replace the complete native XShm/Damage/input resource
generation before subsequent queued XCB events; ignore client SendEvent
imitations. Register isolated-Xvfb `x11.same-pixel-randr-capture-retirement`
to change physical RandR screen millimeters with unchanged root pixels,
reject stale native capture and admit the fresh capture. No seat0,
credentials, listener or live protocol peer is authorized by this test.

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

## R6 Windows native host-conflict and offline mutation denials (2026-10-19)

Read-only WindowsRdpConflictProbe queries TermService via
SC_MANAGER_CONNECT/SERVICE_QUERY_STATUS and IPv4/IPv6 TCP listener tables
via GetExtendedTcpTable. Unavailable evidence is a fail-closed result.
Five native CTests cover TermService-active, requested-port conflict,
unavailable observation, clear classification, and actual read-only OS
observation. The existing portable GUI source guard rejects service,
registry, firewall and socket mutators in this path. The released GUI
smoke compares firewall rules and profiles, TermService configuration,
Windows OS RDP port and policy before and after two real window launches.
Unreadable state fails closed. One separate synthetic native Windows CTest
injects a change into each field and requires denial without querying OS
state, GUI launch, credentials or privilege. These tests do not authorize
Start and do not replace R9's independent clean-Windows ZIP acceptance.
Provenance: PR #25 source SHA 581d6828441b37b677a148466fe7bbcdc426d32e
hosted CI PASS; merged-main exact SHA CI NOT RUN at publication.

## R7 typed R1 TLS identity Qt display regressions (2026-10-19)

Use the existing R10 RuntimeTlsIdentityStatus with real offscreen Qt widgets;
do not create a second certificate parser or store an old fingerprint. Require
32-byte exact SHA-256 formatting, ConfiguredUnbound versus genuinely confirmed
BoundAndMatched distinction, fixed Unknown client trust and fresh verification
after rotation. Check missing digest, mismatched/changed endpoint, unavailable
interface, stale/revoked host, unavailable control and reconnect. Reject stale
positive identity even if an old R10 status still has tlsIdentityReady; the raw
R10 stage must continue to gate explicit Stop/Close. These tests confer no
native consent or client trust.

## R2 explicit owner consent and deny-only revocation tests (2026-10-19)

Ordinary CTest must register exact behavior names
`security.owner-consent-gui-intent-never-authorizes`,
`security.owner-consent-invalid-scope-and-lifetime-denials` and
`security.owner-consent-stop-lock-session-credential-revocations`.
They use the real noninstalled R2 production authority header, but do
not fabricate an affirmative physical owner, synthetic native lease, lock
proof, listener or credential. Validate view-inclusive scope and bounded
requested duration without converting well-formed GUI intent into positive
authority. Verify invalid scope, missing view, unknown permission bits,
zero/oversized duration and epoch invalidation for each Stop/lock-unknown/
logout/switch/session replacement/credential change/native-auth-loss event.
The real Linux admission broker must reject missing or non-authorizing R2 host authority at issuance and revalidation. **Current M1 correction:** positive fresh-seat0/unlocked grant behavior is now covered and source can issue bounded grants from valid physical evidence. Offline fake evidence remains state-machine evidence only; never substitute it, a fake `LockedHint`, or a GUI bool for physical FIRST.

## R5 replacement-X11-owner capture epoch anti-ABA (2026-10-19)

After terminal native owner retirement, constructing a replacement X11 owner
in the same process must allocate a distinct nonzero capture generation,
even if the root pixel geometry and R2-selected native session generation
are unchanged. Keep allocation off the hot frame path and fail closed on
uint64 exhaustion. An isolated Xvfb production-backed CTest must reject
the retired typed native observation, legacy scalar frame borrow and R4
consumer without entering the callback, while admitting the replacement
owner's current synchronous borrow. This does not authorize any R2 lease,
bind a listener or exercise authenticated Graphics remap.

## R7 real R10 Linux shell and terminal listener offscreen tests (2026-10-19)

Test the shared Qt GUI against the production Linux R10 HostControl as well
as the existing fake: confirm no listener, admission or desktop authority on
startup, credential/permission/Start denial, and explicit Stop/Revoke. Do not
depend on physical seat0 or interface availability. A separate cross-platform
real-Qt test must suppress `listenerReady` when stale/revoked R2 error
overrides an old positive `listenerAvailable`, while retaining the raw
R10 stage for Stop/close consent. Neither test is real-client acceptance.

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

## Windows GUI clean-loader acceptance (2026-10-19)

Never accept a portable Windows GUI based solely on an MSYS2-hosted ZIP
smoke with inherited development PATH, or on PE import scanning alone.
The independent Windows run must download the exact uploaded archive,
verify hashes and source SHA, extract under Unicode-and-spaces paths,
then observe a real GUI window and ordinary close with only OS system DLL
search directories. Retain socket/system-state/Start-denial tests and a
native synthetic PATH-sanitization CTest. Compare the human and CI ZIPs
before naming exact missing DLLs or asserting release success.

## R5 native geometry observation and synchronous XShm borrow (2026-10-19)

Require an R5 production-backed isolated-Xvfb test to capture value-only
pixel geometry/capture epoch with a caller-supplied R2-selected native session
generation. Reject zero generation, stale RandR geometry, replaced XShm
generation and mismatched session generation before entering the synchronous
frame callback; never persist the framebuffer span. Exercise repeated
resize, queued pointer movement, terminal native retirement and fresh
callback admission without a real seat0/authorization fixture. This is
native provenance and lifetime evidence only; R10 must independently
revalidate R2 admission before any protocol publication, and R3/R4 must
prove Graphics remap/FRAME_ACK receipts before integration is accepted.

## Windows shared-GUI credential-surface regression (R6/R7, 2026-10-19)

The hidden Windows launcher verifier must track the shared R7 credential
surface instead of preserving obsolete secret-widget assumptions. With
independent-password NLA unsupported, require no `password` or
`confirmation` QObject, require the disabled
`setApplicationPasswordUnsupported` action, and keep Start/Stop denied
under `UnavailableRuntimeHostControl`. Register
`windows.gui-independent-password-input-unavailable` in ordinary Windows
CTest and retain the existing self-test/start-denial/package-qwindows cases.
These checks initialize the packaged Qt platform only; they do not show a
window, bind a socket, request credentials or native desktop permissions.

## R7 independent application-password UI is non-collecting (2026-10-18)

Before R2 proves interoperable independent-password NLA, the Qt GUI must not
create password/confirmation entry widgets at all. A disabled, clearly
unsupported action may explain future scope but cannot accept text, mutate
credential status, configure R10 or affect Start readiness. Keep ordinary
`gui.offscreen-independent-password-workflow-unavailable` checking the
disabled action, absence of the historical `password` and `confirmation`
QObject inputs, zero credential/configure/Start calls, and normal Start
eligibility from supported OS-account status alone.

## R7 R10 raw-stage shutdown and exact GUI phase projection (2026-10-18)

A terminal R2 HostSessionStale result may suppress the GUI's projected
`sharing` and `startPending` flags before R10 retires the raw host
stage. Active raw stages must still require explicit Stop/close consent
and fresh retired R10 status. No GUI-owned state cache or second listener
is permitted. Use a plain-text typed R10 lifecycle label; only a true R10
listenerAvailable bit permits "Listener ready", and a genuinely visible
per-client Share permits "Client connected". The ordinary dedicated
`gui.offscreen-r10-lifecycle-and-terminal-close-denials` must cover
nine R10 stages, denied listener/visible-client evidence, terminal
R2 stale status, Stop/Revoke and unavailable host control without network,
real authorization or native permissions.

## R2 GUI-facing authentication outcome separation (2026-10-18)

Preserve the existing numeric `RuntimeHostError` values; append only
`AuthenticationRateLimited` and `HostSessionStale`. GUI text is fixed,
bounded and redacted, without per-account identity or credential paths.
`runtime.host-control-authentication-outcome-denials` exercises the
actual shared R10 status API and deny-only implementation on all hosts.
The existing R7 client-stage offscreen case must reject stale-session
snapshots even when obsolete `hostOwnerAuthorized` and client fields
remain set, and render rate limiting as a failure rather than connected
admission. Neither fixture authorizes R2/R3 nor changes real throttling;
live R10 alone reports actual peer/account budget outcomes.

## R8 stale positive committed-byte receipt across Stop/reconnect (2026-10-18)

R1 must copy R3 route/reply/slice/offered bytes before its mutating R2/R3
receipt; R8 observes only those stable, already-committed scalar identities.
When a positive receipt arrives after R8 retired the old route, ignore it
without changing the new route's pending response or source epoch. Preserve
fail-closed validation of malformed current-route receipts and
zero/future identities. Test old partial Pending and final Delivered receipts
against a new, bound FORMAT_LIST response and prove independent normal
delivery using actual R3 `onAcceptedBytes` outcomes.
`runtime.r8-r3-retired-route-positive-receipt-isolation` is a dedicated
ordinary offline test, deliberately outside the unchanged fixed 87-case
clipboard sanitizer selection. Do not enable any native CLIPRDR publication.

## R7 explicit Qt close consent and runtime retirement (2026-10-18)

An active or pending R10 state must not treat a generic window close as
Stop authorization or consent to hidden hosting. The Qt close dialog has a
safe Keep Window Open default; dismissal sends no runtime Stop/Revoke.
Only explicit Stop Sharing and Close requests R10 retirement. Refuse closing
while R10 status is unavailable or still active/pending. Stopped windows
close normally without a prompt or runtime command. Keep both
`gui.offscreen-close-revokes-pending-host` and new
`gui.offscreen-close-requires-explicit-owner-stop` in ordinary CTest;
Qt timer-driven modal selections and injected R10 status require no socket,
real owner credential, capture, native permission, or clipboard activation.

## R2 repeated Linux native session identity check (2026-10-18)

After the second physical seat0 identity read, repeat the observed
session UID and session-start timestamp through existing public sd-login
APIs; unknown, failed or differing values must deny the native candidate.
`security.linux-seat0-session-identity-denials` checks production pure
candidate consistency for changed UID, missing start, non-user
lock-screen class, inactive/remote and switched sessions without a
synthetic positive R2 lease. Public libsystemd sd-login does not have a
`sd_session_get_locked_hint` API; the logind D-Bus `LockedHint` is
advisory, and real owner lock/consent proof is still an independent gate.

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

## R8 clipboard TLS receipt avoids stale R3 borrowed packet (2026-10-18)

Before R2/R3 commits actual R1 accepted clipboard plaintext, copy the
exact route/reply/slice identity and offered TLS length. R3 may replace
or retire its borrowed wire slice during that commit; notify R8 only
through copied scalars, never by retaining or dereferencing a stale
pending span. R3 remains the sole byte-offset/write-sequence owner.
Only positive accepted bytes carry route identity. Missing lease, SSL
WANT and terminal zero-byte paths have no route identity. R8 observes
Pending or Delivered only after R2/R3 committed it, with full offered
slice required for Delivered.

Keep dedicated `runtime.r8-r3-stable-scalar-write-receipt` ordinary
CTest outside R9's fixed 87 clipboard sanitizer cases and two native
linkage guards; exercise R3 partial+full acceptance, stale reconnect,
zero-byte terminal denial and production no-lease identity non-disclosure.
The tests do not authorize native X11 clipboard or live client admission.

## R3/R4 frame-credit preflight stays read-only (2026-10-18)

`transport.dvc-graphics-frame-credit-preflight` must fill the production R4
ACK window through complete R3 frame delivery, prove the 65th fresh frame is
reported as `DeferredForFrameAcknowledge` with no pending wire record or
state mutation, consume one real FRAME_ACK through R3's existing handoff, and
prove capacity becomes `Ready` again. A duplicate outstanding frame ID with
available capacity must be `Rejected`, not misreported as credit pressure.
Keep this case in R9's exact-count R3 Graphics ASan/UBSan selector. Do not add a
second ACK counter, caller-supplied generation, synthetic admission or frame
reservation to the preflight.

## R10 shared Linux verified listener policy CTest (2026-10-18)

`runtime.linux-serve-loopback-listener-exact-endpoint-denials` uses the
**same production Linux listener** target linked by the CLI, but calls
only its pure literal endpoint gate. It checks accepted loopback address
families, nonzero port and denial of wildcard, alias, malformed, mapped
IPv6, remote LAN and zero-port text. Compile-time checks make the real
`LinuxListenerOwner` noncopyable/nonmovable; a harmless invalid descriptor
is retired via RAII. The test must never bind/listen, authenticate an OS
session, or invent a positive R2 lease. Live listener/GUI integration
requires separate authorized evidence.

## R9 cross-owner GUI LAN selection validation (2026-10-18)

For a GUI projection of the R10-selected LAN endpoint, native hosted
AppleClang/Qt CI must explicitly exercise both existing executable
behavior CTests: the R10 pure stable-ID/address eligibility check and
the Qt offscreen projection denials. Build both targets and select
exactly those two tests with a count and name check in the real
macOS packaging job before extracting/signature-verifying the app.
Validate the step, selector and exact-two contract separately.
Fake local addresses and offscreen widgets are only negative-policy
evidence; R1 bind, R2 OS lease, owner approval and LAN Microsoft
client success remain distinct requirements.

## R7 client stage and stale host-status UI test (2026-10-18)

A `RuntimeHostClient` in the current R10 status may describe an
authenticating TCP/NLA peer or a Share-activated session waiting for
desktop readiness. The R7 Qt status projection must not call these
records Connected. Require the current global sharing stage and
`shareActivated && desktopVisible && !authenticating` per-client
flags to list a connected desktop. Keep pending peers in a distinct
activity section. Opaque IDs stay R10-owned and may be submitted for
guarded disconnection, not interpreted as authenticated leases.
On R10 stopped/revoked/unavailable status, discard stale endpoint,
peers, and disconnect choices even when raw snapshot fields persist.
The normal offscreen test
`gui.offscreen-r10-client-stage-and-retirement-status-denials`
uses the existing injected mock without a listener, credentials,
capture or clipboard owner.

## R4 ClearCodec mapped geometry versus native capture (2026-10-18)

Keep the ordinary `graphics.clearcodec-denials` test production-backed
and ensure a current R3 mapped surface with different dimensions from a
valid native BGRA capture rejects both direct and segmented ClearCodec
preparation without mutating caller wire bytes, receipt, ACK window,
surface mapping or ClearCodec sequence. After zero-byte cancellation of
a correct old-surface frame and receipt-safe surface DELETE/CREATE/MAP,
allow only the newly mapped geometry, with complete outer delivery
accounting and a matching FRAME_ACK. This portable test is not live R10
resize/surface recreation evidence; never silently crop, stretch, forge a
lease or conflate TLS write receipts with client-visible pixels. Retain
the four-case R9 ClearCodec sanitizer selection.

## R2 IPv4-mapped IPv6 shares native IPv4 attempt identity (2026-10-18)

The same transport peer must not gain additional pre-CredSSP attempts
merely by changing from a native four-octet IPv4 socket address to the
16-octet mapped prefix `::ffff:a.b.c.d`. Canonicalize only the
RFC 4291 ten-zero, two-0xff mapped prefix into four octets before
matching the service's existing peer slots. Do not coalesce ordinary
IPv6, IPv6 loopback, different mapped addresses, or arbitrary
transitional IPv6; global attempt overload and monotonic expiry
remain unchanged. Keep
`security.ipv4-mapped-ipv6-peer-quota-identity` in ordinary cross-host
CTest on the exact production limiter rather than opening a real
listener or duplicating authentication-window state. This change
does not imply an authorized LAN Start or real R2 session.

## R7 shared R10 LAN selection projection (2026-10-18)

The R7 GUI must enumerate native interface choices once per status
projection, then use R10's existing pure
`assessRuntimeSelectedLanEndpoint` on each stable-ID/address pair
before showing it. Reject duplicated stable IDs, loopback, ineligible
and wildcard entries instead of allowing the UI to advertise a
selection Start will deny. Do not discard a second legitimate address
on a single eligible interface. The UI uses a nonzero validation port
only to assess bind eligibility; R10 rechecks the actual user-selected
port on Start. The real R10 owner must still re-enumerate and
authorize any socket bind; no projected value is a credential lease.
`gui.offscreen-r10-selected-lan-endpoint-preflight-denials` is
registered in ordinary Qt-enabled CTest and exercises an injected fake
without listener/native-session side effects.

## R5 native pointer buttons are owner-held transitions (2026-10-18)

Only a successful owner-issued XTEST ButtonPress creates a held-button
slot that permits an XTEST ButtonRelease on the same sole native
controller. Ignore both duplicate makes and unmatched breaks after
the already-applied R2 per-event authorization. An untracked remote
break must never release a button currently held by a local or
replacement X11 input source. Use the existing fixed
`pressedButtons_` array; do not introduce a second device-state
owner or copy R2 authority into the native adapter. MouseX side
buttons use the same 8/9 tracking; signed wheel 4–7 click pulses
are transient and separate. Graceful shutdown may release only
owner-held input while the R2 lease remains live; terminal expiry
sends zero native input.

Add the dedicated Xvfb behavior CTest
`x11.input-native-pointer-button-owner-held-break-denials` to check
unmatched break, duplicate transitions, synthetic foreign-held
button preservation and fresh-owner isolation. Ordinary test
fixtures may use isolated Xvfb only and cannot prove actual OS
login or client-facing input acceptance.

## R4 mapped ClearCodec ACK-capacity nonmutation (2026-10-18)

Keep the existing `graphics.frame-publication-backpressure` CTest
production-backed and exercise the ClearCodec prepare boundary with a
mapped tiny surface after 64 full deliveries, not merely the abstract
ACK window. Saturation must not touch encoded bytes, receipt, codec
sequence, mapped state or outstanding ACKs. A matching client ACK
reclaims one reservation; zero-outer-write cancellation must not
increment sequence; exact complete delivery then refills ACK credit.
Preserve the fixed R9 test inventory. Offline credit correctness does
not permit R10 to treat normal credit saturation as session revocation
or substitute for genuine R2 admission and visible client acceptance.

## R10 shared GUI/runtime LAN selector boundary (2026-10-18)

`runtime.host-control-selected-lan-interface-denials` is a new ordinary
cross-platform executable-backed CTest using the R10 production host-control
header. An exact interface ID/address preference may pass pure selection
preflight but must not allow `UnavailableRuntimeHostControl` to start or
report a bound endpoint. Duplicate stable identities, ineligible or loopback
interfaces, wildcard addresses and zero port fail closed. R7 UI consumes
the same R10 check, but R1 bind, R2 native authorization and consent must
be tested separately with real approved host evidence.

## R9 exact-count source tests in native-facing CI (2026-10-18)

When an upstream R10/R5/R7 change adds a source-only CMake guard to
ordinary CTest for a release-critical authority, Stop, input retirement,
or untrusted GUI status construction boundary, R9 may also select that
same test in the relevant focused native CI job. Pin exact names and
count with a single bounded CTest selection, and require those tokens
in the independently executing CI workflow validator. Do not describe
`cmake -P` source tests as ASan-instrumented runtime tests simply
because they run in a Clang sanitizer-equipped job. On hosted macOS,
run Qt PlainText constructor ordering on the real Qt Release build
before package signature and LaunchServices checks: an offscreen QLabel
end-state test alone can miss transient AutoText parsing. Owner Mac 27
Finder/Gatekeeper and live LAN authorization are separate and cannot
be simulated or marked PASS by CI.

## R2 fixed-slot verified-principal saturation and expiry (2026-10-18)

A service-wide account-attempt policy must not evict an unexpired
provider-verified principal because a 65th unique principal arrives.
Keep the bounded table at 64 fixed slots, with eight attempts per
principal per monotonic 60-second window and generic fail-closed
overflow. Account expiry permits reset/reuse only at the exact deadline;
malformed identities must not consume or displace slots. Key the
budget by case-sensitive GSS-derived principal bytes, never by the
client-delegated local username. Account pressure may not corrupt
the same service owner's independent peer/global budget.
`security.verified-account-table-exhaustion` is the ordinary
non-networked production-code CTest for this state-lifetime contract,
separate from `security.bounded-peer-global-and-account-attempts`
and the Linux GSS/PAM source and binding gates.

## R7 avoid transient Qt AutoText status parsing (2026-10-18)

The status-label constructor must create a blank QLabel, set
`Qt::PlainText`, and only then set its runtime message. An end-state
`textFormat()` test misses transient HTML/resource parsing in
`QLabel(message)`. `gui.runtime-label-plain-before-text-assignment`
guards that source-level ordering; the existing
`gui.offscreen-runtime-peer-and-endpoint-plain-text` checks actual
offscreen status labels with HTML-looking R10 metadata. Neither
fixture requests R2 admission, native permission or TCP sockets.

## R10 serialized loopback Stop CTest boundary (2026-10-18)

`runtime.linux-serve-cooperative-signal-stop-order` is a production-source
ordinary offline test, not synthetic authenticated OS admission. It must
require 13 handshake Stop fences, the real native loop Stop fence, POSIX
SIGINT/SIGTERM handler restoration and native no-XTEST retirement before
R3/R1 revoke; it must not send signals, listen or touch a desktop.

## R7 Qt runtime status inert text CTest (2026-10-18)

Run `gui.offscreen-runtime-peer-and-endpoint-plain-text` with ordinary
offscreen GUI CTests. Inject R10 snapshot peer/interface/endpoint text
containing HTML link/image markup and assert the real QLabels use
`Qt::PlainText`, retain literal values and cannot dispatch Start from
unverified host credentials. No listening, native capture or real
R2 credentials are exercised. Hosted native macOS 26 arm64 R7 GUI
`5/5` and package `3/3` CTests passed at SHA `549a12c0`
([run 39142229897](https://github.com/k1moradi/RDP-server/actions/runs/39142229897));
new plain-text CTest exact-publication evidence is **PENDING**.

## R5 protected-input terminal failure semantics (2026-10-18)

The two entry points into R5 native input share one terminal rule:
active R10 `dispatchAuthenticatedSlowPathTpkt` and the
older `X11AuthorizedInputRoute::dispatch` may use R2-authorized
`handleAuthorizedInput`, but any failed native injection must call
`retireAfterAuthorizationLoss()` and never `disconnect()` or emit
cleanup XTEST. A legacy direct dispatch must also revoke its R3
session after retirement. The offline source CTest
`x11.input-direct-route-native-failure-no-xtest` pins the
permission fence and no-XTEST failure ordering; the Xvfb controller
test still establishes genuine held-key/button state behavior, not
OS admission. Explicit graceful disconnect under still-current
authority alone may release held native input.

## R9 credential-source guard focused CTest assurance (2026-10-18)

Because malformed CMake source-level R2 security tests can go
undetected by green ASan-backed executable suites, enroll the
existing `security.linux-verified-account-pam-attempt-fence-source`
as its own **one** behavior-named focused CTest. Require a
registration count and literal name sentinel, plus independent
workflow-structure validation for the step/selector/cardinality.
Do not fold source-level CMake scripts into the 40-case sanitizer
executable inventory or skip ordinary full Linux CTest. Preserve
the R2 GSS-verified principal/one-shot PAM budget security assertions.

## R7 macOS extracted GUI LaunchServices and package CTests (2026-10-18)

The native macOS arm64 GUI packaging lane explicitly enumerates and
runs three integrity CTests (archive, signed framework aliases, shared
malicious-link verifier), then verifies the extracted `.app` with
`codesign --verify --deep --strict`. `scripts/smoke_macos_gui_open.py`
uses LaunchServices `open -n -a` on the extracted Cocoa app, requires
a sustained GUI process, rejects TCP LISTEN sockets owned by that
process, and terminates it. Failure to obtain a usable Aqua session
must fail the smoke rather than be silently called PASS. This is not a
human Finder double-click or Gatekeeper/notarization approval and
grants no R2 credential authority or R10 native host ownership.

## R1/R8 clipboard output interest regression (2026-10-18)

Register `runtime.linux-connection-clipboard-outbound-want-precedence`
as ordinary offline CTest. Check that R8 writer-in-progress demands
Write over idle SSL Read, that R1 SSL_write_ex WANT_READ/WANT_WRITE
and terminal state override output preference, and buffered unrelated
plaintext cannot interrupt a queued CLIPRDR suffix. No synthetic R2
lease or native clipboard fixture.

## R5 native aggregate terminal failure input safety (2026-10-18)

Full X11 desktop `cancelNativeResources()` is used by failures
in XCB event draining, XShm capture, input injection, geometry rebuild
and construction. It must default to terminal
`SuppressNativeInput`, not send best-effort key/button XTEST releases.
Only the explicit authority-current graceful `disconnect()` may opt
in to `ReleaseHeldState`; successful RandR geometry-only teardown
retains its existing separate input-state semantics. Register a
cross-host production-source test
`x11.input-native-failure-terminal-retirement-no-xtest`,
and retain independent Xvfb
`x11.input-native-authority-retirement-no-native-post`
for actual held-key/button behavior. Neither is positive OS admission.

## R9 new production clipboard TLS writer sanitizer inventory (2026-10-18)

A new R8 connection-local R1/TLS clipboard writer must retain a
separately counted exact-one production-backed CTest in the focused
Linux Clang ASan/UBSan lane, with CI structure sentinels for the test
name and expected count. Do not silently fold it into the existing 87
R8 component-only clipboard cases, two dormant native bridge guards,
two post-Share R10 negative cases, or 40 R2 executable security tests.
A no-R2-lease denial is not a positive native CLIPRDR acceptance claim.
Actual extracted macOS framework `codesign --verify --deep --strict`
and an owner-authorized Aqua GUI launch remain separate obligations.

## R2 service-wide GSS verified-principal budget source assurance (2026-10-18)

Preserve the production final-credential sequence: the GSS provider
has established the exact TLS-bound principal, the decrypted delegated
local account matches R2 identity policy, then exactly that principal
is charged to the fixed service budget before PAM sees the password.
Never move the reservation after the verifier or key it by claimed
local-account text. One serialized Linux service owns peer/global and
per-principal windows; GSS binding is one-shot after explicit
provisioning and cleared on rejection. The distinct offline source
CTest `security.linux-verified-account-pam-attempt-fence-source`
guards these private authority handoffs without needing Kerberos or
synthetic native admission, alongside executable-backed rate-window
and actual keytab acceptor denial tests.

## R8 serialized CLIPRDR TLS writes preserve R1/R2/R3 receipts (2026-10-18)

A live post-Share R8 clipboard writer must reborrow the current R3
static-VC slice under fresh R2 lease and permission before every write.
Only R1's actual accepted plaintext bytes may advance the R3
route/reply/slice receipt. Positive partial acceptance retains exclusive
TLS write ownership until the whole TPKT is delivered; SSL WANT_READ
continues the same write and cannot be reinterpreted as application input.
No new R1 reader, writer, scheduler, clipboard generation or receipt state
is permitted. R10 must prioritize this retained slice ahead of Graphics
DATA and inbound TPKTs; terminal revocation defeats late callbacks.

Keep `runtime.linux-connection-personal-clipboard-tls-write-denials`
as one ordinary no-lease R1 write/retirement regression, separately from
R8's fixed 87 clipboard sanitizer cases and R9's two native-linkage
guards. Positive full/partial receipts and native X11 INCR Stop/reconnect
retirement must also be verified once the authenticated R10 scheduler
selects the real R8 clipboard branch. Static linkage is not publication.

## R1 persistent read-WANT/interleaved outbound frame regression (2026-10-18)

The ordinary full CTest `transport.tcp-owned-tls-read-want-interleaved-frame-write`
performs a real completed TLS handshake on a nonblocking loopback pair,
then forces idle application read WANT_READ, publishes a server-side frame
without client input, receives it at the TLS peer, resumes a client
TPKT read, and confirms cancellation blocks late I/O. Keep it outside
fixed-count sanitizer selections. Existing wrong-size read retry and
pending SSL-write positive partial receipt tests remain mandatory. This
test does not grant R2 admission or claim Microsoft-client visibility.

## R7 macOS signed framework aliases in PORTABLE-GUI ZIP (2026-10-18)

Qt `macdeployqt` frameworks require their versioned symlink topology to
remain stable across ZIP extraction for `codesign --verify --deep --strict`.
For a macOS-only PORTABLE-GUI archive, regular staged framework aliases
may be encoded as POSIX ZIP symlink entries containing the original bounded
relative targets, but **only** below `rdp-server-desktop.app/Contents/Frameworks/`.
The builder must validate every target resolves inside its own framework
(or the local Frameworks directory for dylib aliases), never the OS or
build host. The shared verifier must reject absolute paths, `..`, missing
destinations, cycles, write-under-symlink entries, and symlinks outside
macOS framework closure or in any Windows/Linux bundle. Manifest hashes,
per-file checksums and external archive SHA include symlink target bytes.
Only a native extracted-app strict signature check proves restoration.

The registered `packaging.macos-portable-gui-framework-alias-integrity-denials`
and `packaging.portable-gui-macos-framework-link-verifier-denials` CTests
run with synthetic fixtures on every OS and do not launch Qt, access
ScreenCaptureKit/TCC, start a listener, or authorize a desktop. Ad-hoc
signing remains a development integrity mechanism, not Developer ID
trust, Gatekeeper assessment, or notarization.

## R5 persistent post-Share native source contracts (2026-10-18)

After R10 replaced one bounded native poll with the authorized persistent
post-Share scheduler, R5's guard must not require the obsolete
`nativeDispatch` temporary, graceful X11 disconnect or absence of frame
capture. Guard the *current* production owner loop instead: unregister the
borrowed R2 logind watch before callbacks, check R2 authorization on both
sides of the bounded XCB drain, prohibit bypassing R1 TLS or R2 protected
input, require synchronous XShm/R4 full-frame borrow only after the
authorized native event service, and retire XTEST without cleanup posts
on expiry. Two ordinary offline CTests,
`runtime.linux-r5-x11-authorized-event-service-denials` and
`runtime.linux-r5-persistent-x11-input-frame-borrow-order`, pin separate
event handoff and authenticated input/borrow boundaries. Source inspection
tests are not native Xvfb or real admission evidence; keep the existing
positive synthetic Xvfb framebuffer and denied unauthenticated XTEST
fixtures separately.

## R9 persistent post-Share ownership focused source guard (2026-10-18)

When R10 lands a new source-level production scheduler CTest, enroll it
in a **separate exact-one** CTest selection in the R9 focused assurance
job. Require its name and count in `scripts/validate_ci_workflow.py`.
This does not execute a sanitized live authenticated session and must
not change the R2 legacy 40-case executable sanitizer count, the R10
two-case production-backed post-Share denials, R8 87-case component
inventory or separate dormant bridge linkage guards. Keep macOS
extracted `codesign --verify --deep --strict` mandatory after ZIP
extraction; valid hashes alone are insufficient signing evidence.

## R2 verified GSS principal rate limit at PAM boundary (2026-10-18)

Only the one serialized service budget may be bound to a configured
GSS/PAM acceptor before any peer token. Reserve a verified account
attempt only for its TLS-bound GSS principal after CredSSP v5/v6
public-key proof, final unwrap and exact R2 delegated local account
match, immediately before invoking PAM. On exhaustion, fail closed
without PAM and without revealing account existence. Never charge a
client-provided username or log identity/password/token content.
Retire borrowed limiter pointer on terminal GSS release.
`runtime.linux-connection-verified-account-attempt-limiter-binding-denials`
proves real binding and absent-TLS rejection offline, not positive
authentication.

## R2 fixed-memory authentication-attempt budget (2026-10-18)

The serialized Linux listener owns one service-lifetime
`AuthenticationAttemptLimiter`. Validate actual peer-family address
and selected local-interface policy first; reserve peer/global attempts
before allocating TLS/GSS. One 60-second steady-clock window allows at
most eight attempts per peer, 128 globally and 64 distinct in-window
peer addresses; full slots and time regression reject without logging.
Provider-verified account reservations share the same allocation-free
fixed-table design (64 principals, eight attempts each); only the exact
GSS-authenticated principal may be passed there, **not** a guessed
or delegated username; the final PAM invocation is now fenced by the
provider-authenticated principal budget (`1aa476e5`), without adding a
second authentication owner.
No denial may reveal whether an account exists, no successful
reservation is a user/session authorization, and the limiter remains
confined to the one listener thread. Test
`security.bounded-peer-global-and-account-attempts` runs on every
platform without external services and verifies boundedness, expiry,
invalid input, capacity and failure-only decisions. Do not claim the
per-account limit is live until the provider-path integration lands.

## Cross-host macOS GUI install-ID fixture path matching (2026-10-18)

A synthetic macOS `otool -D` fixture must recognize a target by the host
`Path(...).name` instead of POSIX-only `/QtGui` string suffix: ordinary
Windows CTest also executes the stdlib-only macOS packaging regression.
Keep the same `install_name_tool -id @rpath/...` and final ad-hoc
`codesign` assertions rather than skipping the regression on Windows.
R10 post-Share runtime classifier and single-reader negative tests use their
own exact-two R9 sanitizer selection until the persistent live scheduler
is composed; the existing 40-case R2 runtime-security selection remains fixed.

## R7 real R10 interface/endpoint and active-client UI gate (2026-10-18)

An R7 Qt GUI may show only a LAN interface identity/address actually
enumerated by R10 and only the currently R10-reported bound endpoint.
Never invent a numeric IP, listener state or TLS trust from a selected
port or identity-readiness boolean. Distinguish a stable native interface
ID from its numeric address: two eligible interfaces may enumerate the
same address and must remain distinct. The GUI adapter rechecks that
exact pair and current credential/desktop/TLS/native state as early
fail-closed gates; concrete R10 remains authoritative.

A disconnect button must use an opaque ID from the latest R10 active
client list, deny zero/removed clients, request R10 disconnection only
during active/pending sharing and reread status after the call. A click
or command return is not a disconnect receipt. Offscreen
`gui.offscreen-r10-interface-endpoint-client-disconnect-denials` runs on
any Qt-enabled CTest host with an injected fake; no network/native OS,
TCC, input or capture operation is permitted in the fixture.

## R5 bounded Set-1 scancode, held-key retirement and one-owner CTests (2026-10-18)

Use the existing R3-decoded `ScancodeKeyboard` and R2's synchronous
per-event protected callback; never synthesize an admitted lease in a
keyboard fixture. `x11.input-scancode-make-release-modifier-extended-denials`
checks press, duplicate held-key make, independent KBDFLAGS_DOWN and RELEASE,
left/right modifiers, E0 navigation, E1/Pause refusal, undefined/OEM
scancodes, reserved flags, invalid geometry and separate Unicode/relative
denial. No independent Unicode or relative-pointer native feature is enabled.

Optional Xvfb fixtures `x11.input-native-keyboard-sequence-and-reconnect`
and `x11.input-native-keyboard-logout-no-native-post` inspect the existing
XTEST controller's held-key mapping, break, repeat, fresh owner construction
and **zero cleanup XTEST after terminal retirement**. The optional
`x11.input-r2-policy-replacement-keyboard-denial` exercises R2 policy
generation change before an unauthenticated input request; it proves refusal,
not positive authorization. Add `x11.input-native-keyboard-layout-change-revokes-owner` for XCB
MappingNotify-driven retirement of the keyboard mapping, without a cleanup
XTEST post. Preserve existing native generation/RandR and absent-lease cases. Register all as behavior-named CTests in the shared
registry; ordinary full CTest must run every applicable case, including
offline cases when Xvfb is unavailable. No synthetic Xvfb event, keymap
snapshot or scripted policy replacement proves genuine OS admission.

## R5 signed wheel and native XTEST scroll contract (2026-10-18)

For RDP MS-RDPBCGR TS_POINTER_EVENT, wheelFlags (0x0200/0x0400)
identify the event; the 0x01ff WheelRotationMask is signed and
bit 0x0100 requires 9-bit sign extension. Vertical wins when
both axis flags are set. Other flags and the untrusted x/y
wheel fields are ignored for wheel semantics. Emit native
X11ScrollInput into the existing 120-unit bounded XTEST
4/5 (vertical) or 6/7 (horizontal) accumulator. XTEST
rootX/rootY matter only on MotionNotify, not button events:
never let wheel fields move the pointer. Preserve R3 horizontal
capability negotiation and R2 per-event input authorization.

Keep a separate offline CTest
`x11.input-rdp-wheel-sign-extension-axis-and-coordinate-denials`
for ±120, extrema, both axes, wheel-field ignore and malformed
non-wheel/zero-geometry denials. Existing MouseX and base
translator cases remain. Do not claim real R2, XTEST or client
acceptance from this test; R9 separately adjusts focused
sanitizer counts.

## R8 production linkage without clipboard authority (2026-10-18)

The source/build linkage guard is not a component sanitizer case and must not
carry the generic `clipboard` label. R9 owns its separate exact-two dormant
native-bridge selection together with the authorized-input linkage guard; keep
the fixed R8 `clipboard` label inventory at 87 unless a new executable
clipboard behavior test is intentionally added.


The production Linux server may link the existing R8 R3 bridge and X11
clipboard adapter once the complete R2 runtime-security/X11 dependency graph is
available, but linkage must remain descriptive build readiness only. Until R10
owns one persistent post-Share R1 complete-TPKT/TLS router plus the same live
X11/logind owner, `main.cpp` must not construct either R8 owner, dispatch
CLIPRDR, queue clipboard writes, commit clipboard receipts or publish an X11
selection. Keep
`runtime.linux-x11-clipboard-production-linkage` as the offline source/build
guard for that boundary. Positive clipboard behavior still requires genuine R2
admission and exact R3 route authorization; ordinary CI must not fabricate it.

## R5 MouseX native decoding under R2 input authority (2026-10-18)

Only the existing R2/R3 per-event authorized callback may reach the R5
X11 input owner. For TS_POINTERX_EVENT accept one of XBUTTON1/XBUTTON2
and optional DOWN, map it to X11 core 8/9, and require exact native
geometry bounds. Do not admit mixed/unknown flags, MOVE, ordinary
buttons or wheel events. The independent offline CTest
`x11.input-rdp-mousex-side-button-bounds-and-flag-denials` exercises
positive press/release and terminal syntax denials without a physical X11
desktop, XTEST post or fabricated positive R2 lease.

## R6 packaged Windows GUI command-mode platform regression (2026-10-18)

Portable command-mode smoke must use only Qt plugins guaranteed by the
artifact contract. Windows guarantees `plugins/platforms/qwindows.dll`;
therefore hidden deny-only self-tests may not rely on `qoffscreen.dll`.
`windows.gui-offline-packaged-qwindows-selection` deliberately inherits an
invalid `QT_QPA_PLATFORM` value and requires the production launcher to
select `windows`, construct the shared GUI without showing it, and exit
normally. R9 separately owns the extracted normal first-screen, no-socket and
firewall-state smoke.

## R5 decoded RDP slow-path input to native X11, per-event (2026-10-18)

R2 `dispatchPersonalDesktopSlowPathInputPdu` is the only gateway permitted
to call R5's private XTEST sink. The sink is synchronous and retains no
authorization grant. It must recheck the current R5 capture geometry
generation beside injection; mismatch or unsupported syntax terminates
and retires held native state without cleanup XTEST. The typed translator
currently permits only exactly one MOVE or button1/2/3 event (mapping RDP
right=button2 to X11 right=button3), and lock synchronization's supported
caps/num/scroll flags. Input coordinates must fit the exact native
geometry; mixed/wheel/unknown flags, extended/relative and all unmapped
keyboard variants fail closed. `Unused` stays an authorized no-op.
Use `x11.input-r2-authorized-slow-path-native-mapping-denials` with
explicit positive/negative decoded-event fixtures and never mint a
synthetic R2 lease in native tests. The R10 serve loop must read each
complete TPKT via the single R1 TLS owner and register no second X11
connection or authorization controller.

## R6 Windows GUI recursive dependency staging regression (2026-10-18)

A successful `windeployqt` invocation is not sufficient evidence that a
portable Windows Qt package is dependency-complete. R6 must resolve the
recursive non-system PE closure independently after deployment and stage every
missing regular DLL before hashing. The portable
`windows.gui-portable-runtime-dependency-staging` CTest injects representative
toolchain DLLs and proves they enter the R9-verified archive without invoking
CMake, a Windows executable, the network, firewall or service APIs. Native R9
CI remains authoritative for real `llvm-objdump` import closure. Windows
system DLLs must be classified as OS-supplied by that verifier, not copied from
System32 into the portable ZIP.

## R5 R2-fenced native XCB event-service handoff (2026-10-18)

The first bounded native event drain must use only R10's one R2-selected
`X11DesktopResources` after its borrowed logind poll registration has
been removed. Each `processEvents()` call uses an explicit event budget,
a current XCB-readability bit, and fresh R2 PersonalDesktop application
authorization both before and after. Native connection, RandR or event
failure revokes without native XTEST release; no callback may mint
admission, publish a frame or dispatch keyboard/pointer events.
`runtime.linux-r5-x11-authorized-event-service-denials` source-guards
the production call ordering under ordinary full offline CTest because
real Kerberos/PAM/logind admission cannot be simulated by an ephemeral Xvfb
fixture. Existing `x11.desktop-resource-*` Xvfb CTests continue to
exercise native event and RandR behavior independently, but are never
positive R2/client authorization evidence.

## R2 runtime slow-path input gateway coverage (2026-10-18)

The runtime-facing slow-path input gateway must not expose the private R2 broker
or admission lease. Offline tests may provide bounded caller packet bytes and a
synchronous sink, but without genuine admission the aggregate must revoke
before event decode/callback dispatch and the sink count must remain zero.
Replay after revocation remains terminal. Positive native-input coverage
requires owner-authorized genuine CredSSP/PAM/NSS/logind admission; ordinary CI
must not manufacture that capability or invoke XTEST on a logged-in desktop.

## R8 Linux runtime clipboard gateway denial boundary (2026-10-18)

The post-Share runtime may expose R8 only through the existing R2 broker's five
CLIPRDR operations: route visit, complete-TPKT dispatch, application-PDU queue,
pending-write borrow and exact accepted-byte completion. These connection
wrappers perform no TLS I/O, native clipboard publication or scheduling and must
fail terminally without the exact PersonalDesktop policy plus genuine current
R2 lease. `runtime.linux-connection-personal-desktop-clipboard-gateway-denials`
exercises all five operations without fabricating positive admission and is
included in the direct runtime-security sanitizer selector, which grows from
38 to 39 cases. A positive live test still requires owner-authorized physical
seat0 credentials; ordinary CI must not synthesize that lease.

## R6 portable Windows canonical-runtime-name regression (2026-10-18)

Portable GUI tests must not depend on the host filesystem being case-sensitive.
The Windows package contract requires canonical `Qt6Core.dll`,
`Qt6Gui.dll`, `Qt6Widgets.dll` and
`plugins/platforms/qwindows.dll` spellings after staging, in addition to
casefold collision rejection. A wrong-case fixture deletes the canonical entry
before recreating it so NTFS/APFS case-insensitive hosts exercise the same
denial. Source-policy scans follow the live shared R7
`src/gui/host_control.cpp` adapter. The dedicated
`windows.gui-portable-canonical-runtime-name-denials` CTest keeps this
boundary visible in ordinary full CTest.

## R5 Qt-native Linux seat0 GUI preflight test boundary (2026-10-18)

Opt-in Linux Qt builds compile the GUI's real read-only prerequisite parser,
register `gui.linux-readonly-seat0-prerequisite-denials` in ordinary CTest,
and run it in the R5 hosted Linux GUI job before actual extracted GUI smoke.
The offline fixture injects logind observations (seat/type/active/remote/
display), tests Wayland/Xvfb-display mismatch, unusable session IDs, missing
logind reply and libraries, and verifies that a deny-only host-control GUI
still refuses Start. The read-only probe must be asynchronous, bounded,
parent-owned, and non-authorizing; native R2 admission, logind-watcher
registration, pixel capture and XTEST are never created by GUI or test.
Neither a synthetic positive seat0 observation nor successful Xvfb GUI
startup is evidence for a true physical seat or an authenticated client.
Run owner full Debug CTest and record exact hosted SHA before claiming PASS.

## R6 Windows PORTABLE-GUI offline contract (2026-10-18)

windows.gui-portable-zip-integrity-path-uninstall-denials is a portable synthetic-PE test of the Windows ZIP builder and passes its output through R9's production PORTABLE-GUI verifier. It exercises Unicode/space paths, full payload and outer hashes, disabled listen/autostart example configuration, Qt platform-plugin presence, case-alias/helper denial and clean removal. It never starts Qt, opens a socket, changes a firewall rule, elevates, installs a service or mints R2 admission.

Native Windows assurance still requires the real windeployqt package, recursive non-system PE dependency closure, extracted --offline-self-test and --offline-start-denial-test, and before/after firewall-state comparison.
## R8 clipboard GUI state is descriptive, never authority (2026-10-18)

Clipboard UI tests may render the four shared R10 status states
`Unavailable`, `Enabled`, `Retired` and `Denied`, but a rendering
fixture must not mint an R2 lease, R3 route generation or native clipboard
owner. The production deny-only host control remains `Unavailable` across
rejected start/stop/revoke. A rendered `Enabled` value is status-only test
data; live code may report it only after fresh R2 authorization, genuine
`ShareActivated`, the exact joined `cliprdr` route and current native
clipboard owner. No GUI preference or checkbox is an authorization input.

## R8 authenticated R3 clipboard bridge coverage (2026-10-18)

The R8 application bridge must be tested below R10 without fabricating a live
R2 lease. Tests may drive R3's production static-channel route mechanics
offline, but R8 receives only an R3-owned nonzero route view and complete
CLIPRDR PDUs; it must not invoke the legacy joined-channel intake Boolean or
construct another static-VC reassembler. Each outbound application request is
bound to R3's route/reply identity, positive partial accepted bytes remain
pending, and only `Delivered` permits a matching response. Retirement clears
source/request/FileContents readiness before reconnect; the replacement route
must have a newer R3 generation while `RemoteTransfer::sourceEpoch()` advances
only when a replacement clipboard offer is accepted. The five
`clipboard.r3-bridge-*` cases extend the R8 sanitizer inventory from **82 to
87**. R3's nine `transport.cliprdr-*` cases use the separate `r3-cliprdr`
label and must not be counted by `ctest -L clipboard`.

## R3 CLIPRDR whole-PDU/receipt gate (2026-10-18)

MS-RDPBCGR 2.2.6.1.1 and 3.1.5.2 require the eight-byte static-VC header and the exact negotiated channel-data bound (1600 unless both optional VCChunkSize fields apply; maximum 16256). Channel data must preserve FIRST/LAST ordering; SHOW_PROTOCOL is optional header-visibility metadata and must not be required for reassembly. Incoming SUSPEND/RESUME and SHADOW_PERSISTENT control bits are ignored as required; unsupported compression, unknown flags, and interleaved, overflowing or underlength fragments must terminate the owner rather than offer partial clipboard data. Only R3 decodes complete MCS SendDataRequests and emits complete MCS SendDataIndication TPKTs; R8 must not add a framing owner. Every positive SSL_write_ex application-plaintext accepted-byte receipt must be bound to the current R3 route/reply/slice and reauthorized by R2; zero/would-block is not progress. A partial accepted packet needs only its suffix resent, and retirement discards it. Test source/parser/receipt mechanics offline without inventing R2 OS admission. The eight route behavior-named `transport.cliprdr-*` CTests plus `transport.cliprdr-pre-share-denial` form a nine-case R3 inventory. Hosted sanitizer CI must build `test_r3_clipboard_static_channel` explicitly and select all nine exact names separately from R8's clipboard inventory. Genuine physical seat0 proof remains a separate live gate.

## R6 hosted reparse proof and reused WTS-number denial (2026-10-18)

A successful aggregate Windows packaging CTest alone does not prove its reparse
negative executed: symlink creation could skip on a restricted account. The
existing Python native lifecycle case first tries a directory symlink, then a
Windows directory junction (both reparse points), and fails the hosted GitHub
Actions run rather than silently skipping if neither is available. The dedicated
`windows.package-reparse-parent-denial` CTest makes this specific denial visible
in the normal Windows full Debug/Release registry; no production packaging code
or installer privilege is changed.

`security.windows-native-session-reused-id-luid-logon-denials` exercises the
production `WindowsNativeSessionEvidence::sameNativeSession()` comparator
against synthetic *candidate identity facts*, never synthetic admission:
unchanged numeric WTS session and SID with changed low/high LSA LUID or logon
time must compare unequal. The ordinary native provider denial test remains
separate. Neither test starts a server, captures a desktop, injects input, or
grants R2/R10 Windows authority. Source parent is `aea0201eed22b90bd6d4bd6ac6d4a0895752c00e`; new commit hosted
CI and owner-native Debug acceptance are NOT RUN / pending.

## R6 PowerShell offline negative-path cases (2026-10-18)

Extend the single existing windows.package-user-lifecycle-offline-contract to reject an internally tampered DLL despite a correctly re-signed outer archive checksum, a modified installed DLL, an unmanifested installed file, an install root outside LOCALAPPDATA, and a reparse-point directory parent. Verify/Status/Start/Stop/Uninstall refuse a modified installed tree, and valid restored contents permit Verify/Uninstall again. The native reparse test may skip only if symlink creation is not permitted by the OS user. These native tests do not authenticate, capture or start a server.

The expanded single Python/PowerShell CTest has a 90-second upper bound; portable checks remain on every host. Hosted publication-SHA evidence is NOT RUN / pending.

## CI CTest regex sentinels must be structurally exact (2026-10-17)

Dedicated hosted CTest gates must be guarded by the full anchored selector
string, not only the step name and test-name substring. This is especially
important for shell regexes ending in `$'`: programmatic replacement APIs may
interpret that sequence as replacement syntax and silently splice unrelated
workflow text. A structure check must therefore require the exact literal
selector and parsed workflow shape before the job is treated as runnable
evidence. A malformed authoring commit is never a PASS.
## R6 package verifier must not contain the secret sentinels it rejects (2026-10-17)

The Windows per-user lifecycle verifier is shipped inside SERVER-TEST and is
therefore scanned by the same generic payload-secret gate as every other bundle
member. Secret-marker detection code must compose marker strings at runtime
rather than embed the complete forbidden byte sequence in the script itself.
`windows.package-user-lifecycle-offline-contract` must assert that every
`FORBIDDEN_BYTE_MARKERS` value is absent from the lifecycle script bytes and
then pass those bytes through `scan_for_secrets()`. This portable portion runs
on Linux, macOS and Windows; Windows additionally executes the native PowerShell
lifecycle cases.

The existing `windows.geometry-gdi-rectangle-name-resolution` compile/runtime
probe must include `rdp/gfx_avc420_picture.h` after `<windows.h>`. This makes
the shared AVC420 header's Rectangle lookup part of the R6 portability sentinel
instead of testing only R6-local geometry aliases.

## R7 macOS protocol-bundle denial test runs before the C++ build (2026-10-17)

The protocol matrix must execute `tests/test_macos_test_bundle.py` directly on
Linux, macOS and Windows immediately after checkout, before dependency setup or
any C++ compile. The test uses only Python's standard library and mocks the
Darwin host/architecture where installation semantics require it. This early
preflight is the same offline integrity/idempotence contract registered later as
`macos.package-offline-integrity-and-idempotence`; it does not package a real
binary, start a process, touch TCC, bind a socket, capture a desktop or inject
input.

Keep the ordinary CTest registration as well. The direct preflight exists so an
unrelated compile failure cannot erase R7 package evidence and so Linux coverage
is explicit rather than inferred from macOS/Windows results. Unsupported or
universal architectures must be rejected; tests should assert the stable
`unsupported bundle` diagnostic prefix rather than an implementation-specific
suffix.

## R6 Windows SERVER-TEST lifecycle offline acceptance (2026-10-17)

`windows.package-user-lifecycle-offline-contract` is the dedicated R6 package
CTest. On every host it checks the Windows manifest contract, app-local runtime
DLL requirement, duplicate-DLL alias denial and a static denylist proving the
PowerShell lifecycle contains no web download, firewall, service, scheduled
task, autostart or process-launch primitive. It also requires explicit
R2-SSPI/CredSSP and R10 interactive-session blocker text.

On Windows, the same CTest executes PowerShell against a synthetic verified
archive: Install twice, Verify, Status, Start (expected exit **3** with no
listener launch), Stop, Uninstall twice. It also verifies adjacent/internal
SHA-256 enforcement, per-user path confinement, reparse/path traversal denial,
modified-tree refusal and generic fail-only logging without credential-bearing
values. The common `packaging.server-test-cross-platform-offline-contract`
continues to cover exact-SHA three-platform status acceptance.

This is packaging evidence only. It neither changes nor replaces the existing
**59-case** R6 native DXGI/cursor/input selector, and it cannot mint Windows R2
admission or authorize SendInput/capture. R3 DATA publication may be present
and still does not grant native desktop authority.

## R3 Graphics DATA publication and receipt mapping gate (2026-10-17)

The production-backed `transport.dvc-graphics-*` sanitizer inventory is
**15** cases after the DATA publication increment. The nine DATA additions
exercise conclusive-zero cancellation, full multi-record publication,
header-only and payload-positive terminal aborts, stale receipt retirement,
Share-loss abort, malformed DATA_FIRST, wrong DVC channel and exact
DATA_FIRST/DATA reassembly including dropped/duplicated-fragment behavior.
They invoke the real R3 lifecycle and R4 move-only frame receipt but never mint
or fabricate a genuine R2 admission lease.

Every server record must keep one immutable ordered mapping from the complete
R4 `wireBytes()` span to outer plaintext. TPKT, X.224, MCS, static-VC and DVC
header byte counts are separate from R4 payload coverage. Only complete mapped
coverage may complete R4; a conclusively unwritten frame may cancel; stale,
positive-partial terminal, uncertain or mapping-error paths abort. ClearCodec
requires confirmed Graphics capabilities, and AVC420 additionally requires its
explicit negotiated capability flag. The server-advertised static virtual
channel chunk size is authoritative only when the optional field is present at
both endpoints; otherwise the wire limit stays 1600. The client's numeric
VCChunkSize never expands the server-to-client limit.

## R10 outbound-interest regression coverage (2026-10-17)

The Linux runtime-security graph registers three production-backed offline
scheduler cases: `runtime.linux-connection-outbound-write-readiness`,
`runtime.linux-connection-outbound-tls-want-precedence`, and
`runtime.linux-connection-outbound-cancellation-revocation`. Together they
cover initial licensing, positive short-write suffix continuation, Valid Client,
Share and Graphics writes, R1 WANT_READ/WANT_WRITE precedence, invalid retry
direction, cancellation and terminal revocation without creating an admission
lease or starting a listener. The R9 direct runtime-security sanitizer inventory
is **31** cases after including the two native-poll guards and the R10
Connect Response admission-denial check.

## R2 admitted MCS Connect Response security boundary (2026-10-17)

R10's new `LinuxRuntimeConnection::advancePostAdmissionMcsConnectResponseWrite()`
requires the exact R2 private lease and the current R3
`AwaitConnectResponse` owner after an admitted Connect Initial. The
server obtains each bounded R3-owned reply suffix only through the R2
broker's protected transition and sends it with the sole R1 TLS writer.
After positive accepted plaintext bytes, the R2 broker revalidates GSS/TLS
principal, immutable policy, logind monitor and exact native generation
before allowing R3's reply/slice sequence to advance. R1 WANT direction
takes precedence during an unfinished TLS write. Revocation retires R3
first and cancels R1 last.

The existing centrally registered production CTest
`runtime.linux-connection-post-admission-mcs-response-denials` is sufficient
for the offline missing-lease and terminal replay fence; do not duplicate
it with a test-only positive admission. Include it in R9's direct Linux
runtime-security sanitizer selector (30→31) with an exact registry
sentinel. Positive response delivery requires an owner-authorized
CredSSP/PAM/NSS/logind physical X11 session and is NOT RUN. R10 still
needs Erect Domain, Attach User/Confirm, Channel Join/Confirm, Client Info
and its logind watch polling before claiming a complete service lifecycle.

## R2 serialized-connection poll expiry assurance (2026-10-17)

The new production `runtime.linux-connection-native-poll-expiry-revocation`
CTest uses real loopback HYBRID X.224 and a pending server write to prove
the exact R10 native poll deadline revokes R3/R2/GSS/R1 before dispatch.
A later deadline, stale readiness or an admission attempt cannot revive it.
R1's expanded `runtime.linux-connection-pre-admission-native-poll`
already tests actual TLS and rejected CredSSP. Both cases must be selected by
R9's direct Linux runtime-security sanitizer preflight: 28→30.
The tests mint no lease, run no PAM authentication and visit no desktop.

## R2 production preflight denial coverage (2026-10-17)

`runtime.linux-security-personal-desktop-preflight-denials` executes the
production R2 preflight API without a live desktop. It must prove that an
unconfigured security owner, AppServer policy, missing PAM production support,
or nonmatching native identity cannot become admission. The fixture must never
invent positive logind/seat0 evidence or a lease. Positive physical-seat
preflight and authenticated admission remain owner-authorized external tests.

Existing policy-replacement, native-session-change and late-receipt tests remain
the reauthorization evidence; do not duplicate their private positive seams.

## R2 production no-tests configuration/link boundary (2026-10-17)

The production Linux security selector must also be exercised independently of
CTest and every developer-only Linux security switch. A nested configure CTest
is intentionally not used: the root project rejects any binary directory other
than the checkout-local `build/`, while reconfiguring that active build from a
running CTest would mutate shared test state. The dedicated
`r2-linux-production-runtime-security` hosted matrix therefore starts from a
fresh checkout and uses its one permitted `build/` root.

The complete-dependency leg configures `BUILD_TESTING=OFF`,
`RDP_SERVER_BUILD_TESTING=OFF`, both Linux `TEST_*` selectors off and
`RDP_SERVER_ENABLE_LINUX_RUNTIME_SECURITY=ON`, then builds the actual
`rdp-server` executable. It must expose the production
`--check-linux-security` command, carry direct ELF `DT_NEEDED` entries for
GSSAPI/Kerberos, PAM and libsystemd, and have no unresolved `ldd` dependency.
The missing-systemd leg hides pkg-config metadata and requires configuration to
fail with a libsystemd diagnostic. Neither leg loads a keytab, calls PAM,
queries a desktop, opens a listener or authenticates a user.

## R7 optional macOS LaunchAgent remains inert until explicit owner action (2026-10-17)

`packaging.macos-user-launch-agent-offline-contract` executes only the
first-party Python renderer/validator with temporary files. It requires the
fixed per-user SERVER-TEST executable path, Aqua session type,
`RunAtLoad=false`, `KeepAlive=false`, exact label and an exact key set.
Alternate executables, root homes, socket/MachService/environment triggers,
unknown keys, malformed plists and direct writes into
`~/Library/LaunchAgents` fail closed. The helper imports no subprocess/socket
activation primitive and contains no TCC, ScreenCaptureKit or Quartz-input
operation. This CTest is Apple-hosted/offline and must not register or start a job; Linux/Windows retain the existing cross-platform SERVER-TEST archive test.

The macOS SERVER-TEST archive may carry the helper because R9 now packages the
actual startup-disabled `rdp-server` executable. Carrying the helper is not
runtime admission: manual `bootstrap` has no start trigger, and a manual
`kickstart` must still encounter the current fail-closed `serve` command
until R2/R10/R3 secure startup is implemented. Keep the existing focused R7
**21-case** native selection and **2-case** authority-loss input sanitizer
selection unchanged.

## R9 cross-platform SERVER-TEST preview assurance (2026-10-17)

`packaging.server-test-cross-platform-offline-contract` is the portable,
synthetic archive/integrity lifecycle CTest. It validates safe paths, exact
manifest/checksum coverage, secret-marker denial, identical reinstall/removal,
tamper refusal and exact-SHA three-platform status acceptance without executing
a payload or touching a service manager/native desktop.

The hosted protocol matrix performs the real preview smoke only after the full
Release CTest: actual executable ABI, resolved dependency closure,
`--version`, `--help`, safe sample `--check-config`, exit-2 refusal of
unconfigured `serve`, an installation-time loopback bind probe, idempotent
extract/remove, no autostart contract and captured-output credential-marker
scan. R9 then downloads all three artifacts and rechecks the outer SHA-256 and
embedded exact SHA. These are **disabled preview** receipts only.

Sanitizer/test-registry inventories stay unchanged and failure-closed:
R10 runtime-security **28**, R3 Graphics DVC **15**, R4 portable **42**,
ClearCodec **4**, R5 **38**, R6 **59**, R7 authority-loss input **2**, and R8
clipboard **87**. M1 owner-native same-SHA receipts and the M2 three-client
human matrix remain separate from hosted artifact CI.

## R10 Graphics DVC control aggregate stays denial-only without genuine Share authority (2026-10-17)

`runtime.linux-connection-personal-graphics-dvc-r1-io-denials` exercises the
production connection aggregate but must not fabricate a lease, ShareActivated
state or dynamic channel merely to reach R1. It proves an ordinary configured
socket plus PersonalDesktop policy is non-authorizing, wrong product mode is
terminal, and replay after revocation remains closed.

Positive DRDYNVC capabilities, Graphics CREATE, RDPGFX CAPS_ADVERTISE and
CAPS_CONFIRM mechanics and DATA publication stay in R3's 15 production-backed Graphics tests.
R2's separate Graphics late-receipt denial proves a positive plaintext count
cannot cross lost authority. Positive aggregate R1→R2→R3 control I/O is
owner-host only after genuine admission and Share activation. Current control
readiness is not evidence for application DATA publication; that requires the
future R3 DATA_FIRST/DATA sender.

## R10 Share aggregate composition stays denial-only without genuine R2 admission (2026-10-17)

`runtime.linux-connection-personal-share-r1-io-denials` exercises the reusable
production TPKT boundary owner and the production connection aggregate. It may
prove frame reset after synchronous completion, closed-state non-revival,
unadmitted Demand Active denial, wrong-mode denial and replay closure. It must
not fabricate a private R2 lease, stage positive aggregate Share state or drive
a synthetic TLS peer merely to claim positive R10 progress.

Positive Share protocol mechanics stay in R3's production-backed tests,
including Demand/Confirm correlation, mandatory Synchronize and Control
ordering, Font finalization, zero/short write receipts, late input and
retirement. Positive R10/R1→R2→R3 Share I/O requires the owner-authorized
genuine host so TLS progress and native admission are both real.

## R10 Valid Client aggregate writer stays denial-only without real admission (2026-10-17)

`runtime.linux-connection-personal-valid-client-r1-write-denials` exercises
the production connection aggregate and must remain unable to reach an R1 write
without the private genuine R2 lease plus the preceding personal licensing
state. Wrong mode and replay after revocation are terminal. Do not inject a test
lease or bypass R2 solely to make the aggregate writer return positive progress.

Positive wire mechanics remain in R3's production-backed Valid Client tests:
exact packet bytes, zero accepted-byte retry, short positive progress with a new
write-slice generation, and rejection after partial-write retirement. The R10
aggregate adds the ownership proof that only R1 may create an accepted-byte
receipt; owner-host testing is required for positive aggregate partial-write and
WANT retry evidence.

## R2 Graphics DVC authority and late-receipt denial (2026-10-17)

`runtime.linux-connection-personal-desktop-graphics-dvc-authority-denials`
is the production-backed R2 denial for the new post-Share Graphics broker seam.
The fixture stages only R3's `ShareActivated` phase/generation bookkeeping and
binds the non-authorizing PersonalDesktop policy pointer. It creates neither a
Graphics DVC allocation nor an R2 admission lease. A positive accepted-byte
count submitted with no current lease must return `Rejected`, close R3, reject
GSS, revoke the broker and clear policy identity before any R3 DVC receipt can
run. This specifically models a late R1 write completion after logout,
disconnect, monitor revocation or equivalent authority loss.

The direct Linux runtime-security ASan/UBSan selection is now carried forward
into the **25-case** R10 Graphics control selector and still requires this
Graphics authority case by exact name. Positive Graphics CREATE/CAPS mechanics remain
in R3's separate six-case sanitizer gate; neither those tests nor this denial
fixture substitutes for a genuine Kerberos/PAM/NSS/logind physical-session
lease. Real Microsoft-client positive validation remains **NOT RUN** without
explicit owner authorization.

## R10 client-licensing runtime intake stays denial-only without real admission (2026-10-17)

The ordinary runtime CTest for PersonalDesktop client licensing exercises the
production fixed-capacity TPKT owner for incomplete/invalid framing and the
production connection aggregate for unadmitted, wrong-mode and replay denial.
It must not fabricate the private R2 lease merely to reach an R1 SSL read or a
positive R3 transition. Positive licensing mechanics remain covered by R3's
existing PersonalDesktop tests; positive aggregate R1→R2→R3 intake is owner-host
only after genuine Kerberos/CredSSP, PAM/NSS and logind physical-session
admission.

Keep this behavior centrally registered and in each direct Linux runtime
ASan/UBSan selector. Selector cardinality and sentinel names are part of the CI
contract: a regex typo that silently omits a security case is a failure, not an
acceptable reduced selection.

## R2 PersonalDesktop policy/receipt boundary and owner-host positive procedure (2026-10-17)

`runtime.linux-connection-personal-desktop-policy-receipt-denials` is a
production-backed denial test. It proves the broker treats a separately
configured but value-equivalent PersonalDesktop policy as replacement identity,
and that a positive accepted-byte count presented after the lease is gone
closes R3 instead of becoming licensing progress. Its test access stages only
R3 protocol bookkeeping and the non-authorizing policy pointer; it never mints
a lease, authenticates a user or supplies native-session evidence. Together
with the existing personal Valid Client/Share partial-revocation tests, this is
the ordinary-CI late-write fence. The direct Linux runtime sanitizer selection
is **25** cases after the R10 Graphics control increment and must continue to require this sentinel by name.

The genuine Linux positive is **NOT RUN** unless the owner explicitly authorizes
a real host and Microsoft-client session. On that host: use the restricted real
TERMSRV service keytab; obtain genuine Kerberos/CredSSP final credentials only
through protected client/provider input; configure the real approved PAM
service; require the authenticated principal/account to resolve through NSS to
the configured UID and to the physical local X11 `seat0` logind session. After
R2 issues the lease, call `visitNativeDesktopSelection()` and construct the X11
owner only from that borrowed admitted session/seat/display view. Do not use the
configured display string as desktop authority.

Drive PersonalDesktop selection, Server License Request, client licensing,
Valid Client and Share only through R10/R2. Register the broker-owned logind
fd/mask with its exact admission/session generations. For logout/replacement,
remove the poller record first, call `unregisterNativeChange()`, then dispatch
the readiness through `dispatchNativeChangeReady()`. Verify R3 is closed, the
lease and application gate are dead, and any saved write receipt is rejected.
Perform an actual fresh local login and a new Kerberos/CredSSP connection; the
reconnect must receive a fresh aggregate/lease/native selection and may not
reuse the old generations or X11 owner. Record exact client/host versions and
all failures. Never place passwords in source, CMake cache, command-line
arguments, environment variables or logs.

## R9 sanitizer selector grouping must match registered CTest names (2026-10-17)

When an anchored sanitizer selector changes cardinality, require every exact
CTest sentinel and the grouped selector fragment that can actually match its
registered spelling. Do not compress alternatives under a shared prefix unless
every expanded name preserves the literal CTest name.

The direct Linux runtime-security gate now contains eight PersonalDesktop-related
cases:
`runtime.linux-connection-personal-desktop-r3-authority-denials`,
`runtime.linux-connection-personal-desktop-policy-receipt-denials`,
`runtime.linux-connection-personal-desktop-graphics-dvc-authority-denials`,
`runtime.linux-connection-personal-license-request-r1-write-denials`,
`runtime.linux-connection-personal-client-licensing-r1-intake-denials`,
`runtime.linux-connection-personal-valid-client-r1-write-denials`,
`runtime.linux-connection-personal-share-r1-io-denials`, and
`runtime.linux-connection-personal-graphics-dvc-r1-io-denials`.
Their grouped expression is
`personal-(desktop-(r3-authority|policy-receipt|graphics-dvc-authority)|license-request-r1-write|client-licensing-r1-intake|valid-client-r1-write|share-r1-io|graphics-dvc-r1-io)-denials`.
Keep the exact **25-case** count check and sentinel checks before execution. A
cardinality mismatch is a CI/registry assurance failure and must not be
reported as a failing CTest.

## R6 upstream-authority input retirement is no-post (2026-10-17)

`windows.input-sendinput-authority-retirement-no-native-post` exercises the
production `WindowsInputController::retireWithoutNativeInput()` seam without
creating R2 admission, R3 Share authority or host input. It proves held
key/button state is discarded while the native generation is still current,
authority loss requested reentrantly from an already-entered native callback
allows no later cleanup post, and retirement requested during generation
observation stops before the native callback. Existing
`windows.input-sendinput-lifecycle` continues to prove graceful cancellation
may release held state while authority remains current.

The current anchored R6 selector is exactly **59** cases. Debug, Release and
CLANG64 ASan/UBSan preflights must require this authority-loss sentinel in
addition to the four whole-owner retirement sentinels and three DXGI-to-R4
sentinels. This case is revocation-only and cannot stand in for a positive
Windows admission capability.

## R8 R3-channel retirement is a revocation test, not synthetic authority (2026-10-17)

`clipboard.r3-channel-retirement-revokes-state` exercises the production
revocation-only R8 seam with fresh joined-channel gates that deliberately reuse
the same numeric CLIPRDR ID. It must prove old format-write receipts,
FileContents request/stream correlations, verified native-ready bytes, pending
paste receipts and destination-plan associations cannot cross retirement, while
monotonic receipt/stream identities do not ABA when the clipboard generation
number repeats.

This test does not manufacture R2 admission, licensing or Share activation and
does not duplicate File List hierarchy parsing or native adapter tests. Existing
Windows/macOS generation-owner-loss cases and X11 disconnect/late-paste fences
remain the production-backed native publication retirement coverage. Live
positive CLIPRDR testing waits for R3's genuine activated authority.

## R8 hierarchy-provenance tests are structural and non-authorizing (2026-10-17)

Test relative File List hierarchy only through production descriptor parsing and
generation owners. Positive cases prove exact descriptor-index parentage,
directory attributes, bounded depth and leaf-only public names. Negative cases
cover duplicate nodes, missing explicit parents, file-as-parent,
caller-placement cycles, excess depth, absolute/UNC/drive/traversal syntax and
generation replacement. When hierarchy verification fails, assert no hierarchy
node is observable while otherwise-valid flat descriptors remain usable.

Do not create local children, traverse directories, open user paths or use a
live clipboard in ordinary hierarchy tests. Native directory capability tests
remain duplicate/close-only. Keep every hierarchy CTest under the broad
`clipboard` label and require its sentinel name in R9's complete clipboard
sanitizer preflight.

## R6/R4 production-ingress convergence (2026-10-17)

The three existing `windows.capture-r4-*` CTests now execute R4's production
`X264Avc420SegmentedFrameProducer::openBgraCapture()/prepareBgra()` interface,
not only its converter primitive. The R4 lifecycle is configured solely inside
the offline test process to make codec/ownership state executable; it is not a
production Share/DVC admission seam and must never be used to authorize live
DXGI access.

The layout case prepares real x264/RDPGFX owned output while the injected D3D11
mapping is live, then observes R6 unmap -> DXGI release and retires the
unsubmitted R4 output with exact unwritten cancellation. The session-revocation
case changes the R6 session generation after synchronous R4 preparation,
requires the outer R6 result to be terminal, and cancels the now-stale prepared
R4 owner before any submit. The replacement case proves a same-geometry device
epoch replacement suppresses the old callback, requires an independently
advanced R4-local capture epoch for the fresh native owner, and exercises the
same cancellation rule when a resize retires the native cycle from inside the
callback.

These tests do not invent R2 authorization, R3 licensing/Share activation,
DRDYNVC/Graphics-DVC ownership, network receipts, WTS delivery or
`SendInput`. That convergence increment left the anchored R6 registry at
**58** cases; the later authority-loss input retirement case raises the current
registry to **59** without changing these three DXGI-to-R4 cases.

## R4 native BGRA ingress compatibility gate (2026-10-17)

R4 keeps `FramebufferView` as the shared borrowed pixel representation.
Platform roads keep native generation authority: R6 carries its validated
session/device pair and R7 its display-geometry/post-consumer retirement fence.
Composition may opt into an additional R4-local capture epoch with
`openBgraCapture()`; do not pack/hash richer native identity into this scalar.

Generic `open()` remains compatible with already generation-fenced callbacks
at epoch zero. `openBgraCapture()` requires a nonzero exact matching epoch,
checked before framebuffer dereference. In either path require exact visible
width/height, nonzero even visible geometry, B/G/R/ignored-alpha bytes, stride
>= `width*4`, and a span covering every pitched row with checked arithmetic.

Focused R4 tests cover padded scanlines, minimum even geometry, source
retirement after synchronous encode, truncated/overflow layouts,
width/height/stride mismatch, zero/stale/future epochs, surface resize,
full-delivery P continuity, exact unwritten cancellation followed by IDR,
terminal abort and fresh reconnect IDR. If a platform post-consumer generation
check rejects after preparation, submit no R3 bytes; cancel that exact unwritten
frame before rebinding a replacement epoch.

Dedicated cases are `graphics.x264-native-bgra-frame-ingress`,
`graphics.x264-native-bgra-resize-recovery`, and
`graphics.avc420-capture-generation-denials`. R9 must enumerate exactly
**27** x264/BGRA cases and require all three names. Portable R4 wire/lifecycle
contains **42** cases, including the segmented-data u32 boundary denial.

## R3 existing-CAL authority-request tests remain non-authorizing (2026-10-17)

The R3 existing-CAL snapshot/borrow boundary has five ordinary production-backed
CTests: ownership, HWID-proof gate, product/correlation denials,
revocation/replay, and the synchronous live-visit lifetime gate.
Positive assertions may prove only production cryptographic proof creation,
exact bounded snapshot ownership and continuity. Test CAL bytes remain opaque
and cannot stand in for a genuine issuer decision.

R9 sanitizer CI enumerates
`^transport\.licensing-existing-cal-authority-request-`, requires exactly
four registrations and all four behavior names, then executes that selection.
This is intentionally separate from both the large cross-road licensing regex
and R10's `^runtime\.licensing-existing-cal-` six-case authority selector.
Malformed CLIENT_LICENSE_INFO framing, empty/oversized CAL request payloads,
altered protected HWID, wrong product/scope/correlation/generation, duplicate
completion, cancellation and late replay must all fail closed.

## R7 macOS capture-to-R4 ingress tests preserve the native commit point (2026-10-17)

The Apple-only R7 compatibility cases may link the existing noninstalled
`rdp-server-graphics` target from `test_macos_capture_stream`, but production
`rdp-server-macos-capture` must remain independent of R4/x264. Exercise only
the existing injected ScreenCaptureKit backend and synthetic CoreVideo buffers;
never expose the quarantined native factory, query/request TCC as test
authorization, enumerate a live desktop or post native input.

A `FramebufferView` remains borrowed only for the synchronous
`MacCaptureFrameConsumer::consume` call. Tests should release the caller's
CoreVideo reference during that call to prove `LockedBgraPixelBuffer` retains
and read-locks storage through R4 conversion/encode, then prove the encoded R4
owner survives after source release without retaining the borrowed BGRA span.
Padded row stride and physical Retina backing dimensions must reach the real R4
BGRA ingestion unchanged.

The post-consumer R7 generation/topology/session check is the publication commit
point. If the consumer has already prepared an R4 frame but the outer
`consumeFrame` returns `RetireStream`, that R4 frame is conclusively
unwritten and must be canceled through the existing R4 cancellation contract
before any R3 handoff. Only `Published` is eligible for later transport.
Synthetic TCC denial/native-failure callbacks prove fail-closed state only;
they are neither R2 admission nor evidence of an actual permission revocation.
When R4's optional capture epoch is exercised, bind the current R7 geometry
generation as capture freshness but keep the synthetic/real R4 presentation
generation distinct. Neither scalar is native authentication or R3 authority.

## R6 CLANG64 native-preflight registry correction (2026-10-17)

The ordinary CLANG64 Debug and Release R6 preflights must independently
enumerate `^windows\.(geometry|capture|cursor|input)-`, require exactly
**59** registrations, require the authority-loss no-post sentinel, the four
whole-owner retirement sentinels and the three DXGI-to-R4 handoff sentinels,
and only then execute the selection.
Do not concatenate sentinel names into one literal search and do not rely on
the sanitizer-only cardinality check to prove ordinary configuration
registration.

## R6 DXGI-to-R4 native framebuffer compatibility tests (2026-10-17)

The Windows R6 selector includes three production-backed cross-road cases:
`windows.capture-r4-bgra-layout-contract`,
`windows.capture-r4-frame-lifetime-revocation`, and
`windows.capture-r4-monitor-replacement-denials`. They use injected
DXGI/D3D11 callbacks only and must never enumerate/capture a live desktop or
invoke host input.

The layout case feeds a padded native BGRA mapping through
`consumeR4Frame()` into the real R4 `BgraNv12Converter` while the mapping is
still alive, checks the pinned session/device generation, and requires
unmap-before-`ReleaseFrame`. It also proves a cycle without explicit
generation provenance cannot use the R4 seam.

The lifetime case changes the session generation during the synchronous R4
conversion. The consumer may have observed/copied bytes, but the outer call
must return terminal `closed`, retire staging then the DXGI lease, and never
report a publishable frame. The monitor/resize case separately changes the
device epoch with unchanged geometry and mutates topology during a callback;
both retire the old cycle without stale publication.

The anchored Windows selector is now **59** cases. Hosted CLANG64 sanitizer
preflight must require all three DXGI-to-R4 sentinel names, the authority-loss
no-post sentinel and exact 59-case cardinality before ASan/UBSan execution.
Existing whole-owner COM-order and WTS/session revocation tests remain
unchanged and mandatory.

## R4 segmented-frame retirement reuse is symmetric (2026-10-17)

For a non-overwriteable `GfxAvc420SegmentedFrame`, test every successful
receipt-retirement path as an owner-consumption boundary. Exact completion,
terminal abort and exact unwritten cancellation must invalidate the object and
release its wire span; short/stale/wrong retirement must preserve it. Reuse the
same output slot after completion and after a fresh generation following abort.
For the x264 producer, additionally prove successful completion preserves
reference continuity (next frame remains P) while terminal abort resets the
encoder (fresh generation begins IDR).

These behaviors run in ordinary CTest and the R9 sanitizer preflights. The
portable R4 selector contains **41** cases and the x264/BGRA label **24** after
this increment.

## R4 owned segmented outputs cannot be silently replaced (2026-10-17)

A valid `GfxAvc420SegmentedFrame` output is an occupied receipt owner.
Preparing another frame into it must fail before lifecycle reservation, BGRA
conversion or x264 reference advancement; existing bytes/generation/frame ID
remain unchanged and the other lifecycle remains reservable. After explicit
retirement invalidates the owner, the same slot may be reused.

Keep the frame move-constructible for the eventual R3 handoff but statically
prove it is not move-assignable. The x264 regression compares the next accepted
publication with an independent control encoder. Both behaviors belong in
ordinary CTest and the R9 portable/x264 registry preflights.

### Explicit broad Windows ACEs must be normalized, not tolerated

`/inheritance:r` is not sufficient evidence of a private synthetic file:
some Windows creation contexts can retain explicit broad-principal ACEs.
After inheritance removal, the shared fixture helper removes allow grants for
Everyone, Authenticated Users, Built-in Users, Guests, Anonymous, Interactive
and Network before granting the current owner. Any remaining unknown allow
principal fails descriptor verification. Permission-denial tests may re-add
only the exact broad ACE required for the negative case.

## CLANG64 cross-road failures do not suppress security evidence

The hosted Windows CLANG64 job remains fail-closed as one job, while road-local
evidence steps continue after unrelated test failures when their configure/build
prerequisites succeeded. Use explicit `always()` conditions bound to named
configure/build step outcomes. A failed R6 focused test, R10 fixture test or full
Debug CTest must remain a job failure, but it must not by itself suppress the
other road's independently buildable Debug/Release fixture evidence.

Never run a CTest selection after its build prerequisite failed and never claim
a skipped step as evidence. The same-root Debug-to-Release reconfiguration rule
remains mandatory; no additional persistent build root is permitted.

## R6 Windows CLANG64 native lifetime sanitizers (2026-10-17)

The hosted Windows CLANG64 gate must instrument the production
`rdp-server-windows-desktop` graph and `test_windows_desktop_geometry`
with Clang AddressSanitizer and UndefinedBehaviorSanitizer after the ordinary
Debug/Release compiler gates complete. Reconfigure the same checkout-local
`build/` root to Debug with `-fsanitize=address,undefined`,
`-fno-omit-frame-pointer` and fail-on-first-error recovery disabled; do not
create a parallel sanitizer build directory.

The sanitizer execution is deliberately limited to the existing deterministic
R6 selector `^windows\.(geometry|capture|cursor|input)-`. Enumerate that
selector before execution, require exactly **55** registered behaviors and the
four whole-owner session-retirement sentinels, then run all selected tests.
This gate must exercise production Windows adapter code with synthetic native
callbacks only: no live desktop capture, WTS notification registration,
`SendInput`, credentials or interactive user-session access.

A sanitizer-runtime or compiler-rt/linker failure is toolchain evidence and
must be reported separately from a production lifetime assertion failure. The
configure, build and execution stages carry explicit fail-closed step IDs and
`always()` fences: an unrelated earlier full-suite failure may not suppress
R6 sanitizer evidence, while a failed sanitizer configure/build must prevent
the dependent stage from running. A green run is memory/UB evidence for the
exercised synthetic Windows ownership paths only; it is not owner-machine M1
evidence and cannot count as M4 desktop/client acceptance.

## R7 hosted Apple lifecycle evidence is failure-isolated, not failure-masking

The primary macOS protocol job remains the authoritative full Debug/Release
suite. In addition, `r7-macos-native-lifecycle` must independently compile the
four production-backed R7 macOS test targets and run the required twenty-case
registry-preflighted selection in Debug and Release from one build root. This
job exists so an unrelated protocol failure cannot erase R7 Release evidence;
it must not use `continue-on-error`, alter full-suite status, request TCC
permission or substitute for owner macOS 27 M1 evidence.

The workflow structure validator must require this job plus sentinel names for
the display-generation fence and Apple capture generation/session retirement.
A green isolated R7 job alongside a red full protocol matrix means only that the
R7 lifetime boundary passed; M1 remains red/open until the full same-SHA matrix
and owner-native rows pass.

## Windows CLANG64 private-fixture security preflight

The hosted MSYS2 CLANG64 parity job must make the Windows synthetic-DACL
boundary independently observable before counting the full suite. After the
complete Debug and Release test graph is built, enumerate
`^runtime\.windows-private-fixture-` with `ctest -N`, require exactly three
registrations and all dedicated R10 fixture names, then execute that exact
selection.

In the same preflight, require and execute representative production-backed
cases for licensing secure-file snapshots, licensing CLI provisioning, the
private Windows configuration DACL, private TLS-file metadata and the owned
runtime TLS handshake. This focused gate supplements rather than replaces the
ordinary full CTest run. A missing registration, failed private ACL setup,
unexpected broad ACE result, or reduced selection is failure; never skip,
exclude or relabel it to preserve a green M1 matrix.

Negative broad-access cases remain valid only when the shared fixture helper
first verifies a private baseline and the production runtime subsequently
returns the documented configuration-security denial. Hosted CLANG64 evidence
does not substitute for the owner's same-SHA MSYS2 CLANG64 / Clang 23 run.

## Windows synthetic private-file fixtures use SID-native ACL setup (2026-10-17)

Windows CTest fixtures that must satisfy production credential-file DACL checks
share one test-only ACL helper. Resolve the current Windows SID rather than
granting by localized account text, convert CMake paths to native absolute
paths, and prefer the System32 native security tools. Treat owner assignment,
inheritance removal and grant replacement as distinct operations: do not
perform `/setowner` when a newly created synthetic file already belongs to
the current SID, and never assume a non-elevated process can change ownership.

After mutation, inspect the resulting security descriptor. A private baseline
must have inheritance protected, the expected current owner, an explicit owner
FullControl allow ACE, and no allow principal outside the owner, LocalSystem or
Administrators. If the filesystem cannot provide that descriptor or any native
operation fails, the test fails closed and reports executable, native path,
operation, exit code, stdout and stderr. Do not skip the test, grant broad
access, elevate the server, or weaken production
`hasRestrictedCredentialDacl()` checks.

Negative permission fixtures start from that verified private baseline and only
then add the exact unsafe Everyone, Authenticated Users or Built-in Users ACE
required by the case. Their success condition remains production rejection of
the insecure file.

## R7 hosted Apple lifecycle coverage must fail closed

The ordinary hosted macOS protocol matrix must make Apple-only R7 lifetime
coverage independently observable in addition to the full CTest suite. After
both Debug and Release compilation, run a focused anchored selection and first
enumerate it with `ctest -N`. The registry preflight must require the exact
same-dimensions geometry-generation case; capture generation, callback,
consumer, native-stop, backend-reentry, late-start and session-watch retirement
cases; capture-to-R4 BGRA layout, pixel-lifetime and display-generation cases;
cursor session/topology/generation freshness; input session-watch
revocation; and GUI-session switch/mid-operation/watch-race/destructor
retirement. A missing required name is a CI failure rather than silently reduced
coverage.

The macOS job must also record `sw_vers`, `xcodebuild -version`,
`xcode-select -p`, `xcrun clang++ --version` and the active macOS SDK
version so an exact-SHA receipt identifies the hosted Apple environment. This
metadata and the focused synthetic tests are not owner macOS 27 evidence, TCC
grant evidence or M5 live-desktop acceptance. The full Debug/Release CTest
remains authoritative and still runs after the focused selection.

## Supported focused selectors assert exact registry cardinality

When a hosted profile intentionally provisions every optional dependency needed
for a road's focused native selector, its `ctest -N` preflight must verify
the exact expected registration count in addition to representative behavior
names. A smaller green selection is missing coverage, not success. Count only
the selected CTest entries, then execute the same anchored selector.

Do not turn optional local development packages into unconditional build
requirements merely to make the count universal. The exact-count assertion
belongs to the supported fully provisioned profile; dependency-reduced local
builds may retain their documented conditional registrations. Update the count,
selector and relevant named sentinels atomically when an intentional behavior
is added or retired.

## CI structure shell self-test diagnostics (2026-10-17)

The workflow structure self-test must prove both sides of shell handling:
explicit PowerShell is a positive fixture and malformed Bash remains a negative
fixture. The malformed Bash oracle keys on the stable diagnostic category
`syntax`, not the incidental word `shell`; the validator still executes
`bash -n` and still requires that malformed fixture to fail.

## CI workflow structure tests fail closed before heavyweight validation

The primary GitHub Actions workflow is executable project policy, not disposable
YAML. Keep one repository-local structural validator under `scripts/` and one
behavior-named CTest, `project.ci-workflow-structure-denials`. Its positive
fixture must parse; negative fixtures must cover duplicate job mappings,
unterminated shell selectors and malformed GitHub expression delimiters.

The validator must also require sentinel registrations/build targets from every
road sharing the sanitizer workflow, both bounded fuzzers, and prerelease
ancestry/version/digest/publication gates. Never repair a corrupted region by
restoring an older whole-workflow snapshot: reconcile from current `main` so
concurrent selectors cannot disappear. Critical sanitizer/fuzzer selections
must enumerate the central CTest registry with `ctest -N` and require named
tests before instrumented execution; zero selected or `Not Run` is failure,
not coverage.

Use a real YAML parser with duplicate-key rejection when one is already
available. The dependency-free lexical/job checks remain authoritative so the
policy test does not silently disappear on hosts without an extra Python
package. Validate Bash block scalars with the shell parser where Bash exists.
An independent minimal structure-guard workflow should validate the primary
workflow on main pushes so a future syntax error in the large workflow still
produces an observable CI failure.

## R6 Windows CLANG64 lifetime/compiler gate (2026-10-17)

The Windows Clang 23 gate must build the production
`rdp-server-windows-desktop` graph and the existing
`test_windows_desktop_geometry` fixture under MSYS2 CLANG64 with
`-Wall -Wextra -Wpedantic -Werror`. Before executing the selector, enumerate
it with `ctest -N` and fail if any whole-owner session-change registration is
missing. Execute `^windows\.(geometry|capture|cursor|input)-` in both Debug
and Release, then execute the ordinary full CTest in both configurations.

The focused gate must retain the existing ownership assertions: staging unmap
before frame release, frame/cycle retirement before parent COM release,
duplication/output/context/device/output/adapter/factory exact-once ordering,
terminal session-generation revocation, callback-time deferred teardown, and
held input cancellation with no post-revocation native send. Do not replace
these with compile-only probes or weaken them for a compiler.

Ordinary CLANG64 CTests remain synthetic and must not register for live WTS
notifications, call host `SendInput`, open an authorized desktop or capture
real screen content. A Clang/MinGW header or import-library incompatibility must
be identified separately from a production lifetime failure.

## R2 delegated-account credential tests (2026-10-16)

## R10 licensing-authority sanitizer registry (2026-10-17)

The service-owned licensing-authority boundary keeps issuance and existing-CAL
validation as two flat sanitizer selections rather than extending the already
large cross-road R1/R3 licensing expression. The existing
`^runtime\.licensing-authority-` group must retain its six centrally
registered behaviors: unavailable denials, issuer/policy correlation,
generation/revocation, result bounds/cancellation, sensitive retirement and
real-process startup isolation.

Existing-client validation uses the separate flat
`^runtime\.licensing-existing-cal-` selector. The workflow must enumerate
exactly six registrations before execution:
`runtime.licensing-existing-cal-provider-unavailable`,
`runtime.licensing-existing-cal-request-correlation`,
`runtime.licensing-existing-cal-policy-generation-revocation`,
`runtime.licensing-existing-cal-result-retirement`,
`runtime.licensing-existing-cal-connection-unavailable-denial`, and
`runtime.licensing-existing-cal-connection-cross-generation-cancellation`.
The two connection-binding cases are denial/cancellation-only: the existing
test provider may keep one request pending solely to prove generation
cancellation, but it must not produce a positive decision. A missing name,
wrong cardinality, selector compile failure, Not Run result or zero-test run is
a CI failure rather than validation evidence.

The positive provider used by both groups is defined only in the test
translation unit and reaches production lifetime logic through a private friend
seam. It must never be linked into `rdp-server`, exposed as runtime
configuration, or described as genuine CAL issuance or validation authority.
## Personal-desktop protocol and policy sanitizer gates (2026-10-17)

Personal-desktop licensing mechanics never substitute for native admission.
The sanitizer job must explicitly enumerate and execute exactly **six** R3
`transport.licensing-personal-*` / `transport.share-personal-*` behaviors,
including `transport.licensing-personal-mode-and-malformed-denials` and
`transport.share-personal-activation-denials`. These cases may verify
MS-RDPELE Valid Client and Share ordering, but they must not construct a genuine
private R2 lease or expose desktop/input authority.

R10's configuration-only deployment policy is a separate **two-case** sanitizer
selection. Build `test_runtime_deployment_policy` under ASan/UBSan and require
both `runtime.personal-desktop-policy-immutable-denials` and
`runtime.personal-desktop-loopback-listener-denials`. Wrong mode,
non-loopback/wildcard addressing, invalid port/listener combinations and policy
mutation remain fail-closed. A policy object, loopback candidate or positive
protocol fixture never authorizes desktop access.

Production `configureUnavailable()` must remain unable to produce a positive
existing-CAL decision. The startup-isolation case executes the real process and
reuses the existing CLI oracle, proving that the test seam cannot bypass normal
startup refusal or any supported offline preflight.


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

## File-destination-plan tests separate metadata from native authority

Destination-plan coverage must use the real `RemoteTransfer` descriptor list
and exact remote descriptor indices. Build at least two same-name descriptors
to prove names do not collapse identity, then exercise nonzero generation,
source replacement and disconnect/reconnect generation-number reuse. A plan
test must not construct a local path from the remote leaf name.

Batch preparation is all-or-nothing: cover out-of-range/duplicate source
indices, zero/duplicate local selection identities, incomplete and over-64
manifests, later-member failure, one-shot recommit, idempotent close and stale
source retirement. When explicit caller placement parents are represented,
cover missing/self/file parents, ambiguous duplicate placement, cycles and the
fixed depth bound. A directory mapping may exist as metadata only and must
return an explicit unsupported-materialization result.

Traversal syntax belongs at the parser boundary, not in a planner sanitizer.
Exercise slash/backslash, parent traversal, absolute/drive/UNC-like names,
embedded-NUL tails and malformed UTF-16 against the production
FILEDESCRIPTORW parser; then verify the planner sees only already-retained leaf
metadata. Caller parent relations are local placement choices, never evidence
of remote tree fidelity.

At least one native integration case must pass a planned descriptor index to an
existing platform destination and separately supply the real caller-selected
native writable capability. Deliberately passing the plan's numeric selection
identity as that capability must fail. Cancellation must retire partial native
state while `RemoteTransfer` drains any exact in-flight receipt, and a late
success must not make the plan or destination publishable. Sanitizer CI must
enumerate every dedicated plan CTest before the full clipboard-labelled run.

## Directory-capability tests separate native authority from hierarchy

A directory-role `RemoteFileDestinationPlan` association remains metadata
only until an independently supplied native directory capability is duplicated.
Test the capability lifetime boundary with the real descriptor manifest and a
native-operation seam: reject a file-role association before any duplicate,
deliberately pass `localSelectionIdentity` as the native token and require
rejection, then succeed only with a distinct caller-authorized token.

Once bound, cover plan cancellation, source generation replacement and explicit
local cancellation. Each terminal path must close the owned duplicate exactly
once and must not resurrect after repeated currentness checks, cancel or close.
The binding itself must expose no path or child-creation operation.

Do not describe a successful directory-capability bind as directory
materialization or hierarchy support. Until verified parent/child provenance is
available, `UnsupportedDirectoryMaterialization` remains the transfer result.
A later relative-creation test must prove component-level traversal/symlink or
reparse denials against the actual native implementation; pathname-based reopen
is not an acceptable substitute for a held directory capability. R9 sanitizer
CI must enumerate every directory-capability CTest before the complete
clipboard-labelled run.

## Native directory-capability tests inspect objects, not paths

Each platform factory must have a dedicated native CTest. The positive fixture
may open only an existing build/CTest working directory and must pass that
already-open object into the production duplicate seam. The negative fixture
must use an unmistakably wrong native object type, such as an anonymous pipe,
so rejection does not depend on pathname parsing.

For POSIX, verify the duplicate itself is a directory descriptor and is
independently closeable. For Windows, query the duplicated HANDLE as a
directory object. Then bind through the production
`RemoteDirectoryCapabilityBinding`, retire the caller's original object, and
require the plan/generation binding to remain current until the owned duplicate
is explicitly retired.

Do not use a symlink pathname as proof of creation safety: the duplication
contract has no child traversal. Symlink/reparse race tests belong to the later
component-relative creation API and must exercise that API directly. R9 must
fail closed on the Linux native registration before the complete clipboard
sanitizer run.

## Multi-file clipboard handoff tests prove atomic completed-set visibility

For a multi-file native handoff, materialize at least two files through the
real one-at-a-time `RemoteTransfer` FileContents path. Require publication to
fail while any member is partial, then verify the entire completed set appears
atomically. Supply the completed objects out of order and require the committed
destination plan's exact remote-index order at the native boundary. Cover
duplicate destination membership/local metadata rejection, exact native list
delimiters, same-generation owner takeover or set mutation denial, plan
cancellation and stale-generation refusal.

Keep file bytes in ordinary build-root fixtures and clipboard operations behind
the existing injected native seam. The test must not imply directory hierarchy:
current FILEDESCRIPTORW validation preserves leaf metadata only. Real
file-manager/portal directory-tree acceptance remains a separate live gate.

## Windows completed-file handoff tests stay host-clipboard free

Exercise CF_HDROP handoff through the production Windows destination and clipboard-adapter state machines with injected clipboard callbacks. Ordinary CTest must never call the real host clipboard. Require: no publication while any selected destination is partial; exact completed caller path retention; `DROPFILES.pFiles=20`, `fWide=TRUE`, one NUL-terminated fully qualified UTF-16 path per planned index plus the final list NUL; reversed caller span order normalizes to plan index order; duplicate membership is denied before native mutation; relative/device-path metadata rejection occurs before native destination duplication; local owner takeover has same-generation reclaim denial; and stale-generation refusal.

Keep the real Win32 `GlobalAlloc`/`SetClipboardData` branch to hosted Windows compile/link coverage unless a separately authorized native acceptance test is requested. Synthetic CF_HDROP success is not Explorer paste acceptance or authenticated Microsoft-client file-copy proof. The R9 sanitizer preflight must enumerate both
`clipboard.windows-completed-file-hdrop-handoff` and
`clipboard.windows-completed-multi-file-hdrop-handoff` before running the
complete clipboard label.

## macOS completed-file set tests publish one NSURL array

Exercise multi-file pasteboard handoff through the production macOS destination
and clipboard-adapter state machines with injected pasteboard callbacks.
Materialize every file independently, require zero native replacement while any
member is partial, then pass the completed destinations in reverse order and
require one replacement containing file URLs in plan index order. Duplicate
destination membership, stale/cancelled plans, reentrant plan cancellation and
same-generation local takeover must deny without leaving a partial remote
pasteboard publication.

The injected native content exposes only borrowed URL views for the synchronous
call; test code copies them solely to inspect the native boundary. Apple hosted
builds compile/link the real AppKit conversion to multiple NSURL objects, while
ordinary CTest never reads or writes the live general pasteboard. The sanitizer
preflight must enumerate
`clipboard.macos-completed-multi-file-url-handoff`.

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
existing deferred physical teardown. For a parent-owned cycle, additionally
require the real `WindowsDxgiDuplicationOwner` to remain logically terminal
while retaining the child object and parent resources until the outer capture
operation returns. An early `completeDeferredClose()` from inside the callback
must be harmless; the same serialized safe-point call after return must then
destroy the child and release parent resources exactly once. Keep the owner
object itself alive across that callback/safe-point boundary.

Whole-owner fixtures must use injected frame/staging callbacks rather than
calling SDK methods through fake COM addresses. Verify guard -> input ->
capture retirement ordering, unmap before frame release, child retirement
before parent duplication release, the established parent COM order, and
idempotent duplicate notification/close. A synthetic injected staging seam
does not independently prove native D3D11 context destruction; document that
scope instead of fabricating a COM oracle. Keep orderly input shutdown as a
separate case: held keys/buttons are best-effort released exactly once only
while the original pinned generation remains current.

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


Authority-loss retirement is distinct from graceful disconnect. A graceful
shutdown or RandR replacement may best-effort release held keys/buttons while
the same input authority is still current. Once R2/R3 input authority has
failed, R5 must discard its held-state bookkeeping and invalidate the borrowed
XCB endpoint without issuing any XTEST request. The dedicated
`x11.input-native-authority-retirement-no-native-post` fixture uses only a
fresh Xvfb server: establish controlled held key/button state, snapshot it,
invoke the production no-post retirement, and require the X server state to
remain unchanged across repeated retirement/disconnect. The ephemeral X server
is destroyed with the fixture; never run this proof against a logged-in display.


## R5 owner-authorized Linux/X11 M3 acceptance

Live M3 is an explicit opt-in and is never part of ordinary CTest. Run it only
after the project owner authorizes real desktop capture/input for the exact
shared-main SHA, hosted CI is green, genuine R2 Linux admission is available,
R10 has composed that admission into the serialized runtime, and R3 has
activated Share plus its authenticated Graphics/input routes. If any
prerequisite is absent, record **NOT RUN**; do not substitute Xvfb, configured
`DISPLAY`, a generation scalar, or a synthetic admission fixture.

Use a disposable physical `seat0` X11 login containing only controlled test
content. R10 must enter through
`LinuxRuntimeConnection::visitNativeDesktopSelection()`. Inside that
synchronous callback require a nonempty session ID, exact `seat0`, the
R2-observed local X11 display, and nonzero admission/session generations, then
construct exactly one `X11DesktopResources` from that display. Do not copy the
selection strings into a second authority object; retain only the generations
needed to correlate later R2/R3 reauthorization. If R2's post-callback
revalidation fails, retire the just-created X11 owner without publishing or
injecting anything.

### Ubuntu 24.04 / GNOME 46 / Xorg physical-seat run sheet

This run sheet is prepared for the first real Linux desktop acceptance.
R2 genuine positive current-owner authority and R10's provisioned GUI listener
Start have now landed. The run remains **BLOCKED / NOT RUN** at the next R10
boundary: the GUI-owned `OwnedLanListener` is not yet serviced into the
existing `LinuxRuntimeConnection` / persistent R2-selected X11 loop. A
successful Start, `listenerReady`, bound endpoint, or matching TLS identity is
transport readiness only and is not accepted-client, R2 admission, native-owner,
frame, or input evidence. Canonical M1 remains the same-SHA owner-native
build/CTest matrix; preparing this physical run does not advance or redefine
M1. Do not substitute Xvfb, a configured `DISPLAY`, `LockedHint=no`, a test
fixture, a debugger write, a patched success Boolean, or a second accept loop
for the missing live-service gate.

Before allowing the client to connect, record the exact source SHA and client
build, then use the GUI's **Refresh Linux X11 prerequisites** read-only report
to record the current process UID, `XDG_SESSION_ID`, logind session UID,
`Seat`, `Type`, `Active`, `Remote`, `State`, advisory
`LockedHint`, and `DISPLAY`. Record the GUI-selected R10 LAN interface
stable ID, address and port separately. After a genuine provisioned Start,
refresh R10 status and record the reported bound LAN endpoint plus the existing
TLS identity/fingerprint observation; require the endpoint to match the selected
interface/address/port and the TLS state to remain bound/current. This is now a
real pre-client transport checkpoint, not permission to connect. Do not attempt
a Microsoft-client connection until R10 accepted-socket servicing is wired to
the existing serialized connection/native loop. `LockedHint=yes` is negative
evidence and the run must not proceed; `LockedHint=no` is only advisory and
never satisfies R2 owner consent or authoritative unlock.

There is deliberately no pre-connection R5 capture generation. Creating an
`X11DesktopResources` owner just to obtain one would cross the native
authority boundary before R2/R10 permit it. Record that field as **unavailable
by design** in the pre-connection evidence. After genuine R2 admission and
inside the existing R2-selected native-owner lifetime, but before the first
frame publication, record the R2 admission/session generations and the
read-only `sourceGeometry()` / `captureGeneration()` values from that
single owner. Record numbers and dimensions only; never pixels, credentials or
input payloads.

Use a controlled local test surface containing no private content. With one
Microsoft client connected, execute this bounded operator sequence:

1. Confirm the initial visible frame is the current physical desktop, not a
   stale/test frame. Correlate the current capture generation with the existing
   R4 first-ClearCodec/exact-write/genuine-FRAME_ACK acceptance status.
2. Move the pointer, then perform one left click and one right click in the
   controlled target. Confirm each event is accepted only through the existing
   R2/R3 protected R5 route.
3. Type ordinary keys and exercise at least Shift plus one other implemented
   modifier. Do not claim unsupported E1/Pause, Unicode or relative input as
   positive behavior.
4. Disconnect and verify the controlled target shows no stuck key or button.
   For authority-loss disconnect, require zero compensating XTEST cleanup after
   revocation.
5. If practical, perform one RandR resize or topology replacement. Record old
   and new geometry/capture generations, require stale old-generation work to
   be rejected, and require the replacement generation to produce the next
   current frame.
6. Invoke Stop and verify listener/client/native ownership retires. Reconnect
   only after a fresh genuine R2 authorization and prove no old watcher,
   session/capture generation, frame or input state is reusable.

For failure routing, collect only the existing read-only/fail-only facts.
Classify **X11 capture/native owner** when R2/R3 authority and the expected
generation are current but the single `X11DesktopResources` owner becomes
invalid, reports `failureReason()`, or its XShm capture fails. Classify
**generation freshness** when the session generation, geometry observation or
capture generation no longer equals the live owner (including RandR
replacement); stale work being rejected is expected behavior, not an input
authorization defect. Classify **input authorization** when capture freshness
is current but the per-event R2/R3 protected input transition denies before
XTEST. If the native XTEST controller itself fails after authorization, record
that separately as an R5 native-input defect rather than weakening or bypassing
R2. Do not add packet dumps, screenshots, key logs, a second XCB connection or
a synthetic authority seam merely to improve diagnostics.

The event loop registers only R2's borrowed logind fd/mask record. It never
duplicates or closes that descriptor. Before any connection revoke or watcher
dispatch, remove the exact registration from the external poller first; then
acknowledge unregistration and dispatch readiness. Late queued records must be
matched against the exact admission/session registration and discarded after
retirement. A kernel fd number reused by a later connection is not identity.
On logout/session replacement, retire R5 on the same serialized owner thread:
held XTEST input first, then XI2/Damage/XShm, then the sole XCB connection.
Do not destroy the owner concurrently with a synchronous XShm→R4 callback.

For each supported client, record the exact client build and execute the same
bounded sequence independently: Windows 11 built-in `mstsc.exe`, Windows App
on Windows, and Windows App on macOS.

1. Complete genuine TLS/CredSSP, R2 physical-`seat0` admission, personal-mode
   licensing and Share activation. Record generations and lifecycle states,
   never credentials or screen pixels.
2. Display one controlled test-pattern frame through the existing
   XShm → R4 → authenticated R3 Graphics path. The XShm span is borrowed only
   synchronously; R3 publication is reauthorized after native work and before
   application-byte submission.
3. Send pointer motion/button and keyboard input only to a dedicated test
   recorder. Each decoded event carries the R5 generation observed when it was
   accepted; immediately before XTEST require current R2/R3 input authority and
   exact equality with the live R5 generation.
4. Trigger a RandR geometry replacement while at least one decoded pointer and
   one keyboard event from the old generation are pending. Neither old event may
   reach XTEST. A fresh event bound to the replacement generation must succeed,
   and capture/Damage/XI2 must use only the replacement resources.
5. While the owner is active, log out or replace the admitted `seat0` session.
   The logind watch must revoke the connection, no later Damage may cause frame
   publication, no queued input may reach XTEST, and R5 retirement must preserve
   input-before-Damage/XShm/XCB teardown. Work already synchronously encoded is
   non-authorizing and must be dropped unless R3 can still freshly authorize
   publication, which a revoked session cannot.
6. Reconnect only after a new genuine R2 admission. Construct a new X11 owner
   from the new visitor callback and prove no old watcher record, R2 generation,
   R5 generation, frame or decoded input is reusable.

A PASS records only observable state/generation transitions, client-visible
test-pattern presentation, controlled input-recorder delivery, resize outcome,
logout revocation and fresh reconnect. Do not retain screenshots, clipboard
payloads, credentials or native input logs containing user data.

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

The same rule applies one layer higher to listener polling. A zero-wait poll
immediately after loopback `connect()` may legitimately return `NoEvent` on
Darwin even though the peer becomes readable shortly afterward. A fixture that
needs to consume that already-connected peer must boundedly repeat the
production one-step poll from the external test caller, using at most
`kMaximumTcpPollWait` per invocation and retrying only `NoEvent`. Keep a
separate drained-listener assertion for the true idle `NoEvent` case; never
turn `Expired`, `Failure` or a completed batch into a retry.

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
`^macos\.desktop-session-` family plus exactly the two input-lifetime cases
`macos.input-controller-session-watch-revocation` and
`macos.input-controller-authority-retirement-no-native-post`, followed by a
fail-closed, registry-preflighted cursor selection containing
`macos.cursor-session-watch-revocation`,
`macos.cursor-topology-publication-revocation` and
`macos.cursor-geometry-generation-publication-denials`. Keep this road-local
rather than retuning the shared R9 Clang toolchain: hosted Clang 18 with
libstdc++ does not expose the C++23 `std::expected` used by the R7 headers.

The dedicated job covers registration, retirement, delayed-callback,
partial-install, destructor, reentry, guard revocation, stale held-input
suppression, input-callback races and stale cursor publication across
GUI-session, topology and geometry-generation replacement without AppKit, TCC,
a live desktop, native cursor sampling or native input posting. Independently,
`macos.input-controller-authority-retirement-no-native-post` must prove that
R2 admission revocation or R3 Share/input-authority loss can terminally retire
held input while geometry/session freshness is still current **without** calling
the native posting callback. The same case covers revocation requested from an
already-active native callback: the accepted event cannot be retracted, but the
outer operation fails and no cleanup/release event follows. Keep
`MacInputController::cancel()` for graceful teardown only while upstream input
authority is still current; use `retireWithoutNativeInput()` after authority
loss. Cursor tests
must distinguish owned shape lifetime from current-desktop eligibility: a
same-dimensions geometry refresh, explicit invalidation, failed refresh or
topology revision change must deny `validFor` / `pixelsFor` and a later
successful refresh must never resurrect the old snapshot.
The portable `macos.desktop-geometry-epoch-generation-fence-revocation`
case must prove a same-facts refresh, explicit invalidation and geometry-owner
destruction revoke an asynchronous generation fence without dereferencing the
retired geometry owner. The Apple-only
`macos.capture-stream-geometry-generation-retirement`,
`macos.capture-stream-session-watch-frame-retirement` and
`macos.capture-stream-session-watch-consumer-race` cases use synthetic
CoreVideo buffers and injected backends. The generation case must exercise
replacement before and during prepare/start, asynchronous start completion,
before frame consumption and inside the synchronous consumer; old state must
never report `Published`, while a fresh replacement-generation stream may
publish. Do not claim Apple-only cases as Linux sanitizer execution. Hosted
Apple full builds remain deterministic compile/link/CoreVideo evidence for
those paths, while owner macOS 27 remains the real fast-user-switch delivery
gate. Do not treat synthetic coverage or Apple SDK compilation as authenticated
R2/R3 admission or live desktop acceptance.

## R7 owner macOS 27 M5 native validation is explicit opt-in

M5 is not part of ordinary CTest and must never be inferred from hosted Apple
SDK compilation. Execution requires a separately recorded owner authorization
for live desktop access, an exact shared-main SHA that already passed the R10
M1 candidate workflow and owner macOS 27 Debug gate, and a genuine positive
R2/R3 macOS desktop-admission capability. If any prerequisite is missing, mark
the live phase **NOT RUN**; do not expose the quarantined ScreenCaptureKit
factory, substitute a test-only admission capability or turn a TCC grant into
R2/R3 authority merely to obtain M5 evidence.

Use a disposable local test account/desktop with no personal content and a
second disposable account for fast-user switching. Record the exact SHA,
`sw_vers`, `xcodebuild -version`, `xcode-select -p`,
`xcrun clang++ --version` and effective CMake AppleClang before any native
activity. TCC checks are read-only: Screen Recording uses the existing
preflight behavior and Accessibility uses the existing non-prompting trust
query. A denied/unavailable preflight stops that subtest. Never call a
permission-request API automatically; the owner may grant permissions manually
in System Settings before a separately authorized rerun.

When the authority-bearing composition exists and the owner has explicitly
authorized live access, validate in this order:

1. Start from fresh native geometry/session state in GUI session A and use only
   a known test-pattern window/desktop. Bind capture, cursor and input to the
   same current geometry generation and session revision.
2. With topology and pixel dimensions unchanged, perform a fresh native geometry
   refresh. The old capture state must retire as
   `StaleGeometryGeneration`; queued prepare/start/output callbacks may finish
   but may not publish an old frame. A successful late native start owns exactly
   one native stop request. A replacement stream may be created only from the
   fresh generation and fresh authorization.
3. Snapshot a visible cursor, then replace the geometry generation without
   changing dimensions. The old snapshot must immediately fail
   `validFor`/`pixelsFor` and must never become valid again after another
   refresh. Repeat for topology invalidation.
4. While capture is starting/capturing, fast-user-switch from disposable
   session A to B and back to A. The native GUI-session watch must advance its
   revision. Capture becomes terminal, stale frames cannot publish, held input
   is retired/released, and old cursor snapshots remain invalid. Returning to A
   must not auto-resurrect capture/input/cursor; a new geometry generation and
   fresh R2/R3 admission are required.
5. Accessibility-authorized input, when separately authorized, targets only a
   dedicated event-recorder test application. Confirm stale-generation and
   stale-session events are denied and no queued native event posts after
   terminal revocation.
6. Clipboard validation uses only synthetic text/PNG or files created for this
   run in the disposable account. Do not read or preserve pre-existing personal
   pasteboard data. Verify generation/owner revocation prevents stale
   publication and that session teardown leaves no delayed old-owner write.
7. Close/terminal-retire every native owner and wait for already submitted
   completions. No callback may publish a frame, cursor, input event or clipboard
   mutation after terminal state, and stop/close retirement must remain
   exact-once/idempotent.

Record observable pass/fail facts only: generation/session revisions, lifecycle
state, frame disposition/drop reason, exact-once stop ownership and whether the
controlled test app received an event. Do not retain screen pixels, clipboard
payloads or credentials as validation artifacts. A full pass establishes only
the approved native behavior exercised at that SHA; M5 still requires the
project's authenticated Microsoft-client end-to-end acceptance where specified.

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

## R1 buffered TLS application-read readiness (2026-10-17)

A production-backed loopback regression for the CredSSP-to-MCS boundary must
place one complete CredSSP DER frame and the following MCS TPKT in the same
logical TLS application record. Consume only the CredSSP frame through the
existing R1-owned `TsRequestFrameReader`, then require R1 to report buffered
application-read progress while a zero-time native socket poll reports no new
readability. Do not consume or authorize the MCS suffix in this test.

Cancellation must clear the buffered-read fact before SSL/BIO/socket teardown
becomes observable to late callbacks. Keep the existing pending-read and
unresolved-write cancellation/replay coverage active. This fixture proves only
transport scheduling and lifetime; a positive final-CredSSP-plus-MCS scenario
remains blocked until a genuine R2 admission lease exists.

## R1 Microsoft-client transport compatibility capture checklist (2026-10-17)

Microsoft-client captures are compatibility evidence only. They never
authenticate the peer, validate delegated credentials, mint a native admission
lease or authorize MCS/R3. Record the exact client product/platform, OS build,
client/file version, server SHA and policy or `.rdp` overrides for every run;
never promote one observed client default into a protocol requirement.

For each supported `mstsc.exe` and Windows App build:

- **X.224 negotiation:** preserve optional cookie/routing-token bytes only as
  bounded syntax and record the exact `requestedProtocols`. The current R1
  HybridNla policy selects `PROTOCOL_HYBRID (0x02)` only when HYBRID was
  offered; it deliberately does not select HYBRID_EX. Public Windows App and
  Windows 11 capture reports have observed `SSL|HYBRID|HYBRID_EX (0x0b)`, but
  this is capture evidence, not a required default. If HYBRID_EX is ever
  enabled, Early User Authorization must follow completed CredSSP plus real
  authorization and precede post-handshake RDP PDUs.
- **TLS/certificate:** record TLS version/cipher, target/SNI name, certificate
  chain/name result and any user trust prompt. Exercise a trusted name-matching
  certificate and an untrusted/mismatched certificate. A user clicking through
  a certificate warning is not identity or native-session authority.
- **CredSSP/NLA:** record every TSRequest version/field shape and negotiated
  SPNEGO mechanism. MS-CSSP accepts versions 2 through 6; version 5+ adds the
  32-byte clientNonce hash-binding flow. Keep the existing R2 version and
  credential-policy gates; a captured NTLM or Kerberos choice is environment
  evidence, not a server authorization shortcut.
- **Fragmentation/coalescing:** MS-CSSP Windows product behavior sends a complete
  TSRequest as one TLS message block subject to TLS maximum-message
  fragmentation. R1 must nevertheless remain byte-stream correct across TCP
  segmentation, TLS record boundaries and multiple decrypted records. The
  CredSSP reader requests exactly the remaining DER bytes, so coalesced first
  MCS plaintext remains unread in the R1-owned SSL until admission.
- **Application I/O/backpressure:** one scheduler invocation performs at most
  one bounded `SSL_read_ex`/`SSL_write_ex`. Preserve the exact WANT_READ or
  WANT_WRITE retry operation and logical byte count. R3 must never add an SSL
  reader/writer, transport queue or accepted-byte counter.
- **Close:** capture a user-initiated MCS Disconnect Provider Ultimatum and/or
  Shutdown Request path and the following network close. Exercise TLS
  `close_notify`, raw EOF and RST separately because R1 intentionally
  distinguishes TLS closure from transport closure and permits no span replay
  after teardown.

Current evidence to reproduce rather than trust: FreeRDP issue #13549 records
Windows App for macOS 11.4.2 (3104) offering `0x0b`, negotiating TLS 1.3,
using CredSSP version 6 with clientNonce and sending final `authInfo`; selecting
HYBRID (0x02) connected while an incorrectly early HYBRID_EX authorization
stalled before MCS. A Microsoft Q&A Windows 11 `mstsc.exe` capture also reports
`0x0b` and an optional `Cookie: mstshash=...`; treat that report as
non-normative capture evidence and repeat it on the exact Windows build under
test. Microsoft's live release page lists Windows App 2.0.1484.0 on Windows
(published 2026-10-13). Its macOS latest-release table still lists 11.4.2
(3104), while the same page's version history lists 11.4.3 (3115, published
2026-09-29); record the actually installed build rather than resolving that
documentation/rollout inconsistency by assumption.

### Genuine final-CredSSP + first-MCS positive fixture

Execute this case only in an owner-authorized environment where the existing
R2 path completes genuine GSS/CredSSP credential verification and the native
broker issues a current non-forgeable lease. The authenticated client sends
the final CredSSP `authInfo` immediately followed by the first MCS TPKT in one
logical TLS application write. Require R1 to consume exactly the CredSSP DER,
then require real R2 admission, then consume and frame the already-buffered MCS
bytes through the existing R1 bounded application-I/O boundary before passing
one complete TPKT to R3 authorization.

The current Linux aggregate exposes `authorizeMcsConnectInitial(completeTpkt)`
but does not yet expose the post-admission R1-owned bounded read/framing route
needed to produce that span after CredSSP application I/O has disabled the
legacy diagnostic MCS reader. That composition is an R10 integration
prerequisite, not permission to revive the legacy reader or create an R3 SSL
reader, wrapper queue or duplicate scheduler. Until both the real R2 lease and
that R1-owned composition exist, record the positive case as **NOT RUN**.

## R1 loopback TLS handshake readiness fixtures (2026-10-16)

Real native-loopback TLS fixtures must not use scheduler sleep/yield loops to
stand in for handshake readiness. Drive one client \`SSL_do_handshake\` step at
a time, accept only exact WANT_READ/WANT_WRITE backpressure, and advance the
R1-owned server only through \`OwnedPreauthTcpConnection::pollSocketOnce\`
under a finite monotonic deadline. Require both client init completion and the
same R1-owned established TLS object before application framing. This is a test
fixture rule only; do not expose a raw descriptor or add a production retry
loop solely to make a test wait.

## R1 two-peer nonblocking TLS readiness fixtures (2026-10-17)

When an ordinary loopback fixture drives both OpenSSL client and server endpoints, do not serialize progress by waiting on one unfinished peer while the other unfinished peer has its own current WANT direction. After each one-step SSL advancement, wait on the union of both sockets' exact WANT_READ/WANT_WRITE interests with one bounded monotonic readiness call, then invoke the next SSL step only for the endpoint whose readiness was observed. This prevents a test scheduler from creating a false TLS deadlock while preserving production's no-hidden-retry rule.

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



## R9 bounded CredSSP coverage-guided fuzzing

The opt-in Linux/Clang sanitizer configuration must also build and execute
`fuzz_credssp` as a separate bounded CTest. Link the real portable protocol
library and call the production `parseCredSspTsRequest`,
`TsRequestFrameReader`, `inspectCredSspCredentials` and
`inspectCredSspDelegatedAccount` surfaces directly. Keep the maximum fuzz
input at the production TSRequest ceiling (16 KiB), use a fixed seed and finite
run count, and keep mutable corpus/artifacts only below the existing
`build/` root.

The checked-in corpus must contain only synthetic non-secret DER seeds: at
least one canonical TSRequest negotiation frame and one canonical
`TSPasswordCreds` envelope. The fuzzer may assert documented fail-closed
invariants such as deterministic classification, zero borrowed metadata on
TSRequest failure, zero rejected delegated-account output, bounded token
counts/sizes and successful manual-frame release. It must not fabricate TLS
provenance, GSS completion, PAM authorization, a native admission lease or
real credentials.

Keep this fuzzer in its own CTest/CI step rather than folding it into the
MCS/CLIPRDR target so crashes and reproducers remain attributable. A bounded
PASS is coverage-guided sampling only and does not replace the deterministic
credential corpora or real-client/provider acceptance gates.

Before invoking the CredSSP fuzzer, enumerate the exact anchored CTest with
`ctest -N` and require `fuzz.credssp-bounded` by name. Zero selected tests
are a CI failure, not a fuzz PASS. The deterministic fragmented-reader drive
must also preserve terminal semantics across chunking: a completed frame must
match the consumed prefix, reparse successfully and release back to
`NeedMore`; an invalid fragmented prefix must agree with whole-input
rejection; and explicit close must leave no completed DER or pending byte
requirement.

## R1 cross-road write-slice compatibility

When a higher-layer R3 writer is expected to feed R1's bounded TLS
application writer directly, keep one production-backed compatibility CTest
that proves the maximum R3 slice fits R1's public byte ceiling and that
receipt semantics survive actual OpenSSL short progress and WANT results.
Such a test must not fabricate R2 authorization: it proves only byte/receipt
compatibility. On zero-byte WANT, retain the same higher-layer receipt and
borrowed span; rotate a receipt only after positive accepted bytes. Use the
real loopback TLS owner and keep all retries explicit in the test fixture.


## R4 zero-byte graphics cancellation regression rule (2026-10-16)

A production cancellation test may exercise the R4 state transition only; it
must not claim that an offline counter or caller Boolean proves transport
progress. The success path must use the exact pending delivery receipt,
preserve mapped generation/surface and prior ACK/client-observation state,
invalidate the owned segmented publication, and prove the next real x264
picture is IDR followed by ordinary P-frame continuity after delivery.
Exercise both direct NV12 and synchronous BGRA conversion.

Keep positive or uncertain transport progress on the terminal abort path and
test that a late cancellation cannot revive that generation. Rejected
wrong/stale/duplicate cancellation must leave lifecycle, publication bytes and
healthy codec reference continuity unchanged. Sanitizer registry preflight
must explicitly name the new portable cancellation cases and both x264
recovery cases.

## R4 x264/BGRA sanitizer selection (2026-10-16)

The one Linux/Clang sanitizer job must compile both existing R4 graphics test
executables, `test_x264_avc420_encoder` and
`test_x264_avc420_segmented_frame_producer`, then run the complete
`x264` CTest label as its own failure-isolated group. The label currently
contains 27 production-backed cases covering the pinned x264 encoder,
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
groups. The bounded selection contains **42** production-backed CTests
from exactly these executables: `test_gfx_surface_lifecycle`,
`test_gfx_frame_acknowledge`, `test_gfx_presentation_lifecycle`,
`test_gfx_avc420_picture`, `test_gfx_segmented_data`, and
`test_gfx_avc420_segmented_frame`.

The sanitizer selector must enumerate the central CTest registry before
execution and assert one representative behavior from every family is present:
zero-valued surface IDs, stale-generation ACK handling, terminal frame-delivery
abort, zero-valued frame IDs, segmented-data denial/in-place safety plus the
u32 envelope boundary, and segmented AVC420 delivery/ACK, exact unsent-frame
cancellation and retained
terminal abort for ambiguous/partial progress. Keep this group separate from
the existing 4-case capability selector and 27-case x264/BGRA label so
failures remain
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

## R2 native session monitor borrowing (2026-10-17)

The Linux-only, noninstalled `LinuxRuntimeConnection::nativeChangeFd()` and
`nativeChangeEvents()` expose the **current** broker-owned logind monitor
fd and libsystemd event mask, not an fd duplicate, monitor owner or admission
proof. Both return `-1` before genuine R2 admission, without a live lease,
after revocation and after teardown. Calls and readiness dispatch are confined
to the aggregate's one event-loop thread. The composition loop MUST remove
its monitor registration **before** revoking/destroying the aggregate and
before dispatching any callback capable of revocation, discard pending events,
and must never close the borrowed fd. A reconnected aggregate requires a fresh
registration; fd numbers can be reused. `onNativeSessionChangeReady()` stays
the sole dispatch; post-revocation callbacks are terminal.

R10 composition adds a two-phase contract around the R2 borrow: the
serialized event loop installs the exact fd/mask plus genuine admission/session
generations returned by `registerNativeChange()`, removes that record
externally, acknowledges it through `unregisterNativeChange()`, and only then
calls `dispatchNativeChangeReady()`. The aggregate clears registration
identity before the R2 callback and never duplicates or closes the descriptor.
A stale record, generation or reconnect is non-authorizing.

`runtime.linux-connection-native-monitor-registration-denials` covers this
ordinary denial surface without fabricating a live fd, and
`runtime.linux-connection-existing-cal-unadmitted-denial` proves a connection
without a genuine R2 lease terminates before borrowing R3 CAL state or touching
provider state. With the existing borrow case, the direct R10 Linux runtime
sanitizer selector is **15** cases on the configured Linux CI provider.

The ordinary production-backed Linux-only
`runtime.linux-connection-native-monitor-borrow-denials` CTest exercises
unconfigured/pre-admission `-1`, premature wakeup, revoked lease absence,
repeated close and late callback. It does NOT fabricate an active lease.
Positive FD/mask acceptance is **NOT RUN** and requires explicit owner
permission on a real Kerberos/PAM/NSS/logind physical X11 `seat0` host:
provision a restricted real `TERMSRV/hostname@REALM` keytab and real client
Kerberos ticket through protected administrator/user input, configure the
service-approved PAM policy and UID/session/display identity, then drive the
existing R1 HYBRID TLS → real GSS/CredSSP final protected password → PAM →
NSS/logind broker to genuine admission. Verify that both accessor values are
nonnegative and the fd is pollable with the returned mask; unregister before
dispatching a native logind change; log out or replace that actual `seat0`
session and verify terminal R3/R2/R1 revocation, `-1` on both accessors and
no restoration by stale readiness. A fresh real login must use a new owner.
Never write the password into CMake cache, command-line arguments,
environment variables or logs. Obtain human authorization before live desktop
or service interaction. A positive test must be explicitly opt-in and must not
be simulated in CI.

## R2 native desktop admission/evidence regression gates (2026-10-17)

`runtime.linux-connection-native-desktop-selection-denials` is an ordinary
production-backed Linux-provider CTest. It proves that an accepted socket plus
configured policy cannot invoke the R10 desktop-selection visitor before a
genuine final CredSSP/PAM/NSS/logind lease, and that replay after terminal
revocation remains denied. It deliberately does not fabricate a positive lease.

On Windows,
`security.windows-native-session-evidence-provider-denials` compiles and calls
the production token/LSA/WTS evidence reader. An observed native snapshot is
tested only as candidate data (including SID/session replay mismatch); lack of a
physical interactive host is a fail-closed unavailable observation, not an
admission failure. The CTest never manufactures an authenticated SID or a lease.

On macOS,
`security.macos-native-session-evidence-provider-denials` calls the production
primary-console, audit-session and Security-session reader without requesting
TCC or starting AppKit/capture/input. Any observed snapshot is candidate data
only; mismatched UID/session replay is denied. No test may promote its own UID,
TCC status, `CGSession` dictionary or synthetic session callback to R2
authorization.

Positive Linux acceptance is opt-in and **NOT RUN** unless the owner authorizes
a real Kerberos/PAM/NSS/logind physical X11 `seat0` host. Drive the existing
HYBRID TLS + GSS/CredSSP final protected credentials through real PAM, issue the
real lease, consume the desktop-selection visitor, register the borrowed logind
monitor, then log out/replace that exact session and verify terminal revocation.
Passwords must be entered only through protected interactive/provider
mechanisms: never CMake cache, command-line arguments, environment variables or
logs. Windows/macOS positive admission stays **NOT RUN** until their genuine R2
authentication providers exist; native evidence alone is never a positive.

## R2 personal-desktop broker wrapper gate (2026-10-17)

`runtime.linux-connection-personal-desktop-r3-authority-denials` is a
production-backed Linux runtime CTest. It uses the real aggregate/broker with a
real sealed service keytab but deliberately never fabricates final CredSSP,
PAM/NSS/logind admission. It verifies pre-admission denial, immutable deployment
mode mismatch, repeated/late selector denial, Valid Client and Share
accepted-byte rejection after cancellation, repeated close, late client intake
and post-Share readiness denial. A small R3 test-access subcase stages protocol
bookkeeping only (never an R2 lease) to prove the already-production one-shot
private selector closes on duplicate use and the existing admission/session
generation fence closes on replacement.

A positive test is opt-in only on an owner-authorized Linux host with genuine
Kerberos final CredSSP credentials, the configured PAM service, matching NSS
identity and a physical X11/logind `seat0` session. Select the exact immutable
PersonalDesktop policy after protected Client Info and before Server License
Request, drive Valid Client plus Share entirely through the R2 wrappers, then
log out/replace the session during a pending write and verify the late receipt
cannot advance R3. Never place passwords in CMake cache, CLI arguments,
environment variables or logs. Ordinary CI must report this positive path
**NOT RUN**, never fixture-mint a lease.


## R3 Graphics DVC control/DATA sanitizer gate (2026-10-17)

The production-backed `transport.dvc-graphics-*` behaviors are one exact
ASan/UBSan registry gate: **15** tests. Six retain CREATE/CAPS selection,
malformed/wrong-ID/duplicate response, generation/cancellation and pre-Share
coverage. Nine additional behaviors cover frame publication and DATA
reassembly. CI selects the complete `^transport\\.dvc-graphics-` namespace,
checks the exact cardinality and requires every named sentinel, so a new R3
registration cannot silently fall outside the isolated sanitizer gate.
Offline success is protocol-mechanics and R4 receipt evidence only; it is never
R2 admission, Share authority, visible-desktop authorization or a live Graphics
endpoint. Positive aggregate use remains behind freshly reauthorized R2/R10
wrappers and the exact R1 plaintext owner.


## R4 ClearCodec sanitizer gate (2026-10-17)

The mandatory ClearCodec fallback is a separate exact ASan/UBSan registry gate.
CI must build `test_gfx_clearcodec_fallback`, enumerate exactly **4**
`graphics.clearcodec-*` behaviors, require all four names and execute them:
wire serialization, capability fallback, owned delivery/recovery and
malformed/layout/alias denials. Ordinary full CTest or AVC420/x264 coverage
does not substitute for this gate because ClearCodec has distinct residual
layout and checked length arithmetic.

## R7 pending-host close and selected-LAN projection (2026-10-18)

The optional Qt GUI CTests now cover no implicit R10-approved interface selection, missing desktop admission, disabled future password controls and test-only mismatch/redaction, no automatic Start, absent endpoint copy, fake client status, stop/revoke and pending-host close behavior. The new `gui.offscreen-close-revokes-pending-host` test refuses close until the test adapter acknowledges retirement. R10 owns the real terminal operation, not the fake, and no GUI test is evidence of actual host admission.

## R9 PORTABLE-GUI archive verification contract (2026-10-18)

`scripts/verify_portable_gui.py` is separate from the SDK and SERVER-TEST preview validator. It requires an independent trusted complete-ZIP SHA-256 and exact 40-hex Git source SHA, rejects traversal/drive/ADS/case-collision/symlink members and excessive uncompressed sizes, checks manifest payload inventory and SHA256SUMS, platform-specific R7/R6/R5 GUI entrypoint and Qt platform plugin, licenses, disabled sample config, macOS signing/trust declarations and Linux glibc/graphics/permissions minimums. `packaging.portable-gui-archive-integrity-denials` is an ordinary stdlib-only Python CTest using synthetic fixtures, not native GUI, R2 admission or RDP client acceptance. A manifest statement alone cannot prove R10 integration: native offline extracted-window/network isolation, binary dependency closure, signer trust, unprivileged rerun, owner-native and user-approved LAN checks must produce separate same-SHA receipts before distribution.

## Shell launcher policy scans distinguish executable content from comments (2026-10-18)

When an offline packaging test prohibits runtime mechanisms such as FUSE, AppImage mounting or systemd activation, inspect executable shell lines rather than matching explanatory comments. Strip comment-only lines first, then apply the same fail-closed token checks to active launcher content. This prevents safety prose such as “no FUSE” from creating a false failure without weakening the prohibition. Keep archive contents, executable modes, dependency closure, tamper and startup-denial assertions independent of this source scan.

## R7 direct R10 host-control adapter coverage (2026-10-18)

The Qt shell uses R10's `RuntimeHostControl` as the sole command/status
authority. `rdp::gui::HostControl` is a concrete view/translation adapter,
not a second interface owner: it derives eligible LAN addresses from
`enumerateLocalInterfaces()`, calls R10 `configure()` then
`startSharing()`, and refreshes R10 status before any active-state UI.
`gui.offscreen-r10-control-adapter-denials` instantiates the production
`UnavailableRuntimeHostControl` and verifies no interface, Start, listener
or sharing state appears. The layout fake implements `RuntimeHostControl`
itself and command success alone must not produce an active state.

## R7 OS-account and host-permission request status gate (2026-10-18)

The credentials page may request only R2's supported
`ExistingOsAccount` mode through R10 `requestCredentialSetup()`; it never
submits an application password as NLA material. Host permission is a separate
explicit user action through R10 `requestHostPermissionSetup()`. Successful
command return is not authorization: GUI readiness refreshes solely from
`RuntimeHostStatus.credentialsConfigured` and `hostOwnerAuthorized`.
`gui.offscreen-r2-os-account-request-status-gate` makes the isolated fake
R10 owner return command success without changing status and verifies the UI
remains blocked until a later authoritative snapshot changes. Production
`UnavailableRuntimeHostControl` denies both requests.

## Discover Qt deployment roots through Qt metadata, not distro package ownership (2026-10-18)

Native GUI packaging CI must resolve Qt plugin locations from the selected Qt installation (for example `qmake6 -query QT_INSTALL_PLUGINS`) and then require the specific platform plugin file. Do not infer plugin ownership from a Debian/RPM package name: distributions can move `libqxcb.so` or equivalent platform plugins between runtime packages without changing the Qt install layout. This affects discovery only; dependency closure, hashes and extracted launch remain mandatory.

## R7/R9 macOS PORTABLE-GUI .app archive contract (2026-10-18)

`packaging.macos-portable-gui-app-integrity-denials` is a stdlib-only,
cross-host synthetic test of the macOS packager. It requires the real app
shape, matching `Info.plist` executable identity, Qt Cocoa plugin and
QtCore/QtGui/QtWidgets framework entries. ZIP members are regular files with
source-SHA binding, checksums, disabled listen/autostart config and explicit
unverified signing/notarization status. The packager rejects extra
`Contents/MacOS` helpers, wrong app identity, missing Cocoa plugin and wrong
archive naming. Synthetic Mach-O bytes do not prove macOS launch, signing,
notarization, TCC or hosting; native CI must separately run macdeployqt,
otool/codesign checks and an extracted offline launch smoke.

## R9 native Windows portable-GUI closure and first-screen smoke (2026-10-18)

Windows portable assurance must run on the actual Qt GUI built by a native Windows toolchain, not only synthetic PE fixtures. After local windeployqt staging, independently recompute the outer ZIP digest, run the common PORTABLE-GUI archive verifier, extract under a space-containing path and recursively inspect every .exe/.dll import. Only documented Windows/API-set DLLs may be absent from the archive; Qt, compiler and other third-party runtimes must be app-local. The extracted deny-only GUI must pass its offline self-test/start-denial modes and normal first-screen launch without owning TCP/UDP sockets or changing firewall profile state, then close and rerun. Hosted-admin execution is not an unprivileged owner-native receipt. Do not upload the ZIP from a job that can complete before the whole exact-SHA matrix is green.

## Source guards advance with intentionally inserted production stages (2026-10-18)

A source-level composition guard must assert the current authority boundary, not a historical exact tail sequence. When a new authorized production stage is inserted between guarded stages, update the earlier guard to require the new handoff and preserve its real safety invariant. Graphics control still must not publish a frame, but immediate revocation is no longer correct once the genuine R2-selected native-owner stage exists; poll/revocation details remain owned by the dedicated native-owner guard.

## Native GUI smoke must be downstream of successful package verification (2026-10-18)

A native extracted-GUI smoke step must depend on the package/closure step's explicit success outcome, not merely on an earlier compile. Otherwise a failed package can trigger a misleading secondary smoke failure or hang. Every launched GUI mode, including deny-only command modes, must have a bounded wait and terminal cleanup; timeout is a failure, never a reason to skip package or smoke assertions.

## Hosted macOS PORTABLE-GUI closure is real-app evidence, not hosting evidence (2026-10-18)

The `r7-macos-portable-gui` job must run on the arm64 `macos-latest`
runner, build the actual CMake `.app`, execute
`packaging.macos-portable-gui-app-integrity-denials`, package through the
local Homebrew Qt `macdeployqt`, re-run the common R9 archive verifier on an
independently recomputed outer digest, and inspect every extracted Mach-O
dependency record. Any absolute Homebrew or runner-home dependency path is a
failure. This proves hosted arm64 bundle shape and relocatable Qt linkage only;
it does not prove first-screen Aqua launch, signing/notarization trust, TCC,
R2 admission, LAN listening or Microsoft-client interoperability.

## CI structure tracks focused security inventory and native package lanes atomically (2026-10-18)

When a new executable-backed protected runtime gateway joins the R9 sanitizer selector, the selector regex, exact count, explicit name sentinel and structure-validator token must change together. Native GUI package jobs that become release prerequisites must also be named in `REQUIRED_JOBS` with a distinctive deployment-tool token, so a syntactically valid workflow cannot silently omit Windows/macOS closure coverage.


## R3 Confirm Active capability-store and early-input coverage (2026-10-18)

Portable Share tests must prove that accepted Confirm Active capability bytes
outlive the caller's mutable TPKT buffer, capability count remains exact, and
the negotiated Input flags are the server/client intersection. A malformed
CAPSTYPE_INPUT or one missing mandatory SCANCODES must fail closed without a
partially published client-capability store.

Because input may arrive after Confirm Active while connection finalization is
still in progress, exercise a correctly routed negotiated slow-path packet
between Confirm Active and Synchronize. Acceptance at this boundary means
validated-and-discarded only: the pending server Synchronize receipt identity
and client finalization stage must remain unchanged, and no native callback or
synthetic admission may be created. Keep the production R10 Share scheduler
guarded so this intake continues reading rather than triggering a write.

## Windows PE closure distinguishes OS DLLs from redistributable runtime (2026-10-18)

The extracted portable-GUI PE verifier may exempt only documented Windows OS/API-set imports. Observed imports AUTHZ.dll, d3d9.dll, ncrypt.dll and mscms.dll are system-provided and must not be copied from System32 into the archive. Microsoft Win32 ICM requirements identify Mscms.dll as the Windows Color Management implementation, so Qt's qwindows.dll may depend on it as an OS component. Toolchain, Qt, ICU, compression, font/image and GLib DLLs remain application closure and must be bundled; never broaden the system allowlist to hide a missing redistributable dependency.

## macOS deployment-tool symlinks resolve before execution (R7, 2026-10-18)

Homebrew may expose `macdeployqt` through one or more symlinked path
components. The PORTABLE-GUI packager may canonicalize that caller-supplied
tool path, but the resolved target must exist, be a regular executable file
and is the exact path passed to `subprocess.run`. This exception applies only
to the local deployment tool; source-app and archive payload symlink denials
remain unchanged. The dedicated
`packaging.macos-portable-gui-macdeployqt-symlink-resolution` CTest covers a
Homebrew-style symlink, non-executable target and broken link without invoking
Qt, AppKit, TCC or networking.

## R5 protected decoded-input mappings belong in the focused sanitizer inventory (2026-10-18)

When R5 adds a production-backed decoded RDP input translation or R2-protected native dispatch CTest, R9 must build its concrete test target under ASan/UBSan and include the exact test name in the anchored X11 selector/count. Ordinary full CTest alone is insufficient for pointer/lock conversion and no-post retirement boundaries immediately beside XTEST. The selector count, explicit sentinel and CI structure-validator tokens must advance atomically.

## Workflow authoring must treat literal shell `$'` as data (2026-10-18)

When generating or patching workflow text programmatically, do not use JavaScript replacement-string semantics for replacement content containing shell dollar constructs. In particular, a literal regex ending in `$'` can be interpreted as JavaScript's suffix-substitution token and corrupt the remainder of the YAML. Use function-based replacement or an equivalent literal-safe operation, then validate the complete reconstructed workflow before publication.

## macOS Qt GUI packaging deploys only the required Cocoa platform plugin (R7, 2026-10-18)

The R7 Widgets GUI is not a QML application. Native PORTABLE-GUI packaging
therefore runs `macdeployqt` with `-no-plugins` and `-no-codesign`,
stages exactly Qt's required `platforms/libqcocoa.dylib`, and passes that
staged Mach-O through `-executable=` so the deployment tool patches and
deploys the app/plugin runtime dependencies together. The Qt plugin root is
queried through the sibling `qmake -query QT_INSTALL_PLUGINS`; both tools
and the plugin path are resolved strictly. Do not relax the extracted
`otool -L` ban on Homebrew/runner paths to accommodate unused QML,
VirtualKeyboard, PDF or SVG plugin closures.

`packaging.macos-portable-gui-minimal-cocoa-deployment` injects the process
runner and proves the production command contains `-no-plugins`,
`-no-codesign` and the exact staged Cocoa plugin, without invoking Qt,
AppKit, codesign, TCC or networking.

## macOS staged Mach-O install IDs are bundle-relative before ad-hoc signing (R7, 2026-10-18)

The native package audit must not whitelist Homebrew prefixes simply because
`otool -L` reports a staged framework or dylib's own install ID. After
`macdeployqt` completes with signing disabled, the packager enumerates each
unique Mach-O inside the staged app, reads its install ID with `otool -D`,
and rewrites absolute framework/plugin IDs to a bundle-relative `@rpath`
identity with `install_name_tool -id`. It then ad-hoc signs the completed
development-preview app so arm64 code-directory integrity covers those final
bytes. Trusted/release signing remains false and notarization remains false.

`packaging.macos-portable-gui-install-id-normalization` injects tool
execution and proves framework/Cocoa IDs are rewritten before the final
ad-hoc sign without invoking AppKit, TCC, networking or a live server.

## Dormant production native bridges need focused source-linkage sentinels (R9, 2026-10-18)

A production-linked native bridge that is intentionally dormant until a later serialized runtime owner exists must have its source/build-graph denial CTest pinned explicitly in focused assurance, even when ordinary full CTest already runs it. Keep these CMake-script guards separate from sanitizer-instrumented executable counts. For the current Linux input and clipboard links, require both exact test names and an exact-two registry count; any premature `main.cpp` dispatch/construction must remain a hard failure.

## Shared packaging fixtures must be idempotent with their class setup (R9, 2026-10-18)

When a packaging behavior test reuses an app tree created by `setUp()`, directory preparation for that same tree must tolerate directories already created by the fixture. Use `exist_ok=True` only for expected fixture-owned directories; do not catch or suppress unexpected filesystem failures. This keeps the test focused on the packaging behavior under assertion rather than failing before it reaches that behavior.


## R3 RDPGFX presentation/surface ownership coverage (2026-10-18)

Graphics DVC tests must not construct a separate presentation lifecycle with an
arbitrary generation or surface ID and then hand that object to production R3.
The DVC owner must derive presentation generation from its own DVC allocation
and geometry from the admitted session. After client CAPS_ADVERTISE, assert the
exact R4-generated CAPS_CONFIRM, CREATE_SURFACE (XRGB8888) and
MAP_SURFACE_TO_OUTPUT bytes and require complete accepted-byte receipts before
`Ready`.

The production ClearCodec boundary accepts frame ID plus a borrowed framebuffer
only. Tests prepare the fallback through that R3-owned mapped presentation,
then preserve the existing zero-write cancellation, multi-record accepted-byte
mapping, partial-write abort and stale-generation denial assertions. Ordinary
CI must never fabricate a positive R2 lease or native desktop merely to reach
these protocol tests.
