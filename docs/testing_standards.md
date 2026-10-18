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
or delegated username, and the final PAM invocation is not yet wired.
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

The extracted portable-GUI PE verifier may exempt only documented Windows OS/API-set imports. Observed imports AUTHZ.dll, d3d9.dll and ncrypt.dll are system-provided and must not be copied from System32 into the archive. Toolchain, Qt, ICU, compression, font/image and GLib DLLs remain application closure and must be bundled; never broaden the system allowlist to hide a missing redistributable dependency.

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
