## R5 RandR stale-damage generation fence exact-SHA hosted validation (2026-10-16)

**Production correction:** `741015795132a623033fabfff624a2a4794088e1`.  
**Actions:** `38977250042` — workflow overall **FAIL** only because the
concurrently expanded R1/R3 licensing sanitizer selector is rejected by CTest
before execution with `RegularExpression::compile(): Too many parentheses`.
The R5 sanitizer step runs later in the same job and is independently green.

The first test-only publication
`c1d5296dcd2b1cc50126188970a6cb4a50658898` correctly exposed the missing
generation fence: Ubuntu/GCC Debug ran **518** tests with **517/518 PASS** and
only `x11.desktop-resource-randr-stale-damage-isolation` failed because the
replacement damage tracker observed a queued notification before any deliberate
post-rebuild draw. The correction records the successful initial
`XDamageSubtract` request sequence and rejects older XCB `full_sequence`
notifications with bounded 32-bit serial arithmetic.

Exact correction-SHA evidence:
- **Linux/GCC:** **520/520 PASS** in Debug and **520/520 PASS** in Release.
  `x11.desktop-resource-randr-stale-damage-isolation` passes in both modes as
  test #462. Installed SDK consumer **1/1 PASS**, ZIP package, digest and
  artifact upload pass.
- **macOS/AppleClang:** **442/442 PASS** in Debug and **442/442 PASS** in
  Release. Installed SDK consumer **1/1 PASS**, package/digest/upload pass.
  Native X11 execution is intentionally absent on this host.
- **Windows/MSVC:** native preflight **51/51 PASS** in both configurations;
  full CTest **472/472 PASS** in Debug and **472/472 PASS** in Release.
  Installed SDK consumer **1/1 PASS**, package/digest/upload pass. Native X11
  execution is intentionally absent on this host.
- **R9 Clang ASan/UBSan native X11:** the fail-closed selector discovers
  exactly **32** R5 cases and completes **32/32 PASS**. The new stale-damage
  case is **27/32 PASS** in 0.04 s; pixel parity, RandR capture generation,
  terminal capture denial and XShm lifetime cases remain green.
- **Documentation policy:** PASS. The independent R7 sanitizer side job also
  passes. Untagged prerelease publication is skipped as intended.

The new native oracle uses the existing independently checked helper XCB drawing
path and the deterministic `kFirstPixelPattern`/`kSecondPixelPattern`.
It resizes real Xvfb geometry from **1280x720 to 1024x600**, retains the same
production XCB connection identity, drains the pre-rebuild Damage event without
publishing replacement-generation damage, captures the already-drawn first
pattern through the rebuilt XShm child, then requires a fresh real XDamage
observation and exact little-endian B/G/R bytes for the second pattern. Packed
row stride remains four bytes per captured pixel; the padding lane is not used
as alpha. No borrowed framebuffer span crosses capture, rebuild or disconnect.

Canonical owner-local `~/rdp-server/build/` testing remains **NOT RUN** in
this connector environment; no alternate persistent build root was created.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 evidence required
for M1 remains outstanding. No live Microsoft-client desktop, M2/M3 acceptance
or R4 graphics delivery is claimed. Functional R5 input integration remains
**BLOCKED ON R3** until R3 exports its authenticated already-decoded bounded
Share/Input or Fast-Path Input event contract; R5 continues to consume only its
existing typed native input boundary and does not add protocol authority.

## R2 Linux PAM password-verifier boundary (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `5b5f349f96195c42eaf0e67ab5445d9887d0b195`.

R2 adds a real Linux-PAM password-verifier component without wiring it to the private final-CredSSP completion latch or native admission. `LinuxPamPasswordVerifier` is Linux-only, noninstalled and enabled only by `RDP_SERVER_TEST_LINUX_PAM=ON`, which requires the existing Linux GSSAPI test mode. There is no fake verifier, caller-supplied success Boolean or public lease path.

The verifier uses explicit one-shot PAM service configuration, bounded policy-compatible local account input, bounded UTF-16LE password validation, allocation-free UTF-8 conversion into a cleansed stack buffer, a single-password PAM conversation, real `pam_authenticate`, and real `pam_acct_mgmt`. Username prompts and extra secret prompts fail closed. Dedicated CTest `security.linux-pam-password-verifier-denials` uses no credential fixture and calls the real host PAM stack only with a deliberately nonexistent synthetic account; only Denied or ProviderFailure are accepted.

Hosted Linux and R9 install `libpam0g-dev`, enable the PAM gate, build the production verifier and execute the exact CTest. `ownedCredSspCredentialAuthorizationComplete_` remains false and final authInfo remains terminal deny-only. The next R2 step is authenticated in-provider extraction of `TSPasswordCreds.userName` and exact match to the immutable Kerberos-principal→local-account policy mapping before PAM can participate in any positive path. Real positive Kerberos/PAM/NSS/logind authorization and M2 remain **BLOCKED / NOT RUN**.

Canonical owner-local `~/rdp-server/build/` testing is **NOT RUN** in this connector environment. Exact-SHA hosted platform/sanitizer/docs/package evidence is **PENDING**.

## R5 RandR stale-damage sequence-fence correction (2026-10-16; exact-SHA CI pending)

**Correction parent:** `83d05e8076982545e57b75b78f5f5b212ddde865`.  
**First test publication:** `c1d5296dcd2b1cc50126188970a6cb4a50658898`.  
**First Actions:** `38976824134`.

The new `x11.desktop-resource-randr-stale-damage-isolation` case exposed the
intended generation boundary instead of passing immediately. Ubuntu/GCC Debug
built the real X11 target and ran **518** CTests; **517/518 passed**. The sole
failure was the new R5 case at
`tests/test_x11_desktop_resources.cpp:878`: after the aggregate had published
the resized generation and before any deliberate post-rebuild drawing,
`damageNotificationCount()` was already nonzero. The adjacent existing
pixel-parity, RandR capture-generation, capture-terminal-denial and other X11
cases passed. This is executable evidence that resource/event identity alone
does not provide the generation fence the event-budget contract requires.

The smallest R5 production correction stays inside the existing
`X11DamageTracker`. Successful construction records the request sequence of
the initial checked `XDamageSubtract`, which is the point after earlier
server-side damage is intentionally cleared. `handles()` now rejects a queued
Damage event whose XCB `full_sequence` predates that generation floor using
bounded 32-bit serial arithmetic before checking the native Damage XID. Normal
post-initialization events remain eligible; disconnect clears the floor with the
rest of the borrowed native state.

No second XCB owner, event loop, RDP parser, scheduler or authorization surface
is added. The already-registered dedicated CTest and R9 exact-name sanitizer
preflight remain unchanged. Canonical owner-local `~/rdp-server/build/`
execution is still **NOT RUN** in this connector environment; no alternate
persistent build root was created. Exact correction-SHA Linux/GCC
Debug+Release, macOS/AppleClang Debug+Release, Windows/MSVC Debug+Release, R9
ASan/UBSan native X11, documentation policy and SDK/package validation are
**PENDING**. Functional R5 input translation remains **BLOCKED ON R3** pending
R3's authenticated already-decoded Share/Input or Fast-Path Input event
contract.

## R10 Windows licensing-preflight portability correction (2026-10-16; exact-SHA CI pending)

R10 implementation `35cfda594f45c15e14966579f05cadb4bc5db8f1` reached
Actions `38976348381`. Linux/GCC passed **515/515 Debug + 515/515 Release**
and installed SDK consumer **1/1**; macOS/AppleClang passed **438/438 Debug +
438/438 Release** and consumer **1/1**. Documentation policy and the independent
R7 sanitizer passed. Windows/MSVC failed Debug compilation before CTest because
`windows.h` expanded the function-like `max` macro in the bounded
product-version parser.

This correction changes no licensing/configuration semantics: the parser caches
the same `uint32_t` limit via macro-safe
`(std::numeric_limits<std::uint32_t>::max)()`. Existing six licensing CLI
CTests remain the behavior gate. Owner-local `~/rdp-server/build/` remains
**NOT RUN** here. Exact-correction-SHA hosted platform, R9 sanitizer, docs and
SDK/package validation are **PENDING**.

## R5 RandR stale-damage generation isolation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `fd1b6a687718f3887c3169a2b4b0bcda129d2d40`.

The requested XShm pixel-parity, RandR capture-generation and terminal-capture
denial boundaries are already present and have later descendant sanitizer
evidence, so this increment does not duplicate them. Current-source review
instead found one narrower unproved event-budget invariant: the existing RandR
helper says events queued behind a geometry transition are offered only to the
replacement geometry-bound trackers, but no CTest deliberately queued an old
XDamage notification behind that transition.

New production-backed CTest
`x11.desktop-resource-randr-stale-damage-isolation` stays in the existing
`test_x11_desktop_resources` dispatcher. On an ephemeral 1280x720x24 Xvfb
server, an independent helper XCB client completes a real resize to 1024x600
and then performs checked deterministic drawing before the production aggregate
processes the queued RandR event. The aggregate must stop at the transition,
transactionally rebuild on the same XCB connection, then drain the queued
old-generation Damage event without incrementing or publishing damage from the
replacement tracker. The already-drawn BGRX pixels remain capturable through
the rebuilt XShm child; a second distinct post-rebuild drawing must produce a
fresh real XDamage observation and exact B/G/R capture.

This is test-only because the existing production stop/rebuild ordering already
implements the intended contract. No R2 admission, R3 protocol/input parsing,
R4 scheduler, second XCB owner or native event loop is added. The shared R9
Clang ASan/UBSan native-X11 selector and fail-closed registry preflight now
include the new behavior, expanding the expected R5 selection from **31** to
**32** cases.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is
**NOT RUN** in this connector environment because the synchronized owner
checkout is unavailable; no alternate persistent build root was created.
Exact-publication-SHA Linux/GCC Debug+Release, macOS/AppleClang Debug+Release,
Windows/MSVC Debug+Release, R9 sanitizer, documentation-policy and SDK/package
evidence are **PENDING**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27 and Microsoft-client M3 acceptance remain **NOT RUN / OPEN**. The
next functional R5 input translation remains **BLOCKED ON R3** until R3
exports its authoritative authenticated already-decoded bounded Share/Input or
Fast-Path Input event contract.

## R8 Windows completed-file Explorer handoff exact-SHA hosted validation (2026-10-16)

**Implementation:** `74b5fb33484e961479a652204d35864ecfc77fd8`.
**Actions:** [38975977794](https://github.com/k1moradi/RDP-server/actions/runs/38975977794) — **SUCCESS**.

The exact implementation SHA is green across the complete hosted matrix. Ubuntu/GCC full CTest is **507/507 PASS** in Debug and Release. macOS/AppleClang full CTest is **430/430 PASS** in Debug and Release. Windows/MSVC focused native preflight is **51/51 PASS** in Debug and Release, and full CTest is **460/460 PASS** in Debug and Release. The dedicated `clipboard.windows-completed-file-hdrop-handoff` case passes on all hosted operating systems.

R9 Clang ASan/UBSan is **PASS**. Its complete clipboard-labelled selection is **60/60 PASS**, including the new CF_HDROP handoff. The same sanitizer job passes its additional selected groups at **33/33**, **20/20**, **4/4**, **80/80**, **29/29**, **10/10**, **31/31**, plus bounded fuzzer **1/1**. Documentation policy, R7 macOS session sanitizers, downstream installed-SDK consumer, package/digest and artifact steps all pass.

This evidence validates the bounded completed-file Windows presentation contract and native Win32 compile/link coverage. It does **not** claim live Explorer paste, owner Windows MSYS2 CLANG64/Clang23, authenticated Microsoft-client file copy, directory-tree materialization or performance. Canonical owner-local `~/rdp-server/build` remains **NOT RUN** in this connector environment.

**Next R8:** bounded multi-file/directory-tree materialization and handoff without whole-tree prefetch or path derivation from remote metadata, then real-client file-copy acceptance.



## R1 owned-TLS licensing cancellation and stale-receipt fence (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** \`2e9b5775077a28593dc6d717c6daecbc3db3141c\`.

The newer R1 bounded-readiness fixture increment
\`0a376216a88733082926c49b3932f70d80af2133\` now has meaningful exact-SHA
hosted evidence in Actions run \`38975448171\`: Linux/GCC **503/503 Debug +
503/503 Release PASS**, macOS/AppleClang **426/426 Debug + 426/426 Release
PASS**, Windows/MSVC **456/456 Debug + 456/456 Release PASS**, and the bounded
R1/R3 Clang ASan/UBSan selection **77/77 PASS**. Both
\`transport.tcp-owned-tls-application-partial-write\` and
\`transport.tcp-owned-r3-connect-response-slice\` executed in every hosted
Debug/Release suite and as selected sanitizer tests. This supersedes the
earlier zero-job workflow as R1 validation evidence.

R1 now adds two production-backed cross-road cancellation regressions without
changing production transport or licensing code:
\`transport.tcp-owned-r3-license-request-cancel-replay\` and
\`transport.tcp-owned-r3-platform-challenge-cancel-replay\`. Both use the real
ephemeral loopback \`OwnedPreauthTcpConnection\`, OpenSSL TLS and the existing
R3 receipt gates. The License Request case proves cancellation before any write
and after a real positive forced-fragment TLS write: only the accepted prefix
advances the R3 suffix receipt, R1 becomes terminal, explicit R3 gate
retirement closes licensing without delivery, and both current and older
receipts are rejected. It does not claim already accepted TLS bytes were
retracted. The Platform Challenge case deterministically cancels before the
94-byte packet is written, proves R1 closure alone cannot mutate R3, then
explicitly retires the R3 gate and rejects stale completion/requeue.

The existing WANT path remains bounded and direction-exact: the License Request
case preserves the current span/receipt across zero-byte WANT and polls only
R1's recorded interest before retry. The already validated application-I/O,
License Request, Platform Challenge and cancellation tests provide the
complementary short-packet/WANT/read coverage; no scheduler sleep, hidden retry,
second TLS reader, transport-to-R3 coordinator or duplicate lifecycle is added.
The optional truncated-inbound fixture is not duplicated in this increment
because R1 exposes plaintext byte progress only and has no frame-forwarding
owner; incomplete-frame assembly remains the existing caller/R3 boundary.

R3's validated \`RdpLicensingAuthorityGrant\` snapshot and R10's administrator
licensing provisioning preflight remain offline/non-live authority boundaries.
They create no receipt-bound New/Upgrade publication, so they do not justify a
new R1 transport surface. R1's 18 KiB application-I/O ceiling and sole
socket/BIO/SSL ownership remain unchanged.

Canonical owner-local \`~/rdp-server/build/\` execution is **NOT RUN** in this
connector environment because the synchronized checkout is unavailable; no
alternate persistent build root, branch or patch artifact is created. Exact
publication-SHA hosted platform, sanitizer, documentation-policy and
SDK/package evidence for the two new cases is pending. M1 owner-platform
same-SHA evidence remains **NOT RUN** and M2/M3 remain **OPEN / NOT ACCEPTED**.


## R4 client decode-backlog observation exact-SHA hosted receipt (2026-10-16)

**Implementation:** `35833ba667a110ec859e04958d2a4ef269616012`.  
**Actions:** `38976220846` — **SUCCESS**.

The sole R4 presentation owner now exposes the already-owned
FRAME_ACKNOWLEDGE backlog facts without creating a throttle policy:
`expectingFrameAcknowledgements()`, `clientQueueDepthAvailable()` and
`clientQueueDepthBytes()`. Positive finite `queueDepth` values remain client
buffered-byte counts; zero remains explicitly unavailable, and suspension
clears the count and ACK expectation.

Dedicated production-backed
`graphics.frame-ack-backpressure-observation` passed in every normal hosted
configuration and under the portable R4 sanitizer gate:
- **Linux/GCC:** Debug **509/509 PASS**, Release **509/509 PASS**; new case
  **#270** in both.
- **macOS/Clang:** Debug **432/432 PASS**, Release **432/432 PASS**; new case
  **#255** in both.
- **Windows/MSVC:** focused native preflight **51/51 PASS** in Debug and
  Release; full Debug **462/462 PASS**, Release **462/462 PASS**; new case
  **#255** in both.
- **Clang ASan+UBSan portable R4 RDPGFX:** **34/34 PASS**; the new case is
  selected and passes as item **14/34**. Existing R4 x264/BGRA remains
  **20/20 PASS** and RDPGFX capability negotiation remains **4/4 PASS**.
- Documentation policy, independent R7 sanitizer, installed-SDK consumer,
  package/digest/upload and all remaining configured sanitizer/fuzzer groups
  PASS; untagged prerelease publication is correctly SKIPPED.

This closes the observation-boundary increment only. No frame-rate threshold,
timer, additional queue, second scheduler, DVC router or authorization path is
introduced. Canonical owner-local `~/rdp-server/build` validation and owner
Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 commands remain
**NOT RUN** in this connector environment. Genuine authenticated R3
`Microsoft::Windows::RDS::Graphics` DVC admission/full-send, native capture
performance and Microsoft-client visible graphics acceptance remain
**BLOCKED/NOT RUN**. Gate B and M3/M4/M5 remain **OPEN**.

## R3 authority-correlated New License receipt gate (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `4ec2b8c5ece830e28427c8501b98ff943465372b`.

R3 now has the receipt owner needed for a future live authority-issued New
License without prematurely treating a caller-provided snapshot as licensing
authority. `RdpServerLicenseGrantWriteGate` is intentionally **not** embedded
in `McsSessionLifecycle` and has no R2 broker entry point in this increment.
It can therefore exercise the production packet/receipt/lifecycle boundary
without creating a live publication capability before R10 owns a real licensing
authority.

The gate accepts only an already-configured
`RdpLicensingAuthorityGrant` whose nonzero generation and fixed 32-byte
fingerprint exactly match the caller's current authority correlation. It also
requires the immutable server-license identity, already-derived licensing keys,
and a lifecycle that has cryptographically reached
`NewLicenseIssuanceRequired`. The current live-eligible branch is
`NewLicense` only; `UpgradeLicense` remains offline because the parallel
`CLIENT_LICENSE_INFO` trust/signature/product/expiration decision is still
unimplemented.

One stable contiguous encrypted/MACed SERVER_NEW_LICENSE packet is retained
through zero-byte backpressure and positive partial writes. Reply and
write-slice receipts remain nonzero and monotonic; positive partial progress
rotates only the slice receipt. Stale/duplicate receipts, over-report, wrong
phase, wrong grant kind, stale authority correlation or invalid encoding close
the lifecycle. Only exact full accepted-byte delivery invokes the private
lifecycle transition and moves `RdpLicensingPhase` to `Licensed`; merely
queueing or partially sending a grant never licenses the connection.

Dedicated central CTests:
`transport.licensing-server-license-grant-write-receipts` and
`transport.licensing-server-license-grant-write-denials`. Both are selected
by the bounded R1/R3 ASan/UBSan licensing gate. They cover stable WANT
resubmission, partial-slice rollover, exact completion, stale authority
fingerprint, Upgrade-on-New branch denial, wrong phase, stale receipt,
over-report and duplicate completion.

This is still **not live publication**. R10 currently provides administrator
licensing credential/product preflight but not a CAL-issuing authority owner;
R2 therefore receives no new API and cannot publish this gate. The existing
authority snapshot is correlation evidence only and remains insufficient by
itself to mint a licensed session.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/AppleClang, Windows/MSVC Debug/Release, R9 sanitizer,
documentation-policy and SDK/package evidence are pending.

**Next R3:** once R10 exposes a concrete licensing-authority owner that returns
the snapshot together with freshly verifiable generation/fingerprint, embed
this gate in the sole R3 session and let R2 freshly authorize every grant slice
and accepted-byte completion. Separately, `CLIENT_LICENSE_INFO` still needs
real CAL trust/signature, product/version/expiration and HWID validation before
any STATUS_VALID_CLIENT path. Share activation remains blocked until one of
those standards-correct licensing completions is live. **M2/M3 remain OPEN /
NOT ACCEPTED.**

## R3 grant receipt-gate compile-order correction (2026-10-16)

The authority-correlated New License receipt-gate implementation remains
unchanged from `525e235e1cc86ae978cf910020511bfcba4f4338`. Its first exact-SHA
hosted run exposed a macOS/AppleClang test compilation error only: the new
`advanceToNewLicenseIssuance` helper referenced the existing
`makeClientPlatformChallengeResponse` fixture before that fixture's later
definition in the same translation unit.

Correction `83d05e8076982545e57b75b78f5f5b212ddde865` adds the explicit
forward declaration and passes all five arguments at the earlier call site.
There is no production source, packet encoding, authority correlation,
receipt-accounting or lifecycle behavior change.

The correction's first hosted workflow correctly failed documentation policy
because that implementation-fix commit lacked a Markdown co-change; this
section supplies the required policy receipt for the corrected-source
descendant. Platform, sanitizer and full CTest results for the corrected source
remain pending and must be recorded only after their exact workflow completes.



## R1 owned-TLS licensing cancellation exact validation (2026-10-16)

**Implementation:** \`597b2871a64096f419844aefa4a6004a9e2c2e65\`.  
**Implementation Actions:** \`38976677537\` — R1-relevant Linux/macOS/R9 **PASS**; Windows blocked by an unrelated R10 compile failure.  
**Clean Windows descendant:** \`4ec2b8c5ece830e28427c8501b98ff943465372b\`.  
**Descendant Actions:** \`38976909719\` — Windows/MSVC **PASS**.

The two new R1/R3 cancellation regressions are centrally registered exactly
once and execute real production \`OwnedPreauthTcpConnection\` TLS plus the
existing R3 receipt gates:

- \`transport.tcp-owned-r3-license-request-cancel-replay\`
- \`transport.tcp-owned-r3-platform-challenge-cancel-replay\`

At the implementation SHA, Linux/GCC passed **517/517 Debug + 517/517
Release** and macOS/AppleClang passed **440/440 Debug + 440/440 Release**.
Both new cases passed in both configurations. The bounded R9 Clang ASan/UBSan
licensing/security selection passed **88/88**, with the License Request
cancellation case executing as selected test 69/88 and the Platform Challenge
case as 71/88. Documentation policy and the independent R7 sanitizer job also
passed. The successful Linux/macOS jobs completed their downstream SDK
consumer/package gates.

The implementation-SHA Windows job compiled the updated
\`test_owned_preauth_session\` target, then failed before full CTest execution
in concurrently added R10 \`src/server/runtime/main.cpp\`: Win32's \`max\`
macro expanded a \`std::numeric_limits<std::uint32_t>::max()\` expression
(C2589/C2059). R10 corrected that boundary in
\`4ec2b8c5ece830e28427c8501b98ff943465372b\`. R1's test source is unchanged
between those SHAs. On that clean descendant Windows/MSVC passed native
preflight **51/51 Debug + 51/51 Release** and full CTest **470/470 Debug +
470/470 Release**; both R1 cancellation cases passed in both configurations
and the installed SDK consumer passed 1/1. The descendant's later Linux
failure is separately attributable to the newly added R5
\`x11.desktop-resource-randr-stale-damage-isolation\` regression and does not
replace the implementation-SHA Linux evidence.

The License Request regression proves two distinct terminal paths. Cancellation
before the first application write leaves R3 at \`NotStarted\` until the caller
explicitly closes its gate. The positive-partial path forces a 1024-byte TLS
fragment ceiling and requires one actual R1 progress result in the range
**1..1024 bytes**, strictly smaller than the pending request; that exact
returned byte count alone is reported to R3. R3 rotates only the slice receipt
and preserves the exact remaining suffix. Subsequent R1 cancellation makes
future writes \`TransportClosed\`; explicit gate retirement moves licensing to
\`Closed\`, clears the pending publication and rejects both the current and
older receipts. Previously accepted TLS bytes are not claimed to have been
retracted.

The short Server Platform Challenge is cancelled deterministically before
delivery. R1 teardown alone leaves R3 at \`AwaitServerDecision /
PlatformChallengeRequired\`; explicit challenge-gate retirement then closes the
lifecycle, clears the challenge, rejects stale completion and denies requeue.
Duplicate R1/R3 cancellation is harmless. The cancellation fixture does not
force a short-packet WANT; direction-exact WANT and stable caller-owned retry
semantics remain covered by the already exact-SHA validated owned-TLS
application, License Request and Platform Challenge readiness cases. No
scheduler sleep, hidden retry, second TLS owner/reader or R1-to-R3 coordinator
was introduced.

Canonical owner-local \`~/rdp-server/build/\` execution remains **NOT RUN** in
this connector environment. Same-integration-SHA owner Linux/X11, Windows
MSYS2 CLANG64/Clang 23 and macOS 27 evidence remains **NOT RUN**, so M1 is not
accepted. Genuine R2 final credential authorization, a concrete R10
CAL-issuing authority, R2-authorized live grant publication and Share
activation remain open, so M2/M3 remain **OPEN / NOT ACCEPTED**.

**Next R1:** do not enlarge or duplicate the transport for R3's new
\`RdpServerLicenseGrantWriteGate\` yet. Its complete New License packet is
already bounded below R1's 18 KiB application-I/O ceiling, and the gate is
explicitly not embedded in the live MCS session or exposed through R2. Once
R10 supplies the real authority owner and R2 exposes fresh authorization for
the live grant slices/completion, verify that final publication through the
sole R1-owned TLS writer. Otherwise wait for the first live Share-activation
boundary that demonstrates a concrete bounded transport mismatch.
