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

