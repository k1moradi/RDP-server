## R5 framebuffer-ingress selector correction receipt (2026-10-17)

Implementation `be81242f6fb5fa438376205650472356595f4aeb` reached Actions
`39023241910`, but CI stopped before build/CTest because the edited R5 selector
was missing its closing regex anchor/quote; standalone guard
`39023241935` reported the same Bash syntax failure.

This correction changes CI/validation policy only: restore the selector
terminator and require `x11.capture-r4-bgra-ingress`,
`x11.capture-r4-stride-layout-denials`,
`x11.capture-r4-generation-retirement`, and R5 cardinality **36**. No
production or CTest-body changes.

## R10 existing-CAL authority exact-SHA hosted validation (2026-10-17)

**Validated source SHA:** `dc81628a9b4431ef6ffd3e69a7156fd44f0b4d06`.  
**Primary Actions:** `39022770856` — **SUCCESS**.  
**Independent workflow structure:** `39022770907` — **SUCCESS**.

The exact R10 source commit passes the complete hosted matrix: Linux/GCC 13.3.0
**591/591 PASS Debug + Release**; macOS 26.6.2 / Xcode 26.6 / AppleClang
21.0.0 **505/505 PASS Debug + Release**, with then-current R7 native focus
**20/20 PASS** in both; Windows/MSVC 19.51.36260.0 **541/541 PASS Debug +
Release** after **58/58** R6 native preflight in both; and hosted MSYS2
CLANG64 Clang **23.1.3** **541/541 PASS Debug + Release**, after **58/58**
R6 native, **3/3** private-DACL and **5/5** security preflights, plus
**58/58** R6 ASan/UBSan lifetime coverage.

The four new `runtime.licensing-existing-cal-` cases pass in every ordinary
full hosted configuration and as exact **4/4 PASS** under Clang 18.1.3
ASan/UBSan. R9's broader groups are green, including **74/74** clipboard,
**41/41** portable R4, **24/24** x264/BGRA, **4/4** RDPGFX capability,
**92/92** M2 licensing/security, **8/8** client-CAL, **6/6** pre-existing R10
authority, **30/30** native GSSAPI, **3/3** PAM, **12/12** direct runtime
security, **33/33** native X11, and both bounded fuzzers **1/1**. Linux, macOS
and Windows installed-SDK consumers are **1/1 PASS**. Three exact-run package
artifacts are present and unexpired; prerelease publication is correctly
**SKIPPED**.

This proves only the fail-closed authority contract. Production still has no
verified CAL provider, positive existing-CAL decision, `STATUS_VALID_CLIENT`,
licensed-session transition, Demand Active/Share activation or listener. R3
descendant `c852d782eedab341371f193d3f20ae386ff7f5d2` adds a
non-authorizing request snapshot and intentionally does not consume a positive
R10 result.

**M1 remains OPEN / NOT ACCEPTED** because the three mandatory owner-native
same-SHA receipts are still absent with the required machine/toolchain and full
CTest facts. Hosted success is not owner evidence.

## R5 X11 -> R4 framebuffer boundary authoring receipt (2026-10-17)

**Authoring parent:** `f037d4b6445950767a126830e391057fcd3417ec`. Exact publication-SHA Actions are
**PENDING**.

Production R5 adds capture-generation provenance, generation-tagged Damage
snapshots, stale-generation capture denial and one synchronous
generation-carrying `consumeR4Frame()` callback. Production R5 remains
R4/x264-independent; only the existing X11 fixture privately links graphics.

Dedicated CTests are `x11.capture-r4-bgra-ingress`,
`x11.capture-r4-stride-layout-denials`, and
`x11.capture-r4-generation-retirement`. R9's exact native-X11 cardinality is
**36**. No R2/R3 authority, DVC sender, second capture implementation or XTEST
input path is added.

## R7 P2 R4 capture-epoch reconciliation authoring receipt (2026-10-17)

**Starting shared `main`:** `162093d3f50f0c9793b1eafc2cba637c98473559`. Exact publication-SHA CI is
**PENDING**.

The R7 P2 test composition now consumes R4's landed
`openBgraCapture()` contract without changing R4 or macOS production source.
The real R7 geometry generation is supplied as the R4-local capture freshness
epoch, while an unrelated fixed synthetic presentation generation drives the
offline R4 lifecycle. Each `X264BgraFrameRequest` carries the capture epoch and
the test asserts the producer retained it. This removes any accidental
suggestion that native capture freshness is R3/presentation authorization.

Dedicated CTest names and the 20-case R7 Apple selector remain unchanged.
Owner macOS 27, TCC/live desktop and M5 remain **NOT RUN / BLOCKED**.

## R4 P1 native BGRA ingress authoring receipt (2026-10-17)

**Starting shared `main`:** `c852d782eedab341371f193d3f20ae386ff7f5d2`. Exact publication-SHA hosted
validation is **PENDING**.

The implementation reuses `FramebufferView`, `BgraNv12Converter`, vendored
x264, segmented ownership and the presentation lifecycle. It adds an optional
nonzero R4 capture epoch: generic `open()` preserves current externally
generation-fenced R6/R7 integration at epoch zero, while
`openBgraCapture()` gives composition an additional mismatch check before
source-byte access.

New ordinary production-linked CTests are
`graphics.x264-native-bgra-frame-ingress`,
`graphics.x264-native-bgra-resize-recovery`, and
`graphics.avc420-capture-generation-denials`. The R9 x264/BGRA fail-closed
expected count becomes **27**; portable R4 remains **41**.

Hosted execution and full platform counts are **NOT RUN / PENDING** at
authoring. Canonical owner `~/rdp-server/build/` is unavailable here, so no
local CTest or alternate persistent build root is claimed. No live native
desktop, Microsoft client, benchmark, R3 Graphics DVC or network publication
was run. M1/M3 remain open.

## R3 P0 existing-client CAL authority-request implementation (2026-10-17)

**Starting reconciled shared `main`:**
`dc81628a9b4431ef6ffd3e69a7156fd44f0b4d06`.

This increment implements the roadmap-selected non-authorizing request
boundary. Production R3 adds a move-only HWID proof produced only by the
existing licensing-key decryption/MAC path and a move-only fixed-capacity
existing-CAL request owner. The live MCS path binds the exact Server License
Request product identity, retains the verified HWID and bounded CAL only on the
CLIENT_LICENSE_INFO branch, captures verification time, generates a fresh
32-byte correlation and records the already-bound R2 admission/session
generations. Teardown and stale-generation paths cleanse the request.

The concurrently landed R10 existing-CAL validation operation is preserved.
This commit only aliases its correlation width to R3's request constant; it
does not call that operation, add a provider, or consume a result. The R3
snapshot's CAL/HWID/time/correlation fields map directly to R10's public
validation inputs, while exact product identity remains independently owned on
both sides for a future equality check.

No positive CAL authority, synthetic production issuer,
`STATUS_VALID_CLIENT`, Demand Active, graphics, clipboard or input permission
is introduced. Four dedicated CTests cover ownership/bounds, the cryptographic
HWID proof gate, product/correlation denials and revocation/replay. R9 adds a
separate four-case exact-cardinality R3 sanitizer preflight; the existing R10
four-case authority selector remains separate.

At authoring time the canonical owner-local `~/rdp-server/build/` command is
**NOT RUN** because that checkout is unavailable in this connector
environment. Hosted publication-SHA matrix/R9 evidence is **PENDING** and will
be recorded after Actions executes the direct-to-`main` commit. Genuine R10
provider validation and Microsoft-client M2 acceptance are **NOT RUN**.

## R10 M1 evidence assessment and existing-CAL authority authoring receipt (2026-10-17)

**Initial hosted evidence SHA:** `e2c1e51d22c2c33cd0de1ca40fc2bf7f45d3c5ae`.  
**Reconciled implementation parent:** `9dc693440cd14d2a372eb48514df70353826c7df`.

Primary Actions `39018706447` and independent workflow validation
`39018706418` are **SUCCESS**. Hosted `e2c1e51d...` results are Linux/GCC
13.3.0 **584/584 Debug + Release**, macOS 26.6.2 / AppleClang 21.0.0
**495/495 Debug + Release** plus **17/17** R7 focus, Windows/MSVC
19.51.36260.0 **531/531 Debug + Release** after **55/55** native focus, and
MSYS2 CLANG64 Clang **23.1.3** **531/531 Debug + Release** after **55/55**,
**3/3** and **5/5** preflights. R9 sanitizer/fuzzer and structure jobs are
green.

The owner's statement that all tests pass is not a formal receipt. No
owner-native record naming this SHA with the required OS/compiler,
configure/build and complete CTest facts is available for Linux/X11, Windows
MSYS2 CLANG64/Clang 23 or macOS 27. **M1 remains OPEN / NOT ACCEPTED.**

The new R10 existing-CAL operation copies one bounded CAL, protected 20-byte
HWID, explicit verification time, exact licensing identity and R3 correlation,
then binds them with SHA-256 to request sequence, private authority generation
and authenticated provider-policy fingerprint. Completion must echo exact
sequence/correlation/digest and the same provider identity/trust. Decisions are
`ValidPermanentNoUpgrade`, `UpgradeRequired` or `Denied`; callers cannot
configure the released result, and release/reauthorization/retirement are
provider-fresh and one-shot.

Production still has no positive provider and returns `Unavailable`; the
positive provider is test-only. No trust is inferred from TLS, the terminal
licensing key, arbitrary CAL roots or caller values, and no RD Licensing RPC
backend is invented.

New CTests:
`runtime.licensing-existing-cal-provider-unavailable`,
`runtime.licensing-existing-cal-request-correlation`,
`runtime.licensing-existing-cal-policy-generation-revocation`,
`runtime.licensing-existing-cal-result-retirement`.
R9 fail-closes on exactly these four registrations. Canonical local
`~/rdp-server/build/` execution is **NOT RUN** in this connector environment;
publication-SHA hosted evidence is **PENDING**.

## R7 P2 macOS capture-to-R4 ingress authoring receipt (2026-10-17)

**Authoring parent:** `8dc9ead1ef0825739a2aa09864c21816ba78dd5a`.  
**Publication:** this direct-to-main implementation; exact-SHA hosted evidence pending.

The existing R7 production lifetime is unchanged. New cross-road tests privately
link the Apple capture fixture to the real R4 BGRA converter/x264 AVC420
producer and exercise synthetic CoreVideo buffers through the production
`MacScreenCaptureState::consumeFrame` path. Dedicated CTests are
`macos.capture-r4-bgra-layout-contract`,
`macos.capture-r4-pixel-lifetime-retirement`, and
`macos.capture-r4-display-generation-denials`.

The layout case uses a 2x Retina observation (2x1 logical points -> 4x2 physical
pixels), a 24-byte padded BGRA row pitch, exact
`kCVPixelFormatType_32BGRA` acceptance and wrong-format rejection before
running the real R4 producer. The lifetime case releases the caller's
CoreVideo reference from inside the R4 consumer and requires the release
callback to stay pending until synchronous conversion/encode returns; it also
proves a session race after encode yields `RetireStream` and the owned,
unwritten R4 frame is canceled. The generation case denies an old same-facts
display generation, denies/cancels a generation replaced after encode, rejects
late asynchronous start completion, and admits only a fresh geometry-bound
stream/producer.

The hosted R7 Apple focused selection is expanded from **17 to 20** and its
registry preflight requires the new names in Debug and Release. No native
ScreenCaptureKit factory is exposed and no ordinary test performs a real TCC
query/request, desktop capture or native input. Owner `~/rdp-server/build/`,
owner macOS 27 and M5 live-desktop acceptance are **NOT RUN**. Exact publication
SHA AppleClang/full-suite/R7 focused evidence is required after publication.

## R6 P2 DXGI-to-R4 CLANG64 preflight correction (2026-10-17)

**Initial implementation:** `c73ff9c004c453fe30a0341ac11387115cbd32ab`.  
**Initial Actions:** `39022323343`.

The implementation-SHA workflow structure guard passed. Windows/MSVC configured,
the expanded R6 native preflight passed and the complete Debug graph compiled.
MSYS2 CLANG64 verified Clang 23, configured successfully, and the complete
Debug graph also compiled successfully. The CLANG64 R6 preflight itself
reported failure before executing its CTest selection because the workflow
authoring change accidentally placed
`windows.capture-session-change-duplication-prior-revocation` and the three
new R4 sentinels inside one quoted `grep -F` pattern. That impossible
multiline literal is a CI validation defect, not a production compile, Clang
23/SDK, DXGI lifetime or R4-conversion failure.

This correction changes no production source and no CTest behavior. Debug and
Release now each enumerate the anchored R6 selector, independently require all
seven lifetime/handoff sentinel names, enforce exact **58**-case cardinality,
and then execute the selection. The workflow-structure validator also requires
the ordinary 58-case cardinality token so this registration check cannot
silently disappear.

Exact correction-SHA MSVC, CLANG64 Debug/Release and Windows CLANG64
ASan/UBSan evidence is **PENDING**. M4 remains **OPEN / NOT ACCEPTED** and no
live desktop, WTS registration, native input injection or synthetic admission
is enabled.

## R8 P2 hierarchy provenance protocol-limit receipt (2026-10-17; exact-SHA CI pending)

**Starting shared `main`:** `c73ff9c004c453fe30a0341ac11387115cbd32ab`.

MS-RDPECLIP review confirms the supported streaming contract has no trustworthy
remote parent edge. `CB_FILECLIP_NO_FILE_PATHS` requires source paths to be
omitted from file descriptions; `CLIPRDR_FILEDESCRIPTOR` supplies per-entry
metadata including the directory attribute, and File Contents `lindex`
addresses only the exact File List entry. There is no parent identifier.
The separate Direct File Access path applies only when one endpoint already has
direct access to the peer filesystem and is not implemented by R8.

No production behavior is broadened. Existing production code remains the
tested contract: path-bearing FILEDESCRIPTORW names are rejected, descriptor
indices/generations/private offer epochs stay authoritative, caller parent
metadata is bounded/acyclic and non-authorizing, and directory materialization
remains unsupported despite a separately authorized native directory
capability.

New ordinary production-backed registrations are
`clipboard.file-hierarchy-provenance-unsupported-denials`,
`clipboard.file-hierarchy-generation-replacement`, and
`clipboard.file-hierarchy-no-path-authority`. The existing
`clipboard.file-destination-plan-directory-traversal-denials` continues to
exercise missing parent, self parent, file-as-parent, parent cycle and maximum
depth rejection; existing index-generation and transactional tests cover
unique exact indices/count and all-or-nothing commit. R9's clipboard sanitizer
preflight now requires the three new registrations before executing the entire
clipboard label.

No local compile/CTest, native filesystem materialization, live clipboard or
real client is executed in this connector environment. Exact publication-SHA
hosted evidence is **PENDING**.

## R6 P2 DXGI-to-R4 handoff authoring receipt (2026-10-17)

**Authoring parent:** `2fa14da2fcfe2a78fe849c69f0051e796f4a8321`.  
**Publication:** this direct-to-main implementation; exact-SHA Actions pending.

The production change is one additive R6 capture method:
`consumeR4Frame(WindowsR4BgraFrameConsumer)`. It is a generation-carrying,
synchronous borrow only. Legacy cycles without an explicit nonzero
session/device generation fail closed. The method reuses
`consumeFrame()` for pre/post generation observation, callback reentry
denials and staging-unmap-before-`ReleaseFrame` teardown, so it neither
duplicates native capture nor creates/retains COM references.

Three new CTests execute the production seam with injected DXGI/D3D11
callbacks. The layout case also calls the real R4 `BgraNv12Converter`;
session change, same-geometry device replacement and resize cases all deny
publication and preserve native release order. No test accesses a live
desktop, registers WTS, or calls `SendInput`.

Hosted Windows/MSVC, MSYS2 CLANG64/Clang 23 and the 58-case R6
ASan/UBSan selector are required before this increment is marked validated.
M4 is not claimed.

## R9 M1 assurance and M2 sanitizer gate (2026-10-17)

**M1 candidate:** `e2c1e51d22c2c33cd0de1ca40fc2bf7f45d3c5ae`. Hosted
Actions `39018706447` is **SUCCESS** and the independent structure guard
`39018706418` is **SUCCESS**. Exact hosted ordinary CTest is Linux/GCC
**584/584 Debug + 584/584 Release**, macOS/AppleClang **495/495 + 495/495**,
Windows/MSVC **531/531 + 531/531**, and hosted MSYS2 CLANG64 / Clang 23.1.3
**531/531 + 531/531**. Windows native R6 preflight is **55/55** in Debug and
Release on MSVC and CLANG64; the CLANG64 private-fixture gate is **3/3** and
focused TLS/licensing/configuration security gate **5/5** in both
configurations. Documentation policy, both workflow-structure gates, R7 native
lifecycle/sanitizer jobs, downstream installed-SDK consumers, ZIP packaging,
SHA-256 generation and all three package uploads pass. Untagged prerelease
publication is correctly skipped.

R9 independently searched the repository validation ledger and issue/comment
coordination for same-SHA owner receipts. The owner reports local success, but
no machine transcript for `e2c1e51d...` is recorded here with exact SHA,
toolchain, full Debug CTest execution, failure/skip count and terminal result
for **all three** required owner machines (Linux/X11, Windows MSYS2 CLANG64 /
Clang 23, macOS 27). Hosted machines are not relabeled as owner evidence.
Therefore R9's independent M1 recommendation remains **OPEN**, with the only
M1 evidence blocker being the three receipted same-SHA owner runs.

**M2 assurance gate:** review of the current fail-closed R2/R3/R10 boundary
finds no production path that can turn an R3 licensing snapshot, protected
HWID bytes, peer-selected CAL root, authority generation/fingerprint or
synthetic provider into R2 desktop authority. The current R10 positive
licensing provider exists only in the noninstalled test executable; production
remains `configureUnavailable()`. R3 has no authenticated post-`Licensed`
Share state yet, so Share/DVC/input/clipboard publication cannot be positively
authorized by the licensing work in this baseline.

The Clang ASan/UBSan gate is strengthened before code-bearing M2 work:
`runtime.licensing-cli-existing-check-compatibility` is added to the existing
production-backed R1/R3/licensing selection, raising that selector from
**91 to 92** tests. Existing flat selectors are now exact-count fail-closed at
CAL **8**, adversarial credential **4**, delegated-account **6**, R10 authority
**6**, native R2/R3 GSSAPI **30**, PAM **3**, and direct R10 Linux runtime
security **12**. Every count is derived from a preceding `ctest -N`; a
missing or unexpectedly added registration fails before execution. The
existing `project.ci-workflow-structure-denials` validator is extended to
require the compatibility case and these exact-count gates; no second workflow
validator or sanitizer job is created.

The nine M2 invariants remain acceptance requirements. In particular, future
existing-CAL validation must bind genuine provider trust, exact
product/version/scope, provider policy generation, verification time and the
CAL's hardware identity to the exact MAC-verified HWID and session/request
correlation. Provider replacement must cancel pending work, stale results must
not cross sessions, and no licensing result may grant R2 or downstream
Share/DVC/input/clipboard authority. New production-backed R2/R3/R10 cases must
be added to these existing sanitizer selectors with their expected counts in
the same commit. Existing bounded CredSSP and MCS/CLIPRDR fuzzers may receive
denial seeds only when they enter the same production parsers.

**Validation of this R9 CI-only increment:** production C++ behavior is
unchanged. The exact descendant workflow is **NOT RUN at authoring time**;
GitHub Actions and the ordinary `project.ci-workflow-structure-denials`
CTest are the next gate. M2 remains **OPEN / NOT ACCEPTED** until
non-forgeable provider-backed CAL authorization and receipt-bound R2/R3
composition exist and pass the complete matrix.

## R3 M2 licensing-to-Share planning audit (2026-10-17)

This is a documentation-only architecture/roadmap audit. Production code,
CTest behavior, licensing state and Share state are unchanged.

Reviewed current R3 MCS/GCC/channel, licensing/CAL and offline Share helpers,
R2 admission/re-authorization ownership, R10 runtime licensing-authority
ownership, and current R4/R5/R8 cross-road blockers. The audit confirms that
the stateful `McsSessionLifecycle` currently ends in licensing phases and has
no post-`Licensed` Demand Active/Confirm Active/finalization phase. Existing
Share helpers are explicitly offline syntax/correlation utilities.

Normative review used MS-RDPELE 3.2.5.3 and 2.2.2.9 plus MS-RDPBCGR 1.3.1.1,
2.2.1.12.1.3, 2.2.1.13.1 and 3.3.5.3.13.2. The resulting plan keeps
CLIENT_LICENSE_INFO fail-closed until genuine issuer trust, exact
product/version/scope, CAL lifetime/classification and CAL-to-HWID binding are
established. It keeps Demand Active after licensing completion and preserves
the required Confirm Active/finalization order.

No compile, CTest, sanitizer, benchmark, owner-native run, licensing-provider
operation or Microsoft-client connection is executed for this documentation
audit: all are **NOT RUN**. The current M1 candidate remains production-frozen
pending the owner-native same-SHA matrix.

The first post-M1 R3 code target is the non-authorizing existing-CAL
authority-request snapshot described in `docs/ROADMAP.md`. Ordinary positive
tests may prove only snapshot construction/ownership/correlation; they may not
manufacture a positive licensing decision.

## R1 P1 runtime TLS post-ACL exact-SHA validation (2026-10-17)

**R10 Windows fixture correction chain:** \`e782cd642f574e7ef45792c8fe168dfad70c8d2a\`,
\`75375ccfeb7523d58d40024f783ebfe84f4db50b\`,
\`4a116fb2501b7cbd5c9314d37337508fd7ed3824\`.  
**R1 readiness correction:** \`e0fc1b3b33a6e1e98a0bf2cb19e8ecd46949b39c\`.  
**R1 Actions:** \`39014912488\` — **SUCCESS**.

The original Windows failure at \`tests/check_runtime_tls_context.cmake:72\`
was fixture preparation, not transport execution. After R10's shared helper
removed inherited and explicit broad-principal allow ACEs and applied the
current-owner grant, hosted MSYS2 CLANG64 proves fixture setup succeeds before
the R1 transport cases run. On the corrected R1 SHA, the Windows fixture
preflight is **3/3 PASS Debug + Release**:
\`runtime.windows-private-fixture-dacl-creation\`,
\`runtime.windows-private-fixture-broad-access-denials\`, and
\`runtime.windows-private-fixture-owner-consistency\`.

The two P1 target CTests remain generated exactly once from the existing
\`runtime_transport_case\` list in \`tests/CMakeLists.txt\`:
\`transport.tcp-owned-runtime-tls-handshake\` and
\`transport.tcp-owned-runtime-tls-identity-continuity\`. They use the same
R10 \`check_runtime_tls_context.cmake\` fixture writer and then execute
\`test_owned_preauth_session\` against production \`RuntimeServerTlsContext\`
and \`OwnedPreauthTcpConnection\`. The handshake test covers real loopback
HYBRID/X.224 negotiation, an R10-created server SSL, exact selected certificate,
bounded encrypted application I/O, peer endpoint continuity, clean TLS close,
raw transport close and terminal cancellation. The identity-continuity test
loads the R10 context, replaces both configured credential pathnames with
invalid material, then proves the retained certificate remains the exact one
presented through the same R1-owned TLS object; R3 remains blocked at
\`AwaitVerifiedR2Admission\`.

Before the R1 correction, hosted CLANG64 at R10 SHA \`4a116fb2...\`, Actions
\`39012368322\`, already proved the ACL blocker was gone: Clang **23.1.3**,
OpenSSL **3.6.5**, fixture preflight **3/3 PASS**, focused security preflight
including \`transport.tcp-owned-runtime-tls-handshake\` **5/5 PASS**, and both
runtime TLS targets PASS in Debug and Release full suites. That wider sweep
exposed a separate R1 test-driver defect in
\`transport.tcp-native-loopback-tls\`: its nonblocking handshake serialized
waiting on one unfinished peer and could starve the other peer's current WANT
direction.

R1 correction \`e0fc1b3b...\` changes only the real-loopback test scheduler:
both client and server WANT_READ/WANT_WRITE interests are observed with one
bounded native \`select\`, and only ready endpoints advance one SSL step. It
does not change production TCP/BIO/SSL code, TLS ownership, pinned certificate
identity, the single connection reader/writer, terminal cancellation, or the
18 KiB application-I/O ceiling.

Exact corrected evidence:
- **Hosted MSYS2 CLANG64:** Clang **23.1.3**, OpenSSL **3.6.5**; full CTest
  **531/531 PASS Debug + 531/531 PASS Release**. The repaired
  \`transport.tcp-native-loopback-tls\` passes as test #178. The P1 runtime TLS
  handshake and identity-continuity tests pass as #382/#383 in both
  configurations. Fixture preflight remains **3/3 PASS** in both.
- **Windows/MSVC:** native focused preflight **55/55 PASS Debug + Release**;
  full CTest **531/531 PASS Debug + 531/531 PASS Release**. The loopback and
  both runtime TLS targets pass in both configurations.
- **Linux/GCC:** **584/584 PASS Debug + 584/584 PASS Release**; loopback #178
  and runtime TLS #389/#390 pass in both.
- **macOS/AppleClang:** **495/495 PASS Debug + 495/495 PASS Release**;
  loopback #178 and runtime TLS #327/#328 pass in both.
- **R9 Clang ASan/UBSan:** bounded R1/R3 transport/security/licensing selection
  **91/91 PASS**, explicitly running both runtime TLS targets as #389/#390.
  The full hosted regression matrix also keeps the existing HYBRID,
  application-I/O, licensing cancellation and terminal-readiness R1 cases.
- Workflow structure, documentation policy, R7 sanitizer/native lifecycle,
  installed SDK consumer/package gates and all configured hosted jobs PASS;
  untagged prerelease publication is correctly **SKIPPED**.

The owner's canonical persistent Windows MSYS2 CLANG64 command remains
**NOT RUN in this connector environment**: this agent cannot execute commands
inside the owner's \`~/rdp-server/build/\` checkout. The hosted CLANG64 result
matches the required compiler family/version and proves the post-fixture
transport path, but it is not relabeled as owner evidence. M1 therefore still
requires the owner to run:

\`\`\`sh
cd ~/rdp-server
git rev-parse HEAD
ctest --test-dir build -C Debug \
  -R '^transport\\.tcp-owned-runtime-tls-(handshake|identity-continuity)$' \
  --output-on-failure -V
\`\`\`

**Next R1:** no production transport change is justified by P1. Preserve the
current single TLS owner and wait for either owner-native same-SHA evidence or
a later live R2/R3 boundary that demonstrates an actual bounded transport
defect. Do not fabricate authentication, CAL authority or premature licensing
publication.

## R4 segmented-frame retirement reuse exact hosted receipt (2026-10-17)

**Implementation:** `9fe503cfe03722b1145d1fc9eaf4b28a417a1c9c`.  
**Validated unchanged-R4 descendant:** `e0fc1b3b33a6e1e98a0bf2cb19e8ecd46949b39c`.  
**Actions:** `39014912488` — **SUCCESS**.

The implementation-SHA run `39014837758` already proved the new R4 cases on
Linux, macOS, Windows/MSVC Debug and R9, but its full platform jobs were red
only at the independent R1 `transport.tcp-native-loopback-tls` fixture. R1
then corrected that test driver without touching R4. The unchanged-R4
descendant is fully green.

Hosted evidence: Linux/GCC **584/584 Debug + Release**; macOS/AppleClang
**495/495 Debug + Release**; Windows/MSVC **531/531 Debug + Release** after
**55/55** native preflight in both; MSYS2 CLANG64 Clang **23.1.3**
**531/531 Debug + Release**. The two new R4 cases pass in every full ordinary
configuration.

R9 is **SUCCESS** with portable graphics **41/41** and x264/BGRA **24/24**.
`graphics.avc420-segmented-frame-retirement-reuse` passes as item **41/41**;
`graphics.x264-segmented-retirement-reuse` passes as **10/24**. The latter
proves completed-slot reuse retains P-frame reference continuity and
post-abort fresh-generation reuse starts IDR.

No live Graphics DVC, native desktop, benchmark or Microsoft-client acceptance
is claimed. Canonical owner-local execution remains **NOT RUN** in this
connector environment.

## R1 P1 runtime TLS verification and native-loopback readiness correction (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `9fe503cfe03722b1145d1fc9eaf4b28a417a1c9c`.

R10's Windows synthetic credential-fixture correction is present on shared main: SID-native/private-DACL setup was centralized at `e782cd642f574e7ef45792c8fe168dfad70c8d2a`, the PowerShell ACL-module dependency was removed at `75375ccfeb7523d58d40024f783ebfe84f4db50b`, and explicit broad-principal ACE normalization landed at `4a116fb2501b7cbd5c9314d37337508fd7ed3824`.

The P1 target cases are centrally generated once from the existing `runtime_transport_case` list: `transport.tcp-owned-runtime-tls-handshake` and `transport.tcp-owned-runtime-tls-identity-continuity`. On hosted MSYS2 CLANG64 at `4a116fb2...`, Actions `39012368322`, Clang **23.1.3** / OpenSSL **3.6.5**, all three R10 private-fixture ACL tests pass first. The runtime TLS handshake then passes in the focused five-case security preflight, and both runtime TLS cases pass in the complete Debug and Release 527-test registries. The tests therefore progress beyond fixture setup into the production `RuntimeServerTlsContext` and R1 `OwnedPreauthTcpConnection` path, including real loopback handshake, exact certificate comparison, negotiation provenance, bounded application I/O and terminal cancellation. This hosted evidence does not replace the owner's same-SHA persistent MSYS2 CLANG64 run.

The required wider R1 regression sweep exposed a separate test-driver defect: `transport.tcp-native-loopback-tls` failed on Linux/GCC, macOS/AppleClang, Windows/MSVC and hosted CLANG64 at the five-second readiness assertion. The test advanced both nonblocking TLS peers once and then waited only on the server socket whenever the server was unfinished. When both peers were unfinished and the client needed to consume server-produced handshake bytes, that serialized wait could starve the client until the deadline.

This correction is test-only. The loopback fixture now records each peer's current WANT direction and performs one bounded native `select` over the union of both sockets. The next SSL step is invoked only for the peer whose current read/write readiness was observed. No production TCP/BIO/SSL source, TLS owner, certificate pinning, 18 KiB application-I/O ceiling, reader/writer authority or cancellation behavior changes. The existing dedicated `transport.tcp-native-loopback-tls` CTest remains the behavior gate; no duplicate test or executable is added.

Canonical owner `~/rdp-server/build/` MSYS2 CLANG64 execution is **NOT RUN** in this connector environment. Exact publication-SHA hosted Linux/GCC, macOS/AppleClang, Windows/MSVC, hosted CLANG64, R9 sanitizer and documentation-policy evidence are **PENDING**.

## R4 segmented-frame retirement reuse authoring receipt (2026-10-17)

**Starting shared `main`:** `f7f8f83c968332cf2b3d86d999cfe2142bec1045`. Exact publication-SHA hosted
validation is **PENDING**.

Successful full delivery and successful terminal abort now invalidate
`GfxAvc420SegmentedFrame` exactly like successful conclusively unwritten
cancellation; failed retirement attempts preserve the owner and wire bytes.
Producer completion preserves x264 reference continuity, while terminal abort
still resets the encoder generation.

New ordinary production-backed tests are
`graphics.avc420-segmented-frame-retirement-reuse` and
`graphics.x264-segmented-retirement-reuse`. R9 registry preflights select
**41** portable R4 cases and **24** x264/BGRA cases after this change.

Pre-change SHA `1c91b828a18e94e286863197b20d72a7440ae3bf`, Actions
`39013412507`, executes the preceding R4 owner-overwrite tests successfully
and passes R9 **40/40** portable graphics plus **23/23** x264/BGRA. That
workflow is overall **FAILURE** only because
`transport.tcp-native-loopback-tls` fails outside R4; it is baseline evidence,
not validation of this new retirement behavior.

Canonical local testing is **NOT RUN** here. No live Graphics DVC, native
desktop, benchmark or Microsoft-client acceptance is claimed.

## R9 P1 Windows CLANG64 security-fixture validation receipt (2026-10-17)

Exact hosted SHA `1c91b828a18e94e286863197b20d72a7440ae3bf`:

- Primary workflow `39013412507`: **FAIL**, solely from
  `transport.tcp-native-loopback-tls` in the full platform suites.
- Independent structure guard `39013412399`: **PASS**; primary
  `ci-workflow-structure`: **PASS**.
- Hosted MSYS2 CLANG64 reports **Clang 23.1.3**.
- R10 private-fixture gate: **3/3 PASS Debug + 3/3 PASS Release**.
- Representative TLS/licensing/config security gate: **5/5 PASS Debug +
  5/5 PASS Release**.
- Full CLANG64 CTest: **528/529 PASS Debug + 528/529 PASS Release**; sole
  failure `transport.tcp-native-loopback-tls` with `0xc0000409`.
- Windows/MSVC full Debug: **528/529 PASS**; sole failure the same R1 test.
  Its native R6 preflight is **55/55 PASS**.
- Linux/GCC full Debug: **577/578 PASS**; sole failure the same R1 test.
- macOS/AppleClang full Debug: **492/493 PASS** after focused R7 **17/17
  PASS**; sole failure the same R1 test.
- R9 Clang ASan/UBSan: **PASS**. R7 sanitizer and isolated Apple lifecycle:
  **PASS**. Documentation policy: **PASS**.

The dedicated broad-access denial fixture passes only after the shared R10
helper verifies a private baseline, then deliberately adds the intended broad
ACE and reaches the production validator. This is evidence that insecure ACL
negative cases still deny for the intended security reason rather than merely
failing fixture setup.

SDK consumer, package, digest and artifact-upload stages are **SKIPPED / NOT
EVIDENCE** on this exact SHA because the ordinary platform jobs stop after the
unrelated R1 Debug failure. No test regex, platform exclusion or count reduction
was used to hide the original Windows ACL failures.

The available owner transcript remains **454/507 PASS, 53 FAIL** but does not
contain `git rev-parse HEAD`, `clang++ --version` or captured native
`icacls` diagnostics. Therefore the exact owner SHA/compiler/failure
mechanism cannot be reconstructed honestly from repository evidence; owner
rerun at the agreed candidate remains required.

## R6 P2 Windows CLANG64 ASan/UBSan exact-SHA validation (2026-10-17)

**Validated R6 source/gate SHA:** `a97933bf7a2b523dac641e97776e111d46a28be0`.  
**Primary Actions:** `39012969426` — overall **FAIL** at the independent R1
native-loopback TLS boundary.  
**Standalone workflow-structure Actions:** `39012969408` — **SUCCESS**.  
**R6 CLANG64 job:** `117339230169`.

MSYS2 CLANG64 provisioned Clang **23.1.3-1** targeting
`x86_64-w64-windows-gnu`, MinGW-w64 headers/CRT
**14.0.0.r426.g4564ee4b5-1**, libc++ **23.1.3-1**, CMake **4.4.4-3**,
Ninja **1.13.2** and OpenSSL **3.6.5-1**. The Windows API surface for this
toolchain remains the MinGW-w64 headers/import libraries rather than a
Microsoft Windows SDK.

The existing production-linked R6 selector
`^windows\.(geometry|capture|cursor|input)-` passes **55/55 in ordinary
Debug** and **55/55 in ordinary Release**. Both complete CLANG64 build graphs
also succeed. The full Debug and Release CTest invocations each finish
**528/529 PASS**, with the sole failure
`transport.tcp-native-loopback-tls` (exit `0xc0000409`) at R1's
`waitForLocalSocketReady(...)` readiness assertion. R6 does not alter or
mask that cross-road failure.

After those ordinary gates, the same `build/` root reconfigures to Debug with
Clang AddressSanitizer + UndefinedBehaviorSanitizer
(`-fsanitize=address,undefined -fno-omit-frame-pointer
-fno-sanitize-recover=all`). The sanitizer build recompiles the complete
production `rdp-server-windows-desktop` object set plus the existing
`test_windows_desktop_geometry` fixture and links successfully. The
fail-closed preflight enumerates exactly **55** R6 behaviors, including all
four whole-owner session-retirement sentinels, and the instrumented execution
is **55/55 PASS** with `ASAN_OPTIONS=halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. No ASan or UBSan
diagnostic is emitted.

This closes the previously open **hosted Windows memory/UB instrumentation
gap** for R6's deterministic synthetic DXGI/D3D11/session/input ownership
paths. It preserves the established lifetime contract: staging unmap before
DXGI frame release; child/capture retirement before parent COM release;
duplication -> output1 -> D3D11 context -> device -> output -> adapter ->
factory exact-once teardown; callback-time logical revocation with serialized
safe-point physical teardown; and held-input retirement without post-revocation
native input.

The sanitizer result does **not** prove a live D3D11/DXGI desktop, real WTS
notification delivery or actual `SendInput`; those native calls remain
deliberately absent from ordinary tests. It also does not replace R10's
owner-native Windows MSYS2 CLANG64/Clang 23 M1 row.

**R6 hosted status:** no known R6-owned Clang 23, COM lifetime, ASan or UBSan
failure remains in the exercised production-backed Windows path.  
**M1:** **OPEN / NOT ACCEPTED** because the same-SHA owner-native matrix is
still incomplete and the full hosted matrix is red at R1.  
**M4:** **OPEN / NOT ACCEPTED** pending a real R2-admitted Windows user
desktop, R10 serialized native session-change delivery, R3 authenticated input
routing and Microsoft-client graphics/input acceptance.

## R2 final credential/native admission compile correction (2026-10-17)

Exact authoring SHA `524f8575be5892803c1ba73a4a9479e063730d29`
failed hosted Linux Debug compilation before tests because the new private R1
CredSSP-completion check referenced conceptual provenance names
`selectedProtocol` / `requestedProtocols` rather than the existing
`SecurityNegotiationProvenance` members `serverSelectedProtocol` /
`clientRequestedProtocols`. This correction changes only those two member
references. The required exact HYBRID selection/offer checks, private ownership
chain, credential/PAM/native admission ordering and denial test are unchanged.

## R2 final credential/native admission join authoring receipt (2026-10-17)

**Starting shared `main`:** `a97933bf7a2b523dac641e97776e111d46a28be0`.

This publication joins the already validated real PAM invocation boundary to
the existing concrete Linux NSS/logind admission broker without adding a test
authority seam. Production changes span only the existing R1 transport owner,
R2 GSS/CredSSP acceptor, Linux admission broker and Linux runtime aggregate.
A PAM `Authorized` result retains only the validated local account; the
password remains synchronous and cleansed. The completion latch and R1
CredSSP-to-MCS phase transition occur only after concrete native session
evidence and the revocation watch are current.

Dedicated ordinary coverage is
`runtime.linux-connection-final-credential-native-admission-denials`. It
establishes real loopback HYBRID TLS using the existing production transport and
explicitly provisions the PAM verifier when that build mode is enabled, but
does not fabricate GSS completion or PAM authorization. It requires an
otherwise policy-shaped admission request to terminate without a lease. The R9
direct runtime-security ASan/UBSan selector requires the exact registration in
addition to the existing runtime cases.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is
**NOT RUN** because that checkout is unavailable in this connector environment.
Exact publication-SHA workflow structure, documentation policy, hosted
Linux/GCC and R9 sanitizer execution are **PENDING**. Genuine positive
Kerberos/PAM/NSS/logind owner admission and authenticated Microsoft-client
acceptance are **NOT RUN** and are not inferred from denial-only CI.

## R6 P2 Windows sanitizer continuation-fence correction (2026-10-17)

**Initial P2 publication:** `bcf8736ce12b061ba62538f2404669b8b4fa1157`,
Actions `39012212923`. Its R6 CLANG64 Debug native preflight was **55/55
PASS** and the R10 focused Windows security preflights passed. The ordinary
full Debug suite then finished **526/527 PASS**, failing only the independent
R1 `transport.tcp-native-loopback-tls` readiness assertion. Because the
initial P2 sanitizer steps followed that full-suite failure with default
GitHub Actions `success()` semantics, Release and sanitizer execution were
skipped; this is negative CI-gate evidence, not sanitizer or R6 source evidence.

On unchanged R6 production code, descendant
`4a116fb2501b7cbd5c9314d37337508fd7ed3824` / Actions
`39012368322` proves the R9 failure-isolation mechanism: R6 Debug and Release
native preflights both pass, both complete CLANG64 build graphs succeed, and
the sanitizer reconfiguration itself succeeds even though the unrelated R1
full Debug/Release tests remain red. That run exposed the final R6-owned gate
defect: the sanitizer build and execution steps lacked their own explicit
`always()` dependency fences and were therefore skipped after the earlier
full-suite failure.

This correction gives sanitizer configure/build explicit step IDs and allows
each dependent sanitizer stage to run only when its immediate sanitizer
predecessor succeeded, regardless of unrelated earlier test failures. The
workflow-structure validator requires both dependency expressions so the
failure-isolation contract cannot silently regress. No production source,
CTest behavior, COM ownership assertion, WTS behavior or SendInput path
changes.

Exact correction-SHA ASan/UBSan execution is **PENDING**. M1 remains tied to
R10's owner-native same-SHA matrix, and M4 remains **OPEN / NOT ACCEPTED**.

## R7 P1 isolated Apple lifecycle validation receipt (2026-10-17)

**SHA:** `583b04b860ce38dda6b3b90001d7f92a3146d3f6`.  
**Actions:** `39012096608` — overall **FAIL outside R7**.  
**Structure run:** `39012096590` — **SUCCESS**.

R7-specific evidence on the exact SHA is green:

- `r7-macos-native-lifecycle`: **SUCCESS**; **17/17 Debug** and
  **17/17 Release** after fail-closed registry preflight.
- `r7-macos-session-sanitizers`: **SUCCESS**.
- `r9-security-protocol-sanitizers`: **SUCCESS**.
- `documentation-policy` and both workflow-structure validations:
  **SUCCESS**.
- Hosted Apple: macOS **26.6.2 (25G83)**, Xcode **26.6 (17F113)**,
  `/Applications/Xcode_26.6.app/Contents/Developer`, Apple clang
  **21.0.0 (clang-2100.1.1.101)**, CMake AppleClang
  **21.0.0.21000101**, SDK **26.5**.

The primary macOS job independently passes the 17-case R7 Debug gate and then
fails only full-suite R1 `transport.tcp-native-loopback-tls` (#178) at the
bounded readiness assertion in `test_owned_preauth_session.cpp:6028`.
Ubuntu and Windows CLANG64 fail the same R1 boundary; Windows/MSVC has that R1
failure plus then-current R10 private-DACL fixture denials. The isolated R7 job
does not use `continue-on-error` and does not convert those failures into an
M1 pass.

Owner macOS 27/TCC/native-session-switch evidence is **NOT RUN**. No permission
request or live desktop access occurred. Genuine R2/R3 positive macOS desktop
admission is still unavailable; the ScreenCaptureKit factory remains
quarantined. **M1 OPEN / NOT ACCEPTED. M5 OPEN / NOT ACCEPTED.**

## R8 native directory-capability factory exact-SHA validation receipt (2026-10-17)

**Implementation:** `0eb444bfab7ae0ce23dde22ba8c5e45c19212c4e`.  
**Actions:** `39012180330` — overall **FAIL** from cross-road failures; R8
factory/binding evidence **PASS**.

Observed exact-SHA R8 results:

- Linux/GCC Debug registry: binding authority **PASS**, binding retirement
  **PASS**, Linux native directory capability **PASS**.
- macOS/AppleClang Debug registry: binding authority **PASS**, binding
  retirement **PASS**, macOS native directory capability **PASS**.
- Windows/MSVC Debug registry: binding authority **PASS**, binding retirement
  **PASS**, Windows native directory capability **PASS**.
- Hosted MSYS2 CLANG64/Clang 23 Debug registry: binding authority **PASS**,
  binding retirement **PASS**, Windows native directory capability **PASS**.
- R9 Clang ASan/UBSan complete clipboard selection: **71/71 PASS**, including
  both binding cases and `clipboard.linux-directory-capability-native`.
- CI workflow structure and documentation policy: **PASS**.

The exact run's non-R8 failures are retained rather than hidden. Linux, macOS
and CLANG64 full Debug suites later fail the independent R1 native-loopback TLS
readiness assertion. Windows/MSVC later fails R10's synthetic private-DACL
fixture setup. Those failures suppress some Release/package stages, so this
receipt does not claim a complete green repository matrix.

Source review matches the executed tests. POSIX accepts only an already-open
directory descriptor and uses object inspection plus `F_DUPFD_CLOEXEC`.
Windows accepts only an already-open disk-directory HANDLE, rejects a final
reparse point and duplicates it with `DuplicateHandle`. The binding pins the
exact current source generation, planned remote directory index and local
selection identity, while the native token comes only from the separately
supplied caller capability. Cancellation, source retirement and close release
the duplicate exactly once.

No child object is created by this implementation. The current remote
FILEDESCRIPTORW parser still rejects slash/backslash/colon path syntax and
stores only leaf metadata; the destination plan still reports
`UnsupportedWithRetainedMetadata` for hierarchy and
`UnsupportedDirectoryMaterialization` for directory associations. A
caller-selected plan parent is local placement metadata, not proof of the
remote tree.

**Security/roadmap decision:** component-relative creation remains **BLOCKED on
verified hierarchy provenance**. R8 must not add POSIX `openat`/`mkdirat`,
Windows pathname reopen, or any directory materialization merely because a
native parent directory capability is now held. A future creation contract must
first define where authenticated/verified parent-child relationships come from
and then add dedicated traversal, symlink/reparse, collision, cancellation and
generation-replacement CTests against the actual native implementation.

Canonical owner-local `~/rdp-server/build/` execution and live filesystem /
Explorer / Finder / Nautilus directory-tree acceptance are **NOT RUN** in this
agent environment. No M1-M6 acceptance claim is made.

## R5 deterministic native-X11 event-readiness exact-SHA receipt (2026-10-17)

`c94c001f7e876df3f353948609a326f78481c1f3`, Actions
`39012274592`: R9's supported Linux/X11 profile enumerates exactly **33** R5
tests and executes **33/33 PASS** under Clang 18.1.3 ASan/UBSan after the seven
test-harness scheduler sleeps were replaced by checked XCB ordering plus
production-connection round trips.

The changed display-error, Damage/event-routing, R4 read-boundary, RandR
rebuild and XI2 pointer event/rebuild cases all pass. Ubuntu/GCC 13.3 Debug is
**574/575 PASS**; its sole failure is R1
`transport.tcp-native-loopback-tls`. macOS and Windows CLANG64 fail that same
R1 fixture, and ordinary Windows/MSVC additionally fails the separate R10
private-ACL fixtures. The R5 sanitizer block itself, documentation policy and
workflow-structure checks are green.

No R5 production failure is present. Owner Linux/X11 and Microsoft-client M3
acceptance remain **NOT RUN**.

## R3 unchanged-descendant validation follow-up (2026-10-17)

At unchanged-R3 descendant
`75375ccfeb7523d58d40024f783ebfe84f4db50b`, Actions
`39012029960`, R3 remains **scoped PASS / Release gate BLOCKED by R1**.

Linux/GCC, macOS/AppleClang/OpenSSL 4 and Windows/MSVC each execute all eight
CAL registrations #67-#74 successfully in Debug, including
`transport.licensing-client-cal-issuer-constraints`. R9 Clang ASan/UBSan
enumerates exactly eight CAL tests and reports **8/8 PASS**; the broader
bounded R1/R3 sanitizer selection reports **91/91 PASS**.

All three ordinary Debug suites later fail the same independent R1
`transport.tcp-native-loopback-tls` readiness assertion at
`test_owned_preauth_session.cpp` around line 6028. Release compile/CTest is
therefore skipped on all three ordinary jobs. No R3 source changed between
`1332fd044773b9da53bff2d81403204ecd137484` and this descendant.

Canonical local and real-client acceptance remain **NOT RUN**. Further R3 CAL
semantics remain gated on a future unchanged-R3 descendant that reaches
ordinary Release.

## R4 segmented-frame overwrite hardening authoring receipt (2026-10-17)

**Starting shared `main`:** `4a116fb2501b7cbd5c9314d37337508fd7ed3824`. Exact publication-SHA hosted
validation is **PENDING**.

Live `GfxAvc420SegmentedFrame` objects are no longer move-assignable, and
direct/x264/BGRA prepare paths fail closed on occupied output before lifecycle
or codec mutation. New ordinary CTests are
`graphics.avc420-segmented-frame-owned-output-reuse-denials` and
`graphics.x264-segmented-owned-output-reuse-preflight`; R9 preflights now
cover **40** portable R4 cases and **23** x264/BGRA cases.

Pre-change shared-main `75375ccfeb7523d58d40024f783ebfe84f4db50b`
executed all existing R4 graphics cases successfully on Linux and macOS; those
full jobs failed only at the unrelated R1 native-loopback TLS readiness
assertion. That is baseline evidence, not validation of this new behavior.
Canonical local testing and exact publication-SHA hosted validation remain
**NOT RUN / PENDING**.

## R10 hosted Windows explicit-ACE evidence (2026-10-17)

At `75375ccfeb7523d58d40024f783ebfe84f4db50b`, the hosted MSYS2 CLANG64
dedicated R10 fixture preflight **PASSed**. Hosted Windows/MSVC reached the
descriptor verifier but failed because the resulting synthetic file still had
an explicit Built-in Users (`S-1-5-32-545`) allow ACE after inheritance
removal. The diagnostic named the SID and native path, proving this was a
fixture normalization difference rather than a production authorization
failure.

The helper now removes broad-principal allow ACEs explicitly before applying
the owner SID grant. This remains test-only and stricter than merely trusting
`icacls` success. Owner-native classification of the original generic
failure remains **NOT RUN** until the owner reruns the corrected publication
SHA.

## R9 P1 CLANG64 cross-road evidence authoring receipt (2026-10-17)

Parent `c94c001f7e876df3f353948609a326f78481c1f3`; exact publication-SHA Actions **PENDING**. The existing
Debug/Release 3-case R10 fixture and 5-case production-backed security
preflights remain unchanged. Explicit `always()` conditions are tied to
successful configure/build outcomes so unrelated test failures cannot suppress
Release fixture/full-suite evidence. Failed steps remain job failures.

R10's demonstrated hosted Windows/MSVC failure was a PowerShell
`Microsoft.PowerShell.Security` autoload failure in the test helper. The
current R10 .NET `File.GetAccessControl()` correction is preserved verbatim;
R9 changes no ACL fixture code or production validator.

## R5 deterministic native-X11 event-readiness authoring receipt (2026-10-17)

**Starting shared `main`:** `bcf8736ce12b061ba62538f2404669b8b4fa1157`. Exact publication-SHA CI is
**PENDING**.

Seven Xvfb/native fixture sleeps were removed from the R5 desktop/display test
paths. Checked helper requests are now followed by a production-connection XCB
round trip and queued-only event draining, matching the existing R5 testing
standard. Existing behavior registrations remain unchanged, including
`x11.display-event-failure-defers-owner-teardown`,
`x11.desktop-resource-event-routing`,
`x11.desktop-resource-r4-read-boundary`,
`x11.desktop-resource-randr-rebuild`,
`x11.desktop-resource-pointer-event-routing` and
`x11.desktop-resource-pointer-randr-rebuild`.

No production X11 or authority behavior changes. Owner Linux/X11 and genuine
Microsoft-client M3 acceptance remain **NOT RUN**.

## R6 P2 Windows CLANG64 sanitizer authoring receipt (2026-10-17)

**Authoring parent:** `0eb444bfab7ae0ce23dde22ba8c5e45c19212c4e`.  
**Publication:** this direct-to-main commit; exact-SHA Actions pending.

The Windows CLANG64 parity job now adds one same-root Debug sanitizer
configuration after its ordinary Debug/Release validation. It applies Clang
ASan+UBSan to the production Windows desktop adapter and the existing
`test_windows_desktop_geometry` fixture, fail-closes on the exact 55-case
R6 selector cardinality and the four whole-owner retirement registrations, and
runs the selected synthetic native lifetime suite with halt-on-error runtime
settings.

No production source or behavior was changed and no new CTest was invented:
the purpose is to instrument the already dedicated production-backed R6
lifetime tests rather than duplicate them. Live desktop capture, WTS
registration, `SendInput`, credentials and user-session mutation remain
absent. Owner-native M1 and real-client M4 evidence remain separate and are
not claimed by this hosted sanitizer gate.

## R8 native directory-capability duplication authoring receipt (2026-10-17)

The preceding portable binding at
`446f13677d57d2ef3bead65bb65dcc460e1fde3a` has direct hosted R8 evidence:
both new binding cases pass on Linux/GCC and macOS/AppleClang, and R9's complete
clipboard ASan/UBSan selection is **70/70 PASS** with both registrations
executed. Those platform full-suite failures are cross-road: R1 loopback TLS on
Linux/macOS and concurrent R10 Windows private-fixture setup.

The follow-on production change adds no creation API. The POSIX factory accepts
only an already-open directory descriptor, verifies it with `fstat`, and
duplicates it using `F_DUPFD_CLOEXEC`. The Windows factory accepts only an
already-open disk-directory HANDLE, verifies directory metadata, rejects a
final reparse-point object, and uses `DuplicateHandle`. Both factories expose
only the existing duplicate/close seam.

The platform-native tests directly exercise each factory before passing it into
`RemoteDirectoryCapabilityBinding`: a directory object duplicates
successfully, a pipe is rejected as the wrong native type, the duplicate is
independently owned, and the caller can close its original after bind without
changing the binding's generation/plan currentness. No test opens a user
destination or creates a remote-derived path.

Exact publication-SHA compile/CTest/sanitizer evidence for these factories is
required before the native boundary is called green. Directory hierarchy and
relative child materialization remain unsupported.

## R7 P1 hosted lifecycle isolation authoring receipt (2026-10-17)

**Starting reconciled shared `main`:** `75375ccfeb7523d58d40024f783ebfe84f4db50b`.  
Exact publication-SHA hosted validation: **PENDING**.

Preceding R7 CI SHA `dc8ad556c6f306b2678aee8d3c1d29284f6d1f85`
registered and passed the focused macOS Debug selection **17/17** on Actions
`39011565660`. Its full macOS Debug suite then failed only R1
`transport.tcp-native-loopback-tls` (#178) at the readiness assertion, so
Release was skipped. Unchanged-R7 descendant `e782cd642f574e7ef45792c8fe168dfad70c8d2a`
again passed **17/17** focused R7 Debug cases before the same R1 failure.

This increment adds a separate `r7-macos-native-lifecycle` hosted Apple job so
R7's Debug and Release registration/execution evidence remains observable across
unrelated full-suite failures. It builds only
`test_macos_capture_pixel_buffer`, `test_macos_input_controller`,
`test_macos_desktop_session_guard` and Apple-only
`test_macos_capture_stream`, records exact Apple host/toolchain metadata, and
runs the same fail-closed seventeen-case selector in both configurations. The
primary protocol job remains unchanged and authoritative for the full suite.

No live desktop or TCC request occurs. Owner macOS 27 and M5 remain **NOT RUN**.

## R10 first hosted ACL-helper diagnostic and correction (2026-10-17)

At `e782cd642f574e7ef45792c8fe168dfad70c8d2a`, hosted Windows/MSVC reached
the new fixture helper and failed with a concrete helper diagnostic:
`WindowsPowerShell/v1.0/powershell.exe` exited 1 because `Get-Acl` could
not autoload `Microsoft.PowerShell.Security`. The full Debug suite therefore
reported **57/524 FAIL**, including the three new dedicated fixture tests.
This is negative evidence for that R10 publication and must not be confused
with the owner's earlier generic `icacls` failure.

The correction removes the PowerShell-module dependency and reads the same
native security descriptor via
`[System.IO.File]::GetAccessControl()`. All SID and DACL assertions remain
fail closed. Corrected-SHA hosted Windows/MSVC, hosted CLANG64 and owner-native
results are **PENDING**.

## R9 P1 Windows CLANG64 fixture-gate authoring receipt (2026-10-17)

**Authoring parent:** `611e3279d7bffc3678bcd8ec899210e14a446cd8`. Exact publication-SHA Actions: **PENDING**.

Source evidence retained without inference: the owner full CTest output ends
**90% tests passed, 53 failed out of 507** and lists all 53 failures, dominated
by generic pre-R10 fixture errors such as `Cannot set private synthetic fixture
DACL`, `Cannot set private synthetic config DACL` and
`Cannot set synthetic TLS fixture DACL`. The supplied transcript contains no
Git SHA, compiler version or captured `icacls` diagnostic. R10's
`e782cd642f574e7ef45792c8fe168dfad70c8d2a` repair must therefore be rerun by
the owner before Windows M1 evidence can close.

R9 adds no production code and no alternative ACL implementation. Hosted
CLANG64 now preflights and executes the three R10 fixture CTests plus five
representative affected production-backed security cases in Debug and Release,
with exact registry counts 3 and 5. The structure validator requires all eight
sentinel names to remain present in the shared CI workflow.

## R8 directory-capability binding authoring receipt (2026-10-17)

**Implementation:** `446f13677d57d2ef3bead65bb65dcc460e1fde3a`.  
**Actions:** `39011707625` — execution pending at authoring.

The new noninstalled `rdp-server-clipboard-directory-capability` target owns
only a portable lifetime binding around an injected native duplicate/close
seam. A successful bind requires the exact current
`RemoteFileDestinationPlan` association to have role `Directory`; a
file-role association is terminally rejected before the native callback. The
binding records the exact generation/index/local-selection identity only after
the caller capability has been independently duplicated.

`clipboard.directory-capability-binding-authority` proves that the plan's
numeric `localSelectionIdentity` does not become native authority: the fake
native owner rejects that value, while a separate caller token succeeds.
`clipboard.directory-capability-binding-retirement` proves plan cancellation,
generation replacement and local cancellation close the owned duplicate once
without resurrection. Both registrations are required by R9's fail-closed
clipboard registry before the full sanitizer label executes.

No local path, remote leaf name or child component enters the new API. It
cannot create a directory, open a child, follow a symlink/reparse point, publish
a clipboard object or schedule FileContents. Directory transfer/publication
remains explicitly unsupported; this is only the prerequisite capability
lifetime boundary.

The implementation SHA's documentation-policy job fails only because this
documentation co-change was not present in that code commit. Do not treat that
expected policy failure as executable R8 evidence, and do not call the
implementation green until the platform compile/CTest/sanitizer jobs complete.

## R3 CAL issuer-constraints exact-SHA validation receipt (2026-10-17)

`1332fd044773b9da53bff2d81403204ecd137484`, Actions
`39011519138`: **R3 scoped PASS / workflow overall FAIL from independent R1**.

The first issuer-constraint publication `586101c7e50326f583ab0479bbfb6785353807b7`
failed macOS/OpenSSL 4 compilation before CTest because its borrowed
`X509_EXTENSION` pointer discarded constness. Correction `1332fd044773...`
changes only that borrowed pointer to `const X509_EXTENSION *const`.

On the corrected SHA:
- Linux/GCC Debug: all eight CAL cases #67-#74 **PASS**; the 572-test suite later
  fails only at R1 `transport.tcp-native-loopback-tls`.
- macOS/AppleClang/OpenSSL 4 Debug: all eight CAL cases #67-#74 **PASS**; the
  488-test suite later fails at the same R1 case.
- Windows/MSVC Debug: all eight CAL cases #67-#74 **PASS**; the 521-test suite
  later times out at the same R1 case.
- R9 Clang ASan/UBSan: flat CAL registry preflight enumerates exactly eight
  cases and executes **8/8 PASS**; the larger bounded R1/R3 group is **91/91
  PASS**.
- CI structure, R7 sanitizer and documentation policy are **PASS**.

Ordinary Release, installed-consumer/package and publication stages are
**NOT RUN** because ordinary Debug fails later outside R3. Canonical local
testing and real Microsoft-client CAL acceptance are **NOT RUN**.

## R5 P1 native-X11 registry cardinality exact-SHA receipt (2026-10-17)

`3e2962cb22c03a30ebc34ad736da7f53cdc70da6`, Actions
`39011365665`: the R9 Linux/Clang R5 preflight prints **Total Tests: 33**,
the corrected exact-cardinality matcher accepts all 33 entries, and the same
selector completes **33/33 PASS** under ASan/UBSan.

Environment: Ubuntu 24.04, Clang **18.1.3**, Xvfb **21.1.12**, with the hosted
XCB XShm/RandR/XFixes/XDamage/XTEST/XI2 development packages. The focused
selection reports **23 synthetic-display**, **30 native**, **33 linux-adapter**
and **33 x11** labeled executions.

The ordinary Ubuntu/GCC 13.3 Debug full suite executes the R5 pixel-parity,
RandR capture-generation/stale-damage, pointer stale-motion and input-route
revocation cases successfully, but the full job is **571/572 PASS** because
R1's `transport.tcp-native-loopback-tls` aborts. That R1 fixture also causes
the other full-platform job failures. The R9 sanitizer job itself, structure
gate, documentation policy and R7 sanitizer job are green.

No R5 production failure is present at this SHA. Owner Linux/X11 and
Microsoft-client M3 acceptance remain **NOT RUN**.

## R10 Windows fixture-DACL repair evidence (2026-10-17; owner native NOT RUN)

Owner evidence before this repair shows **53 failures out of 507**, with the
common harness failure occurring before production assertions while preparing
synthetic config, TLS and licensing files. The transcript excerpt suppresses
the underlying `icacls` diagnostic, so the exact owner-machine mechanism is
**not yet demonstrated** and must not be guessed.

Control evidence: hosted MSYS2 CLANG64 at
`03f7675cfedd2691ff2e446d8b960170bd7625a4`, Actions
`39010975844`, provisions Clang **23.1.3-1**, MinGW-w64 headers/CRT
**14.0.0.r426.g4564ee4b5-1**, CMake **4.4.4-3** and OpenSSL **3.6.5-1**.
The previously owner-blocked licensing-context, licensing CLI, runtime TLS,
Windows config-DACL and TLS credential permission cases all **PASS** there.
The complete hosted CLANG64 Debug result is **519/520 PASS**; the only failure
is unrelated `transport.tcp-native-loopback-tls` (`0xc0000409`), so Release
was skipped by the fail-fast job.

This repair changes only test-fixture preparation and central CTest
registration. The shared helper uses a native absolute path and current SID,
avoids unnecessary `/setowner`, separates inheritance removal from grant
replacement, validates the resulting owner/protected DACL, and emits native
stdout/stderr and exit code on failure. Negative Everyone, Authenticated Users,
Built-in Users and private-key public-read fixtures still deliberately add
their unsafe ACE only after a verified private baseline and still rely on the
production validator to reject them.

New Windows-only registrations:
`runtime.windows-private-fixture-dacl-creation`,
`runtime.windows-private-fixture-broad-access-denials`,
`runtime.windows-private-fixture-owner-consistency`.

Publication-SHA owner MSYS2 CLANG64 and full hosted regression evidence are
**PENDING**. The owner must record `git rev-parse HEAD`, `clang++ --version`,
full CTest totals and the exact new ACL diagnostic if any fixture setup still
fails. No owner-native PASS is claimed from hosted CI.

## R7 P1 hosted Apple lifecycle-gate authoring receipt (2026-10-17)

**Starting reconciled shared `main`:** `1332fd044773b9da53bff2d81403204ecd137484`.  
Exact publication-SHA hosted validation: **PENDING**.

The macOS protocol matrix now records host/toolchain metadata and fail-closes on
the current R7 native-lifecycle registrations in both Debug and Release. The
focused selection preflights and runs seventeen cases spanning
`macos.desktop-geometry-epoch-generation-fence-revocation`, the generation,
callback, consumer, native-stop, late-start and session-watch
`macos.capture-stream-*` retirement cases, current-generation/session cursor
publication cases, input session-watch revocation and GUI-session
switch/terminal watch races.

This is CI/test-only hardening. It performs no live ScreenCaptureKit capture,
native cursor sampling or input posting and issues no Screen Recording or
Accessibility request. R2/R3 desktop admission remains independent and
non-forgeable; owner macOS 27/TCC/native-session evidence remains **NOT RUN**.

## R3 CAL issuer-constraints OpenSSL 4 compile correction receipt (2026-10-17)

`586101c7e50326f583ab0479bbfb6785353807b7`, Actions
`39011330461`: structure guard **PASS**; macOS Debug compilation stops in
`rdp_licensing.cpp` before CTest because OpenSSL 4 exposes the borrowed
`X509_EXTENSION` as const. The exact diagnostic is a mutable-pointer
initialization from `const X509_EXTENSION *`.

The correction preserves all issuer-authorization behavior and changes only
the local borrowed pointer to const. No assertion, trust rule, CAL policy
decision or test registration is weakened. Hosted correction-SHA execution is
**PENDING**; canonical local testing remains **NOT RUN**.

## R5 P1 registry-cardinality parser correction receipt (2026-10-17)

At `910cdad63b2b0cb384bf85d63731482c42e340cd`, Actions
`39011106741`, `ctest -N` printed **Total Tests: 33** for the R5 selector,
but the newly added AWK expression contained `x11\\.` and therefore reported
zero matching entries. The R5 sanitizer step stopped before execution as
designed.

The correction changes only that matcher to `x11\.`. Ordinary Ubuntu/GCC on
the failed first publication still ran the full suite and the inspected R5
native cases passed; its sole full-suite failure was the unrelated R1
`transport.tcp-native-loopback-tls` fixture. Exact correction-SHA R5
sanitizer evidence is **PENDING**. Owner Linux/X11 and Microsoft-client M3
acceptance remain **NOT RUN**.

## R3 CAL intermediate issuer-constraints authoring receipt (2026-10-17; exact-SHA CI pending)

**Starting shared `main`:** `dcbf605fc11c10db65b4e14b522c4806777b2bec`.

Production CAL inspection now rejects signature-valid chains whose
peer-supplied intermediate is not a proper RFC 3280 certificate-signing CA.
The independently configured root remains the trust anchor. New CTest
`transport.licensing-client-cal-issuer-constraints` exercises missing,
false and non-critical basic constraints, denied `keyCertSign`, and the
permitted absence of key usage. Existing signature-denial assertions remain
cryptographic and unchanged.

The R9 flat CAL selector explicitly requires the new registration, bringing the
focused family to eight cases. Canonical local build/CTest and benchmark
execution are **NOT RUN** because this connector environment does not expose
the mandated `~/rdp-server/` checkout. Hosted exact-SHA evidence is
**PENDING**.

## R4 post-structure-recovery exact hosted validation (2026-10-17)

**Validated SHA:** `04a272c8b9b52f59a24401643a46d495978d1f95`.  
**Actions:** `39010848190` — **SUCCESS**.  
**Documentation publication parent:** `09184dc4c5fffe99e411af78b5b6b3ed4a822b3e`.

R4 regression coverage is green on the first fully schedulable shared workflow
after the P2 handoff audit. Linux/GCC passes **570/570** in Debug and Release;
macOS/AppleClang passes **487/487** in Debug and Release; Windows/MSVC passes
**520/520** in Debug and Release after **55/55** native preflight in each
configuration.

The retained R4 recovery cases all execute in all six ordinary configurations:
`graphics.frame-delivery-unsent-cancellation`,
`graphics.frame-delivery-partial-send-remains-terminal`,
`graphics.avc420-segmented-frame-unsent-cancellation`,
`graphics.x264-segmented-unsent-cancel-idr`, and
`graphics.x264-bgra-unsent-cancel-idr`.

R9's instrumented R4 groups are independently green: portable RDPGFX
**39/39** and x264/BGRA **22/22**. Exact cancellation/terminal cases are
**19/39**, **20/39** and **39/39**; real x264 IDR recovery is **12/22** for
direct NV12 and **22/22** for BGRA. This revalidates the landed semantics:
exact unwritten cancellation preserves mapped/ACK/client-observation state and
forces the next real x264 picture to IDR, while partial or uncertain progress
remains terminal.

No production source or test registration changes in this validation receipt.
The R4 frame owner and BGRA/x264 path already match the planned single R3 sender
boundary. Additional R4 publication code remains intentionally absent until R3
supplies genuine joined DRDYNVC/Graphics-DVC authority and cumulative
accepted-byte receipts. Canonical owner-local testing, native capture
performance and Microsoft-client visible graphics remain **NOT RUN**.

## R6 P1 Windows CLANG64/Clang 23 hosted lifetime evidence (2026-10-17)

**Validated SHA:** `04a272c8b9b52f59a24401643a46d495978d1f95`.  
**Primary workflow:** Actions `39010848190` — **SUCCESS**.  
**Standalone structure guard:** Actions `39010848289` — **SUCCESS**.

The hosted R6 Windows compiler-parity job completed the complete requested
CLANG64 path on Windows Server 2025. The verified toolchain is Clang
**23.1.3-1** targeting `x86_64-w64-windows-gnu`, MinGW-w64 headers and CRT
**14.0.0.r426.g4564ee4b5-1**, libc++ **23.1.3-1**, CMake **4.4.4-3**,
Ninja **1.13.2** and OpenSSL **3.6.5-1**. This CLANG64 build uses the
MinGW-w64 Windows headers/import libraries rather than a Microsoft Windows SDK;
there is therefore no Microsoft Windows SDK version to report for this job.

Using the one checkout-local `build/` root, the focused R6 native selector
`^windows\.(geometry|capture|cursor|input)-` is **55/55 PASS in Debug** and
**55/55 PASS in Release**. The ordinary full Windows CLANG64 CTest is
**520/520 PASS in Debug** and **520/520 PASS in Release**.

The focused passes include all four whole-owner retirement cases:
`windows.capture-session-change-duplication-owner-retirement`,
`windows.capture-session-change-duplication-release-order`,
`windows.capture-session-change-duplication-callback-retirement`, and
`windows.capture-session-change-duplication-prior-revocation`. Their existing
production-backed assertions retain exact-once child unmap/frame release,
child-before-parent retirement, parent COM release ordering, callback-time
logical revocation with safe-point physical teardown, terminal reopen denial,
and held-input retirement with no post-revocation native send.

No Clang 23 or MinGW-w64 source/SDK incompatibility remains in the exercised
R6 Windows adapter. The only failures encountered while establishing this gate
were CI-validation defects: a cache-type-specific compiler assertion, inherited
duplicate/corrupted workflow mappings, PowerShell parsed as Bash, and a
negative-fixture diagnostic mismatch. Those were corrected without changing R6
production lifetime code or weakening its tests.

This is **hosted compiler/SDK parity evidence, not owner-native M1 evidence**.
The agent environment still has no canonical Windows owner checkout or MSYS2
owner machine, so R10's required owner row—exact candidate SHA, native MSYS2
CLANG64/Clang 23, canonical `~/rdp-server/build/`, and full Debug CTest—remains
**NOT RUN / OPEN**. Because shared `main` advanced after `04a272c8...`,
that SHA is not automatically the next owner candidate; R10 must name a current
same-SHA candidate after its hosted workflow is green.

For future authorized Windows composition, R10 must provide the sole
serialized delivery of native session-change notifications to the existing R6
owner and keep that owner alive through callback-safe-point teardown. WTS
observation remains revocation-only and cannot grant admission; fresh desktop
construction requires a non-forgeable R2 admission/reauthorization capability.

R3 must provide the authenticated, bounded, already-decoded keyboard/pointer
route only while the matching R2 lease and R6 session/device generation remain
current, deliver events to the existing `WindowsInputController`, and retire
that route before or with native session revocation. Protocol parsing or caller
booleans must never synthesize Windows authorization.

**M1 remains OPEN** pending R10's exact-same-SHA owner matrix convergence.
**M4 remains OPEN / NOT ACCEPTED**: no real R2-admitted Windows user desktop or
Microsoft-client graphics/input acceptance was exercised.

## R5 P1 native-X11 registry cardinality authoring receipt (2026-10-17)

**Starting shared `main`:** `03f7675cfedd2691ff2e446d8b960170bd7625a4`. Exact publication-SHA CI is
**PENDING**.

The supported R9 Linux/Clang profile already provisions all R5 XCB extension
development packages plus Xvfb/xauth and enumerates the anchored native-X11
selector before execution. R5 now additionally requires that enumeration to
contain exactly **33** `x11.*` tests before the existing sentinel-name checks
and sanitizer run. This turns loss of any non-sentinel Xvfb/native registration
into an immediate preflight failure instead of a smaller green selection.

The change is workflow/testing-policy only. No production X11 behavior or
optional local-build dependency policy changes. Owner Linux/X11 and
Microsoft-client M3 acceptance remain **NOT RUN**.

## R3 CAL leaf-validity exact-SHA validation receipt (2026-10-17)

`ca56ededf527a46bcf535a5c3396d3b9e4d69db4`, Actions
`39010430295`:

- Linux/GCC full CTest: **569/569 PASS Debug**, **569/569 PASS Release**.
- macOS/AppleClang full CTest: **486/486 PASS Debug**, **486/486 PASS Release**.
- Windows/MSVC full CTest: **519/519 PASS Debug**, **519/519 PASS Release**.
- `transport.licensing-client-cal-certificate-validity` passes in all six
  ordinary configurations.
- R9 Clang ASan/UBSan CAL registry preflight finds all seven
  `transport.licensing-client-cal-*` cases and executes **7/7 PASS**.
- Documentation policy and ordinary installed-SDK/package gates pass.

The workflow conclusion is **FAIL** solely because the independent R6
`r6-windows-clang23` job failed during CLANG64 configuration. That job does
not compile or execute the R3 CAL test path and is not reported as R3 evidence.

Canonical owner-local and genuine Microsoft-client acceptance remain
**NOT RUN**. No valid-client authorization or Share activation is claimed.

## R1 legacy native-loopback handshake readiness hardening (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared \`main\`:** \`04a272c8b9b52f59a24401643a46d495978d1f95\`.

A standards audit found two older R1 real-loopback handshake fixtures still
using scheduler \`yield()\` as the readiness oracle even though
\`docs/testing_standards.md\` now requires bounded native readiness for TLS
handshakes. The affected existing behaviors are
\`transport.tcp-owned-connection-tls-lifecycle\` and
\`transport.tcp-native-loopback-tls\`.

The owned-connection lifecycle now advances the server only through
\`OwnedPreauthTcpConnection::pollSocketOnce\` with
\`kMaximumTcpPollWait\` under one five-second monotonic deadline while the
client performs one \`SSL_do_handshake\` step per loop. The attached-adapter
diagnostic preserves its distinct \`PreauthTcpAdapter\` path: after one client
and one server handshake step, it waits only for the exact server
NeedRead/NeedWrite direction on the real accepted socket; after server
establishment, any remaining client WANT is waited on the exact client socket
direction. Neither fixture fabricates readable/writable readiness or sleeps
during handshake.

This is test-harness hardening only. Production socket/BIO/SSL ownership,
one-step callbacks, the 18 KiB application-I/O ceiling, authorization,
licensing and listener behavior are unchanged. Existing behavior names and
central CTest registration remain authoritative; no duplicate test executable
or transport surface is added.

Canonical owner-local \`~/rdp-server/build/\` execution is **NOT RUN** in this
connector environment. Exact publication-SHA hosted Linux/GCC,
macOS/AppleClang, Windows/MSVC Debug/Release, R9 sanitizer,
documentation-policy and SDK/package evidence are **PENDING**.

**Next R1:** after exact hosted validation, retain the live-publication
dependency gate. R10 still lacks a genuine production CAL issuer and R2 still
withholds final native admission/positive grant reauthorization, so do not
fabricate grant-through-TLS success. The M1 owner-native exact-SHA matrix also
remains an owner-run gate, not something hosted CI can substitute for.

## R6 P1 structure self-test blocker correction (2026-10-17)

**Blocked descendant:** `9cfeabe694e89c3fc89c714fb4e461236c6e61c9`.  
**Structure run:** `39010778228` — **FAIL before dependent jobs**.

R9's shell-aware validator correctly stopped treating explicit PowerShell as
Bash, then exposed a self-test oracle mismatch: the malformed Bash fixture was
correctly rejected with `bash syntax failure`, while the harness required the
literal substring `shell`. The oracle now requires `syntax` and a dedicated
PowerShell-positive fixture locks the interpreter distinction.

This changes only CI validation infrastructure. R6 production code, existing
Windows CTests, COM ownership assertions, WTS semantics and SendInput behavior
are unchanged. CLANG64 compilation still has not run past configuration in a
structure-gated candidate.

## R9 P0 structure-gate correction receipt (2026-10-17)

First P0 SHA `24a57c8e5b2805bb326b461e896b9068ec95ab38`:
primary Actions `39010503457` **FAIL before jobs**; independent guard
`39010504332` **executed and failed closed** on duplicate
`r7-macos-session-sanitizers`. This was an R9 authoring failure, not a road
test failure. Current reconciled parent `484877ce8157ab146f1f6c0e166d5022f1be090f` inherits the R6
runnable-workflow repair with seven unique primary job IDs and zero duplicates.

This correction keeps the independent guard, policy CTest and three denial
fixtures, reinstates fail-closed registry preflight for the MCS/CLIPRDR fuzzer
and R7 desktop/input groups, and skips explicit PowerShell blocks during
`bash -n` validation. Exact correction-SHA hosted evidence is **PENDING**.

## R6 P1 shared-workflow structural blocker reconciliation (2026-10-17)

**Blocked R6 correction:** `c6e650ba586e3ecc00306e6aacc38a99fa8aba60`.  
**Main workflow:** Actions `39010587446` — **FAIL before jobs**.  
**Structure guard:** Actions `39010588499` — **FAIL**.

The new fail-closed structure guard correctly diagnosed an inherited shared-CI
corruption before the corrected R6 Clang gate could run: `.github/workflows/ci.yml`
contained three top-level `r7-macos-session-sanitizers` mappings and four
copies each of `documentation-policy` and `publish-protocol-prerelease`.
The same damaged tail also contained truncated fuzzer and R7 shell selectors.
This corruption was introduced after the last runnable R6 workflow and is not
a Clang 23, MinGW-w64 SDK or R6 production-source failure.

To unblock the evidence matrix without weakening any selector, this correction
reconstructs `ci.yml` from the last runnable R6 workflow
`11e7286570cd4537a3e5fda405dbab24c9faf0da`, reapplies only the intended R9
`ci-workflow-structure` prerequisite to each unique job, retains the corrected
R6 compiler-identity assertion, and preserves exactly one copy of every
platform/sanitizer/documentation/publication job. The standalone structure
guard and its fixtures remain authoritative.

No production source, CTest registration, COM ownership assertion, WTS
semantics, SendInput behavior or authorization path changes here. R6 CLANG64
Debug/Release focused/full execution remains pending the repaired workflow.

## R6 P1 CLANG64 compiler-cache assertion correction (2026-10-17)

**First gate:** `11e7286570cd4537a3e5fda405dbab24c9faf0da`, Actions
`39010380922`, R6 job `117331486750`.

The first hosted CLANG64 gate successfully provisioned and verified the intended
Windows toolchain: Clang **23.1.3-1** targeting
`x86_64-w64-windows-gnu`, MinGW-w64 headers and CRT
**14.0.0.r426.g4564ee4b5-1**, libc++ **23.1.3-1**, CMake **4.4.4-3**,
Ninja **1.13.2** and OpenSSL **3.6.5-1**. CMake itself configured and
generated the Debug build successfully and found the CLANG64 OpenSSL import
library.

The job then failed before compilation because the gate's post-config assertion
assumed CMake stored `CMAKE_C_COMPILER` and `CMAKE_CXX_COMPILER` with the
cache type `FILEPATH`. That type assumption is not part of CMake's compiler
identity contract. This is an R6 CI validation defect, not a Clang 23,
MinGW-w64 SDK or production-source failure.

The correction keeps the assertion fail-closed but accepts any CMake cache type
while still requiring the resolved values to end in `clang[.exe]` and
`clang++[.exe]` separately. No production source, COM ownership assertion,
CTest registration, WTS behavior, SendInput path or authorization boundary is
changed. Debug/Release focused and full CLANG64 execution remains pending the
corrected workflow.

## R8 P2 native multi-file verification receipt and acceptance checklist (2026-10-17)

**Audited shared-main SHA:** `24a57c8e5b2805bb326b461e896b9068ec95ab38`.  
**Corrected R8 source:** `583b59272cb51f95c967e3f0af9d13553e581e3a`.  
**Green hosted baseline:** `6457f259840fbfe3998f50517593cfd9185e75fe`, Actions `39009925959` — **SUCCESS**.

A compare from the corrected R8 source to the audit SHA shows no changes in the
Windows/macOS/X11 clipboard adapters or the three dedicated multi-file test
source files. Current-main review confirms the Windows
`renderFormatInternal` correction is present, the Windows and macOS
plan-consuming completed-set collectors still reject partial/stale/duplicate
membership, and the X11 completed-set path still requires every member to be a
current-generation `Complete` destination.

Hosted evidence from the unchanged green descendant is direct:
Linux/GCC **568/568 Debug + 568/568 Release**, macOS/AppleClang
**485/485 Debug + Release**, Windows/MSVC **518/518 Debug + Release**. The three
required multi-file registrations pass in those ordinary suites where
applicable. R9's fail-closed clipboard preflight enumerates all three and the
complete Clang ASan/UBSan clipboard selection is **68/68 PASS**. Within that
selection, the Linux/macOS/Windows size-cancel and denial cases plus
`clipboard.file-destination-plan-index-generation` and
`clipboard.file-destination-plan-cancel-replay` also pass.

The Windows multi-file test validates the native CF_HDROP representation:
20-byte DROPFILES header, `pFiles=20`, `fWide=TRUE`, two caller-selected
fully qualified UTF-16 paths with per-path NULs and the final list NUL. It
deliberately uses duplicate remote leaf names, independent native destination
objects and reverse caller ordering; publication normalizes by the committed
plan's exact remote descriptor index. A partial second member, duplicate
destination, local takeover, cancelled plan or reentrant cancellation cannot
leave a completed set published.

The macOS multi-file test likewise uses duplicate remote leaf names and two
independently completed destinations. The portable seam observes two distinct
file URL entries in plan-index order. The production AppKit bridge bounds the
set to 64, rejects duplicate/invalid entries, constructs one NSURL per file and
writes the complete array in one `writeObjects:` operation. Partial,
duplicate, local-takeover and cancelled-plan states are denied/rolled back.

The Linux/X11 case independently binds descriptor 0 and 1 to separate
caller-opened local descriptors, refuses publication before both are complete,
rejects duplicate URIs, emits the exact CRLF `text/uri-list`, GNOME
`copy\n...` form and KDE cut-selection byte, and rejects the set after a
new remote generation. No local filesystem path on any platform is synthesized
from the remote FILEDESCRIPTORW leaf name.

### Live acceptance gating

No live clipboard, filesystem, Finder, Explorer, Nautilus or RDP client was
accessed for this receipt. Execution requires explicit owner authorization and
must use the exact M1 candidate SHA declared by R10 after a complete SUCCESS
hosted workflow. The same SHA must have the required owner-native Debug evidence
for Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27; a later main commit
supersedes the candidate.

The approved run sheet must cover text, PNG plus Windows DIB/DIBV5, one file,
multiple files, mid-transfer/batch cancellation, disconnect/reconnect and
session revocation. For file cases, record the exact source descriptor index,
caller-authorized local destination, completion size/hash and file-manager
visible result. For cancellation/reconnect/revocation, record that no stale or
partial native publication survives and that a fresh generation requires fresh
materialization. Use only an owner-approved disposable destination directory.

R6 and R7 evidence must be joined rather than inferred: Windows WTS/session
revocation and macOS session/TCC revocation must retire the existing native
owners before any R8 live acceptance can count toward M4/M5. R10's hosted M1
baseline is stable, but its same-SHA owner matrix is still open. R2 still does
not expose a final non-forgeable native desktop admission capability and R3
licensing remains non-authorizing, so no positive real Microsoft-client
clipboard/file result may be produced through a detached synthetic R3 channel.

**Acceptance status:** synthetic/native-bridge R8 handoff validation **PASS**;
owner-machine real file-manager/client acceptance **NOT RUN**; M1/M3/M4/M5
**OPEN / NOT ACCEPTED**. There is no R8-owned CI regression in the last fully
green hosted baseline.

## R9 P0 CI workflow structural gate authoring receipt (2026-10-17)

**Authoring parent:** `ca56ededf527a46bcf535a5c3396d3b9e4d69db4`. **Publication:** this commit; exact-SHA
hosted results are **PENDING**.

The pre-publication audit retained R2's `dcac5920949d697d517ba08b9c0ab5d0f33438a1`
repair rather than duplicating it, found zero duplicate primary job IDs, and
preserved the concurrently added R3 CAL certificate-validity selector and R6
Windows Clang 23 gate. Release main-ancestry, version, three-digest/archive and
prerelease publication checks remain required.

The validator has one positive fixture plus three negative fixtures: duplicate
job IDs, the recent unterminated single-quoted sanitizer selector class, and an
unterminated GitHub expression. Shell block scalars are checked with `bash -n`
when Bash exists. The full check also requires current cross-road selector
sentinels, sanitizer build targets, both fuzz registrations and at least ten
`ctest -N` preflight sites. No production RDP/security behavior changes.

Local CMake/CTest is **NOT RUN** because this environment does not expose the
canonical `~/rdp-server/` checkout and policy forbids a second persistent
build root.

## R3 CAL leaf-validity compile correction receipt (2026-10-17)

Actions `39010291382` for implementation
`3822ca6d230336f8db2e20d1c4ae6153e22b92a3` reached macOS Debug compile
and failed in `test_owned_mcs_connect_initial.cpp`: the fixed 121-element
behavior dispatch array had 122 initializers after registering
`licensing-client-cal-certificate-validity`. No R3 CTest executed in that
macOS job.

The correction raises the test-only dispatch bound to 122 and changes the
fixed 2026/2027 certificate fixtures to canonical RFC 5280 UTCTime spelling.
Production leaf-validity inspection is unchanged. Exact correction-SHA hosted
evidence is **PENDING**; canonical owner-local testing remains **NOT RUN**.

## R6 P1 Windows CLANG64/Clang 23 authoring receipt (2026-10-17)

**Starting shared `main`:** `a503fb558cee88cea2d03f97929136caec77171b`.  
**Publication SHA:** pending this direct-to-main commit.

The R6 P1 validation increment adds a dedicated hosted Windows MSYS2 CLANG64
compiler gate without changing production R6 lifetime code. The job verifies
that `clang++` is Clang 23.x and records the installed MinGW-w64 Windows
headers/CRT, libc++, CMake and OpenSSL packages before configuration.

Using the one checkout-local `build/` root, it configures Debug with
CLANG64, builds `test_windows_desktop_geometry`, enumerates the focused R6
selector and requires all four whole-owner retirement registrations, executes
that selector, executes full Debug CTest, reconfigures the same root to Release,
reruns the R6 selector and executes full Release CTest. No live desktop,
`SendInput`, WTS notification registration or credentials are used.

This hosted gate is compiler/SDK parity evidence, not the owner's required
persistent `~/rdp-server/build/` receipt. Owner Windows CLANG64/Clang 23
remains **NOT RUN / PENDING** until a same-SHA owner report is received. No M4
claim is made.

## M1 owner-platform acceptance matrix (P0 coordination, 2026-10-17)

R10 has paused runtime/service feature expansion and opened the formal
same-SHA M1 validation window. The **candidate is the commit containing this
section**, but it becomes executable owner-test evidence only after the complete
GitHub Actions workflow for that exact commit is SUCCESS. The coordinator final
report supplies the literal candidate SHA and Actions URL; owner reports must
repeat the same SHA from `git rev-parse HEAD`.

The last fully completed green hosted baseline before this coordination
publication is `6457f259840fbfe3998f50517593cfd9185e75fe`, Actions
`39009925959` — **SUCCESS**. It confirms that R9 and the complete hosted
pipeline were green before the M1 candidate publication, but it is not an owner
machine result and must not be substituted for the candidate workflow.

| Evidence row | Exact SHA | Environment/build | Tests / failures / skips | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| Owner Linux/X11 | Candidate required | Native owner machine; Debug; canonical `~/rdp-server/build/` | Await owner full CTest summary | **NOT RUN** | Await owner transcript |
| Owner Windows MSYS2 CLANG64 / Clang 23 | Candidate required | Native owner machine; Debug; canonical `~/rdp-server/build/` | Await owner full CTest summary | **NOT RUN** | Await owner transcript |
| Owner macOS 27 | Candidate required | Native owner machine; macOS 27; exact Xcode + AppleClang; Debug; canonical `~/rdp-server/build/` | Await owner full CTest summary | **NOT RUN** | Await owner transcript |
| Hosted Linux/GCC | Containing candidate commit | Debug + Release | Candidate workflow required | **PENDING** | Candidate Actions run |
| Hosted macOS/AppleClang | Containing candidate commit | Debug + Release | Candidate workflow required | **PENDING** | Candidate Actions run |
| Hosted Windows/MSVC | Containing candidate commit | native preflight + Debug + Release | Candidate workflow required | **PENDING** | Candidate Actions run |
| R9 Clang ASan/UBSan | Containing candidate commit | sanitizer/fuzzer selections | Candidate workflow required | **PENDING** | Candidate Actions run |
| R7 macOS session sanitizer | Containing candidate commit | GCC ASan/UBSan side job | Candidate workflow required | **PENDING** | Candidate Actions run |
| Documentation policy | Containing candidate commit | policy job | Candidate workflow required | **PENDING** | Candidate Actions run |
| SDK consumer / package / digest | Containing candidate commit | all hosted platform jobs | Candidate workflow required | **PENDING** | Candidate Actions run |

Owner evidence must capture the exact SHA, OS version, compiler version, build
type, total tests, failures, skipped/not-run tests and complete
`--output-on-failure` diagnostics. The macOS row additionally records
`xcodebuild -version`, `xcode-select -p` and
`xcrun clang++ --version`; `sw_vers -productVersion` must report major
version 27. The required Debug command is the exact
one in `docs/compile.md`:

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

After the pull, record `git rev-parse HEAD` and stop before configure if it is
not the literal candidate SHA from the coordinator report. Do not delete
`build/`, create another build root, enable the listener, or opt into live
desktop/clipboard/credential/service tests for M1.

Failure routing is fixed for this window: R1 = macOS native TCP/TLS, R5 =
Linux/X11 native, R6 = Windows native, R7 = macOS capture/session. R10 owns
matrix coordination and records the first failing boundary. Any repair creates
a new candidate and invalidates same-SHA convergence from the previous one.

**Acceptance decision:** **M1 OPEN / NOT ACCEPTED**. It can become PASS only
when the complete candidate hosted workflow and all three owner-native Debug
runs are PASS on the exact same SHA. Hosted Windows/MSVC is explicitly not
owner Windows MSYS2 CLANG64/Clang 23 evidence.

## R7 generation-fence exact-SHA hosted validation and owner handoff (2026-10-17)

**Implementation:** `8ee59f77a0db27df3bb06096955cee07ed8b938a`.  
**Actions:** `39009608665` — **SUCCESS**.

Hosted macOS executed on macOS **26.6.2 (25G83)**,
`macos-26-arm64` image `20261013.0424.1`, whose manifest selects
**Xcode 26.6 (17F113)**. CMake identified
**AppleClang 21.0.0.21000101** for C, C++ and Objective-C++. Debug and Release
full CTest are both **484/484 PASS**. The two new dedicated R7 cases execute in
both configurations:
`macos.desktop-geometry-epoch-generation-fence-revocation` (#394) and
`macos.capture-stream-geometry-generation-retirement` (#428). The installed
SDK consumer is **1/1 PASS**, package/digest generation passes, R7 sanitizer,
R9 ASan/UBSan and documentation policy all pass.

This proves Apple compilation/execution of the injected CoreVideo capture
lifecycle and portable generation fence, including same-dimensions replacement.
It does not prove a live ScreenCaptureKit stream, native fast-user-switch
delivery, real cursor/input, macOS 27, TCC grant state or M5.

The R7 production/test bodies remain unchanged from `8ee59f77...` through
R10's matrix publication `a503fb558cee88cea2d03f97929136caec77171b`.
Owner macOS 27 evidence therefore uses R10's exact-candidate rule and same
canonical build root. The owner transcript must include the candidate SHA,
`sw_vers`, `xcodebuild -version`, `xcode-select -p`,
`xcrun clang++ --version`, CMake's effective AppleClang, the complete Debug
CTest summary, then the optional R7 focused selector recorded in
`docs/ROADMAP.md`. R7 owns capture/session failures; R10 owns the matrix.

**Owner macOS 27:** **NOT RUN**.  
**TCC/live desktop:** **NOT RUN; no permission request issued**.  
**M1:** **OPEN / NOT ACCEPTED** until the R10 matrix has same-SHA owner evidence.  
**M5:** **OPEN / NOT ACCEPTED**; live execution remains blocked on explicit
authorization plus genuine positive R2/R3 macOS desktop admission.

## R3 CAL leaf-validity authoring receipt (2026-10-17; exact-SHA CI pending)

**Starting shared `main`:** `2f4fd534bc070977582ed899c620cd79171edecf`.

Production adds only deterministic leaf-certificate validity inspection at an
explicit caller-supplied Unix timestamp. The ordinary chain inspector remains
clock-free. The new behavior CTest
`transport.licensing-client-cal-certificate-validity` covers both inclusive
boundaries, before/inside/after states, malformed and inverted windows, while
requiring the existing RDP licensing-extension policy to remain unparsed and
non-authorizing.

The R9 flat CAL selector now fail-closed preflights the new registration in
addition to the existing six cases. Canonical local build/CTest and benchmark
execution are **NOT RUN** because this connector environment does not expose
the mandated `~/rdp-server/` checkout. Hosted exact-SHA evidence is
**PENDING**.

## R2 explicit runtime PAM provisioning authoring receipt (2026-10-17)

**Starting shared `main`:** `910cdad63b2b0cb384bf85d63731482c42e340cd`.  
**Source/test publication:** `14c2e5995e3eb83e0d89725ec41f46837860708f`.

Linux GSS+PAM builds now let the immutable runtime security owner provision one
explicit `LinuxPamPasswordVerifier` alongside its sealed keytab and
`ConsoleIdentityPolicy`. The verifier is owned by
`LinuxRuntimeSecurityConfiguration`; each connection acceptor receives only
the existing borrowed one-shot binding after the same policy is bound and
before GSS configuration. The non-PAM overload is unchanged, no default PAM
service is selected, and the process configuration does not silently enable
this opt-in path.

Dedicated production-backed coverage is
`runtime.linux-security-pam-verifier-provisioning`. It uses the existing
synthetic keytab only to exercise provider configuration, configures the
non-authorizing PAM service name `rdp-server-r2-ci` without authenticating a
user, rejects an invalid `../login` service and proves failed configuration
cannot be retried. It also confirms that provisioning alone leaves the native
admission broker ready with no session-change watch. No fake positive PAM
result, Kerberos authentication, NSS/logind ownership, completion latch, lease
or R3 authority is created.

Canonical local `~/rdp-server/build/` execution is **NOT RUN** because that
mandated checkout is not mounted in this connector environment. The source
commit's hosted Ubuntu Debug suite registered and passed
`runtime.linux-security-pam-verifier-provisioning`; that workflow remained
overall failed because the concurrent R1
`transport.tcp-native-loopback-tls` case timed out on both Linux and macOS,
and because the implementation commit lacked a same-commit Markdown co-change.
The first selector publication, `0e02825fd8b89770ad12229440ada781386e88c1`,
created zero CI jobs because its authoring tool accidentally interpreted the
literal shell-regex suffix `$'` as a replacement token and duplicated the
workflow tail. It is negative evidence only. This repair restores the workflow
verbatim from the last structure-guarded parent and reapplies only the R2
runtime selector addition plus its exact registry preflight using literal-safe
editing. Positive PAM/native authority remains **NOT RUN**.

## R2 administrator PAM-service provisioning hosted validation (2026-10-17)

**Starting shared `main`:** `313140fdd5d803e6b0ae934b0d02f859d7548328`.

The real non-listening runtime checker now accepts `pam_service` only when the
Linux PAM target is present and only as part of the existing complete Linux
security provisioning group. `--check-linux-security` forwards it to
`LinuxRuntimeSecurityConfiguration`; no second verifier owner is introduced.

New process CTests are
`runtime.rejects-linux-security-missing-pam-service`,
`runtime.rejects-linux-security-invalid-pam-service`,
`runtime.rejects-linux-security-password-config`, and
`runtime.rejects-linux-security-authorization-result-config`. The existing
`runtime.validates-linux-security-provisioning` becomes the positive
configuration-only case in PAM builds. Fixtures use only the existing synthetic
TLS/keytab material; they never authenticate a user or install/modify a PAM
service.

The preceding final-credential/native-admission join is denial/lifetime
validated on descendant `e656f805f119cb35c65231279742a7d1088b7df4`:
Ubuntu ran its dedicated final-credential admission denial successfully and
R9 Clang ASan/UBSan passed the direct runtime-security set **12/12**. The full
Ubuntu suite remained red only at the independent R1 native-loopback TLS case.

Follow-up test-plumbing commit
`f7f8f83c968332cf2b3d86d999cfe2142bec1045` propagates the PAM-enabled
fixture flag through the existing licensing/startup meta-tests so their
recursive Linux security preflight exercises the same administrator
configuration contract; production code is unchanged.

Hosted validation for that descendant is Actions `39014765641`, with
standalone workflow-structure Actions `39014765654` **SUCCESS**.
Documentation policy passes. Ubuntu/GCC compiles the PAM-enabled Debug graph
and executes **581/582 PASS**; the sole failure is the independent R1
`transport.tcp-native-loopback-tls` test. The positive
`runtime.validates-linux-security-provisioning`, all four new PAM-service
configuration denials, `runtime.licensing-cli-existing-check-compatibility`,
and `runtime.licensing-authority-no-startup-bypass` pass.

The exact descendant's R9 Clang ASan/UBSan job is **SUCCESS**: native R2/R3
GSSAPI **30/30 PASS**, Linux PAM verifier denials **3/3 PASS**, and direct
runtime security **12/12 PASS**. macOS/AppleClang and Windows/MSVC both
configure and compile their non-PAM Debug graphs, confirming that the
conditional configuration grammar does not alter those builds.

Canonical local `~/rdp-server/build/` execution is **NOT RUN** because that
checkout is not mounted in this connector environment. Genuine positive
Kerberos + PAM + NSS/logind physical-desktop admission/revocation and
Microsoft-client acceptance remain **NOT RUN / BLOCKED**; M2 is not accepted.

## R2 authenticated PAM invocation hosted validation (2026-10-17)

Exact code SHA `92ddb689b0ca3200b2ef420f818c04cd630da147` completed GitHub Actions
run `39009841176` successfully. Documentation policy, Linux, macOS and Windows
hosted protocol jobs, the R7 macOS sanitizer job, and the R9 Clang ASan/UBSan
security job all passed. The Linux and macOS jobs passed Debug and Release
CTest runs plus downstream SDK packaging/digest checks; Windows passed its
portable Debug/Release matrix and packaging. R9's sanitizer job specifically
passed both the bounded native R2/R3 GSSAPI selection and the R2 Linux PAM
denial selection, including the new synchronous password-field visitor and PAM
verifier-binding cases.

The preceding exact-SHA attempts are retained as negative evidence:
`680d15e563f5fd4a8a2d70b481821f3ae960828f` / run `39009664731`
failed before creating jobs because of a malformed workflow edit, and
`dcac5920949d697d517ba08b9c0ab5d0f33438a1` / run `39009725570`
then exposed the empty-account visitor defect in hosted Debug testing. Both
issues were corrected before the successful exact-SHA run above.

This evidence proves the new denial/lifetime boundary only. No positive PAM
fixture, real Kerberos client authentication, NSS/logind native desktop
admission, private final-authentication latch, LinuxConsoleAdmissionLease, or
R3 Share activation is claimed. Those gates remain BLOCKED / NOT RUN where a
controlled real-provider/owner environment is required.

## R3 CAL signature-fixture exact-SHA validation receipt (2026-10-17)

`17fd924eb642a21b9f985800097d975fe551752b`, Actions
`39009556082`: **overall SUCCESS**.

- Linux/GCC: **564/564 PASS Debug**, **564/564 PASS Release**.
- macOS/AppleClang: **482/482 PASS Debug**, **482/482 PASS Release**.
- Windows/MSVC: **516/516 PASS Debug**, **516/516 PASS Release**.
- R9 Clang ASan/UBSan: fail-closed CAL registry preflight finds all six
  `transport.licensing-client-cal-*` cases and the CAL selection is
  **6/6 PASS**.
- Documentation policy, installed-SDK consumer, package/digest and artifact
  publication gates pass.

The corrected denial fixture signs a fresh leaf, mutates a unique extension
payload in serialized signed DER, reparses a fresh X.509 object, proves direct
`X509_verify()` failure, and then requires the production inspector to report
`SignatureVerificationFailure`. No production source changed in this
validation fix.

Canonical owner-local testing and real-client/provider acceptance remain
**NOT RUN** in this connector environment. No valid-client authorization or
Share activation is claimed.

## R6 whole-owner Windows session revocation hosted validation (2026-10-17)

**Implementation:** `3a98aa4e26316346b494e82d84bb909fc3d39904`.  
**Exact implementation-SHA Actions:** [39009347305](https://github.com/k1moradi/RDP-server/actions/runs/39009347305) — **FAIL before job creation**.  
**Validated descendant:** `17fd924eb642a21b9f985800097d975fe551752b`.  
**Descendant Actions:** [39009556082](https://github.com/k1moradi/RDP-server/actions/runs/39009556082) — **SUCCESS**.

The exact implementation-SHA workflow did not compile or execute R6: inherited
R9 workflow YAML from `7751e079a56e15034845ab61e4ad5e527204efc6`
contained an unterminated CredSSP fuzzer selector, so Actions created zero
jobs. R9 repaired that shared workflow independently. On the first runnable
descendant, all four new R6 whole-owner cases passed, while full platform
Debug suites stopped only on the unrelated R3 CAL mutation fixture. R3 then
reparsed the mutated signed leaf in `17fd924eb642a21b9f985800097d975fe551752b`,
which produced the fully green hosted matrix below.

Windows/MSVC native preflight is **55/55 PASS in Debug** and **55/55 PASS in
Release**. It includes
`windows.capture-session-change-duplication-owner-retirement`,
`windows.capture-session-change-duplication-release-order`,
`windows.capture-session-change-duplication-callback-retirement`, and
`windows.capture-session-change-duplication-prior-revocation`; all four pass
in both configurations. Full Windows CTest is **516/516 PASS in Debug** and
**516/516 PASS in Release**.

Hosted Linux/GCC full CTest is **564/564 PASS** in both Debug and Release.
Hosted macOS/AppleClang full CTest is **482/482 PASS** in both Debug and
Release. Each platform's installed SDK downstream consumer is **1/1 PASS**,
and package/archive plus digest generation gates pass.

The R7 GCC sanitizer job passes. The R9 Clang ASan/UBSan job also passes all
of its registered selections, including clipboard **68/68**, portable RDPGFX
wire/lifecycle **39/39**, x264/BGRA **22/22**, RDPGFX capabilities **4/4**,
bounded R1/R3 transport/security **91/91**, focused CAL **6/6**, runtime
licensing authority **6/6**, bounded native R2/R3 GSSAPI **30/30**, Linux PAM
**1/1**, direct runtime security **10/10**, native X11 **33/33**, and both
bounded fuzzers **1/1**. This Linux sanitizer evidence does **not** instrument
the Windows-only R6 owner/callback path and is not claimed as Windows memory
safety evidence.

The verified whole-owner contract is guard revocation -> input retirement ->
capture-cycle cancellation -> staging unmap -> DXGI `ReleaseFrame` -> child
destruction/native staging-context retirement -> duplication -> output1 ->
D3D11 context -> device -> output -> adapter -> factory. A callback-time
terminal event makes guard/input/parent logically unusable immediately, but
keeps the active child object and parent native references alive until the
serialized `completeDeferredClose()` safe point after the outer capture call
returns. Repeated notification, close and safe-point drain are idempotent;
the terminal owner cannot reopen.

The injected whole-owner fixture independently verifies child unmap/frame
release and parent reference ordering/exact-once release without dereferencing
fake COM pointers through SDK methods. The production native staging-context
reset remains structurally ordered between child destruction and duplication
release; the synthetic fixture does not claim an independent real-D3D11
destructor oracle.

Canonical owner-local `~/rdp-server/build/` execution remains **NOT RUN** in
this agent environment because the required checkout was absent and shell
networking could not resolve GitHub. Owner Windows MSYS2 CLANG64/Clang 23
validation and any approved direct Windows sanitizer run remain **NOT RUN /
OPEN**. Real R2/R3 authorization, R10 serialized native notification delivery,
an actually authorized Windows desktop and Microsoft-client acceptance also
remain prerequisites. **M1 and M4 remain OPEN.**

## R2 synchronous visitor validity correction (2026-10-17)

The first hosted execution of the new portable visitor at
`dcac5920949d697d517ba08b9c0ab5d0f33438a1`, Actions
`39009725570`, compiled successfully on macOS but failed
`security.credssp-password-field-synchronous-visitor`: the callback observed
an empty account. The internal visitor had correctly filled the fixed account
buffer but then called the public metadata result's `accountName()`, whose
public validity flag is intentionally not set by the internal path.

This correction passes a bounded `std::string_view` over the already validated
fixed account buffer directly to the synchronous callback, before that buffer is
cleansed. It does not weaken the account grammar, domain rule, GSS provenance,
policy-generation check, password lifetime, PAM service configuration, private
completion latch or native-admission boundary.

## R2 PAM sanitizer selector repair receipt (2026-10-17)

Commit `dcac5920949d697d517ba08b9c0ab5d0f33438a1` repairs only the R2 exact-name sanitizer selectors after the
preceding feature publication exposed a malformed workflow edit. The failed
feature run `39009664731` created zero jobs and is not test evidence. This
documentation co-change records the repair explicitly so the repository's
per-commit documentation policy can validate the follow-up publication.

The repaired workflow requires registry preflight for
`security.credssp-password-field-synchronous-visitor`,
`security.credssp-pam-password-field-verifier-denials`, and
`security.gssapi-pam-verifier-binding-denials`. It does not alter the R2
authentication boundary, enable positive PAM authority, set the private
completion latch, issue a native lease, or open R3.

## R2 authenticated PAM invocation authoring (2026-10-17)

**Reconciled shared-main parent:** `8ee59f77a0db27df3bb06096955cee07ed8b938a`.

This R2 publication wires the existing explicit-service Linux PAM verifier only
inside the already authenticated final-CredSSP plaintext lifetime. The portable
canonical parser gains a noninstalled synchronous field visitor; the GSS owner
gains a one-shot borrowed verifier binding; exact account policy matching still
precedes the PAM call. Every PAM outcome remains subordinate evidence and is
discarded before the existing terminal rejection, so this change cannot mint
final CredSSP completion, a native admission lease or R3 authority.

Dedicated CTests are
`security.credssp-password-field-synchronous-visitor`,
`security.credssp-pam-password-field-verifier-denials` and
`security.gssapi-pam-verifier-binding-denials`. The PAM credential case uses
a deliberately nonexistent synthetic account with the real provider and accepts
only Denied or ProviderFailure. R9's bounded portable and PAM sanitizer
selectors include exact registry preflight checks for the new names.

No canonical local checkout/build root is mounted in this connector, so local
Debug/Release/ASan/UBSan execution is **NOT RUN** rather than inferred. Exact-SHA
hosted results are **PENDING** until the publication workflow completes.
Positive Kerberos, positive PAM, NSS/logind native admission, Microsoft-client
acceptance and M2 remain **BLOCKED / NOT RUN**.

## R7 capture geometry-generation retirement authoring receipt (2026-10-16)

**Starting reconciled shared `main`:** `17fd924eb642a21b9f985800097d975fe551752b`.  
Exact publication-SHA hosted validation: **SUCCESS** — Actions `39009608665`.

R7 now gives asynchronous capture callback state a revocation-only generation
fence from `NativeDisplayGeometryRefresh`. It is shared because queued native
callbacks can outlive the mutable geometry owner, but carries no geometry
pointer, display handle, TCC state or authorization. Refresh/invalidate/owner
destruction revoke old generations; successful geometry install publishes the
new generation only after install. Capture prepare/start/completion/frame
boundaries combine this fence with the existing topology and GUI-session
checks.

New production-backed tests:
`macos.desktop-geometry-epoch-generation-fence-revocation` and Apple-only
`macos.capture-stream-geometry-generation-retirement`. The Apple test uses
synthetic CoreVideo plus the injected backend only and proves a same-topology
refresh cannot let an old callback report `Published`; a fresh generation can
still publish. Native ScreenCaptureKit factory exposure and R2/R3/R4 authority
remain unchanged.

## R3 CAL DER-mutation fixture authoring receipt (2026-10-17; exact-SHA CI pending)

**Starting shared `main`:** `f0f852f7da2b7b0dc7c277efe63016ab32b339db`. On Actions `39009402865`, macOS
Debug executes 482 tests and fails only R3 CAL test #67 at the fixture's direct
`X509_verify()` assertion: mutating the serial of an `X509_dup()` through
the setter does not reliably invalidate cached signed bytes on that provider.

The revised fixture mutates a unique 16-byte noncritical extension payload only
after the valid leaf has been signed and encoded. It reparses the changed DER
into a fresh `X509`, requires direct signature verification to fail, and only
then invokes `inspectRdpClientCalCertificateChain()`. This is test-only; no
production CAL source or acceptance rule changes.

Canonical local build/CTest is **NOT RUN** because the required
`~/rdp-server/` checkout is unavailable here. Hosted exact-SHA execution is
**PENDING**.

## R9 workflow repair reconciliation receipt (2026-10-16)

`5419ad7f657a30d745a40eb62a0a1c083af715b4` fixed YAML syntax but sourced
the full workflow from a commit that predated later R4 sanitizer selectors.
That rollback is R9-owned and the SHA is superseded for cross-road validation.

The correction derives the workflow from `3a98aa4e26316346b494e82d84bb909fc3d39904`, whose corrupted
CredSSP insertion has two R7 markers. It retains everything before the R9
fuzzer step, inserts the repaired fail-closed block, and resumes at the second
R7 marker, preserving the genuine suffix and newer R4 selections. Prepublication
checks require one R9/R7/docs/publish job, one of each fuzzer step, the exact
CredSSP registration grep, and the R4 unsent/partial-terminal plus x264/BGRA
cancellation selectors.

## R8 planned completed-set exact-SHA validation (2026-10-17)

**Implementation:** `2e0f2814b8943fa8a83fccd97b7294a43f873b9f`.  
**Validated source:** `583b59272cb51f95c967e3f0af9d13553e581e3a`.  
**Actions:** `39009046269`.

The validated R8 source adds bounded plan-backed Windows CF_HDROP and macOS
multi-NSURL publication. Every publication borrows only independently completed
destination objects, requires exact current `RemoteFileDestinationPlan`
membership, normalizes caller order to remote descriptor index order, rejects
duplicate local metadata and directory associations, and revalidates a copied
canonical set after the native callback. Reentrant plan cancellation therefore
rolls back the native set rather than allowing borrowed-view aliasing to mask a
same-generation mutation.

Hosted evidence on the correction SHA:
- macOS/AppleClang: **477/477 Debug**, **477/477 Release**; both new R8 tests
  pass in both configurations; real AppKit multi-NSURL code compiles/links;
  installed-SDK consumer, package, digest and upload pass.
- Windows/MSVC: **507/507 Debug**, **507/507 Release**; both new R8 tests pass
  in both configurations; installed-SDK consumer, package, digest and upload
  pass.
- Ubuntu/GCC: full Debug compile succeeds; both new R8 tests pass inside the
  559-test suite. The suite stops at **558/559** because unrelated R3
  `transport.licensing-client-cal-issuer-signature-denials` aborts, so Linux
  Release/SDK/package are **NOT RUN**.
- Clang ASan/UBSan: production-linked targets compile; registry preflight finds
  both new names; clipboard selection is **68/68 PASS**, including
  `clipboard.macos-completed-multi-file-url-handoff` (41/68) and
  `clipboard.windows-completed-multi-file-hdrop-handoff` (52/68). The job
  later fails only in the same R3 CAL test inside the R1/R3 selection.
- Documentation policy passes.

The earlier implementation run `39008936302` is retained as negative
regression evidence: it found a missing pre-existing
`WindowsClipboardAdapter::renderFormatInternal` definition introduced by the
source-range replacement. Correction `583b59272cb51f95c967e3f0af9d13553e581e3a`
restores that helper verbatim.

Canonical local testing is **NOT RUN** because this environment does not provide
the synchronized canonical checkout and project policy forbids a second
persistent checkout/build root. Live file-manager/client acceptance and all
directory materialization remain outside this increment.

## R9 CredSSP fuzzer preflight workflow repair receipt (2026-10-16)

`7751e079a56e15034845ab61e4ad5e527204efc6` / Actions
`39009145045` failed at workflow parsing with zero jobs. Inspection of the
committed YAML showed the selector truncated after
`fuzz_selection='^fuzz\.credssp-bounded` and a duplicated workflow suffix,
so no result from that SHA is accepted.

The correction rebuilds the workflow from
`2ad37e35e9c1109e2e5509a19025a6a7551030f2` and uses index slicing rather
than replacement-string substitution for the new shell block. Before
publication it validates one occurrence each of the R9 sanitizer job, R7
sanitizer job, documentation-policy job, prerelease job, both fuzzer steps and
the exact CredSSP registration grep. The R9 fuzzer source hardening from the
superseded commit remains present on the current tree. Exact-SHA execution is
required before this correction is called green.

## R6 whole-owner Windows session revocation (2026-10-17; hosted validation pending)

**Authoring base:** `339f760d3c718eaf7a4192cbf17347f70552deec`.

R6 now extends the existing revocation-only coordinator to the complete
`WindowsDxgiDuplicationOwner` graph without adding another DXGI owner,
watcher, service loop or authorization source. Terminal ordering is guard ->
input -> parent close. Parent close cancels its owned capture cycle before
parent release; a close requested from an active child callback is logically
terminal immediately but keeps the child's `unique_ptr` and parent COM
resources alive until `completeDeferredClose()` runs after the outer capture
operation returns.

The owned-cycle attachment accepts deterministic frame/staging callbacks for
ordinary CTests, so the production parent/cycle ownership path is exercised
without dereferencing fake COM tokens or touching a live desktop. Native
production attachment still creates the existing D3D11 staging context and
DXGI adapters. Reconnect remains fresh-owner only; WTS observations,
generation numbers and injected callbacks remain non-authorizing.

Four behavior-specific CTests are registered once in the existing
`test_windows_desktop_geometry` executable:
`windows.capture-session-change-duplication-owner-retirement`,
`windows.capture-session-change-duplication-release-order`,
`windows.capture-session-change-duplication-callback-retirement`, and
`windows.capture-session-change-duplication-prior-revocation`.
They cover unrelated-session no-op, target revocation, held-input suppression,
unmap-before-frame-release, child-before-parent COM retirement, callback-time
safe-point deferral, duplicate close/notification, reopen denial, and prior
guard failures from WTS/read/generation/reentrant observations.

The canonical checkout was absent in this execution environment; an attempted
clone into the required `~/rdp-server` path failed because shell networking
could not resolve GitHub. No alternate checkout, branch or build root was
created. Earlier shared-main run `39008734992` failed before creating jobs;
later shared-main workflows restored the normal platform matrix. Local
Windows/MSVC Debug/Release, owner Windows MSYS2 CLANG64/Clang 23 and direct
Windows sanitizer evidence for this increment are therefore **PENDING / NOT
RUN** until exact-publication-SHA CI/owner execution.

M1 and M4 remain open: this lifetime work does not create R2/R3 authorization,
R10 notification delivery, a live Windows desktop capability or Microsoft
client acceptance.

## macOS listener-poll readiness authoring (2026-10-16)

Owner-local macOS evidence reports subprocess aborts only in
`transport.tcp-listener-poll-budget-handoff` and
`transport.tcp-listener-poll-deadline-denials` after the earlier direct-accept
fixtures were corrected.

The remaining fixtures still assumed that loopback `connect()` completion
made the listener synchronously readable to the next zero/short-wait poll.
Darwin may instead return `TcpListenerPollOutcome::NoEvent` before the queued
peer becomes observable. The authored change is test-only: a shared helper
reissues the existing one-step production poll from the external test caller,
bounded to 128 attempts and `kMaximumTcpPollWait` each, retrying only
`NoEvent`. It does not retry expiration, native failure or any completed batch,
and does not alter the production listener, acceptor, callback ownership or RDP
state.

The explicit idle-listener `NoEvent` assertion remains in place after the
pending peer has been consumed. Hosted exact-SHA Debug/Release evidence and
owner macOS rerun are **PENDING**. No live listener service, credentials,
desktop/session admission or R5 native X11 behavior is exercised.

## R4 zero-byte AVC420 cancellation authoring receipt (2026-10-16)

**Starting reconciled shared `main`:** `17f0f11bb420ba6772fb0e6639e04bc73e745552`.  
**Implementation SHA:** pending publication.  
**Exact-SHA Actions:** pending.

The new R4 path cancels only the exact pending unwritten frame receipt,
invalidates the move-only segmented publication and rebuilds the existing x264
reference history so the next accepted picture must be IDR. It preserves the
mapped generation/surface plus earlier ACK and client-observation state.
Positive or uncertain transport progress remains terminal abort. R4 cannot
independently prove transport progress; the zero-byte condition and retirement
of all `wireBytes()` borrows are external R3 preconditions.

Dedicated centrally registered cases are
`graphics.frame-delivery-unsent-cancellation`,
`graphics.avc420-segmented-frame-unsent-cancellation`,
`graphics.x264-segmented-unsent-cancel-idr`,
`graphics.x264-bgra-unsent-cancel-idr`, and
`graphics.frame-delivery-partial-send-remains-terminal`. The shared R9
workflow fail-closed preflights the three portable cases and both x264-labelled
recovery cases.

Canonical local configure/build/CTest is **NOT RUN** because this connector
environment cannot synchronize the mandated `~/rdp-server` checkout and
policy forbids a second persistent checkout/build root. Exact-SHA hosted
Linux/GCC, macOS/AppleClang, Windows/MSVC Debug/Release, ASan/UBSan,
documentation-policy, installed-SDK and package results are **PENDING**. No
authenticated Graphics DVC, accepted-byte R3 evidence, native desktop or
Microsoft-client visible frame is claimed.

## R3 CAL exact-SHA CI blocker receipt (2026-10-17)

Implementation `4cbe0168f9f0996d44d3f589ec6cafb335d62844`, Actions
`39009166683`: **FAIL before job creation / R3 NOT RUN**. The implementation
touches only the CAL denial fixture and R3 documentation, but inherits malformed
workflow text from parent R9 commit `7751e079a56e15034845ab61e4ad5e527204efc6`.
That commit's CredSSP fuzzer edit leaves the `fuzz_selection` shell quote
unterminated and embeds subsequent YAML job definitions inside the run block.

No compiler, CTest, ASan/UBSan or platform result is claimed for the R3
implementation SHA. The previous executable sanitizer run `39008819773`
selected all six CAL cases, passed five, and failed only the changed-signed-
property assertion now corrected. Re-run exact or unchanged-R3 descendant CI
after R9 repairs workflow syntax; do not bypass the fail-closed selectors.

## R3 CAL issuer-signature fixture portability correction (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `7751e079a56e15034845ab61e4ad5e527204efc6`. Actions `39008819773`
proves the flat R9 CAL selector enumerates and executes all six dedicated tests:
five pass and `transport.licensing-client-cal-issuer-signature-denials` fails
at the changed-signed-property assertion.

This correction is test-only. A duplicated signed leaf receives a new serial
through the owning OpenSSL setter `X509_set_serialNumber()`, backed by RAII
`ASN1_INTEGER` storage. The fixture asserts direct `X509_verify()` failure
before exercising `inspectRdpClientCalCertificateChain()`, so provider cache
behavior fails at the fixture boundary rather than being mistaken for
production verifier behavior.

No production source, CAL acceptance rule, CTest registration, trust-anchor
contract, licensing lifecycle or R2/R10 authority path changes. Canonical local
`~/rdp-server/build/` execution is **NOT RUN** because that checkout is not
available in this connector environment. Exact-SHA hosted matrix and sanitizer
evidence is **PENDING**.

## R9 CredSSP fuzzer executable receipt and hardening (2026-10-16)

**Executable evidence:** `ec8f9df25f9986a2d51fb258f7798ac8596cfed3`,
Actions `39008900352`. The R9 sanitizer build explicitly built
`fuzz_credssp`; CTest `fuzz.credssp-bounded` was test #538 and passed
**1/1** in 0.08 s under the job's ASan/UBSan environment. The same job later
reported overall failure solely because the independent R3 CAL
issuer-signature denial aborted; native GSS, PAM, runtime-security, X11 and the
MCS/CLIPRDR fuzzer groups also continued independently. This receipt therefore
claims the dedicated CredSSP fuzzer step, not an all-green workflow.

Static/runtime review found the fuzzer CI invocation lacked the repository's
usual fail-closed registration proof. The new R9 increment adds
`ctest -N` plus an exact-name grep before execution and strengthens the
fragmented manual-reader oracle: terminal Complete/Closed outcomes must agree
with the whole-input path, completed bytes equal the consumed prefix, release
returns the reader to an empty `NeedMore` state, and close leaves zero pending
bytes. Production CredSSP code, authentication state and corpus bounds are
unchanged.

The publication is based on reconciled shared main `2ad37e35e9c1109e2e5509a19025a6a7551030f2`, which currently
contains an unrelated R8 sanitizer compile/link blocker in
`test_windows_clipboard_adapter`. Exact-SHA evidence for the new preflight and
framing assertions remains **PENDING** and must not be inferred from the
earlier 1/1 fuzzer receipt.

## R1 hosted convergence after bounded handshake and native-accept hardening (2026-10-17)

**Handshake implementation:** \`31abf200efa83bf4fc7badf3b35f30b8ff2db127\`.  
**Cross-road matrix recovery:** \`04d4e7c559012fa4e3636ac7f778d32445d3bc4d\`,
Actions \`39008344089\`.  
**macOS accept-fixture hardening:** \`d8e731ca488f1f8d545348b19a97756be660db46\`,
Actions \`39008487916\`.  
**Workflow/CAL-selector validating descendant:** \`6c20df0d79ee20d8093e4be9e8abe0bcded4c070\`,
Actions \`39008819773\`.

R1's production transport remains unchanged across this chain. The common
real-loopback TLS handshake fixture and HYBRID path use bounded monotonic
readiness instead of scheduler sleep/yield, and the native accept regressions
now wait only at the external test-fixture boundary for Darwin's accept-queue
visibility. Production \`acceptNonblockingTcpConnection\`,
\`acceptNonblockingTcpBatch\`, socket/BIO/SSL ownership and the 18 KiB
application-I/O ceiling remain one-step and unchanged.

The cross-road recovery at \`04d4e7c5...\` removed the GCC
\`range-loop-construct\` blocker in the R10 authority test and explicitly built
\`test_runtime_licensing_authority\` in R9. Linux/GCC then reached the R1
suite directly: HYBRID NLA (#158), application I/O (#162), partial write
(#163), R3 License Request slice (#165) and terminal readiness (#171) all
passed. All six \`runtime.licensing-authority-*\` cases also executed and
passed. The Linux job's only full-suite failure was the unrelated R3
\`transport.licensing-client-cal-issuer-signature-denials\` case (#67).

The exact macOS-accept publication \`d8e731ca...\` validates the five corrected
native accept fixtures in every hosted ordinary configuration reached:

- macOS/AppleClang: **475/475 PASS Debug** and **475/475 PASS Release**.
  \`tcp-native-accept-ownership\` (#140), move replacement (#142), batch
  budget/handoff (#144), batch stop/denials (#145), and listener role/mode
  denials (#146) all pass in both configurations. The bounded handshake-backed
  R1 cases #158/#163/#165/#171 also pass.
- Windows/MSVC: native preflight **51/51 PASS Debug + Release** and full CTest
  **505/505 PASS Debug + Release**. The same five native accept fixtures and
  handshake-backed R1 cases pass in both configurations.
- Linux/GCC executes **557** registered cases and the same five native accept
  fixtures plus the handshake-backed R1 cases all pass. The suite is
  **556/557** solely because R3 CAL issuer-signature denial #67 aborts.
- R9's bounded R1/R3 selection is **91/91 PASS**, including native batch
  accept #144 as item 62/91, HYBRID #158 as 64/91, partial write #163 as
  68/91, License Request slice #165 as 70/91 and terminal readiness #171 as
  76/91. The authority group is **6/6 PASS**.

R1's CAL-selector correction \`035e2e8a...\` had no workflow run because its
R9-fuzzer parent malformed the workflow YAML. R9 repaired that structure in
\`6c20df0d...\` while preserving the corrected flat
\`^transport\\.licensing-client-cal-\` selector. On Actions \`39008819773\`
the selector now enumerates and executes all six CAL tests instead of
reporting zero tests. Five pass under ASan/UBSan; the same R3
issuer-signature-denials case aborts. The R1/R3 selection remains **91/91
PASS**, the authority group remains **6/6 PASS**, and the new CredSSP fuzzer
executes **1/1 PASS**. macOS remains **475/475 Debug + Release** and Windows
remains **505/505 Debug + Release**.

The later shared-main R8 native multi-file publication currently introduces an
unrelated clipboard-link failure on macOS/R9; it does not change R1 transport
source or invalidate the validated R1 descendant above. Project-wide CI should
therefore remain reported red where those R3/R8 failures occur; this receipt
claims only the directly executed R1 evidence.

Canonical owner-local \`~/rdp-server/build/\`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, and owner macOS 27 remain **NOT RUN** in this connector
environment. The owner's previously reported macOS accept failures did not
include a trustworthy exact SHA, so hosted convergence does not substitute for
that requested owner rerun.

The new R10 \`RuntimeLicensingAuthority\` still exposes no supported production
issuer; positive providers remain test-only. R2 still does not complete live
PAM/native admission or mint fresh positive reauthorization. Therefore R1
must not create a synthetic grant-through-TLS success path.

**Next R1:** retain the dependency gate. Once R10 has a genuine supported CAL
issuer and R2 exposes fresh positive authorization for every R3 grant slice and
accepted-byte completion, verify final grant publication through the sole
R1-owned TLS application writer. Otherwise wait for a concrete Share-activation
boundary that demonstrates a bounded transport mismatch.

## R8 Windows render-helper compile repair (2026-10-17; exact-SHA CI pending)

Actions `39008936302` for
`2e0f2814b8943fa8a83fccd97b7294a43f873b9f` configured the macOS Debug tree
and built the new macOS multi-file destination executable successfully, then
failed while linking the portable Windows clipboard test executables. The sole
R8 diagnostic was an undefined
`WindowsClipboardAdapter::renderFormatInternal(unsigned int)` symbol.

The multi-file source replacement had accidentally removed that existing
private definition while leaving its declaration and callers intact. The
correction restores the parent implementation verbatim. No R8 test expectation,
native publication contract, ownership rule or sanitizer selection is changed.
Exact correction-SHA validation is **PENDING**.

## R8 Windows/macOS planned completed-set authoring validation (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `ec8f9df25f9986a2d51fb258f7798ac8596cfed3`.

The next roadmap increment extends only native presentation of already-completed
files. Windows and macOS each gain a plan-consuming bounded multi-file
publication API; the existing one-at-a-time FileContents coordinator and
platform destination ownership remain unchanged. The APIs borrow at most 64
destination objects, require exact current plan/generation membership, reorder
by remote descriptor index, reject duplicate indices and local paths/URLs, and
revalidate a copied canonical set after the native callback.

Windows emits one CF_HDROP list with exact UTF-16 per-path NULs plus the final
list NUL. macOS sends one bounded file-URL span through the injected seam and
the AppKit implementation converts it into one NSArray of NSURL objects.
Neither path stores whole file bytes in presentation state or derives a local
name from remote metadata.

New production-backed registrations are
`clipboard.windows-completed-multi-file-hdrop-handoff` and
`clipboard.macos-completed-multi-file-url-handoff`. Both use two same-name
remote descriptors, sequential real FileContents completion, partial-set
invisibility, reversed input order, duplicate-member denial, atomic publication,
local owner takeover and reentrant/terminal plan cancellation. The R9 clipboard
sanitizer registry preflight requires both names.

Canonical local configure/build/CTest is **NOT RUN** because this connector
environment does not provide the canonical synchronized checkout and policy
forbids an alternate persistent checkout/build root. Exact publication-SHA
hosted matrix, sanitizer, documentation and package evidence is **PENDING**.
Directory materialization, symlink policy and live Finder/Explorer acceptance
remain **NOT RUN / OPEN**.

## R9 CredSSP fuzzer compile-scope correction (2026-10-16; exact-SHA CI pending)

Static review after workflow recovery found two test-only source issues before
claiming executable evidence. The C-linkage libFuzzer entry point is outside the
anonymous namespace that imports the CredSSP symbols, so the production 16-KiB
limit is now explicitly namespace-qualified. The failure-token loop also binds
each `std::span` by const reference to stay warning-clean under strict
range-loop diagnostics. Fuzzer behavior, corpus, bounds and production code are
unchanged. The preceding workflow remains non-authoritative until the corrected
SHA executes.

## R9 CredSSP fuzzer workflow correction receipt (2026-10-16)

Superseded publication `8ad5f1285fa2e37b0ee19b2b04e74e42ec2d8c46`,
Actions `39008662630`: **workflow parse failure before jobs**. It supplies no
compile, sanitizer or fuzzing evidence.

The malformed YAML came from JavaScript replacement-string handling of the
literal `$'` at the end of the new anchored CTest regex. The correction
rebuilds from `d8e731ca488f1f8d545348b19a97756be660db46`, carries forward the
R1 CAL selector correction from `035e2e8a702abef1304d2aea51e4de960d90fd5b`,
and inserts the R9 target/step by string indices. Uniqueness checks cover the
R9/R7/publish jobs and the new fuzzer step before publication. Corrected
exact-SHA CI is **PENDING**.

## R1/R9 CAL sanitizer selector recovery (2026-10-17; exact-SHA CI pending)

**Starting shared \`main\`:** \`8ad5f1285fa2e37b0ee19b2b04e74e42ec2d8c46\`.

The bounded R1/R3 sanitizer step already keeps the new R3 client-CAL family in
its own flat selector, but the shell single-quoted regex was over-escaped as
\`^transport\\\\.licensing-client-cal-\`. CTest therefore saw a literal
backslash pattern and reported \`Total Tests: 0\`; the fail-closed registry
greps stopped that step before any CAL sanitizer execution.

This CI-only recovery uses the same escaping convention as the adjacent working
selectors: \`^transport\\.licensing-client-cal-\`. No CTest registration,
production R1/R3/R10 source, CAL validation rule, TLS ownership or authorization
path changes. The six explicit registry greps remain unchanged, so the step
still fails closed if any expected CAL behavior disappears.

Exact publication-SHA R9 execution is **PENDING**. The current Linux/GCC full
matrix separately reaches and passes R1 handshake/application-I/O cases but
still has an unrelated R3
\`transport.licensing-client-cal-issuer-signature-denials\` runtime failure;
this selector correction does not mask or reinterpret that behavior.

**Next R1:** after exact CI, record whether the CAL group now executes. R1's
live-publication gate remains unchanged: no grant-through-TLS success path
until R10 has a genuine supported issuer and R2 exposes fresh positive
authorization for every grant slice/completion.

## R9 bounded CredSSP fuzzing authoring receipt (2026-10-16)

Starting reconciled shared `main`: `d8e731ca488f1f8d545348b19a97756be660db46`.

Added one opt-in production-linked libFuzzer target, `fuzz_credssp`, without
changing production CredSSP code. The entry point is bounded to 16 KiB and
drives the real TSRequest parser, manual `TsRequestFrameReader`, canonical
credential inspection and delegated-account extraction. Invariant failures
abort so ASan/UBSan/libFuzzer preserve a reproducer; malformed inputs are
otherwise expected and fail closed.

The target has two synthetic checked-in seeds (canonical v6 negotiation
TSRequest and canonical `TSPasswordCreds`), 5,000 fixed-seed runs, bounded
RSS/malloc limits and its own `fuzz.credssp-bounded` CTest/CI step. It is
separate from `fuzz.mcs-cliprdr-bounded` for attribution. No TLS identity,
GSS/PAM provider, native admission or real credential is introduced.

Canonical local execution is **NOT RUN** in this connector environment because
the owner checkout is unavailable and project policy forbids creating another
persistent build root. Exact-SHA hosted compilation and ASan/UBSan/libFuzzer
execution are **PENDING**.

## macOS native-accept fixture visibility authoring (2026-10-16)

**Starting shared main:** `04d4e7c559012fa4e3636ac7f778d32445d3bc4d`.

Owner macOS full CTest reports five subprocess aborts in native loopback accept
behaviors: ownership, move replacement, batch budget/handoff, batch stop/denial
and listener role/mode denial. The report did not include the checkout SHA, so
the local evidence is recorded as **FAIL at those five behaviors / exact SHA
unknown from supplied output**, rather than being attached to a guessed commit.

The failing cases shared a stale fixture assumption: they called the production
nonblocking accept/batch immediately after a successful loopback `connect()`
and required the peer to be visible synchronously. Other tests in the same
translation unit already use bounded caller-side retries because Darwin may
make the pending peer observable later. The correction reuses that existing
one-shot helper and adds one DRY test-only batch helper. It retries only
`TcpAcceptBatchOutcome::WouldBlock` with zero transferred sockets and has a
finite ceiling; any production failure or semantic batch result is returned
unchanged for the behavior assertion.

No production socket implementation or RDP state machine changes. Hosted
exact-SHA validation and owner macOS rerun are **PENDING**. The owner should
rerun the unchanged canonical command after pulling the published descendant.

## R1 cross-road CI recovery for handshake validation (2026-10-17; exact-SHA CI pending)

**Starting shared \`main\`:** \`7d07fae0196c9e857f0200d9f4b6365210a72279\`.

R1's bounded owned-TLS handshake-readiness implementation is unchanged. Its
remaining Linux/GCC validation was blocked before R1 execution by two
test/CI-only defects introduced with the new fail-closed R10 licensing
authority owner:

1. GCC with strict warnings rejects a by-value structured binding in
   \`test_runtime_licensing_authority.cpp\` under
   \`-Werror=range-loop-construct\`.
2. R9 registers the six \`runtime.licensing-authority-*\` CTests but its
   sanitizer compile step did not build \`test_runtime_licensing_authority\`,
   leaving five executable-backed cases Not Run while the process-only startup
   case still executed.

This recovery binds that fixed \`std::array<std::pair<...>>\` element by
\`const auto&\` and adds the existing authority test executable to the existing
R9 production-linked target build. There is no production R10 or R1 source
change, no provider/issuer behavior change, no CTest registration change and no
new authorization/publication path.

Exact publication-SHA Linux/GCC full Debug/Release, R9 ASan/UBSan, hosted
macOS/Windows regression, documentation policy and SDK/package evidence are
**PENDING**. Canonical owner-local \`~/rdp-server/build/\` remains **NOT RUN**
in this connector environment.

**Next R1:** if this restores clean Linux/GCC and R9 execution, close the
handshake-readiness validation gap and retain the live-publication dependency
gate. Do not add a grant-through-TLS success path until R10 has a genuine
supported issuer and R2 exposes fresh positive authorization for each grant
slice/completion.

## R8 bounded destination-plan exact-SHA validation (2026-10-16)

**Starting reconciled shared `main`:** `541a9460a19f7cfca1c5c73fdb74cc1630e21772`.  
**Implementation:** `0d6621beac09ea35e7065f6119731242cae56d24`.  
**Validated lifecycle-hardening SHA:** `ecee09dd7bc5eb07293cae7101d354c72908795b`.  
**Actions run:** `39006670277`.

Source/protocol review confirms the retained R8 FileGroupDescriptorW list is an
ordered set of at most 64 safe leaf descriptors, not a verified directory tree.
`FD_ATTRIBUTES` plus `FILE_ATTRIBUTE_DIRECTORY` can mark a directory, but
the current parser rejects both slash forms, drive/path punctuation, malformed
UTF-16 and nonzero data after the terminating NUL. With negotiated
`CB_FILECLIP_NO_FILE_PATHS`, no source path is available to reconstruct a
parent. The implementation therefore adds only explicit caller placement
metadata and reports remote hierarchy/directory materialization unsupported.

The production `RemoteFileDestinationPlan` uses fixed-capacity state:
64 associations, maximum placement depth 16, exact descriptor indices, unique
nonzero selection identities and transactional all-member validation. It is
bound to the exact `RemoteTransfer` object, public generation and a private
monotonic offer epoch that survives disconnect to prevent generation-number
ABA. It is non-copyable/non-movable and has no path strings, native handles,
FileContents coordinator, background work or native clipboard writer.

Five behavior CTests are centrally registered:
`clipboard.file-destination-plan-index-generation`,
`clipboard.file-destination-plan-directory-traversal-denials`,
`clipboard.file-destination-plan-transactional-commit`,
`clipboard.file-destination-plan-cancel-replay`, and
`clipboard.file-destination-plan-native-capability-integration`. The first
four reuse `test_owned_remote_transfer`; the fifth composes the existing
production Windows materializer/adapter using deterministic injected native
operations.

Exact-SHA hosted evidence on `ecee09dd7bc5eb07293cae7101d354c72908795b`:
macOS/AppleClang passed **475/475** in both Debug and Release and all five R8
cases ran in each configuration. Windows/MSVC passed **505/505** in both Debug
and Release and all five R8 cases ran in each configuration. Both jobs passed
the installed-SDK consumer plus package/digest verification. Documentation
policy passed.

The exact-SHA R9 Clang ASan/UBSan clipboard step compiled its production-linked
targets, verified every new R8 registry name, and passed **66/66** clipboard
tests; all five destination-plan tests passed under ASan/UBSan. The sanitizer
job's overall conclusion is **FAILURE** only because later non-R8 steps failed:
a bounded R1/R3 selection hit a separate zero-test registry preflight, and the
R10 licensing-authority selection reported five Not Run cases because
`test_runtime_licensing_authority` was absent. The Ubuntu/GCC matrix also
failed in R10 before CTest at
`tests/test_runtime_licensing_authority.cpp:658` with
`-Werror=range-loop-construct`; therefore no R8 CTest ran in that Ubuntu job.
The overall Actions run is consequently **FAILURE**, not a fully green matrix.

Canonical local configure/build/CTest is **NOT RUN**: this execution environment
cannot synchronize `~/rdp-server` from GitHub, and project policy forbids a
second persistent checkout/build root. No live desktop clipboard, native file
manager, authenticated Microsoft client, directory creation or M1-M6 acceptance
is claimed.

## R1 owned-TLS handshake readiness hosted validation (2026-10-17)

**Implementation:** \`31abf200efa83bf4fc7badf3b35f30b8ff2db127\`.  
**Implementation Actions:** \`39006099373\`.  
**Unchanged-R1 descendant:** \`a7d724e3988e88f8bb3440b19f76e760b3870cf7\`.  
**Descendant Actions:** \`39006137656\`.

The R1 implementation removes the remaining scheduler sleep/yield from the
common real-loopback application-TLS handshake fixture and the duplicate
HYBRID negotiation handshake. Client OpenSSL still advances one step at a
time; the server progresses only through
\`OwnedPreauthTcpConnection::pollSocketOnce\` with
\`kMaximumTcpPollWait\` under a five-second monotonic deadline. Production R1
socket/BIO/SSL code, the 18 KiB application-I/O ceiling and all authority
surfaces are unchanged.

The implementation-SHA hosted run was cross-road blocked rather than R1
failing. Ubuntu/GCC stopped before the R1 test executable on R10
\`tests/test_runtime_licensing_authority.cpp:658\`: strict
\`-Werror=range-loop-construct\` rejects a by-value structured binding. macOS
and Windows reached the R1 cases successfully but their full suites later
failed solely in the concurrent R3
\`transport.licensing-client-cal-product-extension-denials\` regression.
The bounded R9 R1/R3 sanitizer selection itself passed **91/91**, including
\`transport.tcp-owned-hybrid-nla-negotiation\` as item 64/91,
\`transport.tcp-owned-tls-application-partial-write\` as 68/91,
\`transport.tcp-owned-r3-license-request-slice\` as 70/91 and
\`transport.tcp-owned-tls-terminal-readiness\` as 76/91. R9 later failed only
because the R10 licensing-authority executable was absent after that R10
target failed to build.

R3 corrected its CAL fixture in descendant
\`a7d724e3988e88f8bb3440b19f76e760b3870cf7\`. Comparison from the R1
implementation to that descendant changes only
\`tests/test_owned_mcs_connect_initial.cpp\` plus documentation; the R1
\`test_owned_preauth_session.cpp\` source is unchanged. On that descendant:

- macOS/AppleClang full CTest is **470/470 PASS Debug** and **470/470 PASS
  Release**. The affected R1 cases all pass in both configurations, including
  HYBRID NLA (#158), application I/O (#162), partial write (#163), R3 License
  Request slice (#165) and terminal readiness (#171). Installed SDK consumer
  is **1/1 PASS**.
- Windows/MSVC focused native preflight is **51/51 PASS** in Debug and Release.
  Full CTest is **500/500 PASS Debug** and **500/500 PASS Release**. The same
  affected R1 cases pass in both configurations and installed SDK consumer is
  **1/1 PASS**.
- The descendant R9 bounded R1/R3 sanitizer group again passes **91/91** with
  the affected handshake-backed cases executing successfully. Native GSS
  subsequently passes **30/30**, PAM **1/1**, direct runtime security **10/10**,
  native X11 **33/33** and the bounded fuzzer **1/1**. The job's overall
  failure remains the separate R10 licensing-authority target absence.
- Ubuntu/GCC full CTest remains **NOT RUN** because the same R10 strict-warning
  compilation failure occurs before R1 execution. This is not counted as an
  R1 PASS.

Documentation policy and the independent R7 sanitizer job pass on both the
implementation and descendant runs. The R1 implementation has therefore
direct hosted execution on macOS, Windows and Linux/Clang ASan+UBSan, but a
clean Linux/GCC full-suite descendant is still pending the R10 test correction.
Canonical owner-local \`~/rdp-server/build/\`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23 and macOS 27 remain **NOT RUN** here.

The new R10 \`RuntimeLicensingAuthority\` does not change R1's live-publication
gate. Production still supports only \`NoVerifiedIssuer\`; positive issuer
providers remain test-only. R2 still does not invoke PAM in the live final
CredSSP path or mint a final native admission/reauthorization capability.
Therefore R1 must not fabricate a grant-through-TLS success path.

**Next R1:** retain the dependency gate. Once a genuine supported CAL issuer
adapter exists and R2 exposes fresh positive authorization for each R3 grant
slice and accepted-byte completion, verify the released grant through the sole
R1-owned TLS application writer. Otherwise wait for a concrete Share-activation
transport mismatch. Linux/GCC clean-descendant validation remains outstanding
until R10 repairs its warning-clean authority test.

## R7 cursor publication exact-SHA validation receipt (2026-10-16)

**Implementation:** `32f46276add9b387e71962376da4329537eff2d8`  
**Exact-SHA workflow:** https://github.com/k1moradi/RDP-server/actions/runs/39006013275  
**Clean unchanged-R7 descendant:** `a7d724e3988e88f8bb3440b19f76e760b3870cf7`  
**Descendant workflow:** https://github.com/k1moradi/RDP-server/actions/runs/39006137656

Production behavior: `MacCursorSnapshot::validFor(geometry)` /
`pixelsFor(geometry)` synchronously require the snapshot's structural and
GUI-session validity, exact saved geometry generation to remain usable, the
current topology revision to exist and equal the saved revision, and a visible
snapshot's display ID to remain present in that generation. The caller owns
the geometry; no pointer is retained, no old snapshot is relabeled, and the
native AppKit sampler remains private.

R7 sanitizer evidence at the implementation SHA: desktop-session **10/10**,
input session-watch **1/1**, cursor publication/session selection **3/3**,
with fail-closed `ctest -N` registration checks before cursor execution.
Documentation policy: **PASS**. On the implementation-SHA macOS Debug suite,
all seven cursor cases passed; on the Windows Debug suite, all seven cursor
cases passed.

Cross-road exact failures at `32f46276add9b387e71962376da4329537eff2d8`:
- `protocol (ubuntu-latest)` / `Compile Debug`: R10
  `tests/test_runtime_licensing_authority.cpp:658`,
  `-Werror=range-loop-construct`.
- `protocol (macos-latest)` / `Run Debug protocol and project-policy tests`:
  R3 `transport.licensing-client-cal-product-extension-denials`, assertion at
  `tests/test_owned_mcs_connect_initial.cpp:7455`; 469/470 overall, with
  R7 cursor **7/7 PASS**.
- `protocol (windows-latest)` / `Run Debug protocol and project-policy tests`:
  the same R3 CAL assertion timed out; 499/500 overall, with R7 cursor
  **7/7 PASS**.
- `r9-security-protocol-sanitizers`: the bounded R1/R3 step's CAL selector
  selected zero tests, and the R10 licensing-authority step lacked the built
  `test_runtime_licensing_authority` executable, leaving five cases Not Run.
  These are not R7 code paths.

Unchanged-R7 descendant `a7d724e3988e88f8bb3440b19f76e760b3870cf7` proves the R3 failure was independent:
macOS **470/470 Debug + 470/470 Release**, Windows **500/500 Debug +
500/500 Release**, downstream installed consumer **PASS** on both, package
digest **PASS** on both, R7 sanitizer **PASS**, documentation policy **PASS**.
Linux still stops at the unrelated R10 line-658 warning and R9 retains the
independent selector/build-target failures.

Owner macOS 27/TCC/native-session-switch tests: **NOT RUN**. R2/R3 genuine
desktop admission and R4 client cursor publication remain external
dependencies. M1 and M5 remain **OPEN / NOT ACCEPTED**.

## R3 CAL X.509-version fixture isolation (2026-10-16; exact-SHA CI pending)

Exact-SHA run 39005961866 passed five of the six dedicated CAL tests on the
macOS OpenSSL 4 runner. The remaining product/extension test used a duplicated
extension-bearing leaf forced to X.509 v2, which is provider-sensitive and did
not reliably isolate the version gate. The corrected vector duplicates the
extension-free self-signed root, sets that certificate to X.509 v2, re-signs
it, and leaves the rest of the chain unchanged. Production code and acceptance
policy are unchanged; the test still requires
`UnsupportedCertificateVersion` exactly.

## R1 owned-TLS handshake readiness hardening (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared \`main\`:** \`32f46276add9b387e71962376da4329537eff2d8\`.

The common real-loopback helper used by the owned TLS application, CredSSP and
R3 transport regressions still completed its initial OpenSSL handshake with a
16,384-iteration scheduler-\`yield()\` loop. The HYBRID negotiation regression
duplicated the same pattern with a one-millisecond sleep. These waits occurred
before the later bounded application-I/O assertions, so a scheduler delay could
masquerade as handshake progress even though R1 already owns an exact bounded
socket-readiness dispatcher.

The test fixture now uses one shared
\`finishOwnedApplicationTlsHandshake()\` helper. The client performs exactly one
\`SSL_do_handshake\` step per iteration and accepts only WANT_READ/WANT_WRITE;
the server advances only through
\`OwnedPreauthTcpConnection::pollSocketOnce\` with
\`kMaximumTcpPollWait\` under one five-second monotonic deadline. Completion
requires the client init state, the same R1-owned established SSL and R1's Read
interest. The HYBRID provenance regression and
\`establishOwnedApplicationTlsForRequest\` both use this path.

This is test-harness reliability only. No production socket/BIO/SSL source,
native descriptor accessor, TLS retry policy, 18 KiB application-I/O ceiling,
authorization result, licensing lifecycle or listener surface changes. Existing
behavior CTests remain authoritative; the shared helper is exercised by the
owned application-I/O, HYBRID, CredSSP and R3 licensing transport cases already
selected by the bounded R9 R1/R3 sanitizer group.

The newly landed R10 \`RuntimeLicensingAuthority\` does not unblock live R1
grant publication: production supports only \`NoVerifiedIssuer\`; positive
providers remain test-only, and R2 still does not invoke PAM or create final
credential/native admission. R1 therefore does not add a detached grant writer
or fabricate positive authorization.

Canonical owner-local \`~/rdp-server/build/\` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent build root
or branch is created. Exact publication-SHA Linux/GCC, macOS/AppleClang,
Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and SDK/package
evidence are **PENDING**.

**Next R1:** keep the live-publication dependency gate. A fail-closed R10
authority owner is not a CAL issuer. Wait for a genuine supported issuer
adapter plus positive R2 admission/reauthorization before integrating the R3
grant gate with the sole R1 TLS writer, unless a concrete Share-activation
transport mismatch appears first.

## R7 current-display cursor publication authoring receipt (2026-10-16)

**Starting shared main:** `3069b2f1e07198d0e060c1619924f9654ffb8826`.  
**Publication parent after shared-main reconciliation:** `c800ef3cacc59d3cc4bc442f5d3a1c88c01ac555`.  
Exact publication-SHA hosted validation: **PENDING**.

The R7 cursor consumer now has an explicit current-geometry contract:
`MacCursorSnapshot::validFor` / `pixelsFor` synchronously revalidate the
stored geometry generation, topology revision, GUI-session revision and visible
display identity against the caller-owned `NativeDisplayGeometryRefresh`.
No geometry owner is retained and no native cursor sampler, TCC prompt,
capture/input path, R2/R3 authority or R4 pointer publication is exposed.

New production-backed CTests are
`macos.cursor-topology-publication-revocation` and
`macos.cursor-geometry-generation-publication-denials`; the existing
`macos.cursor-session-watch-revocation` remains intact and now traverses the
same checked consumer path. The road-local GCC ASan/UBSan job
registry-preflights and runs all three cursor cases. Synthetic BGRA/geometry
evidence is only a lifetime/freshness regression gate, not macOS 27 native
desktop or Microsoft-client acceptance.



## R4 P2 graphics recovery and R3 handoff validation receipt (2026-10-17)

**Authoring parent:** `9cfeabe694e89c3fc89c714fb4e461236c6e61c9`.  
**Landed implementation:** `17261a9d880698b4c979f349cf49e24640a94aca`.  
**Validated unchanged-R4 SHA:** `2f4fd534bc070977582ed899c620cd79171edecf`.  
**Actions:** `39010087859` — **SUCCESS**.  
**Authoring-parent CI:** Actions `39010778228` (CI workflow structure guard): **FAILURE**. Actions `39010778231` (C++23 protocol CI and prerelease delivery): **FAILURE**.

Ordinary hosted CTest on `2f4fd534...` is Linux/GCC **568/568** in Debug
and Release, Windows/MSVC **518/518** in Debug and Release after **55/55**
native preflight in both, and macOS/AppleClang **485/485** in Debug and
Release. The five retained R4 cases are:

- `graphics.frame-delivery-unsent-cancellation`, `graphics.avc420-segmented-frame-unsent-cancellation`, `graphics.x264-segmented-unsent-cancel-idr`, `graphics.x264-bgra-unsent-cancel-idr`, `graphics.frame-delivery-partial-send-remains-terminal`.

R9 independently passes portable graphics **39/39**, x264/BGRA **22/22**
and RDPGFX capabilities **4/4**. The lifecycle test proves mapped surface,
prior outstanding ACKs, queue-depth observation and decoded-frame observation
survive exact cancellation. The x264 NV12/BGRA tests prove the canceled P
picture is followed by a fresh IDR, then ordinary P-frame continuity after
successful delivery. The partial-send test proves nonzero/uncertain delivery
cannot use the preserving cancel operation and remains terminal.

P2 adds no production code or CTest. The R4 frame/receipt API is already the
correct single logical publication boundary. The production gap is R3's
missing authorized DRDYNVC/Graphics DVC lifecycle and cumulative outer-byte
writer. Existing MCS user data is capped at 16,383 bytes; large R4 frames
therefore require real DVC/static-channel fragmentation. R1's bounded TLS
writer already supplies exact progress, but a zero-byte WANT retains a pending
logical write and cannot be abandoned nonterminally. Safe unsent cancellation
is consequently a **pre-first-R1-submit** decision unless a future explicit
R1 retirement API is designed.

The next cross-component implementation must keep one active R4 frame, one
bounded outer fragment and R3-owned publication/slice receipts; call R4
completion only after every outer fragment is accepted, cancel only before
first submit, and abort on positive/uncertain progress. That implementation
requires a dedicated production-backed compatibility CTest.

Canonical local testing is **NOT RUN** because the synchronized
`~/rdp-server/` checkout is unavailable here and policy forbids a second
persistent checkout/build root. Real authenticated Graphics DVC admission,
native capture-to-wire timing and Microsoft-client visible frames remain
**NOT RUN**.
