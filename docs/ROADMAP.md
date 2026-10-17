## R6 P2 Windows CLANG64 native lifetime sanitizer gate (2026-10-17; exact-SHA CI pending)

**Authoring parent:** `0eb444bfab7ae0ce23dde22ba8c5e45c19212c4e`.

R6's remaining hosted lifetime gap is Windows-specific instrumentation. The
existing Linux R9 sanitizer job cannot instrument `_WIN32` DXGI/D3D11/WTS/
SendInput translation units, while ordinary Windows/MSVC and CLANG64 runs prove
compile/behavior but not AddressSanitizer/UndefinedBehaviorSanitizer execution.

The existing `r6-windows-clang23` job now reuses its one `build/` root
after ordinary Debug and Release complete, reconfigures Debug with Clang
ASan+UBSan, rebuilds the production-linked
`test_windows_desktop_geometry` fixture and executes the complete anchored R6
selector. The preflight requires exactly **55** registrations plus all four
whole-owner retirement sentinels before execution, so a lost non-sentinel
lifetime case cannot silently produce a smaller green sanitizer run.

This changes no R6 production source, COM ownership rule, WTS semantics,
input authorization or CTest behavior. All sanitizer cases continue to use
deterministic synthetic callbacks and never capture a live desktop, register
native WTS notifications or invoke host `SendInput`.

Exact-SHA hosted execution is **PENDING**. A Clang/MinGW compiler-rt problem
must be distinguished from a source/lifetime assertion failure. Owner Windows
MSYS2 CLANG64 evidence remains R10's separate same-SHA M1 gate. M4 remains
**OPEN / NOT ACCEPTED** without real R2 admission, R3 routing, an admitted
desktop and Microsoft-client acceptance.

## R8 native directory-capability duplication boundary (2026-10-17; exact-SHA CI pending)

**Portable binding:** `446f13677d57d2ef3bead65bb65dcc460e1fde3a`, Actions `39011707625`.  
**Documentation receipt:** `611e3279d7bffc3678bcd8ec899210e14a446cd8`.

The portable binding is executable-green for R8. Linux/GCC and
macOS/AppleClang compile the new target and pass
`clipboard.directory-capability-binding-authority` plus
`clipboard.directory-capability-binding-retirement`; their full suites fail
only at the unrelated R1 `transport.tcp-native-loopback-tls` readiness case.
R9's complete Clang ASan/UBSan clipboard selection expands to **70/70 PASS**
and explicitly executes both new bindings. The Windows full suite is blocked by
concurrent R10 synthetic owner-SID fixture failures, not an R8 compile or
binding-test failure.

R8's next bounded increment adds platform-native **duplicate/close only**
factories for already-open caller-authorized directory objects. POSIX validates
the supplied descriptor with `fstat`, requires a directory object and
duplicates it with `F_DUPFD_CLOEXEC`; it never reopens a path. Windows
validates the supplied HANDLE as a disk directory, rejects a final reparse-point
object, and duplicates it with `DuplicateHandle`; it never constructs or
opens a pathname.

Dedicated native-object CTests are platform-scoped:
`clipboard.linux-directory-capability-native`,
`clipboard.macos-directory-capability-native`, and
`clipboard.windows-directory-capability-native`. They use only the
CTest/build working directory as the positive existing directory object and an
anonymous pipe as a wrong-object negative. The Linux case is required by R9's
clipboard sanitizer preflight.

This still does **not** create a child directory/file, expose a native
capability to callers, infer a remote hierarchy, or change
`UnsupportedDirectoryMaterialization`. Relative child creation remains the
next separate review. POSIX must remain descriptor-relative with no-follow
semantics; Windows must use a reviewed handle-relative mechanism or
pre-authorized child handles rather than falling back to absolute-path reopen.

## R7 P1 isolated hosted Apple lifecycle evidence (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `75375ccfeb7523d58d40024f783ebfe84f4db50b`.

R7 CI hardening `dc8ad556c6f306b2678aee8d3c1d29284f6d1f85`,
Actions `39011565660`, proved the new in-matrix fail-closed Debug selection:
all **17/17** required macOS lifetime cases were registered and passed on hosted
macOS **26.6.2 (25G83)**, **Xcode 26.6 (17F113)**,
**Apple clang 21.0.0 (clang-2100.1.1.101)** / CMake
**AppleClang 21.0.0.21000101**, SDK **26.5**. The exact SHA's structure guard,
documentation policy, R7 GCC ASan/UBSan job and R9 Clang ASan/UBSan job also
passed.

The subsequent full Debug suite failed only cross-road R1 test
`transport.tcp-native-loopback-tls` (#178), at
`test_owned_preauth_session.cpp:6028` on macOS and the same readiness assertion
on Ubuntu/Windows/Windows CLANG64. macOS therefore reported **487/488 PASS** and
skipped Release. Unchanged-R7 descendant
`e782cd642f574e7ef45792c8fe168dfad70c8d2a`, Actions `39011665925`,
again passed the focused R7 Debug gate **17/17** before reproducing the same R1
failure. R7 does not alter or suppress that transport failure.

To preserve road-local Release evidence without weakening the authoritative
full matrix, this increment adds independent hosted job
`r7-macos-native-lifecycle`. It uses one ephemeral build root, builds only the
production-backed macOS capture/session test targets, fail-closed preflights the
same seventeen names, and runs them in Debug and Release. The primary macOS job
still runs the focused gate plus the complete suite; a full-suite failure still
fails M1 and prerelease acceptance. The repository workflow validator now
requires the new R7 job and the generation/session sentinel names.

No production code, native factory exposure, TCC behavior or R2/R3 authority is
changed. Owner macOS 27 remains a separate R10 same-SHA gate and M5 remains
**BLOCKED / NOT RUN** pending explicit authorization and genuine positive
macOS desktop admission.

## R10 Windows ACL helper PowerShell-module correction (2026-10-17)

R10 publication `e782cd642f574e7ef45792c8fe168dfad70c8d2a`, Actions
`39011665925`, exposed a helper-only hosted Windows/MSVC defect before any
`icacls` mutation: Windows PowerShell found `Get-Acl` but could not
autoload `Microsoft.PowerShell.Security`. The new diagnostics correctly
identified the executable, native path, exit code and stderr, but this was not
the owner's original failure mechanism.

The helper now obtains the same native `FileSecurity` descriptor through the
Windows PowerShell 5.1 .NET Framework API
`[System.IO.File]::GetAccessControl()`, avoiding module discovery entirely.
Owner-SID, protected-DACL and explicit ACE verification are unchanged. No
production credential policy, listener, admission or licensing path changes.

## R9 P1 Windows CLANG64 security-fixture regression gate (2026-10-17; exact-SHA CI pending)

**Authoring parent:** `611e3279d7bffc3678bcd8ec899210e14a446cd8`.

The owner-native transcript is complete for the 507-test invocation: **454 PASS
/ 53 FAIL**. It does not contain `git rev-parse HEAD`, `clang++ --version`
or native `icacls` stdout/stderr, so the owner run cannot be promoted into an
exact-SHA/compiler M1 receipt and the exact ACL failure mechanism remains
**undemonstrated**. R10 owns the repair and has centralized SID-native fixture
setup at `e782cd642f574e7ef45792c8fe168dfad70c8d2a`; R9 does not rewrite that
helper.

The hosted MSYS2 CLANG64 parity job previously exercised the affected runtime
TLS, licensing and configuration tests only through the full CTest suite. P1
adds a focused fail-closed gate in **both Debug and Release** after the complete
test graph is built. It first enumerates exactly three dedicated R10 fixture
tests and requires all names before executing them:
`runtime.windows-private-fixture-dacl-creation`,
`runtime.windows-private-fixture-broad-access-denials`, and
`runtime.windows-private-fixture-owner-consistency`. It then enumerates and
executes five representative production-backed cases spanning the original
failure families: licensing secure-file snapshot, licensing CLI provisioning,
Windows private config DACL, private TLS-file metadata and the owned runtime TLS
handshake. Exact cardinality is required for both selections.

The broad-access fixture starts only from R10's verified private ACL baseline,
then adds the intended Everyone / Authenticated Users / Built-in Users or
public-read ACE and calls the existing runtime checker. The preflight therefore
cannot count a negative security test as valid if private ACL creation failed,
and it does not bypass or weaken production `hasRestrictedCredentialDacl()`
policy. The ordinary full CLANG64 suite still runs afterward; no regex reduces
the test count or converts failures to skips.

The independent workflow-structure guard remains separate from this fixture
gate. Current parent structure validation is green; exact publication-SHA
structure, Windows/MSVC, Linux, macOS, R7/R9 sanitizer, SDK/package and CLANG64
Debug/Release results are **PENDING**. Owner-native rerun remains required.

## R8 directory-capability binding before hierarchy materialization (2026-10-17; exact-SHA CI pending)

**Reconciled parent:** `e782cd642f574e7ef45792c8fe168dfad70c8d2a`.  
**Implementation:** `446f13677d57d2ef3bead65bb65dcc460e1fde3a`.  
**Implementation Actions:** `39011707625` — execution pending at this receipt.

R8 now adds the deliberately narrower ownership primitive required before any
directory creation can be reviewed:
`RemoteDirectoryCapabilityBinding`. It binds one exact current
`RemoteFileDestinationPlan` directory association to a separately supplied
opaque native directory token. The token is accepted only through caller
provided native operations that duplicate the already-authorized directory
capability; the binding never treats `localSelectionIdentity` as authority,
never opens/reopens a path, and never sees a remote filename.

The binding is one-shot, non-copyable and non-movable. It pins the
`RemoteTransfer` generation, remote descriptor index and planned local
selection identity. Plan cancellation, source replacement or association
retirement releases the duplicate exactly once. Cancellation/close are terminal
and idempotent. No child-name API, mkdir/openat/CreateFile call, symlink/reparse
traversal, clipboard publication or file-byte transfer is added.

Two dedicated production-backed CTests are
`clipboard.directory-capability-binding-authority` and
`clipboard.directory-capability-binding-retirement`. The authority case uses
a real directory-role descriptor plus a file-role sibling, proves file
associations are rejected before native duplication, deliberately supplies the
plan's numeric selection identity as the native token and requires native
rejection, then binds the independently supplied caller token. The retirement
case proves plan cancellation, generation replacement and explicit cancellation
release the duplicate exactly once. R9's complete clipboard sanitizer preflight
requires both exact registrations.

This does **not** change
`RemoteFileDestinationPlan::hierarchyStatus()`:
`UnsupportedWithRetainedMetadata` remains authoritative, and directory
associations still report `UnsupportedDirectoryMaterialization` for transfer
or publication. Caller parent relations remain local placement metadata only,
not evidence of remote tree fidelity.

The implementation commit's documentation-policy job is expected to fail
because the source/test increment was intentionally published before this
co-change receipt; compiler/CTest/sanitizer results from that run must be
inspected independently and the documentation receipt must get its own policy
result before this increment is called fully green.

**Next R8:** once the portable binding is executable-green, add platform-native
duplicate/close factories that inspect already-open directory objects without
path reopen. Then separately review handle-relative child creation: POSIX must
stay beneath the held directory descriptor with no-follow semantics, while
Windows must not fall back to constructing/reopening an absolute pathname.
Remote directory materialization remains disabled until that creation contract
and verified hierarchy source both exist.

## R3 CAL issuer-constraints scoped hosted validation (2026-10-17)

**Implementation:** `586101c7e50326f583ab0479bbfb6785353807b7`.  
**OpenSSL 4 correction / validated R3 source:** `1332fd044773b9da53bff2d81403204ecd137484`.  
**Actions:** `39011519138` — overall **FAIL** from the independent R1
`transport.tcp-native-loopback-tls` readiness regression; R3-specific
ordinary Debug and sanitizer evidence **PASS**.

The const-corrected issuer gate compiles on Linux/GCC, macOS/AppleClang with
OpenSSL 4 and Windows/MSVC. In each ordinary Debug suite all eight flat
`transport.licensing-client-cal-*` cases pass before the suite later reaches
the unrelated R1 loopback-TLS failure:

- Linux/GCC: CAL #67-#74 **8/8 PASS** inside the 572-test Debug registry.
- macOS/AppleClang/OpenSSL 4: CAL #67-#74 **8/8 PASS** inside the 488-test
  Debug registry.
- Windows/MSVC: CAL #67-#74 **8/8 PASS** inside the 521-test Debug registry.

The new `transport.licensing-client-cal-issuer-constraints` case passes on
all three ordinary hosted toolchains. R9 Clang ASan/UBSan fail-closed
preflights exactly the same eight CAL registrations and executes **8/8 PASS**;
the larger bounded R1/R3 sanitizer selection also passes **91/91**. Workflow
structure, R7 sanitizer and documentation-policy jobs pass.

Ordinary Release CTest, installed-SDK/package gates and publication are
**NOT RUN** because each ordinary Debug suite stops later at the independent R1
native loopback-TLS test. That cross-road failure does not invalidate the
executed R3 tests, but this roadmap item is not called fully platform-complete
until an unchanged-R3 descendant reaches Release after R1 recovery.

This gate remains non-authorizing. It proves only that peer-supplied
intermediates are X.509 certificate-signing CAs after cryptographic signature
verification and exact independent-root matching. Product/version correlation,
CAL-specific expiration/renewal/classification, revocation and path-length
policy, proprietary Microsoft licensing-extension payload decoding,
CAL-to-HWID binding and a genuine issuing authority remain incomplete. No
`STATUS_VALID_CLIENT`, synthetic CAL issuance or Share activation is enabled.

Canonical owner-local `~/rdp-server/build/` and real-client acceptance are
**NOT RUN** in this connector environment.

**Next R3 gate:** use an unchanged-R3 descendant after the R1 loopback-TLS
recovery to complete ordinary Linux/macOS/Windows Release execution. Do not
advance additional CAL semantics before that validation gate closes.

## R5 P1 native-X11 registry cardinality exact-SHA validation (2026-10-17)

**Correction:** `3e2962cb22c03a30ebc34ad736da7f53cdc70da6`.  
**Actions:** `39011365665` — overall **FAIL** only in cross-road ordinary
full-suite execution; the R5 sanitizer gate itself is **PASS**.

On Ubuntu 24.04 with Clang **18.1.3**, Xvfb **21.1.12** and the complete
XCB XShm/RandR/XFixes/XDamage/XTEST/XI2 development profile, the corrected
fail-closed preflight enumerates exactly **33** selected R5 registrations.
The cardinality assertion passes, all existing named sentinels pass, and the
same anchored selector executes **33/33 PASS** under ASan/UBSan with leak
detection. Pixel parity is **25/33**, RandR capture generation **26/33**,
stale-damage isolation **27/33**, terminal capture denial **28/33**, pointer
stale-motion isolation **32/33**, and R3 admission-route denial/revocation
**33/33**.

The ordinary Ubuntu/GCC 13.3 Debug full suite also reaches the R5 native cases;
the inspected pixel, RandR/damage, pointer-generation and input-route cases all
pass. That suite finishes **571/572 PASS** because the unrelated R1
`transport.tcp-native-loopback-tls` fixture aborts. The same R1 behavior is
the failure in the macOS, Windows/MSVC and Windows CLANG64 full suites at this
SHA, so Release/full-matrix green evidence is not claimed for R5 from this
workflow. Documentation policy, the independent workflow-structure gate, R7
sanitizers and the complete R9 sanitizer job pass.

The supported-profile registration gap is therefore closed: no expected
non-sentinel R5 native/Xvfb behavior can silently disappear while the focused
gate remains green. No production X11 source or CTest behavior changed in this
increment.

Canonical owner Linux/X11 remains **NOT RUN**, so M1 is still open under R10's
same-SHA owner matrix. M3 remains **BLOCKED ON R3** for authenticated,
already-decoded bounded Share/Input or Fast-Path Input delivery; no live XTEST,
capture or Microsoft-client acceptance is enabled or claimed.

## R10 Windows MSYS2 CLANG64 synthetic-DACL fixture blocker (2026-10-17; owner rerun required)

The owner supplied a native MSYS2 CLANG64 full-CTest transcript with **507
tests, 454 PASS and 53 FAIL**. The dominant failures occur in test-fixture
preparation before the intended production assertion and report only generic
messages such as `Cannot set private synthetic fixture DACL`,
`Cannot set private synthetic config DACL` and
`Cannot set synthetic TLS fixture DACL`. The supplied excerpt does not
contain `git rev-parse HEAD` or the captured `icacls` stdout/stderr, so it
cannot establish an exact-SHA M1 receipt or honestly distinguish executable
resolution, account-name mapping, path formatting, filesystem ACL support or a
specific ACL operation.

A hosted MSYS2 CLANG64 control at
`03f7675cfedd2691ff2e446d8b960170bd7625a4`, Actions
`39010975844`, uses Clang **23.1.3** and CMake **4.4.4**. Its Debug run
reaches the same production-backed licensing/config/TLS fixture families and
passes the previously reported DACL-blocked cases. The full hosted CLANG64
Debug suite is **519/520 PASS**; its sole unrelated failure is
`transport.tcp-native-loopback-tls` with Windows exit `0xc0000409`. This
proves the owner failure is not a universal Clang 23/MinGW-w64 fixture failure.

R10 centralizes disposable Windows fixture preparation in one test-only
helper. It resolves native System32 security tools, converts CMake paths to
native absolute paths, resolves the current SID instead of granting by localized
account name, checks the actual file-owner SID, skips `/setowner` when
ownership already matches, and fails closed if a required ownership correction
cannot be performed. Inheritance removal and owner grant replacement are
separate `icacls` operations. Every failure reports the exact operation,
native path, executable, exit code, stdout and stderr. A post-operation
descriptor check requires protected inheritance, current-SID ownership,
explicit owner FullControl, and no allow ACE outside owner, LocalSystem or
Administrators. No production authorization code or
`hasRestrictedCredentialDacl()` policy is changed.

Dedicated Windows CTests
`runtime.windows-private-fixture-dacl-creation`,
`runtime.windows-private-fixture-broad-access-denials` and
`runtime.windows-private-fixture-owner-consistency` exercise the shared
helper and reuse the real runtime config/TLS checks for positive and
broad-principal negative assertions. Owner-native validation is **NOT RUN**
until the owner fast-forwards to the publication SHA. If it still fails, the
new diagnostic is the required root-cause evidence; do not weaken DACL checks
or run elevated by default.

**M1 Windows status:** **OPEN / owner rerun required**. Listener startup,
admission/licensing gates and production credential authorization remain
unchanged.

## R7 P1 hosted Apple capture/session fail-closed gate (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `1332fd044773b9da53bff2d81403204ecd137484`.

R7's Apple-only capture lifecycle has direct exact-SHA evidence at
`8ee59f77a0db27df3bb06096955cee07ed8b938a`, but the ordinary macOS matrix
previously relied on the aggregate full CTest suite to keep those registrations
observable. A removed or accidentally renamed Apple-only R7 test could therefore
reduce coverage without a road-local registry failure as long as the remaining
full suite stayed green.

This increment changes CI/test evidence only. The hosted macOS protocol job now
records `sw_vers`, exact Xcode version, active developer directory,
`xcrun clang++ --version`, and macOS SDK version. After each Debug and Release
compile it performs a fail-closed `ctest -N` preflight over the focused R7
capture/session selection, requires all seventeen named lifetime tests to be
registered, and then executes the same anchored selection before the ordinary
full CTest. The gate includes the same-dimensions display-generation fence,
ScreenCaptureKit callback/start/stop retirement, session-watch frame/consumer
races, cursor publication freshness, input session revocation and GUI-session
switch/terminal retirement.

No production source, TCC probe/request behavior, ScreenCaptureKit factory
visibility, R2/R3 authority or live desktop path changes. The tests remain
injected/synthetic and permission-free; the ordinary full Debug/Release suites
remain authoritative after the focused gate. Owner macOS 27 execution is still
required by R10's same-SHA M1 matrix, and live M5 remains blocked on explicit
authorization plus genuine positive R2/R3 macOS desktop admission.

Exact publication-SHA hosted validation is **PENDING**. M1 and M5 remain
**OPEN / NOT ACCEPTED**.

## R3 CAL issuer-constraints OpenSSL 4 constness correction (2026-10-17; exact-SHA CI pending)

**Implementation:** `586101c7e50326f583ab0479bbfb6785353807b7`.  
**First Actions:** `39011330461` — macOS/OpenSSL 4 Debug compile **FAIL** before
R3 CTest execution.

The hosted AppleClang/OpenSSL 4 build exposed one source-portability defect in
the new issuer-constraint helper. OpenSSL 4 returns
`const X509_EXTENSION *` from `X509_get_ext()`; the implementation stored
that borrowed extension in `X509_EXTENSION *const`. The compiler correctly
rejected the discarded const qualifier before any CA-policy behavior executed.

This correction changes only that borrowed pointer to
`const X509_EXTENSION *const`. `X509_EXTENSION_get_critical()` is
read-only, so no cast or mutable access is needed. The standards-defined
`basicConstraints CA:TRUE` / optional-`keyUsage` `keyCertSign` policy,
the dedicated `transport.licensing-client-cal-issuer-constraints` CTest,
existing cryptographic signature verification, exact trust-anchor matching and
the R9 eight-case CAL selector are unchanged.

Canonical owner-local `~/rdp-server/build/` remains **NOT RUN**. Exact
correction-SHA Linux/GCC, macOS/AppleClang, Windows/MSVC and R9 ASan/UBSan
evidence is **PENDING**.

## R5 P1 registry-cardinality parser correction (2026-10-17; exact-SHA CI pending)

**First publication:** `910cdad63b2b0cb384bf85d63731482c42e340cd`.  
**First Actions:** `39011106741` — R5 preflight **FAIL before execution**.

The new fail-closed preflight correctly enumerated **33** R5 registrations, but
its AWK matcher was over-escaped and counted those printed `x11.*` lines as
zero. This is an R5-owned workflow parser defect, not an X11 production or
CTest failure. The ordinary Ubuntu/GCC full suite at that SHA still executed
the native X11 cases: pixel parity, RandR capture generation, stale-damage
isolation, pointer stale-motion isolation and R3 admission-route denial all
passed. The full Linux/macOS suites failed separately in R1
`transport.tcp-native-loopback-tls`.

The correction removes exactly one redundant backslash from the AWK regular
expression so it counts the actual `ctest -N` entries while retaining the
expected cardinality of **33** and all existing exact-name sentinels. No
production source, CTest registration, Xvfb discovery, authorization or native
input/capture behavior changes.

Canonical owner Linux/X11 remains **NOT RUN**. Exact correction-SHA R9 native
X11 execution is **PENDING**; M1 remains under R10's same-SHA owner gate and M3
remains blocked on R3's authenticated decoded input handoff.

## R3 CAL intermediate issuer-authorization boundary (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `dcbf605fc11c10db65b4e14b522c4806777b2bec`.

MS-RDPELE 2.2.2.9 defines license-server/client certificates as X.509 v3 under
RFC 3280. The existing inspector already reconstructs one unique chain, checks
RSA/SHA-1 signatures and requires an independent exact root trust anchor, but
it previously accepted a cryptographically valid peer-supplied intermediate
even when that certificate was not authorized as a CA.

This increment adds the missing fail-closed intermediate issuer prerequisite.
Every non-root, non-leaf path certificate must carry exactly one critical
`basicConstraints` extension with `CA:TRUE`. When key usage is present,
`keyCertSign` must be asserted. The trust anchor itself remains out-of-band
policy and is not required to derive authority from its peer-provided
extensions. A dedicated production-backed CTest
`transport.licensing-client-cal-issuer-constraints` covers the positive
constrained issuer plus signature-valid chains with missing constraints,
`CA:FALSE`, non-critical CA constraints and denied key usage; it also proves
that absent key usage is allowed when the critical CA constraint is valid.
R9's flat CAL sanitizer selector now fail-closed preflights the new case.

The prior signature, root-match, leaf-validity and licensing-extension behavior
is unchanged. Product/version correlation, CAL-specific license expiry,
renewal/permanent/temporary classification, revocation/path-length handling,
proprietary extension decoding, CAL-to-HWID binding and a genuine issuing
authority remain incomplete and non-authorizing. No `STATUS_VALID_CLIENT`,
Platform Challenge decision, Share activation or R2 admission behavior changes.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest and
benchmarks are **NOT RUN** in this connector environment. The change is
connection-time certificate validation, not a hot graphics/input loop; no
performance claim is made. Exact publication-SHA Linux/GCC,
macOS/AppleClang, Windows/MSVC, R9 ASan/UBSan, documentation and package
evidence is **PENDING**.

**Next R3:** validate this issuer-authorization gate. Then continue only with
standards-defined X.509/path prerequisites or authoritative CAL encodings;
do not infer Microsoft licensing-extension payload layouts.

## R4 P2 post-structure-recovery hosted validation (2026-10-17)

**Validated unchanged-R4 SHA:** `04a272c8b9b52f59a24401643a46d495978d1f95`.  
**Actions:** `39010848190` — **SUCCESS**.  
**Documentation publication parent:** `09184dc4c5fffe99e411af78b5b6b3ed4a822b3e`.

The first gate after the R4 P2 handoff audit is now closed. R9's workflow
structure guard is schedulable and the complete hosted workflow executes
rather than skipping the protocol matrix. No R4 production source, dedicated
R4 test translation unit, R4 central CTest registration or R9 R4 selector
changed from the validated SHA through this documentation parent.

Ordinary full CTest at the validated SHA passes:

- Linux/GCC: **570/570 Debug + 570/570 Release**.
- macOS/AppleClang: **487/487 Debug + 487/487 Release**.
- Windows/MSVC: native preflight **55/55 Debug + 55/55 Release** and full
  **520/520 Debug + 520/520 Release**.

All five retained zero-byte/terminal recovery cases execute in every ordinary
full suite: `graphics.frame-delivery-unsent-cancellation`,
`graphics.frame-delivery-partial-send-remains-terminal`,
`graphics.avc420-segmented-frame-unsent-cancellation`,
`graphics.x264-segmented-unsent-cancel-idr`, and
`graphics.x264-bgra-unsent-cancel-idr`.

R9 Clang ASan/UBSan independently registry-preflights and passes the complete
portable R4 RDPGFX group **39/39** and x264/BGRA group **22/22**. The three
portable cancellation/terminal cases pass as items **19/39**, **20/39** and
**39/39**; direct-NV12 and BGRA x264 recovery pass as **12/22** and **22/22**.
Documentation policy, R7 sanitizers and the Windows CLANG64/Clang 23 parity
job also complete successfully; ordinary prerelease publication is correctly
skipped.

This is validation only. No new R4 production behavior or CTest is added
because the next code-bearing production boundary remains R3-owned: protected
joined-DRDYNVC authority, `Microsoft::Windows::RDS::Graphics` DVC creation/
fragmentation, and one receipt-bound cumulative accepted-byte sender. Adding a
second R4 transport adapter, native graphics queue or test-only authority would
violate the existing ownership contract.

The proposed Linux/X11 -> R4 ingress also needs no additional production shim.
R5 already returns the supported 32-bit little-endian BGRX
`FramebufferView`; R4 already covers padded stride, synchronous borrowed
lifetime, full-surface BGRA -> NV12 conversion and genuine x264 segmented
publication. An extra Xvfb-to-x264 convergence case would repeat those
road-local contracts without proving the missing R3 authorization boundary, so
P2 does not add one solely to increase test count.

Canonical owner-local `~/rdp-server/build/`, native capture performance and
Microsoft-client visible graphics remain **NOT RUN** here. The next R4
code-bearing step is therefore **BLOCKED ON R3**. Once R3 supplies the
authorized Graphics DVC sender, R4 owns the dedicated production-backed
cross-component byte/receipt compatibility test and then measured native
capture/decode acceptance work. M3/M4/M5 remain **OPEN / NOT ACCEPTED**.

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

## R5 P1 native-X11 registry cardinality gate (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `03f7675cfedd2691ff2e446d8b960170bd7625a4`.

R5's supported hosted Linux/X11 profile intentionally installs XShm, RandR,
XFixes, XDamage, XTEST, XI2, Xvfb and `xvfb-run`. The CMake audit confirms
that optional local Linux builds may legitimately omit native/Xvfb-only cases
when those development dependencies are absent, while the hosted profile
discovers `xvfb-run` before every R5 aggregate/input registration that uses
it.

The remaining validation gap was fail-closed cardinality. R9 enumerated the
anchored R5 selector and checked six sentinel names, but a non-sentinel native
registration could disappear from the supported profile without making that
preflight fail. The selector now requires exactly **33** listed
`x11.*` behaviors before any instrumented execution, in addition to the
existing named sentinels. CTest test names are unique, so the supported profile
cannot silently lose or duplicate one of the expected R5 registrations and
still claim the 33-case sanitizer receipt.

This is CI/test-policy hardening only. No X11 production source, CMake optional
dependency rule, native authority, live desktop access, capture scheduler or
input path changes. Optional developer builds are not made artificially
`REQUIRED` merely to satisfy hosted coverage.

Canonical owner-local `~/rdp-server/build/` and genuine owner Linux/X11 are
**NOT RUN** in this connector environment. Exact publication-SHA hosted
Linux/GCC and R9 execution are **PENDING**. R10's same-SHA M1 owner gate remains
the next native acceptance step after a fully green candidate. M3 remains
**BLOCKED ON R3** for an authenticated, already-decoded bounded Share/Input or
Fast-Path Input handoff; R5 does not enable live XTEST or capture here.

## R3 CAL leaf-validity exact-SHA hosted validation (2026-10-17)

**Implementation:** `3822ca6d230336f8db2e20d1c4ae6153e22b92a3`.  
**Test-only correction:** `ca56ededf527a46bcf535a5c3396d3b9e4d69db4`.  
**Actions:** `39010430295` — overall **FAIL** only in the independent R6
Windows CLANG64 configure gate; all R3-relevant ordinary and sanitizer jobs
**PASS**.

The corrected fixed-size test dispatch and canonical RFC 5280 UTCTime fixtures
leave the production explicit-time CAL leaf-validity API unchanged. Hosted
ordinary CTest passes Linux/GCC **569/569 Debug + 569/569 Release**,
macOS/AppleClang **486/486 Debug + 486/486 Release**, and Windows/MSVC
**519/519 Debug + 519/519 Release**. In every ordinary configuration
`transport.licensing-client-cal-certificate-validity` passes as test #69.

R9's Clang ASan/UBSan CAL preflight enumerates all seven flat
`transport.licensing-client-cal-*` registrations and executes **7/7 PASS**,
including chain structure, issuer-signature denials, product-extension denials,
certificate validity, expiry/HWID denials, no-premature-completion and terminal
retirement. Documentation policy and the ordinary downstream installed-SDK,
package/digest and artifact gates also pass.

This closes only the X.509 leaf certificate validity fact. It does not decode
the proprietary RDP licensing extension payloads, prove CAL-specific
expiration/renewal semantics, correlate product/version, bind the CAL to the
protected-message HWID, establish a genuine CAL issuer, emit
`STATUS_VALID_CLIENT` or activate Share.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27 and real-client CAL acceptance remain **NOT RUN**
for this R3 increment.

**Next R3:** keep CLIENT_LICENSE_INFO non-authorizing and advance only another
standards-defined certificate/path prerequisite or an authority encoding that
is explicitly documented. Do not infer the five Microsoft licensing-extension
payload layouts from synthetic certificates.

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

## R9 P0 structure-gate correction (2026-10-17; exact-SHA CI pending)

The first P0 publication `24a57c8e5b2805bb326b461e896b9068ec95ab38`
is negative evidence. Primary run `39010503457` failed before jobs; independent
guard run `39010504332` executed and rejected duplicate YAML job mappings.
The duplicate suffix was removed by the intervening R6 runnable-workflow repair
`4811d75279379b739ca851deb0a178fd141ffabb`, leaving seven unique primary
jobs and zero duplicate IDs while retaining the P0 structure job.

This R9 correction restores the two intended `ctest -N` additions lost in that
workflow repair: MCS/CLIPRDR fuzzer registration preflight and R7 desktop/input
session preflights. It also narrows `bash -n` validation to Bash/default/MSYS2
block scalars so explicit PowerShell is not parsed as Bash. The independent
duplicate/expression/YAML checks remain global. Exact-SHA CI is pending; M1 is
OPEN and cannot be accepted from hosted CI alone.

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

## R8 P2 native multi-file verification and real-client acceptance gate (2026-10-17)

**Audited shared-main SHA:** `24a57c8e5b2805bb326b461e896b9068ec95ab38`.  
**Multi-file implementation:** `2e0f2814b8943fa8a83fccd97b7294a43f873b9f`.  
**Windows render-helper correction / validated R8 source:** `583b59272cb51f95c967e3f0af9d13553e581e3a`.  
**Known-green hosted M1 baseline:** `6457f259840fbfe3998f50517593cfd9185e75fe`, Actions `39009925959` — **SUCCESS**.

R8 production and dedicated multi-file test sources are unchanged between the
corrected source SHA and this audit SHA. The current central CTest registry
still contains
`clipboard.x11-completed-multi-file-uri-handoff`,
`clipboard.windows-completed-multi-file-hdrop-handoff`, and
`clipboard.macos-completed-multi-file-url-handoff`; R9's complete clipboard
sanitizer preflight fail-closes on all three exact names before executing the
full clipboard label.

The known-green hosted baseline executes the unchanged R8 implementation:
Linux/GCC full CTest is **568/568 PASS Debug + 568/568 PASS Release**,
macOS/AppleClang is **485/485 PASS Debug + Release**, Windows/MSVC is
**518/518 PASS Debug + Release**, and R9 Clang ASan/UBSan clipboard coverage is
**68/68 PASS**. All three multi-file handoff cases pass. The same sanitizer
selection passes the existing Linux/macOS/Windows file-destination size-cancel
and denial cases plus the destination-plan generation and cancel/replay cases,
so partial materializations and stale/cancelled associations are not omitted
from P2 evidence.

Windows multi-file publication is plan-indexed rather than name-indexed:
each destination must be `Complete`, current-generation and a
`CurrentFile` association for its exact `RemoteTransfer` descriptor index.
The test uses two identical remote leaf names, completes descriptor 0 and 1
independently into separately supplied native destinations, passes the finished
objects in reverse order and verifies one CF_HDROP payload in descriptor-index
order. The payload uses `DROPFILES.pFiles=20`, `fWide=TRUE`, one
NUL-terminated UTF-16 path per file and the final list NUL. The pre-existing
`renderFormatInternal` helper restored in `583b5927...` remains present.

macOS applies the same current-plan/current-generation checks and publishes the
completed local URLs through the existing AppKit bridge. The bridge rejects an
empty, duplicate or >64 URL set, converts every entry to a file `NSURL`, and
uses one `writeObjects:` call. The dedicated test proves two distinct file URL
entries are delivered in descriptor-index order even when the caller span is
reversed, while partial, duplicate, takeover and cancelled-plan states remain
unpublished.

Linux/X11 continues to materialize each member independently through its
caller-opened descriptor and bound remote `fileIndex`, then exposes the set
only when every destination is `Complete` for the current generation. Its
multi-file test proves partial-set invisibility, duplicate URI denial, exact
URI-list/GNOME/KDE formats and stale-generation refusal. No platform derives a
local path from FILEDESCRIPTORW names, and no directory-tree fidelity is
claimed from leaf metadata.

### R8 owner-approved real-client interoperability checklist

This checklist is **prepared, not executed**. It authorizes no clipboard,
filesystem, desktop-session or client access. Before any live case, the owner
must explicitly approve the platform/test destination and R10 must name the
literal current M1 candidate SHA after that SHA's complete hosted workflow is
SUCCESS. The owner-native M1 Debug runs for Linux/X11, Windows MSYS2 CLANG64 /
Clang 23 and macOS 27 must be recorded on that same SHA. R6/R7 revocation
evidence and the genuine R2/R3 authorization state must be current; a detached
synthetic R3 channel must never be used to manufacture a positive client path.

| Scenario | Required live check | Pass condition |
| --- | --- | --- |
| Clipboard text | Copy/paste both directions with non-ASCII text; repeat after local ownership takeover | Exact text, no stale-generation republish, local owner wins until a fresh remote generation |
| PNG / DIB | Exercise PNG on all supported paths and Windows DIB/DIBV5 where advertised | Correct image payload/format, no delayed-render network wait, no publication after generation/session retirement |
| One file | Use one owner-approved disposable destination; record source descriptor index, caller-selected native destination and final size/hash | File appears only after exact completion/flush/close; content/hash match; remote leaf name is never used to choose the local path |
| Multiple files | Use at least two files, including same remote leaf names where practical; inspect Explorer/Finder/Nautilus result | One atomic set; every member independently complete/current; no partial visibility; Windows paths and macOS URLs remain distinct and index-correlated |
| Cancellation | Cancel during a file and after one member of a batch is complete | Partial native object is retired/truncated per destination contract and no file-manager batch is published |
| Reconnect | Replace/disconnect before publication, reconnect, then attempt old and fresh sets | Old generation is refused; only newly materialized current-generation destinations can publish |
| Session revocation | Trigger the platform's approved logout/lock/session/TCC/WTS/X11-owner revocation path while transfer/publication state exists | Native owners/resources retire once, held input/capture paths remain revoked, no stale clipboard/file set survives or reappears |

For every live run record the exact Git SHA, OS/client versions, effective
compiler, owner build/CTest receipt, RDP client identity, approved test
directory, scenario result and failure diagnostics. Do not enable live
clipboard/filesystem access as part of ordinary M1 CTest, and do not treat
hosted synthetic clipboard tests as Finder/Explorer/Nautilus acceptance.

**Owner-machine coordination status:** R10's M1 same-SHA matrix is established,
but owner Linux/X11, owner Windows CLANG64/Clang 23 and owner macOS 27 results
are still **NOT RUN / PENDING**. R6's Windows CLANG64 parity gate is hosted
compiler/SDK evidence only, not an owner-machine substitute; R7 likewise still
requires owner macOS 27/TCC/native-session evidence. R2 does not yet mint final
native desktop admission and R3 licensing remains non-authorizing, so genuine
Microsoft-client file-copy acceptance is **BLOCKED / NOT RUN**. M1, M3, M4 and
M5 remain **OPEN / NOT ACCEPTED**.

**Next R8:** after R10 declares a same-SHA M1 PASS and the owner explicitly
authorizes live clipboard/filesystem testing, execute the checklist on the
supported real clients. Directory-tree materialization remains a separate
reviewed capability requiring verified hierarchy plus race-safe relative
creation and symlink policy.

## R9 P0 trustworthy main-branch CI gate (2026-10-17; exact-SHA CI pending)

**Authoring parent:** `ca56ededf527a46bcf535a5c3396d3b9e4d69db4`. **Implementation:** this publication.

The zero-job Actions failure at `680d15e563f5fd4a8a2d70b481821f3ae960828f`
(run `39009664731`) came from a malformed single-quoted R2 sanitizer selector
plus a duplicated workflow suffix. R2 correction
`dcac5920949d697d517ba08b9c0ab5d0f33438a1` removed the duplicate suffix and
repaired the selector; R9 did not reconstruct or replace that correction.
Unchanged descendant `92ddb689b0ca3200b2ef420f818c04cd630da147`
then completed Actions `39009841176` successfully across Linux, macOS,
Windows, R7 and R9, proving the repaired pre-P0 workflow itself was executable.

This P0 adds a deterministic repository-local workflow validator and dedicated
CTest `project.ci-workflow-structure-denials`. It rejects duplicate
top-level/job mappings, malformed GitHub expression delimiters and Bash syntax
errors, including the exact unterminated-selector failure class. It requires
the current R1/R2/R3/R4/R5/R6/R7/R8/R10 sentinel selectors, both bounded
fuzzers, sanitizer build targets and the prerelease main-ancestry/version/
digest/publication protections. PyYAML is used with duplicate-key rejection
when available; deterministic lexical checks remain mandatory without it.

A lightweight independent `.github/workflows/ci-structure.yml` checks
`ci.yml` on every main push even if the primary workflow is too malformed to
create jobs. The primary workflow also gates the hosted protocol matrix,
Windows Clang 23 gate, R7/R9 sanitizers and documentation policy behind the
same structure check. The MCS/CLIPRDR fuzzer and R7 desktop/input selections
now perform explicit `ctest -N` registry preflight before execution.

Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN** here.
Exact publication-SHA hosted matrix, sanitizer, SDK/package and independent
structure-guard evidence is **PENDING**. M1 remains **OPEN / NOT ACCEPTED**;
hosted CI alone cannot accept it.

## R3 CAL leaf-validity fixture/registry correction (2026-10-17; exact-SHA CI pending)

**Implementation being corrected:** `3822ca6d230336f8db2e20d1c4ae6153e22b92a3`.  
**First Actions:** `39010291382` — macOS Debug compile **FAIL** before CTest.

The first hosted compile exposed test-only registration bookkeeping: adding the
seventh CAL behavior left the fixed `kMcsTestCases` dispatch array at 121
entries, so AppleClang rejected the 122nd initializer. The correction updates
only that array bound.

The same fixture is also canonicalized to RFC 5280 certificate time encoding.
Dates in 2026/2027 are now encoded as UTCTime (`YYMMDDHHMMSSZ`) rather than
four-digit GeneralizedTime. The injected Unix timestamps and production
validity logic are unchanged. This avoids relying on provider tolerance where
X.509 requires UTCTime through 2049.

No production source, API, CAL decision, trust rule, CTest name or sanitizer
selector changes in this correction. Exact correction-SHA Linux/GCC,
macOS/AppleClang, Windows/MSVC and ASan/UBSan evidence is **PENDING**.

## R6 P1 Windows CLANG64/Clang 23 evidence gate (2026-10-17; publication validation pending)

**Starting reconciled shared `main`:** `a503fb558cee88cea2d03f97929136caec77171b`.

R6 P1 aligns its Windows owner evidence with R10's M1 matrix: one owner
checkout at `~/rdp-server`, one persistent `build/`, MSYS2 **CLANG64**,
Clang **23.x**, and the ordinary full CTest command. The evidence receipt must
record the exact Git SHA plus Clang, CMake, MinGW-w64 headers/CRT and OpenSSL
package versions. MSVC remains useful hosted coverage but is not a substitute
for this gate.

A new hosted CLANG64 parity job provisions the current CLANG64 repository,
verifies Clang 23 before configuration, and uses the existing single build root
for Debug and Release. It fail-closes on registration drift for the four
whole-owner retirement cases, runs the complete existing R6 native selector in
both configurations, then runs full CTest in both. It uses deterministic
synthetic callbacks only; no desktop capture, WTS registration or SendInput is
authorized.

The parity job is intentionally **not owner-machine evidence**. It is a
compiler/MinGW SDK discriminator: if it fails, R6 owns source/test repairs for
R6 failures; if it passes while the owner command fails at the same SHA, the
remaining failure is owner environment/cache/toolchain specific until proven
otherwise. Owner CLANG64 evidence is therefore still **PENDING** at this
publication.

For future authorized Windows composition, R10 must supply the sole serialized
delivery of `WM_WTSSESSION_CHANGE` or `SERVICE_CONTROL_SESSIONCHANGE` to the
R6 owner plus the service/session lifetime that keeps the owner alive through
callback-safe-point teardown. That delivery is revocation only: R10 must not
turn WTS observations into authentication. Positive desktop construction still
requires a fresh non-forgeable R2 admission/reauthorization capability.

R3 must supply the authenticated, already-decoded bounded input route after the
R2 lease is current: keyboard/pointer events must be correlated with the same
session/generation and delivered only to the existing R6
`WindowsInputController`. R3 must retire that route before or with session
revocation and must never let protocol parsing or a caller Boolean synthesize
Windows authorization.

M1 remains **OPEN** until the owner Windows CLANG64 receipt covers the agreed
M1 SHA (or a concrete R6-owned failure is recorded and fixed). M4 remains
**OPEN / NOT ACCEPTED** without a real R2-admitted Windows user desktop and
Microsoft-client graphics/input acceptance.

## P0 M1 same-SHA owner-platform acceptance coordination (2026-10-17)

**R10 role:** M1 validation coordinator. Production runtime/service expansion is
paused until this baseline is either accepted or reduced to an exact
owner-assigned failure list. The normal service listener remains disabled and
all existing R2 admission, R3 licensing and live-publication gates remain
unchanged.

**Candidate rule:** the commit that contains this section is the next M1
candidate **only after its own complete GitHub Actions workflow reports
SUCCESS**, including R9. The coordinator's final report must publish that
commit's literal SHA and Actions URL. The owner must run
`git rev-parse HEAD` immediately after the required fast-forward pull and stop
without configuring if it differs from that literal candidate SHA. A later
`main` commit supersedes the candidate before owner execution; results from
different SHAs cannot be combined into M1 acceptance.

The last fully completed green hosted baseline before this coordination
publication is `6457f259840fbfe3998f50517593cfd9185e75fe`, Actions
`39009925959` — **SUCCESS**. Its documentation policy, Linux/GCC,
macOS/AppleClang, Windows/MSVC, R7 sanitizer and R9 ASan/UBSan jobs all
completed successfully. That baseline establishes a known-green starting
point; it is **not** owner-native M1 evidence.

### Canonical M1 evidence matrix

| Gate | Required candidate evidence | Status at this coordination commit |
| --- | --- | --- |
| Owner Linux/X11 | Exact candidate SHA; OS/version; effective C++ compiler/version; Debug configure/build/full CTest from only `~/rdp-server/build/`; total, failed, skipped and failure log | **NOT RUN** |
| Owner Windows MSYS2 CLANG64 / Clang 23 | Exact candidate SHA; Windows/MSYS2 version; `clang++ --version` proving Clang 23; Debug configure/build/full CTest from only `~/rdp-server/build/`; total, failed, skipped and failure log | **NOT RUN** |
| Owner macOS 27 | Exact candidate SHA; `sw_vers`; `xcodebuild -version`; `xcode-select -p`; `xcrun clang++ --version`; CMake effective AppleClang; Debug configure/build/full CTest from only `~/rdp-server/build/`; total, failed, skipped and failure log | **NOT RUN** |
| Hosted Linux/GCC | Candidate workflow Debug + Release full CTest, SDK consumer, package/digest/artifact | **PENDING candidate workflow** |
| Hosted macOS/AppleClang | Candidate workflow Debug + Release full CTest, SDK consumer, package/digest/artifact | **PENDING candidate workflow** |
| Hosted Windows/MSVC | Candidate workflow native preflight plus Debug + Release full CTest, SDK consumer, package/digest/artifact | **PENDING candidate workflow** |
| R9 Clang ASan/UBSan | Every configured fail-closed sanitizer/fuzzer group in the candidate workflow | **PENDING candidate workflow** |
| R7 macOS session sanitizer | Candidate workflow dedicated R7 sanitizer job | **PENDING candidate workflow** |
| Documentation policy | Candidate workflow documentation-policy job | **PENDING candidate workflow** |
| Same-SHA convergence | All three owner-native reports must name the exact candidate SHA above; hosted evidence must be for that same SHA | **BLOCKED on owner runs** |

The formal owner-native gate is the unchanged Debug command required by
`AGENTS.md` and `docs/compile.md`; hosted Debug/Release does not replace it.
A Release local dry run may be recorded additionally, but it cannot substitute
for the required Debug full CTest.

### Owner command and evidence contract

Run this unchanged command in the platform's required shell/toolchain
environment:

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

Immediately after the pull, before configure, also record:

```sh
git rev-parse HEAD
cmake --version
```

Record the platform-native OS version and effective compiler version as well:
Linux/X11 records `cat /etc/os-release` (or equivalent) and
`c++ --version`; Windows MSYS2 CLANG64 records `uname -a` and
`clang++ --version`; macOS records `sw_vers`, `xcodebuild -version`,
`xcode-select -p` and `xcrun clang++ --version`. The macOS M1 row is valid
only when `sw_vers -productVersion` reports major version 27. Do not delete or
replace `build/`; CMake's configure
output must be checked to ensure the reused cache selected the intended
compiler. Report the complete CTest summary, including total tests, failures,
skips/not-run tests, and the `--output-on-failure` diagnostics for every
failure. Do not enable opt-in live desktop, clipboard, credential, service or
listener tests as part of M1.

If an additional Release dry run is requested, reconfigure and reuse the same
root exactly as documented:

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Release --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Release --output-on-failure
cmake --install "$HOME/rdp-server/build" --config Release --prefix "$HOME/rdp-server/build/stage"
cmake -S "$HOME/rdp-server/tests/consumer" -B "$HOME/rdp-server/build/consumer" -DCMAKE_PREFIX_PATH="$HOME/rdp-server/build/stage" -DCMAKE_BUILD_TYPE=Release
cmake --build "$HOME/rdp-server/build/consumer" --config Release --parallel 2
ctest --test-dir "$HOME/rdp-server/build/consumer" -C Release --output-on-failure
cmake --build "$HOME/rdp-server/build" --config Release --target package
```

### Failure ownership

M1 failures are routed without ambiguity: **R1 owns macOS native TCP/TLS
failures; R5 owns Linux/X11 native failures; R6 owns Windows native failures;
R7 owns macOS capture/session failures.** R10 coordinates the matrix and keeps
cross-road failures attached to the first failing boundary; it does not mask a
failure by changing test selection. Every repair must land directly on
`main`, pass its own hosted workflow, and produces a new M1 candidate; owner
results from the superseded SHA are retained as historical evidence but cannot
be mixed into acceptance.

**M1 status:** **OPEN / NOT ACCEPTED** until all three mandatory owner-native
rows and the complete hosted rows are PASS on one exact SHA. No evidence-format
checker is added: the current matrix is deterministic without new production
or test code, and fabricated validation output is prohibited.

## R7 macOS generation-fence hosted validation and owner M1/M5 gate (2026-10-17)

**Implementation:** `8ee59f77a0db27df3bb06096955cee07ed8b938a`.  
**Exact-SHA Actions:** `39009608665` — **SUCCESS**.

The exact implementation workflow proves the new generation fence and Apple
capture-state integration on hosted macOS. The hosted runner was macOS
**26.6.2 (25G83)** on image `macos-26-arm64`
`20261013.0424.1`; the image manifest selects **Xcode 26.6 (17F113)** and CMake
reported **AppleClang 21.0.0.21000101** for C, C++ and Objective-C++. Full
CTest is **484/484 PASS Debug** and **484/484 PASS Release**. In both
configurations
`macos.desktop-geometry-epoch-generation-fence-revocation` (#394) and
`macos.capture-stream-geometry-generation-retirement` (#428) execute and pass.
The installed-SDK consumer is **1/1 PASS**, package/digest generation passes,
the R7 GCC ASan/UBSan job passes, the complete R9 Clang ASan/UBSan job passes,
and documentation policy passes. This is deterministic SDK/CoreVideo and
state-machine evidence only; the hosted job does not run macOS 27, a live
ScreenCaptureKit stream, native cursor/input, a real session switch or any TCC
prompt.

Comparison from `8ee59f77...` through R10's M1 coordination publication
`a503fb558cee88cea2d03f97929136caec77171b` changes none of the R7 macOS
capture, geometry, cursor, input, desktop-session or session-watch production
files and none of their four dedicated test sources. R7 therefore joins R10's
same-SHA owner matrix rather than creating a second M1 candidate rule. Any
later candidate must still contain those R7 bodies unchanged or obtain fresh R7
hosted validation before its owner result is accepted.

On the owner macOS 27 candidate, first run R10's unchanged canonical Debug
configure/build/full-CTest command and record the exact SHA plus
`sw_vers`, `xcodebuild -version`, `xcode-select -p` and
`xcrun clang++ --version`. The CMake configure output must identify the
effective AppleClang from the reused `~/rdp-server/build/` cache. After the
full CTest gate, this additional attribution-only focused selection may be run
from the same build root; it does not replace the full suite:

```sh
r7_focus='^(macos\.desktop-geometry-epoch-generation-fence-revocation|macos\.capture-stream-(geometry-generation-retirement|callback-retirement|consumer-cancellation|native-stop-single-ownership|backend-callback-reentry-retirement|start-retirement-after-completion|session-watch-frame-retirement|session-watch-consumer-race)|macos\.cursor-(topology-publication-revocation|geometry-generation-publication-denials|session-watch-revocation)|macos\.input-controller-session-watch-revocation|macos\.desktop-session-(switch-away-back-revocation|mid-operation-epoch-change|watch-retirement-callback-race|watch-destructor-retirement))$'
ctest --test-dir build -C Debug -N -R "$r7_focus"
ctest --test-dir build -C Debug --output-on-failure -R "$r7_focus"
ctest --test-dir build -C Debug -N -R '^runtime\.licensing-authority-'
ctest --test-dir build -C Debug --output-on-failure -R '^runtime\.licensing-authority-'
```

R7 owns any macOS capture/session failure from that same-SHA run; R10 retains
matrix coordination. No M1 result may combine a hosted SHA and an owner SHA
that differ. Owner macOS 27 execution remains **NOT RUN** until that transcript
exists, so **M1 remains OPEN / NOT ACCEPTED**.

The live M5 protocol is separately authorization-gated in
`docs/testing_standards.md`. It requires a disposable test desktop, read-only
Screen Recording/Accessibility preflight, same-generation-replacement and
fast-user-switch retirement observations, and synthetic clipboard content. The
current tree still has no genuine positive R2/R3 macOS desktop-admission
capability and keeps the native ScreenCaptureKit factory quarantined, so the
live phase is **BLOCKED / NOT RUN** and **M5 remains OPEN / NOT ACCEPTED**.

## R3 deterministic CAL leaf-certificate validity boundary (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `2f4fd534bc070977582ed899c620cd79171edecf`.

With the CAL signature/trust fixture validated green at
`17fd924eb642a21b9f985800097d975fe551752b`, R3 advances only the next
standards-defined prerequisite. MS-RDPELE certificates are X.509 v3 under
RFC 3280, whose validity interval is inclusive from `notBefore` through
`notAfter`. The existing inspector therefore gains an explicit-time variant
that reports the leaf certificate as `NotYetValid`, `Valid`, `Expired`,
`MalformedWindow` or `UnsupportedVerificationTime`.

No wall clock is read implicitly. Tests inject fixed Unix timestamps and cover
one second before `notBefore`, exact `notBefore`, an interior time, exact
`notAfter`, one second after `notAfter`, an inverted window and a malformed
ASN.1 time. The legacy two-argument API remains unchanged and reports
`NotEvaluated`. A new production-backed CTest,
`transport.licensing-client-cal-certificate-validity`, is centrally
registered and explicitly required by the R9 CAL sanitizer preflight.

This does **not** claim complete CAL license-expiration validation. MS-RDPELE
also requires correct product information and client HWID matching before a
client license can be valid, while the public specification does not define
the proprietary payload layouts of the five leaf licensing extensions in a
way this project can safely infer. `policyStatus` therefore remains
`RequiredExtensionsPresentButUnparsed` even when the X.509 leaf is currently
valid. No `STATUS_VALID_CLIENT`, Platform Challenge decision, Share activation
or R2 admission behavior changes.

Canonical owner-local `~/rdp-server/build/` execution and benchmark execution
are **NOT RUN** in this connector environment. This path is connection-time
certificate inspection, not a graphics/input hot loop; no benchmark claim is
made. Exact publication-SHA Linux/GCC, macOS/AppleClang, Windows/MSVC,
ASan/UBSan, documentation, SDK and package evidence is **PENDING**.

**Next R3:** validate this necessary certificate-time fact. Then keep
product/version, CAL-specific expiration/classification and CAL-to-HWID policy
fail-closed until an authoritative encoding is available; do not infer
proprietary extension payloads from synthetic examples.

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

## R3 existing-client CAL signature-fixture exact-SHA validation (2026-10-17)

**Implementation:** `17fd924eb642a21b9f985800097d975fe551752b`.  
**Actions:** `39009556082` — **SUCCESS**.

The DER-level changed-signed-content fixture closes the provider-cache
portability gap. The exact implementation SHA passes the complete hosted matrix:
Linux/GCC **564/564 Debug** and **564/564 Release**, macOS/AppleClang
**482/482 Debug** and **482/482 Release**, and Windows/MSVC **516/516 Debug**
and **516/516 Release**. In every ordinary configuration the six
`transport.licensing-client-cal-*` cases pass, including
`transport.licensing-client-cal-issuer-signature-denials`.

The R9 Clang ASan/UBSan job enumerates all six CAL registrations with the flat
fail-closed selector and passes **6/6**. Documentation policy, downstream
installed-SDK consumer, packaging, digest generation and artifact upload also
pass; the overall workflow conclusion is **SUCCESS**.

This validates only the current bounded CAL chain/signature/trust mechanics.
It does not validate product/version correlation, license expiration/renewal,
CAL-to-HWID binding, permanent/temporary classification, a genuine issuer or
any `STATUS_VALID_CLIENT` path. MS-RDPELE 3.2.5.3 still requires a terminal
server to validate the license-server signature, correct product information,
license expiration date and client hardware identification before treating a
client license as valid.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27 and real Microsoft-client CAL acceptance remain
**NOT RUN** here.

**Next R3:** continue fail-closed CAL policy work only from wire semantics that
are explicitly supported by MS-RDPELE or an authoritative referenced encoding.
Do not infer proprietary extension payload layouts from examples. The live
`ClientLicenseInfoValidation` branch remains non-authorizing until product,
expiration and HWID policy are all validated with a genuine supported issuer.

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

## R2 authenticated PAM invocation boundary (2026-10-17; hosted validated)

**Reconciled shared-main parent:** `8ee59f77a0db27df3bb06096955cee07ed8b938a`.

The completed delegated-account binding now feeds the existing real Linux PAM
verifier synchronously, but still cannot authorize a desktop. A new
noninstalled `credssp_credentials_internal.h` visitor reuses the one canonical
credential parser and exposes validated account/password views only during one
stack callback. The GSS final-authInfo path reaches that visitor only after the
existing original-R1 HYBRID/TLS, certificate, GSS principal, binding-reply and
policy-generation fences. PAM is called only after exact
principal-to-delegated-account `CandidateOnly` matching and before the GSS
plaintext is cleansed and released.

`GssapiSpnegoAcceptor` can bind one already-configured
`LinuxPamPasswordVerifier` after its identity policy and before provider
configuration. No implicit PAM service is selected. PAM remains Linux-only and
noninstalled. Even `Authorized` is intentionally discarded: the private final
credential latch remains false, no native lease is issued and R3 remains
closed. Positive PAM still needs to be joined to fresh NSS/logind owner evidence
and revocation in a later audited R2 completion contract.

New production-backed coverage is
`security.credssp-password-field-synchronous-visitor`,
`security.credssp-pam-password-field-verifier-denials` and
`security.gssapi-pam-verifier-binding-denials`. The first is portable; the
latter two remain behind Linux GSS+PAM mode and use only a nonexistent synthetic
account against the real host PAM provider. R9 sanitizer selectors now preflight
all three names. No fake positive PAM, GSS identity or native admission fixture
is introduced.

Exact-SHA hosted validation is **SUCCESS** at
`92ddb689b0ca3200b2ef420f818c04cd630da147`, Actions `39009841176`.
Documentation policy, Linux/GCC, macOS/AppleClang, Windows/MSVC, R7 sanitizer
and R9 Clang ASan/UBSan jobs all passed. The R9 job includes the bounded native
R2/R3 GSSAPI selection and the dedicated Linux PAM denial/lifetime selection.
The canonical owner-local `~/rdp-server/build/` is unavailable in this
connector environment and is therefore **NOT RUN**. Positive
Kerberos/PAM/NSS/logind, owner Linux/X11 and authenticated Microsoft-client
acceptance remain **BLOCKED / NOT RUN**.

### R2 explicit runtime PAM provisioning (2026-10-17; exact-SHA CI pending)

Source commit `14c2e5995e3eb83e0d89725ec41f46837860708f` advances only the
configuration/ownership prerequisite for the later positive completion
contract. In Linux GSS+PAM builds, `LinuxRuntimeSecurityConfiguration` may be
configured with an explicit PAM service name in the same one-shot operation
that seals the keytab and installs the immutable identity rule. It owns the
`LinuxPamPasswordVerifier` for the configuration lifetime and binds that
already-configured verifier into each per-connection
`GssapiSpnegoAcceptor` after the same identity policy and before GSS provider
configuration.

There is still no implicit `login`/`other` PAM fallback and the production
process configuration does not silently opt into PAM. The existing
three-argument runtime-security configuration remains non-PAM. The new
`runtime.linux-security-pam-verifier-provisioning` CTest proves explicit
service acceptance, invalid-service one-shot denial, per-connection acceptor
configuration and that mere provisioning creates neither a native change
watch nor admission authority. The private final-CredSSP completion latch
remains false, no `LinuxConsoleAdmissionLease` is minted and R3 remains
closed.

The next R2 authority-bearing step remains deliberately separate: a genuine
`Authorized` PAM result from the live GSS-unwrapped credential must be tied
privately to the exact delegated account/principal/policy generation, then
fresh concrete NSS/logind owner evidence and an active revocation watch must
succeed before the private completion latch may be set and the existing broker
may issue a lease. Ordinary CI must not manufacture a positive PAM/GSS/native
owner to exercise that transition.

## R7 ScreenCaptureKit geometry-generation retirement fence (2026-10-16; hosted validated, owner macOS 27 pending)

**Starting reconciled shared `main`:** `17fd924eb642a21b9f985800097d975fe551752b`.

The R7 audit found one remaining lifetime asymmetry below the still-blocked
R2/R3 authority boundary. Input, desktop-session guard and cursor consumption
already reject a replaced `NativeDisplayGeometryRefresh` generation even when
display facts and Quartz topology are unchanged. `MacScreenCaptureState`,
however, retained only scalar generation metadata plus the process topology
revision, so a voluntary same-topology geometry refresh could leave queued old
capture callbacks eligible to report `Published`.

This increment adds a revocation-only `NativeDisplayGenerationFence`. One
shared atomic state belongs to each serialized geometry owner; capture bindings
copy only that state plus their immutable expected generation. Refresh,
invalidate and geometry-owner destruction publish revocation before replacing
mutable geometry, while successful install publishes the new generation last.
Late capture callbacks therefore never retain or dereference a mutable geometry
pointer. Prepare/start boundaries, asynchronous completion and frame
publication recheck generation, topology and GUI-session lifetime. A stale
generation retires with `StaleGeometryGeneration` and frames use the distinct
`StaleGeometryGeneration` drop reason. This fence is lifetime evidence only:
it grants no TCC permission, R2 authentication/admission, R3 session authority,
R4 scheduling or native factory access.

New behavior CTests are
`macos.desktop-geometry-epoch-generation-fence-revocation` (portable) and
Apple-only `macos.capture-stream-geometry-generation-retirement`. The latter
uses only the existing injected backend and synthetic CoreVideo storage to
cover same-dimensions replacement before/during prepare and start, late start
completion, pre-frame replacement, replacement inside the synchronous consumer,
old-state non-resurrection and fresh-generation publication. No live
ScreenCaptureKit stream, AppKit event source, TCC prompt or desktop is touched.

Exact implementation-SHA hosted validation is **SUCCESS** at
`8ee59f77a0db27df3bb06096955cee07ed8b938a`, Actions `39009608665`;
the current R7 validation section above records the platform/toolchain and
focused-test evidence. Canonical owner-local `~/rdp-server/build/` and owner
macOS 27 native/TCC testing remain **NOT RUN**. The next authority-bearing R7
gate remains **BLOCKED** on a genuine non-forgeable R2/R3 macOS desktop
admission capability; M1 and M5 remain **OPEN / NOT ACCEPTED**.

## R3 CAL changed-signed-content DER fixture correction (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `f0f852f7da2b7b0dc7c277efe63016ab32b339db`.

The first unchanged-R3 validation descendant after workflow recovery,
`5419ad7f657a30d745a40eb62a0a1c083af715b4` / Actions
`39009402865`, reaches the ordinary macOS Debug suite and still fails
`transport.licensing-client-cal-issuer-signature-denials`. The failure is now
earlier and conclusive: direct `X509_verify()` returns success after
`X509_set_serialNumber()` on an `X509_dup()`, so the negative fixture still
depends on provider-specific cached TBSCertificate behavior and never reaches
the production CAL inspector.

This correction removes that setter/cache dependency. The test creates a fresh
valid leaf with one noncritical synthetic marker extension, signs it, serializes
it to DER, mutates one byte of the unique marker inside the already-signed DER,
and reparses those bytes into a fresh `X509`. Direct `X509_verify()` must
then fail before the certificate is placed into the production PKCS#7 CAL
inspection path, which must report `SignatureVerificationFailure`. Issuer and
subject names, chain topology, signature algorithm and certificate lengths are
unchanged by the mutation.

Production R3 source, CAL grammar, trust-anchor matching, licensing extension
policy, lifecycle and CTest registration are unchanged. Canonical owner-local
`~/rdp-server/build/` execution is **NOT RUN** in this connector environment.

**Next R3 gate:** exact/unchanged-descendant Linux/GCC, macOS/AppleClang,
Windows/MSVC and R9 ASan/UBSan execution of all six CAL cases. Additional CAL
product/expiry/HWID policy remains gated on this result.

## R9 workflow repair reconciliation with concurrent selectors (2026-10-16; exact-SHA CI pending)

The syntactically repaired workflow commit
`5419ad7f657a30d745a40eb62a0a1c083af715b4` restored from an older workflow
snapshot and unintentionally removed newer R4 sanitizer-selection entries. Its
Actions run `39009402865` is **superseded** and is not shared-matrix
acceptance evidence.

This correction reconstructs from immediate pre-repair shared workflow
`3a98aa4e26316346b494e82d84bb909fc3d39904`: it preserves the current prefix, replaces only the corrupted
R9 CredSSP-fuzzer region, and resumes at the second genuine R7 job marker.
Publication checks require the concurrent R4 unsent-cancellation,
partial-terminal and x264/BGRA cancellation selectors to remain present, along
with one R9/R7/docs/publish job and the exact CredSSP registration preflight.
No production behavior or corpus changes. Exact corrected-SHA CI is
**PENDING**.

## R8 Windows/macOS planned completed-set hosted validation (2026-10-17)

**Implementation:** `2e0f2814b8943fa8a83fccd97b7294a43f873b9f`.  
**Render-helper correction / validated R8 source SHA:** `583b59272cb51f95c967e3f0af9d13553e581e3a`.  
**First Actions:** `39008936302` — **FAIL**, R8-owned Windows adapter link regression found.  
**Correction Actions:** `39009046269` — **overall FAIL from unrelated R3 CAL test; R8 evidence PASS**.

The first hosted build correctly exposed that the completed-set refactor had
accidentally removed the pre-existing
`WindowsClipboardAdapter::renderFormatInternal` definition while retaining its
declaration and callers. Linux/GCC, macOS/AppleClang, Windows/MSVC and the
sanitizer target all reached the same undefined-symbol link failure. Correction
`583b59272cb51f95c967e3f0af9d13553e581e3a` restores that implementation
verbatim; delayed-render behavior and the new multi-file contract are otherwise
unchanged.

On the correction SHA, macOS/AppleClang compiled the real AppKit multi-NSURL
bridge and passed **477/477 Debug** and **477/477 Release**. Both
`clipboard.macos-completed-multi-file-url-handoff` and the portable Windows
`clipboard.windows-completed-multi-file-hdrop-handoff` passed in each
configuration. The downstream installed-SDK consumer, package, digest and
artifact upload all passed.

Windows/MSVC passed **507/507 Debug** and **507/507 Release**; both new R8
completed-set cases passed in each configuration. The installed-SDK consumer,
package, digest and artifact upload also passed.

Ubuntu/GCC compiled the complete Debug tree and ran **559** tests. Both new R8
cases passed:
`clipboard.macos-completed-multi-file-url-handoff` was 511/559 and
`clipboard.windows-completed-multi-file-hdrop-handoff` was 522/559. The
single failing test was the unrelated R3
`transport.licensing-client-cal-issuer-signature-denials` (67/559), so the
workflow stopped before Linux Release, SDK consumer and package stages. No R8
failure occurred in that job.

The exact-SHA R9 Clang ASan/UBSan job compiled its production-linked targets,
its fail-closed clipboard registry preflight found both new registrations, and
the complete clipboard-labelled selection passed **68/68**. The macOS
multi-file case was 41/68 and the Windows multi-file case was 52/68. The job's
only failed step occurred later in the bounded R1/R3 selection, where the same
unrelated R3 CAL issuer-signature test failed; the remaining sanitizer families
continued.

Documentation policy and the independent R7 sanitizer job passed. The overall
Actions run is therefore intentionally recorded as **FAILURE**, not a green
matrix, while R8's hosted Debug/Release and sanitizer evidence is positive
except for the Linux Release path blocked by R3.

Canonical owner-local `~/rdp-server/build/` execution remains **NOT RUN** in
this connector environment; no alternate checkout or build root was created.
Live Explorer/Finder/Nautilus acceptance, authenticated Microsoft-client file
copy, native directory creation and symlink-policy acceptance remain
**NOT RUN / OPEN**. No M1-M6 milestone is accepted by this increment.

**Next R8:** define and review the race-safe native directory capability and
relative-creation/symlink policy before enabling any directory materialization;
after that, advance real-client completed-set acceptance without deriving local
paths from remote FILEDESCRIPTORW names.

## R9 CredSSP fuzzer preflight workflow repair (2026-10-16; exact-SHA CI pending)

Superseded hardening publication `7751e079a56e15034845ab61e4ad5e527204efc6`,
Actions `39009145045`: **workflow parse failure before jobs**. It supplies no
compiler, CTest, ASan/UBSan or fuzzing evidence. The R9 CI-generation step
reintroduced the documented JavaScript replacement-string `$'` hazard and
truncated the anchored CredSSP selector while duplicating the workflow suffix.

This repair reconstructs only `.github/workflows/ci.yml` from known-good
parent `2ad37e35e9c1109e2e5509a19025a6a7551030f2` and inserts the fail-closed
CredSSP fuzzer preflight by explicit string indices. Publication checks require
exactly one R9 job, R7 job, documentation job, prerelease job, MCS fuzzer step,
CredSSP fuzzer step and CredSSP registration grep. The stronger
fragmented-reader assertions and all concurrent source changes on shared main
are retained. Production code and fuzzer corpus are unchanged. Exact
correction-SHA execution is **PENDING**.

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

## macOS listener-poll fixture readiness correction (2026-10-16; owner re-test pending)

The owner reports two remaining macOS full-CTest aborts after the direct native
accept fixture correction:
`transport.tcp-listener-poll-budget-handoff` and
`transport.tcp-listener-poll-deadline-denials`.

Source review found the same Darwin visibility assumption one layer higher:
both tests required a newly connected loopback peer to be consumed by an
immediate listener poll, including zero-wait probes. The production
`pollNonblockingTcpAcceptBatch` contract explicitly permits `NoEvent` when
that single bounded native wait sees no readiness; this is not a transport
failure.

The test-only correction adds one shared bounded caller helper that repeats the
existing production poll only after `NoEvent`, with at most
`kMaximumTcpPollWait` per call and a fixed 128-attempt ceiling. Any
`Expired`, `Failure` or completed batch is returned unchanged to the
behavior assertion. Production polling, accept ownership, deadlines and batch
semantics are unchanged. Exact-publication-SHA hosted validation and the
owner's unchanged-command macOS rerun are **PENDING**.

## R3 CAL signed-property exact-SHA CI blocker receipt (2026-10-17)

**Implementation:** `4cbe0168f9f0996d44d3f589ec6cafb335d62844`.  
**Actions:** `39009166683` — **FAIL before job creation; R3 tests NOT RUN**.

The exact implementation-SHA push created the standard CI workflow, but GitHub
rejected execution before any job existed. Inspection of the inherited parent
`7751e079a56e15034845ab61e4ad5e527204efc6` identifies an R9-only workflow
authoring defect: the CredSSP fuzzer step begins an unterminated
`fuzz_selection='^fuzz\.credssp-bounded` shell string and splices later job
definitions into that run block. R3 did not modify `.github/workflows/ci.yml`.

Therefore the new CAL fixture correction has **no exact-SHA compile, CTest or
sanitizer evidence yet**. The last executable R3 evidence remains Actions
`39008819773`: all six CAL registrations were selected, five passed under
ASan/UBSan, and only
`transport.licensing-client-cal-issuer-signature-denials` failed at the
provider-sensitive changed-signed-property fixture that this increment changes.

Do not treat the workflow parse failure as an R3 pass or failure. The next R3
gate is an unchanged-code descendant after R9 restores valid workflow syntax:
run all six CAL CTests under ASan/UBSan plus the full Linux/macOS/Windows
Debug/Release matrix. `CLIENT_LICENSE_INFO` remains non-authorizing and no
live licensing-success or Share transition is enabled.

## R3 CAL signed-property fixture portability correction (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `7751e079a56e15034845ab61e4ad5e527204efc6`.

Actions `39008819773` executes all six R3 client-CAL tests under the existing
R9 ASan/UBSan selector. Five pass; the remaining
`transport.licensing-client-cal-issuer-signature-denials` case aborts at the
changed-signed-property assertion because that synthetic leaf mutation does not
reliably yield `SignatureVerificationFailure` on Linux/OpenSSL.

The negative fixture now changes a duplicated leaf serial through
`X509_set_serialNumber()` with a separately owned `ASN1_INTEGER`, then
asserts direct `X509_verify()` failure before the chain reaches
`inspectRdpClientCalCertificateChain()`. This avoids direct mutation of
getter-owned ASN.1 storage and avoids changing issuer/subject path semantics
while still proving that modified signed contents are rejected.

Production CAL parsing, PKCS#7 grammar, signature-algorithm policy, explicit
trust-anchor matching, licensing-extension handling and the non-authorizing
`ClientLicenseInfoValidation` lifecycle are unchanged. The existing
behavior-named CTest remains the gate; no new production behavior is introduced.

Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN** in this
connector environment. Exact publication-SHA hosted Linux/GCC,
macOS/AppleClang, Windows/MSVC and R9 ASan/UBSan evidence is **PENDING**.

## R9 CredSSP fuzzer registry/framing hardening (2026-10-16; exact-SHA CI pending)

**Reconciled shared-main parent:** `2ad37e35e9c1109e2e5509a19025a6a7551030f2`.

The corrected fuzzer already has direct instrumented evidence at
`ec8f9df25f9986a2d51fb258f7798ac8596cfed3`, Actions `39008900352`:
the R9 Clang sanitizer build compiled and linked `fuzz_credssp`, and the
dedicated `fuzz.credssp-bounded` step completed **1/1 PASS** under
ASan/UBSan. The R9 job's failure was separately the R3
`transport.licensing-client-cal-issuer-signature-denials` case; it is not a
CredSSP/libFuzzer finding.

This increment closes two test-harness gaps without changing production code.
The dedicated fuzzer CI step now performs an exact `ctest -N` registry
preflight and requires `fuzz.credssp-bounded` before execution, so regex or
registration drift cannot report a zero-test green result. The fragmented
`TsRequestFrameReader` path now verifies terminal equivalence with the
whole-input drive: completed frames must match the consumed prefix, reparse,
release cleanly to `NeedMore`, and invalid fragmented prefixes must agree
with whole-input rejection. Explicit close must leave no frame or pending byte
requirement.

Current shared main also carries an unrelated R8 sanitizer-link blocker in the
Windows clipboard adapter (`renderFormatInternal(unsigned int)` undefined
while linking `test_windows_clipboard_adapter`). R9 does not modify or mask
that road. Exact publication-SHA execution of this new preflight/framing
hardening is **PENDING**. Canonical owner-local `~/rdp-server/build/`,
owner-platform runs, positive Kerberos/PAM/NSS/logind admission and real
Microsoft-client acceptance remain **NOT RUN / BLOCKED**.

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

## R8 Windows adapter render-helper restoration (2026-10-17; exact-SHA CI pending)

The first planned multi-file publication build exposed one R8-owned link error
on macOS: the Windows adapter refactor replaced the source range that previously
contained `WindowsClipboardAdapter::renderFormatInternal`. The declaration and
its existing callers remained, so the portable Windows adapter archive compiled
but macOS arm64 link failed for both Windows clipboard test executables.

This correction restores the original `renderFormatInternal` implementation
verbatim between the new completed-set publisher and `renderFormat`. There is
no delayed-rendering behavior change, no multi-file contract change and no
CTest registration change. Existing
`clipboard.windows-clipboard-*` behavior tests plus the Windows file-
destination executable provide the compile/link regression gate on every hosted
OS.

**Implementation being corrected:** `2e0f2814b8943fa8a83fccd97b7294a43f873b9f`.  
**First Actions run:** `39008936302` — macOS Debug compile/link **FAIL** before
CTest because `renderFormatInternal` was undefined.

Exact correction-SHA hosted validation is **PENDING**.

## R8 planned Windows/macOS completed-set publication (2026-10-17; exact-SHA CI pending)

**Starting reconciled shared `main`:** `ec8f9df25f9986a2d51fb258f7798ac8596cfed3`.

R8 now consumes the generation-pinned `RemoteFileDestinationPlan` in the
remaining Windows and macOS completed-file presentation paths. The new
`publishCompletedFileDestinations` APIs accept a bounded span of borrowed
completed destination objects plus the exact committed plan. Every member must
belong to the current `RemoteTransfer` generation, be complete, map to one
unique planned remote descriptor index and have a `CurrentFile` association.
Input order is ignored: native publication is rebuilt in exact remote descriptor
index order. Null entries, duplicate indices, duplicate local paths/URLs,
partial destinations, stale generations, cancelled plans and directory
associations fail before changing native ownership.

Windows encodes the set as one bounded CF_HDROP payload with
`DROPFILES.pFiles=20`, `fWide=TRUE`, one NUL-terminated caller-selected
absolute UTF-16 path per planned file and the final list NUL. Aggregate storage
is bounded by the existing 64-file descriptor limit and the existing per-path
32767-code-unit limit. The single-file API delegates through the same
collection/publication path.

macOS extends the synchronous native pasteboard seam from one borrowed file URL
to a bounded span of borrowed URL views. The AppKit bridge validates every URL
as a file URL, creates at most 64 NSURL objects and publishes them together with
one `writeObjects:` call. File sets cannot be mixed with text or PNG content.

Both adapters copy only bounded presentation metadata before the native call,
then re-collect and compare the exact set afterward. Reentrant cancellation of
the committed plan therefore rolls back the just-written native set rather than
allowing borrowed view aliasing to hide a same-generation mutation.

Dedicated production-backed CTests are
`clipboard.windows-completed-multi-file-hdrop-handoff` and
`clipboard.macos-completed-multi-file-url-handoff`. Each materializes two
same-name remote files sequentially through the real one-request-at-a-time
`RemoteTransfer` FileContents path, proves partial-set invisibility, supplies
the completed destinations in reverse order, verifies plan-index ordering and
atomic native publication, rejects duplicate destination membership, exercises
same-generation local takeover, and proves reentrant/terminal plan cancellation
cannot leave the native set published. R9's clipboard sanitizer preflight
enumerates both registrations.

No local path or URL is derived from FILEDESCRIPTORW metadata; callers still
supply the native destination capabilities and completed local handoff metadata.
Directory entries remain explicitly unsupported for materialization/publication,
so this increment adds no mkdir/openat/CreateFile-relative traversal or symlink
policy.

Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN** in this
connector environment; project policy forbids an alternate persistent checkout
or build root. Exact-SHA Linux/GCC, macOS/AppleClang, Windows/MSVC,
ASan/UBSan, documentation, SDK consumer and package evidence is **PENDING**.

**Next R8 after validation:** design the separately reviewed race-safe native
directory capability, relative-creation and symlink policy before any directory
materialization, then proceed to real-client file-copy acceptance.

## R9 CredSSP fuzzer compile-scope correction (2026-10-16; exact-SHA CI pending)

Static review after workflow recovery found two test-only source issues before
claiming executable evidence. The C-linkage libFuzzer entry point is outside the
anonymous namespace that imports the CredSSP symbols, so the production 16-KiB
limit is now explicitly namespace-qualified. The failure-token loop also binds
each `std::span` by const reference to stay warning-clean under strict
range-loop diagnostics. Fuzzer behavior, corpus, bounds and production code are
unchanged. The preceding workflow remains non-authoritative until the corrected
SHA executes.

## R9 CredSSP fuzzer workflow-generation correction (2026-10-16; exact-SHA CI pending)

The first fuzzing publication `8ad5f1285fa2e37b0ee19b2b04e74e42ec2d8c46`
created Actions run `39008662630`, which failed before job creation. No
compiler, CTest, ASan/UBSan or libFuzzer result exists for that SHA. The cause
was R9 CI authoring only: a JavaScript replacement string contained the
anchored CTest regex terminator `$'`, triggering suffix expansion and
splicing later workflow text into the inserted step.

This correction reconstructs the workflow from known-good parent
`d8e731ca488f1f8d545348b19a97756be660db46`, preserves the intervening R1
client-CAL selector escape fix from `035e2e8a702abef1304d2aea51e4de960d90fd5b`,
and reapplies the two intended R9 fuzzer edits using index-based insertion.
Production code, fuzzer source, seeds and CTest registration are unchanged.
Exact correction-SHA evidence is **PENDING**.

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

## R9 bounded CredSSP coverage-guided fuzzing (2026-10-16; exact-SHA CI pending)

R9 extends the existing opt-in Linux/Clang libFuzzer gate to the portable
CredSSP structural boundary. New target `fuzz_credssp` links
`rdp-server-protocol` and drives the production TSRequest parser, manual
fragment framer, credential classifier and delegated-account extractor on the
same bounded input. It enforces only documented invariants: deterministic
classification, no client-controlled TSRequest views after failure, bounded
token metadata, clean frame release, and zero rejected delegated-account
output.

The fuzz input ceiling is exactly the production 16 KiB TSRequest limit.
CTest uses 5,000 deterministic runs, a fixed seed, 512 MiB RSS / 64 MiB malloc
limits and a 30-second test watchdog. Checked-in non-secret seeds include one
canonical v6 negotiation TSRequest and one canonical password-credential DER
envelope. Mutable corpus and crash artifacts remain under the single CI
`build/` root. The existing MCS/CLIPRDR fuzzer is unchanged and executes in a
separate failure-isolated CI step.

This is structural memory-safety sampling only. It does not perform TLS, GSS,
PAM, NSS/logind authorization, native admission or Microsoft-client
interoperability. Canonical owner-local `~/rdp-server/build/` execution and
owner-platform/real-provider gates remain **NOT RUN** here. Exact publication
SHA hosted sanitizer evidence is **PENDING**.

## macOS native-accept fixture visibility correction (2026-10-16; owner re-test pending)

The owner reports five macOS full-CTest aborts in the native R1 loopback accept
family: `tcp-native-accept-ownership`, `tcp-native-accept-move-replacement`,
`tcp-native-accept-batch-budget-handoff`,
`tcp-native-accept-batch-stops-denials` and
`tcp-native-listener-role-and-mode-denials`. The reported output did not
include the exact pulled SHA, so that local failure is not assigned to an
invented commit.

Source review found one common test-harness race: these five cases still
assumed that synchronous loopback `connect()` completion made the listener's
next nonblocking `accept()` immediately observable. The same file already
contains a bounded one-shot wait helper and the testing standard explicitly
forbids that assumption. The fixtures now reuse that helper for direct accepts
and one new shared test-only batch helper that retries only zero-transfer
`WouldBlock`. Production `acceptNonblockingTcpConnection` and
`acceptNonblockingTcpBatch` remain retry-free, nonblocking and unchanged;
`Drained`, `BudgetReached`, `CallbackStopped` and hard failures retain
their exact semantics.

Starting shared main: `04d4e7c559012fa4e3636ac7f778d32445d3bc4d`. Canonical owner-local macOS rerun and
exact-publication-SHA hosted Linux/macOS/Windows plus sanitizer evidence are
**PENDING**. No R5 native X11 production source, protocol parser, admission
authority, listener runtime or desktop state is changed by this portability
repair.

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

## R8 bounded file-destination planning contract (2026-10-16; hosted evidence recorded)

**Starting reconciled shared `main`:** `541a9460a19f7cfca1c5c73fdb74cc1630e21772`.  
**Implementation:** `0d6621beac09ea35e7065f6119731242cae56d24`.  
**Lifecycle hardening / exact validation SHA:** `ecee09dd7bc5eb07293cae7101d354c72908795b`.  
**Actions:** `39006670277` — **overall FAILURE from cross-road gates; R8 evidence PASS**.

R8 now has a fixed-capacity, non-authorizing
`RemoteFileDestinationPlan` between retained FileGroupDescriptorW metadata
and the existing native file destinations. A complete plan maps every current
remote descriptor index to one nonzero caller selection identity, optionally
records an explicit caller-selected parent index, derives only the descriptor's
file/directory role, and commits atomically only after the full manifest is
valid. The representation is bounded to the existing 64 remote descriptors,
one active mapping per index, unique local selection identities and placement
depth 16. It owns no path, descriptor, HANDLE, file bytes, request scheduler or
clipboard publication state. The plan is explicitly non-copyable and
non-movable so a committed one-shot lifecycle cannot be duplicated before
retirement.

The hierarchy audit is deliberately fail-closed. MS-RDPECLIP
FileGroupDescriptorW can identify directories through `FD_ATTRIBUTES` plus
`FILE_ATTRIBUTE_DIRECTORY`; the filename field can describe path-bearing
names in protocol modes that allow them. The negotiated
`CB_FILECLIP_NO_FILE_PATHS` capability forbids source paths, and R8's existing
parser is stricter still: it retains only bounded safe UTF-16 leaf names and
rejects slash, backslash, drive-colon/path syntax, embedded-NUL tails and
malformed surrogate sequences. Consequently the retained descriptor list
contains no verified parent identity. A caller-supplied parent relation is only
local placement metadata and never proof of a remote tree. Directory entries
therefore report `UnsupportedDirectoryMaterialization`; no mkdir/openat,
CreateFile, symlink traversal or path synthesis is added.

A committed plan is pinned to the exact `RemoteTransfer` owner, its public
clipboard generation and a private monotonic accepted-offer epoch. The epoch
does not reset on disconnect, so a numeric generation reused after reconnect
cannot resurrect an old mapping. Source replacement, disconnect/reconnect,
cancellation or close makes the association unusable. Native materialization
still requires the independently supplied caller-opened descriptor/HANDLE
already consumed by `LinuxClipboardFileDestination`,
`WindowsClipboardFileDestination` or `MacClipboardFileDestination`; the
plan's numeric selection identity is explicitly not such a capability.

Dedicated production-backed CTests are
`clipboard.file-destination-plan-index-generation`,
`clipboard.file-destination-plan-directory-traversal-denials`,
`clipboard.file-destination-plan-transactional-commit`,
`clipboard.file-destination-plan-cancel-replay`, and
`clipboard.file-destination-plan-native-capability-integration`. Exact-SHA
macOS/AppleClang passed all five in **475/475 Debug** and **475/475 Release**.
Windows/MSVC passed all five in **505/505 Debug** and **505/505 Release**.
Both platform jobs also passed the installed-SDK consumer, package and digest
steps.

R9's exact-SHA Clang ASan/UBSan job compiled the production-linked clipboard
targets, enumerated all five names in registry preflight and passed the complete
clipboard-labelled selection **66/66**, including all five new R8 cases. That
job failed only afterward: the bounded R1/R3 step encountered a separate
zero-test preflight, and the R10 licensing-authority selection could not find
its test executable. Ubuntu/GCC likewise failed before CTest in the unrelated
R10 source `tests/test_runtime_licensing_authority.cpp:658` because
`-Werror=range-loop-construct` rejects a by-value structured binding. Thus
the hosted workflow is not reported as green, and R8's new tests did **NOT RUN**
in the Ubuntu full-matrix job. Documentation policy passed.

Canonical owner-local `~/rdp-server/build/` Debug/Release execution is
**NOT RUN** in this connector environment because the canonical checkout could
not be synchronized and project policy forbids an alternate persistent checkout
or build root. Live Finder/Explorer/Nautilus interoperability, authenticated
Microsoft-client file copy, owner-native M1 platforms and directory-tree
materialization remain **NOT RUN / OPEN**. This increment does not accept M1-M6.

**Next R8:** consume completed planned sets in bounded Windows multi-file
`CF_HDROP` and macOS multi-NSURL publication, then design a separately
reviewed race-safe native directory capability/symlink policy before any
directory creation.

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

## R7 current-display cursor publication validation (2026-10-16)

R7 implementation SHA `32f46276add9b387e71962376da4329537eff2d8` is published on shared `main`.
Exact-SHA Actions: https://github.com/k1moradi/RDP-server/actions/runs/39006013275. The dedicated
`r7-macos-session-sanitizers` job passed: ten desktop-session cases, the
input session-watch revocation case, and the fail-closed registry-preflighted
three-case cursor selection all passed under GCC ASan/UBSan. The cursor
selection was exactly
`macos.cursor-topology-publication-revocation`,
`macos.cursor-geometry-generation-publication-denials`, and
`macos.cursor-session-watch-revocation`. Documentation policy also passed.

The implementation-SHA full matrix exposed only concurrent cross-road
failures. Linux/GCC stopped in Debug compile at
`tests/test_runtime_licensing_authority.cpp:658` because
`-Werror=range-loop-construct` rejected an R10 copied structured binding.
macOS/AppleClang compiled Debug and ran 470 tests; all seven R7 cursor cases
passed, while the concurrent R3
`transport.licensing-client-cal-product-extension-denials` case asserted at
`tests/test_owned_mcs_connect_initial.cpp:7455`, so Release was skipped.
Windows/MSVC compiled Debug and ran 500 tests; all seven R7 cursor cases
passed, while that same R3 CAL case timed out after the same assertion, so
Release was skipped. The R9 sanitizer job separately failed a concurrent
R1/R3 CAL registry selector that selected zero tests and an R10
licensing-authority selection whose executable had not been built; its other
instrumented selections continued independently. These failures are not in
the R7 cursor code path.

Clean unchanged-R7 descendant `a7d724e3988e88f8bb3440b19f76e760b3870cf7` was then validated by
https://github.com/k1moradi/RDP-server/actions/runs/39006137656. Its R3 repair restored macOS to **470/470 Debug and
470/470 Release** and Windows to **500/500 Debug and 500/500 Release**; both
platforms also passed the installed downstream CMake consumer and package
digest path. The descendant R7 GCC ASan/UBSan job and documentation policy
passed again. Linux remained blocked before CTest by the same R10 line-658
warning, and R9 retained its independent registry/build-target failures.

This evidence is synthetic/offline cursor lifetime evidence. Owner macOS 27,
real TCC approval, native AppKit cursor sampling, real GUI-session switching,
R2/R3 authorized desktop admission, R4 pointer publication, and Microsoft
client interoperability are **NOT RUN / NOT ESTABLISHED** here. M1 and M5
therefore remain **OPEN / NOT ACCEPTED**.

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

## R7 current-display cursor publication fence (2026-10-16; exact-SHA CI pending)

**Starting shared main:** `3069b2f1e07198d0e060c1619924f9654ffb8826`.  
**Reconciled publication parent:** `c800ef3cacc59d3cc4bc442f5d3a1c88c01ac555`.

R7 cursor construction already pinned display generation/topology and the
process GUI-session watch, but later `MacCursorSnapshot::valid()` /
`pixels()` could not compare a preserved snapshot with the caller's current
`NativeDisplayGeometryRefresh`. An owned shape therefore remained inspectable
after a display-generation replacement as long as the GUI-session revision was
unchanged.

This increment adds synchronous, allocation-free `validFor(geometry)` and
`pixelsFor(geometry)` consumption checks. They require existing structural and
GUI-session validity, the exact nonzero saved generation to remain
`geometry.usable()`, an existing current topology revision equal to the saved
revision, and the visible snapshot's display identity to remain present. The
geometry owner is caller-supplied and never retained, so no stack-borrow can
dangle. Existing `valid()` / `pixels()` are documented as owned-storage
inspection only and are not a current-desktop publication gate. Geometry
freshness still grants no R2/R3 authorization and performs no R4 publication.

Dedicated portable CTests
`macos.cursor-topology-publication-revocation` and
`macos.cursor-geometry-generation-publication-denials` use the existing
synthetic display/session seams. They prove stale publication denial after a
real production topology revision, a same-bounds geometry refresh, explicit
geometry invalidation and a failed refresh; a later successful refresh never
resurrects an old snapshot, while a newly observed current-generation snapshot
succeeds. The existing cursor session-watch case remains the independent
GUI-session axis and now exercises the same checked consumption API. The R7
GCC ASan/UBSan job performs a fail-closed `ctest -N` registry check for all
three cursor revocation/publication cases before executing them.

Canonical owner-local `~/rdp-server/build/`, owner macOS 27/TCC/fast-user
switch testing and real Microsoft-client publication are **NOT RUN** in this
connector environment. Exact publication-SHA hosted Linux/GCC,
macOS/AppleClang, Windows/MSVC Debug/Release, R7 sanitizer,
documentation-policy, SDK/package/digest evidence are **PENDING**. M1 and M5
remain **OPEN / NOT ACCEPTED**; genuine R2/R3 macOS admission and R4 cursor
composition remain prerequisites.

## R3 existing-client CAL certificate-chain trust boundary (2026-10-16; exact-SHA CI pending)

## R10 service-owned licensing authority boundary (2026-10-17; hosted CI pending)

**Reconciled shared-main parent:** `fa5653d10390c84ef6a5cfa52fe2ebcb576fea20`.

R10's licensing-authority audit now distinguishes the standards-defined terminal
server from the actual CAL issuer. Microsoft
[MS-RDPELE 1.3.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/a229ac6a-0d37-448f-929f-8940f32254fd)
defines app-server terminal-server licensing as a client↔terminal-server
licensing exchange backed by a separate license server. The license server
manages and issues terminal-server CALs and the terminal server uses RPC to
request new CALs or upgrades; that terminal-server↔license-server exchange is
explicitly outside MS-RDPELE. Personal-terminal-server behavior is therefore
not an acceptable substitute for this project's app-server/authenticated
desktop model.

No authoritative, supportable Microsoft specification or platform API for a
portable Linux/Windows/macOS implementation of the RD Session Host→RD
Licensing Server CAL issuance/upgrade RPC contract has been established in the
available project environment. A genuine positive production provider would
also require an activated/registered RD Licensing server with applicable CAL
packs plus supported authentication/authorization of this server as an issuer
client. R10 therefore keeps production issuance **UNAVAILABLE** rather than
inventing an issuer protocol, signature, clearing-house registration flow or
CAL format.

The new noninstalled
`src/server/runtime/runtime_licensing_authority.{h,cpp}` owns the fail-closed
service boundary. Production can explicitly configure the immutable R3
product/company/product-id/scope policy as **NoVerifiedIssuer**, but no public
API can attach a positive provider. The ordinary `rdp-server` entry point
does not construct a provider, add configuration fields, bind a listener,
publish an R2 lease or expose an R3 grant.

An internal provider contract exists solely so the dedicated test executable
can exercise the future lifetime rules. Verified-provider configuration is
private and reachable only through a test friend. On that path R10:

- authenticates a bounded provider identity/trust snapshot before becoming
  ready;
- derives a SHA-256 authority fingerprint from a domain-separated canonical
  representation of provider identity, trust configuration, product version,
  company name, product ID and scope, deliberately excluding the unrelated
  terminal-server licensing RSA certificate;
- creates a nonzero 64-bit authority generation from OpenSSL private CSPRNG
  bytes rather than a small restart counter, and never increments it, so there
  is no generation wrap path;
- permits only one bounded outstanding request/result publication record;
- copies a CAL immediately from provider-owned memory and enforces R3's
  `kMaximumRdpServerLicenseGrantCalBytes` bound;
- binds release to one exact 32-byte request/session correlation and retains a
  digest of the released kind/CAL so a caller-fabricated grant with merely the
  current generation/fingerprint is insufficient;
- freshly re-verifies provider identity/trust before result release and before
  each future publication authorization check;
- requires explicit retirement after publication and makes revoke/destruction
  cancel pending work, close the provider exactly once, clear retained result
  eligibility and invalidate the generation/fingerprint.

Six centrally registered behavior CTests cover the boundary:

- `runtime.licensing-authority-unconfigured-denials`
- `runtime.licensing-authority-issuer-policy-correlation`
- `runtime.licensing-authority-generation-revocation`
- `runtime.licensing-authority-result-bounds-and-cancellation`
- `runtime.licensing-authority-sensitive-retirement`
- `runtime.licensing-authority-no-startup-bypass`

The last case executes the real non-listening `rdp-server` and delegates to
the established process oracle for normal startup refusal, wrong arguments and
every supported offline config/TLS/licensing/Linux-security preflight. The
test-only positive provider is never linked into that executable. R9's
sanitizer workflow selects these six cases with the separate flat prefix
`^runtime\.licensing-authority-` to avoid extending the historically
over-nested R1/R3 licensing expression.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is **NOT
RUN** in this connector environment; no alternate checkout or build root was
created. Exact-publication-SHA hosted Linux/GCC, macOS/AppleClang,
Windows/MSVC, R9 ASan/UBSan, documentation, SDK/package and artifact evidence
is **PENDING** and must not be claimed green until the workflow completes.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 remain **NOT
RUN**.

**Next R10:** keep live issuance/publication blocked until a genuine,
documented and supportable RD Licensing provider integration plus required
issuer infrastructure exists. Once it does, the adapter must replace the
test-only provider with real provider authentication/issuance while preserving
the owner generation/fingerprint/request-correlation contract. Live delivery
still additionally requires real positive R2 admission/reauthorization and the
sole R3 grant write gate through R1. M1 remains open on owner-native evidence;
M2 remains **BLOCKED / NOT ACCEPTED**.


The owner's first macOS execution of the mandated one-line command at
`bdcb68520c5339aa9866f2e7d5949cf6b5c9c056` is **CONFIGURE FAIL** before any
compile or CTest. The shell successfully entered `~/rdp-server`, while CMake
reported the same case-preserving checkout as
`/Users/keivanmoradi/RDP-server`; the local-path guard compared those strings
lexically and rejected the case-only alias.

The correction keeps both policy fences: local work must still resolve from
`~/rdp-server`, and the only build root is still `<checkout>/build`. Existing
filesystem paths are now resolved before comparison, with case-insensitive
spelling accepted on macOS/Windows only after the `~/rdp-server` candidate is
known to exist. Windows/MSYS2 additionally translates the shell `HOME` through
`cygpath -m` when available and also considers `USERPROFILE`; this avoids
assuming that MSYS2 `~` and the Windows profile directory are identical.

New CTest `project.local-checkout-path-comparison` locks exact,
case-insensitive and strict-case comparison behavior without creating another
build root. Hosted exact-SHA configure/build/full CTest and the owner's rerun of
the unchanged command are **PENDING**. Do not claim owner macOS or Windows
MSYS2 PASS until those reports arrive.


**Reconciled parent:** `3069b2f1e07198d0e060c1619924f9654ffb8826`. This increment keeps
`CLIENT_LICENSE_INFO` non-authorizing while adding independently testable CAL
chain groundwork.

The protocol audit separates two encodings that must not be conflated.
`CLIENT_LICENSE_INFO::LicenseInfo` is a `BB_DATA_BLOB` containing the opaque
`pbLicenseInfo` CAL previously issued by a license server. The published
MS-RDPELE example encodes that CAL as DER PKCS#7 `SignedData` carrying X.509
certificates. This is distinct from the little-endian
`X509_CERTIFICATE_CHAIN` framing used by the server's
`SERVER_CERTIFICATE`.

R3 now exposes synchronous `inspectRdpClientCalCertificateChain()` only. It
accepts at most 16 KiB total, at most 16 certificates and at most 8 KiB per
certificate; requires exact canonical DER consumption; supports the observed
degenerate PKCS#7 SignedData/data form; requires one unambiguous X.509 v3
root-to-leaf path; rejects duplicate/disconnected/ambiguous material; verifies
the self-issued root and every child signature; restricts keys to RSA and
signatures to SHA-1/RSA (the protocol OIW OID plus OpenSSL's PKCS#1 alias); and
requires the embedded root to match a separately supplied exact DER trust
anchor. No machine-global certificate store and no server TLS/licensing
key-exchange certificate is an implicit CAL authority.

The leaf is checked only for presence/cardinality of the five documented RDP
licensing OIDs (`.18.4`, `.18.2`, `.18.5`, `.18.6`, `.18.7`) and
unknown critical extensions. Their payload encodings remain deliberately
unparsed. Product/version correlation, CAL expiry/renewal semantics, CAL HWID
binding and permanent/temporary/upgrade classification therefore remain
unsupported and fail closed. A valid protected-message HWID MAC and a
cryptographically trusted synthetic chain are still insufficient to complete
licensing.

Dedicated production-linked CTests are:
`transport.licensing-client-cal-chain-structure`,
`transport.licensing-client-cal-issuer-signature-denials`,
`transport.licensing-client-cal-product-extension-denials`,
`transport.licensing-client-cal-expiry-hwid-denials`,
`transport.licensing-client-cal-no-premature-completion`, and
`transport.licensing-client-cal-terminal-retirement`. The existing R9
sanitizer job selects this family with its own flat fail-closed prefix selector
rather than extending the parenthesis-heavy cross-road regex.

No `STATUS_VALID_CLIENT`, Upgrade License publication, Share activation,
R2 lease construction or live grant bypass is added. Exact hosted
Linux/macOS/Windows Debug/Release and ASan/UBSan evidence is pending this
publication. M1 and M2 remain open.

## R9 delegated-account failure-output audit (2026-10-16; exact-SHA validated)

**Correction:** `3069b2f1e07198d0e060c1619924f9654ffb8826`.  
**Actions:** `39005416459` — **SUCCESS**.

Hosted Linux/GCC completed **538/538 PASS** in Debug and Release; macOS/AppleClang
completed **456/456 PASS** in Debug and Release; Windows/MSVC completed the native
preflight **51/51 PASS** in both configurations and the full suite **486/486 PASS**
in Debug and Release. The corrected adversarial behavior is test #255 on Linux,
#240 on macOS/Windows and passes in every full suite. Installed SDK consumers,
package creation, reproducible digests/artifact upload, documentation policy and
the independent R7 sanitizer job also pass.

R9 Clang ASan/UBSan explicitly preflights and executes the portable delegated
account selection **5/5 PASS**, including
`security.credssp-delegated-account-adversarial-boundaries` as item 4/5. The
same job keeps the original password-credential structural corpus separate and
green at **4/4 PASS**, and the native GSS selection is **30/30 PASS** including
`security.gssapi-credssp-delegated-account-origin-denials`. The PAM denial-only
selection remains **1/1 PASS**. No parser test or sanitizer result is being used
as positive authentication evidence.

R9 independently reviewed R2's newly landed delegated-account extraction
boundary. The account result is intentionally an owning, non-secret local
identity candidate, while password bytes remain inside the GSS plaintext
lifetime and final CredSSP remains terminal deny-only.

The audit found one fail-closed output-hygiene defect: an invalid UNIX account
whose prefix was syntactically valid (for example `alice.name`) could return
`InvalidUnixAccount` with that rejected prefix still present in the public
fixed `account[]` result buffer even though `accountLength==0` and
`accountName()` was empty. This is not password disclosure, but a failed
parse must not publish a partial rejected identity. The smallest R2 boundary
correction now clears the account array and length on every failed account
conversion.

New production-backed CTest
`security.credssp-delegated-account-adversarial-boundaries` stays in the
existing `test_owned_credssp_tsrequest` executable. It runs a deterministic
640-case ASCII/non-ASCII code-unit mutation corpus against the real
`inspectCredSspDelegatedAccount`, uses a compact independent account-syntax
oracle, verifies repeated results and immutable caller input, proves successful
results own their account bytes after input retirement, checks 32/33-character
bounds and explicit rejected-prefix forms, and requires every failed result to
contain no residual candidate bytes. Password mutation remains syntax-only and
does not imply authentication.

The R9 sanitizer job's existing delegated-account group preflights this
registration explicitly and executes it under ASan/UBSan with leak detection
and without the MIT-krb5 suppression. No PAM invocation, completion latch,
native admission lease, listener or R3 state is enabled. Canonical owner-local
`~/rdp-server/build/`, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27, positive Kerberos/PAM/NSS/logind admission and real Microsoft-client
acceptance remain **NOT RUN / BLOCKED**.

## R2 delegated-account binding hosted validation receipt (2026-10-16)

Implementation SHA `a4315bf38144ff390ae5ef12170d645c5458bb0b`,
Actions run `39005097892`: **SUCCESS**. Linux/GCC, macOS/AppleClang and
Windows/MSVC each passed Debug and Release build/test, SDK downstream consumer,
packaging and digest verification. Documentation policy passed.

The R9 Clang ASan/UBSan job compiled the production-linked R2 targets and
successfully executed both the portable delegated-account selector (including
extraction, domain ambiguity, sensitive retirement and candidate policy binding)
and the native GSS selector containing
`security.gssapi-credssp-delegated-account-origin-denials`. The existing PAM
denial-only sanitizer step also passed. This evidence does **not** convert PAM
denial coverage into positive authentication authority.

Canonical owner-local `~/rdp-server/build/`, opt-in positive Kerberos/PAM,
NSS/logind foreground-owner admission and authenticated Microsoft-client
acceptance remain **NOT RUN / BLOCKED**. The private final-credential latch
remains false, no native admission lease is issued, and R3 remains unopened by
this increment.

## Cross-platform owner-command checkout-path correction (2026-10-16; owner re-test pending)

The owner's first macOS execution of the mandated one-line command at
`bdcb68520c5339aa9866f2e7d5949cf6b5c9c056` is **CONFIGURE FAIL** before any
compile or CTest. The shell successfully entered `~/rdp-server`, while CMake
reported the same case-preserving checkout as
`/Users/keivanmoradi/RDP-server`; the local-path guard compared those strings
lexically and rejected the case-only alias.

The correction keeps both policy fences: local work must still resolve from
`~/rdp-server`, and the only build root is still `<checkout>/build`. Existing
filesystem paths are now resolved before comparison, with case-insensitive
spelling accepted on macOS/Windows only after the `~/rdp-server` candidate is
known to exist. Windows/MSYS2 additionally translates the shell `HOME` through
`cygpath -m` when available and also considers `USERPROFILE`; this avoids
assuming that MSYS2 `~` and the Windows profile directory are identical.

New CTest `project.local-checkout-path-comparison` locks exact,
case-insensitive and strict-case comparison behavior without creating another
build root. Hosted exact-SHA configure/build/full CTest and the owner's rerun of
the unchanged command are **PENDING**. Do not claim owner macOS or Windows
MSYS2 PASS until those reports arrive.

## R1 terminal TLS/EOF readiness exact-SHA validation (2026-10-16)

**Implementation:** \`9b8f6092e4a0265688ec3bbf51b10cd34db8746e\`.  
**Win32 fixture correction:** \`cd3b5173149f4c93fad5c04afdab3bce3b901937\`.  
**Corrected Actions:** \`39004697959\` — **SUCCESS**.

The implementation publication replaced scheduler-yield terminal-read retries
with a dedicated real-loopback behavior,
\`transport.tcp-owned-tls-terminal-readiness\`, while leaving production R1
socket/BIO/SSL code unchanged. Its first Actions run \`39004463035\` provided
partial evidence only: macOS/AppleClang passed the new case as test #164 in
both configurations and full suites were **446/446 PASS** Debug + Release.
Linux/GCC and R9 stopped before R1 execution on the concurrently inherited R8
X11 clipboard compile error (\`fileUri_\` / \`fileUriLength_\`), and
Windows/MSVC exposed the R1 test-only Win32 \`min\` macro collision at the
client-readiness helper. Those failed legs are not counted as R1 PASS.

Correction \`cd3b5173...\` replaces only the macro-sensitive \`std::min\`
expression with an equivalent explicit duration comparison. Exact corrected
hosted evidence:

- Linux/GCC full CTest: **528/528 PASS Debug** and **528/528 PASS Release**;
  the new test is #164 and passes in both.
- macOS/AppleClang: **447/447 PASS Debug** and **447/447 PASS Release**;
  the new test is #164 and passes in both.
- Windows/MSVC native preflight: **51/51 PASS Debug + Release**; full CTest:
  **477/477 PASS Debug** and **477/477 PASS Release**; the new test is #164
  and passes in both.
- R9 Clang ASan/UBSan bounded R1/R3 MCS/CredSSP/licensing selection:
  **91/91 PASS**; \`transport.tcp-owned-tls-terminal-readiness\` executes as
  item **76/91** and passes. The separately flattened CredSSP credential corpus
  is **4/4 PASS**.
- Other sanitizer groups also pass: clipboard **61/61**, portable graphics
  **34/34**, x264/BGRA **20/20**, RDPGFX capabilities **4/4**, native
  R2/R3 GSS **29/29**, R2 PAM verifier **1/1**, direct Linux runtime security
  **10/10**, native X11 **33/33**, and bounded fuzzer **1/1**.
- Documentation policy and the independent R7 sanitizer job pass. Installed
  SDK consumer **1/1**, package generation and artifact upload pass on all
  three hosted platforms; untagged prerelease publication is correctly
  **SKIPPED**.

The new behavior proves two terminal distinctions through real nonblocking
readiness: client \`close_notify\` becomes R1 \`TlsClosed\`, while raw peer EOF
becomes \`TransportClosed\`; both leave the sole R1 owner inactive with closed
I/O interest, and later raw-EOF read replay remains terminal. Client OpenSSL
WANT direction is waited with a bounded native readiness fixture and the
server advances only through \`OwnedPreauthTcpConnection::pollSocketOnce\`;
no scheduler sleep/yield or hidden SSL retry is used in the behavior.

Canonical owner-local \`~/rdp-server/build/\`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23 and macOS 27 remain **NOT RUN** in this connector
environment. This is transport-lifetime evidence only: no R2 admission,
licensing authority, live grant publication, Share activation or client
acceptance is implied.

**Next R1:** retain the existing dependency gate. Do not add another
transport/publication surface until R10 supplies a real CAL-issuing authority
and R2 exposes fresh authorization for live grant slices/completion, or a later
Share-activation boundary demonstrates a concrete bounded R1 transport
mismatch.

## R2 authenticated delegated-account binding boundary (2026-10-16)

R2 now has the next fail-closed final-CredSSP identity boundary. The canonical
password-credential parser can derive only one bounded 32-byte local UNIX
account candidate from `TSPasswordCreds.userName`; it still exports no password
or borrowed field view. The supported form requires an empty `domainName`.
Nonempty domains, `DOMAIN\\user`, realm suffixes, Unicode/confusable account
names, uppercase/case rewriting, `root`, overlength names and unsupported
credential types are denied rather than normalized.

`ConsoleIdentityPolicy::matchPrincipalAccountCandidate()` is a read-only
`CandidateOnly` query over the service-owned mapping. It requires the exact
provider-derived Kerberos principal, exact local account and the nonzero policy
generation captured when the per-connection GSS owner is configured. A changed
generation, missing rule, mismatch, service principal, or principal with
multiple configured local accounts denies. It performs no NSS/logind lookup and
cannot issue a native lease.

The live final-authInfo path now requires the original R1-owned HYBRID
connection, exact reader/writer, delivered server binding reply, pinned TLS
certificate, live GSS context/principal and unchanged bound policy generation
before it will unwrap credentials. Candidate extraction and policy matching
occur synchronously while provider plaintext is protected by
`SensitiveBytesGuard`; the plaintext is cleansed before provider-buffer
release. The candidate is not persisted. This increment remains terminal
deny-only: PAM is **not invoked**, the private final-credential completion latch
remains false, no `LinuxConsoleAdmissionLease` is issued and R3 is not opened.

Dedicated coverage is
`security.credssp-delegated-account-extraction`,
`security.credssp-delegated-domain-identity-denials`,
`security.console-policy-delegated-account-binding`,
`security.gssapi-credssp-delegated-account-origin-denials`, and
`security.credssp-delegated-account-sensitive-retirement`. Portable
credential/policy cases are included in bounded ASan/UBSan without the
MIT-krb5 LSan suppression; the origin case is in the native GSS selection.
Hosted exact-SHA validation for this publication is pending. Positive
Kerberos/PAM/NSS/logind/Microsoft-client acceptance and M2 remain
**BLOCKED / NOT RUN**.

## R9 final CredSSP adversarial-parser hosted convergence (2026-10-16)

**Validated shared integration SHA:** `bdcb68520c5339aa9866f2e7d5949cf6b5c9c056`.  
**Actions:** `39004774467` — **SUCCESS**.

The three new production-backed R9 CTests are centrally registered once and
execute through the existing `test_owned_credssp_tsrequest` binary:

- `security.credssp-password-credential-nested-der-mutations`
- `security.credssp-password-credential-length-boundary-denials`
- `security.credssp-password-credential-utf16-mutation-boundaries`

Linux/GCC Debug and Release are **528/528 PASS** in each configuration.
macOS/AppleClang Debug and Release run **447** tests each and both jobs pass.
Windows/MSVC Debug and Release run **477** tests each and both jobs pass.
Installed SDK consumer/package checks pass on all three hosted platforms.
The R9 Clang ASan/UBSan job passes; its fail-closed registry preflight finds
strict-fields plus all three new cases and the dedicated instrumented
credential selection is **4/4 PASS** with leak detection enabled and no GSS
leak suppression applied to parser tests.

The bounded corpora remain test-only: a 59-byte canonical password seed with
236 bytewise mutations plus 8 structured cases; a 40-vector DER/length corpus
including 9 outer and 9 nested malformed encodings and the valid 8191-byte
maximum; and a 96-vector UTF-16LE matrix with an independent test-only Unicode
oracle. Repeated parsing is deterministic and input bytes remain unchanged.
A structure-preserving payload mutation may still parse successfully only when
the independent payload oracle accepts it.

Historical failures remain part of the evidence trail. At
`d82e9836b5457f43293ca46bc3c712c0565e1188`, workflow `39004093895`
failed the R9 combined sanitizer selection before execution because CMake
reported `Too many parentheses` and `Total Tests: 0`; R9 corrected that by
keeping the existing cross-road selection intact and adding a flat dedicated
credential selector. At `da9d3e21c4c684d553e20a4d2594f2911cdabe00`,
workflow `39004533589` had the R9 sanitizer, Linux and macOS jobs green but
failed Windows `Compile Debug` in the R1 readiness fixture because Win32's
`min` macro expanded `std::min`; R1 corrected that in
`cd3b5173149f4c93fad5c04afdab3bce3b901937`. The final convergence workflow
is green and R9 was not implicated in that R1 compile failure.

These tests establish bounded structural parsing and memory-safety evidence;
they do **not** establish successful password verification or native admission.
Existing GSS/native-admission denial tests remain the authentication boundary.
Owner same-SHA Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27, genuine
Kerberos/PAM/NSS/logind positive authorization, Microsoft-client end-to-end
HYBRID admission and M1-M6 external acceptance remain **NOT RUN / BLOCKED** as
applicable.

## R7 cursor GUI-session revocation exact-SHA validation (2026-10-16)

**Implementation:** `1d4f154bd548b11dcf95ac671ecdd3e4d5a5d288`.  
**Implementation Actions:** `39004615992`.  
**Validated clean descendant:** `cd3b5173149f4c93fad5c04afdab3bce3b901937`.  
**Validation Actions:** `39004697959` — **SUCCESS**.

The implementation SHA's dedicated R7 GCC ASan/UBSan job passed all 10
`macos.desktop-session-*` cases, the exact input session-watch case **1/1**,
and the new `macos.cursor-session-watch-revocation` case **1/1**. Its
macOS Debug run also passed all five cursor cases, including the new case, but
the overall implementation workflow was not accepted because an immediately
preceding R1 test failed `transport.tcp-native-accept-batch-budget-handoff` on
macOS and hit a Win32 `min` macro compile error on Windows. Those failures were
outside R7; R1 corrected the test-only portability issue in the next descendant.

At clean descendant `cd3b5173...`, whose only intervening change is R1 test
code/docs, the unchanged R7 implementation passes the complete hosted matrix:
macOS/AppleClang **447/447 Debug** and **447/447 Release**; Linux/GCC
**528/528 Debug** and **528/528 Release**; Windows/MSVC native preflight
**51/51 Debug + Release** and full **477/477 Debug + Release**. The cursor
session-watch case passes in every applicable full suite (#375 macOS, #432
Linux, #421 Windows). The dedicated R7 GCC ASan/UBSan job again passes
**10/10 + 1/1 input + 1/1 cursor**. The broader R9 Clang ASan/UBSan job,
documentation policy, installed SDK consumer, package, digest and artifact
stages all pass. Untagged prerelease publication is skipped as intended.

This validates only synthetic production-backed revocation semantics and Apple
compile/link of the quarantined native sampler. Canonical owner-local
`~/rdp-server/build/`, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and
macOS 27 remain **NOT RUN** here. Genuine macOS 27 fast-user-switch delivery,
TCC/native cursor/capture/input and Microsoft-client M5 remain **NOT RUN**.
The next authority-bearing R7 gate remains **BLOCKED** on a genuine
non-forgeable R2/R3 macOS desktop admission capability; no watch revision,
geometry fact or synthetic test callback is admission. **M5 remains OPEN / NOT
ACCEPTED.**

## R8 bounded multi-file X11 handoff exact-SHA validation (2026-10-16)

**Implementation/fix:** `013b834eaab7b863d1257d8e4730677260746581` +
`7318bb23fbcde4f9051f08eec06ff8c6b9a218ba`.
**Actions:** [39004494523](https://github.com/k1moradi/RDP-server/actions/runs/39004494523).

The first implementation run exposed one R8-owned Linux compile error from a
stale single-file cleanup field in `disconnect()`; the follow-up fix reuses
the canonical `clearFileHandoff()` path. At the fixed SHA, Linux/GCC full
CTest is **527/527 PASS** in Debug and **527/527 PASS** in Release. The new
`clipboard.x11-completed-multi-file-uri-handoff` case passes in both. The
installed SDK consumer is **1/1 PASS**, and Linux package/artifact steps pass.

R9 Clang ASan/UBSan completes successfully. The complete clipboard-labelled
selection is **61/61 PASS**, including the new multi-file case. Its additional
selected groups are also green: portable RDPGFX **34/34**, x264/BGRA **20/20**,
RDPGFX capabilities **4/4**, bounded R1/R3 transport/security **91/91**,
runtime security **4/4**, native GSS/R2/R3 **29/29**, direct runtime-security
**10/10**, native X11 **33/33**, and bounded fuzzer **1/1**.

macOS/AppleClang full CTest is **446/446 PASS** in Debug and Release with its
downstream consumer/package gates green. The Linux-only X11 multi-file target
is not registered there. Windows focused native preflight is **51/51 PASS**,
but full Windows Debug compilation stops in unrelated R1
`tests/test_owned_preauth_session.cpp:1541` with MSVC C2589 before ordinary
full CTest; Windows Release/package are therefore **NOT RUN** in this workflow.
No R8 source appears in that failing diagnostic. A descendant R1 commit later
addresses that Windows fixture boundary; it is not an R8 ownership change.
Documentation policy and the independent R7 macOS sanitizer job pass.

Accordingly, the R8 multi-file X11 boundary has exact-SHA Linux Debug/Release
and ASan/UBSan evidence, plus unaffected macOS regression evidence. The overall
workflow conclusion is **FAIL** solely because of the unrelated R1 Windows
compile blocker; do not reinterpret that as Windows or real-client acceptance
for this Linux-only increment.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows
MSYS2 CLANG64/Clang23, macOS27, live Nautilus/Dolphin/Wayland portal use,
authenticated Microsoft-client file copy, remote directory-tree mapping and
performance remain **NOT RUN/OPEN**.

**Next R8:** define a bounded explicit directory-tree mapping/capability
contract that never constructs local paths from untrusted remote names, then
extend completed-set handoff to Windows/macOS and real-client acceptance.

## R1 terminal-readiness Win32 macro correction (2026-10-16; exact-SHA CI pending)

**Implementation:** \`9b8f6092e4a0265688ec3bbf51b10cd34db8746e\`.  
**Implementation Actions:** \`39004463035\`.  
**Correction base:** \`1d4f154bd548b11dcf95ac671ecdd3e4d5a5d288\`.

The new \`transport.tcp-owned-tls-terminal-readiness\` behavior compiled and
passed on macOS/AppleClang as test #164 in both Debug and Release
(**446/446 PASS** each). The implementation-SHA Linux and R9 jobs stopped
before R1 execution on the inherited R8 X11 clipboard compile error
(\`fileUri_\` / \`fileUriLength_\` after the multi-file member replacement);
R8 corrected that independently in \`7318bb23fbcde4f9051f08eec06ff8c6b9a218ba\`.

Windows/MSVC exposed an R1 test-only portability bug: the new bounded
client-readiness helper used \`std::min(remaining, maximumWait)\`, but a Win32
\`min\` macro had already been introduced before this translation unit's later
\`NOMINMAX\` guard, producing C2589 at the helper call. The correction replaces
that expression with an explicit duration comparison/ternary. It changes no
deadline, readiness direction, socket behavior, production source or R1
ownership contract.

The corrected descendant must pass the new CTest on Linux/GCC,
macOS/AppleClang and Windows/MSVC Debug/Release and under the bounded R9
R1/R3 sanitizer selection before this increment is accepted. Canonical
owner-local \`~/rdp-server/build/\` and owner-platform evidence remain
**NOT RUN**.

## R7 cursor GUI-session revocation fence (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `00b0aa8a3c58fd6866a3574f85e7d85c74ad9cd5`.

R7's capture and input consumers already pin the process-scoped
`NativeSessionChangeWatch` revision, but the quarantined cursor snapshot
boundary still used only display generation/topology. A fast-user switch can
leave display geometry unchanged, so an old owned cursor shape could otherwise
remain structurally valid across GUI-session replacement.

This increment makes the watch revision part of `MacCursorSnapshot` identity.
The native private sampler pins active coverage before its first cursor read;
`makeMacCursorSnapshot` requires that caller-pinned revision and revalidates it
before publication. Existing snapshots fail `valid()` and expose an empty
`pixels()` span after a later session event. A revision is revocation state
only: the AppKit sampler stays translation-unit-private and no R2/R3 admission,
R4 scheduler/protocol publication, TCC prompt, event tap or input capability is
created.

Dedicated portable CTest `macos.cursor-session-watch-revocation` keeps geometry
and topology unchanged, constructs an owned shape, injects a switch-away/back,
proves the old shape becomes unreadable and rejects reconstruction with the old
revision. The road-local GCC ASan/UBSan job now builds the existing cursor test
executable and selects this exact case in addition to guard/input coverage.
Ordinary tests install only synthetic callbacks and never read AppKit cursor
state.

Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN** in this
connector environment; no alternate persistent build root is created.
Exact-publication-SHA hosted Debug/Release, R7 sanitizer, documentation-policy
and SDK/package evidence are **PENDING**. The next authority-bearing R7 gate is
unchanged and remains **BLOCKED** on genuine non-forgeable R2/R3 macOS desktop
admission, followed by owner macOS 27 fast-user-switch/TCC/native testing and
Microsoft-client M5 acceptance. **M5 remains OPEN / NOT ACCEPTED.**

## R5 XI2 stale-motion generation fence exact-SHA hosted validation (2026-10-16)

**Implementation:** `366303f35156cdd00c125dfa976d72bc23016bb3`.  
**Optional-build guard correction / validated SHA:** `2cdb16e42e1b642fcfb02c0a34f581b53e202598`.  
**Actions:** `39004283125` — workflow overall **FAIL** only because the
separate bounded R1/R3 MCS/CredSSP/licensing sanitizer selector is rejected by
CTest with `RegularExpression::compile(): Too many parentheses`. The later R5
native-X11 sanitizer step executes independently and is fully green.

Exact validated evidence:
- **Linux/GCC:** **525/525 PASS** in Debug and **525/525 PASS** in Release.
  `x11.desktop-resource-pointer-randr-stale-motion-isolation` is test #471
  and passes in **0.04 s** in both configurations. Installed SDK consumer
  **1/1 PASS**, package generation, digest and artifact upload pass.
- **macOS/AppleClang:** **445/445 PASS** in Debug and **445/445 PASS** in
  Release. Installed SDK consumer **1/1 PASS**, package/digest/upload pass.
  Native X11 execution is intentionally absent on this host.
- **Windows/MSVC:** focused native preflight **51/51 PASS** in Debug and
  **51/51 PASS** in Release; full CTest **475/475 PASS** in Debug and
  **475/475 PASS** in Release. Installed SDK consumer **1/1 PASS** and
  package/digest/upload pass. Native X11 execution is intentionally absent.
- **R9 Clang ASan/UBSan native X11:** the fail-closed selector discovers
  exactly **33** R5 behaviors and completes **33/33 PASS**. The new stale-motion
  case is selected as **32/33** (central test #471) and passes in **0.04 s**.
  No ASan/UBSan finding is reported in the R5 selection.
- **Documentation policy:** PASS. The independent R7 sanitizer job also passes.
  Untagged prerelease publication is skipped as intended.

The validated native sequence is one-XCB-owner only. A helper completes a real
Xvfb RandR resize from **1280x720 to 1024x600** and then warps the root pointer
before the production aggregate consumes the queued transition. R5 rebuilds its
geometry-bound children on the same XCB connection, consumes only the new
tracker's synchronous `QueryPointer` snapshot, rejects the queued pre-generation
XI2 motion using the `XISelectEvents` request-sequence floor, then accepts a
fresh post-rebuild motion normally.

The optional-build correction is also part of the validated SHA: the new
aggregate behavior is compiled only when `RDP_TEST_XINPUT_POINTER` is present,
matching its registration and preserving supported Linux builds where optional
`xcb-xinput` development support is unavailable.

Canonical owner-local `~/rdp-server/build/` testing remains **NOT RUN** in
this connector environment; no alternate persistent build root was created.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 M1 evidence,
genuine R2/R3-admitted XTEST operation and Microsoft-client M3 acceptance remain
**NOT RUN / OPEN**. Current source still exposes no R3 authenticated,
already-decoded bounded Share/Input or Fast-Path Input handoff, so functional
R5 input translation remains **BLOCKED ON R3**; R5 does not add a competing
RDP parser, authorization token, session owner or scheduler.

## R9 CredSSP adversarial-corpus oracle refinement (2026-10-16; exact-SHA CI pending)

The three production-backed credential tests now carry explicit bounded corpus
oracles rather than relying on production acceptance as their own expectation.
The canonical password seed is exactly 59 bytes; its nested-DER test performs
236 bytewise complement/insertion/removal/truncation cases plus 8 explicit
structured field/tag/trailing cases. Any successful one-byte mutation must lie
inside one of the known unchanged-length text payloads and independently pass
the small test-only UTF-16LE oracle.

The length test contains exactly 40 parsed vectors: the required small and DER
transition sizes, 4094..4097 field boundaries, 9 malformed outer length
encodings, 9 malformed nested length encodings (including nonminimal,
leading-zero, indefinite, truncated/excessive length-of-length, unavailable
declared length, and inflation/deflation), the largest representable valid
8191-byte credential, an exactly-8192-byte trailing-data denial, and an
8193-byte over-limit denial. The near-cap fixture is found by a bounded
descending scan and never allocates from hostile declared lengths.

The Unicode test contains exactly 96 vectors across domain, username and
password and beginning/middle/end positions. A separate test-only oracle checks
BMP characters, valid surrogate pairs, malformed high/low ordering, embedded
NUL, pair truncation, odd byte counts and permitted/forbidden empty fields.
This remains structural evidence only; existing
`security.gssapi-credssp-authinfo-terminal-denials`,
`security.gssapi-native-os-admission-capability-denials`, and
`runtime.linux-connection-aggregate-premature-admission-denial` retain the
independent no-native-admission boundary. Exact hosted and sanitizer evidence
for this refinement is **PENDING**.

## R8 multi-file X11 disconnect compile repair (2026-10-16; exact-SHA CI pending)

Implementation `013b834eaab7b863d1257d8e4730677260746581` reached hosted CI
Actions `39004341947`. Linux/GCC Debug failed during
`rdp-server-linux-x11-clipboard` compilation because the final
`disconnect()` cleanup still named the pre-multi-file fields
`fileUri_`/`fileUriLength_`. The production multi-file state itself had
already replaced those fields with the canonical list owner. macOS compiled
successfully because the X11 target is Linux-only.

This follow-up removes the stale duplicate cleanup and reuses
`clearFileHandoff()`, which already clears the canonical URI list, file count,
generation and file-offered state. No protocol, ownership, native-format or
test semantics change. The original exact-SHA run is **FAIL** for Linux compile
and cannot validate this R8 increment; descendant exact-SHA hosted CI is
required.

## R1 owned-TLS terminal close readiness hardening (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared \`main\`:** \`c1112051ed5a81db34bdfc4cf8193e9bc114cdb5\`.

R1's real loopback application-I/O cancellation coverage still had two
scheduler-\`yield()\` retry loops after TLS establishment: one while producing
a client \`close_notify\`, and one while waiting for the server to observe
clean TLS closure/raw TCP EOF. That timing pattern is unnecessary now that R1
has the bounded one-step socket poller used by the rest of the owned-TLS
readiness fixtures.

New dedicated CTest
\`transport.tcp-owned-tls-terminal-readiness\` stays in the existing
\`test_owned_preauth_session\` executable. It uses a short-lived ephemeral
loopback TCP connection and real OpenSSL TLS. The client side waits only for
the exact WANT_READ/WANT_WRITE direction through a bounded native \`select\`
fixture with a five-second monotonic deadline. The server side advances only
through \`OwnedPreauthTcpConnection::pollSocketOnce\` and explicitly resubmits
the same caller-owned read span. Clean \`close_notify\` must produce
\`TlsClosed\`; raw peer close must produce \`TransportClosed\`; both must leave
R1 inactive with \`Closed\` I/O interest, and raw EOF replay remains terminal.

The existing \`transport.tcp-owned-tls-application-cancellation\` behavior now
retains the independent deadline-cancellation and malformed-record
\`FatalTlsFailure\` cases. No production socket/BIO/SSL code, application-I/O
bound, retry policy, authorization state, licensing lifecycle or listener
surface changes. The bounded R9 R1/R3 sanitizer selector explicitly requires
the new test.

Canonical owner-local \`~/rdp-server/build/\` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent build root
or branch is created. Exact publication-SHA Linux/GCC, macOS/AppleClang,
Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and SDK/package
evidence are **PENDING**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27 and real-client acceptance remain **NOT RUN**.

**Next R1:** this closes test-harness nondeterminism only. Do not add another
transport/publication surface until R10 supplies a real CAL-issuing authority
and R2 exposes fresh live grant authorization, or a later Share-activation
boundary demonstrates a concrete bounded R1 transport mismatch.

## R9 CredSSP sanitizer selector split (2026-10-16; exact-SHA CI pending)

The first adversarial credential-corpus sanitizer publication exposed a CI
selection limit rather than a parser defect: the pre-existing combined
R1/R3/licensing CTest regular expression exceeded CMake's regex parenthesis
budget after R9 added three nested alternatives. The job failed closed with
`RegularExpression::compile(): Too many parentheses` and `Total Tests: 0`.
Ordinary hosted Linux/macOS builds for the corrected test source were green,
so this incident is test-registration/execution infrastructure, owned by R9.

The existing cross-road selector is restored to its prior R2 strict-fields
shape. The same ASan/UBSan step now uses a second flat
`^security\.credssp-password-credential-` selector, performs an explicit
`ctest -N` registry preflight for strict-fields plus all three new R9 cases,
and executes that bounded group with leak detection enabled and no GSS leak
suppression. No R1/R3/R4/R5/R8/R10 selection is removed. Exact correction-SHA
hosted validation is **PENDING**; owner-local and real-provider/client gates
remain **NOT RUN**.

## R8 bounded multi-file X11 handoff (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `2cdb16e42e1b642fcfb02c0a34f581b53e202598`. The existing R8 Linux
descriptor materializer and completed-file X11 URI handoff remain the native
building blocks. This increment extends only the completed presentation set:
up to the existing 64 remote-file bound may be published atomically after each
caller-selected destination independently reaches `Complete`.

`X11ClipboardAdapter::publishCompletedFiles` accepts a span of completed
`LinuxClipboardFileDestination` proofs. Every member must be non-null,
complete, from the exact current synchronized `RemoteTransfer` generation,
and expose a caller-bound strict local `file:///` URI. Duplicate URIs are
rejected. The adapter copies only bounded URI metadata into one fixed
allocation-free canonical LF-separated buffer; it never copies file bodies,
opens paths or derives a local path from FILEDESCRIPTORW.

The aggregate canonical URI metadata is capped below 64 KiB so the derived
`text/uri-list` payload (CRLF after every URI) remains within one direct X11
property write. GNOME/Nautilus receives `copy\n<uri1>\n<uri2>...` without a
trailing empty URI; KDE's copy marker remains `0`. The existing single-file
API delegates to the multi-file path. Once one completed set owns X11 for a
generation, changing that set behind the same ownership transition is refused;
a new remote generation or genuine local owner transition is required.

Dedicated CTest:
`clipboard.x11-completed-multi-file-uri-handoff`. It materializes two real
build-root files sequentially through the production `RemoteTransfer`
FileContents owner, proves a partially completed set is not publishable,
rejects duplicate destination URIs, validates exact URI-list/GNOME/KDE
payloads, rejects same-generation set mutation, and rejects the stale set after
generation replacement. Ordinary CTest uses the injected XCB seam and never
touches a live user's clipboard or file manager. R9 sanitizer selection now
enumerates this case before running the complete clipboard label.

This advances bounded **multi-file** handoff only. The current portable
FILEDESCRIPTORW parser intentionally retains safe leaf names and rejects path
separators, so it does not preserve authoritative remote tree hierarchy.
Directory-tree reconstruction therefore remains **BLOCKED** until R8 has an
explicit bounded hierarchy/mapping contract that cannot synthesize local paths
from untrusted remote names. Live Nautilus/Dolphin paste, Wayland portal
FileTransfer, authenticated Microsoft-client file copy, owner Linux/X11 and
performance remain **NOT RUN/OPEN**.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate build root was
created. Exact-publication-SHA hosted Linux/GCC, R9 ASan/UBSan, full
cross-platform regression and documentation-policy evidence are **PENDING**.

**Next R8 after hosted validation:** define the bounded explicit directory-tree
mapping/capability contract (caller-selected local destinations, no remote-name
path construction), then extend completed-set handoff across Windows/macOS and
real-client acceptance.

## R5 XI2 optional-build guard correction (2026-10-16; exact-SHA CI pending)

**Correction parent:** `366303f35156cdd00c125dfa976d72bc23016bb3`.

Immediate diff review found the new aggregate stale-motion function was placed
just after the existing `RDP_TEST_XINPUT_POINTER` block even though its
dispatcher and CTest registration were correctly conditional on the optional
XInput2 target. Hosted Linux installs XInput2 and would not expose that omission,
but a supported Linux build with the desktop aggregate and no `xcb-xinput`
development package could compile the test executable without
`RDP_TEST_XINPUT_POINTER` and still see pointer-only helper references.

The correction only wraps
`syntheticXvfbPointerRandrStaleMotionIsolation()` in the same compile-time
feature guard as the existing pointer event/RandR behaviors. Production XI2
generation-fence semantics, CTest registration, sanitizer selection and test
assertions are unchanged. Exact correction-SHA hosted validation is **PENDING**.

## R5 XI2 stale-motion generation isolation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `deabb822e2f795a2b2cde37979246beb7e876334`.

Current R3 source still exports no authenticated already-decoded Share/Input or
Fast-Path Input event handoff, so functional R5 translation remains blocked and
this increment stays inside the existing native owner. The prior XDamage RandR
regression established that queued native events need explicit generation
provenance. Source review found the geometry-bound XI2 pointer tracker had the
same class of gap: after RandR rebuild it matched queued motion only by XGE
extension opcode, XI2 motion type and root window.

`X11PointerPositionTracker` now records the request sequence of its successful
checked `XISelectEvents` subscription. Its event matcher rejects XCB
`full_sequence` values older than that generation floor using bounded 32-bit
serial arithmetic; disconnect clears the floor with the rest of the borrowed
native identity. The constructor's synchronous `QueryPointer` snapshot remains
a current-state observation and is intentionally not treated as a queued event.

New production-backed CTest
`x11.desktop-resource-pointer-randr-stale-motion-isolation` remains in the
existing `test_x11_desktop_resources` executable and uses the same one
production XCB connection. An independent helper completes the real Xvfb resize
from 1280x720 to 1024x600, then warps the root pointer before the aggregate
consumes RandR. After the transactional rebuild, the test consumes only the
replacement tracker's synchronous pointer snapshot, drains the queued old XI2
motion without allowing a pending coordinate to reappear, then requires a fresh
post-rebuild warp to publish normally. The existing pointer tracker synthetic
fixtures now stamp their injected XGE records with a synchronized current XCB
request sequence so they continue exercising the production generation check.

The shared R9 Clang ASan/UBSan R5 selector and exact-name preflight include the
new case, expanding the expected native-X11 selection from **32** to **33**
behaviors. No second XCB owner, event loop, RDP parser, scheduler or authority
surface is added.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is **NOT
RUN** in this connector environment; no alternate persistent build root is
created. Exact publication-SHA Linux/GCC, macOS/AppleClang, Windows/MSVC,
R9 sanitizer, documentation-policy and SDK/package evidence are **PENDING**.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27, genuine admitted
XTEST operation and Microsoft-client M3 acceptance remain **NOT RUN / OPEN**.
Functional R5 input integration remains **BLOCKED ON R3**.

## R10 licensing provisioning hosted validation (2026-10-16)

**Implementation:** `35cfda594f45c15e14966579f05cadb4bc5db8f1`.  
**Windows portability correction:** `4ec2b8c5ece830e28427c8501b98ff943465372b`.  
**Validated unchanged descendant:** `a9a656e9c5dc93b8316a6ae1298d658ff4ffcba6`.  
**Actions:** `38978665476` — **SUCCESS**.

The administrator-facing R10 licensing preflight is now hosted-validated on
the corrected source. Comparison from the Windows correction through the
validated descendant shows no change to `src/server/runtime/main.cpp`,
`runtime_licensing_context.*`, `tests/check_runtime_entrypoint.cmake` or
`tests/check_runtime_licensing_context.cmake`. The six centrally registered
process CTests execute the production `rdp-server` binary and all pass:

- `runtime.licensing-cli-valid-provisioning`
- `runtime.licensing-cli-incomplete-configuration`
- `runtime.licensing-cli-invalid-product-identity`
- `runtime.licensing-cli-credential-file-denials`
- `runtime.licensing-cli-existing-check-compatibility`
- `runtime.licensing-cli-service-still-disabled`

Linux/GCC is **521/521 PASS Debug + 521/521 PASS Release**; the six R10 CLI
cases are tests **332-337**. macOS/AppleClang is **442/442 PASS Debug +
442/442 PASS Release**; the six cases are tests **280-285**. Windows/MSVC
focused native preflight is **51/51 PASS Debug + 51/51 PASS Release** and full
CTest is **472/472 PASS Debug + 472/472 PASS Release**; the six cases are again
tests **280-285**, proving the `std::numeric_limits<uint32_t>::max` Win32-macro
correction.

The Clang ASan/UBSan bounded licensing/security selection is **90/90 PASS**.
It actually runs five R10 process cases instrumented:
valid provisioning, incomplete configuration, invalid product identity,
credential-file denials and service-still-disabled. The legacy-check
compatibility case remains covered by all six ordinary hosted Debug/Release
suites and is not claimed as sanitizer-executed. Documentation policy, the
independent R7 sanitizer, downstream installed-SDK consumers and package
artifact gates pass on the validated descendant.

This validates only explicit bounded provisioning and non-listening startup
preflight. It does not create a CAL, licensing authority, R2 lease, listener,
authenticated user, live R3 grant publication, Share activation or
Microsoft-client acceptance. Canonical owner-local `~/rdp-server/build/` and
owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 remain
**NOT RUN**, so M1 remains open.

**Next R10:** do not treat an administrator-provided opaque CAL or the existing
`RdpLicensingAuthorityGrant` snapshot as authority. The next functional
boundary is a concrete service-owned CAL-issuing authority whose nonzero
generation/fingerprint are freshly revalidated with each issuance result; only
then can R2/R3 consider live receipt-bound New License publication. M2 remains
**BLOCKED / NOT ACCEPTED**.

## R9 final CredSSP structural-corpus validation (2026-10-16)

Three new behavior-named tests use `test_owned_credssp_tsrequest` and real R2 `inspectCredSspCredentials`: `security.credssp-password-credential-nested-der-mutations`, `security.credssp-password-credential-length-boundary-denials`, and `security.credssp-password-credential-utf16-mutation-boundaries`. The bounded deterministic corpus covers every one-byte complement, insertion, removal and truncation of a domain/user/password seed; duplicate/missing/reordered nested context fields; malformed length headers and 0x81/0x82 boundaries; field sizes through 4096; near-total-8192 rejection; and BMP, surrogate, NUL, odd-length and empty-field cases at multiple code-unit positions. Structural success is not R2 authentication, PAM success or native lease issuance. The R9 CI selection includes all three tests and fail-closed registry checks; actual instrumented results must be confirmed from the exact publication workflow. Owner Linux/X11, Windows CLANG64, macOS 27 and real-client acceptance remain NOT RUN here.

## R2 Linux PAM verifier exact-SHA validation (2026-10-16)

**Validated implementation/integration SHA:** `d2a1ac10ac3c5ecd64b7d34b3777e2121119f678`.  
**Actions:** `38978066830` — **SUCCESS**.

The real Linux-PAM verifier groundwork is validated without enabling admission.
Linux/GCC Debug + Release are **521/521 PASS** and the PAM denial case is
test **#319** in both. macOS/AppleClang is **442/442 PASS** Debug + Release
without PAM. Windows/MSVC native preflight is **51/51 PASS** Debug + Release
and full suites are **472/472 PASS** Debug + Release. R9 Clang ASan/UBSan
compiles the production PAM target and executes the exact PAM denial selection
**1/1 PASS**; native GSS/R2/R3 is **29/29**, direct Linux runtime security
**10/10**, native X11 **32/32**, and the fuzzer **1/1**, all PASS.
Documentation policy, R7 sanitizer, SDK consumers and packaging pass.

This closes only the standalone real-provider verifier boundary. Final
CredSSP remains terminal deny-only and the private completion latch remains
false. The next R2 work is authenticated extraction of the confidential
`TSPasswordCreds` username plus exact immutable
Kerberos-principal-to-local-account policy matching before PAM invocation.
Positive Kerberos/PAM/NSS/logind admission and M2 remain **BLOCKED / NOT RUN**.
Owner-local `~/rdp-server/build/` remains **NOT RUN** in this connector.

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



**Current shared-main descendant validation:** \`a9a656e9c5dc93b8316a6ae1298d658ff4ffcba6\`,
Actions \`38978665476\` — **SUCCESS**. No R1 transport source changed between
the implementation SHA and this descendant; the intervening transport-source
changes are confined to R3 licensing. Linux/GCC full CTest is **521/521 PASS**
in both Debug and Release, macOS/AppleClang is **442/442 PASS** in both, and
Windows/MSVC is **472/472 PASS** in both with the focused native preflight
**51/51 PASS** in both configurations. The R1 cancellation cases remain tests
#159 and #161 and pass in all six full hosted runs. The bounded R9
Clang ASan/UBSan R1/R3 licensing selection is **90/90 PASS**; it explicitly
runs the License Request cancellation case as item 71/90 and the Platform
Challenge cancellation case as item 73/90. Documentation policy, R7
session-watch sanitizers, installed SDK consumers, package generation and
artifact upload also pass; the untagged prerelease remains correctly skipped.

This newer evidence does not unblock another R1 implementation. R2's validated
PAM component is still a denial-only subordinate verifier and cannot mint final
CredSSP/native admission. R3's validated License Grant receipt gate remains
detached from the live MCS session and has no R2 publication API, while R10
still has no real CAL-issuing authority owner. Per the existing Next R1 gate,
adding another transport writer, direct SSL path, detached grant-through-TLS
fixture or second coordinator now would duplicate already-bounded ownership
without proving the required live authorization boundary.

**Next R1:** do not enlarge or duplicate the transport for R3's new
\`RdpServerLicenseGrantWriteGate\` yet. Its complete New License packet is
already bounded below R1's 18 KiB application-I/O ceiling, and the gate is
explicitly not embedded in the live MCS session or exposed through R2. Once
R10 supplies the real authority owner and R2 exposes fresh authorization for
the live grant slices/completion, verify that final publication through the
sole R1-owned TLS writer. Otherwise wait for the first live Share-activation
boundary that demonstrates a concrete bounded transport mismatch.

## R3 bounded licensing sanitizer selector correction (2026-10-16)

The corrected grant-gate source descendant `f41d2a4b41362bbaf7bd5d6e030ea917dabe2796`
compiled and passed ordinary Debug coverage on Linux and macOS, but R9's
bounded R1/R3 licensing step did not execute: CTest rejected its selector with
`RegularExpression::compile(): Too many parentheses`. This was a selector
construction failure, not an ASan/UBSan finding and not a production/test
binary failure.

This correction flattens only the newly added
`license-grant-(...|write-receipts|write-denials)` alternatives, removing one
nested regex group while preserving the exact selected test names and existing
explicit registration greps. Production code, CTest registration, authority
correlation, grant bytes and receipt behavior are unchanged. Exact-SHA
sanitizer and full hosted validation remain required before acceptance.

## R3 authority-correlated New License receipt-gate hosted validation (2026-10-16)

**Implementation:** `525e235e1cc86ae978cf910020511bfcba4f4338`.  
**Compile-order correction:** `83d05e8076982545e57b75b78f5f5b212ddde865`.  
**Sanitizer-selector correction:** `dd9ebf76bb1087a25733f74744d155a1f903d1b8`.  
**Validated descendant:** `d2a1ac10ac3c5ecd64b7d34b3777e2121119f678`.  
**Actions:** `38978066830` — **SUCCESS**.

The validated descendant contains the R3 grant-gate production source unchanged
from the implementation/fix chain plus the flattened bounded sanitizer
selector. Linux/GCC full CTest is **521/521 PASS Debug** and **521/521 PASS
Release**. macOS/AppleClang is **442/442 PASS Debug** and **442/442 PASS
Release**. Windows/MSVC focused native preflight is **51/51 PASS** in both
configurations and full CTest is **472/472 PASS Debug** plus **472/472 PASS
Release**. Both new cases,
`transport.licensing-server-license-grant-write-receipts` and
`transport.licensing-server-license-grant-write-denials`, pass in all six
full hosted configurations.

R9 Clang ASan/UBSan is **PASS**. Its bounded R1/R3 licensing selection is
**90/90 PASS** and explicitly enumerates/runs both new grant receipt cases
(**PASS**). Other configured groups also pass: clipboard **60/60**, portable
graphics **34/34**, x264/BGRA **20/20**, RDPGFX capabilities **4/4**, native
R2/R3 GSS **29/29**, R2 PAM verifier **1/1**, direct Linux runtime security
**10/10**, native X11 **32/32**, and bounded fuzzer **1/1**. The separate R7
macOS session-watch ASan/UBSan job also **PASS**.

Documentation policy, installed SDK downstream consumer, package generation,
digest/artifact upload on Linux/macOS/Windows all **PASS**. Untagged protocol
prerelease publication is correctly **SKIPPED**.

The validated behavior remains deliberately detached from live R2/session
publication. A configured `RdpLicensingAuthorityGrant` is correlation data,
not CAL authority. The gate requires the exact authority generation/fingerprint,
the cryptographically reached `NewLicenseIssuanceRequired` branch, immutable
product identity and derived licensing keys; it preserves stable bytes through
backpressure/partial writes and moves only the detached licensing lifecycle to
`Licensed` after exact full accepted-byte delivery. Upgrade publication and
the CLIENT_LICENSE_INFO valid-client path remain unavailable.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27, genuine Kerberos/logind positive admission, a real
CAL-issuing licensing authority, Microsoft-client New License acceptance,
Share activation and desktop acceptance remain **NOT RUN / OPEN**.

**Next R3:** do not expose this gate through the live session until R10 supplies
a concrete licensing-authority owner whose current generation/fingerprint can
be freshly revalidated and R2 can authorize every slice/completion. In
parallel, implement CLIENT_LICENSE_INFO CAL trust/signature,
product/version/expiration and HWID validation before any
STATUS_VALID_CLIENT path. **M2/M3 remain OPEN / NOT ACCEPTED.**



## R4 client decoded-frame observation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `bdcb68520c5339aa9866f2e7d5949cf6b5c9c056`.

MS-RDPEGFX FRAME_ACKNOWLEDGE carries both the already-retained client
`queueDepth` and `totalFramesDecoded`, a uint32 count of frames decoded
since connection initiation. R4 previously parsed the latter and discarded it.
The existing generation-bound `GfxFrameAckWindow` now retains the **raw latest
valid** decoded-frame count and exposes it through the sole
`GfxPresentationLifecycle`. A separate availability bit distinguishes a
legitimate reported zero from "no valid ACK observed yet".

Malformed and stale-generation PDUs cannot mutate the observation.
Valid unmatched ACKs do update it because they remain valid client telemetry.
ACK suspension preserves the count reported in the suspension PDU while ACK
expectation becomes false; channel reset/disconnect clears value and
availability. No monotonicity rule, wrap arithmetic, decoded-rate calculation,
timer, throttle threshold, queue, second scheduler or DVC authority is added.

New production-backed CTests are
`graphics.frame-ack-decode-progress` and
`graphics.frame-ack-decode-progress-observation`. The portable R4
Clang ASan/UBSan selector is extended with fail-closed registry preflight for
both cases.

Canonical owner-local `~/rdp-server/build` execution is **NOT RUN** in this
connector environment. Exact-SHA Linux/GCC, macOS/AppleClang and Windows/MSVC
Debug/Release, portable R4 sanitizer, documentation policy and SDK/package
evidence are required after publication. Genuine authenticated R3
`Microsoft::Windows::RDS::Graphics` DVC admission/full-send, measured
decode-lag throttle calibration, native capture performance and
Microsoft-client visible graphics remain **BLOCKED/NOT RUN**. Gate B and
M3/M4/M5 remain **OPEN**.


## R4 client decoded-frame observation exact-SHA hosted receipt (2026-10-16)

**Implementation:** `631ceb3b5d9e212a1a7ddaf399a91d8ad57ad183`.  
**Actions:** `39004943407` — **SUCCESS**.

The existing generation-bound FRAME_ACKNOWLEDGE owner now retains the raw
latest valid `totalFramesDecoded` value plus explicit availability, and the
sole `GfxPresentationLifecycle` exposes that observation beside the existing
queue-depth facts. Zero remains a valid observed counter value; malformed and
stale-generation PDUs cannot mutate it; valid unmatched ACKs can update it;
the suspension PDU's value remains inspectable while ACK expectation is false;
disconnect/reconnect clears both value and availability. No monotonic/wrap
rule, derived decode rate, timer or frame-rate threshold was introduced.

Dedicated production-backed cases
`graphics.frame-ack-decode-progress` and
`graphics.frame-ack-decode-progress-observation` pass in every ordinary
hosted configuration and under the portable R4 sanitizer gate:

- **Linux/GCC:** Debug **530/530 PASS**, Release **530/530 PASS**; the new
  cases are **#273** and **#280** in both configurations.
- **macOS/AppleClang:** Debug **449/449 PASS**, Release **449/449 PASS**; the
  new cases are **#258** and **#265** in both configurations.
- **Windows/MSVC:** focused native preflight **51/51 PASS** in Debug and
  Release; full Debug **479/479 PASS**, Release **479/479 PASS**; the new
  cases are **#258** and **#265** in both full suites.
- **Clang ASan+UBSan portable R4 RDPGFX:** **36/36 PASS**; registry preflight
  explicitly finds both new cases and they pass as items **9/36** and
  **16/36**. Existing R4 x264/BGRA remains **20/20 PASS** and RDPGFX
  capability negotiation remains **4/4 PASS**.
- Documentation policy, independent R7 sanitizer, installed-SDK
  consumer/package/digest/upload and all other configured sanitizer/fuzzer
  groups pass; ordinary prerelease publication is correctly **SKIPPED**.

This closes decode-progress **observation** only. MS-RDPEGFX recommends using
finite nonzero queue depth to judge client decode lag and throttle frame rate,
but the protocol does not prescribe thresholds. R4 therefore does not guess a
cadence policy without measured/client evidence. Canonical owner-local
`~/rdp-server/build`, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and
macOS 27, authenticated R3 Graphics DVC/full-send, native capture performance
and Microsoft-client visible graphics remain **NOT RUN/BLOCKED**. Gate B and
M3/M4/M5 remain **OPEN**.


## R4 safe zero-byte AVC420 frame cancellation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `17f0f11bb420ba6772fb0e6639e04bc73e745552`.

R4 now distinguishes an exact, conclusively unwritten prepared frame from a
partially or ambiguously submitted frame. The sole
`GfxPresentationLifecycle` can cancel only its exact pending
generation/serial/frame-ID/byte-count receipt while mapped, clearing that
reservation without changing the active graphics generation, mapped surface,
earlier ACK-pending frame IDs, ACK suspension state, queue-depth observation or
decoded-frame observation. R4 deliberately has no caller Boolean or SSL/DVC
inspection that could pretend to prove transport progress: a future authorized
R3 sender must first establish cumulative accepted bytes are zero and retire
every borrow of the frame bytes.

The move-only `GfxAvc420SegmentedFrame` cancellation boundary invalidates and
releases its owned segmented payload only after exact lifecycle cancellation
succeeds, and move operations explicitly invalidate the source object.
`X264Avc420SegmentedFrameProducer::cancelUnwrittenDelivery()` then rebuilds
the existing x264 encoder so the next accepted NV12/BGRA picture begins a new
IDR sequence. A stale, wrong or duplicate cancellation does not reset a
healthy encoder. If post-cancellation encoder rebuild fails, the producer
becomes unusable and the lifecycle disconnects. Any positive or uncertain
transport progress remains on the pre-existing terminal abort path.

Five dedicated production-backed CTests are centrally registered:
`graphics.frame-delivery-unsent-cancellation`,
`graphics.avc420-segmented-frame-unsent-cancellation`,
`graphics.x264-segmented-unsent-cancel-idr`,
`graphics.x264-bgra-unsent-cancel-idr`, and
`graphics.frame-delivery-partial-send-remains-terminal`. The portable R4
ASan/UBSan selector now fail-closed preflights all three portable cancellation
cases, and the x264-labelled selector preflights both real-codec recovery
cases before running the complete label.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment because the synchronized checkout is
unavailable; no alternate checkout, branch or persistent build root was
created. Exact publication-SHA Linux/GCC, macOS/AppleClang, Windows/MSVC
Debug/Release, portable R4 sanitizer, x264/BGRA sanitizer, capability
sanitizer, documentation-policy and SDK/package evidence are **PENDING**.

**Next R4:** wire this contract only behind genuine R2/R3 admission and an
authenticated R3 Graphics DVC writer that owns cumulative accepted-byte
evidence. Do not enable graphics publication from this offline lifecycle.
Measured native capture/decode performance and Microsoft-client visible
desktop acceptance remain open; M2-M5 are not accepted by these tests.


## R4 P2 graphics recovery validation and authorized R3 handoff audit (2026-10-17)

**Authoring parent:** `9cfeabe694e89c3fc89c714fb4e461236c6e61c9`.
**Landed cancellation implementation:** `17261a9d880698b4c979f349cf49e24640a94aca`.
**Last fully green unchanged-R4 validation point:** `2f4fd534bc070977582ed899c620cd79171edecf`.
**Validated Actions:** `39010087859` — **SUCCESS**.
**Authoring-parent CI:** Actions `39010778228` (CI workflow structure guard): **FAILURE**. Actions `39010778231` (C++23 protocol CI and prerelease delivery): **FAILURE**.

P2 does not reimplement zero-byte cancellation. Comparison from the landed
implementation to `2f4fd534...` changes no R4 graphics source or dedicated
R4 test translation unit. On that validated descendant, ordinary full CTest
passes Linux/GCC **568/568 Debug + 568/568 Release**, Windows/MSVC
**518/518 Debug + 518/518 Release** after **55/55** native preflight in
each configuration, and macOS/AppleClang **485/485 Debug + 485/485 Release**.
The retained production-backed cases are `graphics.frame-delivery-unsent-cancellation`, `graphics.avc420-segmented-frame-unsent-cancellation`, `graphics.x264-segmented-unsent-cancel-idr`, `graphics.x264-bgra-unsent-cancel-idr`, `graphics.frame-delivery-partial-send-remains-terminal`. All five execute and
pass in every ordinary hosted full suite.

R9 on the same SHA registry-preflights and passes portable R4 RDPGFX
**39/39**, x264/BGRA **22/22**, and RDPGFX capabilities **4/4**. The
portable group includes exact unsent cancellation, segmented-frame
invalidation and partial-send-terminal behavior. The x264 group includes both
NV12 and BGRA recovery cases.

The verified state contract is unchanged: conclusively unwritten cancellation
keeps the presentation mapped, preserves the surface and prior ACK/client
queue-depth/totalFramesDecoded observations, invalidates the canceled owned
frame, rebuilds x264, and makes the next accepted picture an IDR. A later
delivered picture resumes normal P-frame continuity. Wrong, stale or duplicate
cancellation cannot reset a healthy reference chain. Any positive or uncertain
wire progress remains terminal through `abortDelivery()` and revokes that
graphics generation.

The R4 owned-wire API is already suitable for one future authorized sender:
one move-only `GfxAvc420SegmentedFrame`, one stable `wireBytes()` backing span
and one private R4 delivery receipt. The exact missing production layer is R3.
R3 can currently identify the static `drdynvc` role syntactically and can
encode bounded MCS Send Data Indications, but it has no protected
R2-reauthorized joined-DRDYNVC role, no MS-RDPEDYC CREATE/response lifecycle
for `Microsoft::Windows::RDS::Graphics`, no DVC DATA fragmentation, and no
single active graphics-send record that correlates cumulative outer-byte
acceptance to R4 complete/cancel/abort. A complete R4 frame can exceed the
16,383-byte MCS user-data ceiling, so direct whole-frame MCS emission is not
a valid handoff.

The future R3 owner must retain exactly one R4 frame, build only a bounded
current DRDYNVC/static-channel/MCS fragment, and track independent nonzero R3
publication/slice receipts while feeding the sole R1 application writer.
R1 already reports exact positive plaintext progress and zero-byte WANT with
an 18 KiB per-call ceiling. Importantly, a zero-byte WANT is **not** a safe
frame-drop point: R1 retains a pending logical write and requires retry with
identical length/content. Therefore preserving R4 cancellation is valid before
the first frame-related R1 write is submitted (with all borrows retired), not
after a WANT unless R1 later gains an explicit nonterminal operation-retirement
contract. Any positive outer header/payload progress or uncertain progress
selects terminal abort. Only full acceptance of every outer fragment maps back
to R4 completion using the logical `frame.wireBytes().size()`.

No production behavior is added in P2, so no new CTest is registered. When R3
implements the authorized Graphics DVC sender, it must add one dedicated
production-backed cross-component receipt test covering pre-submit cancel,
zero-byte WANT with stable slice identity, positive partial progress, exact
full completion and terminal failure after progress.

Linux/X11 is the first native-source integration: after genuine R2/R3
authorization, R5 snapshots damage and captures a **full mapped visible
surface** through `X11DesktopResources::capture()`, then R4 synchronously
consumes that borrowed `FramebufferView` in `prepareBgra()` before any next
capture, RandR rebuild or disconnect. The initial path fails closed on odd or
unsupported geometry rather than silently cropping or inventing a partial
framebuffer compositor. R6 DXGI and R7 CoreVideo subsequently feed the same
borrow-only framebuffer contract while retaining native generation/revocation
ownership.

`docs/benchmark.md` now records repeatable Release/CTest recovery commands
under the canonical `~/rdp-server/build/` as diagnostics only and defines the
future Damage -> capture -> conversion/x264 -> R3/R1 wire -> ACK/visibility
measurement boundary. No fps/decode threshold is inferred from hosted CTest
timing, `queueDepth`, or `totalFramesDecoded`.

Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN** in this
connector environment; no alternate checkout or build root was created.
Graphics publication remains disabled until genuine R2/R3 session authority,
licensing/share activation, joined DRDYNVC authorization and Graphics DVC
creation exist. Native capture performance, real client decode-lag calibration
and Microsoft-client visible graphics remain **NOT RUN / OPEN**. M3/M4/M5 are
not accepted by this audit.

**Next R4/R3 gate:** first restore/confirm a fully schedulable current-main CI
if the authoring-parent workflow is not green, then rerun the full matrix and
R9 selectors. R3—not R4—then owns the protected DRDYNVC/Graphics DVC
lifecycle and the one receipt-bound sender.