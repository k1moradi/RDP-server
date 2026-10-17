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

