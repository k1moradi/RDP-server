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

