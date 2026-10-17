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

