## R7 callback-retirement exact-SHA qualification and current dependency audit (2026-10-30)

**Qualified R7 implementation:** `34e508105d7f7f9f503d3d29475949269dd370cf`.
Primary workflow `41157153368` provides the missing hosted evidence: R7 macOS
native lifecycle job `124407093817` **PASS** with the focused
`macos.native-desktop-owner-borrow-callback-retirement` regression included in
both Debug and Release 22/22 selections; macOS protocol job
`124407093927` **PASS** and the new regression is present in the ordinary
full CTest; R7 macOS portable GUI `124407094074` **PASS**; R7 session
sanitizers `124407093868` **PASS**; R9 security/protocol sanitizers
`124407093911` **PASS**; macOS and Ubuntu owner-GUI credential parity
`124407093974` / `124407093879` **PASS**; R9 GUI Round 2
`124410451261` **PASS** with exact receipt
`GUI ROUND 2 PASS: 34e508105d7f7f9f503d3d29475949269dd370cf`.
The separate clean-Windows self-hosted job remained queued and is not an R7
native/macOS qualification dependency.

**Current descendant audit head:** `a267f37c4df9e8ac69c67e6ef165fa3db7dbae0f`. R7's macOS native-lifecycle,
portable-GUI, session-sanitizer, GUI-parity and Round-2 jobs remain **PASS** on
that descendant. Its repository-wide macOS protocol job fails while compiling
`src/server/runtime/runtime_tls_context.cpp` under OpenSSL 4.1 at
`::sk_GENERAL_NAME_value`; this is an R1 TLS compatibility defect introduced
outside R7 and does not involve the R7 native-owner or Qt sources. R7 does not
modify that R1 owner.

**QColorSpace:** still no first-party `QColorSpace` construction, Qt custom
primaries, ICC/profile-to-Qt conversion or global warning suppression is
present in the audited GUI/macOS sources or package assets. Existing
`gui.round2-qcolor-warning-classification` remains the source guard. No
project-owned warning source is proved, so R4 pixel conversion remains
unchanged.

**macOS native attachment dependency:** `RuntimePlatformNativeDesktop`
continues to expose `attachAuthenticatedSession()` as an R2-proof consumer,
but current `MacRuntimeHostControl` has no positive call that attaches it.
Accepted TCP, TLS, configured Username, standalone `CredentialsVerified` and
GUI Sharing therefore still cannot make the macOS native desktop ready. The
remaining live-desktop dependency is R10 composition of the exact accepted
client with genuine R2 authenticated/admitted authority; R7 must not implement
that state machine. Physical native attachment remains **BLOCKED / NOT RUN**
until that composition exists, an R9 exact-SHA owner candidate is manually
qualified, and the owner separately authorizes the attempt.

Local canonical build/CTest, local Qt warning reproduction and physical
capture/input remain **NOT RUN** in this connector environment. R7 has no
unresolved code blocker of its own after the hosted callback-retirement
qualification; its next live step is dependency-bound to R10/R2.

## R6 current incremental gate — paired physical Windows clients (2026-10-30)

The previously verified delegated Microsoft memory-BIO positive reaches
production CredentialsVerified, has no authInfo failure or observed empty
fields, and never creates native Admission. Negative server binding and
malformed required-AV controls remain prerequisite oracles. The live
macOS Windows App Type-2-commit/zero-post-Type-2-bytes/FIN observation
still has no client-attributed cause; it does not prove a bad password,
TLS error or Type-2 defect.

R6 supplies an offline strict paired A/B validator for the existing private
R5 macOS manifest plus the owner-controlled Windows 11 mstsc row, a
dedicated ordinary CTest denial suite and read-only owner instructions
in docs/MACOS_WINDOWS_APP_OWNER_EVIDENCE.md. It rejects contradictory
Type3/bytes, authInfo/credentials/native admission, saved/re-entered
credential claims, unobserved TLS alert attribution and SHA/profile/IP/
certificate mismatches. No R1 wire or Windows native production change.
Python syntax and seven stub-R5 local synthetic checks PASS, but real
integrated CTest and newest-head Windows MSVC/CLANG64 CI NOT RUN/PENDING.
Next gate: exact published SHA full CTest/oracle receipts, R9 manual
candidate PASS, separate owner permission, then physical two-client A/B.
WTS/DXGI/SendInput already have reviewed offline negative coverage; no
new genuine missing denial boundary was proved. Benchmark NOT RUN.

