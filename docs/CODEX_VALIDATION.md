## R2 P0 authentication challenge — exact-SHA Microsoft qualification (2026-10-29)

- Publication SHA: `2e423e4dbb9cdbf506b11a1b5a44132b58f88180`.
- Workflow: `40841093750`; Windows protocol job: `123337434778`.
- Exact-SHA artifact: `r9-microsoft-interop-2e423e4dbb9cdbf506b11a1b5a44132b58f88180`, artifact
  `12883051440`, digest
  `sha256:4740f131d6f406d460aef189798a82ffed9a63652eeabd43a184469a65df5575`.
- CI structure guard: **PASS**.
- Production fixed-name Microsoft CREDSSP control: **PASS**, Type 2 consumed and
  Type 3 emitted.
- Required-AV negative control `MsvAvNbComputerName` removed: **PASS** as an
  oracle control; challenge committed/consumed, no next client output, no Type
  3, Microsoft terminal `SEC_E_INVALID_TOKEN (0x80090308)`.
- Required-AV negative control `MsvAvNbDomainName` removed: **PASS** with the
  same independently observed Microsoft terminal boundary.
- Negative-control summary:
  `control=TYPE3 invalid-controls=DETECTED status=PASS process-isolation=per-challenge production-type2-change-authorized=no`.
- Interop artifact final status: `interop-matrix-final=COMPLETE_PASS`.
- Canonical owner local one-`build/` configure/build/full CTest: **NOT RUN**
  in this connector environment.
- Conclusion: **no production challenge defect demonstrated; no production wire
  change authorized**. Continue with the controlled R6 physical-client
  differential rather than modifying Type-2 fields.

## R5 P0 macOS evidence + pre-auth native isolation first round (2026-10-29)

- Initial authoring base: `d9b255bef6ae54952b50ffbca24f4b17ce969d72`.
- Reconciled publication parent: `56df83fef6d98e03fb7fa14058ff909b3fe5317d`; concurrent R3/R8/R9 changes
  preserved.
- Read-only evidence helper authoring copy: `python3 -m py_compile`
  **PASS** and direct unittest **13/13 PASS**.
- Evidence coverage: certificate SHA-256, client version/build, explicit
  credential selection/match, offset-aware attempt/Linux timestamps, complete
  pre-auth stage matrix, first-client-error contract, private raw-log retention,
  redacted R2/R6 projection and fail-closed A/B comparability.
- Linux native-order source audit: **PASS by inspection**. X11 capture/input/
  clipboard construction is reachable only after genuine R2 Admission, Share
  activation and GraphicsReady. Pre-auth performs only current read-only
  owner/session/lock evidence refresh plus R1/R2 service work.
- New production-backed Direct-NTLM owner-loss CTests: authored for lock,
  logout, session-generation replacement and explicit owner revoke while the
  peer is held after Type 2 and before Type 3.
- Canonical `~/rdp-server/build/` configure/build/focused/full CTest:
  **NOT RUN** because this connector environment has no approved checkout/build
  root.
- Physical macOS Windows App / Windows 11 client execution: **NOT RUN**; no
  Keychain or trust-store access/modification performed.
- Exact publication-SHA hosted CI/sanitizers: **PENDING**.
- Next gate: exact-SHA hosted producers green, then only R9-authorized physical
  evidence collection and R6 pair validation.

## R8 P1 offline CLIPRDR conformance first round (2026-10-29)

- Source parent: `79ed26a8ff082b7ec8a506b47aae00e77a1e79bf`.
- MS-RDPECLIP conformance review: **PASS by inspection** for capability flags,
  Format List layouts, Format Data request/response framing and FileContents
  stream correlation.
- Canonical local `~/rdp-server/build/` configure/build/full CTest: **NOT RUN**
  because this connector environment has no checkout and direct GitHub DNS
  checkout is unavailable.
- Live desktop/clipboard/Microsoft-client testing: **NOT RUN** (not authorized
  by this offline assignment and production activation remains false).
- First publication `6a9b3b34c3eca18a406d62bdea6833d3ebe1bbf4`:
  structure Actions `40839945517` **FAIL** before build because the source
  validator still required `clipboard_expected_test_count=97`; primary
  Actions `40839945545` was queued at diagnosis.
- Corrective source-validator update: expected clipboard count 100 plus exact
  sentinels for the three new R8 cases; correction-SHA CI/ASan/UBSan **PENDING**.

# Validation evidence

## R1 pre-TLS accounting fixture CI correction — 2026-10-29

- Initial publication: `3fdde5748e1c88d2684e13632778d9775eddc36f`.
- Structure workflow `40840884642`: **PASS**.
- Primary workflow `40840884671`, Ubuntu protocol job `123336728405`:
  build **PASS**; full CTest **966/967 PASS**, with only
  `transport.tcp-owned-pre-tls-transport-byte-accounting` aborting.
- First failing boundary: synthetic client TLS started while the 19-byte
  plaintext HYBRID X.224 Confirm was still unread on its socket.
- Correction: consume and verify the exact X.224 Confirm before client TLS BIO
  attachment. Production R1 source and all security/timing policy remain
  unchanged.
- Correction-SHA hosted CI: **PENDING**.

## R1 accepted-to-TLS transport attribution — 2026-10-29

- Reconciled source parent: `675cf908d0e67018157b309ee1585e703f9068a9`; assignment-time main:
  `d9b255bef6ae54952b50ffbca24f4b17ce969d72`.
- Required policy/vision/roadmap/coding/testing/compile/benchmark context:
  re-read from current `main` after concurrent publication.
- R1 socket/X.224/HYBRID/TLS/BIO and R10 serialized pre-auth service audit:
  **PASS by source inspection**.
- Existing independent Type-2 outer-TSRequest DER oracle and exact
  partial-write/backpressure tests: **PASS by source inspection**.
- Local canonical configure/build/full CTest: **NOT RUN** — this connector
  environment cannot resolve GitHub to create the approved checkout.
- Exact publication-SHA hosted CI: **PENDING**.
- Physical Windows App attribution with the new fields: **NOT RUN**.
- Production TLS security level, timeout policy and certificate verification:
  **UNCHANGED**.

## R9 exact-SHA qualification ledger — 2026-10-29

Source SHA under review: `d9b255bef6ae54952b50ffbca24f4b17ce969d72`.
Primary workflow: `40761365568`.

| Gate | Exact-SHA result |
| --- | --- |
| Linux GUI ZIP | PASS |
| Linux protocol Debug/Release | PASS |
| macOS protocol Debug/Release | PASS |
| Windows MSVC protocol Debug/Release + Microsoft interop artifact | PASS |
| R9 protocol/security sanitizers | PASS |
| Linux/macOS GUI credential parity | PASS |
| Documentation / workflow structure | PASS |
| Windows CLANG64 Release full CTest | PASS, 849/849 |
| Windows native sanitizer selection | PASS, 60/60 |
| Windows firewall snapshot semantic CTest | PASS in Debug and Release |
| Extracted Windows GUI no-socket/native-state smoke | PASS |
| Windows CLANG64 Debug full CTest | FAIL: test #37 `security.windows-credssp-credential-semantic-differential` segfault |
| GUI Round 2 aggregate | FAIL CLOSED because Windows CLANG64 producer failed |
| Manual `r9_credssp_owner_candidate=true` | NOT RUN on ordinary push |

The failing Debug credential test completed the correct, wrong-password and
empty-password Type-3 rows, then terminated before the unavailable/no-SPNEGO
row emitted its first SSPI status. Immediate parent
`c542f861ff8bc35300445ae7c1d91325470708e7`, workflow
`40760910388`, Windows CLANG64 job `123072335370`, passed the same test in
Debug and Release. The reviewed `d9b255b` commit changes only the Windows
firewall smoke plus testing/roadmap documentation, so no authentication-wire
change is attributed to this regression.

Corrective qualification keeps production wire behavior unchanged. Credential
rows are process-isolated with crash-as-failure diagnostics; exact-SHA
interop output is explicitly PARTIAL until every required case completes; the
Windows CLANG64 producer ends with a fail-closed aggregate over required
Debug/Release/GUI/sanitizer steps; and the dispatch-only owner candidate
requires all exact-SHA producers before emitting its manifest.

Corrective descendant local build/full CTest: **NOT RUN** in the connector
environment. Hosted exact-SHA CI and explicit manual candidate dispatch:
**PENDING**.
