## R3 T.125/GCC UserId range correction — 2026-10-29

- Authoring parent: `0a40bc6c78ed4243b3e74e3a38eee6911e1d3618`.
- Normative finding: T.125 `DynamicChannelId` / `UserId` is 1001..65535;
  T.124 GCC UserID has the same dynamic range. The former production upper
  bound 65536 was one past the ASN.1 constraint.
- Corrected production boundaries: ChannelJoin and SendData request parsers,
  Attach/Join confirm encoders, join gate, SendDataIndication, GCC
  Connect-Response nodeID and RDPGFX MCS-user handoff.
- Dedicated gate: `transport.mcs-user-id-range-conformance`; the existing
  sanitizer-selected `transport.mcs-send-data-joined-denials` also invokes
  the shared routine.
- Security boundary: protocol-only; no synthetic R2 admission, HostControl
  progression, live MCS, licensing/Share activation or native desktop.
- Local canonical build/full CTest: **NOT RUN** in this connector environment.
- Exact publication-SHA hosted CI/sanitizers: **PENDING**.

## R5 timing-attribution evidence follow-up — 2026-10-29

- Initial authoring parent: `cde24568f8bcb60a69559dae19ac40ba96fbf092`.
- Reconciled publication parent: `92be9706e2b60ff46fd3f0b0fb8c38e23b6d97d0`; concurrent R9 Release-fixture work
  preserved.
- Dependency review: prior pre-TLS fixture blocker resolved by R9; R2 Microsoft
  production Type-2 control/negative controls qualified; R10 corrected measured
  pre-auth service starvation and published R1/R10 timing buckets.
- Change: private schema-v2 owner evidence now carries the same-attempt R1/R10
  timing attribution; redacted R2/R6 output carries only bounded scalar timing.
- Validation semantics: missing/contradictory timing is evidence **FAIL**;
  nonzero early native maintenance remains valid evidence but reports
  `EARLY_NATIVE_MAINTENANCE_OBSERVED` and native-isolation qualification
  **FAIL** without assigning a client-side cause.
- Existing evidence unittest gains missing-timing, zero-byte/first-byte
  inconsistency and early-native-maintenance cases.
- Authoring source/test/docs review: **PASS by inspection**.
- Local Python command:
  `python3 tests/test_macos_windows_app_owner_evidence.py --script scripts/macos_windows_app_owner_evidence.py`:
  **NOT RUN** in this connector environment.
- Canonical C++ configure/build/full CTest: **NOT RUN**; no production C++ source
  changed in this R5 follow-up.
- Exact publication-SHA hosted CI: **PENDING**.
- Physical Windows App/mstsc execution, Keychain and trust-store mutation:
  **NOT RUN / NOT AUTHORIZED**.
- Next gate: hosted evidence CTest + current R10 qualification green, then the
  existing dispatch-only R9 owner-candidate and owner-authorized R6 physical
  differential.

## R9 Windows CLANG64 Release clipboard-fixture crash — 2026-10-29

- Exact source SHA: `1942cb4ecf08056c6d636a57acfcd6ae40be4773`.
- Primary workflow: `40844853414`; Windows CLANG64 job:
  `123349778099`.
- Debug: isolated credential-source oracle **PASS**; full Debug CTest **PASS**.
- Release: 858/859 executed tests passed; first and only failure was
  `clipboard.file-contents-joined-mcs-envelope` with **SEGFAULT**.
- The same clipboard test passed in Debug on the same SHA. The extracted
  Windows GUI firewall/no-socket smoke and native sanitizer inventory also
  passed after the Release failure.
- Root cause by source inspection: `tests/test_owned_remote_transfer.cpp`
  cleared `NDEBUG` only after project headers. Its assert-driven fixture has
  state-changing expressions, so a transitive disabled `<cassert>` definition
  can remove setup calls in Release and leave later optional state invalid.
- Correction: activate assertions before all project headers and add an
  always-live assertion-expression sentinel with bounded diagnostic.
- Production clipboard/authentication/wire code: **UNCHANGED**.
- Corrective exact-SHA hosted qualification: **PENDING**.

## R10 qualification follow-up — 2026-10-29

- Initial exact-SHA run 40846283148: Ubuntu Debug compile PASS; structure guard
  PASS; production Linux security with and without systemd PASS.
- Full Debug CTest found two R10-local assertions: the new no-starvation fixture
  crossed Type 1 within a burst before sampling its counter, and the refactor
  bypassed the historical pre-listener standalone credential-session refresh.
- Follow-up restores that pre-listener refresh through validateRuntimeOwnerOnce
  without adding interface/logind authorization work when no listener exists.
  The fixture now samples after each bounded service step until Type 1 and uses
  the burst helper after that boundary. No timeout, wire byte, admission gate
  or owner-loss Await-Type-3 contract changed.
- Exact follow-up SHA hosted CI: PENDING.

## R10 P0 pre-auth no-starvation service correction — 2026-10-29

- Authoring parent: 1942cb4ecf08056c6d636a57acfcd6ae40be4773; concurrent work preserved.
- Source audit demonstrated fixed-25-ms pacing of immediate work and blocking
  pre-auth GUI/service native probes on the same Qt owner thread.
- Correction keeps one owner: finite eight-call immediate burst, zero-delay
  yield/reschedule, 25 ms only for no-event wait, accept-before-native ordering,
  no full native probe in Accepted-to-TLS/TLS-to-Type-1, Await-Type-3 owner-loss
  maintenance after no-event plus R1 re-poll, and non-probing PreAdmission status.
- R10 timing buckets add app-reschedule wait, peer-wait upper bound, service work,
  native-maintenance work, call count and max gap. They compose with R1's newly
  published socket-poll and Read/Write ready-to-service dwell fields.
- Production-backed no-starvation CTest injects a 75 ms application gap and a
  deliberately slow owner-evidence source, requires zero native reads through
  Type 1, and reaches unchanged Type 2 with no MCS/Share/native authority.
- Sanitizer selection also executes interleaved TLS WANT_READ/WANT_WRITE and
  the production-peer partial TLS-record case; existing timeout/silence and
  partial-write/backpressure cases remain the stalled-peer/cancellation gates.
- Integrated evidence: physical Accepted-to-TLS 4,825,323 us and TLS-to-Type-1
  1,176,476 us are anomalous early spans; Type-1-to-Type-2 queue is about 4 us.
  R2 Microsoft exact-SHA consumes unchanged Type 2 and emits Type 3, with
  required-AV negative controls rejected. R6 independently reaches Type 3 on
  TLS 1.3 / TLS_AES_256_GCM_SHA384. Physical Windows App's roughly 48,702 us
  Type-2-to-FIN/no-Type-3 boundary remains separate and client-specific.
- TLS/certificate/NTLM/CredSSP bytes, 30 s timeout, owner-consent/native
  Admission and CredentialsVerified-to-MCS authority are unchanged.
- Canonical owner one-build configure/build/full CTest: NOT RUN here.
  Exact publication-SHA hosted CI/sanitizers: PENDING. No live client, desktop
  or system mutation was performed.

## R9 GUI parity legacy-branch stale assertion — 2026-10-29

- Exact source SHA: `88b9aedbfa3202110fde4a24daee5d3f1c7f08e3`.
- Primary workflow: `40844429155`.
- Ubuntu GUI parity job `123348390366`: **FAIL**, 5/6 selected tests PASS.
- First failing boundary after the prior correction:
  `gui.offscreen-authentication-incomplete-before-native-admission`,
  legacy retained-Admission compatibility block at
  `tests/test_desktop_gui_offline.cpp:2331`.
- Runtime projection remained correct: the peer EOF is incomplete remote
  authentication, while Main uses the bounded product summary and Advanced
  diagnostics owns the Type-2 commit detail.
- Correction is test/docs only; no production wire or authority code changes.
- Corrective exact-SHA hosted qualification: **PENDING**.

## R9 GUI parity stale structural-label assertion — 2026-10-29

- Exact source SHA: `12af8f1e5946250138f222721e91497543e50889`.
- Primary workflow: `40842771764`.
- Ubuntu GUI parity job `123344061623`: **FAIL**, 5/6 selected tests PASS.
- First failing boundary:
  `gui.offscreen-authentication-incomplete-before-native-admission` at
  `tests/test_desktop_gui_offline.cpp:2291`.
- The fixture changed only `directNtlmTypeTwoDelivered=true -> false`. Main
  `hostErrorExplanation` correctly became
  `Client disconnected before completing authentication.`; the stale test
  expected an old structural `Authentication: Direct NTLM — ...` sentence.
- Advanced `authenticationDiagnosticsStatus` owns the current
  `NTLM Type 2: queued locally` / `NTLM Type 3: not observed` evidence.
- Correction is test/docs only. TLS, NTLM, CredSSP, credentials, Admission,
  listener and native behavior are unchanged.
- Corrective exact-SHA hosted qualification: **PENDING**.

## R1 zero-timeout readiness-dwell attribution follow-up — 2026-10-29

- Parent: `12af8f1e5946250138f222721e91497543e50889`.
- Source finding: GUI HostControl uses zero-timeout socket polls, so the prior
  Read/Write counters measured only time spent inside `poll()` and could leave
  a multi-second authoritative `NeedRead` / `NeedWrite` interval in the
  residual bucket.
- Diagnostic correction: the same R10 accepted-connection steady clock now
  accounts wall time by R1 Read/Write interest; native poll duration and
  readiness-observed-to-next-service ages are separate non-additive subsets.
- Dedicated behavior gate:
  `runtime.linux-direct-ntlm-preauth-zero-timeout-readiness-attribution`,
  reusing the existing production-backed two-peer lifecycle executable.
- Production R1 transport/TLS/CredSSP bytes, TLS security levels, certificate
  verification and timeout policy: **UNCHANGED**.
- Existing memory-BIO fragmentation/coalescing/backpressure coverage and the
  independent production Type-2 outer-TSRequest DER oracle: **UNCHANGED**.
- Canonical local configure/build/full CTest: **NOT RUN** in this connector
  environment.
- Exact publication-SHA hosted CI: **PENDING**.

## R4 P1 offline first-frame graphics qualification — 2026-10-29

- Reconciled publication parent: `cd839fe4b18d29943df921294ef67c1289542b92`; concurrent road work preserved.
- Microsoft protocol review: Client Core 0x0100 is required to claim RDPGFX;
  codec choice is controlled only by the selected RDPGFX capability set;
  ClearCodec is mandatory; VERSION10+ requires QoE frame-ACK processing; and
  FRAME_ACKNOWLEDGE suspension clears outstanding frames and forbids ACK waits.
- Independently demonstrated defect: production could allocate/start the
  Graphics DVC after admitted Share without checking the parsed Client Core
  Graphics Pipeline bit. R3 now refuses allocation when that bit is absent;
  authentication, R2 admission, Share and joined-channel gates are unchanged.
- New protocol-only CTests: `transport.rdpgfx-client-core-capability-gate` and
  `graphics.first-frame-compatibility-contract`. Existing cases retain
  unsupported-capability, AVC420, malformed-dimension, stale/duplicate ID,
  generation, 64-credit, zero-write and partial-write coverage.
- Live scheduler source guards pin native framebuffer construction after
  Graphics readiness/fresh R2 authority and ACK-credit defer before XShm
  capture with a bounded next-capture time. Runtime has no pre-admission x264
  encoder publication path.
- Canonical local configure/build/full CTest: **NOT RUN** because this connector
  environment has no approved checkout/build root. Exact publication-SHA hosted
  CI/sanitizers: **PENDING**.
- Benchmark: **NOT RUN / not applicable**; no encoder algorithm or hot path was
  changed and no desktop-performance claim is made.
- Remaining Microsoft-client acceptance: genuine owner-authorized physical
  X11 seat0 admission, observed Client Core 0x0100, DRDYNVC/RDPGFX CAPS exchange,
  first visible ClearCodec frame, matching FRAME_ACKNOWLEDGE, resize/recovery,
  revocation/reconnect, and same-SHA evidence from Windows App/mstsc.exe.

## R9 current-main qualification blocker — pre-TLS byte-accounting fixture (2026-10-29)

- `3fdde5748e1c88d2684e13632778d9775eddc36f`: Linux/macOS/Windows protocol
  jobs failed `transport.tcp-owned-pre-tls-transport-byte-accounting`; other
  R9 qualification producers remained green.
- `d671a572292ab68253c62121e3873bf7a81dd992`: R1 consumed the plaintext X.224
  Confirm before TLS, removing the Linux/Windows protocol-order assertion,
  but macOS still failed at `owner.receivedTransportBytes() == 3U` immediately
  after a three-byte client send.
- Root cause: the test asserted immediate loopback readability without a real
  readiness observation. The existing production callback is nonblocking and
  may correctly return no progress at that instant.
- R9 corrective scope: bounded test-fixture retry only; no production R1 or
  authentication wire change. Exact corrective-SHA hosted result: **PENDING**.

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
