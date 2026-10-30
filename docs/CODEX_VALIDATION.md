## R8 Round 3 test compile correction — 2026-10-30

- Failing parent: `aeeb318315db1634068b885f24a103ce06f4d236`,
  workflow `41086564468`.
- Ubuntu job `124170655769`: production sources compiled; Debug build stopped
  at `test_r8_r3_clipboard_bridge.cpp` with unknown
  `R3ClipboardStaticChannelRoute`.
- Sanitizer job `124170655879`: same isolated fixture compile error and compiler
  suggestion `RdpClipboardStaticChannelRoute`.
- Correction: test-only type spelling; protocol/state/authority logic unchanged.
- Correction-SHA hosted CI: **PENDING**. Local build: **NOT RUN**.

## R1 delegated final-authInfo qualification and Microsoft payload receipt — 2026-10-30

- R1 exact SHA `10f9c502c3ca97ba93a86cbb5a3428aa40670c4b`; workflow `41085415452`; Ubuntu job `124166024982`: Debug full CTest **987/987 PASS**, Release full CTest **987/987 PASS**.
- Dedicated `runtime.linux-direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect`: **PASS** in Debug (0.44 s) and Release (0.36 s). Prior `runtime.linux-direct-ntlm-final-authinfo-tls-fragments-reconnect` and `runtime.linux-host-control-stop-queued-authinfo-retirement` also PASS in both full suites.
- R9 ASan/UBSan job `124166024771`: **PASS**; the modified lifecycle executable compiles under ASan/UBSan and the existing R1/CredSSP sanitizer selections pass. The new large/coalesced-tail mode is not directly invoked by that explicit sanitizer inventory, so that one mode is **NOT RUN under sanitizers**.
- Local canonical `~/rdp-server/build/` configure/build/focused/full CTest and local sanitizers: **NOT RUN**; the approved checkout is absent and local GitHub DNS is unavailable.
- Agent 6 descendant `671cae88da7dcb604ced089a9f21c2af9fe78597`, workflow `41085647004`, MSVC job `124166200509`: after server binding Microsoft returns `SEC_E_OK`, emits **98 bytes** of TLS 1.3 application data with no retained/extra/missing input, and production reaches `CredentialsVerified` with authInfo failure `none` and empty-fields `none`.
- From the fixture's public test constants (empty domain, `User`, `Password`) and the canonical MS-CSSP/NTLM wrapper sizes, the final TSRequest is **76 plaintext bytes**. A single TLS 1.3 record adds exactly 22 bytes (record header + inner content type + AEAD tag), matching the observed 98-byte SSPI output. R1's 16 KiB frame cap and exact `bytesNeeded()` reads therefore cover the actual delegation-enabled Microsoft payload with wide margin; the 518-byte R1 stress fixture is larger and crosses the 512-byte reader chunk boundary.
- First remaining failure is **outside R1**: Agent 6 records `delegation-requested=yes delegation-returned=no`; its positive oracle requires final `ISC_RET_DELEGATE` even though authInfo is emitted and production credentials verify. Physical client/native admission: **NOT RUN / not authorized**.

## R8 local-generation route-observation fence — 2026-10-30

- Parent: `aeeb318315db1634068b885f24a103ce06f4d236`.
- Production change: observing a newer server-local clipboard generation now
  clears the bridge's borrowed fresh-route bit. A new Format List for that
  generation requires another protected R2/R3 route visit.
- Regression: existing
  `clipboard.route-bridge-server-initialization-generation-replacement`
  rejects reuse of the pre-generation observation, succeeds after a fresh
  visit, and preserves the higher generation across reconnect.
- Wire serialization, Monitor Ready ordering, Format List response draining,
  FileContents/INCR owners, test count 104, and
  `kLinuxProductionClipboardActivationApproved = false`: **UNCHANGED**.
- Local build/CTest/sanitizers: **NOT RUN**. Exact publication-SHA CI:
  **PENDING**. Physical clipboard/files/client: **NOT RUN / BLOCKED**.

## R8 dormant CLIPRDR initialization/order authoring evidence — 2026-10-30

- Authoring parent: `f85ae6baaa48c110bfcbb95cb433cd0d0945c2b1`.
- MS-RDPECLIP review: **PASS by inspection**. Server capabilities precede
  Monitor Ready; after Monitor Ready the server remains ready for a client
  Format List plus late first capabilities/Temporary Directory. The initial
  client Format List is acknowledged before server-local copy/publication
  generations are allowed.
- Production state: existing `R3ClipboardTransferBridge` gains receipt-driven
  initialization stages, Monitor Ready serialization, server-local monotonic
  clipboard generations and generation-scoped Format List Response receipts.
  No second controller/writer/framer is introduced.
- Interop correction: `RemoteTransfer` permits the first valid client
  capabilities and Temporary Directory after an already accepted Format List;
  duplicate/malformed PDUs remain terminal. Missing capabilities still mean
  zero negotiated flags; Temporary Directory remains a file-lock prerequisite,
  not base initialization authority.
- New CTests:
  `clipboard.route-bridge-server-initialization-ordering`,
  `clipboard.route-bridge-server-initialization-generation-replacement`,
  `clipboard.route-bridge-server-initialization-pending-write-retirement`.
  Shared clipboard sanitizer count: **104**.
- Existing server capability/Format List serialization semantics are retained:
  General Capability v2, supported flag mask, negotiated long names, bounded
  short ASCII/Unicode fallback, nonzero unique IDs, registered PNG/file names,
  no silent truncation, max 64 formats.
- FileContents request/stream receipt logic, stale Format Data response draining,
  file lock/`clipDataId`, X11 INCR cleanup and native generation revocation:
  **UNCHANGED**.
- Future R10 construction is defined but not enabled: current R2
  authorization/native/session generations, Share/Graphics readiness, current
  joined `cliprdr` route, and the one R1 TLS/static-channel writer are required
  before the dormant owner could begin capabilities -> Monitor Ready -> client
  initialization. Later local publications revalidate that same authority.
- `kLinuxProductionClipboardActivationApproved = false`: **VERIFIED by source
  review / unchanged**. Live clipboard/files/physical client: **NOT RUN /
  BLOCKED**.
- Local canonical configure/build/focused/full CTest, MSVC/CLANG64 and
  sanitizers: **NOT RUN** in this connector environment. Exact
  publication-SHA hosted CI: **PENDING**. Benchmark: **NOT RUN / not
  applicable**.

## R10 final-authInfo diagnostic projection and replacement fencing — 2026-10-30

- Authoring parent: `3040716a0f098f117a0895ed15101824191a0f7c`.
- Latch R2's typed final-authInfo reason before acceptor reset and reduce it to
  a bounded R10 accepted-client diagnostic enum; R6 empty-field observations
  remain unprojected.
- Explicit Stop and standalone credential replacement clear accepted-client
  diagnostic ownership; replacement clients and fresh listener generations
  begin with no prior reason.
- New production-backed CTest:
  `runtime.linux-authinfo-diagnostic-replacement-fencing`.
- Authority audit: `CredentialsVerified` and `issueAdmission()` are one
  serialized HostControl owner step; the native broker independently samples
  authority and R3 revalidates any issued lease before first MCS. The test
  reaches valid `CredentialsVerified` and still proves no
  MCS/Share/native/graphics/clipboard without real native Admission.
- Local build/focused/full CTest and sanitizers: **NOT RUN** (no approved local
  checkout/build root). Exact publication-SHA hosted CI: **PENDING**. Physical
  client/native admission: **BLOCKED / NOT RUN**.

## R5 queued XDamage authority-retirement regression — 2026-10-30

- Authoring baseline: `671cae88da7dcb604ced089a9f21c2af9fe78597`.
- Audit: `X11DesktopResources` construction remains behind R10 `GraphicsReady` and the R2-protected `visitNativeDesktopSelection()`; the broker checks concrete lease/principal/R1/native facts before and after synchronous construction. `CredentialsVerified` alone is not native authority.
- New Xvfb CTest: `x11.desktop-resource-authority-retirement-queued-damage-isolation`. A genuine old-owner XDamage event is queued but not dispatched, authorization loss retires that aggregate, and a replacement owner must observe no stale damage and reject old capture/native provenance. A new post-replacement draw is required before replacement damage/capture can occur.
- R5 sanitizer selection/inventory: 42 -> 43, with an exact-name sentinel for the new case. Workflow structure validator updated accordingly.
- Private evidence-validator review: timing-subset contradiction, stage ordering, first-byte/zero-byte inconsistency and unknown-field redaction cases already exist; no unauthoritative attempt-generation field was added.
- Local build/Xvfb/sanitizers: **NOT RUN** in this connector-only environment. Exact publication-SHA hosted CI: **PENDING**.
- Physical Linux seat0/native admission: **BLOCKED / NOT RUN / not authorized** pending positive Microsoft delegated-credential verification and R9 exact-SHA approval. The future run sheet requires fresh seat0/unlocked same-UID evidence, Sharing ON, exact authenticated connection, fresh R2 lease, first capture/frame ACK, keyboard/mouse, lock/logout/switch/Stop revocation, and fresh reconnect with no stale resources.
- Benchmark: **NOT RUN / not applicable**; no production hot-path algorithm changed.

## R6 Microsoft CredSSP delegation-request oracle correction — 2026-10-30

- Authoring parent: `10f9c502c3ca97ba93a86cbb5a3428aa40670c4b`.
- Test-harness only: an explicit context profile adds only
  `ISC_REQ_DELEGATE` for the positive full exchange and bad-binding parity
  control. Legacy stop-at-Type3, credential-source, TLS-version and target-name
  controls keep their existing flags; `ISC_REQ_USE_SUPPLIED_CREDS` remains
  absent.
- The fixture records only `delegation-requested=yes|no` and
  `delegation-returned=yes|no`. `ISC_RET_DELEGATE` is inspected only after
  the final successful `InitializeSecurityContextW` return; intermediate
  security attributes are not evidence.
- R9's exact-SHA artifact/structure gate now normalizes and requires both
  delegation scalars for a positive, plus
  `production-authinfo-empty-fields=none`; bad-binding parity requires
  requested=yes/returned=no and rejection before authInfo.
- No production R2 authentication/verifier code is changed. Required AV,
  TLS-version, credential-source process isolation, target-name, stack-budget
  and native-admission controls remain intact.
- Local canonical MSVC/CLANG64 Debug/Release build/focused/full CTest:
  **NOT RUN** in this connector environment. Exact publication-SHA hosted
  Windows qualification: **PENDING**. Physical Windows App/mstsc and native
  admission: **NOT RUN**.

## R1 realistic delegated final-authInfo framing coverage — 2026-10-30

- Authoring parent: `1371b43d1b8c0e2a88d044894c932c9ad611e6e1`. No production R1/R2/R10 code is changed.
- Current R6 blocker remains external to R1: the Windows Microsoft CredSSP
  oracle omits `ISC_REQ_DELEGATE` and delegates both username and password as
  empty; Agent 6 owns the delegation-enabled rerun. R9's normalized evidence
  requires an explicit `delegation-requested=yes` scalar before candidate
  success.
- Coverage gap found: the prior real-TLS final-authInfo regression uses
  nonempty credentials but a small frame and 1/2/3/remainder writes; it does
  not cross the 512-byte R2 read chunk or test a complete final frame
  immediately followed by unrelated TLS application plaintext.
- Added CTest
  `runtime.linux-direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect`.
  It uses valid 32-code-unit username / 192-code-unit password credentials,
  yielding a 518-byte final authInfo with outer `0x82` DER length. The peer
  sends 1/2/1/97/131-byte fragments, the remaining body, then the final
  11 authInfo bytes plus a 9-byte unrelated marker in the same application
  write. Production must reach `CredentialsVerified` before real native
  Admission denial while its CredSSP plaintext accounting excludes the marker.
  The same case covers incomplete-final `close_notify` retirement and clean
  same-listener retry with a fresh NTLM challenge.
- Size/ownership audit: CredSSP frame cap 16 KiB <= R1 TLS application cap
  18 KiB; reader uses checked bounded arithmetic and
  `min(512, bytesNeeded())`, so it cannot consume beyond one DER frame.
  Existing `security.credssp-stream-coalesced` covers manual near-limit
  16,000-byte authInfo framing. Final CredSSP has no TPKT conversion.
- Local focused test, canonical Debug/full CTest and sanitizers: **NOT RUN**
  (approved checkout absent / local GitHub DNS unavailable). Source/static
  review: **PASS**. Exact publication-SHA hosted CI: **PENDING**.
- Physical client/native admission: **NOT RUN / not authorized**.

## R4 deferred ACK retirement across graphics generations — 2026-10-30

- Authoring parent: `a816c678f6a4d876d187e9a4de9c7892899a61aa`.
- Source audit: R5/R10 synchronous capture-generation borrow -> R3 exact
  surface/write receipts -> sole R4 prepared-frame/ACK owner; complete delivery
  creates ACK membership, partial progress is terminal, teardown disconnects R4.
- Added `graphics.frame-ack-deferred-revocation-generation-reset` for 64-entry
  saturation, unreserved deferral, generation retirement, numeric ID reuse,
  stale old-generation SUSPEND denial, and matching new-generation ACK.
- Fixed-buffer/arithmetic audit: PASS by inspection; no production codec change
  or new arithmetic negative is justified.
- Local full CTest and ASan/UBSan: **NOT RUN**; publication-SHA hosted CI:
  **PENDING**. Physical first-frame acceptance: **BLOCKED / NOT RUN** pending
  upstream authorization and R9 qualification. No FPS or latency claim is made.

## R3 Round 2 split-TLS first-MCS authority gate — 2026-10-30

- Baseline reviewed: `4cb2635175df3610a1221b213dac04c681f1ae7b`.
- Microsoft specifications rechecked: MS-RDPBCGR keeps Connect-Initial/Response
  before Erect/Attach/Join, and MS-RDPELE PersonalDesktop terminates licensing
  with STATUS_VALID_CLIENT/ST_NO_TRANSITION without removing authentication or
  native-session authority.
- Source audit: **PASS by inspection**. Connect-Response, Erect, Attach, Join,
  Client Info, PersonalDesktop licensing, Share activation and virtual-channel
  routes all refresh R2 authorization; write completion uses a second
  accepted-byte authorization. No R3 production defect found.
- Added production-backed CTest
  `runtime.linux-connection-pre-admission-mcs-split-tls-revocation-denials`
  and enrolled it in the existing Linux runtime-security ASan/UBSan selection
  (41 -> 42).
- R8 handoff documented: server CLIPRDR serialization remains R8-owned; R3/R2
  retain activated route generation, authority, queue and write receipts.
- Local canonical configure/build/focused/full CTest and sanitizers:
  **NOT RUN** in this connector environment because the approved
  `~/rdp-server/build/` checkout is unavailable. Exact publication-SHA hosted
  CI: **PENDING** at authoring.
- Positive live receipt and physical Microsoft client: **BLOCKED / NOT RUN**.
  Current upstream R2/R6 evidence still has no positive
  `CredentialsVerified` and no genuine native admission lease; none is
  fabricated here.

## R7 authInfo generation replacement and macOS package no-prompt follow-up — 2026-10-30

- Authoring parent: `9e8ee7807d57455938f8c14d9f2e78f5573f0da4`.
- R10 diagnostic projection audit: **BLOCKED for Advanced category integration**.
  `RuntimeAcceptedClientPreauthDiagnostics` still has the AuthInfo failure
  stage but no projected bounded final-authInfo reason. No R2 parser/verifier
  data is read from Qt and Main/Activity remain generic.
- Strengthened existing
  `gui.offscreen-authinfo-failure-connection-replacement-redaction`: a
  distinctive 64-bit connection-A identifier, A-only stage/timings/failure,
  and secret sentinels must disappear from Main, Activity, Advanced and export
  when connection B becomes current; B identifier/timing must then disappear
  on retirement.
- macOS archive integrity now asserts trust wording remains explicitly
  ad-hoc preview only, release signing/notarization unverified, with no
  Developer ID claim.
- The `r7-macos-portable-gui` job now builds and runs exact-one
  `runtime.macos-host-control-no-prompt-on-app-launch` before the existing
  extracted LaunchServices/no-TCP-listener smoke, tying the production
  pre-listener no-TCC-prompt contract to the package SHA.
- Windows portable GUI system-state smoke is unchanged and already snapshots
  firewall profiles/rules, TermService, RDP-Tcp port/policy and process sockets.
- Current authentication blocker: Agent 6's Microsoft CredSSP client context
  omitted `ISC_REQ_DELEGATE`; same-SHA R2 evidence shows both delegated fields
  empty and `CredentialsVerified` false. No R7 classification change is
  authorized by that oracle result.
- Local canonical build/focused/full CTest: **NOT RUN** (connector environment
  has no owner-approved local checkout/build root). Hosted publication-SHA
  structure/macOS GUI/full CTest: **PENDING**. Physical client/native desktop:
  **BLOCKED / NOT RUN**.

## R2 authInfo diagnostic reset regression — 2026-10-30

- Parent source: `1c172fc0d3d864f267289ebf320a450ac541c130`.
- Strengthened the existing production-backed authInfo rejection helper to
  require reset of both the typed failure reason and fail-only empty-field
  observation after mismatch/domain/empty-field rejection.
- No production code, Microsoft SSPI harness, credential policy or native
  admission change. Existing behavior CTests are reused; no duplicate test
  executable/controller was added.
- Local canonical Debug/full CTest and sanitizers: **NOT RUN** in this connector
  environment. Exact publication-SHA hosted CI: **PENDING**.

## R2 production CredSSP verifier freeze and Microsoft delegation blocker — 2026-10-30

- Audited source SHA: `fc35cc370ba002f6dadd42813a32bd296fbb282b`; no production R2 code change.
- `processAuthInfo()` acceptance remains fail-closed across final-frame/version
  state, pinned owned TLS provenance, protected-length bounds, NTLM SIGN/SEAL,
  validated password-credential syntax, empty standalone domain, configured
  credential, existing case-insensitive ASCII Username semantics, constant-time
  password-hash comparison, and final frame release.
- Credential generation replacement remains fenced by
  `StandalonePasswordCredentialOwner::visit()` plus the authenticated-principal
  proof's exact generation/TLS revalidation; native admission remains a separate
  R2 step.
- Workflow `41080994452`: Ubuntu full Debug/Release **984/984 PASS**; macOS
  full Debug/Release **769/769 PASS**; R9 sanitizer selections **PASS**.
  Strict-field/UTF-16 parser reconciliation and authInfo empty-field/mismatch
  regressions are green.
- Windows MSVC job `124149857609` and CLANG64 job `124149857159`:
  Type 3, pubKeyAuth, committed binding and Microsoft final authInfo reached;
  `credentials-verified=no`,
  `production-authinfo-failure=credential-identity-or-password-mismatch`,
  `production-authinfo-empty-fields=both-empty`. CLANG64 Debug/Release fail
  only `security.windows-credssp-production-full-exchange`.
- Source audit confirms Agent 6's current CredSSP context flags omit
  `ISC_REQ_DELEGATE`. Microsoft CredSSP documentation states omission
  delegates an empty credential set. The current positive oracle is therefore
  not yet a valid request for delegated User/Password.
- **BLOCKED outside R2:** Agent 6 must rerun with `ISC_REQ_DELEGATE` before any
  production verifier relaxation is considered. Desired next result:
  nonempty delegated fields, production `CredentialsVerified`, and
  `native-admission=no`. Physical client/native admission remains NOT RUN.
- Local owner canonical build/full CTest: **NOT RUN** in this connector
  environment. This audit introduces documentation only; publication-SHA hosted
  CI is not required to establish a new binary behavior.

## R6 Microsoft delegated empty-field diagnostic after Agent 2 parser correction (2026-10-30)

- R6 SHA `2b75e267ea25dce33737ac5e9ddc29ae31d00856`, workflow `41077183098`: Windows MSVC job `124136732870`, CLANG64 job `124136732710` both **FAIL** full Microsoft CredSSP positive at `password-credential-fields` after Type 3, pubKeyAuth, binding, Microsoft `SEC_E_OK` and final authInfo; CLANG64 structural classifier passes Debug and Release. Bad-binding negative remains **PASS**.
- Agent 2 SHA `2944f354f2cff5074d5dcf492b48a2a21c6ddd64` changes empty user/password strings to syntactically permitted fields, preserving policy denial: MSVC `124137657394` and CLANG64 `124137656832` now report `credential-identity-or-password-mismatch` (still **FAIL**). Separate old strict-parser fixture assertions initially fail across Linux/Windows/sanitizers; R2 follow-up `c78815cbe2fbe694452e6025b0e9c9384f5be95a`, `1642ce2330eaf67780d83737cca9ed52ada0d1e3` update those fixtures, exact-SHA qualification pending.
- R6 adds only fail-only validated delegated user/password emptiness classification, without retaining bytes or affecting credential acceptance, Type 2, TLS, SSPI, pubKeyAuth or native R2 admission. New ordinary behavior CTest `security.standalone-credssp-authinfo-empty-field-categories`; negative controls retained.
- Local canonical Windows MSVC/CLANG64 Debug and Release configure/build/full CTest **NOT RUN** (connector environment has no approved Windows checkout). Exact publication-SHA CI **PENDING**. Real RDP client/physical A/B and native admission **BLOCKED / NOT RUN**. First unresolved invariant is Microsoft's delegated username/password equivalence; initial syntax rejection has been resolved.

## R9 exact-SHA artifact/delegation qualification ledger — 2026-10-30

- Baseline SHA `fc35cc370ba002f6dadd42813a32bd296fbb282b`,
  workflow `41080994452`.
- PASS: CI workflow structure, Windows PowerShell parser, Ubuntu protocol
  Debug/Release 984/984, macOS protocol Debug/Release 769/769, R9
  security/protocol sanitizers, both Linux runtime-security variants, Linux GUI
  ZIP, Ubuntu/macOS GUI credential parity, R7 macOS native lifecycle/portable
  GUI/session sanitizers, portable GUI bootstrap, documentation policy.
  The former strict-parser regressions are **resolved by executable evidence**.
- Windows MSVC job `124149857609`: **FAIL**, first exact failing prerequisite
  is `security.windows-credssp-production-full-exchange`.
  Receipt: `authinfo=yes credentials-verified=no
  production-authinfo-failure=credential-identity-or-password-mismatch
  production-authinfo-empty-fields=both-empty`. Bad-binding negative PASS.
- Windows CLANG64 job `124149857159`: Debug full 871/872 FAIL and Release
  full 871/872 FAIL only the same positive Microsoft test; native sanitizer
  inventory PASS. R8 FileContents PASS in both Debug and Release.
- Exact artifact `r9-microsoft-interop-fc35cc370ba002f6dadd42813a32bd296fbb282b`,
  artifact `12988788914`: final `INCOMPLETE_FAIL`. It retained
  `credssp-full-production-authinfo-failure=credential-identity-or-password-mismatch`
  but omitted the available empty-field scalar. That R9 evidence gap is fixed
  by normalizing
  `credssp-full-production-authinfo-empty-fields=none|empty-username|empty-password|both-empty`.
  Missing/unknown values fail evidence collection.
- R9 requires the Microsoft full-exchange summary to expose bounded
  `delegation-requested=yes|no`; this Agent 6 increment adds
  `delegation-returned=yes|no`, derived only from final-success
  `ISC_RET_DELEGATE`. Candidate success now requires both normalized
  delegation scalars `yes`, empty fields `none`, failure `none`, raw
  `credentials-verified=yes`, and `COMPLETE_PASS`.
- ASan/UBSan authInfo inventory advances four -> five by adding existing
  `security.standalone-credssp-authinfo-empty-field-categories`; exact
  name/count preflight remains fail-closed.
- Current R2/R6 source audit shows the Microsoft client request omits
  `ISC_REQ_DELEGATE`; Agent 6 owns the next test-client publication. R9 does
  not change the production verifier or Microsoft client in this commit.
- Manual `r9_credssp_owner_candidate=true`: **NOT ELIGIBLE**. Ordinary-push
  skipped candidate is not PASS. Physical Windows App/mstsc: NOT RUN /
  not authorized. M1 owner-native same-SHA receipts remain separate.
- Local canonical build/full CTest: NOT RUN. Publication-SHA hosted structure
  and producer qualification: PENDING after this R9 CI/docs commit.

## R2 strict-fields fixture source-order correction (2026-10-30)

The immediate test-only follow-up replaces a call to the later-defined
`assertPasswordCredentialAccepted` helper in
`testStrictPasswordCredentialFields` with direct inspection assertions.
This preserves the intended empty-field syntax checks while avoiding an
undeclared forward reference. No production code or authentication-policy
change. Local compile/CTest/sanitizer NOT RUN; exact-SHA CI PENDING.

## R2 P0 Microsoft final-authInfo transition and parser fixture recovery — 2026-10-30

- Source `2944f354f2cff5074d5dcf492b48a2a21c6ddd64`,
  workflow `41077369304`, MSVC job `124137657394`:
  Microsoft final-authInfo first failure **changed** from
  `credential-der-or-fields` to
  `credential-identity-or-password-mismatch`; credential verification
  **FAIL**, correctly no R2/native admission. Typed parser barrier fixed.
- Same-SHA Ubuntu job `124137656961`: full 980/982 PASS, two existing
  `credssp-password-credential-(strict-fields|utf16-mutation-boundaries)`
  assertions **FAIL**; macOS job `124137656905` 765/767 PASS,
  same two FAIL; R9 sanitizer job `124137657124` 93/94 PASS,
  strict-fields FAIL. New standalone empty-fields-mismatch CTest PASS.
- Repaired only the outdated expected parser/UTF-16 oracle results.
  Security policy, production parser, Microsoft fixture, and all other
  production code are unchanged; malformed fields remain denied.
- Local canonical Debug/full CTest and ASan/UBSan NOT RUN because this
  connector environment lacks the owner-approved checkout/build root.
  Exact publication-SHA hosted regression verification PENDING.
- Next: Agent 6 establishes why Microsoft SSPI delegates a mismatched
  or absent identity/password, without exporting secret material.
  No production credential acceptance relaxation is authorized.

## R8 Release crash resolution and outbound CLIPRDR seam — 2026-10-30

- Crash-fix SHA: `2f3e46909051880b6d7342086e20c4625307d13c`.
  Workflow `41072241953`, Windows CLANG64 job `124119123794`: the
  production-backed `clipboard.file-contents-joined-mcs-envelope` CTest
  **PASS** in Debug and **PASS** in Release. A later descendant job
  `124124539950` repeats both PASS results. The CLANG64 producer's remaining
  failure is the independent R6 Microsoft CredSSP full-exchange/authInfo test.
  R8's Release crash is no longer an offline dependency.
- Existing R8 sanitizer job on the crash-fix workflow: **PASS**. Structure and
  documentation guards: **PASS**. Independent same-SHA MSVC full qualification
  of the R8 fixture remains **NOT VERIFIED** because the Windows producer is
  still gated by the separate R6 failure.
- Outbound implementation: extend only `R3ClipboardTransferBridge` with
  bounded first-party `CB_CLIP_CAPS` and server `CB_FORMAT_LIST` staging.
  Reuse the existing R3 static-channel route and accepted-byte receipt owner.
  Add behavior CTest
  `clipboard.route-bridge-server-outbound-capabilities-format-lists`, covering
  supported capability masking, long/short names, channel framing and bounded
  denials. Clipboard sanitizer inventory changes 100 -> 101; no Windows
  selector changes.
- `kLinuxProductionClipboardActivationApproved` remains **false**. No live
  Monitor Ready/clipboard activation, native clipboard, filesystem transfer,
  desktop or physical Microsoft client was used.
- Authoring parent: `2944f354f2cff5074d5dcf492b48a2a21c6ddd64`. Source/spec review: **PASS by inspection**.
  Local configure/build/focused/full CTest, MSVC and sanitizers: **NOT RUN** in
  this connector environment. Exact publication-SHA Actions: **PENDING**.
  Benchmark: **NOT RUN / not applicable**.

## R6 Microsoft authInfo structural classifier continuation — 2026-10-30

- Exact prior Agent 6 SHA `e8def2b91a433a727094711345c60f868577d7ac`, workflow `41072936007`.
- MSVC job `124124540101`: full Microsoft CredSSP **FAIL**, first production final-authInfo reason `credential-der-or-fields`; TLS1.3, Type 3, pubKeyAuth, binding commit, Microsoft `SEC_E_OK` and final authInfo all reached. Bad-binding negative remains **PASS** with `SEC_E_INVALID_TOKEN` before authInfo.
- CLANG64 job `124124539950`: same full-exchange category in Debug and Release. Offline first-failure classifier **PASS** in both configs. This rules out a compiler-only positive failure and resolves the prior wait-for-oracle dependency.
- Current-line MSVC job `124124681701` repeats the same category after R2/R7/R10 follow-ups; R1 Linux transport is independently green. R9 now records the failed authInfo scalar in the exact-SHA interop artifact. No later commit changed the production delegated-credential parser.
- Continued source change is diagnostic-only: split existing aggregate parser rejection into outer credential-envelope DER versus nested password-field validation using the existing secret-free inspection API. Acceptance predicate, TLS/NTLM/CredSSP wire, domain/password policy and native admission are unchanged. Dedicated CTest added for the split.
- Local build/full CTest: **NOT RUN**. Exact publication-SHA Windows producer qualification: **PENDING**. Physical client/native admission: **BLOCKED / NOT RUN**.

## R9 failed-positive CredSSP artifact capture — 2026-10-30

- Parent reviewed: `b5f7301ff1c6f2d223125b1625d9da0362a11a25`.
- R8 post-fix executable evidence:
  `58ba13d5aa515fda10f7b559b8c5adee28b324e8`, workflow `41073164830`,
  CLANG64 job `124124607506`. Debug and Release ordinary full CTest both
  PASS `clipboard.file-contents-joined-mcs-envelope`; Release no longer
  segfaults. The job remains red only because
  `security.windows-credssp-production-full-exchange` fails.
- R6 typed-attribution executable evidence:
  `975c62cdac3e4008056b24f53bbab6adc43181d5`, workflow `41073410701`,
  MSVC job `124124681701`: `authinfo=yes`,
  `credentials-verified=no`,
  `production-authinfo-failure=credential-der-or-fields`; bad-binding
  negative PASS; matrix `INCOMPLETE_FAIL`.
- Proven R9 defect: the failed full-exchange branch did not append the detailed
  redacted receipt to `r9-microsoft-interop-<sha>`; the category existed only
  in the job log. The corrected workflow records one allowlisted
  `credssp-full-production-authinfo-failure=<category>` line regardless of
  positive CTest outcome. Unknown/missing category stays red. Candidate
  validation requires `...=none` in addition to `COMPLETE_PASS`.
- Structural guard: `scripts/validate_ci_workflow.py` requires normalized
  capture before the success-only full-exchange gate and requires the failed
  CTest to remain observable without shell early-exit.
- No verifier, R6 oracle, R8 production clipboard, CTest registration,
  assertion, warning policy or candidate prerequisite is weakened.
- Owner candidate: **BLOCKED** by the positive Microsoft authInfo verifier.
  Physical Windows App/mstsc: **NOT RUN / not authorized**.
- Local build/CTest: **NOT RUN** (no permitted checkout). Exact publication-SHA
  structure and platform CI: **PENDING**.

## R7 Round 2 qualification follow-up — 2026-10-30

- Qualified code SHA: `975c62cdac3e4008056b24f53bbab6adc43181d5`; workflow `41073410701`.
- **PASS:** Ubuntu and macOS GUI parity; macOS native lifecycle; macOS portable GUI;
  macOS session sanitizers; portable GUI bootstrap; Linux GUI ZIP.
- Ubuntu full Debug and Release CTest: **980/980 PASS**; the ordinary registry includes
  `gui.offscreen-authinfo-failure-connection-replacement-redaction`.
- R7's prior exact-SHA hosted GUI/package verification PENDING item is resolved.
- **BLOCKED outside R7:** Windows MSVC reaches Microsoft final authInfo and reports
  `production-authinfo-failure=credential-der-or-fields` with
  `credentials-verified=no`. R1 transport is green. R2/R6 own the first failing
  verifier boundary.
- The production CredSSP verifier has typed `StandaloneAuthInfoFailureReason` values,
  but R10 does not currently expose that reason through
  `RuntimeAcceptedClientPreauthDiagnostics`; Qt sees only the AuthInfo failure stage.
  Therefore no new user-visible identity/password/native-admission reason is authorized.
- Local owner build/CTest: **NOT RUN** in this connector environment. Physical
  Windows App/mstsc and native desktop admission: **BLOCKED / NOT AUTHORIZED** pending
  R9 Windows-producer qualification and positive R2 `CredentialsVerified`.
- No production source, wire behavior, CI selector, native permission, TCC, firewall,
  TermService, listener, or credential policy change accompanies this documentation update.

## R1 Round 2 qualification follow-up — 2026-10-30

- Exact tested SHA: `975c62cdac3e4008056b24f53bbab6adc43181d5`; primary workflow `41073410701`; Ubuntu protocol job `124124681621`.
- Linux Debug full CTest: **980/980 PASS**. Linux Release full CTest: **980/980 PASS**.
- R1 acceptance gates in the same job: **PASS** for `runtime.linux-direct-ntlm-final-authinfo-tls-fragments-reconnect`, `runtime.linux-host-control-stop-queued-authinfo-retirement`, `runtime.linux-direct-ntlm-preauth-service-no-starvation`, `transport.tcp-owned-tls-read-want-interleaved-frame-write`, and `transport.credssp-direct-ntlm-type2-delivery-receipts`.
- This resolves the prior hosted-execution blocker for the R1 Round 2 transport increment. Local `~/rdp-server/build/` execution remains **NOT RUN** because this connector environment still has no approved checkout / usable GitHub DNS.
- Dependency graph remains blocked outside R1: Windows MSVC job `124124681701` reaches Microsoft final authInfo and reports `production-authinfo-failure=credential-der-or-fields` with `credentials-verified=no`; R2/R6 own that verifier boundary. The current CLANG64 producer is not yet qualified, so R9 owner-candidate and physical Windows App/mstsc testing remain **BLOCKED / NOT AUTHORIZED**.
- R1 conclusion: **READY / no demonstrated transport defect**. Local TLS write completion is not peer receipt; readiness/timing counters remain diagnostic only. No TLS policy, Type-2, polling, timeout, socket-owner or retry workaround is justified.

## R2 final-authInfo offline negative-fixture follow-up (2026-10-30)

- Parent `58ba13d5aa515fda10f7b559b8c5adee28b324e8`: current typed production verifier and Microsoft
  SSPI oracle were not modified by this test-only increment.
- New/expanded existing CTest modes: malformed final request, short sealed
  length, malformed DER under valid NTLM sign/seal, and post-binding credential
  revoke; each requires closed reader/writer and exact typed rejection.
- Source/test static review PASS; actual local Debug full CTest and focused
  ASan/UBSan NOT RUN (no approved checkout or GitHub DNS in connector).
- Exact SHA `975c62cdac3e4008056b24f53bbab6adc43181d5`, workflow
  `41073410701`: Windows CLANG64 Debug/Release both PASS
  `security.standalone-credssp-authinfo-first-failure-classification` and
  `security.standalone-credssp-authinfo-post-binding-revocation`. MSVC and
  CLANG64 both report Microsoft final authInfo
  `production-authinfo-failure=credential-der-or-fields`.
- R1 same-SHA transport gates are green. Source review localizes one parser
  classification defect: empty userName/password OCTET STRING values are
  syntactically representable but were rejected as malformed before the
  credential comparator. The corrective production change permits empty field
  syntax only; the unchanged standalone matcher, Unix-account policy and PAM
  verifier still reject empty credentials. New CTest:
  `security.standalone-credssp-authinfo-empty-fields-are-mismatch`.
- Local Debug/full CTest and ASan/UBSan for this corrective descendant:
  NOT RUN in this connector environment. Exact corrective-SHA CI: PENDING.

## R6 Round 2 Microsoft delegated authInfo typed diagnosis — 2026-10-30

- Initial source SHA `2c838a57bb30ebeb3db902b399054d4cdff8e1b8`; [Actions 40860372282](https://github.com/k1moradi/RDP-server/actions/runs/40860372282).
- Windows MSVC protocol job `123401900562`: **FAIL** at full CredSSP,
  despite TLS1.3, production Type 2, Type 3, pubKeyAuth, server binding and
  Microsoft final authInfo; production CredentialsVerified is false.
- Windows CLANG64 job `123401900577`: **FAIL** at same positive in Debug
  and Release; a separate Release clipboard segfault remains R9-owned.
  Bad-server-binding Microsoft control: **PASS** `SEC_E_INVALID_TOKEN`,
  no authInfo.
- Source-level review: **PASS** for explicit SSPI empty-domain input
  request; delegated-domain payload remains **UNKNOWN**. Authored read-only
  production classification and a separate production-backed offline CTest;
  no protocol wire, password policy, native authorization or CI workflow
  change. Typed category must be measured, not guessed.
- Local owner Windows MSVC/CLANG64 Debug/Release configure/build/CTest:
  **NOT RUN** (connector environment; approved Windows build root absent).
  Exact publication-SHA hosted CI **PENDING**; physical client and native
  admission **NOT RUN**. The first unresolved boundary remains production
  final authInfo. Agent 2 owns verified security-policy disposition.

## R5 Round 2 evidence subset/summary redaction — 2026-10-30

- Inspected baseline `2c838a57bb30ebeb3db902b399054d4cdff8e1b8` and existing R2/R10/R5 authority, X11 native generation and owner-evidence tests.
- Added timing-subset contradiction detection and field-only redaction to the existing macOS Windows App evidence validator. New behavior CTest `macos.windows-app-owner-evidence-timing-subset-denials` exercises six impossible subsets and private extension-field suppression. Existing positive early-native-maintenance finding is preserved.
- Source/static patch review: **PASS by inspection**. Actual Python unittest/CTest, Linux Debug build/full CTest, Xvfb and sanitizer: **NOT RUN** (no local checkout, GitHub DNS unavailable in execution container).
- Exact publication-SHA CI: **PENDING**. Physical Windows App/mstsc, owner-consented native seat0 and R2 admission: **BLOCKED / NOT RUN** pending R9 and Windows producer gates.
- Next: qualify exact publication SHA in hosted Python/Linux/sanitizer jobs, then wait for R9 approval for physical evidence; no change to native authorization or graphics is authorized by this increment.

## R4 first-frame sanitizer-selection correction — 2026-10-30

- Publication parent: `a812df7668b7a45b85dd1cd9f5d73c956411948b`.
- Corrected the existing portable RDPGFX CTest selection/required-name
  sentinel to include the new remap-before-first-frame regression.
- Source/CMake/CI reconciliation PASS by inspection; selected sanitizer and
  full CTest at this exact publication SHA PENDING.
- No production behavior or physical client activity changed.

## R9 Round 2 baseline qualification ledger — 2026-10-30

Source SHA `2c838a57bb30ebeb3db902b399054d4cdff8e1b8` ·
[workflow 40860372282](https://github.com/k1moradi/RDP-server/actions/runs/40860372282) ·
`push` · attempt 1 · conclusion **FAILURE**. Every job and artifact
below belongs to this **historical one SHA**; do not merge with later SHAs.

| Producer (job ID) | Exact Debug/Release coverage or selection | Result, artifact, first failure and owner |
| --- | --- | --- |
| Workflow structure (`123401782413`) | 18 job IDs, no duplicates, 3 negative fixtures | **PASS**, R9 |
| PowerShell parser (`123401782002`) | Offline parser | **PASS**, R9 |
| Documentation (`123401900430`) | Policy/structure | **PASS**, R9 |
| Ubuntu protocol (`123401900694`) | Debug 973/973, Release 973/973, consumer 1/1 | **PASS**; protocol SDK artifact `12891207204`, R9 |
| macOS protocol (`123401900633`) | Debug 761/761, Release 761/761, consumer 1/1 | **PASS**; protocol SDK artifact `12891192902`, R9 |
| MSVC protocol (`123401900562`) | Native preflight Debug 60/60, Release 60/60; Microsoft focused suite; full suite NOT RUN after prerequisite failure | **FAIL** `security.windows-credssp-production-full-exchange` (R2/R6); interop `r9-microsoft-interop-2c838a57bb30ebeb3db902b399054d4cdff8e1b8`, artifact `12891656145`, `INCOMPLETE_FAIL` |
| CLANG64 Clang 23 (`123401900577`) | Full Debug 862/863, full Release 861/863; native sanitizer 60/60 PASS; extracted GUI smoke PASS | **FAIL** full CredSSP both configs (R2/R6), plus Release `clipboard.file-contents-joined-mcs-envelope` SEGFAULT (R8). Credential-source diagnostic artifact `12892080305`; unverified Windows GUI artifact `12891712921` is not a qualified bundle |
| Security/protocol sanitizers (`123401900452`) | Debug security/transport/graphics; clipboard 100/100, R3 CLIPRDR 9/9, portable graphics 43/43 | **PASS**, R9 |
| Linux runtime security complete (`123401900450`) | Production GSS/PAM/systemd linkage | **PASS**, R2/R10 |
| Linux runtime security missing-systemd (`123401900560`) | Negative configure | **PASS**, R2/R10 |
| macOS native lifecycle (`123401900467`) | Focused Debug 21/21, Release 21/21 | **PASS**, R7 |
| macOS portable GUI (`123401900513`) | Packaging/offline GUI | **PASS**, artifact `12891287757`, R7 |
| macOS session sanitizers (`123401900529`) | Native sanitizer selection | **PASS**, R7/R9 |
| Linux GUI ZIP (`123401900589`) | Packaging/offline GUI | **PASS**, artifact `12891491666`, R5 |
| Portable GUI bootstrap (`123401900573`) | Focused 10/10 | **PASS**, R9/R10 |
| GUI parity Ubuntu (`123401900626`) | Focused 6/6 | **PASS**, R7/R9 |
| GUI parity macOS (`123401900693`) | Focused 6/6 | **PASS**, R7/R9 |
| SERVER-TEST aggregate (`123403949577`) | Required three-platform producers | **FAIL** Windows producer, R9 |
| GUI Round 2 (`123408311031`) | Linux/macOS GUI, Windows CLANG64, docs all success | **FAIL** Windows producer, R9 |
| Clean Windows self-hosted (`123408311105`) | Separate release gate, not GUI Round 2 prerequisite | **CANCELLED**, not PASS, R9/owner |
| Prerelease publisher (`123403951890`) | Required successful matrix | **SKIPPED**, not PASS, R9 |
| Manual owner candidate (`123408355406`) | Explicit manual input, same-SHA COMPLETE_PASS and producers | **SKIPPED** on push, not PASS, R9/owner |

**R2/R6 separate P0:** The positive MSVC/CLANG64 log reads
`type3-observed=yes type3-verified=yes pubkeyauth=yes
server-binding-committed=yes authinfo=yes credentials-verified=no
stage=production-authinfo`. It proves Microsoft generated authInfo,
not that R2 accepted it. Only a generic stage, **not a typed first
production authInfo rejection category**, was logged. Agents 2/6 must
attribute the exact first failure with bounded non-secret status only;
never print delegated credentials, keys or raw SSPI tokens. The
bad-binding negative separately **PASSes** (`SEC_E_INVALID_TOKEN`,
authinfo=no); keep it independent and mandatory.

**R8 separate P0:** CLANG64 Release's ordinary full 863-case CTest
keeps `clipboard.file-contents-joined-mcs-envelope` registered as #426;
it **SEGFAULTS** while Debug passes. Do not hide/filter/skip it or
weaken assertions. R8 later published a fixture-owned correction in
[`2f3e4690`](https://github.com/k1moradi/RDP-server/commit/2f3e46909051880b6d7342086e20c4625307d13c);
its exact-SHA Windows Release result was **NOT VERIFIED** at audit.

**R9 CI findings:** CLANG64 uses verified MSYS2 Clang 23; full Debug and
Release CTest failures propagate; Windows native sanitizer selection 60/60
passes; the fresh-process Microsoft credential-source oracle marks child
crash, missing begin/end marker and nonzero exit as failure. Its verbose
diagnostic uses `set -euo pipefail` and `tee`. MSVC interoperability
terminates `INCOMPLETE_FAIL`, not `COMPLETE_PASS`; GUI Round 2 requires
Windows CLANG64, not the separate clean-Windows VM. Exact-SHA workflow
structure validation PASS (18 jobs, 0 duplicate keys, 3 negative fixtures).
No independently verified infrastructure defect warrants modifying
`ci.yml`, `validate_ci_workflow.py` or centralized CTest registration.

**Concurrent SHA qualification:** R4 then advanced `main` to
[`3db1bcd9`](https://github.com/k1moradi/RDP-server/commit/3db1bcd9c7aa5818e329dfc6e3fa0c4b0cc7b7f5);
structure [41071989245](https://github.com/k1moradi/RDP-server/actions/runs/41071989245)
PASS, primary [41071989194](https://github.com/k1moradi/RDP-server/actions/runs/41071989194)
QUEUED when reviewed. R8's later `2f3e4690` is a separate SHA.
Neither queued work nor earlier green jobs qualify a later HEAD.

**Disposition: OWNER CANDIDATE BLOCKED.** The next candidate needs one
exact SHA with MSVC positive `CredentialsVerified`, deliberately
bad-binding negative, CLANG64 full Debug/Release including Release
clipboard, native Windows 60/60 sanitizer, `COMPLETE_PASS` Microsoft
artifact, Linux/macOS protocol/security, GUI parity/Round 2/bootstrap
and documentation/structure success. Only then may the owner explicitly
dispatch `r9_credssp_owner_candidate=true` and require its own PASS.
Same-SHA owner-native Linux/X11, Windows MSYS2 CLANG64/Clang 23 and
macOS 27 Debug/full CTest receipts remain **NOT VERIFIED** for M1.
Physical Windows App/mstsc tests **NOT RUN / not authorized** until manual
qualification and owner permission. The existing checklist requires
exact SHA/client builds, identical listener/endpoint/certificate,
explicit independent Session Password and warning decisions, typed
stage progression and redacted private evidence.

**Validation:** Remote exact-SHA workflow structure PASS and GitHub
job logs inspected. Local `scripts/validate_ci_workflow.py` execution,
configure/build and CTests **NOT RUN**; the only permitted checkout
`~/rdp-server/` does not exist in this environment, and local GitHub
DNS resolution failed. This is documentation-only, not a new CI PASS.

---
## R1 Round 2 — final CredSSP transport framing / reconnect (2026-10-30)

- Source baseline: `2c838a57bb30ebeb3db902b399054d4cdff8e1b8` (`main`). Reviewed `nonblocking_tcp_adapter.*`, `preauth_session.*`, R2 `credssp_tsrequest.cpp`, R10 `linux_runtime_connection.cpp`, and the real-TLS direct-NTLM lifecycle/CTest registry.
- Source audit: **READY for focused verification**, not live-client acceptance. One R1 socket/SSL/BIO owns final CredSSP I/O; the R2 reader/writer pin TLS identity, certificate and generation; R10 consumes only complete DER frames. `WANT_READ`/`WANT_WRITE`, incomplete writes and terminal closure do not grant CredentialsVerified or native admission. No production transport behavior changed.
- New test: `runtime.linux-direct-ntlm-final-authinfo-tls-fragments-reconnect` drives truncated final authInfo + TLS close, a second complete final authInfo over separate 1/2/3/remainder TLS writes, and a third same-listener retry. All positive credentials are expected to fail at genuine R2 native admission; no MCS/desktop capability is synthesized.
- Command attempted: `git clone --depth 1 --branch main https://github.com/k1moradi/RDP-server.git ~/rdp-server`: **BLOCKED** (`Could not resolve host: github.com`). Canonical `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`, `cmake --build build --config Debug --parallel 2`, `ctest --test-dir build -C Debug --output-on-failure`, and focused sanitizers: **NOT RUN**. No second build root created.
- Exact publication-SHA hosted CI: **PENDING / NOT VERIFIED**. No claim that transport caused R6's final authInfo failure, that the physical Windows App received Type 2, or that any real desktop was admitted. Next: exact-SHA Linux test/CI qualification, then R9-authorized physical evidence and R6 verification at the first failing protected-authInfo boundary.

## R8 CLANG64 Release FileContents fixture containment — 2026-10-30

- Source parent: `2c838a57bb30ebeb3db902b399054d4cdff8e1b8`; workflow `40860372282`, CLANG64 job
  `123401900577` confirms Debug joined FileContents PASS / Release SEGFAULT.
  The existing Release assert-header sentinel did not prevent the crash; no
  symbolized stack/faulting instruction was uploaded.
- R8 updates only `tests/test_owned_remote_transfer.cpp`: always-live
  fail-only checks before optional dereferences and RAII ownership for four
  large test-local `RemoteTransfer` objects. The existing behavior CTest is
  reused without weakening a single assertion. Production clipboard and R3
  outbound code are unchanged.
- Local CLANG64 Debug and Release focused/full CTest, MSVC, sanitizers:
  **NOT RUN** in this connector execution environment. Exact publication-SHA
  hosted CI: **PENDING**. No native clipboard or filesystem access performed.
- If Release still crashes, obtain a symbolized first-invalid-operation trace
  before attributing the defect to the production `RemoteTransfer` lifetime.

## R4 Round 2 remap-before-first-frame authoring evidence — 2026-10-30

- Parent source inspected: `2c838a57bb30ebeb3db902b399054d4cdff8e1b8`.
- Production path R10 native capture -> R2 admission revalidation ->
  R3 surface receipts -> R4 ClearCodec/ACK owner: PASS by source inspection.
  No production code or codec/scheduler change.
- New CTest: `graphics.surface-remap-before-first-frame-wire`.
  16-byte padded input, 96-byte output, 79-byte wire contract; three
  receipt stages, stale ACK/geometry denial and zero-byte retry.
- GitHub-connector authoring inspection: PASS. Local checkout/build,
  focused/full CTest and sanitizers: NOT RUN (DNS unavailable).
  Exact publication-SHA hosted CI: PENDING.
- Physical Microsoft CredSSP/R2/MCS/Share/first DATA/ACK/resize: BLOCKED/
  NOT RUN. No live desktop operation or benchmark performed.
- Next: qualify exact-SHA hosted R4 graphics CTests and sanitizers; obtain
  separately authorized physical R6/R9/R2 admission evidence.

## R4 Round 2 remap-before-first-frame authoring evidence — 2026-10-30

- Parent source inspected: `2c838a57bb30ebeb3db902b399054d4cdff8e1b8`.
- Production path R10 native capture -> R2 admission revalidation ->
  R3 surface receipts -> R4 ClearCodec/ACK owner: PASS by source inspection.
  No production code or codec/scheduler change.
- New CTest: `graphics.surface-remap-before-first-frame-wire`.
  16-byte padded input, 96-byte output, 79-byte wire contract; three
  receipt stages, stale ACK/geometry denial and zero-byte retry.
- GitHub-connector authoring inspection: PASS. Local checkout/build,
  focused/full CTest and sanitizers: NOT RUN (DNS unavailable).
  Exact publication-SHA hosted CI: PENDING.
- Physical Microsoft CredSSP/R2/MCS/Share/first DATA/ACK/resize: BLOCKED/
  NOT RUN. No live desktop operation or benchmark performed.
- Next: qualify exact-SHA hosted R4 graphics CTests and sanitizers; obtain
  separately authorized physical R6/R9/R2 admission evidence.

## R7 Round 2 AuthInfo GUI replacement isolation — 2026-10-30

Original authoring SHA `2c838a57bb30ebeb3db902b399054d4cdff8e1b8`;
published on refreshed main without overwriting concurrent owners.
New `gui.offscreen-authinfo-failure-connection-replacement-redaction`
uses the existing HostControl fake for final AuthInfo rejection, a new
connection and retirement. It verifies generic Main/Activity classification,
current Advanced status, no old connection ID/stage/timing in display/export,
and no runtime/pending Username, Session Password, delegated-domain, NTLM
proof, authInfo, MIC, binding token or TLS-secret sentinels in export.
No Qt, R1/R2/R10 or platform production source changed. Source/CTest and
package-policy inspection PASS. Local Qt configure/build/focused/full CTest
NOT RUN (no checkout/Qt toolchain); publication-SHA hosted CI PENDING.
R2 owns any new AuthInfo taxonomy; no physical Microsoft-client acceptance
is claimed. Next gate: exact-SHA CI plus owner-native platform CTest.

## R4 dependency-graph reconciliation — 2026-10-29

- Reconciled source parent: `cd117cb374042fec463bf64c231e22625bd8bd99`.
- Source audit: **PASS** for the three former R4 handoff blockers. ACK-window
  exhaustion defers before XShm capture; typed X11 geometry is reconciled
  through R3-owned DELETE/CREATE/MAP with generation fencing; pending outbound
  Graphics writes cannot turn an expired capture deadline into a zero-timeout
  busy poll.
- Linux GUI/runtime dependency: **RESOLVED IN SOURCE**. Normal Linux GUI startup
  owns `LinuxPortableDesktopRuntime` / `LinuxRuntimeHostControl`, and
  `serviceOnce()` performs serialized accept/pre-auth/admitted-client
  advancement. Old roadmap text describing an unavailable/deny-only Linux
  HostControl is stale.
- Descendant executable evidence at
  `cde24568f8bcb60a69559dae19ac40ba96fbf092`, workflow
  `40847067020`: macOS protocol job `123357097770` **760/760 PASS**,
  including `transport.rdpgfx-client-core-capability-gate` and
  `graphics.first-frame-compatibility-contract`; sanitizer job
  `123357097494` portable R4 **43/43 PASS** and ClearCodec **4/4 PASS**.
- R6 dependency: the Microsoft-native protocol-only CredSSP fixture now
  exercises verified Type 3, pubKeyAuth, committed binding and Microsoft-
  generated `authInfo`, but positive `CredentialsVerified` remains **FAIL /
  NOT PROVED** at `2c838a57bb30ebeb3db902b399054d4cdff8e1b8`, Actions
  40860372282 (`authinfo=yes credentials-verified=no stage=production-authinfo`).
  The bad-binding negative PASSes. Future positive completion still cannot
  mint native admission or authorize MCS/Share/RDPGFX.
- Physical Microsoft-client first-frame acceptance: **BLOCKED / NOT RUN**.
  Current physical Windows App evidence still terminates after server Type 2
  with FIN/no Type 3. Genuine owner-consented R2 native admission on a physical
  X11 seat remains required before R4 may claim visible Microsoft-client pixels
  or a matching live FRAME_ACK.
- Local canonical `~/rdp-server/build/` configure/build/full CTest:
  **NOT RUN** in this connector environment. This reconciliation is
  documentation-only; current-head hosted producers are **PENDING**.
- Benchmark: **NOT RUN / not applicable**; no hot path, encoder or scheduler
  behavior changed.
- Next gate: preserve current ClearCodec/AVC/ACK/authentication behavior until a
  real admitted Microsoft client reaches graphics; then capture the first
  failing wire/lifecycle boundary and fix only evidence-backed behavior.

## R6 first-publication regression and stack-budget correction — 2026-10-29

- First publication SHA: `fc3ccea61c9da0d046810ad6694a05c35821fa38`.
- Structure guard `40850215722`: **PASS**.
- Protocol Windows job `123367591533`: Debug compile, certificate policy and
  CredSSP harness-round tests **PASS**; the pre-existing system-default,
  TLS-1.2-only and TLS-1.3-only CredSSP tests each **SEGFAULT** before the new
  provider-call begin marker, so the later Microsoft matrix was correctly
  blocked.
- Immediate parent control `e4a6275bbc7a3b72e8c88a67dda944c29233b46d`,
  Windows protocol job `123367218888`: the same TLS-version matrix, modern
  Schannel probe and primary Microsoft NTLM/CredSSP differential **PASS**.
- CLANG64 first-publication job `123367591161`: Debug build and isolated
  credential-source diagnostic **PASS** before the full Debug suite.
- Root cause in the R6 delta: `FullCredSspAttempt` was enlarged by an
  additional fixed 128-round `CredSspPumpResult` trace even though the
  post-Type-2 trace is no longer needed after its commit/consume facts are
  copied.  This changed the stack-resident Windows harness footprint and
  reproduced as an immediate MSVC-only crash before SSPI acquisition.
- Correction: reuse `nextPump` for the later binding/authInfo phase only in
  completion/negative modes; the legacy stop-at-Type-3 path is unchanged.
  No production source or security assertion changed.
- Corrective exact-SHA hosted validation: **PENDING**.

## R3 Round-2 HYBRID TLS first-MCS admission gate — 2026-10-30

- Inspected parent: `75fc65aa081c2f7452d9c17750e90021de41acaf`, existing main. Prior UserId-range,
  borrowed-span, ChannelJoin, Microsoft first-exchange corrections retained.
- Added production-backed CTest:
  `runtime.linux-connection-mcs-pre-admission-tls-coalesced-denials`,
  using real R1 loopback OpenSSL, R2 CredSSP, R10 connection and the
  checked-in 416-byte Microsoft MCS fixture. The negative scenarios are
  early valid MCS and rejected-TSRequest+MCS coalescing; R3 consumes zero
  bytes and stale connection callbacks remain terminal.
- Source/ownership/test-registration audit: PASS by inspection only.
  Owner canonical Debug configure/build/focused/full CTest: NOT RUN;
  sanitizers: NOT RUN; exact publication-SHA hosted CI: PENDING.
  No production source/authorization change, fake OS admission, live
  MCS/Share or client acceptance. Next: hosted exact-SHA producer suite,
  then real R2-admitted physical-client positive completion/revocation.
  R8 remains owner of later outbound CLIPRDR format/capability payload.

## R9/R3 macOS MCS borrowed-view fixture blocker — 2026-10-29

- Failing source SHA: `b93e8110f44558f07c096132977856dd54db97a4`.
- Workflow: `40849704993`; macOS protocol job: `123365876850`.
- Debug full CTest first failure:
  `transport.mcs-user-id-range-conformance`; the same routine also failed
  through `transport.mcs-send-data-joined-denials`.
- First boundary: `test_owned_mcs_connect_initial.cpp:1706`, reading the
  one-byte SendData payload from `McsChannelRequest::userData`.
- R3's newer `e4a6275bbc7a3b72e8c88a67dda944c29233b46d` correctly restores
  the MS-RDPBCGR 1001..65536 User Channel ID profile and remains preserved.
- Residual root cause: the test parsed a temporary framed vector even though
  `userData` is documented as a borrowed span into that vector. The
  temporary was destroyed before the span was dereferenced.
- Correction: keep the framed SendData vector alive through all borrowed-span
  assertions. Production MCS and authentication behavior are unchanged.
- Canonical local build/full CTest: **NOT RUN** in this connector environment.
- Corrective exact-SHA hosted qualification: **PENDING**.

## R6 Microsoft-native CredSSP crash containment and completion oracle — 2026-10-29

- Historical failing source: `d9b255bef6ae54952b50ffbca24f4b17ce969d72`,
  workflow `40761365568`, Windows CLANG64 job `123073932690`: Debug
  `security.windows-credssp-credential-semantic-differential` SEGFAULT after
  complete correct/wrong/empty Type-3 rows and before an unavailable/no-SPNEGO
  receipt; Release passed.  No crash dump/symbolized stack was published by
  that run.
- Resolved dependency evidence: exact SHA
  `cde24568f8bcb60a69559dae19ac40ba96fbf092`, workflow `40847067020`,
  CLANG64 job `123357097619`, artifact id `12885258246`: the isolated Debug
  credential-source diagnostic PASSed.  The unavailable/no-SPNEGO child
  entered `AcquireCredentialsHandleW`, returned
  `SEC_E_INSUFFICIENT_MEMORY (0x80090300)`, never called
  `InitializeSecurityContextW`, and completed as `FAILED_BEFORE_TYPE1`.
  Correct, wrong-password and empty-password each emitted Type 3.
- Root-cause boundary: the current fresh-process result makes the same
  Schannel-only `CREDSSP_CRED` construction a typed provider failure instead
  of a process crash.  For that row no security context, input/output SecBuffer
  exchange, `CompleteAuthToken`, or context cleanup is reached.  The
  historical Debug-only crash is therefore contained as process/provider state
  interaction around credential acquisition; absence of the historical dump
  prevents claiming a stack-level symbolized fault.
- Implementation: preserve per-credential process isolation as fail-closed
  containment and add non-secret provider call boundaries.  Extend the
  Microsoft-native memory-BIO client through the existing production
  `StandaloneCredSspNtlmAcceptor` to verified Type 3 + pubKeyAuth, server
  binding reply, final authInfo and `CredentialsVerified`, using explicit
  in-memory credentials only.  Add a cryptographically mismatched server
  binding negative that must fail before authInfo.  Native admission remains
  impossible on this direct-SSL test path.
- Existing independent controls retained: TLS 1.3/SystemDefault qualification,
  target-name and OEM differentials, correct/wrong/empty credential rows,
  required Type-2 TargetInfo AV-pair negatives, and the observational physical
  40-byte Type-1 / production Type-2 structural comparison.
- Authoring parent: `e4a6275bbc7a3b72e8c88a67dda944c29233b46d`.
- Source/test/CI/docs review: **PASS by inspection**.
- Canonical local owner build/full CTest: **NOT RUN** in this connector
  environment.
- Exact publication-SHA hosted Windows Debug/Release and Microsoft full
  interoperability matrix: **PENDING**.
- Live Windows App/mstsc, desktop, clipboard, trust-store changes and native
  admission: **NOT RUN / NOT AUTHORIZED**.

## R9 current-main GUI parity blocker — typed diagnostic vs visible fallback (2026-10-29)

- Exact source SHA: `0a40bc6c78ed4243b3e74e3a38eee6911e1d3618`.
- Primary workflow: `40848699217`.
- Ubuntu GUI parity job `123362528262`: **FAIL**, 5/6 selected tests PASS.
- First failing boundary:
  `gui.offscreen-authentication-incomplete-before-native-admission` at
  `tests/test_desktop_gui_offline.cpp:2370`.
- Runtime projection is correct: `AuthenticationRejected` without a typed
  credential/admission reason remains generic remote authentication failure and
  `HostStatus::authenticationDiagnostic` is empty.
- Desktop presentation is also correct: an empty typed diagnostic falls back to
  the bounded runtime error as
  `Diagnostics: Client authentication rejected`.
- Correction is test/docs only and preserves concurrent R3 UserId-range work.
- Corrective exact-SHA hosted qualification: **PENDING**.

## R3 Microsoft-profile User Channel ID correction — 2026-10-29

- Correction parent: `b93e8110f44558f07c096132977856dd54db97a4`.
- The preceding 65535 tightening was rejected during qualification because
  MS-RDPBCGR explicitly specifies RDP User Channel ID and GCC nodeID
  1001..65536 inclusive, while generic T.124/T.125 ASN.1 says 1001..65535.
- Project policy makes Microsoft's published RDP definitions primary for this
  wire boundary. Production therefore accepts 65536 / PER offset `0xFC17`
  and rejects 65537 / `0xFC18`.
- Dedicated gate:
  `transport.mcs-rdp-user-id-range-conformance`; the sanitizer-selected
  `transport.mcs-send-data-joined-denials` reuses the same routine.
- No synthetic admission, HostControl progression, live MCS, licensing/Share
  activation or native desktop is introduced.
- Local canonical build/full CTest: **NOT RUN** in this connector environment.
- Exact corrective-SHA hosted CI/sanitizers: **PENDING**.

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

**R10 Round 2 queued authInfo retirement (2026-10-30):** Added
`runtime.linux-host-control-stop-queued-authinfo-retirement` to production-backed Linux TLS/Direct-NTLM lifecycle coverage.
It holds valid final authInfo pending during Stop, verifies retained memory
credential with retired listener, rejects stale client ID on a replacement,
then requires genuine R2 native admission even after another complete
CredentialsVerified. No production source modified. Authoring/source/registry
inspection PASS; local Debug CTest and ASan/UBSan NOT RUN (checkout and DNS
unavailable); publication-SHA hosted qualification PENDING. M1 owner-native
and M2 physical-client acceptance NOT RUN; independent R6/R8 blockers remain.


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
